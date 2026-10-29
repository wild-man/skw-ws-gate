use std::{
    cell::RefCell,
    net::SocketAddr,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};

use dashmap::mapref::entry::Entry;

use ntex::{
    chain,
    channel::oneshot,
    fn_service, rt,
    service::{Service, fn_factory_with_config, fn_shutdown},
    time,
    util::{Bytes, inflight::InFlightService},
    web,
    web::ws::start,
    ws::CloseCode,
    ws::CloseReason,
    ws::Message,
    ws::{Frame, WsSink},
};

use skw_lib_shared::AppError;
use tokio::sync::mpsc::UnboundedSender;

use crate::cfg::{CFG_CLIENT_TIMEOUT, CFG_HEARTBEAT_INTERVAL, CFG_MAX_INFLIGHT_FRAMES, CFG_MAX_PENDING_REQUESTS};
use crate::crypto::{check_authorize, verify_signature};
use crate::gate::{ConnectionEntry, PendingRequestEntry, PendingSlot, WsGateState, WsOutbound, publish_to_service};
use crate::structs::{AuthState, WsMethod, WsRequest, WsState};
use skw_lib_shared::prelude::{
    axum::StatusCode,
    chrono::Utc,
    consts::BACK_MESSAGE_TIMEOUT,
    iggy::SkwTopicType,
    log::*,
    tools::{skw_is_outdated, skw_random_signature},
    uuid::Uuid,
};

/// Marks the client alive and passes `parsed` through: any client text frame proves it is
/// alive, since browsers can't send pings and their pongs only answer ours.
fn refresh_hb<T>(state: &RefCell<WsState>, parsed: T) -> T {
    state.borrow_mut().hb = Instant::now();
    parsed
}

/// handler for a single incoming websocket frame
pub(crate) async fn handle_frame(
    state: Rc<RefCell<WsState>>,
    gate_state: WsGateState,
    outbound_tx: UnboundedSender<WsOutbound>,
    frame: Frame,
) -> Result<Option<Message>, AppError> {
    let item = match frame {
        // update heartbeat: any responsive client stays connected, authorized or not,
        // since public/open requests need no authorization
        Frame::Ping(msg) => {
            trace!("ws ping <- connection {}", state.borrow().connection_id);
            state.borrow_mut().hb = Instant::now();
            Some(Message::Pong(msg))
        }

        Frame::Pong(_) => {
            trace!("ws pong <- connection {}", state.borrow().connection_id);
            state.borrow_mut().hb = Instant::now();
            None
        }

        // validate the frame is valid UTF-8 *and* deserializes into our expected shape
        Frame::Text(text) => match refresh_hb(&state, serde_json::from_slice::<WsRequest>(&text)) {
            Ok(req) => {
                // checked before the signature check: a client over the limit costs no more work.
                // Check and count (in `dispatch_request`) run before the first `.await`, and a
                // connection's frames share one worker thread, so the limit can't be overshot
                let pending = state.borrow().pending.clone();
                if pending.load(Ordering::Relaxed) >= *CFG_MAX_PENDING_REQUESTS {
                    warn!(
                        "connection {} has {} pending requests, closing",
                        state.borrow().describe(),
                        *CFG_MAX_PENDING_REQUESTS
                    );
                    return Ok(close_connection(&outbound_tx, "Too many pending requests"));
                }

                // public/open topics need neither authorization nor a valid signature (like
                // gates/api); `Signature` is then only the client's request id, echoed in the reply
                if is_unsigned_topic(req.uri.as_deref()) {
                    let rnd_signature = skw_random_signature();
                    return Ok(dispatch_request(
                        &gate_state,
                        &outbound_tx,
                        &pending,
                        None,
                        &rnd_signature,
                        req,
                    )
                    .await);
                }

                let auth = state.borrow().auth;

                match auth {
                    AuthState::Authorizing => unauthorized_close(&outbound_tx),

                    AuthState::Pending => {
                        // claim the single authorization attempt synchronously,
                        // before the `.await` below gives another frame a chance
                        // to be dispatched concurrently.
                        state.borrow_mut().auth = AuthState::Authorizing;

                        match serde_json::from_value::<WsMethod>(req.data.method.clone()) {
                            Ok(WsMethod::Authorize { api_key }) => match check_authorize(api_key, &req.signature, req.data.raw_str()).await {
                                // an old Authorize frame must not open a session: it fails like bad credentials
                                Ok(_) if skw_is_outdated(req.data.ts) => {
                                    warn!(
                                        "outdated Authorize frame, Ts: {}; api key: {}; connection {}",
                                        req.data.ts,
                                        api_key,
                                        state.borrow().describe()
                                    );
                                    unauthorized_close(&outbound_tx)
                                }
                                Ok(public_key) => {
                                    let connection_id = {
                                        let mut state = state.borrow_mut();
                                        state.auth = AuthState::Authorized;
                                        state.hb = Instant::now();
                                        state.public_key = Some(public_key);
                                        state.api_key = Some(api_key);
                                        state.connection_id
                                    };

                                    // now that identity is known, this connection becomes
                                    // targetable — register it in the gate's connections
                                    // registry (deregistered on shutdown, see ws_service)
                                    gate_state.connections.insert(
                                        connection_id,
                                        ConnectionEntry {
                                            outbound: outbound_tx.clone(),
                                        },
                                    );

                                    //@todo replace to Payload struct like in api gate
                                    let reply = serde_json::json!({ "Authorized": true }).to_string();

                                    // debug!("{:?}", state);
                                    Some(Message::Text(reply.into()))
                                }
                                Err(_) => unauthorized_close(&outbound_tx),
                            },
                            Err(_) => unauthorized_close(&outbound_tx),
                        }
                    }
                    AuthState::Authorized => {
                        // set together with AuthState::Authorized, so always present here
                        let (public_key, api_key) = {
                            let state = state.borrow();
                            (
                                state
                                    .public_key
                                    .clone()
                                    .expect("public_key set once Authorized"),
                                state.api_key,
                            )
                        };

                        match verify_signature(&public_key, &req.signature, req.data.raw_str()) {
                            // valid key, but an old (possibly replayed) or future-dated frame:
                            // refuse the frame, keep the connection
                            Ok(()) if skw_is_outdated(req.data.ts) => {
                                warn!(
                                    "outdated signed frame, Ts: {}; signature: {}",
                                    req.data.ts, req.signature
                                );
                                error_message(&req.signature, "request outdated", StatusCode::CONFLICT)
                            }
                            Ok(()) => {
                                // signature is verified and unforgeable, so it doubles as the correlation id
                                let signature = req.signature.clone();
                                dispatch_request(
                                    &gate_state,
                                    &outbound_tx,
                                    &pending,
                                    api_key,
                                    &signature,
                                    req,
                                )
                                .await
                            }
                            Err(_) => unauthorized_close(&outbound_tx),
                        }
                    }
                }
            }
            Err(err) => {
                warn!(
                    "invalid message from connection {}: {}",
                    state.borrow().describe(),
                    err
                );

                unauthorized_close(&outbound_tx)
            }
        },

        // close connection
        Frame::Close(reason) => Some(Message::Close(reason)),

        // ignore other frames
        _ => None,
    };

    Ok(item)
}

/// Resolves the target service from `req.uri`, registers a pending-request
/// entry keyed by `signature` (also sent to the service as the iggy
/// signature header), spawns a timeout watchdog, and publishes the request to
/// the resolved service topic. The reply reaches the client under
/// `req.signature`. Returns `None` immediately without waiting for a reply —
/// the frame-processing service stays free to handle the next frame
/// (heartbeats, other requests) on this connection while the reply is
/// delivered later, asynchronously, via the shared back-topic consumer loop
/// -> outbound channel -> heartbeat task -> sink.
async fn dispatch_request(
    gate_state: &WsGateState,
    outbound_tx: &UnboundedSender<WsOutbound>,
    pending: &Arc<AtomicUsize>,
    api_key: Option<Uuid>,
    signature: &str,
    req: WsRequest,
) -> Option<Message> {
    let uri = req.uri.clone().unwrap_or_default();
    let mut slug_split = uri.trim_matches('/').split("/");

    let slug1 = slug_split.next();
    let slug2 = slug_split.next();

    let topic_key = match (slug1, slug2) {
        (None, _) => {
            return error_message(
                &req.signature,
                "missing or empty uri",
                StatusCode::BAD_REQUEST,
            );
        }
        (Some(s1), None) => s1,
        (Some(s1), Some(s2)) => &format!("{s1}/{s2}"),
    };

    let Some(producer) = gate_state.routes_map.map.get(topic_key).cloned() else {
        return error_message(&req.signature, "unknown service", StatusCode::BAD_REQUEST);
    };

    // a signed request's signature is its key: a duplicate still in flight would overwrite the
    // first entry and run the request twice, so it is refused until the first one is answered
    match gate_state.pending_requests.entry(signature.to_string()) {
        Entry::Occupied(_) => {
            warn!("request already pending, signature: {}", signature);
            return error_message(
                &req.signature,
                "request already pending",
                StatusCode::CONFLICT,
            );
        }
        Entry::Vacant(slot) => {
            slot.insert(PendingRequestEntry {
                outbound: outbound_tx.clone(),
                reply_id: req.signature.clone(),
                uri: uri.clone(),
                ts_gate_published: Utc::now(),
                _slot: PendingSlot::new(pending),
            });
        }
    }

    // timeout watchdog: if the back-topic consumer loop never removes this
    // entry (no reply arrived in time), remove it ourselves and notify the
    // client — mirrors gates/api's 30s BACK_MESSAGE_TIMEOUT / 504 behavior
    let pending_requests = gate_state.pending_requests.clone();
    let signature_for_timeout = signature.to_string();

    tokio::spawn(async move {
        tokio::time::sleep(BACK_MESSAGE_TIMEOUT).await;
        if let Some((s, entry)) = pending_requests.remove(&signature_for_timeout) {
            warn!("timeout waiting for backend response signature: {}", s);
            let _ = entry.outbound.send(WsOutbound::Timeout {
                signature: entry.reply_id,
                uri: uri.clone(),
            });
        }
    });

    let uri = req.uri.unwrap_or_default();
    if let Err(e) = publish_to_service(
        producer,
        api_key.as_ref(),
        signature,
        &uri,
        req.data.raw_str().as_bytes(),
    )
    .await
    {
        error!("publish to service error: {}", e);
        gate_state.pending_requests.remove(signature);
        return error_message(
            &req.signature,
            "internal error",
            StatusCode::INTERNAL_SERVER_ERROR,
        );
    }

    None
}

/// `uri` targets a public/open topic (`/{service}/public|open`), which needs no authorization
fn is_unsigned_topic(uri: Option<&str>) -> bool {
    uri.and_then(|u| u.trim_matches('/').split('/').nth(1))
        .and_then(|t| t.parse::<SkwTopicType>().ok())
        .is_some_and(|t| matches!(t, SkwTopicType::Public | SkwTopicType::Open))
}

/// WebSockets service factory
pub(crate) async fn ws_service(
    sink: WsSink,
    gate_state: WsGateState,
    peer_addr: Option<SocketAddr>,
) -> Result<impl Service<Frame, Response = Option<Message>, Error = AppError>, web::Error> {
    let connection_id = Uuid::now_v7();

    let state = Rc::new(RefCell::new(WsState {
        hb: Instant::now(),
        auth: AuthState::Pending,
        public_key: None,
        api_key: None,
        connection_id,
        pending: Arc::new(AtomicUsize::new(0)),
        peer_addr,
    }));
    debug!("ws connection {} opened", state.borrow().describe());

    // outbound channel: the only Send-safe handle to this connection reachable
    // from other tasks (WsSink itself is !Send, thread-affine to this
    // connection's worker thread — see heartbeat below, the sole owner of `sink`)
    let (outbound_tx, outbound_rx) = tokio::sync::mpsc::unbounded_channel::<WsOutbound>();

    // disconnect notification
    let (tx, rx) = oneshot::channel();

    // start heartbeat + outbound-delivery task
    rt::spawn(heartbeat(state.clone(), sink, rx, outbound_rx));

    // handler service for incoming websockets frames; at most CFG_MAX_INFLIGHT_FRAMES at once,
    // so one client's burst can't hold this worker (and its other connections) for long
    let gate_state_frames = gate_state.clone();
    let service = InFlightService::new(
        *CFG_MAX_INFLIGHT_FRAMES,
        fn_service(move |frame| {
            handle_frame(
                state.clone(),
                gate_state_frames.clone(),
                outbound_tx.clone(),
                frame,
            )
        }),
    );

    // handler service for shutdown notification: stops the heartbeat task and
    // deregisters this connection from the gate's connections registry
    let on_shutdown = fn_shutdown(async move || {
        gate_state.connections.remove(&connection_id);
        let _ = tx.send(());
    });

    // pipe our service with on_shutdown callback
    Ok(chain(service).and_then(on_shutdown))
}

/// sends ping to client every heartbeat interval, and is the sole task
/// allowed to call `sink.send(...)` for this connection — both for
/// heartbeat pings and for backend-originated replies/pushes/timeouts
/// arriving on `outbound_rx` from the shared back-topic consumer loop or a
/// request's timeout watchdog (both of which run on the tokio (`Send`)
/// runtime and cannot touch `WsSink` directly, since it wraps an `Rc` and is
/// `!Send`/`!Sync`, thread-affine to this connection's worker thread).
pub(crate) async fn heartbeat(
    state: Rc<RefCell<WsState>>,
    sink: WsSink,
    mut rx: oneshot::Receiver<()>,
    mut outbound_rx: tokio::sync::mpsc::UnboundedReceiver<WsOutbound>,
) {
    // one interval for the whole connection: a `sleep` created per loop pass would be
    // restarted by every outbound message, so a busy connection never got pinged and was
    // dropped as silent once its replies stopped
    let ping = time::interval(*CFG_HEARTBEAT_INTERVAL);
    loop {
        tokio::select! {
            _ = ping.tick() => {
                // check client heartbeats
                if Instant::now().duration_since(state.borrow().hb) > *CFG_CLIENT_TIMEOUT {
                    // heartbeat timed out
                    warn!("ws client {} silent for {:?}, disconnecting", state.borrow().describe(), *CFG_CLIENT_TIMEOUT);
                    sink.io().terminate();
                    return;
                }

                // send ping
                debug!("ws ping -> connection {}", state.borrow().connection_id);
                if sink.send(Message::Ping(Bytes::default())).await.is_err() {
                    warn!("ws ping to {} failed, disconnecting", state.borrow().describe());
                    sink.io().terminate();
                    return;
                }
            }
            _ = &mut rx => {
                debug!("ws connection {} closed, stop heartbeat task", state.borrow().describe());
                sink.io().close();
                return;
            }
            // once all senders are dropped `recv()` yields `None` at once on every poll; a failed
            // pattern disables this branch instead of spinning, teardown is up to the other branches
            Some(msg) = outbound_rx.recv() => {
                let close = matches!(msg, WsOutbound::Close(_));
                if sink.send(build_ws_message(msg)).await.is_err() {
                    sink.io().terminate();
                    return;
                }
                // after our own Close, close the socket ourselves (flushing the Close first):
                // nothing else would if the client never echoes it
                if close {
                    sink.io().close();
                    return;
                }
            }
        }
    }
}

fn build_ws_message(outbound: WsOutbound) -> Message {
    let json = match outbound {
        WsOutbound::Close(reason) => return Message::Close(Some(reason)),
        WsOutbound::Reply {
            signature,
            payload,
            service_error,
            service_status,
        } => {
            let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap_or(serde_json::Value::Null);
            // HTTP status the api gate answers with: error code, 201/202 for a provisional reply
            // (request taken, its result comes later), else 200
            let status = service_error
                .as_ref()
                .map(|e| e.status_code())
                .or(service_status.map(|s| s.status_code()))
                .unwrap_or(StatusCode::OK);

            serde_json::json!({
                "Signature": signature,
                "Status": status.as_u16(),
                "ErrorMsg": service_error.as_ref().map(|e| e.to_string()),
                "ErrCode": service_error.map(|e| e.status_code().as_u16()),
                "Payload": payload,
            })
        }
        WsOutbound::Push { payload } => {
            let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap_or(serde_json::Value::Null);
            serde_json::json!({ "Push": true, "Payload": payload })
        }
        WsOutbound::Timeout { signature, uri } => {
            serde_json::json!({
                "Signature": signature,
                "ErrorMsg": "Timeout",
                "ErrCode": StatusCode::GATEWAY_TIMEOUT.as_u16(),
                "Uri": uri,
            })
        }
    };
    Message::Text(json.to_string().into())
}

/// do websocket handshake and start web sockets service
pub(crate) async fn ws_index(req: web::HttpRequest, state: web::types::State<WsGateState>) -> Result<web::HttpResponse, web::Error> {
    let gate_state = state.get_ref().clone();
    let peer_addr = req.peer_addr();
    start(
        req,
        None::<String>,
        fn_factory_with_config(move |sink| {
            let gate_state = gate_state.clone();
            async move { ws_service(sink, gate_state, peer_addr).await }
        }),
    )
    .await
}

// connection is not authorized until the client's first message
// successfully authorizes it; a bad/failed attempt closes the connection.
pub(crate) fn unauthorized_close(outbound_tx: &UnboundedSender<WsOutbound>) -> Option<Message> {
    close_connection(outbound_tx, "Unauthorized") // @todo move to some Payload struct
}

/// Closes the connection with policy code 1008 and `reason`. Goes through the heartbeat task,
/// which sends the Close frame and then closes the socket: returning the Close as this frame's
/// response would only write it, leaving the socket open for a client that never echoes it.
pub(crate) fn close_connection(outbound_tx: &UnboundedSender<WsOutbound>, reason: &str) -> Option<Message> {
    let _ = outbound_tx.send(WsOutbound::Close(CloseReason {
        code: CloseCode::Policy,
        description: Some(reason.into()),
    }));
    None
}

// non-terminal error reply for a signed-but-unroutable/unpublishable
// request; the connection stays open for further requests.
// `code` mirrors the HTTP status gates/api answers in the same situation.
fn error_message(signature: &str, reason: &str, code: StatusCode) -> Option<Message> {
    Some(Message::Text(
        serde_json::json!({ "Signature": signature, "ErrorMsg": reason, "ErrCode": code.as_u16() })
            .to_string()
            .into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use skw_lib_shared::prelude::jsonrpc::{SkwServiceHttpError, SkwServiceStatus};

    /// the Close goes through the heartbeat task (which then closes the socket), not as the
    /// frame's response
    #[test]
    fn close_connection_queues_policy_close() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        assert!(close_connection(&tx, "Too many pending requests").is_none());

        let Ok(WsOutbound::Close(reason)) = rx.try_recv() else {
            panic!("no Close queued");
        };
        assert_eq!(reason.code, CloseCode::Policy);
        assert_eq!(
            reason.description.as_deref(),
            Some("Too many pending requests")
        );
        assert!(matches!(
            build_ws_message(WsOutbound::Close(reason)),
            Message::Close(Some(_))
        ));
    }

    #[test]
    fn unsigned_topics() {
        assert!(is_unsigned_topic(Some("/ping/open")));
        assert!(is_unsigned_topic(Some("ping/public/")));
        assert!(is_unsigned_topic(Some("/ping/OPEN"))); // SkwTopicType parses case-insensitively
        assert!(!is_unsigned_topic(Some("/ping/signed")));
        assert!(!is_unsigned_topic(Some("/ping")));
        assert!(!is_unsigned_topic(Some("/ping/bogus")));
        assert!(!is_unsigned_topic(Some("")));
        assert!(!is_unsigned_topic(None));
    }

    fn reply_json(outbound: WsOutbound) -> serde_json::Value {
        let Message::Text(text) = build_ws_message(outbound) else {
            panic!("expected a text frame");
        };
        serde_json::from_str(&text).unwrap()
    }

    fn reply(service_error: Option<SkwServiceHttpError>, service_status: Option<SkwServiceStatus>) -> serde_json::Value {
        reply_json(WsOutbound::Reply {
            signature: "sig".into(),
            payload: br#"{"Ping":{"Count":1}}"#.to_vec(),
            service_error,
            service_status,
        })
    }

    #[test]
    fn final_reply_is_200() {
        let r = reply(None, None);
        assert_eq!(r["Signature"], "sig");
        assert_eq!(r["Status"], 200);
        assert!(r["ErrCode"].is_null());
        assert_eq!(r["Payload"]["Ping"]["Count"], 1);
    }

    #[test]
    fn provisional_replies_are_201_202() {
        assert_eq!(reply(None, Some(SkwServiceStatus::Created))["Status"], 201);
        assert_eq!(reply(None, Some(SkwServiceStatus::Accepted))["Status"], 202);
        assert!(reply(None, Some(SkwServiceStatus::Accepted))["ErrCode"].is_null());
    }

    #[test]
    fn error_reply_carries_err_code() {
        let r = reply(Some(SkwServiceHttpError::NotFound), None);
        assert_eq!(r["Status"], 404);
        assert_eq!(r["ErrCode"], 404);
        assert_eq!(r["ErrorMsg"], "NotFound");
    }

    #[test]
    fn invalid_payload_becomes_null() {
        let r = reply_json(WsOutbound::Reply {
            signature: "sig".into(),
            payload: b"not json".to_vec(),
            service_error: None,
            service_status: None,
        });
        assert!(r["Payload"].is_null());
    }

    #[test]
    fn timeout_is_504() {
        let r = reply_json(WsOutbound::Timeout {
            signature: "sig".into(),
            uri: "/ping/signed".into(),
        });
        assert_eq!(r["Signature"], "sig");
        assert_eq!(r["ErrCode"], 504);
        assert_eq!(r["ErrorMsg"], "Timeout");
    }
}
