use std::{
    cell::{Cell, RefCell},
    net::SocketAddr,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicI64, AtomicUsize, Ordering},
    },
    time::Instant,
};

use dashmap::mapref::entry::Entry;

use ntex::{
    channel::oneshot,
    fn_service, rt,
    service::{self as svc, Service},
    time,
    util::{Bytes, inflight::InFlightService},
    web,
    web::ws::start,
    ws::CloseCode,
    ws::CloseReason,
    ws::Message,
    ws::{Frame, WsSink},
};

use tokio::sync::mpsc::UnboundedSender;

use crate::cfg::{CFG_CLIENT_TIMEOUT, CFG_HEARTBEAT_INTERVAL, CFG_MAX_INFLIGHT_FRAMES, CFG_MAX_PENDING_REQUESTS, CFG_MAX_SESSIONS_PER_TOKEN};
use crate::crypto::{check_authorize, verify_signature};
use crate::gate::{ConnectionEntry, PendingRequestEntry, PendingSlot, WsGateState, WsOutbound, publish_to_service};
use crate::structs::{AuthState, WsMethod, WsRequest, WsState};
use skw_lib_shared::{
    AppError,
    prelude::{
        axum::StatusCode,
        chrono::Utc,
        consts::BACK_MESSAGE_TIMEOUT,
        iggy::SkwTopicType,
        jsonrpc::SkwServiceHttpError,
        log::*,
        serde::{RawValue, Serialize},
        tools::{skw_is_outdated, skw_random_signature},
        uuid::Uuid,
    },
};

/// Marks the client alive and passes `parsed` through: any client text frame proves it is
/// alive, since browsers can't send pings and their pongs only answer ours.
fn refresh_hb<T>(state: &RefCell<WsState>, parsed: T) -> T {
    state.borrow_mut().hb = Instant::now();
    parsed
}

/// One connection's context, shared by `Rc` between its frame service, heartbeat task and
/// shutdown hook. A frame clones this one non-atomic `Rc` instead of the gate state's `Arc`s
/// (refcounts written by every connection on every worker), the outbound sender and the
/// pending counter.
pub(crate) struct Connection {
    pub state: RefCell<WsState>,
    pub gate: WsGateState,
    pub outbound_tx: UnboundedSender<WsOutbound>,
    /// requests of this connection waiting for their reply (see `gate::PendingSlot`);
    /// outside `state`, so a frame can use it across `.await` without a `RefCell` borrow
    pub pending: Arc<AtomicUsize>,
}

/// handler for a single incoming websocket frame
pub(crate) async fn handle_frame(conn: Rc<Connection>, frame: Frame) -> Result<Option<Message>, AppError> {
    // borrowed from the connection for the whole frame: nothing cloned
    let Connection {
        state,
        gate: gate_state,
        outbound_tx,
        pending,
    } = &*conn;
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
        Frame::Text(text) => match refresh_hb(state, serde_json::from_slice::<WsRequest>(&text)) {
            Ok(req) => {
                // checked before the signature check: a client over the limit costs no more work.
                // Check and count (in `dispatch_request`) run before the first `.await`, and a
                // connection's frames share one worker thread, so the limit can't be overshot
                if pending.load(Ordering::Relaxed) >= *CFG_MAX_PENDING_REQUESTS {
                    warn!(
                        "connection {} has {} pending requests, closing",
                        state.borrow().describe(),
                        *CFG_MAX_PENDING_REQUESTS
                    );
                    return Ok(close_connection(outbound_tx, "Too many pending requests"));
                }

                // public/open topics need neither authorization nor a valid signature (like
                // gates/api); `Signature` is then only the client's request id, echoed in the reply
                if is_unsigned_topic(req.uri.as_deref()) {
                    return Ok(dispatch_request(gate_state, outbound_tx, pending, None, req).await);
                }

                let auth = state.borrow().auth;

                match auth {
                    AuthState::Authorizing => unauthorized_close(outbound_tx),

                    AuthState::Pending => {
                        // claim the single authorization attempt synchronously,
                        // before the `.await` below gives another frame a chance
                        // to be dispatched concurrently.
                        state.borrow_mut().auth = AuthState::Authorizing;

                        match serde_json::from_str::<WsMethod>(req.data.raw_str()) {
                            Ok(WsMethod::Authorize { api_key }) => match check_authorize(api_key, &req.signature, req.data.raw_str()).await {
                                // an old Authorize frame must not open a session: it fails like bad credentials
                                Ok(_) if skw_is_outdated(req.data.ts) => {
                                    warn!(
                                        "outdated Authorize frame, Ts: {}; api key: {}; connection {}",
                                        req.data.ts,
                                        api_key,
                                        state.borrow().describe()
                                    );
                                    unauthorized_close(outbound_tx)
                                }
                                Ok(public_key) => {
                                    // counted only for valid credentials, so unknown keys can't use up a key's sessions
                                    let Some(session) = gate_state
                                        .sessions
                                        .try_acquire(api_key, *CFG_MAX_SESSIONS_PER_TOKEN)
                                    else {
                                        warn!(
                                            "api key {} already has {} sessions, refusing connection {}",
                                            api_key,
                                            *CFG_MAX_SESSIONS_PER_TOKEN,
                                            state.borrow().describe()
                                        );
                                        return Ok(too_many_sessions_close(outbound_tx, &req.signature));
                                    };

                                    let connection_id = {
                                        let mut state = state.borrow_mut();
                                        state.auth = AuthState::Authorized;
                                        state.hb = Instant::now();
                                        state.public_key = Some(public_key);
                                        state.api_key = Some(api_key);
                                        state.session = Some(session);
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
                                    Some(Message::Text(r#"{"Authorized":true}"#.into()))
                                }
                                Err(_) => unauthorized_close(outbound_tx),
                            },
                            Err(_) => unauthorized_close(outbound_tx),
                        }
                    }
                    AuthState::Authorized => {
                        // set together with AuthState::Authorized; refuse rather than panic if that ever breaks
                        let (Some(public_key), Some(api_key)) = ({
                            let state = state.borrow();
                            (state.public_key, state.api_key)
                        }) else {
                            return Ok(unauthorized_close(outbound_tx));
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
                            Ok(()) => dispatch_request(gate_state, outbound_tx, pending, Some(api_key), req).await,
                            Err(_) => unauthorized_close(outbound_tx),
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

                unauthorized_close(outbound_tx)
            }
        },

        // close connection
        Frame::Close(reason) => Some(Message::Close(reason)),

        // ignore other frames
        _ => None,
    };

    Ok(item)
}

/// Resolves the target service from `req.uri`, registers a pending-request entry, spawns a
/// timeout watchdog, and publishes the request to the resolved service topic. The entry's key
/// (also sent to the service as the iggy signature header) is the request's verified signature
/// for a signed request (`api_key` is `Some`: unforgeable, so it doubles as the correlation id)
/// and a gate-minted id for an unsigned one, whose `Signature` is only the client's request id.
/// The reply reaches the client under `req.signature`. Returns `None` immediately without waiting for a reply —
/// the frame-processing service stays free to handle the next frame
/// (heartbeats, other requests) on this connection while the reply is
/// delivered later, asynchronously, via the shared back-topic consumer loop
/// -> outbound channel -> heartbeat task -> sink.
async fn dispatch_request(
    gate_state: &WsGateState,
    outbound_tx: &UnboundedSender<WsOutbound>,
    pending: &Arc<AtomicUsize>,
    api_key: Option<Uuid>,
    req: WsRequest,
) -> Option<Message> {
    let WsRequest {
        signature,
        uri,
        data,
    } = req;
    // shared by the registry key, the watchdog and every reply: one copy of the id
    let reply_id: Arc<str> = signature.into();
    let key: Arc<str> = match api_key {
        Some(_) => reply_id.clone(),
        None => skw_random_signature().into(),
    };
    // copied once, into the entry
    let uri = uri.unwrap_or_default();

    let Some(topic_key) = route_key(&uri) else {
        return error_message(&reply_id, "missing or empty uri", StatusCode::BAD_REQUEST);
    };

    let Some(producer) = gate_state.routes_map.map.get(topic_key).cloned() else {
        return error_message(&reply_id, "unknown service", StatusCode::BAD_REQUEST);
    };

    // a signed request's signature is its key: a duplicate still in flight would overwrite the
    // first entry and run the request twice, so it is refused until the first one is answered
    match gate_state.pending_requests.entry(key.clone()) {
        Entry::Occupied(_) => {
            warn!("request already pending, signature: {}", key);
            return error_message(&reply_id, "request already pending", StatusCode::CONFLICT);
        }
        Entry::Vacant(slot) => {
            slot.insert(PendingRequestEntry {
                outbound: outbound_tx.clone(),
                reply_id: reply_id.clone(),
                uri: uri.clone(),
                ts_gate_published: Utc::now(),
                deadline_ms: AtomicI64::new(Utc::now().timestamp_millis() + BACK_MESSAGE_TIMEOUT.as_millis() as i64),
                _slot: PendingSlot::new(pending),
            });
        }
    }

    // timeout watchdog: if the back-topic consumer loop never removes this
    // entry (no reply arrived in time), remove it ourselves and notify the
    // client — mirrors gates/api's 30s BACK_MESSAGE_TIMEOUT / 504 behavior
    let pending_requests = gate_state.pending_requests.clone();
    let watched = key.clone();

    // (a provisional reply moves the deadline, so the watchdog sleeps again until the new one)
    tokio::spawn(async move {
        loop {
            // the map guard must not be held across the sleep
            let wait_ms = match pending_requests.get(&*watched) {
                Some(entry) => entry.deadline_ms() - Utc::now().timestamp_millis(),
                None => return,
            };
            if wait_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(wait_ms as u64)).await;
                continue;
            }
            match pending_requests.remove_if(&*watched, |_, e| {
                e.deadline_ms() <= Utc::now().timestamp_millis()
            }) {
                Some((s, entry)) => {
                    warn!("timeout waiting for backend response signature: {}", s);
                    let _ = entry.outbound.send(WsOutbound::Timeout {
                        signature: entry.reply_id,
                        uri: entry.uri,
                    });
                    return;
                }
                // gone (answered) or extended meanwhile: the next round finds out which
                None => continue,
            }
        }
    });

    if let Err(e) = publish_to_service(
        producer,
        api_key.as_ref(),
        &key,
        &uri,
        data.into_raw_string(),
    )
    .await
    {
        error!("publish to service error: {}", e);
        gate_state.pending_requests.remove(&*key);
        return error_message(
            &reply_id,
            "internal error",
            StatusCode::INTERNAL_SERVER_ERROR,
        );
    }

    None
}

/// The `RoutesMap` key of `uri`: its first two path segments, as a slice of the uri itself
/// (`"/ping/signed/x"` -> `"ping/signed"`), so the lookup allocates nothing. `None` for an empty uri.
fn route_key(uri: &str) -> Option<&str> {
    let trimmed = uri.trim_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    Some(match trimmed.match_indices('/').nth(1) {
        Some((end, _)) => &trimmed[..end],
        None => trimmed,
    })
}

/// `uri` targets a public/open topic (`/{service}/public|open`), which needs no authorization
fn is_unsigned_topic(uri: Option<&str>) -> bool {
    uri.and_then(|u| u.trim_matches('/').split('/').nth(1))
        .and_then(|t| t.parse::<SkwTopicType>().ok())
        .is_some_and(|t| matches!(t, SkwTopicType::Public | SkwTopicType::Open))
}

/// the ws gate's web application state: shared by every worker (`web::server_with_config`)
impl web::State for WsGateState {
    type Error = web::DefaultError;
}

/// One connection's frame service. ntex 4 runs it with the connection's `WsSink` as pipeline
/// state, so the heartbeat task (which owns writing to the sink) starts on the dispatcher's
/// first readiness check, which ntex makes before decoding any frame.
pub(crate) fn ws_service(
    gate_state: WsGateState,
    peer_addr: Option<SocketAddr>,
) -> impl Service<WsSink, Frame, Res = Option<Message>, Error = AppError> {
    let connection_id = Uuid::now_v7();

    // outbound channel: the only Send-safe handle to this connection reachable
    // from other tasks (WsSink itself is !Send, thread-affine to this
    // connection's worker thread — see heartbeat below, the sole owner of `sink`)
    let (outbound_tx, outbound_rx) = tokio::sync::mpsc::unbounded_channel::<WsOutbound>();

    let conn = Rc::new(Connection {
        state: RefCell::new(WsState {
            hb: Instant::now(),
            auth: AuthState::Pending,
            public_key: None,
            api_key: None,
            connection_id,
            peer_addr,
            session: None,
        }),
        gate: gate_state,
        outbound_tx,
        pending: Arc::new(AtomicUsize::new(0)),
    });
    debug!("ws connection {} opened", conn.state.borrow().describe());

    // disconnect notification
    let (tx, rx) = oneshot::channel();

    // heartbeat + outbound-delivery task, started once the sink is known (see `readiness` below)
    let heartbeat_start = Rc::new(Cell::new(Some((rx, outbound_rx))));
    let conn_ready = conn.clone();

    // handler service for incoming websockets frames; at most CFG_MAX_INFLIGHT_FRAMES at once,
    // so one client's burst can't hold this worker (and its other connections) for long
    let conn_frames = conn.clone();
    let service = InFlightService::new(
        *CFG_MAX_INFLIGHT_FRAMES,
        // one non-atomic `Rc` clone per frame
        fn_service(move |frame| handle_frame(conn_frames.clone(), frame)),
    );

    svc::service(service)
        // the dispatcher checks readiness before decoding the first frame: the sink is the
        // pipeline state, so this starts the heartbeat for silent clients too. Readiness may be
        // checked again later; the task is started only once.
        .readiness(async move |sink: &WsSink| {
            if let Some((rx, outbound_rx)) = heartbeat_start.take() {
                rt::spawn(heartbeat(conn_ready.clone(), sink.clone(), rx, outbound_rx));
            }
            Ok(())
        })
        // shutdown: stops the heartbeat task, deregisters this connection from the gate's
        // connections registry and frees its API key's session
        .shutdown(async move |_: &WsSink| {
            conn.gate.connections.remove(&connection_id);
            conn.state.borrow_mut().session.take();
            let _ = tx.send(());
        })
}

/// sends ping to client every heartbeat interval, and is the sole task
/// allowed to call `sink.send(...)` for this connection — both for
/// heartbeat pings and for backend-originated replies/pushes/timeouts
/// arriving on `outbound_rx` from the shared back-topic consumer loop or a
/// request's timeout watchdog (both of which run on the tokio (`Send`)
/// runtime and cannot touch `WsSink` directly, since it wraps an `Rc` and is
/// `!Send`/`!Sync`, thread-affine to this connection's worker thread).
pub(crate) async fn heartbeat(
    conn: Rc<Connection>,
    sink: WsSink,
    mut rx: oneshot::Receiver<()>,
    mut outbound_rx: tokio::sync::mpsc::UnboundedReceiver<WsOutbound>,
) {
    let state = &conn.state;
    // one interval for the whole connection: a `sleep` created per loop pass would be
    // restarted by every outbound message, so a busy connection never got pinged and was
    // dropped as silent once its replies stopped
    let ping = time::interval(*CFG_HEARTBEAT_INTERVAL);
    // the first tick is immediate: take it here, so the first ping goes out one interval
    // after the handshake instead of being the first frame the client gets
    ping.tick().await;
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
            // `conn` holds a sender, so `recv()` doesn't yield `None` while this task runs; if it
            // ever did, the failed pattern disables this branch instead of spinning, and teardown
            // stays with the other branches (shutdown oneshot, client timeout, send failures)
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

/// A reply to a request. `None` fields are written as `null`, like the former `json!` frames.
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct ReplyFrame<'a> {
    signature: &'a str,
    status: u16,
    /// unit variants serialize as their name: the same text as `Display` ("NotFound", ...)
    error_msg: Option<&'a SkwServiceHttpError>,
    err_code: Option<u16>,
    /// the service's JSON, passed through verbatim; invalid JSON becomes `null`
    payload: Option<&'a RawValue>,
}

/// The gate's own error reply to a frame (`Uri` only on timeouts).
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct ErrorFrame<'a> {
    signature: &'a str,
    error_msg: &'a str,
    err_code: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    uri: Option<&'a str>,
}

/// An unsolicited push to a connection.
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct PushFrame<'a> {
    push: bool,
    payload: Option<&'a RawValue>,
}

/// `payload` as a borrowed JSON value; `None` (written as `null`) if it isn't valid JSON
fn raw_json(payload: &[u8]) -> Option<&RawValue> {
    serde_json::from_slice(payload).ok()
}

/// One text frame, written into a single buffer sized for the payload.
fn text_frame<T: Serialize>(frame: &T, payload_len: usize) -> Message {
    let mut buf = Vec::with_capacity(payload_len + 160);
    if let Err(e) = serde_json::to_writer(&mut buf, frame) {
        // can't happen: string keys only, no fallible Serialize impls
        error!("serializing ws frame: {}", e);
    }
    // serde_json writes UTF-8 only, so this never falls back
    Message::Text(String::from_utf8(buf).unwrap_or_default().into())
}

fn build_ws_message(outbound: WsOutbound) -> Message {
    match outbound {
        WsOutbound::Close(reason) => Message::Close(Some(reason)),
        WsOutbound::Error {
            signature,
            reason,
            code,
        } => text_frame(
            &ErrorFrame {
                signature: &signature,
                error_msg: reason,
                err_code: code.as_u16(),
                uri: None,
            },
            0,
        ),
        WsOutbound::Reply {
            signature,
            payload,
            service_error,
            service_status,
        } => {
            // HTTP status the api gate answers with: error code, 201/202 for a provisional reply
            // (request taken, its result comes later), else 200
            let status = service_error
                .as_ref()
                .map(|e| e.status_code())
                .or(service_status.map(|s| s.status_code()))
                .unwrap_or(StatusCode::OK);

            text_frame(
                &ReplyFrame {
                    signature: &signature,
                    status: status.as_u16(),
                    error_msg: service_error.as_ref(),
                    err_code: service_error.as_ref().map(|e| e.status_code().as_u16()),
                    payload: raw_json(&payload),
                },
                payload.len(),
            )
        }
        WsOutbound::Push { payload } => text_frame(
            &PushFrame {
                push: true,
                payload: raw_json(&payload),
            },
            payload.len(),
        ),
        WsOutbound::Timeout { signature, uri } => text_frame(
            &ErrorFrame {
                signature: &signature,
                error_msg: "Timeout",
                err_code: StatusCode::GATEWAY_TIMEOUT.as_u16(),
                uri: Some(&uri),
            },
            0,
        ),
    }
}

/// Does the websocket handshake and serves the connection until it ends (ntex 4 `start` runs
/// the whole connection). A failed handshake is answered by `start` itself; after a handshake
/// the socket belongs to the ws dispatcher, so the response returned here is never sent.
pub(crate) async fn ws_index(gate_state: &WsGateState, _: (), req: web::HttpRequest) -> web::HttpResponse {
    let peer_addr = req.peer_addr();
    if let Err(e) = start(&req, None, ws_service(gate_state.clone(), peer_addr)).await {
        debug!(
            "ws connection from {:?} ended with error: {:?}",
            peer_addr, e
        );
    }
    web::HttpResponse::Ok().build()
}

// connection is not authorized until the client's first message
// successfully authorizes it; a bad/failed attempt closes the connection.
pub(crate) fn unauthorized_close(outbound_tx: &UnboundedSender<WsOutbound>) -> Option<Message> {
    close_connection(outbound_tx, "Unauthorized") // @todo move to some Payload struct
}

/// Refuses an `Authorize` whose API key already holds `/service/maxSessionsPerToken` sessions:
/// a 403 error reply to the frame, then Close 1008. Both go through the heartbeat task, so the
/// reply is written before the Close.
fn too_many_sessions_close(outbound_tx: &UnboundedSender<WsOutbound>, signature: &str) -> Option<Message> {
    const REASON: &str = "Too many sessions";
    let _ = outbound_tx.send(WsOutbound::Error {
        signature: signature.into(),
        reason: REASON,
        code: StatusCode::FORBIDDEN,
    });
    close_connection(outbound_tx, REASON)
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
    Some(text_frame(
        &ErrorFrame {
            signature,
            error_msg: reason,
            err_code: code.as_u16(),
            uri: None,
        },
        0,
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

    #[test]
    fn route_keys() {
        assert_eq!(route_key("/ping/signed"), Some("ping/signed"));
        assert_eq!(route_key("ping/signed/extra"), Some("ping/signed"));
        assert_eq!(route_key("/ping"), Some("ping"));
        assert_eq!(route_key("ping//x"), Some("ping/"));
        assert_eq!(route_key(""), None);
        assert_eq!(route_key("///"), None);
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
            payload: br#"{"Ping":{"Count":1}}"#.as_slice().into(),
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
            payload: b"not json".as_slice().into(),
            service_error: None,
            service_status: None,
        });
        assert!(r["Payload"].is_null());
    }

    fn frame_text(message: Message) -> String {
        let Message::Text(text) = message else {
            panic!("expected a text frame");
        };
        text.to_string()
    }

    /// the service's JSON goes out byte for byte (not re-serialized through a `Value`)
    #[test]
    fn reply_payload_is_passed_through_verbatim() {
        let payload = r#"{ "Big": 123456789012345678901234567890, "F": 1.10 }"#;
        let text = frame_text(build_ws_message(WsOutbound::Reply {
            signature: "sig".into(),
            payload: payload.as_bytes().into(),
            service_error: None,
            service_status: None,
        }));
        assert!(text.contains(payload), "{text}");
    }

    #[test]
    fn push_frame() {
        let r: serde_json::Value = serde_json::from_str(&frame_text(build_ws_message(WsOutbound::Push {
            payload: br#"{"A":1}"#.as_slice().into(),
        })))
        .unwrap();
        assert_eq!(
            r,
            serde_json::json!({ "Push": true, "Payload": { "A": 1 } })
        );
    }

    /// same keys as the former `json!` frames: `Uri` only on timeouts, `null`s kept on replies
    #[test]
    fn frame_keys() {
        let keys = |m: Message| {
            let v: serde_json::Value = serde_json::from_str(&frame_text(m)).unwrap();
            let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
            k.sort();
            k
        };
        assert_eq!(
            keys(error_message("sig", "unknown service", StatusCode::BAD_REQUEST).unwrap()),
            ["ErrCode", "ErrorMsg", "Signature"]
        );
        assert_eq!(
            keys(build_ws_message(WsOutbound::Error {
                signature: "sig".into(),
                reason: "Too many sessions",
                code: StatusCode::FORBIDDEN,
            })),
            ["ErrCode", "ErrorMsg", "Signature"]
        );
        assert_eq!(
            keys(build_ws_message(WsOutbound::Timeout {
                signature: "sig".into(),
                uri: "/ping/signed".into(),
            })),
            ["ErrCode", "ErrorMsg", "Signature", "Uri"]
        );
        assert_eq!(
            keys(build_ws_message(WsOutbound::Reply {
                signature: "sig".into(),
                payload: b"{}".as_slice().into(),
                service_error: None,
                service_status: None,
            })),
            ["ErrCode", "ErrorMsg", "Payload", "Signature", "Status"]
        );
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
