use std::{cell::RefCell, rc::Rc, time::Instant};

use ntex::service::{Service, fn_factory_with_config, fn_shutdown};
use ntex::util::Bytes;
use ntex::web;
use ntex::{chain, fn_service};
use ntex::{channel::oneshot, rt, time};

use skw_lib_shared::AppError;
use tokio::sync::mpsc::UnboundedSender;

use crate::cfg::{CFG_CLIENT_TIMEOUT, CFG_HEARTBEAT_INTERVAL};
use crate::crypto::{check_authorize, verify_signature};
use crate::gate::{ConnectionEntry, PendingRequestEntry, WsGateState, WsOutbound, publish_to_service};
use crate::structs::{AuthState, WsMethod, WsRequest, WsState};
use skw_lib_shared::prelude::{
    axum::StatusCode, chrono::Utc, consts::BACK_MESSAGE_TIMEOUT, iggy::SkwTopicType, log::*, tools::skw_random_signature, uuid::Uuid,
};

/// handler for a single incoming websocket frame
pub(crate) async fn handle_frame(
    state: Rc<RefCell<WsState>>,
    gate_state: WsGateState,
    outbound_tx: UnboundedSender<WsOutbound>,
    frame: web::ws::Frame,
) -> Result<Option<web::ws::Message>, AppError> {
    let item = match frame {
        // update heartbeat: any responsive client stays connected, authorized or not,
        // since public/open requests need no authorization
        web::ws::Frame::Ping(msg) => {
            state.borrow_mut().hb = Instant::now();
            Some(web::ws::Message::Pong(msg))
        }

        web::ws::Frame::Pong(_) => {
            state.borrow_mut().hb = Instant::now();
            None
        }

        // validate the frame is valid UTF-8 *and* deserializes into our expected shape
        web::ws::Frame::Text(text) => match serde_json::from_slice::<WsRequest>(&text) {
            Ok(req) => {
                // public/open topics need neither authorization nor a valid signature (like
                // gates/api); `Signature` is then only the client's request id, echoed in the reply
                if is_unsigned_topic(req.uri.as_deref()) {
                    let correlation_id = skw_random_signature();
                    return Ok(dispatch_request(&gate_state, &outbound_tx, None, correlation_id, req).await);
                }

                let auth = state.borrow().auth;

                match auth {
                    AuthState::Authorizing => unauthorized_close(),

                    AuthState::Pending => {
                        // claim the single authorization attempt synchronously,
                        // before the `.await` below gives another frame a chance
                        // to be dispatched concurrently.
                        state.borrow_mut().auth = AuthState::Authorizing;

                        match serde_json::from_value::<WsMethod>(req.data.method.clone()) {
                            Ok(WsMethod::Authorize { api_key }) => match check_authorize(api_key, &req.signature, req.data.raw_str()).await {
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
                                    Some(web::ws::Message::Text(reply.into()))
                                }
                                Err(_) => unauthorized_close(),
                            },
                            Err(_) => unauthorized_close(),
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
                            Ok(()) => {
                                // signature is verified and unforgeable, so it doubles as the correlation id
                                let correlation_id = req.signature.clone();
                                dispatch_request(&gate_state, &outbound_tx, api_key, correlation_id, req).await
                            }
                            Err(_) => unauthorized_close(),
                        }
                    }
                }
            }
            Err(err) => {
                warn!("invalid message received. error: {}", err);
                // let reply = serde_json::json!({ "error": err.to_string() }).to_string();
                // Some(web::ws::Message::Text(reply.into()));
                unauthorized_close()
            }
        },

        // close connection
        web::ws::Frame::Close(reason) => Some(web::ws::Message::Close(reason)),

        // skip binary messages
        // web::ws::Frame::Binary(bin) => Some(web::ws::Message::Binary(bin)),

        // ignore other frames
        _ => None,
    };

    Ok(item)
}

/// Resolves the target service from `req.uri`, registers a pending-request
/// entry keyed by `correlation_id` (also sent to the service as the iggy
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
    api_key: Option<Uuid>,
    correlation_id: String,
    req: WsRequest,
) -> Option<web::ws::Message> {
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

    gate_state.pending_requests.insert(
        correlation_id.clone(),
        PendingRequestEntry {
            outbound: outbound_tx.clone(),
            reply_id: req.signature.clone(),
            uri: uri.clone(),
            ts_gate_published: Utc::now(),
        },
    );

    // timeout watchdog: if the back-topic consumer loop never removes this
    // entry (no reply arrived in time), remove it ourselves and notify the
    // client — mirrors gates/api's 30s BACK_MESSAGE_TIMEOUT / 504 behavior
    let pending_requests = gate_state.pending_requests.clone();
    let correlation_for_timeout = correlation_id.clone();

    tokio::spawn(async move {
        tokio::time::sleep(BACK_MESSAGE_TIMEOUT).await;
        if let Some((correlation_id, entry)) = pending_requests.remove(&correlation_for_timeout) {
            warn!(
                "timeout waiting for backend response correlation_id: {}",
                correlation_id
            );
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
        &correlation_id,
        &uri,
        req.data.raw_str().as_bytes(),
    )
    .await
    {
        error!("publish to service error: {}", e);
        gate_state.pending_requests.remove(&correlation_id);
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
    sink: web::ws::WsSink,
    gate_state: WsGateState,
) -> Result<impl Service<web::ws::Frame, Response = Option<web::ws::Message>, Error = AppError>, web::Error> {
    let connection_id = Uuid::now_v7();

    let state = Rc::new(RefCell::new(WsState {
        hb: Instant::now(),
        auth: AuthState::Pending,
        public_key: None,
        api_key: None,
        connection_id,
    }));

    // outbound channel: the only Send-safe handle to this connection reachable
    // from other tasks (WsSink itself is !Send, thread-affine to this
    // connection's worker thread — see heartbeat below, the sole owner of `sink`)
    let (outbound_tx, outbound_rx) = tokio::sync::mpsc::unbounded_channel::<WsOutbound>();

    // disconnect notification
    let (tx, rx) = oneshot::channel();

    // start heartbeat + outbound-delivery task
    rt::spawn(heartbeat(state.clone(), sink, rx, outbound_rx));

    // handler service for incoming websockets frames
    let gate_state_frames = gate_state.clone();
    let service = fn_service(move |frame| {
        handle_frame(
            state.clone(),
            gate_state_frames.clone(),
            outbound_tx.clone(),
            frame,
        )
    });

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
    sink: web::ws::WsSink,
    mut rx: oneshot::Receiver<()>,
    mut outbound_rx: tokio::sync::mpsc::UnboundedReceiver<WsOutbound>,
) {
    loop {
        tokio::select! {
            _ = time::sleep(*CFG_HEARTBEAT_INTERVAL) => {
                // check client heartbeats
                if Instant::now().duration_since(state.borrow().hb) > *CFG_CLIENT_TIMEOUT {
                    // heartbeat timed out
                    warn!("Websocket Client heartbeat failed, disconnecting!");
                    sink.io().terminate();
                    return;
                }

                // send ping
                if sink.send(web::ws::Message::Ping(Bytes::default())).await.is_err() {
                    return;
                }
            }
            _ = &mut rx => {
                warn!("Connection is dropped, stop heartbeat task");
                return;
            }
            msg = outbound_rx.recv() => {
                let Some(msg) = msg else {
                    // all senders dropped; connection teardown handled by the other branches
                    continue;
                };
                if sink.send(build_ws_message(msg)).await.is_err() {
                    return;
                }
            }
        }
    }
}

//@todo replace to Payload struct like in api gate
fn build_ws_message(outbound: WsOutbound) -> web::ws::Message {
    let json = match outbound {
        WsOutbound::Reply {
            signature,
            payload,
            service_error,
        } => {
            let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap_or(serde_json::Value::Null);
            serde_json::json!({
                "Signature": signature,
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
    web::ws::Message::Text(json.to_string().into())
}

/// do websocket handshake and start web sockets service
pub(crate) async fn ws_index(req: web::HttpRequest, state: web::types::State<WsGateState>) -> Result<web::HttpResponse, web::Error> {
    let gate_state = state.get_ref().clone();
    web::ws::start(
        req,
        None::<String>,
        fn_factory_with_config(move |sink| {
            let gate_state = gate_state.clone();
            async move { ws_service(sink, gate_state).await }
        }),
    )
    .await
}

// connection is not authorized until the client's first message
// successfully authorizes it; a bad/failed attempt closes the connection.
pub(crate) fn unauthorized_close() -> Option<web::ws::Message> {
    Some(web::ws::Message::Close(Some(web::ws::CloseReason {
        code: web::ws::CloseCode::Policy,
        description: Some("Unauthorized".into()), // @todo move to some Payload struct
    })))
}

// non-terminal error reply for a signed-but-unroutable/unpublishable
// request; the connection stays open for further requests.
// `code` mirrors the HTTP status gates/api answers in the same situation.
fn error_message(signature: &str, reason: &str, code: StatusCode) -> Option<web::ws::Message> {
    Some(web::ws::Message::Text(
        serde_json::json!({ "Signature": signature, "ErrorMsg": reason, "ErrCode": code.as_u16() })
            .to_string()
            .into(),
    ))
}
