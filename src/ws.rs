use std::{cell::RefCell, rc::Rc, time::Instant};

use futures::future::{Either, select};
use ntex::service::{Service, fn_factory_with_config, fn_shutdown};
use ntex::util::Bytes;
use ntex::web;
use ntex::{chain, fn_service};
use ntex::{channel::oneshot, rt, time};

use crate::cfg::{CFG_CLIENT_TIMEOUT, CFG_HEARTBEAT_INTERVAL};
use crate::crypto::{check_authorize, verify_signature};
use crate::structs::{AuthState, WsMethod, WsRequest, WsState};
use skw_lib_shared::prelude::log::*;

/// handler for a single incoming websocket frame
pub(crate) async fn handle_frame(state: Rc<RefCell<WsState>>, frame: web::ws::Frame) -> Result<Option<web::ws::Message>, anyhow::Error> {
    let item = match frame {
        // update heartbeat (only once authorized)
        web::ws::Frame::Ping(msg) => {
            if state.borrow().auth == AuthState::Authorized {
                state.borrow_mut().hb = Instant::now();
            }
            Some(web::ws::Message::Pong(msg))
        }

        // update heartbeat (only once authorized)
        web::ws::Frame::Pong(_) => {
            if state.borrow().auth == AuthState::Authorized {
                state.borrow_mut().hb = Instant::now();
            }
            None
        }

        // validate the frame is valid UTF-8 *and* deserializes into our expected shape
        web::ws::Frame::Text(text) => match serde_json::from_slice::<WsRequest>(&text) {
            Ok(req) => {
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
                                    let mut state = state.borrow_mut();
                                    state.auth = AuthState::Authorized;
                                    state.hb = Instant::now();
                                    state.public_key = Some(public_key);

                                    //@todo replace to Payload struct like in api gate
                                    let reply = serde_json::json!({ "authorized": true }).to_string();

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
                        let public_key = state
                            .borrow()
                            .public_key
                            .clone()
                            .expect("public_key set once Authorized");

                        match verify_signature(&public_key, &req.signature, req.data.raw_str()) {
                            Ok(()) => {
                                info!("received: {req:?}");
                                let reply = serde_json::to_string(&req).expect("serialize WsRequest");
                                Some(web::ws::Message::Text(reply.into()))
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

/// WebSockets service factory
pub(crate) async fn ws_service(
    sink: web::ws::WsSink,
) -> Result<impl Service<web::ws::Frame, Response = Option<web::ws::Message>, Error = anyhow::Error>, web::Error> {
    let state = Rc::new(RefCell::new(WsState {
        hb: Instant::now(),
        auth: AuthState::Pending,
        public_key: None,
    }));

    // disconnect notification
    let (tx, rx) = oneshot::channel();

    // start heartbeat task
    rt::spawn(heartbeat(state.clone(), sink, rx));

    // handler service for incoming websockets frames
    let service = fn_service(move |frame| handle_frame(state.clone(), frame));

    // handler service for shutdown notification that stop heartbeat task
    let on_shutdown = fn_shutdown(async move || {
        let _ = tx.send(());
    });

    // pipe our service with on_shutdown callback
    Ok(chain(service).and_then(on_shutdown))
}

/// helper method that sends ping to client every heartbeat interval
pub(crate) async fn heartbeat(state: Rc<RefCell<WsState>>, sink: web::ws::WsSink, mut rx: oneshot::Receiver<()>) {
    loop {
        match select(Box::pin(time::sleep(*CFG_HEARTBEAT_INTERVAL)), &mut rx).await {
            Either::Left(_) => {
                // check client heartbeats
                if Instant::now().duration_since(state.borrow().hb) > *CFG_CLIENT_TIMEOUT {
                    // heartbeat timed out
                    warn!("Websocket Client heartbeat failed, disconnecting!");
                    sink.io().terminate();
                    return;
                }

                // send ping
                if sink
                    .send(web::ws::Message::Ping(Bytes::default()))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            Either::Right(_) => {
                warn!("Connection is dropped, stop heartbeat task");
                return;
            }
        }
    }
}

/// do websocket handshake and start web sockets service
pub(crate) async fn ws_index(req: web::HttpRequest) -> Result<web::HttpResponse, web::Error> {
    web::ws::start(req, None::<String>, fn_factory_with_config(ws_service)).await
}

// connection is not authorized until the client's first message
// successfully authorizes it; a bad/failed attempt closes the connection.
pub(crate) fn unauthorized_close() -> Option<web::ws::Message> {
    Some(web::ws::Message::Close(Some(web::ws::CloseReason {
        code: web::ws::CloseCode::Policy,
        description: Some("unauthorized".into()), // @todo move to some Payload struct
    })))
}
