use ntex::{SharedCfg, web};

use skw_lib_shared::{
    APP, AppError,
    prelude::{consts::*, log::*, tools::*},
};

mod cfg;
mod crypto;
mod gate;
mod structs;
mod tls;
mod ws;

use cfg::*;
use ws::*;

use mimalloc::MiMalloc;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[ntex::main]
async fn main() -> Result<(), AppError> {
    let bind_addr = APP.config.expect_string(SERVICE_BIND_ADDRESS);
    let back_topic = skw_get_back_topic_name();
    let stream = skw_get_stream_name();

    let workers = APP
        .config
        .get(SERVICE_WORKERS)
        .map(|w| w.as_u64().expect("workers is not a number") as usize)
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(2, std::num::NonZeroUsize::get));

    // force config validation (fail-fast) and initialization at startup
    // rather than lazily on the first websocket auth/heartbeat
    info!("using auth service url: {}", CFG_AUTH_SERVICE_URL.as_str());
    info!(
        "heartbeat interval: {:?}, client timeout: {:?}, max in-flight frames: {}, max pending requests: {}, max sessions per token: {}",
        *CFG_HEARTBEAT_INTERVAL, *CFG_CLIENT_TIMEOUT, *CFG_MAX_INFLIGHT_FRAMES, *CFG_MAX_PENDING_REQUESTS, *CFG_MAX_SESSIONS_PER_TOKEN
    );

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("unable to install rustls aws-lc-rs CryptoProvider");

    let tls_config = tls::build_rustls_config()?;

    let iggy_client = APP.iggy.clone().connect().await?.inner();

    let routes_map = gate::init_iggy(&stream, &back_topic, &iggy_client).await?;
    let ws_state = gate::WsGateState::new(&stream, &back_topic, routes_map, iggy_client).await?;

    info!("starting skw-ws-gate listening on https://{}", bind_addr);

    // one shared gate state for all workers (it is all `Arc`s), handed to each worker's app
    web::server_with_config(
        async move || Ok::<_, std::io::Error>(ws_state.clone()),
        async |_| {
            web::App::<gate::WsGateState>::new()
                // enable logger
                .middleware(web::middleware::Logger::default())
                // websocket route
                .service(web::resource("/ws/").route(web::get().to_with_state(ws_index)))
        },
    )
    .bind_rustls(&bind_addr, &tls_config, SharedCfg::default())
    .map_err(|e| AppError::Custom(e.to_string()))?
    .workers(workers)
    .run()
    .await
    .map_err(|e| AppError::Custom(e.to_string()))?;

    Ok(())
}
