use skw_lib_shared::{APP, prelude::consts::*};
use std::{sync::LazyLock, time::Duration};

/// How often heartbeat pings are sent
pub(crate) static CFG_HEARTBEAT_INTERVAL: LazyLock<Duration> = LazyLock::new(|| {
    APP.config
        .get("/service/heartbeatIntervalSecs")
        .map(|v| v.as_u64().expect("invalid /service/heartbeatIntervalSecs"))
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(5))
});

/// How long before lack of client response causes a timeout
pub(crate) static CFG_CLIENT_TIMEOUT: LazyLock<Duration> = LazyLock::new(|| {
    APP.config
        .get("/service/clientTimeoutSecs")
        .map(|v| v.as_u64().expect("invalid /service/clientTimeoutSecs"))
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(10))
});

/// How many frames of one connection are handled at once (signature check + publish to Iggy).
/// At the limit the gate stops reading that socket, so a burst slows only its own client.
pub(crate) static CFG_MAX_INFLIGHT_FRAMES: LazyLock<usize> = LazyLock::new(|| {
    APP.config
        .get("/service/maxInFlightFrames")
        .map(|v| {
            v.as_u64()
                .and_then(|n| usize::try_from(n).ok())
                .filter(|&n| n > 0)
                .expect("invalid /service/maxInFlightFrames")
        })
        .unwrap_or(64)
});

/// How many requests of one connection may wait for their reply at once; a frame over the
/// limit closes the connection (1008)
pub(crate) static CFG_MAX_PENDING_REQUESTS: LazyLock<usize> = LazyLock::new(|| {
    APP.config
        .get("/service/maxPendingRequests")
        .map(|v| {
            v.as_u64()
                .and_then(|n| usize::try_from(n).ok())
                .filter(|&n| n > 0)
                .expect("invalid /service/maxPendingRequests")
        })
        .unwrap_or(300)
});

pub(crate) static CFG_AUTH_SERVICE_URL: LazyLock<String> = LazyLock::new(|| {
    let auth_service_url = APP
        .config
        .get(AUTH_SREVICE_URL)
        .map(|a| {
            a.as_str()
                .expect("invalid /service/authServiceUrl")
                .to_string()
        })
        .filter(|a| !a.is_empty())
        .unwrap_or_else(|| skw_lib_http_protos::auth::DEFAULT_SERVICE_URL.to_string());

    format!("{}{}", auth_service_url, INTERNAL_URL_PREFIX)
});
