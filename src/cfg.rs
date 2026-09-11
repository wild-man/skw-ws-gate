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
