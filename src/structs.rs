use std::time::Instant;

use skw_lib_shared::prelude::{jsonrpc::JsonRpcGateHttpRequest, serde::*, uuid::Uuid};

/// A parsed value paired with the exact raw JSON text it came from. One
/// `Deserialize` pass gives both typed field access (via `Deref`) and the
/// original bytes needed for ed25519 signature verification —
/// re-serializing the parsed value would only reproduce those bytes if the
/// client's JSON codec happened to order/format fields identically to
/// serde_json's, which isn't guaranteed. `Serialize` re-emits the stored
/// raw text verbatim, so echoing a `Signed<T>` back reproduces exactly what
/// the client sent, byte for byte.
pub(crate) struct Signed<T> {
    raw: Box<serde_json::value::RawValue>,
    value: T,
}

impl<T> Signed<T> {
    pub(crate) fn raw_str(&self) -> &str {
        self.raw.get()
    }
}

impl<T> std::ops::Deref for Signed<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for Signed<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.value.fmt(f)
    }
}

impl<'de, T: serde::de::DeserializeOwned> serde::Deserialize<'de> for Signed<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = Box::<serde_json::value::RawValue>::deserialize(deserializer)?;
        let value = serde_json::from_str(raw.get()).map_err(serde::de::Error::custom)?;
        Ok(Self { raw, value })
    }
}

impl<T> Serialize for Signed<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.raw.serialize(serializer)
    }
}

/// Client frame: `{"Signature", "Uri", "Data"}`.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub(crate) struct WsRequest {
    pub signature: String,
    pub uri: Option<String>,
    pub data: Signed<JsonRpcGateHttpRequest>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "Method", content = "Params", rename_all = "PascalCase")]
pub(crate) enum WsMethod {
    #[serde(rename_all = "PascalCase")]
    Authorize { api_key: Uuid },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthState {
    Pending,
    Authorizing,
    Authorized,
}

#[derive(Debug)]
pub(crate) struct WsState {
    /// Client must send ping (or answer ours) at least once per CLIENT_TIMEOUT,
    /// otherwise we drop connection. Refreshed for unauthorized connections too,
    /// since public/open requests need no authorization.
    pub hb: Instant,
    pub auth: AuthState,
    pub public_key: Option<String>,
    /// set together with public_key on successful Authorize; forwarded as
    /// IGGY_HEADER_API_KEY on every request published for this connection
    pub api_key: Option<Uuid>,
    /// minted once per connection; used to address this connection in the
    /// gate's connections registry (registered only after Authorize)
    pub connection_id: Uuid,
}
