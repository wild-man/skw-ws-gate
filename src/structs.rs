use std::borrow::Cow;
use std::fmt::{Debug, Formatter};
use std::net::SocketAddr;
use std::sync::{Arc, atomic::AtomicUsize};
use std::time::Instant;

use crate::gate::SessionSlot;
use ed25519_dalek::VerifyingKey;
use serde_json::value::RawValue;
use skw_lib_shared::prelude::{
    chrono::{DateTime, Utc},
    serde::*,
    uuid::Uuid,
};

/// A frame's `Data`: the exact raw JSON text the client signed, borrowed from the frame
/// buffer, plus its `Ts`. Re-serializing a parsed value would only reproduce the signed bytes
/// if the client's JSON codec happened to order/format fields identically to serde_json's,
/// which isn't guaranteed, so the raw text is what gets verified and forwarded. Only `Ts` is
/// parsed (the gate needs nothing else for a signed request; services parse their own method),
/// and nothing is copied: `Serialize` re-emits the raw text verbatim.
pub(crate) struct SignedData<'a> {
    raw: &'a RawValue,
    pub ts: DateTime<Utc>,
}

impl<'a> SignedData<'a> {
    pub(crate) fn raw_str(&self) -> &'a str {
        self.raw.get()
    }

    /// Parses the method (`{"Method", "Params"}`, `Ts` ignored) the gate handles itself, e.g. `Authorize`.
    pub(crate) fn method<T: Deserialize<'a>>(&self) -> serde_json::Result<T> {
        serde_json::from_str(self.raw.get())
    }
}

impl Debug for SignedData<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.raw.get())
    }
}

impl<'de: 'a, 'a> Deserialize<'de> for SignedData<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        /// the one field the gate reads; the others are skipped without allocating
        #[derive(Deserialize)]
        struct Head {
            #[serde(rename = "Ts")]
            ts: DateTime<Utc>,
        }

        let raw = <&'de RawValue>::deserialize(deserializer)?;
        // a struct would also accept a JSON array (`["<ts>"]`): `Data` must be an object
        if !raw.get().starts_with('{') {
            return Err(serde::de::Error::custom("Data must be a JSON object"));
        }
        let head: Head = serde_json::from_str(raw.get()).map_err(serde::de::Error::custom)?;
        Ok(Self { raw, ts: head.ts })
    }
}

impl Serialize for SignedData<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.raw.serialize(serializer)
    }
}

/// `Option<Cow<str>>` that borrows: serde borrows a `Cow<str>` only when it is the field type
/// itself, inside an `Option` it would always allocate
fn borrow_opt_str<'de, D>(deserializer: D) -> Result<Option<Cow<'de, str>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    struct Borrowed<'a>(#[serde(borrow)] Cow<'a, str>);
    Ok(Option::<Borrowed>::deserialize(deserializer)?.map(|b| b.0))
}

/// Client frame: `{"Signature", "Uri", "Data"}`, borrowed from the frame buffer. The strings
/// are `Cow`: borrowed unless the client escaped characters in them.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub(crate) struct WsRequest<'a> {
    #[serde(borrow)]
    pub signature: Cow<'a, str>,
    #[serde(borrow, default, deserialize_with = "borrow_opt_str")]
    pub uri: Option<Cow<'a, str>>,
    #[serde(borrow)]
    pub data: SignedData<'a>,
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
    /// parsed once on Authorize: every signed frame is verified against it
    pub verifying_key: Option<VerifyingKey>,
    /// set together with verifying_key on successful Authorize; forwarded as
    /// IGGY_HEADER_API_KEY on every request published for this connection
    pub api_key: Option<Uuid>,
    /// minted once per connection; used to address this connection in the
    /// gate's connections registry (registered only after Authorize)
    pub connection_id: Uuid,
    /// requests of this connection waiting for their reply (see `gate::PendingSlot`)
    pub pending: Arc<AtomicUsize>,
    /// client's address as seen by the gate's socket (a proxy in front would show its own)
    pub peer_addr: Option<SocketAddr>,
    /// this connection's place in its API key's `/service/maxSessionsPerToken`, taken on
    /// Authorize, released on connection shutdown
    pub session: Option<SessionSlot>,
}

impl WsState {
    /// `"<connection id> (<peer addr>)"`, for log lines about this connection
    pub(crate) fn describe(&self) -> String {
        match self.peer_addr {
            Some(addr) => format!("{} ({addr})", self.connection_id),
            None => format!("{} (unknown peer)", self.connection_id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_keeps_exact_client_bytes() {
        // odd spacing and key order: re-serializing would change these bytes and break the signature
        let data = r#"{ "Params":{},  "Method":"Ping","Ts":"2026-01-01T00:00:00Z" }"#;
        let frame = format!(r#"{{"Signature":"s","Uri":"/ping/signed","Data":{data}}}"#);

        let req: WsRequest = serde_json::from_str(&frame).unwrap();

        assert_eq!(req.data.raw_str(), data);
        assert_eq!(req.data.ts.to_rfc3339(), "2026-01-01T00:00:00+00:00");
        assert_eq!(req.uri.as_deref(), Some("/ping/signed"));
    }

    #[test]
    fn frame_strings_are_borrowed_unless_escaped() {
        let frame = br#"{"Signature":"abc","Uri":"/ping/signed","Data":{"Ts":"2026-01-01T00:00:00Z","Method":"Ping"}}"#;
        let req: WsRequest = serde_json::from_slice(frame).unwrap();
        assert!(matches!(req.signature, Cow::Borrowed("abc")));
        assert!(matches!(req.uri, Some(Cow::Borrowed("/ping/signed"))));

        // an escape can't be borrowed: still parsed, as an owned string
        let frame = br#"{"Signature":"a\/c","Data":{"Ts":"2026-01-01T00:00:00Z","Method":"Ping"}}"#;
        let req: WsRequest = serde_json::from_slice(frame).unwrap();
        assert_eq!(req.signature, "a/c");
        assert!(matches!(req.signature, Cow::Owned(_)));
        assert!(req.uri.is_none(), "a missing Uri is None");
    }

    #[test]
    fn signed_reserializes_verbatim() {
        let frame = r#"{"Signature":"s","Uri":null,"Data":{"Ts":"2026-01-01T00:00:00Z",  "Method":"Ping"}}"#;
        let req: WsRequest = serde_json::from_str(frame).unwrap();
        assert_eq!(serde_json::to_string(&req).unwrap(), frame);
    }

    #[test]
    fn invalid_frames_are_rejected() {
        for bad in [
            r#"{"Signature":"s","Data":{"Ts":"2026-01-01T00:00:00Z","Method":"Ping"},"Extra":1}"#, // deny_unknown_fields
            r#"{"Signature":"s","Data":{"Method":"Ping"}}"#,                                       // no Ts
            r#"{"Data":{"Ts":"2026-01-01T00:00:00Z","Method":"Ping"}}"#,                           // no Signature
            r#"{"Signature":"s","Data":{"Ts":"2026-01-01T00:00:00Z","Method":"Ping"}"#,            // truncated
            r#"{"Signature":"s","Data":["2026-01-01T00:00:00Z"]}"#,                                // Data not an object
            r#"{"Signature":"s","Data":{"Ts":"yesterday","Method":"Ping"}}"#,                      // bad Ts
        ] {
            assert!(
                serde_json::from_str::<WsRequest>(bad).is_err(),
                "accepted: {bad}"
            );
        }
    }

    #[test]
    fn authorize_method_parses() {
        // parsed from the frame's Data, next to its Ts
        let frame = r#"{"Signature":"s","Data":{"Ts":"2026-01-01T00:00:00Z","Method":"Authorize","Params":{"ApiKey":"01a01500-98d5-71fc-9038-71acb78d61c4"}}}"#;
        let req: WsRequest = serde_json::from_str(frame).unwrap();
        let m: WsMethod = req.data.method().unwrap();
        let WsMethod::Authorize { api_key } = m;
        assert_eq!(api_key.to_string(), "01a01500-98d5-71fc-9038-71acb78d61c4");
    }
}
