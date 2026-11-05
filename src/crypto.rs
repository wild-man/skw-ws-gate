use ed25519_dalek::pkcs8::DecodePublicKey;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use skw_lib_http_protos::auth::internal::{HttpMethod, HttpPayload};
use skw_lib_shared::prelude::{AppError, base64::*, jsonrpc::*, uuid::*};

use crate::cfg::CFG_AUTH_SERVICE_URL;

/// Parses the auth service's public key (base64 SPKI DER); done once per connection, on
/// Authorize, so signed frames verify against the cached `VerifyingKey`.
pub(crate) fn parse_public_key(public_key: &str) -> Result<VerifyingKey, AppError> {
    let der = BASE64_STANDARD
        .decode(public_key)
        .map_err(|_| SkwServiceHttpError::Forbidden)?;
    VerifyingKey::from_public_key_der(&der).map_err(|_| SkwServiceHttpError::Forbidden.into())
}

/// Verifies `signature` (base64) against `data` — the raw bytes/text of the
/// request's `Data` field exactly as sent on the wire. Same scheme as
/// gates/api/src/auth.rs. Verifying against the original raw text (instead of
/// re-serializing a parsed struct) means this doesn't depend on the client's
/// JSON codec matching serde_json's field order/formatting. The signature is
/// decoded into a stack buffer: no allocation per frame.
pub(crate) fn verify_signature(key: &VerifyingKey, signature: &str, data: &str) -> Result<(), AppError> {
    let mut bytes = [0u8; Signature::BYTE_SIZE];
    // a longer input fails with OutputSliceTooSmall, a shorter one decodes to fewer bytes
    let Ok(Signature::BYTE_SIZE) = BASE64_STANDARD.decode_slice(signature, &mut bytes) else {
        return Err(SkwServiceHttpError::Forbidden.into());
    };

    key.verify(data.as_bytes(), &Signature::from_bytes(&bytes))
        .map_err(|_| SkwServiceHttpError::Forbidden)?;

    Ok(())
}

pub(crate) async fn check_authorize(api_key: Uuid, signature: &str, data: &str) -> Result<VerifyingKey, AppError> {
    let auth_req = HttpMethod::GetKeyById { id: api_key };
    let HttpPayload::GetKeyById {
        public_key,
        enabled,
        ..
    } = internal_http_request(CFG_AUTH_SERVICE_URL.as_str(), auth_req)
        .await?
        .try_into()?;

    if !enabled {
        return Err(SkwServiceHttpError::Forbidden.into());
    }

    let key = parse_public_key(&public_key)?;
    verify_signature(&key, signature, data)?;

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey, pkcs8::EncodePublicKey};

    const DATA: &str = r#"{"Ts":"2026-01-01T00:00:00Z","Method":"Ping","Params":{}}"#;

    /// fixed seed, so the key (and every signature) is deterministic
    fn key(seed: u8) -> (SigningKey, String) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let der = sk.verifying_key().to_public_key_der().unwrap();
        (sk, BASE64_STANDARD.encode(der.as_bytes()))
    }

    fn sign(sk: &SigningKey, data: &str) -> String {
        BASE64_STANDARD.encode(sk.sign(data.as_bytes()).to_bytes())
    }

    fn verify(pk: &str, signature: &str, data: &str) -> Result<(), AppError> {
        verify_signature(&parse_public_key(pk)?, signature, data)
    }

    #[test]
    fn valid_signature_passes() {
        let (sk, pk) = key(7);
        assert!(verify(&pk, &sign(&sk, DATA), DATA).is_ok());
    }

    #[test]
    fn tampered_data_is_forbidden() {
        let (sk, pk) = key(7);
        let tampered = DATA.replace("Ping", "Pong");
        assert!(verify(&pk, &sign(&sk, DATA), &tampered).is_err());
    }

    #[test]
    fn other_key_is_forbidden() {
        let (_, pk) = key(7);
        let (other, _) = key(8);
        assert!(verify(&pk, &sign(&other, DATA), DATA).is_err());
    }

    #[test]
    fn garbage_input_is_forbidden() {
        let (sk, pk) = key(7);
        let signature = sign(&sk, DATA);
        assert!(parse_public_key("%%%").is_err(), "bad key base64");
        assert!(
            parse_public_key(&BASE64_STANDARD.encode(b"not a der key")).is_err(),
            "bad key der"
        );
        let key = parse_public_key(&pk).unwrap();
        assert!(
            verify_signature(&key, "%%%", DATA).is_err(),
            "bad signature base64"
        );
        assert!(
            verify_signature(&key, &BASE64_STANDARD.encode([0u8; 10]), DATA).is_err(),
            "short signature"
        );
        assert!(
            verify_signature(&key, &BASE64_STANDARD.encode([0u8; 65]), DATA).is_err(),
            "long signature"
        );
        assert!(verify_signature(&key, &signature, DATA).is_ok());
    }
}
