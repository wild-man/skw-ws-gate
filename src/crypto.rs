use ed25519_dalek::pkcs8::DecodePublicKey;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use skw_lib_http_protos::auth::internal::{HttpMethod, HttpPayload};
use skw_lib_shared::prelude::{AppError, base64::*, jsonrpc::*, uuid::*};

use crate::cfg::CFG_AUTH_SERVICE_URL;

/// Verifies `signature` (base64) against `data` — the raw bytes/text of the
/// request's `Data` field exactly as sent on the wire — using `public_key`
/// (base64 SPKI DER). Same scheme as gates/api/src/auth.rs. Verifying
/// against the original raw text (instead of re-serializing a parsed
/// struct) means this doesn't depend on the client's JSON codec matching
/// serde_json's field order/formatting.
pub(crate) fn verify_signature(public_key: &str, signature: &str, data: &str) -> Result<(), AppError> {
    let public_key_der = BASE64_STANDARD
        .decode(public_key)
        .map_err(|_| SkwServiceHttpError::Forbidden)?;
    let verifying_key = VerifyingKey::from_public_key_der(&public_key_der).map_err(|_| SkwServiceHttpError::Forbidden)?;

    let signature_bytes = BASE64_STANDARD
        .decode(signature)
        .map_err(|_| SkwServiceHttpError::Forbidden)?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|_| SkwServiceHttpError::Forbidden)?;

    verifying_key
        .verify(data.as_bytes(), &signature)
        .map_err(|_| SkwServiceHttpError::Forbidden)?;

    Ok(())
}

pub(crate) async fn check_authorize(api_key: Uuid, signature: &str, data: &str) -> Result<String, AppError> {
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

    verify_signature(&public_key, signature, data)?;

    Ok(public_key)
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

    #[test]
    fn valid_signature_passes() {
        let (sk, pk) = key(7);
        assert!(verify_signature(&pk, &sign(&sk, DATA), DATA).is_ok());
    }

    #[test]
    fn tampered_data_is_forbidden() {
        let (sk, pk) = key(7);
        let tampered = DATA.replace("Ping", "Pong");
        assert!(verify_signature(&pk, &sign(&sk, DATA), &tampered).is_err());
    }

    #[test]
    fn other_key_is_forbidden() {
        let (_, pk) = key(7);
        let (other, _) = key(8);
        assert!(verify_signature(&pk, &sign(&other, DATA), DATA).is_err());
    }

    #[test]
    fn garbage_input_is_forbidden() {
        let (sk, pk) = key(7);
        let signature = sign(&sk, DATA);
        assert!(
            verify_signature("%%%", &signature, DATA).is_err(),
            "bad key base64"
        );
        assert!(
            verify_signature(&BASE64_STANDARD.encode(b"not a der key"), &signature, DATA).is_err(),
            "bad key der"
        );
        assert!(
            verify_signature(&pk, "%%%", DATA).is_err(),
            "bad signature base64"
        );
        assert!(
            verify_signature(&pk, &BASE64_STANDARD.encode([0u8; 10]), DATA).is_err(),
            "short signature"
        );
    }
}
