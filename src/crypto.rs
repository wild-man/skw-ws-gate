use ed25519_dalek::pkcs8::DecodePublicKey;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use skw_lib_http_protos::auth::internal::{HttpMethod, HttpPayload};
use skw_lib_shared::prelude::{AppError, base64::*, jsonrpc::*, uuid::*};

use crate::cfg::CFG_AUTH_SERVICE_URL;

/// Verifies `signature` (base64) against `data` — the raw bytes/text of the
/// request's `data` field exactly as sent on the wire — using `public_key`
/// (base64 SPKI DER). Same scheme as gates/api/src/auth.rs. Verifying
/// against the original raw text (instead of re-serializing a parsed
/// struct) means this doesn't depend on the client's JSON codec matching
/// serde_json's field order/formatting.
pub(crate) fn verify_signature(public_key: &str, signature: &str, data: &str) -> Result<(), AppError> {
    let public_key_der = BASE64_STANDARD
        .decode(public_key)
        .map_err(|_| ServiceHttpError::Forbidden)?;
    let verifying_key = VerifyingKey::from_public_key_der(&public_key_der).map_err(|_| ServiceHttpError::Forbidden)?;

    let signature_bytes = BASE64_STANDARD
        .decode(signature)
        .map_err(|_| ServiceHttpError::Forbidden)?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|_| ServiceHttpError::Forbidden)?;

    verifying_key
        .verify(data.as_bytes(), &signature)
        .map_err(|_| ServiceHttpError::Forbidden)?;

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
        return Err(ServiceHttpError::Forbidden.into());
    }

    verify_signature(&public_key, signature, data)?;

    Ok(public_key)
}
