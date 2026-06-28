//! iOS App Attest assertion bundle (no iCloud / Apple ID required).

use ciborium::Value;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

use super::{ios_app_id_hash, ios_client_data_hash, MobileVerdict, IOS_PLATFORM};

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct IosAppAttestBundle {
    pub version: u32,
    pub platform: String,
    pub key_id: String,
    /// Base64 CBOR `{ "authenticatorData", "signature" }` from `generateAssertion`.
    pub assertion: String,
    /// Uncompressed P-256 public key (hex, 65 bytes `04||x||y`) from enrollment.
    pub credential_public_key: String,
    /// Allowlist key: `sha256(team_id||bundle_id)` hex (64 chars).
    pub app_id_hash: String,
    pub team_id: String,
    pub bundle_id: String,
    /// Must equal eat-pass channel binding.
    pub binding: String,
    /// Must equal [`super::ios_client_data_hash`] of binding (hex).
    pub client_data_hash: String,
}

#[derive(Debug, thiserror::Error)]
pub enum IosVerifyError {
    #[error("parse: {0}")]
    Parse(String),
    #[error("verify: {0}")]
    Verify(String),
}

pub fn verify_bundle(
    bundle: &IosAppAttestBundle,
    expected_binding: &[u8; 32],
) -> Result<MobileVerdict, IosVerifyError> {
    if bundle.version != 1 {
        return Err(IosVerifyError::Verify(format!(
            "unsupported version {}",
            bundle.version
        )));
    }
    if bundle.platform != IOS_PLATFORM {
        return Err(IosVerifyError::Verify(format!(
            "expected platform {IOS_PLATFORM}, got {}",
            bundle.platform
        )));
    }
    let binding = parse_hex32(&bundle.binding, "binding")?;
    if &binding != expected_binding {
        return Err(IosVerifyError::Verify(
            "binding does not match expected channel binding".into(),
        ));
    }
    let client_hash = parse_hex32(&bundle.client_data_hash, "client_data_hash")?;
    let want_hash = ios_client_data_hash(&binding);
    if client_hash != want_hash {
        return Err(IosVerifyError::Verify(
            "client_data_hash does not match uq/mobile/ios/v1 binding digest".into(),
        ));
    }
    let _app_id = parse_hex32(&bundle.app_id_hash, "app_id_hash")?;
    let computed = ios_app_id_hash(&bundle.team_id, &bundle.bundle_id);
    if hex::encode(computed) != bundle.app_id_hash.to_lowercase() {
        return Err(IosVerifyError::Verify(
            "app_id_hash does not match team_id/bundle_id".into(),
        ));
    }

    let pk = parse_uncompressed_p256(&bundle.credential_public_key)?;
    let (auth_data, sig_bytes) = parse_assertion(&bundle.assertion)?;
    let signed = [auth_data.as_slice(), client_hash.as_slice()].concat();
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|e| IosVerifyError::Verify(format!("signature: {e}")))?;
    pk.verify(&signed, &sig)
        .map_err(|e| IosVerifyError::Verify(format!("assertion signature: {e}")))?;

    Ok(MobileVerdict {
        verdict: "verified".into(),
        platform: IOS_PLATFORM.into(),
        app_id_hash: bundle.app_id_hash.clone(),
        package_or_bundle: bundle.bundle_id.clone(),
    })
}

fn parse_assertion(b64: &str) -> Result<(Vec<u8>, Vec<u8>), IosVerifyError> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    let raw = B64
        .decode(b64.trim().as_bytes())
        .map_err(|e| IosVerifyError::Parse(format!("assertion base64: {e}")))?;
    let val: Value = ciborium::de::from_reader(raw.as_slice())
        .map_err(|e| IosVerifyError::Parse(format!("assertion cbor: {e}")))?;
    let map = match val {
        Value::Map(m) => m,
        _ => {
            return Err(IosVerifyError::Parse(
                "assertion must be CBOR map".into(),
            ))
        }
    };
    let mut auth_data = None;
    let mut signature = None;
    for (k, v) in map {
        let key = match k {
            Value::Text(s) => s,
            Value::Integer(i) => i
                .try_into()
                .map(|n: i128| n.to_string())
                .unwrap_or_else(|_| "0".into()),
            _ => continue,
        };
        match key.as_str() {
            "authenticatorData" | "1" => {
                auth_data = bytes_from_value(v);
            }
            "signature" | "2" => {
                signature = bytes_from_value(v);
            }
            _ => {}
        }
    }
    Ok((
        auth_data.ok_or_else(|| IosVerifyError::Parse("missing authenticatorData".into()))?,
        signature.ok_or_else(|| IosVerifyError::Parse("missing signature".into()))?,
    ))
}

fn bytes_from_value(v: Value) -> Option<Vec<u8>> {
    match v {
        Value::Bytes(b) => Some(b),
        _ => None,
    }
}

fn parse_uncompressed_p256(hex: &str) -> Result<VerifyingKey, IosVerifyError> {
    let raw = hex::decode(hex.trim()).map_err(|e| IosVerifyError::Parse(format!("pubkey: {e}")))?;
    VerifyingKey::from_sec1_bytes(&raw)
        .map_err(|e| IosVerifyError::Parse(format!("p256 pubkey: {e}")))
}

fn parse_hex32(s: &str, field: &str) -> Result<[u8; 32], IosVerifyError> {
    let v = hex::decode(s.trim()).map_err(|e| IosVerifyError::Parse(format!("{field}: {e}")))?;
    v.as_slice()
        .try_into()
        .map_err(|_| IosVerifyError::Parse(format!("{field} must be 32 bytes")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_client_data_hash_mismatch() {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine;
        let binding = [1u8; 32];
        let bundle = IosAppAttestBundle {
            version: 1,
            platform: IOS_PLATFORM.into(),
            key_id: "kid".into(),
            assertion: B64.encode([0u8; 4]),
            credential_public_key: hex::encode([0u8; 65]),
            app_id_hash: hex::encode(ios_app_id_hash("TEAM", "com.example.app")),
            team_id: "TEAM".into(),
            bundle_id: "com.example.app".into(),
            binding: hex::encode(binding),
            client_data_hash: hex::encode([2u8; 32]),
        };
        let err = verify_bundle(&bundle, &binding).unwrap_err();
        assert!(err.to_string().contains("client_data_hash"));
    }
}
