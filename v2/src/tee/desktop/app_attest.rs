//! macOS App Attest (same wire format and crypto as iOS).

use crate::tee::mobile::{ios_app_id_hash, ios_client_data_hash, IOS_PLATFORM};

use super::{DesktopVerdict, MACOS_APP_ATTEST_PLATFORM};

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct MacOsAppAttestBundle {
    pub version: u32,
    pub platform: String,
    pub key_id: String,
    pub assertion: String,
    pub credential_public_key: String,
    pub app_id_hash: String,
    pub team_id: String,
    pub bundle_id: String,
    pub binding: String,
    pub client_data_hash: String,
}

#[derive(Debug, thiserror::Error)]
pub enum MacOsVerifyError {
    #[error("parse: {0}")]
    Parse(String),
    #[error("verify: {0}")]
    Verify(String),
}

pub fn verify_bundle(
    bundle: &MacOsAppAttestBundle,
    expected_binding: &[u8; 32],
) -> Result<DesktopVerdict, MacOsVerifyError> {
    use ciborium::Value;
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    let _ = IOS_PLATFORM;
    if bundle.version != 1 {
        return Err(MacOsVerifyError::Verify(format!(
            "unsupported version {}",
            bundle.version
        )));
    }
    if bundle.platform != MACOS_APP_ATTEST_PLATFORM {
        return Err(MacOsVerifyError::Verify(format!(
            "expected platform {MACOS_APP_ATTEST_PLATFORM}, got {}",
            bundle.platform
        )));
    }
    let binding = parse_hex32(&bundle.binding, "binding")?;
    if &binding != expected_binding {
        return Err(MacOsVerifyError::Verify(
            "binding does not match expected channel binding".into(),
        ));
    }
    let client_hash = parse_hex32(&bundle.client_data_hash, "client_data_hash")?;
    let want_hash = ios_client_data_hash(&binding);
    if client_hash != want_hash {
        return Err(MacOsVerifyError::Verify(
            "client_data_hash does not match uq/mobile/ios/v1 binding digest".into(),
        ));
    }
    let computed = ios_app_id_hash(&bundle.team_id, &bundle.bundle_id);
    if hex::encode(computed) != bundle.app_id_hash.to_lowercase() {
        return Err(MacOsVerifyError::Verify(
            "app_id_hash does not match team_id/bundle_id".into(),
        ));
    }

    let pk = parse_uncompressed_p256(&bundle.credential_public_key)?;
    let (auth_data, sig_bytes) = parse_assertion(&bundle.assertion)?;
    let signed = [auth_data.as_slice(), client_hash.as_slice()].concat();
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|e| MacOsVerifyError::Verify(format!("signature: {e}")))?;
    pk.verify(&signed, &sig)
        .map_err(|e| MacOsVerifyError::Verify(format!("assertion signature: {e}")))?;

    Ok(DesktopVerdict {
        verdict: "verified".into(),
        platform: MACOS_APP_ATTEST_PLATFORM.into(),
        identity_hash: bundle.app_id_hash.clone(),
        ima_verified: false,
        boot_aggregate: None,
    })
}

fn parse_assertion(b64: &str) -> Result<(Vec<u8>, Vec<u8>), MacOsVerifyError> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use ciborium::Value;
    let raw = B64
        .decode(b64.trim().as_bytes())
        .map_err(|e| MacOsVerifyError::Parse(format!("assertion base64: {e}")))?;
    let val: Value = ciborium::de::from_reader(raw.as_slice())
        .map_err(|e| MacOsVerifyError::Parse(format!("assertion cbor: {e}")))?;
    let map = match val {
        Value::Map(m) => m,
        _ => return Err(MacOsVerifyError::Parse("assertion must be CBOR map".into())),
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
            "authenticatorData" | "1" => auth_data = bytes_from_value(v),
            "signature" | "2" => signature = bytes_from_value(v),
            _ => {}
        }
    }
    Ok((
        auth_data.ok_or_else(|| MacOsVerifyError::Parse("missing authenticatorData".into()))?,
        signature.ok_or_else(|| MacOsVerifyError::Parse("missing signature".into()))?,
    ))
}

fn bytes_from_value(v: ciborium::Value) -> Option<Vec<u8>> {
    match v {
        ciborium::Value::Bytes(b) => Some(b),
        _ => None,
    }
}

fn parse_uncompressed_p256(hex: &str) -> Result<p256::ecdsa::VerifyingKey, MacOsVerifyError> {
    use p256::ecdsa::VerifyingKey;
    let raw =
        hex::decode(hex.trim()).map_err(|e| MacOsVerifyError::Parse(format!("pubkey: {e}")))?;
    VerifyingKey::from_sec1_bytes(&raw)
        .map_err(|e| MacOsVerifyError::Parse(format!("p256 pubkey: {e}")))
}

fn parse_hex32(s: &str, field: &str) -> Result<[u8; 32], MacOsVerifyError> {
    let v = hex::decode(s.trim()).map_err(|e| MacOsVerifyError::Parse(format!("{field}: {e}")))?;
    v.as_slice()
        .try_into()
        .map_err(|_| MacOsVerifyError::Parse(format!("{field} must be 32 bytes")))
}
