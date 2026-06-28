//! TPM2 client attestation for Linux and Windows desktops (no CVM).

use der::Decode;
use p256::ecdsa::{signature::Verifier, Signature as P256Sig, VerifyingKey as P256Vk};
use p384::ecdsa::{Signature as P384Sig, VerifyingKey as P384Vk};
use sha2::{Digest, Sha256, Sha384};
use x509_cert::Certificate;

use super::{desktop_build_id_hash, DesktopVerdict, LINUX_TPM_PLATFORM, WINDOWS_TPM_PLATFORM};

const TPM_GENERATED_VALUE: u32 = 0xff54_4347;
const TPM_ALG_ECDSA: u16 = 0x0018;
const TPM_ALG_RSASSA: u16 = 0x0014;

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct TpmClientBundle {
    pub version: u32,
    /// `linux-tpm-client` or `windows-tpm-client`.
    pub platform: String,
    /// Must equal eat-pass `binding_of(blinded)`.
    pub binding: String,
    /// SHA-256 of the agent binary or signed bundle (hex, 32 bytes).
    pub build_digest: String,
    /// Attestation Key certificate (hex DER).
    pub ak_cert: String,
    /// TPM2B_ATTEST (hex), including the leading size field.
    pub quote_msg: String,
    /// TPMT_SIGNATURE (hex).
    pub quote_sig: String,
    /// Qualifying data from the quote (hex); must equal `binding`.
    pub qualifying_data: String,
}

#[derive(Debug, thiserror::Error)]
pub enum TpmVerifyError {
    #[error("parse: {0}")]
    Parse(String),
    #[error("verify: {0}")]
    Verify(String),
}

pub fn verify_bundle(
    bundle: &TpmClientBundle,
    expected_binding: &[u8; 32],
) -> Result<DesktopVerdict, TpmVerifyError> {
    if bundle.version != 1 {
        return Err(TpmVerifyError::Verify(format!(
            "unsupported version {}",
            bundle.version
        )));
    }
    if bundle.platform != LINUX_TPM_PLATFORM && bundle.platform != WINDOWS_TPM_PLATFORM {
        return Err(TpmVerifyError::Verify(format!(
            "expected platform {LINUX_TPM_PLATFORM} or {WINDOWS_TPM_PLATFORM}, got {}",
            bundle.platform
        )));
    }
    let binding = parse_hex32(&bundle.binding, "binding")?;
    if &binding != expected_binding {
        return Err(TpmVerifyError::Verify(
            "binding does not match expected channel binding".into(),
        ));
    }
    let qualifying = parse_hex(&bundle.qualifying_data, "qualifying_data")?;
    if qualifying.as_slice() != expected_binding {
        return Err(TpmVerifyError::Verify(
            "qualifying_data does not match expected channel binding".into(),
        ));
    }
    let build_digest = parse_hex32(&bundle.build_digest, "build_digest")?;
    let ak_der = parse_hex(&bundle.ak_cert, "ak_cert")?;
    let quote_msg = parse_hex(&bundle.quote_msg, "quote_msg")?;
    let quote_sig = parse_hex(&bundle.quote_sig, "quote_sig")?;

    let extra = parse_attest_extra_data(&quote_msg)?;
    if extra.as_slice() != expected_binding {
        return Err(TpmVerifyError::Verify(
            "quote extraData does not match expected channel binding".into(),
        ));
    }

    let ak = Certificate::from_der(&ak_der)
        .map_err(|e| TpmVerifyError::Parse(format!("ak_cert: {e}")))?;
    verify_quote_signature(&ak, &quote_msg, &quote_sig)?;

    let identity = desktop_build_id_hash(&build_digest);
    Ok(DesktopVerdict {
        verdict: "verified".into(),
        platform: bundle.platform.clone(),
        identity_hash: hex::encode(identity),
    })
}

fn verify_quote_signature(
    ak: &Certificate,
    quote_msg: &[u8],
    quote_sig: &[u8],
) -> Result<(), TpmVerifyError> {
    if quote_sig.len() < 2 {
        return Err(TpmVerifyError::Parse("quote_sig too short".into()));
    }
    let alg = u16::from_be_bytes([quote_sig[0], quote_sig[1]]);
    let body = &quote_sig[2..];
    let spki = ak
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();

    match alg {
        TPM_ALG_ECDSA => verify_ecdsa_quote(spki, quote_msg, body)?,
        TPM_ALG_RSASSA => verify_rsa_quote(spki, quote_msg, body)?,
        other => {
            return Err(TpmVerifyError::Verify(format!(
                "unsupported TPM quote signature alg 0x{other:04x}"
            )))
        }
    }
    Ok(())
}

fn verify_ecdsa_quote(spki: &[u8], quote_msg: &[u8], sig_body: &[u8]) -> Result<(), TpmVerifyError> {
    let (r, s) = parse_tpm_ecc_signature(sig_body)?;
    let digest256 = Sha256::digest(quote_msg);
    let digest384 = Sha384::digest(quote_msg);

    if let Ok(vk) = P256Vk::from_sec1_bytes(spki) {
        let mut raw = Vec::with_capacity(r.len() + s.len());
        raw.extend_from_slice(&r);
        raw.extend_from_slice(&s);
        if let Ok(sig) = P256Sig::from_slice(&raw) {
            if vk.verify(digest256.as_slice(), &sig).is_ok() {
                return Ok(());
            }
        }
    }
    if let Ok(vk) = P384Vk::from_sec1_bytes(spki) {
        let mut raw = Vec::with_capacity(r.len() + s.len());
        raw.extend_from_slice(&r);
        raw.extend_from_slice(&s);
        let sig = P384Sig::from_slice(&raw)
            .map_err(|e| TpmVerifyError::Parse(format!("p384 sig: {e}")))?;
        vk.verify(digest384.as_slice(), &sig)
            .map_err(|e| TpmVerifyError::Verify(format!("p384 quote sig: {e}")))?;
        return Ok(());
    }
    Err(TpmVerifyError::Verify(
        "AK public key is not P-256 or P-384 ECDSA".into(),
    ))
}

fn verify_rsa_quote(spki: &[u8], quote_msg: &[u8], sig_body: &[u8]) -> Result<(), TpmVerifyError> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::pss::{Signature, VerifyingKey};
    use rsa::signature::Verifier as _;

    let sig_bytes = read_tpm2b(sig_body, 0)?.0;
    let pk = rsa::RsaPublicKey::from_pkcs1_der(spki)
        .map_err(|e| TpmVerifyError::Parse(format!("rsa ak: {e}")))?;
    let vk = VerifyingKey::<Sha256>::new(pk);
    let sig = Signature::try_from(sig_bytes.as_slice())
        .map_err(|e| TpmVerifyError::Parse(format!("rsa sig: {e}")))?;
    vk.verify(quote_msg, &sig)
        .map_err(|e| TpmVerifyError::Verify(format!("rsa quote sig: {e}")))?;
    Ok(())
}

fn parse_tpm_ecc_signature(body: &[u8]) -> Result<(Vec<u8>, Vec<u8>), TpmVerifyError> {
    let (r, off) = read_tpm2b(body, 0)?;
    let (s, _) = read_tpm2b(body, off)?;
    Ok((r, s))
}

/// Parse TPM2_ATTEST `extraData` (TPM2B_DATA) from a TPM2B_ATTEST blob.
fn parse_attest_extra_data(quote_msg: &[u8]) -> Result<Vec<u8>, TpmVerifyError> {
    if quote_msg.len() < 4 {
        return Err(TpmVerifyError::Parse("quote_msg too short".into()));
    }
    let size = u16::from_be_bytes([quote_msg[0], quote_msg[1]]) as usize;
    if quote_msg.len() < 2 + size {
        return Err(TpmVerifyError::Parse("quote_msg size mismatch".into()));
    }
    let attest = &quote_msg[2..2 + size];
    if attest.len() < 4 {
        return Err(TpmVerifyError::Parse("attest too short".into()));
    }
    let magic = u32::from_be_bytes(attest[0..4].try_into().unwrap());
    if magic != TPM_GENERATED_VALUE {
        return Err(TpmVerifyError::Verify(format!(
            "bad TPM_GENERATED magic 0x{magic:08x}"
        )));
    }
    let (_, off) = read_tpm2b(attest, 4)?; // qualifiedSigner (TPM2B_NAME)
    let (extra, _) = read_tpm2b(attest, off)?;
    Ok(extra)
}

fn read_tpm2b(buf: &[u8], mut off: usize) -> Result<(Vec<u8>, usize), TpmVerifyError> {
    if off + 2 > buf.len() {
        return Err(TpmVerifyError::Parse("truncated TPM2B".into()));
    }
    let sz = u16::from_be_bytes([buf[off], buf[off + 1]]) as usize;
    off += 2;
    if off + sz > buf.len() {
        return Err(TpmVerifyError::Parse("truncated TPM2B payload".into()));
    }
    Ok((buf[off..off + sz].to_vec(), off + sz))
}

fn parse_hex32(s: &str, field: &str) -> Result<[u8; 32], TpmVerifyError> {
    let v = parse_hex(s, field)?;
    v.as_slice()
        .try_into()
        .map_err(|_| TpmVerifyError::Parse(format!("{field} must be 32 bytes")))
}

fn parse_hex(s: &str, field: &str) -> Result<Vec<u8>, TpmVerifyError> {
    hex::decode(s.trim()).map_err(|e| TpmVerifyError::Parse(format!("{field}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_binding_mismatch() {
        let bundle = TpmClientBundle {
            version: 1,
            platform: LINUX_TPM_PLATFORM.into(),
            binding: hex::encode([1u8; 32]),
            build_digest: hex::encode([0u8; 32]),
            ak_cert: String::new(),
            quote_msg: String::new(),
            quote_sig: String::new(),
            qualifying_data: hex::encode([1u8; 32]),
        };
        let err = verify_bundle(&bundle, &[2u8; 32]).unwrap_err();
        assert!(err.to_string().contains("binding"));
    }
}
