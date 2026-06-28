//! Android KeyMint key attestation bundle (no Play Integrity / no GMS account).

use der::Decode;
use x509_cert::Certificate;

use super::{android_app_id_hash, MobileVerdict, ANDROID_PLATFORM};

const ATTESTATION_OID: &str = "1.3.6.1.4.1.11129.2.1.17";

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct AndroidKeyAttestationBundle {
    pub version: u32,
    pub platform: String,
    /// X.509 chain, leaf first (hex DER each).
    pub attestation_chain: Vec<String>,
    /// Must equal eat-pass `binding_of(blinded)` (`setAttestationChallenge` on device).
    pub binding: String,
    pub package_name: String,
    /// SHA-256 of APK signing certificate (hex, 32 bytes).
    pub signing_cert_digest: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AndroidVerifyError {
    #[error("parse: {0}")]
    Parse(String),
    #[error("verify: {0}")]
    Verify(String),
}

pub fn verify_bundle(
    bundle: &AndroidKeyAttestationBundle,
    expected_binding: &[u8; 32],
) -> Result<MobileVerdict, AndroidVerifyError> {
    if bundle.version != 1 {
        return Err(AndroidVerifyError::Verify(format!(
            "unsupported version {}",
            bundle.version
        )));
    }
    if bundle.platform != ANDROID_PLATFORM {
        return Err(AndroidVerifyError::Verify(format!(
            "expected platform {ANDROID_PLATFORM}, got {}",
            bundle.platform
        )));
    }
    let binding = parse_hex32(&bundle.binding, "binding")?;
    if &binding != expected_binding {
        return Err(AndroidVerifyError::Verify(
            "binding does not match expected channel binding".into(),
        ));
    }
    let cert_digest = parse_hex32(&bundle.signing_cert_digest, "signing_cert_digest")?;
    if bundle.attestation_chain.is_empty() {
        return Err(AndroidVerifyError::Verify(
            "attestation_chain is empty".into(),
        ));
    }

    let certs = decode_chain(&bundle.attestation_chain)?;
    verify_chain_signatures(&certs)?;

    let leaf = &certs[0];
    let ext_bytes = leaf
        .tbs_certificate
        .extensions
        .as_ref()
        .and_then(|exts| {
            exts.iter()
                .find(|e| e.extn_id.to_string() == ATTESTATION_OID)
                .map(|e| e.extn_value.as_bytes())
        })
        .ok_or_else(|| {
            AndroidVerifyError::Verify("leaf cert missing key attestation extension".into())
        })?;

    if !ext_bytes.windows(32).any(|w| w == expected_binding) {
        return Err(AndroidVerifyError::Verify(
            "attestation extension does not contain binding as attestationChallenge".into(),
        ));
    }
    if !ext_bytes
        .windows(32)
        .any(|w| w == cert_digest)
    {
        return Err(AndroidVerifyError::Verify(
            "attestation extension does not contain signing_cert_digest".into(),
        ));
    }
    if !ext_bytes
        .windows(bundle.package_name.len())
        .any(|w| w == bundle.package_name.as_bytes())
    {
        return Err(AndroidVerifyError::Verify(
            "attestation extension does not contain package_name".into(),
        ));
    }

    let app_hash = android_app_id_hash(&bundle.package_name, &cert_digest);
    Ok(MobileVerdict {
        verdict: "verified".into(),
        platform: ANDROID_PLATFORM.into(),
        app_id_hash: hex::encode(app_hash),
        package_or_bundle: bundle.package_name.clone(),
    })
}

fn decode_chain(hex_certs: &[String]) -> Result<Vec<Certificate>, AndroidVerifyError> {
    hex_certs
        .iter()
        .map(|h| {
            let der = hex::decode(h.trim())
                .map_err(|e| AndroidVerifyError::Parse(format!("cert hex: {e}")))?;
            Certificate::from_der(&der)
                .map_err(|e| AndroidVerifyError::Parse(format!("cert der: {e}")))
        })
        .collect()
}

fn verify_chain_signatures(certs: &[Certificate]) -> Result<(), AndroidVerifyError> {
    if certs.len() == 1 {
        return Ok(());
    }
    for i in 0..certs.len() - 1 {
        let subject_der = cert_der(&certs[i])?;
        let issuer_der = cert_der(&certs[i + 1])?;
        if !verify_cert_sig(&issuer_der, &subject_der)? {
            return Err(AndroidVerifyError::Verify(format!(
                "cert chain link {i} failed signature check"
            )));
        }
    }
    Ok(())
}

fn cert_der(c: &Certificate) -> Result<Vec<u8>, AndroidVerifyError> {
    use der::Encode;
    c.to_der()
        .map_err(|e| AndroidVerifyError::Parse(format!("cert der: {e}")))
}

fn verify_cert_sig(issuer_der: &[u8], subject_der: &[u8]) -> Result<bool, AndroidVerifyError> {
    use der::Encode;
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use sha2::{Digest, Sha256, Sha384};

    let issuer = Certificate::from_der(issuer_der)
        .map_err(|e| AndroidVerifyError::Parse(format!("issuer cert: {e}")))?;
    let subject = Certificate::from_der(subject_der)
        .map_err(|e| AndroidVerifyError::Parse(format!("subject cert: {e}")))?;
    let issuer_pk = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let tbs_der = subject
        .tbs_certificate
        .to_der()
        .map_err(|e| AndroidVerifyError::Parse(format!("tbs: {e}")))?;
    let sig_bytes = subject.signature.raw_bytes();
    let sig_alg = subject.signature_algorithm.oid.to_string();

    match sig_alg.as_str() {
        "1.2.840.10045.4.3.2" => {
            use p256::ecdsa::{self, VerifyingKey};
            let vk = VerifyingKey::from_sec1_bytes(issuer_pk)
                .map_err(|e| AndroidVerifyError::Parse(format!("p256 issuer: {e}")))?;
            let sig = ecdsa::DerSignature::from_bytes(sig_bytes)
                .map_err(|e| AndroidVerifyError::Parse(format!("sig: {e}")))?;
            let digest = Sha256::digest(&tbs_der);
            Ok(vk.verify_prehash(&digest, &sig).is_ok())
        }
        "1.2.840.10045.4.3.3" => {
            use p384::ecdsa::{self, VerifyingKey};
            let vk = VerifyingKey::from_sec1_bytes(issuer_pk)
                .map_err(|e| AndroidVerifyError::Parse(format!("p384 issuer: {e}")))?;
            let sig = ecdsa::DerSignature::from_bytes(sig_bytes)
                .map_err(|e| AndroidVerifyError::Parse(format!("sig: {e}")))?;
            let digest = Sha384::digest(&tbs_der);
            Ok(vk.verify_prehash(&digest, &sig).is_ok())
        }
        "1.2.840.113549.1.1.10" => {
            use rsa::pkcs1::DecodeRsaPublicKey;
            use rsa::pss::{Signature, VerifyingKey as RsaVk};
            use rsa::signature::Verifier as _;
            let pk = rsa::RsaPublicKey::from_pkcs1_der(issuer_pk)
                .map_err(|e| AndroidVerifyError::Parse(format!("rsa issuer: {e}")))?;
            let vk = RsaVk::<Sha384>::new(pk);
            let sig = Signature::try_from(sig_bytes)
                .map_err(|e| AndroidVerifyError::Parse(format!("rsa sig: {e}")))?;
            Ok(vk.verify(&tbs_der, &sig).is_ok())
        }
        other => Err(AndroidVerifyError::Parse(format!(
            "unsupported cert sig alg {other}"
        ))),
    }
}

fn parse_hex32(s: &str, field: &str) -> Result<[u8; 32], AndroidVerifyError> {
    let v = hex::decode(s.trim()).map_err(|e| AndroidVerifyError::Parse(format!("{field}: {e}")))?;
    v.as_slice()
        .try_into()
        .map_err(|_| AndroidVerifyError::Parse(format!("{field} must be 32 bytes")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_binding_mismatch() {
        let bundle = AndroidKeyAttestationBundle {
            version: 1,
            platform: ANDROID_PLATFORM.into(),
            attestation_chain: vec![],
            binding: hex::encode([1u8; 32]),
            package_name: "com.example.app".into(),
            signing_cert_digest: hex::encode([0u8; 32]),
        };
        let err = verify_bundle(&bundle, &[2u8; 32]).unwrap_err();
        assert!(err.to_string().contains("binding"));
    }
}
