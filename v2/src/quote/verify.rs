//! Platform-specific TEE quote verification.
//!
//! Verifies raw platform quotes from Nitro, SNP, and TDX:
//!   - ECDSA signature chain (P-384 for Nitro/SNP, P-256 for TDX)
//!   - Certificate chain validation back to pinned vendor root CA
//!   - report_data binding (proves specific data was committed to the quote)
//!
//! See CONSTITUTION.md: verification is the core. Without it, quotes are just bytes.

use super::Platform;
use sha2::{Digest, Sha256};

/// Verify a raw platform quote: signature chain + report_data binding.
///
/// `expected_binding` is the EAT `binding_bytes()` value committed to
/// report_data[0..32] by the producer before quote collection.
///
/// Returns Ok(measurements) if the quote is genuine and binds to the expected data.
pub fn verify_platform_quote(
    platform: Platform,
    raw_quote: &[u8],
    expected_binding: &[u8; 32],
) -> Result<Vec<(String, Vec<u8>)>, VerifyError> {
    match platform {
        #[cfg(feature = "nitro")]
        Platform::Nitro => {
            let (valid, measurements) = verify_nitro_quote(raw_quote, expected_binding)?;
            if !valid {
                return Err(VerifyError::PlatformError(
                    "Nitro: platform signature chain did not verify".into(),
                ));
            }
            Ok(measurements)
        }
        #[cfg(feature = "sev-snp")]
        Platform::SevSnp => {
            let (valid, measurements) = verify_snp_quote_raw(raw_quote, expected_binding)?;
            if !valid {
                return Err(VerifyError::PlatformError(
                    "SNP: platform signature chain did not verify".into(),
                ));
            }
            Ok(measurements)
        }
        #[cfg(feature = "tdx")]
        Platform::Tdx => {
            let (valid, measurements) = verify_tdx_quote_raw(raw_quote, expected_binding)?;
            if !valid {
                return Err(VerifyError::PlatformError(
                    "TDX: platform signature chain did not verify".into(),
                ));
            }
            Ok(measurements)
        }
        #[allow(unreachable_patterns)]
        _ => Err(VerifyError::UnsupportedPlatform(platform)),
    }
}

// ============================================================================
// X.509 cert chain helpers (shared across platforms)
// ============================================================================

/// Verify that `subject` cert was signed by `issuer` cert using ECDSA-P384.
#[cfg(feature = "sev-snp")]
fn verify_cert_chain_p384(issuer_der: &[u8], subject_der: &[u8]) -> Result<bool, VerifyError> {
    use der::{Decode, Encode};
    use p384::ecdsa::{self, signature::hazmat::PrehashVerifier};
    use sha2::Sha384;
    use x509_cert::Certificate;

    let issuer = Certificate::from_der(issuer_der)
        .map_err(|e| VerifyError::PlatformError(format!("parse issuer cert: {e}")))?;
    let subject = Certificate::from_der(subject_der)
        .map_err(|e| VerifyError::PlatformError(format!("parse subject cert: {e}")))?;

    let issuer_pk_bytes = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let vk = ecdsa::VerifyingKey::from_sec1_bytes(issuer_pk_bytes)
        .map_err(|e| VerifyError::PlatformError(format!("issuer P-384 key: {e}")))?;

    let tbs_der = subject
        .tbs_certificate
        .to_der()
        .map_err(|e| VerifyError::PlatformError(format!("re-encode TBS: {e}")))?;

    let sig_bytes = subject.signature.raw_bytes();
    let sig = ecdsa::DerSignature::from_bytes(sig_bytes)
        .map_err(|e| VerifyError::PlatformError(format!("parse cert signature: {e}")))?;

    let digest = Sha384::digest(&tbs_der);
    vk.verify_prehash(&digest, &sig)
        .map_err(|e| VerifyError::PlatformError(format!("cert chain sig verify: {e}")))?;

    Ok(true)
}

/// Verify that `subject` cert was signed by `issuer` cert using ECDSA-P256.
#[cfg(feature = "tdx")]
fn verify_cert_chain_p256(issuer_der: &[u8], subject_der: &[u8]) -> Result<bool, VerifyError> {
    use der::{Decode, Encode};
    use p256::ecdsa::{self, signature::hazmat::PrehashVerifier};
    use x509_cert::Certificate;

    let issuer = Certificate::from_der(issuer_der)
        .map_err(|e| VerifyError::PlatformError(format!("parse issuer cert: {e}")))?;
    let subject = Certificate::from_der(subject_der)
        .map_err(|e| VerifyError::PlatformError(format!("parse subject cert: {e}")))?;

    let issuer_pk_bytes = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let vk = ecdsa::VerifyingKey::from_sec1_bytes(issuer_pk_bytes)
        .map_err(|e| VerifyError::PlatformError(format!("issuer P-256 key: {e}")))?;

    let tbs_der = subject
        .tbs_certificate
        .to_der()
        .map_err(|e| VerifyError::PlatformError(format!("re-encode TBS: {e}")))?;

    let sig_bytes = subject.signature.raw_bytes();
    let sig = ecdsa::DerSignature::from_bytes(sig_bytes)
        .map_err(|e| VerifyError::PlatformError(format!("parse cert signature: {e}")))?;

    let digest = Sha256::digest(&tbs_der);
    vk.verify_prehash(&digest, &sig)
        .map_err(|e| VerifyError::PlatformError(format!("cert chain sig verify: {e}")))?;

    Ok(true)
}

// ============================================================================
// AWS Nitro Enclave verification
// ============================================================================
//
// Attestation doc is COSE_Sign1 [RFC 9052]:
//   Tag(18, [protected, unprotected, payload, signature])
//
// Crypto chain:
//   AWS Nitro Root CA (pinned)
//     → cabundle intermediates
//       → leaf certificate (in payload)
//         → COSE_Sign1 signature (ECDSA-P384 / ES384)
//
// The leaf cert's P-384 key signs the COSE Sig_structure:
//   Sig_structure = ["Signature1", protected, b"", payload]

#[cfg(feature = "nitro")]
fn verify_nitro_quote(
    raw_quote: &[u8],
    expected_binding: &[u8; 32],
) -> Result<(bool, Vec<(String, Vec<u8>)>), VerifyError> {
    use p384::ecdsa::{self, signature::hazmat::PrehashVerifier};
    use serde_cbor::Value;
    use sha2::Sha384;

    // Parse outer COSE_Sign1
    let cose: Value = serde_cbor::from_slice(raw_quote)
        .map_err(|e| VerifyError::PlatformError(format!("CBOR parse: {e}")))?;

    let arr = match &cose {
        Value::Tag(18, inner) => match inner.as_ref() {
            Value::Array(a) => a,
            _ => {
                return Err(VerifyError::PlatformError(
                    "COSE_Sign1: not array inside tag".into(),
                ))
            }
        },
        Value::Array(a) => a,
        _ => return Err(VerifyError::PlatformError("Not a COSE_Sign1".into())),
    };

    if arr.len() < 4 {
        return Err(VerifyError::PlatformError(format!(
            "COSE_Sign1 array too short: {} elements",
            arr.len()
        )));
    }

    // Extract protected header and payload bytes for signature verification
    let protected_bytes = match &arr[0] {
        Value::Bytes(b) => b.clone(),
        _ => {
            return Err(VerifyError::PlatformError(
                "protected header not bytes".into(),
            ))
        }
    };

    let payload_bytes = match &arr[2] {
        Value::Bytes(b) => b.clone(),
        _ => return Err(VerifyError::PlatformError("Payload not bytes".into())),
    };

    let cose_signature = match &arr[3] {
        Value::Bytes(b) => b.clone(),
        _ => return Err(VerifyError::PlatformError("Signature not bytes".into())),
    };

    // Parse payload CBOR map
    let payload: Value = serde_cbor::from_slice(&payload_bytes)
        .map_err(|e| VerifyError::PlatformError(format!("Payload parse: {e}")))?;

    let map = match &payload {
        Value::Map(m) => m,
        _ => return Err(VerifyError::PlatformError("Payload not a map".into())),
    };

    // Extract all fields
    let mut pcrs: Vec<(String, Vec<u8>)> = Vec::new();
    let mut user_data: Option<Vec<u8>> = None;
    let mut public_key: Option<Vec<u8>> = None;
    let mut certificate: Option<Vec<u8>> = None;
    let mut cabundle: Option<Vec<Vec<u8>>> = None;

    for (k, v) in map {
        if let Value::Text(key) = k {
            match key.as_str() {
                "pcrs" => {
                    if let Value::Map(pcr_map) = v {
                        for (idx, val) in pcr_map {
                            if let (Value::Integer(i), Value::Bytes(b)) = (idx, val) {
                                pcrs.push((format!("PCR{i}"), b.clone()));
                            }
                        }
                    }
                }
                "user_data" => {
                    if let Value::Bytes(b) = v {
                        user_data = Some(b.clone());
                    }
                }
                "public_key" => {
                    if let Value::Bytes(b) = v {
                        public_key = Some(b.clone());
                    }
                }
                "certificate" => {
                    if let Value::Bytes(b) = v {
                        certificate = Some(b.clone());
                    }
                }
                "cabundle" => {
                    if let Value::Array(certs) = v {
                        let mut bundle = Vec::new();
                        for cert in certs {
                            if let Value::Bytes(b) = cert {
                                bundle.push(b.clone());
                            }
                        }
                        cabundle = Some(bundle);
                    }
                }
                _ => {}
            }
        }
    }

    // --- Binding check: user_data[0..32] == expected_binding ---
    // user_data carries the full 64-byte report_data:
    //   [0..32]  = sha256(CT || A || X) — the binding hash
    //   [32..64] = value_x[0..32] prefix
    // Same check as SNP/TDX: first 32 bytes must match expected_binding.
    let binding_ok = match &user_data {
        Some(ud) if ud.len() >= 32 => ud[..32] == expected_binding[..],
        _ => false,
    };
    if !binding_ok {
        let got = user_data
            .as_ref()
            .map(|ud| hex::encode(&ud[..ud.len().min(32)]))
            .unwrap_or_default();
        return Err(VerifyError::PlatformError(format!(
            "Nitro: user_data binding mismatch\n  expected: {}\n  got:      {}",
            hex::encode(expected_binding),
            got
        )));
    }

    // --- COSE_Sign1 signature verification ---
    let leaf_cert_der = certificate.ok_or_else(|| {
        VerifyError::PlatformError("Nitro: no certificate in attestation doc".into())
    })?;

    // Extract P-384 public key from the leaf certificate
    let leaf_cert = {
        use der::Decode;
        x509_cert::Certificate::from_der(&leaf_cert_der)
            .map_err(|e| VerifyError::PlatformError(format!("parse leaf cert: {e}")))?
    };
    let leaf_pk_bytes = leaf_cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let leaf_vk = ecdsa::VerifyingKey::from_sec1_bytes(leaf_pk_bytes)
        .map_err(|e| VerifyError::PlatformError(format!("leaf P-384 key: {e}")))?;

    // Build COSE Sig_structure = ["Signature1", protected, b"", payload]
    let sig_structure = serde_cbor::Value::Array(vec![
        Value::Text("Signature1".to_string()),
        Value::Bytes(protected_bytes),
        Value::Bytes(vec![]), // external_aad
        Value::Bytes(payload_bytes),
    ]);
    let sig_structure_bytes = serde_cbor::to_vec(&sig_structure)
        .map_err(|e| VerifyError::PlatformError(format!("encode Sig_structure: {e}")))?;

    // Verify ECDSA-P384 signature over SHA-384(Sig_structure)
    let digest = Sha384::digest(&sig_structure_bytes);

    // COSE ES384 signature is r || s (each 48 bytes, fixed-size)
    if cose_signature.len() != 96 {
        return Err(VerifyError::PlatformError(format!(
            "Nitro: COSE signature wrong length: {} (expected 96)",
            cose_signature.len()
        )));
    }
    let sig = ecdsa::Signature::from_slice(&cose_signature)
        .map_err(|e| VerifyError::PlatformError(format!("parse COSE signature: {e}")))?;

    let cose_sig_valid = leaf_vk.verify_prehash(&digest, &sig).is_ok();
    if !cose_sig_valid {
        return Err(VerifyError::PlatformError(
            "Nitro: COSE_Sign1 signature verification FAILED".into(),
        ));
    }

    // --- Certificate chain verification ---
    let cab = cabundle.ok_or_else(|| {
        VerifyError::PlatformError("Nitro: no cabundle in attestation doc".into())
    })?;

    // cabundle is ordered root-to-leaf: cab[0] is closest to root, cab[last] issued leaf
    // Verify chain: cab[0] -> cab[1] -> ... -> cab[N] -> leaf_cert
    if !cab.is_empty() {
        // Verify cab[i] signed cab[i+1]
        for i in 0..cab.len() - 1 {
            verify_cert_chain_p384_nitro(&cab[i], &cab[i + 1])?;
        }
        // Verify cab[last] signed leaf_cert
        verify_cert_chain_p384_nitro(cab.last().unwrap(), &leaf_cert_der)?;

        // Verify root cert (cab[0]) is self-signed
        verify_cert_chain_p384_nitro(&cab[0], &cab[0])?;

        // Pin root CA fingerprint
        if !super::roots::verify_root_fingerprint(&cab[0], super::roots::AWS_NITRO_ROOT_SHA256) {
            return Err(VerifyError::PlatformError(
                "Nitro: root CA fingerprint does not match pinned AWS Nitro Root CA".into(),
            ));
        }
    }

    // Sort PCRs by index
    pcrs.sort_by(|a, b| {
        let a_num: u32 = a.0.trim_start_matches("PCR").parse().unwrap_or(99);
        let b_num: u32 = b.0.trim_start_matches("PCR").parse().unwrap_or(99);
        a_num.cmp(&b_num)
    });

    Ok((true, pcrs))
}

/// Verify cert chain link for Nitro (ECDSA-P384 certs).
#[cfg(feature = "nitro")]
fn verify_cert_chain_p384_nitro(issuer_der: &[u8], subject_der: &[u8]) -> Result<(), VerifyError> {
    use der::{Decode, Encode};
    use p384::ecdsa::{self, signature::hazmat::PrehashVerifier};
    use sha2::Sha384;
    use x509_cert::Certificate;

    let issuer = Certificate::from_der(issuer_der)
        .map_err(|e| VerifyError::PlatformError(format!("parse issuer cert: {e}")))?;
    let subject = Certificate::from_der(subject_der)
        .map_err(|e| VerifyError::PlatformError(format!("parse subject cert: {e}")))?;

    let issuer_pk_bytes = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let vk = ecdsa::VerifyingKey::from_sec1_bytes(issuer_pk_bytes)
        .map_err(|e| VerifyError::PlatformError(format!("issuer P-384 key: {e}")))?;

    let tbs_der = subject
        .tbs_certificate
        .to_der()
        .map_err(|e| VerifyError::PlatformError(format!("re-encode TBS: {e}")))?;

    let sig_bytes = subject.signature.raw_bytes();
    let sig = ecdsa::DerSignature::from_bytes(sig_bytes)
        .map_err(|e| VerifyError::PlatformError(format!("parse cert sig: {e}")))?;

    let digest = Sha384::digest(&tbs_der);
    vk.verify_prehash(&digest, &sig)
        .map_err(|e| VerifyError::PlatformError(format!("Nitro cert chain: {e}")))?;

    Ok(())
}

// ============================================================================
// AMD SEV-SNP verification
// ============================================================================
//
// Report: 1152 bytes binary.
// Signed data: bytes [0x000..0x2A0] (672 bytes)
// Signature: ECDSA-P384 at offset 0x2A0 (r||s, 48 bytes each, padded to 72 each in 512 byte field)
//
// Crypto chain: ARK (self-signed) → ASK → VCEK → report signature
// VCEK fetched from AMD KDS or embedded in cert table from SNP_GET_EXT_REPORT.

#[cfg(feature = "sev-snp")]
fn verify_snp_quote(
    raw_quote: &[u8],
    expected_binding: &[u8; 32],
) -> Result<(bool, Vec<(String, Vec<u8>)>), VerifyError> {
    use p384::ecdsa::{self, signature::hazmat::PrehashVerifier};
    use sha2::Sha384;

    // Require enough bytes to read the signature (r at 0x2A0..0x2D0, s at 0x2E8..0x318).
    // Full SNP report is 1184 bytes (0x4A0), but captured reports may be 1152 (0x480)
    // if the 32-byte response header was stripped. Either way, we need at least 0x318
    // to read the complete ECDSA-P384 signature.
    if raw_quote.len() < 0x318 {
        return Err(VerifyError::PlatformError(format!(
            "SNP report too short for signature verification: {} bytes (need >= {})",
            raw_quote.len(),
            0x318
        )));
    }

    // Parse version
    let version = u32::from_le_bytes(raw_quote[0..4].try_into().unwrap());
    if version != 2 && version != 5 {
        return Err(VerifyError::PlatformError(format!(
            "SNP report version {version}, expected 2 or 5"
        )));
    }

    // Extract MEASUREMENT (48 bytes at offset 0x090)
    let measurement = raw_quote[0x090..0x0C0].to_vec();

    // Extract REPORT_DATA (64 bytes at offset 0x050)
    let report_data = &raw_quote[0x050..0x090];

    if report_data[..32] != expected_binding[..] {
        return Err(VerifyError::PlatformError(
            "SNP: REPORT_DATA[0..32] does not match EAT binding".into(),
        ));
    }

    let host_data = raw_quote[0x0C0..0x0E0].to_vec();

    // --- ECDSA-P384 signature verification ---
    let mut sig_verified = false;
    let mut chain_verified = false;
    {
        let signed_data = &raw_quote[0x000..0x2A0];

        // Signature at 0x2A0: r (48 bytes) at +0, s (48 bytes) at +72
        // Each component is 48 bytes with 24 bytes padding after
        let r = &raw_quote[0x2A0..0x2D0];
        let s = &raw_quote[0x2E8..0x318];
        let mut sig_bytes = Vec::with_capacity(96);
        sig_bytes.extend_from_slice(r);
        sig_bytes.extend_from_slice(s);

        let sig = ecdsa::Signature::from_slice(&sig_bytes)
            .map_err(|e| VerifyError::PlatformError(format!("SNP parse signature: {e}")))?;

        let digest = Sha384::digest(signed_data);

        // Try to get VCEK from appended cert table (SNP_GET_EXT_REPORT path)
        let mut vcek_der: Option<Vec<u8>> = None;
        let mut ask_der: Option<Vec<u8>> = None;
        let mut ark_der: Option<Vec<u8>> = None;

        if raw_quote.len() > 0x480 {
            parse_snp_cert_table(raw_quote, &mut vcek_der, &mut ask_der, &mut ark_der);
        }

        // Fallback: fetch VCEK from AMD KDS if not in cert table
        if vcek_der.is_none() {
            if let Ok((product, chip_id, bl, tee, snp_ver, ucode)) =
                crate::tee::kds::extract_kds_params(raw_quote)
            {
                match crate::tee::kds::fetch_vcek(&product, &chip_id, bl, tee, snp_ver, ucode) {
                    Ok(vcek) => {
                        vcek_der = Some(vcek);
                        // Also fetch the cert chain
                        if let Ok((ask, ark)) = crate::tee::kds::fetch_cert_chain(&product) {
                            ask_der = Some(ask);
                            ark_der = Some(ark);
                        }
                    }
                    Err(e) => {
                        eprintln!("[bountynet/verify] AMD KDS fetch failed: {e}");
                    }
                }
            }
        }

        if let Some(ref vcek) = vcek_der {
            let cert = {
                use der::Decode;
                x509_cert::Certificate::from_der(vcek)
                    .map_err(|e| VerifyError::PlatformError(format!("parse VCEK: {e}")))?
            };
            let pk_bytes = cert
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes();
            let vk = ecdsa::VerifyingKey::from_sec1_bytes(pk_bytes)
                .map_err(|e| VerifyError::PlatformError(format!("VCEK P-384 key: {e}")))?;

            sig_verified = vk.verify_prehash(&digest, &sig).is_ok();
            if !sig_verified {
                return Err(VerifyError::PlatformError(
                    "SNP: report signature verification FAILED against VCEK".into(),
                ));
            }

            // Verify VCEK → ASK → ARK chain if available
            if let (Some(ref ask), Some(ref ark)) = (&ask_der, &ark_der) {
                verify_cert_chain_p384(ark, ark)?; // ARK is self-signed
                                                   // Pin AMD root fingerprint
                let version =
                    u32::from_le_bytes(raw_quote[0..4].try_into().expect("version bytes"));
                let expected_fp = if version >= 5 {
                    super::roots::AMD_ARK_GENOA_SHA256
                } else {
                    super::roots::AMD_ARK_MILAN_SHA256
                };
                if !super::roots::verify_root_fingerprint(ark, expected_fp) {
                    return Err(VerifyError::PlatformError(
                        "SNP: ARK fingerprint does not match pinned AMD root".into(),
                    ));
                }
                verify_cert_chain_p384(ark, ask)?; // ARK signed ASK
                verify_cert_chain_p384(ask, vcek)?; // ASK signed VCEK
                chain_verified = true;
            }
        }
        // If no VCEK available (KDS also failed), sig_verified stays false
    }

    let mut measurements = vec![
        ("MEASUREMENT".to_string(), measurement),
        ("HOST_DATA".to_string(), host_data),
        ("REPORT_DATA".to_string(), report_data.to_vec()),
        (
            "SIG_VERIFIED".to_string(),
            vec![if sig_verified { 1 } else { 0 }],
        ),
        (
            "CHAIN_VERIFIED".to_string(),
            vec![if chain_verified { 1 } else { 0 }],
        ),
    ];

    if raw_quote.len() > 0x4A0 || raw_quote.len() > 0x480 {
        measurements.push(("HAS_CERT_TABLE".to_string(), vec![1]));
    }

    // platform_valid reflects actual crypto verification status.
    // If VCEK or its AMD root chain are unavailable, the caller sees
    // platform_valid=false plus SIG_VERIFIED/CHAIN_VERIFIED=0.
    // Pubkey binding was already checked above (would have returned Err).
    Ok((sig_verified && chain_verified, measurements))
}

/// Parse the SNP_GET_EXT_REPORT certificate table.
/// The table appears after the 1152-byte report (+ possible padding).
/// Format: array of {guid: [u8;16], offset: u32, length: u32} entries.
#[cfg(feature = "sev-snp")]
fn parse_snp_cert_table(
    raw: &[u8],
    vcek: &mut Option<Vec<u8>>,
    ask: &mut Option<Vec<u8>>,
    ark: &mut Option<Vec<u8>>,
) {
    // Known GUIDs for SNP cert table entries
    const VCEK_GUID: [u8; 16] = [
        0x63, 0xda, 0x75, 0x8d, 0xe6, 0x64, 0x56, 0x45, 0xb4, 0x58, 0x73, 0x2a, 0x2b, 0x5d, 0xcc,
        0xf7,
    ];
    const ASK_GUID: [u8; 16] = [
        0x4a, 0xb7, 0xb3, 0x79, 0xbb, 0xac, 0x4f, 0xe4, 0xa0, 0x2f, 0x05, 0xae, 0xf3, 0x27, 0xc7,
        0x82,
    ];
    const ARK_GUID: [u8; 16] = [
        0xc0, 0xb4, 0x06, 0xa4, 0x43, 0x8f, 0x4a, 0xf3, 0xab, 0x09, 0xa6, 0xf2, 0xea, 0xb4, 0x43,
        0x74,
    ];

    // Cert table starts right after the 1184-byte report
    let table_start = 0x4A0; // 1184 bytes
    if raw.len() <= table_start + 24 {
        return;
    }

    let mut offset = table_start;
    loop {
        if offset + 24 > raw.len() {
            break;
        }
        let guid: [u8; 16] = raw[offset..offset + 16].try_into().unwrap();
        if guid == [0u8; 16] {
            break; // terminator
        }
        let data_offset =
            u32::from_le_bytes(raw[offset + 16..offset + 20].try_into().unwrap()) as usize;
        let data_length =
            u32::from_le_bytes(raw[offset + 20..offset + 24].try_into().unwrap()) as usize;

        // data_offset is relative to start of cert table data area
        let abs_offset = table_start + data_offset;
        if abs_offset + data_length <= raw.len() {
            let cert_data = raw[abs_offset..abs_offset + data_length].to_vec();
            if guid == VCEK_GUID {
                *vcek = Some(cert_data);
            } else if guid == ASK_GUID {
                *ask = Some(cert_data);
            } else if guid == ARK_GUID {
                *ark = Some(cert_data);
            }
        }

        offset += 24;
    }
}

// ============================================================================
// Intel TDX verification (DCAP)
// ============================================================================
//
// Quote v4: Header (48) + Body (584) + Signature section
//
// Signature section layout (att_key_type=2, ECDSA-P256):
//   [0:64]    ECDSA signature (r||s) over header+body, signed by AK
//   [64:128]  AK public key (x||y, 32 bytes each)
//   [128:134] CertificationData { type: u16, size: u32 }
//     type=6: QE Report Certification Data containing:
//       [0:384]     QE Report
//       [384:448]   QE Report signature (signed by PCK)
//       [448:450]   QE Auth Data size
//       [450:450+N] QE Auth Data
//       [450+N:]    Inner CertificationData { type: u16, size: u32, data }
//         type=5: PEM cert chain (PCK → Intermediate → Root)
//
// Crypto chain:
//   Intel SGX Root CA (pinned)
//     → Platform CA Intermediate
//       → PCK cert (per-CPU)
//         → QE Report signature (proves QE is genuine)
//           → AK binding: SHA256(AK_pub || QE_Auth) == QE_REPORTDATA[0:32]
//             → AK signs header+body (ECDSA-P256)

#[cfg(feature = "tdx")]
fn verify_tdx_quote(
    raw_quote: &[u8],
    expected_binding: &[u8; 32],
) -> Result<(bool, Vec<(String, Vec<u8>)>), VerifyError> {
    use p256::ecdsa::{self, signature::hazmat::PrehashVerifier};

    // TD Quote v4 minimum: 48 (header) + 584 (body) = 632 bytes
    if raw_quote.len() < 636 {
        return Err(VerifyError::PlatformError(format!(
            "TDX quote too short: {} bytes (need >= 636)",
            raw_quote.len()
        )));
    }

    // Parse header
    let version = u16::from_le_bytes(raw_quote[0..2].try_into().unwrap());
    if version != 4 && version != 5 {
        return Err(VerifyError::PlatformError(format!(
            "TDX quote version {version}, expected 4 or 5"
        )));
    }

    let tee_type = u32::from_le_bytes(raw_quote[4..8].try_into().unwrap());
    if tee_type != 0x81 {
        return Err(VerifyError::PlatformError(format!(
            "TDX tee_type 0x{tee_type:x}, expected 0x81"
        )));
    }

    // Body starts at offset 48
    let body = &raw_quote[48..632];

    // Extract measurements (TDX 1.5 / Quote v4 layout)
    let mrtd = body[136..184].to_vec();
    let rtmr0 = body[328..376].to_vec();
    let rtmr1 = body[376..424].to_vec();
    let rtmr2 = body[424..472].to_vec();
    let rtmr3 = body[472..520].to_vec();
    let report_data = &body[520..584];

    if report_data[..32] != expected_binding[..] {
        return Err(VerifyError::PlatformError(
            "TDX: REPORTDATA[0..32] does not match EAT binding".into(),
        ));
    }

    // --- Parse signature section ---
    let sig_data_size = u32::from_le_bytes(raw_quote[632..636].try_into().unwrap()) as usize;
    if raw_quote.len() < 636 + sig_data_size {
        return Err(VerifyError::PlatformError(
            "TDX: quote truncated in signature section".into(),
        ));
    }
    let sig_data = &raw_quote[636..636 + sig_data_size];

    if sig_data.len() < 134 {
        return Err(VerifyError::PlatformError(
            "TDX: signature data too short".into(),
        ));
    }

    // 1. ECDSA quote signature (r||s, 64 bytes)
    let quote_sig_bytes = &sig_data[0..64];
    let quote_sig = ecdsa::Signature::from_slice(quote_sig_bytes)
        .map_err(|e| VerifyError::PlatformError(format!("TDX parse quote sig: {e}")))?;

    // 2. AK public key (x||y, 64 bytes = uncompressed without 0x04 prefix)
    let ak_pub_xy = &sig_data[64..128];
    // Construct SEC1 uncompressed point: 0x04 || x || y
    let mut ak_sec1 = Vec::with_capacity(65);
    ak_sec1.push(0x04);
    ak_sec1.extend_from_slice(ak_pub_xy);
    let ak_vk = ecdsa::VerifyingKey::from_sec1_bytes(&ak_sec1)
        .map_err(|e| VerifyError::PlatformError(format!("TDX AK key: {e}")))?;

    // 3. Verify AK signature over header+body
    let header_body = &raw_quote[0..632];
    let hb_digest = Sha256::digest(header_body);
    let quote_sig_valid = ak_vk.verify_prehash(&hb_digest, &quote_sig).is_ok();
    if !quote_sig_valid {
        return Err(VerifyError::PlatformError(
            "TDX: quote signature verification FAILED".into(),
        ));
    }

    // 4. Parse CertificationData at offset 128
    let cert_data_type = u16::from_le_bytes(sig_data[128..130].try_into().unwrap());
    let cert_data_size = u32::from_le_bytes(sig_data[130..134].try_into().unwrap()) as usize;

    let mut qe_verified = false;
    let mut chain_verified = false;

    if cert_data_type == 6 && sig_data.len() >= 134 + cert_data_size {
        let qe_cd = &sig_data[134..134 + cert_data_size];

        if qe_cd.len() >= 450 {
            // QE Report (384 bytes)
            let qe_report = &qe_cd[0..384];
            // QE Report Signature (64 bytes)
            let qe_report_sig_bytes = &qe_cd[384..448];
            // QE Auth Data
            let qe_auth_size = u16::from_le_bytes(qe_cd[448..450].try_into().unwrap()) as usize;
            let qe_auth = if qe_cd.len() >= 450 + qe_auth_size {
                &qe_cd[450..450 + qe_auth_size]
            } else {
                &[]
            };

            // 5. Verify AK binding: SHA256(AK_pub || QE_Auth) == QE_REPORTDATA[0:32]
            let mut ak_auth_hasher = Sha256::new();
            ak_auth_hasher.update(ak_pub_xy);
            ak_auth_hasher.update(qe_auth);
            let ak_auth_hash: [u8; 32] = ak_auth_hasher.finalize().into();
            let qe_reportdata = &qe_report[320..384];

            if ak_auth_hash != qe_reportdata[..32] {
                return Err(VerifyError::PlatformError(
                    "TDX: AK not bound to QE (hash mismatch)".into(),
                ));
            }

            // 6. Parse inner CertificationData (cert chain)
            let inner_off = 450 + qe_auth_size;
            if qe_cd.len() >= inner_off + 6 {
                let inner_type =
                    u16::from_le_bytes(qe_cd[inner_off..inner_off + 2].try_into().unwrap());
                let inner_size =
                    u32::from_le_bytes(qe_cd[inner_off + 2..inner_off + 6].try_into().unwrap())
                        as usize;

                if inner_type == 5 && qe_cd.len() >= inner_off + 6 + inner_size {
                    let pem_data = &qe_cd[inner_off + 6..inner_off + 6 + inner_size];
                    let pem_str = std::str::from_utf8(pem_data).unwrap_or("");

                    // Parse PEM certs into DER
                    let der_certs = parse_pem_chain(pem_str);

                    if der_certs.len() >= 2 {
                        // der_certs[0] = PCK, der_certs[1] = Intermediate, der_certs[2] = Root
                        let pck_der = &der_certs[0];

                        // 7. Verify QE report signature with PCK cert
                        let pck_cert = {
                            use der::Decode;
                            x509_cert::Certificate::from_der(pck_der).map_err(|e| {
                                VerifyError::PlatformError(format!("parse PCK cert: {e}"))
                            })?
                        };
                        let pck_pk_bytes = pck_cert
                            .tbs_certificate
                            .subject_public_key_info
                            .subject_public_key
                            .raw_bytes();
                        let pck_vk =
                            ecdsa::VerifyingKey::from_sec1_bytes(pck_pk_bytes).map_err(|e| {
                                VerifyError::PlatformError(format!("PCK P-256 key: {e}"))
                            })?;

                        let qe_sig =
                            ecdsa::Signature::from_slice(qe_report_sig_bytes).map_err(|e| {
                                VerifyError::PlatformError(format!("parse QE sig: {e}"))
                            })?;

                        let qe_digest = Sha256::digest(qe_report);
                        qe_verified = pck_vk.verify_prehash(&qe_digest, &qe_sig).is_ok();

                        // 8. Verify cert chain
                        if der_certs.len() >= 3 {
                            let root_der = &der_certs[der_certs.len() - 1];
                            // Verify each link
                            let mut chain_ok = true;
                            for i in (0..der_certs.len() - 1).rev() {
                                if verify_cert_chain_p256(&der_certs[i + 1], &der_certs[i]).is_err()
                                {
                                    chain_ok = false;
                                    break;
                                }
                            }
                            // Verify root is self-signed
                            if chain_ok {
                                chain_ok = verify_cert_chain_p256(root_der, root_der).is_ok();
                            }
                            // Pin Intel SGX Root CA fingerprint
                            if chain_ok {
                                chain_ok = super::roots::verify_root_fingerprint(
                                    root_der,
                                    super::roots::INTEL_SGX_ROOT_SHA256,
                                );
                                if !chain_ok {
                                    eprintln!("[bountynet/verify] TDX: Intel root CA fingerprint mismatch");
                                }
                            }
                            chain_verified = chain_ok;
                        }
                    }
                }
            }

            if !qe_verified {
                return Err(VerifyError::PlatformError(
                    "TDX: QE report signature verification FAILED".into(),
                ));
            }
        }
    }

    let measurements = vec![
        ("MRTD".to_string(), mrtd),
        ("RTMR0".to_string(), rtmr0),
        ("RTMR1".to_string(), rtmr1),
        ("RTMR2".to_string(), rtmr2),
        ("RTMR3".to_string(), rtmr3),
        ("REPORTDATA".to_string(), report_data.to_vec()),
        (
            "QUOTE_SIG_VERIFIED".to_string(),
            vec![if quote_sig_valid { 1 } else { 0 }],
        ),
        (
            "QE_SIG_VERIFIED".to_string(),
            vec![if qe_verified { 1 } else { 0 }],
        ),
        (
            "CHAIN_VERIFIED".to_string(),
            vec![if chain_verified { 1 } else { 0 }],
        ),
    ];

    Ok((
        quote_sig_valid && qe_verified && chain_verified,
        measurements,
    ))
}

/// Parse a PEM certificate chain string into a Vec of DER byte vectors.
#[cfg(feature = "tdx")]
fn parse_pem_chain(pem_str: &str) -> Vec<Vec<u8>> {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;

    let mut certs = Vec::new();
    for block in pem_str.split("-----END CERTIFICATE-----") {
        if let Some(start) = block.find("-----BEGIN CERTIFICATE-----") {
            let b64 = &block[start + 27..];
            let cleaned: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
            if let Ok(der) = engine.decode(&cleaned) {
                certs.push(der);
            }
        }
    }
    certs
}

// ============================================================================
// EAT binding verification wrappers.
// These pass the already-computed EAT binding into the full platform
// verifier instead of reconstructing legacy sha256(pubkey || value_x)
// bindings.
// ============================================================================

#[cfg(feature = "sev-snp")]
fn verify_snp_quote_raw(
    raw_quote: &[u8],
    expected_binding: &[u8; 32],
) -> Result<(bool, Vec<(String, Vec<u8>)>), VerifyError> {
    verify_snp_quote(raw_quote, expected_binding)
}

#[cfg(feature = "tdx")]
fn verify_tdx_quote_raw(
    raw_quote: &[u8],
    expected_binding: &[u8; 32],
) -> Result<(bool, Vec<(String, Vec<u8>)>), VerifyError> {
    verify_tdx_quote(raw_quote, expected_binding)
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("unsupported platform: {0:?}")]
    UnsupportedPlatform(Platform),
    #[error("platform quote verification failed: {0}")]
    PlatformError(String),
}
