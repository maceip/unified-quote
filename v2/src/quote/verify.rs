//! Platform-specific TEE quote verification.
//!
//! Verifies raw platform quotes from Nitro, SNP, and TDX:
//!   - Platform signatures (P-384 for Nitro/SNP, P-256 for TDX)
//!   - Certificate chain validation back to pinned vendor root CA
//!   - report_data binding (proves specific data was committed to the quote)
//!
//! See CONSTITUTION.md: verification is the core. Without it, quotes are just bytes.

use super::Platform;
use sha2::{Digest, Sha256};

#[path = "pki.rs"]
pub(crate) mod pki;

/// Verify a raw platform quote: signature chain + report_data binding.
///
/// `expected_binding` is the EAT `binding_bytes()` value committed to
/// report_data[0..32] by the producer before quote collection.
///
/// Returns authenticated measurements after signature, PKIX, and binding checks.
/// This primitive does not appraise Intel/AMD TCB collateral. Admission callers
/// must use `verify_platform_quote_for_admission` with independent policy.
pub fn verify_platform_quote(
    platform: Platform,
    raw_quote: &[u8],
    expected_binding: &[u8; 32],
) -> Result<Vec<(String, Vec<u8>)>, VerifyError> {
    let now = trusted_now()?;
    verify_platform_quote_at(platform, raw_quote, expected_binding, now)
}

/// Cryptographic verification at an explicitly supplied trusted clock. Intended
/// for archival interoperability checks, not current platform admission.
/// The caller must not take this time from untrusted evidence.
pub fn verify_platform_quote_at(
    platform: Platform,
    raw_quote: &[u8],
    expected_binding: &[u8; 32],
    now: u64,
) -> Result<Vec<(String, Vec<u8>)>, VerifyError> {
    if raw_quote.is_empty() || raw_quote.len() > 8 * 1024 * 1024 {
        return Err(VerifyError::PlatformError(
            "CPU quote size outside limit".into(),
        ));
    }
    match platform {
        #[cfg(feature = "nitro")]
        Platform::Nitro => {
            let (valid, measurements) = verify_nitro_quote(raw_quote, expected_binding, now)?;
            if !valid {
                return Err(VerifyError::PlatformError(
                    "Nitro: platform signature chain did not verify".into(),
                ));
            }
            Ok(measurements)
        }
        #[cfg(feature = "sev-snp")]
        Platform::SevSnp => {
            let (valid, measurements) = verify_snp_quote(raw_quote, expected_binding, now, None)?;
            if !valid {
                return Err(VerifyError::PlatformError(
                    "SNP: platform signature chain did not verify".into(),
                ));
            }
            Ok(measurements)
        }
        #[cfg(feature = "tdx")]
        Platform::Tdx => {
            let (valid, measurements) = verify_tdx_quote(raw_quote, expected_binding, now)?;
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

/// Independently signed vendor collateral. No network retrieval is performed by
/// admission verification; supply bounded captured collateral from a trusted service.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(
    tag = "platform",
    content = "collateral",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum CpuCollateral {
    #[cfg(feature = "tdx")]
    IntelTdx(super::tdx_collateral::TdxCollateral),
    #[cfg(feature = "sev-snp")]
    AmdSnp(super::snp_collateral::SnpCollateral),
}

/// Verifier-owned minimum security versions; never deserialize this policy from
/// the attester's bundle or confuse it with vendor-signed collateral.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(
    tag = "platform",
    content = "policy",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum CpuTcbPolicy {
    #[cfg(feature = "tdx")]
    IntelTdx {
        minimum_tcb_evaluation_data_number: u64,
    },
    #[cfg(feature = "sev-snp")]
    AmdSnp(super::snp_collateral::SnpTcbPolicy),
}

/// Current-clock CPU admission: quote authenticity and nonce/key binding plus
/// authenticated, fresh vendor collateral and independent TCB policy.
pub fn verify_platform_quote_for_admission(
    platform: Platform,
    raw_quote: &[u8],
    expected_binding: &[u8; 32],
    collateral: Option<&CpuCollateral>,
    policy: Option<&CpuTcbPolicy>,
) -> Result<Vec<(String, Vec<u8>)>, VerifyError> {
    if raw_quote.is_empty() || raw_quote.len() > 8 * 1024 * 1024 {
        return Err(VerifyError::PlatformError(
            "CPU quote size outside limit".into(),
        ));
    }
    let now = trusted_now()?;
    match platform {
        #[cfg(feature = "nitro")]
        Platform::Nitro => {
            if collateral.is_some() || policy.is_some() {
                return Err(VerifyError::PlatformError(
                    "CPU collateral/policy platform mismatch for Nitro".into(),
                ));
            }
            let measurements =
                verify_platform_quote_at(platform, raw_quote, expected_binding, now)?;
            if !measurements
                .iter()
                .any(|(name, value)| name == "PCR0" && value.iter().any(|b| *b != 0))
            {
                return Err(VerifyError::PlatformError(
                    "Nitro debug/zero launch measurement is forbidden".into(),
                ));
            }
            Ok(measurements)
        }
        #[cfg(feature = "tdx")]
        Platform::Tdx => {
            let (
                Some(CpuCollateral::IntelTdx(collateral)),
                Some(CpuTcbPolicy::IntelTdx {
                    minimum_tcb_evaluation_data_number,
                }),
            ) = (collateral, policy)
            else {
                return Err(VerifyError::PlatformError(
                    "TDX admission requires Intel collateral and independent TCB policy".into(),
                ));
            };
            if *minimum_tcb_evaluation_data_number == 0 {
                return Err(VerifyError::PlatformError(
                    "TDX TCB evaluation floor must be nonzero".into(),
                ));
            }
            let measurements =
                verify_platform_quote_at(platform, raw_quote, expected_binding, now)?;
            if raw_quote[168] & 1 != 0
                || !measurements
                    .iter()
                    .any(|(name, value)| name == "MRTD" && value.iter().any(|b| *b != 0))
            {
                return Err(VerifyError::PlatformError(
                    "TDX debug/zero launch measurement is forbidden".into(),
                ));
            }
            super::tdx_collateral::appraise_tdx(
                raw_quote,
                collateral,
                now,
                *minimum_tcb_evaluation_data_number,
            )
            .map_err(pki_error)?;
            Ok(measurements)
        }
        #[cfg(feature = "sev-snp")]
        Platform::SevSnp => {
            let (Some(CpuCollateral::AmdSnp(collateral)), Some(CpuTcbPolicy::AmdSnp(policy))) =
                (collateral, policy)
            else {
                return Err(VerifyError::PlatformError(
                    "SNP admission requires AMD collateral and independent TCB policy".into(),
                ));
            };
            collateral.validate_bounds().map_err(pki_error)?;
            policy.validate().map_err(pki_error)?;
            let (valid, measurements) = verify_snp_quote(
                raw_quote,
                expected_binding,
                now,
                Some((&collateral.certificate_chain, policy.product.name())),
            )?;
            if !valid {
                return Err(VerifyError::PlatformError(
                    "SNP quote signature/chain did not verify".into(),
                ));
            }
            if !measurements
                .iter()
                .any(|(name, value)| name == "MEASUREMENT" && value.iter().any(|b| *b != 0))
            {
                return Err(VerifyError::PlatformError(
                    "SNP zero launch measurement is forbidden".into(),
                ));
            }
            super::snp_collateral::appraise_snp(raw_quote, collateral, policy, now)
                .map_err(pki_error)?;
            Ok(measurements)
        }
        #[allow(unreachable_patterns)]
        _ => Err(VerifyError::UnsupportedPlatform(platform)),
    }
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
    now: u64,
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

    if arr.len() != 4 {
        return Err(VerifyError::PlatformError(format!(
            "COSE_Sign1 must have exactly four elements: {} elements",
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
    let protected: Value = serde_cbor::from_slice(&protected_bytes)
        .map_err(|e| VerifyError::PlatformError(format!("Nitro protected header: {e}")))?;
    match protected {
        Value::Map(m)
            if m.len() == 1 && m.get(&Value::Integer(1)) == Some(&Value::Integer(-35)) => {}
        _ => {
            return Err(VerifyError::PlatformError(
                "Nitro requires protected ES384 and no unsupported headers".into(),
            ))
        }
    }
    if !matches!(&arr[1], Value::Map(m) if m.is_empty()) {
        return Err(VerifyError::PlatformError(
            "Nitro unsupported unprotected COSE headers".into(),
        ));
    }

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
    let mut certificate: Option<Vec<u8>> = None;
    let mut cabundle: Option<Vec<Vec<u8>>> = None;

    for (k, v) in map {
        if let Value::Text(key) = k {
            match key.as_str() {
                "pcrs" => {
                    if let Value::Map(pcr_map) = v {
                        for (idx, val) in pcr_map {
                            if let (Value::Integer(i), Value::Bytes(b)) = (idx, val) {
                                if !(0..=31).contains(i) || b.len() != 48 {
                                    return Err(VerifyError::PlatformError(
                                        "Nitro invalid PCR index/digest width".into(),
                                    ));
                                }
                                pcrs.push((format!("PCR{i}"), b.clone()));
                            } else {
                                return Err(VerifyError::PlatformError(
                                    "Nitro invalid PCR entry".into(),
                                ));
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
                        if b.len() > 4096 {
                            return Err(VerifyError::PlatformError(
                                "Nitro public key exceeds limit".into(),
                            ));
                        }
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
                            } else {
                                return Err(VerifyError::PlatformError(
                                    "Nitro certificate bundle entry is not DER bytes".into(),
                                ));
                            }
                        }
                        cabundle = Some(bundle);
                    }
                }
                _ => {}
            }
        }
    }
    if map.get(&Value::Text("digest".into())) != Some(&Value::Text("SHA384".into()))
        || !pcrs.iter().any(|(name, _)| name == "PCR0")
    {
        return Err(VerifyError::PlatformError(
            "Nitro missing SHA384/PCR0 claims".into(),
        ));
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

    // Never let an empty bundle skip the pinned-root check.
    if cab.is_empty() {
        return Err(VerifyError::PlatformError(
            "Nitro: empty certificate bundle".into(),
        ));
    }
    let mut chain = vec![leaf_cert_der];
    chain.extend(cab.into_iter().rev());
    pki::validate_chain(
        &chain,
        super::roots::AWS_NITRO_ROOT_SHA256,
        now,
        pki::Curve::P384,
    )
    .map_err(pki_error)?;

    // Sort PCRs by index
    pcrs.sort_by(|a, b| {
        let a_num: u32 = a.0.trim_start_matches("PCR").parse().unwrap_or(99);
        let b_num: u32 = b.0.trim_start_matches("PCR").parse().unwrap_or(99);
        a_num.cmp(&b_num)
    });

    // Return only after the COSE signature and pinned chain were verified.
    if let Some(user_data) = user_data {
        pcrs.push(("USER_DATA".into(), user_data));
    }
    Ok((true, pcrs))
}

// ============================================================================
// AMD SEV-SNP verification
// ============================================================================
//
// Report: 1184 bytes binary.
// Signed data: bytes [0x000..0x2A0] (672 bytes)
// Signature: ECDSA-P384 at offset 0x2A0 (r||s, 48 bytes each, padded to 72 each in 512 byte field)
//
// Crypto chain: ARK (self-signed) → ASK → VCEK → report signature
// VCEK fetched from AMD KDS or embedded in cert table from SNP_GET_EXT_REPORT.

#[cfg(feature = "sev-snp")]
fn verify_snp_quote(
    raw_quote: &[u8],
    expected_binding: &[u8; 32],
    now: u64,
    explicit_chain: Option<(&[Vec<u8>], &str)>,
) -> Result<(bool, Vec<(String, Vec<u8>)>), VerifyError> {
    use p384::ecdsa::{self, signature::hazmat::PrehashVerifier};
    use sha2::Sha384;

    // The SNP report structure itself is exactly 1184 bytes, before the
    // optional certificate table. Stripped transport headers do not shorten it.
    if raw_quote.len() < 0x4a0 {
        return Err(VerifyError::PlatformError(format!(
            "SNP report too short for signature verification: {} bytes (need >= {})",
            raw_quote.len(),
            0x4a0
        )));
    }

    // Parse version
    let version = u32::from_le_bytes(raw_quote[0..4].try_into().unwrap());
    if version != 2 && version != 5 {
        return Err(VerifyError::PlatformError(format!(
            "SNP report version {version}, expected 2 or 5"
        )));
    }

    let signature_algorithm = u32::from_le_bytes(raw_quote[0x34..0x38].try_into().unwrap());
    let key_info = u32::from_le_bytes(raw_quote[0x48..0x4c].try_into().unwrap());
    if signature_algorithm != 1 || ((key_info >> 2) & 7) > 1 || key_info & !0x1f != 0 {
        return Err(VerifyError::PlatformError(
            "SNP unsupported signature algorithm/signing-key encoding".into(),
        ));
    }
    if raw_quote[0x2d0..0x2e8]
        .iter()
        .chain(&raw_quote[0x318..0x4a0])
        .any(|b| *b != 0)
    {
        return Err(VerifyError::PlatformError(
            "SNP nonzero reserved signature bytes".into(),
        ));
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

        // Signature at 0x2A0: r (72-byte field) then s (72-byte field at +72).
        // For P-384 each scalar occupies the low 48 bytes — and AMD stores them
        // LITTLE-ENDIAN. The `ecdsa` crate wants big-endian r||s, so reverse each.
        let mut r = raw_quote[0x2A0..0x2D0].to_vec();
        let mut s = raw_quote[0x2E8..0x318].to_vec();
        r.reverse();
        s.reverse();
        let mut sig_bytes = Vec::with_capacity(96);
        sig_bytes.extend_from_slice(&r);
        sig_bytes.extend_from_slice(&s);

        let sig = ecdsa::Signature::from_slice(&sig_bytes)
            .map_err(|e| VerifyError::PlatformError(format!("SNP parse signature: {e}")))?;

        let digest = Sha384::digest(signed_data);

        // Determine the report's signing-key kind. Offset 0x48, key_info,
        // bits [4:2]: 0 = VCEK (per-chip), 1 = VLEK (cloud-provisioned). AWS and
        // Azure confidential VMs sign with VLEK, so a verifier that only knows
        // VCEK-by-chip_id will always fail against the AMD root on those clouds.
        let key_info = u32::from_le_bytes(raw_quote[0x48..0x4C].try_into().unwrap());
        let is_vlek = ((key_info >> 2) & 0x7) == 1;

        // Leaf endorsement cert (VCEK or VLEK) from the appended cert table
        // (SNP_GET_EXT_REPORT / configfs-tsm auxblob path), plus any intermediates.
        let mut vcek_der: Option<Vec<u8>> = None;
        let mut vlek_der: Option<Vec<u8>> = None;
        let mut ask_der: Option<Vec<u8>> = None;
        let mut ark_der: Option<Vec<u8>> = None;

        if raw_quote.len() > 0x4A0 {
            parse_snp_cert_table(
                raw_quote,
                &mut vcek_der,
                &mut vlek_der,
                &mut ask_der,
                &mut ark_der,
            )?;
        }

        if let Some((chain, _)) = explicit_chain {
            if chain.len() != 3 {
                return Err(VerifyError::PlatformError(
                    "SNP requires leaf/intermediate/root collateral chain".into(),
                ));
            }
            let supplied_leaf = if is_vlek { &vlek_der } else { &vcek_der };
            if supplied_leaf.as_ref().is_some_and(|v| v != &chain[0])
                || ask_der.as_ref().is_some_and(|v| v != &chain[1])
                || ark_der.as_ref().is_some_and(|v| v != &chain[2])
            {
                return Err(VerifyError::PlatformError(
                    "SNP embedded/collateral certificate paths disagree".into(),
                ));
            }
            if is_vlek {
                vlek_der = Some(chain[0].clone());
            } else {
                vcek_der = Some(chain[0].clone());
            }
            ask_der = Some(chain[1].clone());
            ark_der = Some(chain[2].clone());
        }
        let product = match explicit_chain {
            Some((_, product)) => product,
            None => crate::tee::kds::snp_product(raw_quote).map_err(VerifyError::PlatformError)?,
        };

        if is_vlek {
            // AWS/Azure ship only the VLEK leaf inline; its intermediate (ASVK)
            // and root (ARK) come from AMD's /vlek/v1/{product}/cert_chain.
            // There is no by-chip_id fallback for VLEK (chip_id is masked).
            if ask_der.is_none() || ark_der.is_none() {
                match crate::tee::kds::fetch_cert_chain_kind(product, "vlek") {
                    Ok((ask, ark)) => {
                        ask_der.get_or_insert(ask);
                        ark_der.get_or_insert(ark);
                    }
                    Err(e) => eprintln!("[uq/verify] AMD KDS vlek cert_chain fetch failed: {e}"),
                }
            }
        } else if vcek_der.is_none() {
            // VCEK path: fetch the per-chip VCEK + chain from KDS.
            if let Ok((product, chip_id, bl, tee, snp_ver, ucode)) =
                crate::tee::kds::extract_kds_params(raw_quote)
            {
                match crate::tee::kds::fetch_vcek(&product, &chip_id, bl, tee, snp_ver, ucode) {
                    Ok(vcek) => {
                        vcek_der = Some(vcek);
                        if let Ok((ask, ark)) = crate::tee::kds::fetch_cert_chain(&product) {
                            ask_der = Some(ask);
                            ark_der = Some(ark);
                        }
                    }
                    Err(e) => {
                        eprintln!("[uq/verify] AMD KDS fetch failed: {e}");
                    }
                }
            }
        }

        // The endorsement key that actually signed this report.
        let leaf_der = if is_vlek {
            vlek_der.as_ref()
        } else {
            vcek_der.as_ref()
        };

        if let Some(leaf) = leaf_der {
            let cert = {
                use der::Decode;
                x509_cert::Certificate::from_der(leaf).map_err(|e| {
                    VerifyError::PlatformError(format!("parse endorsement cert: {e}"))
                })?
            };
            let pk_bytes = cert
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes();
            let vk = ecdsa::VerifyingKey::from_sec1_bytes(pk_bytes)
                .map_err(|e| VerifyError::PlatformError(format!("endorsement P-384 key: {e}")))?;

            sig_verified = vk.verify_prehash(&digest, &sig).is_ok();
            if !sig_verified {
                return Err(VerifyError::PlatformError(
                    "SNP: report signature verification FAILED against endorsement key".into(),
                ));
            }

            // Verify leaf → ASK/ASVK → ARK chain if available. The ARK root is
            // shared across the VCEK and VLEK chains for a product line.
            if let (Some(ref ask), Some(ref ark)) = (&ask_der, &ark_der) {
                // Pin to the ARK for the exact product line. An unrecognized
                // product is a hard error — we will not silently fall back to a
                // different vendor root (that would let a Turin/other quote be
                // checked against the Milan root and rejected for the wrong reason).
                let expected_fp = match product {
                    "Milan" => super::roots::AMD_ARK_MILAN_SHA256,
                    "Genoa" => super::roots::AMD_ARK_GENOA_SHA256,
                    "Turin" => super::roots::AMD_ARK_TURIN_SHA256,
                    other => {
                        return Err(VerifyError::PlatformError(format!(
                            "SNP: no pinned AMD ARK for product line '{other}'"
                        )));
                    }
                };
                if !super::roots::verify_root_fingerprint(ark, expected_fp) {
                    return Err(VerifyError::PlatformError(
                        "SNP: ARK fingerprint does not match pinned AMD root".into(),
                    ));
                }
                pki::validate_chain(
                    &[leaf.clone(), ask.clone(), ark.clone()],
                    expected_fp,
                    now,
                    pki::Curve::AmdEndorsement,
                )
                .map_err(pki_error)?;
                chain_verified = true;
            }
        }
        // If no endorsement cert available, sig_verified stays false
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

    if raw_quote.len() > 0x4A0 {
        measurements.push(("HAS_CERT_TABLE".to_string(), vec![1]));
    }

    // platform_valid reflects actual crypto verification status.
    // If VCEK or its AMD root chain are unavailable, the caller sees
    // platform_valid=false plus SIG_VERIFIED/CHAIN_VERIFIED=0.
    // Pubkey binding was already checked above (would have returned Err).
    Ok((sig_verified && chain_verified, measurements))
}

/// Parse the SNP_GET_EXT_REPORT certificate table.
/// The table appears after the 1184-byte report.
/// Format: array of {guid: [u8;16], offset: u32, length: u32} entries.
#[cfg(feature = "sev-snp")]
fn parse_snp_cert_table(
    raw: &[u8],
    vcek: &mut Option<Vec<u8>>,
    vlek: &mut Option<Vec<u8>>,
    ask: &mut Option<Vec<u8>>,
    ark: &mut Option<Vec<u8>>,
) -> Result<(), VerifyError> {
    // AMD GHCB 56421 rev2.04 §4.1.8.1: RFC4122 canonical UUID bytes.
    // VCEK 63da758d-e664-4564-adc5-f4b93be8accd, ARK
    // c0b406a4-a803-4952-9743-3fb6014cd0ae. No UEFI GUID endian swap.
    const VCEK_GUID: [u8; 16] = [
        0x63, 0xda, 0x75, 0x8d, 0xe6, 0x64, 0x45, 0x64, 0xad, 0xc5, 0xf4, 0xb9, 0x3b, 0xe8, 0xac,
        0xcd,
    ];
    // VLEK (Versioned Loaded Endorsement Key) — used by AWS / Azure CVMs.
    // GUID a8074bc2-a25a-483e-aae6-39c045a0b8a1, stored in canonical UUID byte order.
    const VLEK_GUID: [u8; 16] = [
        0xa8, 0x07, 0x4b, 0xc2, 0xa2, 0x5a, 0x48, 0x3e, 0xaa, 0xe6, 0x39, 0xc0, 0x45, 0xa0, 0xb8,
        0xa1,
    ];
    const ASK_GUID: [u8; 16] = [
        0x4a, 0xb7, 0xb3, 0x79, 0xbb, 0xac, 0x4f, 0xe4, 0xa0, 0x2f, 0x05, 0xae, 0xf3, 0x27, 0xc7,
        0x82,
    ];
    const ARK_GUID: [u8; 16] = [
        0xc0, 0xb4, 0x06, 0xa4, 0xa8, 0x03, 0x49, 0x52, 0x97, 0x43, 0x3f, 0xb6, 0x01, 0x4c, 0xd0,
        0xae,
    ];

    // Cert table starts right after the 1184-byte report
    let table_start = 0x4A0; // 1184 bytes
    if raw.len() == table_start {
        return Ok(());
    }
    if raw.len() < table_start + 24 {
        return Err(VerifyError::PlatformError(
            "SNP truncated certificate table".into(),
        ));
    }

    let mut offset = table_start;
    let mut seen = std::collections::HashSet::new();
    let mut ranges = Vec::new();
    loop {
        if offset + 24 > raw.len() {
            return Err(VerifyError::PlatformError(
                "SNP unterminated certificate table".into(),
            ));
        }
        let guid: [u8; 16] = raw[offset..offset + 16].try_into().unwrap();
        if guid == [0u8; 16] {
            if raw[offset + 16..offset + 24].iter().any(|v| *v != 0) {
                return Err(VerifyError::PlatformError(
                    "SNP invalid table terminator".into(),
                ));
            }
            break;
        }
        if !seen.insert(guid) || seen.len() > 32 {
            return Err(VerifyError::PlatformError(
                "SNP duplicate/excessive certificate table entries".into(),
            ));
        }
        let data_offset =
            u32::from_le_bytes(raw[offset + 16..offset + 20].try_into().unwrap()) as usize;
        let data_length =
            u32::from_le_bytes(raw[offset + 20..offset + 24].try_into().unwrap()) as usize;

        // data_offset is relative to start of cert table data area
        let abs_offset = table_start
            .checked_add(data_offset)
            .ok_or_else(|| VerifyError::PlatformError("SNP certificate offset overflow".into()))?;
        if data_length == 0
            || data_length > 256 * 1024
            || abs_offset < offset + 24
            || data_length > raw.len().saturating_sub(abs_offset)
        {
            return Err(VerifyError::PlatformError(
                "SNP certificate table range invalid".into(),
            ));
        }
        ranges.push((abs_offset, abs_offset + data_length));
        {
            let cert_data = raw[abs_offset..abs_offset + data_length].to_vec();
            if guid == VCEK_GUID {
                *vcek = Some(cert_data);
            } else if guid == VLEK_GUID {
                *vlek = Some(cert_data);
            } else if guid == ASK_GUID {
                *ask = Some(cert_data);
            } else if guid == ARK_GUID {
                *ark = Some(cert_data);
            }
        }

        offset += 24;
    }
    ranges.sort_unstable();
    let mut end = offset + 24; // Payloads cannot overlap table entries/terminator.
    for (start, stop) in ranges {
        if start < end {
            return Err(VerifyError::PlatformError(
                "SNP overlapping certificate table ranges".into(),
            ));
        }
        end = stop;
    }
    Ok(())
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
    now: u64,
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
    if version != 4 {
        return Err(VerifyError::PlatformError(format!(
            "TDX quote version {version}, only v4 is supported"
        )));
    }

    if raw_quote[2..4] != [2, 0] {
        return Err(VerifyError::PlatformError(
            "TDX unsupported attestation key type".into(),
        ));
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
    if sig_data_size != raw_quote.len() - 636 {
        return Err(VerifyError::PlatformError(
            "TDX: quote signature section length mismatch".into(),
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

    if cert_data_type != 6 || cert_data_size != sig_data.len() - 134 {
        return Err(VerifyError::PlatformError(
            "TDX unsupported/trailing certification data".into(),
        ));
    }
    if cert_data_type == 6 {
        let qe_cd = &sig_data[134..134 + cert_data_size];

        if qe_cd.len() >= 450 {
            // QE Report (384 bytes)
            let qe_report = &qe_cd[0..384];
            // QE Report Signature (64 bytes)
            let qe_report_sig_bytes = &qe_cd[384..448];
            // QE Auth Data
            let qe_auth_size = u16::from_le_bytes(qe_cd[448..450].try_into().unwrap()) as usize;
            if qe_auth_size > qe_cd.len() - 450 {
                return Err(VerifyError::PlatformError(
                    "TDX truncated QE authentication data".into(),
                ));
            }
            let qe_auth = &qe_cd[450..450 + qe_auth_size];

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

                if inner_type != 5 || inner_size != qe_cd.len() - inner_off - 6 {
                    return Err(VerifyError::PlatformError(
                        "TDX unsupported/trailing PCK certification data".into(),
                    ));
                }
                if inner_type == 5 {
                    let pem_data = &qe_cd[inner_off + 6..inner_off + 6 + inner_size];
                    let der_certs = pki::parse_pem_chain(pem_data).map_err(pki_error)?;

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
                            pki::validate_chain(
                                &der_certs,
                                super::roots::INTEL_SGX_ROOT_SHA256,
                                now,
                                pki::Curve::P256,
                            )
                            .map_err(pki_error)?;
                            chain_verified = true;
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

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("unsupported platform: {0:?}")]
    UnsupportedPlatform(Platform),
    #[error("platform quote verification failed: {0}")]
    PlatformError(String),
}

fn trusted_now() -> Result<u64, VerifyError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|e| VerifyError::PlatformError(format!("invalid verifier clock: {e}")))
}
fn pki_error(error: anyhow::Error) -> VerifyError {
    VerifyError::PlatformError(format!("CPU PKIX: {error:#}"))
}

#[cfg(test)]
mod security_tests {
    use super::*;

    #[cfg(feature = "nitro")]
    #[test]
    fn attacker_signed_nitro_document_cannot_bypass_root_with_empty_cabundle() {
        use p384::{
            ecdsa::{signature::Signer, Signature, SigningKey},
            pkcs8::DecodePrivateKey,
        };
        use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P384_SHA384};
        use serde_cbor::Value as V;
        let key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let cert = CertificateParams::default().self_signed(&key).unwrap();
        let binding = [37; 32];
        let payload = V::Map(
            [
                (V::Text("digest".into()), V::Text("SHA384".into())),
                (
                    V::Text("pcrs".into()),
                    V::Map([(V::Integer(0), V::Bytes(vec![1; 48]))].into()),
                ),
                (V::Text("user_data".into()), V::Bytes(binding.to_vec())),
                (V::Text("certificate".into()), V::Bytes(cert.der().to_vec())),
                (V::Text("cabundle".into()), V::Array(vec![])),
            ]
            .into(),
        );
        let payload = serde_cbor::to_vec(&payload).unwrap();
        let protected =
            serde_cbor::to_vec(&V::Map([(V::Integer(1), V::Integer(-35))].into())).unwrap();
        let signed = serde_cbor::to_vec(&V::Array(vec![
            V::Text("Signature1".into()),
            V::Bytes(protected.clone()),
            V::Bytes(vec![]),
            V::Bytes(payload.clone()),
        ]))
        .unwrap();
        let signer = SigningKey::from_pkcs8_der(&key.serialize_der()).unwrap();
        let sig: Signature = signer.sign(&signed);
        let doc = serde_cbor::to_vec(&V::Array(vec![
            V::Bytes(protected),
            V::Map(Default::default()),
            V::Bytes(payload),
            V::Bytes(sig.to_bytes().to_vec()),
        ]))
        .unwrap();
        let err = verify_platform_quote_at(Platform::Nitro, &doc, &binding, 1_791_849_600)
            .unwrap_err()
            .to_string();
        assert!(err.contains("empty certificate bundle"), "{err}");
    }

    #[cfg(feature = "sev-snp")]
    #[test]
    fn authentic_amd_signature_verifies_and_unsigned_claim_mutation_fails() {
        let report = include_bytes!("../../testdata/snp-collateral/google-milan-debug-report.bin");
        let mut chain =
            vec![include_bytes!("../../testdata/snp-collateral/google-milan-vcek.der").to_vec()];
        chain.extend(
            pki::parse_pem_chain(include_bytes!(
                "../../testdata/snp-collateral/amd-milan-chain.pem"
            ))
            .unwrap(),
        );
        let binding = report[0x50..0x70].try_into().unwrap();
        assert!(
            verify_snp_quote(report, &binding, 1_791_849_600, Some((&chain, "Milan")))
                .unwrap()
                .0
        );
        let mut bad = report.to_vec();
        bad[10] &= !8;
        assert!(verify_snp_quote(&bad, &binding, 1_791_849_600, Some((&chain, "Milan"))).is_err());
        for end in [0, 671, 792, 1152, 1183] {
            assert!(verify_snp_quote(
                &report[..end],
                &binding,
                1_791_849_600,
                Some((&chain, "Milan"))
            )
            .is_err());
        }
        let mut bad = report.to_vec();
        bad[0x34] = 2;
        assert!(verify_snp_quote(&bad, &binding, 1_791_849_600, Some((&chain, "Milan"))).is_err());
        let mut bad = report.to_vec();
        bad[0x318] = 1;
        assert!(verify_snp_quote(&bad, &binding, 1_791_849_600, Some((&chain, "Milan"))).is_err());
    }

    #[cfg(feature = "sev-snp")]
    #[test]
    fn authentic_amd_certificates_parse_with_published_cert_table_uuid_bytes() {
        // Repackage unchanged public report/certificates into the Linux SNP
        // auxiliary table. UUIDs are the AMD GHCB/primary ABI registry values.
        let report = include_bytes!("../../testdata/snp-collateral/google-milan-debug-report.bin");
        let mut chain =
            vec![include_bytes!("../../testdata/snp-collateral/google-milan-vcek.der").to_vec()];
        chain.extend(
            pki::parse_pem_chain(include_bytes!(
                "../../testdata/snp-collateral/amd-milan-chain.pem"
            ))
            .unwrap(),
        );
        let ids = [
            "63da758de6644564adc5f4b93be8accd",
            "4ab7b379bbac4fe4a02f05aef327c782",
            "c0b406a4a803495297433fb6014cd0ae",
        ];
        let mut raw = report.to_vec();
        raw.resize(1184 + 4 * 24, 0);
        for (index, (id, cert)) in ids.iter().zip(&chain).enumerate() {
            let start = 1184 + index * 24;
            raw[start..start + 16].copy_from_slice(&hex::decode(id).unwrap());
            let offset = (raw.len() - 1184) as u32;
            raw[start + 16..start + 20].copy_from_slice(&offset.to_le_bytes());
            raw[start + 20..start + 24].copy_from_slice(&(cert.len() as u32).to_le_bytes());
            raw.extend_from_slice(cert);
        }
        let (mut vcek, mut vlek, mut ask, mut ark) = (None, None, None, None);
        parse_snp_cert_table(&raw, &mut vcek, &mut vlek, &mut ask, &mut ark).unwrap();
        assert_eq!(vcek.as_ref(), Some(&chain[0]));
        assert_eq!(ask.as_ref(), Some(&chain[1]));
        assert_eq!(ark.as_ref(), Some(&chain[2]));
        assert!(vlek.is_none());
        let binding = report[0x50..0x70].try_into().unwrap();
        assert!(
            verify_snp_quote(&raw, &binding, 1_791_849_600, Some((&chain, "Milan")))
                .unwrap()
                .0
        );
        let mut duplicate = raw.clone();
        let first = duplicate[1184..1200].to_vec();
        duplicate[1208..1224].copy_from_slice(&first);
        assert!(
            parse_snp_cert_table(&duplicate, &mut vcek, &mut vlek, &mut ask, &mut ark).is_err()
        );
        let mut overlap = raw;
        overlap[1200..1204].copy_from_slice(&24u32.to_le_bytes());
        assert!(parse_snp_cert_table(&overlap, &mut vcek, &mut vlek, &mut ask, &mut ark).is_err());
    }

    #[cfg(feature = "tdx")]
    #[test]
    fn tdx_v5_is_not_interpreted_as_v4_and_missing_collateral_never_admits() {
        let mut raw = vec![0u8; 636];
        raw[..2].copy_from_slice(&5u16.to_le_bytes());
        raw[2] = 2;
        raw[4] = 0x81;
        let err = verify_platform_quote_at(Platform::Tdx, &raw, &[0; 32], 1_791_849_600)
            .unwrap_err()
            .to_string();
        assert!(err.contains("version"), "{err}");
        assert!(
            verify_platform_quote_for_admission(Platform::Tdx, &raw, &[0; 32], None, None).is_err()
        );
    }
}
