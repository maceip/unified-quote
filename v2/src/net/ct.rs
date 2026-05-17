//! Certificate Transparency verification.
//!
//! Parses the X.509 SCT (Signed Certificate Timestamp) list extension
//! from a Let's Encrypt (or any CA-issued) certificate, reconstructs
//! the precert that was signed by the CT log, and verifies the ECDSA
//! signature against pinned CT log public keys.
//!
//! ## Why we bother
//!
//! Every cert that Let's Encrypt issues is submitted to multiple CT
//! logs. The log returns an SCT — a signed promise that the cert will
//! be included in the log within the MMD (Maximum Merge Delay,
//! typically 24h). LE embeds the SCTs back into the final cert so
//! browsers can verify them during handshake.
//!
//! For the bountynet flow, the CT property is structural: every time
//! an enclave boots, it goes through ACME, gets a fresh LE cert for
//! `<value_x_prefix>.aeon.site`, and that cert lands in a CT log.
//! A malicious enclave variant either:
//! - Gets its own cert (different Value X → visible in CT monitoring)
//! - Reuses a legit cert (fails attested-TLS channel binding)
//! - Uses no cert (unreachable)
//!
//! The CT verification here closes the "gets its own cert" branch:
//! if SCTs don't verify against a log we trust, we can detect it.
//! Without this step, we're trusting the CA silently.
//!
//! ## What this module does
//!
//! 1. Parse the SCT list extension
//!    (OID `1.3.6.1.4.1.11129.2.4.2`) from a DER-encoded cert.
//! 2. For each SCT, look up the log by its 32-byte LogID in
//!    [`PINNED_LOGS`].
//! 3. Reconstruct the precert TBS certificate by removing the SCT
//!    list extension from the final cert's TBS (the precert is what
//!    the log actually signed, before the SCTs were embedded).
//! 4. Build the signed-data structure per RFC 6962 §3.2.
//! 5. Verify the ECDSA-P256-SHA256 signature.
//!
//! ## Deliberately NOT here
//!
//! - **STH verification** / inclusion proofs. An SCT is a *promise*
//!   of inclusion. A proper auditor would additionally query the log,
//!   fetch a signed tree head, and verify a Merkle inclusion proof.
//!   We don't do that — the SCT check is an anti-rogue-CA measure,
//!   not a full CT audit. The monitoring pipeline (a separate
//!   certstream watcher on `*.aeon.site`) is the audit-layer witness.
//! - **OCSP / stapling**. Out of scope — we're not a browser.
//! - **Revocation**. Value X rotation replaces revocation in our
//!   model; if a given Value X is compromised, the fix is a new
//!   Value X, not a CRL entry.

use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};

/// The X.509 extension OID for the embedded SCT list (RFC 6962 §3.3).
pub const CT_SCT_LIST_OID: &str = "1.3.6.1.4.1.11129.2.4.2";

/// CT poison extension OID (RFC 6962 §3.1). Never appears in a real
/// cert; present only in precerts to prevent them being served as
/// normal certificates. When we reconstruct the precert TBS for
/// signature verification, if a cert had a poison extension, we'd
/// strip it — but we're verifying real certs, not precerts, so this
/// is here for documentation only.
#[allow(dead_code)]
pub const CT_POISON_OID: &str = "1.3.6.1.4.1.11129.2.4.3";

/// A CT log we trust. The `spki_der` is the full
/// SubjectPublicKeyInfo DER; `log_id` is its sha256.
pub struct PinnedLog {
    pub name: &'static str,
    pub log_id: [u8; 32],
    pub spki_der: &'static [u8],
}

// Pinned log keys. Source: https://www.gstatic.com/ct/log_list/v3/log_list.json
// Fetched April 2026, filtered for `state: usable` and `temporal_interval`
// covering April 2026. All entries use P-256 ECDSA.
//
// Updating: re-fetch the log list, re-run the extraction for usable logs
// whose interval still covers the current date, and replace the byte arrays.
// Do NOT add a log without verifying its operator and state.

/// Google 'Argon2026h1' — coverage Jan 1 – Jul 1, 2026.
const GOOGLE_ARGON_2026H1_LOG_ID: [u8; 32] = [
    0x0e, 0x57, 0x94, 0xbc, 0xf3, 0xae, 0xa9, 0x3e, 0x33, 0x1b, 0x2c, 0x99, 0x07, 0xb3, 0xf7, 0x90,
    0xdf, 0x9b, 0xc2, 0x3d, 0x71, 0x32, 0x25, 0xdd, 0x21, 0xa9, 0x25, 0xac, 0x61, 0xc5, 0x4e, 0x21,
];
const GOOGLE_ARGON_2026H1_SPKI: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x07, 0xfc, 0x1e, 0xe8, 0x63,
    0x8e, 0xff, 0x1c, 0x31, 0x8a, 0xfc, 0xb8, 0x1e, 0x19, 0x2b, 0x60, 0x50, 0x00, 0x3e, 0x8e, 0x9e,
    0xda, 0x77, 0x37, 0xe3, 0xa5, 0xa8, 0xda, 0x8d, 0x94, 0xf8, 0x6b, 0xe8, 0x3d, 0x64, 0x8f, 0x27,
    0x3f, 0x75, 0xb3, 0xfc, 0x6b, 0x12, 0xf0, 0x37, 0x06, 0x4f, 0x64, 0x58, 0x75, 0x14, 0x5d, 0x56,
    0x52, 0xe6, 0x6a, 0x2b, 0x14, 0x4c, 0xec, 0x81, 0xd1, 0xea, 0x3e,
];

/// Cloudflare 'Nimbus2026' — coverage Jan 1, 2026 – Jan 1, 2027.
const CLOUDFLARE_NIMBUS_2026_LOG_ID: [u8; 32] = [
    0xcb, 0x38, 0xf7, 0x15, 0x89, 0x7c, 0x84, 0xa1, 0x44, 0x5f, 0x5b, 0xc1, 0xdd, 0xfb, 0xc9, 0x6e,
    0xf2, 0x9a, 0x59, 0xcd, 0x47, 0x0a, 0x69, 0x05, 0x85, 0xb0, 0xcb, 0x14, 0xc3, 0x14, 0x58, 0xe7,
];
const CLOUDFLARE_NIMBUS_2026_SPKI: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xd8, 0x5c, 0x61, 0x4f, 0xac,
    0x6a, 0xd2, 0x20, 0x80, 0x4e, 0x8a, 0x42, 0xf6, 0x04, 0xad, 0x4b, 0xd4, 0xb1, 0x1c, 0x79, 0x8e,
    0x29, 0x32, 0xde, 0x69, 0x53, 0x59, 0xeb, 0xad, 0x78, 0xf3, 0xc0, 0x2a, 0xf2, 0xd0, 0x11, 0x5d,
    0x05, 0x7e, 0xeb, 0xe8, 0xc1, 0xd3, 0xdf, 0x37, 0xbf, 0x91, 0x64, 0x46, 0x6e, 0x0e, 0x27, 0x13,
    0xea, 0xbb, 0x6f, 0x46, 0x27, 0x58, 0x86, 0xef, 0x40, 0x21, 0xa3,
];

/// DigiCert 'Wyvern2026h1' — coverage Jan 1 – Jul 1, 2026.
const DIGICERT_WYVERN_2026H1_LOG_ID: [u8; 32] = [
    0x64, 0x11, 0xc4, 0x6c, 0xa4, 0x12, 0xec, 0xa7, 0x89, 0x1c, 0xa2, 0x02, 0x2e, 0x00, 0xbc, 0xab,
    0x4f, 0x28, 0x07, 0xd4, 0x1e, 0x35, 0x27, 0xab, 0xea, 0xfe, 0xd5, 0x03, 0xc9, 0x7d, 0xcd, 0xf0,
];
const DIGICERT_WYVERN_2026H1_SPKI: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xec, 0xbc, 0x34, 0x39, 0xe2,
    0x9a, 0x8d, 0xb7, 0x99, 0x7a, 0x91, 0xf1, 0x05, 0x72, 0x52, 0xda, 0x93, 0x89, 0x5d, 0x3a, 0x07,
    0x8b, 0x99, 0xed, 0x80, 0xa5, 0x16, 0xda, 0x73, 0x21, 0x20, 0xeb, 0x86, 0x96, 0x87, 0xc5, 0xc6,
    0xd9, 0x17, 0xba, 0x6e, 0xb9, 0x4c, 0x13, 0x58, 0xd5, 0xd1, 0x83, 0xf8, 0x7a, 0xdf, 0x1e, 0x07,
    0xbc, 0x15, 0xcd, 0xc0, 0x4a, 0xcd, 0x2a, 0x31, 0x71, 0x07, 0x55,
];

/// Sectigo 'Elephant2026h1' — coverage Jan 1 – Jul 1, 2026.
const SECTIGO_ELEPHANT_2026H1_LOG_ID: [u8; 32] = [
    0xd1, 0x6e, 0xa9, 0xa5, 0x68, 0x07, 0x7e, 0x66, 0x35, 0xa0, 0x3f, 0x37, 0xa5, 0xdd, 0xbc, 0x03,
    0xa5, 0x3c, 0x41, 0x12, 0x14, 0xd4, 0x88, 0x18, 0xf5, 0xe9, 0x31, 0xb3, 0x23, 0xcb, 0x95, 0x04,
];
const SECTIGO_ELEPHANT_2026H1_SPKI: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x53, 0x49, 0x6a, 0x9c, 0xf1,
    0xe8, 0x5e, 0xe5, 0x3d, 0x15, 0xcf, 0x5d, 0x26, 0xfd, 0x47, 0x41, 0x90, 0xaf, 0xb2, 0xc2, 0x5f,
    0xbf, 0x12, 0xec, 0x8a, 0xbc, 0x15, 0x43, 0xf7, 0xe4, 0x17, 0x25, 0x2a, 0x7a, 0xee, 0x22, 0x9f,
    0x03, 0xca, 0x8a, 0x47, 0x93, 0xe0, 0x31, 0xb2, 0xc9, 0x65, 0x87, 0xe0, 0xd4, 0x7f, 0x0c, 0x22,
    0x5a, 0xd9, 0xb0, 0x2e, 0x98, 0x7a, 0xd7, 0x25, 0xd0, 0x1c, 0x69,
];

pub const PINNED_LOGS: &[PinnedLog] = &[
    PinnedLog {
        name: "Google Argon2026h1",
        log_id: GOOGLE_ARGON_2026H1_LOG_ID,
        spki_der: GOOGLE_ARGON_2026H1_SPKI,
    },
    PinnedLog {
        name: "Cloudflare Nimbus2026",
        log_id: CLOUDFLARE_NIMBUS_2026_LOG_ID,
        spki_der: CLOUDFLARE_NIMBUS_2026_SPKI,
    },
    PinnedLog {
        name: "DigiCert Wyvern2026h1",
        log_id: DIGICERT_WYVERN_2026H1_LOG_ID,
        spki_der: DIGICERT_WYVERN_2026H1_SPKI,
    },
    PinnedLog {
        name: "Sectigo Elephant2026h1",
        log_id: SECTIGO_ELEPHANT_2026H1_LOG_ID,
        spki_der: SECTIGO_ELEPHANT_2026H1_SPKI,
    },
];

/// A parsed Signed Certificate Timestamp (RFC 6962 §3.2).
#[derive(Debug, Clone)]
pub struct Sct {
    /// SCT version byte. Must be 0 (v1) today.
    pub version: u8,
    /// 32-byte log identifier (sha256 of the log's DER SPKI).
    pub log_id: [u8; 32],
    /// Timestamp, milliseconds since unix epoch.
    pub timestamp_ms: u64,
    /// Extensions field — usually empty.
    pub extensions: Vec<u8>,
    /// TLS HashAlgorithm (sha256 = 4).
    pub hash_alg: u8,
    /// TLS SignatureAlgorithm (ecdsa = 3).
    pub sig_alg: u8,
    /// DER-encoded ECDSA signature.
    pub signature_der: Vec<u8>,
}

impl Sct {
    /// Look up this SCT's log in the pinned list.
    pub fn pinned_log(&self) -> Option<&'static PinnedLog> {
        PINNED_LOGS.iter().find(|l| l.log_id == self.log_id)
    }
}

/// Parse the SignedCertificateTimestampList from the raw extension
/// value bytes.
///
/// Wire format (RFC 6962 §3.3):
///
/// ```text
/// struct {
///   SerializedSCT sct_list<1..2^16-1>;
/// } SignedCertificateTimestampList;
///
/// opaque SerializedSCT<1..2^16-1>;
/// ```
///
/// The extension value is usually wrapped in an OCTET STRING (handled
/// by [`extract_scts_from_cert`]). This function takes the bytes
/// AFTER that wrapping: a 2-byte total length followed by a sequence
/// of (2-byte length, SCT bytes) pairs.
pub fn parse_sct_list(bytes: &[u8]) -> Result<Vec<Sct>> {
    if bytes.len() < 2 {
        return Err(anyhow!("SCT list too short: {}", bytes.len()));
    }
    let total_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    if bytes.len() < 2 + total_len {
        return Err(anyhow!(
            "SCT list truncated: header says {total_len}, have {}",
            bytes.len() - 2
        ));
    }
    let mut cursor = &bytes[2..2 + total_len];
    let mut out = Vec::new();
    while !cursor.is_empty() {
        if cursor.len() < 2 {
            return Err(anyhow!("SCT entry length truncated"));
        }
        let sct_len = u16::from_be_bytes([cursor[0], cursor[1]]) as usize;
        cursor = &cursor[2..];
        if cursor.len() < sct_len {
            return Err(anyhow!("SCT body truncated"));
        }
        out.push(parse_sct(&cursor[..sct_len])?);
        cursor = &cursor[sct_len..];
    }
    Ok(out)
}

fn parse_sct(bytes: &[u8]) -> Result<Sct> {
    // SCT v1 layout:
    //   u8  version
    //   u8[32] log_id
    //   u64 timestamp (big-endian)
    //   u16 extensions_len
    //   u8[extensions_len] extensions
    //   u8  hash_alg
    //   u8  sig_alg
    //   u16 sig_len
    //   u8[sig_len] signature (DER ECDSA)
    if bytes.len() < 1 + 32 + 8 + 2 {
        return Err(anyhow!("SCT header truncated"));
    }
    let version = bytes[0];
    if version != 0 {
        return Err(anyhow!("unsupported SCT version: {version}"));
    }
    let mut log_id = [0u8; 32];
    log_id.copy_from_slice(&bytes[1..33]);
    let timestamp_ms = u64::from_be_bytes(bytes[33..41].try_into().unwrap());

    let ext_len = u16::from_be_bytes([bytes[41], bytes[42]]) as usize;
    if bytes.len() < 43 + ext_len + 4 {
        return Err(anyhow!("SCT extensions / signature header truncated"));
    }
    let extensions = bytes[43..43 + ext_len].to_vec();

    let sig_hdr = 43 + ext_len;
    let hash_alg = bytes[sig_hdr];
    let sig_alg = bytes[sig_hdr + 1];
    let sig_len = u16::from_be_bytes([bytes[sig_hdr + 2], bytes[sig_hdr + 3]]) as usize;
    if bytes.len() < sig_hdr + 4 + sig_len {
        return Err(anyhow!("SCT signature truncated"));
    }
    let signature_der = bytes[sig_hdr + 4..sig_hdr + 4 + sig_len].to_vec();

    Ok(Sct {
        version,
        log_id,
        timestamp_ms,
        extensions,
        hash_alg,
        sig_alg,
        signature_der,
    })
}

/// Extract the SCT list from a DER-encoded certificate.
///
/// Returns the parsed SCTs, or `Ok(vec![])` if the extension is
/// absent. Errors are only for malformed extension content.
pub fn extract_scts_from_cert(cert_der: &[u8]) -> Result<Vec<Sct>> {
    use x509_cert::der::Decode;
    use x509_cert::Certificate;

    let cert = Certificate::from_der(cert_der).map_err(|e| anyhow!("x509 decode: {e}"))?;
    let exts = match &cert.tbs_certificate.extensions {
        Some(v) => v,
        None => return Ok(Vec::new()),
    };

    let target_oid = x509_cert::der::asn1::ObjectIdentifier::new(CT_SCT_LIST_OID)
        .map_err(|e| anyhow!("oid parse: {e}"))?;

    for ext in exts {
        if ext.extn_id == target_oid {
            // The extension value is an OCTET STRING containing the
            // SignedCertificateTimestampList. x509-cert gives us the
            // inner bytes; one more OCTET STRING unwrap peels the
            // outer SCT list wrapping that RFC 6962 mandates.
            let outer = ext.extn_value.as_bytes();
            let inner = if let Ok(os) = x509_cert::der::asn1::OctetString::from_der(outer) {
                os.as_bytes().to_vec()
            } else {
                outer.to_vec()
            };
            return parse_sct_list(&inner);
        }
    }
    Ok(Vec::new())
}

/// Verify a single SCT against the cert it witnesses and the issuer
/// cert (for the `issuer_key_hash`).
///
/// # Args
/// - `sct`: the parsed SCT from [`extract_scts_from_cert`]
/// - `leaf_der`: the DER bytes of the cert that carries the SCT
/// - `issuer_der`: the DER bytes of the cert that signed `leaf_der`
///
/// # Procedure
///
/// 1. Look up the pinned log by `sct.log_id`. If not pinned, return
///    `Err` with a descriptive message — the caller decides whether
///    "unpinned log" is a failure or a skip.
/// 2. Reconstruct the precert TBS by removing the SCT list extension
///    from `leaf_der`'s TBSCertificate and re-encoding it.
/// 3. Compute `issuer_key_hash = sha256(issuer.subjectPublicKeyInfo)`.
/// 4. Build the `digitally-signed` input per RFC 6962 §3.2:
///    ```text
///    u8 version (0)
///    u8 signature_type (0 = certificate_timestamp)
///    u64 timestamp
///    u16 entry_type (1 = precert_entry)
///    u8[32] issuer_key_hash
///    u24 tbs_len
///    u8[tbs_len] precert_tbs
///    u16 extensions_len
///    u8[ext_len] extensions
///    ```
/// 5. Verify the ECDSA-P256-SHA256 signature over this input using
///    the log's pinned SPKI.
pub fn verify_sct(sct: &Sct, leaf_der: &[u8], issuer_der: &[u8]) -> Result<&'static PinnedLog> {
    let log = sct
        .pinned_log()
        .ok_or_else(|| anyhow!("unpinned CT log: {}", hex::encode(sct.log_id)))?;

    // Check the signature algorithm is what we support.
    // hash_alg 4 = sha256, sig_alg 3 = ecdsa.
    if sct.hash_alg != 4 || sct.sig_alg != 3 {
        return Err(anyhow!(
            "unsupported SCT sig algorithm: hash={} sig={}",
            sct.hash_alg,
            sct.sig_alg
        ));
    }

    // 1. Reconstruct the precert TBS.
    let precert_tbs = reconstruct_precert_tbs(leaf_der)?;

    // 2. issuer_key_hash = sha256(issuer.spki)
    let issuer_key_hash = issuer_spki_hash(issuer_der)?;

    // 3. Build the signed-data struct.
    let mut sig_input = Vec::with_capacity(128 + precert_tbs.len());
    sig_input.push(0u8); // version
    sig_input.push(0u8); // signature_type = certificate_timestamp
    sig_input.extend_from_slice(&sct.timestamp_ms.to_be_bytes());
    sig_input.extend_from_slice(&1u16.to_be_bytes()); // entry_type = precert_entry
    sig_input.extend_from_slice(&issuer_key_hash);
    // 24-bit length prefix for tbs
    let tbs_len = precert_tbs.len();
    if tbs_len > 0xffffff {
        return Err(anyhow!("precert TBS too large: {tbs_len}"));
    }
    sig_input.push(((tbs_len >> 16) & 0xff) as u8);
    sig_input.push(((tbs_len >> 8) & 0xff) as u8);
    sig_input.push((tbs_len & 0xff) as u8);
    sig_input.extend_from_slice(&precert_tbs);
    // extensions: u16 length + bytes
    sig_input.extend_from_slice(&(sct.extensions.len() as u16).to_be_bytes());
    sig_input.extend_from_slice(&sct.extensions);

    // 4. Verify ECDSA-P256-SHA256 with the pinned log key.
    verify_ecdsa_p256_sha256(log.spki_der, &sig_input, &sct.signature_der)
        .map_err(|e| anyhow!("SCT signature verify ({}): {e}", log.name))?;

    Ok(log)
}

/// Remove the SCT list extension from a cert's TBSCertificate and
/// return the re-encoded DER. This is what the CT log signed.
fn reconstruct_precert_tbs(cert_der: &[u8]) -> Result<Vec<u8>> {
    use x509_cert::der::{Decode, Encode};
    use x509_cert::Certificate;

    let mut cert = Certificate::from_der(cert_der).map_err(|e| anyhow!("x509 decode: {e}"))?;

    let target_oid = x509_cert::der::asn1::ObjectIdentifier::new(CT_SCT_LIST_OID)
        .map_err(|e| anyhow!("oid parse: {e}"))?;

    if let Some(ref mut exts) = cert.tbs_certificate.extensions {
        exts.retain(|e| e.extn_id != target_oid);
    }

    cert.tbs_certificate
        .to_der()
        .map_err(|e| anyhow!("TBS re-encode: {e}"))
}

fn issuer_spki_hash(issuer_der: &[u8]) -> Result<[u8; 32]> {
    use x509_cert::der::{Decode, Encode};
    use x509_cert::Certificate;

    let cert = Certificate::from_der(issuer_der).map_err(|e| anyhow!("issuer x509 decode: {e}"))?;
    let spki = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| anyhow!("issuer spki encode: {e}"))?;
    Ok(Sha256::digest(&spki).into())
}

fn verify_ecdsa_p256_sha256(spki_der: &[u8], message: &[u8], signature_der: &[u8]) -> Result<()> {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;

    let vk =
        VerifyingKey::from_public_key_der(spki_der).map_err(|e| anyhow!("bad log SPKI: {e}"))?;
    let sig = Signature::from_der(signature_der).map_err(|e| anyhow!("bad signature DER: {e}"))?;
    vk.verify(message, &sig)
        .map_err(|e| anyhow!("ECDSA verify: {e}"))
}

/// Result of verifying all SCTs in a certificate chain.
#[derive(Debug, Default)]
pub struct CtReport {
    pub verified: Vec<&'static str>,
    pub unpinned: Vec<String>,
    pub failed: Vec<String>,
}

impl CtReport {
    pub fn is_empty(&self) -> bool {
        self.verified.is_empty() && self.unpinned.is_empty() && self.failed.is_empty()
    }
    pub fn any_verified(&self) -> bool {
        !self.verified.is_empty()
    }
}

/// Parse + verify every SCT found in `leaf_der` against `issuer_der`.
///
/// This is the one-shot helper the verifier side uses. Semantics:
/// - SCTs from pinned logs that verify go into `verified`.
/// - SCTs from unpinned logs go into `unpinned` (informational).
/// - SCTs that fail verification go into `failed` (call that out).
///
/// Caller's policy: N of M verified → accept. We suggest requiring
/// at least 1 verified and 0 failed, with a loud warning if fewer
/// than 2 pinned-log SCTs are present (Let's Encrypt embeds ≥2).
pub fn verify_scts_in_cert(leaf_der: &[u8], issuer_der: &[u8]) -> Result<CtReport> {
    let scts = extract_scts_from_cert(leaf_der)?;
    let mut report = CtReport::default();

    for sct in scts {
        match verify_sct(&sct, leaf_der, issuer_der) {
            Ok(log) => report.verified.push(log.name),
            Err(e) => {
                let msg = e.to_string();
                if msg.starts_with("unpinned CT log") {
                    report.unpinned.push(hex::encode(sct.log_id));
                } else {
                    report
                        .failed
                        .push(format!("{}: {msg}", hex::encode(sct.log_id)));
                }
            }
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_logs_have_consistent_log_ids() {
        // Each pinned log's advertised log_id must equal sha256 of its
        // advertised SPKI. If these disagree the data is corrupt.
        for log in PINNED_LOGS {
            let computed: [u8; 32] = Sha256::digest(log.spki_der).into();
            assert_eq!(
                computed, log.log_id,
                "log {}: advertised log_id does not match sha256(spki)",
                log.name
            );
        }
    }

    #[test]
    fn pinned_logs_have_valid_p256_spki() {
        // Every pinned SPKI must parse as a P-256 verifying key.
        use p256::ecdsa::VerifyingKey;
        use p256::pkcs8::DecodePublicKey;

        for log in PINNED_LOGS {
            VerifyingKey::from_public_key_der(log.spki_der)
                .unwrap_or_else(|e| panic!("log {}: bad SPKI: {e}", log.name));
        }
    }

    #[test]
    fn parse_empty_sct_list() {
        // A list header of 0x0000 = empty list; should parse as no entries.
        let bytes = [0u8, 0u8];
        let list = parse_sct_list(&bytes).unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn parse_one_synthetic_sct() {
        // Build a minimal well-formed SCT: version=0, log_id = zeros,
        // timestamp=1_000_000, empty extensions, hash=sha256, sig=ecdsa,
        // signature is 8 zero bytes (not a real DER sig but we don't
        // verify here).
        let mut sct = Vec::new();
        sct.push(0u8); // version
        sct.extend_from_slice(&[0u8; 32]); // log_id
        sct.extend_from_slice(&1_000_000u64.to_be_bytes()); // timestamp
        sct.extend_from_slice(&0u16.to_be_bytes()); // ext_len
        sct.push(4u8); // hash_alg = sha256
        sct.push(3u8); // sig_alg = ecdsa
        sct.extend_from_slice(&8u16.to_be_bytes()); // sig_len
        sct.extend_from_slice(&[0u8; 8]); // signature

        let mut list = Vec::new();
        // total_len covers the (sct_len + sct_body) tuple
        let total_len = (2 + sct.len()) as u16;
        list.extend_from_slice(&total_len.to_be_bytes());
        list.extend_from_slice(&(sct.len() as u16).to_be_bytes()); // sct_len
        list.extend_from_slice(&sct);

        let parsed = parse_sct_list(&list).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].version, 0);
        assert_eq!(parsed[0].timestamp_ms, 1_000_000);
        assert_eq!(parsed[0].hash_alg, 4);
        assert_eq!(parsed[0].sig_alg, 3);
        assert!(parsed[0].pinned_log().is_none()); // all-zero log_id is not pinned
    }

    #[test]
    fn truncated_list_rejected() {
        assert!(parse_sct_list(&[]).is_err());
        assert!(parse_sct_list(&[0x00]).is_err());
        // Header claims 10 bytes but only has 2.
        assert!(parse_sct_list(&[0x00, 0x0a, 0xff, 0xff]).is_err());
    }

    #[test]
    fn pinned_count_is_at_least_four() {
        // Sanity: we pinned at least 4 logs so the multi-log property holds.
        assert!(PINNED_LOGS.len() >= 4, "expected ≥4 pinned logs");
    }
}
