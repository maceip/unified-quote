//! NitroTPM attestation for kernel measurement linking.
//!
//! On AWS SNP, the SNP MEASUREMENT only covers OVMF firmware.
//! The kernel, initrd, and cmdline are measured by NitroTPM into PCR 0-7.
//!
//! Two approaches, in order of preference:
//!
//! 1. **NitroTPM attestation document** (COSE_Sign1 signed by Nitro Hypervisor)
//!    Retrieved via `nitro-tpm-attest` tool (vendor TPM2 command 0x20000001).
//!    The document is signed by the same AWS Nitro PKI as Nitro Enclave
//!    attestations. A verifier checks it against the same root CA.
//!    We bind sha256(attestation_doc) into SNP REPORT_DATA.
//!
//! 2. **Sysfs PCR reading** (fallback if tool not installed)
//!    Read PCR values from /sys/class/tpm/tpm0/pcr-sha256/{0..7}.
//!    Less strong: values aren't cryptographically authenticated by themselves,
//!    but are bound into SNP REPORT_DATA which IS AMD-signed.
//!
//! Trust model:
//!   SNP report (AMD-signed) proves our code is genuine.
//!   Our code collected the NitroTPM attestation and bound its hash.
//!   NitroTPM attestation (Nitro-signed) proves kernel PCR values.
//!   Two independent hardware roots of trust, cryptographically linked.

use sha2::{Digest, Sha256};

const TPM_SYSFS_BASE: &str = "/sys/class/tpm/tpm0/pcr-sha256";

/// Result of NitroTPM attestation collection.
pub struct TpmAttestation {
    /// sha256 of the attestation material (for binding into REPORT_DATA)
    pub digest: [u8; 32],
    /// Raw NitroTPM attestation document (COSE_Sign1, Nitro-signed) if available
    pub attestation_doc: Option<Vec<u8>>,
    /// PCR 0-7 values (from attestation doc or sysfs)
    pub pcrs: Vec<[u8; 32]>,
    /// Which method was used
    pub method: &'static str,
}

/// Check if NitroTPM is available (either the attestation tool or sysfs PCRs).
pub fn tpm_available() -> bool {
    // Check for the signed attestation tool first
    which_nitro_tpm_attest().is_some() || std::path::Path::new(TPM_SYSFS_BASE).exists()
}

/// Collect NitroTPM attestation.
/// Prefers the signed attestation document; falls back to sysfs PCR reading.
pub fn collect_tpm_attestation(nonce: &[u8]) -> Result<TpmAttestation, String> {
    // Try signed attestation document first (strongest)
    if let Some(tool) = which_nitro_tpm_attest() {
        match collect_signed_attestation(&tool, nonce) {
            Ok(att) => return Ok(att),
            Err(e) => {
                eprintln!("[bountynet/tpm] Signed attestation failed ({e}), trying sysfs");
            }
        }
    }

    // Fallback: read PCRs from sysfs
    if std::path::Path::new(TPM_SYSFS_BASE).exists() {
        return collect_sysfs_pcrs();
    }

    Err("No NitroTPM interface available".into())
}

/// Collect a signed NitroTPM attestation document via nitro-tpm-attest.
/// The tool sends vendor command 0x20000001 to the TPM and returns
/// a COSE_Sign1 blob signed by the Nitro Hypervisor.
fn collect_signed_attestation(tool_path: &str, nonce: &[u8]) -> Result<TpmAttestation, String> {
    use std::io::Write;

    // Write nonce to a temp file
    let nonce_path = "/tmp/bountynet-tpm-nonce";
    std::fs::write(nonce_path, nonce).map_err(|e| format!("write nonce: {e}"))?;

    // Call nitro-tpm-attest with nonce
    let output = std::process::Command::new(tool_path)
        .args(["--nonce", nonce_path])
        .output()
        .map_err(|e| format!("nitro-tpm-attest: {e}"))?;

    let _ = std::fs::remove_file(nonce_path);

    if !output.status.success() {
        return Err(format!(
            "nitro-tpm-attest failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let doc = output.stdout;
    if doc.len() < 100 {
        return Err(format!("attestation doc too small: {} bytes", doc.len()));
    }

    // Extract PCRs from the COSE_Sign1 payload (CBOR)
    let pcrs = extract_pcrs_from_attestation_doc(&doc).unwrap_or_default();

    // Digest = sha256(entire signed document)
    let digest: [u8; 32] = Sha256::digest(&doc).into();

    eprintln!(
        "[bountynet/tpm] Signed NitroTPM attestation: {} bytes, {} PCRs",
        doc.len(),
        pcrs.len()
    );

    Ok(TpmAttestation {
        digest,
        attestation_doc: Some(doc),
        pcrs,
        method: "nitro-tpm-attest (COSE_Sign1, Nitro-signed)",
    })
}

/// Fallback: read PCR 0-7 from sysfs.
fn collect_sysfs_pcrs() -> Result<TpmAttestation, String> {
    let pcrs: Vec<[u8; 32]> = (0..8)
        .map(|i| {
            let path = format!("{TPM_SYSFS_BASE}/{i}");
            let text = std::fs::read_to_string(&path).map_err(|e| format!("read PCR{i}: {e}"))?;
            let bytes = hex::decode(text.trim()).map_err(|e| format!("PCR{i} hex decode: {e}"))?;
            bytes.try_into().map_err(|_| format!("PCR{i} not 32 bytes"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let digest = pcr_digest(&pcrs);

    Ok(TpmAttestation {
        digest,
        attestation_doc: None,
        pcrs,
        method: "sysfs (unsigned PCR values)",
    })
}

/// Compute sha256(PCR0 || PCR1 || ... || PCR7).
pub fn pcr_digest(pcrs: &[[u8; 32]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for pcr in pcrs {
        h.update(pcr);
    }
    h.finalize().into()
}

/// Extract PCR values from a NitroTPM attestation document (COSE_Sign1 → CBOR payload).
/// Best-effort: returns empty vec if parsing fails.
fn extract_pcrs_from_attestation_doc(doc: &[u8]) -> Option<Vec<[u8; 32]>> {
    // The doc is a COSE_Sign1: CBOR Tag(18, [protected, unprotected, payload, signature])
    // We need the payload (index 2), which is itself CBOR containing "nitrotpm_pcrs" map.
    // Use serde_cbor to parse.
    #[cfg(feature = "nitro")]
    {
        use serde_cbor::Value;
        let cose: Value = serde_cbor::from_slice(doc).ok()?;
        let arr = match &cose {
            Value::Tag(18, inner) => match inner.as_ref() {
                Value::Array(a) => a,
                _ => return None,
            },
            Value::Array(a) => a,
            _ => return None,
        };
        let payload_bytes = match arr.get(2)? {
            Value::Bytes(b) => b,
            _ => return None,
        };
        let payload: Value = serde_cbor::from_slice(payload_bytes).ok()?;
        let map = match &payload {
            Value::Map(m) => m,
            _ => return None,
        };

        // Look for "nitrotpm_pcrs" or "pcrs" key
        for (k, v) in map {
            if let Value::Text(key) = k {
                if key == "nitrotpm_pcrs" || key == "pcrs" {
                    if let Value::Map(pcr_map) = v {
                        let mut pcrs = Vec::new();
                        for i in 0..8 {
                            if let Some(Value::Bytes(b)) = pcr_map.get(&Value::Integer(i)) {
                                if b.len() == 32 {
                                    let mut arr = [0u8; 32];
                                    arr.copy_from_slice(b);
                                    pcrs.push(arr);
                                }
                            }
                        }
                        if !pcrs.is_empty() {
                            return Some(pcrs);
                        }
                    }
                }
            }
        }
    }
    None
}

/// Find the nitro-tpm-attest binary.
fn which_nitro_tpm_attest() -> Option<String> {
    for path in &[
        "/usr/bin/nitro-tpm-attest",
        "/usr/local/bin/nitro-tpm-attest",
    ] {
        if std::path::Path::new(path).exists() {
            return Some(path.to_string());
        }
    }
    // Check PATH
    std::process::Command::new("which")
        .arg("nitro-tpm-attest")
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
}
