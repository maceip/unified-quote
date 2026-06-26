//! Azure confidential VM (AMD SEV-SNP under the vTOM paravisor).
//!
//! Azure CVMs do **not** expose `/dev/sev-guest` or configfs-tsm to the guest:
//! the paravisor mediates the firmware. Instead it publishes a genuine AMD
//! SEV-SNP attestation report through the **vTPM**, in a Microsoft "HCL" report
//! blob stored at NV index `0x01400001`:
//!
//! ```text
//!   [ HCLA header (32B) ][ SNP report (1184B) ][ runtime-data (JSON, var) ]
//! ```
//!
//! The SNP report's `REPORT_DATA[0..32] == SHA-256(runtime-data)`, and the
//! runtime data carries the vTPM attestation key (`HCLAkPub`). So the AMD report
//! is a hardware-rooted endorsement of the vTPM AK.
//!
//! We verify the embedded SNP report against the **AMD root** exactly like a
//! bare-metal SNP quote — Azure signs with a per-chip VCEK (Milan), fetched from
//! AMD's public KDS by `chip_id`. This gives Azure a hardware root of trust
//! **without trusting Microsoft Azure Attestation (MAA)**: the verdict chains to
//! AMD silicon, not to a Microsoft-operated service.

use sha2::{Digest, Sha256};

/// vTPM NV index where the paravisor stores the HCL attestation report.
pub const AZURE_HCL_NV_INDEX: &str = "0x01400001";

/// "HCLA" stored little-endian at offset 0 of the HCL report.
const HCL_SIG: u32 = 0x414c_4348;
/// The AMD SNP report begins right after the 32-byte HCLA header.
const SNP_OFFSET: usize = 0x20;
/// Length of an AMD SEV-SNP ATTESTATION_REPORT.
const SNP_LEN: usize = 1184;

/// Parsed evidence extracted from a raw HCL report blob.
pub struct AzureEvidence {
    /// The embedded AMD SEV-SNP attestation report (1184 bytes).
    pub snp_report: Vec<u8>,
    /// The runtime-data region (UTF-8 JSON) that the report commits to.
    pub runtime: Vec<u8>,
}

/// Result of verifying an Azure HCL report.
#[derive(Debug, serde::Serialize)]
pub struct AzureVerdict {
    /// "verified" when the SNP signature **and** AMD chain both check out.
    pub verdict: String,
    /// Launch MEASUREMENT (hex) from the SNP report.
    pub measurement: String,
    /// REPORT_DATA (hex) — equals sha256(runtime) in [0..32].
    pub report_data: String,
    /// SHA-256 of the runtime-data the report commits to (hex).
    pub runtime_sha256: String,
    /// AMD endorsement-key signature over the report verified.
    pub sig_verified: bool,
    /// VCEK → ASK → ARK chain verified against the pinned AMD Milan root.
    pub chain_verified: bool,
    /// vTPM attestation-key id from the runtime data (e.g. "HCLAkPub").
    pub ak_kid: Option<String>,
    /// Azure VM unique id from the runtime vm-configuration.
    pub vm_unique_id: Option<String>,
}

/// Split a raw HCL blob into the SNP report and the runtime-data JSON.
pub fn parse_hcl(hcl: &[u8]) -> Result<AzureEvidence, String> {
    if hcl.len() < SNP_OFFSET + SNP_LEN {
        return Err(format!("HCL blob too short: {} bytes", hcl.len()));
    }
    let sig = u32::from_le_bytes(hcl[0..4].try_into().unwrap());
    if sig != HCL_SIG {
        return Err(format!(
            "not an HCL report: signature 0x{sig:08x} (expected 0x{HCL_SIG:08x})"
        ));
    }
    let snp_report = hcl[SNP_OFFSET..SNP_OFFSET + SNP_LEN].to_vec();

    // Runtime data is the UTF-8 JSON object: first `{"` to the last `}`.
    let start = hcl
        .windows(2)
        .position(|w| w == b"{\"")
        .ok_or("runtime-data JSON not found in HCL blob")?;
    let end = hcl
        .iter()
        .rposition(|&c| c == b'}')
        .ok_or("runtime-data JSON terminator not found")?
        + 1;
    if end <= start {
        return Err("runtime-data JSON bounds invalid".into());
    }
    let runtime = hcl[start..end].to_vec();
    Ok(AzureEvidence { snp_report, runtime })
}

/// Verify a raw HCL report: AMD-rooted SNP signature/chain plus the
/// `REPORT_DATA == sha256(runtime)` binding that endorses the vTPM AK.
pub fn verify_hcl(hcl: &[u8]) -> Result<AzureVerdict, String> {
    let ev = parse_hcl(hcl)?;

    // The report commits to the runtime data (which carries the vTPM AK).
    let mut h = Sha256::new();
    h.update(&ev.runtime);
    let mut expected = [0u8; 32];
    expected.copy_from_slice(&h.finalize());

    let report_data = &ev.snp_report[0x50..0x90];
    if report_data[..32] != expected[..] {
        return Err(
            "Azure: SNP REPORT_DATA[0..32] != sha256(runtime-data) — \
             the vTPM AK is not bound to this hardware report"
                .into(),
        );
    }

    // Verify the SNP report against the AMD root. Passing the runtime hash as
    // the expected binding satisfies the generic verifier's REPORT_DATA check
    // (on Azure the paravisor owns REPORT_DATA, committing it to the AK), while
    // the signature + VCEK→ASK→ARK(Milan) chain proves genuine AMD silicon.
    let measurements = crate::quote::verify::verify_platform_quote(
        crate::quote::Platform::SevSnp,
        &ev.snp_report,
        &expected,
    )
    .map_err(|e| format!("Azure SNP verification failed: {e}"))?;

    let mut sig_verified = false;
    let mut chain_verified = false;
    let mut measurement = String::new();
    for (k, v) in &measurements {
        match k.as_str() {
            "SIG_VERIFIED" => sig_verified = v.first() == Some(&1),
            "CHAIN_VERIFIED" => chain_verified = v.first() == Some(&1),
            "MEASUREMENT" => measurement = hex::encode(v),
            _ => {}
        }
    }

    let (ak_kid, vm_unique_id) = parse_runtime_meta(&ev.runtime);
    let verdict = if sig_verified && chain_verified {
        "verified"
    } else {
        "fail"
    };

    Ok(AzureVerdict {
        verdict: verdict.into(),
        measurement,
        report_data: hex::encode(report_data),
        runtime_sha256: hex::encode(expected),
        sig_verified,
        chain_verified,
        ak_kid,
        vm_unique_id,
    })
}

fn parse_runtime_meta(runtime: &[u8]) -> (Option<String>, Option<String>) {
    let v: serde_json::Value = match serde_json::from_slice(runtime) {
        Ok(v) => v,
        Err(_) => return (None, None),
    };
    let ak_kid = v
        .get("keys")
        .and_then(|k| k.as_array())
        .and_then(|a| {
            a.iter()
                .find(|k| k.get("kid").and_then(|s| s.as_str()) == Some("HCLAkPub"))
        })
        .and_then(|k| k.get("kid"))
        .and_then(|s| s.as_str())
        .map(str::to_string);
    let vm_unique_id = v
        .get("vm-configuration")
        .and_then(|c| c.get("vmUniqueId"))
        .and_then(|s| s.as_str())
        .map(str::to_string);
    (ak_kid, vm_unique_id)
}

/// Read the HCL report from the vTPM. Linux-only; requires `tpm2-tools`
/// (`tpm2_nvread`). The index is `ownerread`, satisfied by the empty owner auth.
#[cfg(unix)]
pub fn read_hcl_report() -> Result<Vec<u8>, String> {
    use std::process::Command;
    let out = Command::new("tpm2_nvread")
        .args([AZURE_HCL_NV_INDEX, "-C", "o", "-o", "/dev/stdout"])
        .output()
        .map_err(|e| {
            format!("running tpm2_nvread (install tpm2-tools): {e}")
        })?;
    if !out.status.success() {
        return Err(format!(
            "tpm2_nvread {AZURE_HCL_NV_INDEX} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    if out.stdout.len() < SNP_OFFSET + SNP_LEN {
        return Err(format!(
            "vTPM NV read returned only {} bytes — not an HCL report",
            out.stdout.len()
        ));
    }
    Ok(out.stdout)
}

#[cfg(not(unix))]
pub fn read_hcl_report() -> Result<Vec<u8>, String> {
    Err("Azure HCL collection is only supported on Linux guests".into())
}
