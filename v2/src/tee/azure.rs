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

/// vTPM persistent handle of the attestation key (HCLAkPub) the paravisor
/// provisions and endorses through the SNP report's runtime data.
pub const AZURE_VTPM_AK_HANDLE: &str = "0x81000003";

/// A self-contained Azure attestation bundle: the vTPM HCL report (AMD-rooted
/// SNP report + runtime data) plus, optionally, an AK-signed TPM2 quote whose
/// `extraData` commits a caller-supplied `value_x` binding. Hex-encoded so it
/// serves/verifies anywhere with no extra trust.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AzureBundle {
    pub version: u32,
    pub platform: String,
    /// Raw HCL report blob (hex).
    pub hcl: String,
    /// TPMS_ATTEST quote body (hex), present when a value_x was bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tpm_quote_msg: Option<String>,
    /// TPMT_SIGNATURE over the quote body (hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tpm_quote_sig: Option<String>,
    /// The 32-byte qualifyingData committed into the AK quote (hex) — the
    /// source/artifact identity (e.g. a GitHub build-provenance subject digest).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_x: Option<String>,
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
    /// When a value_x was bound: the AK-signed TPM quote verified and its
    /// `extraData` matched value_x (so the source identity is AMD-rooted via
    /// the SNP-endorsed vTPM AK). `None` when the bundle carried no quote.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_x_bound: Option<bool>,
    /// The bound source/artifact identity (hex), echoed from the quote.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_x: Option<String>,
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
        value_x_bound: None,
        value_x: None,
    })
}

/// Extract the SNP-endorsed vTPM attestation key (HCLAkPub) as (n, e) big-endian
/// bytes from the runtime-data JSON. This is the key `report_data` commits to,
/// so it inherits the AMD hardware root — we never trust a separately-shipped key.
fn ak_pub_from_runtime(runtime: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    use base64::Engine;
    let v: serde_json::Value =
        serde_json::from_slice(runtime).map_err(|e| format!("runtime JSON: {e}"))?;
    let ak = v
        .get("keys")
        .and_then(|k| k.as_array())
        .and_then(|a| {
            a.iter()
                .find(|k| k.get("kid").and_then(|s| s.as_str()) == Some("HCLAkPub"))
        })
        .ok_or("HCLAkPub not present in runtime data")?;
    let b64u = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let dec = |field: &str| -> Result<Vec<u8>, String> {
        let s = ak
            .get(field)
            .and_then(|s| s.as_str())
            .ok_or_else(|| format!("HCLAkPub missing '{field}'"))?;
        b64u.decode(s.trim_end_matches('='))
            .map_err(|e| format!("HCLAkPub '{field}' base64url: {e}"))
    };
    Ok((dec("n")?, dec("e")?))
}

/// Verify an AK-signed TPM2 quote: RSASSA(SHA-256) over the TPMS_ATTEST body
/// using the runtime AK key, and confirm the quote `extraData` equals the
/// expected 32-byte binding. Returns Ok(()) only when both hold.
fn verify_ak_quote(
    runtime: &[u8],
    quote_msg: &[u8],
    quote_sig: &[u8],
    expected_binding: &[u8],
) -> Result<(), String> {
    use rsa::{traits::SignatureScheme, BigUint, Pkcs1v15Sign, RsaPublicKey};
    use sha2::{Digest, Sha256};

    // --- TPMS_ATTEST: magic, type, qualifiedSigner, extraData ---
    if quote_msg.len() < 8 {
        return Err("TPM quote body too short".into());
    }
    let magic = u32::from_be_bytes(quote_msg[0..4].try_into().unwrap());
    if magic != 0xff54_4347 {
        return Err(format!("bad TPMS_ATTEST magic 0x{magic:08x} (expected 0xff544347)"));
    }
    let typ = u16::from_be_bytes(quote_msg[4..6].try_into().unwrap());
    if typ != 0x8018 {
        return Err(format!("TPM attest type 0x{typ:04x} is not ATTEST_QUOTE (0x8018)"));
    }
    let mut off = 6usize;
    let qsn = u16::from_be_bytes(quote_msg[off..off + 2].try_into().unwrap()) as usize;
    off += 2 + qsn; // skip qualifiedSigner TPM2B_NAME
    if off + 2 > quote_msg.len() {
        return Err("TPM quote truncated before extraData".into());
    }
    let ed_len = u16::from_be_bytes(quote_msg[off..off + 2].try_into().unwrap()) as usize;
    off += 2;
    if off + ed_len > quote_msg.len() {
        return Err("TPM quote truncated in extraData".into());
    }
    let extra = &quote_msg[off..off + ed_len];
    if extra != expected_binding {
        return Err(format!(
            "TPM quote extraData != value_x binding\n  bound:    {}\n  expected: {}",
            hex::encode(extra),
            hex::encode(expected_binding)
        ));
    }

    // --- TPMT_SIGNATURE: sigAlg(2) hashAlg(2) size(2) sig ---
    if quote_sig.len() < 6 {
        return Err("TPM signature too short".into());
    }
    let sig_alg = u16::from_be_bytes(quote_sig[0..2].try_into().unwrap());
    if sig_alg != 0x0014 {
        return Err(format!("TPM sig alg 0x{sig_alg:04x} is not RSASSA (0x0014)"));
    }
    let sz = u16::from_be_bytes(quote_sig[4..6].try_into().unwrap()) as usize;
    if quote_sig.len() < 6 + sz {
        return Err("TPM signature length mismatch".into());
    }
    let raw_sig = &quote_sig[6..6 + sz];

    let (n, e) = ak_pub_from_runtime(runtime)?;
    let pk = RsaPublicKey::new(BigUint::from_bytes_be(&n), BigUint::from_bytes_be(&e))
        .map_err(|e| format!("construct AK RSA key: {e}"))?;
    let digest = Sha256::digest(quote_msg);
    // EMSA-PKCS1-v1_5 DigestInfo prefix for SHA-256 (avoids needing sha2's
    // `oid` feature for the generic `Pkcs1v15Sign::new::<Sha256>()`).
    const SHA256_DIGESTINFO: &[u8] = &[
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    let scheme = Pkcs1v15Sign {
        hash_len: Some(32),
        prefix: SHA256_DIGESTINFO.into(),
    };
    scheme
        .verify(&pk, &digest, raw_sig)
        .map_err(|_| "AK quote signature did not verify (RSASSA/SHA-256)".to_string())
}

/// Verify a full Azure bundle: HCL report → AMD root, plus (if present) the
/// AK-signed quote binding `value_x` to the SNP-endorsed vTPM AK.
pub fn verify_bundle(bundle: &AzureBundle) -> Result<AzureVerdict, String> {
    let hcl = hex::decode(&bundle.hcl).map_err(|e| format!("bundle.hcl hex: {e}"))?;
    let mut verdict = verify_hcl(&hcl)?;

    match (&bundle.tpm_quote_msg, &bundle.tpm_quote_sig, &bundle.value_x) {
        (Some(msg_hex), Some(sig_hex), Some(vx_hex)) => {
            let ev = parse_hcl(&hcl)?;
            let msg = hex::decode(msg_hex).map_err(|e| format!("tpm_quote_msg hex: {e}"))?;
            let sig = hex::decode(sig_hex).map_err(|e| format!("tpm_quote_sig hex: {e}"))?;
            let binding = hex::decode(vx_hex).map_err(|e| format!("value_x hex: {e}"))?;
            verify_ak_quote(&ev.runtime, &msg, &sig, &binding)?;
            verdict.value_x_bound = Some(true);
            verdict.value_x = Some(vx_hex.clone());
            // A bound bundle is only "verified" if BOTH the AMD chain and the
            // value_x binding hold.
            if verdict.verdict != "verified" {
                verdict.verdict = "fail".into();
            }
        }
        (None, None, _) => { /* platform-only bundle */ }
        _ => return Err("bundle has a partial TPM quote (msg/sig/value_x must all be present)".into()),
    }
    Ok(verdict)
}

/// Collect an HCL report and (when `binding` is Some) an AK-signed TPM2 quote
/// over that 32-byte binding, returning a self-contained bundle. Linux + tpm2-tools.
#[cfg(unix)]
pub fn collect_bundle(binding: Option<&[u8; 32]>) -> Result<AzureBundle, String> {
    let hcl = read_hcl_report()?;
    let mut bundle = AzureBundle {
        version: 1,
        platform: "azure-sev-snp-vtpm".into(),
        hcl: hex::encode(&hcl),
        tpm_quote_msg: None,
        tpm_quote_sig: None,
        value_x: None,
    };
    if let Some(b) = binding {
        let (msg, sig) = tpm_quote_over(b)?;
        bundle.tpm_quote_msg = Some(hex::encode(msg));
        bundle.tpm_quote_sig = Some(hex::encode(sig));
        bundle.value_x = Some(hex::encode(b));
    }
    Ok(bundle)
}

/// Run `tpm2_quote` with the vTPM AK over `binding` as qualifyingData; returns
/// (TPMS_ATTEST body, TPMT_SIGNATURE).
#[cfg(unix)]
fn tpm_quote_over(binding: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), String> {
    use std::process::Command;
    let dir = std::env::temp_dir();
    let msg_path = dir.join("uq-azure-quote.msg");
    let sig_path = dir.join("uq-azure-quote.sig");
    let pcr_path = dir.join("uq-azure-quote.pcr");
    let out = Command::new("tpm2_quote")
        .args([
            "-c",
            AZURE_VTPM_AK_HANDLE,
            "-l",
            "sha256:0,1,2,3,4,5,6,7",
            "-q",
            &hex::encode(binding),
            "-g",
            "sha256",
            "-m",
            msg_path.to_str().unwrap(),
            "-s",
            sig_path.to_str().unwrap(),
            "-o",
            pcr_path.to_str().unwrap(),
        ])
        .output()
        .map_err(|e| format!("running tpm2_quote (install tpm2-tools): {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "tpm2_quote failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let msg = std::fs::read(&msg_path).map_err(|e| format!("read quote msg: {e}"))?;
    let sig = std::fs::read(&sig_path).map_err(|e| format!("read quote sig: {e}"))?;
    let _ = std::fs::remove_file(&msg_path);
    let _ = std::fs::remove_file(&sig_path);
    let _ = std::fs::remove_file(&pcr_path);
    Ok((msg, sig))
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
