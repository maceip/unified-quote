//! AMD Key Distribution Service (KDS) client.
//!
//! Fetches VCEK certificates and cert chains from AMD's public KDS at
//! https://kdsintf.amd.com. This is the fallback when SNP_GET_EXT_REPORT
//! doesn't include certificates (host didn't populate the cert table).
//!
//! Also fetches ASK + ARK cert chain for the product family.
//!
//! No authentication required — KDS is a free public API.

/// KDS base URL
const KDS_BASE: &str = "https://kdsintf.amd.com";

/// GET a KDS URL with retry/backoff. AMD KDS rate-limits aggressively (HTTP
/// 429) and occasionally 5xxs; the certificates are immutable, so retrying is
/// always safe. Honors `Retry-After` when present, else exponential backoff.
fn kds_get(url: &str) -> Result<Vec<u8>, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| format!("HTTP client: {e}"))?;

    let max_attempts = 6u32;
    let mut last_err = String::new();
    for attempt in 0..max_attempts {
        if attempt > 0 {
            // exponential backoff: 1s, 2s, 4s, 8s, 16s (capped)
            let secs = (1u64 << (attempt - 1)).min(16);
            eprintln!("[uq/kds] retrying in {secs}s (attempt {}/{max_attempts}) — {last_err}", attempt + 1);
            std::thread::sleep(std::time::Duration::from_secs(secs));
        }
        let resp = match client
            .get(url)
            .header("Accept", "application/x-pem-file")
            .send()
        {
            Ok(r) => r,
            Err(e) => {
                last_err = format!("request failed: {e}");
                continue;
            }
        };
        let status = resp.status();
        if status.is_success() {
            return resp
                .bytes()
                .map(|b| b.to_vec())
                .map_err(|e| format!("KDS read body: {e}"));
        }
        // Retry on rate-limit / transient server errors; fail fast otherwise.
        if status.as_u16() == 429 || status.is_server_error() {
            if let Some(ra) = resp
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.trim().parse::<u64>().ok())
            {
                eprintln!("[uq/kds] {status}; Retry-After {ra}s");
                std::thread::sleep(std::time::Duration::from_secs(ra.min(30)));
            }
            last_err = format!("KDS returned {status}");
            continue;
        }
        return Err(format!("KDS returned {status}: {url}"));
    }
    Err(format!("KDS exhausted retries ({url}): {last_err}"))
}

/// Fetch the VCEK certificate for a specific chip and TCB version.
///
/// URL: /vcek/v1/{product}/{chip_id_hex}?blSPL={bl}&teeSPL={tee}&snpSPL={snp}&ucodeSPL={ucode}
///
/// Returns the DER-encoded VCEK certificate.
pub fn fetch_vcek(
    product: &str,
    chip_id: &[u8],
    bl_spl: u8,
    tee_spl: u8,
    snp_spl: u8,
    ucode_spl: u8,
) -> Result<Vec<u8>, String> {
    let chip_id_hex = hex::encode(chip_id);
    let url = format!(
        "{KDS_BASE}/vcek/v1/{product}/{chip_id_hex}?blSPL={bl_spl}&teeSPL={tee_spl}&snpSPL={snp_spl}&ucodeSPL={ucode_spl}"
    );

    eprintln!("[uq/kds] Fetching VCEK from AMD KDS: {url}");

    let body = kds_get(&url)?;

    // KDS returns DER by default, PEM if Accept header requests it.
    // We request PEM but handle both.
    // Check if it's PEM or DER
    if body.starts_with(b"-----BEGIN") {
        // Parse PEM to DER
        pem_to_der(&body).ok_or_else(|| "Failed to parse PEM from KDS".into())
    } else {
        // Already DER
        Ok(body.to_vec())
    }
}

/// Fetch the ASK + ARK cert chain for a product family (VCEK endorsement).
///
/// URL: /vcek/v1/{product}/cert_chain
///
/// Returns (ASK DER, ARK DER).
pub fn fetch_cert_chain(product: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    fetch_cert_chain_kind(product, "vcek")
}

/// Fetch the intermediate + ARK cert chain for a product family for a given
/// endorsement-key kind: `"vcek"` (per-chip) or `"vlek"` (cloud-provisioned).
///
/// VLEK-signed reports — used by AWS and Azure confidential VMs — are signed by
/// a Versioned Loaded Endorsement Key whose intermediate (ASVK) + root (ARK) are
/// published at `/vlek/v1/{product}/cert_chain`. The chip-specific VCEK endpoint
/// cannot serve them (the chip_id is masked), so a verifier must select the
/// right endpoint based on the report's signing-key field.
///
/// URL: /{kind}/v1/{product}/cert_chain
///
/// Returns (intermediate DER, ARK DER).
pub fn fetch_cert_chain_kind(product: &str, kind: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let url = format!("{KDS_BASE}/{kind}/v1/{product}/cert_chain");

    eprintln!("[uq/kds] Fetching {kind} cert chain from AMD KDS: {url}");

    let body = kds_get(&url)?;
    let pem_str = String::from_utf8_lossy(&body);

    // Parse PEM chain — contains ASK then ARK
    let certs = parse_pem_certs(&pem_str);
    if certs.len() < 2 {
        return Err(format!("Expected 2 certs (ASK + ARK), got {}", certs.len()));
    }

    Ok((certs[0].clone(), certs[1].clone()))
}

/// Extract SNP report fields needed for KDS URL construction.
///
/// Returns (product_name, chip_id, bl_spl, tee_spl, snp_spl, ucode_spl)
pub fn extract_kds_params(report: &[u8]) -> Result<(String, Vec<u8>, u8, u8, u8, u8), String> {
    if report.len() < 0x1E0 {
        return Err(format!("Report too short: {} bytes", report.len()));
    }

    let product = snp_product(report)?;

    // CHIP_ID at offset 0x1A0 (64 bytes), per the AMD SEV-SNP ABI
    // (ATTESTATION_REPORT). 0x140 is REPORT_ID — using it produced the wrong
    // KDS path and a 404. This only affects the per-chip VCEK lookup (Azure /
    // bare-metal SNP); the VLEK path used by AWS does not consult chip_id.
    let chip_id = report[0x1A0..0x1E0].to_vec();

    // REPORTED_TCB at offset 0x180 (8 bytes)
    // Layout: boot_loader(1), tee(1), reserved(4), snp(1), microcode(1)
    let tcb = &report[0x180..0x188];
    let bl_spl = tcb[0];
    let tee_spl = tcb[1];
    let snp_spl = tcb[6];
    let ucode_spl = tcb[7];

    Ok((
        product.to_string(),
        chip_id,
        bl_spl,
        tee_spl,
        snp_spl,
        ucode_spl,
    ))
}

/// Determine the AMD product line (the KDS path segment) for an SNP report.
///
/// IMPORTANT: the product is a function of the CPU family/model, NOT the
/// report *format* version (offset 0x000). Report formats >= 3 carry CPUID
/// fields at offset 0x188 (`cpuid_fam_id`, `cpuid_mod_id`, `cpuid_step`);
/// legacy v2 reports predate Genoa and are therefore always Milan.
///
/// Family/model → product (per AMD's KDS naming):
///   - 0x19, model 0x00..=0x0F → Milan  (Zen 3, e.g. EPYC 7R13)
///   - 0x19, model 0x10..=0x1F → Genoa  (Zen 4)
///   - 0x1A, any model         → Turin  (Zen 5)
pub fn snp_product(report: &[u8]) -> Result<&'static str, String> {
    if report.len() < 0x18b {
        return Err(format!("report too short for product detection: {} bytes", report.len()));
    }
    let fam = report[0x188];
    let model = report[0x189];
    // Legacy v2 reports leave 0x188 reserved (zero) — those are Milan-era.
    if fam == 0 {
        return Ok("Milan");
    }
    match (fam, model) {
        (0x19, 0x00..=0x0f) => Ok("Milan"),
        (0x19, 0x10..=0x1f) => Ok("Genoa"),
        (0x1a, _) => Ok("Turin"),
        _ => Err(format!(
            "unknown AMD product: cpuid family {fam:#x} model {model:#x}"
        )),
    }
}

fn pem_to_der(pem_bytes: &[u8]) -> Option<Vec<u8>> {
    let pem_str = std::str::from_utf8(pem_bytes).ok()?;
    let certs = parse_pem_certs(pem_str);
    certs.into_iter().next()
}

fn parse_pem_certs(pem_str: &str) -> Vec<Vec<u8>> {
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
