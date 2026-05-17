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

    eprintln!("[bountynet/kds] Fetching VCEK from AMD KDS: {url}");

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP client: {e}"))?;

    let resp = client
        .get(&url)
        .header("Accept", "application/x-pem-file")
        .send()
        .map_err(|e| format!("KDS request failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("KDS returned {}: {}", resp.status(), url));
    }

    // KDS returns DER by default, PEM if Accept header requests it.
    // We request PEM but handle both.
    let body = resp.bytes().map_err(|e| format!("KDS read body: {e}"))?;

    // Check if it's PEM or DER
    if body.starts_with(b"-----BEGIN") {
        // Parse PEM to DER
        pem_to_der(&body).ok_or_else(|| "Failed to parse PEM from KDS".into())
    } else {
        // Already DER
        Ok(body.to_vec())
    }
}

/// Fetch the ASK + ARK cert chain for a product family.
///
/// URL: /vcek/v1/{product}/cert_chain
///
/// Returns (ASK DER, ARK DER).
pub fn fetch_cert_chain(product: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let url = format!("{KDS_BASE}/vcek/v1/{product}/cert_chain");

    eprintln!("[bountynet/kds] Fetching cert chain from AMD KDS: {url}");

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP client: {e}"))?;

    let resp = client
        .get(&url)
        .header("Accept", "application/x-pem-file")
        .send()
        .map_err(|e| format!("KDS cert chain request: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("KDS cert chain returned {}", resp.status()));
    }

    let body = resp.bytes().map_err(|e| format!("KDS read: {e}"))?;
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
    if report.len() < 0x188 {
        return Err(format!("Report too short: {} bytes", report.len()));
    }

    // Version at offset 0x000 (4 bytes LE)
    let version = u32::from_le_bytes(report[0..4].try_into().map_err(|_| "version bytes")?);
    let product = match version {
        2 => "Milan",
        5 => "Genoa",
        _ => return Err(format!("Unknown SNP version {version}")),
    };

    // CHIP_ID at offset 0x140 (64 bytes)
    let chip_id = report[0x140..0x180].to_vec();

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
