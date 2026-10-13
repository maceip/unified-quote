//! AMD Key Distribution Service (KDS) client.
//!
//! Fetches VCEK certificates and cert chains from AMD's public KDS at
//! https://kdsintf.amd.com for the legacy signature-inspection API. Strict
//! admission uses explicit signed collateral and independent product/TCB policy.
//!
//! Also fetches ASK + ARK cert chain for the product family.
//!
//! No authentication required — KDS is a free public API.

/// KDS base URL
const KDS_BASE: &str = "https://kdsintf.amd.com";

/// GET a KDS URL with a digest-pinned local cache in front (A.1) and
/// retry/backoff behind it. AMD KDS rate-limits aggressively (HTTP 429) and
/// occasionally 5xxs; the certificates are immutable, so both caching and
/// retrying are always safe. Honors `Retry-After` when present, else
/// exponential backoff.
///
/// Cached bytes remain untrusted. Their local digest detects corruption but
/// does not authenticate a writer who can change both files. Certificate path,
/// time validity and any required revocation/TCB appraisal remain mandatory.
fn kds_get(url: &str) -> Result<Vec<u8>, String> {
    let cache_dir = cache::dir();
    if let Some(dir) = &cache_dir {
        if let Some(bytes) = cache::load(dir, url) {
            eprintln!("[uq/kds] cache hit: {url}");
            return Ok(bytes);
        }
    }
    let body = kds_get_network(url)?;
    if let Some(dir) = &cache_dir {
        cache::store(dir, url, &body, cache::ttl_secs());
    }
    Ok(body)
}

/// The network half of [`kds_get`], with no cache.
fn kds_get_network(url: &str) -> Result<Vec<u8>, String> {
    let client = reqwest::blocking::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| format!("HTTP client: {e}"))?;

    let max_attempts = 6u32;
    let mut last_err = String::new();
    for attempt in 0..max_attempts {
        if attempt > 0 {
            // exponential backoff: 1s, 2s, 4s, 8s, 16s (capped)
            let secs = (1u64 << (attempt - 1)).min(16);
            eprintln!(
                "[uq/kds] retrying in {secs}s (attempt {}/{max_attempts}) — {last_err}",
                attempt + 1
            );
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
            use std::io::Read;
            let mut bytes = Vec::new();
            resp.take(256 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| format!("KDS read body: {e}"))?;
            if bytes.is_empty() || bytes.len() > 256 * 1024 {
                return Err("KDS certificate response size outside limit".into());
            }
            return Ok(bytes);
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
    if !matches!(product, "Milan" | "Genoa") || chip_id.len() != 64 {
        return Err("legacy VCEK acquisition requires Milan/Genoa and a 64-byte chip ID; Turin needs explicit FMC-aware collateral".into());
    }
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
    if !matches!(product, "Milan" | "Genoa" | "Turin") || !matches!(kind, "vcek" | "vlek") {
        return Err("unsupported AMD product or endorsement kind".into());
    }
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
    if product == "Turin" {
        return Err("legacy KDS parameters cannot represent Turin FMC; provide explicit endorsement collateral".into());
    }

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
/// legacy v2 reports lack this identity and require independent product policy.
///
/// Family/model → product (per AMD's KDS naming):
///   - 0x19, model 0x00..=0x0F → Milan  (Zen 3, e.g. EPYC 7R13)
///   - 0x19, model 0x10..=0x1F → Genoa  (Zen 4)
///   - 0x1A, model 0x00..=0x1F → Turin  (AMD revision guides 58251/58730)
pub fn snp_product(report: &[u8]) -> Result<&'static str, String> {
    if report.len() < 0x18b {
        return Err(format!(
            "report too short for product detection: {} bytes",
            report.len()
        ));
    }
    let fam = report[0x188];
    let model = report[0x189];
    let version = u32::from_le_bytes(report[..4].try_into().unwrap());
    if !matches!(version, 3..=5) || fam == 0 {
        return Err("SNP product is unavailable from this report; supply independent product policy and collateral".into());
    }
    match (fam, model) {
        (0x19, 0x00..=0x0f) => Ok("Milan"),
        (0x19, 0x10..=0x1f) => Ok("Genoa"),
        (0x1a, 0x00..=0x1f) => Ok("Turin"),
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

/// Digest-pinned, TTL'd local cache of KDS responses (A.1).
///
/// Each entry is a `<sha256(url)>.bin` blob plus a `<sha256(url)>.json`
/// manifest recording the source url, fetch time, ttl, and a SHA-256 of the
/// blob. A load returns the bytes only when the manifest matches the blob hash
/// AND the entry is unexpired. This is a transport cache, not an authenticated
/// certificate or revocation verdict.
pub mod cache {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Default TTL: the certs are immutable, so a week keeps KDS off the hot
    /// path without going stale in any meaningful way.
    const DEFAULT_TTL_SECS: u64 = 7 * 24 * 3600;
    /// Hard ceiling so a misconfigured override can never serve stale KDS
    /// evidence (VCEK/VLEK chains) indefinitely; freshness can be tightened but
    /// never relaxed past 30 days.
    const MAX_TTL_SECS: u64 = 30 * 24 * 3600;
    const MAX_BLOB_BYTES: usize = 256 * 1024;

    #[derive(serde::Serialize, serde::Deserialize)]
    struct Manifest {
        url: String,
        fetched_at: u64,
        ttl_secs: u64,
        sha256: String,
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn key(url: &str) -> String {
        hex::encode(Sha256::digest(url.as_bytes()))
    }

    /// Resolve the cache directory, or `None` if caching is disabled.
    /// `UQ_KDS_CACHE` overrides the location; set it to `off`/`0` to disable.
    /// Default: `$HOME/.cache/uq/kds` (`%USERPROFILE%\.cache\uq\kds` on Windows).
    pub fn dir() -> Option<PathBuf> {
        match std::env::var("UQ_KDS_CACHE") {
            Ok(v) if matches!(v.trim(), "off" | "0" | "false") => return None,
            Ok(v) if !v.trim().is_empty() => return Some(PathBuf::from(v)),
            _ => {}
        }
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .ok()?;
        Some(PathBuf::from(home).join(".cache").join("uq").join("kds"))
    }

    /// TTL, overridable via `UQ_KDS_CACHE_TTL_SECS` but hard-capped at
    /// [`MAX_TTL_SECS`] so freshness can be tightened, never relaxed past the
    /// ceiling.
    pub fn ttl_secs() -> u64 {
        let requested = std::env::var("UQ_KDS_CACHE_TTL_SECS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(DEFAULT_TTL_SECS);
        if requested > MAX_TTL_SECS {
            eprintln!(
                "[uq/kds] UQ_KDS_CACHE_TTL_SECS={requested} exceeds the {MAX_TTL_SECS}s cap; clamping"
            );
            MAX_TTL_SECS
        } else {
            requested
        }
    }

    fn read_bounded(path: &Path, limit: usize) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .ok()?
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        (!bytes.is_empty() && bytes.len() <= limit).then_some(bytes)
    }

    /// Return untrusted cached bytes if present, fresh, and digest-matched.
    pub fn load(dir: &Path, url: &str) -> Option<Vec<u8>> {
        let k = key(url);
        let manifest_path = dir.join(format!("{k}.json"));
        let blob_path = dir.join(format!("{k}.bin"));
        let manifest: Manifest =
            serde_json::from_slice(&read_bounded(&manifest_path, 8192)?).ok()?;
        if manifest.url != url {
            return None; // sha256 collision guard / corruption
        }
        let current_time = now();
        if manifest.fetched_at > current_time
            || manifest.ttl_secs > MAX_TTL_SECS
            || current_time >= manifest.fetched_at.saturating_add(manifest.ttl_secs)
        {
            return None; // expired (ttl 0 == immediately expired)
        }
        let blob = read_bounded(&blob_path, MAX_BLOB_BYTES)?;
        if hex::encode(Sha256::digest(&blob)) != manifest.sha256 {
            eprintln!("[uq/kds] cache entry for {url} failed digest pin; ignoring");
            return None;
        }
        Some(blob)
    }

    /// Write `bytes` for `url` with the given TTL. Best-effort: cache write
    /// failures are logged and never fail the fetch.
    pub fn store(dir: &Path, url: &str, bytes: &[u8], ttl_secs: u64) {
        if bytes.is_empty() || bytes.len() > MAX_BLOB_BYTES {
            return;
        }
        if let Err(e) = std::fs::create_dir_all(dir) {
            eprintln!("[uq/kds] cache dir create failed: {e}");
            return;
        }
        let k = key(url);
        let manifest = Manifest {
            url: url.to_string(),
            fetched_at: now(),
            ttl_secs: ttl_secs.min(MAX_TTL_SECS),
            sha256: hex::encode(Sha256::digest(bytes)),
        };
        let blob_path = dir.join(format!("{k}.bin"));
        let manifest_path = dir.join(format!("{k}.json"));
        if let Err(e) = std::fs::write(&blob_path, bytes) {
            eprintln!("[uq/kds] cache blob write failed: {e}");
            return;
        }
        match serde_json::to_vec_pretty(&manifest) {
            Ok(j) => {
                if let Err(e) = std::fs::write(&manifest_path, j) {
                    eprintln!("[uq/kds] cache manifest write failed: {e}");
                }
            }
            Err(e) => eprintln!("[uq/kds] cache manifest encode failed: {e}"),
        }
    }
}

#[cfg(test)]
mod cache_tests {
    use super::cache;
    use sha2::Digest;

    #[test]
    fn store_then_load_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let url = "https://kdsintf.amd.com/vcek/v1/Milan/cert_chain";
        let bytes = b"-----BEGIN CERTIFICATE-----\nMII...\n-----END CERTIFICATE-----";
        cache::store(dir.path(), url, bytes, 3600);
        assert_eq!(cache::load(dir.path(), url).as_deref(), Some(&bytes[..]));
    }

    #[test]
    fn expired_entry_is_a_miss() {
        let dir = tempfile::tempdir().unwrap();
        let url = "https://kdsintf.amd.com/vcek/v1/Turin/cert_chain";
        cache::store(dir.path(), url, b"data", 0); // ttl 0 → already expired
        assert!(cache::load(dir.path(), url).is_none());
    }

    #[test]
    fn tampered_blob_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let url = "https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain";
        cache::store(dir.path(), url, b"trusted-bytes", 3600);
        // Flip the blob without updating the manifest digest.
        let k = hex::encode(sha2::Sha256::digest(url.as_bytes()));
        std::fs::write(dir.path().join(format!("{k}.bin")), b"evil-bytes").unwrap();
        assert!(cache::load(dir.path(), url).is_none());
    }

    #[test]
    fn unknown_url_is_a_miss() {
        let dir = tempfile::tempdir().unwrap();
        assert!(cache::load(dir.path(), "https://kdsintf.amd.com/nope").is_none());
    }

    #[test]
    fn forged_cache_time_and_oversized_data_are_misses() {
        let dir = tempfile::tempdir().unwrap();
        let url = "https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain";
        let k = hex::encode(sha2::Sha256::digest(url.as_bytes()));
        let path = dir.path().join(format!("{k}.json"));
        cache::store(dir.path(), url, b"data", 3600);
        let original = std::fs::read(&path).unwrap();
        for (field, value) in [("fetched_at", u64::MAX), ("ttl_secs", u64::MAX)] {
            let mut manifest: serde_json::Value = serde_json::from_slice(&original).unwrap();
            manifest[field] = value.into();
            std::fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
            assert!(cache::load(dir.path(), url).is_none());
        }
        let oversized = vec![0; 256 * 1024 + 1];
        let mut manifest: serde_json::Value = serde_json::from_slice(&original).unwrap();
        manifest["sha256"] = hex::encode(sha2::Sha256::digest(&oversized)).into();
        std::fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        std::fs::write(dir.path().join(format!("{k}.bin")), oversized).unwrap();
        assert!(cache::load(dir.path(), url).is_none());
    }

    #[test]
    fn product_detection_never_guesses_and_legacy_parameters_reject_turin() {
        let mut report = vec![0; 1184];
        report[..4].copy_from_slice(&2u32.to_le_bytes());
        assert!(super::snp_product(&report).is_err());
        report[..4].copy_from_slice(&5u32.to_le_bytes());
        assert!(super::snp_product(&report).is_err());
        for (family, model, expected) in [
            (0x19, 0x01, "Milan"),
            (0x19, 0x11, "Genoa"),
            (0x1a, 0x02, "Turin"),
            (0x1a, 0x11, "Turin"),
        ] {
            report[0x188] = family;
            report[0x189] = model;
            assert_eq!(super::snp_product(&report).unwrap(), expected);
        }
        assert!(super::extract_kds_params(&report).is_err());
        report[0x189] = 0x90;
        assert!(super::snp_product(&report).is_err());
        assert!(super::fetch_vcek("Turin", &[0; 64], 1, 1, 1, 1).is_err());
        assert!(super::fetch_cert_chain_kind("../Genoa", "vcek").is_err());
    }
}
