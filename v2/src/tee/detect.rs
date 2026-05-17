//! Auto-detect which TEE platform we're running in.
//!
//! Detection: check for platform-specific devices first (unambiguous),
//! then fall back to configfs-tsm with provider check.
//!
//! On Linux 6.7+, configfs-tsm (/sys/kernel/config/tsm/report) exists
//! for BOTH TDX and SNP. We must check the provider string to distinguish.

use super::{TeeError, TeeProvider};

/// Detect the TEE platform and return the appropriate provider.
#[cfg(not(unix))]
pub fn detect_tee() -> Result<Box<dyn TeeProvider>, TeeError> {
    Err(TeeError::NoTeeDetected)
}

/// Detect the TEE platform and return the appropriate provider.
#[cfg(unix)]
pub fn detect_tee() -> Result<Box<dyn TeeProvider>, TeeError> {
    use std::path::Path;

    // AWS Nitro: Nitro Security Module device (unambiguous)
    #[cfg(all(feature = "nitro", unix))]
    if Path::new("/dev/nsm").exists() {
        return Ok(Box::new(super::nitro::NitroProvider::new()?));
    }

    // Check platform-specific devices first (unambiguous)
    let has_tdx_device =
        Path::new("/dev/tdx-guest").exists() || Path::new("/dev/tdx_guest").exists();
    let has_snp_device = Path::new("/dev/sev-guest").exists();

    // If both exist (shouldn't happen, but be safe): prefer the specific device
    if has_tdx_device && !has_snp_device {
        #[cfg(all(feature = "tdx", unix))]
        return Ok(Box::new(super::tdx::TdxProvider::new()?));
    }
    if has_snp_device && !has_tdx_device {
        #[cfg(all(feature = "sev-snp", unix))]
        return Ok(Box::new(super::snp::SnpProvider::new()?));
    }

    // configfs-tsm: check the provider string to distinguish
    let tsm_report = Path::new("/sys/kernel/config/tsm/report");
    if tsm_report.exists() {
        // Create a temporary report entry to read the provider
        let probe_dir = tsm_report.join("bountynet-detect");
        if std::fs::create_dir(&probe_dir).is_ok() {
            let provider = std::fs::read_to_string(probe_dir.join("provider"))
                .unwrap_or_default()
                .trim()
                .to_string();
            let _ = std::fs::remove_dir(&probe_dir);

            match provider.as_str() {
                "tdx_guest" => {
                    #[cfg(all(feature = "tdx", unix))]
                    return Ok(Box::new(super::tdx::TdxProvider::new()?));
                }
                "sev_guest" => {
                    #[cfg(all(feature = "sev-snp", unix))]
                    return Ok(Box::new(super::snp::SnpProvider::new()?));
                }
                _ => {
                    // Unknown provider — fall through
                }
            }
        }
    }

    // Last resort: try devices again (in case we missed them above due to feature gates)
    #[cfg(all(feature = "sev-snp", unix))]
    if has_snp_device {
        return Ok(Box::new(super::snp::SnpProvider::new()?));
    }
    #[cfg(all(feature = "tdx", unix))]
    if has_tdx_device {
        return Ok(Box::new(super::tdx::TdxProvider::new()?));
    }

    Err(TeeError::NoTeeDetected)
}
