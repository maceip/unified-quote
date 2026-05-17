//! Intel TDX evidence collection.
//!
//! Two paths for collecting TD Quotes:
//!
//! 1. Modern (Linux 6.7+): /sys/kernel/config/tsm/report (configfs-tsm)
//!    - Unified kernel interface (also works for SEV-SNP on newer kernels)
//!    - Write report_data → read quote back
//!    - Preferred path
//!
//! 2. Legacy: /dev/tdx-guest or /dev/tdx_guest ioctl
//!    - TDX_CMD_GET_REPORT → TD Report (local, not remotely verifiable)
//!    - Then pass to QGS (Quote Generation Service) for a full TD Quote
//!
//! TD Quote contains:
//! - MRTD: hash of initial TD memory (firmware measurement, locked at boot)
//! - RTMR0-3: runtime measurement registers (extensible, like TPM PCRs)
//! - REPORTDATA: 64 bytes user data (we put sha256(pubkey) + value_x prefix)
//!
//! Quote is signed by the QE (Quoting Enclave) via Intel DCAP.

use super::{TeeError, TeeEvidence, TeeProvider};
use crate::quote::Platform;
use std::fs;
use std::os::unix::io::AsRawFd;
use std::path::Path;

/// configfs-tsm report directory
const TSM_REPORT_BASE: &str = "/sys/kernel/config/tsm/report";

/// ioctl number for TDX_CMD_GET_REPORT0 (legacy path)
const TDX_CMD_GET_REPORT0: u64 = 0xc0409401; // _IOWR('T', 0x01, struct tdx_report_req)

pub struct TdxProvider {
    /// Whether to use configfs-tsm (preferred) or legacy ioctl.
    use_configfs: bool,
}

impl TdxProvider {
    pub fn new() -> Result<Self, TeeError> {
        let use_configfs = Path::new(TSM_REPORT_BASE).exists();
        let has_legacy =
            Path::new("/dev/tdx-guest").exists() || Path::new("/dev/tdx_guest").exists();

        if !use_configfs && !has_legacy {
            return Err(TeeError::DeviceNotFound("tdx-guest".into()));
        }

        Ok(Self { use_configfs })
    }
}

impl TeeProvider for TdxProvider {
    fn collect_evidence(&self, report_data: &[u8; 64]) -> Result<TeeEvidence, TeeError> {
        if self.use_configfs {
            collect_via_configfs(report_data)
        } else {
            collect_via_ioctl(report_data)
        }
    }

    fn platform(&self) -> Platform {
        Platform::Tdx
    }
}

/// Preferred path: configfs-tsm (Linux 6.7+).
///
/// 1. mkdir /sys/kernel/config/tsm/report/<name>
/// 2. Write report_data to inblob
/// 3. Read quote from outblob
/// 4. Optionally read auxblob for cert chain
/// 5. rmdir the report entry
fn collect_via_configfs(report_data: &[u8; 64]) -> Result<TeeEvidence, TeeError> {
    let report_name = format!("bountynet-{}", std::process::id());
    let report_dir = format!("{TSM_REPORT_BASE}/{report_name}");

    // Create the report directory
    fs::create_dir(&report_dir)
        .map_err(|e| TeeError::DeviceNotFound(format!("Failed to create {report_dir}: {e}")))?;

    // Cleanup on any error
    let _cleanup = scopeguard(&report_dir);

    // Write report_data as hex to inblob
    fs::write(format!("{report_dir}/inblob"), report_data)
        .map_err(|e| TeeError::InvalidResponse(format!("Failed to write inblob: {e}")))?;

    // Read the provider to confirm it's TDX
    let provider = fs::read_to_string(format!("{report_dir}/provider")).unwrap_or_default();
    if !provider.trim().is_empty() && !provider.contains("tdx") {
        return Err(TeeError::InvalidResponse(format!(
            "configfs-tsm provider is '{provider}', expected tdx"
        )));
    }

    // Read the quote from outblob
    let quote = fs::read(format!("{report_dir}/outblob"))
        .map_err(|e| TeeError::InvalidResponse(format!("Failed to read outblob: {e}")))?;

    // Try to read aux certs (may not exist)
    let cert_chain = match fs::read(format!("{report_dir}/auxblob")) {
        Ok(aux_data) => vec![aux_data],
        Err(_) => Vec::new(),
    };

    // Cleanup
    let _ = fs::remove_dir(&report_dir);

    Ok(TeeEvidence {
        platform: Platform::Tdx,
        raw_quote: quote,
        cert_chain,
        kms_private_key: None,
    })
}

/// Simple scope guard for directory cleanup
fn scopeguard(dir: &str) -> impl Drop + '_ {
    struct Guard<'a>(&'a str);
    impl Drop for Guard<'_> {
        fn drop(&mut self) {
            let _ = fs::remove_dir(self.0);
        }
    }
    Guard(dir)
}

/// Legacy path: /dev/tdx-guest ioctl → TD Report → needs QGS for full Quote.
///
/// Note: This only produces a TD Report (not a full TD Quote).
/// A full Quote requires the Quote Generation Service (QGS) which
/// is typically a separate service running on the host.
fn collect_via_ioctl(report_data: &[u8; 64]) -> Result<TeeEvidence, TeeError> {
    let dev_path = if Path::new("/dev/tdx-guest").exists() {
        "/dev/tdx-guest"
    } else if Path::new("/dev/tdx_guest").exists() {
        "/dev/tdx_guest"
    } else {
        return Err(TeeError::DeviceNotFound("tdx-guest device".into()));
    };

    let fd = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(dev_path)
        .map_err(|e| TeeError::DeviceNotFound(format!("{dev_path}: {e}")))?;

    // TDX_CMD_GET_REPORT0 request structure
    // struct tdx_report_req {
    //     __u8 reportdata[64];  // Input: user data
    //     __u8 tdreport[1024];  // Output: TD Report
    // };
    #[repr(C)]
    struct TdxReportReq {
        reportdata: [u8; 64],
        tdreport: [u8; 1024],
    }

    let mut req = TdxReportReq {
        reportdata: *report_data,
        tdreport: [0u8; 1024],
    };

    let ret = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            TDX_CMD_GET_REPORT0 as libc::c_ulong,
            &mut req as *mut TdxReportReq,
        )
    };

    if ret < 0 {
        return Err(TeeError::Ioctl(nix::Error::last()));
    }

    // The TD Report is a local attestation structure.
    // For remote attestation, we'd need to send this to QGS to get a full TD Quote.
    // For now, return the raw TD Report — the caller would need to contact QGS.
    Ok(TeeEvidence {
        platform: Platform::Tdx,
        raw_quote: req.tdreport.to_vec(),
        cert_chain: Vec::new(),
        kms_private_key: None,
    })
}
