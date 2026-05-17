//! AMD SEV-SNP evidence collection.
//!
//! SEV-SNP attestation reports are collected via /dev/sev-guest ioctls:
//! - SNP_GET_REPORT: returns a signed attestation report (1184 bytes)
//! - SNP_GET_EXT_REPORT: returns report + certificate chain in one call
//!
//! The report contains:
//! - MEASUREMENT: hash of initial guest memory (launch digest)
//! - REPORT_DATA: 64 bytes of user-supplied data (we put sha256(pubkey) + value_x prefix)
//! - HOST_DATA: 32 bytes set by the hypervisor
//! - Signature: ECDSA-P384, signed by VCEK or VLEK
//!
//! Cert chain: ARK → ASK → VCEK/VLEK
//! Can be fetched from AMD KDS (kds.amd.com) or bundled via SNP_GET_EXT_REPORT.

use super::{TeeError, TeeEvidence, TeeProvider};
use crate::quote::Platform;
use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;

const SEV_GUEST_DEVICE: &str = "/dev/sev-guest";

/// ioctl request type for SNP_GET_REPORT
const SNP_GET_REPORT: u64 = 0xc0189600; // _IOWR('S', 0x00, struct snp_guest_request_ioctl)

/// ioctl request type for SNP_GET_EXT_REPORT (report + certs)
const SNP_GET_EXT_REPORT: u64 = 0xc0189602; // _IOWR('S', 0x02, struct snp_guest_request_ioctl)

/// SNP report request structure (matches kernel's struct snp_report_req)
#[repr(C)]
struct SnpReportReq {
    /// User-supplied data to include in the report
    report_data: [u8; 64],
    /// VMPL level (0 = most privileged)
    vmpl: u32,
    _reserved: [u8; 28],
}

/// SNP report response header
#[repr(C)]
struct SnpReportResp {
    /// Status (0 = success)
    status: u32,
    /// Size of the report data
    report_size: u32,
    _reserved: [u8; 24],
    // Followed by the attestation report bytes
}

/// ioctl argument structure (matches kernel's struct snp_guest_request_ioctl)
#[repr(C)]
struct SnpGuestRequestIoctl {
    /// Request message version (must be 1)
    msg_version: u8,
    _padding: [u8; 7],
    /// Pointer to request data
    req_data: u64,
    /// Pointer to response data
    resp_data: u64,
    /// Firmware error code (output)
    fw_err: u64,
}

/// Extended report ioctl argument (matches struct snp_ext_report_req)
#[repr(C)]
struct SnpExtReportReq {
    /// The report request
    data: SnpReportReq,
    /// Pointer to certificate buffer
    certs_address: u64,
    /// Size of certificate buffer (in/out)
    certs_len: u32,
    _reserved: [u8; 28],
}

pub struct SnpProvider;

impl SnpProvider {
    pub fn new() -> Result<Self, TeeError> {
        if !std::path::Path::new(SEV_GUEST_DEVICE).exists() {
            return Err(TeeError::DeviceNotFound(SEV_GUEST_DEVICE.into()));
        }
        Ok(Self)
    }
}

impl TeeProvider for SnpProvider {
    fn collect_evidence(&self, report_data: &[u8; 64]) -> Result<TeeEvidence, TeeError> {
        // Prefer configfs-tsm on Linux 6.7+ (works for SNP too)
        let tsm_report = std::path::Path::new("/sys/kernel/config/tsm/report");
        if tsm_report.exists() {
            match collect_via_configfs_tsm(report_data) {
                Ok(evidence) => return Ok(evidence),
                Err(e) => {
                    eprintln!("[bountynet/snp] configfs-tsm failed ({e}), falling back to ioctl");
                }
            }
        }

        // Fall back to /dev/sev-guest ioctl
        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .open(SEV_GUEST_DEVICE)
            .map_err(|e| TeeError::DeviceNotFound(format!("{SEV_GUEST_DEVICE}: {e}")))?;

        // First try SNP_GET_EXT_REPORT to get report + certs in one call.
        // If cert buffer is too small, the kernel returns the needed size.
        let mut certs_buf = vec![0u8; 8192]; // Start with 8KB for certs
        let mut report_buf = vec![0u8; 4096]; // Report response buffer

        let mut req = SnpExtReportReq {
            data: SnpReportReq {
                report_data: *report_data,
                vmpl: 0,
                _reserved: [0; 28],
            },
            certs_address: certs_buf.as_mut_ptr() as u64,
            certs_len: certs_buf.len() as u32,
            _reserved: [0; 28],
        };

        let mut ioctl_arg = SnpGuestRequestIoctl {
            msg_version: 1,
            _padding: [0; 7],
            req_data: &mut req as *mut SnpExtReportReq as u64,
            resp_data: report_buf.as_mut_ptr() as u64,
            fw_err: 0,
        };

        let ret = unsafe {
            libc::ioctl(
                fd.as_raw_fd(),
                SNP_GET_EXT_REPORT as libc::c_ulong,
                &mut ioctl_arg as *mut SnpGuestRequestIoctl,
            )
        };

        if ret < 0 {
            let errno = std::io::Error::last_os_error();
            // If ENOSPC, the cert buffer was too small. Retry with larger buffer.
            if errno.raw_os_error() == Some(libc::ENOSPC) {
                let needed = req.certs_len as usize;
                certs_buf.resize(needed, 0);
                req.certs_address = certs_buf.as_mut_ptr() as u64;
                req.certs_len = needed as u32;

                let ret2 = unsafe {
                    libc::ioctl(
                        fd.as_raw_fd(),
                        SNP_GET_EXT_REPORT as libc::c_ulong,
                        &mut ioctl_arg as *mut SnpGuestRequestIoctl,
                    )
                };
                if ret2 < 0 {
                    return Err(TeeError::Ioctl(nix::Error::last()));
                }
            } else {
                // Fall back to SNP_GET_REPORT (no certs)
                return self.collect_report_only(&fd, report_data);
            }
        }

        // Parse the response — the attestation report is in report_buf
        // after the SnpReportResp header (32 bytes)
        let resp_header: &SnpReportResp =
            unsafe { &*(report_buf.as_ptr() as *const SnpReportResp) };

        if resp_header.status != 0 {
            return Err(TeeError::InvalidResponse(format!(
                "SNP firmware error: status={}",
                resp_header.status
            )));
        }

        let report_size = resp_header.report_size as usize;
        let report_start = std::mem::size_of::<SnpReportResp>();
        let report_bytes = report_buf[report_start..report_start + report_size].to_vec();

        // Parse cert table from certs_buf if present
        let certs_len = req.certs_len as usize;
        let cert_chain = if certs_len > 0 {
            parse_snp_cert_table(&certs_buf[..certs_len])
        } else {
            Vec::new()
        };

        Ok(TeeEvidence {
            platform: Platform::SevSnp,
            raw_quote: report_bytes,
            cert_chain,
            kms_private_key: None,
        })
    }

    fn platform(&self) -> Platform {
        Platform::SevSnp
    }
}

impl SnpProvider {
    /// Fallback: SNP_GET_REPORT without certificate chain.
    fn collect_report_only(
        &self,
        fd: &std::fs::File,
        report_data: &[u8; 64],
    ) -> Result<TeeEvidence, TeeError> {
        let mut report_buf = vec![0u8; 4096];

        let mut req = SnpReportReq {
            report_data: *report_data,
            vmpl: 0,
            _reserved: [0; 28],
        };

        let mut ioctl_arg = SnpGuestRequestIoctl {
            msg_version: 1,
            _padding: [0; 7],
            req_data: &mut req as *mut SnpReportReq as u64,
            resp_data: report_buf.as_mut_ptr() as u64,
            fw_err: 0,
        };

        let ret = unsafe {
            libc::ioctl(
                fd.as_raw_fd(),
                SNP_GET_REPORT as libc::c_ulong,
                &mut ioctl_arg as *mut SnpGuestRequestIoctl,
            )
        };

        if ret < 0 {
            return Err(TeeError::Ioctl(nix::Error::last()));
        }

        let resp_header: &SnpReportResp =
            unsafe { &*(report_buf.as_ptr() as *const SnpReportResp) };
        let report_size = resp_header.report_size as usize;
        let report_start = std::mem::size_of::<SnpReportResp>();
        let report_bytes = report_buf[report_start..report_start + report_size].to_vec();

        Ok(TeeEvidence {
            platform: Platform::SevSnp,
            raw_quote: report_bytes,
            cert_chain: Vec::new(),
            kms_private_key: None,
        })
    }
}

/// Collect SNP evidence via configfs-tsm (Linux 6.7+).
/// Same interface as TDX configfs-tsm but provider is "sev_guest".
fn collect_via_configfs_tsm(report_data: &[u8; 64]) -> Result<TeeEvidence, TeeError> {
    use std::fs;

    let report_name = format!("bountynet-snp-{}", std::process::id());
    let report_dir = format!("/sys/kernel/config/tsm/report/{report_name}");

    fs::create_dir(&report_dir)
        .map_err(|e| TeeError::DeviceNotFound(format!("Failed to create {report_dir}: {e}")))?;

    // Write report_data
    fs::write(format!("{report_dir}/inblob"), report_data).map_err(|e| {
        let _ = fs::remove_dir(&report_dir);
        TeeError::InvalidResponse(format!("Failed to write inblob: {e}"))
    })?;

    // Read the quote
    let quote = fs::read(format!("{report_dir}/outblob")).map_err(|e| {
        let _ = fs::remove_dir(&report_dir);
        TeeError::InvalidResponse(format!("Failed to read outblob: {e}"))
    })?;

    // Try auxblob for certs
    let cert_chain = match fs::read(format!("{report_dir}/auxblob")) {
        Ok(aux) => vec![aux],
        Err(_) => Vec::new(),
    };

    let _ = fs::remove_dir(&report_dir);

    Ok(TeeEvidence {
        platform: Platform::SevSnp,
        raw_quote: quote,
        cert_chain,
        kms_private_key: None,
    })
}

/// Parse the SNP certificate table format.
/// The table is a sequence of (GUID, offset, length) entries followed by cert data.
fn parse_snp_cert_table(data: &[u8]) -> Vec<Vec<u8>> {
    let mut certs = Vec::new();

    // Certificate table entries are 24 bytes each:
    //   GUID (16 bytes) + offset (4 bytes) + length (4 bytes)
    // Table ends when GUID is all zeros.
    let mut pos = 0;
    let mut entries = Vec::new();

    while pos + 24 <= data.len() {
        let guid = &data[pos..pos + 16];
        if guid.iter().all(|&b| b == 0) {
            break; // End of table
        }
        let offset =
            u32::from_le_bytes(data[pos + 16..pos + 20].try_into().unwrap_or([0; 4])) as usize;
        let length =
            u32::from_le_bytes(data[pos + 20..pos + 24].try_into().unwrap_or([0; 4])) as usize;
        entries.push((offset, length));
        pos += 24;
    }

    for (offset, length) in entries {
        if offset + length <= data.len() {
            certs.push(data[offset..offset + length].to_vec());
        }
    }

    certs
}
