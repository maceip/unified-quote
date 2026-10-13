//! AMD SEV-SNP signed-report collection through configfs-TSM or, when that
//! interface is absent, the Linux SNP_GET_EXT_REPORT ioctl. A failed configfs
//! request never silently changes transports or drops endorsement errors.

use super::{
    detect::{path_exists, TsmRequest, TSM_REPORT_BASE},
    TeeError, TeeEvidence, TeeProvider,
};
use crate::quote::Platform;
use std::{collections::BTreeSet, fs::OpenOptions, os::unix::io::AsRawFd, path::Path};

const SEV_GUEST_DEVICE: &str = "/dev/sev-guest";
const REPORT_BYTES: usize = 1184;
const RESPONSE_BYTES: usize = 4000;
// Linux SEV_FW_BLOB_MAX_SIZE. Allocate the driver's maximum once; never trust
// an unbounded hypervisor-supplied retry size.
const MAX_CERT_TABLE_BYTES: usize = 0x4000;
// Linux x86_64 _IOWR('S', 0x02, struct snp_guest_request_ioctl), sizeof=32.
const SNP_GET_EXT_REPORT: u64 = 0xc0205302;

#[repr(C)]
struct SnpReportReq {
    report_data: [u8; 64],
    vmpl: u32,
    reserved: [u8; 28],
}

#[repr(C)]
struct SnpGuestRequestIoctl {
    msg_version: u8,
    padding: [u8; 7],
    req_data: u64,
    resp_data: u64,
    // Low32 firmware error; high32 VMM error, per Linux sev-guest.h.
    exitinfo2: u64,
}

#[repr(C)]
struct SnpExtReportReq {
    data: SnpReportReq,
    certs_address: u64,
    certs_len: u32,
    padding: [u8; 4],
}

pub struct SnpProvider {
    use_configfs: bool,
}

impl SnpProvider {
    pub fn new() -> Result<Self, TeeError> {
        let use_configfs = path_exists(Path::new(TSM_REPORT_BASE))?;
        if use_configfs {
            let request = TsmRequest::create(Path::new(TSM_REPORT_BASE), "snp-probe")?;
            request.require_provider("sev_guest")?;
            request.finish()?;
        } else if !path_exists(Path::new(SEV_GUEST_DEVICE))? {
            return Err(TeeError::DeviceNotFound(SEV_GUEST_DEVICE.into()));
        }
        Ok(Self { use_configfs })
    }
}

impl TeeProvider for SnpProvider {
    fn collect_evidence(&self, report_data: &[u8; 64]) -> Result<TeeEvidence, TeeError> {
        if self.use_configfs {
            return collect_via_configfs(report_data);
        }
        collect_via_ioctl(report_data)
    }

    fn platform(&self) -> Platform {
        Platform::SevSnp
    }
}

fn collect_via_configfs(report_data: &[u8; 64]) -> Result<TeeEvidence, TeeError> {
    let request = TsmRequest::create(Path::new(TSM_REPORT_BASE), "snp")?;
    request.require_provider("sev_guest")?;
    request.write_report_data(report_data)?;
    let report = request.read_blob("outblob", REPORT_BYTES)?;
    validate_report(&report, report_data)?;
    let cert_table = request
        .optional_blob("auxblob", MAX_CERT_TABLE_BYTES)?
        .unwrap_or_default();
    let evidence = assemble_evidence(report, &cert_table)?;
    request.require_provider("sev_guest")?;
    request.finish()?;
    Ok(evidence)
}

fn collect_via_ioctl(report_data: &[u8; 64]) -> Result<TeeEvidence, TeeError> {
    // This ioctl number and UAPI layout are specific to the Linux x86_64 SNP
    // driver. Other hosts may parse evidence but must not execute this ABI.
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return Err(TeeError::DeviceNotFound(
            "SNP guest ioctl requires Linux x86_64".into(),
        ));
    }
    let fd = OpenOptions::new()
        .read(true)
        .write(true)
        .open(SEV_GUEST_DEVICE)
        .map_err(|e| TeeError::DeviceNotFound(format!("{SEV_GUEST_DEVICE}: {e}")))?;
    let mut certs = vec![0; MAX_CERT_TABLE_BYTES];
    let mut response = [0; RESPONSE_BYTES];
    let mut request = SnpExtReportReq {
        data: SnpReportReq {
            report_data: *report_data,
            vmpl: 0,
            reserved: [0; 28],
        },
        certs_address: certs.as_mut_ptr() as u64,
        certs_len: certs.len() as u32,
        padding: [0; 4],
    };
    let mut argument = SnpGuestRequestIoctl {
        msg_version: 1,
        padding: [0; 7],
        req_data: &mut request as *mut SnpExtReportReq as u64,
        resp_data: response.as_mut_ptr() as u64,
        exitinfo2: 0,
    };
    // All pointers refer to live, initialized allocations of the exact UAPI
    // sizes for the duration of the call. Bytes are decoded without casts.
    let ret = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            SNP_GET_EXT_REPORT as libc::c_ulong,
            &mut argument as *mut SnpGuestRequestIoctl,
        )
    };
    if ret < 0 {
        if argument.exitinfo2 != 0 {
            return Err(TeeError::InvalidResponse(format!(
                "SNP_GET_EXT_REPORT firmware error={:#x}, VMM error={:#x}, requested certificate bytes={}",
                argument.exitinfo2 as u32, argument.exitinfo2 >> 32, request.certs_len,
            )));
        }
        return Err(TeeError::Ioctl(nix::Error::last()));
    }
    if argument.exitinfo2 != 0 {
        return Err(TeeError::InvalidResponse(format!(
            "SNP_GET_EXT_REPORT returned error status {:#x}",
            argument.exitinfo2
        )));
    }
    let report = parse_response(&response, report_data)?.to_vec();
    if report[0x30..0x34] != 0u32.to_le_bytes() {
        return Err(TeeError::InvalidResponse(
            "SNP report VMPL differs from requested VMPL0".into(),
        ));
    }
    let cert_len = request.certs_len as usize;
    if cert_len > certs.len() {
        return Err(TeeError::InvalidResponse(
            "SNP certificate response length exceeds allocated buffer".into(),
        ));
    }
    assemble_evidence(report, &certs[..cert_len])
}

fn parse_response<'a>(response: &'a [u8], report_data: &[u8; 64]) -> Result<&'a [u8], TeeError> {
    if response.len() != RESPONSE_BYTES {
        return Err(TeeError::InvalidResponse(
            "SNP ioctl response size mismatch".into(),
        ));
    }
    let status = u32::from_le_bytes(response[0..4].try_into().unwrap());
    let report_len = u32::from_le_bytes(response[4..8].try_into().unwrap()) as usize;
    if status != 0 || report_len != REPORT_BYTES || response[8..32].iter().any(|v| *v != 0) {
        return Err(TeeError::InvalidResponse(format!(
            "SNP response status={status}, report_size={report_len}, or reserved bytes invalid"
        )));
    }
    let report = &response[32..32 + REPORT_BYTES];
    validate_report(report, report_data)?;
    Ok(report)
}

/// Structural/challenge checks, never a claim of signature authentication.
fn validate_report(report: &[u8], report_data: &[u8; 64]) -> Result<(), TeeError> {
    if report.len() != REPORT_BYTES {
        return Err(TeeError::InvalidResponse(
            "SNP signed report must be exactly 1184 bytes".into(),
        ));
    }
    let version = u32::from_le_bytes(report[0..4].try_into().unwrap());
    if !matches!(version, 2 | 5) {
        return Err(TeeError::InvalidResponse(format!(
            "unsupported SNP report version {version}; verifier supports 2 and 5"
        )));
    }
    if report[0x34..0x38] != 1u32.to_le_bytes() {
        return Err(TeeError::InvalidResponse(
            "SNP report signature algorithm must be ECDSA-P384-SHA384".into(),
        ));
    }
    if report[0x50..0x90] != report_data[..] {
        return Err(TeeError::InvalidResponse(
            "SNP REPORT_DATA does not match this collection request".into(),
        ));
    }
    Ok(())
}

fn assemble_evidence(mut report: Vec<u8>, table: &[u8]) -> Result<TeeEvidence, TeeError> {
    let cert_chain = parse_snp_cert_table(table)?;
    if !table.is_empty() {
        report.extend_from_slice(table);
    }
    Ok(TeeEvidence {
        platform: Platform::SevSnp,
        raw_quote: report,
        cert_chain,
        kms_private_key: None,
    })
}

/// Decode the GHCB certificate table only after every entry's framing is valid.
/// Endorsement authenticity is checked by the remote verifier, not this parser.
fn parse_snp_cert_table(data: &[u8]) -> Result<Vec<Vec<u8>>, TeeError> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    if data.len() > MAX_CERT_TABLE_BYTES {
        return Err(TeeError::InvalidResponse(
            "SNP certificate table exceeds kernel maximum".into(),
        ));
    }
    let invalid = || TeeError::InvalidResponse("malformed SNP certificate table".into());
    let mut entries = Vec::new();
    let mut guids = BTreeSet::new();
    let mut position = 0;
    let table_end = loop {
        let entry = data.get(position..position + 24).ok_or_else(invalid)?;
        position += 24;
        let guid: [u8; 16] = entry[..16].try_into().unwrap();
        let offset = u32::from_le_bytes(entry[16..20].try_into().unwrap()) as usize;
        let length = u32::from_le_bytes(entry[20..24].try_into().unwrap()) as usize;
        if guid == [0; 16] {
            if offset != 0 || length != 0 {
                return Err(invalid());
            }
            break position;
        }
        if !guids.insert(guid) || entries.len() >= 32 || length == 0 {
            return Err(invalid());
        }
        let end = offset.checked_add(length).ok_or_else(invalid)?;
        if end > data.len() {
            return Err(invalid());
        }
        entries.push((offset, end));
    };
    let mut ranges = entries.clone();
    ranges.sort_unstable();
    let mut prior_end = table_end;
    for (start, end) in ranges {
        if start < prior_end {
            return Err(invalid());
        }
        prior_end = end;
    }
    Ok(entries
        .into_iter()
        .map(|(start, end)| data[start..end].to_vec())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioctl_structs_match_linux_x86_64_uapi() {
        assert_eq!(std::mem::size_of::<SnpReportReq>(), 96);
        assert_eq!(std::mem::size_of::<SnpExtReportReq>(), 112);
        assert_eq!(std::mem::size_of::<SnpGuestRequestIoctl>(), 32);
        assert_eq!(std::mem::offset_of!(SnpExtReportReq, certs_address), 96);
        assert_eq!(std::mem::offset_of!(SnpExtReportReq, certs_len), 104);
        assert_eq!(std::mem::offset_of!(SnpGuestRequestIoctl, req_data), 8);
        let linux_iowr = (3u64 << 30) | (32 << 16) | ((b'S' as u64) << 8) | 2;
        assert_eq!(SNP_GET_EXT_REPORT, linux_iowr);
    }

    #[test]
    fn response_requires_exact_size_status_algorithm_and_challenge() {
        let nonce = [9; 64];
        let mut response = vec![0; RESPONSE_BYTES];
        response[4..8].copy_from_slice(&(REPORT_BYTES as u32).to_le_bytes());
        response[32..36].copy_from_slice(&2u32.to_le_bytes());
        response[32 + 0x34..32 + 0x38].copy_from_slice(&1u32.to_le_bytes());
        response[32 + 0x50..32 + 0x90].copy_from_slice(&nonce);
        // Framing only. The zero signature in this vector is not trusted.
        parse_response(&response, &nonce).unwrap();
        assert!(parse_response(&response, &[0; 64]).is_err());
        for (index, byte) in [(0, 1), (8, 1), (4, 0), (32, 3), (32 + 0x34, 0)] {
            let mut changed = response.clone();
            changed[index] = byte;
            assert!(parse_response(&changed, &nonce).is_err());
        }
        response.pop();
        assert!(parse_response(&response, &nonce).is_err());
    }

    #[test]
    fn certificate_table_rejects_missing_terminator_overlap_and_duplicates() {
        let mut table = vec![0; 104];
        table[0..16].fill(1);
        table[16..20].copy_from_slice(&72u32.to_le_bytes());
        table[20..24].copy_from_slice(&16u32.to_le_bytes());
        table[24..40].fill(2);
        table[40..44].copy_from_slice(&88u32.to_le_bytes());
        table[44..48].copy_from_slice(&16u32.to_le_bytes());
        table[72..88].fill(5);
        table[88..104].fill(6);
        assert_eq!(
            parse_snp_cert_table(&table).unwrap(),
            vec![vec![5; 16], vec![6; 16]]
        );
        assert_eq!(
            parse_snp_cert_table(&[0; 24]).unwrap(),
            Vec::<Vec<u8>>::new()
        );
        for (offset, value) in [(16, 0u32), (20, u32::MAX), (40, 80u32), (64, 1u32)] {
            let mut changed = table.clone();
            changed[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            assert!(parse_snp_cert_table(&changed).is_err());
        }
        let mut changed = table.clone();
        changed[24..40].fill(1);
        assert!(parse_snp_cert_table(&changed).is_err());
        assert!(parse_snp_cert_table(&table[..48]).is_err());
        assert!(parse_snp_cert_table(&table[..103]).is_err());
    }
}
