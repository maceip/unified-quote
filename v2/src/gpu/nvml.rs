//! Minimal read-only bindings to NVIDIA's public NVML confidential-computing
//! ABI. See the pinned reference links in `v2/GPU.md`. No NVIDIA SDK, headers,
//! Python, external verifier, or link-time driver dependency is required.

use std::collections::HashSet;
use std::ffi::{c_char, c_int, c_uint, c_void};

use libloading::Library;

use super::spdm::{SpdmReport, MAX_REPORT_SIZE};
use super::{GpuError, GpuEvidence, GpuEvidenceBundle, NvmlCcState};

const MAX_GPUS: u32 = 256;
const CERT_CHAIN_SIZE: usize = 0x1000;
const ATTESTATION_CERT_CHAIN_SIZE: usize = 0x1400;
const CEC_REPORT_SIZE: usize = 0x1000;

type Device = *mut c_void;
type Init = unsafe extern "C" fn() -> c_int;
type Shutdown = unsafe extern "C" fn() -> c_int;
type Count = unsafe extern "C" fn(*mut c_uint) -> c_int;
type Handle = unsafe extern "C" fn(c_uint, *mut Device) -> c_int;
type DriverVersion = unsafe extern "C" fn(*mut c_char, c_uint) -> c_int;
type DeviceString = unsafe extern "C" fn(Device, *mut c_char, c_uint) -> c_int;
type State = unsafe extern "C" fn(*mut RawCcState) -> c_int;
type Certificate = unsafe extern "C" fn(Device, *mut RawCertificate) -> c_int;
type Report = unsafe extern "C" fn(Device, *mut RawReport) -> c_int;

#[repr(C)]
#[derive(Default)]
struct RawCcState {
    environment: c_uint,
    cc_feature: c_uint,
    dev_tools_mode: c_uint,
}

#[repr(C)]
struct RawCertificate {
    cert_chain_size: c_uint,
    attestation_cert_chain_size: c_uint,
    cert_chain: [u8; CERT_CHAIN_SIZE],
    attestation_cert_chain: [u8; ATTESTATION_CERT_CHAIN_SIZE],
}

#[repr(C)]
struct RawReport {
    cec_present: c_uint,
    report_size: c_uint,
    cec_report_size: c_uint,
    nonce: [u8; 32],
    report: [u8; MAX_REPORT_SIZE],
    cec_report: [u8; CEC_REPORT_SIZE],
}

impl RawCertificate {
    fn empty() -> Self {
        Self {
            cert_chain_size: 0,
            attestation_cert_chain_size: 0,
            cert_chain: [0; CERT_CHAIN_SIZE],
            attestation_cert_chain: [0; ATTESTATION_CERT_CHAIN_SIZE],
        }
    }

    fn extract(&self) -> Result<(Vec<u8>, Vec<u8>), GpuError> {
        // The identity chain may be absent on some drivers. The attestation
        // chain used for report signatures must always be retained/nonempty.
        Ok((
            checked_buffer(
                &self.cert_chain,
                self.cert_chain_size,
                false,
                "certificate chain",
            )?,
            checked_buffer(
                &self.attestation_cert_chain,
                self.attestation_cert_chain_size,
                true,
                "attestation certificate chain",
            )?,
        ))
    }
}

impl RawReport {
    fn for_nonce(nonce: [u8; 32]) -> Self {
        Self {
            cec_present: 0,
            report_size: 0,
            cec_report_size: 0,
            nonce,
            report: [0; MAX_REPORT_SIZE],
            cec_report: [0; CEC_REPORT_SIZE],
        }
    }

    fn extract(&self, expected_nonce: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), GpuError> {
        if self.nonce != *expected_nonce {
            return Err(GpuError::InvalidEvidence(
                "NVML changed the input nonce".into(),
            ));
        }
        let report = checked_buffer(&self.report, self.report_size, true, "SPDM report")?;
        // Validate the transcript nonce too; checking the input buffer alone
        // would accept a cached report. This still does not verify a signature.
        SpdmReport::parse(&report)?.check_nonce(expected_nonce)?;
        let cec = match self.cec_present {
            0 if self.cec_report_size == 0 => Vec::new(),
            1 => checked_buffer(&self.cec_report, self.cec_report_size, true, "CEC report")?,
            _ => {
                return Err(GpuError::InvalidEvidence(
                    "inconsistent CEC report presence/size".into(),
                ))
            }
        };
        Ok((report, cec))
    }
}

/// An initialized NVML session. Drop calls nvmlShutdown before unloading the
/// library. Every device must succeed or collection returns an error, so a
/// failed device cannot silently disappear from the resulting evidence.
pub struct NvmlCollector {
    initialized: bool,
    shutdown: Shutdown,
    count: Count,
    handle: Handle,
    driver_version: DriverVersion,
    uuid: DeviceString,
    name: DeviceString,
    vbios: DeviceString,
    state: State,
    ready: Count,
    certificate: Certificate,
    report: Report,
    // Owns the loaded code for the entire lifetime of the function pointers.
    _library: Library,
}

/// Driver observations only. These values are not signed security claims.
#[derive(Debug, serde::Serialize)]
pub struct NvmlStatus {
    pub driver_version: String,
    pub cc_state: NvmlCcState,
    pub devices: Vec<NvmlDeviceStatus>,
}

#[derive(Debug, serde::Serialize)]
pub struct NvmlDeviceStatus {
    pub index: u32,
    pub uuid: String,
    pub name: String,
    pub vbios_version: String,
}

impl NvmlCollector {
    /// Query readiness and inventory without issuing an attestation report or
    /// changing GPU readiness. A changed inventory is an error, not a partial
    /// successful observation.
    pub fn status(&self) -> Result<NvmlStatus, GpuError> {
        let count = self.device_count()?;
        if count > MAX_GPUS {
            return Err(GpuError::InvalidEvidence(
                "GPU status count exceeds limit".into(),
            ));
        }
        let cc_state = self.cc_state()?;
        let mut driver = [0u8; 80];
        // SAFETY: the output buffer and its length match for this live session.
        check(
            unsafe { (self.driver_version)(driver.as_mut_ptr().cast(), driver.len() as c_uint) },
            "nvmlSystemGetDriverVersion",
        )?;
        let driver_version = read_string(&driver, "driver version")?;
        let mut devices = Vec::with_capacity(count as usize);
        let mut seen = HashSet::new();
        for index in 0..count {
            let device = self.device(index)?;
            let uuid = self.device_string(device, self.uuid, 96, "nvmlDeviceGetUUID")?;
            if !seen.insert(uuid.clone()) {
                return Err(GpuError::InvalidEvidence("duplicate NVML GPU UUID".into()));
            }
            devices.push(NvmlDeviceStatus {
                index,
                uuid,
                name: self.device_string(device, self.name, 96, "nvmlDeviceGetName")?,
                vbios_version: self.device_string(
                    device,
                    self.vbios,
                    32,
                    "nvmlDeviceGetVbiosVersion",
                )?,
            });
        }
        if self.device_count()? != count || self.cc_state()? != cc_state {
            return Err(GpuError::InvalidEvidence(
                "GPU inventory or CC state changed during status query".into(),
            ));
        }
        for device in &devices {
            if self.device_string(
                self.device(device.index)?,
                self.uuid,
                96,
                "nvmlDeviceGetUUID",
            )? != device.uuid
            {
                return Err(GpuError::InvalidEvidence(
                    "GPU identity changed during status query".into(),
                ));
            }
        }
        Ok(NvmlStatus {
            driver_version,
            cc_state,
            devices,
        })
    }

    pub fn open() -> Result<Self, GpuError> {
        if !cfg!(target_os = "linux") {
            return Err(GpuError::UnsupportedHost);
        }
        // SAFETY: load the system NVIDIA driver by its documented soname. Its
        // initialization routines are trusted native driver code. Callers must
        // protect the dynamic loader search path as for any native dependency.
        let library = unsafe { Library::new("libnvidia-ml.so.1") }
            .or_else(|_| unsafe { Library::new("libnvidia-ml.so") })
            .map_err(|e| GpuError::Library(e.to_string()))?;
        // SAFETY: signatures and repr(C) structures match NVIDIA's NVML ABI.
        // Resolve every required symbol before init, so a missing symbol
        // cannot leak an initialized session. Keep the library alive in Self.
        unsafe {
            let init: Init = symbol(&library, b"nvmlInit_v2\0")?;
            let mut collector = Self {
                initialized: false,
                shutdown: symbol(&library, b"nvmlShutdown\0")?,
                count: symbol(&library, b"nvmlDeviceGetCount_v2\0")?,
                handle: symbol(&library, b"nvmlDeviceGetHandleByIndex_v2\0")?,
                driver_version: symbol(&library, b"nvmlSystemGetDriverVersion\0")?,
                uuid: symbol(&library, b"nvmlDeviceGetUUID\0")?,
                name: symbol(&library, b"nvmlDeviceGetName\0")?,
                vbios: symbol(&library, b"nvmlDeviceGetVbiosVersion\0")?,
                state: symbol(&library, b"nvmlSystemGetConfComputeState\0")?,
                ready: symbol(&library, b"nvmlSystemGetConfComputeGpusReadyState\0")?,
                certificate: symbol(&library, b"nvmlDeviceGetConfComputeGpuCertificate\0")?,
                report: symbol(&library, b"nvmlDeviceGetConfComputeGpuAttestationReport\0")?,
                _library: library,
            };
            // Do not call Shutdown if initialization failed: NVML may be in
            // use by another component in the same process.
            check(init(), "nvmlInit_v2")?;
            collector.initialized = true;
            Ok(collector)
        }
    }

    /// Capture all GPUs using exactly the caller's 32-byte challenge. This
    /// produces unverified evidence and never marks GPUs ready for workloads.
    /// Enumeration and driver-reported state are checked for changes during
    /// collection, but do not prove a physical topology or fabric policy.
    pub fn collect(&self, nonce: [u8; 32]) -> Result<GpuEvidenceBundle, GpuError> {
        let count = self.device_count()?;
        if count == 0 || count > MAX_GPUS {
            return Err(GpuError::InvalidEvidence(format!(
                "GPU count {count} is outside 1..={MAX_GPUS}"
            )));
        }
        let cc_state = self.cc_state()?;
        let mut driver = [0u8; 80];
        // SAFETY: buffer and length agree; NVML session/library remain alive.
        check(
            unsafe { (self.driver_version)(driver.as_mut_ptr().cast(), driver.len() as c_uint) },
            "nvmlSystemGetDriverVersion",
        )?;
        let driver_version = read_string(&driver, "driver version")?;
        let mut gpus = Vec::with_capacity(count as usize);
        let mut uuids = HashSet::new();
        for index in 0..count {
            let gpu = self
                .collect_device(index, &nonce)
                .map_err(|source| GpuError::Device {
                    index,
                    source: Box::new(source),
                })?;
            if !uuids.insert(gpu.uuid.clone()) {
                return Err(GpuError::InvalidEvidence("duplicate NVML GPU UUID".into()));
            }
            gpus.push(gpu);
        }
        if self.device_count()? != count || self.cc_state()? != cc_state {
            return Err(GpuError::InvalidEvidence(
                "GPU inventory or CC state changed during collection".into(),
            ));
        }
        // Detect replacement/reordering even when the total count is stable.
        for gpu in &gpus {
            let device = self.device(gpu.index)?;
            if self.device_string(device, self.uuid, 96, "nvmlDeviceGetUUID")? != gpu.uuid {
                return Err(GpuError::InvalidEvidence(
                    "GPU identity changed during collection".into(),
                ));
            }
        }
        Ok(GpuEvidenceBundle {
            version: 1,
            nonce,
            driver_version,
            cc_state,
            gpus,
            switches: Vec::new(),
            collateral: Default::default(),
        })
    }

    fn device_count(&self) -> Result<u32, GpuError> {
        let mut count = 0;
        // SAFETY: valid output pointer for a live NVML session.
        check(unsafe { (self.count)(&mut count) }, "nvmlDeviceGetCount_v2")?;
        Ok(count)
    }

    fn cc_state(&self) -> Result<NvmlCcState, GpuError> {
        let mut state = RawCcState::default();
        let mut ready = 0;
        // SAFETY: output structures match the ABI and are writable.
        check(
            unsafe { (self.state)(&mut state) },
            "nvmlSystemGetConfComputeState",
        )?;
        check(
            unsafe { (self.ready)(&mut ready) },
            "nvmlSystemGetConfComputeGpusReadyState",
        )?;
        Ok(NvmlCcState {
            environment: state.environment,
            cc_feature: state.cc_feature,
            dev_tools_mode: state.dev_tools_mode,
            accepting_client_requests: ready,
        })
    }

    fn device(&self, index: u32) -> Result<Device, GpuError> {
        let mut device = std::ptr::null_mut();
        // SAFETY: valid output pointer; index is checked by NVML.
        check(
            unsafe { (self.handle)(index, &mut device) },
            "nvmlDeviceGetHandleByIndex_v2",
        )?;
        if device.is_null() {
            return Err(GpuError::InvalidEvidence(
                "NVML returned a null device handle".into(),
            ));
        }
        Ok(device)
    }

    fn device_string(
        &self,
        device: Device,
        function: DeviceString,
        size: usize,
        operation: &'static str,
    ) -> Result<String, GpuError> {
        let mut buffer = vec![0u8; size];
        // SAFETY: private helper receives a handle returned by this session;
        // buffer/length match and the function signature is checked on load.
        check(
            unsafe { function(device, buffer.as_mut_ptr().cast(), size as c_uint) },
            operation,
        )?;
        read_string(&buffer, operation)
    }

    fn collect_device(&self, index: u32, nonce: &[u8; 32]) -> Result<GpuEvidence, GpuError> {
        let device = self.device(index)?;
        let uuid = self.device_string(device, self.uuid, 96, "nvmlDeviceGetUUID")?;
        let name = self.device_string(device, self.name, 96, "nvmlDeviceGetName")?;
        let vbios_version =
            self.device_string(device, self.vbios, 32, "nvmlDeviceGetVbiosVersion")?;
        let mut certificate = Box::new(RawCertificate::empty());
        let mut report = Box::new(RawReport::for_nonce(*nonce));
        // SAFETY: fixed-capacity repr(C) output buffers match NVML exactly.
        // All returned lengths are bounded before accessing these buffers.
        check(
            unsafe { (self.certificate)(device, &mut *certificate) },
            "nvmlDeviceGetConfComputeGpuCertificate",
        )?;
        let (certificate_chain, attestation_certificate_chain) = certificate.extract()?;
        check(
            unsafe { (self.report)(device, &mut *report) },
            "nvmlDeviceGetConfComputeGpuAttestationReport",
        )?;
        let (attestation_report, cec_attestation_report) = report.extract(nonce)?;
        Ok(GpuEvidence {
            index,
            uuid,
            name,
            vbios_version,
            certificate_chain,
            attestation_certificate_chain,
            attestation_report,
            cec_attestation_report,
        })
    }
}

impl Drop for NvmlCollector {
    fn drop(&mut self) {
        // SAFETY: exactly one shutdown for this successful init; the owned
        // library is still loaded until after this Drop implementation.
        if self.initialized {
            unsafe {
                (self.shutdown)();
            }
        }
    }
}

unsafe fn symbol<T: Copy>(library: &Library, name: &[u8]) -> Result<T, GpuError> {
    // SAFETY: callers supply an ABI-correct function type and retain Library.
    unsafe { library.get::<T>(name) }
        .map(|symbol| *symbol)
        .map_err(|e| GpuError::Library(e.to_string()))
}

fn check(code: c_int, operation: &'static str) -> Result<(), GpuError> {
    if code == 0 {
        Ok(())
    } else {
        Err(GpuError::Nvml { operation, code })
    }
}

fn checked_buffer(
    bytes: &[u8],
    length: u32,
    required: bool,
    field: &str,
) -> Result<Vec<u8>, GpuError> {
    if (required && length == 0) || length as usize > bytes.len() {
        return Err(GpuError::InvalidEvidence(format!(
            "{field} length {length} exceeds capacity {} or is empty",
            bytes.len()
        )));
    }
    Ok(bytes[..length as usize].to_vec())
}

fn read_string(bytes: &[u8], field: &str) -> Result<String, GpuError> {
    let end = bytes
        .iter()
        .position(|b| *b == 0)
        .filter(|end| *end > 0)
        .ok_or_else(|| GpuError::InvalidEvidence(format!("empty or unterminated {field}")))?;
    std::str::from_utf8(&bytes[..end])
        .map(str::to_owned)
        .map_err(|_| GpuError::InvalidEvidence(format!("non-UTF8 {field}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{offset_of, size_of};

    #[test]
    fn nvml_abi_layout() {
        assert_eq!(size_of::<RawCcState>(), 12);
        assert_eq!(size_of::<RawCertificate>(), 9224);
        assert_eq!(offset_of!(RawCertificate, cert_chain), 8);
        assert_eq!(offset_of!(RawCertificate, attestation_cert_chain), 4104);
        assert_eq!(size_of::<RawReport>(), 12332);
        assert_eq!(offset_of!(RawReport, nonce), 12);
        assert_eq!(offset_of!(RawReport, report), 44);
        assert_eq!(offset_of!(RawReport, cec_report), 8236);
    }

    #[test]
    fn certificate_lengths_are_checked_before_slicing() {
        let mut cert = RawCertificate::empty();
        assert!(cert.extract().is_err());
        cert.attestation_cert_chain_size = 1;
        assert!(cert.extract().is_ok());
        cert.cert_chain_size = CERT_CHAIN_SIZE as u32 + 1;
        assert!(cert.extract().is_err());
        cert.cert_chain_size = 0;
        cert.attestation_cert_chain_size = u32::MAX;
        assert!(cert.extract().is_err());
    }

    #[test]
    fn report_lengths_and_nonce_are_checked() {
        let mut report = RawReport::for_nonce([1; 32]);
        assert!(report.extract(&[1; 32]).is_err());
        report.report_size = u32::MAX;
        assert!(report.extract(&[1; 32]).is_err());
        assert!(report.extract(&[2; 32]).is_err());
    }

    fn reference_report() -> RawReport {
        let bytes = hex::decode(
            include_str!("../../testdata/gpu/nvidia/hopperAttestationReport.txt").trim(),
        )
        .unwrap();
        let mut report = RawReport::for_nonce(bytes[4..36].try_into().unwrap());
        report.report_size = bytes.len() as u32;
        report.report[..bytes.len()].copy_from_slice(&bytes);
        report
    }

    #[test]
    fn cec_evidence_is_preserved_and_presence_and_lengths_are_checked() {
        let mut raw = reference_report();
        let (report, cec) = raw.extract(&raw.nonce).unwrap();
        assert_eq!(report, raw.report[..raw.report_size as usize]);
        assert!(cec.is_empty());
        raw.cec_present = 1;
        assert!(raw.extract(&raw.nonce).is_err()); // present but empty
        raw.cec_report_size = 3;
        raw.cec_report[..3].copy_from_slice(b"cec");
        assert_eq!(raw.extract(&raw.nonce).unwrap().1, b"cec");
        raw.cec_report_size = CEC_REPORT_SIZE as u32 + 1;
        assert!(raw.extract(&raw.nonce).is_err());
        raw.cec_report_size = 3;
        raw.cec_present = 0;
        assert!(raw.extract(&raw.nonce).is_err()); // bytes but not present
        raw.cec_present = 2;
        assert!(raw.extract(&raw.nonce).is_err());
    }

    #[test]
    fn stale_report_is_rejected_even_when_nvml_input_nonce_is_correct() {
        let mut raw = reference_report();
        raw.nonce = [9; 32];
        assert!(matches!(
            raw.extract(&[9; 32]),
            Err(GpuError::Spdm(super::super::spdm::SpdmError::NonceMismatch))
        ));
    }

    #[test]
    fn driver_strings_are_bounded_and_validated() {
        assert!(read_string(b"", "test").is_err());
        assert!(read_string(b"\0", "test").is_err());
        assert!(read_string(b"no terminator", "test").is_err());
        assert!(read_string(b"\xff\0", "test").is_err());
        assert_eq!(read_string(b"H100\0tail", "test").unwrap(), "H100");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn unsupported_host_fails_without_loading_nvml() {
        assert!(matches!(
            NvmlCollector::open(),
            Err(GpuError::UnsupportedHost)
        ));
    }
}
