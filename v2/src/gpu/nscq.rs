//! Native read-only NVSwitch attestation collection through NSCQ.
//!
//! ABI definitions follow NVIDIA attestation-sdk revision
//! 11b2bfeb42a1158aa08744603ecb239ccb3d2265 `src/switch/nscq_client.cpp`.
//! NSCQ reports and modes are untrusted evidence until cryptographic appraisal.
//! No switch ready/lock/security state is modified; only the session's report
//! nonce input is set. Hardware/driver interoperability remains to be exercised.

use std::{
    collections::{BTreeMap, HashSet},
    ffi::{c_char, c_void, CString},
    marker::PhantomData,
    panic::{catch_unwind, AssertUnwindSafe},
    rc::Rc,
    sync::Mutex,
};

use anyhow::{bail, ensure, Context, Result};
use libloading::Library;

use super::{spdm::SpdmReport, SwitchEvidence};

const MAX_SWITCHES: usize = 64;
const CERTIFICATE_SIZE: usize = 0x1400;
const REPORT_SIZE: usize = 0x2000;
const LABEL_SIZE: usize = 64;
const SESSION_MOUNT_DEVICES: u32 = 1;
const ARCH_LS10: i8 = 2;

type Session = *mut c_void;
type Callback = unsafe extern "C" fn();
type SessionCreate = unsafe extern "C" fn(u32) -> RawSessionResult;
type SessionDestroy = unsafe extern "C" fn(Session);
type Observe = unsafe extern "C" fn(Session, *const c_char, Callback, *mut c_void, u32) -> i8;
type SetInput = unsafe extern "C" fn(Session, u32, *mut c_void, u32) -> i8;
type UuidToLabel = unsafe extern "C" fn(*const RawUuid, *mut RawLabel, u32) -> i8;

#[repr(C)]
#[derive(Clone, Copy)]
struct RawUuid {
    bytes: [u8; 16],
}

#[repr(C)]
struct RawLabel {
    data: [c_char; LABEL_SIZE],
}

#[repr(C)]
struct RawSessionResult {
    rc: i8,
    session: Session,
}

#[repr(C)]
struct RawCertificate {
    cert_chain: [u8; CERTIFICATE_SIZE],
    cert_chain_size: u32,
}

#[repr(C)]
struct RawReport {
    report_size: u32,
    report: [u8; REPORT_SIZE],
}

/// Owns one session and its dynamic library. Deliberately neither Send nor
/// Sync: nonce input and NSCQ observation sequencing belong to this session.
pub struct NscqCollector {
    session: Session,
    destroy: SessionDestroy,
    observe: Observe,
    set_input: SetInput,
    uuid_to_label: UuidToLabel,
    _library: Library,
    _thread_bound: PhantomData<Rc<()>>,
}

impl NscqCollector {
    pub fn open() -> Result<Self> {
        ensure!(
            cfg!(target_os = "linux"),
            "native NSCQ collection requires Linux"
        );
        // SAFETY: the system NVIDIA driver is a trusted native dependency. Its
        // documented soname and ABI are used; the library outlives all symbols.
        let library = unsafe { Library::new("libnvidia-nscq.so.2") }
            .context("cannot load libnvidia-nscq.so.2")?;
        unsafe {
            let create: SessionCreate = symbol(&library, b"nscq_session_create\0")?;
            let destroy: SessionDestroy = symbol(&library, b"nscq_session_destroy\0")?;
            let observe = symbol(&library, b"nscq_session_path_observe\0")?;
            let set_input = symbol(&library, b"nscq_session_set_input\0")?;
            let uuid_to_label = symbol(&library, b"nscq_uuid_to_label\0")?;
            let result = create(SESSION_MOUNT_DEVICES);
            if result.rc != 0 {
                if !result.session.is_null() {
                    destroy(result.session);
                }
                bail!("nscq_session_create failed with status {}", result.rc);
            }
            ensure!(
                !result.session.is_null(),
                "NSCQ returned success without a session"
            );
            Ok(Self {
                session: result.session,
                destroy,
                observe,
                set_input,
                uuid_to_label,
                _library: library,
                _thread_bound: PhantomData,
            })
        }
    }

    /// Collect every enumerated switch under the same challenge. An empty
    /// inventory, any callback error, missing callback, duplicate, overflow,
    /// nonce mismatch, unsupported architecture or changing inventory is an
    /// error. A failed switch cannot silently disappear from returned evidence.
    pub fn collect(&self, nonce: [u8; 32]) -> Result<Vec<SwitchEvidence>> {
        let inventory = self.inventory()?;
        ensure!(!inventory.is_empty(), "no NVSwitch devices found");
        let architectures = self.architectures()?;
        ensure!(
            architectures.keys().eq(inventory.keys()),
            "NSCQ architecture and UUID inventories differ"
        );
        ensure!(
            architectures.values().all(|a| *a == ARCH_LS10),
            "only the published LS10 attestation profile is supported"
        );
        let mut evidence = Vec::with_capacity(inventory.len());
        for (device, label) in &inventory {
            let tnvl_mode = self.mode(device, label)?;
            let certificate_chain = self.certificate(device, label)?;
            let attestation_report = self.report(device, label, nonce)?;
            ensure!(
                self.mode(device, label)? == tnvl_mode,
                "NVSwitch mode changed during collection"
            );
            ensure!(
                self.certificate(device, label)? == certificate_chain,
                "NVSwitch certificate changed during collection"
            );
            evidence.push(SwitchEvidence {
                uuid: label.clone(),
                tnvl_mode,
                certificate_chain,
                attestation_report,
            });
        }
        ensure!(
            self.inventory()? == inventory && self.architectures()? == architectures,
            "NVSwitch inventory changed during collection"
        );
        Ok(evidence)
    }

    fn inventory(&self) -> Result<BTreeMap<[u8; 16], String>> {
        let capture = Mutex::new(Capture::<[u8; 16]>::new(None));
        // SAFETY: NSCQ dispatches the documented UUID callback signature for
        // this path. The synchronized context lives through synchronous observe.
        let callback: Callback = unsafe {
            std::mem::transmute(
                uuid_callback
                    as unsafe extern "C" fn(*const RawUuid, i8, *const RawUuid, *mut c_void),
            )
        };
        self.observe_path("/drv/nvswitch/{device}/uuid", callback, &capture)?;
        let uuids = capture
            .into_inner()
            .map_err(|_| anyhow::anyhow!("NSCQ UUID callback lock poisoned"))?
            .finish()?;
        let mut inventory = BTreeMap::new();
        let mut labels = HashSet::new();
        for (_, uuid) in uuids {
            let mut label = RawLabel {
                data: [0; LABEL_SIZE],
            };
            // SAFETY: raw UUID and fixed label buffer match the NSCQ ABI.
            check(
                unsafe { (self.uuid_to_label)(&RawUuid { bytes: uuid }, &mut label, 0) },
                "nscq_uuid_to_label",
            )?;
            let label = checked_label(&label)?;
            ensure!(
                labels.insert(label.clone()),
                "NSCQ returned duplicate UUID labels"
            );
            ensure!(
                inventory.insert(uuid, label).is_none(),
                "NSCQ returned duplicate UUIDs"
            );
        }
        Ok(inventory)
    }

    fn architectures(&self) -> Result<BTreeMap<[u8; 16], i8>> {
        let capture = Mutex::new(Capture::<i8>::new(None));
        // SAFETY: this path dispatches an int8 architecture argument.
        let callback: Callback = unsafe {
            std::mem::transmute(
                scalar_callback as unsafe extern "C" fn(*const RawUuid, i8, i8, *mut c_void),
            )
        };
        self.observe_path("/{nvswitch}/id/arch", callback, &capture)?;
        capture
            .into_inner()
            .map_err(|_| anyhow::anyhow!("NSCQ architecture callback lock poisoned"))?
            .finish()
    }

    fn mode(&self, uuid: &[u8; 16], label: &str) -> Result<i8> {
        let capture = Mutex::new(Capture::<i8>::new(Some(*uuid)));
        // SAFETY: mode is the documented int8 callback ABI.
        let callback: Callback = unsafe {
            std::mem::transmute(
                scalar_callback as unsafe extern "C" fn(*const RawUuid, i8, i8, *mut c_void),
            )
        };
        self.observe_path(&format!("/{label}/config/pcie_mode"), callback, &capture)?;
        let mode = capture
            .into_inner()
            .map_err(|_| anyhow::anyhow!("NSCQ mode callback lock poisoned"))?
            .one()?;
        ensure!((-1..=3).contains(&mode), "unknown NSCQ TNVL mode {mode}");
        Ok(mode)
    }

    fn certificate(&self, uuid: &[u8; 16], label: &str) -> Result<Vec<u8>> {
        let capture = Mutex::new(Capture::<Vec<u8>>::new(Some(*uuid)));
        // SAFETY: NSCQ certificate callback takes the complete repr(C) struct
        // BY VALUE. Changing this argument to a pointer would violate the ABI.
        let callback: Callback = unsafe {
            std::mem::transmute(
                certificate_callback
                    as unsafe extern "C" fn(*const RawUuid, i8, RawCertificate, *mut c_void),
            )
        };
        self.observe_path(&format!("/{label}/config/certificate"), callback, &capture)?;
        capture
            .into_inner()
            .map_err(|_| anyhow::anyhow!("NSCQ certificate callback lock poisoned"))?
            .one()
    }

    fn report(&self, uuid: &[u8; 16], label: &str, nonce: [u8; 32]) -> Result<Vec<u8>> {
        let mut input = nonce;
        // SAFETY: input id 0 is the documented 32-byte attestation nonce. NSCQ
        // copies this session input synchronously; no security mode is set.
        check(
            unsafe {
                (self.set_input)(
                    self.session,
                    0,
                    input.as_mut_ptr().cast(),
                    input.len() as u32,
                )
            },
            "nscq_session_set_input",
        )?;
        ensure!(input == nonce, "NSCQ modified input nonce");
        let capture = Mutex::new(Capture::<Vec<u8>>::new(Some(*uuid)));
        // SAFETY: the report struct is passed by value in the vendor ABI.
        let callback: Callback = unsafe {
            std::mem::transmute(
                report_callback as unsafe extern "C" fn(*const RawUuid, i8, RawReport, *mut c_void),
            )
        };
        self.observe_path(
            &format!("/{label}/config/attestation_report"),
            callback,
            &capture,
        )?;
        let report = capture
            .into_inner()
            .map_err(|_| anyhow::anyhow!("NSCQ report callback lock poisoned"))?
            .one()?;
        SpdmReport::parse(&report)?.check_nonce(&nonce)?;
        Ok(report)
    }

    fn observe_path<T>(
        &self,
        path: &str,
        callback: Callback,
        capture: &Mutex<Capture<T>>,
    ) -> Result<()> {
        let path = CString::new(path)?;
        // SAFETY: path is NUL-terminated, the callback ABI matches that path,
        // and the context lives until synchronous observation returns. The
        // callback uses a Mutex in case the native library dispatches workers.
        check(
            unsafe {
                (self.observe)(
                    self.session,
                    path.as_ptr(),
                    callback,
                    (capture as *const Mutex<Capture<T>>).cast_mut().cast(),
                    0,
                )
            },
            "nscq_session_path_observe",
        )
    }
}

impl Drop for NscqCollector {
    fn drop(&mut self) {
        // SAFETY: this object uniquely owns the initialized session; its
        // library field is dropped only after session destruction completes.
        unsafe { (self.destroy)(self.session) };
    }
}

unsafe fn symbol<T: Copy>(library: &Library, name: &[u8]) -> Result<T> {
    // SAFETY: caller selects T from the vendor NSCQ ABI declarations above.
    Ok(*unsafe { library.get::<T>(name) }
        .with_context(|| format!("missing NSCQ symbol {}", String::from_utf8_lossy(name)))?)
}

fn check(rc: i8, operation: &str) -> Result<()> {
    ensure!(rc == 0, "{operation} returned NSCQ status {rc}");
    Ok(())
}

fn checked_label(label: &RawLabel) -> Result<String> {
    let bytes: Vec<u8> = label.data.iter().map(|c| *c as u8).collect();
    let length = bytes
        .iter()
        .position(|b| *b == 0)
        .context("NSCQ UUID label is not NUL-terminated")?;
    let label = std::str::from_utf8(&bytes[..length])?;
    ensure!(
        !label.is_empty()
            && label != "."
            && label != ".."
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':')),
        "invalid NSCQ UUID label"
    );
    Ok(label.to_owned())
}

struct Capture<T> {
    expected: Option<[u8; 16]>,
    values: BTreeMap<[u8; 16], T>,
    error: Option<String>,
}

impl<T> Capture<T> {
    fn new(expected: Option<[u8; 16]>) -> Self {
        Self {
            expected,
            values: BTreeMap::new(),
            error: None,
        }
    }

    fn insert(&mut self, uuid: [u8; 16], value: T) -> Result<()> {
        ensure!(uuid != [0; 16], "NSCQ returned a zero device UUID");
        ensure!(
            self.expected.is_none_or(|expected| expected == uuid),
            "NSCQ callback device differs from requested UUID"
        );
        ensure!(
            self.values.len() < MAX_SWITCHES,
            "NSCQ switch inventory exceeds limit"
        );
        ensure!(
            self.values.insert(uuid, value).is_none(),
            "NSCQ callback returned a duplicate device"
        );
        Ok(())
    }

    fn finish(self) -> Result<BTreeMap<[u8; 16], T>> {
        if let Some(error) = self.error {
            bail!(error);
        }
        Ok(self.values)
    }

    fn one(self) -> Result<T> {
        let values = self.finish()?;
        ensure!(
            values.len() == 1,
            "NSCQ observation requires exactly one successful callback"
        );
        values.into_values().next().context("NSCQ callback missing")
    }
}

/// Contain errors/panics at the FFI boundary and retain the first callback
/// failure. A later successful callback cannot erase an earlier failure.
unsafe fn capture<T>(user_data: *mut c_void, action: impl FnOnce(&mut Capture<T>) -> Result<()>) {
    if user_data.is_null() {
        return;
    } // Our observe calls never supply null.
      // SAFETY: every callback receives the exact live Mutex<Capture<T>> type
      // supplied to synchronous observe_path for that callback signature.
    let mutex = unsafe { &*user_data.cast::<Mutex<Capture<T>>>() };
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let mut guard = mutex
            .lock()
            .map_err(|_| anyhow::anyhow!("NSCQ callback lock poisoned"))?;
        if guard.error.is_none() {
            if let Err(error) = action(&mut guard) {
                guard.error = Some(error.to_string());
            }
        }
        Ok::<(), anyhow::Error>(())
    }));
    if !matches!(outcome, Ok(Ok(()))) {
        let mut guard = mutex.lock().unwrap_or_else(|poison| poison.into_inner());
        guard.error = Some("NSCQ callback panicked or lock was poisoned".to_owned());
    }
}

unsafe fn device_uuid(device: *const RawUuid) -> Result<[u8; 16]> {
    ensure!(!device.is_null(), "NSCQ callback device pointer is null");
    // SAFETY: a nonnull device points to a valid UUID for the callback lifetime
    // under the documented native ABI. It is copied before callback return.
    Ok(unsafe { (*device).bytes })
}

unsafe extern "C" fn uuid_callback(
    device: *const RawUuid,
    rc: i8,
    uuid: *const RawUuid,
    user_data: *mut c_void,
) {
    unsafe {
        capture(user_data, |state: &mut Capture<[u8; 16]>| {
            check(rc, "NSCQ UUID callback")?;
            let device = device_uuid(device)?;
            let value = device_uuid(uuid)?;
            state.insert(device, value)
        })
    }
}

unsafe extern "C" fn scalar_callback(
    device: *const RawUuid,
    rc: i8,
    value: i8,
    user_data: *mut c_void,
) {
    unsafe {
        capture(user_data, |state: &mut Capture<i8>| {
            check(rc, "NSCQ scalar callback")?;
            state.insert(device_uuid(device)?, value)
        })
    }
}

unsafe extern "C" fn certificate_callback(
    device: *const RawUuid,
    rc: i8,
    value: RawCertificate,
    user_data: *mut c_void,
) {
    unsafe {
        capture(user_data, |state: &mut Capture<Vec<u8>>| {
            check(rc, "NSCQ certificate callback")?;
            let length = value.cert_chain_size as usize;
            ensure!(
                length > 0 && length <= CERTIFICATE_SIZE,
                "NSCQ certificate size outside ABI buffer"
            );
            state.insert(device_uuid(device)?, value.cert_chain[..length].to_vec())
        })
    }
}

unsafe extern "C" fn report_callback(
    device: *const RawUuid,
    rc: i8,
    value: RawReport,
    user_data: *mut c_void,
) {
    unsafe {
        capture(user_data, |state: &mut Capture<Vec<u8>>| {
            check(rc, "NSCQ report callback")?;
            let length = value.report_size as usize;
            ensure!(
                length > 0 && length <= REPORT_SIZE,
                "NSCQ report size outside ABI buffer"
            );
            state.insert(device_uuid(device)?, value.report[..length].to_vec())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nscq_abi_buffers_and_offsets_match_documented_c_structures() {
        assert_eq!(std::mem::size_of::<RawUuid>(), 16);
        assert_eq!(std::mem::size_of::<RawLabel>(), 64);
        assert_eq!(std::mem::size_of::<RawCertificate>(), 0x1404);
        assert_eq!(
            std::mem::offset_of!(RawCertificate, cert_chain_size),
            0x1400
        );
        assert_eq!(std::mem::size_of::<RawReport>(), 0x2004);
        assert_eq!(std::mem::offset_of!(RawReport, report), 4);
        assert_eq!(
            std::mem::offset_of!(RawSessionResult, session),
            std::mem::align_of::<Session>()
        );
    }

    #[test]
    fn callback_errors_missing_callbacks_duplicates_and_wrong_devices_fail() {
        assert!(Capture::<i8>::new(None).one().is_err());
        let device = RawUuid { bytes: [1; 16] };
        for (rc, expected) in [(-7, [1; 16]), (0, [2; 16])] {
            let state = Mutex::new(Capture::<i8>::new(Some(expected)));
            unsafe {
                scalar_callback(
                    &device,
                    rc,
                    1,
                    (&state as *const Mutex<Capture<i8>>).cast_mut().cast(),
                )
            };
            assert!(state.into_inner().unwrap().one().is_err());
        }
        let state = Mutex::new(Capture::<i8>::new(Some(device.bytes)));
        let ptr = (&state as *const Mutex<Capture<i8>>).cast_mut().cast();
        unsafe {
            scalar_callback(&device, 0, 1, ptr);
            scalar_callback(&device, 0, 1, ptr);
        }
        assert!(state.into_inner().unwrap().one().is_err());
    }

    #[test]
    fn malicious_report_lengths_and_unterminated_labels_are_rejected() {
        let device = RawUuid { bytes: [1; 16] };
        for length in [0, REPORT_SIZE as u32 + 1, u32::MAX] {
            let state = Mutex::new(Capture::<Vec<u8>>::new(Some(device.bytes)));
            unsafe {
                report_callback(
                    &device,
                    0,
                    RawReport {
                        report_size: length,
                        report: [0; REPORT_SIZE],
                    },
                    (&state as *const Mutex<Capture<Vec<u8>>>).cast_mut().cast(),
                )
            };
            assert!(state.into_inner().unwrap().one().is_err());
        }
        assert!(checked_label(&RawLabel {
            data: [b'x' as c_char; LABEL_SIZE]
        })
        .is_err());
        let mut label = RawLabel {
            data: [0; LABEL_SIZE],
        };
        label.data[0] = b'/' as c_char;
        assert!(checked_label(&label).is_err());
    }

    #[test]
    fn successful_native_callback_preserves_bytes_and_first_error() {
        let device = RawUuid { bytes: [1; 16] };
        let state = Mutex::new(Capture::<Vec<u8>>::new(Some(device.bytes)));
        let ptr = (&state as *const Mutex<Capture<Vec<u8>>>).cast_mut().cast();
        let mut report = RawReport {
            report_size: 3,
            report: [0; REPORT_SIZE],
        };
        report.report[..3].copy_from_slice(&[7, 8, 9]);
        unsafe { report_callback(&device, 0, report, ptr) };
        assert_eq!(state.into_inner().unwrap().one().unwrap(), vec![7, 8, 9]);

        let state = Mutex::new(Capture::<i8>::new(Some(device.bytes)));
        let ptr = (&state as *const Mutex<Capture<i8>>).cast_mut().cast();
        unsafe {
            scalar_callback(&device, -7, 0, ptr);
            scalar_callback(&device, 0, 1, ptr);
        }
        assert!(state.into_inner().unwrap().one().is_err());
    }
}
