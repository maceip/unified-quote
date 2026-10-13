//! Detect the platform without treating failed/unknown provider probes as absence.
//! A separate configfs report instance is used for every probe and collection.

use super::{TeeError, TeeProvider};

#[cfg(unix)]
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

#[cfg(unix)]
pub(crate) const TSM_REPORT_BASE: &str = "/sys/kernel/config/tsm/report";

/// An exclusively created kernel report instance. The random suffix prevents
/// collisions between threads, processes, and stale instances after a crash.
#[cfg(unix)]
pub(crate) struct TsmRequest {
    path: PathBuf,
    removed: bool,
}

#[cfg(unix)]
impl TsmRequest {
    pub(crate) fn create(base: &Path, purpose: &str) -> Result<Self, TeeError> {
        use rand::RngCore;
        let mut suffix = [0; 16];
        rand::rngs::OsRng.try_fill_bytes(&mut suffix).map_err(|e| {
            TeeError::InvalidResponse(format!("configfs request randomness unavailable: {e}"))
        })?;
        let path = base.join(format!(
            "uq-{purpose}-{}-{}",
            std::process::id(),
            hex::encode(suffix)
        ));
        fs::create_dir(&path).map_err(|e| {
            TeeError::DeviceNotFound(format!("create configfs report {}: {e}", path.display()))
        })?;
        Ok(Self {
            path,
            removed: false,
        })
    }

    pub(crate) fn provider(&self) -> Result<String, TeeError> {
        let bytes = self.read_blob("provider", 128)?;
        let value = std::str::from_utf8(&bytes)
            .map_err(|_| TeeError::InvalidResponse("configfs provider is not UTF-8".into()))?;
        let value = value.strip_suffix('\n').unwrap_or(value);
        if value.is_empty()
            || !value
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_')
        {
            return Err(TeeError::InvalidResponse(
                "empty or malformed configfs provider".into(),
            ));
        }
        Ok(value.to_owned())
    }

    pub(crate) fn require_provider(&self, expected: &str) -> Result<(), TeeError> {
        let actual = self.provider()?;
        if actual != expected {
            return Err(TeeError::InvalidResponse(format!(
                "configfs provider {actual:?}, expected {expected:?}"
            )));
        }
        Ok(())
    }

    pub(crate) fn write_report_data(&self, report_data: &[u8; 64]) -> Result<(), TeeError> {
        fs::write(self.path.join("inblob"), report_data)
            .map_err(|e| TeeError::InvalidResponse(format!("write configfs inblob: {e}")))
    }

    pub(crate) fn read_blob(&self, name: &str, limit: usize) -> Result<Vec<u8>, TeeError> {
        self.optional_blob(name, limit)?
            .ok_or_else(|| TeeError::InvalidResponse(format!("configfs {name} is missing")))
    }

    pub(crate) fn optional_blob(
        &self,
        name: &str,
        limit: usize,
    ) -> Result<Option<Vec<u8>>, TeeError> {
        let file = match fs::File::open(self.path.join(name)) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(TeeError::InvalidResponse(format!(
                    "open configfs {name}: {e}"
                )))
            }
        };
        let mut bytes = Vec::new();
        file.take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| TeeError::InvalidResponse(format!("read configfs {name}: {e}")))?;
        if bytes.len() > limit {
            return Err(TeeError::InvalidResponse(format!(
                "configfs {name} exceeds {limit} bytes"
            )));
        }
        Ok(Some(bytes))
    }

    /// Report cleanup failures on successful operations. Error paths also make
    /// a best effort to remove just this request's directory in Drop.
    pub(crate) fn finish(mut self) -> Result<(), TeeError> {
        fs::remove_dir(&self.path).map_err(|e| {
            TeeError::InvalidResponse(format!(
                "remove configfs report {}: {e}",
                self.path.display()
            ))
        })?;
        self.removed = true;
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for TsmRequest {
    fn drop(&mut self) {
        if !self.removed {
            let _ = fs::remove_dir(&self.path);
        }
    }
}

#[cfg(unix)]
pub(crate) fn path_exists(path: &Path) -> Result<bool, TeeError> {
    path.try_exists()
        .map_err(|e| TeeError::DeviceNotFound(format!("inspect {}: {e}", path.display())))
}

#[cfg(not(unix))]
pub fn detect_tee() -> Result<Box<dyn TeeProvider>, TeeError> {
    Err(TeeError::NoTeeDetected)
}

#[cfg(unix)]
pub fn detect_tee() -> Result<Box<dyn TeeProvider>, TeeError> {
    let has_nsm = path_exists(Path::new("/dev/nsm"))?;
    let has_tdx =
        path_exists(Path::new("/dev/tdx-guest"))? || path_exists(Path::new("/dev/tdx_guest"))?;
    let has_snp = path_exists(Path::new("/dev/sev-guest"))?;
    if [has_nsm, has_tdx, has_snp]
        .into_iter()
        .filter(|v| *v)
        .count()
        > 1
    {
        return Err(TeeError::InvalidResponse(
            "conflicting TEE device identities".into(),
        ));
    }
    let tsm = Path::new(TSM_REPORT_BASE);
    let provider = if path_exists(tsm)? {
        let request = TsmRequest::create(tsm, "detect")?;
        let provider = request.provider()?;
        request.finish()?;
        Some(provider)
    } else {
        None
    };
    let platform = choose_provider(has_nsm, has_tdx, has_snp, provider.as_deref())?;
    match platform {
        Some("nsm") => {
            #[cfg(feature = "nitro")]
            {
                Ok(Box::new(super::nitro::NitroProvider::new()?))
            }
            #[cfg(not(feature = "nitro"))]
            {
                Err(TeeError::DeviceNotFound(
                    "Nitro detected but feature nitro is disabled".into(),
                ))
            }
        }
        Some("tdx_guest") => {
            #[cfg(feature = "tdx")]
            {
                Ok(Box::new(super::tdx::TdxProvider::new()?))
            }
            #[cfg(not(feature = "tdx"))]
            {
                Err(TeeError::DeviceNotFound(
                    "TDX detected but feature tdx is disabled".into(),
                ))
            }
        }
        Some("sev_guest") => {
            #[cfg(feature = "sev-snp")]
            {
                Ok(Box::new(super::snp::SnpProvider::new()?))
            }
            #[cfg(not(feature = "sev-snp"))]
            {
                Err(TeeError::DeviceNotFound(
                    "SNP detected but feature sev-snp is disabled".into(),
                ))
            }
        }
        None => Err(TeeError::NoTeeDetected),
        _ => unreachable!("choose_provider returns only known identities"),
    }
}

#[cfg(unix)]
fn choose_provider(
    nsm: bool,
    tdx: bool,
    snp: bool,
    configfs: Option<&str>,
) -> Result<Option<&'static str>, TeeError> {
    if [nsm, tdx, snp].into_iter().filter(|v| *v).count() > 1 {
        return Err(TeeError::InvalidResponse(
            "conflicting TEE device identities".into(),
        ));
    }
    match configfs {
        Some("tdx_guest") if !snp && !nsm => Ok(Some("tdx_guest")),
        Some("sev_guest") if !tdx && !nsm => Ok(Some("sev_guest")),
        Some("tdx_guest" | "sev_guest") => Err(TeeError::InvalidResponse(
            "configfs provider conflicts with TEE device".into(),
        )),
        Some(value) => Err(TeeError::InvalidResponse(format!(
            "unsupported configfs provider {value:?}"
        ))),
        None if nsm => Ok(Some("nsm")),
        None if tdx => Ok(Some("tdx_guest")),
        None if snp => Ok(Some("sev_guest")),
        None => Ok(None),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn identities_are_exact_and_conflicts_fail() {
        assert_eq!(
            choose_provider(false, false, false, Some("tdx_guest")).unwrap(),
            Some("tdx_guest")
        );
        assert_eq!(
            choose_provider(false, false, true, None).unwrap(),
            Some("sev_guest")
        );
        for provider in ["", "tdx", "sev_guest_other", "future_tee"] {
            assert!(choose_provider(false, false, false, Some(provider)).is_err());
        }
        assert!(choose_provider(false, false, true, Some("tdx_guest")).is_err());
        assert!(choose_provider(true, false, false, Some("sev_guest")).is_err());
        assert!(choose_provider(false, true, true, None).is_err());
    }

    #[test]
    fn requests_are_unique_cleanup_owned_directory_and_bound_reads() {
        let temp = tempfile::tempdir().unwrap();
        let first = TsmRequest::create(temp.path(), "test").unwrap();
        let second = TsmRequest::create(temp.path(), "test").unwrap();
        assert_ne!(first.path, second.path);
        let first_path = first.path.clone();
        drop(first);
        assert!(!first_path.exists());
        assert!(second.path.exists());
        assert!(second.provider().is_err());
        fs::write(second.path.join("provider"), b"tdx_guest\n").unwrap();
        second.require_provider("tdx_guest").unwrap();
        assert!(second.require_provider("sev_guest").is_err());
        fs::write(second.path.join("provider"), b"\n").unwrap();
        assert!(second.provider().is_err());
        fs::write(second.path.join("provider"), vec![b'a'; 129]).unwrap();
        assert!(second.provider().is_err());
        fs::remove_file(second.path.join("provider")).unwrap();
        let second_path = second.path.clone();
        second.finish().unwrap();
        assert!(!second_path.exists());
    }
}
