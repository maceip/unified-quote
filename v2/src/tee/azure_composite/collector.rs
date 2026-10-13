//! Linux collection through explicitly configured installed tpm2-tools.
//! Collection is untrusted evidence acquisition, never an admission result.
use super::*;
use std::path::{Path, PathBuf};

/// Operator configuration, never read from evidence, PATH or environment.
#[derive(Debug, Clone)]
pub struct AzureCompositeCollector {
    nvread: PathBuf,
    quote: PathBuf,
    device: PathBuf,
}

impl AzureCompositeCollector {
    pub fn new(
        nvread: impl AsRef<Path>,
        quote: impl AsRef<Path>,
        device: impl AsRef<Path>,
    ) -> Result<Self> {
        let device = device.as_ref();
        ensure!(
            matches!(device.to_str(), Some("/dev/tpmrm0" | "/dev/tpm0")),
            "Azure TPM device must be explicitly /dev/tpmrm0 or /dev/tpm0"
        );
        Ok(Self {
            nvread: executable(nvread.as_ref())?,
            quote: executable(quote.as_ref())?,
            device: device.to_owned(),
        })
    }

    /// Collect only; the relying party must run `verify` with independent
    /// enrollment, current AMD collateral and TCB policy. All PCRs are acquired
    /// in the same tpm2_quote operation and checked against its signed digest.
    pub fn collect(
        &self,
        report_data: &[u8; 64],
        pcr_indices: &[u8],
    ) -> Result<AzureCompositeEvidence> {
        validate_indices(pcr_indices)?;
        #[cfg(target_os = "linux")]
        {
            self.collect_linux(report_data, pcr_indices)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (report_data, &self.nvread, &self.quote, &self.device);
            anyhow::bail!("Azure vTPM collection requires a Linux Azure SNP guest")
        }
    }
}

/// Default Linux profile uses exactly these local executables and resource
/// manager device. Missing tools/device are errors; no alternate is selected.
/// Use `AzureCompositeCollector::new` to explicitly configure another supported
/// device or absolute tool installation paths.
pub fn collect(report_data: &[u8; 64], pcr_indices: &[u8]) -> Result<AzureCompositeEvidence> {
    validate_indices(pcr_indices)?;
    #[cfg(target_os = "linux")]
    {
        AzureCompositeCollector::new("/usr/bin/tpm2_nvread", "/usr/bin/tpm2_quote", "/dev/tpmrm0")?
            .collect(report_data, pcr_indices)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = report_data;
        anyhow::bail!("Azure vTPM collection requires a Linux Azure SNP guest")
    }
}

fn validate_indices(indices: &[u8]) -> Result<()> {
    ensure!(
        !indices.is_empty()
            && indices.len() <= 16
            && indices.iter().all(|index| *index < 16)
            && indices.windows(2).all(|pair| pair[0] < pair[1]),
        "Azure collection requires 1..16 unique increasing PCR indices within 0..15"
    );
    Ok(())
}

fn executable(path: &Path) -> Result<PathBuf> {
    ensure!(
        path.is_absolute(),
        "Azure collection requires absolute trusted tool paths"
    );
    let path = path
        .canonicalize()
        .context("resolve Azure TPM tool executable")?;
    let metadata = path.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() > 0 && metadata.len() <= 64 * 1024 * 1024,
        "Azure TPM tool is not a bounded nonempty regular file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            metadata.permissions().mode() & 0o111 != 0,
            "Azure TPM tool is not executable"
        );
    }
    Ok(path)
}

#[cfg(any(target_os = "linux", all(test, unix)))]
impl AzureCompositeCollector {
    // Also type-checked in Unix host tests, without permitting non-Linux public
    // collection or pretending that a TPM is present.
    #[cfg_attr(all(test, not(target_os = "linux")), allow(dead_code))]
    fn collect_linux(
        &self,
        report_data: &[u8; 64],
        indices: &[u8],
    ) -> Result<AzureCompositeEvidence> {
        use std::{os::unix::fs::FileTypeExt, process::Command};
        ensure!(
            self.device
                .metadata()
                .context("Azure TPM device unavailable")?
                .file_type()
                .is_char_device(),
            "Azure TPM device is not a character device"
        );
        let directory = PrivateDirectory::new()?;
        let hcl_path = directory.0.join("hcl.bin");
        let quote_path = directory.0.join("quote.bin");
        let signature_path = directory.0.join("signature.bin");
        let pcr_path = directory.0.join("pcrs.bin");
        let tcti = format!("device:{}", self.device.display());
        let mut nvread = Command::new(&self.nvread);
        nvread
            .args(["-Q", "-T", &tcti, "-C", "o", "0x01400001", "-o"])
            .arg(&hcl_path);
        run_tool(nvread, &directory.0, &[(&hcl_path, HCL_NV_SIZE)])?;
        let hcl_report = read_bounded(&hcl_path, HCL_NV_SIZE)?;
        // Sanity and key extraction only; this remains unverified evidence.
        let hcl = parse_hcl(&hcl_report)?;
        let ak = parse_claims(hcl.claims)?.ak_key()?;
        let selection = format!(
            "sha256:{}",
            indices
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(",")
        );
        let challenge = hex::encode(qualifying_data(report_data));
        let mut quote = Command::new(&self.quote);
        quote
            .args([
                "-Q",
                "-T",
                &tcti,
                "-c",
                "0x81000003",
                "-l",
                &selection,
                "-q",
                &challenge,
                "-g",
                "sha256",
                "--scheme",
                "rsassa",
                "-f",
                "tss",
                "-F",
                "values",
                "-m",
            ])
            .arg(&quote_path)
            .arg("-s")
            .arg(&signature_path)
            .arg("-o")
            .arg(&pcr_path);
        run_tool(
            quote,
            &directory.0,
            &[
                (&quote_path, MAX_QUOTE),
                (&signature_path, MAX_SIGNATURE),
                (&pcr_path, indices.len() * 32),
            ],
        )?;
        let values = read_bounded(&pcr_path, indices.len() * 32)?;
        ensure!(
            values.len() == indices.len() * 32,
            "tpm2_quote PCR output does not match explicit selection"
        );
        let evidence = AzureCompositeEvidence {
            version: 1,
            hcl_report,
            quote_message: read_bounded(&quote_path, MAX_QUOTE)?,
            quote_signature: read_bounded(&signature_path, MAX_SIGNATURE)?,
            pcrs: indices
                .iter()
                .zip(values.chunks_exact(32))
                .map(|(index, value)| AzurePcrValue {
                    index: *index,
                    value: value.try_into().expect("32-byte PCR chunk"),
                })
                .collect(),
        };
        evidence.validate_bounds()?;
        verify_quote(&ak, &evidence, report_data)
            .context("collected TPM quote does not match HCL AK/challenge/PCRs")?;
        Ok(evidence)
    }
}

#[cfg(any(target_os = "linux", all(test, unix)))]
struct PrivateDirectory(PathBuf);
#[cfg(any(target_os = "linux", all(test, unix)))]
impl PrivateDirectory {
    fn new() -> Result<Self> {
        use rand::RngCore;
        use std::os::unix::fs::DirBuilderExt;
        // Fixed sticky system temp directory: no attacker-controlled TMPDIR.
        for _ in 0..8 {
            let mut nonce = [0u8; 16];
            rand::rngs::OsRng.try_fill_bytes(&mut nonce)?;
            let path = Path::new("/tmp").join(format!("uq-azure-{}", hex::encode(nonce)));
            match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        anyhow::bail!("could not create private Azure collection directory")
    }
}
#[cfg(any(target_os = "linux", all(test, unix)))]
impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    use std::{io::Read, os::unix::fs::OpenOptionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    ensure!(
        file.metadata()?.is_file() && file.metadata()?.len() <= limit as u64,
        "Azure TPM output exceeds limit or is not regular"
    );
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= limit,
        "Azure TPM output is empty or exceeds limit"
    );
    Ok(bytes)
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn run_tool(
    mut command: std::process::Command,
    directory: &Path,
    outputs: &[(&Path, usize)],
) -> Result<()> {
    use std::{
        os::unix::{fs::OpenOptionsExt, process::CommandExt},
        process::Stdio,
        thread,
        time::{Duration, Instant},
    };
    let diagnostic_path = directory.join("stderr.txt");
    let diagnostic = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&diagnostic_path)?;
    ensure!(
        diagnostic.metadata()?.is_file(),
        "Azure TPM diagnostic output is not a regular file"
    );
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .current_dir(directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(diagnostic)
        .process_group(0);
    let mut child = command
        .spawn()
        .context("start explicitly configured Azure TPM tool")?;
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut limits = outputs.to_vec();
    limits.push((&diagnostic_path, 16 * 1024));
    let outcome = loop {
        let bounded = limits.iter().try_for_each(|(path, limit)| -> Result<()> {
            match std::fs::symlink_metadata(path) {
                Ok(metadata) => ensure!(
                    metadata.is_file() && metadata.len() <= *limit as u64,
                    "Azure TPM tool output exceeded a file bound"
                ),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            Ok(())
        });
        if let Err(error) = bounded {
            break Err(error);
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                break if status.success() {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("Azure TPM tool failed with {status}"))
                }
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                break Err(anyhow::anyhow!(
                    "Azure TPM tool exceeded 15-second deadline"
                ))
            }
            Err(error) => break Err(error.into()),
        }
    };
    // Also terminate descendants after normal exit: none may outlive acquisition
    // and modify output files after their initial bound check.
    unsafe {
        libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL);
    }
    let _ = child.kill();
    let _ = child.wait();
    outcome
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::{symlink, PermissionsExt},
        process::Command,
    };

    #[test]
    fn acquisition_output_limits_exit_status_and_symlinks_are_enforced() {
        // Process/file transport only. These commands never emulate a TPM or
        // return attestation evidence or an accepting verifier result.
        let directory = PrivateDirectory::new().unwrap();
        assert_eq!(
            directory.0.metadata().unwrap().permissions().mode() & 0o777,
            0o700
        );
        let output = directory.0.join("output.bin");
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf abc > output.bin"]);
        run_tool(command, &directory.0, &[(&output, 3)]).unwrap();
        assert_eq!(read_bounded(&output, 3).unwrap(), b"abc");
        assert!(read_bounded(&output, 2).is_err());
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf abcdef > output.bin"]);
        assert!(run_tool(command, &directory.0, &[(&output, 3)]).is_err());
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exit 7"]);
        assert!(run_tool(command, &directory.0, &[]).is_err());
        let link = directory.0.join("link.bin");
        symlink(&output, &link).unwrap();
        assert!(read_bounded(&link, 6).is_err());
        let fifo = directory.0.join("fifo.bin");
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        assert!(read_bounded(&fifo, 6).is_err());
    }
}
