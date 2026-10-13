//! Strict AWS NitroTPM signed-document collection. Runtime sysfs values are
//! available only through a separately named, explicitly unverified diagnostic.
#[cfg(not(unix))]
use anyhow::bail;
use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[path = "nitrotpm_verify.rs"]
mod nitrotpm;
pub use nitrotpm::{
    verify_nitrotpm_document, NitroTpmPolicy, VerifiedNitroTpm, MAX_NITROTPM_DOCUMENT_BYTES,
};

pub struct TpmAttestation {
    pub digest: [u8; 32],
    /// Unverified COSE transport bytes. Only verify_nitrotpm_document can
    /// establish their signature, trust chain, freshness and PCR policy.
    pub attestation_doc: Option<Vec<u8>>,
    pub pcrs: BTreeMap<u32, Vec<u8>>,
    pub method: &'static str,
}
pub fn tpm_available() -> bool {
    which_nitro_tpm_attest().is_some()
}
pub fn collect_tpm_attestation(nonce: &[u8]) -> std::result::Result<TpmAttestation, String> {
    let nonce: &[u8; 32] = nonce
        .try_into()
        .map_err(|_| "NitroTPM requires a 32-byte challenge".to_owned())?;
    let doc = collect_nitrotpm_document(nonce, None).map_err(|e| format!("{e:#}"))?;
    let pcrs = nitrotpm::inspect_document(&doc, nonce, None).map_err(|e| format!("{e:#}"))?;
    Ok(TpmAttestation {
        digest: Sha256::digest(&doc).into(),
        attestation_doc: Some(doc),
        pcrs,
        method: "unverified NitroTPM COSE document; verifier appraisal required",
    })
}

/// Invoke the installed AWS tool with exact nonce and optional user-data bytes.
/// Output is structurally checked and request-bound, but not authenticated here.
/// Signed collection errors never fall back to sysfs or another provider.
pub fn collect_nitrotpm_document(nonce: &[u8; 32], user_data: Option<&[u8]>) -> Result<Vec<u8>> {
    let tool = which_nitro_tpm_attest().context("signed NitroTPM tool is unavailable")?;
    collect_nitrotpm_document_with_tool(&tool, nonce, user_data)
}

pub fn collect_nitrotpm_document_with_tool(
    tool: &Path,
    nonce: &[u8; 32],
    user_data: Option<&[u8]>,
) -> Result<Vec<u8>> {
    ensure!(tool.is_absolute(), "NitroTPM tool path must be absolute");
    ensure!(
        user_data.is_none_or(|d| d.len() <= 1024),
        "NitroTPM user_data exceeds AWS limit"
    );
    #[cfg(unix)]
    {
        use rand::RngCore;
        use std::io::Write;
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        let mut random = [0u8; 16];
        rand::rngs::OsRng
            .try_fill_bytes(&mut random)
            .context("NitroTPM temporary directory randomness")?;
        let directory = Path::new("/tmp").join(format!(
            "uq-nitrotpm-{}-{}",
            std::process::id(),
            hex::encode(random)
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&directory)?;
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let cleanup = Cleanup(directory);
        let write = |name: &str, value: &[u8]| -> Result<PathBuf> {
            let path = cleanup.0.join(name);
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&path)?;
            file.write_all(value)?;
            Ok(path)
        };
        let nonce_file = write("nonce", nonce)?;
        let mut command = std::process::Command::new(tool);
        command.arg("--nonce").arg(&nonce_file);
        if let Some(data) = user_data {
            command.arg("--user-data").arg(write("user-data", data)?);
        }
        let output = bounded_output(
            &mut command,
            std::time::Duration::from_secs(20),
            MAX_NITROTPM_DOCUMENT_BYTES,
        )?;
        nitrotpm::inspect_document(&output, nonce, user_data)?;
        return Ok(output);
    }
    #[cfg(not(unix))]
    {
        let _ = (tool, nonce, user_data);
        bail!("NitroTPM collection requires Unix")
    }
}

#[cfg(unix)]
fn bounded_output(
    command: &mut std::process::Command,
    timeout: std::time::Duration,
    limit: usize,
) -> Result<Vec<u8>> {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    command
        .env_clear()
        .process_group(0)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command.spawn().context("start NitroTPM tool")?;
    let mut stdout = child.stdout.take().context("NitroTPM stdout")?;
    let mut stderr = child.stderr.take().context("NitroTPM stderr")?;
    let result = (|| -> Result<Vec<u8>> {
        for fd in [stdout.as_raw_fd(), stderr.as_raw_fd()] {
            // SAFETY: both descriptors are live owned pipe endpoints; F_SETFL
            // only enables nonblocking reads and cannot modify filesystem data.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            ensure!(flags >= 0, "read pipe flags");
            ensure!(
                unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } >= 0,
                "set nonblocking pipe"
            );
        }
        let start = std::time::Instant::now();
        let mut out = Vec::new();
        let mut err = Vec::new();
        fn drain(reader: &mut impl Read, out: &mut Vec<u8>, limit: usize) -> Result<()> {
            let mut buffer = [0; 4096];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => return Ok(()),
                    Ok(n) => {
                        ensure!(
                            out.len().saturating_add(n) <= limit,
                            "NitroTPM output exceeds limit"
                        );
                        out.extend_from_slice(&buffer[..n]);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }
        loop {
            drain(&mut stdout, &mut out, limit)?;
            drain(&mut stderr, &mut err, 16 * 1024)?;
            if let Some(status) = child.try_wait()? {
                drain(&mut stdout, &mut out, limit)?;
                drain(&mut stderr, &mut err, 16 * 1024)?;
                ensure!(status.success(), "NitroTPM tool failed with {status}");
                return Ok(out);
            }
            ensure!(start.elapsed() < timeout, "NitroTPM tool timed out");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    })();
    if result.is_err() {
        // SAFETY: the child was spawned in its own process group with ID equal
        // to its PID. A negative kill target confines cancellation to that group.
        if let Ok(pid) = i32::try_from(child.id()) {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
        let _ = child.kill();
    }
    let _ = child.wait();
    result
}
fn which_nitro_tpm_attest() -> Option<PathBuf> {
    [
        "/usr/bin/nitro-tpm-attest",
        "/usr/local/bin/nitro-tpm-attest",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|path| std::fs::metadata(path).is_ok_and(|m| m.is_file()))
}

#[derive(Debug, serde::Serialize)]
pub struct UnverifiedSysfsPcrs {
    pub pcrs: BTreeMap<u32, Vec<u8>>,
}
pub fn read_unverified_sysfs_pcrs(base: &Path, indices: &[u32]) -> Result<UnverifiedSysfsPcrs> {
    use std::io::Read;
    ensure!(
        !indices.is_empty() && indices.len() <= 24,
        "invalid diagnostic PCR selection"
    );
    let mut pcrs = BTreeMap::new();
    for &index in indices {
        ensure!(
            index < 24 && !pcrs.contains_key(&index),
            "invalid/duplicate diagnostic PCR index"
        );
        let mut data = Vec::new();
        std::fs::File::open(base.join(index.to_string()))?
            .take(129)
            .read_to_end(&mut data)?;
        ensure!(data.len() <= 128, "PCR sysfs text exceeds limit");
        let bytes = hex::decode(std::str::from_utf8(&data)?.trim())?;
        ensure!(
            bytes.len() == 32,
            "diagnostic pcr-sha256 value must be 32 bytes"
        );
        pcrs.insert(index, bytes);
    }
    Ok(UnverifiedSysfsPcrs { pcrs })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{process::Command, time::Duration};

    #[test]
    fn subprocess_is_bounded_and_environment_is_not_inherited() {
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "test -z \"$UQ_TEST_INHERITED\" || exit 9; printf abc"])
            .env("UQ_TEST_INHERITED", "must-not-reach-tool");
        assert_eq!(
            bounded_output(&mut command, Duration::from_secs(2), 3).unwrap(),
            b"abc"
        );
        let mut excessive = Command::new("/bin/sh");
        excessive.args(["-c", "printf abcd"]);
        assert!(bounded_output(&mut excessive, Duration::from_secs(2), 3)
            .unwrap_err()
            .to_string()
            .contains("exceeds limit"));
        let mut failed = Command::new("/bin/sh");
        failed.args(["-c", "exit 7"]);
        assert!(bounded_output(&mut failed, Duration::from_secs(2), 32)
            .unwrap_err()
            .to_string()
            .contains("failed"));
    }

    #[test]
    fn timeout_cancels_descendants_in_the_isolated_process_group() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("must-not-exist");
        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                "(/bin/sleep 0.2; printf escaped > \"$1\") & wait",
                "test-vector",
            ])
            .arg(&marker);
        let start = std::time::Instant::now();
        assert!(bounded_output(&mut command, Duration::from_millis(30), 32)
            .unwrap_err()
            .to_string()
            .contains("timed out"));
        assert!(start.elapsed() < Duration::from_secs(2));
        std::thread::sleep(Duration::from_millis(300));
        assert!(!marker.exists(), "tool descendant survived cancellation");
    }

    #[test]
    fn diagnostic_sysfs_values_remain_indexed_and_fail_on_malformed_input() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("4"), hex::encode([4; 32])).unwrap();
        let diagnostic = read_unverified_sysfs_pcrs(directory.path(), &[4]).unwrap();
        assert_eq!(diagnostic.pcrs.get(&4).unwrap(), &vec![4; 32]);
        assert!(read_unverified_sysfs_pcrs(directory.path(), &[4, 4]).is_err());
        assert!(read_unverified_sysfs_pcrs(directory.path(), &[5]).is_err());
        std::fs::write(directory.path().join("4"), "not hex").unwrap();
        assert!(read_unverified_sysfs_pcrs(directory.path(), &[4]).is_err());
        std::fs::write(directory.path().join("4"), "00".repeat(100)).unwrap();
        assert!(read_unverified_sysfs_pcrs(directory.path(), &[4]).is_err());
    }
}
