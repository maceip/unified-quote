//! Bounded transport to the explicitly selected Google attestation adapter.
//!
//! The helper is a trusted executable installed by the operator. It is never
//! selected from evidence, PATH, or an environment variable. A helper failure
//! rejects the request; this transport never retries with another verifier.
use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const MAX_REQUEST: usize = 48 * 1024 * 1024;
const MAX_RESPONSE: usize = 16 * 1024 * 1024;
const MAX_DIAGNOSTIC: usize = 16 * 1024;

/// An explicitly selected Google collection transport. Failure never selects
/// another transport. Collected bytes remain unverified evidence.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TdxTransport {
    Configfs,
    Ioctl,
}

/// Configuration comes from the relying party, independently of any evidence.
#[derive(Debug, Clone)]
pub struct GoogleVerifier {
    executable: PathBuf,
    timeout: Duration,
}

#[derive(Serialize)]
struct Request<'a, T> {
    version: u32,
    operation: &'a str,
    payload: &'a T,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Response<T> {
    version: u32,
    request_sha256: String,
    result: Option<T>,
    error: Option<String>,
}

impl GoogleVerifier {
    #[cfg(feature = "tdx")]
    pub(crate) fn verify_tdx(
        &self,
        quote: &[u8],
        report_data: &[u8; 64],
        measurement: &[u8],
        collateral: &crate::quote::tdx_collateral::TdxCollateral,
        minimum_tcb_evaluation_data_number: u64,
    ) -> Result<std::collections::BTreeMap<String, Vec<u8>>> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ResultData {
            measurements: std::collections::BTreeMap<String, String>,
            quote_version: u16,
            tdx_version: String,
            tcb_status: String,
        }
        let payload = serde_json::json!({
            "quote": STANDARD.encode(quote),
            "expected_report_data": STANDARD.encode(report_data),
            "expected_measurement": STANDARD.encode(measurement),
            "collateral": {
                "tcb_info_json": STANDARD.encode(&collateral.tcb_info_json),
                "tcb_info_signing_chain": collateral.tcb_info_signing_chain.iter().map(|v| STANDARD.encode(v)).collect::<Vec<_>>(),
                "qe_identity_json": STANDARD.encode(&collateral.qe_identity_json),
                "qe_identity_signing_chain": collateral.qe_identity_signing_chain.iter().map(|v| STANDARD.encode(v)).collect::<Vec<_>>(),
                "root_ca_crl": STANDARD.encode(&collateral.root_ca_crl),
                "pck_crl": STANDARD.encode(&collateral.pck_crl),
            },
            "policy": { "minimum_tcb_evaluation_data_number": minimum_tcb_evaluation_data_number }
        });
        let result: ResultData = self.invoke("tdx_verify", &payload)?;
        ensure!(matches!(result.quote_version, 4 | 5)
            && matches!(result.tdx_version.as_str(), "1.0" | "1.5")
            && result.tcb_status == "UpToDate", "Google returned an unacceptable TDX profile/status");
        let values: std::collections::BTreeMap<_, _> = result.measurements.into_iter()
            .map(|(key, value)| Ok((key, STANDARD.decode(value)?)))
            .collect::<Result<_>>()?;
        for key in ["MRTD", "RTMR0", "RTMR1", "RTMR2", "RTMR3"] {
            ensure!(values.get(key).is_some_and(|v| v.len() == 48), "Google TDX result lacks {key}");
        }
        ensure!(values.get("MRTD").is_some_and(|v| v == measurement)
            && values.get("REPORTDATA").is_some_and(|v| v.as_slice() == report_data)
            && values.get("TD_ATTRIBUTES").is_some_and(|v| v.len() == 8),
            "Google TDX result does not match expected commitments");
        Ok(values)
    }

    #[cfg(feature = "tdx")]
    pub(crate) fn collect_tdx(&self, transport: TdxTransport, report_data: &[u8; 64]) -> Result<Vec<u8>> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Collected { quote: String }
        let result: Collected = self.invoke("tdx_collect", &serde_json::json!({
            "platform": "tdx", "transport": transport, "report_data": STANDARD.encode(report_data)
        }))?;
        let bytes = STANDARD.decode(result.quote)?;
        tdx_body_offset(&bytes)?;
        Ok(bytes)
    }
    /// Compare exact CCEL/AAEL bytes with registers already authenticated by the
    /// CPU verifier. This is crate-private so callers cannot turn arbitrary
    /// register values into an attestation verdict.
    pub(crate) fn replay_tdx(&self, log: &[u8], registers: &[[u8; 48]; 4]) -> Result<()> {
        #[derive(Serialize)]
        struct ReplayRequest {
            log: String,
            registers: Vec<String>,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ReplayResult {
            event_count: usize,
            registers_verified: usize,
        }
        let result: ReplayResult = self.invoke(
            "tdx_replay",
            &ReplayRequest {
                log: STANDARD.encode(log),
                registers: registers.iter().map(|r| STANDARD.encode(r)).collect(),
            },
        )?;
        ensure!(
            result.registers_verified == 4 && result.event_count <= 65_536,
            "Google replay did not verify all four RTMRs within event limits"
        );
        Ok(())
    }
    pub fn new(executable: impl AsRef<Path>) -> Result<Self> {
        let path = executable.as_ref();
        ensure!(
            path.is_absolute(),
            "Google verifier requires an absolute executable path"
        );
        let executable = path
            .canonicalize()
            .context("resolve Google verifier executable")?;
        ensure!(
            executable.is_file(),
            "Google verifier executable is not a regular file"
        );
        Ok(Self {
            executable,
            timeout: Duration::from_secs(60),
        })
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self> {
        ensure!(
            !timeout.is_zero() && timeout <= Duration::from_secs(60),
            "Google verifier timeout must be greater than zero and at most 60 seconds"
        );
        self.timeout = timeout;
        Ok(self)
    }

    pub(crate) fn invoke<T: Serialize, R: DeserializeOwned>(
        &self,
        operation: &str,
        payload: &T,
    ) -> Result<R> {
        let request = serde_json::to_vec(&Request {
            version: 1,
            operation,
            payload,
        })?;
        ensure!(
            request.len() <= MAX_REQUEST,
            "Google verifier request exceeds limit"
        );
        let expected_digest = hex::encode(Sha256::digest(&request));
        let mut command = Command::new(&self.executable);
        command
            .arg("--stdio-v1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut child = command.spawn().context("start Google verifier")?;
        let mut stdin = child
            .stdin
            .take()
            .context("Google verifier stdin unavailable")?;
        let stdout = child
            .stdout
            .take()
            .context("Google verifier stdout unavailable")?;
        let stderr = child
            .stderr
            .take()
            .context("Google verifier stderr unavailable")?;
        // Drain both pipes concurrently so a child cannot deadlock the caller by
        // filling one while the caller reads the other. Readers are bounded.
        let input = thread::spawn(move || stdin.write_all(&request));
        let output = thread::spawn(move || read_limited(stdout, MAX_RESPONSE));
        let diagnostic = thread::spawn(move || read_limited(stderr, MAX_DIAGNOSTIC));
        let deadline = Instant::now() + self.timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                Ok(None) => {
                    terminate(&mut child);
                    let _ = child.wait();
                    break Err(anyhow::anyhow!("Google verifier exceeded its deadline"));
                }
                Err(error) => {
                    terminate(&mut child);
                    let _ = child.wait();
                    break Err(error.into());
                }
            }
        };
        let written = input
            .join()
            .map_err(|_| anyhow::anyhow!("Google verifier input worker failed"))?;
        let output = output
            .join()
            .map_err(|_| anyhow::anyhow!("Google verifier output worker failed"))?;
        let diagnostic = diagnostic
            .join()
            .map_err(|_| anyhow::anyhow!("Google verifier diagnostic worker failed"))?;
        let status = status?;
        written.context("write Google verifier request")?;
        let output = output?;
        let diagnostic = diagnostic?;
        let response: Response<R> =
            serde_json::from_slice(&output).context("invalid Google verifier response")?;
        ensure!(
            response.version == 1 && response.request_sha256 == expected_digest,
            "Google verifier response does not match the request"
        );
        match (status.success(), response.result, response.error) {
            (true, Some(result), None) => Ok(result),
            (_, None, Some(error)) => bail!("Google verifier rejected evidence: {error}"),
            _ => bail!(
                "Google verifier failed ({}): {}",
                status,
                String::from_utf8_lossy(&diagnostic)
            ),
        }
    }
}

/// Validate only framing, not authenticity. This supports collection of both
/// published quote versions without representing a local TDREPORT as a quote.
pub(crate) fn tdx_body_offset(quote: &[u8]) -> Result<usize> {
    ensure!(quote.len() >= 48 && quote.len() <= 8 * 1024 * 1024,
        "TDX quote size outside limits");
    ensure!(quote[2..4] == [2, 0] && quote[4..8] == [0x81, 0, 0, 0],
        "unsupported TDX attestation key or TEE type");
    let (start, len) = match u16::from_le_bytes(quote[..2].try_into()?) {
        4 => (48, 584),
        5 => {
            ensure!(quote.len() >= 54, "truncated TDX v5 descriptor");
            let kind = u16::from_le_bytes(quote[48..50].try_into()?);
            let len = u32::from_le_bytes(quote[50..54].try_into()?) as usize;
            ensure!(matches!((kind, len), (2, 584) | (3, 648)), "unsupported TDX v5 body");
            (54, len)
        }
        _ => bail!("unsupported TDX quote version"),
    };
    let signature_offset = start + len;
    ensure!(quote.len() >= signature_offset + 4, "truncated TDX quote");
    let signature_len = u32::from_le_bytes(quote[signature_offset..signature_offset + 4].try_into()?) as usize;
    ensure!(signature_len > 0 && signature_len == quote.len() - signature_offset - 4,
        "TDX signature data is missing or has trailing bytes");
    Ok(start)
}

fn terminate(child: &mut std::process::Child) {
    #[cfg(unix)]
    // The helper owns a new process group; terminate descendants which might
    // otherwise keep inherited pipe descriptors open after its deadline.
    unsafe {
        libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL);
    }
    let _ = child.kill();
}

fn read_limited(reader: impl Read, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "Google verifier output exceeds limit");
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn helper_output_is_bounded() {
        assert_eq!(read_limited(&b"abc"[..], 3).unwrap(), b"abc");
        assert!(read_limited(&b"abcd"[..], 3).is_err());
    }
    #[test]
    fn does_not_search_path_for_a_verifier() {
        assert!(GoogleVerifier::new("uq-google-attestation").is_err());
    }

    #[cfg(unix)]
    fn script(contents: &str) -> (tempfile::TempDir, GoogleVerifier) {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transport-test");
        std::fs::write(&path, format!("#!/bin/sh\n{contents}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let verifier = GoogleVerifier::new(path).unwrap();
        (dir, verifier)
    }

    #[cfg(unix)]
    #[test]
    fn process_response_must_match_request_and_success_status() {
        // Transport fixture only: no attestation or crypto verdict is simulated.
        let payload = serde_json::json!({"transport_test":1});
        let request = serde_json::to_vec(&Request {
            version: 1,
            operation: "transport_test",
            payload: &payload,
        })
        .unwrap();
        let digest = hex::encode(Sha256::digest(request));
        for (response_digest, exit_status, accepted) in [
            (digest.as_str(), 0, true),
            ("wrong-request", 0, false),
            (digest.as_str(), 1, false),
        ] {
            let response = serde_json::json!({"version":1,"request_sha256":response_digest,"result":{"transport_test":1}});
            let (_dir, verifier) = script(&format!(
                "cat >/dev/null\nprintf '%s' '{response}'\nexit {exit_status}"
            ));
            let result = verifier.invoke::<_, serde_json::Value>("transport_test", &payload);
            assert_eq!(result.is_ok(), accepted);
        }
    }

    #[cfg(unix)]
    #[test]
    fn deadline_terminates_child_and_inherited_pipes() {
        let (_dir, verifier) = script("sleep 10");
        let verifier = verifier.with_timeout(Duration::from_millis(50)).unwrap();
        let start = Instant::now();
        let result = verifier.invoke::<_, serde_json::Value>("transport_test", &());
        assert!(result.unwrap_err().to_string().contains("deadline"));
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}
