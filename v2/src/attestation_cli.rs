//! Composite collection, verifier policy, and a local fresh-evidence endpoint.
//! Nothing in this module starts automatically. Service operation requires an
//! explicit command; collection emits evidence and never an admission verdict.

use anyhow::{bail, ensure, Context, Result};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use unified_quote::attestation::{AttestationCollector, AttestationVerifier, BootPolicy};
use unified_quote::eat::EatToken;
use unified_quote::quote::Platform;

const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;
const MAX_HEADER_BYTES: usize = 8192;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const OUTPUT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Cbor,
    Json,
}
impl Format {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "cbor" => Ok(Self::Cbor),
            "json" => Ok(Self::Json),
            _ => bail!("format must be cbor or json"),
        }
    }
    fn content_type(self) -> &'static str {
        match self {
            Self::Cbor => "application/cbor",
            Self::Json => "application/json",
        }
    }
}

fn parse_flags(
    args: &[String],
    values: &[&str],
    switches: &[&str],
) -> Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    let mut args = args.iter();
    while let Some(key) = args.next() {
        let value = if switches.contains(&key.as_str()) {
            "true".to_owned()
        } else if values.contains(&key.as_str()) {
            let value = args
                .next()
                .with_context(|| format!("missing value for {key}"))?;
            ensure!(
                !value.is_empty() && !value.starts_with("--"),
                "missing value for {key}"
            );
            value.clone()
        } else {
            bail!("unknown argument {key}");
        };
        ensure!(
            result.insert(key.clone(), value).is_none(),
            "duplicate argument {key}"
        );
    }
    Ok(result)
}

fn required<'a>(flags: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str> {
    flags
        .get(name)
        .map(String::as_str)
        .with_context(|| format!("{name} is required"))
}

fn fixed_hex<const N: usize>(text: &str, name: &str) -> Result<[u8; N]> {
    ensure!(
        text.len() == 2 * N,
        "{name} must contain {} hexadecimal characters",
        2 * N
    );
    let mut out = [0; N];
    hex::decode_to_slice(text, &mut out)
        .with_context(|| format!("invalid {name} hexadecimal value"))?;
    Ok(out)
}

fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    std::fs::File::open(path)
        .with_context(|| format!("read {}", path.display()))?
        .take((max + 1) as u64)
        .read_to_end(&mut data)?;
    ensure!(
        data.len() <= max,
        "{} exceeds input byte limit",
        path.display()
    );
    Ok(data)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn encode(token: &EatToken, format: Format) -> Result<Vec<u8>> {
    let bytes = match format {
        Format::Cbor => token.to_cbor()?,
        Format::Json => serde_json::to_vec_pretty(token)?,
    };
    ensure!(
        bytes.len() <= MAX_INPUT_BYTES,
        "receipt exceeds response byte limit"
    );
    Ok(bytes)
}

fn validate_collection_boot_log(
    bytes: &[u8],
    profile: &unified_quote::tee::composite::CpuCollectionProfile,
) -> Result<()> {
    use unified_quote::{boot::EventLog, tee::composite::CpuCollectionProfile};
    match profile {
        CpuCollectionProfile::Direct => EventLog::parse_tdx_ccel(bytes, Default::default())?,
        CpuCollectionProfile::AzureSnpVtpm { .. } | CpuCollectionProfile::AwsSnpNitroTpm => {
            EventLog::parse_tcg2(bytes, Default::default())?
        }
    };
    Ok(())
}

struct CollectionConfig {
    tls_spki: PathBuf,
    value_x: [u8; 48],
    gpu: bool,
    topology: String,
    collateral: Option<PathBuf>,
    boot_log: Option<PathBuf>,
    runtime_log: Option<PathBuf>,
    source_hash: Option<[u8; 48]>,
    artifact_hash: Option<[u8; 48]>,
    previous_attestation: Option<PathBuf>,
    cpu_profile: unified_quote::tee::composite::CpuCollectionProfile,
}
impl CollectionConfig {
    fn from_flags(flags: &BTreeMap<String, String>) -> Result<Self> {
        use der::Decode;
        let gpu = flags.contains_key("--gpu");
        let topology = flags
            .get("--topology")
            .map(String::as_str)
            .unwrap_or("auto");
        ensure!(
            matches!(topology, "auto" | "independent" | "ppcie"),
            "invalid --topology"
        );
        ensure!(
            gpu || (!flags.contains_key("--collateral") && !flags.contains_key("--topology")),
            "--collateral and --topology require --gpu"
        );
        #[cfg(not(feature = "gpu"))]
        ensure!(
            !gpu,
            "GPU collection requires a binary built with --features gpu"
        );
        let tls_spki = PathBuf::from(required(flags, "--tls-spki")?);
        ensure!(
            flags.contains_key("--source-hash") == flags.contains_key("--artifact-hash"),
            "build claims require both --source-hash and --artifact-hash"
        );
        ensure!(
            !flags.contains_key("--previous-attestation") || flags.contains_key("--source-hash"),
            "--previous-attestation requires explicit build hashes"
        );
        ensure!(
            !flags.contains_key("--runtime-log") || flags.contains_key("--boot-log"),
            "--runtime-log requires --boot-log"
        );
        spki::SubjectPublicKeyInfoOwned::from_der(&read_bounded(&tls_spki, 16 * 1024)?)
            .context("invalid configured TLS SPKI DER")?;
        let cpu_profile = match flags
            .get("--cpu-profile")
            .map(String::as_str)
            .unwrap_or("direct")
        {
            "direct" => {
                ensure!(
                    !flags.contains_key("--tpm-pcrs"),
                    "--tpm-pcrs requires Azure collection"
                );
                unified_quote::tee::composite::CpuCollectionProfile::Direct
            }
            "azure-snp-vtpm" => unified_quote::tee::composite::CpuCollectionProfile::AzureSnpVtpm {
                pcr_indices: required(flags, "--tpm-pcrs")?
                    .split(',')
                    .map(|s| s.parse::<u8>().context("invalid --tpm-pcrs index"))
                    .collect::<Result<Vec<_>>>()?,
            },
            "aws-snp-nitrotpm" => {
                ensure!(
                    !flags.contains_key("--tpm-pcrs"),
                    "AWS NitroTPM controls its signed PCR set"
                );
                unified_quote::tee::composite::CpuCollectionProfile::AwsSnpNitroTpm
            }
            _ => bail!("--cpu-profile must be direct, azure-snp-vtpm or aws-snp-nitrotpm"),
        };
        cpu_profile.validate()?;
        ensure!(
            matches!(
                cpu_profile,
                unified_quote::tee::composite::CpuCollectionProfile::Direct
            ) || !flags.contains_key("--runtime-log"),
            "CoCo AAEL runtime log requires direct TDX collection"
        );
        Ok(Self {
            cpu_profile,
            tls_spki,
            value_x: fixed_hex(required(flags, "--value-x")?, "--value-x")?,
            gpu,
            topology: topology.to_owned(),
            collateral: flags.get("--collateral").map(PathBuf::from),
            boot_log: flags.get("--boot-log").map(PathBuf::from),
            runtime_log: flags.get("--runtime-log").map(PathBuf::from),
            source_hash: flags
                .get("--source-hash")
                .map(|s| fixed_hex(s, "--source-hash"))
                .transpose()?,
            artifact_hash: flags
                .get("--artifact-hash")
                .map(|s| fixed_hex(s, "--artifact-hash"))
                .transpose()?,
            previous_attestation: flags.get("--previous-attestation").map(PathBuf::from),
        })
    }
    fn collect(&self, nonce: &[u8; 32]) -> Result<EatToken> {
        let spki = read_bounded(&self.tls_spki, 64 * 1024)?;
        let mut builder = AttestationCollector::builder()
            .with_nonce(nonce)
            .with_tls_spki_der(&spki)
            .with_value_x(&self.value_x)
            .with_cpu_profile(self.cpu_profile.clone());
        if let (Some(source_hash), Some(artifact_hash)) = (self.source_hash, self.artifact_hash) {
            builder = builder.with_build_claims(unified_quote::attestation::BuildClaims {
                source_hash,
                artifact_hash,
                previous_attestation: self
                    .previous_attestation
                    .as_ref()
                    .map(|path| read_bounded(path, 8 * 1024 * 1024))
                    .transpose()?
                    .unwrap_or_default(),
            });
        }
        if let Some(path) = &self.boot_log {
            let bytes = read_bounded(
                path,
                unified_quote::boot::ParseLimits::default().max_log_bytes,
            )?;
            // Select the parser from the explicit collection profile. Parsing
            // here cannot promote replay values to authenticated registers.
            let combined = if let Some(runtime) = &self.runtime_log {
                let aael = read_bounded(runtime, 16 * 1024 * 1024)?;
                unified_quote::boot::runtime::append_coco_aael(&bytes, &aael, Default::default())?
            } else {
                validate_collection_boot_log(&bytes, &self.cpu_profile)?;
                bytes
            };
            builder = builder.with_boot_log(combined);
        }
        #[cfg(feature = "gpu")]
        if self.gpu {
            use unified_quote::attestation::GpuTopologyMode;
            let topology = match self.topology.as_str() {
                "auto" => GpuTopologyMode::AutoDetect,
                "independent" => GpuTopologyMode::Independent,
                "ppcie" => GpuTopologyMode::ProtectedPcie,
                _ => unreachable!("validated topology"),
            };
            // Reload material per request so operator-controlled revocation
            // refresh does not require a daemon restart. Collection does not
            // transform an expired cache into an authenticated verdict.
            builder = builder.with_gpu_topology(topology);
            if let Some(path) = &self.collateral {
                let bytes = read_bounded(path, MAX_INPUT_BYTES)?;
                let collateral =
                    serde_json::from_slice::<unified_quote::gpu::GpuCollateral>(&bytes)
                        .context("invalid GPU collateral JSON")?;
                builder = builder.with_gpu_collateral(collateral);
            }
        }
        builder.build()?.collect()
    }
}

pub fn collect(args: &[String]) -> Result<()> {
    let flags = parse_flags(
        args,
        &[
            "--nonce",
            "--tls-spki",
            "--value-x",
            "--collateral",
            "--topology",
            "--boot-log",
            "--runtime-log",
            "--cpu-profile",
            "--tpm-pcrs",
            "--source-hash",
            "--artifact-hash",
            "--previous-attestation",
            "--out",
            "--format",
        ],
        &["--gpu"],
    )?;
    let nonce = fixed_hex(required(&flags, "--nonce")?, "--nonce")?;
    let format = Format::parse(flags.get("--format").map(String::as_str).unwrap_or("cbor"))?;
    let out = Path::new(required(&flags, "--out")?);
    let config = CollectionConfig::from_flags(&flags)?;
    let token = config.collect(&nonce)?;
    write_new(out, &encode(&token, format)?)?;
    eprintln!(
        "[uq] collected fresh composite evidence into {}",
        out.display()
    );
    Ok(())
}

/// Capability and driver observations only; this command neither quotes nor
/// verifies hardware and never marks a GPU ready for workloads.
pub fn status(args: &[String]) -> Result<()> {
    parse_flags(args, &[], &["--json"])?;
    let cpu = match unified_quote::tee::detect::detect_tee() {
        Ok(provider) => {
            serde_json::json!({"detected": true, "platform": provider.platform(), "attestation": "not_performed"})
        }
        Err(error) => {
            serde_json::json!({"detected": false, "detail": error.to_string(), "attestation": "not_performed"})
        }
    };
    #[cfg(feature = "gpu")]
    let gpu = match unified_quote::gpu::NvmlCollector::open()
        .and_then(|collector| collector.status())
    {
        Ok(observed) => {
            serde_json::json!({"available": true, "observations": observed, "attestation": "not_performed"})
        }
        Err(error) => {
            serde_json::json!({"available": false, "detail": error.to_string(), "attestation": "not_performed"})
        }
    };
    #[cfg(not(feature = "gpu"))]
    let gpu = serde_json::json!({"available": false, "detail": "binary built without gpu feature", "attestation": "not_performed"});
    serde_json::to_writer_pretty(
        std::io::stdout().lock(),
        &serde_json::json!({
            "status_kind": "unverified_capability_observations", "cpu": cpu, "gpu": gpu,
            "boot_logs": {"tcg2_path_present": Path::new(unified_quote::boot::TPM_EVENT_LOG_PATH).exists(),
                "ccel_path_present": Path::new(unified_quote::boot::CCEL_DATA_PATH).exists()}
        }),
    )?;
    println!();
    Ok(())
}

pub fn verify(args: &[String]) -> Result<()> {
    let flags = parse_verifier_flags(args)?;
    verify_with_flags(flags)
}

fn parse_verifier_flags(args: &[String]) -> Result<BTreeMap<String, String>> {
    let mut normalized = Vec::new();
    let mut positional = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let key = match arg.as_str() {
            "--expected-value-x" => "--value-x",
            "--require-gpu-verified" => "--require-gpu",
            key => key,
        };
        if !key.starts_with('-') {
            ensure!(
                positional.replace(key.to_owned()).is_none(),
                "multiple receipt filenames"
            );
            continue;
        }
        normalized.push(key.to_owned());
        if !matches!(key, "--require-gpu" | "--json") {
            normalized.push(
                iter.next()
                    .with_context(|| format!("missing value for {key}"))?
                    .clone(),
            );
        }
    }
    if let Some(file) = positional {
        normalized.extend(["--in".into(), file]);
    }
    parse_flags(
        &normalized,
        &[
            "--in",
            "--format",
            "--nonce",
            "--tls-spki",
            "--value-x",
            "--platform",
            "--expected-platform-measurement",
            "--expected-mrtd",
            "--cpu-collateral",
            "--cpu-tcb-policy",
            "--azure-policy",
            "--nitrotpm-policy",
            "--gpu-policy",
            "--boot-policy",
            "--google-boot-verifier",
            "--prior-stage-policy",
            "--uki",
            "--max-age",
        ],
        &["--require-gpu", "--json"],
    )
}

fn verify_with_flags(flags: BTreeMap<String, String>) -> Result<()> {
    let nonce = fixed_hex(required(&flags, "--nonce")?, "--nonce")?;
    let value_x = fixed_hex(required(&flags, "--value-x")?, "--value-x")?;
    let spki = read_bounded(Path::new(required(&flags, "--tls-spki")?), 64 * 1024)?;
    let mut builder = AttestationVerifier::builder()
        .with_expected_nonce(&nonce)
        .with_tls_spki_der(&spki)
        .with_expected_value_x(&value_x);
    if let Some(platform) = flags.get("--platform") {
        builder = builder.require_platform(match platform.as_str() {
            "tdx" => Platform::Tdx,
            "sev-snp" => Platform::SevSnp,
            "nitro" => Platform::Nitro,
            "azure-snp-vtpm" => Platform::AzureSnpVtpm,
            "aws-snp-nitrotpm" => Platform::AwsSnpNitroTpm,
            _ => bail!("unsupported --platform"),
        });
    }
    ensure!(flags.contains_key("--expected-platform-measurement") ^ flags.contains_key("--expected-mrtd"),
        "choose exactly one --expected-platform-measurement or --expected-mrtd from the approved image manifest");
    let measurement = flags
        .get("--expected-platform-measurement")
        .or_else(|| flags.get("--expected-mrtd"))
        .unwrap();
    let bytes = fixed_hex::<48>(measurement, "expected platform measurement")?;
    builder = builder.with_expected_platform_measurement(&bytes);
    if flags.contains_key("--expected-mrtd") {
        ensure!(
            flags.get("--platform").is_none_or(|p| p == "tdx"),
            "--expected-mrtd requires TDX"
        );
        builder = builder.require_platform(Platform::Tdx);
    }
    if let Some(age) = flags.get("--max-age") {
        builder = builder.with_max_age_secs(age.parse().context("invalid --max-age seconds")?);
    }
    if let Some(path) = flags.get("--cpu-collateral") {
        let collateral = serde_json::from_slice::<unified_quote::quote::verify::CpuCollateral>(
            &read_bounded(Path::new(path), 16 * 1024 * 1024)?,
        )
        .context("invalid CPU collateral JSON")?;
        builder = builder.with_cpu_collateral(collateral);
    }
    if let Some(path) = flags.get("--cpu-tcb-policy") {
        let policy = serde_json::from_slice::<unified_quote::quote::verify::CpuTcbPolicy>(
            &read_bounded(Path::new(path), 64 * 1024)?,
        )
        .context("invalid CPU TCB policy JSON")?;
        builder = builder.with_cpu_tcb_policy(policy);
    }
    #[cfg(feature = "sev-snp")]
    if let Some(path) = flags.get("--azure-policy") {
        let policy = serde_json::from_slice::<
            unified_quote::tee::azure_composite::AzureCompositePolicy,
        >(&read_bounded(Path::new(path), 1024 * 1024)?)
        .context("invalid Azure composite policy JSON")?;
        builder = builder.with_azure_policy(policy);
    }
    #[cfg(not(feature = "sev-snp"))]
    ensure!(
        !flags.contains_key("--azure-policy"),
        "Azure policy requires sev-snp support"
    );
    #[cfg(feature = "nitro")]
    if let Some(path) = flags.get("--nitrotpm-policy") {
        let policy = serde_json::from_slice::<unified_quote::tee::tpm::NitroTpmPolicy>(
            &read_bounded(Path::new(path), 1024 * 1024)?,
        )
        .context("invalid NitroTPM policy JSON")?;
        builder = builder.with_nitrotpm_policy(policy);
    }
    #[cfg(not(feature = "nitro"))]
    ensure!(
        !flags.contains_key("--nitrotpm-policy"),
        "NitroTPM policy requires nitro support"
    );
    if let Some(path) = flags.get("--boot-policy") {
        let policy =
            serde_json::from_slice::<BootPolicy>(&read_bounded(Path::new(path), MAX_INPUT_BYTES)?)
                .context("invalid boot policy JSON")?;
        builder = builder.with_boot_policy(policy);
    }
    if let Some(path) = flags.get("--google-boot-verifier") {
        builder = builder
            .with_google_boot_verifier(unified_quote::google_backend::GoogleVerifier::new(path)?);
    }
    if let Some(path) = flags.get("--uki") {
        ensure!(
            flags.contains_key("--boot-policy"),
            "--uki requires --boot-policy"
        );
        builder = builder.with_uki_evidence(read_bounded(
            Path::new(path),
            unified_quote::boot::uki::MAX_UKI_BYTES,
        )?);
    }
    let gpu_required = flags.contains_key("--require-gpu") || flags.contains_key("--gpu-policy");
    if let Some(path) = flags.get("--prior-stage-policy") {
        let policy = serde_json::from_slice::<unified_quote::attestation_chain::PriorStagePolicy>(
            &read_bounded(Path::new(path), 32 * 1024 * 1024)?,
        )
        .context("invalid prior-stage policy JSON")?;
        builder = builder.with_prior_stage_policy(policy);
    }
    builder = builder.require_gpu_verified(gpu_required);
    #[cfg(feature = "gpu")]
    if let Some(path) = flags.get("--gpu-policy") {
        let policy = serde_json::from_slice::<unified_quote::gpu::verify::GpuPolicy>(
            &read_bounded(Path::new(path), MAX_INPUT_BYTES)?,
        )
        .context("invalid GPU policy JSON")?;
        builder = builder.with_gpu_policy(policy);
    }
    #[cfg(not(feature = "gpu"))]
    ensure!(
        !gpu_required,
        "GPU verification requires a binary built with --features gpu"
    );
    let bytes = read_bounded(Path::new(required(&flags, "--in")?), MAX_INPUT_BYTES)?;
    let token = match Format::parse(flags.get("--format").map(String::as_str).unwrap_or("cbor"))? {
        Format::Cbor => EatToken::from_cbor(&bytes)?,
        Format::Json => serde_json::from_slice(&bytes).context("invalid EAT JSON")?,
    };
    let verdict = builder.build()?.verify(&token);
    serde_json::to_writer_pretty(std::io::stdout().lock(), &verdict)?;
    println!();
    ensure!(
        verdict.is_valid(),
        "attestation did not satisfy verifier policy"
    );
    Ok(())
}

trait LocalStream: Read + Write {
    fn read_deadline(&self, duration: Duration) -> std::io::Result<()>;
    fn write_deadline(&self, duration: Duration) -> std::io::Result<()>;
}
impl LocalStream for TcpStream {
    fn read_deadline(&self, duration: Duration) -> std::io::Result<()> {
        self.set_read_timeout(Some(duration))
    }
    fn write_deadline(&self, duration: Duration) -> std::io::Result<()> {
        self.set_write_timeout(Some(duration))
    }
}
#[cfg(unix)]
impl LocalStream for std::os::unix::net::UnixStream {
    fn read_deadline(&self, duration: Duration) -> std::io::Result<()> {
        self.set_read_timeout(Some(duration))
    }
    fn write_deadline(&self, duration: Duration) -> std::io::Result<()> {
        self.set_write_timeout(Some(duration))
    }
}

struct Request {
    nonce: [u8; 32],
    format: Format,
}
#[derive(Debug)]
struct RequestError {
    status: u16,
    message: &'static str,
}
type RequestResult<T> = std::result::Result<T, RequestError>;

fn parse_request(bytes: &[u8]) -> RequestResult<Request> {
    let bad = || RequestError {
        status: 400,
        message: "invalid request",
    };
    let text = std::str::from_utf8(bytes).map_err(|_| bad())?;
    if !text.ends_with("\r\n\r\n") || text.contains('\0') {
        return Err(bad());
    }
    let mut lines = text[..text.len() - 4].split("\r\n");
    let first = lines.next().ok_or_else(bad)?;
    let parts: Vec<_> = first.split(' ').collect();
    if parts.len() != 3 || parts[2] != "HTTP/1.1" {
        return Err(bad());
    }
    if parts[0] != "GET" {
        return Err(RequestError {
            status: 405,
            message: "GET required",
        });
    }
    let mut headers = BTreeMap::new();
    for line in lines {
        let (key, value) = line.split_once(':').ok_or_else(bad)?;
        if key.is_empty()
            || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || value.bytes().any(|b| b < 0x20 && b != b'\t')
        {
            return Err(bad());
        }
        let key = key.to_ascii_lowercase();
        if headers.insert(key, value.trim()).is_some() {
            return Err(bad());
        }
    }
    if headers.get("host").is_none_or(|value| value.is_empty())
        || headers.contains_key("transfer-encoding")
        || headers.contains_key("expect")
        || headers.get("content-length").is_some_and(|v| *v != "0")
    {
        return Err(bad());
    }
    let (path, query) = parts[1].split_once('?').ok_or_else(bad)?;
    if path != "/v1/attest" {
        return Err(RequestError {
            status: 404,
            message: "unknown endpoint",
        });
    }
    let mut parameters = BTreeMap::new();
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').ok_or_else(bad)?;
        if !matches!(key, "nonce" | "format") || parameters.insert(key, value).is_some() {
            return Err(bad());
        }
    }
    let nonce =
        fixed_hex::<32>(parameters.get("nonce").ok_or_else(bad)?, "nonce").map_err(|_| bad())?;
    let format = if let Some(value) = parameters.get("format") {
        Format::parse(value).map_err(|_| bad())?
    } else {
        match headers.get("accept").copied().unwrap_or("application/cbor") {
            "application/cbor" | "*/*" => Format::Cbor,
            "application/json" => Format::Json,
            _ => {
                return Err(RequestError {
                    status: 406,
                    message: "accept application/cbor or application/json",
                })
            }
        }
    };
    Ok(Request { nonce, format })
}

fn read_request(stream: &mut impl LocalStream) -> RequestResult<Request> {
    let start = Instant::now();
    let mut data = Vec::new();
    let mut chunk = [0; 1024];
    loop {
        let remaining = REQUEST_TIMEOUT
            .checked_sub(start.elapsed())
            .filter(|d| !d.is_zero())
            .ok_or(RequestError {
                status: 408,
                message: "request deadline exceeded",
            })?;
        stream.read_deadline(remaining).map_err(|_| RequestError {
            status: 400,
            message: "stream configuration failed",
        })?;
        let n = stream.read(&mut chunk).map_err(|_| RequestError {
            status: 408,
            message: "request read failed",
        })?;
        if n == 0 {
            return Err(RequestError {
                status: 400,
                message: "truncated request",
            });
        }
        data.extend_from_slice(&chunk[..n]);
        if data.len() > MAX_HEADER_BYTES {
            return Err(RequestError {
                status: 431,
                message: "request header too large",
            });
        }
        if let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            if end + 4 != data.len() {
                return Err(RequestError {
                    status: 400,
                    message: "request bodies and pipelining are unsupported",
                });
            }
            return parse_request(&data);
        }
    }
}

fn respond(
    stream: &mut impl LocalStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    let deadline = Instant::now() + OUTPUT_TIMEOUT;
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        408 => "Request Timeout",
        431 => "Request Header Fields Too Large",
        _ => "Service Unavailable",
    };
    let header = format!("HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\n\r\n", body.len());
    for data in [header.as_bytes(), body] {
        let mut offset = 0;
        while offset < data.len() {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|time| !time.is_zero())
                .context("response deadline exceeded")?;
            stream.write_deadline(remaining)?;
            let end = data.len().min(offset + 64 * 1024);
            let count = match stream.write(&data[offset..end]) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                result => result?,
            };
            ensure!(count != 0, "response stream closed");
            offset += count;
        }
    }
    stream.flush()?;
    Ok(())
}

fn handle(mut stream: impl LocalStream, config: &CollectionConfig) -> Result<()> {
    let request = match read_request(&mut stream) {
        Ok(request) => request,
        Err(error) => {
            let body = serde_json::to_vec(&serde_json::json!({ "error": error.message }))?;
            return respond(&mut stream, error.status, "application/json", &body);
        }
    };
    match config
        .collect(&request.nonce)
        .and_then(|token| encode(&token, request.format))
    {
        Ok(body) => respond(&mut stream, 200, request.format.content_type(), &body),
        Err(error) => {
            eprintln!("[uq/attest] collection failed: {error:#}");
            respond(
                &mut stream,
                503,
                "application/json",
                b"{\"error\":\"attestation collection failed\"}",
            )
        }
    }
}

pub fn serve(args: &[String]) -> Result<()> {
    let flags = parse_flags(
        args,
        &[
            "--tls-spki",
            "--value-x",
            "--collateral",
            "--topology",
            "--boot-log",
            "--runtime-log",
            "--cpu-profile",
            "--tpm-pcrs",
            "--source-hash",
            "--artifact-hash",
            "--previous-attestation",
            "--unix",
            "--listen",
        ],
        &["--gpu"],
    )?;
    ensure!(
        flags.contains_key("--unix") ^ flags.contains_key("--listen"),
        "choose exactly one --unix path or --listen loopback-address"
    );
    let config = CollectionConfig::from_flags(&flags)?;
    if let Some(address) = flags.get("--listen") {
        let address: SocketAddr = address
            .parse()
            .context("--listen must be an IP address and port")?;
        ensure!(
            address.ip().is_loopback() && address.port() != 0,
            "--listen requires a loopback IP and a nonzero port"
        );
        let listener = TcpListener::bind(address)?;
        eprintln!("[uq/attest] listening on {address}; fresh challenge required per request");
        // One hardware collection at a time, bounded headers and absolute read
        // deadlines. Parallel callers cannot exhaust native device operations.
        for stream in listener.incoming() {
            let stream = stream?;
            if let Err(error) = handle(stream, &config) {
                eprintln!("[uq/attest] client request failed: {error:#}");
            }
        }
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        use std::os::unix::net::UnixListener;
        let path = Path::new(required(&flags, "--unix")?);
        ensure!(path.is_absolute(), "--unix requires an absolute path");
        let parent = path
            .parent()
            .context("Unix socket parent directory missing")?;
        let metadata = std::fs::symlink_metadata(parent)?;
        ensure!(
            metadata.is_dir()
                && metadata.mode() & 0o077 == 0
                && metadata.uid() == unsafe { libc::geteuid() },
            "Unix socket parent must be an owner-only directory owned by the service user"
        );
        // Never remove or replace an existing socket/file. The service manager
        // owns its private RuntimeDirectory and can clean it after shutdown.
        let listener =
            UnixListener::bind(path).with_context(|| format!("bind {}", path.display()))?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        eprintln!(
            "[uq/attest] listening on {}; fresh challenge required per request",
            path.display()
        );
        for stream in listener.incoming() {
            let stream = stream?;
            if let Err(error) = handle(stream, &config) {
                eprintln!("[uq/attest] client request failed: {error:#}");
            }
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        bail!("Unix socket service is unsupported on this platform")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn get(query: &str, headers: &str) -> Vec<u8> {
        format!("GET /v1/attest?{query} HTTP/1.1\r\nHost: localhost\r\n{headers}\r\n").into_bytes()
    }
    #[test]
    fn requests_require_unique_exact_freshness_input_and_supported_media() {
        let nonce = "ab".repeat(32);
        let good = parse_request(&get(&format!("nonce={nonce}"), "")).unwrap();
        assert_eq!(good.nonce, [0xab; 32]);
        assert_eq!(good.format, Format::Cbor);
        assert_eq!(
            parse_request(&get(&format!("nonce={nonce}&format=json"), ""))
                .unwrap()
                .format,
            Format::Json
        );
        for query in [
            "".into(),
            "nonce=ab".into(),
            format!("nonce={nonce}&nonce={nonce}"),
            format!("nonce={nonce}&unknown=1"),
            format!("nonce={nonce}&format=xml"),
        ] {
            assert!(parse_request(&get(&query, "")).is_err());
        }
        for headers in [
            "Content-Length: 1\r\n",
            "Transfer-Encoding: chunked\r\n",
            "Host: other\r\n",
            "Accept: text/html\r\n",
            "Expect: 100-continue\r\n",
        ] {
            assert!(parse_request(&get(&format!("nonce={nonce}"), headers)).is_err());
        }
    }
    #[test]
    fn collected_boot_log_must_match_the_explicit_cpu_profile() {
        use unified_quote::tee::composite::CpuCollectionProfile;
        let tpm = include_bytes!("../testdata/boot/intel-tpm2-bios.bin");
        let ccel = include_bytes!("../testdata/boot/intel-CCEL.data.bin");
        validate_collection_boot_log(
            tpm,
            &CpuCollectionProfile::AzureSnpVtpm {
                pcr_indices: vec![0, 7],
            },
        )
        .unwrap();
        validate_collection_boot_log(tpm, &CpuCollectionProfile::AwsSnpNitroTpm).unwrap();
        validate_collection_boot_log(ccel, &CpuCollectionProfile::Direct).unwrap();
        assert!(validate_collection_boot_log(tpm, &CpuCollectionProfile::Direct).is_err());
        assert!(validate_collection_boot_log(ccel, &CpuCollectionProfile::AwsSnpNitroTpm).is_err());
    }

    #[test]
    fn flag_parser_rejects_ignored_or_duplicate_inputs() {
        for flags in [
            vec!["--gpu", "--gpu"],
            vec!["--nonce"],
            vec!["--nonce", "--gpu"],
            vec!["--typo", "x"],
        ] {
            assert!(parse_flags(
                &flags.into_iter().map(String::from).collect::<Vec<_>>(),
                &["--nonce"],
                &["--gpu"]
            )
            .is_err());
        }
    }

    #[test]
    fn documented_verifier_flags_normalize_without_ambiguity() {
        let args = [
            "receipt.cbor",
            "--nonce",
            &"ab".repeat(32),
            "--tls-spki",
            "tls.der",
            "--expected-value-x",
            &"cd".repeat(48),
            "--expected-mrtd",
            &"ef".repeat(48),
            "--require-gpu-verified",
            "--gpu-policy",
            "policy.json",
            "--boot-policy",
            "boot-policy.json",
            "--uki",
            "candidate.efi",
            "--json",
        ];
        let parsed =
            parse_verifier_flags(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        assert_eq!(parsed["--in"], "receipt.cbor");
        assert_eq!(parsed["--value-x"], "cd".repeat(48));
        assert!(parsed.contains_key("--require-gpu"));
        assert_eq!(parsed["--uki"], "candidate.efi");
        for args in [
            vec!["receipt.cbor", "--in", "other.cbor"],
            vec!["--value-x", "a", "--expected-value-x", "b"],
            vec!["--require-gpu", "--require-gpu-verified"],
            vec!["receipt.cbor", "other.cbor"],
        ] {
            assert!(
                parse_verifier_flags(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                    .is_err()
            );
        }
    }
}
