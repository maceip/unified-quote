//! Boot evidence diagnostics and explicit immutable-closure tooling.

use anyhow::{bail, Context};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use unified_quote::boot::{self, closure, EventLog, ParseLimits};

const USAGE: &str =
    "uq boot inspect --kind tpm|tdx --log <file> [--algorithm sha256|sha384|sha512]\n\
uq boot collect --kind tpm|tdx --out <file> [--log <path>] [--ccel-table <path>]\n\
uq boot inspect-mounted-verity [--policy <JSON-file>] [--out <file>]\n\
uq boot closure --root <dir> --file <relative-path>... [--expected-root <96-hex>] [--out <file>]";

fn options(args: &[String], allowed: &[&str]) -> anyhow::Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    let mut args = args.iter();
    while let Some(key) = args.next() {
        if !allowed.contains(&key.as_str()) {
            bail!("unknown argument {key}; {USAGE}");
        }
        let value = args
            .next()
            .with_context(|| format!("missing value for {key}"))?;
        if value.is_empty() || value.starts_with("--") {
            bail!("missing value for {key}");
        }
        if out.insert(key.clone(), value.clone()).is_some() {
            bail!("duplicate argument {key}");
        }
    }
    Ok(out)
}

fn required<'a>(options: &'a BTreeMap<String, String>, key: &str) -> anyhow::Result<&'a str> {
    options
        .get(key)
        .map(String::as_str)
        .with_context(|| format!("{key} is required"))
}

fn read(path: &Path, max: usize) -> anyhow::Result<Vec<u8>> {
    let mut data = Vec::new();
    std::fs::File::open(path)
        .with_context(|| format!("read {}", path.display()))?
        .take((max + 1) as u64)
        .read_to_end(&mut data)?;
    if data.len() > max {
        bail!("{} exceeds byte limit", path.display());
    }
    Ok(data)
}

fn write_new(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
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

fn parse_log(kind: &str, bytes: &[u8]) -> anyhow::Result<EventLog> {
    Ok(match kind {
        "tpm" => EventLog::parse_tcg2(bytes, ParseLimits::default())?,
        "tdx" => EventLog::parse_tdx_ccel(bytes, ParseLimits::default())?,
        _ => bail!("--kind must be tpm or tdx"),
    })
}

pub fn run(args: &[String]) -> anyhow::Result<()> {
    let (command, args) = args.split_first().context(USAGE)?;
    match command.as_str() {
        "inspect" => {
            let options = options(args, &["--kind", "--log", "--algorithm"])?;
            let kind = required(&options, "--kind")?;
            let data = read(
                Path::new(required(&options, "--log")?),
                ParseLimits::default().max_log_bytes,
            )?;
            let log = parse_log(kind, &data)?;
            let algorithm = match options
                .get("--algorithm")
                .map(String::as_str)
                .unwrap_or(if kind == "tdx" { "sha384" } else { "sha256" })
            {
                "sha256" => boot::TPM_ALG_SHA256,
                "sha384" => boot::TPM_ALG_SHA384,
                "sha512" => boot::TPM_ALG_SHA512,
                _ => bail!("unsupported --algorithm"),
            };
            let replay = log.replay(algorithm)?;
            let registers: BTreeMap<_, _> = replay
                .registers
                .iter()
                .map(|(i, d)| (i.to_string(), hex::encode(d)))
                .collect();
            serde_json::to_writer_pretty(
                std::io::stdout().lock(),
                &serde_json::json!({
                    "verification_status": "unverified_diagnostic",
                    "reason": "no authenticated fresh CPU quote was supplied",
                    "kind": log.kind(), "event_count": log.events().len(),
                    "consumed_bytes": log.consumed_bytes(), "algorithm": algorithm,
                    "replayed_registers": registers, "events": log.events()
                }),
            )?;
            println!();
        }
        "collect" => {
            let options = options(args, &["--kind", "--out", "--log", "--ccel-table"])?;
            let kind = required(&options, "--kind")?;
            let default_path = match kind {
                "tpm" => boot::TPM_EVENT_LOG_PATH,
                "tdx" => boot::CCEL_DATA_PATH,
                _ => bail!("--kind must be tpm or tdx"),
            };
            if kind == "tpm" && options.contains_key("--ccel-table") {
                bail!("--ccel-table requires --kind tdx");
            }
            let data = read(
                Path::new(
                    options
                        .get("--log")
                        .map(String::as_str)
                        .unwrap_or(default_path),
                ),
                ParseLimits::default().max_log_bytes,
            )?;
            if kind == "tdx" {
                let table = read(
                    Path::new(
                        options
                            .get("--ccel-table")
                            .map(String::as_str)
                            .unwrap_or(boot::CCEL_TABLE_PATH),
                    ),
                    56,
                )?;
                let table = boot::CcelTable::parse(&table, ParseLimits::default())?;
                if (data.len() as u64) < table.log_area_minimum_length {
                    bail!("CCEL data is shorter than the ACPI minimum log area");
                }
            }
            let log = parse_log(kind, &data)?;
            let out = Path::new(required(&options, "--out")?);
            write_new(out, &data)?;
            eprintln!(
                "[uq/boot] captured {} unverified events into {}",
                log.events().len(),
                out.display()
            );
        }
        "closure" => {
            let mut regular = Vec::new();
            let mut files = Vec::new();
            let mut args = args.iter();
            while let Some(key) = args.next() {
                let value = args
                    .next()
                    .with_context(|| format!("missing value for {key}"))?;
                if key == "--file" {
                    files.push(PathBuf::from(value));
                } else {
                    regular.extend([key.clone(), value.clone()]);
                }
            }
            let options = options(&regular, &["--root", "--out", "--expected-root"])?;
            let manifest = closure::measure_closure(
                Path::new(required(&options, "--root")?),
                &files,
                closure::ClosureLimits::default(),
            )?;
            if let Some(expected) = options.get("--expected-root") {
                let mut digest = [0; 48];
                hex::decode_to_slice(expected, &mut digest)
                    .context("--expected-root must be 96 hex characters")?;
                manifest.verify_expected_root(&digest)?;
            }
            let mut bytes = serde_json::to_vec_pretty(&manifest)?;
            bytes.push(b'\n');
            if let Some(path) = options.get("--out") {
                write_new(Path::new(path), &bytes)?;
            } else {
                std::io::stdout().lock().write_all(&bytes)?;
            }
        }
        "inspect-mounted-verity" => {
            let options = options(args, &["--policy", "--out"])?;
            let observation = boot::verity::collect_mounted_verity()?;
            let policy_match = if let Some(path) = options.get("--policy") {
                let policy: boot::verity::MountedVerityPolicy =
                    serde_json::from_slice(&read(Path::new(path), 64 * 1024)?)?;
                observation.check_observed_policy(&policy)?;
                Some(true)
            } else {
                None
            };
            let mut bytes = serde_json::to_vec_pretty(&serde_json::json!({
                "verification_status": "unverified_runtime_observation",
                "admission": false,
                "observed_policy_match": policy_match,
                "observation": observation,
            }))?;
            bytes.push(b'\n');
            if let Some(path) = options.get("--out") {
                write_new(Path::new(path), &bytes)?;
            } else {
                std::io::stdout().lock().write_all(&bytes)?;
            }
        }
        _ => bail!("{USAGE}"),
    }
    Ok(())
}
