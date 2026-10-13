//! CLI for the first GPU implementation slice: raw evidence collection.

use std::io::Write;
use std::path::PathBuf;

use anyhow::{bail, Context};
use unified_quote::gpu::NvmlCollector;

const USAGE: &str = "uq gpu collect --nonce <64-hex> --out <file> [--format cbor|json]";

struct Options {
    nonce: [u8; 32],
    out: PathBuf,
    json: bool,
}

fn parse(args: &[String]) -> anyhow::Result<Options> {
    if args.first().map(String::as_str) != Some("collect") {
        bail!("Usage: {USAGE}");
    }
    let (mut nonce, mut out, mut format) = (None, None, None);
    let mut args = args[1..].iter();
    while let Some(flag) = args.next() {
        let slot = match flag.as_str() {
            "--nonce" => &mut nonce,
            "--out" => &mut out,
            "--format" => &mut format,
            _ => bail!("unknown argument {flag}; usage: {USAGE}"),
        };
        if slot.is_some() {
            bail!("duplicate argument {flag}");
        }
        *slot = Some(
            args.next()
                .with_context(|| format!("missing value for {flag}"))?
                .as_str(),
        );
    }
    let nonce = nonce.context("--nonce <64-hex> is required; use a verifier-supplied challenge")?;
    if nonce.len() != 64 {
        bail!("--nonce must be exactly 64 hexadecimal characters");
    }
    let mut nonce_bytes = [0u8; 32];
    hex::decode_to_slice(nonce, &mut nonce_bytes).context("--nonce is not hexadecimal")?;
    let out = out
        .filter(|s| !s.is_empty())
        .context("--out <file> is required")?;
    let json = match format.unwrap_or("cbor") {
        "cbor" => false,
        "json" => true,
        value => bail!("unsupported format {value}; use cbor or json"),
    };
    Ok(Options {
        nonce: nonce_bytes,
        out: out.into(),
        json,
    })
}

pub fn run(args: &[String]) -> anyhow::Result<()> {
    let options = parse(args)?;
    let evidence = NvmlCollector::open()?.collect(options.nonce)?;
    let mut bytes = Vec::new();
    if options.json {
        serde_json::to_writer_pretty(&mut bytes, &evidence)?;
        bytes.push(b'\n');
    } else {
        ciborium::into_writer(&evidence, &mut bytes)?;
    }
    // Never truncate an existing receipt. A successful exit means a complete
    // evidence file was written; failures never print a verification verdict.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&options.out)
        .with_context(|| format!("create {}", options.out.display()))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    eprintln!(
        "[uq/gpu] collected unverified evidence from {} GPU(s): {}",
        evidence.gpus.len(),
        options.out.display()
    );
    eprintln!("[uq/gpu] certificate trust, revocation, RIM, fabric, and CPU binding have not been verified");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(tail: &[&str]) -> Vec<String> {
        [
            "collect",
            "--nonce",
            &"ab".repeat(32),
            "--out",
            "evidence.cbor",
        ]
        .into_iter()
        .chain(tail.iter().copied())
        .map(str::to_owned)
        .collect()
    }

    #[test]
    fn nonce_is_required_and_exactly_32_bytes() {
        assert!(parse(&["collect".into()]).is_err());
        for bad in ["", "ab", &"00".repeat(33), &"zz".repeat(32)] {
            let mut a = args(&[]);
            a[2] = bad.into();
            assert!(parse(&a).is_err());
        }
        assert_eq!(parse(&args(&[])).unwrap().nonce, [0xab; 32]);
    }

    #[test]
    fn unknown_duplicate_and_missing_options_fail() {
        for tail in [
            vec!["--json"],
            vec!["--format"],
            vec!["--format", "jwt"],
            vec!["--nonce", "00"],
            vec!["--out", "other"],
        ] {
            assert!(parse(&args(&tail)).is_err(), "{tail:?}");
        }
        assert!(!parse(&args(&[])).unwrap().json);
        assert!(parse(&args(&["--format", "json"])).unwrap().json);
    }
}
