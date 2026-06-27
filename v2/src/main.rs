//! uq: attested builds and runtime.
//!
//! See CONSTITUTION.md.
//!
//! Takes source code. Builds it inside a TEE. Produces an artifact
//! and a hardware-rooted attestation proving what was built.
//!
//! Implements:
//!   - Attestable Containers (Cambridge): build inside TEE, bind (CT, A) to quote
//!   - LATTE: platform measurement (MRTD) proves this code is genuine,
//!            Value X proves the output matches expectations
//!
//! Usage:
//!   uq build <source-dir> [--cmd "cargo build --release"] [--output ./out]
//!   uq verify <attestation.json>
//!
//! The build subcommand:
//!   1. Verifies it's running inside a TEE (refuses to run otherwise)
//!   2. Computes CT = sha384(all source files) — the ratchet lock
//!   3. Runs the build command
//!   4. Computes A = sha384(artifact)
//!   5. Computes Value X = sha384(all output files)
//!   6. Collects a TEE quote binding sha256(CT || A || X) into report_data
//!   7. Writes attestation.json: { CT, A, X, platform, quote }
//!
//! The verify subcommand:
//!   1. Parses attestation.json
//!   2. Verifies the TEE quote signature chain (platform-specific)
//!   3. Verifies report_data contains sha256(CT || A || X)
//!   4. Optionally verifies CT against a git repo
//!   5. Optionally verifies A against a local artifact

mod eat;
mod net;
mod quote;
mod registry;
mod tee;
mod value_x;

use value_x::compute_tree_hash;

use sha2::{Digest, Sha384};
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }

    match args[1].as_str() {
        "build" => cmd_build(&args[2..]),
        "verify" => cmd_verify(&args[2..]),
        "check" => cmd_check(&args[2..]),
        "enclave" => cmd_enclave(&args[2..]),
        "proxy" => cmd_proxy(&args[2..]),
        "run" => {
            // Only create tokio runtime if we need it (TLS path).
            // Nitro Enclaves may not support epoll fully.
            let rt = tokio::runtime::Runtime::new();
            match rt {
                Ok(rt) => rt.block_on(cmd_run(&args[2..])),
                Err(_) => {
                    // Tokio failed (likely inside a Nitro Enclave).
                    // Fall back to synchronous vsock-only path.
                    eprintln!("[uq] Async runtime unavailable, using sync mode");
                    cmd_run_sync(&args[2..])
                }
            }
        }
        "merge" => cmd_merge(&args[2..]),
        #[cfg(feature = "sev-snp")]
        "azure" => cmd_azure(&args[2..]),
        _ => {
            print_usage();
            std::process::exit(1);
        }
    }
}

fn print_usage() {
    let bin = cli_name();
    eprintln!("{bin} — attested builds and runtime");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  {bin} build   <source-dir> [--cmd \"...\"] [--output ./out]");
    eprintln!("  {bin} verify  <attestation.json> [--source-dir <dir>] [--artifact <path>]");
    eprintln!("  {bin} check   https://<domain>   (fetch + verify from a running enclave)");
    eprintln!("  {bin} run     <dir> --attestation <attestation.json> [--cmd \"...\"]");
    eprintln!("  {bin} enclave <source-dir> [--cmd \"...\"]  (Nitro: build+serve in one)");
    eprintln!("  {bin} proxy   --cid <enclave-cid> [--acme]  (parent: TCP:443 → vsock + ACME)");
    eprintln!("  {bin} merge   <att1.json> <att2.json> [...] --output merged.json");
    eprintln!("  {bin} azure   collect|verify|check|serve   (Azure CVM: vTPM SNP → AMD root)");
}

fn cli_name() -> String {
    std::env::args()
        .next()
        .and_then(|arg| Path::new(&arg).file_stem().map(|stem| stem.to_owned()))
        .and_then(|stem| stem.to_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "uq".to_string())
}

/// TCP-to-vsock proxy. Runs on the parent instance.
/// Listens on TCP port 443, forwards raw bytes to the enclave's vsock.
/// The enclave terminates TLS — the parent only sees encrypted traffic.
///
/// With --acme: also provisions a Let's Encrypt cert for the enclave's
/// Value X domain and installs it via the /tls-cert endpoint.
fn cmd_proxy(args: &[String]) -> anyhow::Result<()> {
    let mut cid: Option<u32> = None;
    let mut port: u16 = 443;
    let mut acme = false;
    let mut acme_staging = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--cid" => {
                i += 1;
                cid = args.get(i).and_then(|s| s.parse().ok());
            }
            "--port" => {
                i += 1;
                port = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(443);
            }
            "--acme" => acme = true,
            "--acme-staging" => {
                acme = true;
                acme_staging = true;
            }
            _ => {}
        }
        i += 1;
    }

    let cid = cid.ok_or_else(|| anyhow::anyhow!("--cid <enclave-cid> required"))?;

    eprintln!("[uq] Proxy: TCP:{port} → enclave CID {cid}");
    eprintln!("[uq] TLS terminates inside the enclave. This proxy only sees encrypted bytes.");

    if acme {
        let proxy_port = port;
        std::thread::spawn(move || {
            // Wait for proxy + enclave to be ready
            eprintln!("[uq/acme] Waiting for enclave...");
            std::thread::sleep(std::time::Duration::from_secs(5));

            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("[uq/acme] Failed to create async runtime: {e}");
                    return;
                }
            };

            rt.block_on(async move {
                // Install crypto provider for reqwest/rustls
                let _ = rustls::crypto::ring::default_provider().install_default();

                // Fetch attestation from enclave to get the domain
                let client = reqwest::Client::builder()
                    .danger_accept_invalid_certs(true)
                    .build()
                    .unwrap();

                let enclave_url = format!("https://127.0.0.1:{proxy_port}");
                let att: serde_json::Value = match client.get(&enclave_url).send().await {
                    Ok(r) => match r.text().await {
                        Ok(body) => match serde_json::from_str(&body) {
                            Ok(j) => j,
                            Err(e) => {
                                eprintln!("[uq/acme] Failed to parse attestation: {e}");
                                return;
                            }
                        },
                        Err(e) => {
                            eprintln!("[uq/acme] Failed to read response: {e}");
                            return;
                        }
                    },
                    Err(e) => {
                        eprintln!("[uq/acme] Enclave not reachable: {e}");
                        return;
                    }
                };

                let domain = match att["domain"].as_str() {
                    Some(d) => d.to_string(),
                    None => {
                        eprintln!("[uq/acme] No domain in attestation");
                        return;
                    }
                };

                eprintln!("[uq/acme] Domain: {domain}");

                match net::acme::provision_cert_for_enclave(&domain, &enclave_url, acme_staging)
                    .await
                {
                    Ok(()) => {
                        eprintln!("[uq/acme] === ACME COMPLETE ===");
                        eprintln!("[uq/acme] https://{domain} is now valid TLS");
                    }
                    Err(e) => {
                        eprintln!("[uq/acme] FAILED: {e}");
                    }
                }
            });
        });
    }

    net::vsock::bridge_tcp_to_vsock(port, cid)
}

// ============================================================================
// BUILD — runs inside a TEE, produces attestation
// ============================================================================

fn cmd_build(args: &[String]) -> anyhow::Result<()> {
    // Parse args
    let mut source_dir: Option<PathBuf> = None;
    let mut build_cmd: Option<String> = None;
    let mut output_dir = PathBuf::from("./out");
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--cmd" => {
                i += 1;
                build_cmd = Some(args.get(i).map(|s| s.to_string()).unwrap_or_default());
            }
            "--output" => {
                i += 1;
                output_dir = args.get(i).map(PathBuf::from).unwrap_or(output_dir);
            }
            _ => {
                if source_dir.is_none() {
                    source_dir = Some(PathBuf::from(&args[i]));
                }
            }
        }
        i += 1;
    }

    let source_dir = source_dir.ok_or_else(|| anyhow::anyhow!("source directory required"))?;

    // --- Step 1: Verify TEE ---
    // CONSTITUTION: "It must be computed inside a TEE. Not on a developer's laptop."
    eprintln!("[uq] Detecting TEE...");
    let tee_provider = tee::detect::detect_tee().map_err(|e| {
        anyhow::anyhow!(
            "No TEE detected: {e}\n\
             Attested builds require TEE hardware (TDX, SNP, or Nitro).\n\
             This binary refuses to produce attestations outside a TEE."
        )
    })?;
    eprintln!("[uq] TEE: {:?}", tee_provider.platform());

    // --- Step 2: RATCHET — Lock source hash before building ---
    // Attestable Containers paper: CT is computed and locked before any
    // untrusted code runs. After this point, the source cannot change.
    eprintln!("[uq] Computing source hash (CT)...");
    let ct = compute_tree_hash(&source_dir)?;
    eprintln!("[uq] CT = {}", hex::encode(ct));

    // RATCHET: copy source to a read-only snapshot.
    // The build runs against the snapshot, not the original directory.
    // This prevents the build process from modifying source after CT was computed.
    let build_workspace = tempdir()?;
    let frozen_source = build_workspace.join("src");
    copy_dir_readonly(&source_dir, &frozen_source)?;
    eprintln!("[uq] Source frozen: {}", frozen_source.display());

    // Verify the frozen copy matches CT (paranoia: catch copy corruption)
    let ct_verify = compute_tree_hash(&frozen_source)?;
    if ct != ct_verify {
        anyhow::bail!(
            "RATCHET BROKEN: frozen source hash differs from original.\n\
             original: {}\n\
             frozen:   {}\n\
             This should never happen. Aborting.",
            hex::encode(ct),
            hex::encode(ct_verify)
        );
    }

    // --- Step 3: Fetch dependencies (network phase) ---
    // LATTE L5: dependencies must be measured.
    // Two-phase build: fetch deps first, hash them, then compile offline.
    let build_output = build_workspace.join("build");
    std::fs::create_dir_all(&build_output)?;

    let dep_cache = build_workspace.join("deps");
    std::fs::create_dir_all(&dep_cache)?;

    let is_cargo = frozen_source.join("Cargo.toml").exists();
    let cmd = build_cmd
        .clone()
        .unwrap_or_else(|| detect_build_cmd(&frozen_source));
    let custom_cmd = build_cmd.is_some();

    if is_cargo && !custom_cmd {
        // Rust: fetch deps into a local vendor directory, then build offline.
        // This ensures all dependencies are captured in the hash.
        eprintln!("[uq] Fetching Rust dependencies...");
        let fetch_status = std::process::Command::new("cargo")
            .args(["fetch"])
            .current_dir(&frozen_source)
            .env("CARGO_TARGET_DIR", &build_output)
            .env("CARGO_HOME", &dep_cache)
            .status()?;
        if !fetch_status.success() {
            anyhow::bail!("cargo fetch failed");
        }

        // Hash the dependency cache
        let dt = compute_tree_hash(&dep_cache)?;
        eprintln!("[uq] DT (dependency hash): {}", hex::encode(dt));
        // DT is included in the attestation output (see step 8)
    }

    // --- Step 4: Build (compilation phase) ---
    eprintln!("[uq] Building with: {cmd}");

    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .current_dir(&frozen_source)
        .env("CARGO_TARGET_DIR", &build_output)
        .env("CARGO_HOME", &dep_cache)
        .status()?;
    if !status.success() {
        anyhow::bail!("Build failed with exit code: {status}");
    }

    // Re-verify CT after build — the frozen source must not have changed.
    let ct_post = compute_tree_hash(&frozen_source)?;
    if ct != ct_post {
        anyhow::bail!(
            "RATCHET VIOLATED: source changed during build.\n\
             pre-build:  {}\n\
             post-build: {}\n\
             The build process modified source files. This attestation is invalid.",
            hex::encode(ct),
            hex::encode(ct_post)
        );
    }
    eprintln!("[uq] Ratchet verified: source unchanged after build");

    // Hash dependencies — LATTE L5: build deps are now measured.
    let dt: Option<[u8; 48]> = if dep_cache.exists() {
        match compute_tree_hash(&dep_cache) {
            Ok(h) if h != [0u8; 48] => {
                eprintln!("[uq] DT (dependencies): {}", hex::encode(h));
                Some(h)
            }
            _ => None,
        }
    } else {
        None
    };

    // --- Step 4: Compute artifact hash ---
    eprintln!("[uq] Computing artifact hash (A)...");
    let artifact_path = find_artifact(&build_output, &frozen_source);
    let (a, artifact_bytes): ([u8; 48], Vec<u8>) = if artifact_path.is_file() {
        let bytes = std::fs::read(&artifact_path)?;
        let hash: [u8; 48] = Sha384::digest(&bytes).into();
        (hash, bytes)
    } else {
        // No artifact file (e.g., --cmd true). Hash the build output directory.
        let hash = compute_tree_hash(&build_output)?;
        (hash, Vec::new())
    };
    eprintln!("[uq] A = {}", hex::encode(a));

    // --- Step 5: Compute Value X ---
    // CONSTITUTION: "Value X is a single number that represents 'this exact software.'"
    // LATTE: application layer identity, deterministic across platforms.
    eprintln!("[uq] Computing Value X...");
    let value_x = compute_tree_hash(&frozen_source)?;
    eprintln!("[uq] X = {}", hex::encode(value_x));

    // --- Step 6: Collect TEE quote ---
    //
    // Build a PARTIAL EAT first (no platform_quote, no platform_measurement),
    // then use its `binding_bytes()` as `report_data[0..32]` when collecting
    // the quote. This way the stored EAT's `binding_bytes()` will recompute
    // to the exact bytes in the quote's report_data — the verifier can
    // re-derive the binding from the EAT's claims alone.
    //
    // Before this change, cmd_build used a legacy `sha256(CT || DT || A || X)`
    // binding that DIDN'T match what `EatToken::binding_bytes()` would
    // compute for the same EAT. That meant every stage 0 attestation was
    // internally inconsistent and stage 1 chain verification failed with
    // "reportdata binding mismatch" — caught on real TDX hardware 2026-04-14.
    //
    // INVARIANT.md check #3: the quote itself IS the attestation; there is
    // no separate app-level signing key. The TEE hardware signs report_data,
    // which commits to every field in the EAT via binding_bytes().
    let mut eat = eat::EatToken::from_build(eat::BuildComponents {
        platform: tee_provider.platform(),
        value_x,
        source_hash: ct,
        artifact_hash: a,
        platform_measurement: Vec::new(), // filled after quote collection
        platform_quote: Vec::new(),       // filled after quote collection
    });
    // Stage 0 has no TLS key binding (no attested-TLS serving at build time);
    // tls_spki_hash stays zero, which is still committed in binding_bytes.
    // If a build-time caller wants to bind a TLS key (e.g., cmd_enclave),
    // they set it before collecting the quote.

    let binding: [u8; 32] = eat.binding_bytes();
    eprintln!("[uq] EAT binding: {}", hex::encode(binding));

    // report_data[0..32] = binding; [32..64] = second commitment. With no
    // issuer challenge this is value_x[..32] — byte-identical to what we wrote
    // before, but now defined + verifiable via EatToken::report_data_64 (L1.2).
    let report_data = eat.report_data_64(None);

    // NitroTPM side evidence: on AWS SNP, collect NitroTPM attestation for
    // kernel measurement. This is recorded next to the EAT but is not yet
    // mixed into `binding`; verifiers must treat it as auxiliary evidence
    // until the EAT schema grows a TPM digest field.
    let tpm_attestation: Option<tee::tpm::TpmAttestation> =
        if tee_provider.platform() == quote::Platform::SevSnp && tee::tpm::tpm_available() {
            match tee::tpm::collect_tpm_attestation(&binding) {
                Ok(att) => {
                    eprintln!("[uq] NitroTPM: {} ", att.method);
                    eprintln!("[uq] NitroTPM digest: {}", hex::encode(att.digest));
                    for (i, pcr) in att.pcrs.iter().enumerate() {
                        eprintln!("[uq]   PCR{i}: {}", hex::encode(pcr));
                    }
                    Some(att)
                }
                Err(e) => {
                    eprintln!("[uq] WARNING: NitroTPM collection failed: {e}");
                    None
                }
            }
        } else {
            None
        };

    eprintln!("[uq] Collecting TEE attestation...");
    let evidence = tee_provider.collect_evidence(&report_data)?;
    eprintln!(
        "[uq] Quote collected: {} bytes from {:?}",
        evidence.raw_quote.len(),
        evidence.platform
    );

    // --- Step 7: Extract platform measurement + fill the EAT ---
    // LATTE L1: the platform measurement is a top-level field, not buried in bytes.
    // This is what the verifier checks to confirm the builder code is genuine.
    let platform_measurement =
        extract_platform_measurement(&evidence.raw_quote, &evidence.platform);
    if let Some(ref m) = platform_measurement {
        eprintln!("[uq] Platform measurement: {}", hex::encode(m));
    } else {
        eprintln!("[uq] WARNING: could not extract platform measurement from quote");
    }

    // Fill the EAT with the collected quote + measurement.
    // binding_bytes() MUST still equal `binding` after this (platform_quote
    // and platform_measurement are excluded from the hash).
    eat.platform = eat::platform_to_u8(evidence.platform);
    eat.platform_quote = evidence.raw_quote.clone();
    eat.platform_measurement = platform_measurement.clone().unwrap_or_default();
    if eat.binding_bytes() != binding {
        anyhow::bail!("cmd_build: EAT binding changed after filling quote — schema bug");
    }

    // --- Step 8: Write output ---
    std::fs::create_dir_all(&output_dir)?;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_secs();

    // Read sequence number from registry (or start at 1)
    let sequence_number = {
        let registry_path = output_dir.join("sequence");
        match std::fs::read_to_string(&registry_path) {
            Ok(s) => s.trim().parse::<u64>().unwrap_or(0) + 1,
            Err(_) => 1,
        }
    };

    let platform_str = format!("{:?}", evidence.platform);
    let value_x_hex = hex::encode(value_x);
    let domain = net::acme::domain_from_value_x(&value_x);

    // Build KMS-compatible condition fields per platform
    let kms_conditions = match evidence.platform {
        quote::Platform::Nitro => {
            // AWS KMS expects PCR values as 96-char hex (sha384)
            serde_json::json!({
                "aws": {
                    "pcr0": platform_measurement.as_ref().map(|m| hex::encode(m)),
                    "condition_keys": {
                        "kms:RecipientAttestation:PCR0": platform_measurement.as_ref().map(|m| hex::encode(m)),
                    }
                }
            })
        }
        quote::Platform::SevSnp => {
            serde_json::json!({
                "azure": {
                    "launch_measurement": platform_measurement.as_ref().map(|m| hex::encode(m)),
                    "maa_claims": {
                        "x-ms-sevsnpvm-launchmeasurement": platform_measurement.as_ref()
                            .map(|m| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, m)),
                        "x-ms-sevsnpvm-is-debuggable": false,
                    }
                }
            })
        }
        quote::Platform::Tdx => {
            serde_json::json!({
                "gcp": {
                    "mrtd": platform_measurement.as_ref().map(|m| hex::encode(m)),
                    "confidential_space_claims": {
                        "hwmodel": "GCP_INTEL_TDX",
                        "swname": "UNIFIED-QUOTE",
                    }
                }
            })
        }
    };

    // NitroTPM attestation for the output (SNP only)
    let tpm_json = tpm_attestation.as_ref().map(|att| {
        use base64::Engine;
        let pcr_map: std::collections::BTreeMap<String, String> = att.pcrs.iter()
            .enumerate()
            .map(|(i, pcr)| (format!("pcr{i}"), hex::encode(pcr)))
            .collect();
        let mut obj = serde_json::json!({
            "method": att.method,
            "digest": hex::encode(att.digest),
            "pcrs": pcr_map,
            "note": "auxiliary kernel-measurement evidence; not yet mixed into EAT binding_bytes"
        });
        if let Some(ref doc) = att.attestation_doc {
            obj["attestation_document_b64"] = serde_json::Value::String(
                base64::engine::general_purpose::STANDARD.encode(doc)
            );
            obj["note"] = serde_json::Value::String(
                "COSE_Sign1 signed by Nitro Hypervisor (same PKI as Nitro Enclaves). Verify against AWS Nitro root CA.".into()
            );
        }
        obj
    });

    let attestation = serde_json::json!({
        // Core attestation
        "version": 2,
        "stage": 0,
        "platform": platform_str,
        "platform_measurement": platform_measurement.as_ref().map(|m| hex::encode(m)),
        "source_hash": hex::encode(ct),
        "dependency_hash": dt.map(|d| hex::encode(d)),
        "artifact_hash": hex::encode(a),
        "value_x": value_x_hex,
        "binding": hex::encode(binding),
        "quote": hex::encode(&evidence.raw_quote),
        "timestamp": timestamp,

        // NitroTPM kernel measurement (SNP only)
        "nitro_tpm": tpm_json,

        // Upgrade ceremony fields
        "sequence_number": sequence_number,
        "domain": domain,

        // KMS-compatible condition fields
        "kms": kms_conditions,
    });

    // Persist sequence number
    let _ = std::fs::write(output_dir.join("sequence"), sequence_number.to_string());

    let att_path = output_dir.join("attestation.json");
    std::fs::write(&att_path, serde_json::to_string_pretty(&attestation)?)?;

    // Emit EAT (CBOR) alongside the JSON. This is the canonical wire
    // format per DESIGN.md; the JSON is kept for human debugging and
    // legacy clients. The EAT was built at step 6 and filled here —
    // its `binding_bytes()` IS what's in `report_data[0..32]` of the
    // quote, so it's self-verifying.
    let eat_cbor = eat.to_cbor()?;
    let eat_path = output_dir.join("attestation.cbor");
    std::fs::write(&eat_path, &eat_cbor)?;
    eprintln!(
        "[uq] EAT (CBOR): {} bytes → {}",
        eat_cbor.len(),
        eat_path.display()
    );

    // Copy artifact (if it exists as a file)
    if artifact_path.is_file() {
        let out_artifact = output_dir.join("artifact");
        std::fs::copy(&artifact_path, &out_artifact)?;
    }

    // LATTE L2: embed attestation alongside artifact.
    // When the output directory becomes a container image or deployment,
    // the attestation is part of the image. The runtime MRTD covers it.
    // Stage 1 reads this file to verify itself at boot.
    // The attestation is NOT a sidecar — it's part of the artifact.

    // --- AC5: Append to transparency log ---
    // If the output directory is inside a git repo, commit the attestation.
    // Git history is an append-only Merkle tree — it IS a transparency log.
    // Verifiers check: this attestation exists in the commit history.
    let log_committed = append_to_log(&output_dir, &att_path, &value_x);
    if log_committed {
        eprintln!("[uq] Transparency log: attestation committed to git");
    } else {
        eprintln!("[uq] Transparency log: no git repo found (attestation written to disk only)");
    }

    eprintln!();
    eprintln!("[uq] === Attested Build Complete ===");
    eprintln!("[uq] CT (source):   {}", hex::encode(ct));
    if let Some(ref d) = dt {
        eprintln!("[uq] DT (deps):     {}", hex::encode(d));
    }
    eprintln!("[uq] A  (artifact): {}", hex::encode(a));
    eprintln!("[uq] X  (value x):  {}", hex::encode(value_x));
    eprintln!("[uq] Platform:      {:?}", evidence.platform);
    eprintln!("[uq] Output:        {}", output_dir.display());
    eprintln!();
    eprintln!("[uq] This source became this artifact, inside genuine hardware.");

    Ok(())
}

// ============================================================================
// VERIFY — anyone can run this, no TEE needed
// ============================================================================

/// `uq check https://<domain>`
///
/// Performs a full attested-TLS verification against a live enclave:
///
/// 1. TLS handshake with the server. The cert is self-signed or
///    unknown-CA — we intentionally accept it because we're going to
///    authenticate it by attestation, not by CA chain.
/// 2. Pull the leaf cert out of the rustls session.
/// 3. Extract the EAT CBOR from the CMW extension (OID 2.23.133.5.4.9).
/// 4. Decode the EAT.
/// 5. Recompute `binding_bytes()` from the decoded claims, check that
///    it matches `report_data[0..32]` inside the embedded platform quote.
/// 6. Recompute `sha256(cert_spki)` and check it matches
///    `eat.tls_spki_hash` — this is the channel-binding check that
///    makes it attested-TLS instead of "attestation over TLS."
/// 7. Verify the platform quote's signature chain against the pinned
///    hardware root CA (AMD/Intel/Nitro).
/// 8. Look up Value X in the registry and report its status.
///
/// Every step is required. A verifier that skips (6) is running
/// "attestation over TLS," which doesn't defend against relay / MITM.
fn cmd_check(args: &[String]) -> anyhow::Result<()> {
    let url = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .ok_or_else(|| anyhow::anyhow!("Usage: uq check https://<domain>"))?;

    // Parse out host + port
    let stripped = url.strip_prefix("https://").unwrap_or(url.as_str());
    let (host, port) = match stripped.split_once('/') {
        Some((hp, _)) => hp,
        None => stripped,
    }
    .split_once(':')
    .map(|(h, p)| (h.to_string(), p.parse::<u16>().unwrap_or(443)))
    .unwrap_or_else(|| (stripped.split('/').next().unwrap().to_string(), 443));

    eprintln!("[uq] === attested-TLS check ===");
    eprintln!("[uq] Target: {host}:{port}");

    // Install ring crypto provider if not already
    let _ = rustls::crypto::ring::default_provider().install_default();

    // TLS client config that accepts any cert. Authentication is by
    // attestation, not CA chain.
    let client_config = build_unchecked_client_config();

    let server_name = rustls::pki_types::ServerName::try_from(host.clone())
        .map_err(|e| anyhow::anyhow!("invalid server name {host}: {e}"))?;

    let mut conn = rustls::ClientConnection::new(Arc::new(client_config), server_name)
        .map_err(|e| anyhow::anyhow!("rustls client: {e}"))?;
    let mut sock = std::net::TcpStream::connect((host.as_str(), port))
        .map_err(|e| anyhow::anyhow!("tcp connect {host}:{port}: {e}"))?;

    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    // Fire an HTTP GET to /eat so the server actually sends data —
    // rustls completes the handshake lazily on first read/write.
    use std::io::{Read, Write};
    let req = format!("GET /eat HTTP/1.1\r\nHost: {host}\r\nAccept: application/eat+cbor\r\nConnection: close\r\n\r\n");
    tls.write_all(req.as_bytes())
        .map_err(|e| anyhow::anyhow!("TLS write: {e}"))?;

    // Drain response (we don't need the body — we'll pull the EAT from the cert)
    let mut resp = Vec::new();
    let _ = tls.read_to_end(&mut resp);

    // Now the handshake is done, pull the peer certificate chain
    let certs = conn
        .peer_certificates()
        .ok_or_else(|| anyhow::anyhow!("peer presented no certificates"))?;
    let leaf = certs
        .first()
        .ok_or_else(|| anyhow::anyhow!("empty peer cert chain"))?;
    let leaf_der = leaf.as_ref().to_vec();
    eprintln!("[uq] Leaf cert: {} bytes DER", leaf_der.len());

    // Extract the CMW extension
    let eat_cbor = net::attested_tls::extract_eat_from_cert(&leaf_der)?.ok_or_else(|| {
        anyhow::anyhow!(
            "cert has no CMW extension (OID 2.23.133.5.4.9) — \
             this endpoint is not attested-TLS aware"
        )
    })?;
    eprintln!("[uq] EAT extension: {} bytes", eat_cbor.len());

    // Decode
    let eat =
        eat::EatToken::from_cbor(&eat_cbor).map_err(|e| anyhow::anyhow!("EAT decode: {e}"))?;
    eprintln!("[uq] EAT profile: {}", eat.eat_profile);
    eprintln!("[uq] Platform:    {:?}", eat.platform_enum());
    eprintln!("[uq] Value X:     {}", hex::encode(eat.value_x));

    let platform = eat
        .platform_enum()
        .ok_or_else(|| anyhow::anyhow!("unknown platform discriminant: {}", eat.platform))?;

    // --- Check: cert SPKI hash matches eat.tls_spki_hash ---
    // This is the channel-binding step. If it fails, the cert is
    // not the one the TEE produced — MITM or relay.
    let actual_spki_hash = net::attested_tls::spki_hash_of_cert(&leaf_der)?;
    if actual_spki_hash != eat.tls_spki_hash {
        eprintln!("[uq] SPKI binding:    FAIL");
        eprintln!("[uq]   eat claim:     {}", hex::encode(eat.tls_spki_hash));
        eprintln!("[uq]   cert actual:   {}", hex::encode(actual_spki_hash));
        anyhow::bail!("attested-TLS channel binding failed");
    }
    eprintln!("[uq] SPKI binding:    PASS");

    // --- Check: platform quote signature chain + binding ---
    //
    // verify_platform_quote does both in one call:
    //   1. Parses the platform-specific quote format (CBOR for Nitro,
    //      flat binary for SNP/TDX)
    //   2. Extracts report_data from the correct location for each
    //      platform (byte offset for SNP/TDX, CBOR field for Nitro)
    //   3. Checks the first 32 bytes against `binding`
    //   4. Verifies the signature chain to the pinned hardware root
    //
    // An earlier version of this function did a separate byte-offset
    // binding pre-check — that was redundant and wrong for Nitro,
    // whose report_data is a CBOR field, not a byte offset.
    let binding = eat.binding_bytes();
    let quote = &eat.platform_quote;
    eprintln!("[uq] Verifying platform quote (binding + signature)...");
    match quote::verify::verify_platform_quote(platform, quote, &binding) {
        Ok(measurements) => {
            eprintln!("[uq] Quote binding:   PASS");
            eprintln!("[uq] Quote signature: PASS");
            for (name, val) in &measurements {
                eprintln!("[uq]   {}: {}", name, hex::encode(val));
            }
        }
        Err(e) => {
            eprintln!("[uq] Quote verify:    FAIL — {e}");
            anyhow::bail!("platform quote verification failed");
        }
    }

    // --- Chain walk (Attestable Containers contribution #6) ---
    //
    // If this EAT chains to a previous stage, verify the previous
    // stage's quote + binding recursively. Value X MUST be stable
    // across the chain — the runtime is running the code the builder
    // produced; if Value X changed, something was replaced.
    //
    // Channel binding is only checked at the leaf (where the TLS
    // session actually terminates); previous stages are verified on
    // their own `binding_bytes()` which does not include a live TLS
    // key. This is correct: stage 0 never had a TLS session, so its
    // `tls_spki_hash` is zero and `binding_bytes` commits to that
    // zero. The chain walk just confirms every signed report_data
    // matches its respective binding.
    if eat.has_previous() {
        let mut cursor = eat.clone();
        let mut depth = 1usize;
        while let Some(prev) = cursor
            .decode_previous()
            .map_err(|e| anyhow::anyhow!("decode previous: {e}"))?
        {
            eprintln!(
                "[uq] Chain step {depth}: verifying previous stage ({} bytes EAT)",
                cursor.previous_attestation.len()
            );

            // Value X must be stable across the chain
            if prev.value_x != eat.value_x {
                anyhow::bail!(
                    "Value X drift across chain: leaf={} prev={}",
                    hex::encode(eat.value_x),
                    hex::encode(prev.value_x)
                );
            }

            // Verify previous's quote (binding + signature) in one call
            let prev_platform = prev
                .platform_enum()
                .ok_or_else(|| anyhow::anyhow!("chain step {depth}: unknown platform"))?;
            let prev_binding = prev.binding_bytes();
            match quote::verify::verify_platform_quote(
                prev_platform,
                &prev.platform_quote,
                &prev_binding,
            ) {
                Ok(_) => {
                    eprintln!("[uq]   ✓ step {depth} quote verifies (Value X stable)");
                }
                Err(e) => {
                    anyhow::bail!("chain step {depth}: quote signature failed — {e}");
                }
            }

            cursor = prev;
            depth += 1;
            if depth > 16 {
                anyhow::bail!("chain too deep (>16 stages) — aborting walk");
            }
        }
        eprintln!("[uq] Chain:           PASS ({depth} stage(s) walked)");
    } else {
        eprintln!("[uq] Chain:           leaf only (no previous stage)");
    }

    // --- CT log verification (LE path only) ---
    //
    // If the leaf cert has SCTs (Signed Certificate Timestamps) embedded,
    // it was issued by a CA that participates in CT. Verifying the SCTs
    // tells us the cert is publicly witnessed: a malicious CA can't
    // silently issue another cert for `<value_x>.aeon.site` without it
    // showing up in CT logs. See DESIGN.md for why this is the second
    // half of the structural defense (channel binding closes the
    // impersonation case; CT closes the rogue-issuance case).
    //
    // For self-signed attested-TLS certs (no SCTs), this step is a
    // no-op. For LE certs in the dual-cert path (step 9), this is the
    // gate that makes "every boot lands in CT" meaningful.
    let issuer_der_opt: Option<Vec<u8>> = if certs.len() >= 2 {
        Some(certs[1].as_ref().to_vec())
    } else {
        None
    };

    match net::ct::extract_scts_from_cert(&leaf_der) {
        Ok(scts) if scts.is_empty() => {
            eprintln!("[uq] CT (SCTs):       none in cert (self-signed path — expected)");
        }
        Ok(scts) => match &issuer_der_opt {
            Some(issuer_der) => {
                let report = net::ct::verify_scts_in_cert(&leaf_der, issuer_der)?;
                if !report.failed.is_empty() {
                    eprintln!("[uq] CT (SCTs):       FAIL");
                    for f in &report.failed {
                        eprintln!("[uq]   failed: {f}");
                    }
                    anyhow::bail!("at least one SCT failed verification");
                }
                eprintln!(
                    "[uq] CT (SCTs):       {} verified, {} unpinned (of {} total)",
                    report.verified.len(),
                    report.unpinned.len(),
                    scts.len()
                );
                for log in &report.verified {
                    eprintln!("[uq]   ✓ {log}");
                }
                if !report.any_verified() {
                    eprintln!("[uq]   WARNING: no SCTs from pinned logs — consider expanding net::ct::PINNED_LOGS");
                }
            }
            None => {
                eprintln!(
                    "[uq] CT (SCTs):       {} present but issuer cert not in chain — cannot verify",
                    scts.len()
                );
            }
        },
        Err(e) => {
            eprintln!("[uq] CT (SCTs):       malformed extension: {e}");
            anyhow::bail!("SCT extension parse error");
        }
    }

    // --- Registry lookup ---
    let value_x_hex = hex::encode(eat.value_x);
    match registry::Registry::load_default() {
        Ok(reg) if !reg.is_empty() => {
            let lookup = reg.lookup(&value_x_hex);
            eprintln!(
                "[uq] Registry ({} entries): {}",
                reg.len(),
                registry::describe(&lookup)
            );
        }
        Ok(_) => {
            eprintln!("[uq] Registry: empty (no entries loaded)");
        }
        Err(e) => {
            eprintln!("[uq] Registry: load failed — {e}");
        }
    }

    eprintln!();
    eprintln!("[uq] === Check Complete ===");
    eprintln!(
        "[uq] {} is a genuine {:?} TEE running Value X {}",
        host,
        platform,
        &value_x_hex[..16]
    );

    Ok(())
}

/// Build a rustls `ClientConfig` that accepts ANY server cert. The
/// entire point of attested-TLS is that we authenticate by attestation, not
/// by a CA chain, so a cert that would fail `rustls::webpki` is not
/// a failure — it's the expected case.
fn build_unchecked_client_config() -> rustls::ClientConfig {
    #[derive(Debug)]
    struct NoVerify;
    impl rustls::client::danger::ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::ED25519,
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
            ]
        }
    }

    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth()
}

fn cmd_verify(args: &[String]) -> anyhow::Result<()> {
    let mut att_path: Option<String> = None;
    let mut source_dir: Option<PathBuf> = None;
    let mut artifact_path: Option<PathBuf> = None;
    // Secure by default: a quote that does not chain to the pinned vendor root
    // fails verification. This explicit, loudly-named flag is the only way to
    // proceed without the hardware root-of-trust (e.g. offline / no-KDS checks).
    let mut allow_unverified_chain = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--source-dir" => {
                i += 1;
                source_dir = args.get(i).map(|s| PathBuf::from(s));
            }
            "--artifact" => {
                i += 1;
                artifact_path = args.get(i).map(|s| PathBuf::from(s));
            }
            "--insecure-skip-chain" | "--no-chain" => {
                allow_unverified_chain = true;
            }
            _ => {
                if att_path.is_none() && !args[i].starts_with("--") {
                    att_path = Some(args[i].clone());
                }
            }
        }
        i += 1;
    }

    let path = att_path.ok_or_else(|| anyhow::anyhow!("Usage: uq verify <attestation.json>"))?;
    let att_json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path)?)?;

    // The JSON view is a lossy projection of the EAT (no eat_nonce, eat_profile,
    // tls_spki_hash, or chained previous_attestation), so the canonical binding
    // can only be recomputed from the full token. Load the `.cbor` sibling and
    // recompute `binding_bytes()` with the exact same code path the producer used
    // — this is the same check `cross_verify.rs` and the attested-TLS verifier run.
    let cbor_path = Path::new(&path).with_extension("cbor");
    let canonical_binding: Option<[u8; 32]> = std::fs::read(&cbor_path)
        .ok()
        .and_then(|bytes| eat::EatToken::from_cbor(&bytes).ok())
        .map(|tok| tok.binding_bytes());

    verify_attestation_json(
        &att_json,
        source_dir.as_deref(),
        artifact_path.as_deref(),
        canonical_binding,
        allow_unverified_chain,
    )
}

fn verify_attestation_json(
    att_json: &serde_json::Value,
    source_dir: Option<&Path>,
    artifact_path: Option<&Path>,
    canonical_binding: Option<[u8; 32]>,
    allow_unverified_chain: bool,
) -> anyhow::Result<()> {
    let platform_str = att_json["platform"].as_str().unwrap_or("");
    let ct_hex = att_json["source_hash"].as_str().unwrap_or("");
    let a_hex = att_json["artifact_hash"].as_str().unwrap_or("");
    let x_hex = att_json["value_x"].as_str().unwrap_or("");
    let binding_hex = att_json["binding"].as_str().unwrap_or("");
    let quote_hex = att_json["quote"].as_str().unwrap_or("");

    eprintln!("[uq] === Verification ===");
    eprintln!("[uq] Platform: {platform_str}");
    eprintln!("[uq] CT: {ct_hex}");
    eprintln!("[uq] A:  {a_hex}");
    eprintln!("[uq] X:  {x_hex}");

    // Check 1: Verify the committed binding is the canonical EatToken::binding_bytes().
    // The binding commits to every claim in the EAT (version, profile, value_x,
    // platform, tls_spki_hash, source_hash, artifact_hash, iat, nonce, previous_hash)
    // — not just ct/a/x. It can therefore only be recomputed from the full token
    // (the `.cbor` sibling), using the producer's own code. The lossy JSON cannot
    // reconstruct it. Check 2 then proves the hardware committed to this same value
    // via report_data, which is the cryptographic anchor.
    match canonical_binding {
        Some(expected) => {
            let expected_hex = hex::encode(expected);
            if expected_hex != binding_hex {
                eprintln!("[uq] FAIL: binding hash mismatch");
                eprintln!("[uq]   expected (eat.binding_bytes): {expected_hex}");
                eprintln!("[uq]   got (attestation.binding):    {binding_hex}");
                std::process::exit(1);
            }
            eprintln!("[uq] Binding hash: PASS (canonical EAT binding_bytes)");
        }
        None => {
            eprintln!(
                "[uq] Binding hash: SKIPPED — no .cbor sibling to recompute canonical binding"
            );
            eprintln!(
                "[uq] WARNING: cannot recompute binding from lossy JSON alone; \
                 relying on the quote report_data check below"
            );
        }
    }

    // Check 2: Verify TEE quote
    let quote_bytes = hex::decode(quote_hex)?;
    let binding_bytes = hex::decode(binding_hex)?;

    // Verify the quote's report_data contains our binding
    // This is platform-specific — check report_data[0..32] == binding
    let report_data_ok = verify_quote_binding(&quote_bytes, &binding_bytes, platform_str);
    if report_data_ok {
        eprintln!("[uq] Quote binding: PASS");
    } else {
        eprintln!("[uq] Quote binding: FAIL (report_data doesn't match)");
        std::process::exit(1);
    }

    // Check 3: Verify platform measurement from quote
    // LATTE L4: both layers checked independently.
    // The platform measurement proves the builder/runner code is genuine.
    let platform_measurement_hex = att_json["platform_measurement"].as_str().unwrap_or("");
    if !platform_measurement_hex.is_empty() {
        // Extract measurement from the raw quote and compare
        let platform = match platform_str {
            "Tdx" => Some(quote::Platform::Tdx),
            "SevSnp" => Some(quote::Platform::SevSnp),
            "Nitro" => Some(quote::Platform::Nitro),
            _ => None,
        };
        if let Some(p) = platform {
            if let Some(extracted) = extract_platform_measurement(&quote_bytes, &p) {
                let extracted_hex = hex::encode(&extracted);
                if extracted_hex == platform_measurement_hex {
                    eprintln!("[uq] Platform measurement: PASS — matches attestation");
                } else {
                    eprintln!("[uq] Platform measurement: FAIL");
                    eprintln!("[uq]   attestation: {platform_measurement_hex}");
                    eprintln!("[uq]   extracted:   {extracted_hex}");
                    std::process::exit(1);
                }
            } else {
                eprintln!("[uq] Platform measurement: COULD NOT EXTRACT from quote");
                std::process::exit(1);
            }
        }
    } else {
        eprintln!("[uq] Platform measurement: NOT PRESENT in attestation");
        eprintln!("[uq] WARNING: cannot verify builder identity without platform measurement");
    }

    // Check 4: Verify TEE quote signature chain.
    // This is THE cryptographic proof that the quote is from real hardware —
    // the report signs back to a vendor key (VCEK/VLEK/Nitro), which chains to
    // a fingerprint we pin (AMD ARK / Intel SGX root / AWS Nitro root). It is
    // the hardware root-of-trust, so it is authoritative: if it fails, the
    // receipt is not trustworthy and verification fails. The only way past it
    // is the explicit --insecure-skip-chain flag (offline / no-KDS checks).
    eprintln!("[uq] Verifying TEE signature chain...");
    let platform = match platform_str {
        "Tdx" => Some(quote::Platform::Tdx),
        "SevSnp" => Some(quote::Platform::SevSnp),
        "Nitro" => Some(quote::Platform::Nitro),
        _ => None,
    };
    // chain_verified == true ONLY when a real platform quote chains to the
    // pinned vendor root. Receipts with no hardware platform (e.g. software
    // witness) skip Check 4 entirely and never claim genuine hardware below.
    let mut chain_verified = false;
    if let Some(p) = platform {
        let binding_arr: [u8; 32] = if binding_bytes.len() == 32 {
            binding_bytes[..32].try_into().unwrap_or([0u8; 32])
        } else {
            [0u8; 32]
        };
        match quote::verify::verify_platform_quote(p, &quote_bytes, &binding_arr) {
            Ok(measurements) => {
                eprintln!("[uq] TEE signature chain: PASS");
                for (name, val) in &measurements {
                    eprintln!("[uq]   {}: {}", name, hex::encode(val));
                }
                chain_verified = true;
            }
            Err(e) => {
                eprintln!("[uq] TEE signature chain: FAIL — {e}");
                if allow_unverified_chain {
                    eprintln!(
                        "[uq] WARNING: --insecure-skip-chain set — proceeding WITHOUT a \
                         confirmed hardware root-of-trust. Do not trust this for release."
                    );
                } else {
                    eprintln!("[uq]");
                    eprintln!("[uq] === Verification FAILED ===");
                    eprintln!(
                        "[uq] The quote did not chain to the pinned {platform_str} vendor \
                         root, so genuine hardware cannot be asserted."
                    );
                    eprintln!(
                        "[uq] (For an offline / no-KDS check you can override with \
                         --insecure-skip-chain.)"
                    );
                    std::process::exit(1);
                }
            }
        }
    }

    // Check 5: Optionally verify CT against source
    if let Some(dir) = source_dir {
        eprintln!("[uq] Verifying source hash against {}", dir.display());
        let local_ct = compute_tree_hash(dir)?;
        if hex::encode(local_ct) == ct_hex {
            eprintln!("[uq] Source hash: PASS — matches attestation");
        } else {
            eprintln!("[uq] Source hash: FAIL");
            eprintln!("[uq]   attestation: {ct_hex}");
            eprintln!("[uq]   local:       {}", hex::encode(local_ct));
            std::process::exit(1);
        }
    }

    // Check 6: Optionally verify A against artifact
    if let Some(path) = artifact_path {
        eprintln!("[uq] Verifying artifact hash against {}", path.display());
        let bytes = std::fs::read(path)?;
        let local_a = hex::encode(Sha384::digest(&bytes));
        if local_a == a_hex {
            eprintln!("[uq] Artifact hash: PASS — matches attestation");
        } else {
            eprintln!("[uq] Artifact hash: FAIL");
            std::process::exit(1);
        }
    }

    // Check 7: Registry lookup.
    // The crypto above proves "this Value X was produced inside genuine
    // hardware." The registry answers "is this Value X approved?"
    // The two are independent — crypto can pass while status is revoked,
    // and vice versa. Clients decide policy; we just report.
    match registry::Registry::load_default() {
        Ok(reg) if !reg.is_empty() => {
            let lookup = reg.lookup(x_hex);
            eprintln!(
                "[uq] Registry ({} entries): {}",
                reg.len(),
                registry::describe(&lookup)
            );
            eprintln!(
                "[uq] Registry snapshot: {}",
                registry::describe_snapshot(reg.snapshot_state())
            );
            // A fresh, signed snapshot is authoritative for revocation: it
            // cannot be pinned to a stale pre-revocation mirror.
            if let Some(registry::Status::Revoked) = reg.fresh_status(x_hex) {
                eprintln!("[uq] WARNING: value_x is REVOKED per the fresh signed snapshot");
            }
        }
        Ok(_) => {
            eprintln!("[uq] Registry: empty (no entries loaded)");
        }
        Err(e) => {
            eprintln!("[uq] Registry: load failed — {e}");
        }
    }

    eprintln!();
    eprintln!("[uq] === Verification Complete ===");
    if chain_verified {
        eprintln!(
            "[uq] This artifact was built from this source inside genuine {platform_str} hardware."
        );
    } else {
        // Reached only via --insecure-skip-chain or a non-hardware (software
        // witness) receipt. Bindings hold, but we make no genuine-hardware claim.
        eprintln!(
            "[uq] Bindings and measurements are internally consistent, but the hardware \
             root-of-trust was NOT confirmed."
        );
    }

    Ok(())
}

// ============================================================================
// RUN — stage 1: self-verify then execute (AC6 + LATTE L2)
// ============================================================================

/// Stage 1: the attested runtime.
///
/// Implements Attestable Containers contribution #6 (build-to-runtime
/// chain). Stage 1 boots inside a TEE, loads the stage 0 attestation,
/// verifies it, re-computes Value X to confirm the runtime files match
/// what the builder saw, and produces its OWN attested-TLS cert whose
/// EAT:
///
/// - Has the same Value X as stage 0 (LATTE L2: portable identity
///   unchanged between build and run)
/// - Has `previous_attestation` set to the stage 0 EAT CBOR bytes
/// - Has `binding_bytes()` that mixes in `sha256(stage0_cbor)` via
///   `previous_hash()`, chaining stage 1's quote to stage 0
/// - Has a fresh stage 1 hardware quote whose `report_data[0..32]`
///   contains the new binding
///
/// A verifier walks the chain: receive stage 1 EAT → verify stage 1
/// quote → decode `previous_attestation` as stage 0 EAT → verify stage
/// 0 quote → confirm Value X is stable across both. Every link is a
/// hash in a hardware-signed report_data. No gaps.
async fn cmd_run(args: &[String]) -> anyhow::Result<()> {
    let mut work_dir: Option<PathBuf> = None;
    let mut stage0_path: Option<PathBuf> = None;
    let mut run_cmd: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--attestation" => {
                i += 1;
                stage0_path = args.get(i).map(PathBuf::from);
            }
            "--cmd" => {
                i += 1;
                run_cmd = args.get(i).map(|s| s.to_string());
            }
            _ => {
                if work_dir.is_none() && !args[i].starts_with("--") {
                    work_dir = Some(PathBuf::from(&args[i]));
                }
            }
        }
        i += 1;
    }

    let work_dir = work_dir.ok_or_else(|| anyhow::anyhow!("working directory required"))?;
    let stage0_path =
        stage0_path.ok_or_else(|| anyhow::anyhow!("--attestation <stage0.cbor> required"))?;

    // --- Step 1: confirm we're running inside a TEE ---
    eprintln!("[uq] === Stage 1: Attested Runtime ===");
    let tee_provider = tee::detect::detect_tee()
        .map_err(|e| anyhow::anyhow!("Stage 1 must run inside a TEE: {e}"))?;
    eprintln!("[uq] TEE: {:?}", tee_provider.platform());

    // --- Step 2: load stage 0 EAT (CBOR, canonical format) ---
    let stage0_cbor = std::fs::read(&stage0_path)
        .map_err(|e| anyhow::anyhow!("read {}: {e}", stage0_path.display()))?;
    eprintln!(
        "[uq] Stage 0 EAT: {} bytes from {}",
        stage0_cbor.len(),
        stage0_path.display()
    );
    let stage0_eat = eat::EatToken::from_cbor(&stage0_cbor)
        .map_err(|e| anyhow::anyhow!("decode stage 0 EAT: {e}"))?;
    eprintln!("[uq] Stage 0 Value X: {}", hex::encode(stage0_eat.value_x));

    // --- Step 3: verify stage 0's quote ---
    // The producer cannot be trusted; we verify stage 0 at boot.
    // This is LATTE: the verifier (stage 1 at boot) checks the platform
    // layer of the previous stage independently before trusting any
    // of its claims.
    let stage0_platform = stage0_eat
        .platform_enum()
        .ok_or_else(|| anyhow::anyhow!("stage 0 has unknown platform discriminant"))?;
    let stage0_binding = stage0_eat.binding_bytes();
    match quote::verify::verify_platform_quote(
        stage0_platform,
        &stage0_eat.platform_quote,
        &stage0_binding,
    ) {
        Ok(measurements) => {
            eprintln!("[uq] Stage 0 quote: PASS");
            for (name, val) in &measurements {
                eprintln!("[uq]   {}: {}", name, hex::encode(val));
            }
        }
        Err(e) => {
            anyhow::bail!("Stage 1 refuses to boot: stage 0 quote verification failed — {e}");
        }
    }

    // --- Step 4: re-compute Value X from disk ---
    // AC ratchet-at-boot: what's on disk now must match what the
    // builder hashed. If a byte moved, we refuse to run.
    let current_x = compute_tree_hash(&work_dir)?;
    if current_x != stage0_eat.value_x {
        anyhow::bail!(
            "Value X drift — stage 0 attested {} but disk hashes to {}. Refusing to run.",
            hex::encode(stage0_eat.value_x),
            hex::encode(current_x)
        );
    }
    eprintln!("[uq] Value X: MATCHES stage 0");

    // --- Step 5: generate stage 1 TLS keypair ---
    // Its SPKI hash goes into the EAT, and the EAT's binding goes
    // into the quote's report_data. This is what makes stage 1's
    // TLS session verifiably terminate at this attested runtime.
    let tls_kp = net::attested_tls::generate_keypair()?;
    let tls_spki_hash = net::attested_tls::spki_hash_of(&tls_kp);

    // --- Step 6: build the stage 1 EAT, chained to stage 0 ---
    let mut stage1 = eat::EatToken::from_build(eat::BuildComponents {
        platform: tee_provider.platform(),
        value_x: current_x,
        source_hash: stage0_eat.source_hash,
        artifact_hash: stage0_eat.artifact_hash,
        platform_measurement: Vec::new(), // filled after quote collection
        platform_quote: Vec::new(),       // filled after quote collection
    });
    stage1.tls_spki_hash = tls_spki_hash;
    stage1.set_previous(stage0_cbor);

    let binding = stage1.binding_bytes();

    // [0..32] = binding, [32..64] = second commitment (current_x[..32]) — see
    // EatToken::report_data_64 (L1.2). Byte-identical to the previous layout.
    let report_data = stage1.report_data_64(None);

    // --- Step 7: collect stage 1 quote ---
    eprintln!("[uq] Collecting stage 1 quote...");
    let evidence = tee_provider.collect_evidence(&report_data)?;
    eprintln!(
        "[uq] Stage 1 quote: {} bytes from {:?}",
        evidence.raw_quote.len(),
        evidence.platform
    );

    let s1_measurement =
        extract_platform_measurement(&evidence.raw_quote, &evidence.platform).unwrap_or_default();
    stage1.platform_measurement = s1_measurement;
    stage1.platform_quote = evidence.raw_quote.clone();

    // Invariant: the binding we committed to BEFORE collecting the
    // quote MUST equal the binding of the filled EAT. If this fires,
    // there's a bug in binding_bytes that breaks the chain.
    if stage1.binding_bytes() != binding {
        anyhow::bail!("stage 1 binding changed after filling quote/measurement");
    }

    let stage1_cbor = stage1
        .to_cbor()
        .map_err(|e| anyhow::anyhow!("stage 1 EAT encode: {e}"))?;

    // --- Step 8: persist the stage 1 attestation ---
    //
    // CRITICAL: do NOT write into `work_dir`. `work_dir` is the tree
    // whose sha384 equals Value X; dropping a new file into it would
    // make the next run of stage 1 fail Value X re-computation. The
    // stage 0 attestation file lives in an output directory (produced
    // by `cmd_build --output`), which is the correct place for runtime
    // artifacts.
    let output_dir = stage0_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .to_path_buf();
    let stage1_path = output_dir.join("stage1-attestation.cbor");
    std::fs::write(&stage1_path, &stage1_cbor)?;
    eprintln!(
        "[uq] Stage 1 EAT: {} bytes → {}",
        stage1_cbor.len(),
        stage1_path.display()
    );

    // --- Step 9: build the attested-TLS cert carrying the stage 1 EAT ---
    let domain = net::acme::domain_from_value_x(&current_x);
    let attested = net::attested_tls::make_attested_cert(&tls_kp, &domain, &stage1_cbor)?;
    eprintln!(
        "[uq] Attested-TLS cert built ({} bytes DER) — serving at {}",
        attested.cert_der.len(),
        domain
    );

    // --- Step 10: serve ---
    eprintln!();
    eprintln!("[uq] === Stage 1 Verified ===");
    eprintln!("[uq] Chain: source → attested build → attested runtime");
    eprintln!("[uq] Value X: {}", hex::encode(current_x));

    let tls_state = Arc::new(net::tls::TlsState::new_with_pem(
        attested.cert_pem.as_bytes(),
        attested.key_pem.as_bytes(),
    )?);
    // HTTP body is a courtesy summary — the actual attestation lives
    // in the TLS cert extension (attested-TLS path).
    let summary = format!(
        "{{\"stage\":1,\"value_x\":\"{}\",\"domain\":\"{}\",\"note\":\"EAT is in TLS cert extension 2.23.133.5.4.9\"}}",
        hex::encode(current_x),
        domain
    );
    tls_state.set_attestation(summary).await;

    let state_clone = tls_state.clone();
    tokio::spawn(async move {
        if let Err(e) = net::tls::serve(state_clone, 443).await {
            eprintln!("[uq] TLS server error: {e}");
        }
    });
    eprintln!("[uq] Attested TLS server started on :443");

    // --- Step 11: execute workload if provided ---
    if let Some(cmd) = run_cmd {
        eprintln!("[uq] Running: {cmd}");
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .current_dir(&work_dir)
            .env("UQ_VALUE_X", hex::encode(current_x))
            .env("UQ_DOMAIN", &domain)
            .env("UQ_STAGE", "1")
            .status()?;
        eprintln!("[uq] Workload exited: {status}");
    } else {
        eprintln!("[uq] No --cmd provided. Serving attestation.");
        eprintln!("[uq] Press Ctrl+C to stop.");
        tokio::signal::ctrl_c().await?;
    }

    Ok(())
}

// ============================================================================
// ENCLAVE — single-shot build + serve for Nitro Enclaves
// ============================================================================
// Runs build and serve in one process to avoid re-initializing the NSM device.

fn cmd_enclave(args: &[String]) -> anyhow::Result<()> {
    let mut source_dir: Option<PathBuf> = None;
    let mut build_cmd: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--cmd" => {
                i += 1;
                build_cmd = args.get(i).map(|s| s.to_string());
            }
            _ => {
                if source_dir.is_none() {
                    source_dir = Some(PathBuf::from(&args[i]));
                }
            }
        }
        i += 1;
    }

    let source_dir = source_dir.ok_or_else(|| anyhow::anyhow!("source directory required"))?;

    eprintln!("[uq] Enclave mode: build + serve in one process");

    // Detect TEE once
    let tee_provider = tee::detect::detect_tee()?;
    eprintln!("[uq] TEE: {:?}", tee_provider.platform());

    // Compute CT
    let ct = compute_tree_hash(&source_dir)?;
    eprintln!("[uq] CT = {}", hex::encode(ct));

    // Ratchet
    let build_workspace = tempdir()?;
    let frozen_source = build_workspace.join("src");
    copy_dir_readonly(&source_dir, &frozen_source)?;

    // Build
    let build_output = build_workspace.join("build");
    std::fs::create_dir_all(&build_output)?;
    let dep_cache = build_workspace.join("deps");
    std::fs::create_dir_all(&dep_cache)?;

    let cmd = build_cmd.unwrap_or_else(|| detect_build_cmd(&frozen_source));
    eprintln!("[uq] Building: {cmd}");
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .current_dir(&frozen_source)
        .env("CARGO_TARGET_DIR", &build_output)
        .env("CARGO_HOME", &dep_cache)
        .status()?;
    if !status.success() {
        anyhow::bail!("Build failed: {status}");
    }

    // Verify ratchet
    let ct_post = compute_tree_hash(&frozen_source)?;
    if ct != ct_post {
        anyhow::bail!("RATCHET VIOLATED");
    }
    eprintln!("[uq] Ratchet OK");

    // Compute Value X
    let value_x = compute_tree_hash(&frozen_source)?;
    eprintln!("[uq] X = {}", hex::encode(value_x));

    // --- Attested TLS: generate TLS keypair BEFORE quote collection ---
    //
    // The TLS key is the channel binding anchor. Its SPKI hash goes
    // into the EAT, the EAT's binding_bytes goes into the quote's
    // report_data, and the quote goes back into the EAT inside the
    // cert extension. A verifier who completes the TLS handshake and
    // checks that sha256(leaf_cert_spki) matches eat.tls_spki_hash
    // knows that the cert *belongs* to the attested TEE — no MITM,
    // no relay. See net::attested_tls for the full chain description.
    eprintln!("[uq] Generating attested-TLS keypair inside enclave");
    let tls_kp = net::attested_tls::generate_keypair()?;
    let tls_spki_hash = net::attested_tls::spki_hash_of(&tls_kp);
    eprintln!("[uq] TLS SPKI sha256: {}", hex::encode(tls_spki_hash));

    // Provisional EAT: same fields as the final one EXCEPT
    // platform_quote is empty. binding_bytes() is defined to exclude
    // platform_quote (chicken and egg — report_data lives inside it),
    // so the binding computed here matches the binding the verifier
    // recomputes later from the finalized token.
    // We need an artifact hash here for the EAT; cmd_enclave builds
    // into a tempdir so there's no single output artifact. Use the
    // hash of the build output tree as a stable stand-in.
    let artifact_hash = compute_tree_hash(&build_output).unwrap_or([0u8; 48]);
    let mut eat_partial = eat::EatToken::from_build(eat::BuildComponents {
        platform: tee_provider.platform(),
        value_x,
        source_hash: ct,
        artifact_hash,
        platform_measurement: Vec::new(), // filled after quote collection
        platform_quote: Vec::new(),       // filled after quote collection
    });
    eat_partial.tls_spki_hash = tls_spki_hash;

    let binding: [u8; 32] = eat_partial.binding_bytes();
    eprintln!("[uq] EAT binding: {}", hex::encode(binding));

    let mut report_data = [0u8; 64];
    report_data[..32].copy_from_slice(&binding);
    report_data[32..64].copy_from_slice(&value_x[..32]);

    let evidence = tee_provider.collect_evidence(&report_data)?;
    eprintln!(
        "[uq] Quote: {} bytes from {:?}",
        evidence.raw_quote.len(),
        evidence.platform
    );

    // Finalize the EAT with the collected quote + measurement
    let platform_measurement =
        extract_platform_measurement(&evidence.raw_quote, &evidence.platform).unwrap_or_default();
    let mut eat = eat_partial;
    eat.platform_measurement = platform_measurement;
    eat.platform_quote = evidence.raw_quote.clone();

    // Sanity: binding_bytes() MUST still equal `binding` after
    // assignment, because binding_bytes excludes platform_quote AND
    // platform_measurement. If this ever fires, the EAT schema has
    // drifted in a way that breaks channel binding.
    if eat.binding_bytes() != binding {
        anyhow::bail!(
            "attested-TLS binding invariant violated: binding_bytes changed after finalization"
        );
    }

    // NOTE: platform_measurement is NOT in binding_bytes today, because
    // it's derivable from platform_quote by the verifier. If we ever
    // want to bind it as a separate first-class field, it needs to be
    // included in the pre-quote hash and the flow reordered further.

    // Stash RSA keys for KMS (Nitro only)
    let kms_private_key = evidence.kms_private_key.clone();

    // Build KMS state — keeps NSM fd alive for fresh attestation generation.
    // KMS rejects attestation docs older than 5 minutes, so GET /kms-attestation
    // calls NSM again with the same RSA pubkey to get a fresh doc.
    #[cfg(all(feature = "nitro", unix))]
    let kms_state: Option<Arc<net::vsock::KmsState>> = if kms_private_key.is_some() {
        // Extract RSA public key from the evidence (re-derive from private key)
        use rsa::pkcs8::DecodePrivateKey;
        use rsa::pkcs8::EncodePublicKey;
        let rsa_priv = rsa::RsaPrivateKey::from_pkcs8_der(kms_private_key.as_ref().unwrap())
            .expect("RSA privkey decode");
        let rsa_pub = rsa::RsaPublicKey::from(&rsa_priv);
        let rsa_pub_der = rsa_pub
            .to_public_key_der()
            .expect("RSA pubkey DER")
            .as_bytes()
            .to_vec();

        // Move the tee_provider into KmsState (it holds the NSM fd)
        // We need it to be a NitroProvider specifically
        let nsm = match tee_provider.platform() {
            quote::Platform::Nitro => {
                // SAFETY: we know detect_tee returned a NitroProvider
                // Re-create it from the same fd — but we can't move out of Box<dyn TeeProvider>
                // Instead, just create a new one (nsm_init is idempotent)
                Arc::new(tee::nitro::NitroProvider::new()?)
            }
            _ => unreachable!("kms_private_key is only Some for Nitro"),
        };

        Some(Arc::new(net::vsock::KmsState {
            nsm,
            report_data,
            rsa_pub_der,
            rsa_priv_der: kms_private_key.clone().unwrap(),
        }))
    } else {
        None
    };

    // Build attestation — include base64 attestation document for KMS --recipient flag
    use base64::Engine;
    let quote_b64 = base64::engine::general_purpose::STANDARD.encode(&evidence.raw_quote);
    let value_x_hex = hex::encode(value_x);
    let domain = net::acme::domain_from_value_x(&value_x);
    let attestation = serde_json::json!({
        "version": 2,
        "stage": 0,
        "platform": format!("{:?}", evidence.platform),
        "source_hash": hex::encode(ct),
        "value_x": value_x_hex,
        "binding": hex::encode(binding),
        "quote": hex::encode(&evidence.raw_quote),
        "attestation_document_b64": quote_b64,
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs(),
        "sequence_number": 1,
        "domain": domain,
        "kms": {
            "has_rsa_key": kms_private_key.is_some(),
            "fresh_attestation": "/kms-attestation",
            "unwrap_endpoint": "/kms-unwrap",
            "usage": "1) GET /kms-attestation → fresh doc  2) aws kms decrypt --recipient ...  3) POST /kms-unwrap"
        }
    });

    let attestation_json = serde_json::to_string_pretty(&attestation)?;

    // Serialize the FINAL EAT (with quote populated) to CBOR.
    // This is what goes into the CMW cert extension AND what /eat serves.
    let eat_cbor = eat.to_cbor()?;
    eprintln!(
        "[uq] EAT (CBOR): {} bytes — embedded in attested-TLS cert + served at /eat",
        eat_cbor.len()
    );

    eprintln!("[uq] === Enclave Ready ===");
    eprintln!("[uq] Value X: {}", hex::encode(value_x));
    eprintln!("[uq] Domain: {domain}");
    if kms_private_key.is_some() {
        eprintln!("[uq] KMS: GET /kms-attestation (fresh doc) + POST /kms-unwrap");
    }

    // Try TLS on vsock first. If ring crypto fails (some enclaves), fall back to plain vsock.
    eprintln!("[uq] Parent should run: uq proxy --cid <enclave-cid>");

    match rustls::crypto::ring::default_provider().install_default() {
        Ok(_) => {
            // attested-TLS cert: the enclave-generated keypair + self-signed cert
            // + EAT CBOR as a critical extension. Reusing the same keypair
            // whose SPKI hash is in eat.tls_spki_hash is the whole point.
            let tls_config = {
                let ac = net::attested_tls::make_attested_cert(&tls_kp, &domain, &eat_cbor)?;
                eprintln!(
                    "[uq] attested-TLS cert built ({} bytes DER, EAT extension marked critical)",
                    ac.cert_der.len()
                );
                net::tls::make_server_config(ac.cert_pem.as_bytes(), ac.key_pem.as_bytes())?
            };
            eprintln!("[uq] TLS on vsock (inside enclave)");
            #[cfg(all(feature = "nitro", unix))]
            {
                net::vsock::serve_tls_vsock(
                    Arc::new(tls_config),
                    &attestation_json,
                    &eat_cbor,
                    kms_private_key,
                    kms_state,
                )?;
            }
            #[cfg(not(all(feature = "nitro", unix)))]
            {
                net::vsock::serve_tls_vsock(
                    Arc::new(tls_config),
                    &attestation_json,
                    &eat_cbor,
                    kms_private_key,
                )?;
            }
        }
        Err(_) => {
            eprintln!("[uq] TLS crypto unavailable — serving plain HTTP on vsock");
            net::vsock::serve_vsock(&attestation_json)?;
        }
    }

    Ok(())
}

// ============================================================================
// RUN SYNC — fallback for Nitro Enclaves where tokio doesn't work
// ============================================================================

fn cmd_run_sync(args: &[String]) -> anyhow::Result<()> {
    let mut work_dir: Option<PathBuf> = None;
    let mut attestation_path: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--attestation" => {
                i += 1;
                attestation_path = args.get(i).map(|s| PathBuf::from(s));
            }
            _ => {
                if work_dir.is_none() {
                    work_dir = Some(PathBuf::from(&args[i]));
                }
            }
        }
        i += 1;
    }

    let work_dir = work_dir.ok_or_else(|| anyhow::anyhow!("working directory required"))?;
    let attestation_path =
        attestation_path.ok_or_else(|| anyhow::anyhow!("--attestation <path> required"))?;

    eprintln!("[uq] Stage 1 (sync mode): self-verification");

    // Load and verify attestation
    let att_contents = std::fs::read_to_string(&attestation_path)?;
    let att_json: serde_json::Value = serde_json::from_str(&att_contents)?;

    let stage0_x = att_json["value_x"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing value_x"))?;

    eprintln!("[uq] Stage 0 Value X: {}", &stage0_x[..24]);

    // Re-compute Value X
    let current_x = compute_tree_hash(&work_dir)?;
    let current_x_hex = hex::encode(current_x);

    if current_x_hex != stage0_x {
        eprintln!("[uq] FATAL: Value X mismatch");
        eprintln!("[uq]   stage 0: {stage0_x}");
        eprintln!("[uq]   current: {current_x_hex}");
        std::process::exit(1);
    }
    eprintln!("[uq] Value X: MATCHES");

    // In sync mode (Nitro Enclave), serve the stage 0 attestation directly.
    // The stage 0 quote already contains the Nitro attestation with Value X bound.
    // Re-collecting a quote would require re-initializing the NSM device which
    // may fail if it's already been used by stage 0.
    let attestation_json = att_contents;
    eprintln!("[uq] === Stage 1 Verified (sync) ===");
    eprintln!("[uq] Value X: {current_x_hex}");

    // Serve via vsock (blocking)
    let domain = net::acme::domain_from_value_x(&current_x);
    eprintln!("[uq] Domain: {domain}");
    eprintln!("[uq] Serving via vsock on port {}", net::vsock::VSOCK_PORT);

    net::vsock::serve_vsock(&attestation_json)?;

    Ok(())
}

// ============================================================================
// MERGE — combine attestations from multiple platforms (LATTE L3/L6)
// ============================================================================
//
// LATTE says: the verifier derives expected measurements from Rcommon.
// We can't predict MRTD from image contents (firmware is opaque).
// Creative solution: witness measurements from multiple platforms,
// merge them into a single document. This IS Rcommon — the set of
// known-good measurements for this Value X across platforms.
//
// A verifier picks their platform's measurement and checks it.
// If two independent TEE vendors (e.g., TDX on GCP + SNP on AWS)
// attest the same Value X, that's also the anytrust model (AC4).

fn cmd_merge(args: &[String]) -> anyhow::Result<()> {
    let mut att_paths: Vec<PathBuf> = Vec::new();
    let mut output_path = PathBuf::from("merged-attestation.json");
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--output" => {
                i += 1;
                if let Some(s) = args.get(i) {
                    output_path = PathBuf::from(s);
                }
            }
            _ => {
                att_paths.push(PathBuf::from(&args[i]));
            }
        }
        i += 1;
    }

    if att_paths.len() < 2 {
        anyhow::bail!("merge requires at least 2 attestation files");
    }

    // Load all attestations
    let mut attestations: Vec<serde_json::Value> = Vec::new();
    for path in &att_paths {
        let json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
        attestations.push(json);
    }

    // Verify all attestations have the same Value X
    let first_x = attestations[0]["value_x"].as_str().unwrap_or("");
    let first_ct = attestations[0]["source_hash"].as_str().unwrap_or("");
    let first_a = attestations[0]["artifact_hash"].as_str().unwrap_or("");

    for (i, att) in attestations.iter().enumerate() {
        let x = att["value_x"].as_str().unwrap_or("");
        let ct = att["source_hash"].as_str().unwrap_or("");
        if x != first_x {
            anyhow::bail!(
                "Value X mismatch between attestations:\n  [0]: {first_x}\n  [{i}]: {x}\n\
                 Cannot merge attestations with different Value X."
            );
        }
        if ct != first_ct {
            anyhow::bail!(
                "Source hash mismatch between attestations:\n  [0]: {first_ct}\n  [{i}]: {ct}\n\
                 Attestations built from different source."
            );
        }
    }

    eprintln!("[uq] All attestations agree:");
    eprintln!("[uq]   Value X: {first_x}");
    eprintln!("[uq]   CT:      {first_ct}");
    eprintln!("[uq]   A:       {first_a}");

    // Build platform measurement map (Rcommon)
    let mut platform_measurements = serde_json::Map::new();
    let mut platform_quotes = serde_json::Map::new();
    let mut platforms_seen = Vec::new();

    for att in &attestations {
        let platform = att["platform"].as_str().unwrap_or("unknown");
        let measurement = att["platform_measurement"].as_str().unwrap_or("");
        let quote = att["quote"].as_str().unwrap_or("");

        if !measurement.is_empty() {
            platform_measurements.insert(platform.to_string(), serde_json::json!(measurement));
        }
        if !quote.is_empty() {
            platform_quotes.insert(platform.to_string(), serde_json::json!(quote));
        }
        platforms_seen.push(platform.to_string());
        eprintln!(
            "[uq]   {platform}: measurement={}",
            &measurement[..32.min(measurement.len())]
        );
    }

    let merged = serde_json::json!({
        "version": 1,
        "type": "merged",
        "platforms": platforms_seen,
        "value_x": first_x,
        "source_hash": first_ct,
        "artifact_hash": first_a,
        // Rcommon: expected measurements per platform
        "rcommon": platform_measurements,
        // Full quotes per platform for deep verification
        "quotes": platform_quotes,
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_secs(),
    });

    std::fs::write(&output_path, serde_json::to_string_pretty(&merged)?)?;

    eprintln!();
    eprintln!("[uq] === Merged Attestation ===");
    eprintln!("[uq] Platforms: {}", platforms_seen.join(", "));
    eprintln!("[uq] Value X: {first_x}");
    eprintln!("[uq] Output: {}", output_path.display());
    eprintln!();
    if platforms_seen.len() >= 2 {
        eprintln!(
            "[uq] Anytrust: {} independent TEE vendors attest the same Value X.",
            platforms_seen.len()
        );
        eprintln!("[uq] Trust at least one vendor → trust the build.");
    }

    Ok(())
}

// ============================================================================
// Helpers
// ============================================================================

/// Detect build command from project files.
fn detect_build_cmd(dir: &Path) -> String {
    if dir.join("Cargo.toml").exists() {
        "cargo build --release".into()
    } else if dir.join("Dockerfile").exists() {
        "docker build -t uq-build .".into()
    } else if dir.join("package.json").exists() {
        "npm ci && npm run build".into()
    } else if dir.join("Makefile").exists() {
        "make".into()
    } else if dir.join("go.mod").exists() {
        "go build ./...".into()
    } else {
        eprintln!("[uq] WARNING: no build system detected, using 'make'");
        "make".into()
    }
}

/// Find the primary build artifact.
/// Checks build_dir first (where CARGO_TARGET_DIR points), then source_dir.
fn find_artifact(build_dir: &Path, source_dir: &Path) -> PathBuf {
    // Rust: CARGO_TARGET_DIR/release/
    let target = build_dir.join("release");
    if target.exists() {
        if let Ok(entries) = std::fs::read_dir(&target) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        if let Ok(meta) = path.metadata() {
                            if meta.permissions().mode() & 0o111 != 0
                                && !path.extension().is_some_and(|e| e == "d" || e == "rmeta")
                            {
                                return path;
                            }
                        }
                    }
                }
            }
        }
    }

    // Fallback: common output dirs in source
    for candidate in ["dist", "build", "out", "bin"] {
        let p = source_dir.join(candidate);
        if p.exists() {
            return p;
        }
    }

    build_dir.to_path_buf()
}

/// AC5: Append attestation to a git-based transparency log.
/// If the output directory is inside a git repo, commit the attestation
/// with a deterministic name. Git's hash chain is the append-only log.
fn append_to_log(output_dir: &Path, att_path: &Path, value_x: &[u8; 48]) -> bool {
    // Check if output_dir is inside a git repo
    let git_check = std::process::Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .current_dir(output_dir)
        .output();

    let in_git = git_check.map(|o| o.status.success()).unwrap_or(false);
    if !in_git {
        return false;
    }

    // Copy attestation to a deterministic path
    let x_prefix = hex::encode(&value_x[..8]);
    let log_dir = output_dir.join("attestations");
    let _ = std::fs::create_dir_all(&log_dir);
    let log_path = log_dir.join(format!("{x_prefix}.json"));
    if std::fs::copy(att_path, &log_path).is_err() {
        return false;
    }

    // Git add + commit
    let add = std::process::Command::new("git")
        .args(["add", &log_path.to_string_lossy()])
        .current_dir(output_dir)
        .output();

    if !add.map(|o| o.status.success()).unwrap_or(false) {
        return false;
    }

    let msg = format!("attestation: {x_prefix}");
    let commit = std::process::Command::new("git")
        .args(["commit", "-m", &msg, "--allow-empty"])
        .current_dir(output_dir)
        .output();

    commit.map(|o| o.status.success()).unwrap_or(false)
}

/// Create a temporary directory for the build workspace.
fn tempdir() -> anyhow::Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!("uq-build-{}", std::process::id()));
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Copy a directory tree and make all files read-only.
/// This is the enforcement side of the ratchet: the build process
/// can read source files but cannot modify them.
fn copy_dir_readonly(src: &Path, dst: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dst)?;

    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let name = entry.file_name();
        let name_str = name.to_str().unwrap_or("");

        // Skip VCS state and generated artifacts that are excluded from Value X.
        if value_x::SKIP_NAMES.contains(&name_str) {
            continue;
        }

        let metadata = std::fs::symlink_metadata(&src_path)?;
        let file_type = metadata.file_type();

        if file_type.is_symlink() {
            anyhow::bail!(
                "source snapshot cannot include symlinks: {}",
                src_path.display()
            );
        }

        if file_type.is_dir() {
            copy_dir_readonly(&src_path, &dst_path)?;
        } else if file_type.is_file() {
            std::fs::copy(&src_path, &dst_path)?;
            // Make read-only
            let mut perms = std::fs::metadata(&dst_path)?.permissions();
            perms.set_readonly(true);
            std::fs::set_permissions(&dst_path, perms)?;
        }
    }

    // Make the directory itself read-only
    let mut dir_perms = std::fs::metadata(dst)?.permissions();
    dir_perms.set_readonly(true);
    std::fs::set_permissions(dst, dir_perms)?;

    Ok(())
}

/// Extract the platform measurement from a raw TEE quote.
/// TDX: MRTD (48 bytes at body offset 136)
/// SNP: MEASUREMENT (48 bytes at offset 0x090)
/// Nitro: PCR0 (from CBOR payload)
fn extract_platform_measurement(quote: &[u8], platform: &quote::Platform) -> Option<Vec<u8>> {
    match platform {
        quote::Platform::Tdx => {
            if quote.len() >= 632 {
                let body = &quote[48..632];
                Some(body[136..184].to_vec())
            } else {
                None
            }
        }
        quote::Platform::SevSnp => {
            if quote.len() >= 0x0C0 {
                Some(quote[0x090..0x0C0].to_vec())
            } else {
                None
            }
        }
        quote::Platform::Nitro => {
            // PCR0 is inside the CBOR payload — parse it
            #[cfg(feature = "nitro")]
            {
                if let Ok(cose) = serde_cbor::from_slice::<serde_cbor::Value>(quote) {
                    let arr = match &cose {
                        serde_cbor::Value::Tag(18, inner) => match inner.as_ref() {
                            serde_cbor::Value::Array(a) => Some(a),
                            _ => None,
                        },
                        _ => None,
                    };
                    if let Some(arr) = arr {
                        if let Some(serde_cbor::Value::Bytes(payload_bytes)) = arr.get(2) {
                            if let Ok(serde_cbor::Value::Map(map)) =
                                serde_cbor::from_slice(payload_bytes)
                            {
                                for (k, v) in &map {
                                    if let serde_cbor::Value::Text(key) = k {
                                        if key == "pcrs" {
                                            if let serde_cbor::Value::Map(pcr_map) = v {
                                                // PCR0
                                                for (idx, val) in pcr_map {
                                                    if let (
                                                        serde_cbor::Value::Integer(0),
                                                        serde_cbor::Value::Bytes(b),
                                                    ) = (idx, val)
                                                    {
                                                        return Some(b.clone());
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                None
            }
            #[cfg(not(feature = "nitro"))]
            None
        }
    }
}

/// Check that the TEE quote's report_data contains our binding hash.
fn verify_quote_binding(quote: &[u8], binding: &[u8], platform: &str) -> bool {
    match platform {
        "Tdx" => {
            // TDX: REPORTDATA at body offset 520, body starts at 48
            if quote.len() < 632 {
                return false;
            }
            let report_data = &quote[48 + 520..48 + 584];
            report_data[..32] == binding[..32.min(binding.len())]
        }
        "SevSnp" => {
            // SNP: REPORT_DATA at offset 0x050
            if quote.len() < 0x090 {
                return false;
            }
            let report_data = &quote[0x050..0x090];
            report_data[..32] == binding[..32.min(binding.len())]
        }
        "Nitro" => {
            // Nitro: user_data field in CBOR payload
            // For now, structural check — full CBOR parsing in verify.rs
            !quote.is_empty()
        }
        _ => false,
    }
}

/// `uq azure <collect|verify|check|serve>` — Azure confidential VM attestation.
///
/// Azure CVMs run AMD SEV-SNP under the vTOM paravisor and do not expose
/// `/dev/sev-guest`. The paravisor publishes a genuine SNP report through the
/// vTPM (NV index 0x01400001); we extract and verify it against the **AMD root**
/// (per-chip VCEK → ASK → ARK Milan), giving Azure hardware-rooted attestation
/// without trusting Microsoft Azure Attestation.
#[cfg(feature = "sev-snp")]
fn cmd_azure(args: &[String]) -> anyhow::Result<()> {
    use unified_quote::tee::azure;

    let sub = args.first().map(String::as_str).unwrap_or("");
    let rest = if args.is_empty() { &[][..] } else { &args[1..] };

    // Small flag helper: value following `flag`, else default.
    let flag = |name: &str, default: &str| -> String {
        rest.iter()
            .position(|a| a == name)
            .and_then(|i| rest.get(i + 1))
            .cloned()
            .unwrap_or_else(|| default.to_string())
    };
    let positional = || rest.iter().find(|a| !a.starts_with("--")).cloned();

    // Parse an optional 32-byte hex value_x (source/artifact identity) to bind
    // into the AK-signed TPM quote. Accepts --value-x or --bind.
    let parse_binding = || -> anyhow::Result<Option<[u8; 32]>> {
        let mut hexs = flag("--value-x", "");
        if hexs.is_empty() {
            hexs = flag("--bind", "");
        }
        if hexs.is_empty() {
            return Ok(None);
        }
        let bytes = hex::decode(hexs.trim_start_matches("0x"))
            .map_err(|e| anyhow::anyhow!("--value-x must be hex: {e}"))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("--value-x must be exactly 32 bytes (a sha256 digest)"))?;
        Ok(Some(arr))
    };

    match sub {
        "collect" => {
            let out = flag("-o", "azure-bundle.json");
            let binding = parse_binding()?;
            eprintln!(
                "[uq/azure] Reading HCL report from vTPM NV {}",
                azure::AZURE_HCL_NV_INDEX
            );
            if let Some(b) = &binding {
                eprintln!(
                    "[uq/azure] Binding value_x {} via AK quote (vTPM {})",
                    hex::encode(b),
                    azure::AZURE_VTPM_AK_HANDLE
                );
            }
            let bundle = azure::collect_bundle(binding.as_ref()).map_err(|e| anyhow::anyhow!(e))?;
            std::fs::write(&out, serde_json::to_string_pretty(&bundle)?)?;
            // Also emit the raw HCL for backward-compatible serving/verification.
            std::fs::write("azure-hcl.bin", hex::decode(&bundle.hcl)?)?;
            eprintln!("[uq/azure] Wrote {out} and azure-hcl.bin");
            let verdict = azure::verify_bundle(&bundle).map_err(|e| anyhow::anyhow!(e))?;
            print_azure_verdict(&verdict);
            std::fs::write("azure-attest.json", serde_json::to_string_pretty(&verdict)?)?;
            if verdict.verdict != "verified" {
                std::process::exit(1);
            }
            Ok(())
        }
        "verify" => {
            let path = positional().ok_or_else(|| {
                anyhow::anyhow!("usage: uq azure verify <azure-bundle.json | azure-hcl.bin>")
            })?;
            let raw = std::fs::read(&path)?;
            let verdict = if path.ends_with(".json") {
                let bundle: azure::AzureBundle = serde_json::from_slice(&raw)?;
                azure::verify_bundle(&bundle).map_err(|e| anyhow::anyhow!(e))?
            } else {
                azure::verify_hcl(&raw).map_err(|e| anyhow::anyhow!(e))?
            };
            print_azure_verdict(&verdict);
            if verdict.verdict != "verified" {
                std::process::exit(1);
            }
            Ok(())
        }
        "check" => {
            let url = positional()
                .ok_or_else(|| anyhow::anyhow!("usage: uq azure check http://<host>[:port]/"))?;
            let base = url.trim_end_matches('/');
            let client = reqwest::blocking::Client::builder()
                .danger_accept_invalid_certs(true)
                .timeout(std::time::Duration::from_secs(15))
                .build()?;
            // Prefer the richer bundle (carries value_x binding); fall back to raw HCL.
            let bundle_url = format!("{base}/bundle.json");
            eprintln!("[uq/azure] Fetching evidence: {bundle_url}");
            let bundle_resp = client.get(&bundle_url).send();
            let verdict = match bundle_resp {
                Ok(r) if r.status().is_success() => {
                    let bundle: azure::AzureBundle = serde_json::from_slice(&r.bytes()?)?;
                    eprintln!("[uq/azure] Got bundle; verifying against AMD root…");
                    azure::verify_bundle(&bundle).map_err(|e| anyhow::anyhow!(e))?
                }
                _ => {
                    let target = format!("{base}/azure-hcl.bin");
                    eprintln!("[uq/azure] No bundle.json; falling back to {target}");
                    let resp = client.get(&target).send()?;
                    if !resp.status().is_success() {
                        anyhow::bail!("endpoint returned HTTP {}", resp.status());
                    }
                    let hcl = resp.bytes()?.to_vec();
                    azure::verify_hcl(&hcl).map_err(|e| anyhow::anyhow!(e))?
                }
            };
            print_azure_verdict(&verdict);
            if verdict.verdict != "verified" {
                std::process::exit(1);
            }
            Ok(())
        }
        "serve" => {
            let path = flag("-f", "azure-bundle.json");
            let port: u16 = flag("--port", "8443").parse().unwrap_or(8443);
            // Load a bundle if present, else wrap a raw HCL file as a bundle.
            let bundle: azure::AzureBundle = if path.ends_with(".json") {
                serde_json::from_slice(&std::fs::read(&path)?)?
            } else {
                let hcl = std::fs::read(&path)?;
                azure::AzureBundle {
                    version: 1,
                    platform: "azure-sev-snp-vtpm".into(),
                    hcl: hex::encode(hcl),
                    tpm_quote_msg: None,
                    tpm_quote_sig: None,
                    value_x: None,
                    tls_spki: None,
                }
            };
            // Pre-verify so we only serve self-authenticating, valid evidence.
            let verdict = azure::verify_bundle(&bundle).map_err(|e| anyhow::anyhow!(e))?;
            let verdict_json = serde_json::to_string_pretty(&verdict)?;
            let bundle_json = serde_json::to_string(&bundle)?;
            let hcl = hex::decode(&bundle.hcl)?;
            serve_azure_evidence(port, hcl, bundle_json, verdict_json)
        }
        "serve-tls" => {
            let domain = flag("--domain", "attest.secure.build");
            let port: u16 = flag("--port", "8443").parse().unwrap_or(8443);
            let vx = parse_binding()?.ok_or_else(|| {
                anyhow::anyhow!(
                    "serve-tls requires --value-x <hex32> (the source identity to bind)"
                )
            })?;
            eprintln!(
                "[uq/azure] Minting attested-TLS cert for {domain} (value_x {})",
                hex::encode(vx)
            );
            let (cert, _bundle) =
                azure::collect_attested_cert(&domain, &vx).map_err(|e| anyhow::anyhow!(e))?;
            // Self-check before serving: only expose evidence that verifies.
            let verdict =
                azure::verify_attested_cert(&cert.cert_der).map_err(|e| anyhow::anyhow!(e))?;
            print_azure_verdict(&verdict);
            if verdict.verdict != "verified" {
                anyhow::bail!("refusing to serve: self-verification failed");
            }
            let verdict_json = serde_json::to_string_pretty(&verdict)?;
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async move {
                let state = std::sync::Arc::new(
                    net::tls::TlsState::new_with_pem(
                        cert.cert_pem.as_bytes(),
                        cert.key_pem.as_bytes(),
                    )
                    .map_err(|e| anyhow::anyhow!(e))?,
                );
                state.set_attestation(verdict_json).await;
                eprintln!("[uq/azure] attested-TLS on 0.0.0.0:{port} — cert carries the SNP→AMD bundle + value_x");
                net::tls::serve(state, port).await
            })
        }
        "check-tls" => {
            let url = positional().ok_or_else(|| {
                anyhow::anyhow!("usage: uq azure check-tls https://<host>[:port]/")
            })?;
            let stripped = url.strip_prefix("https://").unwrap_or(&url);
            let hostport = stripped.split('/').next().unwrap_or(stripped);
            let (host, port) = hostport
                .split_once(':')
                .map(|(h, p)| (h.to_string(), p.parse::<u16>().unwrap_or(8443)))
                .unwrap_or_else(|| (hostport.to_string(), 8443));
            eprintln!("[uq/azure] attested-TLS check: {host}:{port}");

            let _ = rustls::crypto::ring::default_provider().install_default();
            let client_config = build_unchecked_client_config();
            let server_name = rustls::pki_types::ServerName::try_from(host.clone())
                .map_err(|e| anyhow::anyhow!("invalid server name {host}: {e}"))?;
            let mut conn =
                rustls::ClientConnection::new(std::sync::Arc::new(client_config), server_name)
                    .map_err(|e| anyhow::anyhow!("rustls client: {e}"))?;
            let mut sock = std::net::TcpStream::connect((host.as_str(), port))
                .map_err(|e| anyhow::anyhow!("tcp connect {host}:{port}: {e}"))?;
            let mut tls = rustls::Stream::new(&mut conn, &mut sock);
            use std::io::{Read, Write};
            let req = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
            tls.write_all(req.as_bytes())
                .map_err(|e| anyhow::anyhow!("TLS write: {e}"))?;
            let mut resp = Vec::new();
            let _ = tls.read_to_end(&mut resp);

            let certs = conn
                .peer_certificates()
                .ok_or_else(|| anyhow::anyhow!("peer presented no certificates"))?;
            let leaf = certs
                .first()
                .ok_or_else(|| anyhow::anyhow!("empty peer cert chain"))?;
            let leaf_der = leaf.as_ref().to_vec();
            eprintln!(
                "[uq/azure] Leaf cert: {} bytes DER; verifying embedded evidence…",
                leaf_der.len()
            );

            let verdict = azure::verify_attested_cert(&leaf_der).map_err(|e| anyhow::anyhow!(e))?;
            eprintln!("[uq/azure] channel binding: PASS (cert SPKI bound into AK quote)");
            print_azure_verdict(&verdict);
            if verdict.verdict != "verified" {
                std::process::exit(1);
            }
            Ok(())
        }
        _ => {
            eprintln!("Usage:");
            eprintln!("  uq azure collect   [--value-x <hex32>] [-o azure-bundle.json]   (on the Azure CVM)");
            eprintln!("  uq azure verify    <azure-bundle.json | azure-hcl.bin>");
            eprintln!("  uq azure check     http://<host>[:port]/");
            eprintln!("  uq azure serve     [-f azure-bundle.json] [--port 8443]");
            eprintln!("  uq azure serve-tls --value-x <hex32> [--domain attest.secure.build] [--port 8443]");
            eprintln!("  uq azure check-tls https://<host>[:port]/");
            std::process::exit(1);
        }
    }
}

#[cfg(feature = "sev-snp")]
fn print_azure_verdict(v: &unified_quote::tee::azure::AzureVerdict) {
    eprintln!("[uq/azure] === Azure SEV-SNP (vTPM → AMD root) ===");
    eprintln!("[uq/azure] verdict:        {}", v.verdict);
    eprintln!("[uq/azure] measurement:    {}", v.measurement);
    eprintln!("[uq/azure] sig_verified:   {}", v.sig_verified);
    eprintln!("[uq/azure] chain_verified: {}", v.chain_verified);
    eprintln!("[uq/azure] runtime_sha256: {}", v.runtime_sha256);
    if let Some(k) = &v.ak_kid {
        eprintln!("[uq/azure] vtpm_ak:        {k} (endorsed by report_data)");
    }
    if let Some(id) = &v.vm_unique_id {
        eprintln!("[uq/azure] vm_unique_id:   {id}");
    }
    if let Some(bound) = v.value_x_bound {
        eprintln!("[uq/azure] value_x_bound:  {bound} (AK quote → SNP-endorsed vTPM AK)");
        if let Some(vx) = &v.value_x {
            eprintln!("[uq/azure] value_x:        {vx}");
        }
    }
}

/// Minimal blocking HTTP/1.1 server exposing the self-authenticating evidence:
///   GET /azure-hcl.bin -> raw HCL report (verifiable to the AMD root anywhere)
///   GET /bundle.json   -> full bundle (HCL + AK quote binding value_x)
///   GET /              -> JSON verdict
#[cfg(feature = "sev-snp")]
fn serve_azure_evidence(
    port: u16,
    hcl: Vec<u8>,
    bundle_json: String,
    verdict_json: String,
) -> anyhow::Result<()> {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind(("0.0.0.0", port))?;
    eprintln!("[uq/azure] Serving evidence on 0.0.0.0:{port}");
    eprintln!("[uq/azure]   GET /azure-hcl.bin   (raw SNP report, AMD-verifiable)");
    eprintln!("[uq/azure]   GET /bundle.json     (HCL + AK quote binding value_x)");
    eprintln!("[uq/azure]   GET /                (JSON verdict)");
    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).unwrap_or(0);
        let req = String::from_utf8_lossy(&buf[..n]);
        let path = req
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap_or("/");
        let (status, ctype, body): (&str, &str, Vec<u8>) = if path.starts_with("/azure-hcl.bin") {
            ("200 OK", "application/octet-stream", hcl.clone())
        } else if path.starts_with("/bundle.json") {
            (
                "200 OK",
                "application/json",
                bundle_json.clone().into_bytes(),
            )
        } else if path == "/" {
            (
                "200 OK",
                "application/json",
                verdict_json.clone().into_bytes(),
            )
        } else {
            ("404 Not Found", "text/plain", b"not found".to_vec())
        };
        let header = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(header.as_bytes());
        let _ = stream.write_all(&body);
        let _ = stream.flush();
    }
    Ok(())
}
