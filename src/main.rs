//! uq-runner: Attestation wrapper for GitHub Actions self-hosted runners.
//!
//! This binary:
//! 1. Detects which TEE it's running in (Nitro / SEV-SNP / TDX)
//! 2. Computes Value X (deterministic hash of the runner image — LATTE Layer 1)
//! 3. Generates a TEE-derived signing key
//! 4. Binds Value X + signing key into the TEE attestation report
//! 5. Produces a UnifiedQuote (the "one ring" format)
//! 6. Starts the GitHub Actions runner as a subprocess
//! 7. Serves a /attest endpoint for remote verification
//!
//! The UnifiedQuote can be submitted to an on-chain oracle so that:
//! - Anyone can verify the runner's identity (Value X) across platforms
//! - The platform quote proves the runner is inside a genuine TEE
//! - The ed25519 signature ties everything together

mod attest;
mod compat;
mod integrity;
mod quote;
mod registry;
mod tee;

use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use quote::{UnifiedQuote, value_x};
use tee::detect::detect_tee;

/// Default port for the attestation endpoint.
const ATTEST_PORT: u16 = 9384;

/// Default path to the GitHub Actions runner.
const DEFAULT_RUNNER_DIR: &str = "/opt/actions-runner";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let runner_dir = std::env::var("RUNNER_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_RUNNER_DIR));

    let attest_port: u16 = std::env::var("ATTEST_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(ATTEST_PORT);

    // --- Step 1: Detect TEE platform ---
    // Fail closed: with no TEE there is no hardware root of trust, so there is
    // nothing to attest. We refuse to run rather than serve an unattested
    // ("insecure mode") endpoint — there is no flag or env var to override this.
    eprintln!("[uq] Detecting TEE platform...");
    let p = detect_tee().map_err(|e| {
        anyhow::anyhow!(
            "no TEE detected ({e}): unified-quote requires a hardware TEE \
             (AMD SEV-SNP, Intel TDX, or AWS Nitro). Refusing to start without a \
             root of trust."
        )
    })?;
    eprintln!("[uq] Detected: {:?}", p.platform());
    let tee_provider = Some(p);

    // --- Step 2: Compute Value X ---
    eprintln!("[uq] Computing Value X from {}...", runner_dir.display());
    let value_x_hash = value_x::compute_value_x(&runner_dir)?;
    eprintln!("[uq] Value X = {}", hex::encode(value_x_hash));

    // --- Step 3: Generate TEE-derived signing key ---
    // In production, this key should be derived deterministically from
    // TEE sealing key + value_x, so the same runner always produces
    // the same pubkey. For the prototype, we generate a fresh key.
    let signing_key = SigningKey::generate(&mut OsRng);
    let pubkey_bytes = signing_key.verifying_key().to_bytes();
    eprintln!(
        "[uq] TEE signing pubkey = {}",
        hex::encode(pubkey_bytes)
    );

    // --- Step 4: Bind value_x + pubkey into TEE report_data ---
    // report_data layout (64 bytes):
    //   [0..32]  = sha256(pubkey || value_x)  — binds BOTH to the hardware quote
    //   [32..64] = value_x[0..32]             — first 32 bytes of Value X for direct extraction
    //
    // The verifier checks:
    //   report_data[0..32] == sha256(quote.pubkey || quote.value_x)
    // This proves the pubkey AND value_x were committed to the TEE at quote time.
    let mut binding = Vec::with_capacity(32 + 48);
    binding.extend_from_slice(&pubkey_bytes);
    binding.extend_from_slice(&value_x_hash);
    let binding_hash: [u8; 32] = Sha256::digest(&binding).into();

    let mut report_data = [0u8; 64];
    report_data[..32].copy_from_slice(&binding_hash);
    report_data[32..64].copy_from_slice(&value_x_hash[..32]);

    // --- Step 5: Collect TEE evidence and build UnifiedQuote ---
    let initial_quote = if let Some(ref provider) = tee_provider {
        match provider.collect_evidence(&report_data) {
            Ok(evidence) => {
                let nonce: [u8; 32] = rand::random();
                let uq = UnifiedQuote::new(
                    evidence.platform,
                    value_x_hash,
                    evidence.raw_quote,
                    nonce,
                    &signing_key,
                );
                eprintln!("[uq] UnifiedQuote generated.");
                Some(uq)
            }
            Err(e) => {
                eprintln!("[uq] WARNING: Failed to collect TEE evidence: {e}");
                None
            }
        }
    } else {
        None
    };

    // --- Step 6: Start attestation endpoint ---
    let signing_key_clone = signing_key.clone();
    let value_x_clone = value_x_hash;
    let tee_provider_for_refresh: Option<Arc<dyn tee::TeeProvider>> =
        tee_provider.map(|p| Arc::from(p));
    let tee_provider_ref = tee_provider_for_refresh.clone();

    let attest_state = Arc::new(attest::AttestState::new(
        initial_quote,
        Box::new(move |challenge_nonce: Option<[u8; 32]>| {
            let provider = tee_provider_ref
                .as_ref()
                .ok_or_else(|| "no TEE available".to_string())?;

            let mut rd = [0u8; 64];
            let pk = signing_key_clone.verifying_key().to_bytes();
            let mut bind = Vec::with_capacity(32 + 48);
            bind.extend_from_slice(&pk);
            bind.extend_from_slice(&value_x_clone);
            let bh: [u8; 32] = Sha256::digest(&bind).into();
            rd[..32].copy_from_slice(&bh);
            rd[32..64].copy_from_slice(&value_x_clone[..32]);

            let evidence = provider
                .collect_evidence(&rd)
                .map_err(|e| e.to_string())?;

            // Use verifier's challenge nonce if provided, otherwise generate one.
            // A verifier-provided nonce proves freshness (challenge-response).
            // A self-generated nonce only prevents replay across different verifiers.
            let nonce = challenge_nonce.unwrap_or_else(|| rand::random());
            Ok(UnifiedQuote::new(
                evidence.platform,
                value_x_clone,
                evidence.raw_quote,
                nonce,
                &signing_key_clone,
            ))
        }),
    ));

    let app = attest::attestation_router(attest_state);
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{attest_port}")).await?;
    eprintln!("[uq] Attestation endpoint listening on :{attest_port}");

    // Spawn the attestation server in the background
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    // --- Step 7: Start the GitHub Actions runner ---
    eprintln!("[uq] Starting GitHub Actions runner...");
    let runner_bin = runner_dir.join("run.sh");

    if runner_bin.exists() {
        let status = Command::new(&runner_bin)
            .current_dir(&runner_dir)
            .env("UQ_VALUE_X", hex::encode(value_x_hash))
            .env("UQ_ATTEST_PORT", attest_port.to_string())
            .status()?;

        eprintln!("[uq] Runner exited with: {status}");
    } else {
        eprintln!(
            "[uq] Runner not found at {}. Running attestation endpoint only.",
            runner_bin.display()
        );
        // Keep the process alive for the attestation endpoint
        tokio::signal::ctrl_c().await?;
    }

    Ok(())
}
