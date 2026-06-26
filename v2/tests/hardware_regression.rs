//! Hardware regression tests.
//!
//! Loads real attestation.cbor bytes captured from live TEE instances
//! and verifies them through the full production path:
//!
//! 1. `EatToken::from_cbor` decodes the bytes.
//! 2. `eat.binding_bytes()` is recomputed from the stored fields.
//! 3. `verify_platform_quote` is called with that binding — which
//!    checks BOTH the report_data binding AND the platform's
//!    vendor-signature chain against the pinned root CA (Intel for
//!    TDX, AMD for SNP, AWS Nitro Root CA for Nitro).
//!
//! If this test fails after any change to `eat.rs`, `quote/verify.rs`,
//! or the cmd_build / cmd_run producer flow, it means the chain
//! produced on real hardware won't round-trip through the verifier
//! any more.
//!
//! ## Testdata provenance
//!
//! Captured 2026-04-14 during the first end-to-end hardware pass:
//!
//! - `tdx_stage0.cbor` / `tdx_stage1.cbor` — GCP c3-standard-4 TDX,
//!   us-central1-a, Linux 6.17, stage 0 via `uq build`, stage 1
//!   via `uq run` chaining stage 0.
//! - `snp_stage0.cbor` / `snp_stage1.cbor` — AWS c6a.xlarge SEV-SNP,
//!   us-east-2, Ubuntu 24.04, same flow.
//! - `nitro_stage0.cbor` — AWS m5.xlarge Nitro enclave (single-process
//!   `uq enclave`), AL2023 parent, debug-mode enclave. No
//!   stage 1 on Nitro in this pass — the single-enclave flow produces
//!   a stage 0 only. Chain-walking on Nitro is a follow-up that needs
//!   a second enclave running `cmd_run`.

use unified_quote::eat::EatToken;
use unified_quote::quote::{verify::verify_platform_quote, Platform};
use std::fs;

fn load(name: &str) -> Vec<u8> {
    let path = format!("testdata/chain/{name}");
    fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

fn verify_full_path(cbor: &[u8], expected_platform: Platform) {
    let eat = EatToken::from_cbor(cbor).unwrap_or_else(|e| panic!("decode EAT: {e}"));

    assert_eq!(eat.platform_enum(), Some(expected_platform));
    assert!(!eat.value_x.iter().all(|b| *b == 0), "value_x is zeros");
    assert!(!eat.platform_quote.is_empty(), "platform_quote empty");

    let binding = eat.binding_bytes();
    verify_platform_quote(expected_platform, &eat.platform_quote, &binding).unwrap_or_else(|e| {
        panic!(
            "verify_platform_quote failed for {:?}: {e}\n\
                 binding={}",
            expected_platform,
            hex::encode(binding)
        )
    });
}

#[cfg(feature = "tdx")]
#[test]
fn tdx_stage0_verifies() {
    verify_full_path(&load("tdx_stage0.cbor"), Platform::Tdx);
}

#[cfg(feature = "tdx")]
#[test]
fn tdx_stage1_verifies_and_chains_to_stage0() {
    let cbor = load("tdx_stage1.cbor");
    let eat = EatToken::from_cbor(&cbor).unwrap();
    assert!(eat.has_previous(), "stage 1 must have a previous stage");

    // Leaf verifies against its own binding
    let binding = eat.binding_bytes();
    verify_platform_quote(Platform::Tdx, &eat.platform_quote, &binding).unwrap();

    // Previous decodes and its binding matches the committed hash
    let prev = eat.decode_previous().unwrap().expect("stage 0");
    assert_eq!(
        prev.value_x, eat.value_x,
        "Value X must be stable across chain"
    );
    assert_eq!(prev.platform_enum(), Some(Platform::Tdx));

    // Previous verifies against its own binding
    let prev_binding = prev.binding_bytes();
    verify_platform_quote(Platform::Tdx, &prev.platform_quote, &prev_binding).unwrap();
}

// These fixtures do not carry the AMD certificate table, so full SNP
// signature-chain verification currently calls AMD KDS. Keep that live
// vendor dependency out of ordinary `cargo test`.
#[cfg(feature = "sev-snp")]
#[test]
#[ignore = "requires live AMD KDS access"]
fn snp_stage0_verifies() {
    verify_full_path(&load("snp_stage0.cbor"), Platform::SevSnp);
}

#[cfg(feature = "sev-snp")]
#[test]
#[ignore = "requires live AMD KDS access"]
fn snp_stage1_verifies_and_chains_to_stage0() {
    let cbor = load("snp_stage1.cbor");
    let eat = EatToken::from_cbor(&cbor).unwrap();
    assert!(eat.has_previous());

    let binding = eat.binding_bytes();
    verify_platform_quote(Platform::SevSnp, &eat.platform_quote, &binding).unwrap();

    let prev = eat.decode_previous().unwrap().expect("stage 0");
    assert_eq!(prev.value_x, eat.value_x);
    assert_eq!(prev.platform_enum(), Some(Platform::SevSnp));
    let prev_binding = prev.binding_bytes();
    verify_platform_quote(Platform::SevSnp, &prev.platform_quote, &prev_binding).unwrap();
}

#[cfg(feature = "nitro")]
#[test]
fn nitro_stage0_verifies() {
    // Nitro cmd_enclave produces stage 0 only; no chain to walk.
    verify_full_path(&load("nitro_stage0.cbor"), Platform::Nitro);
}

/// The ouroboros run: this attestation.cbor was produced by the
/// self-hosted GitHub Actions workflow `attested-self-build.yml`
/// running on a GCP TDX instance, on 2026-04-14, in response to the
/// push of commit 2593db6 which added that very workflow file. This
/// is the first time unified-quote was built inside a TEE *as a CI step
/// of its own repository*, rather than by a hand-typed SSH command.
///
/// Keeping this byte-identical copy in testdata is an archival
/// record: it's the exact attestation that proved the ouroboros
/// closed. The test verifies it through the same
/// `verify_platform_quote` path as every other TDX testdata entry.
#[cfg(feature = "tdx")]
#[test]
fn ouroboros_attestation_verifies() {
    verify_full_path(&load("tdx_ouroboros.cbor"), Platform::Tdx);
}

#[cfg(all(feature = "tdx", feature = "sev-snp", feature = "nitro"))]
#[test]
fn all_three_platforms_share_no_cross_contamination() {
    // Sanity: each platform's bytes decode to its own platform
    // discriminant. Guards against accidentally committing the wrong
    // file under the wrong name.
    let tdx = EatToken::from_cbor(&load("tdx_stage0.cbor")).unwrap();
    let snp = EatToken::from_cbor(&load("snp_stage0.cbor")).unwrap();
    let nit = EatToken::from_cbor(&load("nitro_stage0.cbor")).unwrap();
    assert_eq!(tdx.platform_enum(), Some(Platform::Tdx));
    assert_eq!(snp.platform_enum(), Some(Platform::SevSnp));
    assert_eq!(nit.platform_enum(), Some(Platform::Nitro));
}
