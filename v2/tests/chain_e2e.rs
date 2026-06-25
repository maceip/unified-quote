//! Stage 0 → Stage 1 chain end-to-end test.
//!
//! Exercises Attestable Containers contribution #6 (build-to-runtime
//! chain) without hardware:
//!
//! 1. Build a stage 0 EAT with a fake SNP-shaped quote whose
//!    `report_data[0..32]` contains the stage 0 EAT's `binding_bytes()`.
//! 2. Build a stage 1 EAT that:
//!    - Has the same Value X (runtime runs builder's output)
//!    - Has `set_previous(stage0_cbor)` populating the chain link
//!    - Has its own `binding_bytes()` committing to
//!      `sha256(stage0_cbor)` via `previous_hash()`
//! 3. Collect a fake stage 1 quote whose `report_data[0..32]` matches
//!    stage 1's binding.
//! 4. Walk the chain from stage 1: confirm Value X is stable, confirm
//!    `decode_previous()` yields stage 0, confirm stage 0's quote
//!    still matches its own binding.
//!
//! What this test does NOT do (and cannot, without hardware):
//! - Verify the platform quote's SIGNATURE chain against vendor roots.
//!   The fake quotes are shaped correctly (right offsets, right
//!   report_data contents) but not signed — so `verify_platform_quote`
//!   would reject them. The test therefore asserts the chain walk's
//!   PURE logic (Value X stability, binding hash chaining,
//!   `decode_previous` behavior, tamper detection) without calling
//!   the signature verifier.
//!
//! What the live hardware test adds on top is exactly and only the
//! signature verification — everything else is exercised here.

use unified_quote::eat::{BuildComponents, EatToken};
use unified_quote::quote::Platform;
use sha2::{Digest, Sha256};

/// SNP-shaped quote: 1152 bytes, `report_data` slot at offset 0x50.
fn fake_snp_quote_with_binding(binding: &[u8; 32]) -> Vec<u8> {
    let mut q = vec![0u8; 1152];
    q[0x50..0x50 + 32].copy_from_slice(binding);
    q
}

fn build_stage0(value_x: [u8; 48]) -> EatToken {
    let mut t = EatToken::from_build(BuildComponents {
        platform: Platform::SevSnp,
        value_x,
        source_hash: [0xab; 48],
        artifact_hash: [0xcd; 48],
        platform_measurement: Vec::new(),
        platform_quote: Vec::new(),
    });
    // Stage 0 has no TLS key binding — tls_spki_hash stays zero.
    // binding_bytes commits to that zero.
    let binding = t.binding_bytes();
    t.platform_quote = fake_snp_quote_with_binding(&binding);
    t.platform_measurement = t.platform_quote[0x090..0x090 + 48].to_vec();
    t
}

fn build_stage1(stage0_cbor: Vec<u8>, value_x: [u8; 48]) -> EatToken {
    let mut t = EatToken::from_build(BuildComponents {
        platform: Platform::SevSnp,
        value_x,
        source_hash: [0xab; 48],
        artifact_hash: [0xcd; 48],
        platform_measurement: Vec::new(),
        platform_quote: Vec::new(),
    });
    t.tls_spki_hash = [0x77u8; 32]; // some fake but stable key hash
    t.set_previous(stage0_cbor);
    let binding = t.binding_bytes();
    t.platform_quote = fake_snp_quote_with_binding(&binding);
    t.platform_measurement = t.platform_quote[0x090..0x090 + 48].to_vec();
    t
}

#[test]
fn two_stage_chain_walks_correctly() {
    let value_x = [0x11u8; 48];

    let stage0 = build_stage0(value_x);
    let stage0_cbor = stage0.to_cbor().unwrap();

    let stage1 = build_stage1(stage0_cbor.clone(), value_x);
    let stage1_cbor = stage1.to_cbor().unwrap();

    // --- walk the chain ---
    let leaf = EatToken::from_cbor(&stage1_cbor).unwrap();

    assert!(leaf.has_previous(), "stage 1 should have a previous stage");

    // leaf's quote contains leaf's binding in report_data
    let leaf_binding = leaf.binding_bytes();
    assert_eq!(
        &leaf.platform_quote[0x50..0x50 + 32],
        &leaf_binding,
        "leaf's report_data must equal its binding"
    );

    // decode the previous
    let prev = leaf.decode_previous().unwrap().expect("stage 0 present");

    // Value X must be stable
    assert_eq!(prev.value_x, leaf.value_x);

    // previous_hash commitment
    let expected_prev_hash: [u8; 32] = Sha256::digest(&stage0_cbor).into();
    assert_eq!(leaf.previous_hash(), expected_prev_hash);

    // prev's own binding matches prev's report_data
    let prev_binding = prev.binding_bytes();
    assert_eq!(
        &prev.platform_quote[0x50..0x50 + 32],
        &prev_binding,
        "stage 0's report_data must equal its binding"
    );

    // stage 0 is the root
    assert!(!prev.has_previous());
}

#[test]
fn chain_detects_stage0_tampering() {
    // An attacker swaps in a different stage 0 attestation (different
    // Value X, different everything). Stage 1's binding — which
    // includes sha256(previous_attestation) — would no longer match
    // stage 1's report_data, catching the swap.
    let value_x = [0x22u8; 48];

    let legit_stage0 = build_stage0(value_x);
    let legit_stage0_cbor = legit_stage0.to_cbor().unwrap();

    let stage1 = build_stage1(legit_stage0_cbor.clone(), value_x);

    // Attacker substitutes a different stage 0
    let evil_stage0 = build_stage0([0x99u8; 48]);
    let evil_stage0_cbor = evil_stage0.to_cbor().unwrap();

    let mut tampered_stage1 = stage1.clone();
    tampered_stage1.previous_attestation = evil_stage0_cbor;

    // The stored platform_quote still has the binding that committed
    // to the ORIGINAL stage 0. But binding_bytes() now recomputes
    // with the EVIL stage 0's hash mixed in. They diverge.
    let stored_rd = &tampered_stage1.platform_quote[0x50..0x50 + 32];
    let recomputed = tampered_stage1.binding_bytes();
    assert_ne!(
        stored_rd, &recomputed,
        "tampering with previous_attestation must break binding check"
    );
}

#[test]
fn chain_detects_value_x_drift() {
    // An attacker tries to claim stage 1 runs different code than
    // stage 0. This would only work if their stage 0 was legit but
    // the runtime was different — a real attack vector. The chain
    // walker explicitly asserts Value X is stable across the chain.
    let v0 = [0x33u8; 48];
    let v1 = [0x44u8; 48];

    let stage0 = build_stage0(v0);
    let stage0_cbor = stage0.to_cbor().unwrap();

    // Stage 1 claims a DIFFERENT Value X than stage 0
    let drifted = build_stage1(stage0_cbor, v1);

    let prev = drifted.decode_previous().unwrap().unwrap();
    assert_ne!(prev.value_x, drifted.value_x);
    // The chain walker in cmd_check bails when it sees this.
    // Here we just confirm the mismatch is detectable at the data level.
}

#[test]
fn chain_binding_survives_quote_fill() {
    // This is the same invariant the EAT unit tests cover, but
    // exercised through the full chain construction flow: the
    // binding committed BEFORE stage 1's quote is collected must
    // equal the binding after the quote bytes are written back.
    let value_x = [0x55u8; 48];
    let stage0 = build_stage0(value_x);
    let stage0_cbor = stage0.to_cbor().unwrap();

    let mut stage1 = EatToken::from_build(BuildComponents {
        platform: Platform::SevSnp,
        value_x,
        source_hash: [0xab; 48],
        artifact_hash: [0xcd; 48],
        platform_measurement: Vec::new(),
        platform_quote: Vec::new(),
    });
    stage1.tls_spki_hash = [0x88u8; 32];
    stage1.set_previous(stage0_cbor);

    let pre_binding = stage1.binding_bytes();
    stage1.platform_quote = fake_snp_quote_with_binding(&pre_binding);
    stage1.platform_measurement = stage1.platform_quote[0x090..0x090 + 48].to_vec();
    let post_binding = stage1.binding_bytes();

    assert_eq!(pre_binding, post_binding);
    assert_eq!(
        &stage1.platform_quote[0x50..0x50 + 32],
        &post_binding,
        "stage 1's report_data must equal its binding after fill"
    );
}

#[test]
fn three_stage_chain_also_walks() {
    // Future-proof: the chain format is recursive. A three-stage
    // chain (e.g., source → build → runtime → overlay) walks the
    // same way. No limit logic in the core; cmd_check imposes a
    // depth cap of 16 at the call site.
    let value_x = [0x66u8; 48];

    let stage0 = build_stage0(value_x);
    let stage0_cbor = stage0.to_cbor().unwrap();

    let stage1 = build_stage1(stage0_cbor, value_x);
    let stage1_cbor = stage1.to_cbor().unwrap();

    let stage2 = build_stage1(stage1_cbor, value_x);

    // Walk from the leaf
    let prev = stage2.decode_previous().unwrap().unwrap();
    assert_eq!(prev.value_x, stage2.value_x);
    assert!(prev.has_previous());

    let root = prev.decode_previous().unwrap().unwrap();
    assert_eq!(root.value_x, stage2.value_x);
    assert!(!root.has_previous());
}
