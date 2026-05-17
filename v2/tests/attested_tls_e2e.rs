//! End-to-end test for attested-TLS cert generation + extraction.
//!
//! Exercises the full producer side:
//!   keypair → SPKI hash → partial EAT → binding_bytes
//!   → (simulated) quote containing binding_bytes in report_data
//!   → final EAT → CBOR → self-signed cert with EAT extension
//!
//! Then the full verifier side:
//!   cert → extract EAT extension → decode EAT
//!   → recompute binding_bytes → check against quote report_data
//!   → recompute SPKI hash from cert → check against eat.tls_spki_hash
//!
//! The only thing missing from a real hardware run is the platform
//! quote signature chain — the "quote" here is a fabricated blob whose
//! first 32 bytes are the expected binding. Once a real TEE runs
//! `bountynet enclave`, the same flow produces a genuine quote whose
//! AMD/Intel signature chain verifies.

use bountynet::eat::{BuildComponents, EatToken};
use bountynet::net::attested_tls::{
    extract_eat_from_cert, generate_keypair, make_attested_cert, spki_hash_of, spki_hash_of_cert,
};
use bountynet::quote::Platform;

/// Fabricate a 1152-byte "SNP-shaped" blob whose report_data slot
/// contains the given binding. Not a valid attestation, but has the
/// exact layout property that matters for attested-TLS channel binding.
fn fake_quote_with_report_data(binding: &[u8; 32]) -> Vec<u8> {
    let mut q = vec![0u8; 1152];
    // SNP report_data is at offset 0x50 (80), 64 bytes.
    q[0x50..0x50 + 32].copy_from_slice(binding);
    q
}

#[test]
fn full_attested_tls_production_and_verification_cycle() {
    // --- producer side ---
    let kp = generate_keypair().unwrap();
    let tls_spki_hash = spki_hash_of(&kp);

    let mut eat_partial = EatToken::from_build(BuildComponents {
        platform: Platform::SevSnp,
        value_x: [0xa1u8; 48],
        source_hash: [0xb2u8; 48],
        artifact_hash: [0xc3u8; 48],
        platform_measurement: Vec::new(),
        platform_quote: Vec::new(),
    });
    eat_partial.tls_spki_hash = tls_spki_hash;

    let binding = eat_partial.binding_bytes();

    // Simulate quote collection: build a quote whose report_data
    // contains the binding we committed to.
    let fake_quote = fake_quote_with_report_data(&binding);

    let mut eat = eat_partial;
    eat.platform_quote = fake_quote.clone();
    eat.platform_measurement = fake_quote[0x090..0x090 + 48].to_vec();

    // Finalization MUST NOT change binding_bytes
    assert_eq!(
        eat.binding_bytes(),
        binding,
        "binding invariant broken: finalized EAT hashes to a different value"
    );

    let eat_cbor = eat.to_cbor().unwrap();
    let cert = make_attested_cert(&kp, "ra-tls.test.local", &eat_cbor).unwrap();

    // --- verifier side ---
    // Step 1: extract the EAT from the cert extension
    let recovered_cbor = extract_eat_from_cert(&cert.cert_der)
        .unwrap()
        .expect("cert must contain an EAT extension");
    assert_eq!(recovered_cbor, eat_cbor);

    // Step 2: decode the EAT
    let recovered_eat = EatToken::from_cbor(&recovered_cbor).unwrap();

    // Step 3: recompute binding from the decoded token
    let recomputed = recovered_eat.binding_bytes();
    assert_eq!(
        recomputed, binding,
        "verifier's recomputed binding disagrees with producer's"
    );

    // Step 4: binding MUST match report_data[0..32] in the embedded quote
    assert_eq!(
        &recovered_eat.platform_quote[0x50..0x50 + 32],
        &recomputed,
        "quote report_data does not contain the EAT binding — attestation is forged"
    );

    // Step 5: SPKI hash from the cert matches eat.tls_spki_hash
    let cert_spki = spki_hash_of_cert(&cert.cert_der).unwrap();
    assert_eq!(
        cert_spki, recovered_eat.tls_spki_hash,
        "TLS channel binding broken: cert SPKI hash differs from EAT claim"
    );
}

#[test]
fn swapping_cert_key_breaks_channel_binding() {
    // The attacker's game: replace the cert but keep the EAT. If they
    // can sign a new cert with a different key, a naive verifier that
    // only checks the EAT's internal consistency would pass — unless
    // the verifier *also* compares spki_hash_of_cert(cert) against
    // eat.tls_spki_hash. This test demonstrates that comparison.

    let legit_kp = generate_keypair().unwrap();
    let tls_spki_hash = spki_hash_of(&legit_kp);

    let mut eat = EatToken::from_build(BuildComponents {
        platform: Platform::Nitro,
        value_x: [0x01u8; 48],
        source_hash: [0x02u8; 48],
        artifact_hash: [0x03u8; 48],
        platform_measurement: vec![0x04u8; 48],
        platform_quote: vec![0x05u8; 512],
    });
    eat.tls_spki_hash = tls_spki_hash;

    let eat_cbor = eat.to_cbor().unwrap();

    // The attacker resigns the *same* EAT bytes with a *different* key.
    // Nothing about the EAT's internal state changes — only who signed
    // the X.509 outer layer.
    let attacker_kp = generate_keypair().unwrap();
    let evil_cert = make_attested_cert(&attacker_kp, "evil.test.local", &eat_cbor).unwrap();

    // The attacker's cert successfully contains the EAT
    let recovered = extract_eat_from_cert(&evil_cert.cert_der).unwrap().unwrap();
    assert_eq!(recovered, eat_cbor);

    // But the SPKI hash check catches the swap
    let evil_spki = spki_hash_of_cert(&evil_cert.cert_der).unwrap();
    assert_ne!(
        evil_spki, tls_spki_hash,
        "attacker's cert should hash to something different from the legit key"
    );
}

#[test]
fn different_builds_produce_different_bindings() {
    // Sanity: two builds with different value_x produce different
    // bindings, which means report_data would differ, which means
    // the two cannot be confused for each other.
    let kp = generate_keypair().unwrap();
    let spki = spki_hash_of(&kp);

    let base = EatToken::from_build(BuildComponents {
        platform: Platform::Tdx,
        value_x: [0x11u8; 48],
        source_hash: [0x22u8; 48],
        artifact_hash: [0x33u8; 48],
        platform_measurement: Vec::new(),
        platform_quote: Vec::new(),
    });

    let mut a = base.clone();
    a.tls_spki_hash = spki;
    let binding_a = a.binding_bytes();

    let mut b = base;
    b.tls_spki_hash = spki;
    b.value_x = [0x99u8; 48];
    let binding_b = b.binding_bytes();

    assert_ne!(binding_a, binding_b);
}
