//! Integration test: Real AMD SEV-SNP attestation report → UnifiedQuote → Verify
//!
//! Uses a real attestation report captured from an AMD EPYC 7R13 (c6a.large)
//! running SEV-SNP on AWS EC2 in us-east-2, 2026-04-06.
//!
//! SECURITY NOTE: The signing_key in testdata is a TEST-ONLY ed25519 key whose
//! pubkey hash was baked into the SNP report's REPORT_DATA during capture.
//! It has no security value — the platform quote itself is public. The key
//! exists solely so UnifiedQuote signature verification works in tests.

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha384};
use uq_runner::quote::verify::verify_unified_quote;
use uq_runner::quote::{Platform, UnifiedQuote};

fn load_snp_test_data() -> (Vec<u8>, SigningKey) {
    let json_str =
        std::fs::read_to_string("testdata/snp_attestation.json").expect("testdata not found");
    let data: serde_json::Value = serde_json::from_str(&json_str).unwrap();

    let doc_hex = data["attestation_report"].as_str().unwrap();
    let doc_bytes = hex::decode(doc_hex).unwrap();

    let sk_hex = data["signing_key"].as_str().unwrap();
    let sk_bytes: [u8; 32] = hex::decode(sk_hex).unwrap().try_into().unwrap();
    let signing_key = SigningKey::from_bytes(&sk_bytes);

    (doc_bytes, signing_key)
}

#[test]
fn test_snp_layer2_verification() {
    let (snp_report, signing_key) = load_snp_test_data();
    let value_x: [u8; 48] = Sha384::digest(b"uq-snp-test").into();
    let nonce = [0xEEu8; 32];

    println!("SNP report size: {} bytes", snp_report.len());

    let quote = UnifiedQuote::new(Platform::SevSnp, value_x, snp_report, nonce, &signing_key);

    // Full verification — our test data has no VCEK cert table,
    // so signature verification is incomplete (no cert to verify against).
    // pubkey binding and structural checks pass; crypto sig doesn't.
    let result =
        verify_unified_quote(&quote, Some(&value_x)).expect("SNP verification should pass");

    assert!(result.signature_valid); // Layer 1: ed25519 over UnifiedQuote
                                     // platform_valid = false because we don't have VCEK certs in test data.
                                     // This is the CORRECT behavior — we refuse to claim hardware authenticity
                                     // without a verified signature chain.
    assert!(!result.platform_valid, "should be false without VCEK certs");
    assert_eq!(result.platform, Platform::SevSnp);
    assert_eq!(result.value_x, value_x);

    // Verify that SIG_VERIFIED measurement reflects the actual state
    let sig_verified = result
        .measurements
        .iter()
        .find(|(k, _)| k == "SIG_VERIFIED")
        .map(|(_, v)| v[0])
        .unwrap_or(0);
    assert_eq!(sig_verified, 0, "sig should not be verified without VCEK");

    println!("=== AMD SEV-SNP LAYER 2 VERIFICATION ===");
    for (name, value) in &result.measurements {
        println!("  {}: {}", name, hex::encode(value));
    }
    println!(
        "  Platform valid: {} (expected false without VCEK)",
        result.platform_valid
    );
    println!("  Note: pubkey binding verified, signature verification requires VCEK cert");
    println!("=== STRUCTURAL CHECK PASSED ===");
}

#[test]
fn test_snp_and_nitro_same_value_x() {
    // Prove that the same Value X comes out regardless of platform
    let (snp_report, snp_key) = load_snp_test_data();

    let nitro_json =
        std::fs::read_to_string("testdata/nitro_attestation.json").expect("nitro testdata");
    let nitro_data: serde_json::Value = serde_json::from_str(&nitro_json).unwrap();
    let nitro_doc = hex::decode(nitro_data["attestation_doc"].as_str().unwrap()).unwrap();
    let nitro_sk_bytes: [u8; 32] = hex::decode(nitro_data["signing_key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let nitro_key = SigningKey::from_bytes(&nitro_sk_bytes);

    // Same Value X for both
    let value_x: [u8; 48] = Sha384::digest(b"same-runner-image-hash").into();
    let nonce = [0x42u8; 32];

    let q_snp = UnifiedQuote::new(Platform::SevSnp, value_x, snp_report, nonce, &snp_key);
    let q_nitro = UnifiedQuote::new(Platform::Nitro, value_x, nitro_doc, nonce, &nitro_key);

    // Both have same Value X
    assert_eq!(q_snp.value_x, q_nitro.value_x);
    assert_eq!(q_snp.value_x, value_x);

    // Both pass structural verification
    let r_snp = verify_unified_quote(&q_snp, Some(&value_x)).expect("SNP verify");
    let r_nitro = verify_unified_quote(&q_nitro, Some(&value_x)).expect("Nitro verify");

    // SNP: no VCEK certs in test data, so platform_valid=false
    assert!(
        !r_snp.platform_valid,
        "SNP needs VCEK for full verification"
    );
    // Nitro: COSE signature + cert chain verified
    assert!(r_nitro.platform_valid);

    // Different platforms, same X
    assert_eq!(r_snp.platform, Platform::SevSnp);
    assert_eq!(r_nitro.platform, Platform::Nitro);
    assert_eq!(r_snp.value_x, r_nitro.value_x);

    // Different platform quote hashes (structurally different quotes)
    assert_ne!(q_snp.platform_quote_hash, q_nitro.platform_quote_hash);

    println!("=== CROSS-PLATFORM HARMONIZATION (REAL DATA) ===");
    println!("Value X (identical): {}", hex::encode(value_x));
    println!(
        "SNP quote hash:   {}",
        hex::encode(q_snp.platform_quote_hash)
    );
    println!(
        "Nitro quote hash: {}",
        hex::encode(q_nitro.platform_quote_hash)
    );
    println!(
        "Both Layer 2 verified: SNP={}, Nitro={}",
        r_snp.platform_valid, r_nitro.platform_valid
    );
    println!("=== HARMONIZED ===");
}
