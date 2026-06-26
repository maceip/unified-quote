//! Integration test: Real Nitro attestation document → UnifiedQuote → Verify
//!
//! This test uses a real attestation document captured from a Nitro Enclave
//! on 2026-04-06 to prove the end-to-end harmonized flow works.
//!
//! SECURITY NOTE: signing_key in testdata is TEST-ONLY (pubkey hash baked into
//! the Nitro doc's user_data during capture). No security value.
//!
//! 1. Parse raw Nitro COSE_Sign1 attestation doc
//! 2. Wrap it in a UnifiedQuote with Value X
//! 3. Sign with the enclave-derived key
//! 4. Verify the UnifiedQuote signature
//! 5. Extract Value X — same value regardless of platform
//! 6. Produce the on-chain compact form (~180 bytes)

use uq_runner::quote::verify::{verify_unified_quote, VerifyError};
use uq_runner::quote::{OnChainAttestation, Platform, UnifiedQuote};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256, Sha384};

/// Load the real Nitro attestation data captured from hardware.
fn load_nitro_test_data() -> (Vec<u8>, SigningKey) {
    let json_str =
        std::fs::read_to_string("testdata/nitro_attestation.json").expect("testdata not found");
    let data: serde_json::Value = serde_json::from_str(&json_str).unwrap();

    let doc_hex = data["attestation_doc"].as_str().unwrap();
    let doc_bytes = hex::decode(doc_hex).unwrap();

    let sk_hex = data["signing_key"].as_str().unwrap();
    let sk_bytes: [u8; 32] = hex::decode(sk_hex).unwrap().try_into().unwrap();
    let signing_key = SigningKey::from_bytes(&sk_bytes);

    (doc_bytes, signing_key)
}

#[test]
fn test_nitro_to_unified_quote_roundtrip() {
    let (nitro_doc, signing_key) = load_nitro_test_data();

    // Compute a fake Value X (in production this would be sha384 of the runner image)
    let value_x: [u8; 48] = Sha384::digest(b"bountynet-runner-v0.1.0-test").into();
    let nonce: [u8; 32] = Sha256::digest(b"test-nonce-anti-replay").into();

    // --- Step 1: Wrap raw Nitro doc into UnifiedQuote ---
    let quote = UnifiedQuote::new(
        Platform::Nitro,
        value_x,
        nitro_doc.clone(),
        nonce,
        &signing_key,
    );

    // Verify basic structure
    assert_eq!(quote.version, 1);
    assert_eq!(quote.platform, Platform::Nitro);
    assert_eq!(quote.value_x, value_x);
    assert!(quote.platform_quote.is_some());
    assert_eq!(quote.platform_quote.as_ref().unwrap().len(), 4555); // Real Nitro doc size

    // --- Step 2: Verify signature ---
    assert!(
        quote.verify_signature().is_ok(),
        "UnifiedQuote signature verification failed"
    );

    // --- Step 3: Verify platform_quote_hash links to raw doc ---
    let expected_hash: [u8; 32] = Sha256::digest(&nitro_doc).into();
    assert_eq!(
        quote.platform_quote_hash, expected_hash,
        "Platform quote hash doesn't match"
    );

    // --- Step 4: Extract Value X (platform-agnostic!) ---
    // This is the key insight: regardless of whether this came from
    // Nitro, TDX, or SNP, value_x is the same deterministic hash.
    assert_eq!(quote.value_x, value_x);
    println!("Value X: {}", hex::encode(quote.value_x));

    // --- Step 5: Produce on-chain compact form ---
    let compact = quote.compact();
    assert!(compact.platform_quote.is_none()); // Raw quote stripped
    assert!(compact.verify_signature().is_ok()); // Signature still valid

    let on_chain = OnChainAttestation::from(&quote);
    let on_chain_json = serde_json::to_string(&on_chain).unwrap();
    println!("On-chain JSON size: {} bytes", on_chain_json.len());
    println!("On-chain: {}", on_chain_json);

    // Verify the on-chain form contains everything needed
    assert_eq!(on_chain.value_x, value_x);
    assert_eq!(on_chain.platform_quote_hash, expected_hash);
    assert_eq!(on_chain.pubkey, signing_key.verifying_key().to_bytes());
}

#[test]
fn test_unified_quote_is_platform_agnostic() {
    // The same Value X wrapped in different platform quotes
    // should produce verifiable UnifiedQuotes with identical value_x.

    let value_x: [u8; 48] = Sha384::digest(b"same-runner-on-any-platform").into();

    // Simulate three different platform quotes (using dummy data for TDX/SNP)
    let fake_nitro_doc = vec![0x84, 0x44]; // COSE_Sign1 header bytes
    let fake_tdx_quote = vec![0x04, 0x00]; // TDX Quote v4 header
    let fake_snp_report = vec![0x02, 0x00]; // SNP report version

    let key1 = SigningKey::from_bytes(&[1u8; 32]);
    let key2 = SigningKey::from_bytes(&[2u8; 32]);
    let key3 = SigningKey::from_bytes(&[3u8; 32]);

    let nonce = [0x42u8; 32];

    let q_nitro = UnifiedQuote::new(Platform::Nitro, value_x, fake_nitro_doc, nonce, &key1);
    let q_tdx = UnifiedQuote::new(Platform::Tdx, value_x, fake_tdx_quote, nonce, &key2);
    let q_snp = UnifiedQuote::new(Platform::SevSnp, value_x, fake_snp_report, nonce, &key3);

    // All three have the SAME Value X
    assert_eq!(q_nitro.value_x, q_tdx.value_x);
    assert_eq!(q_tdx.value_x, q_snp.value_x);
    assert_eq!(q_nitro.value_x, value_x);

    // All three have valid signatures (different keys, same Value X)
    assert!(q_nitro.verify_signature().is_ok());
    assert!(q_tdx.verify_signature().is_ok());
    assert!(q_snp.verify_signature().is_ok());

    // Different platforms
    assert_eq!(q_nitro.platform, Platform::Nitro);
    assert_eq!(q_tdx.platform, Platform::Tdx);
    assert_eq!(q_snp.platform, Platform::SevSnp);

    // Different platform quote hashes (different raw quotes)
    assert_ne!(q_nitro.platform_quote_hash, q_tdx.platform_quote_hash);
    assert_ne!(q_tdx.platform_quote_hash, q_snp.platform_quote_hash);

    println!("=== HARMONIZED ATTESTATION ===");
    println!(
        "Value X (same on all platforms): {}",
        hex::encode(value_x)
    );
    println!("Nitro quote hash: {}", hex::encode(q_nitro.platform_quote_hash));
    println!("TDX quote hash:   {}", hex::encode(q_tdx.platform_quote_hash));
    println!("SNP quote hash:   {}", hex::encode(q_snp.platform_quote_hash));
    println!("=== All verify: ✓ ===");
}

#[test]
fn test_unified_quote_json_serialization() {
    let (nitro_doc, signing_key) = load_nitro_test_data();
    let value_x: [u8; 48] = Sha384::digest(b"unified-quote-test").into();
    let nonce = [0xABu8; 32];

    let quote = UnifiedQuote::new(Platform::Nitro, value_x, nitro_doc, nonce, &signing_key);

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&quote).unwrap();
    println!("Full UnifiedQuote JSON size: {} bytes", json.len());

    // Deserialize back
    let restored: UnifiedQuote = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.value_x, quote.value_x);
    assert_eq!(restored.platform_quote_hash, quote.platform_quote_hash);
    assert_eq!(restored.signature, quote.signature);
    assert_eq!(restored.pubkey, quote.pubkey);

    // Verify signature survives serialization roundtrip
    assert!(restored.verify_signature().is_ok());

    // Compact form JSON
    let compact_json = serde_json::to_string(&quote.compact()).unwrap();
    println!("Compact (on-chain) JSON size: {} bytes", compact_json.len());
    println!(
        "Savings: {} bytes stripped (raw platform quote)",
        json.len() - compact_json.len()
    );
}

#[test]
fn test_nitro_layer2_verification() {
    // Full Layer 2 verification: parse COSE_Sign1, verify pubkey binding,
    // extract PCRs from a real Nitro attestation document.
    let (nitro_doc, signing_key) = load_nitro_test_data();
    let value_x: [u8; 48] = Sha384::digest(b"bountynet-layer2-test").into();
    let nonce = [0xCDu8; 32];

    let quote = UnifiedQuote::new(Platform::Nitro, value_x, nitro_doc, nonce, &signing_key);

    // Run full verification (Layer 1 + Layer 2)
    let result = verify_unified_quote(&quote, Some(&value_x)).expect("verification should pass");

    assert!(result.signature_valid, "Layer 1: signature should be valid");
    assert!(result.platform_valid, "Layer 2: platform quote should verify");
    assert_eq!(result.value_x, value_x);
    assert_eq!(result.platform, Platform::Nitro);

    // Should have extracted PCRs from the Nitro attestation doc
    assert!(!result.measurements.is_empty(), "should have PCR measurements");
    println!("=== NITRO LAYER 2 VERIFICATION ===");
    for (name, value) in &result.measurements {
        println!("  {}: {}", name, hex::encode(value));
    }
    println!("  Platform valid: {}", result.platform_valid);
    println!("=== VERIFIED ===");
}

#[test]
fn test_verification_rejects_wrong_value_x() {
    let (nitro_doc, signing_key) = load_nitro_test_data();
    let value_x: [u8; 48] = Sha384::digest(b"real-runner").into();
    let wrong_x: [u8; 48] = Sha384::digest(b"tampered-runner").into();
    let nonce = [0u8; 32];

    let quote = UnifiedQuote::new(Platform::Nitro, value_x, nitro_doc, nonce, &signing_key);

    // Verification should fail if we expect a different Value X
    let err = verify_unified_quote(&quote, Some(&wrong_x));
    assert!(matches!(err, Err(VerifyError::ValueXMismatch { .. })));
}

#[test]
fn test_verification_rejects_compact_form_for_layer2() {
    let (nitro_doc, signing_key) = load_nitro_test_data();
    let value_x: [u8; 48] = Sha384::digest(b"test").into();
    let nonce = [0u8; 32];

    let quote = UnifiedQuote::new(Platform::Nitro, value_x, nitro_doc, nonce, &signing_key);
    let compact = quote.compact();

    // Layer 2 verification should fail on compact form (no raw platform quote)
    let err = verify_unified_quote(&compact, None);
    assert!(matches!(err, Err(VerifyError::NoPlatformQuote)));
}
