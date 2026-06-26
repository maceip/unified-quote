//! Integration test: Real Intel TDX attestation quote → UnifiedQuote → Verify
//!
//! Uses a real TDX quote captured from a GCP c3-standard-4 Confidential VM
//! (Intel Sapphire Rapids) in us-central1-a via configfs-tsm, 2026-04-08.
//!
//! SECURITY NOTE: signing_key in testdata is TEST-ONLY (pubkey hash baked into
//! the TDX quote's REPORTDATA during capture). No security value.

use uq_runner::quote::verify::verify_unified_quote;
use uq_runner::quote::{Platform, UnifiedQuote};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha384};

fn load_tdx_test_data() -> (Vec<u8>, SigningKey) {
    let json_str =
        std::fs::read_to_string("testdata/tdx_attestation.json").expect("testdata not found");
    let data: serde_json::Value = serde_json::from_str(&json_str).unwrap();

    let doc_hex = data["raw_quote_hex"].as_str().unwrap();
    let doc_bytes = hex::decode(doc_hex).unwrap();

    let sk_hex = data["signing_key"].as_str().unwrap();
    let sk_bytes: [u8; 32] = hex::decode(sk_hex).unwrap().try_into().unwrap();
    let signing_key = SigningKey::from_bytes(&sk_bytes);

    (doc_bytes, signing_key)
}

#[test]
fn test_tdx_layer2_verification() {
    let (tdx_quote, signing_key) = load_tdx_test_data();
    let value_x: [u8; 48] = Sha384::digest(b"bountynet-tdx-test").into();
    let nonce = [0xAAu8; 32];

    println!("TDX quote size: {} bytes", tdx_quote.len());

    let quote = UnifiedQuote::new(
        Platform::Tdx,
        value_x,
        tdx_quote,
        nonce,
        &signing_key,
    );

    let result = verify_unified_quote(&quote, Some(&value_x)).expect("TDX verification should pass");

    assert!(result.signature_valid);
    assert!(result.platform_valid);
    assert_eq!(result.platform, Platform::Tdx);
    assert_eq!(result.value_x, value_x);

    println!("=== Intel TDX LAYER 2 VERIFICATION ===");
    for (name, value) in &result.measurements {
        println!("  {}: {}", name, hex::encode(value));
    }
    println!("  Platform valid: {}", result.platform_valid);
    println!("=== VERIFIED ===");
}

#[test]
fn test_all_three_platforms_same_value_x() {
    // The crown jewel: same Value X verified across Nitro, SNP, AND TDX
    let (tdx_quote, tdx_key) = load_tdx_test_data();

    let snp_json =
        std::fs::read_to_string("testdata/snp_attestation.json").expect("snp testdata");
    let snp_data: serde_json::Value = serde_json::from_str(&snp_json).unwrap();
    let snp_report = hex::decode(snp_data["attestation_report"].as_str().unwrap()).unwrap();
    let snp_sk: [u8; 32] = hex::decode(snp_data["signing_key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let snp_key = SigningKey::from_bytes(&snp_sk);

    let nitro_json =
        std::fs::read_to_string("testdata/nitro_attestation.json").expect("nitro testdata");
    let nitro_data: serde_json::Value = serde_json::from_str(&nitro_json).unwrap();
    let nitro_doc = hex::decode(nitro_data["attestation_doc"].as_str().unwrap()).unwrap();
    let nitro_sk: [u8; 32] = hex::decode(nitro_data["signing_key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let nitro_key = SigningKey::from_bytes(&nitro_sk);

    // Same Value X for all three
    let value_x: [u8; 48] = Sha384::digest(b"one-ring-to-rule-them-all").into();
    let nonce = [0x42u8; 32];

    let q_tdx = UnifiedQuote::new(Platform::Tdx, value_x, tdx_quote, nonce, &tdx_key);
    let q_snp = UnifiedQuote::new(Platform::SevSnp, value_x, snp_report, nonce, &snp_key);
    let q_nitro = UnifiedQuote::new(Platform::Nitro, value_x, nitro_doc, nonce, &nitro_key);

    // All three have the same Value X
    assert_eq!(q_tdx.value_x, q_snp.value_x);
    assert_eq!(q_snp.value_x, q_nitro.value_x);
    assert_eq!(q_tdx.value_x, value_x);

    // All three pass verification (structural + crypto where certs available)
    let r_tdx = verify_unified_quote(&q_tdx, Some(&value_x)).expect("TDX verify");
    let r_snp = verify_unified_quote(&q_snp, Some(&value_x)).expect("SNP verify");
    let r_nitro = verify_unified_quote(&q_nitro, Some(&value_x)).expect("Nitro verify");

    assert!(r_tdx.platform_valid);   // TDX: full DCAP chain verified
    assert!(!r_snp.platform_valid);  // SNP: no VCEK certs in test data
    assert!(r_nitro.platform_valid); // Nitro: COSE + cert chain verified

    // Different platforms, same X
    assert_eq!(r_tdx.platform, Platform::Tdx);
    assert_eq!(r_snp.platform, Platform::SevSnp);
    assert_eq!(r_nitro.platform, Platform::Nitro);

    // All structurally different quotes
    assert_ne!(q_tdx.platform_quote_hash, q_snp.platform_quote_hash);
    assert_ne!(q_snp.platform_quote_hash, q_nitro.platform_quote_hash);
    assert_ne!(q_tdx.platform_quote_hash, q_nitro.platform_quote_hash);

    println!("=== THREE-PLATFORM HARMONIZATION (ALL REAL DATA) ===");
    println!("Value X (identical): {}", hex::encode(value_x));
    println!("TDX quote hash:   {}", hex::encode(q_tdx.platform_quote_hash));
    println!("SNP quote hash:   {}", hex::encode(q_snp.platform_quote_hash));
    println!("Nitro quote hash: {}", hex::encode(q_nitro.platform_quote_hash));
    println!(
        "Layer 2: TDX={} (full DCAP), SNP={} (no VCEK), Nitro={} (full COSE)",
        r_tdx.platform_valid, r_snp.platform_valid, r_nitro.platform_valid
    );
    println!("=== THE ONE RING ===");
}
