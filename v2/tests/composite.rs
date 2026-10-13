use p256::pkcs8::EncodePublicKey;
use unified_quote::{
    eat::{BuildComponents, EatToken, BINDING_SUITE_COMPOSITE},
    AttestationVerifier, Platform,
};

fn token() -> EatToken {
    let mut token = EatToken::from_build_with_nonce(
        BuildComponents {
            platform: Platform::Tdx,
            value_x: [1; 48],
            source_hash: [2; 48],
            artifact_hash: [3; 48],
            platform_measurement: vec![],
            platform_quote: vec![],
        },
        [4; 32],
    );
    token.binding_suite = BINDING_SUITE_COMPOSITE;
    token.gpu_evidence = vec![1, 2, 3, 4];
    token.boot_evidence = vec![5, 6, 7, 8];
    token
}

#[test]
fn composite_evidence_cannot_be_swapped_removed_reordered_or_downgraded() {
    let original = token();
    let binding = original.binding_bytes();
    for field in 0..7 {
        let mut changed = original.clone();
        match field {
            0 => changed.gpu_evidence[0] ^= 1,
            1 => changed.gpu_evidence.clear(),
            2 => changed.gpu_evidence.reverse(),
            3 => changed.boot_evidence[0] ^= 1,
            4 => changed.eat_nonce[0] ^= 1,
            5 => changed.tls_spki_hash[0] ^= 1,
            6 => changed.binding_suite = 0,
            _ => unreachable!(),
        }
        assert_ne!(binding, changed.binding_bytes(), "mutation {field}");
    }
    let mut claimed_legacy = original.clone();
    claimed_legacy.binding_suite = 0;
    assert!(EatToken::from_cbor(&claimed_legacy.to_cbor().unwrap()).is_err());
    let mut after_collection = original.clone();
    after_collection.platform_quote = vec![0xff; 640];
    after_collection.platform_measurement = vec![0xff; 48];
    assert_eq!(binding, after_collection.binding_bytes());
}

#[test]
fn unknown_suites_and_trailing_cbor_cannot_alias_legacy_tokens() {
    let mut legacy = token();
    legacy.binding_suite = 0;
    legacy.gpu_evidence.clear();
    legacy.boot_evidence.clear();
    let original = legacy.binding_bytes();
    let mut trailing = legacy.to_cbor().unwrap();
    trailing.push(0);
    assert!(EatToken::from_cbor(&trailing).is_err());
    for suite in [3, 42, u16::MAX] {
        legacy.binding_suite = suite;
        assert_ne!(legacy.binding_bytes(), original);
        assert!(EatToken::from_cbor(&legacy.to_cbor().unwrap()).is_err());
    }
}

#[test]
fn tpm_profiles_cannot_alias_direct_cpu_evidence_or_legacy_bindings() {
    let direct = token();
    for platform in [Platform::AzureSnpVtpm, Platform::AwsSnpNitroTpm] {
        let mut compound = direct.clone();
        compound.platform = unified_quote::eat::platform_to_u8(platform);
        assert_ne!(compound.report_data_64(None), direct.report_data_64(None));
        assert_eq!(compound.platform_enum(), Some(platform));
        compound.validate_shape().unwrap();
        compound.gpu_evidence.clear();
        compound.boot_evidence.clear();
        for suite in [0, 1] {
            compound.binding_suite = suite;
            assert!(compound.validate_shape().is_err());
        }
    }
}

#[test]
fn compound_cpu_profiles_cannot_build_without_independent_vendor_and_tpm_policy() {
    let spki = p256::SecretKey::from_slice(&[7; 32])
        .unwrap()
        .public_key()
        .to_public_key_der()
        .unwrap();
    for platform in [Platform::AzureSnpVtpm, Platform::AwsSnpNitroTpm] {
        assert!(AttestationVerifier::builder()
            .with_expected_nonce(&[4; 32])
            .with_tls_spki_der(spki.as_bytes())
            .with_expected_value_x(&[1; 48])
            .with_expected_platform_measurement(&[9; 48])
            .require_platform(platform)
            .build()
            .is_err());
    }
    use unified_quote::tee::composite::AwsSnpNitroTpmEvidence;
    assert!(AwsSnpNitroTpmEvidence::from_json(
        br#"{"version":1,"version":1,"snp_report":[],"nitrotpm_document":[]}"#
    )
    .is_err());
    assert!(AwsSnpNitroTpmEvidence::from_json(
        br#"{"version":1,"snp_report":[],"nitrotpm_document":[],"verified":true}"#
    )
    .is_err());
}

#[test]
fn verifier_requires_independent_policy_and_rejects_fake_cpu_evidence() {
    let spki = p256::SecretKey::from_slice(&[7; 32])
        .unwrap()
        .public_key()
        .to_public_key_der()
        .unwrap();
    assert!(AttestationVerifier::builder().build().is_err());
    assert!(unified_quote::AttestationCollector::builder()
        .with_nonce(&[4; 32])
        .with_tls_spki_der(spki.as_bytes())
        .with_value_x(&[0; 48])
        .build()
        .is_err());
    assert!(AttestationVerifier::builder()
        .with_expected_nonce(&[4; 32])
        .with_tls_spki_der(spki.as_bytes())
        .with_expected_value_x(&[0; 48])
        .with_expected_platform_measurement(&[9; 48])
        .build()
        .is_err());
    assert!(AttestationVerifier::builder()
        .with_expected_nonce(&[4; 32])
        .with_tls_spki_der(spki.as_bytes())
        .with_expected_value_x(&[1; 48])
        .with_expected_platform_measurement(&[9; 48])
        .with_uki_evidence(vec![1; 128])
        .build()
        .is_err());
    let boot_policy = serde_json::from_value(serde_json::json!({
        "events": [{"event_index": 1, "algorithm": 12,
            "digest": hex::encode([9; 48]), "identity": "approved loader"}],
        "uki": {
            "profile": "systemd_stub_v258", "first_section_event": 2,
            "algorithm": 12, "expected_sections": {".linux": hex::encode([8; 48])}
        }
    }))
    .unwrap();
    assert!(AttestationVerifier::builder()
        .with_expected_nonce(&[4; 32])
        .with_tls_spki_der(spki.as_bytes())
        .with_expected_value_x(&[1; 48])
        .with_expected_platform_measurement(&[9; 48])
        .with_boot_policy(boot_policy)
        .build()
        .is_err());
    assert!(AttestationVerifier::builder()
        .with_expected_nonce(&[4; 32])
        .with_tls_spki_der(spki.as_bytes())
        .with_expected_value_x(&[1; 48])
        .build()
        .is_err());
    let verifier = AttestationVerifier::builder()
        .with_expected_nonce(&[4; 32])
        .with_tls_spki_der(spki.as_bytes())
        .with_expected_value_x(&[1; 48])
        .with_expected_platform_measurement(&[9; 48])
        .require_platform(Platform::Tdx)
        .build()
        .unwrap();
    let mut evidence = token();
    use sha2::{Digest, Sha256};
    evidence.tls_spki_hash = Sha256::digest(spki.as_bytes()).into();
    let verdict = verifier.verify(&evidence);
    assert!(!verdict.is_valid());
    assert!(verdict.checks.iter().any(|v| !v.passed));
    assert!(verdict.boot.is_none());

    evidence.previous_attestation = token().to_cbor().unwrap();
    let prior_stage_verdict = verifier.verify(&evidence);
    assert!(!prior_stage_verdict.is_valid());
    assert!(prior_stage_verdict
        .checks
        .iter()
        .any(|check| { !check.passed && check.detail.contains("prior-stage policy") }));
}
