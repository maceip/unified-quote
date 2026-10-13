use super::*;

// Constructed parser/cryptography vectors, not hardware evidence.
fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out).unwrap();
    out
}
fn payload() -> Value {
    Value::Map(vec![
        (
            Value::Text("module_id".into()),
            Value::Text("test-only-vector".into()),
        ),
        (
            Value::Text("timestamp".into()),
            Value::Integer(1_800_000_000_000u64.into()),
        ),
        (Value::Text("digest".into()), Value::Text("SHA384".into())),
        (
            Value::Text("nitrotpm_pcrs".into()),
            Value::Map(
                (0..=16)
                    .chain([23])
                    .map(|index| {
                        (
                            Value::Integer(index.into()),
                            Value::Bytes(vec![index as u8; 32]),
                        )
                    })
                    .collect(),
            ),
        ),
        (Value::Text("certificate".into()), Value::Bytes(vec![1])),
        (
            Value::Text("cabundle".into()),
            Value::Array(vec![Value::Bytes(vec![2])]),
        ),
        (Value::Text("nonce".into()), Value::Bytes(vec![7; 32])),
        (Value::Text("user_data".into()), Value::Bytes(vec![9; 64])),
    ])
}
fn field_mut<'a>(payload: &'a mut Value, key: &str) -> &'a mut Value {
    let Value::Map(fields) = payload else {
        panic!()
    };
    &mut fields
        .iter_mut()
        .find(|(name, _)| name == &Value::Text(key.into()))
        .unwrap()
        .1
}
fn document(payload: Value) -> Vec<u8> {
    encode(&Value::Array(vec![
        Value::Bytes(encode(&Value::Map(vec![(
            Value::Integer(1.into()),
            Value::Integer((-35).into()),
        )]))),
        Value::Map(vec![]),
        Value::Bytes(encode(&payload)),
        Value::Bytes(vec![0; 96]),
    ]))
}
fn policy() -> NitroTpmPolicy {
    NitroTpmPolicy {
        pcr_algorithm: 0xb,
        expected_pcrs: [(4, hex::encode([4; 32]))].into(),
        max_age_secs: 60,
        max_future_skew_secs: 3,
    }
}

#[test]
fn parses_only_the_nitrotpm_profile_with_exact_request_bytes() {
    let raw = document(payload());
    let parsed = parse_document(&raw).unwrap();
    assert_eq!(
        parsed.pcrs.keys().copied().collect::<Vec<_>>(),
        (0..=16).chain([23]).collect::<Vec<_>>()
    );
    assert!(inspect_document(&raw, &[7; 32], Some(&[9; 64])).is_ok());
    assert!(inspect_document(&raw, &[8; 32], Some(&[9; 64])).is_err());
    assert!(inspect_document(&raw, &[7; 32], Some(&[8; 64])).is_err());
    assert!(inspect_document(&raw, &[7; 32], None).is_err());
    let mut foreign = payload();
    let Value::Map(fields) = &mut foreign else {
        panic!()
    };
    fields
        .iter_mut()
        .find(|(key, _)| key == &Value::Text("nitrotpm_pcrs".into()))
        .unwrap()
        .0 = Value::Text("pcrs".into());
    assert!(parse_document(&document(foreign)).is_err());
    let mut tagged = vec![0xd2];
    tagged.extend_from_slice(&raw);
    assert!(parse_document(&tagged).is_ok());
    let mut trailing = raw;
    trailing.push(0);
    assert!(parse_document(&trailing).is_err());
}

#[test]
fn rejects_duplicate_claims_pcrs_and_missing_profile_values() {
    let mut duplicate = payload();
    let Value::Map(fields) = &mut duplicate else {
        panic!()
    };
    fields.push(fields[0].clone());
    assert!(parse_document(&document(duplicate)).is_err());
    let mut duplicate = payload();
    let Value::Map(pcrs) = field_mut(&mut duplicate, "nitrotpm_pcrs") else {
        panic!()
    };
    pcrs.push(pcrs[4].clone());
    assert!(parse_document(&document(duplicate)).is_err());
    let mut missing = payload();
    let Value::Map(pcrs) = field_mut(&mut missing, "nitrotpm_pcrs") else {
        panic!()
    };
    pcrs.remove(4);
    assert!(parse_document(&document(missing)).is_err());
    let mut invalid_index = payload();
    let Value::Map(pcrs) = field_mut(&mut invalid_index, "nitrotpm_pcrs") else {
        panic!()
    };
    pcrs.push((Value::Integer(32.into()), Value::Bytes(vec![0; 32])));
    assert!(parse_document(&document(invalid_index)).is_err());
    let mut huge = payload();
    *field_mut(&mut huge, "nonce") = Value::Bytes(vec![0; 1025]);
    assert!(parse_document(&document(huge)).is_err());
    assert!(parse_document(&vec![0; MAX_NITROTPM_DOCUMENT_BYTES + 1]).is_err());
}

#[test]
fn policy_requires_independent_bounded_bank_and_freshness() {
    let good = policy();
    good.validate().unwrap();
    let mut bad = good.clone();
    bad.expected_pcrs.clear();
    assert!(bad.validate().is_err());
    let mut bad = good.clone();
    bad.pcr_algorithm = 4;
    assert!(bad.validate().is_err());
    let mut bad = good.clone();
    bad.pcr_algorithm = 0xc;
    assert!(bad.validate().is_err());
    let mut bad = good.clone();
    bad.expected_pcrs.insert(24, hex::encode([0; 32]));
    assert!(bad.validate().is_err());
    for index in [0, 1, 16, 23] {
        let mut bad = good.clone();
        bad.expected_pcrs = [(index, hex::encode([7; 32]))].into();
        assert!(bad.validate().is_err());
    }
    let mut bad = good.clone();
    bad.expected_pcrs = [(4, hex::encode([0; 32]))].into();
    assert!(bad.validate().is_err());
    for (age, skew) in [(0, 0), (3601, 0), (60, 31)] {
        let mut bad = good.clone();
        bad.max_age_secs = age;
        bad.max_future_skew_secs = skew;
        assert!(bad.validate().is_err());
    }
    assert!(serde_json::from_value::<NitroTpmPolicy>(serde_json::json!({"pcr_algorithm":11,"expected_pcrs":{"4":hex::encode([4;32])},"max_age_secs":60,"max_future_skew_secs":0,"skip_signature":true})).is_err());
}

#[cfg(any(feature = "nitro", feature = "sev-snp"))]
#[test]
fn rejects_stale_future_mixed_bank_and_attacker_root() {
    let raw = document(payload());
    for now in [1_800_000_061, 1_799_999_996] {
        let error = verify_nitrotpm_document(&raw, &[7; 32], Some(&[9; 64]), &policy(), now)
            .unwrap_err()
            .to_string();
        assert!(error.contains("stale or future"), "{error}");
    }
    let mut mixed = payload();
    let Value::Map(pcrs) = field_mut(&mut mixed, "nitrotpm_pcrs") else {
        panic!()
    };
    pcrs[1].1 = Value::Bytes(vec![1; 48]);
    let error = verify_nitrotpm_document(
        &document(mixed),
        &[7; 32],
        Some(&[9; 64]),
        &policy(),
        1_800_000_000,
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("bank policy"), "{error}");
    use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P384_SHA384};
    let key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
    let cert = CertificateParams::new(vec!["attacker.invalid".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let other = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
    let root = CertificateParams::new(vec!["attacker-root.invalid".into()])
        .unwrap()
        .self_signed(&other)
        .unwrap();
    let mut attacker = payload();
    *field_mut(&mut attacker, "certificate") = Value::Bytes(cert.der().to_vec());
    *field_mut(&mut attacker, "cabundle") = Value::Array(vec![Value::Bytes(root.der().to_vec())]);
    let error = verify_nitrotpm_document(
        &document(attacker),
        &[7; 32],
        Some(&[9; 64]),
        &policy(),
        1_800_000_000,
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("root fingerprint mismatch"), "{error}");
}

#[cfg(any(feature = "nitro", feature = "sev-snp"))]
#[test]
fn cose_verification_authenticates_exact_original_payload_and_protected_bytes() {
    use p384::ecdsa::{signature::Signer, Signature, SigningKey};
    let key = SigningKey::from_bytes((&[17u8; 48]).into()).unwrap();
    let mut doc = parse_document(&document(payload())).unwrap();
    // Independently encode COSE's Signature1 preimage using its known prefix.
    let mut signed = vec![0x84, 0x6a];
    signed.extend_from_slice(b"Signature1");
    signed.extend_from_slice(&encode(&Value::Bytes(doc.protected.clone())));
    signed.push(0x40);
    signed.extend_from_slice(&encode(&Value::Bytes(doc.payload.clone())));
    let signature: Signature = key.sign(&signed);
    doc.signature = signature.to_bytes().to_vec();
    let public = key.verifying_key().to_encoded_point(false);
    verify_document_signature(&doc, public.as_bytes()).unwrap();
    doc.payload[20] ^= 1;
    assert!(verify_document_signature(&doc, public.as_bytes()).is_err());
    doc.payload[20] ^= 1;
    doc.protected.push(0);
    assert!(verify_document_signature(&doc, public.as_bytes()).is_err());
}

#[test]
fn boot_promotion_excludes_aws_constants_and_resettable_pcrs() {
    // Direct construction is test-only access to private state; callers cannot
    // create or deserialize this verified type.
    let bytes = include_bytes!("../../../testdata/boot/intel-tpm2-bios.bin");
    let log =
        crate::boot::EventLog::parse_tcg2(bytes, crate::boot::ParseLimits::default()).unwrap();
    let mut pcrs = log.replay(0xb).unwrap().registers;
    pcrs.insert(0, vec![255; 32]);
    pcrs.insert(1, vec![255; 32]);
    pcrs.insert(16, vec![255; 32]);
    pcrs.insert(23, vec![255; 32]);
    let result = VerifiedNitroTpm {
        module_id: "test-only-vector".into(),
        timestamp_millis: 0,
        pcr_algorithm: 0xb,
        pcrs,
    };
    let verified = result
        .verify_boot_log(bytes, crate::boot::ParseLimits::default())
        .unwrap();
    assert!(verified
        .covered_registers()
        .iter()
        .all(|(_, index)| (2..=15).contains(index)));
    assert!(!verified.covered_registers().contains(&(0xb, 0)));
    assert!(!verified.covered_registers().contains(&(0xb, 1)));
}

#[cfg(not(any(feature = "nitro", feature = "sev-snp")))]
#[test]
fn absent_signature_provider_never_promotes_structural_evidence() {
    let error = verify_nitrotpm_document(
        &document(payload()),
        &[7; 32],
        Some(&[9; 64]),
        &policy(),
        1_800_000_000,
    )
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("requires nitro or sev-snp feature"),
        "{error}"
    );
}
