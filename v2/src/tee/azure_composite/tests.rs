use super::*;
use rand::{rngs::StdRng, SeedableRng};
use rsa::RsaPrivateKey;
use std::sync::OnceLock;

// Explicitly generated TEST-ONLY key and framing vectors. These have no AMD
// endorsement and must never produce a VerifiedAzureComposite result.
fn key() -> &'static RsaPrivateKey {
    static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
    KEY.get_or_init(|| {
        RsaPrivateKey::new(&mut StdRng::seed_from_u64(0x415a_5552_4554_4553), 2048).unwrap()
    })
}
fn runtime() -> Vec<u8> {
    let modulus = URL_SAFE_NO_PAD.encode(key().n().to_bytes_be());
    serde_json::to_vec(&serde_json::json!({
        "keys":[
            {"kid":"HCLAkPub","kty":"RSA","key_ops":["sign"],"n":modulus,"e":"AQAB"},
            {"kid":"HCLEkPub","kty":"RSA","key_ops":["encrypt"],"n":modulus,"e":"AQAB"}
        ],
        "vm-configuration":{
            "root-cert-thumbprint":"", "console-enabled":false,
            "secure-boot":true,"tpm-enabled":true,"tpm-persisted":true,
            "vmUniqueId":"68dc0ac0-2ed9-4b2a-a03e-4953e416d939"
        },
        "user-data":"00".repeat(64)
    }))
    .unwrap()
}
fn hcl(claims: &[u8]) -> Vec<u8> {
    let mut result = vec![0; CLAIMS_OFFSET + claims.len()];
    let length = result.len() as u32;
    for (offset, value) in [
        (0, 0x414c4348u32),
        (4, 2),
        (8, length),
        (12, 2),
        (RUNTIME_OFFSET, 20 + claims.len() as u32),
        (RUNTIME_OFFSET + 4, 1),
        (RUNTIME_OFFSET + 8, 2),
        (RUNTIME_OFFSET + 12, 1),
        (RUNTIME_OFFSET + 16, claims.len() as u32),
    ] {
        result[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    result[HCL_HEADER..HCL_HEADER + 4].copy_from_slice(&2u32.to_le_bytes());
    result[HCL_HEADER + 0x50..HCL_HEADER + 0x70].copy_from_slice(&Sha256::digest(claims));
    result[HCL_HEADER + 0x90..HCL_HEADER + 0xc0].fill(7);
    result[CLAIMS_OFFSET..].copy_from_slice(claims);
    result
}
fn pcrs() -> Vec<AzurePcrValue> {
    vec![
        AzurePcrValue {
            index: 0,
            value: [0x42; 32],
        },
        AzurePcrValue {
            index: 7,
            value: [0xa5; 32],
        },
        AzurePcrValue {
            index: 11,
            value: [0x24; 32],
        },
    ]
}
fn policy() -> AzureCompositePolicy {
    let public = RsaPublicKey::from(key());
    AzureCompositePolicy {
        version: 1,
        allowed_ak_spki_sha256: vec![hex::encode(Sha256::digest(
            public.to_public_key_der().unwrap().as_bytes(),
        ))],
        enrolled_ak_public_areas: vec![public_area()],
        allowed_paravisor_measurements: vec!["07".repeat(48)],
        expected_vm_id: "68dc0ac0-2ed9-4b2a-a03e-4953e416d939".into(),
        expected_pcrs: pcrs(),
        allow_console: false,
    }
}
fn public_area() -> Vec<u8> {
    let mut area = hex::decode("0001000b00050472000000100014000b0800000000000100").unwrap();
    area.extend_from_slice(&key().n().to_bytes_be());
    area
}
fn put2b(result: &mut Vec<u8>, value: &[u8]) {
    result.extend_from_slice(&(value.len() as u16).to_be_bytes());
    result.extend_from_slice(value);
}
fn message(report_data: &[u8; 64], pcrs: &[AzurePcrValue]) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend_from_slice(&0xff544347u32.to_be_bytes());
    result.extend_from_slice(&0x8018u16.to_be_bytes());
    let qn = enrolled_ak_name(&public_area()).unwrap().1;
    put2b(&mut result, &qn);
    put2b(&mut result, &qualifying_data(report_data));
    result.extend_from_slice(&1234u64.to_be_bytes());
    result.extend_from_slice(&1u32.to_be_bytes());
    result.extend_from_slice(&2u32.to_be_bytes());
    result.push(1);
    result.extend_from_slice(&3u64.to_be_bytes());
    result.extend_from_slice(&1u32.to_be_bytes());
    result.extend_from_slice(&SHA256.to_be_bytes());
    result.push(3);
    let mut bitmap = [0u8; 3];
    let mut hash = Sha256::new();
    for pcr in pcrs {
        bitmap[usize::from(pcr.index / 8)] |= 1 << (pcr.index % 8);
        hash.update(pcr.value);
    }
    result.extend_from_slice(&bitmap);
    put2b(&mut result, &hash.finalize());
    result
}
fn signature(message: &[u8]) -> Vec<u8> {
    let mut result = RSASSA.to_be_bytes().to_vec();
    result.extend_from_slice(&SHA256.to_be_bytes());
    put2b(
        &mut result,
        &key()
            .sign(Pkcs1v15Sign::new::<Sha256>(), &Sha256::digest(message))
            .unwrap(),
    );
    result
}
fn evidence(report_data: &[u8; 64]) -> AzureCompositeEvidence {
    let message = message(report_data, &pcrs());
    AzureCompositeEvidence {
        version: 1,
        hcl_report: hcl(&runtime()),
        quote_signature: signature(&message),
        quote_message: message,
        pcrs: pcrs(),
    }
}

#[test]
fn challenge_has_fixed_domain_and_authenticates_both_halves() {
    let report_data = std::array::from_fn(|i| i as u8);
    // Independent Python hashlib fixture, not another call to this helper.
    assert_eq!(
        hex::encode(qualifying_data(&report_data)),
        "d7e513d0ccb04717efc0b49769225b18eac58aa976c8f8d5dd0bd70d22e8db9e"
    );
    let original = qualifying_data(&report_data);
    for index in 0..64 {
        let mut changed = report_data;
        changed[index] ^= 1;
        assert_ne!(qualifying_data(&changed), original);
    }
    assert_ne!(original.as_slice(), Sha256::digest(report_data).as_slice());
}

#[test]
fn signed_quote_rejects_replay_and_every_transcript_substitution() {
    let report_data = [0x33; 64];
    let public = RsaPublicKey::from(key());
    let fixture = evidence(&report_data);
    verify_quote(&public, &fixture, &report_data).unwrap();
    for index in 0..64 {
        let mut changed = report_data;
        changed[index] ^= 1;
        assert!(
            verify_quote(&public, &fixture, &changed).is_err(),
            "report_data byte{index}"
        );
    }
    for index in 0..fixture.quote_message.len() {
        let mut changed = fixture.clone();
        changed.quote_message[index] ^= 1;
        assert!(
            verify_quote(&public, &changed, &report_data).is_err(),
            "transcript byte{index}"
        );
    }
    let mut changed = fixture.clone();
    changed.quote_signature[100] ^= 1;
    assert!(verify_quote(&public, &changed, &report_data).is_err());
}

#[test]
fn exact_quote_pcr_selection_digest_and_signature_encoding_are_enforced() {
    let report_data = [0x33; 64];
    let fixture = evidence(&report_data);
    let public = RsaPublicKey::from(key());
    let mut cases = Vec::new();
    let mut wrong = fixture.clone();
    wrong.pcrs[1].value[0] ^= 1;
    cases.push(wrong);
    let mut wrong = fixture.clone();
    wrong.pcrs.swap(0, 1);
    cases.push(wrong);
    let mut wrong = fixture.clone();
    wrong.pcrs.pop();
    cases.push(wrong);
    let mut wrong = fixture.clone();
    wrong.pcrs.push(AzurePcrValue {
        index: 12,
        value: [0; 32],
    });
    cases.push(wrong);
    let mut wrong = fixture.clone();
    wrong.quote_signature[3] = 0x0c;
    cases.push(wrong);
    let mut wrong = fixture.clone();
    wrong.quote_signature.push(0);
    cases.push(wrong);
    let mut wrong = fixture.clone();
    wrong.quote_message.push(0);
    wrong.quote_signature = signature(&wrong.quote_message);
    cases.push(wrong);
    let mut wrong = fixture.clone();
    let length = (wrong.quote_message.len() as u16).to_be_bytes();
    wrong.quote_message.splice(..0, length);
    wrong.quote_signature = signature(&wrong.quote_message);
    cases.push(wrong);
    // Re-signed malformed TPM clock/selection is still unsupported.
    let mut wrong = fixture.clone();
    wrong.quote_message[92] = 0;
    wrong.quote_signature = signature(&wrong.quote_message);
    cases.push(wrong);
    let mut wrong = fixture.clone();
    wrong.quote_message[105] = 0x0c;
    wrong.quote_signature = signature(&wrong.quote_message);
    cases.push(wrong);
    for wrong in cases {
        assert!(verify_quote(&public, &wrong, &report_data).is_err());
    }
    for length in 0..fixture.quote_message.len() {
        assert!(parse_quote(&fixture.quote_message[..length]).is_err());
    }
    for length in 0..fixture.quote_signature.len() {
        let mut wrong = fixture.clone();
        wrong.quote_signature.truncate(length);
        assert!(verify_quote(&public, &wrong, &report_data).is_err());
    }
}

#[test]
fn exact_hcl_bounds_profiles_and_complete_report_data_are_required() {
    let claims = runtime();
    let original = hcl(&claims);
    assert_eq!(parse_hcl(&original).unwrap().claims, claims);
    let mut padded = original.clone();
    padded.resize(HCL_NV_SIZE, 0);
    parse_hcl(&padded).unwrap();
    padded[HCL_NV_SIZE - 1] = 1;
    assert!(parse_hcl(&padded).is_err());
    for length in 0..original.len() {
        assert!(parse_hcl(&original[..length]).is_err());
    }
    for offset in [
        0,
        4,
        8,
        12,
        16,
        20,
        RUNTIME_OFFSET,
        RUNTIME_OFFSET + 4,
        RUNTIME_OFFSET + 8,
        RUNTIME_OFFSET + 12,
        RUNTIME_OFFSET + 16,
        HCL_HEADER + 0x50,
        HCL_HEADER + 0x70,
    ] {
        let mut changed = original.clone();
        changed[offset] ^= 1;
        assert!(parse_hcl(&changed).is_err(), "offset{offset}");
    }
    let mut changed = original.clone();
    changed[CLAIMS_OFFSET] ^= 1;
    assert!(parse_hcl(&changed).is_err());
    let mut changed = original;
    changed.extend_from_slice(&[0]);
    assert!(parse_hcl(&changed).is_err());
}

#[test]
fn historical_microsoft_hcl_v1_fixture_is_explicitly_unsupported() {
    let original = include_bytes!("../../../testdata/azure/hcl-legacy-v1.bin");
    assert_eq!(
        hex::encode(Sha256::digest(original)),
        "54b5e72f382f77655f0550a3cd755dd7cf34242b7c00f8684500889b38426255"
    );
    assert!(parse_hcl(original)
        .unwrap_err()
        .to_string()
        .contains("version"));
}

#[test]
fn enrolled_ak_requires_restricted_primary_attributes_and_exact_names() {
    // Genuine Microsoft source public-area vector. Its object Name matches the
    // published CreatePrimary reply; the qualified name was computed separately
    // using Python hashlib with the endorsement hierarchy handle.
    let public = include_bytes!("../../../testdata/azure/microsoft-ak-public.bin");
    assert_eq!(
        hex::encode(Sha256::digest(public)),
        "9257643821f968e9fc47fabf9c56497a63c2c08a12804973c38b000699e9fc22"
    );
    assert_eq!(
        hex::encode(enrolled_ak_name(public).unwrap().1),
        "000b26cf4b85e012e06f00ff64f5333a0ebc861a9110f02cab13c70bf1f66fedd93b"
    );
    for length in 0..public.len() {
        assert!(enrolled_ak_name(&public[..length]).is_err());
    }
    for offset in [0, 2, 4, 5, 6, 7, 8, 10, 12, 14, 16, 18, 22] {
        let mut changed = public.to_vec();
        changed[offset] ^= 1;
        assert!(
            enrolled_ak_name(&changed).is_err(),
            "TPMT_PUBLIC field offset{offset}"
        );
    }
    let mut policy = policy();
    policy.enrolled_ak_public_areas.clear();
    assert!(policy.validate().is_err());
    policy.enrolled_ak_public_areas.push(public.to_vec());
    assert!(policy
        .validate()
        .unwrap_err()
        .to_string()
        .contains("SPKI pin"));
}

#[test]
fn runtime_rejects_ambiguous_jwks_and_missing_security_claims() {
    let claims = runtime();
    parse_claims(&claims).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&claims).unwrap();
    value["keys"][0]["key_ops"] = serde_json::json!(["encrypt"]);
    assert!(parse_claims(&serde_json::to_vec(&value).unwrap()).is_err());
    let mut value: serde_json::Value = serde_json::from_slice(&claims).unwrap();
    value["keys"][1] = value["keys"][0].clone();
    assert!(parse_claims(&serde_json::to_vec(&value).unwrap()).is_err());
    let mut value: serde_json::Value = serde_json::from_slice(&claims).unwrap();
    value["vm-configuration"]
        .as_object_mut()
        .unwrap()
        .remove("tpm-persisted");
    assert!(parse_claims(&serde_json::to_vec(&value).unwrap()).is_err());
    let mut value: serde_json::Value = serde_json::from_slice(&claims).unwrap();
    value["vm-configuration"]["debug"] = true.into();
    assert!(parse_claims(&serde_json::to_vec(&value).unwrap()).is_err());
    let text = String::from_utf8(claims).unwrap();
    let duplicate = text.replace(
        "\"secure-boot\":true",
        "\"secure-boot\":false,\"secure-boot\":true",
    );
    assert!(parse_claims(duplicate.as_bytes()).is_err());
    let mut value: serde_json::Value = serde_json::from_str(&text).unwrap();
    value["keys"][0]["e"] = "Aw".into();
    assert!(parse_claims(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn enrollment_never_accepts_placeholder_or_evidence_supplied_policy() {
    let expected = policy();
    expected.validate().unwrap();
    let claims = parse_claims(&runtime()).unwrap();
    claims.check_policy(&expected).unwrap();
    let mut wrong = expected.clone();
    wrong.expected_vm_id = "68dc0ac0-2ed9-4b2a-a03e-4953e416d938".into();
    assert!(claims.check_policy(&wrong).is_err());
    for bad in ["00".repeat(32), "ff".repeat(32), "11".repeat(31)] {
        let mut wrong = expected.clone();
        wrong.allowed_ak_spki_sha256 = vec![bad];
        assert!(wrong.validate().is_err());
    }
    let mut wrong = expected.clone();
    wrong.expected_pcrs[1].index = 0;
    assert!(wrong.validate().is_err());
    let mut wrong = expected.clone();
    wrong.expected_pcrs.clear();
    assert!(wrong.validate().is_err());
    let mut wrong = expected.clone();
    for pcr in &mut wrong.expected_pcrs {
        pcr.value = [0; 32];
    }
    assert!(wrong.validate().is_err());
    let mut wrong = expected;
    wrong.allowed_paravisor_measurements.clear();
    assert!(wrong.validate().is_err());
    let bytes = evidence(&[0x33; 64]).to_json().unwrap();
    AzureCompositeEvidence::from_json(&bytes).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    value["policy"] = serde_json::json!({});
    assert!(AzureCompositeEvidence::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
    let duplicate = String::from_utf8(bytes).unwrap().replacen(
        "\"version\":1",
        "\"version\":0,\"version\":1",
        1,
    );
    assert!(AzureCompositeEvidence::from_json(duplicate.as_bytes()).is_err());
    assert!(AzureCompositeEvidence::from_json(&vec![b' '; MAX_WIRE + 1]).is_err());
}

#[test]
fn fresh_test_ak_signature_cannot_replace_amd_endorsement() {
    use crate::quote::snp_collateral::{SnpProduct, SnpTcbVersion};
    let report_data = [0x33; 64];
    let fixture = evidence(&report_data);
    verify_quote(&RsaPublicKey::from(key()), &fixture, &report_data).unwrap();
    let tcb = SnpTcbPolicy {
        product: SnpProduct::Milan,
        minimum_tcb: SnpTcbVersion {
            fmc: None,
            boot_loader: 1,
            tee: 1,
            snp: 1,
            microcode: 1,
        },
        minimum_guest_svn: 0,
        expected_vmpl: 0,
        require_smt_disabled: false,
        require_alias_check_complete: false,
        minimum_launch_mitigation_vector: 0,
        minimum_current_mitigation_vector: 0,
        allowed_vlek_csp_ids: vec![],
    };
    // Nonempty bytes pass transport bounds but are no AMD vendor collateral.
    let collateral = SnpCollateral {
        certificate_chain: vec![vec![1], vec![2], vec![3]],
        product_crl: vec![1],
    };
    let error = verify(&fixture, &report_data, &policy(), &collateral, &tcb).unwrap_err();
    assert!(error.to_string().contains("AMD endorsement"), "{error:#}");
    let mut wrong_name = fixture;
    wrong_name.quote_message[10] ^= 1;
    wrong_name.quote_signature = signature(&wrong_name.quote_message);
    // A mathematically correct signature cannot override enrolled TPM identity.
    verify_quote(&RsaPublicKey::from(key()), &wrong_name, &report_data).unwrap();
    let error = verify(&wrong_name, &report_data, &policy(), &collateral, &tcb).unwrap_err();
    assert!(error.to_string().contains("qualified signer"), "{error:#}");
}

#[test]
fn collector_rejects_implicit_tools_and_ambiguous_pcr_sets() {
    assert!(AzureCompositeCollector::new("tpm2_nvread", "tpm2_quote", "/dev/tpmrm0").is_err());
    assert!(AzureCompositeCollector::new(
        "/usr/bin/tpm2_nvread",
        "/usr/bin/tpm2_quote",
        "swtpm:host=localhost"
    )
    .is_err());
    for indices in [vec![], vec![0, 0], vec![7, 0], vec![16]] {
        assert!(collect(&[0x33; 64], &indices).is_err());
    }
}
