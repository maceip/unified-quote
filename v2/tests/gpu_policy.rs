//! Policy/parser regressions. Locally constructed wire bytes are adversarial
//! test inputs only; none are presented as authenticated device evidence.
#![cfg(feature = "gpu")]

use std::collections::{BTreeMap, BTreeSet};

use unified_quote::gpu::{
    opaque::{ConfidentialMode, OpaqueData},
    spdm::SpdmReport,
    verify::{DevicePolicy, GpuPolicy, GpuVerifier, SwitchPolicy},
    GpuCollateral, GpuEvidence, GpuEvidenceBundle, NvmlCcState,
};

fn policy() -> GpuPolicy {
    GpuPolicy {
        devices: vec![DevicePolicy {
            identity_spki_sha256: "01".repeat(32),
            model: "GB100".into(),
            mode: ConfidentialMode::Spt,
            required_opaque: BTreeMap::new(),
            pdi: None,
        }],
        switches: vec![],
    }
}

fn fabric_policy() -> GpuPolicy {
    let mut result = policy();
    result.devices[0].mode = ConfidentialMode::Ppcie;
    result.devices[0].pdi = Some("11".repeat(8));
    result.devices[0].required_opaque.insert(21, vec![0xaa]);
    result.switches.push(SwitchPolicy {
        identity_spki_sha256: "02".repeat(32),
        model: "LS_10".into(),
        pdi: "22".repeat(8),
        gpu_pdis: BTreeSet::from(["11".repeat(8)]),
        required_opaque: BTreeMap::from([
            (21, vec![0xaa]),
            (23, vec![0]),
            (25, vec![0xaa]),
            (26, vec![0x11; 64]),
        ]),
    });
    result
}

fn legacy(fields: &[(u16, &[u8])]) -> Vec<u8> {
    let mut result = Vec::new();
    for (id, value) in fields {
        result.extend(id.to_le_bytes());
        result.extend((value.len() as u16).to_le_bytes());
        result.extend_from_slice(value);
    }
    result
}

fn typed(fields: &[(u16, u16, &[u8])]) -> Vec<u8> {
    let mut result = b"NVDAOD\0\0\x02\0\0\0".to_vec();
    for (id, value_type, value) in fields {
        result.extend(id.to_le_bytes());
        result.extend(value_type.to_le_bytes());
        result.extend((value.len() as u16).to_le_bytes());
        result.extend_from_slice(value);
    }
    result
}

#[test]
fn required_inventory_is_exact_and_explicit() {
    policy().validate().unwrap();
    for mutation in 0..7 {
        let mut p = policy();
        match mutation {
            0 => p.devices.clear(),
            1 => p.devices.push(p.devices[0].clone()),
            2 => p.devices[0].identity_spki_sha256 = "AB".repeat(32),
            3 => p.devices[0].identity_spki_sha256 = "01".repeat(31),
            4 => p.devices[0].model.clear(),
            5 => p.devices = vec![p.devices[0].clone(); 257],
            6 => p.devices[0].identity_spki_sha256 = "00".repeat(32),
            _ => unreachable!(),
        }
        assert!(p.validate().is_err(), "mutation {mutation}");
    }
    let verifier = GpuVerifier::new(policy()).unwrap();
    let mut empty = GpuEvidenceBundle {
        version: 1,
        nonce: [3; 32],
        driver_version: "unsigned NVML text must not imply a verdict".into(),
        cc_state: NvmlCcState {
            environment: 1,
            cc_feature: 1,
            dev_tools_mode: 0,
            accepting_client_requests: 1,
        },
        gpus: vec![],
        switches: vec![],
        collateral: GpuCollateral::default(),
    };
    assert!(verifier
        .verify(&empty, &[3; 32], 1_790_000_000)
        .unwrap_err()
        .to_string()
        .contains("inventory"));
    empty.nonce = [4; 32];
    assert!(verifier
        .verify(&empty, &[3; 32], 1_790_000_000)
        .unwrap_err()
        .to_string()
        .contains("nonce"));
    empty.version = 2;
    assert!(verifier.verify(&empty, &[4; 32], 1_790_000_000).is_err());

    empty.version = 1;
    empty.gpus.push(GpuEvidence {
        index: 0,
        uuid: String::new(),
        name: String::new(),
        vbios_version: String::new(),
        certificate_chain: vec![],
        attestation_certificate_chain: vec![],
        attestation_report: vec![],
        cec_attestation_report: vec![1],
    });
    assert!(verifier
        .verify(&empty, &[4; 32], 1_790_000_000)
        .unwrap_err()
        .to_string()
        .contains("CEC"));
}

#[test]
fn enrolled_models_cannot_enable_an_undocumented_profile() {
    for model in ["GH100", "GB100"] {
        let mut p = policy();
        p.devices[0].model = model.into();
        p.validate().unwrap();
    }
    for model in ["", "GH200", "GB200", "GB300", "gh100", "H100", "LS_10"] {
        let mut p = policy();
        p.devices[0].model = model.into();
        assert!(p.validate().is_err(), "{model}");
    }
    fabric_policy().validate().unwrap();
    for model in ["", "LS10", "LS_11", "ls_10", "GB100"] {
        let mut p = fabric_policy();
        p.switches[0].model = model.into();
        assert!(p.validate().is_err(), "{model}");
    }
}

#[test]
fn fabric_policy_requires_enrolled_reciprocal_graph_and_signed_security_fields() {
    fabric_policy().validate().unwrap();
    for mutation in 0..13 {
        let mut p = fabric_policy();
        match mutation {
            0 => p.devices[0].pdi = None,
            1 => {
                p.devices[0].required_opaque.remove(&21);
            }
            2 => p.switches.clear(),
            3 => p.switches[0].gpu_pdis.clear(),
            4 => {
                p.switches[0].gpu_pdis.insert("33".repeat(8));
            }
            5 => {
                p.switches[0].required_opaque.remove(&25);
            }
            6 => {
                p.switches[0].required_opaque.insert(26, vec![]);
            }
            7 => p.switches[0].identity_spki_sha256 = p.devices[0].identity_spki_sha256.clone(),
            8 => p.devices[0].mode = ConfidentialMode::Spt,
            9 => p.switches.push(p.switches[0].clone()),
            10 => p.devices[0].pdi = Some("00".repeat(8)),
            11 => p.switches[0].pdi = "00".repeat(8),
            12 => p.switches[0].identity_spki_sha256 = "00".repeat(32),
            _ => unreachable!(),
        }
        assert!(p.validate().is_err(), "mutation {mutation}");
    }
}

#[test]
fn published_nvdaod_capture_parses_header_and_typed_mode_without_authenticity_claim() {
    // NVIDIA provides no corresponding chain for this vector. This is strictly
    // a format check, never a successful report-signature/admission test.
    let bytes =
        hex::decode(include_str!("../testdata/gpu/nvidia/nvdaodAttestationReport.txt").trim())
            .unwrap();
    let report = SpdmReport::parse(&bytes).unwrap();
    let opaque = OpaqueData::parse(report.opaque_data()).unwrap();
    assert_eq!(opaque.major_version, 2);
    assert_eq!(opaque.field(36).unwrap().value_type, 0x85);
    assert_eq!(opaque.bytes(36).unwrap(), [0, 0]);
    assert_eq!(opaque.bytes(34).unwrap(), [0, 2]);
    assert_eq!(opaque.mode().unwrap(), ConfidentialMode::Mpt);
}

#[test]
fn mode_requires_supported_type_width_version_and_value() {
    for (encoded, expected) in [
        (0, ConfidentialMode::Mpt),
        (1, ConfidentialMode::Spt),
        (2, ConfidentialMode::Ppcie),
    ] {
        let modern = typed(&[(36, 0x85, &[encoded, 0])]);
        assert_eq!(
            OpaqueData::parse(&modern).unwrap().mode().unwrap(),
            expected
        );
        for width in 1..=8 {
            let mut scalar = vec![0; width];
            scalar[0] = encoded;
            let old = legacy(&[(34, &[1, 0]), (36, &scalar)]);
            assert_eq!(OpaqueData::parse(&old).unwrap().mode().unwrap(), expected);
        }
    }
    for value_type in [0, 1, 0x82, 0x86, 0x87, 0xffff] {
        let bytes = typed(&[(36, value_type, &[1, 0])]);
        assert!(OpaqueData::parse(&bytes).unwrap().mode().is_err());
    }
    for width in [0, 1, 3, 8, 9] {
        let bytes = typed(&[(36, 0x85, &vec![0; width])]);
        assert!(OpaqueData::parse(&bytes).unwrap().mode().is_err());
    }
    for scalar in [&[3, 0][..], &[1, 1][..]] {
        let bytes = typed(&[(36, 0x85, scalar)]);
        assert!(OpaqueData::parse(&bytes).unwrap().mode().is_err());
    }
    for fields in [
        vec![(36, &[1][..])],
        vec![(34, &[0, 0][..]), (36, &[1][..])],
        vec![(34, &[1, 0][..])],
    ] {
        let bytes = legacy(&fields);
        assert!(OpaqueData::parse(&bytes).unwrap().mode().is_err());
    }
}

#[test]
fn svn_uses_profile_specific_type_and_exact_u16_width() {
    let modern = typed(&[(0, 0x87, &[5, 1])]);
    let old = legacy(&[(0, &[5, 1])]);
    assert_eq!(OpaqueData::parse(&modern).unwrap().svn(0).unwrap(), 261);
    assert!(OpaqueData::parse(&old).unwrap().svn(0).is_err());
    let wrong_type = typed(&[(0, 0, &[5, 1])]);
    assert!(OpaqueData::parse(&wrong_type).unwrap().svn(0).is_err());
    for width in [0, 1, 3, 8] {
        let bytes = typed(&[(0, 0x87, &vec![1; width])]);
        assert!(OpaqueData::parse(&bytes).unwrap().svn(0).is_err());
    }
}

#[test]
fn opaque_fields_reject_duplicates_truncation_and_unsupported_headers() {
    let zero = typed(&[(0, 0x87, &[0, 0, 0, 0])]);
    assert_eq!(
        OpaqueData::parse(&zero).unwrap().field(0).unwrap().value,
        [0; 4]
    );
    let duplicate = typed(&[(0, 0x87, &[0]), (0, 0x87, &[1])]);
    assert!(OpaqueData::parse(&duplicate).is_err());
    let good = typed(&[(36, 0x85, &[1, 0])]);
    for i in 13..good.len() {
        assert!(OpaqueData::parse(&good[..i]).is_err(), "length {i}");
    }
    for (offset, value) in [(6, 1), (8, 3), (11, 1)] {
        let mut invalid = good.clone();
        invalid[offset] = value;
        assert!(OpaqueData::parse(&invalid).is_err());
    }
    assert!(OpaqueData::parse(&typed(&[(255, 0x85, &[0])])).is_err());
}

#[test]
fn minor_and_patch_are_compatible_but_legacy_version_has_exact_u16_width() {
    let mut modern = typed(&[(36, 0x85, &[1, 0])]);
    for (minor, patch) in [(1, 0), (0, 1), (255, 255)] {
        modern[9] = minor;
        modern[10] = patch;
        let parsed = OpaqueData::parse(&modern).unwrap();
        assert_eq!(parsed.major_version, 2);
        assert_eq!(parsed.mode().unwrap(), ConfidentialMode::Spt);
    }
    for width in [0, 1, 3, 8] {
        let bytes = legacy(&[(34, &vec![0; width])]);
        assert!(OpaqueData::parse(&bytes).is_err());
    }
    let oversized_driver = typed(&[(3, 0x86, b"111111.222222.333333")]);
    assert!(OpaqueData::parse(&oversized_driver)
        .unwrap()
        .text(3)
        .is_err());
}

#[test]
fn typed_values_require_the_published_discriminator_before_consumption() {
    let bytes =
        hex::decode(include_str!("../testdata/gpu/nvidia/nvdaodAttestationReport.txt").trim())
            .unwrap();
    let report = SpdmReport::parse(&bytes).unwrap();
    let opaque = OpaqueData::parse(report.opaque_data()).unwrap();
    // This is a parser regression against the published capture, not an
    // authenticity or admission assertion for that unpaired vector.
    for id in [
        3, 4, 6, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 34, 36, 37,
    ] {
        let field = opaque.field(id).unwrap();
        assert_eq!(opaque.bytes(id).unwrap(), field.value);
        let changed = typed(&[(id, field.value_type ^ 1, field.value)]);
        assert!(
            OpaqueData::parse(&changed).unwrap().bytes(id).is_err(),
            "{id}"
        );
    }
    assert_eq!(opaque.text(3).unwrap(), "620.12");
    assert_eq!(opaque.vbios_version().unwrap(), "96.00.D9.00.0F");
    assert_eq!(opaque.svn(37).unwrap(), 0);
    for id in [22, 23, 25, 26, 35, 38] {
        let unprofiled = typed(&[(id, 0x82, &[1; 8])]);
        let parsed = OpaqueData::parse(&unprofiled).unwrap();
        assert_eq!(parsed.field(id).unwrap().value, [1; 8]);
        assert!(parsed.bytes(id).is_err(), "{id}");
    }
    let mut unsupported_version = typed(&[(36, 0x85, &[1, 0])]);
    unsupported_version[8] = 1;
    assert!(OpaqueData::parse(&unsupported_version)
        .unwrap()
        .mode()
        .is_err());
    let typed_switch = typed(&[(6, 0x86, b"96.10.55.00.01")]);
    assert!(OpaqueData::parse(&typed_switch)
        .unwrap()
        .switch_vbios_version()
        .is_err());
}
