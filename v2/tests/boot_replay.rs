//! Captured Intel SDK logs, not generated production substitutes. Reference
//! replay constants were computed independently with Python hashlib. The SDK
//! fixture does not include an authenticated quote; these tests do not claim a
//! successful live boot attestation.

use unified_quote::boot::{
    self, BootError, CcelTable, EventLog, ParseLimits, TPM_ALG_SHA256, TPM_ALG_SHA384,
};

const CCEL: &[u8] = include_bytes!("../testdata/boot/intel-CCEL.data.bin");
const TABLE: &[u8] = include_bytes!("../testdata/boot/intel-CCEL.bin");
const TPM: &[u8] = include_bytes!("../testdata/boot/intel-tpm2-bios.bin");

#[test]
fn intel_captured_ccel_replays_using_uefi_measurement_register_mapping() {
    let table = CcelTable::parse(TABLE, ParseLimits::default()).unwrap();
    assert_eq!(table.log_area_minimum_length, 65536);
    let log = EventLog::parse_tdx_ccel(CCEL, ParseLimits::default()).unwrap();
    assert_eq!(log.events().len(), 19);
    assert_eq!(log.consumed_bytes(), 2026);
    let replay = log.replay(TPM_ALG_SHA384).unwrap();
    for (index, wanted) in [
        "8083cd6898cc52a90231cdf9c0532bf9513c40465c6f71e56cbe32ee2c11a9dfc030297ca3ca0f62477d6d1f610d3fdb",
        "6484f0d72c03521c0434553be34e8db8228b729e799666d2b7754085c77aa9981f5a440df3047194b24f212ff1160c1e",
        "c3e7ed9d7e909b29732f676d01dc63de869b049362b522a315cb042689670be07344c347cf85d985c7b928d4934e41e1",
    ].iter().enumerate() {
        assert_eq!(hex::encode(&replay.registers[&(index as u32)]), *wanted);
    }
    assert_eq!(replay.registers[&3], [0; 48]);
}

#[test]
fn intel_captured_tpm2_log_replays_pcr_zero_through_nine_with_startup_locality_three() {
    let log = EventLog::parse_tcg2(TPM, ParseLimits::default()).unwrap();
    assert_eq!(log.events().len(), 135);
    let replay = log.replay(TPM_ALG_SHA256).unwrap();
    let values = [
        "079a2a9d8dff890295ecbca39089b01c06f0866f2080941a651f97433dcbf584",
        "6b52cd178e6a9902bc4cc89365f9a6837833eb370b2858df909b13748898ac9a",
        "af3544b4e74294f11b94e5c0ea5660a2a9c0f7c0ad3247880e18b80b1a369674",
        "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969",
        "e400522fa78f9e1206086aa4c2741027dee88e9b7e10c5245c7e9ab2a4c1c84e",
        "386c84f8657e6049167ed1d857639b48d35acb155f96dbf41ccb462b9c95a2b3",
        "9701e437ff48261705a195fa33d2ee7e49e9a4cf4036e49a66cdc2eb973df3bf",
        "292aa56f305f800981b80f96005dc3ca744aa7008b431b4b19e60a4bc3a365d1",
        "5ad4920ba260a6608139827f06ae853292b42a97a14e1781889717e0ac83e760",
        "53fbbb31a717f980b48b83f9830dc7b07b5d9b13f71073edcc09e9e5fb2e156b",
    ];
    for (index, wanted) in values.iter().enumerate() {
        assert_eq!(hex::encode(&replay.registers[&(index as u32)]), *wanted);
    }
    assert!(matches!(
        log.replay(4),
        Err(BootError::UnsupportedAlgorithm(4))
    ));
}

#[test]
fn acpi_checksums_and_lengths_are_enforced() {
    let mut invalid = TABLE.to_vec();
    invalid[20] ^= 1;
    assert!(CcelTable::parse(&invalid, ParseLimits::default()).is_err());
    for end in 0..56 {
        assert!(CcelTable::parse(&TABLE[..end], ParseLimits::default()).is_err());
    }
}

#[test]
fn ccel_padding_cannot_hide_an_event_tail() {
    let mut invalid = CCEL.to_vec();
    invalid[65535] = 0;
    assert!(EventLog::parse_tdx_ccel(&invalid, ParseLimits::default()).is_err());
}

#[test]
fn every_interior_ccel_truncation_rejects_without_panicking() {
    let log = EventLog::parse_tdx_ccel(CCEL, ParseLimits::default()).unwrap();
    let mut boundaries: Vec<_> = log.events().iter().map(|e| e.offset).collect();
    boundaries.push(log.consumed_bytes());
    for end in 0..log.consumed_bytes() {
        if !boundaries.contains(&end) {
            assert!(
                EventLog::parse_tdx_ccel(&CCEL[..end], ParseLimits::default()).is_err(),
                "accepted interior byte {end}"
            );
        }
    }
}

#[test]
fn malformed_counts_algorithms_and_indexes_are_rejected() {
    let first_event = EventLog::parse_tdx_ccel(CCEL, ParseLimits::default())
        .unwrap()
        .events()[0]
        .offset;
    for (offset, replacement) in [
        (first_event, 4u32),
        (first_event + 8, u32::MAX),
        (56, u32::MAX),
    ] {
        let mut invalid = CCEL.to_vec();
        invalid[offset..offset + 4].copy_from_slice(&replacement.to_le_bytes());
        assert!(EventLog::parse_tdx_ccel(&invalid, ParseLimits::default()).is_err());
    }
    let mut invalid = CCEL.to_vec();
    invalid[first_event + 12..first_event + 14].copy_from_slice(&0xffffu16.to_le_bytes());
    assert!(EventLog::parse_tdx_ccel(&invalid, ParseLimits::default()).is_err());
}

#[test]
fn configured_resource_bounds_are_enforced() {
    for limits in [
        ParseLimits {
            max_log_bytes: 65535,
            ..Default::default()
        },
        ParseLimits {
            max_events: 18,
            ..Default::default()
        },
        ParseLimits {
            max_event_bytes: 8,
            ..Default::default()
        },
        ParseLimits {
            max_algorithms: 0,
            ..Default::default()
        },
    ] {
        assert!(EventLog::parse_tdx_ccel(CCEL, limits).is_err());
    }
}

#[test]
fn filesystem_reader_checks_table_against_actual_log_area() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("table"), TABLE).unwrap();
    std::fs::write(temp.path().join("data"), &CCEL[..2026]).unwrap();
    assert!(boot::read_tdx_ccel(
        &temp.path().join("table"),
        &temp.path().join("data"),
        ParseLimits::default()
    )
    .is_err());
    std::fs::write(temp.path().join("data"), CCEL).unwrap();
    assert!(boot::read_tdx_ccel(
        &temp.path().join("table"),
        &temp.path().join("data"),
        ParseLimits::default()
    )
    .is_ok());
}

#[test]
fn closure_identity_covers_contents_paths_permissions_and_has_no_implicit_exclusions() {
    use boot::closure::{measure_closure, ClosureLimits};
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    std::fs::write(root.join("kernel"), b"kernel bytes").unwrap();
    std::fs::write(root.join("out"), b"included despite legacy skip-name").unwrap();
    let names = vec!["kernel".into(), "out".into()];
    let original = measure_closure(&root, &names, ClosureLimits::default()).unwrap();
    let reordered = measure_closure(
        &root,
        &["out".into(), "kernel".into()],
        ClosureLimits::default(),
    )
    .unwrap();
    assert_eq!(original.root_sha384(), reordered.root_sha384());
    std::fs::set_permissions(root.join("kernel"), std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_ne!(
        original.root_sha384(),
        measure_closure(&root, &names, ClosureLimits::default())
            .unwrap()
            .root_sha384()
    );
    assert!(measure_closure(&root, &["../kernel".into()], ClosureLimits::default()).is_err());
    assert!(measure_closure(
        &root,
        &["kernel".into(), "kernel".into()],
        ClosureLimits::default()
    )
    .is_err());
    std::os::unix::fs::symlink(&root, root.join("escape")).unwrap();
    assert!(measure_closure(&root, &["escape/kernel".into()], ClosureLimits::default()).is_err());
    assert!(measure_closure(
        &root,
        &names,
        ClosureLimits {
            max_total_bytes: 1,
            ..Default::default()
        }
    )
    .is_err());
}
