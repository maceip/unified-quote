use super::*;

fn tpm_log() -> EventLog {
    EventLog::parse_tcg2(
        include_bytes!("../../testdata/boot/intel-tpm2-bios.bin"),
        ParseLimits::default(),
    )
    .unwrap()
}
fn registers_from_fixture() -> AuthenticatedRegisters {
    // Independent Python hashlib constants, standing in for the already
    // authenticated register input solely in this unit test.
    AuthenticatedRegisters::tpm(
        [
            (
                8,
                "5ad4920ba260a6608139827f06ae853292b42a97a14e1781889717e0ac83e760",
            ),
            (
                9,
                "53fbbb31a717f980b48b83f9830dc7b07b5d9b13f71073edcc09e9e5fb2e156b",
            ),
        ]
        .into_iter()
        .map(|(i, d)| ((TPM_ALG_SHA256, i), hex::decode(d).unwrap()))
        .collect(),
    )
    .unwrap()
}

#[test]
fn authenticates_grub_measured_bytes_but_not_event_labels() {
    let log = tpm_log();
    let verified = log.verify(&registers_from_fixture()).unwrap();
    let cmdline = verified
        .authenticated_command_line(130, TPM_ALG_SHA256, CommandLineProfile::Grub)
        .unwrap();
    assert!(cmdline
        .text()
        .starts_with("/vmlinuz-5.15.0-119-generic root="));
    assert!(verified.authenticated_digest(0, TPM_ALG_SHA256).is_err()); // NO_ACTION
    assert!(verified.authenticated_digest(1, TPM_ALG_SHA256).is_err()); // PCR0 not selected
    assert!(verified
        .authenticated_command_line(129, TPM_ALG_SHA256, CommandLineProfile::Grub)
        .is_err()); // file description
    let mut modified = tpm_log();
    modified.events[130].untrusted_event_data[20] ^= 1;
    let verified = modified.verify(&registers_from_fixture()).unwrap(); // metadata is not extended
    assert!(matches!(
        verified.authenticated_command_line(130, TPM_ALG_SHA256, CommandLineProfile::Grub),
        Err(BootError::ContentMismatch { .. })
    ));
}

#[test]
fn changed_digest_and_reordered_measurements_fail_quote_comparison() {
    let mut log = tpm_log();
    log.events[130].digests.get_mut(&TPM_ALG_SHA256).unwrap()[0] ^= 1;
    assert!(matches!(
        log.verify(&registers_from_fixture()),
        Err(BootError::RegisterMismatch { .. })
    ));
    let mut log = tpm_log();
    log.events.swap(128, 130);
    assert!(matches!(
        log.verify(&registers_from_fixture()),
        Err(BootError::RegisterMismatch { .. })
    ));
}

#[test]
fn unexplained_rtmr_three_is_a_hard_failure() {
    let log = EventLog::parse_tdx_ccel(
        include_bytes!("../../testdata/boot/intel-CCEL.data.bin"),
        ParseLimits::default(),
    )
    .unwrap();
    let replay = log.replay(TPM_ALG_SHA384).unwrap();
    let mut values = [[0; 48]; 4];
    for (i, v) in &replay.registers {
        values[*i as usize].copy_from_slice(v);
    }
    assert!(log.verify(&AuthenticatedRegisters::tdx(values)).is_ok());
    values[3][0] = 1;
    assert!(matches!(
        log.verify(&AuthenticatedRegisters::tdx(values)),
        Err(BootError::RegisterMismatch { index: 3, .. })
    ));
}

#[test]
fn invalid_or_repeated_locality_is_rejected() {
    let mut log = tpm_log();
    log.events[0].untrusted_event_data[16] = 4;
    assert!(log.replay(TPM_ALG_SHA256).is_err());
    let mut log = tpm_log();
    log.events.push(log.events[0].clone());
    assert!(log.replay(TPM_ALG_SHA256).is_err());
}

fn measured_command_line(profile: CommandLineProfile, text: &str) -> VerifiedBootLog {
    // Explicit test vector for loader encodings. Production has no constructor
    // that can manufacture a VerifiedBootLog from these fields.
    let (index, event_data, preimage) = match profile {
        CommandLineProfile::Grub => (
            8,
            format!("kernel_cmdline: {text}\0").into_bytes(),
            text.as_bytes().to_vec(),
        ),
        CommandLineProfile::SystemdLoadOptions => {
            let bytes: Vec<_> = text
                .encode_utf16()
                .chain([0])
                .flat_map(u16::to_le_bytes)
                .collect();
            (12, bytes.clone(), bytes)
        }
        CommandLineProfile::SystemdUkiEmbedded => {
            unreachable!("UKI section pairs use their own tests")
        }
    };
    let digest = hash(TPM_ALG_SHA256, &preimage).unwrap();
    let log = EventLog {
        kind: LogKind::Tpm2,
        algorithms: [(TPM_ALG_SHA256, 32)].into(),
        consumed_bytes: 0,
        events: vec![Event {
            offset: 0,
            register_index: index,
            reported_event_type: EV_IPL,
            digests: [(TPM_ALG_SHA256, digest)].into(),
            untrusted_event_data: event_data,
        }],
    };
    let value = log.replay(TPM_ALG_SHA256).unwrap().registers[&index].clone();
    log.verify(&AuthenticatedRegisters::tpm([((TPM_ALG_SHA256, index), value)].into()).unwrap())
        .unwrap()
}

#[test]
fn dm_verity_requires_authenticated_canonical_unique_root() {
    let expected = [0xab; 32];
    let root = hex::encode(expected);
    for profile in [
        CommandLineProfile::Grub,
        CommandLineProfile::SystemdLoadOptions,
    ] {
        let verified = measured_command_line(profile, &format!("quiet ro roothash={root}"));
        let claim = verified
            .verified_dm_verity(0, TPM_ALG_SHA256, profile, &expected)
            .unwrap();
        assert_eq!(claim.root_digest_hex, root);
        assert!(verified
            .verified_dm_verity(0, TPM_ALG_SHA256, profile, &[0xac; 32])
            .is_err());
        for text in [
            format!("roothash={root} roothash={root}"),
            format!("-- roothash={root}"),
            format!("roothash={root} systemd.verity=0"),
            format!("roothash=\"{root}\""),
            "quiet ro".into(),
        ] {
            let verified = measured_command_line(profile, &text);
            assert!(
                verified
                    .verified_dm_verity(0, TPM_ALG_SHA256, profile, &expected)
                    .is_err(),
                "accepted {text}"
            );
        }
    }
}
