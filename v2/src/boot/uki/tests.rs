use super::*;
use crate::boot::{AuthenticatedRegisters, Event, EventLog};

const KERNEL: &[u8] = b"kernel payload";
const OSREL: &[u8] = b"ID=test\nVERSION_ID=1\n\0";
const UNAME: &[u8] = b"6.12.1\0";

fn put16(out: &mut [u8], offset: usize, value: u16) {
    out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(out: &mut [u8], offset: usize, value: usize) {
    out[offset..offset + 4].copy_from_slice(&(value as u32).to_le_bytes());
}
fn align(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}
fn table_start(pe32: bool) -> usize {
    0x80 + 24 + if pe32 { 224 } else { 240 }
}

// Explicit PE/profile conformance vectors, not hardware captures. Production
// authentication still requires a verified quote; only this test module can
// construct AuthenticatedRegisters from the vector's independent PCR values.
fn pe_image(sections: &[(&str, &[u8])], pe32: bool) -> Vec<u8> {
    let headers = align(table_start(pe32) + sections.len() * 40, 512);
    let file_size = headers
        + sections
            .iter()
            .map(|(_, b)| align(b.len(), 512))
            .sum::<usize>();
    let mut out = vec![0; file_size];
    out[..2].copy_from_slice(b"MZ");
    put32(&mut out, 0x3c, 0x80);
    out[0x80..0x84].copy_from_slice(b"PE\0\0");
    put16(&mut out, 0x84, if pe32 { 0x14c } else { 0x8664 });
    put16(&mut out, 0x86, sections.len() as u16);
    put16(&mut out, 0x94, if pe32 { 224 } else { 240 });
    put16(&mut out, 0x96, 2);
    let optional = 0x98;
    put16(&mut out, optional, if pe32 { 0x10b } else { 0x20b });
    put32(&mut out, optional + 32, 4096);
    put32(&mut out, optional + 36, 512);
    put32(&mut out, optional + 56, (sections.len() + 1) * 4096);
    put32(&mut out, optional + 60, headers);
    put16(&mut out, optional + 68, 10);
    put32(&mut out, optional + if pe32 { 92 } else { 108 }, 16);
    let mut raw_offset = headers;
    for (i, (name, content)) in sections.iter().enumerate() {
        let entry = table_start(pe32) + i * 40;
        out[entry..entry + name.len()].copy_from_slice(name.as_bytes());
        put32(&mut out, entry + 8, content.len());
        put32(&mut out, entry + 12, (i + 1) * 4096);
        let raw_size = align(content.len(), 512);
        put32(&mut out, entry + 16, raw_size);
        put32(
            &mut out,
            entry + 20,
            if raw_size == 0 { 0 } else { raw_offset },
        );
        put32(&mut out, entry + 36, 0x4000_0040);
        out[raw_offset..raw_offset + content.len()].copy_from_slice(content);
        // Deliberately nonzero disk padding: it is outside VirtualSize and must
        // not be measured as if it were part of the loaded section content.
        out[raw_offset + content.len()..raw_offset + raw_size].fill(0xcc);
        raw_offset += raw_size;
    }
    out
}

fn command_line() -> String {
    format!("quiet ro roothash={}", "ab".repeat(32))
}
fn components(cmdline: &[u8]) -> Vec<(&'static str, &[u8])> {
    // PE order intentionally differs from the systemd measurement order.
    vec![
        (".text", b"stub code"),
        (".cmdline", cmdline),
        (".pcrsig", b"UNTRUSTED"),
        (".uname", UNAME),
        (".osrel", OSREL),
        (".linux", KERNEL),
    ]
}

fn vector_log(kind: LogKind, algorithm: u16, sections: &[(&str, &[u8])]) -> (EventLog, UkiPolicy) {
    let mut events = Vec::new();
    let mut expected_sections = BTreeMap::new();
    for name in MEASURED_SECTIONS {
        let Some((_, content)) = sections.iter().find(|(n, _)| n == name) else {
            continue;
        };
        for bytes in [format!("{name}\0").into_bytes(), content.to_vec()] {
            events.push(Event {
                offset: events.len(),
                register_index: if kind == LogKind::Tpm2 { 11 } else { 3 },
                reported_event_type: EV_IPL,
                digests: [(algorithm, hash(algorithm, &bytes).unwrap())].into(),
                // Descriptions are deliberately false. Neither these labels nor
                // candidate PE section-table names can select trusted claims.
                untrusted_event_data: b"attacker-controlled label".to_vec(),
            });
        }
        expected_sections.insert(
            (*name).to_owned(),
            hex::encode(hash(algorithm, content).unwrap()),
        );
    }
    let log = EventLog {
        kind,
        algorithms: [(algorithm, hash(algorithm, b"").unwrap().len())].into(),
        events,
        consumed_bytes: 0,
    };
    let policy = UkiPolicy {
        selection: None,
        execution: None,
        profile: UkiProfile::SystemdStubV258,
        first_section_event: 0,
        algorithm,
        expected_sections,
        expected_command_line: None,
        expected_verity_root: None,
    };
    (log, policy)
}

fn authenticate_vector(log: EventLog, algorithm: u16) -> VerifiedBootLog {
    let replay = log.replay(algorithm).unwrap();
    let registers = match log.kind {
        LogKind::Tpm2 => {
            AuthenticatedRegisters::tpm([((algorithm, 11), replay.registers[&11].clone())].into())
                .unwrap()
        }
        LogKind::TdxCcel => {
            let mut values = [[0; 48]; 4];
            for (index, value) in replay.registers {
                values[index as usize].copy_from_slice(&value)
            }
            AuthenticatedRegisters::tdx(values)
        }
    };
    log.verify(&registers).unwrap()
}

#[test]
fn published_pair_profile_binds_metadata_and_verity_for_tpm_and_ccel() {
    let line = command_line();
    let components = components(line.as_bytes());
    for (kind, algorithm) in [
        (LogKind::Tpm2, TPM_ALG_SHA256),
        (LogKind::TdxCcel, TPM_ALG_SHA384),
    ] {
        for pe32 in [false, true] {
            let image = pe_image(&components, pe32);
            let (log, mut policy) = vector_log(kind, algorithm, &components);
            // Independently calculated Python hashlib section vectors.
            let (kernel, osrel) = if algorithm == TPM_ALG_SHA256 {
                (
                    "22b5d44ceedf4085570834c0c9611d00b445c093ca6f57de8a7fd3982fbe7772",
                    "e6c839d63d4908f9495cc15a81d53947c12e156c601f45397dcf7b908819a171",
                )
            } else {
                ("6d5cdbf2db5570b8c965c7ea8b66ff6f44664e59c16a1dfc6ec12760e03f378eae505bdb53622931480e6d6a999abcb2",
                 "3ee2d242b7d49717323289d5bff9baab07ccb0cbaa3e5de2f093e3487624b3ac3468102b90b79f576f9b2197929464ad")
            };
            policy
                .expected_sections
                .insert(".linux".into(), kernel.into());
            policy
                .expected_sections
                .insert(".osrel".into(), osrel.into());
            policy.expected_command_line = Some(line.clone());
            policy.expected_verity_root = Some("ab".repeat(32));
            let claims = authenticate_vector(log, algorithm)
                .verify_uki(&image, &policy)
                .unwrap();
            assert_eq!(claims.embedded_command_line(), Some(line.as_str()));
            assert_eq!(claims.os_release(), Some("ID=test\nVERSION_ID=1\n"));
            assert_eq!(claims.kernel_release(), Some("6.12.1"));
            assert_eq!(claims.dm_verity().unwrap().root_digest_hex, "ab".repeat(32));
            assert_eq!(claims.sections.len(), 4);
            assert!(!claims
                .sections
                .iter()
                .any(|s| matches!(s.name.as_str(), ".pcrsig" | ".text")));
        }
    }
}

#[test]
fn independent_pcr_vectors_commit_section_name_nul_and_payload_order() {
    let line = command_line();
    let components = components(line.as_bytes());
    let image = pe_image(&components, false);
    // Python hashlib, independent of both Rust replay and the PE parser:
    // p = zero(digest_size); for name,data in canonical order:
    // for b in [name.encode()+b'\0',data]: p = H(p + H(b)).
    for (kind, algorithm, expected) in [
        (LogKind::Tpm2, TPM_ALG_SHA256, "0951edf38e927e3bb66eba41f984d2d2a5b2e04c353f78d3ac61b2050bbb6f47"),
        (LogKind::TdxCcel, TPM_ALG_SHA384, "f79e10ab736f33a0b480d7f63cfd60eed0e06c9dbeacec2c52d956f53d4610fee759072b5e4830a9974ebf0740b765a0"),
    ] {
        let (log, policy) = vector_log(kind, algorithm, &components);
        let registers = if kind == LogKind::Tpm2 {
            AuthenticatedRegisters::tpm([((algorithm, 11), hex::decode(expected).unwrap())].into()).unwrap()
        } else {
            let mut rtmr = [[0; 48]; 4];
            rtmr[2].copy_from_slice(&hex::decode(expected).unwrap());
            AuthenticatedRegisters::tdx(rtmr)
        };
        assert!(log.clone().verify(&registers).unwrap().verify_uki(&image, &policy).is_ok());
        let mut wrong = log.clone();
        wrong.events[0].digests.insert(algorithm, hash(algorithm, b".linux").unwrap());
        assert!(wrong.verify(&registers).is_err());
        let mut wrong = log;
        wrong.events.swap(0, 1);
        assert!(wrong.verify(&registers).is_err());
    }
}

#[test]
fn candidate_bytes_names_policy_and_pair_order_cannot_be_substituted() {
    let components = components(b"quiet\0");
    let image = pe_image(&components, false);
    let (log, policy) = vector_log(LogKind::Tpm2, TPM_ALG_SHA256, &components);
    let verified = authenticate_vector(log.clone(), TPM_ALG_SHA256);
    let parsed = UnverifiedUki::parse(&image).unwrap();
    let mut changed = image.clone();
    changed[parsed.section(".cmdline").unwrap().raw_offset] ^= 1;
    assert!(matches!(
        verified.verify_uki(&changed, &policy),
        Err(BootError::ContentMismatch { .. })
    ));
    let mut changed_policy = policy.clone();
    changed_policy
        .expected_sections
        .insert(".linux".into(), "00".repeat(32));
    assert!(verified.verify_uki(&image, &changed_policy).is_err());
    changed_policy = policy.clone();
    changed_policy.expected_sections.remove(".osrel");
    assert!(verified.verify_uki(&image, &changed_policy).is_err());
    changed_policy = policy.clone();
    changed_policy
        .expected_sections
        .insert(".pcrsig".into(), "00".repeat(32));
    assert!(verified.verify_uki(&image, &changed_policy).is_err());
    // A raw data digest without its preceding authenticated section-name digest
    // cannot establish that those bytes represent .cmdline or any other name.
    let mut missing_name = log.clone();
    missing_name.events.remove(4);
    assert!(authenticate_vector(missing_name, TPM_ALG_SHA256)
        .verify_uki(&image, &policy)
        .is_err());
    let mut swapped = log;
    swapped.events.swap(4, 6);
    assert!(authenticate_vector(swapped, TPM_ALG_SHA256)
        .verify_uki(&image, &policy)
        .is_err());
}

#[test]
fn only_authenticated_registers_and_same_register_order_are_used() {
    let components = components(b"quiet");
    let image = pe_image(&components, false);
    let (mut log, policy) = vector_log(LogKind::Tpm2, TPM_ALG_SHA256, &components);
    let unrelated = Event {
        offset: 0,
        register_index: 4,
        reported_event_type: EV_IPL,
        digests: [(TPM_ALG_SHA256, vec![0; 32])].into(),
        untrusted_event_data: vec![],
    };
    log.events.insert(1, unrelated.clone());
    assert!(authenticate_vector(log.clone(), TPM_ALG_SHA256)
        .verify_uki(&image, &policy)
        .is_ok());
    let raw_pcr4 = log.replay(TPM_ALG_SHA256).unwrap().registers[&4].clone();
    let uncovered = log
        .clone()
        .verify(&AuthenticatedRegisters::tpm([((TPM_ALG_SHA256, 4), raw_pcr4)].into()).unwrap())
        .unwrap();
    assert!(matches!(
        uncovered.verify_uki(&image, &policy),
        Err(BootError::UnauthenticatedEvent(_))
    ));
    log.events[1].register_index = 11;
    assert!(authenticate_vector(log, TPM_ALG_SHA256)
        .verify_uki(&image, &policy)
        .is_err());
}

#[test]
fn pe_virtual_zero_fill_is_measured_but_raw_alignment_padding_is_not() {
    let mut content = vec![0x41; 512];
    content.extend_from_slice(&[0; 17]);
    let mut image = pe_image(&[(".linux", &content[..512])], false);
    put32(&mut image, table_start(false) + 8, content.len());
    let (log, policy) = vector_log(LogKind::Tpm2, TPM_ALG_SHA256, &[(".linux", &content)]);
    let verified = authenticate_vector(log, TPM_ALG_SHA256);
    assert!(verified.verify_uki(&image, &policy).is_ok());
    let (wrong_log, wrong_policy) = vector_log(
        LogKind::Tpm2,
        TPM_ALG_SHA256,
        &[(".linux", &content[..512])],
    );
    assert!(authenticate_vector(wrong_log, TPM_ALG_SHA256)
        .verify_uki(&image, &wrong_policy)
        .is_err());
}

#[test]
fn a_candidate_cannot_omit_a_following_measured_section() {
    let image = pe_image(&[(".linux", KERNEL)], false);
    let (log, _) = vector_log(
        LogKind::Tpm2,
        TPM_ALG_SHA256,
        &[(".linux", KERNEL), (".osrel", OSREL)],
    );
    let (_, policy) = vector_log(LogKind::Tpm2, TPM_ALG_SHA256, &[(".linux", KERNEL)]);
    assert!(authenticate_vector(log, TPM_ALG_SHA256)
        .verify_uki(&image, &policy)
        .is_err());
}

#[test]
fn text_claims_require_unambiguous_authenticated_contents_and_exact_policy() {
    for line in [b"quiet\0hidden".as_slice(), &[0xff, 0], b"quiet\x1b"] {
        let components = components(line);
        let image = pe_image(&components, false);
        let (log, policy) = vector_log(LogKind::Tpm2, TPM_ALG_SHA256, &components);
        assert!(authenticate_vector(log, TPM_ALG_SHA256)
            .verify_uki(&image, &policy)
            .is_err());
    }
    let line = command_line();
    let components = components(line.as_bytes());
    let image = pe_image(&components, false);
    let (log, mut policy) = vector_log(LogKind::Tpm2, TPM_ALG_SHA256, &components);
    let verified = authenticate_vector(log, TPM_ALG_SHA256);
    policy.expected_command_line = Some("different".into());
    assert!(verified.verify_uki(&image, &policy).is_err());
    policy.expected_command_line = None;
    policy.expected_verity_root = Some("ac".repeat(32));
    assert!(matches!(
        verified.verify_uki(&image, &policy),
        Err(BootError::VerityRootMismatch)
    ));
    assert!(verified
        .authenticated_command_line(5, TPM_ALG_SHA256, CommandLineProfile::SystemdUkiEmbedded)
        .is_err());
}

#[test]
fn malformed_pe_ranges_headers_counts_and_names_are_rejected() {
    let image = pe_image(&[(".linux", KERNEL), (".cmdline", b"quiet")], false);
    for length in [0, 1, 63, 127, 151, table_start(false) + 79, image.len() - 1] {
        assert!(
            UnverifiedUki::parse(&image[..length]).is_err(),
            "length {length}"
        );
    }
    let table = table_start(false);
    for (offset, value) in [
        (0x3c, u32::MAX as usize),
        (0x98 + 32, 3),
        (0x98 + 56, 0),
        (0x98 + 60, 384),
        (table + 8, u32::MAX as usize),
        (table + 20, u32::MAX as usize),
        (table + 40 + 20, 512),
        (table + 40 + 12, 4096),
        (table + 24, 1),
    ] {
        let mut bad = image.clone();
        put32(&mut bad, offset, value);
        assert!(
            UnverifiedUki::parse(&bad).is_err(),
            "offset {offset:x} value {value:x}"
        );
    }
    for (offset, value) in [(0x86, 97), (0x94, 2), (0x98, 0x999), (0x98 + 68, 3)] {
        let mut bad = image.clone();
        put16(&mut bad, offset, value);
        assert!(UnverifiedUki::parse(&bad).is_err());
    }
    let mut duplicate = image.clone();
    duplicate[table + 40..table + 48].copy_from_slice(&image[table..table + 8]);
    assert!(UnverifiedUki::parse(&duplicate).is_ok()); // published first-match selection
    let mut hidden_name = image;
    hidden_name[table + 7] = b'x';
    assert!(UnverifiedUki::parse(&hidden_name).is_err());
}

#[test]
fn absent_kernel_fails_explicitly() {
    assert!(UnverifiedUki::parse(&pe_image(&[(".cmdline", b"quiet")], false)).is_err());
}

#[test]
fn profile_overlay_uses_base_then_chosen_profile_and_first_match() {
    let image_sections = [
        (".linux", KERNEL),
        (".cmdline", b"base".as_slice()),
        (".profile", b"ID=normal".as_slice()),
        (".cmdline", b"normal".as_slice()),
        (".profile", b"ID=recovery".as_slice()),
        (".cmdline", b"recovery".as_slice()),
        (".cmdline", b"ignored duplicate".as_slice()),
    ];
    let image = pe_image(&image_sections, false);
    let selected = [
        (".linux", KERNEL),
        (".cmdline", b"recovery".as_slice()),
        (".profile", b"ID=recovery".as_slice()),
    ];
    let (log, mut policy) = vector_log(LogKind::TdxCcel, TPM_ALG_SHA384, &selected);
    policy.selection = Some(UkiSelectionPolicy {
        profile_index: 1,
        ..Default::default()
    });
    let verified = authenticate_vector(log, TPM_ALG_SHA384);
    let uki = verified.verify_uki(&image, &policy).unwrap();
    assert_eq!(uki.embedded_command_line(), Some("recovery"));
    assert_eq!(uki.authenticated_profile_index(), None); // no numeric CCEL tag in v258
    policy.selection.as_mut().unwrap().profile_index = 0;
    assert!(verified.verify_uki(&image, &policy).is_err());
    policy.selection.as_mut().unwrap().profile_index = 2;
    assert!(verified.verify_uki(&image, &policy).is_err());
}

fn fdt(compatible: &[u8]) -> Vec<u8> {
    let mut structure = Vec::new();
    structure.extend_from_slice(&1u32.to_be_bytes());
    structure.extend_from_slice(&[0; 4]);
    structure.extend_from_slice(&3u32.to_be_bytes());
    structure.extend_from_slice(&(compatible.len() as u32).to_be_bytes());
    structure.extend_from_slice(&0u32.to_be_bytes());
    structure.extend_from_slice(compatible);
    while structure.len() % 4 != 0 {
        structure.push(0);
    }
    structure.extend_from_slice(&2u32.to_be_bytes());
    structure.extend_from_slice(&9u32.to_be_bytes());
    let mut data = vec![0; 56];
    let strings = b"compatible\0";
    for (at, value) in [
        (0, 0xd00dfeed),
        (4, 56 + structure.len() + strings.len()),
        (8, 56),
        (12, 56 + structure.len()),
        (16, 40),
        (20, 17),
        (24, 16),
        (32, strings.len()),
        (36, structure.len()),
    ] {
        data[at..at + 4].copy_from_slice(&(value as u32).to_be_bytes());
    }
    data.extend_from_slice(&structure);
    data.extend_from_slice(strings);
    data
}
fn efifw(id: &[u8]) -> Vec<u8> {
    let mut blob = vec![0; 16];
    for (at, n) in [(0, 0xfeeddead), (4, 16), (8, id.len()), (12, 4)] {
        put32(&mut blob, at, n);
    }
    blob.extend_from_slice(id);
    blob.extend_from_slice(b"code");
    blob
}

#[test]
fn device_selection_matches_first_compatible_and_first_firmware_id() {
    let dt1 = fdt(b"vendor,wrong\0vendor,right\0");
    let dt2 = fdt(b"vendor,right\0vendor,soc\0");
    let fw1 = efifw(b"wrong\0");
    let fw2 = efifw(b"selected\0");
    let image = pe_image(
        &[
            (".linux", KERNEL),
            (".dtbauto", &dt1),
            (".dtbauto", &dt2),
            (".efifw", &fw1),
            (".efifw", &fw2),
        ],
        false,
    );
    let selected = [
        (".linux", KERNEL),
        (".dtbauto", dt2.as_slice()),
        (".efifw", fw2.as_slice()),
    ];
    let (log, mut policy) = vector_log(LogKind::TdxCcel, TPM_ALG_SHA384, &selected);
    let verified = authenticate_vector(log, TPM_ALG_SHA384);
    assert!(verified.verify_uki(&image, &policy).is_err());
    policy.selection = Some(UkiSelectionPolicy {
        expected_compatible: Some("vendor,right".into()),
        expected_firmware_id: Some("selected".into()),
        ..Default::default()
    });
    verified.verify_uki(&image, &policy).unwrap();
    policy.selection.as_mut().unwrap().expected_compatible = Some("vendor,soc".into());
    assert!(verified.verify_uki(&image, &policy).is_err());
    let mut invalid = dt2.clone();
    invalid[32..36].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(selection::fdt_first_compatible(&invalid).is_err());
    let mut invalid = fw2.clone();
    put32(&mut invalid, 8, u32::MAX as usize);
    assert!(selection::efi_firmware_id(&invalid).is_err());
    assert!(selection::efi_firmware_id(&efifw(b"embedded\0nul\0")).is_err());
}

fn add_load_options(log: &mut EventLog, text: &str) -> usize {
    let index = log.events.len();
    let raw: Vec<_> = text
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect();
    log.events.push(Event {
        offset: index,
        register_index: if log.kind == LogKind::Tpm2 { 12 } else { 3 },
        reported_event_type: EV_IPL,
        digests: [(TPM_ALG_SHA384, hash(TPM_ALG_SHA384, &raw).unwrap())].into(),
        untrusted_event_data: b"false event description".to_vec(),
    });
    index
}
#[test]
fn execution_reconstructs_mangled_embedded_and_aggregate_addon_command_line() {
    let parts = [
        (".linux", KERNEL),
        (".cmdline", b"\t quiet\t ro  \n".as_slice()),
    ];
    let image = pe_image(&parts, false);
    let (mut log, mut policy) = vector_log(LogKind::TdxCcel, TPM_ALG_SHA384, &parts);
    let addon = add_load_options(&mut log, "global=1 local=2");
    policy.execution = Some(UkiExecutionPolicy {
        base: UkiCommandLineBase::Embedded,
        addons: Some(UkiMeasuredAppend {
            event_index: addon,
            expected_fragments: vec![" global=1 ".into(), "\tlocal=2\n".into()],
        }),
        smbios: None,
        binary_addons: vec![],
        expected_effective_command_line: "quiet  ro global=1 local=2".into(),
        expected_verity_root: None,
        other_config_events: BTreeMap::new(),
    });
    let verified = authenticate_vector(log.clone(), TPM_ALG_SHA384);
    assert_eq!(
        verified
            .verify_uki(&image, &policy)
            .unwrap()
            .execution()
            .unwrap()
            .effective_command_line(),
        "quiet  ro global=1 local=2"
    );
    add_load_options(&mut log, "unexpected=1");
    let verified = authenticate_vector(log, TPM_ALG_SHA384);
    assert!(verified.verify_uki(&image, &policy).is_err()); // every configuration measurement accounted
}

#[test]
fn execution_rejects_reordered_appends_and_unsupported_tdx_smbios_or_tagged_addons() {
    let parts = [(".linux", KERNEL), (".cmdline", b"embedded".as_slice())];
    let image = pe_image(&parts, false);
    let (mut log, mut policy) = vector_log(LogKind::TdxCcel, TPM_ALG_SHA384, &parts);
    let base = add_load_options(&mut log, "override");
    let addon = add_load_options(&mut log, "extra");
    policy.execution = Some(UkiExecutionPolicy {
        base: UkiCommandLineBase::LoadOptions {
            event_index: base,
            expected_text: "override".into(),
        },
        addons: Some(UkiMeasuredAppend {
            event_index: addon,
            expected_fragments: vec!["extra".into()],
        }),
        smbios: None,
        binary_addons: vec![],
        expected_effective_command_line: "override extra".into(),
        expected_verity_root: None,
        other_config_events: BTreeMap::new(),
    });
    let verified = authenticate_vector(log, TPM_ALG_SHA384);
    verified.verify_uki(&image, &policy).unwrap();
    policy
        .execution
        .as_mut()
        .unwrap()
        .addons
        .as_mut()
        .unwrap()
        .event_index = base;
    assert!(verified.verify_uki(&image, &policy).is_err());
    policy
        .execution
        .as_mut()
        .unwrap()
        .addons
        .as_mut()
        .unwrap()
        .event_index = addon;
    let execution = policy.execution.as_mut().unwrap();
    execution.smbios = execution.addons.take();
    assert!(verified.verify_uki(&image, &policy).is_err());
}

#[test]
fn tpm_profile_number_and_binary_addons_require_their_own_quoted_pcr() {
    let parts = [
        (".linux", KERNEL),
        (".cmdline", b"quiet".as_slice()),
        (".profile", b"ID=recovery".as_slice()),
    ];
    let image = pe_image(
        &[
            (".linux", KERNEL),
            (".profile", b"ID=normal"),
            (".profile", b"ID=recovery"),
            (".cmdline", b"quiet"),
        ],
        false,
    );
    let (mut log, mut policy) = vector_log(LogKind::Tpm2, TPM_ALG_SHA256, &parts);
    let number: Vec<_> = "1"
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect();
    log.events.insert(
        0,
        Event {
            offset: 0,
            register_index: 12,
            reported_event_type: 6,
            digests: [(TPM_ALG_SHA256, hash(TPM_ALG_SHA256, &number).unwrap())].into(),
            untrusted_event_data: vec![],
        },
    );
    policy.first_section_event = 1;
    policy.selection = Some(UkiSelectionPolicy {
        profile_index: 1,
        profile_event: Some(0),
        ..Default::default()
    });
    let initrd = b"approved addon initrd";
    let index = log.events.len();
    let digest = hash(TPM_ALG_SHA256, initrd).unwrap();
    log.events.push(Event {
        offset: 0,
        register_index: 12,
        reported_event_type: 6,
        digests: [(TPM_ALG_SHA256, digest.clone())].into(),
        untrusted_event_data: b"filename is not authenticated".to_vec(),
    });
    policy.execution = Some(UkiExecutionPolicy {
        base: UkiCommandLineBase::Embedded,
        addons: None,
        smbios: None,
        binary_addons: vec![UkiAddonMeasurement {
            kind: UkiAddonKind::Initrd,
            event_index: index,
            expected_digest_hex: hex::encode(digest),
        }],
        expected_effective_command_line: "quiet".into(),
        expected_verity_root: None,
        other_config_events: [(0, hex::encode(hash(TPM_ALG_SHA256, &number).unwrap()))].into(),
    });
    let replay = log.replay(TPM_ALG_SHA256).unwrap();
    let regs = AuthenticatedRegisters::tpm(
        [11, 12]
            .into_iter()
            .map(|i| ((TPM_ALG_SHA256, i), replay.registers[&i].clone()))
            .collect(),
    )
    .unwrap();
    let verified = log.verify(&regs).unwrap();
    let result = verified.verify_uki(&image, &policy).unwrap();
    assert_eq!(result.authenticated_profile_index(), Some(1));
    assert!(result.execution().is_some());
    let limited =
        AuthenticatedRegisters::tpm([((TPM_ALG_SHA256, 11), replay.registers[&11].clone())].into())
            .unwrap();
    assert!(log
        .verify(&limited)
        .unwrap()
        .verify_uki(&image, &policy)
        .is_err());
}
