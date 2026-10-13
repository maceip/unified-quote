use super::*;

fn captured() -> Vec<u8> {
    include_bytes!("../../../testdata/boot/coco-ccel-aael.bin").to_vec()
}
fn registers() -> AuthenticatedRegisters {
    // Independent Python hashlib replay of the upstream captured log. These
    // constants test replay; they do not represent an authenticated quote.
    let digests = [
        "b796e1c11396c198ae88794def4cb8e24fa9b35468287c298087f00d4de7433e4e31a297a4e5a03d4300fa6f3a96d47c",
        "3b0b906140fcea689c8774ac1eafcf0fef8e22ba81a047fd750ebd7df3235c2704df6106a758e31e5645e9838ff37406",
        "35f2801338c1b5fce96518f058c37e0fe9ed247a12dcd5f50d9c18fe4b6c71311bb63fca2640c7915817b6aa412a8480",
        "5e4ecd49d3c7983d6f9ca36755b5cee0b423d7fa8c5a88aeb0681bd4698772bc37b4463dc5f722efe352a66417257dad",
    ];
    AuthenticatedRegisters::tdx(digests.map(|v| hex::decode(v).unwrap().try_into().unwrap()))
}
fn policy() -> RuntimePolicy {
    RuntimePolicy {
        profile: RuntimeProfile::CocoAaelTcg2,
        expected_events: vec![
            RuntimeEvent {
                domain: "coco.com".into(),
                operation: "some-operation".into(),
                content: "some-content".into(),
            },
            RuntimeEvent {
                domain: "coco.com".into(),
                operation: "some-operation".into(),
                content: r#"{"key": "value", "nested-key": {"sub-key": "value"}}"#.into(),
            },
        ],
    }
}
fn parse(bytes: &[u8]) -> EventLog {
    EventLog::parse_tdx_ccel_with_aael(bytes, ParseLimits::default()).unwrap()
}

#[test]
fn captured_coco_runtime_replays_and_authenticates_tagged_statements() {
    let bytes = captured();
    assert!(EventLog::parse_tdx_ccel(&bytes, ParseLimits::default()).is_err());
    let log = parse(&bytes);
    assert_eq!(log.events().len(), 87);
    let (boot, runtime) = log.verify_tdx_runtime(&registers(), &policy()).unwrap();
    assert_eq!(runtime.events(), policy().expected_events);
    assert_eq!(runtime.event_indices(), [85, 86]);
    assert_eq!(
        runtime.rtmr3_hex(),
        hex::encode(&registers().values[&(TPM_ALG_SHA384, 3)])
    );
    assert!(boot.covered_registers().contains(&(TPM_ALG_SHA384, 3)));
}

#[test]
fn runtime_metadata_substitution_is_rejected_even_when_replay_matches() {
    let mut log = parse(&captured());
    log.events[85].untrusted_event_data[8] ^= 1;
    assert!(log.verify(&registers()).is_ok());
    assert!(matches!(
        log.verify_tdx_runtime(&registers(), &policy()),
        Err(BootError::ContentMismatch { event: 85 })
    ));
    let mut log = parse(&captured());
    log.events[85].digests.get_mut(&TPM_ALG_SHA384).unwrap()[0] ^= 1;
    assert!(matches!(
        log.verify_tdx_runtime(&registers(), &policy()),
        Err(BootError::RegisterMismatch { index: 3, .. })
    ));
}

#[test]
fn runtime_policy_rejects_omission_order_and_content_normalization() {
    let log = parse(&captured());
    let mut p = policy();
    p.expected_events.pop();
    assert!(log.verify_tdx_runtime(&registers(), &p).is_err());
    let mut p = policy();
    p.expected_events.reverse();
    assert!(log.verify_tdx_runtime(&registers(), &p).is_err());
    let mut p = policy();
    p.expected_events[1].content = p.expected_events[1].content.replace(' ', "");
    assert!(log.verify_tdx_runtime(&registers(), &p).is_err());
    let mut regs = registers();
    regs.values.remove(&(TPM_ALG_SHA384, 3));
    assert!(log.verify_tdx_runtime(&regs, &policy()).is_err());
}

#[test]
fn malformed_tags_lengths_types_and_truncated_records_are_rejected() {
    let original = captured();
    let log = parse(&original);
    let off = log.events[85].offset;
    for pos in [off + 4, off + 10, off + 12, off + 66, off + 70] {
        let mut bytes = original.clone();
        bytes[pos] ^= 1;
        assert!(
            EventLog::parse_tdx_ccel_with_aael(&bytes, ParseLimits::default()).is_err(),
            "accepted changed header at {pos}"
        );
    }
    for length in (off + 1)..log.events[86].offset {
        assert!(
            EventLog::parse_tdx_ccel_with_aael(&original[..length], ParseLimits::default())
                .is_err(),
            "accepted truncated record at {length}"
        );
    }
}

#[test]
fn collector_append_removes_only_validated_padding_and_rejects_foreign_records() {
    let bytes = captured();
    let log = parse(&bytes);
    let off = log.events[85].offset;
    let mut firmware = bytes[..off].to_vec();
    firmware.extend_from_slice(&[0xff; 16]);
    let aael = &bytes[off..log.consumed_bytes()];
    let combined = append_coco_aael(&firmware, aael, ParseLimits::default()).unwrap();
    assert_eq!(combined, &bytes[..log.consumed_bytes()]);
    parse(&combined)
        .verify_tdx_runtime(&registers(), &policy())
        .unwrap();
    assert!(append_coco_aael(&firmware, &bytes[off..], ParseLimits::default()).is_err());
    let mut foreign = aael.to_vec();
    foreign[0] = 3;
    assert!(append_coco_aael(&firmware, &foreign, ParseLimits::default()).is_err());
    let mut limits = ParseLimits::default();
    limits.max_log_bytes = combined.len() - 1;
    assert!(append_coco_aael(&firmware, aael, limits).is_err());
}
