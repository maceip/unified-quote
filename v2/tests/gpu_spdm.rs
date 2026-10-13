//! NVIDIA-published reference vectors, not a claim of local hardware testing.
//! See testdata/gpu/nvidia/README.md for the pinned source and license.
#![cfg(feature = "gpu")]

use der::Decode;
use p384::ecdsa::VerifyingKey;
use unified_quote::gpu::spdm::{SpdmError, SpdmReport, MAX_REPORT_SIZE};
use x509_cert::Certificate;

struct Fixture {
    report: Vec<u8>,
    nonce: [u8; 32],
    key: VerifyingKey,
}

fn fixture(blackwell: bool) -> Fixture {
    let (report, chain, nonce) = if blackwell {
        (
            include_str!("../testdata/gpu/nvidia/blackwellAttestationReport.txt"),
            include_str!("../testdata/gpu/nvidia/blackwellCertChain.txt"),
            "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb",
        )
    } else {
        (
            include_str!("../testdata/gpu/nvidia/hopperAttestationReport.txt"),
            include_str!("../testdata/gpu/nvidia/hopperCertChain.txt"),
            "27a328247bf7935c993341cf587be6f05986ccce4fe7ba2c54100bd616a58f66",
        )
    };
    let mut pem = std::io::Cursor::new(chain);
    let leaf = rustls_pemfile::certs(&mut pem).next().unwrap().unwrap();
    let cert = Certificate::from_der(&leaf).unwrap();
    // Deliberately only extract the key: these tests prove report signature
    // interoperability, not certificate trust, freshness today, or RIM policy.
    let key = VerifyingKey::from_sec1_bytes(
        cert.tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .unwrap(),
    )
    .unwrap();
    Fixture {
        report: hex::decode(report.trim()).unwrap(),
        nonce: hex::decode(nonce).unwrap().try_into().unwrap(),
        key,
    }
}

#[test]
fn nvidia_hopper_and_blackwell_transcripts_verify() {
    for blackwell in [false, true] {
        let f = fixture(blackwell);
        let report = SpdmReport::parse(&f.report).unwrap();
        assert_eq!(report.request_nonce(), f.nonce);
        assert_eq!(report.measurements().len(), 64);
        for (i, measurement) in report.measurements().iter().enumerate() {
            assert_eq!(measurement.index as usize, i + 1);
            assert_eq!(measurement.value.len(), 48);
            assert_eq!(measurement.value_type, 1);
            assert!(!measurement.raw_bit_stream);
        }
        assert!(!report.opaque_data().is_empty());
        assert_ne!(report.responder_nonce(), report.request_nonce());
        report.verify_signature(&f.nonce, &f.key).unwrap();
    }
}

#[test]
fn wrong_nonce_and_other_device_key_are_rejected() {
    let f = fixture(false);
    let report = SpdmReport::parse(&f.report).unwrap();
    assert_eq!(
        report.verify_signature(&[0; 32], &f.key),
        Err(SpdmError::NonceMismatch)
    );
    assert_eq!(
        report.verify_signature(&f.nonce, &fixture(true).key),
        Err(SpdmError::Signature)
    );
}

#[test]
fn nonce_measurement_responder_nonce_opaque_and_signature_tampering_fail() {
    let f = fixture(false);
    let record_end =
        45 + u32::from_le_bytes([f.report[42], f.report[43], f.report[44], 0]) as usize;
    for offset in [4, 52, record_end, record_end + 34, f.report.len() - 1] {
        let mut bytes = f.report.clone();
        bytes[offset] ^= 1;
        let mut expected = f.nonce;
        if offset == 4 {
            // Even if the attacker rewrites the challenge, it is signed.
            expected[0] ^= 1;
        }
        let report = SpdmReport::parse(&bytes).unwrap();
        assert_eq!(
            report.verify_signature(&expected, &f.key),
            Err(SpdmError::Signature),
            "offset {offset}"
        );
    }
}

#[test]
fn every_truncation_and_trailing_data_are_rejected() {
    for blackwell in [false, true] {
        let f = fixture(blackwell);
        for len in 0..f.report.len() {
            assert!(SpdmReport::parse(&f.report[..len]).is_err(), "length {len}");
        }
        let mut bytes = f.report.clone();
        bytes.push(0);
        assert!(SpdmReport::parse(&bytes).is_err());
    }
    assert_eq!(
        SpdmReport::parse(&vec![0; MAX_REPORT_SIZE + 1]).unwrap_err(),
        SpdmError::Oversized
    );
}

#[test]
fn malformed_headers_lengths_and_duplicate_indices_are_rejected() {
    let f = fixture(false);
    // Fixed bytes in the externally generated transcript: 37-byte request,
    // 8-byte response header, followed by 55-byte DMTF blocks.
    let cases = [
        (0, 0x12),  // other SPDM version requires a different signing transcript
        (1, 0),     // wrong request opcode
        (2, 0),     // unsigned request
        (3, 1),     // partial measurement request
        (36, 8),    // invalid slot
        (37, 0x12), // response version
        (38, 0),    // response opcode
        (39, 1),    // reserved Param1 for all measurements
        (40, 1),    // response slot doesn't match request
        (41, 0),
        (41, 63),
        (41, 65),   // block count
        (44, 0xff), // u24 record length must fit
        (45, 0),
        (45, 255),  // reserved measurement index
        (46, 2),    // non-DMTF specification
        (47, 52),   // outer block length disagrees with DMTF value size
        (49, 0x7f), // reserved value type
        (50, 47),
        (50, 49), // nested length disagrees
        (100, 1), // duplicate first block index
    ];
    for (offset, value) in cases {
        let mut bytes = f.report.clone();
        bytes[offset] = value;
        assert!(
            SpdmReport::parse(&bytes).is_err(),
            "accepted mutation at {offset}"
        );
    }
    let record_end = 45 + 64 * 55;
    let mut bytes = f.report.clone();
    bytes[record_end + 32..record_end + 34].copy_from_slice(&u16::MAX.to_le_bytes());
    assert!(SpdmReport::parse(&bytes).is_err());
}

#[test]
fn invalid_p384_scalars_are_rejected() {
    let f = fixture(false);
    let mut bytes = f.report.clone();
    let signature_start = bytes.len() - 96;
    bytes[signature_start..].fill(0);
    let report = SpdmReport::parse(&bytes).unwrap();
    assert_eq!(
        report.verify_signature(&f.nonce, &f.key),
        Err(SpdmError::Signature)
    );
}
