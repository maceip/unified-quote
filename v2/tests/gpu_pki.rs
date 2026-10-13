//! PKI interoperability tests use NVIDIA-published certificates. Revocation
//! adversarial tests use freshly generated, explicitly test-only signing keys.
#![cfg(feature = "gpu")]

use std::time::Duration;

use der::{
    asn1::{BitString, GeneralizedTime, ObjectIdentifier, OctetString},
    Decode, Encode,
};
use p384::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    pkcs8::DecodePrivateKey,
};
use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, PKCS_ECDSA_P384_SHA384,
};
use sha2::{Digest, Sha256};
use spki::AlgorithmIdentifierOwned;
use unified_quote::gpu::{
    cert::{
        parse_certificates, pinned_device_roots, pinned_rim_roots, validate_chain, Purpose,
        ValidatedChain,
    },
    revocation::{check_chain, RevocationCache, RevocationClient, RevocationEvidence},
};
use x509_cert::{
    crl::{CertificateList, RevokedCert, TbsCertList},
    ext::Extension,
    time::Time,
    Certificate, Version,
};
use x509_ocsp::{
    BasicOcspResponse, CertId, CertStatus, OcspResponse, ResponderId, ResponseData, SingleResponse,
};

const NOW: u64 = 1_790_000_000;

fn algorithm() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3"),
        parameters: None,
    }
}

fn time(seconds: u64) -> Time {
    Time::GeneralTime(GeneralizedTime::from_unix_duration(Duration::from_secs(seconds)).unwrap())
}

fn sign(key: &KeyPair, data: &[u8]) -> BitString {
    let signing = SigningKey::from_pkcs8_der(&key.serialize_der()).unwrap();
    let signature: Signature = signing.sign(data);
    BitString::from_bytes(signature.to_der().as_bytes()).unwrap()
}

struct TestPki {
    root_rcgen: rcgen::Certificate,
    root_key: KeyPair,
    root: Certificate,
    leaf: Certificate,
}

fn params(name: &str, ca: bool) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = if ca {
        IsCa::Ca(BasicConstraints::Unconstrained)
    } else {
        IsCa::ExplicitNoCa
    };
    params.key_usages = if ca {
        vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign]
    } else {
        vec![KeyUsagePurpose::DigitalSignature]
    };
    params
}

impl TestPki {
    fn new() -> Self {
        let root_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let root_rcgen = params("TEST ONLY root", true)
            .self_signed(&root_key)
            .unwrap();
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let leaf_rcgen = params("TEST ONLY leaf", false)
            .signed_by(&leaf_key, &root_rcgen, &root_key)
            .unwrap();
        let root = Certificate::from_der(root_rcgen.der()).unwrap();
        let leaf = Certificate::from_der(leaf_rcgen.der()).unwrap();
        Self {
            root_rcgen,
            root_key,
            root,
            leaf,
        }
    }

    fn chain(&self) -> ValidatedChain {
        validate_chain(
            &self.leaf.to_der().unwrap(),
            std::slice::from_ref(&self.root),
            NOW,
            Purpose::Device,
        )
        .unwrap()
    }

    fn resign_leaf(&mut self) {
        self.leaf.signature = sign(&self.root_key, &self.leaf.tbs_certificate.to_der().unwrap());
    }

    fn crl(&self, revoked: bool) -> CertificateList {
        let list = TbsCertList {
            version: Version::V2,
            signature: algorithm(),
            issuer: self.root.tbs_certificate.subject.clone(),
            this_update: time(NOW - 60),
            next_update: Some(time(NOW + 600)),
            revoked_certificates: if revoked {
                Some(vec![RevokedCert {
                    serial_number: self.leaf.tbs_certificate.serial_number.clone(),
                    revocation_date: time(NOW - 120),
                    crl_entry_extensions: None,
                }])
            } else {
                None
            },
            crl_extensions: None,
        };
        CertificateList {
            signature: sign(&self.root_key, &list.to_der().unwrap()),
            signature_algorithm: algorithm(),
            tbs_cert_list: list,
        }
    }

    fn ocsp(&self, status: CertStatus) -> BasicOcspResponse {
        let id = CertId {
            hash_algorithm: AlgorithmIdentifierOwned {
                oid: ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1"),
                parameters: None,
            },
            issuer_name_hash: OctetString::new(
                Sha256::digest(self.root.tbs_certificate.subject.to_der().unwrap()).to_vec(),
            )
            .unwrap(),
            issuer_key_hash: OctetString::new(
                Sha256::digest(
                    self.root
                        .tbs_certificate
                        .subject_public_key_info
                        .subject_public_key
                        .raw_bytes(),
                )
                .to_vec(),
            )
            .unwrap(),
            serial_number: self.leaf.tbs_certificate.serial_number.clone(),
        };
        let data = ResponseData {
            version: x509_ocsp::Version::V1,
            responder_id: ResponderId::ByName(self.root.tbs_certificate.subject.clone()),
            produced_at: time(NOW - 30).into(),
            responses: vec![SingleResponse {
                cert_id: id,
                cert_status: status,
                this_update: time(NOW - 60).into(),
                next_update: Some(time(NOW + 600).into()),
                single_extensions: None,
            }],
            response_extensions: None,
        };
        BasicOcspResponse {
            signature: sign(&self.root_key, &data.to_der().unwrap()),
            signature_algorithm: algorithm(),
            tbs_response_data: data,
            certs: None,
        }
    }

    fn delegated(&self, correct_eku: bool, no_check: bool) -> (Certificate, KeyPair) {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let mut p = params("TEST ONLY responder", false);
        p.extended_key_usages = vec![if correct_eku {
            ExtendedKeyUsagePurpose::OcspSigning
        } else {
            ExtendedKeyUsagePurpose::ServerAuth
        }];
        if no_check {
            p.custom_extensions.push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 5, 5, 7, 48, 1, 5],
                vec![5, 0],
            ));
        }
        let cert = p.signed_by(&key, &self.root_rcgen, &self.root_key).unwrap();
        (Certificate::from_der(cert.der()).unwrap(), key)
    }
}

fn ocsp_evidence(response: BasicOcspResponse) -> RevocationEvidence {
    RevocationEvidence {
        ocsp_responses: vec![OcspResponse::successful(response)
            .unwrap()
            .to_der()
            .unwrap()],
        crls: vec![],
    }
}

fn crl_evidence(crl: CertificateList) -> RevocationEvidence {
    RevocationEvidence {
        ocsp_responses: vec![],
        crls: vec![crl.to_der().unwrap()],
    }
}

#[test]
fn nvidia_hopper_and_blackwell_chains_reach_pinned_root() {
    for pem in [
        include_bytes!("../testdata/gpu/nvidia/hopperCertChain.txt").as_slice(),
        include_bytes!("../testdata/gpu/nvidia/blackwellCertChain.txt").as_slice(),
    ] {
        let roots = pinned_device_roots().unwrap();
        let chain = validate_chain(pem, &roots, NOW, Purpose::Device).unwrap();
        assert_eq!(chain.certificates().len(), 5);
        assert_eq!(chain.certificates().last().unwrap(), &roots[0]);
        let mut der_without_root = Vec::new();
        for certificate in &chain.certificates()[..4] {
            der_without_root.extend(certificate.to_der().unwrap());
        }
        assert!(validate_chain(&der_without_root, &roots, NOW, Purpose::Device).is_ok());
        assert!(validate_chain(pem, &pinned_rim_roots().unwrap(), NOW, Purpose::Device).is_err());
        assert!(validate_chain(pem, &roots, 1, Purpose::Device).is_err());
        assert!(check_chain(&chain, &RevocationEvidence::default(), NOW).is_err());
    }
}

#[test]
fn evidence_cannot_introduce_its_own_root_or_unsigned_leaf() {
    let a = TestPki::new();
    let b = TestPki::new();
    let mut supplied = a.leaf.to_der().unwrap();
    supplied.extend(a.root.to_der().unwrap());
    assert!(validate_chain(&supplied, &[b.root], NOW, Purpose::Device).is_err());
    let mut changed = a.leaf.clone();
    changed.tbs_certificate.serial_number =
        x509_cert::serial_number::SerialNumber::new(&[7]).unwrap();
    assert!(validate_chain(&changed.to_der().unwrap(), &[a.root], NOW, Purpose::Device).is_err());
}

#[test]
fn malformed_duplicate_and_extra_certificates_are_rejected() {
    let pki = TestPki::new();
    let mut bytes = pki.leaf.to_der().unwrap();
    bytes.extend(pki.leaf.to_der().unwrap());
    assert!(parse_certificates(&bytes).is_err());
    let pem = include_str!("../testdata/gpu/nvidia/hopperCertChain.txt");
    assert!(parse_certificates(format!("{pem}ignored garbage").as_bytes()).is_err());
    assert!(parse_certificates(&[0x30, 0xff]).is_err());
}

#[test]
fn signed_expired_leaf_unknown_critical_extension_and_weak_algorithm_fail() {
    let mut pki = TestPki::new();
    pki.leaf.tbs_certificate.validity.not_after = time(NOW - 1);
    pki.resign_leaf();
    assert!(validate_chain(
        &pki.leaf.to_der().unwrap(),
        &[pki.root],
        NOW,
        Purpose::Device
    )
    .is_err());

    let mut pki = TestPki::new();
    pki.leaf
        .tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .push(Extension {
            extn_id: ObjectIdentifier::new_unwrap("1.2.3.4"),
            critical: true,
            extn_value: OctetString::new(vec![5, 0]).unwrap(),
        });
    pki.resign_leaf();
    assert!(validate_chain(
        &pki.leaf.to_der().unwrap(),
        &[pki.root],
        NOW,
        Purpose::Device
    )
    .is_err());

    let mut pki = TestPki::new();
    pki.leaf.tbs_certificate.signature.oid = ObjectIdentifier::new_unwrap("1.2.840.10045.4.1");
    pki.leaf.signature_algorithm = pki.leaf.tbs_certificate.signature.clone();
    pki.resign_leaf();
    assert!(validate_chain(
        &pki.leaf.to_der().unwrap(),
        &[pki.root],
        NOW,
        Purpose::Device
    )
    .is_err());
}

#[test]
fn signed_ocsp_good_is_accepted_and_all_other_statuses_rejected() {
    let pki = TestPki::new();
    let chain = pki.chain();
    check_chain(&chain, &ocsp_evidence(pki.ocsp(CertStatus::good())), NOW).unwrap();
    assert!(check_chain(&chain, &ocsp_evidence(pki.ocsp(CertStatus::unknown())), NOW).is_err());
    let revoked = CertStatus::revoked(x509_ocsp::RevokedInfo {
        revocation_time: time(NOW - 100).into(),
        revocation_reason: None,
    });
    assert!(check_chain(&chain, &ocsp_evidence(pki.ocsp(revoked)), NOW).is_err());
}

#[test]
fn ocsp_tampering_missing_expiry_future_stale_duplicate_and_wrong_issuer_fail() {
    let pki = TestPki::new();
    let chain = pki.chain();
    for mutation in 0..7 {
        let mut response = pki.ocsp(CertStatus::good());
        match mutation {
            0 => {
                response.tbs_response_data.responses[0].cert_status = CertStatus::unknown();
            }
            1 => {
                response.tbs_response_data.responses[0].next_update = None;
            }
            2 => {
                response.tbs_response_data.produced_at = time(NOW + 1).into();
            }
            3 => {
                response.tbs_response_data.responses[0].next_update = Some(time(NOW).into());
            }
            4 => {
                response
                    .tbs_response_data
                    .responses
                    .push(response.tbs_response_data.responses[0].clone());
            }
            5 => {
                response.tbs_response_data.responses[0]
                    .cert_id
                    .issuer_key_hash = OctetString::new(vec![0; 32]).unwrap();
            }
            6 => {
                response.signature_algorithm.parameters = Some(der::asn1::Null.into());
            }
            _ => unreachable!(),
        }
        if mutation != 0 {
            response.signature = sign(&pki.root_key, &response.tbs_response_data.to_der().unwrap());
        }
        assert!(
            check_chain(&chain, &ocsp_evidence(response), NOW).is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn delegated_ocsp_requires_same_issuer_eku_and_responder_revocation_coverage() {
    let pki = TestPki::new();
    let chain = pki.chain();
    for (correct_eku, no_check, same_issuer) in [
        (true, true, true),
        (false, true, true),
        (true, false, true),
        (true, true, false),
    ] {
        let other = TestPki::new();
        let source = if same_issuer { &pki } else { &other };
        let (responder, key) = source.delegated(correct_eku, no_check);
        let mut response = pki.ocsp(CertStatus::good());
        response.tbs_response_data.responder_id =
            ResponderId::ByName(responder.tbs_certificate.subject.clone());
        response.certs = Some(vec![responder]);
        response.signature = sign(&key, &response.tbs_response_data.to_der().unwrap());
        assert_eq!(
            check_chain(&chain, &ocsp_evidence(response), NOW).is_ok(),
            correct_eku && no_check && same_issuer
        );
    }
}

#[test]
fn signed_crl_good_and_revoked_and_tampered_are_distinguished() {
    let pki = TestPki::new();
    let chain = pki.chain();
    check_chain(&chain, &crl_evidence(pki.crl(false)), NOW).unwrap();
    assert!(check_chain(&chain, &crl_evidence(pki.crl(true)), NOW).is_err());
    let mut crl = pki.crl(true);
    crl.tbs_cert_list.revoked_certificates = None;
    assert!(check_chain(&chain, &crl_evidence(crl), NOW).is_err());
}

#[test]
fn scoped_delta_stale_and_unsigned_crls_cannot_claim_good() {
    let pki = TestPki::new();
    let chain = pki.chain();
    for oid in ["2.5.29.27", "2.5.29.28", "2.23.133.5.4.1"] {
        let mut crl = pki.crl(false);
        crl.tbs_cert_list.crl_extensions = Some(vec![Extension {
            extn_id: oid.parse().unwrap(),
            critical: false,
            extn_value: OctetString::new(vec![5, 0]).unwrap(),
        }]);
        crl.signature = sign(&pki.root_key, &crl.tbs_cert_list.to_der().unwrap());
        assert!(check_chain(&chain, &crl_evidence(crl), NOW).is_err());
    }
    assert!(check_chain(&chain, &crl_evidence(pki.crl(false)), NOW + 600).is_err());
    let mut missing_next = pki.crl(false);
    missing_next.tbs_cert_list.next_update = None;
    missing_next.signature = sign(&pki.root_key, &missing_next.tbs_cert_list.to_der().unwrap());
    assert!(check_chain(&chain, &crl_evidence(missing_next), NOW).is_err());
}

#[test]
fn conflicting_revocation_status_and_cache_expiration_are_fail_closed() {
    let pki = TestPki::new();
    let chain = pki.chain();
    let good = ocsp_evidence(pki.ocsp(CertStatus::good()));
    let mut conflicting = good.clone();
    conflicting.crls.push(pki.crl(true).to_der().unwrap());
    assert!(check_chain(&chain, &conflicting, NOW).is_err());
    let mut cache = RevocationCache::default();
    cache.insert(&chain, good, NOW).unwrap();
    let serialized = cache.to_json().unwrap();
    let restored = RevocationCache::from_json(&serialized).unwrap();
    restored.checked_evidence(&chain, NOW).unwrap();
    assert!(restored.checked_evidence(&chain, NOW + 600).is_err());
    assert!(restored
        .checked_evidence(&TestPki::new().chain(), NOW)
        .is_err());
}

#[test]
fn network_transport_requires_explicit_https_endpoints() {
    for endpoint in [
        "http://ocsp.example",
        "file:///etc/passwd",
        "https://user:secret@ocsp.example",
        "https://ocsp.example/#fragment",
    ] {
        assert!(RevocationClient::new(endpoint, &[]).is_err());
    }
}

#[test]
fn nvidia_dice_identity_and_firmware_are_parsed_without_tail_fallback() {
    use unified_quote::gpu::{
        identity::{certificate_identity, OperationalFlag},
        opaque::OpaqueData,
        spdm::SpdmReport,
    };
    for (name, pem, report_text) in [
        (
            "GH100",
            include_bytes!("../testdata/gpu/nvidia/hopperCertChain.txt").as_slice(),
            include_str!("../testdata/gpu/nvidia/hopperAttestationReport.txt"),
        ),
        (
            "GB100",
            include_bytes!("../testdata/gpu/nvidia/blackwellCertChain.txt").as_slice(),
            include_str!("../testdata/gpu/nvidia/blackwellAttestationReport.txt"),
        ),
    ] {
        let chain =
            validate_chain(pem, &pinned_device_roots().unwrap(), NOW, Purpose::Device).unwrap();
        let identity = certificate_identity(&chain).unwrap();
        assert_eq!(identity.manufacturer, "NVIDIA");
        assert_eq!(identity.model, name);
        assert!(identity.ueid.is_none());
        let expected_hash: [u8; 32] = Sha256::digest(
            chain.certificates()[1]
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .unwrap(),
        )
        .into();
        assert_eq!(identity.device_key_sha256, expected_hash);
        let raw = hex::decode(report_text.trim()).unwrap();
        let report = SpdmReport::parse(&raw).unwrap();
        let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(
            chain
                .leaf()
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .as_bytes()
                .unwrap(),
        )
        .unwrap();
        let nonce: [u8; 32] = report.request_nonce().try_into().unwrap();
        report.verify_signature(&nonce, &key).unwrap();
        let opaque = OpaqueData::parse(report.opaque_data()).unwrap();
        if name == "GB100" {
            let flags = identity.operational_flags.as_ref().unwrap();
            assert_eq!(flags.not_configured, Some(true));
            assert_eq!(flags.not_secure, Some(false));
            assert_eq!(flags.debug, Some(false));
            identity
                .require_security_flags(&[
                    (OperationalFlag::NotSecure, false),
                    (OperationalFlag::Debug, false),
                ])
                .unwrap();
            assert!(identity
                .require_security_flags(&[(OperationalFlag::NotConfigured, false)])
                .is_err());
            assert!(identity
                .require_security_flags(&[(OperationalFlag::Debug, true)])
                .is_err());
            assert_eq!(identity.firmware_digests().len(), 2);
            identity
                .verify_report_fwid(opaque.bytes(20).unwrap())
                .unwrap();
            assert!(identity.verify_report_fwid(&[0; 48]).is_err());
        } else {
            // This historical Hopper sample does not have a report FWID field.
            // Explicitly record absence; do not fabricate a matching verdict.
            assert!(opaque.bytes(20).is_err());
            assert!(identity.operational_flags.is_none());
            assert!(identity
                .require_security_flags(&[(OperationalFlag::Debug, false)])
                .is_err());
            assert_eq!(identity.firmware_digests().len(), 1);
        }
    }
}

#[test]
fn malformed_signed_dice_extensions_and_conflicting_vendor_fail() {
    use unified_quote::gpu::identity::certificate_identity;
    let fixture = parse_certificates(include_bytes!(
        "../testdata/gpu/nvidia/blackwellCertChain.txt"
    ))
    .unwrap();
    let extension = |oid: &str| {
        fixture[0]
            .tbs_certificate
            .extensions
            .as_ref()
            .unwrap()
            .iter()
            .find(|e| e.extn_id.to_string() == oid)
            .unwrap()
            .clone()
    };
    for invalid in 0..3 {
        let mut pki = TestPki::new();
        pki.leaf
            .tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .push(extension("2.5.29.17"));
        let mut tcb = extension("2.23.133.5.4.1.1");
        let mut bytes = tcb.extn_value.as_bytes().to_vec();
        match invalid {
            0 => bytes.extend([0; 48]), // A digest-looking tail cannot rescue malformed DER.
            1 => {
                let offset = bytes.windows(6).position(|w| w == b"NVIDIA").unwrap();
                bytes[offset..offset + 6].copy_from_slice(b"BADAAA");
            }
            2 => {
                let sha384 = [
                    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
                ];
                let offset = bytes
                    .windows(sha384.len())
                    .position(|w| w == sha384)
                    .unwrap();
                bytes[offset + 10] = 1; // SHA256 OID with SHA384-sized digest.
            }
            _ => unreachable!(),
        }
        tcb.extn_value = OctetString::new(bytes).unwrap();
        pki.leaf
            .tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .push(tcb);
        pki.resign_leaf();
        assert!(certificate_identity(&pki.chain()).is_err());
    }
}

#[test]
fn signed_missing_masked_or_unsafe_dice_flags_cannot_satisfy_security_policy() {
    use der::{asn1::Any, Reader, Tag, Tagged};
    use unified_quote::gpu::identity::{certificate_identity, OperationalFlag};

    let fixture = parse_certificates(include_bytes!(
        "../testdata/gpu/nvidia/blackwellCertChain.txt"
    ))
    .unwrap();
    let extension = |oid: &str| {
        fixture[0]
            .tbs_certificate
            .extensions
            .as_ref()
            .unwrap()
            .iter()
            .find(|e| e.extn_id.to_string() == oid)
            .unwrap()
            .clone()
    };
    let required = [
        (OperationalFlag::NotConfigured, false),
        (OperationalFlag::NotSecure, false),
        (OperationalFlag::Recovery, false),
        (OperationalFlag::Debug, false),
        (OperationalFlag::NotReplayProtected, false),
        (OperationalFlag::NotIntegrityProtected, false),
    ];
    for case in 0..5 {
        let mut pki = TestPki::new();
        let mut tcb = extension("2.23.133.5.4.1.1");
        let seq = Any::from_der(tcb.extn_value.as_bytes()).unwrap();
        let mut reader = der::SliceReader::new(seq.value()).unwrap();
        let mut fields = Vec::new();
        while !reader.is_finished() {
            let field = Any::decode(&mut reader).unwrap();
            if !matches!(field.tag().octet(), 0x87 | 0x8a) {
                fields.push(field);
            }
        }
        if matches!(case, 1 | 2 | 4) {
            // Test-only signed state: fixedWidth alone, or debug + fixedWidth.
            let flags = [0x87, 5, 0, if case == 4 { 0x10 } else { 0 }, 0, 0, 1];
            fields.push(Any::from_der(&flags).unwrap());
        }
        if case == 1 {
            // Only notSecure meaningful: a clear debug bit remains unknown.
            fields.push(Any::from_der(&[0x8a, 2, 6, 0x40]).unwrap());
        } else if matches!(case, 2 | 3) {
            fields.push(Any::from_der(&[0x8a, 3, 7, 0xff, 0x80]).unwrap());
        }
        fields.sort_by_key(|f| f.tag().octet() & 0x1f);
        let content: Vec<u8> = fields.iter().flat_map(|f| f.to_der().unwrap()).collect();
        tcb.extn_value =
            OctetString::new(Any::new(Tag::Sequence, content).unwrap().to_der().unwrap()).unwrap();
        pki.leaf
            .tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .extend([extension("2.5.29.17"), tcb]);
        pki.resign_leaf();
        let identity = certificate_identity(&pki.chain());
        if case == 3 {
            assert!(identity.is_err(), "mask without flags must fail");
        } else {
            let identity = identity.unwrap();
            assert_eq!(
                identity.require_security_flags(&required).is_ok(),
                case == 2,
                "case {case}"
            );
            assert!(identity
                .require_security_flags(&[
                    (OperationalFlag::NotSecure, false),
                    (OperationalFlag::NotSecure, false)
                ])
                .is_err());
        }
    }
}

#[test]
fn path_length_and_certificate_signing_key_usage_are_enforced() {
    let mut pki = TestPki::new();
    let intermediate_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
    let intermediate = params("TEST ONLY intermediate", true)
        .signed_by(&intermediate_key, &pki.root_rcgen, &pki.root_key)
        .unwrap();
    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
    let leaf = params("TEST ONLY deep leaf", false)
        .signed_by(&leaf_key, &intermediate, &intermediate_key)
        .unwrap();
    let mut chain = leaf.der().to_vec();
    chain.extend(intermediate.der().as_ref());
    assert!(validate_chain(&chain, &[pki.root.clone()], NOW, Purpose::Device).is_ok());
    let bc = pki
        .root
        .tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .iter_mut()
        .find(|e| e.extn_id.to_string() == "2.5.29.19")
        .unwrap();
    bc.extn_value = OctetString::new(
        x509_cert::ext::pkix::BasicConstraints {
            ca: true,
            path_len_constraint: Some(0),
        }
        .to_der()
        .unwrap(),
    )
    .unwrap();
    pki.root.signature = sign(&pki.root_key, &pki.root.tbs_certificate.to_der().unwrap());
    assert!(validate_chain(&chain, &[pki.root], NOW, Purpose::Device).is_err());

    let mut pki = TestPki::new();
    let ku = pki
        .root
        .tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .iter_mut()
        .find(|e| e.extn_id.to_string() == "2.5.29.15")
        .unwrap();
    ku.extn_value = OctetString::new(vec![0x03, 0x02, 0x07, 0x80]).unwrap(); // digitalSignature only.
    pki.root.signature = sign(&pki.root_key, &pki.root.tbs_certificate.to_der().unwrap());
    assert!(validate_chain(
        &pki.leaf.to_der().unwrap(),
        &[pki.root],
        NOW,
        Purpose::Device
    )
    .is_err());
}
