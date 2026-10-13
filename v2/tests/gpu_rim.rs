//! Unmodified NVIDIA-signed RIMs exercise XML canonicalization, path building,
//! digest and signature interoperability. They do not represent live hardware
//! evidence or provide a fresh revocation proof.
#![cfg(feature = "gpu")]

use unified_quote::gpu::{
    cert::pinned_rim_roots,
    revocation::RevocationEvidence,
    rim::{verify_xml, verify_xml_signature_and_chain, RimKind},
};

const NOW: u64 = 1_791_849_600; // 2026-10-13 00:00:00 UTC, within all fixture chains.
const DRIVER: &str = include_str!("../testdata/gpu/rim/NV_GPU_DRIVER_GH100_550.144.03.xml");
const VBIOS: &str = include_str!("../testdata/gpu/rim/NV_GPU_VBIOS_1010_0200_882_96005E0001.xml");
const SWITCH: &str =
    include_str!("../testdata/gpu/rim/switchVBIOSRim_NV_SWITCH_BIOS_5612_0002_890_9610550001.xml");

#[test]
fn original_nvidia_driver_vbios_and_switch_signatures_verify() {
    let roots = pinned_rim_roots().unwrap();
    for (xml, kind, model, version) in [
        (DRIVER, RimKind::GpuDriver, "GH100", "550.144.03"),
        (VBIOS, RimKind::GpuVbios, "GH100", "96.00.5E.00.01"),
        (SWITCH, RimKind::NvSwitchVbios, "LS10", "96.10.55.00.01"),
    ] {
        let rim = verify_xml_signature_and_chain(xml, &roots, NOW).unwrap();
        assert_eq!(rim.kind(), kind);
        assert_eq!(rim.model(), model);
        assert_eq!(rim.version(), version);
        assert!(!rim.measurements().is_empty());
        assert!(rim
            .measurements()
            .values()
            .flatten()
            .all(|hash| hash.len() == 48));
        assert!(rim
            .inactive_indices()
            .iter()
            .all(|i| !rim.measurements().contains_key(i)));
        assert_eq!(rim.metadata().firmware_manufacturer_id, 5703);
    }
}

#[test]
fn driver_alternatives_and_inactive_indices_are_preserved() {
    let rim = verify_xml_signature_and_chain(DRIVER, &pinned_rim_roots().unwrap(), NOW).unwrap();
    assert_eq!(rim.measurements()[&35].len(), 4);
    assert!(rim.inactive_indices().contains(&0));
    assert!(!rim.measurements().contains_key(&0));
    assert_eq!(hex::encode(&rim.measurements()[&7][0]),
        "4a5e4b3d501fe31f91bd8b6f2921b58437704a504dbedba971440e840c938c805612689ae3ac04b1009515a179063d49");
}

#[test]
fn authenticated_signature_is_insufficient_without_revocation() {
    let err = verify_xml(
        DRIVER,
        &pinned_rim_roots().unwrap(),
        &RevocationEvidence::default(),
        NOW,
    )
    .unwrap_err();
    assert!(format!("{err:#}").contains("revocation"));
}

#[test]
fn reference_digest_detects_changed_metadata_measurements_and_active_flags() {
    let roots = pinned_rim_roots().unwrap();
    for modified in [
        DRIVER.replacen("550.144.03", "550.144.04", 1),
        DRIVER.replacen("4a5e4b3d", "4b5e4b3d", 1),
        DRIVER.replacen("active=\"True\"", "active=\"False\"", 1),
        DRIVER.replacen("alternatives=\"4\"", "alternatives=\"3\"", 1),
        DRIVER.replacen("name=\"GH100\"", "name=\"GB100\"", 1),
    ] {
        let err = verify_xml_signature_and_chain(&modified, &roots, NOW).unwrap_err();
        assert!(format!("{err:#}").contains("digest mismatch"));
    }
}

#[test]
fn signature_corruption_and_untrusted_or_expired_chains_are_rejected() {
    let roots = pinned_rim_roots().unwrap();
    let altered = DRIVER.replacen("<ds:SignatureValue>T", "<ds:SignatureValue>A", 1);
    assert_ne!(altered, DRIVER);
    let err = verify_xml_signature_and_chain(&altered, &roots, NOW).unwrap_err();
    assert!(format!("{err:#}").contains("signature mismatch"));
    assert!(verify_xml_signature_and_chain(DRIVER, &[], NOW).is_err());
    assert!(verify_xml_signature_and_chain(DRIVER, &roots, 1_893_456_000).is_err());
}

#[test]
fn external_references_wrapping_entities_and_unexpected_transforms_are_rejected() {
    let roots = pinned_rim_roots().unwrap();
    let sig_start = DRIVER.find("<ds:Signature ").unwrap();
    let sig_end = DRIVER.find("</ds:Signature>").unwrap() + "</ds:Signature>".len();
    let duplicate_signature = DRIVER.replacen(
        "</SoftwareIdentity>",
        &format!("{}</SoftwareIdentity>", &DRIVER[sig_start..sig_end]),
        1,
    );
    for modified in [
        DRIVER.replacen("URI=\"\"", "URI=\"https://attacker.invalid/rim.xml\"", 1),
        DRIVER.replacen("URI=\"\"", "URI=\"#selected\"", 1),
        DRIVER.replacen(
            "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
            "http://www.w3.org/TR/1999/REC-xpath-19991116",
            1,
        ),
        DRIVER.replacen(
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
            1,
        ),
        format!("<!DOCTYPE SoftwareIdentity [<!ENTITY x SYSTEM 'file:///etc/passwd'>]>{DRIVER}"),
        format!("<wrapper>{DRIVER}</wrapper>"),
        DRIVER.replacen(
            "<ds:KeyInfo>",
            "<ds:KeyInfo><ds:RetrievalMethod URI=\"https://attacker.invalid/key\"/>",
            1,
        ),
        duplicate_signature,
    ] {
        assert!(verify_xml_signature_and_chain(&modified, &roots, NOW).is_err());
    }
}

#[test]
fn comments_do_not_affect_signed_claims_or_canonicalization() {
    let commented = DRIVER.replacen(
        "<ns0:Payload ",
        "<!-- unsigned comment carries no claims --><ns0:Payload ",
        1,
    );
    let roots = pinned_rim_roots().unwrap();
    let original = verify_xml_signature_and_chain(DRIVER, &roots, NOW).unwrap();
    let with_comment = verify_xml_signature_and_chain(&commented, &roots, NOW).unwrap();
    assert_eq!(original.metadata(), with_comment.metadata());
    assert_eq!(original.measurements(), with_comment.measurements());
    assert_ne!(original.source_sha384(), with_comment.source_sha384());
}
