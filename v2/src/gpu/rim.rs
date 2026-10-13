//! Authenticated NVIDIA TCG/SWID reference integrity manifests.
//!
//! This is a deliberately constrained XMLDSig profile, matching NVIDIA's
//! published driver, VBIOS and NVSwitch RIMs: one enveloped whole-document
//! reference, C14N 1.1 without comments, SHA-384 and ECDSA P-384. Unsupported
//! signature profiles and ambiguous document structures are errors. No XML
//! resource, entity, schema or signature reference is fetched.
//!
//! [`verify_xml`] is the admission API and always checks signer revocation.
//! [`verify_xml_signature_and_chain`] is a separate cryptographic primitive;
//! its result cannot be used as a [`VerifiedRim`]. Both use the same parsed DOM
//! for canonicalization and claim extraction to avoid parser disagreement.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use bergshamra_c14n::{canonicalize_doc, C14nMode};
use bergshamra_xml::NodeSet;
use der::Encode;
use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p384::pkcs8::DecodePublicKey;
use serde::Serialize;
use sha2::{Digest, Sha384};
use uppsala::{Document, Element, NodeId, NodeKind};
use x509_cert::Certificate;

use super::cert::{self, Purpose, ValidatedChain};
use super::revocation::{self, RevocationEvidence};

const SWID: &str = "http://standards.iso.org/iso/19770/-2/2015/schema.xsd";
const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const RIM: &str = "https://trustedcomputinggroup.org/resource/tcg-reference-integrity-manifest-rim-information-model/";
const HASH: &str = "http://www.w3.org/2001/04/xmlenc#sha384";
const OPAQUE: &str = "https://docs.nvidia.com/attestation/specs/latest/opaque-data.html";
const C14N11: &str = "http://www.w3.org/2006/12/xml-c14n11";
const ECDSA384: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
const DIGEST384: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";
const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const MAX_XML_BYTES: usize = 2 * 1024 * 1024;
const MAX_NODES: usize = 16_384;
const MAX_CERTIFICATES: usize = 8;
const MAX_ALTERNATIVES: usize = 256;
/// NVIDIA's documented separation between measurement and opaque RIM indices.
pub const OPAQUE_INDEX_BASE: u32 = 0x1000;

/// Role classified from the authenticated edition and version grammar.
///
/// NVIDIA XML does not include a distinct driver/VBIOS role attribute. A GPU
/// driver uses two or three decimal version components; VBIOS uses five hexadecimal
/// byte components. Consumers must also match the exact authenticated version
/// to the corresponding signed SPDM version, and appraise every measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RimKind {
    GpuDriver,
    GpuVbios,
    NvSwitchVbios,
}

/// Identity values covered by the whole-document XML signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RimMetadata {
    pub kind: RimKind,
    pub version: String,
    pub model: String,
    pub product: String,
    pub edition: String,
    pub tag_id: String,
    pub firmware_manufacturer_id: u32,
    pub platform_manufacturer_id: u32,
}

/// An authenticated minimum-SVN constraint on signed SPDM opaque data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpaqueSvnConstraint {
    pub type_id: u16,
    pub name: String,
    /// Signed XML resource size, retained as metadata. NVIDIA's opaque RIM
    /// examples use size=1 even though rmDataValueType=0x87 is a uint16.
    pub declared_size: u32,
    /// Scalar width comes from NVIDIA's documented rmDataValueType=0x87.
    pub value_size: u8,
    pub min_svn: u64,
    pub include_in_result: bool,
}

#[derive(Debug, Clone)]
struct RimData {
    metadata: RimMetadata,
    measurements: BTreeMap<u16, Vec<Vec<u8>>>,
    inactive_indices: BTreeSet<u16>,
    opaque_constraints: Vec<OpaqueSvnConstraint>,
    source_sha384: [u8; 48],
}

/// Manifest whose signature, signer path and fresh revocation are verified.
/// No public constructor or deserialization can manufacture this type.
#[derive(Debug, Clone)]
pub struct VerifiedRim {
    data: RimData,
}

/// A signature/path result, explicitly lacking a revocation verdict.
///
/// Useful for historical signed documents and cryptographic diagnostics. It is
/// intentionally a different type from [`VerifiedRim`] and has no admission
/// conversion. Production callers should use [`verify_xml`].
#[derive(Debug)]
pub struct SignatureVerifiedRim {
    data: RimData,
    chain: ValidatedChain,
}

macro_rules! rim_accessors {
    () => {
        pub fn metadata(&self) -> &RimMetadata {
            &self.data.metadata
        }
        pub fn kind(&self) -> RimKind {
            self.data.metadata.kind
        }
        pub fn version(&self) -> &str {
            &self.data.metadata.version
        }
        pub fn model(&self) -> &str {
            &self.data.metadata.model
        }
        pub fn product(&self) -> &str {
            &self.data.metadata.product
        }
        /// Active golden measurements. Indices are RIM zero-based indices;
        /// NVIDIA SPDM measurement block indices are one greater.
        pub fn measurements(&self) -> &BTreeMap<u16, Vec<Vec<u8>>> {
            &self.data.measurements
        }
        /// Declared inactive indices are not approved zero measurements.
        pub fn inactive_indices(&self) -> &BTreeSet<u16> {
            &self.data.inactive_indices
        }
        pub fn opaque_constraints(&self) -> &[OpaqueSvnConstraint] {
            &self.data.opaque_constraints
        }
        pub fn source_sha384(&self) -> &[u8; 48] {
            &self.data.source_sha384
        }
    };
}

impl VerifiedRim {
    rim_accessors!();
}
impl SignatureVerifiedRim {
    rim_accessors!();

    pub(crate) fn signer_chain(&self) -> &ValidatedChain {
        &self.chain
    }
}

/// Verify an XML RIM, including the complete signer path and strict revocation.
/// `now` is the verifier's trusted Unix time, never a bundle-provided timestamp.
pub fn verify_xml(
    xml: &str,
    roots: &[Certificate],
    revocation_evidence: &RevocationEvidence,
    now: u64,
) -> Result<VerifiedRim> {
    let checked = verify_xml_signature_and_chain(xml, roots, now)?;
    revocation::check_chain(&checked.chain, revocation_evidence, now)
        .context("RIM signer revocation")?;
    Ok(VerifiedRim { data: checked.data })
}

/// Verify a historical/reference RIM's signature and certificate path only.
/// This does not assert that its signer was unrevoked at `now`.
pub fn verify_xml_signature_and_chain(
    xml: &str,
    roots: &[Certificate],
    now: u64,
) -> Result<SignatureVerifiedRim> {
    let doc = parse_document(xml)?;
    let root = doc.document_element().context("RIM document has no root")?;
    ensure!(
        matches(&doc, root, SWID, "SoftwareIdentity"),
        "RIM root must be SWID SoftwareIdentity"
    );
    let parts = exact_children(
        &doc,
        root,
        &[
            (SWID, "Entity"),
            (SWID, "Meta"),
            (SWID, "Payload"),
            (DS, "Signature"),
        ],
    )?;
    let signature_id = parts[3];
    ensure!(
        doc.descendants(root)
            .iter()
            .filter(|&&id| matches(&doc, id, DS, "Signature"))
            .count()
            == 1,
        "RIM must contain exactly one signature"
    );
    let sig_parts = exact_children(
        &doc,
        signature_id,
        &[(DS, "SignedInfo"), (DS, "SignatureValue"), (DS, "KeyInfo")],
    )?;
    exact_attributes(element(&doc, signature_id)?, &[])?;
    let signed_info = sig_parts[0];
    exact_attributes(element(&doc, signed_info)?, &[])?;
    let si = exact_children(
        &doc,
        signed_info,
        &[
            (DS, "CanonicalizationMethod"),
            (DS, "SignatureMethod"),
            (DS, "Reference"),
        ],
    )?;
    algorithm(&doc, si[0], C14N11)?;
    algorithm(&doc, si[1], ECDSA384)?;
    exact_attributes(element(&doc, si[2])?, &[(None, "URI")])?;
    ensure!(
        attribute(element(&doc, si[2])?, None, "URI")?.is_empty(),
        "RIM reference must cover the entire document (URI=\"\")"
    );
    let reference = exact_children(
        &doc,
        si[2],
        &[
            (DS, "Transforms"),
            (DS, "DigestMethod"),
            (DS, "DigestValue"),
        ],
    )?;
    exact_attributes(element(&doc, reference[0])?, &[])?;
    let transforms = exact_children(&doc, reference[0], &[(DS, "Transform"), (DS, "Transform")])?;
    algorithm(&doc, transforms[0], ENVELOPED)?;
    algorithm(&doc, transforms[1], C14N11)?;
    algorithm(&doc, reference[1], DIGEST384)?;

    let expected_digest = base64_element(&doc, reference[2], 48)?;
    ensure!(
        expected_digest.len() == 48,
        "RIM SHA-384 digest must be 48 bytes"
    );
    let covered = NodeSet::all_without_comments(&doc)
        .subtract(&NodeSet::tree_with_comments(signature_id, &doc));
    let canonical_document =
        canonicalize_doc(&doc, C14nMode::Inclusive11, Some(&covered), &[] as &[&str])
            .map_err(|e| anyhow!("RIM canonicalization: {e}"))?;
    ensure!(
        Sha384::digest(&canonical_document).as_slice() == expected_digest,
        "RIM reference digest mismatch"
    );

    let cert_bytes = extract_certificate_chain(&doc, sig_parts[2])?;
    let chain =
        cert::validate_chain(&cert_bytes, roots, now, Purpose::Rim).context("RIM signer path")?;
    let spki_der = chain
        .leaf()
        .tbs_certificate
        .subject_public_key_info
        .to_der()?;
    let key = VerifyingKey::from_public_key_der(&spki_der)
        .context("RIM signer must use a P-384 public key")?;
    let signature = Signature::from_slice(&base64_element(&doc, sig_parts[1], 96)?)
        .context("RIM XMLDSig signature must be fixed-width 48-byte r || 48-byte s")?;
    let si_nodes = NodeSet::tree_without_comments(signed_info, &doc);
    let canonical_signed_info =
        canonicalize_doc(&doc, C14nMode::Inclusive11, Some(&si_nodes), &[] as &[&str])
            .map_err(|e| anyhow!("RIM SignedInfo canonicalization: {e}"))?;
    key.verify(&canonical_signed_info, &signature)
        .context("RIM ECDSA signature mismatch")?;

    // Extract only after authenticating exactly the DOM covered by the digest.
    let data = extract_data(&doc, root, &parts, xml)?;
    Ok(SignatureVerifiedRim { data, chain })
}

fn parse_document(xml: &str) -> Result<Document<'_>> {
    ensure!(
        !xml.is_empty() && xml.len() <= MAX_XML_BYTES,
        "RIM XML size is outside the supported bound"
    );
    ensure!(
        !xml.contains("<!DOCTYPE") && !xml.contains("<!ENTITY"),
        "RIM DTDs and entity declarations are forbidden"
    );
    let doc = uppsala::Parser::new()
        .with_max_depth(32)
        .parse(xml)
        .context("malformed RIM XML")?;
    if let Some(declaration) = &doc.xml_declaration {
        ensure!(declaration.version == "1.0", "RIM must use XML 1.0");
        ensure!(
            declaration
                .encoding
                .as_ref()
                .is_none_or(|s| s.eq_ignore_ascii_case("utf-8")),
            "RIM XML must use UTF-8"
        );
    }
    let nodes = doc.descendants(doc.root());
    ensure!(nodes.len() <= MAX_NODES, "RIM XML has too many nodes");
    let mut ids = BTreeSet::new();
    for id in nodes {
        ensure!(
            !matches!(doc.node_kind(id), Some(NodeKind::ProcessingInstruction(_))),
            "RIM processing instructions are forbidden"
        );
        if let Some(elem) = doc.element(id) {
            for a in &elem.attributes {
                if a.name.local_name.eq_ignore_ascii_case("id") {
                    ensure!(
                        ids.insert(a.value.to_string()),
                        "RIM contains an ambiguous duplicate ID"
                    );
                }
            }
        }
    }
    Ok(doc)
}

fn extract_data(doc: &Document<'_>, root: NodeId, parts: &[NodeId], xml: &str) -> Result<RimData> {
    let identity = element(doc, root)?;
    exact_attributes(
        identity,
        &[
            (None, "corpus"),
            (None, "name"),
            (None, "patch"),
            (None, "supplemental"),
            (None, "tagId"),
            (None, "version"),
            (None, "tagVersion"),
        ],
    )?;
    for flag in ["corpus", "patch", "supplemental"] {
        ensure!(
            attribute(identity, None, flag)? == "false",
            "RIM {flag} must be false for a complete direct manifest"
        );
    }
    ensure!(
        attribute(identity, None, "version")? == "1.0",
        "unsupported SWID version"
    );
    decimal(attribute(identity, None, "tagVersion")?, "tagVersion")?;
    let tag_id = attribute(identity, None, "tagId")?;
    ensure!(
        !tag_id.is_empty() && tag_id.len() <= 256,
        "invalid RIM tagId"
    );
    let entity = element(doc, parts[0])?;
    exact_attributes(entity, &[(None, "name"), (None, "role")])?;
    empty_element(doc, parts[0])?;
    ensure!(
        attribute(entity, None, "name")? == "NVIDIA Corporation",
        "RIM entity is not NVIDIA"
    );
    let roles: BTreeSet<_> = attribute(entity, None, "role")?
        .split_ascii_whitespace()
        .collect();
    ensure!(
        roles == BTreeSet::from(["softwareCreator", "tagCreator"]),
        "unsupported RIM entity role"
    );
    let meta = element(doc, parts[1])?;
    empty_element(doc, parts[1])?;
    exact_attributes(
        meta,
        &[
            (None, "colloquialVersion"),
            (None, "edition"),
            (None, "product"),
            (None, "revision"),
            (None, "PayloadType"),
            (Some(RIM), "BindingSpec"),
            (Some(RIM), "BindingSpecVersion"),
            (Some(RIM), "PlatformManufacturerId"),
            (Some(RIM), "PlatformManufacturerStr"),
            (Some(RIM), "PlatformModel"),
            (Some(RIM), "FirmwareManufacturer"),
            (Some(RIM), "FirmwareManufacturerId"),
        ],
    )?;
    ensure!(
        attribute(meta, None, "PayloadType")? == "direct",
        "RIM must contain direct reference values"
    );
    ensure!(
        attribute(meta, Some(RIM), "BindingSpec")? == "RIMIM"
            && attribute(meta, Some(RIM), "BindingSpecVersion")? == "1.01",
        "unsupported RIM binding specification"
    );
    ensure!(
        attribute(meta, Some(RIM), "PlatformManufacturerStr")? == "NVIDIA Corporation"
            && attribute(meta, Some(RIM), "FirmwareManufacturer")? == "NVIDIA Corporation",
        "RIM manufacturer is not NVIDIA"
    );
    let firmware_manufacturer_id = u32::try_from(decimal(
        attribute(meta, Some(RIM), "FirmwareManufacturerId")?,
        "FirmwareManufacturerId",
    )?)?;
    let platform_manufacturer_id = u32::try_from(decimal(
        attribute(meta, Some(RIM), "PlatformManufacturerId")?,
        "PlatformManufacturerId",
    )?)?;
    ensure!(
        firmware_manufacturer_id == 5703 && platform_manufacturer_id == 5703,
        "RIM manufacturer PEN must be NVIDIA 5703"
    );
    let model = attribute(meta, Some(RIM), "PlatformModel")?;
    let product = attribute(meta, None, "product")?;
    ensure!(
        !model.is_empty() && model == product && model == attribute(identity, None, "name")?,
        "RIM model/product identity is inconsistent"
    );
    let edition = attribute(meta, None, "edition")?;
    let version = attribute(meta, None, "colloquialVersion")?;
    let components: Vec<_> = version.split('.').collect();
    let vbios_version = components.len() == 5
        && components
            .iter()
            .all(|s| s.len() == 2 && s.bytes().all(|b| b.is_ascii_hexdigit()));
    let driver_version = (2..=3).contains(&components.len())
        && components
            .iter()
            .all(|s| !s.is_empty() && s.len() <= 6 && s.bytes().all(|b| b.is_ascii_digit()));
    let kind = match (edition, driver_version, vbios_version) {
        ("GPU", true, false) => RimKind::GpuDriver,
        ("GPU", false, true) => RimKind::GpuVbios,
        ("SWITCH", false, true) => RimKind::NvSwitchVbios,
        _ => bail!("unsupported or ambiguous RIM edition/version profile"),
    };
    let metadata = RimMetadata {
        kind,
        version: version.into(),
        model: model.into(),
        product: product.into(),
        edition: edition.into(),
        tag_id: tag_id.into(),
        firmware_manufacturer_id,
        platform_manufacturer_id,
    };
    exact_attributes(element(doc, parts[2])?, &[])?;
    let mut measurements = BTreeMap::new();
    let mut inactive_indices = BTreeSet::new();
    let mut opaque_constraints = Vec::new();
    let mut seen = BTreeSet::new();
    for id in element_children(doc, parts[2])? {
        ensure!(
            matches(doc, id, SWID, "Resource"),
            "unexpected RIM Payload child"
        );
        empty_element(doc, id)?;
        let resource = element(doc, id)?;
        ensure!(
            attribute(resource, None, "type")? == "Measurement",
            "unsupported RIM Resource type"
        );
        let index = decimal(attribute(resource, None, "index")?, "measurement index")?;
        ensure!(
            seen.insert(index),
            "duplicate RIM measurement index {index}"
        );
        let active = strict_bool(attribute(resource, None, "active")?)?;
        let name = attribute(resource, None, "name")?;
        ensure!(!name.is_empty(), "RIM resource name is empty");
        if index >= u64::from(OPAQUE_INDEX_BASE) {
            let type_id = u16::try_from(index - u64::from(OPAQUE_INDEX_BASE))
                .context("RIM opaque type exceeds u16")?;
            allowed_attributes(
                resource,
                &[
                    (None, "type"),
                    (None, "index"),
                    (None, "active"),
                    (None, "name"),
                    (None, "alternatives"),
                    (None, "size"),
                    (Some(OPAQUE), "minSvn"),
                    (Some(OPAQUE), "includeInResult"),
                ],
            )?;
            let min_svn = decimal(
                attribute(resource, Some(OPAQUE), "minSvn")?,
                "opaque minimum SVN",
            )?;
            ensure!(
                decimal(
                    attribute(resource, None, "alternatives")?,
                    "opaque alternatives"
                )? == 1,
                "opaque minimum SVN supports exactly one constraint"
            );
            let declared_size = u32::try_from(decimal(
                attribute(resource, None, "size")?,
                "opaque declared size",
            )?)?;
            ensure!(declared_size > 0, "opaque declared size is zero");
            ensure!(
                min_svn <= u64::from(u16::MAX),
                "minimum SVN exceeds NVIDIA uint16 field"
            );
            let include_in_result = optional_attribute(resource, Some(OPAQUE), "includeInResult")
                .map(strict_bool)
                .transpose()?
                .unwrap_or(false);
            if active {
                opaque_constraints.push(OpaqueSvnConstraint {
                    type_id,
                    name: name.into(),
                    declared_size,
                    value_size: 2,
                    min_svn,
                    include_in_result,
                });
            }
            continue;
        }
        // SPDM 1.x has 8-bit indices; 0 and 255 are reserved operations.
        ensure!(
            index < 254,
            "RIM index cannot map to an individual SPDM measurement block"
        );
        let index = index as u16;
        ensure!(
            decimal(attribute(resource, None, "size")?, "measurement size")? == 48,
            "RIM measurements must be 48-byte SHA-384 digests"
        );
        let alternatives = usize::try_from(decimal(
            attribute(resource, None, "alternatives")?,
            "alternatives",
        )?)?;
        ensure!(
            (1..=MAX_ALTERNATIVES).contains(&alternatives),
            "RIM alternatives count outside bound"
        );
        let mut values = Vec::with_capacity(alternatives);
        for alt in 0..alternatives {
            let hash = attribute(resource, Some(HASH), &format!("Hash{alt}"))?;
            ensure!(hash.len() == 96, "RIM Hash{alt} must encode 48 bytes");
            let value = hex::decode(hash).context("RIM measurement is not hexadecimal")?;
            values.push(value);
        }
        for a in &resource.attributes {
            let standard = a.name.namespace_uri.is_none()
                && ["type", "index", "active", "alternatives", "name", "size"]
                    .contains(&a.name.local_name.as_ref());
            let hash = a.name.namespace_uri.as_deref() == Some(HASH)
                && a.name
                    .local_name
                    .strip_prefix("Hash")
                    .and_then(|s| s.parse::<usize>().ok())
                    .is_some_and(|n| n < alternatives && a.name.local_name == format!("Hash{n}"));
            ensure!(
                standard || hash,
                "unexpected RIM resource attribute {}",
                a.name.prefixed_name()
            );
        }
        if active {
            measurements.insert(index, values);
        } else {
            inactive_indices.insert(index);
        }
    }
    ensure!(
        !measurements.is_empty(),
        "RIM contains no active reference measurements"
    );
    Ok(RimData {
        metadata,
        measurements,
        inactive_indices,
        opaque_constraints,
        source_sha384: Sha384::digest(xml.as_bytes()).into(),
    })
}

fn extract_certificate_chain(doc: &Document<'_>, key_info: NodeId) -> Result<Vec<u8>> {
    exact_attributes(element(doc, key_info)?, &[])?;
    let x509 = exact_children(doc, key_info, &[(DS, "X509Data")])?[0];
    exact_attributes(element(doc, x509)?, &[])?;
    let cert_nodes = element_children(doc, x509)?;
    ensure!(
        !cert_nodes.is_empty() && cert_nodes.len() <= MAX_CERTIFICATES,
        "RIM certificate count outside bound"
    );
    let mut chain = Vec::new();
    for id in cert_nodes {
        ensure!(
            matches(doc, id, DS, "X509Certificate"),
            "only inline X509Certificate is supported in RIM KeyInfo"
        );
        let der = base64_element(doc, id, 16 * 1024)?;
        ensure!(!der.is_empty(), "empty RIM signer certificate");
        chain.extend_from_slice(&der);
    }
    Ok(chain)
}

fn element<'a, 'b>(doc: &'a Document<'b>, id: NodeId) -> Result<&'a Element<'b>> {
    doc.element(id).context("expected XML element")
}

fn matches(doc: &Document<'_>, id: NodeId, namespace: &str, local: &str) -> bool {
    doc.element(id)
        .is_some_and(|e| e.name.matches(Some(namespace), local))
}

fn optional_attribute<'a>(elem: &'a Element<'_>, ns: Option<&str>, local: &str) -> Option<&'a str> {
    elem.attributes
        .iter()
        .find(|a| a.name.matches(ns, local))
        .map(|a| a.value.as_ref())
}

fn attribute<'a>(elem: &'a Element<'_>, ns: Option<&str>, local: &str) -> Result<&'a str> {
    optional_attribute(elem, ns, local).with_context(|| format!("missing RIM attribute {local}"))
}

fn allowed_attributes(elem: &Element<'_>, allowed: &[(Option<&str>, &str)]) -> Result<()> {
    for attr in &elem.attributes {
        ensure!(
            allowed
                .iter()
                .any(|(ns, name)| attr.name.matches(*ns, name)),
            "unexpected RIM attribute {}",
            attr.name.prefixed_name()
        );
    }
    Ok(())
}

fn exact_attributes(elem: &Element<'_>, expected: &[(Option<&str>, &str)]) -> Result<()> {
    ensure!(
        elem.attributes.len() == expected.len(),
        "unexpected attribute count on {}",
        elem.name.prefixed_name()
    );
    allowed_attributes(elem, expected)?;
    for (ns, name) in expected {
        attribute(elem, *ns, name)?;
    }
    Ok(())
}

fn element_children(doc: &Document<'_>, id: NodeId) -> Result<Vec<NodeId>> {
    let mut result = Vec::new();
    for child in doc.children_iter(id) {
        match doc.node_kind(child) {
            Some(NodeKind::Element(_)) => result.push(child),
            Some(NodeKind::Text(text) | NodeKind::CData(text)) => ensure!(
                text.trim().is_empty(),
                "unexpected text in RIM structural element"
            ),
            Some(NodeKind::Comment(_)) => {}
            _ => bail!("unexpected XML node in RIM structure"),
        }
    }
    Ok(result)
}

fn exact_children(
    doc: &Document<'_>,
    id: NodeId,
    expected: &[(&str, &str)],
) -> Result<Vec<NodeId>> {
    let children = element_children(doc, id)?;
    ensure!(
        children.len() == expected.len(),
        "unexpected RIM child count on {}",
        element(doc, id)?.name.prefixed_name()
    );
    for (&child, &(ns, name)) in children.iter().zip(expected) {
        ensure!(
            matches(doc, child, ns, name),
            "expected RIM child {name} in namespace {ns}"
        );
    }
    Ok(children)
}

fn empty_element(doc: &Document<'_>, id: NodeId) -> Result<()> {
    ensure!(
        element_children(doc, id)?.is_empty(),
        "RIM element must be empty"
    );
    Ok(())
}

fn algorithm(doc: &Document<'_>, id: NodeId, expected: &str) -> Result<()> {
    let elem = element(doc, id)?;
    exact_attributes(elem, &[(None, "Algorithm")])?;
    empty_element(doc, id)?;
    ensure!(
        attribute(elem, None, "Algorithm")? == expected,
        "unsupported RIM algorithm; expected {expected}"
    );
    Ok(())
}

fn base64_element(doc: &Document<'_>, id: NodeId, max_bytes: usize) -> Result<Vec<u8>> {
    exact_attributes(element(doc, id)?, &[])?;
    let mut text = String::new();
    for child in doc.children_iter(id) {
        match doc.node_kind(child) {
            Some(NodeKind::Text(s) | NodeKind::CData(s)) => {
                text.extend(s.chars().filter(|c| !matches!(c, ' ' | '\t' | '\r' | '\n')))
            }
            Some(NodeKind::Comment(_)) => {}
            _ => bail!("RIM base64 element contains nested content"),
        }
    }
    ensure!(
        text.len() <= max_bytes.div_ceil(3) * 4,
        "RIM base64 value exceeds bound"
    );
    let decoded = STANDARD.decode(&text).context("invalid base64 in RIM")?;
    ensure!(
        decoded.len() <= max_bytes,
        "RIM decoded value exceeds bound"
    );
    Ok(decoded)
}

fn decimal(value: &str, label: &str) -> Result<u64> {
    ensure!(
        !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()),
        "RIM {label} must be unsigned decimal"
    );
    value
        .parse()
        .with_context(|| format!("RIM {label} exceeds supported range"))
}

fn strict_bool(value: &str) -> Result<bool> {
    match value {
        "True" => Ok(true),
        "False" => Ok(false),
        _ => bail!("RIM boolean must be exactly True or False"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const DRIVER: &str = include_str!("../../testdata/gpu/rim/NV_GPU_DRIVER_GH100_550.144.03.xml");

    // These parser-only tests deliberately alter signed fixture text. They do
    // not create VerifiedRim or exercise an admission bypass.
    fn extract_unsigned(xml: &str) -> Result<RimData> {
        let doc = parse_document(xml)?;
        let root = doc.document_element().unwrap();
        let parts = element_children(&doc, root)?;
        extract_data(&doc, root, &parts, xml)
    }

    #[test]
    fn measurement_schema_rejects_ambiguous_or_truncated_values() {
        for bad in [
            DRIVER.replacen("active=\"False\"", "active=\"false\"", 1),
            DRIVER.replacen("index=\"1\"", "index=\"0\"", 1),
            DRIVER.replacen("index=\"1\"", "index=\"-1\"", 1),
            DRIVER.replacen("alternatives=\"1\"", "alternatives=\"0\"", 1),
            DRIVER.replacen("size=\"48\"", "size=\"32\"", 1),
            DRIVER.replacen("ns2:Hash0=\"", "ns2:Hash9=\"", 1),
        ] {
            assert!(extract_unsigned(&bad).is_err());
        }
    }

    #[test]
    fn opaque_svn_constraints_preserve_type_width_and_minimum() {
        let resource = format!("<ns0:Resource xmlns:opaque=\"{OPAQUE}\" type=\"Measurement\" index=\"4133\" active=\"True\" alternatives=\"1\" size=\"1\" name=\"FSP_UCODE_MIN_SVN\" opaque:minSvn=\"5\" opaque:includeInResult=\"True\"/>");
        let xml = DRIVER.replacen("</ns0:Payload>", &(resource + "</ns0:Payload>"), 1);
        let parsed = extract_unsigned(&xml).unwrap();
        assert_eq!(parsed.opaque_constraints.len(), 1);
        assert_eq!(parsed.opaque_constraints[0].type_id, 37);
        assert_eq!(parsed.opaque_constraints[0].min_svn, 5);
        assert_eq!(parsed.opaque_constraints[0].declared_size, 1);
        assert_eq!(parsed.opaque_constraints[0].value_size, 2);
        assert!(parsed.opaque_constraints[0].include_in_result);
        assert!(extract_unsigned(&xml.replace("minSvn=\"5\"", "minSvn=\"65536\"")).is_err());
        assert!(extract_unsigned(&xml.replace("minSvn=\"5\"", "minSvn=\"5bad\"")).is_err());
    }
}
