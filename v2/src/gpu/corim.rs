//! Signed CoRIM/CoMID authentication and typed reference claims.
//!
//! COSE follows RFC 9052/9360 (ES384, an embedded payload and pinned X.509
//! chain); the supported reference subset follows NVIDIA's published CoRIM
//! CDDL and the CoRIM draft-11 inline signing profile. Unknown extensions,
//! dependent external RIMs, linked tags and unimplemented triple kinds fail
//! closed. No reference URI is fetched and no CoMID claim is discarded.
//!
//! [`VerifiedCorim`] authenticates a manifest. It is **not** a GPU verdict and
//! is not convertible to the legacy XML [`super::rim::VerifiedRim`]. A caller
//! must select an authorized profile/environment, enforce dependency triples,
//! and match all typed claims against the device's signed CoMID evidence.

use super::{
    cert::{self, Purpose, ValidatedChain},
    revocation::{self, RevocationEvidence},
};
use anyhow::{bail, ensure, Context, Result};
use ciborium::value::Value;
use der::{asn1::ObjectIdentifier, Encode};
use p384::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    pkcs8::DecodePublicKey,
};
use serde::Serialize;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::collections::{BTreeMap, BTreeSet};
use x509_cert::Certificate;

const MAX_BYTES: usize = 4 * 1024 * 1024;
const MAX_NODES: usize = 32_768;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Identifier {
    Text(String),
    Uuid([u8; 16]),
    Oid(String),
    Bytes(Vec<u8>),
    Ueid(Vec<u8>),
    Unsigned(u64),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Profile {
    Uri(String),
    Oid(String),
    Text(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Validity {
    pub not_before: Option<u64>,
    pub not_after: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Entity {
    pub name: String,
    pub uri: Option<String>,
    pub roles: BTreeSet<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Class {
    pub id: Option<Identifier>,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub layer: Option<u64>,
    pub index: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Environment {
    pub class: Option<Class>,
    pub instance: Option<Identifier>,
    pub group: Option<Identifier>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReferenceTriple {
    pub environment: Environment,
    pub measurements: Vec<Measurement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DependencyTriple {
    pub domain: Environment,
    pub trustees: Vec<Environment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Measurement {
    pub key: Option<Identifier>,
    pub values: MeasurementValues,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum VersionScheme {
    Integer(i64),
    Text(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Version {
    pub value: String,
    pub scheme: Option<VersionScheme>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum SecurityVersion {
    Exact(u64),
    Minimum(u64),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReferenceDigest {
    /// IANA Named Information algorithm identifier: 1=SHA256, 7=SHA384, 8=SHA512.
    pub algorithm: u64,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum RawValue {
    Exact(Vec<u8>),
    Masked { value: Vec<u8>, mask: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IntegerRange {
    pub minimum: Option<i64>,
    pub maximum: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MeasurementValues {
    pub version: Option<Version>,
    pub svn: Option<SecurityVersion>,
    pub digests: Vec<ReferenceDigest>,
    /// CoMID flag numbers 0..9, preserving both true and false constraints.
    pub flags: BTreeMap<u64, bool>,
    pub raw_value: Option<RawValue>,
    pub name: Option<String>,
    pub integer_range: Option<IntegerRange>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Comid {
    pub id: Identifier,
    pub version: Option<u64>,
    pub language: Option<String>,
    pub entities: Vec<Entity>,
    pub references: Vec<ReferenceTriple>,
    pub dependencies: Vec<DependencyTriple>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CorimClaims {
    pub id: Identifier,
    pub profile: Option<Profile>,
    pub validity: Option<Validity>,
    pub entities: Vec<Entity>,
    pub comids: Vec<Comid>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignerMetadata {
    pub name: String,
    pub uri: Option<String>,
    pub subject: Option<String>,
    pub validity: Option<Validity>,
}

#[derive(Debug, Clone)]
pub struct VerifiedCorim {
    claims: CorimClaims,
    signer: SignerMetadata,
    source_sha384: [u8; 48],
}

#[derive(Debug)]
pub struct SignatureVerifiedCorim {
    claims: CorimClaims,
    signer: SignerMetadata,
    source_sha384: [u8; 48],
    chain: ValidatedChain,
}

macro_rules! accessors {
    () => {
        pub fn claims(&self) -> &CorimClaims {
            &self.claims
        }
        pub fn signer(&self) -> &SignerMetadata {
            &self.signer
        }
        pub fn source_sha384(&self) -> &[u8; 48] {
            &self.source_sha384
        }
    };
}
impl VerifiedCorim {
    accessors!();
}
impl SignatureVerifiedCorim {
    accessors!();
}

/// Authenticate the signature, trusted path, validity intervals and revocation.
/// Successful authentication still requires profile-specific claim appraisal.
pub fn verify_corim(
    bytes: &[u8],
    roots: &[Certificate],
    evidence: &RevocationEvidence,
    now: u64,
) -> Result<VerifiedCorim> {
    let verified = verify_corim_signature_and_chain(bytes, roots, now)?;
    revocation::check_chain(&verified.chain, evidence, now).context("CoRIM signer revocation")?;
    Ok(VerifiedCorim {
        claims: verified.claims,
        signer: verified.signer,
        source_sha384: verified.source_sha384,
    })
}

/// Cryptographic primitive without a revocation verdict. Not an admission API.
pub fn verify_corim_signature_and_chain(
    bytes: &[u8],
    roots: &[Certificate],
    now: u64,
) -> Result<SignatureVerifiedCorim> {
    let envelope = decode(bytes)?;
    let fields = array(tag(&envelope, 18)?, 4, 4)?;
    let protected_bytes = bstr(&fields[0])?;
    let protected_value = decode(protected_bytes)?;
    let protected = map(&protected_value, &[1, 2, 3, 4, 8, 15, 33, 34])?;
    let unprotected = map(&fields[1], &[33])?;
    for key in unprotected.keys() {
        ensure!(
            !protected.contains_key(key),
            "COSE header appears in protected and unprotected maps"
        );
    }
    ensure!(
        integer(required(&protected, 1)?)? == -35,
        "CoRIM requires protected ES384 algorithm (-35)"
    );
    ensure!(
        text(required(&protected, 3)?)? == "application/rim+cbor",
        "CoRIM requires protected application/rim+cbor content type"
    );
    if let Some(kid) = protected.get(&4) {
        ensure!(bstr(kid)?.len() <= 1024, "COSE key ID exceeds bound");
    }
    if let Some(critical) = protected.get(&2) {
        let mut seen = BTreeSet::new();
        for key in array(critical, 1, 8)? {
            let key = integer(key)?;
            ensure!(
                key != 2 && seen.insert(key) && protected.contains_key(&key),
                "invalid or duplicate COSE critical header"
            );
        }
    }
    let chain_value = protected
        .get(&33)
        .or_else(|| unprotected.get(&33))
        .context("CoRIM x5chain is missing")?;
    let chain_certs: Vec<&[u8]> = match chain_value {
        Value::Bytes(v) => vec![v],
        v => array(v, 2, 8)?.iter().map(bstr).collect::<Result<_>>()?,
    };
    for c in &chain_certs {
        ensure!(
            !c.is_empty() && c.len() <= 16 * 1024,
            "CoRIM certificate size outside bound"
        );
    }
    // Protect the leaf certificate identity when the chain itself is mutable.
    if !protected.contains_key(&33) {
        ensure!(
            protected.contains_key(&34),
            "unprotected x5chain requires a protected x5t thumbprint"
        );
    }
    if let Some(thumbprint) = protected.get(&34) {
        let hash = array(thumbprint, 2, 2)?;
        let expected = match integer(&hash[0])? {
            -16 => Sha256::digest(chain_certs[0]).to_vec(),
            -43 => Sha384::digest(chain_certs[0]).to_vec(),
            -44 => Sha512::digest(chain_certs[0]).to_vec(),
            _ => bail!("unsupported COSE x5t digest algorithm"),
        };
        ensure!(
            expected == bstr(&hash[1])?,
            "COSE x5t certificate thumbprint mismatch"
        );
    }
    let chain_bytes = chain_certs.concat();
    let chain = cert::validate_chain(&chain_bytes, roots, now, Purpose::Rim)
        .context("CoRIM signer path")?;
    let payload = bstr(&fields[2]).context("CoRIM requires an embedded CBOR payload")?;
    let signature = Signature::from_slice(bstr(&fields[3])?)
        .context("COSE ES384 signature must be 96-byte r || s")?;
    let key = VerifyingKey::from_public_key_der(
        &chain
            .leaf()
            .tbs_certificate
            .subject_public_key_info
            .to_der()?,
    )?;
    let signature_structure = Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected_bytes.to_vec()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.to_vec()),
    ]);
    let mut message = Vec::new();
    ciborium::ser::into_writer(&signature_structure, &mut message)?;
    key.verify(&message, &signature)
        .context("CoRIM COSE signature mismatch")?;
    let signer = signer_metadata(&protected, now)?;
    let claims = parse_payload(payload, now)?;
    if let Some(subject) = &signer.subject {
        let expected = match &claims.id {
            Identifier::Text(id) => id.clone(),
            Identifier::Uuid(id) => {
                let h = hex::encode(id);
                format!(
                    "{}-{}-{}-{}-{}",
                    &h[..8],
                    &h[8..12],
                    &h[12..16],
                    &h[16..20],
                    &h[20..]
                )
            }
            _ => bail!("unsupported CWT subject identity"),
        };
        ensure!(
            subject == &expected,
            "CWT subject does not match CoRIM identity"
        );
    }
    Ok(SignatureVerifiedCorim {
        claims,
        signer,
        source_sha384: Sha384::digest(bytes).into(),
        chain,
    })
}

fn signer_metadata(protected: &BTreeMap<i64, &Value>, now: u64) -> Result<SignerMetadata> {
    let legacy = if let Some(value) = protected.get(&8) {
        let decoded = decode(bstr(value)?)?;
        let meta = map(&decoded, &[0, 1])?;
        let signer = map(required(&meta, 0)?, &[0, 1])?;
        Some(SignerMetadata {
            name: text(required(&signer, 0)?)?.into(),
            uri: signer.get(&1).map(|v| uri(v)).transpose()?,
            subject: None,
            validity: meta.get(&1).map(|v| validity(v, now)).transpose()?,
        })
    } else {
        None
    };
    let cwt = if let Some(value) = protected.get(&15) {
        let m = map(value, &[1, 2, 4, 5])?;
        let before = m.get(&5).map(|v| unsigned(v)).transpose()?;
        ensure!(
            before.is_none() || m.contains_key(&4),
            "CWT not-before requires expiration"
        );
        let validity = m
            .get(&4)
            .map(|v| {
                let validity = Validity {
                    not_before: before,
                    not_after: unsigned(v)?,
                };
                check_validity(&validity, now)?;
                Ok::<_, anyhow::Error>(validity)
            })
            .transpose()?;
        Some(SignerMetadata {
            name: text(required(&m, 1)?)?.into(),
            uri: None,
            subject: m.get(&2).map(|v| text(v).map(str::to_owned)).transpose()?,
            validity,
        })
    } else {
        None
    };
    match (legacy, cwt) {
        (Some(mut a), Some(b)) => {
            ensure!(
                a.name == b.name && a.validity == b.validity,
                "CoRIM legacy metadata and CWT claims conflict"
            );
            a.subject = b.subject;
            Ok(a)
        }
        (Some(a), None) | (None, Some(a)) => Ok(a),
        _ => bail!("CoRIM requires protected signer metadata (8 or 15)"),
    }
}

fn parse_payload(bytes: &[u8], now: u64) -> Result<CorimClaims> {
    let value = decode(bytes)?;
    let m = map(tag(&value, 501)?, &[0, 1, 3, 4, 5])?;
    let id = manifest_id(required(&m, 0)?)?;
    let profile = m
        .get(&3)
        .map(|v| match v {
            Value::Text(s) => Ok(Profile::Text(s.clone())),
            Value::Tag(32, _) => uri(v).map(Profile::Uri),
            Value::Tag(111, _) => oid(v).map(Profile::Oid),
            _ => bail!("unsupported CoRIM profile type"),
        })
        .transpose()?;
    let validity = m.get(&4).map(|v| validity(v, now)).transpose()?;
    let entities = m
        .get(&5)
        .map(|v| entities(v, &[1, 2]))
        .transpose()?
        .unwrap_or_default();
    let tags = array(required(&m, 1)?, 1, 25)?;
    let mut comids = Vec::with_capacity(tags.len());
    for concise_tag in tags {
        comids.push(parse_comid(bstr(tag(concise_tag, 506)?)?)?);
    }
    for (i, a) in comids.iter().enumerate() {
        ensure!(
            !comids[..i].iter().any(|b| b.id == a.id),
            "duplicate CoMID identity"
        );
    }
    Ok(CorimClaims {
        id,
        profile,
        validity,
        entities,
        comids,
    })
}

fn parse_comid(bytes: &[u8]) -> Result<Comid> {
    let value = decode(bytes)?;
    let m = map(&value, &[0, 1, 2, 4])?;
    let identity = map(required(&m, 1)?, &[0, 12])?;
    let id = manifest_id(required(&identity, 0)?)?;
    let version = identity.get(&12).map(|v| unsigned(v)).transpose()?;
    let language = m.get(&0).map(|v| text(v).map(str::to_owned)).transpose()?;
    let entities = m
        .get(&2)
        .map(|v| entities(v, &[0, 1, 2]))
        .transpose()?
        .unwrap_or_default();
    let triples = map(required(&m, 4)?, &[0, 4])?;
    let mut references = Vec::new();
    if let Some(value) = triples.get(&0) {
        for r in array(value, 1, 256)? {
            let r = array(r, 2, 2)?;
            let environment = environment(&r[0])?;
            let measurements = array(&r[1], 1, 256)?
                .iter()
                .map(measurement)
                .collect::<Result<_>>()?;
            references.push(ReferenceTriple {
                environment,
                measurements,
            });
        }
    }
    ensure!(
        !references.is_empty(),
        "CoMID contains no supported reference triples"
    );
    let mut dependencies = Vec::new();
    if let Some(value) = triples.get(&4) {
        for d in array(value, 1, 256)? {
            let d = array(d, 2, 2)?;
            let domain = environment(&d[0])?;
            let trustees = array(&d[1], 1, 256)?
                .iter()
                .map(environment)
                .collect::<Result<_>>()?;
            dependencies.push(DependencyTriple { domain, trustees });
        }
    }
    Ok(Comid {
        id,
        version,
        language,
        entities,
        references,
        dependencies,
    })
}

fn environment(value: &Value) -> Result<Environment> {
    let m = map(value, &[0, 1, 2])?;
    ensure!(!m.is_empty(), "empty CoMID environment is ambiguous");
    let class = m
        .get(&0)
        .map(|v| {
            let c = map(v, &[0, 1, 2, 3, 4])?;
            ensure!(
                c.contains_key(&0) || c.contains_key(&1) || c.contains_key(&2),
                "CoMID class has no identity"
            );
            Ok::<_, anyhow::Error>(Class {
                id: c
                    .get(&0)
                    .map(|v| typed_identifier(v, &[37, 111, 560]))
                    .transpose()?,
                vendor: c.get(&1).map(|v| text(v).map(str::to_owned)).transpose()?,
                model: c.get(&2).map(|v| text(v).map(str::to_owned)).transpose()?,
                layer: c.get(&3).map(|v| unsigned(v)).transpose()?,
                index: c.get(&4).map(|v| unsigned(v)).transpose()?,
            })
        })
        .transpose()?;
    Ok(Environment {
        class,
        instance: m
            .get(&1)
            .map(|v| typed_identifier(v, &[37, 550, 560]))
            .transpose()?,
        group: m
            .get(&2)
            .map(|v| typed_identifier(v, &[37, 560]))
            .transpose()?,
    })
}

fn measurement(value: &Value) -> Result<Measurement> {
    let m = map(value, &[0, 1])?;
    let key = m
        .get(&0)
        .map(|v| match v {
            Value::Integer(_) => unsigned(v).map(Identifier::Unsigned),
            Value::Text(s) => Ok(Identifier::Text(s.clone())),
            _ => typed_identifier(v, &[37, 111]),
        })
        .transpose()?;
    let values = measurement_values(required(&m, 1)?)?;
    Ok(Measurement { key, values })
}

fn measurement_values(value: &Value) -> Result<MeasurementValues> {
    let m = map(value, &[0, 1, 2, 3, 4, 11, 15])?;
    ensure!(!m.is_empty(), "empty CoMID measurement values");
    let version = m
        .get(&0)
        .map(|v| {
            let m = map(v, &[0, 1])?;
            let scheme = m
                .get(&1)
                .map(|v| match v {
                    Value::Integer(_) => integer(v).map(VersionScheme::Integer),
                    Value::Text(s) => Ok(VersionScheme::Text(s.clone())),
                    _ => bail!("unsupported CoMID version scheme"),
                })
                .transpose()?;
            Ok::<_, anyhow::Error>(Version {
                value: text(required(&m, 0)?)?.into(),
                scheme,
            })
        })
        .transpose()?;
    let svn = m
        .get(&1)
        .map(|v| match v {
            Value::Integer(_) => unsigned(v).map(SecurityVersion::Exact),
            Value::Tag(552, v) => unsigned(v).map(SecurityVersion::Exact),
            Value::Tag(553, v) => unsigned(v).map(SecurityVersion::Minimum),
            _ => bail!("unsupported CoMID SVN constraint"),
        })
        .transpose()?;
    let mut digests = Vec::new();
    if let Some(value) = m.get(&2) {
        for d in array(value, 1, 32)? {
            let d = array(d, 2, 2)?;
            let algorithm = unsigned(&d[0])?;
            let size = match algorithm {
                1 => 32,
                7 => 48,
                8 => 64,
                _ => bail!("unsupported CoMID reference digest algorithm"),
            };
            let value = bstr(&d[1])?.to_vec();
            ensure!(value.len() == size, "CoMID digest has incorrect size");
            ensure!(
                !digests
                    .iter()
                    .any(|d: &ReferenceDigest| d.algorithm == algorithm && d.value == value),
                "duplicate CoMID digest"
            );
            digests.push(ReferenceDigest { algorithm, value });
        }
    }
    let mut flags = BTreeMap::new();
    if let Some(value) = m.get(&3) {
        for (k, v) in map(value, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9])? {
            let Value::Bool(v) = v else {
                bail!("CoMID flag is not boolean")
            };
            flags.insert(k as u64, *v);
        }
        ensure!(!flags.is_empty(), "empty CoMID flags map");
    }
    let raw_value = m
        .get(&4)
        .map(|v| match v {
            Value::Tag(560, v) => Ok(RawValue::Exact(bstr(v)?.to_vec())),
            Value::Tag(563, v) => {
                let fields = array(v, 2, 2)?;
                let value = bstr(&fields[0])?.to_vec();
                let mask = bstr(&fields[1])?.to_vec();
                ensure!(
                    !value.is_empty() && value.len() == mask.len(),
                    "CoMID masked raw value length mismatch"
                );
                Ok(RawValue::Masked { value, mask })
            }
            _ => bail!("unsupported CoMID raw-value type"),
        })
        .transpose()?;
    let name = m.get(&11).map(|v| text(v).map(str::to_owned)).transpose()?;
    let integer_range = m
        .get(&15)
        .map(|v| match v {
            Value::Integer(_) => {
                let value = integer(v)?;
                Ok(IntegerRange {
                    minimum: Some(value),
                    maximum: Some(value),
                })
            }
            Value::Tag(564, v) => {
                let fields = array(v, 2, 2)?;
                let minimum = if fields[0] == Value::Null {
                    None
                } else {
                    Some(integer(&fields[0])?)
                };
                let maximum = if fields[1] == Value::Null {
                    None
                } else {
                    Some(integer(&fields[1])?)
                };
                ensure!(
                    !matches!((minimum,maximum),(Some(a),Some(b)) if a>b),
                    "inverted CoMID integer range"
                );
                Ok(IntegerRange { minimum, maximum })
            }
            _ => bail!("unsupported CoMID integer range"),
        })
        .transpose()?;
    Ok(MeasurementValues {
        version,
        svn,
        digests,
        flags,
        raw_value,
        name,
        integer_range,
    })
}

fn entities(value: &Value, allowed_roles: &[u64]) -> Result<Vec<Entity>> {
    array(value, 1, 32)?
        .iter()
        .map(|v| {
            let m = map(v, &[0, 1, 2])?;
            let mut roles = BTreeSet::new();
            for role in array(required(&m, 2)?, 1, allowed_roles.len())? {
                let role = unsigned(role)?;
                ensure!(
                    allowed_roles.contains(&role) && roles.insert(role),
                    "unknown or repeated CoRIM entity role"
                );
            }
            Ok(Entity {
                name: text(required(&m, 0)?)?.into(),
                uri: m.get(&1).map(|v| uri(v)).transpose()?,
                roles,
            })
        })
        .collect()
}

fn manifest_id(value: &Value) -> Result<Identifier> {
    match value {
        Value::Text(s) if !s.is_empty() && s.len() <= 1024 => Ok(Identifier::Text(s.clone())),
        Value::Bytes(v) => Ok(Identifier::Uuid(
            v.as_slice()
                .try_into()
                .context("manifest UUID must be 16 bytes")?,
        )),
        _ => bail!("invalid CoRIM/CoMID identity"),
    }
}

fn typed_identifier(value: &Value, tags: &[u64]) -> Result<Identifier> {
    let Value::Tag(t, v) = value else {
        bail!("identifier requires an explicit CBOR tag")
    };
    ensure!(tags.contains(t), "unsupported identifier tag {t}");
    match t {
        111 => oid(value).map(Identifier::Oid),
        37 => Ok(Identifier::Uuid(
            bstr(v)?.try_into().context("UUID must be 16 bytes")?,
        )),
        550 => {
            let bytes = bstr(v)?;
            ensure!((7..=33).contains(&bytes.len()), "invalid UEID size");
            Ok(Identifier::Ueid(bytes.to_vec()))
        }
        560 => {
            let bytes = bstr(v)?;
            ensure!(!bytes.is_empty(), "empty byte identifier");
            Ok(Identifier::Bytes(bytes.to_vec()))
        }
        _ => bail!("unsupported identifier"),
    }
}

fn oid(value: &Value) -> Result<String> {
    let raw = bstr(tag(value, 111)?)?;
    Ok(ObjectIdentifier::from_bytes(raw)
        .context("malformed BER OID content")?
        .to_string())
}

fn uri(value: &Value) -> Result<String> {
    let s = text(tag(value, 32)?)?;
    let (scheme, _) = s.split_once(':').context("URI has no scheme")?;
    ensure!(
        scheme
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphabetic)
            && scheme
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || [b'+', b'-', b'.'].contains(&b))
            && !s.chars().any(|c| c.is_whitespace() || c.is_control()),
        "invalid absolute URI"
    );
    Ok(s.into())
}

fn validity(value: &Value, now: u64) -> Result<Validity> {
    let m = map(value, &[0, 1])?;
    let not_before = m.get(&0).map(|v| unsigned(tag(v, 1)?)).transpose()?;
    let not_after = unsigned(tag(required(&m, 1)?, 1)?)?;
    let validity = Validity {
        not_before,
        not_after,
    };
    check_validity(&validity, now)?;
    Ok(validity)
}

fn check_validity(validity: &Validity, now: u64) -> Result<()> {
    ensure!(
        validity
            .not_before
            .is_none_or(|t| t <= now && t < validity.not_after),
        "CoRIM validity has not begun or is inverted"
    );
    ensure!(now < validity.not_after, "CoRIM validity expired");
    Ok(())
}

fn map<'a>(value: &'a Value, allowed: &[i64]) -> Result<BTreeMap<i64, &'a Value>> {
    let Value::Map(entries) = value else {
        bail!("expected CoRIM CBOR map")
    };
    let mut result = BTreeMap::new();
    for (key, value) in entries {
        let key = integer(key)?;
        ensure!(allowed.contains(&key), "unsupported CoRIM/COSE field {key}");
        ensure!(
            result.insert(key, value).is_none(),
            "duplicate CoRIM/COSE map key {key}"
        );
    }
    Ok(result)
}
fn required<'a>(m: &BTreeMap<i64, &'a Value>, key: i64) -> Result<&'a Value> {
    m.get(&key)
        .copied()
        .with_context(|| format!("missing CoRIM field {key}"))
}
fn array(value: &Value, min: usize, max: usize) -> Result<&[Value]> {
    let Value::Array(v) = value else {
        bail!("expected CoRIM array")
    };
    ensure!(
        (min..=max).contains(&v.len()),
        "CoRIM array size outside bound"
    );
    Ok(v)
}
fn bstr(value: &Value) -> Result<&[u8]> {
    let Value::Bytes(v) = value else {
        bail!("expected CBOR byte string")
    };
    Ok(v)
}
fn text(value: &Value) -> Result<&str> {
    let Value::Text(v) = value else {
        bail!("expected CBOR text")
    };
    ensure!(
        !v.is_empty() && v.len() <= 4096,
        "CoRIM text size outside bound"
    );
    Ok(v)
}
fn integer(value: &Value) -> Result<i64> {
    let Value::Integer(v) = value else {
        bail!("expected CBOR integer")
    };
    Ok(i64::try_from(*v)?)
}
fn unsigned(value: &Value) -> Result<u64> {
    let Value::Integer(v) = value else {
        bail!("expected unsigned CBOR integer")
    };
    Ok(u64::try_from(*v)?)
}
fn tag(value: &Value, expected: u64) -> Result<&Value> {
    let Value::Tag(t, v) = value else {
        bail!("required CBOR tag {expected} is missing")
    };
    ensure!(
        *t == expected,
        "unexpected CBOR tag {t}, expected {expected}"
    );
    Ok(v)
}

fn decode(bytes: &[u8]) -> Result<Value> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_BYTES,
        "CoRIM CBOR size outside bound"
    );
    let mut offset = 0;
    let mut budget = MAX_NODES;
    scan(bytes, &mut offset, 0, &mut budget)?;
    ensure!(offset == bytes.len(), "trailing CBOR data");
    let mut reader = bytes;
    let value = ciborium::de::from_reader_with_recursion_limit(&mut reader, 32)
        .context("malformed CoRIM CBOR")?;
    ensure!(reader.is_empty(), "trailing CoRIM CBOR");
    Ok(value)
}

// Preflight before allocation: bounded definite-length CBOR only. This profile
// never accepts floats, undefined values, indefinite containers or huge lengths.
fn scan(bytes: &[u8], offset: &mut usize, depth: usize, budget: &mut usize) -> Result<()> {
    ensure!(
        depth <= 24 && *budget > 0,
        "CoRIM CBOR nesting/node limit exceeded"
    );
    *budget -= 1;
    let head = *bytes.get(*offset).context("truncated CBOR")?;
    *offset += 1;
    let major = head >> 5;
    let ai = head & 31;
    if major == 7 {
        ensure!(
            [20, 21, 22].contains(&ai),
            "unsupported CBOR simple/float value"
        );
        return Ok(());
    }
    let length = match ai {
        0..=23 => u64::from(ai),
        24..=27 => {
            let count = 1usize << (ai - 24);
            let end = offset.checked_add(count).context("CBOR length overflow")?;
            let b = bytes.get(*offset..end).context("truncated CBOR argument")?;
            *offset = end;
            b.iter().fold(0u64, |n, b| (n << 8) | u64::from(*b))
        }
        _ => bail!("indefinite/reserved CBOR encoding is not supported"),
    };
    match major {
        0 | 1 => {}
        2 | 3 => {
            let end = offset
                .checked_add(usize::try_from(length)?)
                .context("CBOR length overflow")?;
            ensure!(end <= bytes.len(), "truncated CBOR string");
            *offset = end;
        }
        4 | 5 => {
            let count = if major == 5 {
                ensure!(length <= 128, "CBOR map too large");
                length * 2
            } else {
                ensure!(length <= 4096, "CBOR array too large");
                length
            };
            ensure!(
                count <= *budget as u64,
                "CBOR container exceeds node budget"
            );
            for _ in 0..count {
                scan(bytes, offset, depth + 1, budget)?;
            }
        }
        6 => scan(bytes, offset, depth + 1, budget)?,
        _ => bail!("invalid CBOR major type"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::{
        asn1::{BitString, GeneralizedTime},
        Decode,
    };
    use p384::{
        ecdsa::{signature::Signer, SigningKey},
        pkcs8::DecodePrivateKey,
    };
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose,
        PKCS_ECDSA_P384_SHA384,
    };
    use std::time::Duration;
    use x509_cert::{
        crl::{CertificateList, TbsCertList},
        time::Time,
        Version as X509Version,
    };

    const NOW: u64 = 1_791_849_600;
    const DRIVER: &str = include_str!("../../testdata/gpu/rim/rubin_driver_example.diag");
    const VBIOS: &str = include_str!("../../testdata/gpu/rim/rubin_vbios_example.diag");
    const FSP: &str = include_str!("../../testdata/gpu/rim/blackwell_fsp_real.diag");

    fn raw_comid(diag: &str) -> Vec<u8> {
        let hex = diag.split("h'").nth(1).unwrap().split('\'').next().unwrap();
        hex::decode(hex).unwrap()
    }
    fn i(n: i64) -> Value {
        Value::Integer(n.into())
    }
    fn m(entries: Vec<(i64, Value)>) -> Value {
        Value::Map(entries.into_iter().map(|(k, v)| (i(k), v)).collect())
    }
    fn encoded(value: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::ser::into_writer(value, &mut out).unwrap();
        out
    }
    fn fixture_payload() -> Vec<u8> {
        encoded(&Value::Tag(
            501,
            Box::new(m(vec![
                (
                    0,
                    Value::Text("TEST ONLY signed wrapper of NVIDIA unsigned CoMID example".into()),
                ),
                (
                    1,
                    Value::Array(vec![Value::Tag(
                        506,
                        Box::new(Value::Bytes(raw_comid(DRIVER))),
                    )]),
                ),
                (
                    4,
                    m(vec![
                        (0, Value::Tag(1, Box::new(i(NOW as i64 - 10)))),
                        (1, Value::Tag(1, Box::new(i(NOW as i64 + 100)))),
                    ]),
                ),
            ])),
        ))
    }

    // Generated test certificates and signatures exercise actual cryptography;
    // they are not NVIDIA credentials and are never compiled into production.
    struct TestSigner {
        root: Certificate,
        leaf: Certificate,
        root_key: KeyPair,
        key: SigningKey,
    }
    impl TestSigner {
        fn new() -> Self {
            let root_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
            let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
            let mut root = CertificateParams::default();
            root.distinguished_name
                .push(DnType::CommonName, "TEST ONLY CoRIM root");
            root.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            root.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            let root = root.self_signed(&root_key).unwrap();
            let mut leaf = CertificateParams::default();
            leaf.distinguished_name
                .push(DnType::CommonName, "TEST ONLY CoRIM signer");
            leaf.is_ca = IsCa::ExplicitNoCa;
            leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            let leaf = leaf.signed_by(&leaf_key, &root, &root_key).unwrap();
            Self {
                root: Certificate::from_der(root.der()).unwrap(),
                leaf: Certificate::from_der(leaf.der()).unwrap(),
                root_key,
                key: SigningKey::from_pkcs8_der(&leaf_key.serialize_der()).unwrap(),
            }
        }
        fn headers(&self, protected_chain: bool) -> (Value, Value) {
            let mut p = vec![
                (1, i(-35)),
                (3, Value::Text("application/rim+cbor".into())),
                (
                    15,
                    m(vec![
                        (1, Value::Text("TEST ONLY CoRIM signer".into())),
                        (4, i(NOW as i64 + 100)),
                        (5, i(NOW as i64 - 10)),
                    ]),
                ),
            ];
            let chain = Value::Array(vec![
                Value::Bytes(self.leaf.to_der().unwrap()),
                Value::Bytes(self.root.to_der().unwrap()),
            ]);
            if protected_chain {
                p.push((33, chain));
                (m(p), m(vec![]))
            } else {
                p.push((
                    34,
                    Value::Array(vec![
                        i(-43),
                        Value::Bytes(Sha384::digest(self.leaf.to_der().unwrap()).to_vec()),
                    ]),
                ));
                (m(p), m(vec![(33, chain)]))
            }
        }
        fn envelope(&self, protected: Value, unprotected: Value, payload: Vec<u8>) -> Vec<u8> {
            let p = encoded(&protected);
            let message = encoded(&Value::Array(vec![
                Value::Text("Signature1".into()),
                Value::Bytes(p.clone()),
                Value::Bytes(vec![]),
                Value::Bytes(payload.clone()),
            ]));
            let signature: Signature = self.key.sign(&message);
            encoded(&Value::Tag(
                18,
                Box::new(Value::Array(vec![
                    Value::Bytes(p),
                    unprotected,
                    Value::Bytes(payload),
                    Value::Bytes(signature.to_bytes().to_vec()),
                ])),
            ))
        }
        fn revocation(&self) -> RevocationEvidence {
            let algorithm = spki::AlgorithmIdentifierOwned {
                oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3"),
                parameters: None,
            };
            let time = |n| {
                Time::GeneralTime(
                    GeneralizedTime::from_unix_duration(Duration::from_secs(n)).unwrap(),
                )
            };
            let tbs = TbsCertList {
                version: X509Version::V2,
                signature: algorithm.clone(),
                issuer: self.root.tbs_certificate.subject.clone(),
                this_update: time(NOW - 10),
                next_update: Some(time(NOW + 100)),
                revoked_certificates: None,
                crl_extensions: None,
            };
            let key = SigningKey::from_pkcs8_der(&self.root_key.serialize_der()).unwrap();
            let signature: Signature = key.sign(&tbs.to_der().unwrap());
            let crl = CertificateList {
                tbs_cert_list: tbs,
                signature_algorithm: algorithm,
                signature: BitString::from_bytes(signature.to_der().as_bytes()).unwrap(),
            };
            RevocationEvidence {
                ocsp_responses: vec![],
                crls: vec![crl.to_der().unwrap()],
            }
        }
    }

    #[test]
    fn original_nvidia_unsigned_comid_examples_preserve_all_supported_claims() {
        for diag in [DRIVER, VBIOS, FSP] {
            let comid = parse_comid(&raw_comid(diag)).unwrap();
            assert!(!comid.references.is_empty());
            assert!(comid
                .references
                .iter()
                .any(|r| r.measurements.iter().any(|m| !m.values.digests.is_empty())));
        }
        let driver = parse_comid(&raw_comid(DRIVER)).unwrap();
        assert_eq!(driver.dependencies.len(), 3);
        assert!(driver.references.iter().any(|r| matches!(
            &r.environment.class.as_ref().unwrap().id,
            Some(Identifier::Oid(_))
        )));
    }

    #[test]
    fn cose_and_corim_authentication_requires_real_signatures_paths_and_revocation() {
        let signer = TestSigner::new();
        for protected_chain in [true, false] {
            let (p, u) = signer.headers(protected_chain);
            let envelope = signer.envelope(p, u, fixture_payload());
            let checked = verify_corim(
                &envelope,
                std::slice::from_ref(&signer.root),
                &signer.revocation(),
                NOW,
            )
            .unwrap();
            assert!(!checked.claims().comids[0].references.is_empty());
            assert!(verify_corim(
                &envelope,
                std::slice::from_ref(&signer.root),
                &RevocationEvidence::default(),
                NOW
            )
            .is_err());
            assert!(verify_corim_signature_and_chain(&envelope, &[], NOW).is_err());
            assert!(verify_corim_signature_and_chain(
                &envelope,
                std::slice::from_ref(&signer.root),
                NOW + 101
            )
            .is_err());
            let mut corrupt = envelope;
            let last = corrupt.len() - 1;
            corrupt[last] ^= 1;
            assert!(verify_corim_signature_and_chain(
                &corrupt,
                std::slice::from_ref(&signer.root),
                NOW
            )
            .is_err());
        }
    }

    #[test]
    fn ambiguous_headers_and_unbound_mutable_chain_are_rejected() {
        let signer = TestSigner::new();
        for mutation in 0..4 {
            let (mut p, u) = signer.headers(false);
            let Value::Map(ref mut entries) = p else {
                unreachable!()
            };
            match mutation {
                0 => entries.retain(|(k, _)| *k != i(34)),
                1 => entries.push((i(1), i(-35))),
                2 => entries.push((i(2), Value::Array(vec![i(99)]))),
                3 => entries.push((i(99), i(0))),
                _ => unreachable!(),
            }
            let envelope = signer.envelope(p, u, fixture_payload());
            assert!(verify_corim_signature_and_chain(
                &envelope,
                std::slice::from_ref(&signer.root),
                NOW
            )
            .is_err());
        }
    }

    #[test]
    fn authenticated_unsupported_claims_fail_without_silent_discard() {
        let signer = TestSigner::new();
        let (p, u) = signer.headers(true);
        let mut payload = decode(&fixture_payload()).unwrap();
        let Value::Tag(_, ref mut body) = payload else {
            unreachable!()
        };
        let Value::Map(ref mut fields) = **body else {
            unreachable!()
        };
        fields.push((i(2), Value::Array(vec![]))); // dependent-rims is not resolved.
        let envelope = signer.envelope(p, u, encoded(&payload));
        let error =
            verify_corim_signature_and_chain(&envelope, std::slice::from_ref(&signer.root), NOW)
                .unwrap_err();
        assert!(format!("{error:#}").contains("unsupported CoRIM/COSE field 2"));
    }

    #[test]
    fn cbor_preflight_rejects_trailing_data_unbounded_depth_and_huge_allocation() {
        let mut trailing = fixture_payload();
        trailing.push(0);
        assert!(decode(&trailing).is_err());
        assert!(decode(&[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).is_err());
        assert!(decode(&[0x9f, 0xff]).is_err());
        let mut nested = vec![0x81; 40];
        nested.push(0);
        assert!(decode(&nested).is_err());
    }
}
