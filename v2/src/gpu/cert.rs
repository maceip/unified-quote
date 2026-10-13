//! Strict certificate path validation for NVIDIA attestation and RIM signing.
//!
//! This implements a deliberately bounded PKIX profile: ordered leaf-first
//! paths, explicitly supplied trust anchors, SHA-256/384/512 signatures and
//! P-256/P-384 or RSA >= 3072-bit keys. Unsupported critical extensions and
//! name/policy constraints are errors, never silently ignored. Path validation
//! alone does not establish revocation status; call `revocation::check_chain`.

use std::collections::HashSet;

use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use der::{asn1::ObjectIdentifier, Decode, Encode, Reader};
use p384::ecdsa::signature::hazmat::PrehashVerifier;
use rsa::{pkcs8::DecodePublicKey, traits::PublicKeyParts};
use sha2::{Digest, Sha256, Sha384, Sha512};
use spki::AlgorithmIdentifierOwned;
use x509_cert::{
    ext::pkix::{
        name::GeneralName, AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage,
        SubjectKeyIdentifier,
    },
    Certificate, Version,
};

const MAX_CHAIN_BYTES: usize = 256 * 1024;
const MAX_CHAIN_CERTS: usize = 12;
const EC_KEY: &str = "1.2.840.10045.2.1";
const P384: &str = "1.3.132.0.34";
const P256: &str = "1.2.840.10045.3.1.7";
const RSA_KEY: &str = "1.2.840.113549.1.1.1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Device,
    Rim,
    OcspResponder,
}

/// A signature/time/policy-validated path, including its configured trust root.
/// Construction is private so untrusted parsed certificates cannot bypass it.
#[derive(Debug, Clone)]
pub struct ValidatedChain {
    certificates: Vec<Certificate>,
}

impl ValidatedChain {
    pub fn leaf(&self) -> &Certificate {
        &self.certificates[0]
    }

    /// Leaf first, pinned root last. The root needs no revocation response.
    pub fn certificates(&self) -> &[Certificate] {
        &self.certificates
    }
}

pub fn pinned_device_roots() -> Result<Vec<Certificate>> {
    parse_certificates(include_bytes!("roots/device-identity.pem"))
}

pub fn pinned_rim_roots() -> Result<Vec<Certificate>> {
    let mut roots = parse_certificates(include_bytes!("roots/rim-signing.pem"))?;
    roots.extend(parse_certificates(include_bytes!("roots/rim-ca001.pem"))?);
    Ok(roots)
}

/// Parse strict PEM blocks or concatenated DER certificates without trusting
/// any of them. Leading/trailing PEM whitespace is accepted, other text is not.
pub fn parse_certificates(bytes: &[u8]) -> Result<Vec<Certificate>> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_CHAIN_BYTES,
        "certificate chain size outside limit"
    );
    let mut certs = Vec::new();
    if bytes.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'-') {
        let mut rest = std::str::from_utf8(bytes)
            .context("PEM is not UTF-8")?
            .trim();
        while !rest.is_empty() {
            rest = rest
                .strip_prefix("-----BEGIN CERTIFICATE-----")
                .context("unexpected text in certificate PEM")?;
            let end = rest
                .find("-----END CERTIFICATE-----")
                .context("unterminated certificate PEM")?;
            let base64: String = rest[..end]
                .chars()
                .filter(|c| !c.is_ascii_whitespace())
                .collect();
            let der = STANDARD
                .decode(base64)
                .context("invalid certificate base64")?;
            certs.push(Certificate::from_der(&der).context("invalid certificate DER")?);
            rest = rest[end + "-----END CERTIFICATE-----".len()..].trim();
            ensure!(certs.len() <= MAX_CHAIN_CERTS, "too many certificates");
        }
    } else {
        let mut reader = der::SliceReader::new(bytes)?;
        while !reader.is_finished() {
            certs.push(
                Certificate::decode(&mut reader).context("invalid concatenated certificate DER")?,
            );
            ensure!(certs.len() <= MAX_CHAIN_CERTS, "too many certificates");
        }
    }
    ensure!(!certs.is_empty(), "empty certificate chain");
    let mut seen = HashSet::new();
    for cert in &certs {
        ensure!(
            seen.insert(cert.to_der()?),
            "duplicate certificate in chain"
        );
    }
    Ok(certs)
}

/// Validate the complete ordered chain at a trusted Unix timestamp. `roots`
/// must come from verifier configuration, never the attestation evidence.
pub fn validate_chain(
    bytes: &[u8],
    roots: &[Certificate],
    now: u64,
    purpose: Purpose,
) -> Result<ValidatedChain> {
    ensure!(!roots.is_empty(), "no pinned trust roots");
    let mut certs = parse_certificates(bytes)?;
    let tail = certs.last().unwrap();
    if !roots.iter().any(|root| root == tail) {
        let root = roots
            .iter()
            .find(|root| {
                tail.tbs_certificate.issuer == root.tbs_certificate.subject
                    && verify_certificate_signature(tail, root).is_ok()
            })
            .context("certificate chain does not terminate at a pinned root")?;
        ensure!(
            certs.len() < MAX_CHAIN_CERTS,
            "certificate path exceeds depth limit"
        );
        certs.push(root.clone());
    }
    ensure!(
        certs.len() >= 2,
        "a trust anchor alone is not an attestation signing chain"
    );
    for (index, cert) in certs.iter().enumerate() {
        check_certificate(cert, now).with_context(|| format!("certificate {index}"))?;
        check_extended_usage(cert, purpose, index == 0)?;
        if index > 0 {
            let (_, bc) = cert
                .tbs_certificate
                .get::<BasicConstraints>()?
                .context("issuer lacks basic constraints")?;
            ensure!(bc.ca, "issuer is not a CA");
            ensure!(
                cert.tbs_certificate.get::<BasicConstraints>()?.unwrap().0,
                "CA basic constraints must be critical"
            );
            ensure!(key_usage(cert)?.key_cert_sign(), "issuer lacks keyCertSign");
            let ca_below = certs[1..index]
                .iter()
                .filter(|c| c.tbs_certificate.subject != c.tbs_certificate.issuer)
                .count();
            if let Some(limit) = bc.path_len_constraint {
                ensure!(
                    ca_below <= limit as usize,
                    "CA path length constraint exceeded"
                );
            }
            verify_certificate_signature(&certs[index - 1], cert)?;
        }
    }
    let leaf = &certs[0];
    ensure!(
        key_usage(leaf)?.digital_signature(),
        "leaf lacks digitalSignature usage"
    );
    if purpose != Purpose::Device {
        if let Some((_, bc)) = leaf.tbs_certificate.get::<BasicConstraints>()? {
            ensure!(!bc.ca, "RIM/OCSP signer must be an end entity");
        }
        ensure!(
            !key_usage(leaf)?.key_cert_sign(),
            "RIM/OCSP leaf cannot sign certificates"
        );
    }
    if purpose != Purpose::OcspResponder {
        let spki = &leaf.tbs_certificate.subject_public_key_info;
        ensure!(
            spki.algorithm.oid.to_string() == EC_KEY && curve(leaf)? == P384,
            "NVIDIA attestation/RIM leaf must use P-384"
        );
    }
    let root = certs.last().unwrap();
    ensure!(
        root.tbs_certificate.issuer == root.tbs_certificate.subject,
        "configured trust root must be self-issued"
    );
    verify_certificate_signature(root, root).context("pinned root self-signature")?;
    Ok(ValidatedChain {
        certificates: certs,
    })
}

pub(crate) fn key_usage(cert: &Certificate) -> Result<KeyUsage> {
    Ok(cert
        .tbs_certificate
        .get::<KeyUsage>()?
        .context("certificate lacks key usage")?
        .1)
}

pub(crate) fn check_certificate(cert: &Certificate, now: u64) -> Result<()> {
    let tbs = &cert.tbs_certificate;
    ensure!(
        tbs.version == Version::V3,
        "only X.509 v3 certificates are supported"
    );
    ensure!(
        tbs.issuer_unique_id.is_none() && tbs.subject_unique_id.is_none(),
        "unique identifiers are outside the supported PKIX profile"
    );
    ensure!(
        now >= tbs.validity.not_before.to_unix_duration().as_secs(),
        "certificate is not yet valid"
    );
    ensure!(
        now <= tbs.validity.not_after.to_unix_duration().as_secs(),
        "certificate has expired"
    );
    ensure!(
        tbs.signature == cert.signature_algorithm,
        "certificate inner/outer signature algorithms differ"
    );
    ensure!(
        !tbs.subject.0.is_empty(),
        "empty certificate subject is unsupported"
    );
    let mut seen = HashSet::new();
    for ext in tbs.extensions.iter().flatten() {
        ensure!(seen.insert(ext.extn_id), "duplicate certificate extension");
        let oid = ext.extn_id.to_string();
        // These constraints must never be ignored, even if incorrectly marked
        // noncritical. Reject rather than pretend to implement their semantics.
        ensure!(
            !matches!(
                oid.as_str(),
                "2.5.29.30" | "2.5.29.33" | "2.5.29.36" | "2.5.29.54"
            ),
            "unsupported name/policy constraints {oid}"
        );
        if ext.critical {
            ensure!(
                matches!(
                    oid.as_str(),
                    "2.5.29.19"
                        | "2.5.29.15"
                        | "2.5.29.37"
                        | "2.5.29.14"
                        | "2.5.29.35"
                        | "1.3.6.1.5.5.7.48.1.5"
                ),
                "unsupported critical certificate extension {oid}"
            );
        }
    }
    // Decode supported constraints even when noncritical, rejecting malformed
    // encodings instead of treating decoding failure as extension absence.
    if let Some((_, bc)) = tbs.get::<BasicConstraints>()? {
        ensure!(
            bc.ca || bc.path_len_constraint.is_none(),
            "path length on non-CA certificate"
        );
    }
    let usage = key_usage(cert)?;
    ensure!(
        !(usage.encipher_only() || usage.decipher_only()) || usage.key_agreement(),
        "encipherOnly/decipherOnly requires keyAgreement"
    );
    tbs.get::<ExtendedKeyUsage>()?;
    tbs.get::<AuthorityKeyIdentifier>()?;
    tbs.get::<SubjectKeyIdentifier>()?;
    let algorithm = &tbs.subject_public_key_info.algorithm;
    match algorithm.oid.to_string().as_str() {
        EC_KEY => match curve(cert)?.as_str() {
            P384 => {
                p384::ecdsa::VerifyingKey::from_sec1_bytes(public_key(cert)?)?;
            }
            P256 => {
                p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key(cert)?)?;
            }
            _ => bail!("unsupported EC curve"),
        },
        RSA_KEY => {
            check_null_or_absent(algorithm)?;
            let key =
                rsa::RsaPublicKey::from_public_key_der(&tbs.subject_public_key_info.to_der()?)?;
            ensure!(
                key.n().bits() >= 3072 && key.n().bits() <= 8192,
                "RSA key outside supported 3072-8192 bit range"
            );
        }
        _ => bail!("unsupported certificate public-key algorithm"),
    }
    Ok(())
}

pub(crate) fn check_extended_usage(cert: &Certificate, purpose: Purpose, leaf: bool) -> Result<()> {
    if let Some(no_check) = cert
        .tbs_certificate
        .extensions
        .iter()
        .flatten()
        .find(|e| e.extn_id.to_string() == "1.3.6.1.5.5.7.48.1.5")
    {
        ensure!(
            purpose == Purpose::OcspResponder && leaf,
            "id-pkix-ocsp-nocheck is only valid for a delegated OCSP signer"
        );
        der::asn1::Null::from_der(no_check.extn_value.as_bytes())
            .context("invalid OCSP no-check extension")?;
    }
    let eku = cert.tbs_certificate.get::<ExtendedKeyUsage>()?;
    if purpose == Purpose::OcspResponder && leaf {
        ensure!(
            eku.as_ref()
                .is_some_and(|(_, v)| v.0.iter().any(|o| o.to_string() == "1.3.6.1.5.5.7.3.9")),
            "delegated responder lacks id-kp-OCSPSigning"
        );
    }
    if let Some((_, eku)) = eku {
        ensure!(!eku.0.is_empty(), "empty extended key usage");
        let purpose_oid = match purpose {
            Purpose::Rim => "1.3.6.1.5.5.7.3.3",
            Purpose::OcspResponder => "1.3.6.1.5.5.7.3.9",
            // There is no generic TLS/code-signing EKU for SPDM attestation.
            Purpose::Device => "2.5.29.37.0",
        };
        ensure!(
            eku.0
                .iter()
                .any(|o| o.to_string() == purpose_oid || o.to_string() == "2.5.29.37.0"),
            "extended key usage excludes requested purpose"
        );
    }
    Ok(())
}

pub(crate) fn verify_certificate_signature(cert: &Certificate, issuer: &Certificate) -> Result<()> {
    ensure!(
        cert.tbs_certificate.issuer == issuer.tbs_certificate.subject,
        "certificate issuer/subject names differ"
    );
    if let Some((_, aki)) = cert.tbs_certificate.get::<AuthorityKeyIdentifier>()? {
        check_authority_key_id(&aki, issuer)?;
    }
    ensure!(
        cert.tbs_certificate.signature == cert.signature_algorithm,
        "certificate inner/outer signature algorithms differ"
    );
    verify_signature(
        issuer,
        &cert.signature_algorithm,
        &cert.tbs_certificate.to_der()?,
        cert.signature
            .as_bytes()
            .context("certificate signature is not byte-aligned")?,
    )
}

pub(crate) fn check_authority_key_id(
    aki: &AuthorityKeyIdentifier,
    issuer: &Certificate,
) -> Result<()> {
    if let Some(key_id) = &aki.key_identifier {
        let (_, ski) = issuer
            .tbs_certificate
            .get::<SubjectKeyIdentifier>()?
            .context("AKI present but issuer lacks SKI")?;
        ensure!(key_id == &ski.0, "authority key identifier mismatch");
    }
    ensure!(
        aki.authority_cert_issuer.is_some() == aki.authority_cert_serial_number.is_some(),
        "authority issuer and serial must occur together"
    );
    if let Some(serial) = &aki.authority_cert_serial_number {
        ensure!(
            serial == &issuer.tbs_certificate.serial_number,
            "authority serial mismatch"
        );
    }
    if let Some(names) = &aki.authority_cert_issuer {
        ensure!(names.iter().any(|name| matches!(name, GeneralName::DirectoryName(n) if n == &issuer.tbs_certificate.issuer)), "authority issuer name mismatch");
    }
    Ok(())
}

fn curve(cert: &Certificate) -> Result<String> {
    let params = cert
        .tbs_certificate
        .subject_public_key_info
        .algorithm
        .parameters
        .as_ref()
        .context("missing named EC curve")?;
    Ok(params.decode_as::<ObjectIdentifier>()?.to_string())
}

pub(crate) fn public_key(cert: &Certificate) -> Result<&[u8]> {
    cert.tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .context("public key is not byte-aligned")
}

pub(crate) fn check_null_or_absent(algorithm: &AlgorithmIdentifierOwned) -> Result<()> {
    if let Some(params) = &algorithm.parameters {
        params
            .decode_as::<der::asn1::Null>()
            .context("algorithm parameters must be absent or NULL")?;
    }
    Ok(())
}

/// Verify an X.509/OCSP/CRL signature with explicit algorithm allowlisting.
/// SHA-1 is never accepted for a signature (OCSP identifier hashes are separate).
pub fn verify_signature(
    issuer: &Certificate,
    algorithm: &AlgorithmIdentifierOwned,
    signed: &[u8],
    signature: &[u8],
) -> Result<()> {
    let oid = algorithm.oid.to_string();
    let (digest, ecdsa) = match oid.as_str() {
        "1.2.840.10045.4.3.2" => (Sha256::digest(signed).to_vec(), true),
        "1.2.840.10045.4.3.3" => (Sha384::digest(signed).to_vec(), true),
        "1.2.840.10045.4.3.4" => (Sha512::digest(signed).to_vec(), true),
        "1.2.840.113549.1.1.11" => (Sha256::digest(signed).to_vec(), false),
        "1.2.840.113549.1.1.12" => (Sha384::digest(signed).to_vec(), false),
        "1.2.840.113549.1.1.13" => (Sha512::digest(signed).to_vec(), false),
        _ => bail!("unsupported signature algorithm {oid}"),
    };
    let key_algorithm = issuer
        .tbs_certificate
        .subject_public_key_info
        .algorithm
        .oid
        .to_string();
    if ecdsa {
        ensure!(
            algorithm.parameters.is_none(),
            "ECDSA signature parameters must be absent"
        );
        ensure!(key_algorithm == EC_KEY, "ECDSA signature requires EC key");
        match curve(issuer)?.as_str() {
            P384 => p384::ecdsa::VerifyingKey::from_sec1_bytes(public_key(issuer)?)?
                .verify_prehash(&digest, &p384::ecdsa::Signature::from_der(signature)?)?,
            P256 => p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key(issuer)?)?
                .verify_prehash(&digest, &p256::ecdsa::Signature::from_der(signature)?)?,
            _ => bail!("unsupported signature curve"),
        }
    } else {
        ensure!(key_algorithm == RSA_KEY, "RSA signature requires RSA key");
        check_null_or_absent(algorithm)?;
        let key = rsa::RsaPublicKey::from_public_key_der(
            &issuer.tbs_certificate.subject_public_key_info.to_der()?,
        )?;
        ensure!(
            key.n().bits() >= 3072 && key.n().bits() <= 8192,
            "RSA key outside supported 3072-8192 bit range"
        );
        let padding = match digest.len() {
            32 => rsa::Pkcs1v15Sign::new::<Sha256>(),
            48 => rsa::Pkcs1v15Sign::new::<Sha384>(),
            64 => rsa::Pkcs1v15Sign::new::<Sha512>(),
            _ => unreachable!(),
        };
        key.verify(padding, &digest, signature)?;
    }
    Ok(())
}
