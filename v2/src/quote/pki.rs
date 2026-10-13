//! Bounded CPU PKIX validation shared by quote and vendor collateral appraisal.
//! Signature/path checking does not establish CPU TCB acceptability or revocation.
use std::collections::HashSet;

use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use der::{asn1::ObjectIdentifier, Decode, Encode};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
#[cfg(feature = "sev-snp")]
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

use x509_cert::{
    crl::CertificateList,
    ext::{
        pkix::{CrlNumber, CrlReason},
        Extensions,
    },
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Curve {
    P256,
    P384,
    /// AMD KDS certificate profile omits KeyUsage on endorsement leaves.
    AmdEndorsement,
}

pub(crate) fn validate_chain(
    leaf_first: &[Vec<u8>],
    pinned_sha256: &str,
    now: u64,
    leaf_curve: Curve,
) -> Result<Vec<Certificate>> {
    ensure!(
        (2..=MAX_CHAIN_CERTS).contains(&leaf_first.len()),
        "CPU certificate path depth outside limit"
    );
    let mut total = 0usize;
    let mut seen = HashSet::new();
    let mut certs = Vec::new();
    for bytes in leaf_first {
        total = total
            .checked_add(bytes.len())
            .context("certificate size overflow")?;
        ensure!(
            !bytes.is_empty() && total <= MAX_CHAIN_BYTES,
            "CPU certificate path size outside limit"
        );
        ensure!(seen.insert(bytes), "duplicate CPU certificate");
        certs.push(Certificate::from_der(bytes)?);
    }
    ensure!(
        hex::encode(Sha256::digest(leaf_first.last().unwrap())) == pinned_sha256,
        "CPU certificate root fingerprint mismatch"
    );
    for (index, cert) in certs.iter().enumerate() {
        check_certificate(cert, now).with_context(|| format!("CPU certificate {index}"))?;
        if index == 0 {
            match cert.tbs_certificate.get::<KeyUsage>()? {
                Some((_, usage)) => ensure!(
                    usage.digital_signature() && !usage.key_cert_sign(),
                    "CPU leaf must permit digitalSignature and not keyCertSign"
                ),
                None => ensure!(
                    leaf_curve == Curve::AmdEndorsement,
                    "CPU signing leaf lacks key usage"
                ),
            }
            if let Some((_, bc)) = cert.tbs_certificate.get::<BasicConstraints>()? {
                ensure!(!bc.ca, "CPU signing leaf must not be a CA");
            }
            ensure!(
                cert.tbs_certificate
                    .subject_public_key_info
                    .algorithm
                    .oid
                    .to_string()
                    == EC_KEY,
                "CPU leaf must use EC"
            );
            let expected = match leaf_curve {
                Curve::P256 => P256,
                Curve::P384 | Curve::AmdEndorsement => P384,
            };
            ensure!(curve(cert)? == expected, "CPU signing leaf curve mismatch");
        } else {
            let (critical, bc) = cert
                .tbs_certificate
                .get::<BasicConstraints>()?
                .context("CPU issuer lacks basicConstraints")?;
            ensure!(
                critical && bc.ca && key_usage(cert)?.key_cert_sign(),
                "CPU issuer lacks critical CA/keyCertSign authorization"
            );
            if let Some(limit) = bc.path_len_constraint {
                let below = certs[1..index]
                    .iter()
                    .filter(|c| c.tbs_certificate.issuer != c.tbs_certificate.subject)
                    .count();
                ensure!(below <= limit as usize, "CPU CA path length exceeded");
            }
            verify_certificate_signature(&certs[index - 1], cert)?;
        }
    }
    let root = certs.last().unwrap();
    ensure!(
        root.tbs_certificate.issuer == root.tbs_certificate.subject,
        "CPU pinned root is not self-issued"
    );
    verify_certificate_signature(root, root)?;
    Ok(certs)
}

pub(crate) fn parse_pem_chain(bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_CHAIN_BYTES,
        "CPU PEM size outside limit"
    );
    // Intel includes a single C-string terminator in some certification blobs.
    let bytes = bytes.strip_suffix(&[0]).unwrap_or(bytes);
    let mut rest = std::str::from_utf8(bytes)?.trim();
    let mut certs = Vec::new();
    while !rest.is_empty() {
        rest = rest
            .strip_prefix("-----BEGIN CERTIFICATE-----")
            .context("unexpected CPU PEM text")?;
        let end = rest
            .find("-----END CERTIFICATE-----")
            .context("unterminated CPU PEM certificate")?;
        let b64: String = rest[..end]
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        let der = STANDARD.decode(b64)?;
        Certificate::from_der(&der)?;
        certs.push(der);
        ensure!(
            certs.len() <= MAX_CHAIN_CERTS,
            "too many CPU PEM certificates"
        );
        rest = rest[end + "-----END CERTIFICATE-----".len()..].trim();
    }
    ensure!(!certs.is_empty(), "empty CPU certificate path");
    Ok(certs)
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
                    "2.5.29.19" | "2.5.29.15" | "2.5.29.37" | "2.5.29.14" | "2.5.29.35"
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
    if let Some((_, usage)) = tbs.get::<KeyUsage>()? {
        ensure!(
            !(usage.encipher_only() || usage.decipher_only()) || usage.key_agreement(),
            "encipherOnly/decipherOnly requires keyAgreement"
        );
    }
    if let Some((_, eku)) = tbs.get::<ExtendedKeyUsage>()? {
        ensure!(!eku.0.is_empty(), "empty extended key usage");
        // Vendor attestation keys do not use TLS/code-signing EKUs. A
        // restrictive EKU we cannot interpret must not silently grant use.
        ensure!(
            eku.0.iter().any(|oid| oid.to_string() == "2.5.29.37.0"),
            "CPU certificate EKU excludes unrestricted attestation use"
        );
    }
    tbs.get::<AuthorityKeyIdentifier>()?;
    tbs.get::<SubjectKeyIdentifier>()?;
    let algorithm = &tbs.subject_public_key_info.algorithm;
    match algorithm.oid.to_string().as_str() {
        EC_KEY => match curve(cert)?.as_str() {
            #[cfg(any(feature = "nitro", feature = "sev-snp"))]
            P384 => {
                p384::ecdsa::VerifyingKey::from_sec1_bytes(public_key(cert)?)?;
            }
            P256 => {
                p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key(cert)?)?;
            }
            _ => bail!("unsupported EC curve"),
        },
        #[cfg(feature = "sev-snp")]
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

pub(crate) fn verify_signature(
    issuer: &Certificate,
    algorithm: &AlgorithmIdentifierOwned,
    signed: &[u8],
    signature: &[u8],
) -> Result<()> {
    let oid = algorithm.oid.to_string();
    #[cfg(feature = "sev-snp")]
    if oid == "1.2.840.113549.1.1.10" {
        ensure!(
            issuer
                .tbs_certificate
                .subject_public_key_info
                .algorithm
                .oid
                .to_string()
                == RSA_KEY,
            "RSA-PSS requires RSA key"
        );
        let encoded = algorithm
            .parameters
            .as_ref()
            .context("missing RSA-PSS parameters")?
            .to_der()?;
        let params = rsa::pkcs1::RsaPssParams::from_der(&encoded)?;
        ensure!(
            params.hash.oid.to_string() == "2.16.840.1.101.3.4.2.2"
                && params.mask_gen.oid.to_string() == "1.2.840.113549.1.1.8"
                && params.salt_len == 48,
            "unsupported AMD RSA-PSS parameters"
        );
        let mgf = params
            .mask_gen
            .parameters
            .as_ref()
            .context("missing RSA-PSS MGF hash")?;
        ensure!(mgf.oid == params.hash.oid, "RSA-PSS MGF/hash mismatch");
        for p in [params.hash.parameters, mgf.parameters]
            .into_iter()
            .flatten()
        {
            p.decode_as::<der::asn1::Null>()?;
        }
        let key = rsa::RsaPublicKey::from_public_key_der(
            &issuer.tbs_certificate.subject_public_key_info.to_der()?,
        )?;
        ensure!(
            (3072..=8192).contains(&key.n().bits()),
            "RSA key outside supported range"
        );
        key.verify(
            rsa::Pss::new_with_salt::<Sha384>(48),
            &Sha384::digest(signed),
            signature,
        )?;
        return Ok(());
    }
    let digest = match oid.as_str() {
        "1.2.840.10045.4.3.2" => Sha256::digest(signed).to_vec(),
        "1.2.840.10045.4.3.3" => Sha384::digest(signed).to_vec(),
        "1.2.840.10045.4.3.4" => Sha512::digest(signed).to_vec(),
        _ => bail!("unsupported CPU signature algorithm {oid}"),
    };
    ensure!(
        algorithm.parameters.is_none(),
        "ECDSA signature parameters must be absent"
    );
    ensure!(
        issuer
            .tbs_certificate
            .subject_public_key_info
            .algorithm
            .oid
            .to_string()
            == EC_KEY,
        "ECDSA signature requires EC key"
    );
    match curve(issuer)?.as_str() {
        P256 => p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key(issuer)?)?
            .verify_prehash(&digest, &p256::ecdsa::Signature::from_der(signature)?)?,
        #[cfg(any(feature = "nitro", feature = "sev-snp"))]
        P384 => p384::ecdsa::VerifyingKey::from_sec1_bytes(public_key(issuer)?)?
            .verify_prehash(&digest, &p384::ecdsa::Signature::from_der(signature)?)?,
        _ => bail!("unsupported CPU signature curve"),
    }
    Ok(())
}
fn check_dates(this: u64, next: u64, now: u64) -> Result<()> {
    ensure!(this < next, "revocation nextUpdate must follow thisUpdate");
    ensure!(this <= now, "revocation thisUpdate is in the future");
    ensure!(now < next, "revocation evidence has expired");
    Ok(())
}

fn check_extensions(extensions: Option<&Extensions>, allowed_critical: &[&str]) -> Result<()> {
    let mut seen = HashSet::new();
    for ext in extensions.into_iter().flatten() {
        ensure!(seen.insert(ext.extn_id), "duplicate revocation extension");
        ensure!(
            !ext.critical || allowed_critical.contains(&ext.extn_id.to_string().as_str()),
            "unsupported critical revocation extension {}",
            ext.extn_id
        );
    }
    Ok(())
}

pub(crate) fn check_crl(
    crl_der: &[u8],
    subject: &Certificate,
    issuer: &Certificate,
    now: u64,
) -> Result<()> {
    ensure!(
        !crl_der.is_empty() && crl_der.len() <= 4 * 1024 * 1024,
        "CPU CRL size outside limit"
    );
    let crl = CertificateList::from_der(crl_der)?;
    let list = &crl.tbs_cert_list;
    ensure!(
        list.version == Version::V2,
        "only X.509 v2 CRLs are supported"
    );
    ensure!(
        list.issuer == issuer.tbs_certificate.subject
            && subject.tbs_certificate.issuer == issuer.tbs_certificate.subject,
        "CRL issuer mismatch"
    );
    ensure!(key_usage(issuer)?.crl_sign(), "CRL issuer lacks cRLSign");
    ensure!(
        list.signature == crl.signature_algorithm,
        "CRL inner/outer signature algorithms differ"
    );
    check_dates(
        list.this_update.to_unix_duration().as_secs(),
        list.next_update
            .context("CRL nextUpdate is required")?
            .to_unix_duration()
            .as_secs(),
        now,
    )?;
    check_extensions(list.crl_extensions.as_ref(), &["2.5.29.35", "2.5.29.20"])?;
    for ext in list.crl_extensions.iter().flatten() {
        match ext.extn_id.to_string().as_str() {
            "2.5.29.35" => check_authority_key_id(
                &AuthorityKeyIdentifier::from_der(ext.extn_value.as_bytes())?,
                issuer,
            )?,
            "2.5.29.20" => {
                CrlNumber::from_der(ext.extn_value.as_bytes())?;
            }
            "2.5.29.27" | "2.5.29.28" | "2.5.29.46" => {
                bail!("delta, scoped, indirect or delta-advertising CRLs are unsupported")
            }
            _ => bail!("unsupported CRL extension {}", ext.extn_id),
        }
    }
    verify_signature(
        issuer,
        &crl.signature_algorithm,
        &list.to_der()?,
        crl.signature
            .as_bytes()
            .context("CRL signature is not byte-aligned")?,
    )?;
    let mut serials = HashSet::new();
    for revoked in list.revoked_certificates.iter().flatten() {
        ensure!(
            serials.insert(revoked.serial_number.as_bytes().to_vec()),
            "duplicate revoked serial in CRL"
        );
        check_extensions(
            revoked.crl_entry_extensions.as_ref(),
            &["2.5.29.21", "2.5.29.24"],
        )?;
        for ext in revoked.crl_entry_extensions.iter().flatten() {
            match ext.extn_id.to_string().as_str() {
                "2.5.29.21" => {
                    ensure!(
                        CrlReason::from_der(ext.extn_value.as_bytes())? != CrlReason::RemoveFromCRL,
                        "removeFromCRL is only valid in delta CRLs"
                    );
                }
                "2.5.29.24" => {
                    der::asn1::GeneralizedTime::from_der(ext.extn_value.as_bytes())?;
                }
                // In particular, DICE-TCB revocation may not be reduced to a
                // serial-number-only comparison even when marked noncritical.
                _ => bail!("unsupported CRL entry extension {}", ext.extn_id),
            }
        }
        if revoked.serial_number == subject.tbs_certificate.serial_number {
            bail!("certificate is revoked by CRL");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::asn1::{BitString, GeneralizedTime, OctetString};
    use p256::{
        ecdsa::{signature::Signer, Signature, SigningKey},
        pkcs8::DecodePrivateKey,
    };
    use rcgen::{CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
    use std::time::Duration;
    use x509_cert::{
        crl::{RevokedCert, TbsCertList},
        ext::Extension,
        time::Time,
    };
    const NOW: u64 = 1_791_849_600;
    fn params(name: &str, ca: bool) -> CertificateParams {
        let mut p = CertificateParams::default();
        p.distinguished_name.push(DnType::CommonName, name);
        p.is_ca = if ca {
            IsCa::Ca(rcgen::BasicConstraints::Unconstrained)
        } else {
            IsCa::ExplicitNoCa
        };
        p.key_usages = if ca {
            vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign]
        } else {
            vec![KeyUsagePurpose::DigitalSignature]
        };
        p
    }
    fn sign(cert: &mut Certificate, key: &KeyPair) {
        let key = SigningKey::from_pkcs8_der(&key.serialize_der()).unwrap();
        let sig: Signature = key.sign(&cert.tbs_certificate.to_der().unwrap());
        cert.signature = BitString::from_bytes(sig.to_der().as_bytes()).unwrap();
    }
    fn at(sec: u64) -> Time {
        Time::GeneralTime(GeneralizedTime::from_unix_duration(Duration::from_secs(sec)).unwrap())
    }
    struct Pki {
        chain: Vec<Certificate>,
        keys: Vec<KeyPair>,
    }
    impl Pki {
        fn new() -> Self {
            let root_key = KeyPair::generate().unwrap();
            let root = params("TEST ONLY CPU ROOT", true)
                .self_signed(&root_key)
                .unwrap();
            let ca_key = KeyPair::generate().unwrap();
            let ca = params("TEST ONLY CPU CA", true)
                .signed_by(&ca_key, &root, &root_key)
                .unwrap();
            let leaf_key = KeyPair::generate().unwrap();
            let leaf = params("TEST ONLY CPU LEAF", false)
                .signed_by(&leaf_key, &ca, &ca_key)
                .unwrap();
            Self {
                chain: vec![
                    Certificate::from_der(leaf.der()).unwrap(),
                    Certificate::from_der(ca.der()).unwrap(),
                    Certificate::from_der(root.der()).unwrap(),
                ],
                keys: vec![leaf_key, ca_key, root_key],
            }
        }
        fn check(&self) -> Result<Vec<Certificate>> {
            let ders = self
                .chain
                .iter()
                .map(|c| c.to_der().unwrap())
                .collect::<Vec<_>>();
            validate_chain(
                &ders,
                &hex::encode(Sha256::digest(ders.last().unwrap())),
                NOW,
                Curve::P256,
            )
        }
        fn resign(&mut self, i: usize) {
            sign(&mut self.chain[i], &self.keys[(i + 1).min(2)]);
        }
        fn extension(&mut self, i: usize, oid: &str, value: Vec<u8>) {
            let ext = self.chain[i]
                .tbs_certificate
                .extensions
                .as_mut()
                .unwrap()
                .iter_mut()
                .find(|e| e.extn_id.to_string() == oid)
                .unwrap();
            ext.extn_value = OctetString::new(value).unwrap();
            self.resign(i);
        }
        fn crl(&self, revoked: bool) -> CertificateList {
            let alg = AlgorithmIdentifierOwned {
                oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
                parameters: None,
            };
            let tbs = TbsCertList {
                version: Version::V2,
                signature: alg.clone(),
                issuer: self.chain[1].tbs_certificate.subject.clone(),
                this_update: at(NOW - 60),
                next_update: Some(at(NOW + 60)),
                crl_extensions: None,
                revoked_certificates: if revoked {
                    Some(vec![RevokedCert {
                        serial_number: self.chain[0].tbs_certificate.serial_number.clone(),
                        revocation_date: at(NOW - 120),
                        crl_entry_extensions: None,
                    }])
                } else {
                    None
                },
            };
            let key = SigningKey::from_pkcs8_der(&self.keys[1].serialize_der()).unwrap();
            let sig: Signature = key.sign(&tbs.to_der().unwrap());
            CertificateList {
                tbs_cert_list: tbs,
                signature_algorithm: alg,
                signature: BitString::from_bytes(sig.to_der().as_bytes()).unwrap(),
            }
        }
    }
    #[test]
    fn signed_cpu_path_enforces_critical_ca_key_usage_and_path_length() {
        let mut p = Pki::new();
        p.check().unwrap();
        p.extension(
            1,
            "2.5.29.19",
            BasicConstraints {
                ca: false,
                path_len_constraint: None,
            }
            .to_der()
            .unwrap(),
        );
        assert!(p
            .check()
            .unwrap_err()
            .to_string()
            .contains("CA/keyCertSign"));
        let mut p = Pki::new();
        p.extension(
            2,
            "2.5.29.19",
            BasicConstraints {
                ca: true,
                path_len_constraint: Some(0),
            }
            .to_der()
            .unwrap(),
        );
        assert!(p.check().unwrap_err().to_string().contains("path length"));
        let mut p = Pki::new();
        p.extension(0, "2.5.29.15", vec![3, 2, 5, 0x20]); // keyEncipherment only
        assert!(p
            .check()
            .unwrap_err()
            .to_string()
            .contains("digitalSignature"));
    }
    #[test]
    fn signed_cpu_path_enforces_time_names_critical_extensions_and_root_pin() {
        let mut p = Pki::new();
        p.chain[0].tbs_certificate.validity.not_after = at(NOW - 1);
        p.resign(0);
        assert!(format!("{:#}", p.check().unwrap_err()).contains("expired"));
        let mut p = Pki::new();
        p.chain[1].tbs_certificate.validity.not_before = at(NOW + 1);
        p.resign(1);
        assert!(format!("{:#}", p.check().unwrap_err()).contains("not yet valid"));
        let mut p = Pki::new();
        p.chain[0].tbs_certificate.issuer = p.chain[2].tbs_certificate.subject.clone();
        p.resign(0);
        assert!(p.check().unwrap_err().to_string().contains("names differ"));
        let mut p = Pki::new();
        p.chain[0]
            .tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .push(Extension {
                extn_id: ObjectIdentifier::new_unwrap("1.2.3.4.5"),
                critical: true,
                extn_value: OctetString::new(vec![5, 0]).unwrap(),
            });
        p.resign(0);
        assert!(format!("{:#}", p.check().unwrap_err()).contains("unsupported critical"));
        let p = Pki::new();
        let ders = p
            .chain
            .iter()
            .map(|c| c.to_der().unwrap())
            .collect::<Vec<_>>();
        assert!(validate_chain(&ders, &"00".repeat(32), NOW, Curve::P256).is_err());
    }
    #[test]
    fn signed_cpu_crl_requires_fresh_authentic_direct_status() {
        let p = Pki::new();
        p.check().unwrap();
        let crl = p.crl(false).to_der().unwrap();
        check_crl(&crl, &p.chain[0], &p.chain[1], NOW).unwrap();
        assert!(check_crl(&crl, &p.chain[0], &p.chain[1], NOW + 60).is_err());
        assert!(check_crl(&crl, &p.chain[0], &p.chain[1], NOW - 61).is_err());
        assert!(check_crl(
            &p.crl(true).to_der().unwrap(),
            &p.chain[0],
            &p.chain[1],
            NOW
        )
        .is_err());
        let mut bad = crl;
        *bad.last_mut().unwrap() ^= 1;
        assert!(check_crl(&bad, &p.chain[0], &p.chain[1], NOW).is_err());
        let mut missing_next = p.crl(false);
        missing_next.tbs_cert_list.next_update = None;
        let key = SigningKey::from_pkcs8_der(&p.keys[1].serialize_der()).unwrap();
        let sig: Signature = key.sign(&missing_next.tbs_cert_list.to_der().unwrap());
        missing_next.signature = BitString::from_bytes(sig.to_der().as_bytes()).unwrap();
        assert!(check_crl(
            &missing_next.to_der().unwrap(),
            &p.chain[0],
            &p.chain[1],
            NOW
        )
        .unwrap_err()
        .to_string()
        .contains("nextUpdate"));
    }
    #[test]
    fn pem_parser_rejects_extra_text_malformed_blocks_and_duplicate_path_certs() {
        let p = Pki::new();
        let ders = p
            .chain
            .iter()
            .map(|c| c.to_der().unwrap())
            .collect::<Vec<_>>();
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
            STANDARD.encode(&ders[0])
        );
        assert_eq!(parse_pem_chain(pem.as_bytes()).unwrap().len(), 1);
        assert!(parse_pem_chain(format!("{pem}garbage").as_bytes()).is_err());
        assert!(parse_pem_chain(b"-----BEGIN CERTIFICATE-----!-----END CERTIFICATE-----").is_err());
        let root_pin = hex::encode(Sha256::digest(&ders[2]));
        assert!(validate_chain(
            &[
                ders[0].clone(),
                ders[1].clone(),
                ders[1].clone(),
                ders[2].clone()
            ],
            &root_pin,
            NOW,
            Curve::P256
        )
        .is_err());
    }
}
