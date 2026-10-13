//! Authenticated, fail-closed OCSP/CRL checking and a revalidated evidence cache.
//!
//! Every non-root certificate requires a current signed status. This includes
//! device alias certificates: missing status is not treated as an exemption.
//! Only complete, direct-issuer CRLs are accepted. Unsupported delta, indirect,
//! partitioned or DICE-TCB CRLs fail explicitly. The network client uses only
//! verifier-configured HTTPS endpoints, never evidence-controlled AIA URLs.

use std::{
    collections::{BTreeMap, HashSet},
    io::Read,
    time::Duration,
};

use anyhow::{bail, ensure, Context, Result};
use der::{
    asn1::{ObjectIdentifier, OctetString},
    Decode, Encode,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use spki::AlgorithmIdentifierOwned;
use x509_cert::{
    crl::CertificateList,
    ext::{
        pkix::{AuthorityKeyIdentifier, BasicConstraints, CrlNumber, CrlReason},
        Extension, Extensions,
    },
    Certificate, Version,
};
use x509_ocsp::{
    BasicOcspResponse, CertId, CertStatus, OcspRequest, OcspResponse, OcspResponseStatus, Request,
    ResponderId, TbsRequest,
};

use super::cert::{self, Purpose, ValidatedChain};

const MAX_OBJECT_BYTES: usize = 4 * 1024 * 1024;
const MAX_EVIDENCE_BYTES: usize = 32 * 1024 * 1024;
const MAX_OBJECTS: usize = 128;
const OCSP_BASIC: &str = "1.3.6.1.5.5.7.48.1.1";
const OCSP_NONCE: &str = "1.3.6.1.5.5.7.48.1.2";
const OCSP_NOCHECK: &str = "1.3.6.1.5.5.7.48.1.5";

/// Original DER OCSPResponse and CertificateList objects. JSON/container
/// metadata is never accepted as a substitute for their signed contents.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationEvidence {
    #[serde(default)]
    pub ocsp_responses: Vec<Vec<u8>>,
    #[serde(default)]
    pub crls: Vec<Vec<u8>>,
}

impl RevocationEvidence {
    fn validate_limits(&self) -> Result<()> {
        ensure!(
            self.ocsp_responses.len() + self.crls.len() <= MAX_OBJECTS,
            "too many revocation objects"
        );
        let mut total = 0usize;
        for bytes in self.ocsp_responses.iter().chain(&self.crls) {
            ensure!(
                !bytes.is_empty() && bytes.len() <= MAX_OBJECT_BYTES,
                "revocation object size outside limit"
            );
            total = total
                .checked_add(bytes.len())
                .context("revocation size overflow")?;
        }
        ensure!(
            total <= MAX_EVIDENCE_BYTES,
            "revocation evidence exceeds size limit"
        );
        Ok(())
    }
}

/// Cache raw signed objects, never a reusable `good` verdict. A cache read
/// rechecks signatures, authorization, validity and current status every time.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationCache {
    entries: BTreeMap<String, RevocationEvidence>,
}

impl RevocationCache {
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_EVIDENCE_BYTES * 4,
            "revocation cache exceeds JSON limit"
        );
        let cache: Self = serde_json::from_slice(bytes)?;
        ensure!(
            cache.entries.len() <= MAX_OBJECTS,
            "too many revocation cache entries"
        );
        for evidence in cache.entries.values() {
            evidence.validate_limits()?;
        }
        ensure!(
            cache.entries.values().map(evidence_size).sum::<usize>() <= MAX_EVIDENCE_BYTES,
            "combined revocation cache exceeds size limit"
        );
        Ok(cache)
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    pub fn insert(
        &mut self,
        chain: &ValidatedChain,
        evidence: RevocationEvidence,
        now: u64,
    ) -> Result<()> {
        check_chain(chain, &evidence, now)?;
        let key = cache_key(chain)?;
        ensure!(
            self.entries.contains_key(&key) || self.entries.len() < MAX_OBJECTS,
            "revocation cache is full"
        );
        let retained: usize = self
            .entries
            .iter()
            .filter(|(k, _)| *k != &key)
            .map(|(_, v)| evidence_size(v))
            .sum();
        ensure!(
            retained + evidence_size(&evidence) <= MAX_EVIDENCE_BYTES,
            "combined revocation cache exceeds size limit"
        );
        self.entries.insert(key, evidence);
        Ok(())
    }

    pub fn checked_evidence(
        &self,
        chain: &ValidatedChain,
        now: u64,
    ) -> Result<&RevocationEvidence> {
        let evidence = self
            .entries
            .get(&cache_key(chain)?)
            .context("revocation evidence is not cached")?;
        check_chain(chain, evidence, now)?;
        Ok(evidence)
    }
}

fn evidence_size(evidence: &RevocationEvidence) -> usize {
    evidence
        .ocsp_responses
        .iter()
        .chain(&evidence.crls)
        .map(Vec::len)
        .sum()
}

fn cache_key(chain: &ValidatedChain) -> Result<String> {
    let mut hash = Sha384::new();
    hash.update(b"unified-quote/revocation-chain/v1\0");
    for certificate in chain.certificates() {
        let der = certificate.to_der()?;
        hash.update((der.len() as u64).to_be_bytes());
        hash.update(der);
    }
    Ok(hex::encode(hash.finalize()))
}

/// Require authenticated current `good` status for every non-root certificate.
/// Caller must provide trusted wall-clock time; an evidence timestamp is not
/// a substitute. Conflicting revoked/unknown or stale matching statuses fail.
pub fn check_chain(chain: &ValidatedChain, evidence: &RevocationEvidence, now: u64) -> Result<()> {
    evidence.validate_limits()?;
    let responses = evidence
        .ocsp_responses
        .iter()
        .map(|raw| parse_ocsp(raw))
        .collect::<Result<Vec<_>>>()?;
    let crls = evidence
        .crls
        .iter()
        .map(|raw| CertificateList::from_der(raw).context("invalid CRL DER"))
        .collect::<Result<Vec<_>>>()?;
    for certificate in chain.certificates() {
        cert::check_certificate(certificate, now)?;
    }
    for (index, pair) in chain.certificates().windows(2).enumerate() {
        let subject = &pair[0];
        let issuer = &pair[1];
        let mut covered = false;
        for response in &responses {
            if response
                .tbs_response_data
                .responses
                .iter()
                .any(|single| cert_id_matches(&single.cert_id, subject, issuer).unwrap_or(false))
            {
                check_ocsp(response, subject, issuer, &crls, now, None)
                    .with_context(|| format!("certificate {index} OCSP"))?;
                covered = true;
            }
        }
        for crl in &crls {
            if crl.tbs_cert_list.issuer == issuer.tbs_certificate.subject {
                check_crl(crl, subject, issuer, now)
                    .with_context(|| format!("certificate {index} CRL"))?;
                covered = true;
            }
        }
        ensure!(
            covered,
            "missing authenticated revocation status for certificate {index} (serial {})",
            hex::encode(subject.tbs_certificate.serial_number.as_bytes())
        );
    }
    Ok(())
}

fn parse_ocsp(raw: &[u8]) -> Result<BasicOcspResponse> {
    ensure!(
        raw.len() <= MAX_OBJECT_BYTES,
        "OCSP response exceeds size limit"
    );
    let response = OcspResponse::from_der(raw).context("invalid OCSPResponse DER")?;
    ensure!(
        response.response_status == OcspResponseStatus::Successful,
        "OCSP responder did not return success"
    );
    let bytes = response
        .response_bytes
        .context("successful OCSP response has no body")?;
    ensure!(
        bytes.response_type.to_string() == OCSP_BASIC,
        "unsupported OCSP response type"
    );
    Ok(BasicOcspResponse::from_der(bytes.response.as_bytes())?)
}

fn identifier_digest(algorithm: &AlgorithmIdentifierOwned, bytes: &[u8]) -> Result<Vec<u8>> {
    cert::check_null_or_absent(algorithm)?;
    Ok(match algorithm.oid.to_string().as_str() {
        // RFC 6960 CertID hashes only: never accepted as signature algorithms.
        "1.3.14.3.2.26" => Sha1::digest(bytes).to_vec(),
        "2.16.840.1.101.3.4.2.1" => Sha256::digest(bytes).to_vec(),
        "2.16.840.1.101.3.4.2.2" => Sha384::digest(bytes).to_vec(),
        "2.16.840.1.101.3.4.2.3" => Sha512::digest(bytes).to_vec(),
        _ => bail!("unsupported OCSP CertID hash algorithm"),
    })
}

fn cert_id_matches(id: &CertId, subject: &Certificate, issuer: &Certificate) -> Result<bool> {
    if id.serial_number != subject.tbs_certificate.serial_number {
        return Ok(false);
    }
    Ok(id.issuer_name_hash.as_bytes()
        == identifier_digest(
            &id.hash_algorithm,
            &issuer.tbs_certificate.subject.to_der()?,
        )?
        && id.issuer_key_hash.as_bytes()
            == identifier_digest(&id.hash_algorithm, cert::public_key(issuer)?)?)
}

fn responder_matches(id: &ResponderId, certificate: &Certificate) -> Result<bool> {
    Ok(match id {
        ResponderId::ByName(name) => name == &certificate.tbs_certificate.subject,
        ResponderId::ByKey(hash) => {
            hash.as_bytes() == Sha1::digest(cert::public_key(certificate)?).as_slice()
        }
    })
}

fn check_ocsp(
    response: &BasicOcspResponse,
    subject: &Certificate,
    issuer: &Certificate,
    crls: &[CertificateList],
    now: u64,
    nonce: Option<&[u8]>,
) -> Result<()> {
    let data = &response.tbs_response_data;
    ensure!(
        data.version == x509_ocsp::Version::V1,
        "unsupported OCSP version"
    );
    ensure!(
        !data.responses.is_empty() && data.responses.len() <= MAX_OBJECTS,
        "OCSP single response count outside limit"
    );
    check_extensions(data.response_extensions.as_ref(), &[OCSP_NONCE])?;
    if let Some(expected) = nonce {
        let ext = data
            .response_extensions
            .iter()
            .flatten()
            .find(|e| e.extn_id.to_string() == OCSP_NONCE)
            .context("OCSP response does not echo request nonce")?;
        let value = OctetString::from_der(ext.extn_value.as_bytes())?;
        ensure!(value.as_bytes() == expected, "OCSP response nonce mismatch");
    }
    let produced = data.produced_at.0.to_unix_duration().as_secs();
    ensure!(produced <= now, "OCSP producedAt is in the future");
    let signer = if responder_matches(&data.responder_id, issuer)? {
        issuer
    } else {
        let mut candidates = response
            .certs
            .iter()
            .flatten()
            .filter(|c| responder_matches(&data.responder_id, c).unwrap_or(false));
        let delegated = candidates
            .next()
            .context("OCSP responder signer certificate is missing")?;
        ensure!(
            candidates.next().is_none(),
            "ambiguous OCSP responder certificate"
        );
        cert::check_certificate(delegated, now)?;
        cert::check_extended_usage(delegated, Purpose::OcspResponder, true)?;
        ensure!(
            cert::key_usage(delegated)?.digital_signature(),
            "OCSP signer lacks digitalSignature"
        );
        ensure!(
            !cert::key_usage(delegated)?.key_cert_sign(),
            "OCSP delegated signer must not be a CA"
        );
        if let Some((_, bc)) = delegated.tbs_certificate.get::<BasicConstraints>()? {
            ensure!(!bc.ca, "OCSP delegated signer must not be a CA");
        }
        // RFC 6960 requires direct delegation by the certificate issuer; merely
        // chaining to the same trust root is not sufficient authorization.
        cert::verify_certificate_signature(delegated, issuer)
            .context("OCSP signer is not directly authorized by this issuer")?;
        let no_check = delegated
            .tbs_certificate
            .extensions
            .iter()
            .flatten()
            .find(|e| e.extn_id.to_string() == OCSP_NOCHECK);
        if let Some(extension) = no_check {
            der::asn1::Null::from_der(extension.extn_value.as_bytes())
                .context("invalid id-pkix-ocsp-nocheck extension")?;
        } else {
            let mut signer_checked = false;
            for crl in crls {
                if crl.tbs_cert_list.issuer == issuer.tbs_certificate.subject {
                    check_crl(crl, delegated, issuer, now).context("OCSP responder revocation")?;
                    signer_checked = true;
                }
            }
            ensure!(signer_checked, "delegated OCSP signer lacks authenticated revocation status or id-pkix-ocsp-nocheck");
        }
        delegated
    };
    ensure!(
        produced
            >= signer
                .tbs_certificate
                .validity
                .not_before
                .to_unix_duration()
                .as_secs()
            && produced
                <= signer
                    .tbs_certificate
                    .validity
                    .not_after
                    .to_unix_duration()
                    .as_secs(),
        "OCSP producedAt is outside signer validity"
    );
    cert::verify_signature(
        signer,
        &response.signature_algorithm,
        &data.to_der()?,
        response
            .signature
            .as_bytes()
            .context("OCSP signature is not byte-aligned")?,
    )?;
    let mut matches = 0usize;
    for single in &data.responses {
        check_extensions(single.single_extensions.as_ref(), &[])?;
        if !cert_id_matches(&single.cert_id, subject, issuer)? {
            continue;
        }
        matches += 1;
        let this = single.this_update.0.to_unix_duration().as_secs();
        let next = single
            .next_update
            .context("OCSP nextUpdate is required under strict policy")?
            .0
            .to_unix_duration()
            .as_secs();
        check_dates(this, next, now)?;
        ensure!(
            this <= produced && produced < next,
            "OCSP producedAt is outside status interval"
        );
        match single.cert_status {
            CertStatus::Good(_) => {}
            CertStatus::Revoked(_) => bail!("certificate is revoked (including certificateHold)"),
            CertStatus::Unknown(_) => bail!("OCSP certificate status is unknown"),
        }
    }
    ensure!(
        matches == 1,
        "OCSP must contain exactly one matching CertID"
    );
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

fn check_crl(
    crl: &CertificateList,
    subject: &Certificate,
    issuer: &Certificate,
    now: u64,
) -> Result<()> {
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
    ensure!(
        cert::key_usage(issuer)?.crl_sign(),
        "CRL issuer lacks cRLSign"
    );
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
            "2.5.29.35" => cert::check_authority_key_id(
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
    cert::verify_signature(
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

/// Explicitly configured HTTPS transport. No endpoint is inferred from an
/// untrusted certificate; redirects are disabled and response sizes bounded.
pub struct RevocationClient {
    client: reqwest::blocking::Client,
    ocsp_url: reqwest::Url,
    crl_urls: Vec<reqwest::Url>,
}

impl RevocationClient {
    pub fn new(ocsp_url: &str, crl_urls: &[String]) -> Result<Self> {
        let parse = |input: &str| -> Result<reqwest::Url> {
            let url = reqwest::Url::parse(input)?;
            ensure!(
                url.scheme() == "https" && url.host_str().is_some(),
                "revocation endpoints must use HTTPS"
            );
            ensure!(
                url.username().is_empty() && url.password().is_none() && url.fragment().is_none(),
                "revocation endpoint credentials/fragments are forbidden"
            );
            Ok(url)
        };
        ensure!(
            crl_urls.len() <= MAX_OBJECTS,
            "too many configured CRL endpoints"
        );
        Ok(Self {
            client: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(20))
                .connect_timeout(Duration::from_secs(5))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            ocsp_url: parse(ocsp_url)?,
            crl_urls: crl_urls.iter().map(|u| parse(u)).collect::<Result<_>>()?,
        })
    }

    /// Fetch and authenticate status, including an unpredictable echoed nonce
    /// for each OCSP request. No failed request becomes a `good` result.
    pub fn fetch_chain(&self, chain: &ValidatedChain) -> Result<RevocationEvidence> {
        let mut evidence = RevocationEvidence::default();
        for url in &self.crl_urls {
            evidence.crls.push(read_response(
                self.client.get(url.clone()).send()?.error_for_status()?,
            )?);
        }
        let crls = evidence
            .crls
            .iter()
            .map(|b| CertificateList::from_der(b).map_err(Into::into))
            .collect::<Result<Vec<_>>>()?;
        for pair in chain.certificates().windows(2) {
            let mut nonce = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut nonce);
            let request = ocsp_request(&pair[0], &pair[1], &nonce)?;
            let response = self
                .client
                .post(self.ocsp_url.clone())
                .header("Content-Type", "application/ocsp-request")
                .header("Accept", "application/ocsp-response")
                .body(request)
                .send()?
                .error_for_status()?;
            let body = read_response(response)?;
            check_ocsp(
                &parse_ocsp(&body)?,
                &pair[0],
                &pair[1],
                &crls,
                unix_now()?,
                Some(&nonce),
            )?;
            evidence.ocsp_responses.push(body);
        }
        check_chain(chain, &evidence, unix_now()?)?;
        Ok(evidence)
    }
}

fn read_response(response: reqwest::blocking::Response) -> Result<Vec<u8>> {
    if let Some(size) = response.content_length() {
        ensure!(
            size <= MAX_OBJECT_BYTES as u64,
            "revocation HTTP response exceeds limit"
        );
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_OBJECT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_OBJECT_BYTES,
        "revocation HTTP body size outside limit"
    );
    Ok(bytes)
}

fn ocsp_request(subject: &Certificate, issuer: &Certificate, nonce: &[u8]) -> Result<Vec<u8>> {
    let id = CertId {
        hash_algorithm: AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1"),
            parameters: None,
        },
        issuer_name_hash: OctetString::new(
            Sha256::digest(issuer.tbs_certificate.subject.to_der()?).to_vec(),
        )?,
        issuer_key_hash: OctetString::new(Sha256::digest(cert::public_key(issuer)?).to_vec())?,
        serial_number: subject.tbs_certificate.serial_number.clone(),
    };
    Ok(OcspRequest {
        tbs_request: TbsRequest {
            request_list: vec![Request {
                req_cert: id,
                single_request_extensions: None,
            }],
            request_extensions: Some(vec![Extension {
                extn_id: ObjectIdentifier::new_unwrap(OCSP_NONCE),
                critical: false,
                extn_value: OctetString::new(OctetString::new(nonce)?.to_der()?)?,
            }]),
            ..Default::default()
        },
        optional_signature: None,
    }
    .to_der()?)
}

fn unix_now() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}
