//! AWS NitroTPM document profile, distinct from Nitro Enclave NSM PCRs.
#[cfg(any(feature = "nitro", feature = "sev-snp"))]
use anyhow::Context;
use anyhow::{anyhow, bail, ensure, Result};
use ciborium::value::Value;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_NITROTPM_DOCUMENT_BYTES: usize = 32 * 1024;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NitroTpmPolicy {
    /// Independent TPM bank selection. `digest: SHA384` is a document-profile
    /// field; the AWS schema permits 32/48/64-byte PCR values.
    pub pcr_algorithm: u16,
    pub expected_pcrs: BTreeMap<u32, String>,
    pub max_age_secs: u64,
    pub max_future_skew_secs: u64,
}
impl NitroTpmPolicy {
    pub fn validate(&self) -> Result<()> {
        let width = bank_size(self.pcr_algorithm)?;
        ensure!(
            !self.expected_pcrs.is_empty() && self.expected_pcrs.len() <= 24,
            "NitroTPM policy requires PCR expectations"
        );
        ensure!(
            (1..=3600).contains(&self.max_age_secs) && self.max_future_skew_secs <= 30,
            "NitroTPM freshness bounds exceed policy limits"
        );
        for (index, digest) in &self.expected_pcrs {
            ensure!(
                *index <= 23
                    && digest.len() == width * 2
                    && digest.bytes().all(|c| c.is_ascii_hexdigit()),
                "invalid expected NitroTPM PCR"
            );
        }
        ensure!(
            self.expected_pcrs
                .iter()
                .any(|(index, digest)| (2..=15).contains(index)
                    && digest.bytes().any(|byte| byte != b'0')),
            "NitroTPM policy requires a nonzero measured static PCR2..15 expectation"
        );
        Ok(())
    }
}
fn bank_size(algorithm: u16) -> Result<usize> {
    match algorithm {
        0xb => Ok(32),
        0xc => Ok(48),
        0xd => Ok(64),
        _ => bail!("NitroTPM requires an independently selected SHA2 bank"),
    }
}

#[derive(Debug, Serialize)]
pub struct VerifiedNitroTpm {
    module_id: String,
    timestamp_millis: u64,
    pcr_algorithm: u16,
    pcrs: BTreeMap<u32, Vec<u8>>,
}
impl VerifiedNitroTpm {
    pub fn pcrs(&self) -> &BTreeMap<u32, Vec<u8>> {
        &self.pcrs
    }
    pub fn timestamp_millis(&self) -> u64 {
        self.timestamp_millis
    }
    pub fn module_id(&self) -> &str {
        &self.module_id
    }
    /// AWS deliberately replaces PCR0/1 with constants. Never present them as
    /// authenticated early-firmware replay values. Dynamic PCRs are also absent.
    pub fn authenticated_registers(&self) -> Result<crate::boot::AuthenticatedRegisters> {
        crate::boot::AuthenticatedRegisters::tpm(
            self.pcrs
                .iter()
                .filter(|(index, _)| (2..=15).contains(*index))
                .map(|(index, digest)| ((self.pcr_algorithm, *index), digest.clone()))
                .collect(),
        )
        .map_err(Into::into)
    }
    pub fn verify_boot_log(
        &self,
        bytes: &[u8],
        limits: crate::boot::ParseLimits,
    ) -> Result<crate::boot::VerifiedBootLog> {
        let log = crate::boot::EventLog::parse_tcg2(bytes, limits)?;
        Ok(log.verify(&self.authenticated_registers()?)?)
    }
}

fn decode(bytes: &[u8]) -> Result<Value> {
    let mut cursor = std::io::Cursor::new(bytes);
    let value = ciborium::de::from_reader(&mut cursor)?;
    ensure!(
        cursor.position() as usize == bytes.len(),
        "trailing CBOR data"
    );
    Ok(value)
}
fn bytes(value: &Value) -> Result<&[u8]> {
    match value {
        Value::Bytes(b) => Ok(b),
        _ => bail!("expected CBOR byte string"),
    }
}
fn text(value: &Value) -> Result<&str> {
    match value {
        Value::Text(s) => Ok(s),
        _ => bail!("expected CBOR text"),
    }
}
fn uint(value: &Value) -> Result<u64> {
    match value {
        Value::Integer(n) => u64::try_from(*n).map_err(|_| anyhow!("expected unsigned integer")),
        _ => bail!("expected CBOR integer"),
    }
}
fn unique_map<'a>(value: &'a Value) -> Result<BTreeMap<&'a str, &'a Value>> {
    let Value::Map(fields) = value else {
        bail!("expected CBOR claim map")
    };
    ensure!(fields.len() <= 12, "too many NitroTPM claims");
    let mut result = BTreeMap::new();
    for (key, value) in fields {
        ensure!(
            result.insert(text(key)?, value).is_none(),
            "duplicate NitroTPM claim"
        );
    }
    Ok(result)
}
fn optional_bytes<'a>(fields: &BTreeMap<&str, &'a Value>, key: &str) -> Result<Option<&'a [u8]>> {
    match fields.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => {
            let b = bytes(v)?;
            ensure!(b.len() <= 1024, "NitroTPM optional field exceeds limit");
            Ok(Some(b))
        }
    }
}
struct ParsedDocument {
    protected: Vec<u8>,
    payload: Vec<u8>,
    signature: Vec<u8>,
    module_id: String,
    timestamp: u64,
    pcrs: BTreeMap<u32, Vec<u8>>,
    certificate: Vec<u8>,
    cabundle: Vec<Vec<u8>>,
    nonce: Option<Vec<u8>>,
    user_data: Option<Vec<u8>>,
}
fn parse_document(raw: &[u8]) -> Result<ParsedDocument> {
    ensure!(
        !raw.is_empty() && raw.len() <= MAX_NITROTPM_DOCUMENT_BYTES,
        "NitroTPM document outside size limit"
    );
    let outer = decode(raw)?;
    let array = match &outer {
        Value::Tag(18, inner) => match inner.as_ref() {
            Value::Array(a) => a,
            _ => bail!("COSE tag does not contain an array"),
        },
        Value::Array(a) => a,
        _ => bail!("NitroTPM document is not COSE_Sign1"),
    };
    ensure!(array.len() == 4, "COSE_Sign1 must have four elements");
    let protected = bytes(&array[0])?;
    ensure!(protected.len() <= 64, "COSE header exceeds limit");
    let header = decode(protected)?;
    let Value::Map(headers) = header else {
        bail!("protected COSE header is not a map")
    };
    ensure!(
        headers.len() == 1
            && headers[0].0 == Value::Integer(1.into())
            && headers[0].1 == Value::Integer((-35).into()),
        "NitroTPM requires exactly protected ES384"
    );
    ensure!(
        matches!(&array[1],Value::Map(m) if m.is_empty()),
        "unsupported unprotected COSE header"
    );
    let payload = bytes(&array[2])?;
    let signature = bytes(&array[3])?;
    ensure!(signature.len() == 96, "ES384 signature must be r||s");
    let decoded = decode(payload)?;
    let fields = unique_map(&decoded)?;
    for key in fields.keys() {
        ensure!(
            matches!(
                *key,
                "module_id"
                    | "timestamp"
                    | "digest"
                    | "nitrotpm_pcrs"
                    | "certificate"
                    | "cabundle"
                    | "nonce"
                    | "user_data"
                    | "public_key"
            ),
            "unknown/foreign NitroTPM claim {key}"
        );
    }
    let get = |key| {
        fields
            .get(key)
            .copied()
            .ok_or_else(|| anyhow!("missing NitroTPM claim {key}"))
    };
    ensure!(
        text(get("digest")?)? == "SHA384",
        "unsupported NitroTPM document digest profile"
    );
    let module_id = text(get("module_id")?)?;
    ensure!(
        !module_id.is_empty()
            && module_id.len() <= 256
            && module_id.bytes().all(|c| (0x21..=0x7e).contains(&c)),
        "invalid NitroTPM module ID"
    );
    let timestamp = uint(get("timestamp")?)?;
    let Value::Map(entries) = get("nitrotpm_pcrs")? else {
        bail!("NitroTPM PCR claims must be a map")
    };
    ensure!(
        !entries.is_empty() && entries.len() <= 32,
        "invalid NitroTPM PCR count"
    );
    let mut pcrs = BTreeMap::new();
    for (key, value) in entries {
        let index = uint(key)?;
        let digest = bytes(value)?;
        ensure!(
            index <= 31 && matches!(digest.len(), 32 | 48 | 64),
            "invalid NitroTPM PCR index/width"
        );
        ensure!(
            pcrs.insert(index as u32, digest.to_vec()).is_none(),
            "duplicate NitroTPM PCR index"
        );
    }
    // AWS's published profile includes static0..15, debug16 and application23.
    ensure!(
        (0..=16).chain([23]).all(|i| pcrs.contains_key(&i)),
        "NitroTPM document omits required profile PCRs"
    );
    let certificate = bytes(get("certificate")?)?;
    ensure!(
        !certificate.is_empty() && certificate.len() <= 1024,
        "invalid NitroTPM certificate size"
    );
    let Value::Array(bundle) = get("cabundle")? else {
        bail!("NitroTPM CA bundle is not an array")
    };
    ensure!(
        !bundle.is_empty() && bundle.len() <= 10,
        "invalid NitroTPM CA bundle depth"
    );
    let mut cabundle = Vec::new();
    let mut seen = BTreeSet::new();
    seen.insert(certificate.to_vec());
    for cert in bundle {
        let cert = bytes(cert)?;
        ensure!(
            !cert.is_empty() && cert.len() <= 1024 && seen.insert(cert.to_vec()),
            "invalid/duplicate NitroTPM CA certificate"
        );
        cabundle.push(cert.to_vec());
    }
    let nonce = optional_bytes(&fields, "nonce")?.map(ToOwned::to_owned);
    let user_data = optional_bytes(&fields, "user_data")?.map(ToOwned::to_owned);
    optional_bytes(&fields, "public_key")?;
    Ok(ParsedDocument {
        protected: protected.to_vec(),
        payload: payload.to_vec(),
        signature: signature.to_vec(),
        module_id: module_id.into(),
        timestamp,
        pcrs,
        certificate: certificate.to_vec(),
        cabundle,
        nonce,
        user_data,
    })
}

pub(super) fn inspect_document(
    raw: &[u8],
    nonce: &[u8; 32],
    user_data: Option<&[u8]>,
) -> Result<BTreeMap<u32, Vec<u8>>> {
    let document = parse_document(raw)?;
    ensure!(
        document.nonce.as_deref() == Some(nonce.as_slice()),
        "returned NitroTPM nonce differs from request"
    );
    ensure!(
        document.user_data.as_deref() == user_data,
        "returned NitroTPM user_data differs from request"
    );
    Ok(document.pcrs)
}

#[cfg(any(feature = "nitro", feature = "sev-snp"))]
/// `now_secs` must come from a trusted verifier clock, never from the evidence.
pub fn verify_nitrotpm_document(
    raw: &[u8],
    nonce: &[u8; 32],
    user_data: Option<&[u8]>,
    policy: &NitroTpmPolicy,
    now_secs: u64,
) -> Result<VerifiedNitroTpm> {
    use crate::quote::verify::pki;
    policy.validate()?;
    ensure!(
        user_data.is_none_or(|d| d.len() <= 1024),
        "expected user_data too large"
    );
    let doc = parse_document(raw)?;
    ensure!(
        doc.nonce.as_deref() == Some(nonce.as_slice()),
        "NitroTPM signed nonce mismatch"
    );
    ensure!(
        doc.user_data.as_deref() == user_data,
        "NitroTPM signed user_data mismatch"
    );
    let now = now_secs
        .checked_mul(1000)
        .context("verifier clock overflow")?;
    ensure!(
        doc.timestamp <= now.saturating_add(policy.max_future_skew_secs * 1000)
            && now.saturating_sub(doc.timestamp) <= policy.max_age_secs * 1000,
        "NitroTPM document is stale or future-dated"
    );
    let width = bank_size(policy.pcr_algorithm)?;
    ensure!(
        doc.pcrs.values().all(|d| d.len() == width),
        "NitroTPM PCR width differs from independent bank policy"
    );
    let mut chain = vec![doc.certificate.clone()];
    chain.extend(doc.cabundle.iter().rev().cloned());
    let certs = pki::validate_chain(
        &chain,
        crate::quote::roots::AWS_NITRO_ROOT_SHA256,
        now_secs,
        pki::Curve::P384,
    )?;
    verify_document_signature(&doc, pki::public_key(&certs[0])?)?;
    for (index, expected) in &policy.expected_pcrs {
        ensure!(
            doc.pcrs.get(index) == Some(&hex::decode(expected)?),
            "NitroTPM PCR{index} differs from independent policy"
        );
    }
    Ok(VerifiedNitroTpm {
        module_id: doc.module_id,
        timestamp_millis: doc.timestamp,
        pcr_algorithm: policy.pcr_algorithm,
        pcrs: doc.pcrs,
    })
}
#[cfg(any(feature = "nitro", feature = "sev-snp"))]
fn verify_document_signature(doc: &ParsedDocument, public_key: &[u8]) -> Result<()> {
    use p384::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
    use sha2::{Digest, Sha384};
    let key = VerifyingKey::from_sec1_bytes(public_key)?;
    let structure = Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(doc.protected.clone()),
        Value::Bytes(vec![]),
        Value::Bytes(doc.payload.clone()),
    ]);
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&structure, &mut encoded)?;
    key.verify_prehash(
        &Sha384::digest(&encoded),
        &Signature::from_slice(&doc.signature)?,
    )?;
    Ok(())
}
#[cfg(not(any(feature = "nitro", feature = "sev-snp")))]
pub fn verify_nitrotpm_document(
    _: &[u8],
    _: &[u8; 32],
    _: Option<&[u8]>,
    _: &NitroTpmPolicy,
    _: u64,
) -> Result<VerifiedNitroTpm> {
    bail!("NitroTPM signature verification requires nitro or sev-snp feature")
}

#[cfg(test)]
#[path = "nitrotpm_verify/tests.rs"]
mod tests;
