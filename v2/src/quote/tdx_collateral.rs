//! Intel PCS v4 collateral appraisal for DCAP TDX quote v4.
//!
//! Collateral is supplied explicitly. Exact signed JSON object bytes are retained;
//! no network response, quote signature alone, or parsed JSON label is a verdict.
//! Only the quote admission verifier calls `appraise_tdx`, after authenticating
//! the quote signature, PCK-signed QE report, and attestation-key binding.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{ensure, Context, Result};
use der::{
    asn1::{Any, ObjectIdentifier, OctetString},
    Decode, Tag, Tagged,
};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use x509_cert::Certificate;

use super::{roots::INTEL_SGX_ROOT_SHA256, verify::pki};

const MAX_JSON: usize = 1024 * 1024;
const MAX_CRL: usize = 4 * 1024 * 1024;
const MAX_LEVELS: usize = 512;
const SGX_EXTENSION: &str = "1.2.840.113741.1.13.1";

/// Captured Intel collateral, not an independent source of security policy.
/// Chains contain DER certificates in leaf-to-root order; CRLs are full DER CRLs.
/// JSON bytes must be the original PCS response, without pretty-printing the
/// signed object. The trusted minimum evaluation-data number is separate policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TdxCollateral {
    #[serde(with = "serde_bytes")]
    pub tcb_info_json: Vec<u8>,
    pub tcb_info_signing_chain: Vec<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    pub qe_identity_json: Vec<u8>,
    pub qe_identity_signing_chain: Vec<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    pub root_ca_crl: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub pck_crl: Vec<u8>,
}

pub(crate) fn appraise_tdx(
    quote: &[u8],
    collateral: &TdxCollateral,
    now: u64,
    minimum_tcb_evaluation_data_number: u64,
) -> Result<()> {
    ensure!(
        minimum_tcb_evaluation_data_number > 0,
        "TDX policy requires a nonzero independently enrolled TCB evaluation-data floor"
    );
    let parsed = QuoteParts::parse(quote)?;
    ensure!(
        !collateral.root_ca_crl.is_empty() && collateral.root_ca_crl.len() <= MAX_CRL,
        "Intel root CRL is missing or oversized"
    );
    ensure!(
        !collateral.pck_crl.is_empty() && collateral.pck_crl.len() <= MAX_CRL,
        "Intel PCK CRL is missing or oversized"
    );
    let pck_chain = pki::parse_pem_chain(parsed.pck_chain)?;
    ensure!(
        pck_chain.len() == 3,
        "unsupported Intel PCK certificate hierarchy"
    );
    let pck = pki::validate_chain(&pck_chain, INTEL_SGX_ROOT_SHA256, now, pki::Curve::P256)?;
    require_cn(&pck[0], &["Intel SGX PCK Certificate"])?;
    require_cn(
        &pck[1],
        &["Intel SGX PCK Platform CA", "Intel SGX PCK Processor CA"],
    )?;
    pki::check_crl(&collateral.root_ca_crl, &pck[1], &pck[2], now)
        .context("Intel PCK issuer revocation")?;
    pki::check_crl(&collateral.pck_crl, &pck[0], &pck[1], now)
        .context("Intel PCK leaf revocation")?;
    let pck_tcb = PckTcb::parse(&pck[0])?;
    let (tcb, qe) = authenticate_documents(collateral, now)?;
    check_document_window(&tcb.issue_date, &tcb.next_update, now)?;
    check_document_window(&qe.issue_date, &qe.next_update, now)?;
    ensure!(
        tcb.tcb_evaluation_data_number >= minimum_tcb_evaluation_data_number
            && qe.tcb_evaluation_data_number >= minimum_tcb_evaluation_data_number,
        "Intel collateral evaluation-data number is below trusted policy floor"
    );
    appraise_qe(&qe, parsed.qe_report, now)?;
    appraise_platform(&tcb, &pck_tcb, parsed.body, now)?;
    Ok(())
}

fn authenticate_documents(collateral: &TdxCollateral, now: u64) -> Result<(TcbInfo, QeIdentity)> {
    ensure!(
        !collateral.tcb_info_json.is_empty() && collateral.tcb_info_json.len() <= MAX_JSON,
        "Intel TCB Info JSON is missing or oversized"
    );
    ensure!(
        !collateral.qe_identity_json.is_empty() && collateral.qe_identity_json.len() <= MAX_JSON,
        "Intel QE Identity JSON is missing or oversized"
    );
    let tcb_envelope: SignedTcb = serde_json::from_slice(&collateral.tcb_info_json)?;
    let qe_envelope: SignedQe = serde_json::from_slice(&collateral.qe_identity_json)?;
    verify_signed_json(
        &tcb_envelope.tcb_info,
        &tcb_envelope.signature,
        &collateral.tcb_info_signing_chain,
        &collateral.root_ca_crl,
        now,
    )?;
    verify_signed_json(
        &qe_envelope.enclave_identity,
        &qe_envelope.signature,
        &collateral.qe_identity_signing_chain,
        &collateral.root_ca_crl,
        now,
    )?;
    // Strongly typed Deserialize rejects duplicate and unknown fields rather
    // than letting a second parser interpret an authenticated object differently.
    let tcb: TcbInfo = serde_json::from_str(tcb_envelope.tcb_info.get())?;
    let qe: QeIdentity = serde_json::from_str(qe_envelope.enclave_identity.get())?;
    ensure!(
        tcb.id == "TDX" && tcb.version == 3 && tcb.tcb_type == 0,
        "requires Intel TDX TCB Info v3 with TCB type 0"
    );
    ensure!(
        qe.id == "TD_QE" && qe.version == 2,
        "requires Intel TD_QE Identity v2"
    );
    Ok((tcb, qe))
}

fn verify_signed_json(
    raw: &RawValue,
    signature: &str,
    chain: &[Vec<u8>],
    root_crl: &[u8],
    now: u64,
) -> Result<()> {
    ensure!(
        chain.len() == 2,
        "unsupported Intel collateral signing hierarchy"
    );
    ensure!(
        !root_crl.is_empty() && root_crl.len() <= MAX_CRL,
        "Intel signing certificate root CRL missing/oversized"
    );
    let certs = pki::validate_chain(chain, INTEL_SGX_ROOT_SHA256, now, pki::Curve::P256)?;
    require_cn(&certs[0], &["Intel SGX TCB Signing"])?;
    pki::check_crl(root_crl, &certs[0], &certs[1], now)
        .context("Intel collateral signer revocation")?;
    let pk = certs[0]
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .context("Intel collateral signer key has unused bits")?;
    let vk = VerifyingKey::from_sec1_bytes(pk)?;
    let bytes = hex_array::<64>(signature)?;
    let signature = Signature::from_slice(&bytes)?;
    vk.verify(raw.get().as_bytes(), &signature)
        .context("Intel collateral JSON signature mismatch")
}

fn require_cn(cert: &Certificate, names: &[&str]) -> Result<()> {
    let mut common_names = cert
        .tbs_certificate
        .subject
        .0
        .iter()
        .flat_map(|rdn| rdn.0.iter())
        .filter(|attribute| attribute.oid.to_string() == "2.5.4.3");
    let cn = common_names
        .next()
        .context("Intel certificate lacks commonName")?;
    ensure!(
        common_names.next().is_none(),
        "duplicate Intel certificate commonName"
    );
    ensure!(
        matches!(cn.value.tag(), Tag::Utf8String | Tag::PrintableString),
        "unsupported Intel commonName encoding"
    );
    ensure!(
        names
            .iter()
            .any(|expected| cn.value.value() == expected.as_bytes()),
        "Intel certificate has unexpected signing role"
    );
    Ok(())
}

struct QuoteParts<'a> {
    body: &'a [u8],
    qe_report: &'a [u8],
    pck_chain: &'a [u8],
}
impl<'a> QuoteParts<'a> {
    fn parse(quote: &'a [u8]) -> Result<Self> {
        ensure!(
            (770..=128 * 1024).contains(&quote.len()),
            "TDX quote length outside supported bounds"
        );
        ensure!(
            quote[..2] == 4u16.to_le_bytes()
                && quote[2..4] == 2u16.to_le_bytes()
                && quote[4..8] == 0x81u32.to_le_bytes(),
            "only TDX DCAP v4 ECDSA-P256 is supported"
        );
        ensure!(
            u32_le(&quote[632..636]) as usize == quote.len() - 636,
            "TDX signature length mismatch"
        );
        let sig = &quote[636..];
        ensure!(
            sig[128..130] == 6u16.to_le_bytes(),
            "TDX requires QE report certification data type 6"
        );
        ensure!(
            u32_le(&sig[130..134]) as usize == sig.len() - 134,
            "TDX outer certification length mismatch"
        );
        let qe = &sig[134..];
        ensure!(qe.len() >= 456, "truncated TDX QE certification data");
        let auth_len = u16::from_le_bytes(qe[448..450].try_into()?) as usize;
        let inner = qe
            .get(450 + auth_len..)
            .context("truncated TDX QE auth data")?;
        ensure!(
            inner.len() >= 6 && inner[..2] == 5u16.to_le_bytes(),
            "TDX requires PCK certificate-chain type 5"
        );
        ensure!(
            u32_le(&inner[2..6]) as usize == inner.len() - 6,
            "TDX inner certification length mismatch"
        );
        Ok(Self {
            body: &quote[48..632],
            qe_report: &qe[..384],
            pck_chain: &inner[6..],
        })
    }
}
fn u32_le(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().expect("fixed-width internal slice"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SignedTcb {
    tcb_info: Box<RawValue>,
    signature: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SignedQe {
    enclave_identity: Box<RawValue>,
    signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TcbInfo {
    id: String,
    version: u32,
    issue_date: String,
    next_update: String,
    fmspc: String,
    pce_id: String,
    tcb_type: u32,
    tcb_evaluation_data_number: u64,
    tdx_module: TdxModule,
    #[serde(default)]
    tdx_module_identities: Vec<TdxModuleIdentity>,
    tcb_levels: Vec<PlatformLevel>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct QeIdentity {
    id: String,
    version: u32,
    issue_date: String,
    next_update: String,
    tcb_evaluation_data_number: u64,
    miscselect: String,
    miscselect_mask: String,
    attributes: String,
    attributes_mask: String,
    mrsigner: String,
    isvprodid: u16,
    tcb_levels: Vec<IsvLevel>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TdxModule {
    mrsigner: String,
    attributes: String,
    attributes_mask: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TdxModuleIdentity {
    id: String,
    mrsigner: String,
    attributes: String,
    attributes_mask: String,
    tcb_levels: Vec<IsvLevel>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Component {
    svn: u8,
    #[serde(default)]
    category: Option<String>,
    #[serde(default, rename = "type")]
    component_type: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlatformTcb {
    sgxtcbcomponents: [Component; 16],
    tdxtcbcomponents: [Component; 16],
    pcesvn: u16,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PlatformLevel {
    tcb: PlatformTcb,
    tcb_date: String,
    tcb_status: String,
    #[serde(default, rename = "advisoryIDs")]
    advisory_ids: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IsvTcb {
    isvsvn: u16,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct IsvLevel {
    tcb: IsvTcb,
    tcb_date: String,
    tcb_status: String,
    #[serde(default, rename = "advisoryIDs")]
    advisory_ids: Vec<String>,
}

fn appraise_qe(identity: &QeIdentity, report: &[u8], now: u64) -> Result<()> {
    ensure!(report.len() == 384, "QE report body length mismatch");
    let expected_misc = u32::from_be_bytes(hex_array::<4>(&identity.miscselect)?);
    let misc_mask = u32::from_be_bytes(hex_array::<4>(&identity.miscselect_mask)?);
    ensure!(
        u32_le(&report[16..20]) & misc_mask == expected_misc,
        "QE MISCSELECT differs from Intel identity"
    );
    masked_equal(
        &report[48..64],
        &hex_array::<16>(&identity.attributes)?,
        &hex_array::<16>(&identity.attributes_mask)?,
        "QE ATTRIBUTES",
    )?;
    // DEBUG must be off even if a future identity profile stops masking it.
    ensure!(
        u64::from_le_bytes(report[48..56].try_into()?) & 2 == 0,
        "debug QE forbidden"
    );
    ensure!(
        report[128..160] == hex_array::<32>(&identity.mrsigner)?,
        "QE MRSIGNER mismatch"
    );
    ensure!(
        u16::from_le_bytes(report[256..258].try_into()?) == identity.isvprodid,
        "QE ISVPRODID mismatch"
    );
    let svn = u16::from_le_bytes(report[258..260].try_into()?);
    let selected = select_isv_level(&identity.tcb_levels, svn, now)?;
    require_current(&selected.tcb_status, "QE")
}

fn appraise_platform(info: &TcbInfo, pck: &PckTcb, body: &[u8], now: u64) -> Result<()> {
    ensure!(body.len() == 584, "TD report body length mismatch");
    ensure!(
        hex_array::<6>(&info.fmspc)? == pck.fmspc && hex_array::<2>(&info.pce_id)? == pck.pce_id,
        "PCK certificate FMSPC/PCEID does not match signed TCB Info"
    );
    let tee_svn = &body[..16];
    ensure!(
        !info.tcb_levels.is_empty() && info.tcb_levels.len() <= MAX_LEVELS,
        "TCB level count outside bounds"
    );
    let mut seen = BTreeSet::new();
    for level in &info.tcb_levels {
        check_level_metadata(&level.tcb_date, &level.tcb_status, &level.advisory_ids, now)?;
        for component in level
            .tcb
            .sgxtcbcomponents
            .iter()
            .chain(&level.tcb.tdxtcbcomponents)
        {
            ensure!(
                component.category.as_ref().is_none_or(|s| s.len() <= 128)
                    && component
                        .component_type
                        .as_ref()
                        .is_none_or(|s| s.len() <= 128),
                "TCB component metadata too long"
            );
        }
        let sgx = level.tcb.sgxtcbcomponents.each_ref().map(|c| c.svn);
        let tdx = level.tcb.tdxtcbcomponents.each_ref().map(|c| c.svn);
        ensure!(
            seen.insert((sgx, tdx, level.tcb.pcesvn)),
            "duplicate platform TCB level"
        );
    }
    // Intel PCS specifies selecting the first matching level from its signed,
    // ordered array. Do not skip an unacceptable match to choose a weaker level.
    let start = if tee_svn[1] == 0 { 0 } else { 2 };
    let selected = info
        .tcb_levels
        .iter()
        .find(|level| {
            pck.components
                .iter()
                .zip(&level.tcb.sgxtcbcomponents)
                .all(|(actual, expected)| *actual >= expected.svn)
                && pck.pce_svn >= level.tcb.pcesvn
                && tee_svn[start..]
                    .iter()
                    .zip(&level.tcb.tdxtcbcomponents[start..])
                    .all(|(actual, expected)| *actual >= expected.svn)
        })
        .context("no matching Intel platform TCB level")?;
    require_current(&selected.tcb_status, "platform")?;
    appraise_module(info, body, now)
}

fn appraise_module(info: &TcbInfo, body: &[u8], now: u64) -> Result<()> {
    ensure!(body.len() == 584, "TD report body length mismatch");
    let tee_svn = &body[..16];
    ensure!(
        info.tdx_module_identities.len() <= 256,
        "too many TDX module identities"
    );
    let mut ids = BTreeSet::new();
    for module in &info.tdx_module_identities {
        ensure!(
            module.id.is_ascii()
                && module.id.len() == 6
                && module.id[..4].eq_ignore_ascii_case("TDX_")
                && module.id[4..].bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid TDX module identity ID"
        );
        ensure!(
            ids.insert(module.id.to_ascii_uppercase()),
            "duplicate TDX module identity"
        );
    }
    let (signer, attributes, mask) = if tee_svn[1] == 0 {
        (
            &info.tdx_module.mrsigner,
            &info.tdx_module.attributes,
            &info.tdx_module.attributes_mask,
        )
    } else {
        let expected_id = format!("TDX_{:02X}", tee_svn[1]);
        let identity = info
            .tdx_module_identities
            .iter()
            .find(|m| m.id.eq_ignore_ascii_case(&expected_id))
            .context("TDX module version has no signed identity")?;
        let level = select_isv_level(&identity.tcb_levels, tee_svn[0] as u16, now)?;
        require_current(&level.tcb_status, "TDX module")?;
        (
            &identity.mrsigner,
            &identity.attributes,
            &identity.attributes_mask,
        )
    };
    ensure!(
        body[64..112] == hex_array::<48>(signer)?,
        "TDX MRSIGNERSEAM mismatch"
    );
    masked_equal(
        &body[112..120],
        &hex_array::<8>(attributes)?,
        &hex_array::<8>(mask)?,
        "TDX SEAMATTRIBUTES",
    )?;
    // The current Intel v4 verifier profile requires all SEAM attribute bits
    // zero. Future nonzero attributes require explicit semantics, not fallback.
    ensure!(
        body[112..120].iter().all(|b| *b == 0),
        "nonzero TDX SEAMATTRIBUTES are unsupported"
    );
    Ok(())
}

fn select_isv_level(levels: &[IsvLevel], svn: u16, now: u64) -> Result<&IsvLevel> {
    ensure!(
        !levels.is_empty() && levels.len() <= MAX_LEVELS,
        "identity TCB level count outside bounds"
    );
    let mut previous = None;
    for level in levels {
        ensure!(
            previous.is_none_or(|prior| prior > level.tcb.isvsvn),
            "identity TCB levels must descend strictly"
        );
        previous = Some(level.tcb.isvsvn);
        check_level_metadata(&level.tcb_date, &level.tcb_status, &level.advisory_ids, now)?;
    }
    levels
        .iter()
        .find(|level| svn >= level.tcb.isvsvn)
        .context("no matching identity SVN level")
}
fn check_level_metadata(date: &str, status: &str, advisories: &[String], now: u64) -> Result<()> {
    ensure!(parse_time(date)? <= now, "TCB level date is in the future");
    ensure!(
        matches!(
            status,
            "UpToDate"
                | "OutOfDate"
                | "Revoked"
                | "ConfigurationNeeded"
                | "OutOfDateConfigurationNeeded"
                | "SWHardeningNeeded"
                | "ConfigurationAndSWHardeningNeeded"
        ),
        "unsupported Intel TCB status {status}"
    );
    ensure!(
        advisories.len() <= 256 && advisories.iter().all(|s| !s.is_empty() && s.len() <= 128),
        "advisory list exceeds bounds"
    );
    Ok(())
}
fn require_current(status: &str, role: &str) -> Result<()> {
    ensure!(
        status == "UpToDate",
        "Intel {role} TCB status is {status}; strict policy requires UpToDate"
    );
    Ok(())
}
fn masked_equal(actual: &[u8], expected: &[u8], mask: &[u8], field: &str) -> Result<()> {
    ensure!(
        actual.len() == expected.len() && actual.len() == mask.len(),
        "{field} size mismatch"
    );
    ensure!(
        actual
            .iter()
            .zip(mask)
            .zip(expected)
            .all(|((value, mask), expected)| value & mask == *expected),
        "{field} mask/value mismatch"
    );
    Ok(())
}
fn hex_array<const N: usize>(s: &str) -> Result<[u8; N]> {
    ensure!(
        s.len() == N * 2 && s.bytes().all(|b| b.is_ascii_hexdigit()),
        "expected {N}-byte hex field"
    );
    let mut value = [0; N];
    hex::decode_to_slice(s, &mut value)?;
    Ok(value)
}
fn check_document_window(issued: &str, next: &str, now: u64) -> Result<()> {
    let issued = parse_time(issued)?;
    let next = parse_time(next)?;
    ensure!(
        issued < next && issued <= now && now < next,
        "Intel collateral is not yet valid or has expired"
    );
    Ok(())
}
fn parse_time(value: &str) -> Result<u64> {
    let b = value.as_bytes();
    ensure!(
        b.len() == 20
            && b[4] == b'-'
            && b[7] == b'-'
            && b[10] == b'T'
            && b[13] == b':'
            && b[16] == b':'
            && b[19] == b'Z',
        "Intel date must be YYYY-MM-DDTHH:MM:SSZ"
    );
    ensure!(
        b.iter()
            .enumerate()
            .all(|(i, c)| matches!(i, 4 | 7 | 10 | 13 | 16 | 19) || c.is_ascii_digit()),
        "invalid Intel date digits"
    );
    let year = value[0..4].parse::<u16>()?;
    let parts = [5, 8, 11, 14, 17].map(|start| value[start..start + 2].parse::<u8>());
    let [month, day, hour, minute, second] = parts;
    Ok(
        der::DateTime::new(year, month?, day?, hour?, minute?, second?)?
            .unix_duration()
            .as_secs(),
    )
}

#[derive(der::Sequence)]
struct OidValue {
    oid: ObjectIdentifier,
    value: Any,
}
struct PckTcb {
    fmspc: [u8; 6],
    pce_id: [u8; 2],
    components: [u8; 16],
    pce_svn: u16,
}
impl PckTcb {
    fn parse(cert: &Certificate) -> Result<Self> {
        let mut extensions = cert
            .tbs_certificate
            .extensions
            .as_deref()
            .unwrap_or_default()
            .iter()
            .filter(|ext| ext.extn_id.to_string() == SGX_EXTENSION);
        let extension = extensions.next().context("PCK lacks SGX extension")?;
        ensure!(extensions.next().is_none(), "duplicate PCK SGX extension");
        let bytes = extension.extn_value.as_bytes();
        ensure!(
            !bytes.is_empty() && bytes.len() <= 8192,
            "PCK SGX extension outside size bounds"
        );
        let mut fields = oid_sequence(Vec::<OidValue>::from_der(bytes)?, SGX_EXTENSION, 7)?;
        octets::<16>(take(&mut fields, 1)?)?; // PPID is structurally required, never used as a policy identity.
        let tcb = take(&mut fields, 2)?;
        let pce_id = octets::<2>(take(&mut fields, 3)?)?;
        let fmspc = octets::<6>(take(&mut fields, 4)?)?;
        let sgx_type = take(&mut fields, 5)?;
        ensure!(
            sgx_type.tag() == Tag::Enumerated && matches!(sgx_type.value(), [0] | [1]),
            "unsupported PCK SGX type"
        );
        if sgx_type.value() == [1] {
            octets::<16>(take(&mut fields, 6)?)?;
            let config = take(&mut fields, 7)?;
            let mut config_fields = oid_sequence(
                config.decode_as::<Vec<OidValue>>()?,
                &format!("{SGX_EXTENSION}.7"),
                3,
            )?;
            for index in 1..=3 {
                let _: bool = take(&mut config_fields, index)?.decode_as()?;
            }
            ensure!(config_fields.is_empty(), "unknown PCK configuration field");
        }
        ensure!(fields.is_empty(), "unknown or inappropriate PCK SGX field");
        let mut tcbs = oid_sequence(
            tcb.decode_as::<Vec<OidValue>>()?,
            &format!("{SGX_EXTENSION}.2"),
            18,
        )?;
        let mut components = [0; 16];
        for (i, component) in components.iter_mut().enumerate() {
            *component = take(&mut tcbs, i as u8 + 1)?.decode_as::<u8>()?;
        }
        let pce_svn = take(&mut tcbs, 17)?.decode_as::<u16>()?;
        octets::<16>(take(&mut tcbs, 18)?)?; // CPUSVN is opaque; individual signed components drive TCB matching.
        ensure!(tcbs.is_empty(), "unknown PCK TCB field");
        Ok(Self {
            fmspc,
            pce_id,
            components,
            pce_svn,
        })
    }
}
fn oid_sequence(entries: Vec<OidValue>, base: &str, maximum: u8) -> Result<BTreeMap<u8, Any>> {
    ensure!(
        !entries.is_empty() && entries.len() <= maximum as usize,
        "Intel extension entry count outside bounds"
    );
    let mut result = BTreeMap::new();
    for entry in entries {
        let oid = entry.oid.to_string();
        let suffix = oid
            .strip_prefix(&format!("{base}."))
            .context("foreign OID in Intel extension")?;
        let index: u8 = suffix
            .parse()
            .context("unsupported nested Intel extension OID")?;
        ensure!(
            index > 0 && index <= maximum && suffix == index.to_string(),
            "unsupported Intel extension index"
        );
        ensure!(
            result.insert(index, entry.value).is_none(),
            "duplicate Intel extension OID"
        );
    }
    Ok(result)
}
fn take(fields: &mut BTreeMap<u8, Any>, index: u8) -> Result<Any> {
    fields
        .remove(&index)
        .with_context(|| format!("missing required Intel extension field {index}"))
}
fn octets<const N: usize>(value: Any) -> Result<[u8; N]> {
    let bytes: OctetString = value.decode_as()?;
    bytes
        .as_bytes()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Intel extension OCTET STRING size mismatch"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collateral() -> TdxCollateral {
        TdxCollateral {
            tcb_info_json: include_bytes!("../../testdata/tdx-collateral/tcb-info.json").to_vec(),
            tcb_info_signing_chain: vec![
                include_bytes!("../../testdata/tdx-collateral/tcb-signer-0.der").to_vec(),
                include_bytes!("../../testdata/tdx-collateral/tcb-signer-1.der").to_vec(),
            ],
            qe_identity_json: include_bytes!("../../testdata/tdx-collateral/qe-identity.json")
                .to_vec(),
            qe_identity_signing_chain: vec![
                include_bytes!("../../testdata/tdx-collateral/qe-signer-0.der").to_vec(),
                include_bytes!("../../testdata/tdx-collateral/qe-signer-1.der").to_vec(),
            ],
            root_ca_crl: include_bytes!("../../testdata/tdx-collateral/root.crl.der").to_vec(),
            pck_crl: include_bytes!("../../testdata/tdx-collateral/pck.crl.der").to_vec(),
        }
    }
    fn now() -> u64 {
        parse_time("2026-10-13T12:00:00Z").unwrap()
    }
    fn captured_quote() -> Vec<u8> {
        let json: serde_json::Value =
            serde_json::from_str(include_str!("../../testdata/tdx_attestation.json")).unwrap();
        let mut quote = hex::decode(json["raw_quote_hex"].as_str().unwrap()).unwrap();
        let exact = 636 + u32_le(&quote[632..636]) as usize;
        // The old fixture saved an 8000-byte kernel buffer. Its zero tail is not
        // part of the signed quote and is rejected by the production parser.
        assert!(quote[exact..].iter().all(|b| *b == 0));
        quote.truncate(exact);
        quote
    }

    #[test]
    fn authentic_intel_documents_and_pck_fields_are_decoded() {
        let evidence = collateral();
        let (tcb, identity) = authenticate_documents(&evidence, now()).unwrap();
        assert_eq!(tcb.tcb_evaluation_data_number, 20);
        assert_eq!(identity.tcb_evaluation_data_number, 20);
        check_document_window(&tcb.issue_date, &tcb.next_update, now()).unwrap();
        check_document_window(&identity.issue_date, &identity.next_update, now()).unwrap();
        let quote = captured_quote();
        let parts = QuoteParts::parse(&quote).unwrap();
        let certs = pki::parse_pem_chain(parts.pck_chain).unwrap();
        let pck = Certificate::from_der(&certs[0]).unwrap();
        let claims = PckTcb::parse(&pck).unwrap();
        assert_eq!(hex::encode(claims.fmspc), "00806f050000");
        assert_eq!(claims.pce_svn, 11);
        assert_eq!(
            claims.components,
            [8, 8, 2, 2, 4, 1, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        appraise_qe(&identity, parts.qe_report, now()).unwrap();
        let rejected = appraise_tdx(&quote, &evidence, now(), 20)
            .unwrap_err()
            .to_string();
        assert!(rejected.contains("OutOfDate"), "{rejected}");
    }

    #[test]
    fn signed_bytes_and_independent_evaluation_floor_cannot_be_substituted() {
        let mut evidence = collateral();
        let json = String::from_utf8(evidence.tcb_info_json.clone()).unwrap();
        evidence.tcb_info_json = json
            .replace(
                "\"tcbEvaluationDataNumber\":20",
                "\"tcbEvaluationDataNumber\":21",
            )
            .into_bytes();
        assert!(authenticate_documents(&evidence, now()).is_err());
        evidence = collateral();
        evidence.qe_identity_json = String::from_utf8(evidence.qe_identity_json)
            .unwrap()
            .replace("\"isvprodid\":2", "\"isvprodid\":1")
            .into_bytes();
        assert!(authenticate_documents(&evidence, now()).is_err());
        let quote = captured_quote();
        let error = appraise_tdx(&quote, &collateral(), now(), 21)
            .unwrap_err()
            .to_string();
        assert!(error.contains("policy floor"), "{error}");
        assert!(appraise_tdx(&quote, &collateral(), now(), 0).is_err());
        evidence = collateral();
        evidence.root_ca_crl.clear();
        assert!(appraise_tdx(&quote, &evidence, now(), 20).is_err());
        evidence = collateral();
        evidence.pck_crl.pop();
        assert!(appraise_tdx(&quote, &evidence, now(), 20).is_err());
    }

    #[test]
    fn qe_masks_svn_product_and_signer_are_mandatory() {
        let (_, identity) = authenticate_documents(&collateral(), now()).unwrap();
        let quote = captured_quote();
        let parts = QuoteParts::parse(&quote).unwrap();
        for index in [16, 48, 128, 256, 258] {
            let mut changed = parts.qe_report.to_vec();
            if index == 258 {
                changed[258..260].fill(0);
            } else {
                changed[index] ^= 2;
            }
            assert!(
                appraise_qe(&identity, &changed, now()).is_err(),
                "changed index {index}"
            );
        }
        let mut debug = parts.qe_report.to_vec();
        debug[48] |= 2;
        assert!(appraise_qe(&identity, &debug, now()).is_err());
    }

    #[test]
    fn module_identity_and_security_version_are_selected_from_signed_tcb_info() {
        let (tcb, _) = authenticate_documents(&collateral(), now()).unwrap();
        let quote = captured_quote();
        let parts = QuoteParts::parse(&quote).unwrap();
        appraise_module(&tcb, parts.body, now()).unwrap();
        for (index, value) in [(0, 0), (1, 0xff), (64, 1), (112, 1)] {
            let mut changed = parts.body.to_vec();
            changed[index] = value;
            assert!(
                appraise_module(&tcb, &changed, now()).is_err(),
                "changed index {index}"
            );
        }
        let mut outdated = parts.body.to_vec();
        outdated[0] = 6;
        let error = appraise_module(&tcb, &outdated, now())
            .unwrap_err()
            .to_string();
        assert!(error.contains("OutOfDate"), "{error}");
        for size in 0..quote.len() {
            assert!(QuoteParts::parse(&quote[..size]).is_err());
        }
    }

    #[test]
    fn expiry_ambiguity_and_unknown_structure_are_rejected() {
        assert_eq!(parse_time("1970-01-01T00:00:00Z").unwrap(), 0);
        for date in [
            "2026-02-30T00:00:00Z",
            "2026-01-01T00:00:60Z",
            "2026-01-01T00:00:00+00:00",
            "2026-1-01T00:00:00Z",
        ] {
            assert!(parse_time(date).is_err());
        }
        let (tcb, _) = authenticate_documents(&collateral(), now()).unwrap();
        assert!(check_document_window(
            &tcb.issue_date,
            &tcb.next_update,
            parse_time(&tcb.next_update).unwrap()
        )
        .is_err());
        assert!(check_document_window(&tcb.issue_date, &tcb.next_update, 0).is_err());
        let bytes = br#"{"tcbInfo":{},"tcbInfo":{},"signature":"00"}"#;
        assert!(serde_json::from_slice::<SignedTcb>(bytes).is_err());
        let unknown = br#"{"tcbInfo":{},"signature":"00","extra":true}"#;
        assert!(serde_json::from_slice::<SignedTcb>(unknown).is_err());
        let mut evidence = collateral();
        // Reformatting authenticated JSON is forbidden: signatures cover bytes.
        let envelope: SignedTcb = serde_json::from_slice(&evidence.tcb_info_json).unwrap();
        evidence.tcb_info_json = String::from_utf8(evidence.tcb_info_json)
            .unwrap()
            .replacen(
                envelope.tcb_info.get(),
                &format!("{{ {}", &envelope.tcb_info.get()[1..]),
                1,
            )
            .into_bytes();
        assert!(authenticate_documents(&evidence, now()).is_err());
        let mut quote = captured_quote();
        quote[0] = 5;
        assert!(QuoteParts::parse(&quote).is_err());
    }
}
