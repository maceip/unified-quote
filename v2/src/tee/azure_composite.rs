//! Azure HCL SNP endorsement plus a fresh vTPM quote.
//!
//! HCL is generated at boot: it authenticates the paravisor and its AK, not a
//! current request. This profile additionally requires an AK-signed quote over
//! a domain-separated hash of the complete 64-byte EAT report data, current AMD
//! admission, and independent AK, VM, paravisor and exact PCR policy.
//! See `AZURE_COMPOSITE.md` for supported formats and assurance boundaries.

use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rsa::{pkcs8::EncodePublicKey, traits::PublicKeyParts, BigUint, Pkcs1v15Sign, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    boot::AuthenticatedRegisters,
    quote::{
        snp_collateral::{SnpCollateral, SnpTcbPolicy},
        verify::{verify_platform_quote_for_admission, CpuCollateral, CpuTcbPolicy},
        Platform,
    },
};

mod collector;
pub use collector::collect;
pub use collector::AzureCompositeCollector;

const HCL_HEADER: usize = 32;
const SNP_SIZE: usize = 1184;
const RUNTIME_OFFSET: usize = HCL_HEADER + SNP_SIZE;
const CLAIMS_OFFSET: usize = RUNTIME_OFFSET + 20;
const HCL_NV_SIZE: usize = 2600;
const MAX_QUOTE: usize = 4096;
const MAX_SIGNATURE: usize = 518;
const MAX_WIRE: usize = 48 * 1024;
const SHA256: u16 = 0x000b;
const RSASSA: u16 = 0x0014;
const CHALLENGE_DOMAIN: &[u8] = b"uq/azure-hcl-vtpm/eat-report-data/v1\0";

/// SHA-256 bank PCR. No supplied index/value is trusted until the signed quote
/// digest and independently provisioned policy both agree with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AzurePcrValue {
    pub index: u8,
    pub value: [u8; 32],
}

/// Evidence only; policy and AMD collateral are supplied separately.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AzureCompositeEvidence {
    pub version: u32,
    #[serde(with = "serde_bytes")]
    pub hcl_report: Vec<u8>,
    /// Raw TPMS_ATTEST, without a TPM2B size prefix.
    #[serde(with = "serde_bytes")]
    pub quote_message: Vec<u8>,
    /// TPMT_SIGNATURE, with RSASSA and SHA-256 algorithm identifiers.
    #[serde(with = "serde_bytes")]
    pub quote_signature: Vec<u8>,
    /// Strictly increasing indices, exactly matching the signed selection.
    pub pcrs: Vec<AzurePcrValue>,
}

impl AzureCompositeEvidence {
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_WIRE,
            "Azure evidence JSON exceeds bounds"
        );
        let evidence: Self = serde_json::from_slice(bytes).context("Azure evidence JSON")?;
        evidence.validate_bounds()?;
        Ok(evidence)
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        self.validate_bounds()?;
        let encoded = serde_json::to_vec(self)?;
        ensure!(
            encoded.len() <= MAX_WIRE,
            "Azure evidence JSON exceeds bounds"
        );
        Ok(encoded)
    }

    fn validate_bounds(&self) -> Result<()> {
        ensure!(
            self.version == 1,
            "unsupported Azure composite evidence version"
        );
        ensure!(
            (CLAIMS_OFFSET + 1..=HCL_NV_SIZE).contains(&self.hcl_report.len()),
            "HCL size outside supported NV profile"
        );
        ensure!(
            !self.quote_message.is_empty() && self.quote_message.len() <= MAX_QUOTE,
            "Azure TPM quote size outside bounds"
        );
        ensure!(
            (262..=MAX_SIGNATURE).contains(&self.quote_signature.len()),
            "Azure TPM signature size outside bounds"
        );
        pcr_values(&self.pcrs)?;
        Ok(())
    }
}

/// Verifier-owned enrollment. These values must never be copied from the
/// evidence being evaluated. No wildcard AK, model, VM or PCR policy exists.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AzureCompositePolicy {
    pub version: u32,
    /// SHA-256 of DER SubjectPublicKeyInfo for independently enrolled HCLAkPub.
    pub allowed_ak_spki_sha256: Vec<String>,
    /// Independently provisioned raw TPMT_PUBLIC bytes (without TPM2B size),
    /// one per SPKI pin. Enrollment MUST confirm these actual object attributes
    /// through a trusted provisioning channel; reconstructing a template from
    /// an untrusted evidence JWK does not establish the restricted-key role.
    pub enrolled_ak_public_areas: Vec<Vec<u8>>,
    /// AMD SNP launch measurements of approved Azure paravisor/UEFI images,
    /// each exactly 48 bytes encoded as hex. These are not workload digests.
    pub allowed_paravisor_measurements: Vec<String>,
    /// Independently enrolled UUID, compared case-insensitively as UUID bytes.
    pub expected_vm_id: String,
    /// SHA-256 PCR values of the approved guest profile, in increasing order.
    /// The quoted selection must equal this set, not merely contain it.
    pub expected_pcrs: Vec<AzurePcrValue>,
    /// Console access is permitted only by explicit verifier configuration.
    pub allow_console: bool,
}

impl AzureCompositePolicy {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1,
            "unsupported Azure composite policy version"
        );
        self.enrolled_ak_names()?;
        hex_allowlist(
            &self.allowed_paravisor_measurements,
            48,
            "paravisor measurement",
        )?;
        vm_id(&self.expected_vm_id)?;
        pcr_values(&self.expected_pcrs)?;
        // Zero is a legitimate value for an unused PCR, but an entirely empty
        // measured-boot profile is not an independently approved guest image.
        ensure!(
            self.expected_pcrs
                .iter()
                .any(|pcr| pcr.value.iter().any(|b| *b != 0)),
            "Azure PCR policy cannot be entirely zero"
        );
        Ok(())
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= 128 * 1024,
            "Azure policy JSON exceeds bounds"
        );
        let policy: Self = serde_json::from_slice(bytes).context("Azure policy JSON")?;
        policy.validate()?;
        Ok(policy)
    }

    fn enrolled_ak_names(&self) -> Result<BTreeMap<[u8; 32], [u8; 34]>> {
        let pins = hex_allowlist(&self.allowed_ak_spki_sha256, 32, "AK SPKI")?;
        ensure!(
            self.enrolled_ak_public_areas.len() == pins.len(),
            "Azure AK public-area enrollment must match every SPKI pin exactly once"
        );
        let mut names = BTreeMap::new();
        for area in &self.enrolled_ak_public_areas {
            let (pin, name) = enrolled_ak_name(area)?;
            ensure!(
                pins.contains(pin.as_slice()),
                "enrolled AK public area differs from SPKI pin policy"
            );
            ensure!(
                names.insert(pin, name).is_none(),
                "duplicate enrolled AK public area"
            );
        }
        Ok(names)
    }
}

/// Only `verify` constructs this result, after both signatures, current AMD
/// collateral, full challenge binding, VM enrollment and exact PCR appraisal.
/// It authenticates these layers; application build/boot policies remain the
/// caller's responsibility and the result is not a complete EAT verdict.
#[derive(Debug)]
pub struct VerifiedAzureComposite {
    measurements: BTreeMap<String, Vec<u8>>,
    pcrs: Vec<AzurePcrValue>,
    ak_spki_sha256: [u8; 32],
    vm_id: String,
    clock: AzureClockInfo,
}

/// Authenticated TPM clock metadata. Nonce freshness comes from the caller's
/// independently issued EAT challenge, not from this clock or HCL timestamps.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct AzureClockInfo {
    pub clock: u64,
    pub reset_count: u32,
    pub restart_count: u32,
    pub firmware_version: u64,
}

impl VerifiedAzureComposite {
    pub fn measurements(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.measurements
    }
    pub fn pcrs(&self) -> &[AzurePcrValue] {
        &self.pcrs
    }
    pub fn ak_spki_sha256(&self) -> &[u8; 32] {
        &self.ak_spki_sha256
    }
    pub fn vm_id(&self) -> &str {
        &self.vm_id
    }
    pub fn clock(&self) -> AzureClockInfo {
        self.clock
    }

    pub fn authenticated_registers(&self) -> Result<AuthenticatedRegisters> {
        Ok(AuthenticatedRegisters::tpm(
            self.pcrs
                .iter()
                .map(|pcr| ((SHA256, u32::from(pcr.index)), pcr.value.to_vec()))
                .collect(),
        )?)
    }
}

/// Fresh TPM qualifyingData for this wire profile. Hashes both halves of the
/// EAT commitment, including its challenge; never pass only Value X or SPKI.
pub fn qualifying_data(report_data: &[u8; 64]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(CHALLENGE_DOMAIN);
    digest.update(report_data);
    digest.finalize().into()
}

/// Verify the current Azure composite profile. The caller supplies the EAT's
/// complete independently reconstructed report_data (including fresh nonce),
/// trusted enrollment, AMD vendor collateral and a separate current TCB floor.
/// This entry point has no historical-clock override and performs no network I/O.
pub fn verify(
    evidence: &AzureCompositeEvidence,
    expected_report_data: &[u8; 64],
    policy: &AzureCompositePolicy,
    collateral: &SnpCollateral,
    tcb_policy: &SnpTcbPolicy,
) -> Result<VerifiedAzureComposite> {
    evidence.validate_bounds()?;
    policy.validate()?;
    collateral.validate_bounds()?;
    tcb_policy.validate()?;
    ensure!(
        expected_report_data[..32].iter().any(|b| *b != 0)
            && expected_report_data[32..].iter().any(|b| *b != 0),
        "Azure requires both halves of the EAT commitment"
    );
    // HCL executes at VMPL0, independently of any caller's looser SNP profile.
    ensure!(
        tcb_policy.expected_vmpl == 0,
        "Azure HCL policy requires VMPL0"
    );
    let hcl = parse_hcl(&evidence.hcl_report)?;
    let claims = parse_claims(hcl.claims)?;
    let ak = claims.ak_key()?;
    let ak_pin: [u8; 32] = Sha256::digest(ak.to_public_key_der()?.as_bytes()).into();
    let ak_pins = hex_allowlist(&policy.allowed_ak_spki_sha256, 32, "AK SPKI")?;
    ensure!(
        ak_pins.contains(ak_pin.as_slice()),
        "HCL AK is not independently enrolled"
    );
    claims.check_policy(policy)?;
    let paravisors = hex_allowlist(
        &policy.allowed_paravisor_measurements,
        48,
        "paravisor measurement",
    )?;
    ensure!(
        paravisors.contains(&hcl.report[0x90..0xc0]),
        "HCL paravisor measurement is not approved"
    );

    // Early structural and RSA checks do not create an authenticated result.
    // Both trust chains below must succeed before any PCR/identity is exposed.
    let quote = verify_quote(&ak, evidence, expected_report_data)?;
    let enrolled_names = policy.enrolled_ak_names()?;
    ensure!(quote.qualified_signer == enrolled_names.get(&ak_pin).context("HCL AK public area is not enrolled")?, "TPM qualified signer differs from the independently enrolled restricted endorsement primary");
    ensure!(
        evidence.pcrs == policy.expected_pcrs,
        "Azure guest PCR values do not satisfy independent policy"
    );
    let runtime_hash: [u8; 32] = Sha256::digest(hcl.claims).into();
    let cpu_measurements = verify_platform_quote_for_admission(
        Platform::SevSnp,
        hcl.report,
        &runtime_hash,
        Some(&CpuCollateral::AmdSnp(collateral.clone())),
        Some(&CpuTcbPolicy::AmdSnp(tcb_policy.clone())),
    )
    .context("Azure AMD endorsement and current TCB appraisal")?;
    let mut measurements: BTreeMap<_, _> = cpu_measurements.into_iter().collect();
    for pcr in &evidence.pcrs {
        measurements.insert(format!("TPM_PCR{}", pcr.index), pcr.value.to_vec());
    }
    measurements.insert("AZURE_AK_SPKI_SHA256".into(), ak_pin.to_vec());
    measurements.insert(
        "AZURE_AK_QUALIFIED_NAME".into(),
        quote.qualified_signer.to_vec(),
    );
    measurements.insert(
        "AZURE_EAT_REPORT_DATA".into(),
        expected_report_data.to_vec(),
    );
    Ok(VerifiedAzureComposite {
        measurements,
        pcrs: evidence.pcrs.clone(),
        ak_spki_sha256: ak_pin,
        vm_id: hex_uuid(vm_id(&claims.configuration.vm_unique_id)?),
        clock: quote.clock,
    })
}

#[derive(Debug)]
struct Hcl<'a> {
    report: &'a [u8],
    claims: &'a [u8],
}

fn parse_hcl(bytes: &[u8]) -> Result<Hcl<'_>> {
    ensure!(
        (CLAIMS_OFFSET + 1..=HCL_NV_SIZE).contains(&bytes.len()),
        "HCL size outside supported profile"
    );
    let le = |offset: usize| {
        u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .expect("checked HCL header"),
        )
    };
    ensure!(
        le(0) == 0x414c_4348 && le(4) == 2 && le(12) == 2,
        "unsupported HCL signature/version/request type"
    );
    ensure!(
        bytes[16..32].iter().all(|b| *b == 0),
        "nonzero HCL reserved/status field"
    );
    let size = le(8) as usize;
    ensure!(
        (CLAIMS_OFFSET + 1..=bytes.len()).contains(&size),
        "HCL report size outside supplied bytes"
    );
    // The documented NV buffer may contain zeros after the explicit report.
    // No other padding/cropping profile or nonzero trailing data is accepted.
    ensure!(
        size == bytes.len()
            || (bytes.len() == HCL_NV_SIZE && bytes[size..].iter().all(|b| *b == 0)),
        "HCL trailing bytes are not documented NV padding"
    );
    ensure!(
        le(RUNTIME_OFFSET + 4) == 1 && le(RUNTIME_OFFSET + 8) == 2 && le(RUNTIME_OFFSET + 12) == 1,
        "unsupported HCL runtime version/report/hash profile"
    );
    let runtime_size = le(RUNTIME_OFFSET) as usize;
    let claims_size = le(RUNTIME_OFFSET + 16) as usize;
    ensure!(
        runtime_size == size - RUNTIME_OFFSET && claims_size == size - CLAIMS_OFFSET,
        "HCL runtime/claim lengths disagree"
    );
    let report = &bytes[HCL_HEADER..RUNTIME_OFFSET];
    let claims = &bytes[CLAIMS_OFFSET..size];
    let hash = Sha256::digest(claims);
    ensure!(
        report[0x50..0x70] == hash[..] && report[0x70..0x90].iter().all(|b| *b == 0),
        "HCL REPORT_DATA must equal SHA256(exact runtime claims) followed by zero padding"
    );
    Ok(Hcl { report, claims })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeClaims {
    keys: Vec<RuntimeKey>,
    #[serde(rename = "vm-configuration")]
    configuration: VmConfiguration,
    #[serde(rename = "user-data")]
    user_data: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeKey {
    kid: String,
    key_ops: Vec<String>,
    kty: String,
    e: String,
    n: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VmConfiguration {
    #[serde(rename = "root-cert-thumbprint")]
    root_cert_thumbprint: String,
    #[serde(rename = "console-enabled")]
    console_enabled: bool,
    #[serde(rename = "secure-boot")]
    secure_boot: bool,
    #[serde(rename = "tpm-enabled")]
    tpm_enabled: bool,
    #[serde(rename = "tpm-persisted")]
    tpm_persisted: bool,
    #[serde(rename = "vmUniqueId")]
    vm_unique_id: String,
    // Authenticated historical metadata, never a clock/freshness source.
    #[serde(rename = "current-time")]
    _current_time: Option<u64>,
}

fn parse_claims(bytes: &[u8]) -> Result<RuntimeClaims> {
    // Typed deserialization rejects duplicate and unknown keys at every level.
    let claims: RuntimeClaims =
        serde_json::from_slice(bytes).context("unsupported HCL runtime claim schema")?;
    ensure!(
        claims.keys.len() == 2,
        "HCL profile requires exactly AK and EK JWKs"
    );
    let mut seen = BTreeSet::new();
    for key in &claims.keys {
        ensure!(seen.insert(key.kid.as_str()), "duplicate HCL JWK identity");
        let operation = match key.kid.as_str() {
            "HCLAkPub" => "sign",
            "HCLEkPub" => "encrypt",
            _ => anyhow::bail!("unsupported HCL JWK identity"),
        };
        ensure!(
            key.kty == "RSA" && key.key_ops == [operation],
            "unsupported HCL JWK type/operation"
        );
        key.rsa()?;
    }
    ensure!(
        claims.user_data.len() == 128 && claims.user_data.bytes().all(|b| b.is_ascii_hexdigit()),
        "HCL user-data is not exactly 64 bytes of hex"
    );
    let thumbprint = &claims.configuration.root_cert_thumbprint;
    ensure!(
        thumbprint.is_empty()
            || ((thumbprint.len() == 40 || thumbprint.len() == 64)
                && thumbprint.bytes().all(|b| b.is_ascii_hexdigit())),
        "unsupported HCL root thumbprint encoding"
    );
    vm_id(&claims.configuration.vm_unique_id)?;
    Ok(claims)
}
impl RuntimeKey {
    fn rsa(&self) -> Result<RsaPublicKey> {
        ensure!(
            (342..=683).contains(&self.n.len()) && self.e == "AQAB",
            "HCL RSA key size/exponent outside profile"
        );
        let modulus = URL_SAFE_NO_PAD
            .decode(&self.n)
            .context("HCL RSA modulus base64url")?;
        ensure!(
            matches!(modulus.len(), 256 | 384 | 512) && modulus[0] & 0x80 != 0,
            "HCL RSA modulus must have exactly 2048/3072/4096 bits"
        );
        ensure!(
            URL_SAFE_NO_PAD.encode(&modulus) == self.n,
            "noncanonical HCL RSA JWK modulus"
        );
        let key = RsaPublicKey::new(BigUint::from_bytes_be(&modulus), BigUint::from(65537u32))?;
        Ok(key)
    }
}
impl RuntimeClaims {
    fn ak_key(&self) -> Result<RsaPublicKey> {
        self.keys
            .iter()
            .find(|key| key.kid == "HCLAkPub")
            .context("missing HCL AK")?
            .rsa()
    }
    fn check_policy(&self, policy: &AzureCompositePolicy) -> Result<()> {
        ensure!(
            self.configuration.secure_boot
                && self.configuration.tpm_enabled
                && self.configuration.tpm_persisted,
            "HCL secure boot/TPM/persistence must be enabled"
        );
        ensure!(
            !self.configuration.console_enabled || policy.allow_console,
            "HCL console access is forbidden by policy"
        );
        ensure!(
            vm_id(&self.configuration.vm_unique_id)? == vm_id(&policy.expected_vm_id)?,
            "HCL VM identity differs from enrollment"
        );
        Ok(())
    }
}

struct ParsedQuote<'a> {
    qualified_signer: &'a [u8],
    extra_data: &'a [u8],
    indices: Vec<u8>,
    digest: &'a [u8],
    clock: AzureClockInfo,
}

fn parse_quote(message: &[u8]) -> Result<ParsedQuote<'_>> {
    ensure!(
        !message.is_empty() && message.len() <= MAX_QUOTE,
        "TPMS_ATTEST size outside bounds"
    );
    let mut reader = Reader {
        bytes: message,
        offset: 0,
    };
    ensure!(
        reader.u32()? == 0xff54_4347 && reader.u16()? == 0x8018,
        "TPMS_ATTEST magic/type mismatch"
    );
    let signer = reader.tpm2b()?;
    ensure!(
        signer.len() == 34
            && signer[..2] == SHA256.to_be_bytes()
            && signer[2..].iter().any(|b| *b != 0),
        "unsupported TPM AK qualified-name profile"
    );
    let extra_data = reader.tpm2b()?;
    ensure!(
        extra_data.len() == 32,
        "TPM qualifyingData must be exactly 32 bytes"
    );
    let clock = reader.u64()?;
    let reset_count = reader.u32()?;
    let restart_count = reader.u32()?;
    ensure!(reader.u8()? == 1, "TPM clockInfo.safe must be true");
    let firmware_version = reader.u64()?;
    ensure!(
        reader.u32()? == 1 && reader.u16()? == SHA256,
        "exactly one SHA256 PCR bank is required"
    );
    ensure!(
        reader.u8()? == 3,
        "PCR selection must use the 24-bit PC-client bitmap"
    );
    let bitmap = reader.take(3)?;
    ensure!(bitmap[2] == 0, "only static PCRs 0..15 are supported");
    let indices: Vec<u8> = (0u8..16)
        .filter(|i| bitmap[usize::from(*i / 8)] & (1 << (i % 8)) != 0)
        .collect();
    ensure!(!indices.is_empty(), "TPM quote cannot select no PCRs");
    let digest = reader.tpm2b()?;
    ensure!(
        digest.len() == 32 && reader.offset == message.len(),
        "TPM PCR digest length or trailing data mismatch"
    );
    Ok(ParsedQuote {
        qualified_signer: signer,
        extra_data,
        indices,
        digest,
        clock: AzureClockInfo {
            clock,
            reset_count,
            restart_count,
            firmware_version,
        },
    })
}

fn verify_quote<'a>(
    ak: &RsaPublicKey,
    evidence: &'a AzureCompositeEvidence,
    expected_report_data: &[u8; 64],
) -> Result<ParsedQuote<'a>> {
    let quote = parse_quote(&evidence.quote_message)?;
    ensure!(
        quote.extra_data == qualifying_data(expected_report_data),
        "Azure TPM quote does not bind the complete expected EAT report data"
    );
    let pcrs = pcr_values(&evidence.pcrs)?;
    ensure!(
        quote.indices.iter().copied().eq(pcrs.keys().copied()),
        "PCR evidence coverage differs from signed selection"
    );
    let mut hash = Sha256::new();
    for value in pcrs.values() {
        hash.update(value);
    }
    ensure!(
        quote.digest == hash.finalize().as_slice(),
        "PCR values do not reproduce the signed TPM digest"
    );
    let mut signature = Reader {
        bytes: &evidence.quote_signature,
        offset: 0,
    };
    ensure!(
        signature.u16()? == RSASSA && signature.u16()? == SHA256,
        "TPM signature must be RSASSA/SHA256"
    );
    let raw_signature = signature.tpm2b()?;
    ensure!(
        raw_signature.len() == ak.size() && signature.offset == evidence.quote_signature.len(),
        "TPM signature size/trailing data mismatch"
    );
    ak.verify(
        Pkcs1v15Sign::new::<Sha256>(),
        &Sha256::digest(&evidence.quote_message),
        raw_signature,
    )
    .context("Azure AK quote signature")?;
    Ok(quote)
}

fn pcr_values(values: &[AzurePcrValue]) -> Result<BTreeMap<u8, [u8; 32]>> {
    ensure!(
        !values.is_empty() && values.len() <= 16,
        "Azure PCR count must be 1..16"
    );
    ensure!(
        values.iter().all(|pcr| pcr.index < 16)
            && values.windows(2).all(|pair| pair[0].index < pair[1].index),
        "Azure PCR indices must be unique, increasing and within 0..15"
    );
    Ok(values.iter().map(|pcr| (pcr.index, pcr.value)).collect())
}

/// Microsoft OpenVMM 1e5ed0ad... tpm_lib::ak_pub_template and
/// create_key_object: a restricted RSA2048/SHA256 endorsement primary.
/// Parsing independently enrolled TPMT_PUBLIC is essential: HCL's RSA JWK
/// omits object attributes, and an unrestricted key can sign fabricated quotes.
fn enrolled_ak_name(public_area: &[u8]) -> Result<([u8; 32], [u8; 34])> {
    ensure!(
        public_area.len() == 280,
        "Azure enrolled AK must use the exact RSA2048 TPMT_PUBLIC profile"
    );
    let mut reader = Reader {
        bytes: public_area,
        offset: 0,
    };
    ensure!(
        reader.u16()? == 0x0001 && reader.u16()? == SHA256,
        "Azure enrolled AK must use RSA and SHA256 nameAlg"
    );
    // fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | noDA |
    // restricted | signEncrypt; no decrypt/exportable/unknown attributes.
    ensure!(
        reader.u32()? == 0x0005_0472,
        "Azure enrolled AK attributes are not the Microsoft restricted signing profile"
    );
    ensure!(
        reader.tpm2b()?.is_empty(),
        "Azure enrolled AK authPolicy must match the published primary template"
    );
    ensure!(
        reader.u16()? == 0x0010
            && reader.u16()? == RSASSA
            && reader.u16()? == SHA256
            && reader.u16()? == 2048
            && reader.u32()? == 0,
        "Azure enrolled AK RSA parameters differ from the published template"
    );
    let modulus = reader.tpm2b()?;
    ensure!(
        modulus.len() == 256 && modulus[0] & 0x80 != 0 && reader.offset == public_area.len(),
        "Azure enrolled AK modulus/length mismatch"
    );
    let key = RsaPublicKey::new(BigUint::from_bytes_be(modulus), BigUint::from(65537u32))?;
    let pin = Sha256::digest(key.to_public_key_der()?.as_bytes()).into();
    let mut name = [0u8; 34];
    name[..2].copy_from_slice(&SHA256.to_be_bytes());
    name[2..].copy_from_slice(&Sha256::digest(public_area));
    let mut hash = Sha256::new();
    // QN(primary) = nameAlg || H(TPM_RH_ENDORSEMENT || Name(primary)).
    hash.update(0x4000_000bu32.to_be_bytes());
    hash.update(name);
    let mut qualified_name = [0u8; 34];
    qualified_name[..2].copy_from_slice(&SHA256.to_be_bytes());
    qualified_name[2..].copy_from_slice(&hash.finalize());
    Ok((pin, qualified_name))
}

fn hex_allowlist(values: &[String], size: usize, name: &str) -> Result<BTreeSet<Vec<u8>>> {
    ensure!(
        !values.is_empty() && values.len() <= 64,
        "Azure {name} allowlist must contain 1..64 entries"
    );
    let mut result = BTreeSet::new();
    for value in values {
        ensure!(value.len() == size * 2, "Azure {name} pin has wrong length");
        let decoded = hex::decode(value).with_context(|| format!("Azure {name} pin is not hex"))?;
        ensure!(
            decoded.iter().any(|b| *b != 0) && decoded.iter().any(|b| *b != 0xff),
            "Azure {name} pin is a placeholder"
        );
        ensure!(result.insert(decoded), "duplicate Azure {name} pin");
    }
    Ok(result)
}
fn vm_id(value: &str) -> Result<[u8; 16]> {
    ensure!(
        value.len() == 36
            && value
                .bytes()
                .enumerate()
                .all(|(i, b)| if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }),
        "Azure VM identity must be a UUID"
    );
    let hex: String = value.chars().filter(|c| *c != '-').collect();
    let id: [u8; 16] = hex::decode(hex)?
        .try_into()
        .expect("UUID hex length checked");
    ensure!(
        id.iter().any(|b| *b != 0) && id.iter().any(|b| *b != 0xff),
        "Azure VM identity cannot be a placeholder"
    );
    Ok(id)
}
fn hex_uuid(value: [u8; 16]) -> String {
    let hex = hex::encode(value);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}
struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(count)
            .context("TPM offset overflow")?;
        let value = self
            .bytes
            .get(self.offset..end)
            .context("truncated TPM attestation")?;
        self.offset = end;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into()?))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into()?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into()?))
    }
    fn tpm2b(&mut self) -> Result<&'a [u8]> {
        let length = usize::from(self.u16()?);
        self.take(length)
    }
}

#[cfg(test)]
mod tests;
