//! Production composite collection and appraisal. Verifier policy and challenge
//! are supplied by the relying party, independently of the received token.
use crate::{
    boot::{self, AuthenticatedRegisters, CommandLineProfile, EventLog, ParseLimits},
    eat::{BuildComponents, EatToken, BINDING_SUITE_COMPOSITE},
    quote::{
        verify::{verify_platform_quote_for_admission, CpuCollateral, CpuTcbPolicy},
        Platform,
    },
    tee,
};
use anyhow::{ensure, Context, Result};
use der::Decode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuTopologyMode {
    AutoDetect,
    Independent,
    ProtectedPcie,
}

#[derive(Default)]
pub struct AttestationCollectorBuilder {
    nonce: Option<[u8; 32]>,
    spki: Vec<u8>,
    value_x: Option<[u8; 48]>,
    boot: Vec<u8>,
    build_claims: Option<BuildClaims>,
    cpu_profile: tee::composite::CpuCollectionProfile,
    #[cfg(feature = "tdx")]
    google_tdx_collector: Option<(crate::google_backend::GoogleVerifier, crate::google_backend::TdxTransport)>,
    #[cfg(feature = "gpu")]
    topology: Option<GpuTopologyMode>,
    #[cfg(feature = "gpu")]
    collateral: Option<crate::gpu::GpuCollateral>,
}
pub struct AttestationCollector {
    config: AttestationCollectorBuilder,
}
/// Producer claims committed to the CPU quote and compared with independently
/// approved stage policy at verification time.
pub struct BuildClaims {
    pub source_hash: [u8; 48],
    pub artifact_hash: [u8; 48],
    pub previous_attestation: Vec<u8>,
}
impl AttestationCollector {
    pub fn builder() -> AttestationCollectorBuilder {
        AttestationCollectorBuilder::default()
    }
    /// Collect all GPU/switch evidence first, then ask the CPU to sign its exact
    /// commitment. This does not appraise the resulting evidence.
    pub fn collect(&self) -> Result<EatToken> {
        let cfg = &self.config;
        let nonce = cfg.nonce.context("missing nonce")?;
        use tee::composite::CpuCollectionProfile;
        #[cfg(feature = "tdx")]
        let google_collection = cfg.google_tdx_collector.is_some();
        #[cfg(not(feature = "tdx"))]
        let google_collection = false;
        let provider = match &cfg.cpu_profile {
            CpuCollectionProfile::Direct if !google_collection => Some(tee::detect::detect_tee()?),
            _ => None,
        };
        let platform = match &cfg.cpu_profile {
            CpuCollectionProfile::Direct if google_collection => Platform::Tdx,
            CpuCollectionProfile::Direct => provider
                .as_ref()
                .context("missing direct provider")?
                .platform(),
            CpuCollectionProfile::AzureSnpVtpm { .. } => Platform::AzureSnpVtpm,
            CpuCollectionProfile::AwsSnpNitroTpm => Platform::AwsSnpNitroTpm,
        };
        let mut token = EatToken::from_build_with_nonce(
            BuildComponents {
                platform,
                value_x: cfg.value_x.context("missing Value X")?,
                source_hash: [0; 48],
                artifact_hash: [0; 48],
                platform_measurement: Vec::new(),
                platform_quote: Vec::new(),
            },
            nonce,
        );
        token.iat = trusted_now()?;
        token.tls_spki_hash = Sha256::digest(&cfg.spki).into();
        token.binding_suite = BINDING_SUITE_COMPOSITE;
        token.boot_evidence = cfg.boot.clone();
        if let Some(build) = &cfg.build_claims {
            token.source_hash = build.source_hash;
            token.artifact_hash = build.artifact_hash;
            token.previous_attestation = build.previous_attestation.clone();
        }
        #[cfg(feature = "gpu")]
        if let Some(topology) = cfg.topology {
            let mut bundle = crate::gpu::NvmlCollector::open()?.collect(nonce)?;
            let fabric = match topology {
                GpuTopologyMode::Independent => false,
                GpuTopologyMode::ProtectedPcie => true,
                GpuTopologyMode::AutoDetect => {
                    let mut modes = Vec::new();
                    for gpu in &bundle.gpus {
                        let report = crate::gpu::spdm::SpdmReport::parse(&gpu.attestation_report)?;
                        modes.push(
                            crate::gpu::opaque::OpaqueData::parse(report.opaque_data())?.mode()?,
                        );
                    }
                    let fabric = modes.contains(&crate::gpu::opaque::ConfidentialMode::Ppcie);
                    ensure!(
                        !fabric
                            || modes
                                .iter()
                                .all(|m| *m == crate::gpu::opaque::ConfidentialMode::Ppcie),
                        "mixed GPU topology during collection"
                    );
                    fabric
                }
            };
            if fabric {
                bundle.switches = crate::gpu::nscq::NscqCollector::open()?.collect(nonce)?;
                ensure!(
                    !bundle.switches.is_empty(),
                    "PPCIE collection requires NVSwitch evidence"
                );
            }
            bundle.collateral = if let Some(collateral) = &cfg.collateral {
                collateral.clone()
            } else {
                // Fresh vendor acquisition is the default production source.
                // A caller can explicitly supply signed collateral instead;
                // it still receives full appraisal at the relying party.
                let client = crate::gpu::collateral::NvidiaCollateralClient::new()?;
                let mut cache = crate::gpu::collateral::CollateralCache::default();
                client.acquire_for_bundle(&bundle, &nonce, trusted_now()?, &mut cache)?
            };
            ciborium::ser::into_writer(&bundle, &mut token.gpu_evidence)?;
        }
        token.iat = trusted_now()?;
        token.validate_shape()?;
        let report_data = token.report_data_64(None);
        match &cfg.cpu_profile {
            CpuCollectionProfile::AzureSnpVtpm { pcr_indices } => {
                #[cfg(feature = "sev-snp")]
                {
                    let evidence = tee::azure_composite::collect(&report_data, pcr_indices)?;
                    token.platform_quote = serde_json::to_vec(&evidence)?;
                }
                #[cfg(not(feature = "sev-snp"))]
                anyhow::bail!("Azure collection requires sev-snp support");
            }
            CpuCollectionProfile::AwsSnpNitroTpm => {
                #[cfg(all(feature = "sev-snp", feature = "nitro", unix))]
                {
                    use tee::TeeProvider;
                    let snp = tee::snp::SnpProvider::new()?.collect_evidence(&report_data)?;
                    ensure!(snp.platform == Platform::SevSnp, "unexpected SNP provider");
                    let evidence = tee::composite::AwsSnpNitroTpmEvidence {
                        version: 1,
                        snp_report: snp.raw_quote,
                        nitrotpm_document: tee::tpm::collect_nitrotpm_document(
                            &nonce,
                            Some(&report_data),
                        )?,
                    };
                    evidence.validate()?;
                    token.platform_measurement = evidence.snp_report[0x90..0xc0].to_vec();
                    token.platform_quote = serde_json::to_vec(&evidence)?;
                }
                #[cfg(not(all(feature = "sev-snp", feature = "nitro", unix)))]
                anyhow::bail!("AWS composite collection requires Unix and sev-snp,nitro support");
            }
            CpuCollectionProfile::Direct => {}
        }
        if platform == Platform::AzureSnpVtpm || platform == Platform::AwsSnpNitroTpm {
            token.validate_shape()?;
            return Ok(token);
        }
        #[cfg(feature = "tdx")]
        if let Some((google, transport)) = &cfg.google_tdx_collector {
            let quote = google.collect_tdx(*transport, &report_data)?;
            let start = crate::google_backend::tdx_body_offset(&quote)?;
            // These are unverified collection observations. Admission verifies
            // the quote and compares its signed measurement independently.
            token.platform_measurement = quote[start + 136..start + 184].to_vec();
            token.platform_quote = quote;
            token.validate_shape()?;
            return Ok(token);
        }
        let quote = provider
            .context("missing direct provider")?
            .collect_evidence(&report_data)?;
        ensure!(
            quote.platform == platform,
            "CPU platform changed during collection"
        );
        // Do not put a local TDREPORT (MAC only) in a field advertised as a
        // remotely verifiable TDQUOTE.
        if quote.platform == Platform::Tdx {
            ensure!(
                quote.raw_quote.len() >= 636
                    && quote.raw_quote[..2] == [4, 0]
                    && quote.raw_quote[4..8] == [0x81, 0, 0, 0],
                "TDX collection did not return a v4 signed quote; configure configfs-TSM/QGS"
            );
            let sig_len = u32::from_le_bytes(quote.raw_quote[632..636].try_into()?) as usize;
            ensure!(
                sig_len > 0 && sig_len == quote.raw_quote.len() - 636,
                "incomplete TDX quote signature data"
            );
            token.platform_measurement = quote.raw_quote[184..232].to_vec();
        } else if quote.platform == Platform::SevSnp {
            ensure!(
                quote.raw_quote.len() >= 1184,
                "incomplete SNP attestation report"
            );
            token.platform_measurement = quote.raw_quote[0x90..0xc0].to_vec();
        }
        token.platform_quote = quote.raw_quote;
        token.validate_shape()?;
        Ok(token)
    }
}
impl AttestationCollectorBuilder {
    pub fn with_nonce(mut self, nonce: &[u8; 32]) -> Self {
        self.nonce = Some(*nonce);
        self
    }
    pub fn with_tls_spki_der(mut self, spki: &[u8]) -> Self {
        self.spki = spki.to_vec();
        self
    }
    pub fn with_value_x(mut self, value: &[u8; 48]) -> Self {
        self.value_x = Some(*value);
        self
    }
    pub fn with_boot_log(mut self, log: Vec<u8>) -> Self {
        self.boot = log;
        self
    }
    /// Select a specific compound profile. There is no detection or fallback
    /// between a direct CPU quote and a CPU/TPM evidence profile.
    pub fn with_cpu_profile(mut self, profile: tee::composite::CpuCollectionProfile) -> Self {
        self.cpu_profile = profile;
        self
    }
    /// Explicit TDX collection through the selected Google transport. No native
    /// provider or alternate transport is tried if this operation fails.
    #[cfg(feature = "tdx")]
    pub fn with_google_tdx_collector(
        mut self,
        verifier: crate::google_backend::GoogleVerifier,
        transport: crate::google_backend::TdxTransport,
    ) -> Self {
        self.google_tdx_collector = Some((verifier, transport));
        self
    }
    pub fn with_build_claims(mut self, claims: BuildClaims) -> Self {
        self.build_claims = Some(claims);
        self
    }
    #[cfg(feature = "gpu")]
    pub fn with_gpu_topology(mut self, mode: GpuTopologyMode) -> Self {
        self.topology = Some(mode);
        self
    }
    #[cfg(feature = "gpu")]
    pub fn with_gpu_collateral(mut self, collateral: crate::gpu::GpuCollateral) -> Self {
        self.collateral = Some(collateral);
        self
    }
    pub fn build(self) -> Result<AttestationCollector> {
        self.cpu_profile.validate()?;
        #[cfg(feature = "tdx")]
        ensure!(self.google_tdx_collector.is_none()
            || matches!(self.cpu_profile, tee::composite::CpuCollectionProfile::Direct),
            "Google TDX collection requires the direct CPU profile");
        ensure!(
            self.nonce.is_some()
                && self
                    .value_x
                    .is_some_and(|value| value.iter().any(|byte| *byte != 0)),
            "collector requires an explicit nonce and nonzero Value X"
        );
        validate_spki(&self.spki)?;
        if let Some(build) = &self.build_claims {
            ensure!(
                build.source_hash.iter().any(|b| *b != 0)
                    && build.artifact_hash.iter().any(|b| *b != 0),
                "build claims require nonzero source and artifact hashes"
            );
            ensure!(
                build.previous_attestation.len() <= 8 * 1024 * 1024,
                "prior-stage receipt exceeds limit"
            );
            if !build.previous_attestation.is_empty() {
                EatToken::from_cbor(&build.previous_attestation)?;
            }
        }
        ensure!(
            self.boot.len() <= 16 * 1024 * 1024,
            "boot log exceeds limit"
        );
        Ok(AttestationCollector { config: self })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedBootEvent {
    pub event_index: usize,
    pub algorithm: u16,
    pub digest: String,
    /// A policy-supplied identity for this approved digest, not an event label.
    pub identity: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerityPolicy {
    pub event_index: usize,
    pub algorithm: u16,
    pub profile: CommandLineProfile,
    pub root_digest: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootPolicy {
    pub events: Vec<ExpectedBootEvent>,
    pub dm_verity: Option<VerityPolicy>,
    #[serde(default)]
    pub uki: Option<boot::uki::UkiPolicy>,
    #[serde(default)]
    pub runtime: Option<boot::runtime::RuntimePolicy>,
}

pub struct AttestationVerifierBuilder {
    nonce: Option<[u8; 32]>,
    spki: Vec<u8>,
    value_x: Option<[u8; 48]>,
    platform: Option<Platform>,
    measurement: Option<Vec<u8>>,
    cpu_collateral: Option<CpuCollateral>,
    cpu_tcb_policy: Option<CpuTcbPolicy>,
    #[cfg(feature = "sev-snp")]
    azure_policy: Option<tee::azure_composite::AzureCompositePolicy>,
    #[cfg(feature = "nitro")]
    nitrotpm_policy: Option<tee::tpm::NitroTpmPolicy>,
    max_age: u64,
    require_gpu: bool,
    boot: Option<BootPolicy>,
    uki: Option<Vec<u8>>,
    google_boot_verifier: Option<crate::google_backend::GoogleVerifier>,
    #[cfg(feature = "tdx")]
    google_tdx_verifier: Option<crate::google_backend::GoogleVerifier>,
    #[cfg(feature = "gpu")]
    google_gpu_verifier: Option<crate::google_backend::GoogleVerifier>,
    prior_stage_policy: Option<crate::attestation_chain::PriorStagePolicy>,
    #[cfg(feature = "gpu")]
    gpu: Option<crate::gpu::verify::GpuPolicy>,
}
impl Default for AttestationVerifierBuilder {
    fn default() -> Self {
        Self {
            nonce: None,
            spki: Vec::new(),
            value_x: None,
            platform: None,
            measurement: None,
            cpu_collateral: None,
            cpu_tcb_policy: None,
            #[cfg(feature = "sev-snp")]
            azure_policy: None,
            #[cfg(feature = "nitro")]
            nitrotpm_policy: None,
            max_age: 300,
            require_gpu: false,
            boot: None,
            uki: None,
            google_boot_verifier: None,
            #[cfg(feature = "tdx")]
            google_tdx_verifier: None,
            #[cfg(feature = "gpu")]
            google_gpu_verifier: None,
            prior_stage_policy: None,
            #[cfg(feature = "gpu")]
            gpu: None,
        }
    }
}
pub struct AttestationVerifier {
    config: AttestationVerifierBuilder,
    #[cfg(feature = "gpu")]
    gpu: Option<crate::gpu::verify::GpuVerifier>,
}

#[derive(Debug, Serialize)]
pub struct AttestationVerdict {
    valid: bool,
    pub checks: Vec<CheckVerdict>,
    pub platform_measurements: BTreeMap<String, String>,
    pub runtime: Option<boot::runtime::VerifiedRuntimeLog>,
    pub prior_stage_count: usize,
    #[cfg(feature = "gpu")]
    pub gpu: Option<crate::gpu::verify::VerifiedGpuBundle>,
    pub boot: Option<boot::VerifiedBootLog>,
    pub dm_verity: Option<boot::DmVerityCommitment>,
    pub uki: Option<boot::uki::VerifiedUki>,
}
#[derive(Debug, Serialize)]
pub struct CheckVerdict {
    pub check: String,
    pub passed: bool,
    pub detail: String,
}
impl AttestationVerdict {
    pub fn is_valid(&self) -> bool {
        self.valid
    }
    fn pass(&mut self, check: &str, detail: &str) {
        self.checks.push(CheckVerdict {
            check: check.into(),
            passed: true,
            detail: detail.into(),
        });
    }
}

impl AttestationVerifier {
    pub fn builder() -> AttestationVerifierBuilder {
        AttestationVerifierBuilder::default()
    }
    pub fn verify(&self, token: &EatToken) -> AttestationVerdict {
        self.verify_internal(token, None)
    }
    pub(crate) fn verify_with_prior_stages(
        &self,
        token: &EatToken,
        prior: &crate::attestation_chain::VerifiedPriorStages,
    ) -> AttestationVerdict {
        self.verify_internal(token, Some(prior))
    }
    fn verify_internal(
        &self,
        token: &EatToken,
        verified_prior: Option<&crate::attestation_chain::VerifiedPriorStages>,
    ) -> AttestationVerdict {
        let mut verdict = AttestationVerdict {
            valid: false,
            checks: Vec::new(),
            platform_measurements: BTreeMap::new(),
            runtime: None,
            prior_stage_count: 0,
            #[cfg(feature = "gpu")]
            gpu: None,
            boot: None,
            dm_verity: None,
            uki: None,
        };
        let result = (|| {
            let prior = self
                .config
                .prior_stage_policy
                .as_ref()
                .map(|policy| policy.verify(&token.previous_attestation))
                .transpose()?;
            ensure!(
                prior.is_none() || verified_prior.is_none(),
                "conflicting prior-stage policy contexts"
            );
            self.verify_inner(token, &mut verdict, prior.as_ref().or(verified_prior))
        })();
        match result {
            Ok(()) => verdict.valid = true,
            Err(error) => verdict.checks.push(CheckVerdict {
                check: "rejected".into(),
                passed: false,
                detail: format!("{error:#}"),
            }),
        }
        verdict
    }
    fn verify_inner(
        &self,
        token: &EatToken,
        verdict: &mut AttestationVerdict,
        prior: Option<&crate::attestation_chain::VerifiedPriorStages>,
    ) -> Result<()> {
        token.validate_shape()?;
        if let Some(prior) = prior {
            ensure!(
                token.binding_suite != 0,
                "prior-stage policy requires full report-data binding"
            );
            prior.check_child(token)?;
            verdict.prior_stage_count = prior.stage_count();
            verdict.pass("prior_stages", "exact prior receipts, signatures, current collateral and independently approved stage policy verified");
        } else {
            ensure!(token.previous_attestation.is_empty(),
                "composite verification requires an explicit prior-stage policy before accepting a build chain");
        }
        let now = trusted_now()?;
        let cfg = &self.config;
        ensure!(
            Some(token.eat_nonce) == cfg.nonce,
            "challenge nonce mismatch"
        );
        ensure!(
            token.iat <= now && now - token.iat <= cfg.max_age,
            "EAT freshness expired or issued in the future"
        );
        ensure!(
            token.tls_spki_hash == <[u8; 32]>::from(Sha256::digest(&cfg.spki)),
            "TLS SPKI binding mismatch"
        );
        ensure!(Some(token.value_x) == cfg.value_x, "Value X mismatch");
        let platform = token.platform_enum().context("unknown platform")?;
        ensure!(
            cfg.platform.is_none_or(|p| p == platform),
            "required CPU platform mismatch"
        );
        #[cfg(feature = "sev-snp")]
        ensure!(
            cfg.azure_policy.is_some() == (platform == Platform::AzureSnpVtpm),
            "Azure profile requires matching independently configured Azure policy"
        );
        #[cfg(feature = "nitro")]
        ensure!(
            cfg.nitrotpm_policy.is_some() == (platform == Platform::AwsSnpNitroTpm),
            "AWS composite profile requires matching independently configured NitroTPM policy"
        );
        let mut tpm_registers: Option<AuthenticatedRegisters> = None;
        let values: BTreeMap<String, Vec<u8>> = match platform {
            #[cfg(feature = "tdx")]
            Platform::Tdx if cfg.google_tdx_verifier.is_some() => {
                let (Some(CpuCollateral::IntelTdx(collateral)), Some(CpuTcbPolicy::IntelTdx { minimum_tcb_evaluation_data_number })) =
                    (&cfg.cpu_collateral, &cfg.cpu_tcb_policy)
                else { anyhow::bail!("Google TDX requires Intel collateral and independent TCB policy"); };
                ensure!(matches!(token.binding_suite, 1 | 2), "Google TDX admission requires full report-data binding");
                let values = cfg.google_tdx_verifier.as_ref().unwrap().verify_tdx(
                    &token.platform_quote, &token.report_data_64(None),
                    cfg.measurement.as_deref().context("missing approved MRTD")?,
                    collateral, *minimum_tcb_evaluation_data_number,
                )?;
                verdict.pass("google_tdx", "Google quote verification and strict current collateral, revocation and independent TCB policy verified");
                values
            }
            #[cfg(feature = "sev-snp")]
            Platform::AzureSnpVtpm => {
                let (Some(CpuCollateral::AmdSnp(collateral)), Some(CpuTcbPolicy::AmdSnp(tcb))) =
                    (&cfg.cpu_collateral, &cfg.cpu_tcb_policy)
                else {
                    anyhow::bail!(
                        "Azure requires current AMD collateral and independent TCB policy"
                    );
                };
                let evidence =
                    tee::azure_composite::AzureCompositeEvidence::from_json(&token.platform_quote)?;
                let verified = tee::azure_composite::verify(
                    &evidence,
                    &token.report_data_64(None),
                    cfg.azure_policy.as_ref().context("missing Azure policy")?,
                    collateral,
                    tcb,
                )?;
                if cfg.boot.is_some() {
                    tpm_registers = Some(verified.authenticated_registers()?);
                }
                verdict.pass("azure_vtpm", "SNP-endorsed AK, fresh TPM quote, exact PCR and independent VM policy verified");
                verified.measurements().clone()
            }
            #[cfg(all(feature = "sev-snp", feature = "nitro"))]
            Platform::AwsSnpNitroTpm => {
                let evidence =
                    tee::composite::AwsSnpNitroTpmEvidence::from_json(&token.platform_quote)?;
                let mut values: BTreeMap<_, _> = verify_platform_quote_for_admission(
                    Platform::SevSnp,
                    &evidence.snp_report,
                    &token.binding_bytes(),
                    cfg.cpu_collateral.as_ref(),
                    cfg.cpu_tcb_policy.as_ref(),
                )?
                .into_iter()
                .collect();
                ensure!(
                    evidence.snp_report.get(0x30..0x34) == Some(&[0, 0, 0, 0][..]),
                    "AWS SNP policy requires VMPL 0"
                );
                let nitro = tee::tpm::verify_nitrotpm_document(
                    &evidence.nitrotpm_document,
                    &token.eat_nonce,
                    Some(&token.report_data_64(None)),
                    cfg.nitrotpm_policy
                        .as_ref()
                        .context("missing NitroTPM policy")?,
                    now,
                )?;
                if cfg.boot.is_some() {
                    tpm_registers = Some(nitro.authenticated_registers()?);
                }
                // The document is verified independently. It cannot introduce
                // caller-controlled names that overwrite the SNP measurements.
                for (index, value) in nitro.pcrs() {
                    values.insert(format!("NITROTPM_PCR{index}"), value.clone());
                }
                verdict.pass("nitrotpm", "signed NitroTPM document and SNP report bind the full EAT commitment; independent PCR policy verified");
                values
            }
            _ => verify_platform_quote_for_admission(
                platform,
                &token.platform_quote,
                &token.binding_bytes(),
                cfg.cpu_collateral.as_ref(),
                cfg.cpu_tcb_policy.as_ref(),
            )?
            .into_iter()
            .collect(),
        };
        let measurement_name = match platform {
            Platform::Tdx => "MRTD",
            Platform::SevSnp | Platform::AzureSnpVtpm | Platform::AwsSnpNitroTpm => "MEASUREMENT",
            Platform::Nitro => "PCR0",
        };
        let measurement = values
            .get(measurement_name)
            .context("quote lacks platform measurement")?;
        ensure!(
            measurement.iter().any(|b| *b != 0),
            "zero/debug CPU launch measurement"
        );
        match platform {
            Platform::Tdx => {
                #[cfg(feature = "tdx")]
                let google_attributes = cfg.google_tdx_verifier.as_ref()
                    .map(|_| values.get("TD_ATTRIBUTES").map(Vec::as_slice));
                #[cfg(not(feature = "tdx"))]
                let google_attributes: Option<Option<&[u8]>> = None;
                let attr = match google_attributes {
                    Some(attributes) => attributes.context("missing Google-authenticated TD attributes")?,
                    None => token.platform_quote.get(168..176).context("missing signed TD attributes")?,
                };
                ensure!(
                    u64::from_le_bytes(attr.try_into()?) & 1 == 0,
                    "TDX debug mode is forbidden"
                );
            }
            Platform::SevSnp => {
                let policy = token
                    .platform_quote
                    .get(8..16)
                    .context("missing signed SNP policy")?;
                ensure!(
                    u64::from_le_bytes(policy.try_into()?) & (1 << 19) == 0,
                    "SNP debug mode is forbidden"
                );
                ensure!(
                    token.platform_quote.get(0x30..0x34) == Some(&[0, 0, 0, 0][..]),
                    "SNP policy requires VMPL 0"
                );
            }
            Platform::Nitro | Platform::AzureSnpVtpm | Platform::AwsSnpNitroTpm => {}
        }
        if !token.platform_measurement.is_empty() {
            ensure!(
                &token.platform_measurement == measurement,
                "EAT measurement differs from signed CPU measurement"
            );
        }
        if let Some(expected) = &cfg.measurement {
            ensure!(
                expected == measurement,
                "CPU platform measurement policy mismatch"
            );
        }
        if token.binding_suite != 0 {
            let name = match platform {
                Platform::Tdx => "REPORTDATA",
                Platform::SevSnp | Platform::AwsSnpNitroTpm => "REPORT_DATA",
                Platform::AzureSnpVtpm => "AZURE_EAT_REPORT_DATA",
                Platform::Nitro => "USER_DATA",
            };
            ensure!(
                values
                    .get(name)
                    .is_some_and(|rd| rd.as_slice() == token.report_data_64(None)),
                "full CPU report-data commitment mismatch"
            );
        }
        verdict.platform_measurements = values
            .iter()
            .map(|(k, v)| (k.clone(), hex::encode(v)))
            .collect();
        verdict.pass("cpu", "signature, pinned root, required vendor collateral and TCB policy, challenge, freshness, TLS key and application binding verified");
        if !token.gpu_evidence.is_empty() {
            ensure!(
                token.binding_suite == BINDING_SUITE_COMPOSITE,
                "GPU evidence is not CPU committed"
            );
            #[cfg(feature = "gpu")]
            {
                let verifier = self
                    .gpu
                    .as_ref()
                    .context("GPU evidence requires an explicit relying-party inventory policy")?;
                let mut cursor = std::io::Cursor::new(&token.gpu_evidence);
                let bundle = ciborium::de::from_reader(&mut cursor).context("decode GPU bundle")?;
                ensure!(
                    cursor.position() == token.gpu_evidence.len() as u64,
                    "trailing GPU evidence data"
                );
                verdict.gpu = Some(verifier.verify(&bundle, &token.eat_nonce, now)?);
                if let Some(google) = &cfg.google_gpu_verifier {
                    crate::gpu::google::verify(google, &bundle,
                        cfg.gpu.as_ref().context("missing GPU inventory policy")?,
                        verdict.gpu.as_ref().context("missing native GPU appraisal")?,
                        &token.eat_nonce, now)?;
                    verdict.pass("google_gpu", "Google GPU/NVSwitch signature, manifest, revocation and topology checks verified alongside application policy");
                }
                verdict.pass("gpu", "certificates, revocation, signatures, manifests, security and inventory policy verified");
            }
            #[cfg(not(feature = "gpu"))]
            anyhow::bail!("GPU evidence requires the gpu feature");
        } else {
            ensure!(
                !cfg.require_gpu,
                "require_gpu_verified: GPU evidence is missing"
            );
        }
        if let Some(policy) = &cfg.boot {
            ensure!(
                token.binding_suite == BINDING_SUITE_COMPOSITE && !token.boot_evidence.is_empty(),
                "required CPU-committed boot evidence is missing"
            );
            let log = if platform == Platform::Tdx {
                let mut registers = [[0u8; 48]; 4];
                for (i, target) in registers.iter_mut().enumerate() {
                    *target = values
                        .get(&format!("RTMR{i}"))
                        .context("missing signed RTMR")?
                        .as_slice()
                        .try_into()?;
                }
                let parsed = if policy.runtime.is_some() {
                    EventLog::parse_tdx_ccel_with_aael(
                        &token.boot_evidence,
                        ParseLimits::default(),
                    )?
                } else {
                    EventLog::parse_tdx_ccel(&token.boot_evidence, ParseLimits::default())?
                };
                if let Some(google) = &cfg.google_boot_verifier {
                    google
                        .replay_tdx(&token.boot_evidence[..parsed.consumed_bytes()], &registers)?;
                    verdict.pass("google_boot_replay", "Google go-eventlog matched all four authenticated RTMRs with event inference disabled");
                }
                if let Some(runtime) = &policy.runtime {
                    let (log, verified) = parsed
                        .verify_tdx_runtime(&AuthenticatedRegisters::tdx(registers), runtime)?;
                    verdict.runtime = Some(verified);
                    log
                } else {
                    parsed.verify(&AuthenticatedRegisters::tdx(registers))?
                }
            } else {
                ensure!(
                    policy.runtime.is_none(),
                    "CoCo AAEL RTMR3 policy requires TDX"
                );
                ensure!(
                    cfg.google_boot_verifier.is_none(),
                    "configured Google replay profile requires TDX"
                );
                let registers = tpm_registers.as_ref().context(
                    "TPM boot evidence requires authenticated CPU/TPM composite evidence",
                )?;
                EventLog::parse_tcg2(&token.boot_evidence, ParseLimits::default())?
                    .verify(registers)?
            };
            for expected in &policy.events {
                log.verify_expected_digest(
                    expected.event_index,
                    expected.algorithm,
                    &hex::decode(&expected.digest)?,
                )?;
            }
            if let Some(verity) = &policy.dm_verity {
                verdict.dm_verity = Some(log.verified_dm_verity(
                    verity.event_index,
                    verity.algorithm,
                    verity.profile,
                    &hex::decode(&verity.root_digest)?,
                )?);
            }
            if let Some(uki_policy) = &policy.uki {
                let image = cfg.uki.as_ref().context("required UKI image is missing")?;
                verdict.uki = Some(log.verify_uki(image, uki_policy)?);
                verdict.pass("uki", "embedded UKI metadata matches authenticated section measurements and independently approved section digests");
            }
            verdict.boot = Some(log);
            verdict.pass(
                "boot",
                "event replay agrees with authenticated registers and required measurement policy",
            );
        } else if !token.boot_evidence.is_empty() {
            anyhow::bail!("boot evidence requires an explicit relying-party policy");
        }
        // Appraisal can include a bounded helper process and several prior
        // stages. A receipt that expires during that work must not authorize a
        // request merely because it was fresh when verification began.
        let completed_at = trusted_now()?;
        ensure!(
            token.iat <= completed_at && completed_at - token.iat <= cfg.max_age,
            "EAT freshness expired during appraisal"
        );
        if let Some(prior) = prior {
            prior.check_child(token)?;
        }
        Ok(())
    }
}
impl AttestationVerifierBuilder {
    pub fn with_expected_nonce(mut self, n: &[u8; 32]) -> Self {
        self.nonce = Some(*n);
        self
    }
    pub fn with_tls_spki_der(mut self, s: &[u8]) -> Self {
        self.spki = s.to_vec();
        self
    }
    pub fn with_expected_value_x(mut self, x: &[u8; 48]) -> Self {
        self.value_x = Some(*x);
        self
    }
    pub fn require_platform(mut self, p: Platform) -> Self {
        self.platform = Some(p);
        self
    }
    pub fn with_expected_platform_measurement(mut self, m: &[u8]) -> Self {
        self.measurement = Some(m.to_vec());
        self
    }
    /// Vendor-signed CPU collateral is matched to this quote. It never supplies
    /// the relying party's approved launch measurement or replaces GPU policy.
    pub fn with_cpu_collateral(mut self, collateral: CpuCollateral) -> Self {
        self.cpu_collateral = Some(collateral);
        self
    }
    #[cfg(feature = "sev-snp")]
    pub fn with_azure_policy(mut self, policy: tee::azure_composite::AzureCompositePolicy) -> Self {
        self.azure_policy = Some(policy);
        self
    }
    #[cfg(feature = "nitro")]
    pub fn with_nitrotpm_policy(mut self, policy: tee::tpm::NitroTpmPolicy) -> Self {
        self.nitrotpm_policy = Some(policy);
        self
    }
    /// Independent relying-party rollback limits, never taken from evidence.
    pub fn with_cpu_tcb_policy(mut self, policy: CpuTcbPolicy) -> Self {
        self.cpu_tcb_policy = Some(policy);
        self
    }
    pub fn with_max_age_secs(mut self, age: u64) -> Self {
        self.max_age = age;
        self
    }
    pub fn require_gpu_verified(mut self, required: bool) -> Self {
        self.require_gpu = required;
        self
    }
    pub fn with_boot_policy(mut self, policy: BootPolicy) -> Self {
        self.boot = Some(policy);
        self
    }
    pub fn with_prior_stage_policy(
        mut self,
        policy: crate::attestation_chain::PriorStagePolicy,
    ) -> Self {
        self.prior_stage_policy = Some(policy);
        self
    }
    /// Explicitly require Google's replay implementation in addition to the
    /// application event policy. Any helper failure rejects the attestation.
    pub fn with_google_boot_verifier(
        mut self,
        verifier: crate::google_backend::GoogleVerifier,
    ) -> Self {
        self.google_boot_verifier = Some(verifier);
        self
    }
    /// Select Google's TDX verifier instead of the native TDX implementation.
    /// A rejection is final; it never triggers an alternate verifier.
    #[cfg(feature = "tdx")]
    pub fn with_google_tdx_verifier(mut self, verifier: crate::google_backend::GoogleVerifier) -> Self {
        self.google_tdx_verifier = Some(verifier);
        self
    }
    /// Require Google's GPU/NVSwitch appraisal as well as the application's
    /// stricter certificate, security, inventory and binding policy.
    #[cfg(feature = "gpu")]
    pub fn with_google_gpu_verifier(mut self, verifier: crate::google_backend::GoogleVerifier) -> Self {
        self.google_gpu_verifier = Some(verifier);
        self
    }
    /// Image bytes are untrusted until their section measurements agree with
    /// authenticated boot registers and independently approved UKI policy.
    pub fn with_uki_evidence(mut self, image: Vec<u8>) -> Self {
        self.uki = Some(image);
        self
    }
    #[cfg(feature = "gpu")]
    pub fn with_gpu_policy(mut self, policy: crate::gpu::verify::GpuPolicy) -> Self {
        self.gpu = Some(policy);
        self.require_gpu = true;
        self
    }
    /// All CPU verifiers already pin the vendor roots; the GPU verifier also
    /// uses its compiled NVIDIA pins. No roots are taken from the evidence.
    pub fn with_pinned_vendor_roots(self) -> Self {
        self
    }
    pub fn build(mut self) -> Result<AttestationVerifier> {
        #[cfg(feature = "tdx")]
        if self.google_tdx_verifier.is_some() {
            ensure!(self.platform == Some(Platform::Tdx), "Google TDX verifier requires explicit TDX platform policy");
            ensure!(matches!(self.cpu_collateral, Some(CpuCollateral::IntelTdx(_)))
                && matches!(self.cpu_tcb_policy, Some(CpuTcbPolicy::IntelTdx { minimum_tcb_evaluation_data_number: 1.. })),
                "Google TDX requires Intel collateral and a nonzero TCB evaluation-data floor");
        }
        #[cfg(feature = "gpu")]
        ensure!(self.google_gpu_verifier.is_none() || self.gpu.is_some(),
            "Google GPU verification requires an enrolled GPU inventory policy");
        #[cfg(feature = "sev-snp")]
        if let Some(policy) = &self.azure_policy {
            ensure!(
                self.platform == Some(Platform::AzureSnpVtpm),
                "Azure policy requires the explicit Azure platform"
            );
            policy.validate()?;
        }
        #[cfg(feature = "nitro")]
        if let Some(policy) = &self.nitrotpm_policy {
            ensure!(
                self.platform == Some(Platform::AwsSnpNitroTpm),
                "NitroTPM policy requires the explicit AWS composite platform"
            );
            policy.validate()?;
        }
        if matches!(
            self.platform,
            Some(Platform::AzureSnpVtpm | Platform::AwsSnpNitroTpm)
        ) {
            #[cfg(feature = "sev-snp")]
            ensure!(
                matches!(self.cpu_collateral, Some(CpuCollateral::AmdSnp(_)))
                    && matches!(self.cpu_tcb_policy, Some(CpuTcbPolicy::AmdSnp(_))),
                "CPU/TPM profiles require current AMD collateral and independent TCB policy"
            );
            #[cfg(not(feature = "sev-snp"))]
            anyhow::bail!("CPU/TPM profiles require sev-snp support");
        }
        if self.platform == Some(Platform::AzureSnpVtpm) {
            #[cfg(feature = "sev-snp")]
            ensure!(
                self.azure_policy.is_some(),
                "Azure profile requires independent Azure policy"
            );
        }
        if self.platform == Some(Platform::AwsSnpNitroTpm) {
            #[cfg(feature = "nitro")]
            ensure!(
                self.nitrotpm_policy.is_some(),
                "AWS profile requires independent NitroTPM policy"
            );
            #[cfg(not(feature = "nitro"))]
            anyhow::bail!("AWS profile requires nitro support");
        }
        if let Some(policy) = &self.prior_stage_policy {
            policy.validate()?;
        }
        ensure!(
            self.nonce.is_some()
                && self
                    .value_x
                    .is_some_and(|value| value.iter().any(|byte| *byte != 0)),
            "verifier requires an expected challenge and nonzero Value X"
        );
        ensure!(
            self.measurement
                .as_ref()
                .is_some_and(|m| m.len() == 48 && m.iter().any(|b| *b != 0)),
            "verifier requires an approved 48-byte CPU platform measurement"
        );
        validate_spki(&self.spki)?;
        ensure!(
            self.max_age > 0 && self.max_age <= 86400,
            "max EAT age must be 1..86400 seconds"
        );
        if let Some(p) = &self.boot {
            if let Some(runtime) = &p.runtime {
                runtime.validate()?;
            }
            ensure!(
                !p.events.is_empty() && p.events.len() <= 1024,
                "boot policy must specify approved event measurements"
            );
            for e in &p.events {
                ensure!(
                    !e.identity.is_empty() && matches!(hex::decode(&e.digest)?.len(), 32 | 48 | 64),
                    "invalid boot digest policy"
                );
            }
            if let Some(uki) = &p.uki {
                uki.validate()?;
            }
        }
        ensure!(
            self.google_boot_verifier.is_none() || self.boot.is_some(),
            "Google boot replay requires an independent boot policy"
        );
        ensure!(
            self.boot
                .as_ref()
                .is_some_and(|policy| policy.uki.is_some())
                == self.uki.is_some(),
            "UKI appraisal requires both a boot UKI policy and image bytes"
        );
        if let Some(image) = &self.uki {
            ensure!(
                !image.is_empty() && image.len() <= boot::uki::MAX_UKI_BYTES,
                "UKI image size outside limit"
            );
        }
        #[cfg(feature = "gpu")]
        let gpu = {
            self.require_gpu |= self.gpu.is_some();
            ensure!(
                !self.require_gpu || self.gpu.is_some(),
                "require_gpu_verified needs an enrolled GPU inventory policy"
            );
            self.gpu
                .clone()
                .map(crate::gpu::verify::GpuVerifier::new)
                .transpose()?
        };
        #[cfg(not(feature = "gpu"))]
        ensure!(
            !self.require_gpu,
            "require_gpu_verified requires the gpu feature"
        );
        Ok(AttestationVerifier {
            config: self,
            #[cfg(feature = "gpu")]
            gpu,
        })
    }
}
fn validate_spki(spki: &[u8]) -> Result<()> {
    ensure!(
        !spki.is_empty() && spki.len() <= 16384,
        "an explicit TLS SubjectPublicKeyInfo DER is required"
    );
    spki::SubjectPublicKeyInfoOwned::from_der(spki).context("invalid TLS SPKI DER")?;
    Ok(())
}
fn trusted_now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
