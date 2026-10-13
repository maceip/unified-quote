//! Finite build ancestry admitted against independently enrolled stage policy.
//!
//! Receipt pins authenticate no claim by themselves: every stage must also pass
//! the ordinary current-clock CPU/composite admission verifier. The private
//! proof below lets the next stage retain and authenticate its original link.
use crate::{
    attestation::{AttestationVerdict, AttestationVerifier, BootPolicy},
    eat::EatToken,
    quote::{
        verify::{CpuCollateral, CpuTcbPolicy},
        Platform,
    },
};
use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    time::{SystemTime, UNIX_EPOCH},
};

pub const MAX_PRIOR_STAGES: usize = 8;
pub const MAX_STAGE_RECEIPT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_DECODED_CHAIN_BYTES: usize = 32 * 1024 * 1024;

/// Relying-party policy, supplied separately from every received receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriorStagePolicy {
    /// Exact stage sequence, oldest first and immediate predecessor last.
    pub stages: Vec<PriorStagePolicyEntry>,
}

/// Hexadecimal fields are exact pins. No expected value is learned from an EAT.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriorStagePolicyEntry {
    pub name: String,
    pub receipt_sha256: String,
    pub source_hash: String,
    pub artifact_hash: String,
    pub expected_nonce: String,
    pub tls_spki_der: String,
    pub expected_value_x: String,
    pub expected_platform: Platform,
    pub expected_platform_measurement: String,
    /// Current admission age in seconds, including historical build stages.
    /// The same 1..=86400 bound as the ordinary verifier applies.
    pub max_age_secs: u64,
    pub cpu_collateral: Option<CpuCollateral>,
    pub cpu_tcb_policy: Option<CpuTcbPolicy>,
    #[cfg(feature = "sev-snp")]
    pub azure_policy: Option<crate::tee::azure_composite::AzureCompositePolicy>,
    #[cfg(feature = "nitro")]
    pub nitrotpm_policy: Option<crate::tee::tpm::NitroTpmPolicy>,
    pub boot_policy: Option<BootPolicy>,
    /// Optional verifier-local UKI bytes encoded as hex, never taken from EAT.
    pub uki_evidence: Option<String>,
    #[cfg(feature = "gpu")]
    pub gpu_policy: Option<crate::gpu::verify::GpuPolicy>,
}

/// Produced only after all stages have passed complete admission. Deliberately
/// neither deserializable nor publicly constructible.
#[derive(Debug, Serialize)]
pub struct VerifiedPriorStages {
    stages: Vec<VerifiedPriorStage>,
    immediate_predecessor_sha256: String,
    value_x: String,
    /// Earliest stage's independently configured freshness deadline. Current
    /// collateral is still authenticated during each ordinary admission call.
    freshness_deadline: u64,
}

#[derive(Debug, Serialize)]
pub struct VerifiedPriorStage {
    name: String,
    receipt_sha256: String,
    source_hash: String,
    artifact_hash: String,
    nonce: String,
    tls_spki_sha256: String,
    value_x: String,
    platform: Platform,
    issued_at: u64,
    verdict: AttestationVerdict,
}

impl VerifiedPriorStages {
    pub fn stage_count(&self) -> usize {
        self.stages.len()
    }
    pub fn stages(&self) -> &[VerifiedPriorStage] {
        &self.stages
    }
    pub(crate) fn check_child(&self, child: &EatToken) -> Result<()> {
        ensure!(
            !self.stages.is_empty() && !child.previous_attestation.is_empty(),
            "verified ancestry requires an exact nonempty predecessor link"
        );
        ensure!(
            matches!(child.binding_suite, 1 | 2),
            "build ancestry requires a full 64-byte CPU report-data binding"
        );
        ensure!(
            hex::encode(child.previous_hash()) == self.immediate_predecessor_sha256,
            "child predecessor bytes differ from verified ancestry"
        );
        ensure!(
            hex::encode(child.value_x) == self.value_x,
            "Value X differs between child and verified ancestry"
        );
        ensure!(
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() <= self.freshness_deadline,
            "verified ancestry freshness expired before child admission"
        );
        Ok(())
    }
}

impl VerifiedPriorStage {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn receipt_sha256(&self) -> &str {
        &self.receipt_sha256
    }
    pub fn verdict(&self) -> &AttestationVerdict {
        &self.verdict
    }
}

struct PendingStage<'a> {
    policy: &'a PriorStagePolicyEntry,
    receipt_sha256: [u8; 32],
    token: EatToken,
}

impl PriorStagePolicy {
    /// Validate independent configuration before accepting any receipt bytes.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=MAX_PRIOR_STAGES).contains(&self.stages.len()),
            "prior-stage policy requires 1..=8 ordered stages"
        );
        let mut names = BTreeSet::new();
        let mut receipts = BTreeSet::new();
        let mut stable_value_x = None;
        for policy in &self.stages {
            policy.validate()?;
            // Reuse normal builder validation for DER SPKI and optional
            // composite policy; no quote or hardware collection is invoked.
            policy.verifier()?;
            ensure!(names.insert(&policy.name), "duplicate prior-stage name");
            ensure!(
                receipts.insert(fixed::<32>(&policy.receipt_sha256, "receipt_sha256")?),
                "duplicate prior-stage receipt pin"
            );
            let value_x = fixed::<48>(&policy.expected_value_x, "expected_value_x")?;
            ensure!(
                stable_value_x.is_none_or(|previous| previous == value_x),
                "prior-stage policies disagree on Value X"
            );
            stable_value_x = Some(value_x);
        }
        Ok(())
    }

    /// Verify the immediate predecessor's exact CBOR and every nested stage.
    /// This API accepts no caller-supplied verification time or trust result.
    pub fn verify(&self, immediate_predecessor: &[u8]) -> Result<VerifiedPriorStages> {
        let pending = self.prepare(immediate_predecessor)?;
        let mut verified: Option<VerifiedPriorStages> = None;
        for stage in pending {
            let verifier = stage.policy.verifier()?;
            let verdict = if let Some(prior) = &verified {
                verifier.verify_with_prior_stages(&stage.token, prior)
            } else {
                verifier.verify(&stage.token)
            };
            if !verdict.is_valid() {
                let failures: Vec<_> = verdict
                    .checks
                    .iter()
                    .filter(|check| !check.passed)
                    .map(|check| check.detail.as_str())
                    .collect();
                bail!(
                    "prior stage {:?} rejected: {}",
                    stage.policy.name,
                    failures.join("; ")
                );
            }
            let stage_deadline = stage
                .token
                .iat
                .checked_add(stage.policy.max_age_secs)
                .context("prior-stage freshness deadline overflow")?;
            let mut chain = verified.unwrap_or_else(|| VerifiedPriorStages {
                stages: Vec::with_capacity(self.stages.len()),
                immediate_predecessor_sha256: String::new(),
                value_x: hex::encode(stage.token.value_x),
                freshness_deadline: stage_deadline,
            });
            chain.freshness_deadline = chain.freshness_deadline.min(stage_deadline);
            chain.immediate_predecessor_sha256 = hex::encode(stage.receipt_sha256);
            chain.stages.push(VerifiedPriorStage {
                name: stage.policy.name.clone(),
                receipt_sha256: hex::encode(stage.receipt_sha256),
                source_hash: hex::encode(stage.token.source_hash),
                artifact_hash: hex::encode(stage.token.artifact_hash),
                nonce: hex::encode(stage.token.eat_nonce),
                tls_spki_sha256: hex::encode(stage.token.tls_spki_hash),
                value_x: hex::encode(stage.token.value_x),
                platform: stage
                    .token
                    .platform_enum()
                    .context("unknown prior-stage platform")?,
                issued_at: stage.token.iat,
                verdict,
            });
            verified = Some(chain);
        }
        let verified = verified.context("prior-stage policy must contain at least one stage")?;
        ensure!(
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() <= verified.freshness_deadline,
            "prior-stage freshness expired during chain admission"
        );
        Ok(verified)
    }

    /// Parse and match exact pins without promoting any token to verified.
    fn prepare(&self, immediate_predecessor: &[u8]) -> Result<Vec<PendingStage<'_>>> {
        self.validate()?;
        ensure!(
            !immediate_predecessor.is_empty()
                && immediate_predecessor.len() <= MAX_STAGE_RECEIPT_BYTES,
            "required prior-stage receipt is missing or exceeds 8 MiB"
        );
        let mut raw = immediate_predecessor.to_vec();
        let mut decoded_bytes = 0usize;
        let mut pending = Vec::with_capacity(self.stages.len());
        for policy in self.stages.iter().rev() {
            ensure!(
                !raw.is_empty() && raw.len() <= MAX_STAGE_RECEIPT_BYTES,
                "prior-stage chain is missing a required stage or exceeds the byte limit"
            );
            decoded_bytes = decoded_bytes
                .checked_add(raw.len())
                .context("chain size overflow")?;
            ensure!(
                decoded_bytes <= MAX_DECODED_CHAIN_BYTES,
                "decoded prior-stage chain exceeds 32 MiB"
            );
            let receipt_sha256: [u8; 32] = Sha256::digest(&raw).into();
            ensure!(
                receipt_sha256 == fixed::<32>(&policy.receipt_sha256, "receipt_sha256")?,
                "prior stage {:?}: receipt SHA256 pin mismatch",
                policy.name
            );
            let token = EatToken::from_cbor(&raw).context("decode prior-stage receipt")?;
            policy.check_token(&token)?;
            // Retain every original field: the CPU verifies this exact link.
            raw = token.previous_attestation.clone();
            pending.push(PendingStage {
                policy,
                receipt_sha256,
                token,
            });
        }
        ensure!(
            raw.is_empty(),
            "prior-stage chain contains an extra unapproved stage"
        );
        pending.reverse();
        Ok(pending)
    }
}

impl PriorStagePolicyEntry {
    fn validate(&self) -> Result<()> {
        ensure!(
            !self.name.is_empty()
                && self.name.len() <= 128
                && !self.name.chars().any(char::is_control),
            "invalid prior-stage policy name"
        );
        for (field, data) in [
            (
                "receipt_sha256",
                fixed::<32>(&self.receipt_sha256, "receipt_sha256")?.to_vec(),
            ),
            (
                "source_hash",
                fixed::<48>(&self.source_hash, "source_hash")?.to_vec(),
            ),
            (
                "artifact_hash",
                fixed::<48>(&self.artifact_hash, "artifact_hash")?.to_vec(),
            ),
            (
                "expected_value_x",
                fixed::<48>(&self.expected_value_x, "expected_value_x")?.to_vec(),
            ),
            (
                "expected_platform_measurement",
                fixed::<48>(
                    &self.expected_platform_measurement,
                    "expected_platform_measurement",
                )?
                .to_vec(),
            ),
        ] {
            ensure!(
                data.iter().any(|byte| *byte != 0),
                "prior-stage {field} must be nonzero"
            );
        }
        fixed::<32>(&self.expected_nonce, "expected_nonce")?;
        ensure!(
            (1..=86400).contains(&self.max_age_secs),
            "prior-stage max age must be 1..86400 seconds"
        );
        bounded_hex(&self.tls_spki_der, 16 * 1024, "tls_spki_der")?;
        #[cfg(feature = "sev-snp")]
        {
            ensure!(self.azure_policy.is_some() == (self.expected_platform == Platform::AzureSnpVtpm),
                "Azure prior stage requires a matching independent Azure policy; other platforms cannot use it");
            if let Some(policy) = &self.azure_policy {
                policy.validate()?;
            }
        }
        #[cfg(feature = "nitro")]
        {
            ensure!(self.nitrotpm_policy.is_some() == (self.expected_platform == Platform::AwsSnpNitroTpm),
                "AWS SNP NitroTPM prior stage requires a matching independent NitroTPM policy; other platforms cannot use it");
            if let Some(policy) = &self.nitrotpm_policy {
                policy.validate()?;
            }
        }
        match self.expected_platform {
            #[cfg(feature = "nitro")]
            Platform::Nitro => {
                ensure!(
                    self.cpu_collateral.is_none() && self.cpu_tcb_policy.is_none(),
                    "Nitro stage cannot use Intel/AMD collateral or TCB policy"
                );
                Ok(())
            }
            #[cfg(feature = "tdx")]
            Platform::Tdx => {
                ensure!(
                    matches!(&self.cpu_collateral, Some(CpuCollateral::IntelTdx(_))),
                    "TDX stage requires independently supplied Intel collateral"
                );
                ensure!(
                    matches!(&self.cpu_tcb_policy, Some(CpuTcbPolicy::IntelTdx { minimum_tcb_evaluation_data_number }) if *minimum_tcb_evaluation_data_number > 0),
                    "TDX stage requires a nonzero independent TCB floor"
                );
                Ok(())
            }
            #[cfg(feature = "sev-snp")]
            Platform::SevSnp | Platform::AzureSnpVtpm => self.validate_amd_policy(),
            #[cfg(all(feature = "sev-snp", feature = "nitro"))]
            Platform::AwsSnpNitroTpm => self.validate_amd_policy(),
            #[allow(unreachable_patterns)]
            _ => bail!("prior-stage platform support was not compiled in"),
        }
    }

    #[cfg(feature = "sev-snp")]
    fn validate_amd_policy(&self) -> Result<()> {
        ensure!(
            matches!(&self.cpu_collateral, Some(CpuCollateral::AmdSnp(_))),
            "SNP stage requires independently supplied AMD collateral"
        );
        let Some(CpuTcbPolicy::AmdSnp(policy)) = &self.cpu_tcb_policy else {
            bail!("SNP stage requires independent AMD TCB floors");
        };
        policy.validate()
    }

    fn check_token(&self, token: &EatToken) -> Result<()> {
        ensure!(
            matches!(token.binding_suite, 1 | 2),
            "prior stage requires full 64-byte CPU report-data binding"
        );
        if matches!(
            self.expected_platform,
            Platform::AzureSnpVtpm | Platform::AwsSnpNitroTpm
        ) {
            ensure!(
                token.binding_suite == crate::eat::BINDING_SUITE_COMPOSITE,
                "Azure and AWS SNP NitroTPM prior stages require composite binding suite 2"
            );
        }
        ensure!(
            token.source_hash == fixed::<48>(&self.source_hash, "source_hash")?,
            "prior-stage source hash mismatch"
        );
        ensure!(
            token.artifact_hash == fixed::<48>(&self.artifact_hash, "artifact_hash")?,
            "prior-stage artifact hash mismatch"
        );
        ensure!(
            token.value_x == fixed::<48>(&self.expected_value_x, "expected_value_x")?,
            "prior-stage Value X mismatch"
        );
        ensure!(
            token.eat_nonce == fixed::<32>(&self.expected_nonce, "expected_nonce")?,
            "prior-stage expected nonce mismatch"
        );
        ensure!(
            token.platform_enum() == Some(self.expected_platform),
            "prior-stage platform mismatch"
        );
        let spki = bounded_hex(&self.tls_spki_der, 16 * 1024, "tls_spki_der")?;
        ensure!(
            token.tls_spki_hash == <[u8; 32]>::from(Sha256::digest(&spki)),
            "prior-stage TLS SPKI mismatch"
        );
        Ok(())
    }

    fn verifier(&self) -> Result<AttestationVerifier> {
        let mut builder = AttestationVerifier::builder()
            .with_expected_nonce(&fixed::<32>(&self.expected_nonce, "expected_nonce")?)
            .with_tls_spki_der(&bounded_hex(&self.tls_spki_der, 16 * 1024, "tls_spki_der")?)
            .with_expected_value_x(&fixed::<48>(&self.expected_value_x, "expected_value_x")?)
            .require_platform(self.expected_platform)
            .with_expected_platform_measurement(&fixed::<48>(
                &self.expected_platform_measurement,
                "expected_platform_measurement",
            )?)
            .with_max_age_secs(self.max_age_secs);
        #[cfg(any(feature = "tdx", feature = "sev-snp"))]
        if let Some(collateral) = &self.cpu_collateral {
            builder = builder.with_cpu_collateral(collateral.clone());
        }
        #[cfg(any(feature = "tdx", feature = "sev-snp"))]
        if let Some(policy) = &self.cpu_tcb_policy {
            builder = builder.with_cpu_tcb_policy(policy.clone());
        }
        #[cfg(feature = "sev-snp")]
        if let Some(policy) = &self.azure_policy {
            builder = builder.with_azure_policy(policy.clone());
        }
        #[cfg(feature = "nitro")]
        if let Some(policy) = &self.nitrotpm_policy {
            builder = builder.with_nitrotpm_policy(policy.clone());
        }
        if let Some(policy) = &self.boot_policy {
            builder = builder.with_boot_policy(policy.clone());
        }
        if let Some(image) = &self.uki_evidence {
            builder = builder.with_uki_evidence(bounded_hex(
                image,
                MAX_DECODED_CHAIN_BYTES / 2,
                "uki_evidence",
            )?);
        }
        #[cfg(feature = "gpu")]
        if let Some(policy) = &self.gpu_policy {
            builder = builder.with_gpu_policy(policy.clone());
        }
        builder
            .build()
            .with_context(|| format!("prior-stage policy {:?}", self.name))
    }
}

fn fixed<const N: usize>(input: &str, field: &str) -> Result<[u8; N]> {
    ensure!(
        input.len() == N * 2,
        "prior-stage {field} requires {N} bytes of hex"
    );
    let mut value = [0; N];
    hex::decode_to_slice(input, &mut value)
        .with_context(|| format!("invalid prior-stage {field} hex"))?;
    Ok(value)
}

fn bounded_hex(input: &str, max: usize, field: &str) -> Result<Vec<u8>> {
    ensure!(
        !input.is_empty() && input.len() % 2 == 0 && input.len() / 2 <= max,
        "prior-stage {field} size outside limit"
    );
    hex::decode(input).with_context(|| format!("invalid prior-stage {field} hex"))
}

#[cfg(all(test, feature = "nitro"))]
mod tests {
    use super::*;
    use crate::eat::{BuildComponents, BINDING_SUITE_COMPOSITE};
    use p256::pkcs8::EncodePublicKey;

    fn unsigned_stage(name: &str, previous: Vec<u8>) -> (EatToken, PriorStagePolicyEntry) {
        let spki = p256::SecretKey::from_slice(&[7; 32])
            .unwrap()
            .public_key()
            .to_public_key_der()
            .unwrap();
        let mut token = EatToken::from_build_with_nonce(
            BuildComponents {
                platform: Platform::Nitro,
                value_x: [1; 48],
                source_hash: [2; 48],
                artifact_hash: [3; 48],
                platform_measurement: vec![],
                platform_quote: vec![],
            },
            [4; 32],
        );
        token.binding_suite = BINDING_SUITE_COMPOSITE;
        token.tls_spki_hash = Sha256::digest(spki.as_bytes()).into();
        token.previous_attestation = previous;
        let policy = PriorStagePolicyEntry {
            name: name.into(),
            receipt_sha256: hex::encode(Sha256::digest(token.to_cbor().unwrap())),
            source_hash: hex::encode(token.source_hash),
            artifact_hash: hex::encode(token.artifact_hash),
            expected_nonce: hex::encode(token.eat_nonce),
            tls_spki_der: hex::encode(spki.as_bytes()),
            expected_value_x: hex::encode(token.value_x),
            expected_platform: Platform::Nitro,
            expected_platform_measurement: hex::encode([9; 48]),
            max_age_secs: 300,
            cpu_collateral: None,
            cpu_tcb_policy: None,
            #[cfg(feature = "sev-snp")]
            azure_policy: None,
            #[cfg(feature = "nitro")]
            nitrotpm_policy: None,
            boot_policy: None,
            uki_evidence: None,
            #[cfg(feature = "gpu")]
            gpu_policy: None,
        };
        (token, policy)
    }

    fn repin(policy: &mut PriorStagePolicyEntry, token: &EatToken) -> Vec<u8> {
        let raw = token.to_cbor().unwrap();
        policy.receipt_sha256 = hex::encode(Sha256::digest(&raw));
        raw
    }

    #[test]
    fn exact_order_and_all_links_are_retained_without_claiming_appraisal() {
        let (root, root_policy) = unsigned_stage("builder", vec![]);
        let root_raw = root.to_cbor().unwrap();
        let (child, child_policy) = unsigned_stage("release", root_raw.clone());
        let raw = child.to_cbor().unwrap();
        let policy = PriorStagePolicy {
            stages: vec![root_policy, child_policy],
        };
        let prepared = policy.prepare(&raw).unwrap();
        assert_eq!(prepared[0].policy.name, "builder");
        assert_eq!(prepared[1].policy.name, "release");
        assert_eq!(prepared[1].token.previous_attestation, root_raw);
        assert!(
            policy.verify(&raw).is_err(),
            "pins cannot replace a signed CPU quote"
        );
        let mut reversed = policy.clone();
        reversed.stages.reverse();
        assert!(reversed.prepare(&raw).is_err());
    }

    #[test]
    fn missing_extra_duplicate_and_altered_stages_reject() {
        let (root, root_policy) = unsigned_stage("builder", vec![]);
        let (child, child_policy) = unsigned_stage("release", root.to_cbor().unwrap());
        let raw = child.to_cbor().unwrap();
        let full = PriorStagePolicy {
            stages: vec![root_policy.clone(), child_policy.clone()],
        };
        assert!(full.prepare(&[]).is_err());
        assert!(full.prepare(&root.to_cbor().unwrap()).is_err());
        assert!(PriorStagePolicy {
            stages: vec![child_policy]
        }
        .prepare(&raw)
        .is_err());
        assert!(PriorStagePolicy {
            stages: vec![root_policy.clone(), root_policy]
        }
        .prepare(&raw)
        .is_err());
        let mut changed = child;
        changed.previous_attestation[0] ^= 1;
        assert!(full.prepare(&changed.to_cbor().unwrap()).is_err());
        let mut altered = full;
        let raw = repin(&mut altered.stages[1], &changed);
        assert!(
            altered.prepare(&raw).is_err(),
            "repinning only the parent cannot change the child pin"
        );
    }

    #[test]
    fn independent_claim_pins_and_full_binding_cannot_be_omitted() {
        let (token, policy) = unsigned_stage("builder", vec![]);
        for field in 0..7 {
            let mut changed = token.clone();
            match field {
                0 => changed.source_hash[0] ^= 1,
                1 => changed.artifact_hash[0] ^= 1,
                2 => changed.eat_nonce[0] ^= 1,
                3 => changed.value_x[0] ^= 1,
                4 => changed.tls_spki_hash[0] ^= 1,
                5 => changed.platform = 2,
                6 => changed.binding_suite = 0,
                _ => unreachable!(),
            }
            let mut changed_policy = policy.clone();
            let raw = repin(&mut changed_policy, &changed);
            assert!(
                PriorStagePolicy {
                    stages: vec![changed_policy]
                }
                .prepare(&raw)
                .is_err(),
                "field {field}"
            );
        }
        let mut trailing = token.to_cbor().unwrap();
        trailing.push(0);
        let mut policy = policy;
        policy.receipt_sha256 = hex::encode(Sha256::digest(&trailing));
        assert!(PriorStagePolicy {
            stages: vec![policy]
        }
        .prepare(&trailing)
        .is_err());
    }

    #[test]
    fn stale_build_is_rejected_even_with_exact_receipt_pin() {
        let (mut token, mut policy) = unsigned_stage("builder", vec![]);
        token.iat = 1;
        let raw = repin(&mut policy, &token);
        let error = PriorStagePolicy {
            stages: vec![policy],
        }
        .verify(&raw)
        .unwrap_err();
        assert!(error.to_string().contains("freshness"), "{error:#}");
        let (mut token, mut policy) = unsigned_stage("future-builder", vec![]);
        token.iat = u64::MAX;
        let raw = repin(&mut policy, &token);
        let error = PriorStagePolicy {
            stages: vec![policy],
        }
        .verify(&raw)
        .unwrap_err();
        assert!(error.to_string().contains("freshness"), "{error:#}");
    }

    #[test]
    fn finite_policy_requires_every_pin_and_current_admission_window() {
        let (token, policy) = unsigned_stage("builder", vec![]);
        let raw = token.to_cbor().unwrap();
        assert!(PriorStagePolicy { stages: vec![] }.prepare(&raw).is_err());
        assert!(PriorStagePolicy {
            stages: vec![policy.clone(); 9]
        }
        .prepare(&raw)
        .is_err());
        for age in [0, 86401, u64::MAX] {
            let mut bad = policy.clone();
            bad.max_age_secs = age;
            assert!(PriorStagePolicy { stages: vec![bad] }
                .prepare(&raw)
                .is_err());
        }
        let mut bad = policy.clone();
        bad.artifact_hash = hex::encode([0; 48]);
        assert!(PriorStagePolicy { stages: vec![bad] }
            .prepare(&raw)
            .is_err());
        let mut bad = policy;
        bad.expected_platform = Platform::Tdx;
        assert!(PriorStagePolicy { stages: vec![bad] }
            .prepare(&raw)
            .is_err());
    }

    #[test]
    #[cfg(feature = "sev-snp")]
    fn vendor_composite_stages_require_separate_policy_and_composite_binding() {
        for platform in [Platform::AzureSnpVtpm, Platform::AwsSnpNitroTpm] {
            let (mut token, mut policy) = unsigned_stage("builder", vec![]);
            policy.expected_platform = platform;
            token.platform = crate::eat::platform_to_u8(platform);
            token.binding_suite = 1;
            let error = policy.validate().unwrap_err();
            assert!(
                error.to_string().contains("matching independent"),
                "{error:#}"
            );
            let error = policy.check_token(&token).unwrap_err();
            assert!(
                error.to_string().contains("composite binding suite 2"),
                "{error:#}"
            );
        }
        let (_, mut policy) = unsigned_stage("builder", vec![]);
        policy.azure_policy = Some(crate::tee::azure_composite::AzureCompositePolicy {
            version: 1,
            allowed_ak_spki_sha256: vec![hex::encode([1; 32])],
            enrolled_ak_public_areas: vec![],
            allowed_paravisor_measurements: vec![hex::encode([2; 48])],
            expected_vm_id: "00000000-0000-4000-8000-000000000001".into(),
            expected_pcrs: vec![crate::tee::azure_composite::AzurePcrValue {
                index: 0,
                value: [3; 32],
            }],
            allow_console: false,
        });
        assert!(policy
            .validate()
            .unwrap_err()
            .to_string()
            .contains("other platforms"));
    }

    #[test]
    fn oversized_receipt_is_rejected_before_decode() {
        let (_, policy) = unsigned_stage("builder", vec![]);
        assert!(PriorStagePolicy {
            stages: vec![policy]
        }
        .prepare(&vec![0; MAX_STAGE_RECEIPT_BYTES + 1])
        .is_err());
    }

    #[test]
    fn policy_rejects_value_x_drift_and_receipt_supplied_clock_controls() {
        let (root, root_policy) = unsigned_stage("builder", vec![]);
        let (mut child, mut child_policy) = unsigned_stage("release", root.to_cbor().unwrap());
        child.value_x = [5; 48];
        child_policy.expected_value_x = hex::encode(child.value_x);
        let raw = repin(&mut child_policy, &child);
        assert!(PriorStagePolicy {
            stages: vec![root_policy.clone(), child_policy]
        }
        .prepare(&raw)
        .is_err());
        let mut json = serde_json::to_value(PriorStagePolicy {
            stages: vec![root_policy],
        })
        .unwrap();
        json["now"] = serde_json::json!(1);
        assert!(serde_json::from_value::<PriorStagePolicy>(json).is_err());
    }
}
