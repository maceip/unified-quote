//! GPU/NVSwitch appraisal. Policy comes from the relying party, never the EAT.
use anyhow::{ensure, Context, Result};
use der::Encode;
use p384::{ecdsa::VerifyingKey, pkcs8::DecodePublicKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use x509_cert::Certificate;

use super::{
    cert::{self, Purpose, ValidatedChain},
    opaque::{ConfidentialMode, OpaqueData},
    revocation,
    rim::{self, OpaqueSvnConstraint, RimKind, VerifiedRim},
    spdm::SpdmReport,
    GpuEvidenceBundle,
};

/// Exact inventory uses the validated immediate issuer (device BROM) SPKI
/// digest. NVML UUID/name/index are not authenticated hardware identities.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePolicy {
    pub identity_spki_sha256: String,
    pub model: String,
    pub mode: ConfidentialMode,
    /// Additional exact, signed opaque field requirements for this deployment.
    #[serde(default)]
    pub required_opaque: BTreeMap<u16, Vec<u8>>,
    /// Required for PPCIE: enrolled GPU PDI used in the switch's signed graph.
    pub pdi: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwitchPolicy {
    pub identity_spki_sha256: String,
    pub model: String,
    pub pdi: String,
    pub gpu_pdis: BTreeSet<String>,
    /// Must explicitly constrain protected-PCIe, lock, disabled-port and port
    /// routing fields (21, 25, 23, 26). Their values are platform-specific.
    pub required_opaque: BTreeMap<u16, Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuPolicy {
    pub devices: Vec<DevicePolicy>,
    #[serde(default)]
    pub switches: Vec<SwitchPolicy>,
}

impl GpuPolicy {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.devices.is_empty() && self.devices.len() <= 256 && self.switches.len() <= 32,
            "invalid required GPU/switch count"
        );
        let mut ids = BTreeSet::new();
        let mut gpu_pdis = BTreeSet::new();
        for d in &self.devices {
            decode_hex(&d.identity_spki_sha256, 32)?;
            ensure!(
                ids.insert(&d.identity_spki_sha256),
                "duplicate enrolled device identity"
            );
            gpu_manifest_model(&d.model)?;
            if d.mode == ConfidentialMode::Ppcie {
                let pdi = d.pdi.as_ref().context("PPCIE policy requires GPU PDI")?;
                decode_hex(pdi, 8)?;
                ensure!(gpu_pdis.insert(pdi.clone()), "duplicate enrolled GPU PDI");
                ensure!(!self.switches.is_empty(), "PPCIE policy requires switches");
                ensure!(
                    d.required_opaque.contains_key(&21),
                    "PPCIE requires explicit signed protected-PCIe state"
                );
            } else {
                ensure!(
                    self.switches.is_empty(),
                    "mixed independent-GPU/fabric policy is unsupported"
                );
            }
        }
        let mut switch_pdis = BTreeSet::new();
        for s in &self.switches {
            switch_manifest_model(&s.model)?;
            decode_hex(&s.identity_spki_sha256, 32)?;
            decode_hex(&s.pdi, 8)?;
            ensure!(
                ids.insert(&s.identity_spki_sha256) && switch_pdis.insert(&s.pdi),
                "duplicate enrolled switch identity/PDI"
            );
            ensure!(
                !s.gpu_pdis.is_empty() && s.gpu_pdis.is_subset(&gpu_pdis),
                "invalid expected switch GPU graph"
            );
            for id in [21, 23, 25, 26] {
                ensure!(
                    s.required_opaque.get(&id).is_some_and(|v| !v.is_empty()),
                    "switch policy requires explicit opaque field {id}"
                );
            }
        }
        for pdi in &gpu_pdis {
            ensure!(
                self.switches.iter().any(|s| s.gpu_pdis.contains(pdi)),
                "enrolled GPU has no switch edge"
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceVerdict {
    pub identity_spki_sha256: String,
    pub model: String,
    pub driver_version: Option<String>,
    pub vbios_version: String,
    pub mode: Option<ConfidentialMode>,
    pub matched_measurements: Vec<u16>,
    /// Explicit exclusions authorized by signed vendor manifests, not matches.
    pub inactive_measurements: Vec<u16>,
    pub nvdec_disabled_measurements: Vec<u16>,
    pub manifest_sha384: Vec<String>,
    /// Actual signed runtime SVN values requested by authenticated RIM
    /// includeInResult attributes. Golden minimum values never replace them.
    pub opaque_claims: BTreeMap<String, u16>,
    /// Scope is signed reference matching plus the explicitly required state.
    /// It does not assert post-load measurement, target immutability, or target
    /// TCB membership; those DICE flags are preserved independently.
    pub security_profile: String,
    pub signed_security_flags: Option<super::identity::DiceOperationalFlags>,
}

/// Only successfully appraised evidence constructs this value.
#[derive(Debug, Clone, Serialize)]
pub struct VerifiedGpuBundle {
    devices: Vec<DeviceVerdict>,
    switches: Vec<DeviceVerdict>,
    /// Signed, reciprocal switch/GPU PDI relationships matched to enrolled
    /// policy; CPU commitment does not establish physical attachment.
    fabric_policy_verified: bool,
}
impl VerifiedGpuBundle {
    pub fn devices(&self) -> &[DeviceVerdict] {
        &self.devices
    }
    pub fn switches(&self) -> &[DeviceVerdict] {
        &self.switches
    }
    pub fn fabric_policy_verified(&self) -> bool {
        self.fabric_policy_verified
    }
}

pub struct GpuVerifier {
    policy: GpuPolicy,
    device_roots: Vec<Certificate>,
    rim_roots: Vec<Certificate>,
}
impl GpuVerifier {
    pub fn new(policy: GpuPolicy) -> Result<Self> {
        Self::with_pinned_roots(
            policy,
            cert::pinned_device_roots()?,
            cert::pinned_rim_roots()?,
        )
    }
    pub fn with_pinned_roots(
        policy: GpuPolicy,
        device_roots: Vec<Certificate>,
        rim_roots: Vec<Certificate>,
    ) -> Result<Self> {
        policy.validate()?;
        ensure!(
            !device_roots.is_empty() && !rim_roots.is_empty(),
            "vendor trust roots cannot be empty"
        );
        Ok(Self {
            policy,
            device_roots,
            rim_roots,
        })
    }
    pub fn verify(
        &self,
        evidence: &GpuEvidenceBundle,
        nonce: &[u8; 32],
        now: u64,
    ) -> Result<VerifiedGpuBundle> {
        ensure!(
            evidence.version == 1 && &evidence.nonce == nonce,
            "GPU bundle version/nonce mismatch"
        );
        ensure!(
            evidence.gpus.len() == self.policy.devices.len()
                && evidence.switches.len() == self.policy.switches.len(),
            "required GPU/switch inventory mismatch"
        );
        ensure!(
            evidence.gpus.iter().all(|gpu| gpu.cec_attestation_report.is_empty()),
            "CEC evidence requires a supported CEC appraisal profile; it cannot be silently ignored"
        );
        ensure!(
            !evidence.collateral.manifests.is_empty() && evidence.collateral.manifests.len() <= 64,
            "invalid manifest inventory"
        );
        let manifests: Vec<_> = evidence
            .collateral
            .manifests
            .iter()
            .map(|xml| rim::verify_xml(xml, &self.rim_roots, &evidence.collateral.revocation, now))
            .collect::<Result<_>>()?;
        let mut devices = Vec::new();
        let mut switches = Vec::new();
        let mut seen = BTreeSet::new();
        let mut gpu_edges: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for gpu in &evidence.gpus {
            let chain = self
                .authenticate(
                    &gpu.attestation_certificate_chain,
                    &gpu.attestation_report,
                    nonce,
                    evidence,
                    now,
                )
                .with_context(|| format!("GPU {}", gpu.index))?;
            let certified = super::identity::certificate_identity(&chain)?;
            require_production_security(&certified)?;
            let identity = hex::encode(certified.device_key_sha256);
            ensure!(
                seen.insert(identity.clone()),
                "repeated device certificate identity"
            );
            let policy = self
                .policy
                .devices
                .iter()
                .find(|p| p.identity_spki_sha256 == identity)
                .context("GPU identity not enrolled")?;
            let report = SpdmReport::parse(&gpu.attestation_report)?;
            let opaque = OpaqueData::parse(report.opaque_data())?;
            ensure!(
                certified.model == policy.model,
                "certificate GPU model differs from enrolled model"
            );
            // A firmware-binding field, when emitted, cannot be silently
            // discarded. Blackwell carries it in the supported profile.
            if certified.model == "GB100" || opaque.field(20).is_ok() {
                certified.verify_report_fwid(opaque.bytes(20)?)?;
            }
            if certified.model == "GB100" && opaque.field(35).is_ok() {
                ensure!(
                    opaque.text(35)? == certified.model,
                    "signed CHIP_INFO differs from certificate model"
                );
            }
            ensure!(
                opaque.mode()? == policy.mode,
                "signed GPU confidential mode violates policy"
            );
            check_fields(&opaque, &policy.required_opaque)?;
            let driver_version = opaque.text(3)?;
            let vbios_version = opaque.vbios_version()?;
            let driver = manifest(
                &manifests,
                RimKind::GpuDriver,
                &policy.model,
                &driver_version,
            )?;
            let vbios = manifest(&manifests, RimKind::GpuVbios, &policy.model, &vbios_version)?;
            let mut verdict = appraise(&report, &opaque, &[driver, vbios], true)?;
            verdict.identity_spki_sha256 = identity;
            verdict.model = policy.model.clone();
            verdict.driver_version = Some(driver_version);
            verdict.vbios_version = vbios_version;
            verdict.mode = Some(policy.mode);
            verdict.signed_security_flags = certified.operational_flags.clone();
            if policy.mode == ConfidentialMode::Ppcie {
                // NVIDIA GPU opaque22 is little endian; LS10 self/peer PDIs
                // and the enrolled hexadecimal identities use display order.
                let mut pdis = opaque.pdis(22)?;
                for pdi in &mut pdis {
                    pdi.reverse();
                }
                let actual = pdi_set(&pdis)?;
                let gpu_pdi = policy.pdi.as_ref().context("missing enrolled GPU PDI")?;
                let expected = self
                    .policy
                    .switches
                    .iter()
                    .filter(|s| s.gpu_pdis.contains(gpu_pdi))
                    .map(|s| s.pdi.clone())
                    .collect();
                ensure!(actual == expected, "signed GPU-to-switch topology mismatch");
                gpu_edges.insert(gpu_pdi.clone(), actual);
            }
            devices.push(verdict);
        }
        for switch in &evidence.switches {
            let chain = self
                .authenticate(
                    &switch.certificate_chain,
                    &switch.attestation_report,
                    nonce,
                    evidence,
                    now,
                )
                .context("NVSwitch")?;
            let certified = super::identity::certificate_identity(&chain)?;
            require_production_security(&certified)?;
            let identity = hex::encode(certified.device_key_sha256);
            ensure!(
                seen.insert(identity.clone()),
                "repeated switch/device certificate identity"
            );
            let policy = self
                .policy
                .switches
                .iter()
                .find(|p| p.identity_spki_sha256 == identity)
                .context("switch identity not enrolled")?;
            let report = SpdmReport::parse(&switch.attestation_report)?;
            let opaque = OpaqueData::parse(report.opaque_data())?;
            ensure!(
                certified.model == policy.model,
                "certificate switch model differs from enrolled model"
            );
            if opaque.field(20).is_ok() {
                certified.verify_report_fwid(opaque.bytes(20)?)?;
            }
            check_fields(&opaque, &policy.required_opaque)?;
            ensure!(
                hex::encode(opaque.bytes(22)?) == policy.pdi,
                "signed switch PDI mismatch"
            );
            let peers = opaque.bytes(26)?;
            // LS10 encodes eight 8-byte PDIs followed by the port-ID vector.
            ensure!(
                peers.len() >= 64 && peers.len() <= 128,
                "invalid LS10 PDI/port vector"
            );
            let parsed = peers[..64]
                .chunks_exact(8)
                .map(|p| p.try_into().expect("8-byte chunk"))
                .collect::<Vec<[u8; 8]>>();
            // LS10 may repeat a peer PDI for multiple links. Keep the exact
            // routing bytes constrained by field26 policy; compare graph peers
            // as a set, matching NVIDIA's published switch report semantics.
            let actual = pdi_set(&parsed)?;
            ensure!(
                actual == policy.gpu_pdis,
                "signed switch-to-GPU topology mismatch"
            );
            for peer in &actual {
                ensure!(
                    gpu_edges.get(peer).is_some_and(|p| p.contains(&policy.pdi)),
                    "nonreciprocal signed fabric edge"
                );
            }
            let version = opaque.switch_vbios_version()?;
            let rim = manifest(
                &manifests,
                RimKind::NvSwitchVbios,
                switch_manifest_model(&policy.model)?,
                &version,
            )?;
            let mut verdict = appraise(&report, &opaque, &[rim], false)?;
            verdict.identity_spki_sha256 = identity;
            verdict.model = policy.model.clone();
            verdict.vbios_version = version;
            verdict.signed_security_flags = certified.operational_flags.clone();
            switches.push(verdict);
        }
        Ok(VerifiedGpuBundle {
            devices,
            switches,
            fabric_policy_verified: !self.policy.switches.is_empty(),
        })
    }
    fn authenticate(
        &self,
        certificates: &[u8],
        bytes: &[u8],
        nonce: &[u8; 32],
        evidence: &GpuEvidenceBundle,
        now: u64,
    ) -> Result<ValidatedChain> {
        let chain = cert::validate_chain(certificates, &self.device_roots, now, Purpose::Device)?;
        revocation::check_chain(&chain, &evidence.collateral.revocation, now)?;
        let key = VerifyingKey::from_public_key_der(
            &chain
                .leaf()
                .tbs_certificate
                .subject_public_key_info
                .to_der()?,
        )?;
        SpdmReport::parse(bytes)?.verify_signature(nonce, &key)?;
        Ok(chain)
    }
}

/// Appraisal and collateral acquisition share the same explicit model gate.
pub(crate) fn gpu_manifest_model(model: &str) -> Result<&str> {
    ensure!(
        matches!(model, "GH100" | "GB100"),
        "unsupported certificate-authenticated GPU model: {model}"
    );
    Ok(model)
}

pub(crate) fn switch_manifest_model(model: &str) -> Result<&'static str> {
    // Pinned switchCertChain.txt: DMTF SAN NVIDIA:LS_10:<serial>.
    // The corresponding signed SWID uses PlatformModel/product LS10.
    ensure!(
        model == "LS_10",
        "unsupported certificate-authenticated switch model: {model}"
    );
    Ok("LS10")
}

fn decode_hex(s: &str, len: usize) -> Result<Vec<u8>> {
    let b = hex::decode(s)?;
    ensure!(
        b.len() == len && hex::encode(&b) == s,
        "policy digest/PDI must be canonical lower-case hex ({len} bytes)"
    );
    ensure!(
        b.iter().any(|byte| *byte != 0),
        "policy digest/PDI cannot be a zero placeholder"
    );
    Ok(b)
}
fn require_production_security(
    identity: &super::identity::DeviceCertificateIdentity,
) -> Result<()> {
    use super::identity::OperationalFlag::*;
    // TCG DICE Attestation Architecture v1.2 §6.1.1.1 assigns separate meaning
    // to post-load measurement, immutability and TCB membership. Reference
    // matching does not establish those properties, and no supported NVIDIA
    // endorsement here specifies a universal value for their three flags.
    identity.require_security_flags(&[
        (NotConfigured, false),
        (NotSecure, false),
        (Recovery, false),
        (Debug, false),
        (NotReplayProtected, false),
        (NotIntegrityProtected, false),
    ])
}
fn pdi_set(values: &[[u8; 8]]) -> Result<BTreeSet<String>> {
    let mut result = BTreeSet::new();
    for pdi in values {
        // Zero is an unconnected position, never an authenticated peer.
        if *pdi != [0; 8] {
            // A peer can occupy multiple physical links. NVIDIA's GPU and
            // switch evidence getters both normalize those links to a set.
            // Inventory identities and enrolled PDIs are checked separately.
            result.insert(hex::encode(pdi));
        }
    }
    ensure!(!result.is_empty(), "empty signed topology");
    Ok(result)
}
fn check_fields(opaque: &OpaqueData<'_>, required: &BTreeMap<u16, Vec<u8>>) -> Result<()> {
    for (id, value) in required {
        ensure!(
            !value.is_empty() && opaque.bytes(*id)? == value,
            "signed security field {id} violates policy"
        );
    }
    Ok(())
}
fn manifest<'a>(
    rims: &'a [VerifiedRim],
    kind: RimKind,
    model: &str,
    version: &str,
) -> Result<&'a VerifiedRim> {
    let matches: Vec<_> = rims
        .iter()
        .filter(|r| r.kind() == kind && r.model() == model && r.version() == version)
        .collect();
    ensure!(
        matches.len() == 1,
        "missing or ambiguous signed {kind:?} RIM for {model}/{version}"
    );
    Ok(matches[0])
}
fn appraise(
    report: &SpdmReport<'_>,
    opaque: &OpaqueData<'_>,
    rims: &[&VerifiedRim],
    gpu: bool,
) -> Result<DeviceVerdict> {
    let mut golden = BTreeMap::new();
    let mut inactive = BTreeSet::<u16>::new();
    for rim in rims {
        for (index, values) in rim.measurements() {
            ensure!(
                golden.insert(*index, values).is_none(),
                "overlapping active RIM measurement {index}"
            );
        }
        inactive.extend(rim.inactive_indices().iter().copied());
    }
    let opaque_claims = appraise_svn(opaque, rims.iter().flat_map(|rim| rim.opaque_constraints()))?;
    let measurement_appraisal = appraise_measurements(report, opaque, &golden, &inactive, gpu)?;
    Ok(DeviceVerdict {
        identity_spki_sha256: String::new(),
        model: String::new(),
        driver_version: None,
        vbios_version: String::new(),
        mode: None,
        matched_measurements: measurement_appraisal.matched,
        inactive_measurements: measurement_appraisal.inactive,
        nvdec_disabled_measurements: measurement_appraisal.nvdec_disabled,
        manifest_sha384: rims
            .iter()
            .map(|r| hex::encode(r.source_sha384()))
            .collect(),
        opaque_claims,
        security_profile: "nvidia_signed_reference_measurements_matched".into(),
        signed_security_flags: None,
    })
}

fn appraise_svn<'a>(
    opaque: &OpaqueData<'_>,
    constraints: impl Iterator<Item = &'a OpaqueSvnConstraint>,
) -> Result<BTreeMap<String, u16>> {
    let mut ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut claims = BTreeMap::new();
    for constraint in constraints {
        ensure!(
            ids.insert(constraint.type_id) && names.insert(&constraint.name),
            "overlapping signed SVN constraints"
        );
        ensure!(constraint.value_size == 2, "unsupported manifest SVN width");
        let runtime = opaque.svn(constraint.type_id)?;
        ensure!(
            u64::from(runtime) >= constraint.min_svn,
            "SVN rollback: {}",
            constraint.name
        );
        if constraint.include_in_result {
            claims.insert(constraint.name.clone(), runtime);
        }
    }
    Ok(claims)
}

#[derive(Debug)]
struct MeasurementAppraisal {
    matched: Vec<u16>,
    inactive: Vec<u16>,
    nvdec_disabled: Vec<u16>,
}

// Internal comparison primitive. It cannot create a device or bundle verdict;
// production calls it only after authenticated manifest extraction above.
fn appraise_measurements(
    report: &SpdmReport<'_>,
    opaque: &OpaqueData<'_>,
    golden: &BTreeMap<u16, &Vec<Vec<u8>>>,
    inactive: &BTreeSet<u16>,
    gpu: bool,
) -> Result<MeasurementAppraisal> {
    ensure!(
        golden.contains_key(&0),
        "security reference profile lacks boot measurement 0"
    );
    let nvdec_disabled = if gpu {
        match opaque.bytes(11)? {
            [0x55] => true,
            [0xaa] => false,
            _ => anyhow::bail!("missing/unknown signed NVDEC state"),
        }
    } else {
        false
    };
    let mut remaining: BTreeSet<_> = golden.keys().copied().collect();
    let mut matched = Vec::new();
    let mut excluded = Vec::new();
    let mut nvdec = Vec::new();
    for m in report.measurements() {
        let index = u16::from(m.index) - 1;
        ensure!(
            !m.raw_bit_stream && m.value_type == 1 && m.value.len() == 48,
            "unsupported NVIDIA reference measurement format"
        );
        if index == 35 && nvdec_disabled {
            nvdec.push(index);
            remaining.remove(&index);
            continue;
        }
        if let Some(values) = golden.get(&index) {
            ensure!(
                values.iter().any(|v| v == m.value),
                "reference measurement {index} mismatch"
            );
            matched.push(index);
            remaining.remove(&index);
        } else {
            ensure!(
                inactive.contains(&index),
                "measurement {index} has no authenticated reference disposition"
            );
            excluded.push(index);
        }
    }
    ensure!(
        remaining.is_empty(),
        "report missing required measurements: {remaining:?}"
    );
    Ok(MeasurementAppraisal {
        matched,
        inactive: excluded,
        nvdec_disabled: nvdec,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn svn_floor_and_result_claim_are_distinct_and_duplicate_constraints_reject() {
        // Locally constructed parser inputs exercise the internal predicate;
        // this helper cannot manufacture an authenticated RIM or GPU verdict.
        let mut bytes = b"NVDAOD\0\0\x02\0\0\0".to_vec();
        bytes.extend_from_slice(&[37, 0, 0x87, 0, 2, 0, 7, 0]);
        let opaque = OpaqueData::parse(&bytes).unwrap();
        let mut constraint = OpaqueSvnConstraint {
            type_id: 37,
            name: "FSP_UCODE_MIN_SVN".into(),
            declared_size: 1,
            value_size: 2,
            min_svn: 5,
            include_in_result: true,
        };
        assert_eq!(
            appraise_svn(&opaque, [&constraint].into_iter()).unwrap(),
            BTreeMap::from([("FSP_UCODE_MIN_SVN".into(), 7)])
        );
        assert!(appraise_svn(&opaque, [&constraint, &constraint].into_iter()).is_err());
        constraint.include_in_result = false;
        assert!(appraise_svn(&opaque, [&constraint].into_iter())
            .unwrap()
            .is_empty());
        constraint.min_svn = 8;
        assert!(appraise_svn(&opaque, [&constraint].into_iter())
            .unwrap_err()
            .to_string()
            .contains("rollback"));
        constraint.min_svn = 5;
        constraint.type_id = 38;
        assert!(appraise_svn(&opaque, [&constraint].into_iter()).is_err());
    }

    #[test]
    fn topology_normalizes_repeated_links_but_preserves_exact_peer_membership() {
        let a = [1, 2, 3, 4, 5, 6, 7, 8];
        let b = [8, 7, 6, 5, 4, 3, 2, 1];
        let expected = BTreeSet::from([hex::encode(a), hex::encode(b)]);
        assert_eq!(pdi_set(&[a, b, a, [0; 8], b]).unwrap(), expected);
        assert_ne!(pdi_set(&[a, a]).unwrap(), expected);
        assert!(pdi_set(&[[0; 8], [0; 8]]).is_err());
        assert!(pdi_set(&[]).is_err());
    }

    #[test]
    fn original_switch_reference_maps_spdm_one_based_indices_and_exact_hashes() {
        // Signature/path and pure measurement comparison only. Neither helper
        // can create VerifiedRim/VerifiedGpuBundle or omit production revocation.
        let xml = include_str!(
            "../../testdata/gpu/rim/switchVBIOSRim_NV_SWITCH_BIOS_5612_0002_890_9610550001.xml"
        );
        let rim = rim::verify_xml_signature_and_chain(
            xml,
            &cert::pinned_rim_roots().unwrap(),
            1_791_849_600,
        )
        .unwrap();
        let bytes = hex::decode(
            include_str!("../../testdata/gpu/nvidia/switchAttestationReport.txt").trim(),
        )
        .unwrap();
        let report = SpdmReport::parse(&bytes).unwrap();
        let opaque = OpaqueData::parse(report.opaque_data()).unwrap();
        let golden: BTreeMap<_, _> = rim.measurements().iter().map(|(i, v)| (*i, v)).collect();
        let result =
            appraise_measurements(&report, &opaque, &golden, rim.inactive_indices(), false)
                .unwrap();
        assert!(result.matched.contains(&0));
        assert_eq!(result.matched.len(), golden.len());
        assert!(result.nvdec_disabled.is_empty());

        let mut wrong_hashes = rim.measurements().clone();
        for alternative in wrong_hashes.get_mut(&0).unwrap() {
            alternative[0] ^= 1;
        }
        let bad: BTreeMap<_, _> = wrong_hashes.iter().map(|(i, v)| (*i, v)).collect();
        let error = appraise_measurements(&report, &opaque, &bad, rim.inactive_indices(), false)
            .unwrap_err();
        assert!(error.to_string().contains("measurement 0 mismatch"));

        let shifted: BTreeMap<_, _> = golden.iter().map(|(i, v)| (i + 1, *v)).collect();
        assert!(
            appraise_measurements(&report, &opaque, &shifted, rim.inactive_indices(), false)
                .is_err()
        );
        let mut missing_reference = golden.clone();
        let active_index = *golden.keys().find(|i| **i != 0).unwrap();
        missing_reference.remove(&active_index);
        assert!(appraise_measurements(
            &report,
            &opaque,
            &missing_reference,
            rim.inactive_indices(),
            false
        )
        .is_err());
        let mut absent_measurement = golden.clone();
        assert!(!report.measurements().iter().any(|m| m.index == 254));
        absent_measurement.insert(253, golden[&0]);
        assert!(appraise_measurements(
            &report,
            &opaque,
            &absent_measurement,
            rim.inactive_indices(),
            false
        )
        .unwrap_err()
        .to_string()
        .contains("missing required measurements"));
    }
}
