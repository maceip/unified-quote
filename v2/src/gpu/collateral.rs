//! NVIDIA collateral acquisition from fixed vendor HTTPS endpoints.
//!
//! Manifest identifiers come from certificate-authenticated device models and
//! nonce/signature-verified opaque report fields. Downloads and cache entries
//! remain untrusted until their signatures, pinned paths and fresh revocation
//! are verified. Cached bytes are revalidated on every use. Failed validation
//! can trigger authenticated refresh; it can never produce an assumed verdict.

use super::{
    cert::{self, Purpose, ValidatedChain},
    identity,
    opaque::OpaqueData,
    revocation::{RevocationCache, RevocationClient, RevocationEvidence},
    rim::{self, RimKind, VerifiedRim},
    spdm::SpdmReport,
    GpuCollateral, GpuEvidenceBundle,
};
use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use der::Encode;
use p384::{ecdsa::VerifyingKey, pkcs8::DecodePublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Read, time::Duration};
use x509_cert::Certificate;

const RIM_ENDPOINT: &str = "https://rim.attestation.nvidia.com/v1/rim/";
const OCSP_ENDPOINT: &str = "https://ocsp.ndis.nvidia.com";
const MAX_XML: usize = 2 * 1024 * 1024;
const MAX_RESPONSE: usize = 3 * 1024 * 1024;
const MAX_MANIFESTS: usize = 64;
const MAX_CACHE: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CachedManifest {
    xml: String,
    revocation: RevocationEvidence,
}

/// Portable cache of original signed bytes. No cached verdict is accepted.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollateralCache {
    manifests: BTreeMap<String, CachedManifest>,
    device_revocation: RevocationCache,
}
impl CollateralCache {
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_CACHE,
            "collateral cache JSON exceeds limit"
        );
        let value: Self = serde_json::from_slice(bytes)?;
        ensure!(
            value.manifests.len() <= MAX_MANIFESTS,
            "too many cached manifests"
        );
        for (id, manifest) in &value.manifests {
            selector_component(id, 160)?;
            ensure!(
                !manifest.xml.is_empty() && manifest.xml.len() <= MAX_XML,
                "cached manifest size outside bound"
            );
        }
        // Validate the nested cache's own resource limits on import as well.
        RevocationCache::from_json(&value.device_revocation.to_json()?)?;
        Ok(value)
    }
    pub fn to_json(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self)?;
        ensure!(
            bytes.len() <= MAX_CACHE,
            "collateral cache exceeds serialization limit"
        );
        Ok(bytes)
    }
}

pub struct NvidiaCollateralClient {
    http: reqwest::blocking::Client,
    revocation: RevocationClient,
    device_roots: Vec<Certificate>,
    rim_roots: Vec<Certificate>,
}

impl NvidiaCollateralClient {
    pub fn new() -> Result<Self> {
        Ok(Self {
            http: reqwest::blocking::Client::builder()
                .https_only(true)
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(5))
                .timeout(Duration::from_secs(20))
                .build()?,
            revocation: RevocationClient::new(OCSP_ENDPOINT, &[])?,
            device_roots: cert::pinned_device_roots()?,
            rim_roots: cert::pinned_rim_roots()?,
        })
    }

    /// Acquire authenticated collateral for all GPU and switch reports.
    ///
    /// `now` must come from the verifier clock. This authenticates evidence for
    /// safe selector derivation; the resulting bundle still needs full runtime,
    /// inventory, topology and CPU-binding appraisal by the main verifier.
    pub fn acquire_for_bundle(
        &self,
        bundle: &GpuEvidenceBundle,
        nonce: &[u8; 32],
        now: u64,
        cache: &mut CollateralCache,
    ) -> Result<GpuCollateral> {
        ensure!(
            bundle.version == 1 && &bundle.nonce == nonce,
            "collateral bundle version/nonce mismatch"
        );
        ensure!(
            !bundle.gpus.is_empty() && bundle.gpus.len() <= 256 && bundle.switches.len() <= 32,
            "collateral device count outside bound"
        );
        let mut selectors = BTreeMap::new();
        let mut output = GpuCollateral::default();
        for gpu in &bundle.gpus {
            let (model, status) = self.authenticate_device(
                &gpu.attestation_certificate_chain,
                &gpu.attestation_report,
                nonce,
                now,
                cache,
            )?;
            merge_status(&mut output.revocation, &status)?;
            let report = SpdmReport::parse(&gpu.attestation_report)?;
            let opaque = OpaqueData::parse(report.opaque_data())?;
            for selector in gpu_selectors(&model, &opaque)? {
                insert_selector(&mut selectors, selector)?;
            }
        }
        for switch in &bundle.switches {
            let (model, status) = self.authenticate_device(
                &switch.certificate_chain,
                &switch.attestation_report,
                nonce,
                now,
                cache,
            )?;
            merge_status(&mut output.revocation, &status)?;
            let report = SpdmReport::parse(&switch.attestation_report)?;
            let opaque = OpaqueData::parse(report.opaque_data())?;
            insert_selector(&mut selectors, switch_selector(&model, &opaque)?)?;
        }
        for selector in selectors.values() {
            let (raw, _verified) = self.manifest(selector, now, cache)?;
            merge_status(&mut output.revocation, &raw.revocation)?;
            output.manifests.push(raw.xml);
        }
        Ok(output)
    }

    fn authenticate_device(
        &self,
        chain_bytes: &[u8],
        report_bytes: &[u8],
        nonce: &[u8; 32],
        now: u64,
        cache: &mut CollateralCache,
    ) -> Result<(String, RevocationEvidence)> {
        let chain = cert::validate_chain(chain_bytes, &self.device_roots, now, Purpose::Device)?;
        let key = VerifyingKey::from_public_key_der(
            &chain
                .leaf()
                .tbs_certificate
                .subject_public_key_info
                .to_der()?,
        )?;
        let report = SpdmReport::parse(report_bytes)?;
        report.verify_signature(nonce, &key)?;
        let identity = identity::certificate_identity(&chain)?;
        let opaque = OpaqueData::parse(report.opaque_data())?;
        if opaque.field(20).is_ok() {
            identity.verify_report_fwid(opaque.bytes(20)?)?;
        } else {
            // Published legacy GH100 and LS10 reports omit field 20. Their
            // certificates and SPDM signatures remain mandatory; no successful
            // report/certificate FWID comparison is claimed for an absent field.
            ensure!(
                identity.model == "GH100" || identity.model == "LS_10",
                "authenticated device profile requires signed report FWID"
            );
        }
        let status = self.device_status(&chain, now, &mut cache.device_revocation)?;
        Ok((identity.model, status))
    }

    fn device_status(
        &self,
        chain: &ValidatedChain,
        now: u64,
        cache: &mut RevocationCache,
    ) -> Result<RevocationEvidence> {
        if let Ok(status) = cache.checked_evidence(chain, now) {
            return Ok(status.clone());
        }
        let status = self
            .revocation
            .fetch_chain(chain)
            .context("NVIDIA device revocation refresh")?;
        cache.insert(chain, status.clone(), now)?;
        Ok(status)
    }

    fn manifest(
        &self,
        selector: &Selector,
        now: u64,
        cache: &mut CollateralCache,
    ) -> Result<(CachedManifest, VerifiedRim)> {
        if let Some(cached) = cache.manifests.get(&selector.id) {
            if let Ok(verified) =
                rim::verify_xml(&cached.xml, &self.rim_roots, &cached.revocation, now)
            {
                check_selector(selector, &verified)?;
                return Ok((cached.clone(), verified));
            }
        }
        let xml = self.download(selector)?;
        let signed = rim::verify_xml_signature_and_chain(&xml, &self.rim_roots, now)?;
        let status = self
            .revocation
            .fetch_chain(signed.signer_chain())
            .context("NVIDIA RIM signer revocation refresh")?;
        let verified = rim::verify_xml(&xml, &self.rim_roots, &status, now)?;
        check_selector(selector, &verified)?;
        let raw = CachedManifest {
            xml,
            revocation: status,
        };
        ensure!(
            cache.manifests.contains_key(&selector.id) || cache.manifests.len() < MAX_MANIFESTS,
            "collateral manifest cache is full"
        );
        cache.manifests.insert(selector.id.clone(), raw.clone());
        Ok((raw, verified))
    }

    fn download(&self, selector: &Selector) -> Result<String> {
        selector_component(&selector.id, 160)?;
        let url = format!("{RIM_ENDPOINT}{}", selector.id);
        let response = self
            .http
            .get(url)
            .header("Accept", "application/json")
            .send()?
            .error_for_status()?;
        ensure!(
            response.status() == reqwest::StatusCode::OK,
            "NVIDIA RIM response is not HTTP 200"
        );
        if let Some(length) = response.content_length() {
            ensure!(
                length <= MAX_RESPONSE as u64,
                "NVIDIA RIM response exceeds size limit"
            );
        }
        let mut bytes = Vec::new();
        response
            .take(MAX_RESPONSE as u64 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= MAX_RESPONSE,
            "NVIDIA RIM response exceeds size limit"
        );
        decode_response(&bytes, &selector.id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Selector {
    id: String,
    model: String,
    version: String,
    kind: RimKind,
}

fn gpu_selectors(model: &str, opaque: &OpaqueData<'_>) -> Result<Vec<Selector>> {
    let model = super::verify::gpu_manifest_model(model)?;
    let driver = opaque.text(3)?;
    let components: Vec<_> = driver.split('.').collect();
    ensure!(
        (2..=3).contains(&components.len())
            && components
                .iter()
                .all(|c| !c.is_empty() && c.len() <= 6 && c.bytes().all(|b| b.is_ascii_digit())),
        "invalid signed driver version for RIM lookup"
    );
    let prefix = match model {
        "GH100" => "NV_GPU_DRIVER_GH100".to_owned(),
        "GB100" => {
            // The model is already authenticated by the certificate SAN.
            // Older Blackwell reports omit the redundant CHIP_INFO field;
            // when present it must agree, including its exact wire syntax.
            if opaque.field(35).is_ok() {
                ensure!(
                    opaque.text(35)? == model,
                    "signed CHIP_INFO differs from certificate model"
                );
            }
            format!("NV_GPU_CC_DRIVER_{model}")
        }
        _ => bail!("unsupported certificate-authenticated GPU model for RIM acquisition: {model}"),
    };
    let version = opaque.vbios_version()?;
    let project = opaque.text(17)?;
    let sku = opaque.text(18)?;
    let chip_sku = opaque.text(15)?;
    for component in [&project, &sku, &chip_sku] {
        selector_component(component, 32)?;
    }
    Ok(vec![
        Selector {
            id: format!("{prefix}_{driver}"),
            model: model.into(),
            version: driver,
            kind: RimKind::GpuDriver,
        },
        Selector {
            id: format!(
                "NV_GPU_VBIOS_{project}_{sku}_{chip_sku}_{}",
                version.replace('.', "")
            ),
            model: model.into(),
            version,
            kind: RimKind::GpuVbios,
        },
    ])
}

fn switch_selector(model: &str, opaque: &OpaqueData<'_>) -> Result<Selector> {
    let model = super::verify::switch_manifest_model(model)?;
    let version = opaque.switch_vbios_version()?;
    Ok(Selector {
        id: format!("NV_SWITCH_BIOS_5612_0002_890_{}", version.replace('.', "")),
        model: model.into(),
        version,
        kind: RimKind::NvSwitchVbios,
    })
}

fn insert_selector(selectors: &mut BTreeMap<String, Selector>, selector: Selector) -> Result<()> {
    if let Some(existing) = selectors.get(&selector.id) {
        ensure!(existing == &selector, "conflicting RIM selector identity");
    } else {
        ensure!(
            selectors.len() < MAX_MANIFESTS,
            "too many required RIM manifests"
        );
        selectors.insert(selector.id.clone(), selector);
    }
    Ok(())
}

fn check_selector(selector: &Selector, rim: &VerifiedRim) -> Result<()> {
    ensure!(
        rim.kind() == selector.kind
            && rim.model() == selector.model
            && rim.version() == selector.version,
        "authenticated RIM identity does not match signed device selector"
    );
    Ok(())
}

fn selector_component(value: &str, max: usize) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= max
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || [b'_', b'.'].contains(&b)),
        "invalid NVIDIA RIM identifier component"
    );
    ensure!(
        !value.contains(".."),
        "RIM identifier cannot contain dot segments"
    );
    Ok(())
}

#[derive(Deserialize)]
struct RimResponse {
    id: String,
    rim: String,
    sha256: String,
    rim_format: String,
}

fn decode_response(bytes: &[u8], requested: &str) -> Result<String> {
    let response: RimResponse =
        serde_json::from_slice(bytes).context("invalid NVIDIA RIM service response")?;
    ensure!(
        response.id == requested,
        "NVIDIA RIM response ID differs from request"
    );
    ensure!(
        response.rim_format == "TCG",
        "RIM service did not return the supported TCG XML profile"
    );
    let bytes = STANDARD
        .decode(response.rim)
        .context("invalid RIM response base64")?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_XML,
        "downloaded XML RIM size outside bound"
    );
    ensure!(
        response.sha256.len() == 64 && hex::encode(Sha256::digest(&bytes)) == response.sha256,
        "NVIDIA RIM transport hash mismatch"
    );
    // The service hash protects transport consistency only. Every caller must
    // still authenticate the XML signature/path/status before trusting content.
    String::from_utf8(bytes).context("NVIDIA RIM XML is not UTF-8")
}

fn merge_status(output: &mut RevocationEvidence, input: &RevocationEvidence) -> Result<()> {
    for (out, values) in [
        (&mut output.ocsp_responses, &input.ocsp_responses),
        (&mut output.crls, &input.crls),
    ] {
        for value in values {
            if !out.contains(value) {
                out.push(value.clone());
            }
        }
    }
    ensure!(
        output.ocsp_responses.len() + output.crls.len() <= 128,
        "combined revocation collateral exceeds object limit"
    );
    let total: usize = output
        .ocsp_responses
        .iter()
        .chain(&output.crls)
        .map(Vec::len)
        .sum();
    ensure!(
        total <= 32 * 1024 * 1024,
        "combined revocation collateral exceeds size limit"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const XML: &str = include_str!("../../testdata/gpu/rim/NV_GPU_DRIVER_GH100_550.144.03.xml");
    #[test]
    fn response_identity_hash_and_format_are_checked_before_xml_authentication() {
        let id = "NV_GPU_DRIVER_GH100_550.144.03";
        let body = serde_json::json!({"id":id,"rim":STANDARD.encode(XML),"sha256":hex::encode(Sha256::digest(XML.as_bytes())),"rim_format":"TCG"});
        assert_eq!(
            decode_response(&serde_json::to_vec(&body).unwrap(), id).unwrap(),
            XML
        );
        for (field, value) in [
            ("id", "other"),
            ("sha256", "bad"),
            ("rim_format", "CORIM"),
            ("rim", "!"),
        ] {
            let mut bad = body.clone();
            bad[field] = value.into();
            assert!(decode_response(&serde_json::to_vec(&bad).unwrap(), id).is_err());
        }
    }
    #[test]
    fn selectors_cannot_redirect_requests_or_escape_cache_keys() {
        for value in [
            "",
            "../x",
            "https://evil.invalid",
            "x/y",
            "x?secret",
            "x#part",
            "x%2fy",
            "x\\y",
        ] {
            assert!(selector_component(value, 160).is_err());
        }
    }
    #[test]
    fn cache_import_stores_bytes_without_manufacturing_a_verified_manifest() {
        let mut cache = CollateralCache::default();
        cache.manifests.insert(
            "NV_GPU_DRIVER_GH100_550.144.03".into(),
            CachedManifest {
                xml: XML.into(),
                revocation: RevocationEvidence::default(),
            },
        );
        let parsed = CollateralCache::from_json(&cache.to_json().unwrap()).unwrap();
        let raw = &parsed.manifests.values().next().unwrap();
        assert!(rim::verify_xml(
            &raw.xml,
            &cert::pinned_rim_roots().unwrap(),
            &raw.revocation,
            1_791_849_600
        )
        .is_err());
    }

    #[test]
    fn published_gpu_reports_select_exact_vendor_manifest_ids() {
        for (report, model, driver, vbios) in [
            (
                include_str!("../../testdata/gpu/nvidia/hopperAttestationReport.txt"),
                "GH100",
                "NV_GPU_DRIVER_GH100_535.86.09",
                "NV_GPU_VBIOS_1010_0200_882_96005E0001",
            ),
            (
                include_str!("../../testdata/gpu/nvidia/blackwellAttestationReport.txt"),
                "GB100",
                "NV_GPU_CC_DRIVER_GB100_575.32",
                "NV_GPU_VBIOS_G525_0220_886_970088000F",
            ),
        ] {
            // Parser/selector unit test only. Production routing additionally
            // verifies device path, revocation, nonce, signature and FWID.
            let bytes = hex::decode(report.trim()).unwrap();
            let report = SpdmReport::parse(&bytes).unwrap();
            let opaque = OpaqueData::parse(report.opaque_data()).unwrap();
            let selectors = gpu_selectors(model, &opaque).unwrap();
            assert_eq!(selectors[0].id, driver);
            assert_eq!(selectors[1].id, vbios);
        }
    }

    #[test]
    fn published_switch_certificate_and_report_select_the_signed_rim_model() {
        // Cryptographic interoperability only: there is no revocation or
        // production security-state verdict in this fixture test.
        let chain = cert::validate_chain(
            include_bytes!("../../testdata/gpu/nvidia/switchCertChain.txt"),
            &cert::pinned_device_roots().unwrap(),
            1_791_849_600,
            Purpose::Device,
        )
        .unwrap();
        let identity = identity::certificate_identity(&chain).unwrap();
        assert_eq!(identity.model, "LS_10");
        let bytes = hex::decode(
            include_str!("../../testdata/gpu/nvidia/switchAttestationReport.txt").trim(),
        )
        .unwrap();
        let report = SpdmReport::parse(&bytes).unwrap();
        let key = VerifyingKey::from_public_key_der(
            &chain
                .leaf()
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .unwrap(),
        )
        .unwrap();
        report
            .verify_signature(&report.request_nonce().try_into().unwrap(), &key)
            .unwrap();
        let opaque = OpaqueData::parse(report.opaque_data()).unwrap();
        let selector = switch_selector(&identity.model, &opaque).unwrap();
        assert_eq!(selector.id, "NV_SWITCH_BIOS_5612_0002_890_9610550001");
        assert_eq!(selector.model, "LS10");
        assert_eq!(selector.version, "96.10.55.00.01");
        assert!(switch_selector("LS10", &opaque).is_err());
        assert!(gpu_selectors("GB200", &opaque).is_err());
    }
}
