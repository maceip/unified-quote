//! Native NVIDIA GPU/NVSwitch collection and attestation appraisal.
//!
//! Enable the `gpu` feature. [`NvmlCollector`] dynamically loads the Linux
//! driver library and captures every enumerated GPU under one caller-supplied
//! challenge. [`spdm::SpdmReport`] parses the signed measurement transcript
//! and checks its nonce and P-384 signature against a caller-supplied key.
//!
//! [`verify::GpuVerifier`] authenticates certificates, revocation, signed RIMs,
//! security state and enrolled inventory; [`crate::AttestationVerifier`] also
//! checks the CPU commitment, challenge and TLS key. Missing required claims
//! fail closed. See `v2/GPU.md` for supported formats and remaining vendor-profile
//! constraints. NVML metadata is not signed evidence or a trust anchor.

pub mod cert;
pub mod collateral;
pub mod corim;
pub mod identity;
pub mod nscq;
pub mod nvml;
pub mod opaque;
pub mod revocation;
pub mod rim;
pub mod spdm;
pub mod verify;

pub use nvml::NvmlCollector;

use serde::{Deserialize, Serialize};

/// Raw, unverified evidence. This is deliberately separate from `EatToken`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuEvidenceBundle {
    pub version: u32,
    pub nonce: [u8; 32],
    /// Informational NVML metadata, not an authenticated driver measurement.
    pub driver_version: String,
    pub cc_state: NvmlCcState,
    pub gpus: Vec<GpuEvidence>,
    #[serde(default)]
    pub switches: Vec<SwitchEvidence>,
    #[serde(default)]
    pub collateral: GpuCollateral,
}

/// Untrusted, signed vendor material. Verification authenticates it using the
/// verifier's pins and clock, never a timestamp or trust decision in this bag.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuCollateral {
    pub manifests: Vec<String>,
    pub revocation: revocation::RevocationEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwitchEvidence {
    pub uuid: String,
    pub tnvl_mode: i8,
    #[serde(with = "serde_bytes")]
    pub certificate_chain: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub attestation_report: Vec<u8>,
}

/// Driver-reported state, not signed SPDM security claims or admission policy.
/// Collecting evidence never changes the driver's GPU ready state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvmlCcState {
    pub environment: u32,
    pub cc_feature: u32,
    pub dev_tools_mode: u32,
    pub accepting_client_requests: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuEvidence {
    /// NVML inventory position; not a cryptographic device identity.
    pub index: u32,
    pub uuid: String,
    pub name: String,
    pub vbios_version: String,
    /// Original NVML certificate buffers, preserved without re-encoding.
    #[serde(with = "serde_bytes")]
    pub certificate_chain: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub attestation_certificate_chain: Vec<u8>,
    /// SPDM GET_MEASUREMENTS request followed by its signed response.
    #[serde(with = "serde_bytes")]
    pub attestation_report: Vec<u8>,
    /// Preserved when present; CEC appraisal is not implemented yet.
    #[serde(with = "serde_bytes")]
    pub cec_attestation_report: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum GpuError {
    #[error("native NVML collection requires Linux; SPDM parsing is portable")]
    UnsupportedHost,
    #[error("cannot load NVML: {0}")]
    Library(String),
    #[error("NVML {operation} failed with status {code}")]
    Nvml { operation: &'static str, code: i32 },
    #[error("invalid GPU evidence: {0}")]
    InvalidEvidence(String),
    #[error("GPU {index}: {source}")]
    Device {
        index: u32,
        #[source]
        source: Box<GpuError>,
    },
    #[error(transparent)]
    Spdm(#[from] spdm::SpdmError),
}
