//! Non-CVM desktop client attestation (verify-only; collection via host tools / SDK).
//!
//! Linux / Windows: TPM2 AK quote with eat-pass channel binding as qualifying data.
//! macOS: App Attest (same crypto as iOS, distinct platform label).

pub mod app_attest;
pub mod host_guest;
pub mod tpm;

use sha2::{Digest, Sha256};

pub const LINUX_TPM_PLATFORM: &str = "linux-tpm-client";
pub const WINDOWS_TPM_PLATFORM: &str = "windows-tpm-client";
pub const MACOS_APP_ATTEST_PLATFORM: &str = "macos-app-attest";
/// A Linux guest (no silicon root of its own) vouched for by a genuine macOS
/// host running an App-Attested launcher that measured the guest image.
pub const MACOS_HOST_ATTESTED_GUEST_PLATFORM: &str = "macos-host-attested-guest";

const BUILD_ID_DOMAIN: &[u8] = b"uq/desktop/build-id/v1\0";

/// Allowlist identity for a desktop agent release (binary / bundle digest).
pub fn desktop_build_id_hash(build_digest: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(BUILD_ID_DOMAIN);
    h.update(build_digest);
    h.finalize().into()
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DesktopVerdict {
    pub verdict: String,
    pub platform: String,
    /// Hex-encoded 32-byte allowlist key (`build_id_hash` or `app_id_hash`).
    pub identity_hash: String,
    /// True when the agent binary identity was proven by a hardware-measured
    /// IMA log reproduced into a TPM-quoted PCR (not merely self-reported).
    /// App Attest verdicts leave this false (Apple vouches for app identity
    /// directly, no IMA).
    #[serde(default)]
    pub ima_verified: bool,
    /// Hex sha256 over the TPM-quoted boot PCRs (PCR 0-9): a known-good-boot
    /// fingerprint the policy can allowlist. Present only for IMA-verified TPM
    /// bundles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_aggregate: Option<String>,
}
