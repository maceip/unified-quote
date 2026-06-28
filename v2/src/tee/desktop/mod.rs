//! Non-CVM desktop client attestation (verify-only; collection via host tools / SDK).
//!
//! Linux / Windows: TPM2 AK quote with eat-pass channel binding as qualifying data.
//! macOS: App Attest (same crypto as iOS, distinct platform label).

pub mod app_attest;
pub mod tpm;

use sha2::{Digest, Sha256};

pub const LINUX_TPM_PLATFORM: &str = "linux-tpm-client";
pub const WINDOWS_TPM_PLATFORM: &str = "windows-tpm-client";
pub const MACOS_APP_ATTEST_PLATFORM: &str = "macos-app-attest";

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
}
