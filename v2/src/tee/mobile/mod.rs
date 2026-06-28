//! Mobile app-identity attestation (verify-only; collection is in the host app).
//!
//! Android: KeyMint key attestation (no Play Integrity).
//! iOS: App Attest assertion bound to eat-pass channel binding.

#[cfg(feature = "mobile")]
pub mod android;
#[cfg(feature = "mobile")]
pub mod ios;

use sha2::{Digest, Sha256};

pub const ANDROID_PLATFORM: &str = "android-key-attestation";
pub const IOS_PLATFORM: &str = "ios-app-attest";

const ANDROID_APP_ID_DOMAIN: &[u8] = b"uq/mobile/android/v1\0";
const IOS_CLIENT_DATA_DOMAIN: &[u8] = b"uq/mobile/ios/v1\0";
const IOS_APP_ID_DOMAIN: &[u8] = b"uq/mobile/ios-app-id/v1\0";

/// Allowlist identity for an Android release (package + signing cert digest).
pub fn android_app_id_hash(package_name: &str, signing_cert_sha256: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ANDROID_APP_ID_DOMAIN);
    h.update(package_name.as_bytes());
    h.update([0u8]);
    h.update(signing_cert_sha256);
    h.finalize().into()
}

/// Allowlist identity for an iOS release (team id + bundle id).
pub fn ios_app_id_hash(team_id: &str, bundle_id: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(IOS_APP_ID_DOMAIN);
    h.update(team_id.as_bytes());
    h.update([0u8]);
    h.update(bundle_id.as_bytes());
    h.finalize().into()
}

/// `clientDataHash` passed to `generateAssertion` on iOS (must match server).
pub fn ios_client_data_hash(binding: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(IOS_CLIENT_DATA_DOMAIN);
    h.update(binding);
    h.finalize().into()
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MobileVerdict {
    pub verdict: String,
    pub platform: String,
    /// Hex-encoded allowlist key (32 bytes).
    pub app_id_hash: String,
    pub package_or_bundle: String,
}
