//! Host-attested guest (Gap C): a macOS host vouches for a Linux guest.
//!
//! On a Mac there is no silicon root for a Linux VM's workload, so the guest
//! cannot attest itself to hardware. Instead the macOS host runs an
//! App-Attested launcher that measures the guest image + the agent's `value_x`
//! and App-Attests with its channel binding committed to the guest's
//! `binding_bytes()`. The result is a two-stage (layered) attestation:
//!
//! - **guest stage** — a unified-quote EAT carrying the agent `value_x` (a
//!   software witness: no hardware quote, since the VM has no silicon root);
//! - **host stage** — a macOS App Attest bundle (genuine Apple device + genuine
//!   launcher app) whose binding is the guest EAT's `binding_bytes()`.
//!
//! Verifying the host stage against the guest's binding cryptographically ties
//! "a genuine Apple device + reviewed launcher app started exactly this guest
//! image" to the guest's `value_x`. Apple is the root; the guest is covered by
//! the host that launched it.

use crate::eat::EatToken;

use super::app_attest::{verify_bundle as verify_macos, MacOsAppAttestBundle};
use super::{DesktopVerdict, MACOS_HOST_ATTESTED_GUEST_PLATFORM};

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct HostAttestedGuest {
    pub version: u32,
    /// Guest stage: hex CBOR of a unified-quote EAT. Its `value_x` is the agent
    /// identity being vouched for.
    pub guest_eat: String,
    /// Host stage: a macOS App Attest bundle whose `binding` is the guest EAT's
    /// `binding_bytes()`.
    pub host: MacOsAppAttestBundle,
}

#[derive(Debug, thiserror::Error)]
pub enum HostGuestError {
    #[error("parse: {0}")]
    Parse(String),
    #[error("guest eat: {0}")]
    GuestEat(String),
    #[error("host app attest: {0}")]
    Host(String),
}

/// Verify a host-attested-guest bundle. On success the returned
/// [`DesktopVerdict::identity_hash`] is the guest agent's `value_x` (hex) — the
/// identity a gate allowlists — and the platform label marks it host-attested.
pub fn verify_bundle(b: &HostAttestedGuest) -> Result<DesktopVerdict, HostGuestError> {
    if b.version != 1 {
        return Err(HostGuestError::Parse(format!(
            "unsupported version {}",
            b.version
        )));
    }

    let guest_cbor = hex::decode(b.guest_eat.trim())
        .map_err(|e| HostGuestError::Parse(format!("guest_eat hex: {e}")))?;
    let guest =
        EatToken::from_cbor(&guest_cbor).map_err(|e| HostGuestError::GuestEat(e.to_string()))?;

    // The host App Attest must commit to exactly this guest's binding, so the
    // Apple-vouched device+app is tied to this guest image, not another.
    let binding = guest.binding_bytes();
    verify_macos(&b.host, &binding).map_err(|e| HostGuestError::Host(e.to_string()))?;

    Ok(DesktopVerdict {
        verdict: "verified".into(),
        platform: MACOS_HOST_ATTESTED_GUEST_PLATFORM.into(),
        identity_hash: hex::encode(guest.value_x),
        ima_verified: false,
        boot_aggregate: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eat::{EatToken, DEFAULT_BINDING_SUITE, EAT_PROFILE, EAT_VERSION};
    use crate::tee::desktop::MACOS_APP_ATTEST_PLATFORM;

    fn guest_eat(value_x: [u8; 48]) -> EatToken {
        EatToken {
            version: EAT_VERSION,
            eat_profile: EAT_PROFILE.to_string(),
            binding_suite: DEFAULT_BINDING_SUITE,
            value_x,
            platform: 2, // carrier only; the guest has no hardware quote
            platform_measurement: vec![0u8; 48],
            platform_quote: Vec::new(),
            tls_spki_hash: [0u8; 32],
            source_hash: [0u8; 48],
            artifact_hash: [0u8; 48],
            iat: 1,
            eat_nonce: [0u8; 32],
            previous_attestation: Vec::new(),
        }
    }

    fn host_bundle(binding_hex: &str, client_data_hex: &str) -> MacOsAppAttestBundle {
        MacOsAppAttestBundle {
            version: 1,
            platform: MACOS_APP_ATTEST_PLATFORM.to_string(),
            key_id: String::new(),
            assertion: String::new(),
            credential_public_key: String::new(),
            app_id_hash: String::new(),
            team_id: "TEAMID".into(),
            bundle_id: "com.example.launcher".into(),
            binding: binding_hex.to_string(),
            client_data_hash: client_data_hex.to_string(),
        }
    }

    #[test]
    fn rejects_host_binding_not_matching_guest() {
        let guest = guest_eat([0xAB; 48]);
        let b = HostAttestedGuest {
            version: 1,
            guest_eat: hex::encode(guest.to_cbor().unwrap()),
            // Host committed to the wrong binding.
            host: host_bundle(&hex::encode([0xFFu8; 32]), &hex::encode([0u8; 32])),
        };
        let err = verify_bundle(&b).unwrap_err().to_string();
        assert!(err.contains("binding does not match"), "got: {err}");
    }

    #[test]
    fn correct_binding_advances_past_binding_check() {
        // When the host binding equals the guest's binding_bytes(), verification
        // proceeds past the binding check (failing later at the client-data /
        // assertion step, which needs a real Apple signature). This proves the
        // guest->host binding linkage is computed correctly.
        let guest = guest_eat([0x11; 48]);
        let binding = guest.binding_bytes();
        let b = HostAttestedGuest {
            version: 1,
            guest_eat: hex::encode(guest.to_cbor().unwrap()),
            host: host_bundle(&hex::encode(binding), &hex::encode([0u8; 32])),
        };
        let err = verify_bundle(&b).unwrap_err().to_string();
        assert!(
            !err.contains("binding does not match"),
            "binding linkage should have matched; got: {err}"
        );
    }

    #[test]
    fn rejects_malformed_guest_eat() {
        let b = HostAttestedGuest {
            version: 1,
            guest_eat: "not-hex".into(),
            host: host_bundle(&hex::encode([0u8; 32]), &hex::encode([0u8; 32])),
        };
        assert!(verify_bundle(&b).is_err());
    }
}
