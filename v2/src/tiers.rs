//! Honest assurance tiers (Gap D).
//!
//! Different attestation roots prove different things; collapsing them into one
//! "secure" badge is dishonest. This classifier maps a verified platform label
//! (+ whether a hardware-measured IMA log was proven) to an explicit tier and a
//! sub-detail, so dashboards and gates can show *what was actually proven*:
//!
//! - `silicon-cvm` — rooted in a CPU vendor (SEV-SNP / TDX / Nitro / Azure
//!   vTPM-rooted SNP). The strongest tier.
//! - `device-attested` — rooted in a consumer secure element (TPM EK, Apple
//!   Secure Enclave / App Attest). Sub-detail distinguishes a hardware-measured
//!   binary (`tpm-ima`) from channel-bound-only (`tpm-channel-bound`), App
//!   Attest, and a host-attested guest.
//! - `relay-inherited` — a device-attested endpoint leaning on a verified cloud
//!   TEE via a relay credential (see [`crate::relay`]).
//! - `software-witness` — no hardware root. Honest floor.

pub const TIER_SILICON_CVM: &str = "silicon-cvm";
pub const TIER_DEVICE_ATTESTED: &str = "device-attested";
pub const TIER_RELAY_INHERITED: &str = "relay-inherited";
pub const TIER_SOFTWARE_WITNESS: &str = "software-witness";

/// The assurance tier and a finer-grained detail for a verified platform label.
/// `ima_verified` only refines the desktop-TPM detail.
pub fn assurance_tier(platform: &str, ima_verified: bool) -> (&'static str, String) {
    let p = platform.trim().to_ascii_lowercase().replace('_', "-");
    match p.as_str() {
        "sev-snp" | "tdx" | "nitro" | "aws-nitro" | "azure-sev-snp-vtpm" => (TIER_SILICON_CVM, p),
        "linux-tpm-client" | "windows-tpm-client" => {
            let detail = if ima_verified {
                "tpm-ima"
            } else {
                "tpm-channel-bound"
            };
            (TIER_DEVICE_ATTESTED, detail.to_string())
        }
        "macos-app-attest" | "ios-app-attest" | "android-key-attestation" => {
            (TIER_DEVICE_ATTESTED, "app-attest".to_string())
        }
        "macos-host-attested-guest" => (TIER_DEVICE_ATTESTED, "host-attested-guest".to_string()),
        other if other.starts_with("relay") => (TIER_RELAY_INHERITED, "relay".to_string()),
        other => (TIER_SOFTWARE_WITNESS, other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn silicon_roots() {
        assert_eq!(assurance_tier("sev-snp", false).0, TIER_SILICON_CVM);
        assert_eq!(assurance_tier("tdx", false).0, TIER_SILICON_CVM);
        assert_eq!(
            assurance_tier("azure-sev-snp-vtpm", false).0,
            TIER_SILICON_CVM
        );
    }

    #[test]
    fn tpm_ima_distinguished_from_channel_bound() {
        assert_eq!(
            assurance_tier("linux-tpm-client", true),
            (TIER_DEVICE_ATTESTED, "tpm-ima".to_string())
        );
        assert_eq!(
            assurance_tier("linux-tpm-client", false),
            (TIER_DEVICE_ATTESTED, "tpm-channel-bound".to_string())
        );
    }

    #[test]
    fn app_attest_and_host_guest() {
        assert_eq!(
            assurance_tier("macos-app-attest", false).0,
            TIER_DEVICE_ATTESTED
        );
        assert_eq!(
            assurance_tier("macos-host-attested-guest", false),
            (TIER_DEVICE_ATTESTED, "host-attested-guest".to_string())
        );
    }

    #[test]
    fn relay_and_software_floor() {
        assert_eq!(
            assurance_tier("relay-inherited", false).0,
            TIER_RELAY_INHERITED
        );
        assert_eq!(
            assurance_tier("software-witness", false).0,
            TIER_SOFTWARE_WITNESS
        );
        assert_eq!(assurance_tier("whatever", false).0, TIER_SOFTWARE_WITNESS);
    }
}
