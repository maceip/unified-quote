//! Pinned root CA fingerprints for TEE vendors.
//!
//! These are the trust anchors. If the root cert in a quote's chain
//! doesn't match one of these fingerprints, the quote is rejected.
//! Without this check, an attacker with their own CA could forge
//! an entire cert chain.

use sha2::{Digest, Sha256};

/// AWS Nitro Attestation Root CA fingerprint (SHA-256 of DER-encoded cert).
/// Computed from the root cert in a real Nitro attestation document's cabundle.
/// This is the first cert in the cabundle (closest to root).
pub const AWS_NITRO_ROOT_SHA256: &str =
    "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b";

/// AMD ARK (Root Key) fingerprint for Milan — SHA-256 of the DER-encoded
/// self-signed `CN=ARK-Milan` cert. This same ARK roots both the VCEK chain
/// (`/vcek/v1/Milan/cert_chain`) and the VLEK chain (`/vlek/v1/Milan/cert_chain`);
/// the two chains carry a byte-identical ARK.
pub const AMD_ARK_MILAN_SHA256: &str =
    "69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd";

/// AMD ARK (Root Key) fingerprint for Genoa — SHA-256 of the DER-encoded
/// self-signed `CN=ARK-Genoa` cert (verified against the live KDS chain).
/// As with Milan, this same ARK roots both the VCEK and VLEK chains.
/// Source: https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain (2nd cert = ARK).
pub const AMD_ARK_GENOA_SHA256: &str =
    "4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1";

/// AMD ARK (Root Key) fingerprint for Turin — SHA-256 of the DER-encoded
/// self-signed `CN=ARK-Turin` cert (verified against the live KDS chain).
/// Source: https://kdsintf.amd.com/vcek/v1/Turin/cert_chain (2nd cert = ARK).
pub const AMD_ARK_TURIN_SHA256: &str =
    "1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a";

/// Intel SGX Root CA fingerprint (SHA-256 of DER-encoded cert).
/// Computed from the root cert in a real TDX quote's embedded cert chain.
pub const INTEL_SGX_ROOT_SHA256: &str =
    "44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3";

/// Check if a DER-encoded certificate matches a pinned fingerprint.
pub fn verify_root_fingerprint(cert_der: &[u8], expected_fingerprint: &str) -> bool {
    let actual = hex::encode(Sha256::digest(cert_der));
    actual == expected_fingerprint
}
