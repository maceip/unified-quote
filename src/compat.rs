//! Ecosystem compatibility layer.
//!
//! Provides conversion between our UnifiedQuote format and other
//! TEE attestation ecosystems:
//!
//! - CoCo (Confidential Containers) kbs-types: Tee enum + evidence format
//! - Constellation: OID-based variant identifiers
//! - IETF RATS: EAT (Entity Attestation Token) profile alignment
//!
//! Goal: anyone already using CoCo or Constellation can consume our
//! quotes without writing custom parsers, and vice versa.

use crate::quote::{Platform, UnifiedQuote};
use serde::{Deserialize, Serialize};

// ============================================================================
// CoCo kbs-types compatibility
// ============================================================================

/// CoCo TEE type enum, matching kbs-types::Tee serialization.
/// We support the three bare TEE types; Azure vTPM variants are
/// cloud-specific wrappers that CoCo adds for Azure Attestation Service.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CocoTee {
    Snp,
    Tdx,
    Sgx,
    // Nitro is not in CoCo's enum — we extend it
    #[serde(rename = "nitro")]
    Nitro,
}

impl From<Platform> for CocoTee {
    fn from(p: Platform) -> Self {
        match p {
            Platform::Nitro => CocoTee::Nitro,
            Platform::SevSnp => CocoTee::Snp,
            Platform::Tdx => CocoTee::Tdx,
        }
    }
}

impl From<CocoTee> for Platform {
    fn from(t: CocoTee) -> Self {
        match t {
            CocoTee::Nitro => Platform::Nitro,
            CocoTee::Snp => Platform::SevSnp,
            CocoTee::Tdx => Platform::Tdx,
            CocoTee::Sgx => Platform::Tdx, // SGX maps to TDX for DCAP compat
        }
    }
}

/// CoCo-compatible attestation evidence wrapper.
/// Matches the structure expected by kbs-types Attestation flow.
#[derive(Debug, Serialize, Deserialize)]
pub struct CocoEvidence {
    /// TEE type (kbs-types compatible).
    pub tee: CocoTee,
    /// Base64-encoded raw platform quote.
    pub evidence: String,
    /// Runtime data: nonce and TEE public key.
    pub runtime_data: CocoRuntimeData,
    /// unified-quote extensions (ignored by standard CoCo consumers).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uq: Option<UqExtension>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CocoRuntimeData {
    pub nonce: String,
    #[serde(rename = "tee-pubkey")]
    pub tee_pubkey: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UqExtension {
    pub value_x: String,
    pub unified_quote_hash: String,
    pub integrity_ok: bool,
    pub heartbeat_seq: u64,
}

impl UnifiedQuote {
    /// Convert to CoCo-compatible evidence format.
    /// The raw platform quote is base64-encoded, matching kbs-types expectations.
    pub fn to_coco_evidence(&self) -> CocoEvidence {
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;

        let evidence = self
            .platform_quote
            .as_ref()
            .map(|q| engine.encode(q))
            .unwrap_or_default();

        CocoEvidence {
            tee: CocoTee::from(self.platform),
            evidence,
            runtime_data: CocoRuntimeData {
                nonce: hex::encode(self.nonce),
                tee_pubkey: hex::encode(self.pubkey),
            },
            uq: Some(UqExtension {
                value_x: hex::encode(self.value_x),
                unified_quote_hash: hex::encode(self.platform_quote_hash),
                integrity_ok: self.integrity_ok,
                heartbeat_seq: self.heartbeat_seq,
            }),
        }
    }
}

// ============================================================================
// Constellation variant compatibility
// ============================================================================

/// Constellation OID-based variant identifier.
/// Constellation encodes cloud+TEE in ASN.1 OIDs under 1.3.9900.*.
pub struct ConstellationVariant {
    pub oid: &'static str,
    pub name: &'static str,
}

/// Map our Platform to the closest Constellation variant.
/// Since we don't track cloud provider, we use the generic variants.
pub fn to_constellation_variant(platform: Platform, cloud: Option<&str>) -> ConstellationVariant {
    match (platform, cloud) {
        (Platform::SevSnp, Some("aws")) => ConstellationVariant {
            oid: "1.3.9900.2.2",
            name: "aws-sev-snp",
        },
        (Platform::SevSnp, Some("gcp")) => ConstellationVariant {
            oid: "1.3.9900.3.2",
            name: "gcp-sev-snp",
        },
        (Platform::SevSnp, Some("azure")) => ConstellationVariant {
            oid: "1.3.9900.4.1",
            name: "azure-sev-snp",
        },
        (Platform::SevSnp, _) => ConstellationVariant {
            oid: "1.3.9900.2.2",
            name: "sev-snp",
        },
        (Platform::Tdx, Some("azure")) => ConstellationVariant {
            oid: "1.3.9900.4.3",
            name: "azure-tdx",
        },
        (Platform::Tdx, _) => ConstellationVariant {
            oid: "1.3.9900.5.99",
            name: "tdx",
        },
        (Platform::Nitro, _) => ConstellationVariant {
            oid: "1.3.9900.2.1",
            name: "aws-nitro",
        },
    }
}

// ============================================================================
// IETF RATS / EAT alignment notes
// ============================================================================
//
// To align with IETF RATS (RFC 9334) and EAT (RFC 9711):
//
// 1. Our UnifiedQuote maps to a RATS "Evidence" artifact.
//    The platform_quote is the raw evidence, UnifiedQuote is the wrapper.
//
// 2. EAT profiles use CBOR/COSE encoding. To produce an EAT token:
//    - Encode our fields as CBOR claims
//    - Sign with COSE_Sign1 (currently we use ed25519, EAT prefers ES256/ES384)
//    - Add standard EAT claims: eat_nonce, oemid, hwmodel, swname, swversion
//
// 3. CoRIM (Concise Reference Integrity Manifest) could encode our
//    Value X registry as reference values for automated policy checking.
//
// 4. AR4SI (Attestation Results for Secure Interactions) is the output
//    of verification — our VerificationResult maps to this.
//
// Future: implement to_eat_token() and from_eat_token() for full
// IETF interop. Requires ciborium + coset crates (already in deps for Nitro).
