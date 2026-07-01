//! UnifiedQuote: the "one ring" attestation format.
//!
//! This is what goes on-chain (compact) and what remote verifiers consume.
//! Design principles:
//! - value_x is deterministic across all platforms (LATTE layer 1)
//! - platform_quote varies per TEE but is hash-linked (LATTE layer 2)
//! - On-chain footprint: ~180 bytes (no raw quote, just hash)
//! - Off-chain: full quote available for deep verification

pub mod eat;
pub mod roots;
pub mod value_x;
pub mod verify;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_with::{hex::Hex, serde_as};
use sha2::{Digest, Sha256};

/// TEE platform identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Platform {
    Nitro = 1,
    SevSnp = 2,
    Tdx = 3,
}

/// The unified attestation quote — platform-agnostic wrapper.
///
/// This is the "one ring": a single format that any on-chain oracle
/// or remote verifier can consume regardless of TEE backend.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedQuote {
    pub version: u8,
    pub platform: Platform,

    // --- LATTE Layer 1: Application identity (DETERMINISTIC) ---
    /// sha384(runner image manifest) — same value on any platform.
    /// This is Value X.
    #[serde_as(as = "Hex")]
    pub value_x: [u8; 48],

    // --- LATTE Layer 2: Platform proof (VARIES) ---
    /// Raw TEE quote bytes. Stored off-chain (IPFS/Arweave/HTTP).
    /// Verifiers who want to check hardware authenticity fetch this.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde_as(as = "Option<Hex>")]
    pub platform_quote: Option<Vec<u8>>,

    /// sha256(platform_quote) — stored on-chain, links to the full quote.
    #[serde_as(as = "Hex")]
    pub platform_quote_hash: [u8; 32],

    // --- LATTE Layer 3: Build provenance (Attestable Builds) ---
    /// sha256 of the build attestation (e.g., Sigstore bundle from GitHub Actions).
    /// Links this runtime quote to the CI pipeline that built the image.
    /// None if build provenance is not available.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde_as(as = "Option<Hex>")]
    pub build_attestation_hash: Option<[u8; 32]>,

    // --- TCB (Trusted Computing Base) status ---
    /// Platform TCB version string for key rotation tracking.
    /// Format varies: TDX="TEE_TCB_SVN hex", SNP="reported_tcb hex", Nitro=None.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcb_version: Option<String>,

    // --- Runtime integrity ---
    /// Whether the runtime integrity monitor confirms Value X unchanged since boot.
    /// false means disk contents changed after attestation — treat with suspicion.
    #[serde(default = "default_true")]
    pub integrity_ok: bool,

    /// Heartbeat sequence number. Monotonically increasing. Gaps indicate
    /// the TEE stopped producing quotes for a period.
    #[serde(default)]
    pub heartbeat_seq: u64,

    // --- Binding ---
    pub timestamp: u64,
    #[serde_as(as = "Hex")]
    pub nonce: [u8; 32],

    // --- TEE-derived signature ---
    /// Ed25519 signature over the canonical encoding of all fields above.
    #[serde_as(as = "Hex")]
    pub signature: [u8; 64],
    /// Public key of the TEE-derived signing keypair.
    /// The platform_quote proves this key was generated inside the enclave.
    #[serde_as(as = "Hex")]
    pub pubkey: [u8; 32],
}

impl UnifiedQuote {
    /// Construct and sign a new UnifiedQuote.
    ///
    /// `signing_key` must be a key derived inside the TEE, bound to
    /// the attestation report via report_data.
    pub fn new(
        platform: Platform,
        value_x: [u8; 48],
        platform_quote: Vec<u8>,
        nonce: [u8; 32],
        signing_key: &SigningKey,
    ) -> Self {
        Self::new_with_metadata(
            platform,
            value_x,
            platform_quote,
            nonce,
            signing_key,
            None,
            None,
            true,
            0,
        )
    }

    /// Construct a UnifiedQuote with full metadata (build provenance, TCB, integrity).
    pub fn new_with_metadata(
        platform: Platform,
        value_x: [u8; 48],
        platform_quote: Vec<u8>,
        nonce: [u8; 32],
        signing_key: &SigningKey,
        build_attestation_hash: Option<[u8; 32]>,
        tcb_version: Option<String>,
        integrity_ok: bool,
        heartbeat_seq: u64,
    ) -> Self {
        let platform_quote_hash: [u8; 32] = Sha256::digest(&platform_quote).into();

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_secs();

        let msg =
            Self::canonical_message(platform, &value_x, &platform_quote_hash, timestamp, &nonce);

        let signature: Signature = signing_key.sign(&msg);
        let pubkey: [u8; 32] = signing_key.verifying_key().to_bytes();

        Self {
            version: 1,
            platform,
            value_x,
            platform_quote: Some(platform_quote),
            platform_quote_hash,
            build_attestation_hash,
            tcb_version,
            integrity_ok,
            heartbeat_seq,
            timestamp,
            nonce,
            signature: signature.to_bytes(),
            pubkey,
        }
    }

    /// The on-chain compact form: strip the raw platform quote.
    /// Retains all metadata fields (build provenance, TCB, integrity).
    pub fn compact(&self) -> Self {
        let mut c = self.clone();
        c.platform_quote = None;
        c
    }

    /// Verify the signature over the quote fields.
    pub fn verify_signature(&self) -> Result<(), ed25519_dalek::SignatureError> {
        let vk = VerifyingKey::from_bytes(&self.pubkey)?;
        let msg = Self::canonical_message(
            self.platform,
            &self.value_x,
            &self.platform_quote_hash,
            self.timestamp,
            &self.nonce,
        );
        let sig = Signature::from_bytes(&self.signature);
        vk.verify_strict(&msg, &sig)
    }

    /// Canonical byte string for signing/verification.
    /// version (1) || platform (1) || value_x (48) || quote_hash (32) || timestamp (8) || nonce (32)
    fn canonical_message(
        platform: Platform,
        value_x: &[u8; 48],
        platform_quote_hash: &[u8; 32],
        timestamp: u64,
        nonce: &[u8; 32],
    ) -> Vec<u8> {
        let mut msg = Vec::with_capacity(1 + 1 + 48 + 32 + 8 + 32);
        msg.push(1u8); // version
        msg.push(platform as u8);
        msg.extend_from_slice(value_x);
        msg.extend_from_slice(platform_quote_hash);
        msg.extend_from_slice(&timestamp.to_be_bytes());
        msg.extend_from_slice(nonce);
        msg
    }
}

impl UnifiedQuote {
    /// Convert to an EAT token (COSE_Sign1 over CBOR).
    /// This is the canonical binary format for wire transport.
    pub fn to_eat(&self, signing_key: &SigningKey) -> eat::EatToken {
        let claims = eat::EatClaims {
            value_x: self.value_x,
            platform: self.platform,
            pubkey: self.pubkey,
            quote_hash: self.platform_quote_hash,
            platform_quote: self.platform_quote.clone(),
            tcb_version: self.tcb_version.clone(),
            collateral_hash: None,
            build_hash: self.build_attestation_hash,
            source_commit: None,
            registry_entry: None,
            iat: self.timestamp,
            nonce: self.nonce,
            heartbeat_seq: self.heartbeat_seq,
            integrity_ok: self.integrity_ok,
        };
        eat::EatToken::sign(claims, signing_key)
    }

    /// Create a UnifiedQuote from an EAT token's claims.
    /// Used when receiving an EAT token and needing JSON compat.
    pub fn from_eat(claims: &eat::EatClaims) -> Self {
        Self {
            version: 2,
            platform: claims.platform,
            value_x: claims.value_x,
            platform_quote: claims.platform_quote.clone(),
            platform_quote_hash: claims.quote_hash,
            build_attestation_hash: claims.build_hash,
            tcb_version: claims.tcb_version.clone(),
            integrity_ok: claims.integrity_ok,
            heartbeat_seq: claims.heartbeat_seq,
            timestamp: claims.iat,
            nonce: claims.nonce,
            // Signature/pubkey from the EAT are COSE-level, not field-level.
            // For JSON compat, zero these — use EAT verification instead.
            signature: [0u8; 64],
            pubkey: claims.pubkey,
        }
    }
}

fn default_true() -> bool {
    true
}

/// On-chain representation — just the fields an oracle stores.
/// ~180 bytes total.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnChainAttestation {
    #[serde_as(as = "Hex")]
    pub value_x: [u8; 48],
    pub platform: Platform,
    #[serde_as(as = "Hex")]
    pub platform_quote_hash: [u8; 32],
    pub timestamp: u64,
    #[serde_as(as = "Hex")]
    pub nonce: [u8; 32],
    #[serde_as(as = "Hex")]
    pub signature: [u8; 64],
    #[serde_as(as = "Hex")]
    pub pubkey: [u8; 32],
}

impl From<&UnifiedQuote> for OnChainAttestation {
    fn from(q: &UnifiedQuote) -> Self {
        Self {
            value_x: q.value_x,
            platform: q.platform,
            platform_quote_hash: q.platform_quote_hash,
            timestamp: q.timestamp,
            nonce: q.nonce,
            signature: q.signature,
            pubkey: q.pubkey,
        }
    }
}
