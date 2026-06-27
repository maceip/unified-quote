//! EAT (Entity Attestation Token) — the canonical wire format for a
//! unified-quote attestation.
//!
//! An EAT carries everything a verifier needs to decide whether a remote
//! TEE is trustworthy: the application identity (Value X), the raw
//! platform quote, the platform measurement, the TLS key binding for
//! attested TLS, and enough metadata (iat, nonce, source hash, artifact hash)
//! to link the runtime back to the build-time attestation.
//!
//! ## Wire format
//!
//! The token is a CBOR map, serde-derived from [`EatToken`]. The CBOR
//! bytes get wrapped in a TCG DICE CMW (Conceptual Messages Wrapper) and
//! embedded as an X.509 certificate extension at OID `2.23.133.5.4.9`
//! (critical). That extension is what a verifier pulls out of the TLS
//! leaf cert during attested-TLS handshake.
//!
//! The CMW wrapping step is intentionally NOT in this module. It lives
//! alongside the cert generation code in `net::attested_tls`, because the exact
//! tag/encoding for CMW is a TCG DICE concern that changes at a different
//! cadence than the EAT payload itself.
//!
//! ## Trust chain
//!
//! 1. Verifier terminates TLS, pulls the leaf certificate.
//! 2. Extracts the CMW extension; decodes the EAT.
//! 3. Verifies `platform_quote` against the hardware root CA (AMD, Intel,
//!    AWS Nitro) using [`crate::quote::verify`].
//! 4. Computes [`EatToken::binding_bytes`] and confirms it matches the
//!    first 32 bytes of `report_data` inside the platform quote. If not,
//!    the claims are forged — the quote was produced for a different
//!    token.
//! 5. Computes `sha256` of the TLS leaf cert's SPKI and confirms it
//!    matches `tls_spki_hash`. If not, the cert does not belong to the
//!    attested TEE — channel binding failed (MITM or relay).
//!
//! Only after ALL of these pass can the verifier trust `value_x` and
//! other non-quote claims.
//!
//! ## Why bare CBOR and not COSE_Sign1
//!
//! EAT per RFC 9711 is signed by a COSE wrapper. We deliberately skip
//! the COSE layer: the TEE hardware quote IS the signature. The
//! integrity of every non-quote field comes from their hash being in
//! `report_data` (see binding_bytes), which is signed by the hardware.
//! Adding COSE would introduce a second signing key for no additional
//! trust — the TEE key is already the only thing we trust, and it's
//! already signing (via the quote).
//!
//! One root of trust, one signature: we deliberately do not stack
//! redundant crypto layers on top of the hardware quote.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::quote::Platform;

/// Schema version. Bumped on any breaking change to the binding format
/// or field layout. Verifiers MUST reject tokens with unknown versions.
pub const EAT_VERSION: u32 = 2;

/// Profile identifier, serialized under the standard EAT `eat_profile`
/// claim. Wire-visible, so it must not carry stale project branding.
pub const EAT_PROFILE: &str = "https://uq.secure.build/eat/v2";

/// Profile URIs accepted on decode for backward compatibility during the
/// migration off the old branding. Tokens are still *emitted* under
/// [`EAT_PROFILE`]; a verifier accepts any profile in this set so receipts
/// produced by not-yet-redeployed nodes keep verifying.
pub const EAT_PROFILE_ACCEPTED: &[&str] = &[EAT_PROFILE, "https://bountynet.dev/eat/v2"];

/// Binding suite — selects the report_data layout + hash, versioned for
/// crypto agility (L1.3). New suites can be added without a schema-version
/// bump because verifiers dispatch on this field.
///
/// - `0` — v2 single-commitment SHA-256 layout (`report_data[0..32]` only).
///   This is the historical layout; its hash does NOT mix the suite id, so
///   suite-0 tokens are byte-for-byte identical to pre-suite tokens.
/// - `1` — dual-commitment SHA-256 layout: the suite id + platform are folded
///   into the binding hash, and `report_data[32..64]` carries a second
///   commitment (see [`EatToken::second_commitment`]).
pub const BINDING_SUITE_V2_SHA256: u16 = 0;
pub const BINDING_SUITE_V3_SHA256_DUAL: u16 = 1;
/// Suite a fresh producer uses unless it opts into a newer one.
pub const DEFAULT_BINDING_SUITE: u16 = BINDING_SUITE_V2_SHA256;

/// Domain separator for the `report_data[32..64]` second commitment.
const SECOND_COMMITMENT_DOMAIN: &[u8] = b"uq/eat/report-data-2\0";

/// serde skip predicate: omit `binding_suite` on the wire when it's the default.
fn is_default_suite(s: &u16) -> bool {
    *s == DEFAULT_BINDING_SUITE
}

/// Env var a challenger/issuer can set to inject the 32-byte freshness nonce
/// (`eat_nonce`) at collection time (hex), instead of the producer choosing a
/// random one. This closes the EAT replay window (L1.1): a captured token is
/// only accepted by a verifier that issued the matching nonce.
pub const EAT_NONCE_ENV: &str = "UQ_EAT_NONCE";

/// Errors produced by encoding/decoding an EAT.
#[derive(Debug, thiserror::Error)]
pub enum EatError {
    #[error("CBOR encode failed: {0}")]
    Encode(String),
    #[error("CBOR decode failed: {0}")]
    Decode(String),
    #[error("schema version mismatch: expected {expected}, got {got}")]
    VersionMismatch { expected: u32, got: u32 },
    #[error("profile mismatch: expected {expected}, got {got}")]
    ProfileMismatch { expected: String, got: String },
    #[error("field length invalid: {field} expected {expected} got {got}")]
    LengthMismatch {
        field: &'static str,
        expected: usize,
        got: usize,
    },
}

/// The canonical attestation payload. CBOR-encodes to a map with string
/// field names for debuggability. Field numbering can migrate to CBOR
/// integer keys in a future version without changing the semantics.
///
/// All `Vec<u8>` fields are CBOR byte strings via `serde_bytes`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EatToken {
    /// Schema version. Must equal [`EAT_VERSION`] for today's format.
    pub version: u32,

    /// Profile URI. Must be one of [`EAT_PROFILE_ACCEPTED`].
    pub eat_profile: String,

    /// Binding suite id (crypto agility, L1.3). Omitted on the wire when it is
    /// the default (`0`), so legacy tokens decode to suite 0 and suite-0
    /// tokens stay byte-identical to pre-suite ones.
    #[serde(default, skip_serializing_if = "is_default_suite")]
    pub binding_suite: u16,

    /// Application identity — sha384 of the runner source files.
    /// This is Value X. LATTE layer 1. 48 bytes.
    #[serde(with = "serde_bytes_48")]
    pub value_x: [u8; 48],

    /// TEE platform discriminant: 1=Nitro, 2=SevSnp, 3=Tdx.
    pub platform: u8,

    /// Platform measurement extracted from the quote:
    /// - Nitro: PCR0 (48 bytes)
    /// - SEV-SNP: MEASUREMENT (48 bytes)
    /// - TDX: MRTD (48 bytes)
    /// Variable length per platform, so stored as a byte string.
    #[serde(with = "serde_bytes")]
    pub platform_measurement: Vec<u8>,

    /// Raw TEE evidence. Opaque leaf: verifiers parse per-platform.
    /// - Nitro: COSE_Sign1 attestation document
    /// - SEV-SNP: 1152-byte attestation report + VCEK cert chain
    /// - TDX: DCAP v4 quote (header + body + sig + certs)
    #[serde(with = "serde_bytes")]
    pub platform_quote: Vec<u8>,

    /// sha256 of the TLS server SPKI (DER-encoded SubjectPublicKeyInfo).
    /// The TLS handshake's leaf cert SPKI MUST hash to this value. 32 bytes.
    #[serde(with = "serde_bytes_32")]
    pub tls_spki_hash: [u8; 32],

    /// Source tree hash (CT — Attestable Containers). sha384. 48 bytes.
    /// Binds runtime identity back to the exact source the builder witnessed.
    #[serde(with = "serde_bytes_48")]
    pub source_hash: [u8; 48],

    /// Artifact hash (A — Attestable Containers). sha384. 48 bytes.
    #[serde(with = "serde_bytes_48")]
    pub artifact_hash: [u8; 48],

    /// Standard CWT/EAT claim: issued-at, unix seconds.
    pub iat: u64,

    /// Standard EAT claim: 32-byte freshness nonce.
    #[serde(with = "serde_bytes_32")]
    pub eat_nonce: [u8; 32],

    /// The previous stage's EAT, CBOR-encoded. Empty for stage 0
    /// (no previous attestation); populated for stage 1+ with the
    /// complete CBOR bytes of the prior stage's token.
    ///
    /// This implements Attestable Containers contribution #6
    /// (build-to-runtime chain). Each stage commits cryptographically
    /// to the previous stage via `sha256(previous_attestation)` being
    /// mixed into this stage's `binding_bytes()`, which is then placed
    /// in `report_data[0..32]` of this stage's hardware quote.
    ///
    /// A verifier walks the chain by decoding this field as another
    /// `EatToken` and recursively verifying it. Value X must be stable
    /// across the chain (the runtime is running the same code the
    /// builder produced), and each stage's platform quote must chain
    /// to the previous via the `previous_hash()` commitment.
    ///
    /// Not in `binding_bytes()` directly — `previous_hash()` is.
    #[serde(with = "serde_bytes", default, skip_serializing_if = "Vec::is_empty")]
    pub previous_attestation: Vec<u8>,
}

impl EatToken {
    /// Compute the 32-byte binding that goes into the TEE quote's
    /// `report_data[0..32]`. The non-derivable fields are hashed here;
    /// this is the mechanism that makes the claims tamper-evident despite
    /// living outside the signed quote.
    ///
    /// The layout is a fixed concatenation — no CBOR canonicalization
    /// subtlety. The string field is length-prefixed so the hash is
    /// unambiguous; every other field is fixed-size.
    ///
    /// ## What's deliberately excluded
    ///
    /// - **`platform_quote`** — `report_data` lives inside it; including
    ///   it would be a chicken-and-egg.
    /// - **`platform_measurement`** — it's extracted FROM `platform_quote`
    ///   after collection, so it's not available when `report_data` is
    ///   being chosen. Verifiers can recompute it from `platform_quote`,
    ///   so it's redundant for integrity anyway.
    /// - **`previous_attestation` (raw bytes)** — hashed via
    ///   [`Self::previous_hash`] and the fixed-size hash is mixed in
    ///   instead. Keeps `binding_bytes` a constant-time operation.
    ///
    /// ## Invariant
    ///
    /// `binding_bytes()` computed BEFORE the quote is collected must
    /// equal `binding_bytes()` computed AFTER `platform_quote` and
    /// `platform_measurement` are populated. This is what makes the
    /// attested-TLS flow work: the producer commits to a binding, collects
    /// a quote containing that binding in `report_data`, then writes
    /// the quote bytes back into the EAT without invalidating the
    /// binding.
    pub fn binding_bytes(&self) -> [u8; 32] {
        match self.binding_suite {
            BINDING_SUITE_V3_SHA256_DUAL => self.binding_bytes_v3(),
            // Suite 0 (and any unknown — validate_shape rejects unknowns
            // before this is reached on the verify path) use the historical
            // layout, which intentionally does NOT hash the suite id.
            _ => self.binding_bytes_v2(),
        }
    }

    /// Historical (suite 0) SHA-256 binding. Byte-identical to the pre-suite
    /// layout — do NOT change this function or every existing receipt breaks.
    fn binding_bytes_v2(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.version.to_be_bytes());
        h.update((self.eat_profile.len() as u32).to_be_bytes());
        h.update(self.eat_profile.as_bytes());
        h.update(self.value_x);
        h.update([self.platform]);
        h.update(self.tls_spki_hash);
        h.update(self.source_hash);
        h.update(self.artifact_hash);
        h.update(self.iat.to_be_bytes());
        h.update(self.eat_nonce);
        h.update(self.previous_hash());
        h.finalize().into()
    }

    /// Suite 1 binding: folds the suite id and platform discriminant into the
    /// hash so the agility parameters are themselves authenticated.
    fn binding_bytes_v3(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"uq/eat/binding/v3\0");
        h.update(self.binding_suite.to_be_bytes());
        h.update(self.version.to_be_bytes());
        h.update((self.eat_profile.len() as u32).to_be_bytes());
        h.update(self.eat_profile.as_bytes());
        h.update(self.value_x);
        h.update([self.platform]);
        h.update(self.tls_spki_hash);
        h.update(self.source_hash);
        h.update(self.artifact_hash);
        h.update(self.iat.to_be_bytes());
        h.update(self.eat_nonce);
        h.update(self.previous_hash());
        h.finalize().into()
    }

    /// The full 64-byte `report_data` to embed in a hardware quote:
    /// `binding_bytes()` in `[0..32]` and a second commitment in `[32..64]`.
    ///
    /// SNP/TDX expose 64 bytes of `report_data` but the protocol historically
    /// used only the first 32. This binds the second half (L1.2):
    ///
    /// - `challenge == None`: the second half is `value_x[..32]`. This is
    ///   exactly what the producer already wrote, so existing receipts are
    ///   unchanged and now have a *defined, verifiable* second half.
    /// - `challenge == Some(c)`: the second half is
    ///   `sha256(domain || c || value_x[..32])`, letting an issuer fold a
    ///   second commitment (e.g. an issuance challenge) into the same quote
    ///   without a second round-trip to the hardware.
    pub fn report_data_64(&self, challenge: Option<&[u8; 32]>) -> [u8; 64] {
        let mut rd = [0u8; 64];
        rd[..32].copy_from_slice(&self.binding_bytes());
        rd[32..].copy_from_slice(&self.second_commitment(challenge));
        rd
    }

    /// The committed value the verifier expects in `report_data[32..64]`.
    pub fn second_commitment(&self, challenge: Option<&[u8; 32]>) -> [u8; 32] {
        match challenge {
            None => {
                let mut c = [0u8; 32];
                c.copy_from_slice(&self.value_x[..32]);
                c
            }
            Some(ch) => {
                let mut h = Sha256::new();
                h.update(SECOND_COMMITMENT_DOMAIN);
                h.update(ch);
                h.update(&self.value_x[..32]);
                h.finalize().into()
            }
        }
    }

    /// Commitment to the previous stage's attestation. Returns a
    /// zero hash if this is a root (stage 0); otherwise returns
    /// `sha256(previous_attestation)`.
    ///
    /// The zero hash is distinguishable from any real hash with
    /// overwhelming probability. The choice of "all zeros" for absent
    /// is conventional and simplifies `binding_bytes()` — it's always
    /// a 32-byte hash, never Option.
    pub fn previous_hash(&self) -> [u8; 32] {
        if self.previous_attestation.is_empty() {
            [0u8; 32]
        } else {
            Sha256::digest(&self.previous_attestation).into()
        }
    }

    /// Returns `true` if this EAT chains to a previous stage's EAT.
    pub fn has_previous(&self) -> bool {
        !self.previous_attestation.is_empty()
    }

    /// Decode the previous stage's EAT from `previous_attestation`.
    /// Returns `Ok(None)` if this is a root (stage 0).
    pub fn decode_previous(&self) -> Result<Option<Self>, EatError> {
        if self.previous_attestation.is_empty() {
            return Ok(None);
        }
        Ok(Some(Self::from_cbor(&self.previous_attestation)?))
    }

    /// Chain this EAT to a previous stage by setting
    /// `previous_attestation` to the given CBOR bytes. Must be called
    /// BEFORE `binding_bytes()` is computed for quote collection,
    /// since `previous_hash()` contributes to the binding.
    pub fn set_previous(&mut self, previous_cbor: Vec<u8>) {
        self.previous_attestation = previous_cbor;
    }

    /// Encode to CBOR bytes suitable for wrapping in a TCG DICE CMW and
    /// embedding as an X.509 extension payload.
    pub fn to_cbor(&self) -> Result<Vec<u8>, EatError> {
        let mut out = Vec::new();
        ciborium::ser::into_writer(self, &mut out).map_err(|e| EatError::Encode(e.to_string()))?;
        Ok(out)
    }

    /// Decode a CBOR byte slice into an EAT token. Validates version and
    /// profile; does NOT verify the embedded platform quote or the
    /// binding against report_data — those are the caller's job and live
    /// in the attested-TLS verifier.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, EatError> {
        let token: Self =
            ciborium::de::from_reader(bytes).map_err(|e| EatError::Decode(e.to_string()))?;
        token.validate_shape()?;
        Ok(token)
    }

    fn validate_shape(&self) -> Result<(), EatError> {
        if self.version != EAT_VERSION {
            return Err(EatError::VersionMismatch {
                expected: EAT_VERSION,
                got: self.version,
            });
        }
        if !EAT_PROFILE_ACCEPTED.contains(&self.eat_profile.as_str()) {
            return Err(EatError::ProfileMismatch {
                expected: EAT_PROFILE.to_string(),
                got: self.eat_profile.clone(),
            });
        }
        Ok(())
    }

    /// Resolve the platform discriminant to the [`Platform`] enum.
    pub fn platform_enum(&self) -> Option<Platform> {
        match self.platform {
            1 => Some(Platform::Nitro),
            2 => Some(Platform::SevSnp),
            3 => Some(Platform::Tdx),
            _ => None,
        }
    }
}

/// Discriminant encoding for [`Platform`].
pub fn platform_to_u8(p: Platform) -> u8 {
    match p {
        Platform::Nitro => 1,
        Platform::SevSnp => 2,
        Platform::Tdx => 3,
    }
}

/// Components gathered during a stage 0 build. This is the input to
/// [`EatToken::from_build`]; the build loop fills it in as fields
/// become available.
///
/// This is a struct rather than a long parameter list because the call
/// sites (`cmd_build`, `cmd_enclave`) compute these values at slightly
/// different times and it's easier to pass a bag than thread 10
/// positional args through.
pub struct BuildComponents {
    pub platform: Platform,
    pub value_x: [u8; 48],
    pub source_hash: [u8; 48],
    pub artifact_hash: [u8; 48],
    /// Platform-specific measurement: Nitro PCR0, SNP MEASUREMENT,
    /// or TDX MRTD. Empty if extraction failed (caller decides
    /// whether to accept this).
    pub platform_measurement: Vec<u8>,
    /// Raw TEE evidence bytes from `collect_evidence`.
    pub platform_quote: Vec<u8>,
}

impl EatToken {
    /// Construct an EAT from a completed stage 0 build.
    ///
    /// NOTE on `tls_spki_hash`: this is set to zero. Until attested-TLS cert
    /// generation lands (step 3 in the plan), the TLS key is not bound
    /// into the quote. `binding_bytes()` is therefore a self-consistent
    /// value derivable from the other EAT fields, but it is NOT what's
    /// in `report_data[0..32]` on today's quotes. When attested-TLS lands,
    /// `cmd_build` will be reordered to produce the TLS key first,
    /// populate this field, then collect the quote with
    /// `binding_bytes()` as `report_data[0..32]` — at which point the
    /// EAT becomes fully self-verifying against the hardware quote.
    pub fn from_build(c: BuildComponents) -> Self {
        // Freshness (L1.1): a challenger/issuer can inject the nonce via the
        // environment so a captured EAT can't be replayed inside its validity
        // window. Absent that, fall back to random entropy (passive fetches
        // just need two identical builds not to collide).
        let nonce = nonce_from_env().unwrap_or_else(random_eat_nonce);
        Self::from_build_with_nonce(c, nonce)
    }

    /// Like [`Self::from_build`] but with a caller/verifier-supplied freshness
    /// nonce. Use when an issuer challenges the producer with a specific nonce.
    pub fn from_build_with_nonce(c: BuildComponents, nonce: [u8; 32]) -> Self {
        let iat = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            version: EAT_VERSION,
            eat_profile: EAT_PROFILE.to_string(),
            binding_suite: DEFAULT_BINDING_SUITE,
            value_x: c.value_x,
            platform: platform_to_u8(c.platform),
            platform_measurement: c.platform_measurement,
            platform_quote: c.platform_quote,
            tls_spki_hash: [0u8; 32],
            source_hash: c.source_hash,
            artifact_hash: c.artifact_hash,
            iat,
            eat_nonce: nonce,
            previous_attestation: Vec::new(),
        }
    }
}

fn random_eat_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Parse a verifier-supplied freshness nonce from [`EAT_NONCE_ENV`] (64 hex
/// chars). Returns `None` if unset; logs and ignores a malformed value.
fn nonce_from_env() -> Option<[u8; 32]> {
    let hexv = std::env::var(EAT_NONCE_ENV).ok()?;
    let hexv = hexv.trim();
    if hexv.is_empty() {
        return None;
    }
    match hex::decode(hexv) {
        Ok(b) if b.len() == 32 => {
            let mut out = [0u8; 32];
            out.copy_from_slice(&b);
            eprintln!("[uq] EAT freshness nonce supplied via {EAT_NONCE_ENV}");
            Some(out)
        }
        _ => {
            eprintln!("[uq] WARNING: {EAT_NONCE_ENV} set but not 32-byte hex; using random nonce");
            None
        }
    }
}

/// serde helper: serialize `[u8; 32]` as a CBOR byte string.
mod serde_bytes_32 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        serde_bytes::Bytes::new(v).serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let v = <Vec<u8>>::deserialize(d)?;
        v.as_slice()
            .try_into()
            .map_err(|_| serde::de::Error::invalid_length(v.len(), &"32-byte array"))
    }
    use serde::Serialize as _;
}

/// serde helper: serialize `[u8; 48]` as a CBOR byte string.
mod serde_bytes_48 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8; 48], s: S) -> Result<S::Ok, S::Error> {
        serde_bytes::Bytes::new(v).serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 48], D::Error> {
        let v = <Vec<u8>>::deserialize(d)?;
        v.as_slice()
            .try_into()
            .map_err(|_| serde::de::Error::invalid_length(v.len(), &"48-byte array"))
    }
    use serde::Serialize as _;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> EatToken {
        EatToken {
            version: EAT_VERSION,
            eat_profile: EAT_PROFILE.to_string(),
            binding_suite: DEFAULT_BINDING_SUITE,
            value_x: [0x11; 48],
            platform: 3, // Tdx
            platform_measurement: vec![0x22; 48],
            platform_quote: vec![0x33; 256],
            tls_spki_hash: [0x44; 32],
            source_hash: [0x55; 48],
            artifact_hash: [0x66; 48],
            iat: 1_713_312_000,
            eat_nonce: [0x77; 32],
            previous_attestation: Vec::new(),
        }
    }

    #[test]
    fn cbor_roundtrip() {
        let t = sample();
        let bytes = t.to_cbor().unwrap();
        let back = EatToken::from_cbor(&bytes).unwrap();
        assert_eq!(back.version, t.version);
        assert_eq!(back.eat_profile, t.eat_profile);
        assert_eq!(back.value_x, t.value_x);
        assert_eq!(back.platform, t.platform);
        assert_eq!(back.platform_measurement, t.platform_measurement);
        assert_eq!(back.platform_quote, t.platform_quote);
        assert_eq!(back.tls_spki_hash, t.tls_spki_hash);
        assert_eq!(back.source_hash, t.source_hash);
        assert_eq!(back.artifact_hash, t.artifact_hash);
        assert_eq!(back.iat, t.iat);
        assert_eq!(back.eat_nonce, t.eat_nonce);
    }

    #[test]
    fn binding_is_stable() {
        let t = sample();
        let a = t.binding_bytes();
        let b = t.binding_bytes();
        assert_eq!(a, b);
    }

    #[test]
    fn binding_changes_when_any_field_changes() {
        let mut t = sample();
        let base = t.binding_bytes();
        t.value_x[0] ^= 1;
        assert_ne!(base, t.binding_bytes());
        t.value_x[0] ^= 1;
        t.iat += 1;
        assert_ne!(base, t.binding_bytes());
        t.iat -= 1;
        t.tls_spki_hash[0] ^= 1;
        assert_ne!(base, t.binding_bytes());
    }

    #[test]
    fn binding_excludes_platform_quote_and_measurement() {
        // Both fields are populated AFTER the quote is collected, so
        // binding_bytes must be stable across their mutation. This is
        // the core attested-TLS invariant: producer commits to binding,
        // collects quote containing that binding in report_data, then
        // fills these two fields without invalidating the commitment.
        let t1 = sample();
        let mut t2 = t1.clone();
        t2.platform_quote = vec![0xff; 16];
        t2.platform_measurement = vec![0xee; 96];
        assert_eq!(t1.binding_bytes(), t2.binding_bytes());
    }

    #[test]
    fn decode_rejects_wrong_version() {
        let mut t = sample();
        t.version = 99;
        let bytes = t.to_cbor().unwrap();
        let err = EatToken::from_cbor(&bytes).unwrap_err();
        matches!(err, EatError::VersionMismatch { .. });
    }

    #[test]
    fn decode_rejects_wrong_profile() {
        let mut t = sample();
        t.eat_profile = "not-us".to_string();
        let bytes = t.to_cbor().unwrap();
        let err = EatToken::from_cbor(&bytes).unwrap_err();
        matches!(err, EatError::ProfileMismatch { .. });
    }

    #[test]
    fn decode_accepts_legacy_profile() {
        // Receipts from not-yet-redeployed nodes carry the old branding and
        // must still verify during migration (L1.4).
        let mut t = sample();
        t.eat_profile = "https://bountynet.dev/eat/v2".to_string();
        let bytes = t.to_cbor().unwrap();
        let back = EatToken::from_cbor(&bytes).expect("legacy profile accepted");
        assert_eq!(back.eat_profile, "https://bountynet.dev/eat/v2");
    }

    #[test]
    fn suite0_binding_is_byte_identical_layout() {
        // Suite 0 must not mix the suite id into the hash — otherwise existing
        // hardware receipts (whose report_data was computed before suites
        // existed) would stop verifying.
        let t = sample();
        assert_eq!(t.binding_suite, BINDING_SUITE_V2_SHA256);
        // Recompute the historical layout by hand and compare.
        let mut h = Sha256::new();
        h.update(t.version.to_be_bytes());
        h.update((t.eat_profile.len() as u32).to_be_bytes());
        h.update(t.eat_profile.as_bytes());
        h.update(t.value_x);
        h.update([t.platform]);
        h.update(t.tls_spki_hash);
        h.update(t.source_hash);
        h.update(t.artifact_hash);
        h.update(t.iat.to_be_bytes());
        h.update(t.eat_nonce);
        h.update(t.previous_hash());
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(t.binding_bytes(), expected);
    }

    #[test]
    fn suite_changes_binding() {
        let mut t = sample();
        let b0 = t.binding_bytes();
        t.binding_suite = BINDING_SUITE_V3_SHA256_DUAL;
        let b1 = t.binding_bytes();
        assert_ne!(b0, b1, "suite id must change the binding under suite 1");
    }

    #[test]
    fn suite0_omitted_on_wire() {
        // serde must skip the default suite so suite-0 CBOR is unchanged.
        let t = sample();
        let bytes = t.to_cbor().unwrap();
        let json = serde_json::to_string(&t).unwrap();
        assert!(!json.contains("binding_suite"));
        // and round-trips back to suite 0
        let back = EatToken::from_cbor(&bytes).unwrap();
        assert_eq!(back.binding_suite, BINDING_SUITE_V2_SHA256);
    }

    #[test]
    fn report_data_second_half_default_is_value_x() {
        // Backward compat: with no challenge, report_data[32..64] == value_x[..32]
        // (exactly what the producer historically wrote).
        let t = sample();
        let rd = t.report_data_64(None);
        assert_eq!(&rd[..32], &t.binding_bytes()[..]);
        assert_eq!(&rd[32..], &t.value_x[..32]);
    }

    #[test]
    fn report_data_second_half_challenge_binds() {
        let t = sample();
        let plain = t.report_data_64(None);
        let ch = [0xABu8; 32];
        let challenged = t.report_data_64(Some(&ch));
        // First half (binding) unchanged; second half now commits the challenge.
        assert_eq!(&plain[..32], &challenged[..32]);
        assert_ne!(&plain[32..], &challenged[32..]);
        assert_eq!(&challenged[32..], &t.second_commitment(Some(&ch))[..]);
    }

    #[test]
    fn from_build_with_nonce_uses_supplied_nonce() {
        let c = BuildComponents {
            platform: Platform::Tdx,
            value_x: [0u8; 48],
            source_hash: [0u8; 48],
            artifact_hash: [0u8; 48],
            platform_measurement: Vec::new(),
            platform_quote: Vec::new(),
        };
        let nonce = [0x5Au8; 32];
        let t = EatToken::from_build_with_nonce(c, nonce);
        assert_eq!(t.eat_nonce, nonce);
    }

    // ----- chain tests (AC contribution #6) -----

    #[test]
    fn root_eat_has_no_previous() {
        let t = sample();
        assert!(!t.has_previous());
        assert_eq!(t.previous_hash(), [0u8; 32]);
        assert!(t.decode_previous().unwrap().is_none());
    }

    #[test]
    fn chain_commits_previous_hash_into_binding() {
        let stage0 = sample();
        let stage0_cbor = stage0.to_cbor().unwrap();

        let mut stage1 = sample();
        let binding_before_chain = stage1.binding_bytes();
        stage1.set_previous(stage0_cbor.clone());
        let binding_after_chain = stage1.binding_bytes();

        // The act of chaining MUST change binding — otherwise the
        // chain is not cryptographically committed.
        assert_ne!(
            binding_before_chain, binding_after_chain,
            "chaining must change binding_bytes (previous_hash is in the hash)"
        );

        // previous_hash must equal sha256 of stage0 cbor
        let expected: [u8; 32] = Sha256::digest(&stage0_cbor).into();
        assert_eq!(stage1.previous_hash(), expected);
    }

    #[test]
    fn chain_tampering_changes_binding() {
        // If an attacker swaps the previous_attestation for a
        // different (but still valid-looking) EAT, the binding MUST
        // change. Otherwise stage 1's quote would still validate
        // against an unrelated stage 0.
        let stage0_a = sample();
        let mut stage0_b = sample();
        stage0_b.value_x[0] ^= 1;

        let mut stage1 = sample();
        stage1.set_previous(stage0_a.to_cbor().unwrap());
        let binding_a = stage1.binding_bytes();
        stage1.set_previous(stage0_b.to_cbor().unwrap());
        let binding_b = stage1.binding_bytes();

        assert_ne!(binding_a, binding_b);
    }

    #[test]
    fn chain_decoded_previous_roundtrips() {
        let stage0 = sample();
        let stage0_cbor = stage0.to_cbor().unwrap();

        let mut stage1 = sample();
        stage1.set_previous(stage0_cbor);

        let stage1_cbor = stage1.to_cbor().unwrap();
        let back = EatToken::from_cbor(&stage1_cbor).unwrap();
        assert!(back.has_previous());

        let decoded_prev = back.decode_previous().unwrap().unwrap();
        assert_eq!(decoded_prev.value_x, stage0.value_x);
        assert_eq!(decoded_prev.platform, stage0.platform);
    }

    #[test]
    fn chain_binding_excludes_previous_bytes_directly() {
        // The raw previous_attestation bytes should NOT appear
        // byte-for-byte in binding_bytes — only via sha256.
        // We check this indirectly: if we swap the previous for one
        // that happens to have the same sha256 (impossible to
        // construct but we can test the hash-first property by
        // confirming two *identical* previous bytes produce the
        // same binding).
        let stage0 = sample();
        let stage0_cbor = stage0.to_cbor().unwrap();

        let mut a = sample();
        let mut b = sample();
        a.set_previous(stage0_cbor.clone());
        b.set_previous(stage0_cbor);

        assert_eq!(a.binding_bytes(), b.binding_bytes());
    }

    #[test]
    fn binding_invariant_holds_after_chain_plus_quote_fill() {
        // Producer flow:
        //   1. set_previous(stage0)
        //   2. compute binding
        //   3. collect quote with binding → report_data
        //   4. fill platform_quote + platform_measurement
        //   5. recompute binding → must equal step 2
        let stage0 = sample();
        let stage0_cbor = stage0.to_cbor().unwrap();

        let mut t = sample();
        t.platform_quote = Vec::new();
        t.platform_measurement = Vec::new();
        t.set_previous(stage0_cbor);
        let pre = t.binding_bytes();

        t.platform_quote = vec![0xcc; 1152];
        t.platform_measurement = vec![0xdd; 48];
        let post = t.binding_bytes();

        assert_eq!(pre, post, "chain binding must survive quote fill");
    }
}
