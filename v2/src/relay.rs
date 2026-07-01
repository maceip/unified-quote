//! Relay / inherit credentials: bootstrap-once, then cheap (Gap B).
//!
//! A weak endpoint (a laptop; or an agent inside a Linux VM with no silicon
//! root of its own) should not have to re-run a full hardware attestation on
//! every request. Instead it leans on a strong, already-attested cloud TEE:
//!
//! 1. **Bootstrap (once, expensive).** The device verifies the cloud TEE's own
//!    unified-quote EAT (`quote::verify`) and proves its *own* device identity
//!    to that TEE with a device attestation (`tee::desktop` TPM / App Attest)
//!    whose channel binding commits to the device's public key
//!    ([`device_binding`]). The TEE — acting as a relay issuer — then signs a
//!    short-lived [`RelayCredential`] binding that device public key to the
//!    accepted device measurement and to the TEE's own `value_x`.
//!
//! 2. **Re-use (many times, cheap).** The device presents the credential plus a
//!    fresh holder-of-key proof ([`Presentation`]): a signature by the device
//!    key over a verifier-issued challenge. A relying party checks the issuer
//!    signature and the proof-of-possession — no hardware quote on the hot path.
//!
//! This is the "bootstrap once, then cheap verification" + "trust inheritance"
//! pattern: the strong silicon root stays in the cloud TEE; the device is a
//! device-bound thin client. Nothing here weakens the gate — the credential is
//! only as strong as the device attestation that earned it and the TEE that
//! signed it, both recorded in the credential and surfaced for honest labeling.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const CRED_DOMAIN: &[u8] = b"uq/relay/credential\0";
const CHALLENGE_DOMAIN: &[u8] = b"uq/relay/challenge\0";
const BIND_DOMAIN: &[u8] = b"uq/relay/device-binding\0";
const POP_DOMAIN: &[u8] = b"uq/relay/proof-of-possession\0";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RelayError {
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("invalid signature encoding")]
    InvalidSignature,
    #[error("device binding mismatch")]
    DeviceBindingMismatch,
    #[error("bootstrap nonce replay")]
    BootstrapReplay,
    #[error("presentation challenge replay")]
    PresentationReplay,
    #[error("challenge expired")]
    ChallengeExpired,
    #[error("credential time overflow")]
    TimeOverflow,
    #[error("issuer signature verification failed")]
    IssuerSignatureInvalid,
    #[error("credential expired")]
    Expired,
    #[error("credential not yet valid")]
    NotYetValid,
    #[error("proof-of-possession failed")]
    ProofOfPossession,
    #[error("tee attestation verification failed: {0}")]
    TeeAttestation(String),
    #[error("device attestation verification failed: {0}")]
    DeviceAttestation(String),
}

/// A verifier-issued one-time challenge. The nonce gives replay identity; the
/// expiry bounds how long the attestation or presentation may be accepted; the
/// context lets a service bind the challenge to a route, audience, session, or
/// relay issuer key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayChallenge {
    pub nonce: [u8; 32],
    pub expires_at: u64,
    #[serde(default)]
    pub context: Vec<u8>,
}

impl RelayChallenge {
    pub fn new(
        nonce: [u8; 32],
        now: u64,
        ttl_secs: u64,
        context: impl Into<Vec<u8>>,
    ) -> Result<Self, RelayError> {
        let expires_at = now.checked_add(ttl_secs).ok_or(RelayError::TimeOverflow)?;
        Ok(Self {
            nonce,
            expires_at,
            context: context.into(),
        })
    }

    pub fn ensure_fresh(&self, now: u64) -> Result<(), RelayError> {
        if now > self.expires_at {
            return Err(RelayError::ChallengeExpired);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(CHALLENGE_DOMAIN);
        b.extend_from_slice(&self.nonce);
        b.extend_from_slice(&self.expires_at.to_be_bytes());
        put_field(&mut b, &self.context);
        b
    }
}

/// The 32-byte value a device's attestation must commit to (in TPM
/// `qualifyingData` / App Attest client-data) so the resulting credential is
/// bound to exactly this device key, this cloud TEE, and this one-time relay
/// challenge.
pub fn device_binding(
    device_pubkey: &[u8; 32],
    tee_value_x: &[u8],
    challenge: &RelayChallenge,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(BIND_DOMAIN);
    h.update(device_pubkey);
    h.update((tee_value_x.len() as u32).to_be_bytes());
    h.update(tee_value_x);
    h.update(challenge.canonical_bytes());
    h.finalize().into()
}

/// A short-lived, holder-of-key credential the cloud TEE issues to a device
/// after a successful bootstrap. Inheritable trust: presenting it (with a PoP)
/// stands in for re-attesting.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayCredential {
    /// ed25519 public key (32 bytes) the credential is bound to.
    pub device_pubkey: Vec<u8>,
    /// Platform label of the device attestation that earned this credential
    /// (e.g. `linux-tpm-client`, `macos-app-attest`).
    pub platform: String,
    /// The device build identity the relay accepted (build_id / app_id hash).
    pub value_x: Vec<u8>,
    /// The cloud TEE's own `value_x` — the strong root this credential inherits.
    pub tee_value_x: Vec<u8>,
    /// Unix seconds.
    pub issued_at: u64,
    /// Unix seconds; the credential is invalid after this.
    pub expiry: u64,
    /// ed25519 signature by the relay issuer (the cloud TEE) over the canonical
    /// bytes of every field above.
    pub sig: Vec<u8>,
}

impl RelayCredential {
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(CRED_DOMAIN);
        put_field(&mut b, &self.device_pubkey);
        put_field(&mut b, self.platform.as_bytes());
        put_field(&mut b, &self.value_x);
        put_field(&mut b, &self.tee_value_x);
        b.extend_from_slice(&self.issued_at.to_be_bytes());
        b.extend_from_slice(&self.expiry.to_be_bytes());
        b
    }

    /// Verify the issuer signature and validity window. Returns the bound device
    /// verifying key on success.
    pub fn verify(&self, issuer: &VerifyingKey, now: u64) -> Result<VerifyingKey, RelayError> {
        if now > self.expiry {
            return Err(RelayError::Expired);
        }
        if now + SKEW_SECS < self.issued_at {
            return Err(RelayError::NotYetValid);
        }
        let sig = sig_from_slice(&self.sig)?;
        issuer
            .verify(&self.canonical_bytes(), &sig)
            .map_err(|_| RelayError::IssuerSignatureInvalid)?;
        vk_from_slice(&self.device_pubkey)
    }

    /// Verify the holder-of-key signature over an already freshness-checked
    /// challenge message.
    fn verify_presentation(
        &self,
        issuer: &VerifyingKey,
        challenge_message: &[u8],
        pop: &Presentation,
        now: u64,
    ) -> Result<(), RelayError> {
        let device_vk = self.verify(issuer, now)?;
        let pop_sig = sig_from_slice(&pop.sig)?;
        device_vk
            .verify(&pop_message(challenge_message), &pop_sig)
            .map_err(|_| RelayError::ProofOfPossession)
    }
}

const SKEW_SECS: u64 = 60;

/// A holder-of-key proof: the device's signature over a verifier-issued
/// challenge, presented alongside a [`RelayCredential`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Presentation {
    pub sig: Vec<u8>,
}

/// Claims accepted by a relying party after checking both the issuer signature
/// and the device holder-of-key proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedRelayClaims {
    pub platform: String,
    pub value_x: Vec<u8>,
    pub tee_value_x: Vec<u8>,
    pub device_pubkey: VerifyingKey,
}

/// Relay TEE identity after verifying the relay's own unified-quote EAT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRelayTee {
    value_x: Vec<u8>,
}

impl VerifiedRelayTee {
    pub fn from_eat(eat_cbor: &[u8]) -> Result<Self, RelayError> {
        let token = crate::eat::EatToken::from_cbor(eat_cbor)
            .map_err(|e| RelayError::TeeAttestation(format!("EAT decode: {e}")))?;
        let platform = token.platform_enum().ok_or_else(|| {
            RelayError::TeeAttestation(format!("unknown platform {}", token.platform))
        })?;
        let expected = token.binding_bytes();
        crate::quote::verify::verify_platform_quote(platform, &token.platform_quote, &expected)
            .map_err(|e| RelayError::TeeAttestation(format!("platform quote: {e}")))?;
        Ok(Self {
            value_x: token.value_x.to_vec(),
        })
    }

    pub fn value_x(&self) -> &[u8] {
        &self.value_x
    }
}

/// Device identity after verifying a device attestation against the relay
/// device-binding challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDeviceAttestation {
    platform: String,
    value_x: Vec<u8>,
    observed_binding: [u8; 32],
}

impl VerifiedDeviceAttestation {
    #[cfg(feature = "desktop")]
    pub fn from_desktop_tpm(
        bundle: &crate::tee::desktop::tpm::TpmClientBundle,
        expected_binding: &[u8; 32],
        options: &crate::tee::desktop::tpm::TpmVerifierOptions,
    ) -> Result<Self, RelayError> {
        let verdict =
            crate::tee::desktop::tpm::verify_bundle_with_options(bundle, expected_binding, options)
                .map_err(|e| RelayError::DeviceAttestation(format!("desktop TPM: {e}")))?;
        if verdict.verdict != "verified" {
            return Err(RelayError::DeviceAttestation(format!(
                "desktop TPM verdict: {}",
                verdict.verdict
            )));
        }
        let value_x = hex::decode(&verdict.identity_hash)
            .map_err(|e| RelayError::DeviceAttestation(format!("identity_hash: {e}")))?;
        Ok(Self {
            platform: verdict.platform,
            value_x,
            observed_binding: *expected_binding,
        })
    }

    #[cfg(feature = "desktop")]
    pub fn from_macos_app_attest(
        bundle: &crate::tee::desktop::app_attest::MacOsAppAttestBundle,
        expected_binding: &[u8; 32],
    ) -> Result<Self, RelayError> {
        let verdict = crate::tee::desktop::app_attest::verify_bundle(bundle, expected_binding)
            .map_err(|e| RelayError::DeviceAttestation(format!("macOS App Attest: {e}")))?;
        if verdict.verdict != "verified" {
            return Err(RelayError::DeviceAttestation(format!(
                "macOS App Attest verdict: {}",
                verdict.verdict
            )));
        }
        let value_x = hex::decode(&verdict.identity_hash)
            .map_err(|e| RelayError::DeviceAttestation(format!("identity_hash: {e}")))?;
        Ok(Self {
            platform: verdict.platform,
            value_x,
            observed_binding: *expected_binding,
        })
    }

    pub fn platform(&self) -> &str {
        &self.platform
    }

    pub fn value_x(&self) -> &[u8] {
        &self.value_x
    }
}

/// Issue a credential. The caller MUST have already (a) verified the device
/// attestation against [`device_binding`] for this `device_pubkey`, extracting
/// `platform` + `value_x`, and (b) be the cloud TEE whose `tee_value_x` is
/// recorded. This function performs the issuer signing step only.
#[allow(clippy::too_many_arguments)]
fn issue(
    issuer_sk: &SigningKey,
    device_pubkey: &VerifyingKey,
    platform: impl Into<String>,
    value_x: Vec<u8>,
    tee_value_x: Vec<u8>,
    issued_at: u64,
    ttl_secs: u64,
) -> RelayCredential {
    let mut cred = RelayCredential {
        device_pubkey: device_pubkey.to_bytes().to_vec(),
        platform: platform.into(),
        value_x,
        tee_value_x,
        issued_at,
        expiry: issued_at + ttl_secs,
        sig: Vec::new(),
    };
    let sig = issuer_sk.sign(&cred.canonical_bytes());
    cred.sig = sig.to_bytes().to_vec();
    cred
}

/// In-memory replay guard for relay bootstrap nonces.
///
/// Production issuers should back this with durable/shared storage. This type
/// never re-accepts a consumed nonce for the lifetime of the process; a service
/// that needs bounded storage should rotate the entire store by epoch, not
/// prune individual consumed nonces back into circulation.
#[derive(Debug, Default, Clone)]
pub struct BootstrapReplayStore {
    seen_until: BTreeMap<[u8; 32], u64>,
}

impl BootstrapReplayStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn check_and_store(
        &mut self,
        challenge: &RelayChallenge,
        now: u64,
    ) -> Result<(), RelayError> {
        challenge.ensure_fresh(now)?;
        if self.seen_until.contains_key(&challenge.nonce) {
            return Err(RelayError::BootstrapReplay);
        }
        self.seen_until
            .insert(challenge.nonce, challenge.expires_at);
        Ok(())
    }
}

/// In-memory replay guard for relying-party presentation challenges.
#[derive(Debug, Default, Clone)]
pub struct PresentationReplayStore {
    seen_until: BTreeMap<[u8; 32], u64>,
}

impl PresentationReplayStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn check_and_store(
        &mut self,
        challenge: &RelayChallenge,
        now: u64,
    ) -> Result<(), RelayError> {
        challenge.ensure_fresh(now)?;
        if self.seen_until.contains_key(&challenge.nonce) {
            return Err(RelayError::PresentationReplay);
        }
        self.seen_until
            .insert(challenge.nonce, challenge.expires_at);
        Ok(())
    }
}

/// Bootstrap a relay credential from verifier-produced relay and device facts.
/// The challenge nonce is consumed before signing, and the device attestation
/// must have committed to [`device_binding`] for this device key, relay TEE, and
/// challenge.
#[allow(clippy::too_many_arguments)]
pub fn bootstrap(
    replay_store: &mut BootstrapReplayStore,
    issuer_sk: &SigningKey,
    device_pubkey: &VerifyingKey,
    device: &VerifiedDeviceAttestation,
    relay_tee: &VerifiedRelayTee,
    challenge: &RelayChallenge,
    issued_at: u64,
    ttl_secs: u64,
) -> Result<RelayCredential, RelayError> {
    issued_at
        .checked_add(ttl_secs)
        .ok_or(RelayError::TimeOverflow)?;
    let expected_device_binding =
        device_binding(&device_pubkey.to_bytes(), relay_tee.value_x(), challenge);
    if device.observed_binding != expected_device_binding {
        return Err(RelayError::DeviceBindingMismatch);
    }
    replay_store.check_and_store(challenge, issued_at)?;

    Ok(issue(
        issuer_sk,
        device_pubkey,
        device.platform.clone(),
        device.value_x.clone(),
        relay_tee.value_x.clone(),
        issued_at,
        ttl_secs,
    ))
}

/// Bootstrap exactly once for a fresh nonce, computing the expected device
/// binding and recording the nonce before issuing the credential. Kept as a
/// convenience alias for callers that already use the "once" terminology.
#[allow(clippy::too_many_arguments)]
pub fn bootstrap_once(
    replay_store: &mut BootstrapReplayStore,
    issuer_sk: &SigningKey,
    device_pubkey: &VerifyingKey,
    device: &VerifiedDeviceAttestation,
    relay_tee: &VerifiedRelayTee,
    challenge: &RelayChallenge,
    issued_at: u64,
    ttl_secs: u64,
) -> Result<RelayCredential, RelayError> {
    bootstrap(
        replay_store,
        issuer_sk,
        device_pubkey,
        device,
        relay_tee,
        challenge,
        issued_at,
        ttl_secs,
    )
}

/// Produce a holder-of-key proof for `challenge` with the device signing key.
pub fn present(device_sk: &SigningKey, challenge: &RelayChallenge) -> Presentation {
    Presentation {
        sig: device_sk
            .sign(&pop_message(&challenge.canonical_bytes()))
            .to_bytes()
            .to_vec(),
    }
}

/// Accept a relay credential presentation and return the relying-party claims.
pub fn accept(
    replay_store: &mut PresentationReplayStore,
    credential: &RelayCredential,
    presentation: &Presentation,
    issuer: &VerifyingKey,
    challenge: &RelayChallenge,
    now: u64,
) -> Result<AcceptedRelayClaims, RelayError> {
    challenge.ensure_fresh(now)?;
    credential.verify_presentation(issuer, &challenge.canonical_bytes(), presentation, now)?;
    replay_store.check_and_store(challenge, now)?;
    let device_pubkey = vk_from_slice(&credential.device_pubkey)?;
    Ok(AcceptedRelayClaims {
        platform: credential.platform.clone(),
        value_x: credential.value_x.clone(),
        tee_value_x: credential.tee_value_x.clone(),
        device_pubkey,
    })
}

fn pop_message(challenge: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(POP_DOMAIN.len() + 4 + challenge.len());
    m.extend_from_slice(POP_DOMAIN);
    m.extend_from_slice(&(challenge.len() as u32).to_be_bytes());
    m.extend_from_slice(challenge);
    m
}

fn put_field(buf: &mut Vec<u8>, field: &[u8]) {
    buf.extend_from_slice(&(field.len() as u32).to_be_bytes());
    buf.extend_from_slice(field);
}

fn vk_from_slice(b: &[u8]) -> Result<VerifyingKey, RelayError> {
    let arr: [u8; 32] = b.try_into().map_err(|_| RelayError::InvalidPublicKey)?;
    VerifyingKey::from_bytes(&arr).map_err(|_| RelayError::InvalidPublicKey)
}

fn sig_from_slice(b: &[u8]) -> Result<Signature, RelayError> {
    let arr: [u8; 64] = b.try_into().map_err(|_| RelayError::InvalidSignature)?;
    Ok(Signature::from_bytes(&arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn challenge(seed: u8, now: u64, ttl: u64) -> RelayChallenge {
        RelayChallenge::new([seed; 32], now, ttl, b"rp:/authorize".to_vec()).unwrap()
    }

    fn relay_tee() -> VerifiedRelayTee {
        VerifiedRelayTee {
            value_x: vec![0xCD; 48],
        }
    }

    fn verified_device(
        device_vk: &VerifyingKey,
        relay_tee: &VerifiedRelayTee,
        challenge: &RelayChallenge,
    ) -> VerifiedDeviceAttestation {
        VerifiedDeviceAttestation {
            platform: "linux-tpm-client".into(),
            value_x: vec![0xAB; 32],
            observed_binding: device_binding(device_vk.as_bytes(), relay_tee.value_x(), challenge),
        }
    }

    #[test]
    fn issue_verify_and_present_roundtrip() {
        let issuer = key(1);
        let device = key(2);
        let cred = issue(
            &issuer,
            &device.verifying_key(),
            "linux-tpm-client",
            vec![0xAB; 32],
            vec![0xCD; 48],
            1000,
            300,
        );

        // Credential verifies within its window and returns the device key.
        let dvk = cred.verify(&issuer.verifying_key(), 1100).unwrap();
        assert_eq!(dvk.to_bytes(), device.verifying_key().to_bytes());

        // Holder-of-key presentation against a fresh challenge.
        let challenge = challenge(4, 1000, 300);
        let pop = present(&device, &challenge);
        let mut replay_store = PresentationReplayStore::new();
        accept(
            &mut replay_store,
            &cred,
            &pop,
            &issuer.verifying_key(),
            &challenge,
            1100,
        )
        .unwrap();
    }

    #[test]
    fn rejects_expired_and_premature() {
        let issuer = key(1);
        let device = key(2);
        let cred = issue(
            &issuer,
            &device.verifying_key(),
            "macos-app-attest",
            vec![1; 32],
            vec![2; 48],
            1000,
            300,
        );
        assert_eq!(
            cred.verify(&issuer.verifying_key(), 2000),
            Err(RelayError::Expired)
        );
        assert_eq!(
            cred.verify(&issuer.verifying_key(), 0),
            Err(RelayError::NotYetValid)
        );
    }

    #[test]
    fn rejects_wrong_issuer_and_tamper() {
        let issuer = key(1);
        let attacker = key(9);
        let device = key(2);
        let cred = issue(
            &issuer,
            &device.verifying_key(),
            "linux-tpm-client",
            vec![1; 32],
            vec![2; 48],
            1000,
            300,
        );

        assert_eq!(
            cred.verify(&attacker.verifying_key(), 1100),
            Err(RelayError::IssuerSignatureInvalid)
        );

        let mut tampered = cred.clone();
        tampered.value_x = vec![0xFF; 32];
        assert_eq!(
            tampered.verify(&issuer.verifying_key(), 1100),
            Err(RelayError::IssuerSignatureInvalid)
        );
    }

    #[test]
    fn rejects_wrong_challenge_and_wrong_device() {
        let issuer = key(1);
        let device = key(2);
        let other = key(3);
        let cred = issue(
            &issuer,
            &device.verifying_key(),
            "linux-tpm-client",
            vec![1; 32],
            vec![2; 48],
            1000,
            300,
        );

        // Right device, wrong challenge.
        let challenge_a = challenge(4, 1000, 300);
        let challenge_b = challenge(5, 1000, 300);
        let pop = present(&device, &challenge_a);
        let mut replay_store = PresentationReplayStore::new();
        assert_eq!(
            accept(
                &mut replay_store,
                &cred,
                &pop,
                &issuer.verifying_key(),
                &challenge_b,
                1100
            ),
            Err(RelayError::ProofOfPossession)
        );

        // A different key cannot present this credential.
        let pop_other = present(&other, &challenge_a);
        let mut replay_store = PresentationReplayStore::new();
        assert_eq!(
            accept(
                &mut replay_store,
                &cred,
                &pop_other,
                &issuer.verifying_key(),
                &challenge_a,
                1100
            ),
            Err(RelayError::ProofOfPossession)
        );
    }

    #[test]
    fn device_binding_is_deterministic_and_sensitive() {
        let pk = [7u8; 32];
        let tee = [8u8; 48];
        let c1 = challenge(9, 1000, 300);
        let b1 = device_binding(&pk, &tee, &c1);
        let b2 = device_binding(&pk, &tee, &c1);
        assert_eq!(b1, b2);
        let b3 = device_binding(&pk, &tee, &challenge(10, 1000, 300));
        let b4 = device_binding(&pk, &tee, &challenge(9, 1000, 301));
        assert_ne!(b1, b3);
        assert_ne!(b1, b4);
    }

    #[test]
    fn bootstrap_rejects_binding_mismatch_before_issuing() {
        let issuer = key(1);
        let device = key(2);
        let relay_tee = relay_tee();
        let expected_challenge = challenge(9, 1000, 300);
        let wrong_challenge = challenge(10, 1000, 300);
        let device_attestation =
            verified_device(&device.verifying_key(), &relay_tee, &wrong_challenge);
        let mut replay_store = BootstrapReplayStore::new();

        let result = bootstrap(
            &mut replay_store,
            &issuer,
            &device.verifying_key(),
            &device_attestation,
            &relay_tee,
            &expected_challenge,
            1000,
            300,
        );

        assert_eq!(result, Err(RelayError::DeviceBindingMismatch));
    }

    #[test]
    fn bootstrap_and_accept_returns_claims() {
        let issuer = key(1);
        let device = key(2);
        let relay_tee = relay_tee();
        let bootstrap_challenge = challenge(9, 1000, 300);
        let device_attestation =
            verified_device(&device.verifying_key(), &relay_tee, &bootstrap_challenge);
        let mut bootstrap_store = BootstrapReplayStore::new();
        let cred = bootstrap(
            &mut bootstrap_store,
            &issuer,
            &device.verifying_key(),
            &device_attestation,
            &relay_tee,
            &bootstrap_challenge,
            1000,
            300,
        )
        .unwrap();
        let presentation_challenge = challenge(11, 1100, 60);
        let pop = present(&device, &presentation_challenge);
        let mut presentation_store = PresentationReplayStore::new();

        let claims = accept(
            &mut presentation_store,
            &cred,
            &pop,
            &issuer.verifying_key(),
            &presentation_challenge,
            1100,
        )
        .unwrap();

        assert_eq!(claims.platform, "linux-tpm-client");
        assert_eq!(claims.value_x, vec![0xAB; 32]);
        assert_eq!(claims.tee_value_x, relay_tee.value_x);
        assert_eq!(
            claims.device_pubkey.to_bytes(),
            device.verifying_key().to_bytes()
        );
    }

    #[test]
    fn bootstrap_once_rejects_nonce_replay() {
        let issuer = key(1);
        let device = key(2);
        let relay_tee = relay_tee();
        let bootstrap_challenge = challenge(9, 1000, 300);
        let device_attestation =
            verified_device(&device.verifying_key(), &relay_tee, &bootstrap_challenge);
        let mut replay_store = BootstrapReplayStore::new();

        bootstrap_once(
            &mut replay_store,
            &issuer,
            &device.verifying_key(),
            &device_attestation,
            &relay_tee,
            &bootstrap_challenge,
            1000,
            300,
        )
        .unwrap();

        let replay = bootstrap_once(
            &mut replay_store,
            &issuer,
            &device.verifying_key(),
            &device_attestation,
            &relay_tee,
            &bootstrap_challenge,
            1100,
            300,
        );

        assert_eq!(replay, Err(RelayError::BootstrapReplay));
    }

    #[test]
    fn bootstrap_replay_store_keeps_consumed_nonces_after_expiry() {
        let mut replay_store = BootstrapReplayStore::new();
        let original = challenge(9, 1000, 10);
        let same_nonce_new_epoch =
            RelayChallenge::new([9u8; 32], 1011, 10, b"new".to_vec()).unwrap();

        replay_store.check_and_store(&original, 1000).unwrap();
        assert_eq!(
            replay_store.check_and_store(&original, 1005),
            Err(RelayError::BootstrapReplay)
        );
        assert_eq!(
            replay_store.check_and_store(&original, 1011),
            Err(RelayError::ChallengeExpired)
        );
        assert_eq!(
            replay_store.check_and_store(&same_nonce_new_epoch, 1011),
            Err(RelayError::BootstrapReplay)
        );
    }

    #[test]
    fn accept_rejects_wrong_challenge() {
        let issuer = key(1);
        let device = key(2);
        let relay_tee = relay_tee();
        let bootstrap_challenge = challenge(9, 1000, 300);
        let device_attestation =
            verified_device(&device.verifying_key(), &relay_tee, &bootstrap_challenge);
        let mut bootstrap_store = BootstrapReplayStore::new();
        let cred = bootstrap(
            &mut bootstrap_store,
            &issuer,
            &device.verifying_key(),
            &device_attestation,
            &relay_tee,
            &bootstrap_challenge,
            1000,
            300,
        )
        .unwrap();
        let challenge_a = challenge(11, 1100, 60);
        let challenge_b = challenge(12, 1100, 60);
        let pop = present(&device, &challenge_a);
        let mut presentation_store = PresentationReplayStore::new();

        assert_eq!(
            accept(
                &mut presentation_store,
                &cred,
                &pop,
                &issuer.verifying_key(),
                &challenge_b,
                1100
            ),
            Err(RelayError::ProofOfPossession)
        );
    }

    #[test]
    fn accept_rejects_expired_credential() {
        let issuer = key(1);
        let device = key(2);
        let relay_tee = relay_tee();
        let bootstrap_challenge = challenge(9, 1000, 300);
        let device_attestation =
            verified_device(&device.verifying_key(), &relay_tee, &bootstrap_challenge);
        let mut bootstrap_store = BootstrapReplayStore::new();
        let cred = bootstrap(
            &mut bootstrap_store,
            &issuer,
            &device.verifying_key(),
            &device_attestation,
            &relay_tee,
            &bootstrap_challenge,
            1000,
            300,
        )
        .unwrap();
        let challenge = challenge(11, 1100, 2000);
        let pop = present(&device, &challenge);
        let mut presentation_store = PresentationReplayStore::new();

        assert_eq!(
            accept(
                &mut presentation_store,
                &cred,
                &pop,
                &issuer.verifying_key(),
                &challenge,
                2000
            ),
            Err(RelayError::Expired)
        );
    }

    #[test]
    fn accept_rejects_presentation_replay() {
        let issuer = key(1);
        let device = key(2);
        let relay_tee = relay_tee();
        let bootstrap_challenge = challenge(9, 1000, 300);
        let device_attestation =
            verified_device(&device.verifying_key(), &relay_tee, &bootstrap_challenge);
        let mut bootstrap_store = BootstrapReplayStore::new();
        let cred = bootstrap(
            &mut bootstrap_store,
            &issuer,
            &device.verifying_key(),
            &device_attestation,
            &relay_tee,
            &bootstrap_challenge,
            1000,
            300,
        )
        .unwrap();
        let challenge = challenge(11, 1100, 60);
        let pop = present(&device, &challenge);
        let mut presentation_store = PresentationReplayStore::new();

        accept(
            &mut presentation_store,
            &cred,
            &pop,
            &issuer.verifying_key(),
            &challenge,
            1100,
        )
        .unwrap();
        assert_eq!(
            accept(
                &mut presentation_store,
                &cred,
                &pop,
                &issuer.verifying_key(),
                &challenge,
                1101
            ),
            Err(RelayError::PresentationReplay)
        );
    }

    #[test]
    fn accept_rejects_expired_challenge() {
        let issuer = key(1);
        let device = key(2);
        let cred = issue(
            &issuer,
            &device.verifying_key(),
            "linux-tpm-client",
            vec![0xAB; 32],
            vec![0xCD; 48],
            1000,
            300,
        );
        let challenge = challenge(11, 1000, 10);
        let pop = present(&device, &challenge);
        let mut presentation_store = PresentationReplayStore::new();

        assert_eq!(
            accept(
                &mut presentation_store,
                &cred,
                &pop,
                &issuer.verifying_key(),
                &challenge,
                1011
            ),
            Err(RelayError::ChallengeExpired)
        );
    }
}
