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
}

/// The 32-byte value a device's attestation must commit to (in TPM
/// `qualifyingData` / App Attest client-data) so the resulting credential is
/// bound to exactly this device key and this cloud TEE. A fresh `nonce` makes
/// each bootstrap non-replayable.
pub fn device_binding(device_pubkey: &[u8; 32], tee_value_x: &[u8], nonce: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(BIND_DOMAIN);
    h.update(device_pubkey);
    h.update((tee_value_x.len() as u32).to_be_bytes());
    h.update(tee_value_x);
    h.update(nonce);
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

    /// Verify a full presentation: the credential is valid AND the holder proved
    /// possession of the device key over `challenge`. This is the cheap hot-path
    /// check a relying party runs instead of a fresh attestation.
    pub fn verify_presentation(
        &self,
        issuer: &VerifyingKey,
        challenge: &[u8],
        pop: &Presentation,
        now: u64,
    ) -> Result<(), RelayError> {
        let device_vk = self.verify(issuer, now)?;
        let pop_sig = sig_from_slice(&pop.sig)?;
        device_vk
            .verify(&pop_message(challenge), &pop_sig)
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

/// Issue a credential. The caller MUST have already (a) verified the device
/// attestation against [`device_binding`] for this `device_pubkey`, extracting
/// `platform` + `value_x`, and (b) be the cloud TEE whose `tee_value_x` is
/// recorded. This function performs the issuer signing step only.
#[allow(clippy::too_many_arguments)]
pub fn issue(
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
/// Production issuers should back this with durable/shared storage. This type is
/// deliberately small and synchronous so single-process issuers and tests do not
/// have to reimplement the freshness rule.
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
        nonce: [u8; 32],
        now: u64,
        ttl_secs: u64,
    ) -> Result<(), RelayError> {
        let expiry = now.checked_add(ttl_secs).ok_or(RelayError::TimeOverflow)?;
        self.seen_until.retain(|_, seen_expiry| *seen_expiry >= now);
        if self.seen_until.contains_key(&nonce) {
            return Err(RelayError::BootstrapReplay);
        }
        self.seen_until.insert(nonce, expiry);
        Ok(())
    }
}

/// Bootstrap a relay credential from already-verified attestation facts.
///
/// This is the safer issuing entry point for normal callers: it refuses to sign
/// unless the binding observed in the device attestation exactly matches the
/// expected binding for this bootstrap. A replay/nonce store is still required
/// at the caller boundary so an old observed binding cannot be reused.
#[allow(clippy::too_many_arguments)]
pub fn bootstrap(
    issuer_sk: &SigningKey,
    device_pubkey: &VerifyingKey,
    platform: impl Into<String>,
    value_x: Vec<u8>,
    expected_device_binding: &[u8; 32],
    observed_device_binding: &[u8; 32],
    tee_value_x: Vec<u8>,
    issued_at: u64,
    ttl_secs: u64,
) -> Result<RelayCredential, RelayError> {
    issued_at
        .checked_add(ttl_secs)
        .ok_or(RelayError::TimeOverflow)?;
    if observed_device_binding != expected_device_binding {
        return Err(RelayError::DeviceBindingMismatch);
    }

    Ok(issue(
        issuer_sk,
        device_pubkey,
        platform,
        value_x,
        tee_value_x,
        issued_at,
        ttl_secs,
    ))
}

/// Bootstrap exactly once for a fresh nonce, computing the expected device
/// binding and recording the nonce before issuing the credential.
#[allow(clippy::too_many_arguments)]
pub fn bootstrap_once(
    replay_store: &mut BootstrapReplayStore,
    issuer_sk: &SigningKey,
    device_pubkey: &VerifyingKey,
    platform: impl Into<String>,
    value_x: Vec<u8>,
    nonce: [u8; 32],
    observed_device_binding: &[u8; 32],
    tee_value_x: Vec<u8>,
    issued_at: u64,
    ttl_secs: u64,
) -> Result<RelayCredential, RelayError> {
    let expected_device_binding = device_binding(&device_pubkey.to_bytes(), &tee_value_x, &nonce);
    if observed_device_binding != &expected_device_binding {
        return Err(RelayError::DeviceBindingMismatch);
    }
    replay_store.check_and_store(nonce, issued_at, ttl_secs)?;

    Ok(issue(
        issuer_sk,
        device_pubkey,
        platform,
        value_x,
        tee_value_x,
        issued_at,
        ttl_secs,
    ))
}

/// Produce a holder-of-key proof for `challenge` with the device signing key.
pub fn present(device_sk: &SigningKey, challenge: &[u8]) -> Presentation {
    Presentation {
        sig: device_sk.sign(&pop_message(challenge)).to_bytes().to_vec(),
    }
}

/// Accept a relay credential presentation and return the relying-party claims.
///
/// This helper is the intended hot-path verifier. It does not replace verifier
/// challenge freshness or replay tracking; callers still need to issue fresh
/// challenges and remember any nonce/session state required by their protocol.
pub fn accept(
    credential: &RelayCredential,
    presentation: &Presentation,
    issuer: &VerifyingKey,
    challenge: &[u8],
    now: u64,
) -> Result<AcceptedRelayClaims, RelayError> {
    credential.verify_presentation(issuer, challenge, presentation, now)?;
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
        let challenge = b"relying-party-nonce-123";
        let pop = present(&device, challenge);
        cred.verify_presentation(&issuer.verifying_key(), challenge, &pop, 1100)
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
        let pop = present(&device, b"challenge-A");
        assert_eq!(
            cred.verify_presentation(&issuer.verifying_key(), b"challenge-B", &pop, 1100),
            Err(RelayError::ProofOfPossession)
        );

        // A different key cannot present this credential.
        let pop_other = present(&other, b"challenge-A");
        assert_eq!(
            cred.verify_presentation(&issuer.verifying_key(), b"challenge-A", &pop_other, 1100),
            Err(RelayError::ProofOfPossession)
        );
    }

    #[test]
    fn device_binding_is_deterministic_and_sensitive() {
        let pk = [7u8; 32];
        let tee = [8u8; 48];
        let nonce = [9u8; 32];
        let b1 = device_binding(&pk, &tee, &nonce);
        let b2 = device_binding(&pk, &tee, &nonce);
        assert_eq!(b1, b2);
        let b3 = device_binding(&pk, &tee, &[10u8; 32]);
        assert_ne!(b1, b3);
    }

    #[test]
    fn bootstrap_rejects_binding_mismatch_before_issuing() {
        let issuer = key(1);
        let device = key(2);
        let nonce = [9u8; 32];
        let tee_value_x = vec![0xCD; 48];
        let expected = device_binding(&device.verifying_key().to_bytes(), &tee_value_x, &nonce);
        let observed = device_binding(
            &device.verifying_key().to_bytes(),
            &tee_value_x,
            &[10u8; 32],
        );

        let result = bootstrap(
            &issuer,
            &device.verifying_key(),
            "linux-tpm-client",
            vec![0xAB; 32],
            &expected,
            &observed,
            tee_value_x,
            1000,
            300,
        );

        assert_eq!(result, Err(RelayError::DeviceBindingMismatch));
    }

    #[test]
    fn bootstrap_and_accept_returns_claims() {
        let issuer = key(1);
        let device = key(2);
        let nonce = [9u8; 32];
        let tee_value_x = vec![0xCD; 48];
        let binding = device_binding(&device.verifying_key().to_bytes(), &tee_value_x, &nonce);
        let cred = bootstrap(
            &issuer,
            &device.verifying_key(),
            "linux-tpm-client",
            vec![0xAB; 32],
            &binding,
            &binding,
            tee_value_x.clone(),
            1000,
            300,
        )
        .unwrap();
        let challenge = b"fresh relying-party challenge";
        let pop = present(&device, challenge);

        let claims = accept(&cred, &pop, &issuer.verifying_key(), challenge, 1100).unwrap();

        assert_eq!(claims.platform, "linux-tpm-client");
        assert_eq!(claims.value_x, vec![0xAB; 32]);
        assert_eq!(claims.tee_value_x, tee_value_x);
        assert_eq!(
            claims.device_pubkey.to_bytes(),
            device.verifying_key().to_bytes()
        );
    }

    #[test]
    fn bootstrap_once_rejects_nonce_replay() {
        let issuer = key(1);
        let device = key(2);
        let nonce = [9u8; 32];
        let tee_value_x = vec![0xCD; 48];
        let binding = device_binding(&device.verifying_key().to_bytes(), &tee_value_x, &nonce);
        let mut replay_store = BootstrapReplayStore::new();

        bootstrap_once(
            &mut replay_store,
            &issuer,
            &device.verifying_key(),
            "linux-tpm-client",
            vec![0xAB; 32],
            nonce,
            &binding,
            tee_value_x.clone(),
            1000,
            300,
        )
        .unwrap();

        let replay = bootstrap_once(
            &mut replay_store,
            &issuer,
            &device.verifying_key(),
            "linux-tpm-client",
            vec![0xAB; 32],
            nonce,
            &binding,
            tee_value_x,
            1100,
            300,
        );

        assert_eq!(replay, Err(RelayError::BootstrapReplay));
    }

    #[test]
    fn replay_store_prunes_expired_nonces() {
        let mut replay_store = BootstrapReplayStore::new();
        let nonce = [9u8; 32];

        replay_store.check_and_store(nonce, 1000, 10).unwrap();
        assert_eq!(
            replay_store.check_and_store(nonce, 1005, 10),
            Err(RelayError::BootstrapReplay)
        );
        replay_store.check_and_store(nonce, 1011, 10).unwrap();
    }

    #[test]
    fn accept_rejects_wrong_challenge() {
        let issuer = key(1);
        let device = key(2);
        let nonce = [9u8; 32];
        let tee_value_x = vec![0xCD; 48];
        let binding = device_binding(&device.verifying_key().to_bytes(), &tee_value_x, &nonce);
        let cred = bootstrap(
            &issuer,
            &device.verifying_key(),
            "linux-tpm-client",
            vec![0xAB; 32],
            &binding,
            &binding,
            tee_value_x,
            1000,
            300,
        )
        .unwrap();
        let pop = present(&device, b"challenge-A");

        assert_eq!(
            accept(&cred, &pop, &issuer.verifying_key(), b"challenge-B", 1100),
            Err(RelayError::ProofOfPossession)
        );
    }

    #[test]
    fn accept_rejects_expired_credential() {
        let issuer = key(1);
        let device = key(2);
        let nonce = [9u8; 32];
        let tee_value_x = vec![0xCD; 48];
        let binding = device_binding(&device.verifying_key().to_bytes(), &tee_value_x, &nonce);
        let cred = bootstrap(
            &issuer,
            &device.verifying_key(),
            "linux-tpm-client",
            vec![0xAB; 32],
            &binding,
            &binding,
            tee_value_x,
            1000,
            300,
        )
        .unwrap();
        let challenge = b"fresh relying-party challenge";
        let pop = present(&device, challenge);

        assert_eq!(
            accept(&cred, &pop, &issuer.verifying_key(), challenge, 2000),
            Err(RelayError::Expired)
        );
    }
}
