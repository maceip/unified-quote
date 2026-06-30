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

const CRED_DOMAIN: &[u8] = b"uq/relay/credential\0";
const BIND_DOMAIN: &[u8] = b"uq/relay/device-binding\0";
const POP_DOMAIN: &[u8] = b"uq/relay/proof-of-possession\0";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RelayError {
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("invalid signature encoding")]
    InvalidSignature,
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
    pub fn verify(
        &self,
        issuer: &VerifyingKey,
        now: u64,
    ) -> Result<VerifyingKey, RelayError> {
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

/// Produce a holder-of-key proof for `challenge` with the device signing key.
pub fn present(device_sk: &SigningKey, challenge: &[u8]) -> Presentation {
    Presentation {
        sig: device_sk.sign(&pop_message(challenge)).to_bytes().to_vec(),
    }
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
        let cred = issue(&issuer, &device.verifying_key(), "macos-app-attest", vec![1; 32], vec![2; 48], 1000, 300);
        assert_eq!(cred.verify(&issuer.verifying_key(), 2000), Err(RelayError::Expired));
        assert_eq!(cred.verify(&issuer.verifying_key(), 0), Err(RelayError::NotYetValid));
    }

    #[test]
    fn rejects_wrong_issuer_and_tamper() {
        let issuer = key(1);
        let attacker = key(9);
        let device = key(2);
        let cred = issue(&issuer, &device.verifying_key(), "linux-tpm-client", vec![1; 32], vec![2; 48], 1000, 300);

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
        let cred = issue(&issuer, &device.verifying_key(), "linux-tpm-client", vec![1; 32], vec![2; 48], 1000, 300);

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
}
