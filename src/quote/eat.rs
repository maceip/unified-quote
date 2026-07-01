//! EAT (Entity Attestation Token) encoding and decoding.
//!
//! Modified EAT profile "bountynet-v2" using COSE_Sign1 over CBOR.
//! Based on RFC 9711 (EAT) with custom claims for TEE attestation.
//!
//! Wire format:
//!   COSE_Sign1 {
//!     protected: { alg: EdDSA (-8) }
//!     payload: CBOR map with integer keys
//!     signature: 64 bytes (ed25519)
//!   }
//!
//! The CBOR map uses integer keys for compactness:
//!
//!   IDENTITY:    1=value_x  2=platform  3=pubkey
//!   EVIDENCE:   10=quote_hash  11=platform_quote  12=tcb_version  13=collateral_hash
//!   PROVENANCE: 20=build_hash  21=source_commit  22=registry_entry
//!   FRESHNESS:  30=iat  31=nonce  32=heartbeat_seq  33=integrity_ok
//!   PROFILE:     0=version  -1=eat_profile

use ciborium::Value as CborValue;
use coset::{iana, CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use super::Platform;

// CBOR map key constants
const KEY_VERSION: i64 = 0;
const KEY_EAT_PROFILE: i64 = -1;
const KEY_VALUE_X: i64 = 1;
const KEY_PLATFORM: i64 = 2;
const KEY_PUBKEY: i64 = 3;
const KEY_QUOTE_HASH: i64 = 10;
const KEY_PLATFORM_QUOTE: i64 = 11;
const KEY_TCB_VERSION: i64 = 12;
const KEY_COLLATERAL_HASH: i64 = 13;
const KEY_BUILD_HASH: i64 = 20;
const KEY_SOURCE_COMMIT: i64 = 21;
const KEY_REGISTRY_ENTRY: i64 = 22;
const KEY_IAT: i64 = 30;
const KEY_NONCE: i64 = 31;
const KEY_HEARTBEAT_SEQ: i64 = 32;
const KEY_INTEGRITY_OK: i64 = 33;

const EAT_PROFILE: &str = "bountynet-v2";
const SCHEMA_VERSION: u64 = 2;

/// All claims in an EAT attestation token.
#[derive(Debug, Clone)]
pub struct EatClaims {
    // Identity
    pub value_x: [u8; 48],
    pub platform: Platform,
    pub pubkey: [u8; 32],

    // Evidence
    pub quote_hash: [u8; 32],
    pub platform_quote: Option<Vec<u8>>,
    pub tcb_version: Option<String>,
    pub collateral_hash: Option<[u8; 32]>,

    // Provenance
    pub build_hash: Option<[u8; 32]>,
    pub source_commit: Option<String>,
    pub registry_entry: Option<String>,

    // Freshness
    pub iat: u64,
    pub nonce: [u8; 32],
    pub heartbeat_seq: u64,
    pub integrity_ok: bool,
}

/// A signed EAT token (COSE_Sign1 envelope).
#[derive(Debug, Clone)]
pub struct EatToken {
    pub claims: EatClaims,
    /// Raw COSE_Sign1 bytes (the canonical wire format).
    pub cose_bytes: Vec<u8>,
}

impl EatClaims {
    /// Encode claims as a CBOR map.
    pub fn to_cbor(&self) -> Vec<u8> {
        let mut map: Vec<(CborValue, CborValue)> = Vec::with_capacity(16);

        // Profile
        map.push((
            CborValue::Integer(KEY_VERSION.into()),
            CborValue::Integer(SCHEMA_VERSION.into()),
        ));
        map.push((
            CborValue::Integer(KEY_EAT_PROFILE.into()),
            CborValue::Text(EAT_PROFILE.into()),
        ));

        // Identity
        map.push((
            CborValue::Integer(KEY_VALUE_X.into()),
            CborValue::Bytes(self.value_x.to_vec()),
        ));
        map.push((
            CborValue::Integer(KEY_PLATFORM.into()),
            CborValue::Integer((self.platform as u8 as u64).into()),
        ));
        map.push((
            CborValue::Integer(KEY_PUBKEY.into()),
            CborValue::Bytes(self.pubkey.to_vec()),
        ));

        // Evidence
        map.push((
            CborValue::Integer(KEY_QUOTE_HASH.into()),
            CborValue::Bytes(self.quote_hash.to_vec()),
        ));
        if let Some(ref q) = self.platform_quote {
            map.push((
                CborValue::Integer(KEY_PLATFORM_QUOTE.into()),
                CborValue::Bytes(q.clone()),
            ));
        }
        if let Some(ref v) = self.tcb_version {
            map.push((
                CborValue::Integer(KEY_TCB_VERSION.into()),
                CborValue::Text(v.clone()),
            ));
        }
        if let Some(ref h) = self.collateral_hash {
            map.push((
                CborValue::Integer(KEY_COLLATERAL_HASH.into()),
                CborValue::Bytes(h.to_vec()),
            ));
        }

        // Provenance
        if let Some(ref h) = self.build_hash {
            map.push((
                CborValue::Integer(KEY_BUILD_HASH.into()),
                CborValue::Bytes(h.to_vec()),
            ));
        }
        if let Some(ref c) = self.source_commit {
            map.push((
                CborValue::Integer(KEY_SOURCE_COMMIT.into()),
                CborValue::Text(c.clone()),
            ));
        }
        if let Some(ref r) = self.registry_entry {
            map.push((
                CborValue::Integer(KEY_REGISTRY_ENTRY.into()),
                CborValue::Text(r.clone()),
            ));
        }

        // Freshness
        map.push((
            CborValue::Integer(KEY_IAT.into()),
            CborValue::Integer(self.iat.into()),
        ));
        map.push((
            CborValue::Integer(KEY_NONCE.into()),
            CborValue::Bytes(self.nonce.to_vec()),
        ));
        map.push((
            CborValue::Integer(KEY_HEARTBEAT_SEQ.into()),
            CborValue::Integer(self.heartbeat_seq.into()),
        ));
        map.push((
            CborValue::Integer(KEY_INTEGRITY_OK.into()),
            CborValue::Bool(self.integrity_ok),
        ));

        let cbor_map = CborValue::Map(map);
        let mut buf = Vec::new();
        ciborium::into_writer(&cbor_map, &mut buf).expect("CBOR encoding should not fail");
        buf
    }

    /// Decode claims from a CBOR map.
    pub fn from_cbor(data: &[u8]) -> Result<Self, EatError> {
        let value: CborValue =
            ciborium::from_reader(data).map_err(|e| EatError::CborDecode(format!("{e}")))?;

        let map = match value {
            CborValue::Map(m) => m,
            _ => return Err(EatError::CborDecode("expected CBOR map".into())),
        };

        let mut claims = EatClaims {
            value_x: [0u8; 48],
            platform: Platform::Tdx,
            pubkey: [0u8; 32],
            quote_hash: [0u8; 32],
            platform_quote: None,
            tcb_version: None,
            collateral_hash: None,
            build_hash: None,
            source_commit: None,
            registry_entry: None,
            iat: 0,
            nonce: [0u8; 32],
            heartbeat_seq: 0,
            integrity_ok: true,
        };

        for (k, v) in &map {
            let key = match k {
                CborValue::Integer(i) => {
                    let val: i128 = (*i).into();
                    val as i64
                }
                _ => continue,
            };

            match key {
                KEY_VALUE_X => {
                    if let CborValue::Bytes(b) = v {
                        if b.len() == 48 {
                            claims.value_x.copy_from_slice(b);
                        }
                    }
                }
                KEY_PLATFORM => {
                    if let CborValue::Integer(i) = v {
                        let val: i128 = (*i).into();
                        claims.platform = match val as u8 {
                            1 => Platform::Nitro,
                            2 => Platform::SevSnp,
                            3 => Platform::Tdx,
                            _ => Platform::Tdx,
                        };
                    }
                }
                KEY_PUBKEY => {
                    if let CborValue::Bytes(b) = v {
                        if b.len() == 32 {
                            claims.pubkey.copy_from_slice(b);
                        }
                    }
                }
                KEY_QUOTE_HASH => {
                    if let CborValue::Bytes(b) = v {
                        if b.len() == 32 {
                            claims.quote_hash.copy_from_slice(b);
                        }
                    }
                }
                KEY_PLATFORM_QUOTE => {
                    if let CborValue::Bytes(b) = v {
                        claims.platform_quote = Some(b.clone());
                    }
                }
                KEY_TCB_VERSION => {
                    if let CborValue::Text(s) = v {
                        claims.tcb_version = Some(s.clone());
                    }
                }
                KEY_COLLATERAL_HASH => {
                    if let CborValue::Bytes(b) = v {
                        if b.len() == 32 {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(b);
                            claims.collateral_hash = Some(arr);
                        }
                    }
                }
                KEY_BUILD_HASH => {
                    if let CborValue::Bytes(b) = v {
                        if b.len() == 32 {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(b);
                            claims.build_hash = Some(arr);
                        }
                    }
                }
                KEY_SOURCE_COMMIT => {
                    if let CborValue::Text(s) = v {
                        claims.source_commit = Some(s.clone());
                    }
                }
                KEY_REGISTRY_ENTRY => {
                    if let CborValue::Text(s) = v {
                        claims.registry_entry = Some(s.clone());
                    }
                }
                KEY_IAT => {
                    if let CborValue::Integer(i) = v {
                        let val: i128 = (*i).into();
                        claims.iat = val as u64;
                    }
                }
                KEY_NONCE => {
                    if let CborValue::Bytes(b) = v {
                        if b.len() == 32 {
                            claims.nonce.copy_from_slice(b);
                        }
                    }
                }
                KEY_HEARTBEAT_SEQ => {
                    if let CborValue::Integer(i) = v {
                        let val: i128 = (*i).into();
                        claims.heartbeat_seq = val as u64;
                    }
                }
                KEY_INTEGRITY_OK => {
                    if let CborValue::Bool(b) = v {
                        claims.integrity_ok = *b;
                    }
                }
                _ => {} // ignore unknown keys (forward compat)
            }
        }

        Ok(claims)
    }
}

impl EatToken {
    /// Create and sign a new EAT token.
    pub fn sign(claims: EatClaims, signing_key: &SigningKey) -> Self {
        let payload = claims.to_cbor();

        // Build COSE_Sign1 with EdDSA algorithm
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .build();

        // Build unsigned first to get the to-be-signed data
        let cose_sign1 = CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .build();

        // Sign the TBS structure
        let tbs = cose_sign1.tbs_data(&[]);
        let signature = signing_key.sign(&tbs);

        // Rebuild with signature
        let protected2 = HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .build();
        let signed = CoseSign1Builder::new()
            .protected(protected2)
            .payload(cose_sign1.payload.unwrap_or_default())
            .signature(signature.to_bytes().to_vec())
            .build();

        let cose_bytes = signed.to_vec().expect("COSE serialization should not fail");

        Self { claims, cose_bytes }
    }

    /// Decode and verify an EAT token from raw COSE_Sign1 bytes.
    pub fn verify(cose_bytes: &[u8]) -> Result<Self, EatError> {
        let cose_sign1 =
            CoseSign1::from_slice(cose_bytes).map_err(|e| EatError::CoseDecode(format!("{e}")))?;

        let payload = cose_sign1
            .payload
            .as_ref()
            .ok_or_else(|| EatError::CoseDecode("no payload".into()))?;

        let claims = EatClaims::from_cbor(payload)?;

        // Verify ed25519 signature
        let vk = VerifyingKey::from_bytes(&claims.pubkey)
            .map_err(|e| EatError::SignatureInvalid(format!("bad pubkey: {e}")))?;

        let tbs = cose_sign1.tbs_data(&[]);
        let sig_bytes = &cose_sign1.signature;
        if sig_bytes.len() != 64 {
            return Err(EatError::SignatureInvalid(format!(
                "signature length {} != 64",
                sig_bytes.len()
            )));
        }
        let sig = Signature::from_slice(sig_bytes)
            .map_err(|e| EatError::SignatureInvalid(format!("{e}")))?;

        vk.verify(&tbs, &sig)
            .map_err(|e| EatError::SignatureInvalid(format!("{e}")))?;

        Ok(Self {
            claims,
            cose_bytes: cose_bytes.to_vec(),
        })
    }

    /// Return the compact form (strip platform_quote, re-sign).
    pub fn compact(&self, signing_key: &SigningKey) -> Self {
        let mut claims = self.claims.clone();
        claims.platform_quote = None;
        Self::sign(claims, signing_key)
    }

    /// Size in bytes of the COSE_Sign1 wire format.
    pub fn wire_size(&self) -> usize {
        self.cose_bytes.len()
    }

    /// Base64-encode for HTTP-A header transport.
    pub fn to_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(&self.cose_bytes)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EatError {
    #[error("CBOR decode: {0}")]
    CborDecode(String),
    #[error("COSE decode: {0}")]
    CoseDecode(String),
    #[error("signature invalid: {0}")]
    SignatureInvalid(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha384};

    #[test]
    fn eat_roundtrip() {
        let sk = SigningKey::generate(&mut OsRng);
        let value_x: [u8; 48] = Sha384::digest(b"test-runner").into();

        let claims = EatClaims {
            value_x,
            platform: Platform::Tdx,
            pubkey: sk.verifying_key().to_bytes(),
            quote_hash: [0xAA; 32],
            platform_quote: Some(vec![1, 2, 3, 4]),
            tcb_version: Some("0d01080000000000".into()),
            collateral_hash: None,
            build_hash: None,
            source_commit: Some("abc1234".into()),
            registry_entry: None,
            iat: 1775655794,
            nonce: [0x42; 32],
            heartbeat_seq: 7,
            integrity_ok: true,
        };

        let token = EatToken::sign(claims.clone(), &sk);
        println!("EAT token size: {} bytes", token.wire_size());
        println!("Base64: {} chars", token.to_base64().len());

        // Verify
        let verified = EatToken::verify(&token.cose_bytes).expect("should verify");
        assert_eq!(verified.claims.value_x, value_x);
        assert_eq!(verified.claims.platform, Platform::Tdx);
        assert_eq!(verified.claims.iat, 1775655794);
        assert_eq!(verified.claims.heartbeat_seq, 7);
        assert!(verified.claims.integrity_ok);
        assert_eq!(verified.claims.source_commit, Some("abc1234".into()));
    }

    #[test]
    fn eat_compact_is_small() {
        let sk = SigningKey::generate(&mut OsRng);
        let value_x: [u8; 48] = Sha384::digest(b"compact-test").into();

        let claims = EatClaims {
            value_x,
            platform: Platform::SevSnp,
            pubkey: sk.verifying_key().to_bytes(),
            quote_hash: [0xBB; 32],
            platform_quote: Some(vec![0u8; 8000]), // big TDX quote
            tcb_version: None,
            collateral_hash: None,
            build_hash: None,
            source_commit: None,
            registry_entry: None,
            iat: 1775655794,
            nonce: [0x00; 32],
            heartbeat_seq: 0,
            integrity_ok: true,
        };

        let full = EatToken::sign(claims, &sk);
        let compact = full.compact(&sk);

        println!("Full size:    {} bytes", full.wire_size());
        println!("Compact size: {} bytes", compact.wire_size());

        assert!(compact.wire_size() < 300, "compact should be <300 bytes");
        assert!(full.wire_size() > 8000, "full should include the 8KB quote");

        // Compact still verifies
        let verified = EatToken::verify(&compact.cose_bytes).expect("compact should verify");
        assert_eq!(verified.claims.platform, Platform::SevSnp);
        assert!(verified.claims.platform_quote.is_none());
    }

    #[test]
    fn eat_rejects_tampered_token() {
        let sk = SigningKey::generate(&mut OsRng);
        let claims = EatClaims {
            value_x: [0xFF; 48],
            platform: Platform::Nitro,
            pubkey: sk.verifying_key().to_bytes(),
            quote_hash: [0; 32],
            platform_quote: None,
            tcb_version: None,
            collateral_hash: None,
            build_hash: None,
            source_commit: None,
            registry_entry: None,
            iat: 0,
            nonce: [0; 32],
            heartbeat_seq: 0,
            integrity_ok: true,
        };

        let token = EatToken::sign(claims, &sk);
        let mut tampered = token.cose_bytes.clone();
        // Flip a byte in the payload
        if tampered.len() > 20 {
            tampered[20] ^= 0xFF;
        }

        assert!(EatToken::verify(&tampered).is_err());
    }
}
