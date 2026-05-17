//! Attested TLS: self-signed certs that embed an EAT attestation.
//!
//! ## What this is and is NOT
//!
//! This module produces and consumes X.509 certificates with an
//! embedded attestation evidence extension. A verifier that completes
//! a TLS handshake against such a cert can confirm that the session
//! terminates inside a genuine TEE running known code — with **no CA
//! in the trust chain**. The CPU vendor's root of trust replaces the
//! CA's.
//!
//! ### Standards mix
//!
//! - **Token format:** [IETF RATS EAT (RFC 9711)](https://datatracker.ietf.org/doc/rfc9711/).
//!   The `platform_quote`, `value_x`, and binding claims are serialized
//!   per the `bountynet-v2` EAT profile defined in [`crate::eat`].
//! - **Wrapper concept:** [CMW (draft-ietf-rats-msg-wrap)](https://datatracker.ietf.org/doc/draft-ietf-rats-msg-wrap/).
//!   An IETF RATS draft for wrapping attestation evidence in a
//!   transport-agnostic container. Still a draft; we use its concept
//!   but the wire format is not frozen.
//! - **X.509 binding:** [TCG DICE Attestation Architecture v1.1](https://trustedcomputinggroup.org/wp-content/uploads/TCG-DICE-Attestation-Architecture-Version-1.1.pdf)
//!   assigns OID `2.23.133.5.4.9`
//!   (`tcg-dice-conceptual-message-wrapper`, formerly
//!   `tcg-dice-tagged-evidence`) to carry a CMW-wrapped evidence blob.
//!   This is **not** an IETF standard; it's a TCG publication. Gramine
//!   uses the same OID, so carrying an EAT at this OID gives us
//!   interop with the Gramine RA-TLS ecosystem.
//! - **The flow** (embed attestation in a self-signed cert, bind TLS
//!   key hash into the quote's report_data, verify both during
//!   handshake) is generically called "RA-TLS" — a term coined by
//!   Intel in 2019 that predates the RATS WG and has no single
//!   specification. We implement the de facto pattern.
//!
//! So: **the token is IETF RATS EAT, the X.509 extension OID is TCG
//! DICE, and the flow name is industry shorthand**. There's no single
//! standard to cite for "attestation in X.509 for TLS" because the
//! IETF hasn't published one yet — the closest drafts
//! (`draft-ounsworth-rats-x509-evidence`, `draft-jpfiset-lamps-attestationkey-eku`)
//! are early and unimplemented.
//!
//! ## Invariants this module enforces
//!
//! 1. The TLS private key is generated inside the enclave, used ONLY
//!    for this cert, never exported.
//! 2. The cert's SPKI hash matches the EAT's `tls_spki_hash`.
//! 3. The extension value is the raw EAT CBOR bytes. The full CMW
//!    outer tagging per TCG DICE v1.1 is left TBD — today both ends
//!    (producer and verifier) live in this codebase so a simple
//!    raw-CBOR container is sufficient, and the extension layer is
//!    independent from the EAT schema.
//!
//! ## The criticality trade-off
//!
//! The ideal attestation extension would be marked **critical**: any
//! client that doesn't understand OID `2.23.133.5.4.9` would reject
//! the cert, fail-closed. That's what Gramine does with mbedtls.
//!
//! rustls (and by extension reqwest, tonic, tokio-rustls, etc.) will
//! **reject** any cert containing an unknown critical extension
//! *before* calling a custom `ServerCertVerifier` — its cert-parsing
//! layer enforces RFC 5280's "MUST reject unknown critical" rule
//! regardless of whether the outer verifier would have accepted. This
//! means a critical extension makes the cert unusable with the entire
//! rustls ecosystem unless we fork the cert parser.
//!
//! We mark the extension **non-critical**. Trade-off:
//!
//! - Attested-TLS-aware clients (our `bountynet check`) look for the
//!   extension unconditionally, verify it, and fail-closed if it's
//!   missing or invalid. Their guarantee is unchanged.
//! - Attested-TLS-unaware clients see the extension, ignore it, and
//!   trust the cert based on whatever other signal they have
//!   (typically the CA chain on the LE path). They get the same
//!   guarantee they'd get from any other self-signed or LE cert — no
//!   worse, no better.
//!
//! The "fail closed on unaware clients" property is deliberately
//! sacrificed to keep the rustls ecosystem usable. When we add the
//! dual-cert path (step 9 in DESIGN.md), attested-aware clients can
//! be directed to a self-signed cert on a separate ALPN, and
//! criticality can be restored by using a non-rustls stack only on
//! that path.
//!
//! ## Caller order (producer)
//!
//! 1. Generate keypair via [`generate_keypair`].
//! 2. Compute SPKI hash via [`spki_hash_of`].
//! 3. Build [`crate::eat::EatToken`] with `tls_spki_hash` set; leave
//!    `platform_quote` empty for now.
//! 4. Call [`crate::eat::EatToken::binding_bytes`] to get the 32-byte
//!    value that MUST go into `report_data[0..32]` before quote
//!    collection.
//! 5. Collect the TEE quote with that report_data.
//! 6. Set `eat.platform_quote = raw_quote_bytes`. Serialize EAT to CBOR.
//! 7. Call [`make_attested_cert`] with the keypair, domain, and final CBOR.

use anyhow::{anyhow, Result};
use rcgen::{CertificateParams, CustomExtension, KeyPair, PKCS_ECDSA_P256_SHA256};
use sha2::{Digest, Sha256};

/// TCG DICE `tcg-dice-conceptual-message-wrapper` OID. X.509 extension
/// that carries an attestation evidence payload (an EAT in our case).
///
/// Defined by TCG DICE Attestation Architecture v1.1. Gramine uses the
/// same OID in its current attested-TLS implementation. **Not** an IETF
/// RATS assignment — the IETF has no standard X.509 OID for attestation
/// evidence yet (as of April 2026).
pub const TCG_DICE_CMW_OID: &[u64] = &[2, 23, 133, 5, 4, 9];

/// Generate a fresh P-256 keypair. Never exported outside the enclave.
pub fn generate_keypair() -> Result<KeyPair> {
    KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|e| anyhow!("rcgen keypair: {e}"))
}

/// sha256 of the keypair's SubjectPublicKeyInfo DER encoding.
///
/// This is the value that goes into `eat.tls_spki_hash` and that the
/// verifier recomputes from the leaf cert during the TLS handshake to
/// prove channel binding.
pub fn spki_hash_of(key_pair: &KeyPair) -> [u8; 32] {
    let spki_der = key_pair.public_key_der();
    Sha256::digest(&spki_der).into()
}

/// Generated attested-TLS certificate material, ready to hand to rustls.
pub struct AttestedCert {
    pub cert_pem: String,
    pub key_pem: String,
    pub cert_der: Vec<u8>,
}

/// Build a self-signed X.509 cert for `domain` containing `eat_cbor`
/// as an extension at [`TCG_DICE_CMW_OID`] (non-critical — see the
/// module-level "criticality trade-off" docs).
pub fn make_attested_cert(
    key_pair: &KeyPair,
    domain: &str,
    eat_cbor: &[u8],
) -> Result<AttestedCert> {
    let mut params = CertificateParams::new(vec![domain.to_string()])
        .map_err(|e| anyhow!("rcgen params: {e}"))?;

    // NON-critical: see module-level docs on "The criticality trade-off".
    // Attested-TLS-aware clients check this extension regardless of the flag.
    let ext = CustomExtension::from_oid_content(TCG_DICE_CMW_OID, eat_cbor.to_vec());
    params.custom_extensions.push(ext);

    let cert = params
        .self_signed(key_pair)
        .map_err(|e| anyhow!("self_signed: {e}"))?;

    Ok(AttestedCert {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
        cert_der: cert.der().to_vec(),
    })
}

/// Pull the raw EAT CBOR bytes out of a DER-encoded certificate's
/// TCG DICE CMW extension. Returns `None` if the extension is missing.
///
/// This is a minimal parser tuned for the attested-TLS hot path — it
/// uses `x509-cert` to reach the extensions list, then looks for
/// [`TCG_DICE_CMW_OID`]. For proper CA chain / SAN validation use
/// `x509-cert` directly on the `tbs_certificate`.
pub fn extract_eat_from_cert(cert_der: &[u8]) -> Result<Option<Vec<u8>>> {
    use x509_cert::der::Decode;
    use x509_cert::Certificate;

    let cert = Certificate::from_der(cert_der).map_err(|e| anyhow!("x509 decode: {e}"))?;

    let exts = match &cert.tbs_certificate.extensions {
        Some(v) => v,
        None => return Ok(None),
    };

    let target_oid = x509_cert::der::asn1::ObjectIdentifier::new("2.23.133.5.4.9")
        .map_err(|e| anyhow!("oid parse: {e}"))?;

    for ext in exts {
        if ext.extn_id == target_oid {
            let inner = ext.extn_value.as_bytes().to_vec();
            // rcgen double-wraps in an extra OCTET STRING. Peel if present.
            if let Ok(outer) = x509_cert::der::asn1::OctetString::from_der(&inner) {
                return Ok(Some(outer.as_bytes().to_vec()));
            }
            return Ok(Some(inner));
        }
    }
    Ok(None)
}

/// Recompute the TLS SPKI hash from a DER-encoded leaf certificate.
/// Used by the verifier to compare against `eat.tls_spki_hash`.
pub fn spki_hash_of_cert(cert_der: &[u8]) -> Result<[u8; 32]> {
    use x509_cert::der::{Decode, Encode};
    use x509_cert::Certificate;

    let cert = Certificate::from_der(cert_der).map_err(|e| anyhow!("x509 decode: {e}"))?;
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| anyhow!("spki encode: {e}"))?;
    Ok(Sha256::digest(&spki_der).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_has_stable_spki_hash() {
        let kp = generate_keypair().unwrap();
        let a = spki_hash_of(&kp);
        let b = spki_hash_of(&kp);
        assert_eq!(a, b);
    }

    #[test]
    fn two_keypairs_have_different_spki_hashes() {
        let a = spki_hash_of(&generate_keypair().unwrap());
        let b = spki_hash_of(&generate_keypair().unwrap());
        assert_ne!(a, b);
    }

    #[test]
    fn cert_extension_roundtrips() {
        let kp = generate_keypair().unwrap();
        let payload = b"test eat cbor payload";
        let cert = make_attested_cert(&kp, "test.local", payload).unwrap();

        let recovered = extract_eat_from_cert(&cert.cert_der)
            .unwrap()
            .expect("extension present");
        assert_eq!(recovered, payload);
    }

    #[test]
    fn cert_spki_hash_matches_keypair() {
        let kp = generate_keypair().unwrap();
        let from_kp = spki_hash_of(&kp);

        let cert = make_attested_cert(&kp, "test.local", b"abc").unwrap();
        let from_cert = spki_hash_of_cert(&cert.cert_der).unwrap();

        assert_eq!(
            from_kp, from_cert,
            "hash of keypair SPKI should equal hash of cert's SPKI — \
             otherwise channel binding is broken"
        );
    }

    #[test]
    fn absent_extension_returns_none() {
        let kp = generate_keypair().unwrap();
        let params = rcgen::CertificateParams::new(vec!["noext.local".to_string()]).unwrap();
        let cert = params.self_signed(&kp).unwrap();
        let der = cert.der().to_vec();
        let found = extract_eat_from_cert(&der).unwrap();
        assert!(found.is_none());
    }
}
