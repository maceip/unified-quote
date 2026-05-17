//! AWS Nitro Enclaves evidence collection.
//!
//! Collects attestation documents from the Nitro Security Module (NSM)
//! via /dev/nsm using the aws-nitro-enclaves-nsm-api crate.
//!
//! The NSM returns a COSE_Sign1 structure containing:
//! - PCR0-15: platform measurement registers
//! - user_data: up to 512 bytes (we put the binding hash)
//! - public_key: DER-encoded RSA-2048 public key (for KMS integration)
//! - nonce: optional anti-replay
//! - certificate + cabundle: cert chain to AWS Nitro Root CA
//!
//! KMS integration: the public_key field carries an RSA-2048 SPKI DER key.
//! When this attestation document is sent to KMS as a Recipient, KMS
//! encrypts its response to this key. Only the enclave holding the
//! corresponding private key can decrypt it.

use super::{TeeError, TeeEvidence, TeeProvider};
use crate::quote::Platform;

pub struct NitroProvider {
    fd: i32,
}

impl NitroProvider {
    pub fn new() -> Result<Self, TeeError> {
        if !std::path::Path::new("/dev/nsm").exists() {
            return Err(TeeError::DeviceNotFound("/dev/nsm".into()));
        }

        let fd = aws_nitro_enclaves_nsm_api::driver::nsm_init();
        if fd < 0 {
            return Err(TeeError::DeviceNotFound(format!(
                "/dev/nsm exists but nsm_init() returned {fd}"
            )));
        }

        Ok(Self { fd })
    }

    /// Generate a fresh attestation document with a pre-existing RSA public key.
    /// Used for KMS integration: the RSA keypair is generated once at boot,
    /// but the attestation document must be refreshed for each KMS call
    /// (KMS rejects documents older than 5 minutes).
    pub fn fresh_attestation(
        &self,
        report_data: &[u8; 64],
        rsa_pub_der: &[u8],
    ) -> Result<Vec<u8>, TeeError> {
        use aws_nitro_enclaves_nsm_api::api::{Request, Response};
        use serde_bytes::ByteBuf;

        let request = Request::Attestation {
            nonce: None,
            user_data: Some(ByteBuf::from(report_data.to_vec())),
            public_key: Some(ByteBuf::from(rsa_pub_der.to_vec())),
        };

        let response = aws_nitro_enclaves_nsm_api::driver::nsm_process_request(self.fd, request);

        match response {
            Response::Attestation { document } => Ok(document),
            Response::Error(code) => Err(TeeError::InvalidResponse(format!(
                "NSM attestation refresh error: {code:?}"
            ))),
            other => Err(TeeError::InvalidResponse(format!(
                "unexpected NSM response: {other:?}"
            ))),
        }
    }
}

impl Drop for NitroProvider {
    fn drop(&mut self) {
        if self.fd >= 0 {
            aws_nitro_enclaves_nsm_api::driver::nsm_exit(self.fd);
        }
    }
}

impl TeeProvider for NitroProvider {
    fn collect_evidence(&self, report_data: &[u8; 64]) -> Result<TeeEvidence, TeeError> {
        use aws_nitro_enclaves_nsm_api::api::{Request, Response};
        use rsa::pkcs8::EncodePublicKey;
        use rsa::RsaPrivateKey;
        use serde_bytes::ByteBuf;

        // report_data layout:
        //   [0..32]  = sha256(binding) — binds CT, A, X into the quote
        //   [32..64] = value_x[0..32] prefix
        //
        // user_data carries the full report_data for binding verification.
        // public_key carries an RSA-2048 SPKI DER key for KMS integration.

        // Generate RSA-2048 keypair inside the enclave.
        // KMS encrypts its response to this public key.
        // The private key never leaves the enclave.
        let mut rng = rand::thread_rng();
        let rsa_private = RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|e| TeeError::InvalidResponse(format!("RSA keygen: {e}")))?;
        let rsa_public = rsa::RsaPublicKey::from(&rsa_private);
        let rsa_pub_der = rsa_public
            .to_public_key_der()
            .map_err(|e| TeeError::InvalidResponse(format!("RSA pubkey DER: {e}")))?;

        // Encode private key for storage (stays inside enclave memory)
        let rsa_priv_der = rsa::pkcs8::EncodePrivateKey::to_pkcs8_der(&rsa_private)
            .map_err(|e| TeeError::InvalidResponse(format!("RSA privkey DER: {e}")))?;

        let request = Request::Attestation {
            nonce: None,
            user_data: Some(ByteBuf::from(report_data.to_vec())),
            public_key: Some(ByteBuf::from(rsa_pub_der.as_bytes().to_vec())),
        };

        let response = aws_nitro_enclaves_nsm_api::driver::nsm_process_request(self.fd, request);

        match response {
            Response::Attestation { document } => {
                eprintln!(
                    "[bountynet/nitro] Attestation document: {} bytes, RSA pubkey: {} bytes",
                    document.len(),
                    rsa_pub_der.as_bytes().len()
                );
                Ok(TeeEvidence {
                    platform: Platform::Nitro,
                    raw_quote: document,
                    cert_chain: Vec::new(), // cert chain is inside the COSE_Sign1 document
                    kms_private_key: Some(rsa_priv_der.as_bytes().to_vec()),
                })
            }
            Response::Error(code) => Err(TeeError::InvalidResponse(format!(
                "NSM attestation error: {code:?}"
            ))),
            other => Err(TeeError::InvalidResponse(format!(
                "unexpected NSM response: {other:?}"
            ))),
        }
    }

    fn platform(&self) -> Platform {
        Platform::Nitro
    }
}

/// Decrypt a KMS CiphertextForRecipient (CMS EnvelopedData) blob.
///
/// KMS wraps the plaintext in CMS EnvelopedData (RFC 5652):
///   1. Generates random AES-256 key (DEK)
///   2. RSA-OAEP-SHA256 encrypts DEK to the enclave's public key
///   3. AES-256-CBC encrypts the plaintext with the DEK
///   4. Wraps both in a CMS EnvelopedData structure
///
/// We reverse the process: parse CMS → RSA decrypt DEK → AES decrypt plaintext.
pub fn kms_decrypt(private_key_der: &[u8], cms_bytes: &[u8]) -> Result<Vec<u8>, TeeError> {
    use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::{Oaep, RsaPrivateKey};
    use sha2::Sha256;

    // Parse the CMS EnvelopedData to extract components
    let cms = parse_cms_enveloped_data(cms_bytes)
        .map_err(|e| TeeError::InvalidResponse(format!("CMS parse: {e}")))?;

    eprintln!(
        "[bountynet/kms] CMS: encrypted_key={} bytes, iv={} bytes, content={} bytes",
        cms.encrypted_key.len(),
        cms.iv.len(),
        cms.encrypted_content.len()
    );

    // Step 1: RSA-OAEP-SHA256 decrypt the AES key
    let rsa_key = RsaPrivateKey::from_pkcs8_der(private_key_der)
        .map_err(|e| TeeError::InvalidResponse(format!("RSA privkey decode: {e}")))?;

    let aes_key = rsa_key
        .decrypt(Oaep::new::<Sha256>(), &cms.encrypted_key)
        .map_err(|e| TeeError::InvalidResponse(format!("RSA-OAEP decrypt DEK: {e}")))?;

    if aes_key.len() != 32 {
        return Err(TeeError::InvalidResponse(format!(
            "Expected 32-byte AES key, got {}",
            aes_key.len()
        )));
    }

    // Step 2: AES-256-CBC decrypt the content
    type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
    let decryptor = Aes256CbcDec::new_from_slices(&aes_key, &cms.iv)
        .map_err(|e| TeeError::InvalidResponse(format!("AES init: {e}")))?;

    let mut buf = cms.encrypted_content.clone();
    let plaintext = decryptor
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| TeeError::InvalidResponse(format!("AES-CBC decrypt: {e}")))?;

    Ok(plaintext.to_vec())
}

/// Parsed components from a CMS EnvelopedData structure.
struct CmsComponents {
    encrypted_key: Vec<u8>, // RSA-OAEP encrypted AES key (256 bytes for RSA-2048)
    iv: Vec<u8>,            // AES-256-CBC IV (16 bytes)
    encrypted_content: Vec<u8>, // AES-256-CBC encrypted plaintext
}

/// Parse KMS CMS EnvelopedData (BER with indefinite length).
///
/// Structure:
///   ContentInfo {
///     contentType: envelopedData (1.2.840.113549.1.7.3)
///     content: [0] EXPLICIT {
///       EnvelopedData {
///         version: 2
///         recipientInfos: SET {
///           KeyTransRecipientInfo {
///             version: 2
///             rid: [0] subjectKeyIdentifier
///             keyEncryptionAlgorithm: RSAES-OAEP { SHA-256, MGF1-SHA-256 }
///             encryptedKey: OCTET STRING (256 bytes)
///           }
///         }
///         encryptedContentInfo: {
///           contentType: data (1.2.840.113549.1.7.1)
///           contentEncryptionAlgorithm: { aes-256-cbc, IV }
///           encryptedContent: [0] IMPLICIT OCTET STRING
///         }
///       }
///     }
///   }
fn parse_cms_enveloped_data(data: &[u8]) -> Result<CmsComponents, String> {
    // Find the 256-byte RSA-encrypted key.
    // In BER, it's: 04 82 01 00 <256 bytes>
    let encrypted_key = find_octet_string_of_size(data, 256)
        .ok_or("Cannot find 256-byte encrypted key (RSA-2048) in CMS")?;

    // Find AES-256-CBC OID: 2.16.840.1.101.3.4.1.42
    // BER encoding: 06 09 60 86 48 01 65 03 04 01 2a
    let aes_cbc_oid = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a];
    let oid_pos =
        find_subsequence(data, &aes_cbc_oid).ok_or("Cannot find AES-256-CBC OID in CMS")?;

    // IV is the OCTET STRING right after the OID
    let after_oid = oid_pos + aes_cbc_oid.len();
    let iv =
        read_ber_octet_string(&data[after_oid..]).ok_or("Cannot find IV after AES-256-CBC OID")?;
    if iv.len() != 16 {
        return Err(format!("Expected 16-byte IV, got {}", iv.len()));
    }

    // Encrypted content: [0] IMPLICIT (context tag 0x80) after the algorithm sequence.
    // Find it after the IV.
    let iv_tag_len = 2; // 04 10 (tag + length for 16-byte OCTET STRING)
    let content_start = after_oid + iv_tag_len + 16;

    // The EncryptedContentInfo's encryptedContent is [0] IMPLICIT OCTET STRING.
    // In BER, the outer SEQUENCE is indefinite-length, so after the algorithm
    // SEQUENCE we may have nested structures. Walk forward to find tag 0x80.
    let encrypted_content = find_context_0_content(&data[content_start..])
        .ok_or("Cannot find encrypted content ([0] IMPLICIT) in CMS")?;

    Ok(CmsComponents {
        encrypted_key,
        iv,
        encrypted_content,
    })
}

/// Find an OCTET STRING (tag 0x04) of exactly `size` bytes in the BER data.
fn find_octet_string_of_size(data: &[u8], size: usize) -> Option<Vec<u8>> {
    for i in 0..data.len().saturating_sub(4) {
        if data[i] == 0x04 {
            if let Some((len, hdr_size)) = read_ber_length(&data[i + 1..]) {
                if len == size && i + 1 + hdr_size + size <= data.len() {
                    let start = i + 1 + hdr_size;
                    return Some(data[start..start + size].to_vec());
                }
            }
        }
    }
    None
}

/// Find [0] content (tag 0xA0 for constructed, 0x80 for primitive).
/// KMS uses constructed [0] with indefinite length: `a0 80 <OCTET STRINGs> 00 00`
fn find_context_0_content(data: &[u8]) -> Option<Vec<u8>> {
    for i in 0..data.len().saturating_sub(2) {
        let tag = data[i];
        // Constructed [0] — 0xA0 (what KMS actually sends)
        if tag == 0xA0 {
            // Indefinite length: a0 80 ... 00 00
            if data.get(i + 1) == Some(&0x80) {
                return collect_indefinite_content(&data[i + 2..]);
            }
            // Definite length
            if let Some((len, hdr_size)) = read_ber_length(&data[i + 1..]) {
                if len > 0 && i + 1 + hdr_size + len <= data.len() {
                    let start = i + 1 + hdr_size;
                    return Some(data[start..start + len].to_vec());
                }
            }
        }
        // Primitive [0] IMPLICIT — 0x80
        if tag == 0x80 {
            if let Some((len, hdr_size)) = read_ber_length(&data[i + 1..]) {
                if len > 0 && i + 1 + hdr_size + len <= data.len() {
                    let start = i + 1 + hdr_size;
                    return Some(data[start..start + len].to_vec());
                }
            }
        }
    }
    None
}

/// Collect content from indefinite-length encoding until 00 00 terminator.
/// Handles chunked OCTET STRINGs (constructed encoding).
fn collect_indefinite_content(data: &[u8]) -> Option<Vec<u8>> {
    let mut result = Vec::new();
    let mut pos = 0;
    while pos + 1 < data.len() {
        // End-of-contents marker
        if data[pos] == 0x00 && data[pos + 1] == 0x00 {
            if !result.is_empty() {
                return Some(result);
            }
            break;
        }
        // OCTET STRING chunk
        if data[pos] == 0x04 {
            if let Some((len, hdr_size)) = read_ber_length(&data[pos + 1..]) {
                let start = pos + 1 + hdr_size;
                if start + len <= data.len() {
                    result.extend_from_slice(&data[start..start + len]);
                    pos = start + len;
                    continue;
                }
            }
        }
        pos += 1;
    }
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

/// Read a BER length field. Returns (length, number of bytes consumed).
fn read_ber_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }
    let first = data[0];
    if first < 0x80 {
        // Short form
        Some((first as usize, 1))
    } else if first == 0x80 {
        // Indefinite — caller handles
        None
    } else {
        // Long form
        let num_bytes = (first & 0x7f) as usize;
        if num_bytes == 0 || num_bytes > 4 || data.len() < 1 + num_bytes {
            return None;
        }
        let mut len = 0usize;
        for j in 0..num_bytes {
            len = (len << 8) | data[1 + j] as usize;
        }
        Some((len, 1 + num_bytes))
    }
}

/// Read a BER OCTET STRING at the current position.
fn read_ber_octet_string(data: &[u8]) -> Option<Vec<u8>> {
    if data.is_empty() || data[0] != 0x04 {
        return None;
    }
    let (len, hdr_size) = read_ber_length(&data[1..])?;
    let start = 1 + hdr_size;
    if start + len <= data.len() {
        Some(data[start..start + len].to_vec())
    } else {
        None
    }
}

/// Find a byte subsequence.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
