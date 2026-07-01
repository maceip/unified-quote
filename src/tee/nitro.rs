//! AWS Nitro Enclaves evidence collection.
//!
//! Collects attestation documents from the Nitro Security Module (NSM)
//! via /dev/nsm using the aws-nitro-enclaves-nsm-api crate.
//!
//! The NSM returns a COSE_Sign1 structure containing:
//! - PCR0-15: platform measurement registers
//! - user_data: up to 512 bytes (we put sha256(pubkey))
//! - public_key: DER-encoded public key (our ed25519 key)
//! - nonce: optional anti-replay
//! - certificate + cabundle: cert chain to AWS Nitro Root CA
//!
//! The attestation document is self-contained — no external fetch needed.

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
        use serde_bytes::ByteBuf;

        // report_data layout:
        //   [0..32]  = sha256(ed25519_pubkey)
        //   [32..48] = value_x[0..16]
        //   [48..64] = reserved
        //
        // We put the first 32 bytes (pubkey hash) in user_data
        // and the full 64 bytes in public_key for binding.
        let user_data = report_data[..32].to_vec();

        let request = Request::Attestation {
            nonce: None,
            user_data: Some(ByteBuf::from(user_data)),
            public_key: Some(ByteBuf::from(report_data.to_vec())),
        };

        let response = aws_nitro_enclaves_nsm_api::driver::nsm_process_request(self.fd, request);

        match response {
            Response::Attestation { document } => Ok(TeeEvidence {
                platform: Platform::Nitro,
                raw_quote: document,
                cert_chain: Vec::new(), // cert chain is inside the COSE_Sign1 document
            }),
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
