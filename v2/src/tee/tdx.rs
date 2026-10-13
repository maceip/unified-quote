//! Intel TDX full DCAP quote collection through Linux configfs-TSM.
//!
//! A local TDREPORT from TDX_CMD_GET_REPORT0 is MAC protected for local use;
//! it is not a remote quote. This provider requires the kernel full-quote path.
//! A legacy-device-only host needs an explicitly implemented QGS transport.

use super::{
    detect::{path_exists, TsmRequest, TSM_REPORT_BASE},
    TeeError, TeeEvidence, TeeProvider,
};
use crate::quote::Platform;
use std::path::Path;

const MAX_QUOTE_BYTES: usize = 128 * 1024;
const MAX_AUX_BYTES: usize = 1024 * 1024;

pub struct TdxProvider;

impl TdxProvider {
    pub fn new() -> Result<Self, TeeError> {
        if !path_exists(Path::new(TSM_REPORT_BASE))? {
            return Err(TeeError::DeviceNotFound(
                "TDX full-quote collection requires configfs-TSM; legacy TDREPORT needs a supported QGS transport".into(),
            ));
        }
        let request = TsmRequest::create(Path::new(TSM_REPORT_BASE), "tdx-probe")?;
        request.require_provider("tdx_guest")?;
        request.finish()?;
        Ok(Self)
    }
}

impl TeeProvider for TdxProvider {
    fn collect_evidence(&self, report_data: &[u8; 64]) -> Result<TeeEvidence, TeeError> {
        let request = TsmRequest::create(Path::new(TSM_REPORT_BASE), "tdx")?;
        request.require_provider("tdx_guest")?;
        request.write_report_data(report_data)?;
        let quote = request.read_blob("outblob", MAX_QUOTE_BYTES)?;
        validate_quote_structure(&quote, report_data)?;
        let cert_chain = request
            .optional_blob("auxblob", MAX_AUX_BYTES)?
            .filter(|bytes| !bytes.is_empty())
            .into_iter()
            .collect();
        request.require_provider("tdx_guest")?;
        request.finish()?;
        Ok(TeeEvidence {
            platform: Platform::Tdx,
            raw_quote: quote,
            cert_chain,
            kms_private_key: None,
        })
    }

    fn platform(&self) -> Platform {
        Platform::Tdx
    }
}

/// Check framing and challenge echo only. Authentication remains the verifier's
/// job; passing this function must never be reported as a verified quote.
fn validate_quote_structure(quote: &[u8], report_data: &[u8; 64]) -> Result<(), TeeError> {
    if quote.len() < 636 + 134 || quote.len() > MAX_QUOTE_BYTES {
        return Err(TeeError::InvalidResponse(
            "TDX DCAP quote length out of bounds".into(),
        ));
    }
    if quote[0..2] != 4u16.to_le_bytes()
        || quote[2..4] != 2u16.to_le_bytes()
        || quote[4..8] != 0x81u32.to_le_bytes()
    {
        return Err(TeeError::InvalidResponse(
            "requires TDX DCAP v4 ECDSA-P256 quote; other formats need explicit support".into(),
        ));
    }
    let signature_bytes = u32::from_le_bytes(quote[632..636].try_into().unwrap()) as usize;
    if signature_bytes != quote.len() - 636 {
        return Err(TeeError::InvalidResponse(
            "TDX quote signature framing mismatch".into(),
        ));
    }
    if quote[568..632] != report_data[..] {
        return Err(TeeError::InvalidResponse(
            "TDX REPORTDATA does not match this collection request".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_local_reports_wrong_types_truncation_and_nonce_substitution() {
        let binding = [42; 64];
        assert!(validate_quote_structure(&[0; 1024], &binding).is_err());
        // A framing vector is not signed evidence; this tests collector framing only.
        let mut framing = vec![0; 636 + 134];
        framing[0..2].copy_from_slice(&4u16.to_le_bytes());
        framing[2..4].copy_from_slice(&2u16.to_le_bytes());
        framing[4..8].copy_from_slice(&0x81u32.to_le_bytes());
        framing[568..632].copy_from_slice(&binding);
        framing[632..636].copy_from_slice(&134u32.to_le_bytes());
        validate_quote_structure(&framing, &binding).unwrap();
        assert!(validate_quote_structure(&framing, &[0; 64]).is_err());
        let mut changed = framing.clone();
        changed[0] = 5;
        assert!(validate_quote_structure(&changed, &binding).is_err());
        changed = framing.clone();
        changed[2] = 3;
        assert!(validate_quote_structure(&changed, &binding).is_err());
        changed = framing.clone();
        changed.push(0);
        assert!(validate_quote_structure(&changed, &binding).is_err());
        framing.pop();
        assert!(validate_quote_structure(&framing, &binding).is_err());
    }
}
