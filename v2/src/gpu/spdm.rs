//! NVIDIA's NVML SPDM 1.1 report profile: a 37-byte signed all-measurements
//! request, followed by MEASUREMENTS with SHA-384 digests and P-384 r||s.
//! The signature covers the entire request and response except the signature.
//! Other SPDM versions/algorithms require their own negotiated transcript
//! rules and are rejected here. Opaque data is retained without appraisal.

use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};

pub const MAX_REPORT_SIZE: usize = 0x2000;
const REQUEST_SIZE: usize = 37;
const SIGNATURE_SIZE: usize = 96;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SpdmError {
    #[error("SPDM report exceeds the NVML 8192-byte limit")]
    Oversized,
    #[error("truncated SPDM {0}")]
    Truncated(&'static str),
    #[error("unsupported or malformed SPDM {0}")]
    Invalid(&'static str),
    #[error("SPDM request nonce does not match the verifier challenge")]
    NonceMismatch,
    #[error("SPDM P-384 signature verification failed")]
    Signature,
}

/// A syntactically valid measurement. Parsing does not authenticate it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Measurement<'a> {
    pub index: u8,
    /// DMTF measurement type (low seven bits of the value-type byte).
    pub value_type: u8,
    /// True for raw bit streams; false for SHA-384 digests.
    pub raw_bit_stream: bool,
    pub value: &'a [u8],
}

/// A parsed, still-untrusted report borrowing the original signed bytes.
/// Private fields prevent replacing parsed claims independently of the bytes
/// used by [`Self::verify_signature`].
#[derive(Debug)]
pub struct SpdmReport<'a> {
    signed_transcript: &'a [u8],
    signature: &'a [u8],
    request_nonce: &'a [u8],
    responder_nonce: &'a [u8],
    measurements: Vec<Measurement<'a>>,
    opaque_data: &'a [u8],
}

impl<'a> SpdmReport<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, SpdmError> {
        if bytes.len() > MAX_REPORT_SIZE {
            return Err(SpdmError::Oversized);
        }
        let mut c = Cursor(bytes);
        let request = c.take(REQUEST_SIZE, "GET_MEASUREMENTS request")?;
        // This profile asks for all hashed measurements with a signature.
        if request[..4] != [0x11, 0xe0, 0x01, 0xff] || request[36] > 7 {
            return Err(SpdmError::Invalid("GET_MEASUREMENTS request header"));
        }
        let header = c.take(4, "MEASUREMENTS header")?;
        if header != [0x11, 0x60, 0, request[36]] {
            return Err(SpdmError::Invalid("MEASUREMENTS response header/slot"));
        }
        let block_count = c.byte("measurement block count")?;
        if block_count == 0 {
            return Err(SpdmError::Invalid("empty measurement record"));
        }
        let length = c.take(3, "measurement record length")?;
        let record_length = u32::from_le_bytes([length[0], length[1], length[2], 0]);
        let mut record = Cursor(c.take(record_length as usize, "measurement record")?);
        let mut measurements = Vec::with_capacity(block_count as usize);
        let mut seen = [false; 256];
        for _ in 0..block_count {
            let index = record.byte("measurement index")?;
            if index == 0 || index == 255 || seen[index as usize] {
                return Err(SpdmError::Invalid(
                    "reserved or duplicate measurement index",
                ));
            }
            seen[index as usize] = true;
            if record.byte("measurement specification")? != 1 {
                return Err(SpdmError::Invalid("non-DMTF measurement specification"));
            }
            let size = record.le16("measurement size")?;
            let mut measurement = Cursor(record.take(size as usize, "measurement")?);
            let value_type = measurement.byte("DMTF value type")?;
            let value_size = measurement.le16("DMTF value size")?;
            let value = measurement.take(value_size as usize, "DMTF value")?;
            if !measurement.0.is_empty() || value.is_empty() {
                return Err(SpdmError::Invalid("DMTF value length"));
            }
            let raw_bit_stream = value_type & 0x80 != 0;
            if value_type & 0x7f > 4 || (!raw_bit_stream && value.len() != 48) {
                return Err(SpdmError::Invalid("DMTF value type or SHA-384 digest size"));
            }
            measurements.push(Measurement {
                index,
                value_type: value_type & 0x7f,
                raw_bit_stream,
                value,
            });
        }
        if !record.0.is_empty() {
            return Err(SpdmError::Invalid("measurement count/record length"));
        }
        let responder_nonce = c.take(32, "responder nonce")?;
        let opaque_length = c.le16("opaque length")?;
        let opaque_data = c.take(opaque_length as usize, "opaque data")?;
        let signed_length = bytes.len() - c.0.len();
        let signature = c.take(SIGNATURE_SIZE, "P-384 signature")?;
        if !c.0.is_empty() {
            return Err(SpdmError::Invalid("trailing bytes"));
        }
        Ok(Self {
            signed_transcript: &bytes[..signed_length],
            signature,
            request_nonce: &request[4..36],
            responder_nonce,
            measurements,
            opaque_data,
        })
    }

    /// Compare the request nonce, which is covered by the signature. The
    /// response carries an independent responder nonce, not an echo.
    /// This check alone does not authenticate either nonce.
    pub fn check_nonce(&self, expected_nonce: &[u8; 32]) -> Result<(), SpdmError> {
        if self.request_nonce != expected_nonce {
            return Err(SpdmError::NonceMismatch);
        }
        Ok(())
    }

    /// Authenticate the transcript and freshness against the supplied key.
    ///
    /// The caller must authenticate this key via certificate path validation
    /// and revocation policy. Success proves a signature by **this key**, not
    /// that the key belongs to NVIDIA hardware, measurements match RIMs, or
    /// the GPU is in an approved security mode.
    pub fn verify_signature(
        &self,
        expected_nonce: &[u8; 32],
        key: &VerifyingKey,
    ) -> Result<(), SpdmError> {
        self.check_nonce(expected_nonce)?;
        let signature = Signature::from_slice(self.signature).map_err(|_| SpdmError::Signature)?;
        key.verify(self.signed_transcript, &signature)
            .map_err(|_| SpdmError::Signature)
    }

    pub fn request_nonce(&self) -> &[u8] {
        self.request_nonce
    }

    pub fn responder_nonce(&self) -> &[u8] {
        self.responder_nonce
    }

    pub fn measurements(&self) -> &[Measurement<'a>] {
        &self.measurements
    }

    pub fn opaque_data(&self) -> &[u8] {
        self.opaque_data
    }
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize, field: &'static str) -> Result<&'a [u8], SpdmError> {
        let value = self.0.get(..n).ok_or(SpdmError::Truncated(field))?;
        self.0 = &self.0[n..];
        Ok(value)
    }

    fn byte(&mut self, field: &'static str) -> Result<u8, SpdmError> {
        Ok(self.take(1, field)?[0])
    }

    fn le16(&mut self, field: &'static str) -> Result<u16, SpdmError> {
        let b = self.take(2, field)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
}
