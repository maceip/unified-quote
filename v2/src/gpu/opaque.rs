//! Bounded NVIDIA opaque-data decoding. Parsed values are claims only after
//! their enclosing SPDM transcript has passed signature and nonce verification.
//!
//! Wire profile: NVIDIA nvtrust / nv-attestation-sdk-cpp at
//! 11b2bfeb42a1158aa08744603ecb239ccb3d2265, Apache-2.0.
//! Version and scalar rules also follow NVIDIA's 2026-10-06 specification:
//! <https://docs.nvidia.com/attestation/specs/latest/opaque-data-format.html>.

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialMode {
    Mpt,
    Spt,
    Ppcie,
}

#[derive(Debug)]
pub struct Field<'a> {
    pub value_type: u16,
    pub value: &'a [u8],
}

#[derive(Debug)]
pub struct OpaqueData<'a> {
    fields: BTreeMap<u16, Field<'a>>,
    has_header: bool,
    pub major_version: u64,
}

impl<'a> OpaqueData<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= 8192,
            "invalid opaque data length"
        );
        let header = bytes.starts_with(b"NVDAOD");
        let mut pos = if header { 12 } else { 0 };
        if header {
            ensure!(bytes.len() >= 12, "truncated NVDAOD header");
            ensure!(bytes[6..8] == [0, 0], "unsupported NVDAOD profile");
            ensure!(bytes[11] == 0, "nonzero NVDAOD padding");
            // NVIDIA's version contract explicitly makes minor and patch
            // revisions backward-compatible. Only the major selects a profile.
        }
        let mut fields = BTreeMap::new();
        while pos < bytes.len() {
            let size = if header { 6 } else { 4 };
            ensure!(bytes.len() - pos >= size, "truncated opaque TLV");
            let id = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]);
            let value_type = if header {
                u16::from_le_bytes([bytes[pos + 2], bytes[pos + 3]])
            } else {
                0
            };
            let len_pos = pos + size - 2;
            let len = u16::from_le_bytes([bytes[len_pos], bytes[len_pos + 1]]) as usize;
            pos += size;
            // Type zero is a legitimate signed min-SVN reference key in the
            // NVIDIA profile; only 255 is the vendor's INVALID identifier.
            ensure!(
                id != 255 && len <= bytes.len() - pos,
                "invalid opaque field {id}"
            );
            ensure!(fields.len() < 256, "too many opaque fields");
            ensure!(
                fields
                    .insert(
                        id,
                        Field {
                            value_type,
                            value: &bytes[pos..pos + len]
                        }
                    )
                    .is_none(),
                "duplicate opaque field {id}"
            );
            pos += len;
        }
        let mut result = Self {
            fields,
            has_header: header,
            major_version: 0,
        };
        result.major_version = if header {
            bytes[8] as u64
        } else {
            result
                .fields
                .get(&34)
                .map(|f| {
                    ensure!(f.value.len() == 2, "invalid legacy opaque version width");
                    le_integer(f.value)
                })
                .transpose()?
                .unwrap_or(0)
        };
        ensure!(
            result.major_version <= 2,
            "unsupported opaque data major version"
        );
        // NVDAOD's header is authoritative. NVIDIA's published v2 capture
        // retains field 34 with a different representation (00 02); it is not
        // the legacy little-endian version field when a header is present.
        Ok(result)
    }

    pub fn field(&self, id: u16) -> Result<&Field<'a>> {
        self.fields
            .get(&id)
            .with_context(|| format!("missing signed opaque field {id}"))
    }
    pub fn bytes(&self, id: u16) -> Result<&'a [u8]> {
        let field = self.field(id)?;
        if self.has_header {
            ensure!(
                self.major_version == 2,
                "unsupported typed NVIDIA opaque profile"
            );
            // rmDataValueType is part of the signed field's interpretation,
            // not padding. These are the types in NVIDIA's pinned, published
            // sample_nvdaod_transcript.txt. Unknown fields remain available as
            // raw parsed fields, but cannot silently acquire byte/text/scalar
            // semantics. MIN_SVN has its own type-driven accessor below.
            let expected = match id {
                3 | 6 | 34 => 0x86,
                4 | 11 | 14..=19 => 0x82,
                12 => 0x84,
                13 => 0x83,
                20 => 0x01,
                21 | 36 => 0x85,
                37 => 0x87,
                _ => anyhow::bail!("unsupported typed NVIDIA opaque field {id}"),
            };
            ensure!(
                field.value_type == expected,
                "unsupported signed opaque field {id} value type"
            );
        }
        Ok(field.value)
    }
    pub fn integer(&self, id: u16) -> Result<u64> {
        le_integer(self.bytes(id)?)
    }
    /// NVIDIA's RIM minSvn requires rmDataValueType=0x87 (uint16 LE).
    /// Legacy TLVs have no discriminator and cannot satisfy this constraint.
    pub fn svn(&self, id: u16) -> Result<u16> {
        let field = self.field(id)?;
        ensure!(
            self.has_header
                && self.major_version == 2
                && field.value_type == 0x87
                && field.value.len() == 2,
            "unsupported signed SVN field type/width"
        );
        Ok(u16::from_le_bytes(field.value.try_into()?))
    }
    pub fn text(&self, id: u16) -> Result<String> {
        let bytes = self.bytes(id)?;
        ensure!(
            !bytes.is_empty() && bytes.len() <= if id == 3 { 16 } else { 128 },
            "invalid text field {id}"
        );
        let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
        ensure!(
            bytes[end..].iter().all(|b| *b == 0),
            "embedded NUL in text field {id}"
        );
        ensure!(
            end > 0 && bytes[..end].iter().all(|b| b.is_ascii_graphic()),
            "invalid ASCII text field {id}"
        );
        Ok(std::str::from_utf8(&bytes[..end])?.to_owned())
    }
    pub fn vbios_version(&self) -> Result<String> {
        let b = self.bytes(6)?;
        ensure!(
            b.len() == 8 && b[5..] == [0, 0, 0],
            "unsupported VBIOS encoding"
        );
        Ok(format!(
            "{:02X}.{:02X}.{:02X}.{:02X}.{:02X}",
            b[3], b[2], b[1], b[0], b[4]
        ))
    }
    /// LS10 uses an ASCII version, distinct from the GPU packed encoding.
    pub fn switch_vbios_version(&self) -> Result<String> {
        ensure!(
            !self.has_header,
            "unsupported typed NVSwitch opaque profile"
        );
        let value = self.text(6)?;
        let parts: Vec<_> = value.split('.').collect();
        ensure!(
            parts.len() == 5
                && parts
                    .iter()
                    .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit())),
            "invalid signed switch VBIOS version"
        );
        Ok(value.to_ascii_uppercase())
    }
    pub fn mode(&self) -> Result<ConfidentialMode> {
        ensure!(
            self.major_version >= 1,
            "signed confidential mode absent in legacy opaque profile"
        );
        let field = self.field(36)?;
        if self.has_header {
            // Pinned NVIDIA sample_nvdaod_transcript.txt: FEATURE_FLAG carries
            // rmDataValueType 0x85 and a two-byte scalar. Other typed profiles
            // require their own documented interpretation, never coercion.
            ensure!(
                field.value_type == 0x85 && field.value.len() == 2,
                "unsupported typed NVIDIA confidential-mode field"
            );
        } else {
            // Legacy TLV has no type discriminator. The vendor getter defines
            // a little-endian scalar up to eight bytes, without a fixed width.
            ensure!(
                field.value_type == 0 && (1..=8).contains(&field.value.len()),
                "invalid legacy NVIDIA confidential-mode field"
            );
        }
        match self.integer(36)? {
            0 => Ok(ConfidentialMode::Mpt),
            1 => Ok(ConfidentialMode::Spt),
            2 => Ok(ConfidentialMode::Ppcie),
            _ => anyhow::bail!("unknown signed confidential mode"),
        }
    }
    pub fn pdis(&self, id: u16) -> Result<Vec<[u8; 8]>> {
        let b = self.bytes(id)?;
        ensure!(
            !b.is_empty() && b.len() % 8 == 0 && b.len() <= 256,
            "invalid PDI list"
        );
        Ok(b.chunks_exact(8)
            .map(|c| c.try_into().expect("8-byte chunk"))
            .collect())
    }
}

fn le_integer(bytes: &[u8]) -> Result<u64> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= 8,
        "invalid opaque integer length"
    );
    let mut buf = [0u8; 8];
    buf[..bytes.len()].copy_from_slice(bytes);
    Ok(u64::from_le_bytes(buf))
}
