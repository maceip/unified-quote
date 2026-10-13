//! UKI section appraisal for an independently approved systemd-stub v258.
//!
//! Parsing PE headers is not authentication. The verified result contains only
//! section names and contents whose paired measurements match quoted registers
//! and independent policy. It does not authenticate PE headers, Authenticode,
//! or the stub executable. Optional execution policy checks measured command-line
//! composition and approved addon payload digests separately.

use super::{
    hash, BootError, CommandLineProfile, DmVerityCommitment, LogKind, MeasuredCommandLine,
    VerifiedBootLog, EV_IPL, EV_NO_ACTION, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::collections::BTreeMap;
mod execution;
mod selection;
pub use execution::{
    UkiAddonKind, UkiAddonMeasurement, UkiCommandLineBase, UkiExecutionPolicy, UkiMeasuredAppend,
    VerifiedUkiExecution,
};
pub use selection::UkiSelectionPolicy;

pub const MAX_UKI_BYTES: usize = 512 * 1024 * 1024;
const MAX_SECTIONS: usize = 96;
const MAX_TEXT_BYTES: usize = 64 * 1024;

// systemd v258 src/fundamental/uki.h, deliberately versioned. The order is
// independent of PE section-table order. .pcrsig is never a PCR11 input.
const MEASURED_SECTIONS: &[&str] = &[
    ".linux", ".osrel", ".cmdline", ".initrd", ".ucode", ".splash", ".dtb", ".uname", ".sbat",
    ".pcrpkey", ".profile", ".dtbauto", ".hwids", ".efifw",
];

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UkiProfile {
    SystemdStubV258,
}

/// Verifier-owned expectations. Never obtain this policy from the attester.
/// Every measured section present in the candidate must have an exact expected
/// digest here, and every expected section must be present and measured.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UkiPolicy {
    #[serde(default)]
    pub selection: Option<UkiSelectionPolicy>,
    #[serde(default)]
    pub execution: Option<UkiExecutionPolicy>,
    pub profile: UkiProfile,
    /// Index of the .linux name measurement in the original event log.
    pub first_section_event: usize,
    pub algorithm: u16,
    pub expected_sections: BTreeMap<String, String>,
    pub expected_command_line: Option<String>,
    pub expected_verity_root: Option<String>,
}
impl UkiPolicy {
    pub fn validate(&self) -> Result<(), BootError> {
        if let Some(selection) = &self.selection {
            selection.validate()?;
        }
        if let Some(execution) = &self.execution {
            execution.validate(self.algorithm)?;
        }
        let digest_size = hash(self.algorithm, b"")?.len();
        if !self.expected_sections.contains_key(".linux")
            || self.expected_sections.len() > MEASURED_SECTIONS.len()
        {
            return Err(BootError::Uki(
                "policy must include the measured kernel section",
            ));
        }
        for (name, digest) in &self.expected_sections {
            if !MEASURED_SECTIONS.contains(&name.as_str())
                || digest.len() != digest_size * 2
                || !digest.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err(BootError::Uki(
                    "unsupported section or invalid digest in UKI policy",
                ));
            }
        }
        if self
            .expected_command_line
            .as_ref()
            .is_some_and(|s| s.len() > MAX_TEXT_BYTES)
            || ((self.expected_command_line.is_some() || self.expected_verity_root.is_some())
                && !self.expected_sections.contains_key(".cmdline"))
        {
            return Err(BootError::Uki(
                "command-line policy requires bounded measured .cmdline",
            ));
        }
        if let Some(root) = &self.expected_verity_root {
            if !matches!(root.len(), 64 | 96 | 128) || !root.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err(BootError::Uki("invalid expected verity digest"));
            }
        }
        Ok(())
    }
}

/// PE fields are untrusted descriptions until paired measurements are checked.
#[derive(Debug, Serialize)]
pub struct UnverifiedPeSection {
    pub name: String,
    pub virtual_size: usize,
    pub virtual_address: usize,
    pub raw_offset: usize,
    pub raw_size: usize,
}

/// Bounded, borrowed PE image. There is no public conversion to verified claims.
#[derive(Debug)]
pub struct UnverifiedUki<'a> {
    bytes: &'a [u8],
    sections: Vec<UnverifiedPeSection>,
}

fn field(bytes: &[u8], start: usize, len: usize) -> Result<&[u8], BootError> {
    let end = start
        .checked_add(len)
        .ok_or(BootError::Limit("PE offset"))?;
    bytes
        .get(start..end)
        .ok_or(BootError::Uki("truncated PE field"))
}
fn u16_at(bytes: &[u8], start: usize) -> Result<u16, BootError> {
    Ok(u16::from_le_bytes(
        field(bytes, start, 2)?.try_into().unwrap(),
    ))
}
fn u32_at(bytes: &[u8], start: usize) -> Result<usize, BootError> {
    Ok(u32::from_le_bytes(field(bytes, start, 4)?.try_into().unwrap()) as usize)
}
fn range_end(start: usize, length: usize) -> Result<usize, BootError> {
    start
        .checked_add(length)
        .ok_or(BootError::Limit("PE range"))
}
fn disjoint(mut ranges: Vec<(usize, usize)>, floor: usize) -> Result<(), BootError> {
    ranges.sort_unstable();
    let mut end = floor;
    for (start, stop) in ranges {
        if start < end {
            return Err(BootError::Uki("overlapping PE sections or headers"));
        }
        end = stop;
    }
    Ok(())
}

impl<'a> UnverifiedUki<'a> {
    /// Parse PE32/PE32+ UEFI applications without executing code or consulting
    /// external parsers. File/virtual ranges and all
    /// selected bytes are checked before any policy or measurement processing.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, BootError> {
        Self::parse_pe(bytes, true)
    }
    pub fn parse_addon(bytes: &'a [u8]) -> Result<Self, BootError> {
        let image = Self::parse_pe(bytes, false)?;
        if image.sections.iter().any(|s| s.name == ".linux") {
            return Err(BootError::Uki("addon contains kernel section"));
        }
        Ok(image)
    }
    pub(super) fn parse_pe(bytes: &'a [u8], require_kernel: bool) -> Result<Self, BootError> {
        if bytes.len() > MAX_UKI_BYTES {
            return Err(BootError::Limit("UKI file bytes"));
        }
        if field(bytes, 0, 2)? != b"MZ" {
            return Err(BootError::Uki("missing DOS image header"));
        }
        let pe = u32_at(bytes, 0x3c)?;
        if pe < 64 || field(bytes, pe, 24)?[..4] != *b"PE\0\0" {
            return Err(BootError::Uki("invalid PE image header"));
        }
        let count = u16_at(bytes, pe + 6)? as usize;
        if count == 0 || count > MAX_SECTIONS {
            return Err(BootError::Limit("PE section count"));
        }
        let characteristics = u16_at(bytes, pe + 22)?;
        if characteristics & 2 == 0 || characteristics & 0x2000 != 0 {
            return Err(BootError::Uki("PE image is not a standalone executable"));
        }
        let optional_len = u16_at(bytes, pe + 20)? as usize;
        let optional = field(bytes, pe + 24, optional_len)?;
        let directory_offset = match u16_at(optional, 0)? {
            0x10b => 96,
            0x20b => 112,
            _ => return Err(BootError::Uki("unsupported PE optional-header format")),
        };
        if u16_at(optional, 68)? != 10 {
            return Err(BootError::Uki("PE subsystem is not an EFI application"));
        }
        let directory_count = u32_at(optional, directory_offset - 4)?;
        if directory_count > 16 {
            return Err(BootError::Uki("unsupported PE data-directory count"));
        }
        field(optional, directory_offset, directory_count * 8)?;
        let section_alignment = u32_at(optional, 32)?;
        let file_alignment = u32_at(optional, 36)?;
        if !section_alignment.is_power_of_two()
            || !file_alignment.is_power_of_two()
            || section_alignment < file_alignment
            || !(512..=65_536).contains(&file_alignment)
            || (section_alignment < 4096 && section_alignment != file_alignment)
        {
            return Err(BootError::Uki("unsupported PE section/file alignment"));
        }
        let image_size = u32_at(optional, 56)?;
        let headers_size = u32_at(optional, 60)?;
        if image_size == 0
            || image_size > MAX_UKI_BYTES
            || image_size % section_alignment != 0
            || headers_size == 0
            || headers_size > bytes.len()
            || headers_size > image_size
            || headers_size % file_alignment != 0
        {
            return Err(BootError::Uki("invalid PE image/header size"));
        }
        let table_start = range_end(pe + 24, optional_len)?;
        let table = field(bytes, table_start, count * 40)?;
        if range_end(table_start, table.len())? > headers_size {
            return Err(BootError::Uki("PE section table outside image headers"));
        }
        let mut sections = Vec::with_capacity(count);
        let mut raw_ranges = Vec::new();
        let mut memory_ranges = Vec::new();
        for entry in table.chunks_exact(40) {
            let name_len = entry[..8].iter().position(|b| *b == 0).unwrap_or(8);
            if name_len == 0
                || entry[0] == b'/'
                || !entry[..name_len].iter().all(|b| (0x21..=0x7e).contains(b))
                || entry[name_len..8].iter().any(|b| *b != 0)
            {
                return Err(BootError::Uki("invalid PE section name"));
            }
            let name = std::str::from_utf8(&entry[..name_len]).unwrap().to_owned();
            let virtual_size = u32_at(entry, 8)?;
            let virtual_address = u32_at(entry, 12)?;
            let raw_size = u32_at(entry, 16)?;
            let raw_offset = u32_at(entry, 20)?;
            let loaded_extent = virtual_size.max(raw_size);
            if virtual_size > MAX_UKI_BYTES
                || loaded_extent > image_size
                || virtual_address % section_alignment != 0
                || range_end(virtual_address, loaded_extent)? > image_size
            {
                return Err(BootError::Uki("invalid PE virtual section range"));
            }
            if loaded_extent > 0 {
                memory_ranges.push((virtual_address, range_end(virtual_address, loaded_extent)?));
            }
            if raw_size > 0 {
                if raw_offset % file_alignment != 0 || raw_size % file_alignment != 0 {
                    return Err(BootError::Uki("unaligned PE raw section"));
                }
                field(bytes, raw_offset, raw_size)?;
                raw_ranges.push((raw_offset, range_end(raw_offset, raw_size)?));
            } else if raw_offset != 0 {
                return Err(BootError::Uki("uninitialized PE section has raw offset"));
            }
            if MEASURED_SECTIONS.contains(&name.as_str()) && virtual_size == 0 {
                return Err(BootError::Uki("empty measured UKI section"));
            }
            // COFF relocations/line numbers belong to object files, not these
            // executable image sections. PE base relocations are a directory.
            if entry[24..36].iter().any(|b| *b != 0) {
                return Err(BootError::Uki(
                    "COFF object section metadata is unsupported",
                ));
            }
            sections.push(UnverifiedPeSection {
                name,
                virtual_size,
                virtual_address,
                raw_offset,
                raw_size,
            });
        }
        disjoint(memory_ranges, headers_size)?;
        // The security directory addresses file bytes, unlike other PE RVAs.
        // Validate its range but do not parse or claim its signature is valid.
        if directory_count > 4 {
            let cert_offset = u32_at(optional, directory_offset + 4 * 8)?;
            let cert_size = u32_at(optional, directory_offset + 4 * 8 + 4)?;
            if (cert_offset == 0) != (cert_size == 0) || cert_offset % 8 != 0 {
                return Err(BootError::Uki("invalid PE certificate directory"));
            }
            if cert_size > 0 {
                field(bytes, cert_offset, cert_size)?;
                raw_ranges.push((cert_offset, range_end(cert_offset, cert_size)?));
            }
        }
        disjoint(raw_ranges, headers_size)?;
        if require_kernel && !sections.iter().any(|s| s.name == ".linux") {
            return Err(BootError::Uki("UKI has no .linux section"));
        }
        Ok(Self { bytes, sections })
    }

    pub fn unverified_sections(&self) -> &[UnverifiedPeSection] {
        &self.sections
    }

    fn section(&self, name: &str) -> Option<&UnverifiedPeSection> {
        self.sections.iter().find(|s| s.name == name)
    }

    fn file_content(&self, section: &UnverifiedPeSection) -> &[u8] {
        &self.bytes
            [section.raw_offset..section.raw_offset + section.raw_size.min(section.virtual_size)]
    }

    fn section_digest(
        &self,
        section: &UnverifiedPeSection,
        algorithm: u16,
    ) -> Result<Vec<u8>, BootError> {
        let bytes = self.file_content(section);
        let zero_count = section.virtual_size - bytes.len();
        match algorithm {
            TPM_ALG_SHA256 => Ok(hash_loaded::<Sha256>(bytes, zero_count)),
            TPM_ALG_SHA384 => Ok(hash_loaded::<Sha384>(bytes, zero_count)),
            TPM_ALG_SHA512 => Ok(hash_loaded::<Sha512>(bytes, zero_count)),
            _ => Err(BootError::UnsupportedAlgorithm(algorithm)),
        }
    }

    fn text(&self, name: &str) -> Result<Option<String>, BootError> {
        let Some(section) = self.section(name) else {
            return Ok(None);
        };
        Ok(Some(self.section_text(section)?))
    }

    fn section_text(&self, section: &UnverifiedPeSection) -> Result<String, BootError> {
        if section.virtual_size > MAX_TEXT_BYTES {
            return Err(BootError::Limit("UKI text section bytes"));
        }
        let content = self.file_content(section);
        let end = content
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(content.len());
        // Do not hide nonzero bytes after the string seen by systemd's bounded
        // string conversion. VirtualSize zero fill is an allowed terminator.
        if content[end..].iter().any(|b| *b != 0) {
            return Err(BootError::Uki("nonzero bytes after UKI text terminator"));
        }
        let text = std::str::from_utf8(&content[..end])
            .map_err(|_| BootError::Uki("invalid UTF-8 UKI metadata"))?;
        if text
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
        {
            return Err(BootError::Uki(
                "unsupported control character in UKI metadata",
            ));
        }
        Ok(text.to_owned())
    }
}

fn hash_loaded<D: Digest>(bytes: &[u8], mut zeros: usize) -> Vec<u8> {
    let mut digest = D::new();
    digest.update(bytes);
    const ZEROES: [u8; 4096] = [0; 4096];
    while zeros > 0 {
        let count = zeros.min(ZEROES.len());
        digest.update(&ZEROES[..count]);
        zeros -= count;
    }
    digest.finalize().to_vec()
}

#[derive(Debug, Serialize)]
pub struct VerifiedUkiSection {
    name: String,
    name_event_index: usize,
    data_event_index: usize,
    measured_size: usize,
    digest_hex: String,
}
impl VerifiedUkiSection {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn digest_hex(&self) -> &str {
        &self.digest_hex
    }
    pub fn measured_size(&self) -> usize {
        self.measured_size
    }
    pub fn event_indices(&self) -> (usize, usize) {
        (self.name_event_index, self.data_event_index)
    }
}

/// Only embedded section content is authenticated. In particular, os_release
/// is the measured text, not a shell-evaluated set of trusted host properties.
#[derive(Debug, Serialize)]
pub struct VerifiedUki {
    profile: UkiProfile,
    algorithm: u16,
    sections: Vec<VerifiedUkiSection>,
    embedded_command_line: Option<String>,
    os_release: Option<String>,
    kernel_release: Option<String>,
    dm_verity: Option<DmVerityCommitment>,
    authenticated_profile_index: Option<u32>,
    execution: Option<VerifiedUkiExecution>,
}
impl VerifiedUki {
    pub fn authenticated_profile_index(&self) -> Option<u32> {
        self.authenticated_profile_index
    }
    pub fn execution(&self) -> Option<&VerifiedUkiExecution> {
        self.execution.as_ref()
    }
    pub fn sections(&self) -> &[VerifiedUkiSection] {
        &self.sections
    }
    pub fn embedded_command_line(&self) -> Option<&str> {
        self.embedded_command_line.as_deref()
    }
    pub fn os_release(&self) -> Option<&str> {
        self.os_release.as_deref()
    }
    pub fn kernel_release(&self) -> Option<&str> {
        self.kernel_release.as_deref()
    }
    pub fn dm_verity(&self) -> Option<&DmVerityCommitment> {
        self.dm_verity.as_ref()
    }
}

impl VerifiedBootLog {
    pub fn verify_uki(&self, bytes: &[u8], policy: &UkiPolicy) -> Result<VerifiedUki, BootError> {
        policy.validate()?;
        let uki = UnverifiedUki::parse(bytes)?;
        let digest_size = hash(policy.algorithm, b"")?.len();
        let selected = uki.selected(policy.selection.as_ref())?;
        let measured: Vec<_> = MEASURED_SECTIONS
            .iter()
            .filter_map(|name| selected.get(name).copied())
            .collect();
        if policy.expected_sections.len() != measured.len()
            || !measured
                .iter()
                .all(|s| policy.expected_sections.contains_key(&s.name))
        {
            return Err(BootError::Uki(
                "policy must approve exactly every measured UKI section",
            ));
        }
        let register = match self.log.kind {
            LogKind::Tpm2 => 11,
            LogKind::TdxCcel => 3,
        };
        // Only order within the authenticated register is committed by replay.
        // Other registers can be interleaved without changing the evidence.
        let mut stream = self
            .log
            .events
            .iter()
            .enumerate()
            .skip(policy.first_section_event)
            .filter(|(_, e)| e.register_index == register && e.reported_event_type != EV_NO_ACTION);
        let mut sections = Vec::new();
        for section in measured {
            let (name_index, name_event) = stream
                .next()
                .ok_or(BootError::Uki("missing UKI name measurement"))?;
            if sections.is_empty() && name_index != policy.first_section_event {
                return Err(BootError::Uki(
                    "first UKI event is outside the selected register",
                ));
            }
            let (data_index, data_event) = stream
                .next()
                .ok_or(BootError::Uki("missing UKI data measurement"))?;
            if name_event.reported_event_type != EV_IPL || data_event.reported_event_type != EV_IPL
            {
                return Err(BootError::Uki("UKI measurements are not EV_IPL pairs"));
            }
            let mut name_preimage = section.name.as_bytes().to_vec();
            name_preimage.push(0);
            self.verify_measured_bytes(name_index, policy.algorithm, &name_preimage)?;
            let digest = uki.section_digest(section, policy.algorithm)?;
            self.verify_expected_digest(data_index, policy.algorithm, &digest)?;
            let expected = hex::decode(&policy.expected_sections[&section.name])
                .map_err(|_| BootError::Uki("invalid expected UKI section digest"))?;
            if expected.len() != digest_size || expected != digest {
                return Err(BootError::Uki(
                    "UKI section differs from independent policy",
                ));
            }
            sections.push(VerifiedUkiSection {
                name: section.name.clone(),
                name_event_index: name_index,
                data_event_index: data_index,
                measured_size: section.virtual_size,
                digest_hex: hex::encode(digest),
            });
        }
        // Do not accept a prefix when another recognized section pair follows.
        // Descriptions remain ignored: check the committed name preimages.
        if let Some((index, _)) = stream.next() {
            let next = self.authenticated_digest(index, policy.algorithm)?;
            for name in MEASURED_SECTIONS {
                let preimage = format!("{name}\0");
                if next == hash(policy.algorithm, preimage.as_bytes())? {
                    return Err(BootError::Uki(
                        "unaccounted UKI section measurement follows candidate",
                    ));
                }
            }
        }
        let embedded_command_line = uki.selected_text(&selected, ".cmdline")?;
        if let Some(expected) = &policy.expected_command_line {
            if expected.len() > MAX_TEXT_BYTES
                || embedded_command_line.as_deref() != Some(expected.as_str())
            {
                return Err(BootError::Uki(
                    "embedded command line differs from independent policy",
                ));
            }
        }
        let dm_verity = if let Some(expected) = &policy.expected_verity_root {
            let section = sections
                .iter()
                .find(|s| s.name == ".cmdline")
                .ok_or(BootError::Uki("verity policy requires measured .cmdline"))?;
            let root = hex::decode(expected)
                .map_err(|_| BootError::Uki("invalid expected verity digest"))?;
            Some(
                MeasuredCommandLine {
                    event_index: section.data_event_index,
                    algorithm: policy.algorithm,
                    profile: CommandLineProfile::SystemdUkiEmbedded,
                    command_line: embedded_command_line
                        .clone()
                        .ok_or(BootError::Uki("missing embedded command line"))?,
                }
                .verify_dm_verity(&root)?,
            )
        } else {
            None
        };
        let authenticated_profile_index = if let Some(selection) = &policy.selection {
            self.verify_uki_profile_number(selection, policy.algorithm, policy.first_section_event)?
        } else {
            None
        };
        let mut result = VerifiedUki {
            profile: policy.profile,
            algorithm: policy.algorithm,
            sections,
            embedded_command_line,
            os_release: uki.selected_text(&selected, ".osrel")?,
            kernel_release: uki.selected_text(&selected, ".uname")?,
            dm_verity,
            authenticated_profile_index,
            execution: None,
        };
        if let Some(execution) = &policy.execution {
            result.execution = Some(self.verify_uki_execution(&result, execution)?);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
