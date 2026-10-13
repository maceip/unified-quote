//! systemd-stub v258 base/profile overlay and device-specific section selection.
use super::*;

/// Independent verifier configuration, never host-reported device metadata.
/// Selectors approve which compatible/FWID payload may be used. Their selection
/// is confirmed by the section-pair measurement, not by trusting SMBIOS files.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UkiSelectionPolicy {
    pub profile_index: u32,
    /// TPM PCR12 tagged profile-number event for a nondefault profile. v258's
    /// tagged-event helper does not implement EFI_CC; TDX authenticates selected
    /// content, not this numeric loader parameter.
    pub profile_event: Option<usize>,
    pub expected_compatible: Option<String>,
    pub expected_firmware_id: Option<String>,
}
impl UkiSelectionPolicy {
    pub fn validate(&self) -> Result<(), BootError> {
        if self.profile_index > 95 || (self.profile_index == 0 && self.profile_event.is_some()) {
            return Err(BootError::Uki(
                "invalid profile number or profile-zero event",
            ));
        }
        for s in [&self.expected_compatible, &self.expected_firmware_id]
            .into_iter()
            .flatten()
        {
            if s.is_empty() || s.len() > 4096 || !s.bytes().all(|c| (0x20..0x7f).contains(&c)) {
                return Err(BootError::Uki("invalid independent device selector"));
            }
        }
        Ok(())
    }
}

impl<'a> UnverifiedUki<'a> {
    pub(super) fn selected(
        &self,
        policy: Option<&UkiSelectionPolicy>,
    ) -> Result<BTreeMap<&str, &UnverifiedPeSection>, BootError> {
        let default = UkiSelectionPolicy::default();
        let policy = policy.unwrap_or(&default);
        policy.validate()?;
        let starts: Vec<_> = self
            .sections
            .iter()
            .enumerate()
            .filter(|(_, s)| s.name == ".profile")
            .map(|(i, _)| i)
            .collect();
        if policy.profile_index as usize >= starts.len()
            && !(starts.is_empty() && policy.profile_index == 0)
        {
            return Err(BootError::Uki("requested UKI profile is absent"));
        }
        let mut chosen = BTreeMap::new();
        self.select_range(
            &self.sections[..starts.first().copied().unwrap_or(self.sections.len())],
            policy,
            &mut chosen,
        )?;
        if let Some(&start) = starts.get(policy.profile_index as usize) {
            let end = starts
                .get(policy.profile_index as usize + 1)
                .copied()
                .unwrap_or(self.sections.len());
            self.select_range(&self.sections[start..end], policy, &mut chosen)?;
        }
        if !chosen.contains_key(".linux") {
            return Err(BootError::Uki("selected profile lacks a kernel"));
        }
        Ok(chosen)
    }
    fn select_range<'b>(
        &'b self,
        range: &'b [UnverifiedPeSection],
        policy: &UkiSelectionPolicy,
        chosen: &mut BTreeMap<&'b str, &'b UnverifiedPeSection>,
    ) -> Result<(), BootError> {
        for name in MEASURED_SECTIONS {
            for section in range.iter().filter(|s| s.name == *name) {
                if *name == ".dtbauto" {
                    let wanted = policy.expected_compatible.as_deref().ok_or(BootError::Uki(
                        ".dtbauto requires independent compatible selector",
                    ))?;
                    if fdt_first_compatible(self.file_content(section))? != wanted {
                        continue;
                    }
                } else if *name == ".efifw" {
                    let wanted = policy
                        .expected_firmware_id
                        .as_deref()
                        .ok_or(BootError::Uki(
                            ".efifw requires independent firmware selector",
                        ))?;
                    if efi_firmware_id(self.file_content(section))? != wanted {
                        continue;
                    }
                }
                chosen.insert(section.name.as_str(), section);
                break; // first matching section within this profile wins
            }
        }
        Ok(())
    }

    pub(super) fn selected_text(
        &self,
        sections: &BTreeMap<&str, &UnverifiedPeSection>,
        name: &str,
    ) -> Result<Option<String>, BootError> {
        sections.get(name).map(|s| self.section_text(s)).transpose()
    }
}

// The v258 matcher compares ONLY the first compatible string. This bounded FDT
// parser additionally validates structure/string ranges and root-property scope.
fn be32(data: &[u8], offset: usize) -> Result<usize, BootError> {
    Ok(u32::from_be_bytes(field(data, offset, 4)?.try_into().unwrap()) as usize)
}
pub(super) fn fdt_first_compatible(data: &[u8]) -> Result<&str, BootError> {
    if data.len() < 40
        || be32(data, 0)? != 0xd00dfeed
        || be32(data, 20)? != 17
        || be32(data, 24)? > 17
    {
        return Err(BootError::Uki("invalid FDT v17 header"));
    }
    let total = be32(data, 4)?;
    if total > data.len() || total > 32 * 1024 * 1024 {
        return Err(BootError::Uki("FDT total size outside section"));
    }
    let data = &data[..total];
    let structure_offset = be32(data, 8)?;
    let strings_offset = be32(data, 12)?;
    let structure_size = be32(data, 36)?;
    let strings_size = be32(data, 32)?;
    if structure_offset < 40
        || structure_offset % 4 != 0
        || structure_size % 4 != 0
        || strings_offset < range_end(structure_offset, structure_size)?
    {
        return Err(BootError::Uki("overlapping or misaligned FDT blocks"));
    }
    let structure = field(data, structure_offset, structure_size)?;
    let strings = field(data, strings_offset, strings_size)?;
    let mut at = 0;
    let mut depth = 0usize;
    let mut compatible = None;
    let mut ended = false;
    while at < structure.len() {
        let token = be32(structure, at)?;
        at += 4;
        match token {
            1 => {
                let remaining = &structure[at..];
                let n = remaining
                    .iter()
                    .position(|v| *v == 0)
                    .ok_or(BootError::Uki("unterminated FDT node"))?;
                if depth == 0 && (n != 0 || compatible.is_some()) {
                    return Err(BootError::Uki("invalid FDT root"));
                }
                at = range_end(at, (n + 4) & !3)?;
                if at > structure.len() {
                    return Err(BootError::Uki("FDT node exceeds block"));
                }
                depth += 1;
                if depth > 128 {
                    return Err(BootError::Limit("FDT nesting"));
                }
            }
            2 => {
                depth = depth
                    .checked_sub(1)
                    .ok_or(BootError::Uki("unbalanced FDT node"))?;
            }
            3 => {
                if depth == 0 {
                    return Err(BootError::Uki("FDT property outside node"));
                }
                let length = be32(structure, at)?;
                let name_offset = be32(structure, at + 4)?;
                at += 8;
                let value = field(structure, at, length)?;
                let names = strings
                    .get(name_offset..)
                    .ok_or(BootError::Uki("FDT property name outside strings"))?;
                let n = names
                    .iter()
                    .position(|v| *v == 0)
                    .ok_or(BootError::Uki("unterminated FDT property name"))?;
                if depth == 1 && &names[..n] == b"compatible" {
                    if compatible.is_some() || value.last() != Some(&0) {
                        return Err(BootError::Uki(
                            "duplicate or unterminated compatible property",
                        ));
                    }
                    let end = value.iter().position(|v| *v == 0).unwrap();
                    if end == 0 {
                        return Err(BootError::Uki("empty FDT compatible"));
                    }
                    compatible = Some(
                        std::str::from_utf8(&value[..end])
                            .map_err(|_| BootError::Uki("invalid FDT compatible"))?,
                    );
                }
                at = range_end(
                    at,
                    length
                        .checked_add(3)
                        .ok_or(BootError::Limit("FDT property"))?
                        & !3,
                )?;
                if at > structure.len() {
                    return Err(BootError::Uki("FDT property exceeds structure"));
                }
            }
            4 => {}
            9 => {
                if depth != 0 {
                    return Err(BootError::Uki("unclosed FDT node"));
                }
                ended = true;
                break;
            }
            _ => return Err(BootError::Uki("unknown FDT structure token")),
        }
    }
    if !ended {
        return Err(BootError::Uki("missing FDT end token"));
    }
    compatible.ok_or(BootError::Uki("FDT lacks root compatible property"))
}

pub(super) fn efi_firmware_id(data: &[u8]) -> Result<&str, BootError> {
    if data.len() < 16 || u32_at(data, 0)? != 0xfeeddead {
        return Err(BootError::Uki("invalid EFI firmware blob header"));
    }
    let header = u32_at(data, 4)?;
    let id_size = u32_at(data, 8)?;
    let payload = u32_at(data, 12)?;
    if header < 16 || id_size == 0 {
        return Err(BootError::Uki("invalid EFI firmware lengths"));
    }
    let id = field(data, header, id_size)?;
    field(data, range_end(header, id_size)?, payload)?;
    if id.last() != Some(&0) || id[..id.len() - 1].contains(&0) {
        return Err(BootError::Uki("invalid EFI firmware identifier terminator"));
    }
    std::str::from_utf8(&id[..id.len() - 1])
        .map_err(|_| BootError::Uki("invalid EFI firmware identifier"))
}

impl VerifiedBootLog {
    pub(super) fn verify_uki_profile_number(
        &self,
        policy: &UkiSelectionPolicy,
        algorithm: u16,
        first_section_event: usize,
    ) -> Result<Option<u32>, BootError> {
        let Some(index) = policy.profile_event else {
            return Ok(None);
        };
        if self.log.kind != LogKind::Tpm2 {
            return Err(BootError::Uki(
                "v258 profile-number tagged events require TPM coverage",
            ));
        }
        let event = self
            .log
            .events
            .get(index)
            .ok_or(BootError::UnauthenticatedEvent(index))?;
        if index >= first_section_event
            || event.register_index != 12
            || event.reported_event_type != 6
        {
            return Err(BootError::Uki(
                "profile measurement must precede UKI sections in TPM PCR12",
            ));
        }
        let text: Vec<_> = policy
            .profile_index
            .to_string()
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect();
        self.verify_measured_bytes(index, algorithm, &text)?;
        Ok(Some(policy.profile_index))
    }
}
