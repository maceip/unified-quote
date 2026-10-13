//! Reconstruct the v258 command line from authenticated measurements and exact
//! policy, and account for every selected configuration-register measurement.
use super::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum UkiCommandLineBase {
    Embedded,
    LoadOptions {
        event_index: usize,
        expected_text: String,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UkiMeasuredAppend {
    pub event_index: usize,
    /// For addons these are independently approved, directory-ordered fragments
    /// (global before per-image); the stub measures their one joined string.
    pub expected_fragments: Vec<String>,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UkiAddonKind {
    DeviceTree,
    Microcode,
    Initrd,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UkiAddonMeasurement {
    pub kind: UkiAddonKind,
    pub event_index: usize,
    pub expected_digest_hex: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UkiExecutionPolicy {
    pub base: UkiCommandLineBase,
    pub addons: Option<UkiMeasuredAppend>,
    pub smbios: Option<UkiMeasuredAppend>,
    pub binary_addons: Vec<UkiAddonMeasurement>,
    pub expected_effective_command_line: String,
    pub expected_verity_root: Option<String>,
    /// Explicit independently approved measurements from other components in
    /// the same register (e.g. earlier loader measurements). No implicit skip.
    pub other_config_events: BTreeMap<usize, String>,
}
impl UkiExecutionPolicy {
    pub fn validate(&self, algorithm: u16) -> Result<(), BootError> {
        let size = hash(algorithm, b"")?.len() * 2;
        if self.expected_effective_command_line.len() > MAX_TEXT_BYTES
            || self.binary_addons.len() > 96
            || self.other_config_events.len() > 65536
        {
            return Err(BootError::Limit("UKI execution policy"));
        }
        if let UkiCommandLineBase::LoadOptions { expected_text, .. } = &self.base {
            canonical(expected_text)?;
        }
        for append in [&self.addons, &self.smbios].into_iter().flatten() {
            if append.expected_fragments.len() > 96 {
                return Err(BootError::Limit("UKI addon fragments"));
            }
            append_text(append)?;
        }
        if self
            .smbios
            .as_ref()
            .is_some_and(|p| p.expected_fragments.len() != 1)
        {
            return Err(BootError::Uki("SMBIOS appends exactly one approved string"));
        }
        for digest in self
            .binary_addons
            .iter()
            .map(|p| &p.expected_digest_hex)
            .chain(self.other_config_events.values())
        {
            if digest.len() != size || !digest.bytes().all(|c| c.is_ascii_hexdigit()) {
                return Err(BootError::Uki("invalid configuration measurement digest"));
            }
        }
        if self.expected_verity_root.as_ref().is_some_and(|s| {
            !matches!(s.len(), 64 | 96 | 128) || !s.bytes().all(|c| c.is_ascii_hexdigit())
        }) {
            return Err(BootError::Uki("invalid execution verity root"));
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct VerifiedUkiExecution {
    effective_command_line: String,
    configuration_event_indices: Vec<usize>,
    binary_addons: Vec<VerifiedAddonMeasurement>,
    dm_verity: Option<DmVerityCommitment>,
}
#[derive(Debug, Serialize)]
struct VerifiedAddonMeasurement {
    kind: UkiAddonKind,
    event_index: usize,
    digest_hex: String,
}
impl VerifiedUkiExecution {
    pub fn effective_command_line(&self) -> &str {
        &self.effective_command_line
    }
    pub fn dm_verity(&self) -> Option<&DmVerityCommitment> {
        self.dm_verity.as_ref()
    }
}

// v258 util.c mangle_stub_cmdline operates on UTF16 code units: trim ASCII
// control/space/DEL at the ends, replace each inner such character with one
// space, preserving repeated spaces and every other character.
pub(super) fn mangle(text: &str) -> String {
    text.trim_matches(|c: char| c <= '\u{20}' || c == '\u{7f}')
        .chars()
        .map(|c| {
            if c <= '\u{20}' || c == '\u{7f}' {
                ' '
            } else {
                c
            }
        })
        .collect()
}
fn canonical(text: &str) -> Result<(), BootError> {
    if text.len() > MAX_TEXT_BYTES || text.contains('\0') || text.is_empty() || mangle(text) != text
    {
        return Err(BootError::Uki(
            "noncanonical or oversized measured load options",
        ));
    }
    Ok(())
}
fn append_text(policy: &UkiMeasuredAppend) -> Result<String, BootError> {
    if policy.expected_fragments.is_empty()
        || policy
            .expected_fragments
            .iter()
            .any(|s| s.len() > MAX_TEXT_BYTES || s.contains('\0'))
    {
        return Err(BootError::Uki(
            "missing or oversized addon command-line fragment",
        ));
    }
    let mut out = String::new();
    for text in &policy.expected_fragments {
        let text = mangle(text);
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(&text);
        if out.len() > MAX_TEXT_BYTES {
            return Err(BootError::Limit("joined addon command line"));
        }
    }
    let out = mangle(&out);
    canonical(&out)?;
    Ok(out)
}

impl VerifiedBootLog {
    pub fn verify_uki_execution(
        &self,
        uki: &VerifiedUki,
        policy: &UkiExecutionPolicy,
    ) -> Result<VerifiedUkiExecution, BootError> {
        policy.validate(uki.algorithm)?;
        let register = if self.log.kind == LogKind::Tpm2 {
            12
        } else {
            3
        };
        let mut covered = std::collections::BTreeSet::new();
        let last_section = uki
            .sections
            .iter()
            .map(|s| s.data_event_index)
            .max()
            .ok_or(BootError::Uki("missing authenticated UKI sections"))?;
        for section in &uki.sections {
            // Bind a supplied typed UKI result back to this exact verified log.
            self.verify_measured_bytes(
                section.name_event_index,
                uki.algorithm,
                format!("{}\0", section.name).as_bytes(),
            )?;
            self.verify_expected_digest(
                section.data_event_index,
                uki.algorithm,
                &hex::decode(&section.digest_hex)
                    .map_err(|_| BootError::Uki("invalid verified section digest"))?,
            )?;
            if self.log.kind == LogKind::TdxCcel {
                covered.insert(section.name_event_index);
                covered.insert(section.data_event_index);
            }
        }
        let mut last = last_section;
        let mut record_text = |index: usize, text: &str| -> Result<(), BootError> {
            canonical(text)?;
            let event = self
                .log
                .events
                .get(index)
                .ok_or(BootError::UnauthenticatedEvent(index))?;
            if index <= last
                || event.register_index != register
                || event.reported_event_type != EV_IPL
                || !covered.insert(index)
            {
                return Err(BootError::Uki(
                    "load-option measurements have invalid order, coverage, or register",
                ));
            }
            let bytes: Vec<_> = text
                .encode_utf16()
                .chain([0])
                .flat_map(u16::to_le_bytes)
                .collect();
            self.verify_measured_bytes(index, uki.algorithm, &bytes)?;
            last = index;
            Ok(())
        };
        let mut line = match &policy.base {
            UkiCommandLineBase::Embedded => {
                mangle(uki.embedded_command_line.as_deref().unwrap_or(""))
            }
            UkiCommandLineBase::LoadOptions {
                event_index,
                expected_text,
            } => {
                record_text(*event_index, expected_text)?;
                expected_text.clone()
            }
        };
        for (is_smbios, append) in [(false, &policy.addons), (true, &policy.smbios)] {
            if let Some(append) = append {
                if is_smbios && self.log.kind == LogKind::TdxCcel {
                    return Err(BootError::Uki(
                        "v258 ignores SMBIOS command lines in confidential VMs",
                    ));
                }
                let text = append_text(append)?;
                record_text(append.event_index, &text)?;
                if !line.is_empty() {
                    line.push(' ');
                }
                line.push_str(&text);
            }
        }
        let mut binary_addons = Vec::new();
        let mut stage = 0;
        for addon in &policy.binary_addons {
            if self.log.kind != LogKind::Tpm2 {
                return Err(BootError::Uki(
                    "v258 binary addon measurements require TPM coverage",
                ));
            }
            let next_stage = match addon.kind {
                UkiAddonKind::DeviceTree => 0,
                UkiAddonKind::Microcode => 1,
                UkiAddonKind::Initrd => 2,
            };
            let event = self
                .log
                .events
                .get(addon.event_index)
                .ok_or(BootError::UnauthenticatedEvent(addon.event_index))?;
            if next_stage < stage
                || addon.event_index <= last
                || event.register_index != 12
                || event.reported_event_type != 6
                || !covered.insert(addon.event_index)
            {
                return Err(BootError::Uki(
                    "invalid addon measurement order or register",
                ));
            }
            let digest = hex::decode(&addon.expected_digest_hex)
                .map_err(|_| BootError::Uki("invalid addon digest"))?;
            self.verify_expected_digest(addon.event_index, uki.algorithm, &digest)?;
            binary_addons.push(VerifiedAddonMeasurement {
                kind: addon.kind,
                event_index: addon.event_index,
                digest_hex: hex::encode(digest),
            });
            stage = next_stage;
            last = addon.event_index;
        }
        for (&index, digest) in &policy.other_config_events {
            let event = self
                .log
                .events
                .get(index)
                .ok_or(BootError::UnauthenticatedEvent(index))?;
            if event.register_index != register || !covered.insert(index) {
                return Err(BootError::Uki(
                    "duplicate or wrong-register additional configuration event",
                ));
            }
            self.verify_expected_digest(
                index,
                uki.algorithm,
                &hex::decode(digest).map_err(|_| BootError::Uki("invalid configuration digest"))?,
            )?;
        }
        for (index, event) in self.log.events.iter().enumerate() {
            if event.register_index == register
                && event.reported_event_type != EV_NO_ACTION
                && !covered.contains(&index)
            {
                return Err(BootError::Uki(
                    "unaccounted configuration-register measurement",
                ));
            }
        }
        if line != policy.expected_effective_command_line {
            return Err(BootError::Uki(
                "reconstructed effective command line differs from policy",
            ));
        }
        let dm_verity = policy
            .expected_verity_root
            .as_ref()
            .map(|root| {
                MeasuredCommandLine {
                    event_index: last_section,
                    algorithm: uki.algorithm,
                    profile: CommandLineProfile::SystemdUkiEmbedded,
                    command_line: line.clone(),
                }
                .verify_dm_verity(
                    &hex::decode(root)
                        .map_err(|_| BootError::Uki("invalid expected execution verity root"))?,
                )
            })
            .transpose()?;
        Ok(VerifiedUkiExecution {
            effective_command_line: line,
            configuration_event_indices: covered.into_iter().collect(),
            binary_addons,
            dm_verity,
        })
    }
}
