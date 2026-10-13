//! Bounded TCG2/TDX event-log parsing and replay against authenticated registers.
//!
//! Parsing and replay do not authenticate a log. Only a successful comparison
//! with registers obtained from a verified, fresh platform quote produces a
//! [`VerifiedBootLog`]. Event descriptions and event types are not themselves
//! committed by PCR extension; callers must authenticate their measured bytes
//! before using them as policy claims. See `BOOT_MEASUREMENTS.md`.

use serde::Serialize;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;

pub mod closure;
pub mod runtime;
pub mod uki;
pub mod verity;

#[cfg(test)]
mod tests;

pub const TPM_ALG_SHA256: u16 = 0x000b;
pub const TPM_ALG_SHA384: u16 = 0x000c;
pub const TPM_ALG_SHA512: u16 = 0x000d;
pub const EV_NO_ACTION: u32 = 3;
pub const EV_IPL: u32 = 13;
pub const TPM_EVENT_LOG_PATH: &str = "/sys/kernel/security/tpm0/binary_bios_measurements";
pub const CCEL_TABLE_PATH: &str = "/sys/firmware/acpi/tables/CCEL";
pub const CCEL_DATA_PATH: &str = "/sys/firmware/acpi/tables/data/CCEL";

#[derive(Debug, thiserror::Error)]
pub enum BootError {
    #[error("boot event log I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed boot event log at byte {offset}: {reason}")]
    Malformed { offset: usize, reason: &'static str },
    #[error("boot evidence exceeds {0} limit")]
    Limit(&'static str),
    #[error("unsupported digest algorithm 0x{0:04x}")]
    UnsupportedAlgorithm(u16),
    #[error("unsupported boot measurement profile: {0}")]
    Unsupported(&'static str),
    #[error("boot log and authenticated registers have different platforms")]
    PlatformMismatch,
    #[error("invalid authenticated register set: {0}")]
    InvalidRegisters(&'static str),
    #[error("replay does not match authenticated register {index} in algorithm 0x{algorithm:04x}")]
    RegisterMismatch { algorithm: u16, index: u32 },
    #[error("event {0} is not covered by the authenticated register selection")]
    UnauthenticatedEvent(usize),
    #[error("event {event} measurement does not authenticate the supplied content")]
    ContentMismatch { event: usize },
    #[error("invalid measured command line: {0}")]
    CommandLine(&'static str),
    #[error("measured dm-verity root does not match expected manifest digest")]
    VerityRootMismatch,
    #[error("invalid UKI evidence or policy: {0}")]
    Uki(&'static str),
    #[error("invalid runtime event log or policy: {0}")]
    Runtime(&'static str),
    #[error("invalid observed mounted verity state: {0}")]
    VerityState(&'static str),
}

#[derive(Clone, Copy, Debug)]
pub struct ParseLimits {
    pub max_log_bytes: usize,
    pub max_events: usize,
    pub max_event_bytes: usize,
    pub max_algorithms: usize,
}

impl Default for ParseLimits {
    fn default() -> Self {
        Self {
            max_log_bytes: 32 * 1024 * 1024,
            max_events: 65_536,
            max_event_bytes: 4 * 1024 * 1024,
            max_algorithms: 16,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LogKind {
    Tpm2,
    TdxCcel,
}

/// These fields are transport metadata until separately authenticated.
#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub offset: usize,
    pub register_index: u32,
    pub reported_event_type: u32,
    pub digests: BTreeMap<u16, Vec<u8>>,
    #[serde(with = "serde_bytes")]
    pub untrusted_event_data: Vec<u8>,
}

/// Immutable parsed data. There is deliberately no Deserialize implementation.
#[derive(Clone, Debug, Serialize)]
pub struct EventLog {
    kind: LogKind,
    algorithms: BTreeMap<u16, usize>,
    events: Vec<Event>,
    consumed_bytes: usize,
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, size: usize) -> Result<&'a [u8], BootError> {
        let end = self
            .offset
            .checked_add(size)
            .ok_or(BootError::Limit("offset"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(BootError::Malformed {
                offset: self.offset,
                reason: "truncated field",
            })?;
        self.offset = end;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8, BootError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, BootError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, BootError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn invalid(&self, reason: &'static str) -> BootError {
        BootError::Malformed {
            offset: self.offset,
            reason,
        }
    }
}

fn known_digest_size(algorithm: u16) -> Option<usize> {
    match algorithm {
        0x0004 => Some(20),
        0x000b => Some(32),
        0x000c => Some(48),
        0x000d => Some(64),
        0x0012 => Some(32),
        0x0027 => Some(32),
        0x0028 => Some(48),
        0x0029 => Some(64),
        _ => None,
    }
}

fn hash(algorithm: u16, bytes: &[u8]) -> Result<Vec<u8>, BootError> {
    match algorithm {
        TPM_ALG_SHA256 => Ok(Sha256::digest(bytes).to_vec()),
        TPM_ALG_SHA384 => Ok(Sha384::digest(bytes).to_vec()),
        TPM_ALG_SHA512 => Ok(Sha512::digest(bytes).to_vec()),
        _ => Err(BootError::UnsupportedAlgorithm(algorithm)),
    }
}

impl EventLog {
    pub fn parse_tcg2(bytes: &[u8], limits: ParseLimits) -> Result<Self, BootError> {
        Self::parse(bytes, LogKind::Tpm2, limits, false)
    }
    pub fn parse_tdx_ccel(bytes: &[u8], limits: ParseLimits) -> Result<Self, BootError> {
        Self::parse(bytes, LogKind::TdxCcel, limits, false)
    }
    /// CCEL with CoCo AAEL TCG2 application events in MRIndex 4 (RTMR3).
    /// Parsing does not authenticate the events or their descriptions.
    pub fn parse_tdx_ccel_with_aael(bytes: &[u8], limits: ParseLimits) -> Result<Self, BootError> {
        Self::parse(bytes, LogKind::TdxCcel, limits, true)
    }
    fn parse(
        bytes: &[u8],
        kind: LogKind,
        limits: ParseLimits,
        aael: bool,
    ) -> Result<Self, BootError> {
        if bytes.len() > limits.max_log_bytes {
            return Err(BootError::Limit("log bytes"));
        }
        let mut c = Cursor { bytes, offset: 0 };
        let initial_index = c.u32()?;
        if (kind == LogKind::Tpm2 && initial_index != 0)
            || (kind == LogKind::TdxCcel && initial_index > 1)
        {
            return Err(c.invalid("invalid SpecID register"));
        }
        if c.u32()? != EV_NO_ACTION || c.take(20)?.iter().any(|b| *b != 0) {
            return Err(c.invalid("missing legacy-format SpecID header"));
        }
        let spec_len = c.u32()? as usize;
        if spec_len > limits.max_event_bytes {
            return Err(BootError::Limit("SpecID bytes"));
        }
        let spec = c.take(spec_len)?;
        let mut s = Cursor {
            bytes: spec,
            offset: 0,
        };
        if s.take(16)? != b"Spec ID Event03\0" {
            return Err(c.invalid("unsupported SpecID signature"));
        }
        let _platform_class = s.u32()?;
        let minor = s.u8()?;
        let major = s.u8()?;
        let _errata = s.u8()?;
        let uintn = s.u8()?;
        if major != 2 || minor != 0 || !matches!(uintn, 1 | 2) {
            return Err(c.invalid("unsupported SpecID version or UINTN size"));
        }
        let count = s.u32()? as usize;
        if count == 0 || count > limits.max_algorithms {
            return Err(BootError::Limit("algorithm count"));
        }
        let mut algorithms = BTreeMap::new();
        for _ in 0..count {
            let algorithm = s.u16()?;
            let size = s.u16()? as usize;
            if size == 0 || size > 128 || known_digest_size(algorithm).is_some_and(|n| n != size) {
                return Err(c.invalid("invalid algorithm digest size"));
            }
            if algorithms.insert(algorithm, size).is_some() {
                return Err(c.invalid("duplicate SpecID algorithm"));
            }
        }
        let vendor_len = s.u8()? as usize;
        s.take(vendor_len)?;
        if s.offset != spec.len() {
            return Err(c.invalid("trailing SpecID data"));
        }
        if kind == LogKind::TdxCcel && algorithms.get(&TPM_ALG_SHA384) != Some(&48) {
            return Err(c.invalid("TDX CCEL lacks SHA-384 bank"));
        }
        let mut events = Vec::new();
        while c.offset < bytes.len() {
            // ACPI log areas use erased 0xff bytes after the last entry. Never
            // accept an arbitrary tail merely because its first DWORD is ff.
            if kind == LogKind::TdxCcel && bytes[c.offset..].iter().all(|b| *b == 0xff) {
                break;
            }
            if events.len() >= limits.max_events {
                return Err(BootError::Limit("event count"));
            }
            let offset = c.offset;
            let register_index = c.u32()?;
            if (kind == LogKind::Tpm2 && register_index > 23)
                || (kind == LogKind::TdxCcel && register_index > if aael { 4 } else { 3 })
            {
                return Err(c.invalid("register outside supported platform profile"));
            }
            let reported_event_type = c.u32()?;
            let count = c.u32()? as usize;
            if count == 0 || count > algorithms.len() {
                return Err(c.invalid("invalid event digest count"));
            }
            let mut digests = BTreeMap::new();
            for _ in 0..count {
                let algorithm = c.u16()?;
                let size = *algorithms
                    .get(&algorithm)
                    .ok_or_else(|| c.invalid("algorithm absent from SpecID"))?;
                let digest = c.take(size)?.to_vec();
                if digests.insert(algorithm, digest).is_some() {
                    return Err(c.invalid("duplicate event digest"));
                }
            }
            let size = c.u32()? as usize;
            if size > limits.max_event_bytes {
                return Err(BootError::Limit("event bytes"));
            }
            let untrusted_event_data = c.take(size)?.to_vec();
            if kind == LogKind::TdxCcel && !digests.contains_key(&TPM_ALG_SHA384) {
                return Err(c.invalid("TDX event lacks SHA-384 digest"));
            }
            events.push(Event {
                offset,
                register_index,
                reported_event_type,
                digests,
                untrusted_event_data,
            });
            if kind == LogKind::TdxCcel && register_index == 4 {
                runtime::parse_aael(events.last().unwrap())?;
            }
        }
        if events.is_empty() {
            return Err(c.invalid("empty measured event log"));
        }
        Ok(Self {
            kind,
            algorithms,
            events,
            consumed_bytes: c.offset,
        })
    }

    pub fn kind(&self) -> LogKind {
        self.kind
    }
    pub fn events(&self) -> &[Event] {
        &self.events
    }
    pub fn algorithms(&self) -> &BTreeMap<u16, usize> {
        &self.algorithms
    }
    pub fn consumed_bytes(&self) -> usize {
        self.consumed_bytes
    }

    /// Compute candidate register values, explicitly unauthenticated. Only
    /// static TPM PCRs 0..15 and the UEFI TDX CCEL profile are implemented.
    pub fn replay(&self, algorithm: u16) -> Result<UnverifiedReplay, BootError> {
        let size = hash(algorithm, b"")?.len();
        if self.algorithms.get(&algorithm) != Some(&size) {
            return Err(BootError::UnsupportedAlgorithm(algorithm));
        }
        if self.kind == LogKind::TdxCcel && algorithm != TPM_ALG_SHA384 {
            return Err(BootError::Unsupported("TDX requires SHA-384"));
        }
        let count = if self.kind == LogKind::Tpm2 { 16 } else { 4 };
        let mut values: BTreeMap<u32, Vec<u8>> = (0..count).map(|i| (i, vec![0; size])).collect();
        let mut pcr0_extended = false;
        let mut locality_seen = false;
        for event in &self.events {
            if event.reported_event_type == EV_NO_ACTION {
                if self.kind == LogKind::Tpm2
                    && event.untrusted_event_data.starts_with(b"StartupLocality\0")
                {
                    if event.register_index != 0
                        || pcr0_extended
                        || locality_seen
                        || event.untrusted_event_data.len() != 17
                        || !matches!(event.untrusted_event_data[16], 0 | 3)
                        || event.digests.values().any(|d| d.iter().any(|b| *b != 0))
                    {
                        return Err(BootError::Unsupported(
                            "invalid or late TPM StartupLocality event",
                        ));
                    }
                    locality_seen = true;
                    values.get_mut(&0).unwrap()[size - 1] = event.untrusted_event_data[16];
                }
                continue;
            }
            let index = if self.kind == LogKind::TdxCcel {
                if event.register_index == 0 {
                    return Err(BootError::Unsupported(
                        "MRTD cannot be reconstructed by RTMR extension",
                    ));
                }
                event.register_index - 1
            } else {
                if event.register_index > 15 {
                    continue;
                }
                if event.register_index == 0 {
                    pcr0_extended = true;
                }
                event.register_index
            };
            let digest = event
                .digests
                .get(&algorithm)
                .ok_or(BootError::Unsupported("event missing replay bank"))?;
            let value = values.get_mut(&index).unwrap();
            let mut input = Vec::with_capacity(size * 2);
            input.extend_from_slice(value);
            input.extend_from_slice(digest);
            *value = hash(algorithm, &input)?;
        }
        Ok(UnverifiedReplay {
            kind: self.kind,
            algorithm,
            registers: values,
        })
    }

    pub fn verify(&self, expected: &AuthenticatedRegisters) -> Result<VerifiedBootLog, BootError> {
        if self.kind != expected.kind {
            return Err(BootError::PlatformMismatch);
        }
        if expected.values.is_empty() {
            return Err(BootError::InvalidRegisters("empty selection"));
        }
        let mut replayed = BTreeMap::new();
        for &(algorithm, _) in expected.values.keys() {
            if let std::collections::btree_map::Entry::Vacant(entry) = replayed.entry(algorithm) {
                entry.insert(self.replay(algorithm)?);
            }
        }
        for (&(algorithm, index), wanted) in &expected.values {
            let actual = replayed[&algorithm]
                .registers
                .get(&index)
                .ok_or(BootError::InvalidRegisters("unsupported register index"))?;
            if wanted.len() != actual.len() {
                return Err(BootError::InvalidRegisters("digest length"));
            }
            if actual != wanted {
                return Err(BootError::RegisterMismatch { algorithm, index });
            }
        }
        Ok(VerifiedBootLog {
            log: self.clone(),
            covered: expected.values.keys().copied().collect(),
        })
    }
}

/// Diagnostic values, not proof that a hardware quote exists or is authentic.
#[derive(Debug, Serialize)]
pub struct UnverifiedReplay {
    pub kind: LogKind,
    pub algorithm: u16,
    pub registers: BTreeMap<u32, Vec<u8>>,
}

/// Constructible only by this crate's platform verification integration after
/// quote signature, collateral, freshness and report-data checks have passed.
#[derive(Debug)]
pub struct AuthenticatedRegisters {
    kind: LogKind,
    values: BTreeMap<(u16, u32), Vec<u8>>,
}
impl AuthenticatedRegisters {
    pub(crate) fn tdx(rtmrs: [[u8; 48]; 4]) -> Self {
        Self {
            kind: LogKind::TdxCcel,
            values: rtmrs
                .into_iter()
                .enumerate()
                .map(|(index, digest)| ((TPM_ALG_SHA384, index as u32), digest.to_vec()))
                .collect(),
        }
    }
    pub(crate) fn tpm(values: BTreeMap<(u16, u32), Vec<u8>>) -> Result<Self, BootError> {
        if values.is_empty() || values.keys().any(|(_, index)| *index > 15) {
            return Err(BootError::InvalidRegisters(
                "only static PCRs 0..15 are supported",
            ));
        }
        for (&(algorithm, _), digest) in &values {
            if hash(algorithm, b"")?.len() != digest.len() {
                return Err(BootError::InvalidRegisters("digest length"));
            }
        }
        Ok(Self {
            kind: LogKind::Tpm2,
            values,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct VerifiedBootLog {
    log: EventLog,
    covered: BTreeSet<(u16, u32)>,
}
impl VerifiedBootLog {
    /// Metadata remains untrusted. Coverage can be checked through
    /// `authenticated_digest`; interpretation requires measured preimages.
    pub fn log(&self) -> &EventLog {
        &self.log
    }
    pub fn covered_registers(&self) -> &BTreeSet<(u16, u32)> {
        &self.covered
    }

    pub fn authenticated_digest(&self, event: usize, algorithm: u16) -> Result<&[u8], BootError> {
        let e = self
            .log
            .events
            .get(event)
            .ok_or(BootError::UnauthenticatedEvent(event))?;
        if e.reported_event_type == EV_NO_ACTION {
            return Err(BootError::UnauthenticatedEvent(event));
        }
        let index = if self.log.kind == LogKind::TdxCcel {
            e.register_index
                .checked_sub(1)
                .ok_or(BootError::UnauthenticatedEvent(event))?
        } else {
            e.register_index
        };
        if !self.covered.contains(&(algorithm, index)) {
            return Err(BootError::UnauthenticatedEvent(event));
        }
        e.digests
            .get(&algorithm)
            .map(Vec::as_slice)
            .ok_or(BootError::UnauthenticatedEvent(event))
    }

    /// Authenticate bytes under an explicitly selected raw-digest measurement
    /// policy. PE/COFF Authenticode digests require their image-specific hash;
    /// a raw file hash is never silently substituted for Authenticode.
    pub fn verify_measured_bytes(
        &self,
        event: usize,
        algorithm: u16,
        bytes: &[u8],
    ) -> Result<(), BootError> {
        if self.authenticated_digest(event, algorithm)? != hash(algorithm, bytes)? {
            return Err(BootError::ContentMismatch { event });
        }
        Ok(())
    }

    /// Compare a policy-approved firmware/bootloader/kernel measurement digest.
    /// The policy supplies the identity, not the untrusted event description.
    pub fn verify_expected_digest(
        &self,
        event: usize,
        algorithm: u16,
        digest: &[u8],
    ) -> Result<(), BootError> {
        if self.authenticated_digest(event, algorithm)? != digest {
            return Err(BootError::ContentMismatch { event });
        }
        Ok(())
    }

    pub fn authenticated_command_line(
        &self,
        event: usize,
        algorithm: u16,
        profile: CommandLineProfile,
    ) -> Result<MeasuredCommandLine, BootError> {
        if matches!(profile, CommandLineProfile::SystemdUkiEmbedded) {
            return Err(BootError::Unsupported(
                "UKI command line requires verified section-name/data pairs",
            ));
        }
        let e = self
            .log
            .events
            .get(event)
            .ok_or(BootError::UnauthenticatedEvent(event))?;
        let expected_register = match (self.log.kind, profile) {
            (LogKind::Tpm2, CommandLineProfile::Grub) => 8,
            (LogKind::Tpm2, CommandLineProfile::SystemdLoadOptions) => 12,
            (LogKind::Tpm2, CommandLineProfile::SystemdUkiEmbedded) => unreachable!(),
            (LogKind::TdxCcel, _) => 3,
        };
        if e.register_index != expected_register || e.reported_event_type != EV_IPL {
            return Err(BootError::CommandLine(
                "event is outside selected loader profile",
            ));
        }
        let command_line = match profile {
            CommandLineProfile::Grub => {
                let data = &e.untrusted_event_data;
                let text = data
                    .strip_suffix(&[0])
                    .ok_or(BootError::CommandLine("missing GRUB terminator"))?;
                let measured =
                    text.strip_prefix(b"kernel_cmdline: ")
                        .ok_or(BootError::CommandLine(
                            "missing GRUB kernel command line description",
                        ))?;
                self.verify_measured_bytes(event, algorithm, measured)?;
                std::str::from_utf8(measured)
                    .map_err(|_| BootError::CommandLine("invalid UTF-8"))?
                    .to_owned()
            }
            CommandLineProfile::SystemdLoadOptions => {
                self.verify_measured_bytes(event, algorithm, &e.untrusted_event_data)?;
                if e.untrusted_event_data.len() < 2 || e.untrusted_event_data.len() % 2 != 0 {
                    return Err(BootError::CommandLine("invalid UTF-16 length"));
                }
                let mut words: Vec<u16> = e
                    .untrusted_event_data
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                if words.pop() != Some(0) || words.contains(&0) {
                    return Err(BootError::CommandLine("invalid UTF-16 termination"));
                }
                String::from_utf16(&words).map_err(|_| BootError::CommandLine("invalid UTF-16"))?
            }
            CommandLineProfile::SystemdUkiEmbedded => unreachable!(),
        };
        if command_line.contains('\0') {
            return Err(BootError::CommandLine("embedded NUL"));
        }
        Ok(MeasuredCommandLine {
            event_index: event,
            algorithm,
            profile,
            command_line,
        })
    }

    pub fn verified_dm_verity(
        &self,
        event: usize,
        algorithm: u16,
        profile: CommandLineProfile,
        expected_root_digest: &[u8],
    ) -> Result<DmVerityCommitment, BootError> {
        self.authenticated_command_line(event, algorithm, profile)?
            .verify_dm_verity(expected_root_digest)
    }
}

/// Caller-selected semantics of an approved loader; never auto-detected from
/// an attacker-editable event description. This identifies measured bytes, not
/// whether the running kernel ultimately honored them.
#[derive(Clone, Copy, Debug, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandLineProfile {
    Grub,
    SystemdLoadOptions,
    /// Embedded UTF-8 section bytes authenticated by the UKI section-pair API.
    /// This cannot be selected through `authenticated_command_line`.
    SystemdUkiEmbedded,
}

#[derive(Debug, Serialize)]
pub struct MeasuredCommandLine {
    event_index: usize,
    algorithm: u16,
    profile: CommandLineProfile,
    command_line: String,
}
impl MeasuredCommandLine {
    pub fn text(&self) -> &str {
        &self.command_line
    }
    /// Check a measured root commitment. This does not assert dm-verity was
    /// mounted or that a read-only system closure equals a verity Merkle root.
    pub fn verify_dm_verity(
        &self,
        expected_root_digest: &[u8],
    ) -> Result<DmVerityCommitment, BootError> {
        if !matches!(expected_root_digest.len(), 32 | 48 | 64) {
            return Err(BootError::CommandLine(
                "unsupported expected root digest length",
            ));
        }
        // Fail closed on noncanonical quoting/escaping instead of approximating
        // the kernel and initrd's argument parsers with a shell parser.
        if self
            .command_line
            .chars()
            .any(|c| matches!(c, '\'' | '"' | '\\') || (c.is_control() && !matches!(c, ' ' | '\t')))
        {
            return Err(BootError::CommandLine(
                "quoted, escaped, or control-character syntax is unsupported",
            ));
        }
        let mut root = None;
        for token in self.command_line.split_ascii_whitespace() {
            if token == "--" {
                break;
            }
            if matches!(
                token,
                "systemd.verity=0"
                    | "systemd.verity=no"
                    | "systemd.verity=false"
                    | "systemd.verity=off"
                    | "rd.systemd.verity=0"
                    | "rd.systemd.verity=no"
                    | "rd.systemd.verity=false"
                    | "rd.systemd.verity=off"
            ) {
                return Err(BootError::CommandLine("dm-verity explicitly disabled"));
            }
            if let Some(encoded) = token.strip_prefix("roothash=") {
                if root.is_some() {
                    return Err(BootError::CommandLine("duplicate roothash argument"));
                }
                let digest = hex::decode(encoded)
                    .map_err(|_| BootError::CommandLine("invalid roothash hex"))?;
                root = Some(digest);
            }
        }
        let root = root.ok_or(BootError::CommandLine("missing measured roothash"))?;
        if root != expected_root_digest {
            return Err(BootError::VerityRootMismatch);
        }
        Ok(DmVerityCommitment {
            event_index: self.event_index,
            measurement_algorithm: self.algorithm,
            root_digest_hex: hex::encode(root),
            command_line: self.command_line.clone(),
        })
    }
}

#[derive(Debug, Serialize)]
pub struct DmVerityCommitment {
    pub event_index: usize,
    pub measurement_algorithm: u16,
    pub root_digest_hex: String,
    pub command_line: String,
}

#[derive(Debug, Serialize)]
pub struct CcelTable {
    pub log_area_minimum_length: u64,
    pub log_area_start_address: u64,
}
impl CcelTable {
    pub fn parse(bytes: &[u8], limits: ParseLimits) -> Result<Self, BootError> {
        if bytes.len() != 56 || bytes.get(..4) != Some(b"CCEL") {
            return Err(BootError::Malformed {
                offset: 0,
                reason: "invalid CCEL ACPI signature or size",
            });
        }
        if u32::from_le_bytes(bytes[4..8].try_into().unwrap()) != 56
            || bytes[8] != 1
            || bytes.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)) != 0
            || bytes[36..40] != [2, 0, 0, 0]
        {
            return Err(BootError::Malformed {
                offset: 4,
                reason: "invalid CCEL ACPI length, revision, checksum or TDX type",
            });
        }
        let log_area_minimum_length = u64::from_le_bytes(bytes[40..48].try_into().unwrap());
        let log_area_start_address = u64::from_le_bytes(bytes[48..56].try_into().unwrap());
        if log_area_minimum_length == 0 || log_area_minimum_length > limits.max_log_bytes as u64 {
            return Err(BootError::Limit("CCEL log area"));
        }
        log_area_start_address
            .checked_add(log_area_minimum_length)
            .ok_or(BootError::Limit("CCEL physical address"))?;
        Ok(Self {
            log_area_minimum_length,
            log_area_start_address,
        })
    }
}

pub fn read_tpm_event_log(path: &Path, limits: ParseLimits) -> Result<EventLog, BootError> {
    EventLog::parse_tcg2(&read_bounded(path, limits.max_log_bytes)?, limits)
}

pub fn read_tdx_ccel(
    table_path: &Path,
    data_path: &Path,
    limits: ParseLimits,
) -> Result<EventLog, BootError> {
    let table = CcelTable::parse(&read_bounded(table_path, 56)?, limits)?;
    let data = read_bounded(data_path, limits.max_log_bytes)?;
    if (data.len() as u64) < table.log_area_minimum_length {
        return Err(BootError::Malformed {
            offset: data.len(),
            reason: "CCEL data shorter than ACPI log area",
        });
    }
    EventLog::parse_tdx_ccel(&data, limits)
}

fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>, BootError> {
    let mut bytes = Vec::new();
    let limit = max.checked_add(1).ok_or(BootError::Limit("file bytes"))?;
    std::fs::File::open(path)?
        .take(limit as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > max {
        return Err(BootError::Limit("file bytes"));
    }
    Ok(bytes)
}
