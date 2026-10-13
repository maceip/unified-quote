//! Native Linux active dm-verity observation. These are untrusted runtime reads,
//! never a substitute for quoted boot commitments or an authenticated measuring
//! agent. No function in this module manufactures a verified mount claim.
use super::BootError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const MAX_MOUNTINFO: usize = 4 * 1024 * 1024;
const MAX_DM_BYTES: usize = 1024 * 1024;
const DM_HEADER: usize = 312;

#[derive(Debug, Clone, Serialize)]
pub struct UnverifiedRootMount {
    pub mount_id: u64,
    pub major: u32,
    pub minor: u32,
    pub filesystem: String,
    pub read_only: bool,
}
#[derive(Debug, Clone, Serialize)]
pub struct UnverifiedVerityTable {
    pub format_version: u32,
    pub data_device: String,
    pub hash_device: String,
    pub data_block_size: u64,
    pub hash_block_size: u64,
    pub data_blocks: u64,
    pub hash_start_block: u64,
    pub hash_algorithm: String,
    pub root_digest_hex: String,
    pub salt_hex: String,
    pub optional_parameters: Vec<String>,
}
#[derive(Debug, Serialize)]
pub struct UnverifiedMountedVerity {
    pub root: UnverifiedRootMount,
    pub table: UnverifiedVerityTable,
    pub mapper_name: String,
    pub mapper_uuid: String,
    pub mapper_event_number: u32,
    pub mapper_read_only: bool,
    pub corruption_detected: bool,
    pub fec_corrected_blocks: Option<u64>,
    pub sectors: u64,
}
/// Independent policy for an observed table. Evaluation remains unverified:
/// admission must separately authenticate the collector and bind this snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MountedVerityPolicy {
    pub expected_root_digest_hex: String,
    pub expected_hash_algorithm: String,
    pub expected_salt_hex: String,
    pub expected_data_blocks: u64,
    pub expected_data_block_size: u64,
    pub expected_hash_block_size: u64,
    pub expected_hash_start_block: u64,
    pub expected_format_version: u32,
    pub expected_filesystem: String,
    pub expected_optional_parameters: Vec<String>,
}
impl UnverifiedMountedVerity {
    pub fn check_observed_policy(&self, policy: &MountedVerityPolicy) -> Result<(), BootError> {
        let t = &self.table;
        if !self.root.read_only
            || !self.mapper_read_only
            || self.corruption_detected
            || t.root_digest_hex != policy.expected_root_digest_hex.to_ascii_lowercase()
            || t.hash_algorithm != policy.expected_hash_algorithm
            || t.salt_hex != policy.expected_salt_hex.to_ascii_lowercase()
            || t.data_blocks != policy.expected_data_blocks
            || t.data_block_size != policy.expected_data_block_size
            || t.hash_block_size != policy.expected_hash_block_size
            || t.hash_start_block != policy.expected_hash_start_block
            || t.format_version != policy.expected_format_version
            || self.root.filesystem != policy.expected_filesystem
            || t.optional_parameters != policy.expected_optional_parameters
            || t.optional_parameters
                .iter()
                .any(|p| matches!(p.as_str(), "ignore_corruption" | "check_at_most_once"))
        {
            return Err(BootError::VerityState(
                "observed mount/table differs from strict policy",
            ));
        }
        Ok(())
    }
}
fn number<T: std::str::FromStr>(s: &str) -> Result<T, BootError> {
    if s.is_empty() || !s.bytes().all(|c| c.is_ascii_digit()) {
        return Err(BootError::VerityState("invalid decimal field"));
    }
    s.parse()
        .map_err(|_| BootError::VerityState("numeric field overflow"))
}
fn device(s: &str) -> Result<(u32, u32), BootError> {
    let (major, minor) = s
        .split_once(':')
        .ok_or(BootError::VerityState("invalid device number"))?;
    Ok((number(major)?, number(minor)?))
}

pub fn parse_root_mountinfo(bytes: &[u8]) -> Result<UnverifiedRootMount, BootError> {
    if bytes.len() > MAX_MOUNTINFO {
        return Err(BootError::Limit("mountinfo bytes"));
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| BootError::VerityState("invalid mountinfo UTF8"))?;
    let mut root = None;
    for line in text.lines() {
        let fields: Vec<_> = line.split(' ').collect();
        let separator = fields
            .iter()
            .position(|s| *s == "-")
            .ok_or(BootError::VerityState("mountinfo separator missing"))?;
        if separator < 6 || fields.len() != separator + 4 || fields.iter().any(|s| s.is_empty()) {
            return Err(BootError::VerityState("malformed mountinfo record"));
        }
        if fields[4] != "/" {
            continue;
        }
        // A bind-mounted subtree or an overmounted/ambiguous root must not be
        // described as the complete verity device's root filesystem.
        if fields[3] != "/" || root.is_some() {
            return Err(BootError::VerityState("ambiguous or subtree root mount"));
        }
        let (major, minor) = device(fields[2])?;
        let mount: BTreeSet<_> = fields[5].split(',').collect();
        let fs: BTreeSet<_> = fields[separator + 3].split(',').collect();
        if mount.contains("ro") == mount.contains("rw") || fs.contains("ro") == fs.contains("rw") {
            return Err(BootError::VerityState("ambiguous mount read-only flags"));
        }
        root = Some(UnverifiedRootMount {
            mount_id: number(fields[0])?,
            major,
            minor,
            filesystem: fields[separator + 1].into(),
            read_only: mount.contains("ro") && fs.contains("ro"),
        });
    }
    root.ok_or(BootError::VerityState("root mount absent"))
}

pub fn parse_verity_parameters(text: &str) -> Result<UnverifiedVerityTable, BootError> {
    if text.len() > 64 * 1024 || !text.is_ascii() || text.bytes().any(|c| c < 0x20 || c == 0x7f) {
        return Err(BootError::VerityState(
            "invalid verity table parameter bytes",
        ));
    }
    let fields: Vec<_> = text.split_ascii_whitespace().collect();
    if fields.len() < 10 {
        return Err(BootError::VerityState("incomplete verity table"));
    }
    let format_version = number(fields[0])?;
    if format_version > 1 {
        return Err(BootError::VerityState("unsupported verity format"));
    }
    // Kernel status output uses device numbers, making aliases unambiguous.
    device(fields[1])?;
    device(fields[2])?;
    let data_block_size: u64 = number(fields[3])?;
    let hash_block_size: u64 = number(fields[4])?;
    if !data_block_size.is_power_of_two()
        || !hash_block_size.is_power_of_two()
        || !(512..=65536).contains(&data_block_size)
        || !(512..=65536).contains(&hash_block_size)
    {
        return Err(BootError::VerityState("invalid verity block geometry"));
    }
    let data_blocks: u64 = number(fields[5])?;
    let hash_start_block: u64 = number(fields[6])?;
    if data_blocks == 0
        || data_blocks.checked_mul(data_block_size).is_none()
        || hash_start_block.checked_mul(hash_block_size).is_none()
    {
        return Err(BootError::VerityState("invalid verity block extent"));
    }
    let size = match fields[7] {
        "sha256" => 32,
        "sha384" => 48,
        "sha512" => 64,
        _ => return Err(BootError::VerityState("unsupported verity hash algorithm")),
    };
    if fields[8].len() != size * 2 || !fields[8].bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(BootError::VerityState("invalid verity root digest"));
    }
    let salt = if fields[9] == "-" { "" } else { fields[9] };
    if salt.len() > 512 || salt.len() % 2 != 0 || !salt.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(BootError::VerityState("invalid verity salt"));
    }
    let optional = if fields.len() == 10 {
        &fields[10..]
    } else {
        let n: usize = number(fields[10])?;
        if n != fields.len() - 11 {
            return Err(BootError::VerityState("verity option count mismatch"));
        }
        &fields[11..]
    };
    validate_options(optional, data_block_size, hash_block_size)?;
    Ok(UnverifiedVerityTable {
        format_version,
        data_device: fields[1].into(),
        hash_device: fields[2].into(),
        data_block_size,
        hash_block_size,
        data_blocks,
        hash_start_block,
        hash_algorithm: fields[7].into(),
        root_digest_hex: fields[8].to_ascii_lowercase(),
        salt_hex: salt.to_ascii_lowercase(),
        optional_parameters: optional.iter().map(|s| (*s).into()).collect(),
    })
}

fn validate_options(options: &[&str], data_block: u64, hash_block: u64) -> Result<(), BootError> {
    let mut seen = BTreeSet::new();
    let mut at = 0;
    while at < options.len() {
        let key = options[at];
        at += 1;
        if !seen.insert(key) {
            return Err(BootError::VerityState("duplicate verity option"));
        }
        match key {
            "ignore_corruption"
            | "restart_on_corruption"
            | "panic_on_corruption"
            | "restart_on_error"
            | "panic_on_error"
            | "ignore_zero_blocks"
            | "check_at_most_once"
            | "try_verify_in_tasklet" => {}
            "use_fec_from_device"
            | "fec_roots"
            | "fec_blocks"
            | "fec_start"
            | "root_hash_sig_key_desc" => {
                let value = options
                    .get(at)
                    .ok_or(BootError::VerityState("missing verity option value"))?;
                at += 1;
                match key {
                    "use_fec_from_device" => {
                        device(value)?;
                    }
                    "fec_roots" => {
                        let n: u64 = number(value)?;
                        if !(2..=24).contains(&n) {
                            return Err(BootError::VerityState("invalid FEC roots"));
                        }
                    }
                    "fec_blocks" | "fec_start" => {
                        let _: u64 = number(value)?;
                    }
                    _ => {}
                }
            }
            _ => return Err(BootError::VerityState("unknown verity option")),
        }
    }
    let fec = [
        "use_fec_from_device",
        "fec_roots",
        "fec_blocks",
        "fec_start",
    ]
    .iter()
    .filter(|s| seen.contains(**s))
    .count();
    if (fec > 0 && (fec != 4 || data_block != hash_block))
        || [
            "ignore_corruption",
            "restart_on_corruption",
            "panic_on_corruption",
        ]
        .iter()
        .filter(|s| seen.contains(**s))
        .count()
            > 1
        || (seen.contains("restart_on_error") && seen.contains("panic_on_error"))
    {
        return Err(BootError::VerityState("inconsistent verity options"));
    }
    Ok(())
}
fn parse_verity_status(text: &str) -> Result<(bool, Option<u64>), BootError> {
    let parts: Vec<_> = text.split(' ').collect();
    let failed = match parts.first().copied() {
        Some("V") => false,
        Some("C") => true,
        _ => return Err(BootError::VerityState("unknown verity runtime status")),
    };
    let corrected = match parts.as_slice() {
        [_] => None,
        [_, "-"] => None,
        [_, value] => Some(number(value)?),
        _ => return Err(BootError::VerityState("malformed verity runtime status")),
    };
    Ok((failed, corrected))
}

fn u32_field(bytes: &[u8], at: usize) -> Result<u32, BootError> {
    Ok(u32::from_ne_bytes(
        bytes
            .get(at..at + 4)
            .ok_or(BootError::VerityState("truncated ioctl field"))?
            .try_into()
            .unwrap(),
    ))
}
fn u64_field(bytes: &[u8], at: usize) -> Result<u64, BootError> {
    Ok(u64::from_ne_bytes(
        bytes
            .get(at..at + 8)
            .ok_or(BootError::VerityState("truncated ioctl field"))?
            .try_into()
            .unwrap(),
    ))
}
fn cstr(bytes: &[u8]) -> Result<&str, BootError> {
    let n = bytes
        .iter()
        .position(|c| *c == 0)
        .ok_or(BootError::VerityState("unterminated ioctl string"))?;
    std::str::from_utf8(&bytes[..n]).map_err(|_| BootError::VerityState("invalid ioctl string"))
}
struct DmResponse {
    name: String,
    uuid: String,
    event: u32,
    read_only: bool,
    sectors: u64,
    parameters: String,
}
fn parse_dm_response(bytes: &[u8], encoded_device: u64) -> Result<DmResponse, BootError> {
    if bytes.len() < DM_HEADER || bytes.len() > MAX_DM_BYTES || u32_field(bytes, 0)? != 4 {
        return Err(BootError::VerityState("invalid DM ioctl version/bounds"));
    }
    let size = u32_field(bytes, 12)? as usize;
    let start = u32_field(bytes, 16)? as usize;
    let flags = u32_field(bytes, 28)?;
    if size > bytes.len()
        || start < DM_HEADER
        || start % 8 != 0
        || start > size
        || u32_field(bytes, 20)? != 1
        || u64_field(bytes, 40)? != encoded_device
        || flags & (1 << 5) == 0
        || flags & ((1 << 1) | (1 << 8) | (1 << 12) | (1 << 17) | (1 << 18)) != 0
    {
        return Err(BootError::VerityState(
            "invalid, suspended, incomplete, inactive, or multi-target DM table",
        ));
    }
    let target = bytes
        .get(start..size)
        .ok_or(BootError::VerityState("DM target outside output"))?;
    if target.len() < 41
        || u64_field(target, 0)? != 0
        || u32_field(target, 16)? != 0
        || cstr(&target[24..40])? != "verity"
    {
        return Err(BootError::VerityState(
            "root device is not one successful verity target",
        ));
    }
    if u32_field(target, 20)? as usize != (target.len() + 7) & !7 {
        return Err(BootError::VerityState("invalid final DM target offset"));
    }
    let sectors = u64_field(target, 8)?;
    if sectors == 0 {
        return Err(BootError::VerityState("empty verity device"));
    }
    Ok(DmResponse {
        name: cstr(&bytes[48..176])?.into(),
        uuid: cstr(&bytes[176..305])?.into(),
        event: u32_field(bytes, 32)?,
        read_only: flags & 1 != 0,
        sectors,
        parameters: cstr(&target[40..])?.into(),
    })
}

/// Read-only Linux ioctls and a before/after mount-namespace snapshot. It rejects
/// races it can observe. Even a consistent result remains unverified evidence.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub fn collect_mounted_verity() -> Result<UnverifiedMountedVerity, BootError> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let before = super::read_bounded(std::path::Path::new("/proc/self/mountinfo"), MAX_MOUNTINFO)?;
    let root = parse_root_mountinfo(&before)?;
    if root.major > 0xfff || root.minor > 0xfffff {
        return Err(BootError::VerityState(
            "device number outside Linux encoding",
        ));
    }
    let encoded = (root.minor as u64 & 0xff)
        | ((root.major as u64) << 8)
        | ((root.minor as u64 & !0xff) << 12);
    let control = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open("/dev/mapper/control")?;
    fn query(fd: i32, device: u64, table: bool) -> Result<DmResponse, BootError> {
        // Linux generic _IOWR(0xfd,12,struct dm_ioctl), 312-byte v4 header.
        const DM_TABLE_STATUS: libc::c_ulong = 0xc138fd0c;
        let mut length = 65536;
        loop {
            let mut data = vec![0u8; length];
            data[0..4].copy_from_slice(&4u32.to_ne_bytes());
            data[12..16].copy_from_slice(&(length as u32).to_ne_bytes());
            data[16..20].copy_from_slice(&(DM_HEADER as u32).to_ne_bytes());
            data[28..32].copy_from_slice(&(if table { 1u32 << 4 } else { 0 }).to_ne_bytes());
            data[40..48].copy_from_slice(&device.to_ne_bytes());
            // SAFETY: DM_TABLE_STATUS only reads the live target's state into
            // this owned buffer, whose initialized header declares its length.
            if unsafe { libc::ioctl(fd, DM_TABLE_STATUS, data.as_mut_ptr()) } < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            if u32_field(&data, 28)? & (1 << 8) != 0 {
                if length == MAX_DM_BYTES {
                    return Err(BootError::Limit("DM ioctl output"));
                }
                length = (length * 2).min(MAX_DM_BYTES);
                continue;
            }
            return parse_dm_response(&data, device);
        }
    }
    let table = query(control.as_raw_fd(), encoded, true)?;
    let status = query(control.as_raw_fd(), encoded, false)?;
    let again = query(control.as_raw_fd(), encoded, true)?;
    if table.name != again.name
        || table.uuid != again.uuid
        || table.event != again.event
        || table.parameters != again.parameters
        || table.sectors != again.sectors
        || table.read_only != again.read_only
        || table.name != status.name
        || table.uuid != status.uuid
        || table.event != status.event
        || table.sectors != status.sectors
        || table.read_only != status.read_only
        || super::read_bounded(std::path::Path::new("/proc/self/mountinfo"), MAX_MOUNTINFO)?
            != before
    {
        return Err(BootError::VerityState(
            "mount/table changed during collection",
        ));
    }
    let (corruption_detected, fec_corrected_blocks) = parse_verity_status(&status.parameters)?;
    let parameters = parse_verity_parameters(&table.parameters)?;
    if parameters.data_blocks * parameters.data_block_size / 512 != table.sectors {
        return Err(BootError::VerityState(
            "verity target extent differs from data geometry",
        ));
    }
    Ok(UnverifiedMountedVerity {
        root,
        table: parameters,
        mapper_name: table.name,
        mapper_uuid: table.uuid,
        mapper_event_number: table.event,
        mapper_read_only: table.read_only,
        corruption_detected,
        fec_corrected_blocks,
        sectors: table.sectors,
    })
}
#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
pub fn collect_mounted_verity() -> Result<UnverifiedMountedVerity, BootError> {
    Err(BootError::Unsupported(
        "native dm-verity observation requires Linux x86_64/aarch64",
    ))
}

#[cfg(test)]
mod tests;
