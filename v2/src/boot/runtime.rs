//! CoCo AAEL TCG2 events measured into TDX RTMR3.
//!
//! The profile authenticates the complete tagged event, including the tag and
//! byte length. Descriptions are claims made by the approved measuring agent;
//! interpreting their application-specific content needs an independent policy.
use super::{
    hash, AuthenticatedRegisters, BootError, Event, EventLog, LogKind, ParseLimits,
    VerifiedBootLog, TPM_ALG_SHA384,
};
use serde::{Deserialize, Serialize};

pub const COCO_AAEL_PATH: &str = "/run/attestation-agent/eventlog";
pub const MAX_RUNTIME_EVENT_BYTES: usize = 64 * 1024;
const AAEL_TAG: u32 = 0x4141454c;
const EV_EVENT_TAG: u32 = 6;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeProfile {
    CocoAaelTcg2,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeEvent {
    pub domain: String,
    pub operation: String,
    pub content: String,
}
impl RuntimeEvent {
    fn validate(&self) -> Result<(), BootError> {
        if self.domain.is_empty()
            || self.operation.is_empty()
            || self.content.is_empty()
            || self
                .domain
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
            || self
                .operation
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
            || self.content.chars().any(char::is_control)
            || self
                .domain
                .len()
                .saturating_add(self.operation.len())
                .saturating_add(self.content.len())
                .saturating_add(10)
                > MAX_RUNTIME_EVENT_BYTES
        {
            return Err(BootError::Runtime("invalid or oversized AAEL fields"));
        }
        Ok(())
    }
}

/// Exact, ordered application events expected by the verifier. No JSON inside
/// `content` is interpreted, merged, normalized, or allowed to supply policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimePolicy {
    pub profile: RuntimeProfile,
    pub expected_events: Vec<RuntimeEvent>,
}
impl RuntimePolicy {
    pub fn validate(&self) -> Result<(), BootError> {
        if self.expected_events.len() > ParseLimits::default().max_events {
            return Err(BootError::Limit("runtime policy event count"));
        }
        let mut bytes = 0usize;
        for event in &self.expected_events {
            event.validate()?;
            bytes = bytes
                .saturating_add(event.domain.len())
                .saturating_add(event.operation.len())
                .saturating_add(event.content.len())
                .saturating_add(10);
        }
        if bytes > ParseLimits::default().max_log_bytes {
            return Err(BootError::Limit("runtime policy bytes"));
        }
        Ok(())
    }
}

pub(super) fn parse_aael(event: &Event) -> Result<RuntimeEvent, BootError> {
    let data = &event.untrusted_event_data;
    if event.register_index != 4
        || event.reported_event_type != EV_EVENT_TAG
        || event.digests.len() != 1
        || event
            .digests
            .get(&TPM_ALG_SHA384)
            .is_none_or(|d| d.len() != 48)
        || data.len() < 8
        || data.len() > MAX_RUNTIME_EVENT_BYTES
    {
        return Err(BootError::Runtime(
            "expected bounded SHA384 AAEL EV_EVENT_TAG in MRIndex4",
        ));
    }
    if u32::from_le_bytes(data[..4].try_into().unwrap()) != AAEL_TAG
        || u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize != data.len() - 8
    {
        return Err(BootError::Runtime("AAEL tag or length mismatch"));
    }
    let text =
        std::str::from_utf8(&data[8..]).map_err(|_| BootError::Runtime("AAEL is not UTF8"))?;
    let mut parts = text.splitn(3, ' ');
    let record = RuntimeEvent {
        domain: parts.next().unwrap_or("").into(),
        operation: parts.next().unwrap_or("").into(),
        content: parts.next().unwrap_or("").into(),
    };
    record.validate()?;
    Ok(record)
}

/// Typed authenticated runtime statements. Construction requires all four
/// RTMRs from the platform verifier and exact independent event policy.
#[derive(Debug, Serialize)]
pub struct VerifiedRuntimeLog {
    profile: RuntimeProfile,
    events: Vec<RuntimeEvent>,
    event_indices: Vec<usize>,
    rtmr3_hex: String,
}
impl VerifiedRuntimeLog {
    pub fn events(&self) -> &[RuntimeEvent] {
        &self.events
    }
    pub fn event_indices(&self) -> &[usize] {
        &self.event_indices
    }
    pub fn rtmr3_hex(&self) -> &str {
        &self.rtmr3_hex
    }
}

impl EventLog {
    pub fn verify_tdx_runtime(
        &self,
        expected: &AuthenticatedRegisters,
        policy: &RuntimePolicy,
    ) -> Result<(VerifiedBootLog, VerifiedRuntimeLog), BootError> {
        policy.validate()?;
        if self.kind() != LogKind::TdxCcel || expected.kind != LogKind::TdxCcel {
            return Err(BootError::PlatformMismatch);
        }
        if expected.values.len() != 4
            || (0..4).any(|i| {
                expected
                    .values
                    .get(&(TPM_ALG_SHA384, i))
                    .is_none_or(|d| d.len() != 48)
            })
        {
            return Err(BootError::InvalidRegisters(
                "runtime appraisal requires all four authenticated RTMRs",
            ));
        }
        let verified = self.verify(expected)?;
        let mut records = Vec::new();
        let mut indices = Vec::new();
        for (index, event) in self.events().iter().enumerate() {
            if event.register_index != 4 {
                continue;
            }
            let record = parse_aael(event)?;
            // TCG event metadata is mutable. The AAEL tag, encoded byte length,
            // and every UTF8 byte must themselves be the measured preimage.
            if verified.authenticated_digest(index, TPM_ALG_SHA384)?
                != hash(TPM_ALG_SHA384, &event.untrusted_event_data)?
            {
                return Err(BootError::ContentMismatch { event: index });
            }
            records.push(record);
            indices.push(index);
        }
        if records != policy.expected_events {
            return Err(BootError::Runtime(
                "runtime events differ from exact ordered policy",
            ));
        }
        let runtime = VerifiedRuntimeLog {
            profile: policy.profile,
            events: records,
            event_indices: indices,
            rtmr3_hex: hex::encode(&expected.values[&(TPM_ALG_SHA384, 3)]),
        };
        Ok((verified, runtime))
    }
}

/// Canonical collector-side concatenation. Remove only a validated erased CCEL
/// tail, retain its one SpecID header, and append standalone AAEL Event2 records.
/// This returns unverified evidence; the collector cannot authenticate RTMRs.
pub fn append_coco_aael(
    ccel: &[u8],
    aael: &[u8],
    limits: ParseLimits,
) -> Result<Vec<u8>, BootError> {
    let firmware = EventLog::parse_tdx_ccel(ccel, limits)?;
    let length = firmware
        .consumed_bytes()
        .checked_add(aael.len())
        .ok_or(BootError::Limit("combined log bytes"))?;
    if length > limits.max_log_bytes {
        return Err(BootError::Limit("combined log bytes"));
    }
    let mut combined = Vec::with_capacity(length);
    combined.extend_from_slice(&ccel[..firmware.consumed_bytes()]);
    combined.extend_from_slice(aael);
    let parsed = EventLog::parse_tdx_ccel_with_aael(&combined, limits)?;
    if parsed.consumed_bytes() != combined.len()
        || parsed.events()[firmware.events().len()..]
            .iter()
            .any(|e| e.register_index != 4)
    {
        return Err(BootError::Runtime(
            "standalone AAEL must contain only complete MRIndex4 records",
        ));
    }
    Ok(combined)
}

#[cfg(test)]
mod tests;
