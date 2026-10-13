//! Certificate-authenticated NVIDIA device identity and firmware binding.
//!
//! Schemas are taken from NVIDIA's pinned `dice_tcb_info.h` and the published
//! Hopper/Blackwell certificate vectors. Both the legacy CompositeDeviceID
//! and the context-tagged DiceTcbInfo are parsed as complete DER structures.
//! Malformed encodings never fall back to extracting trailing digest bytes.

use anyhow::{ensure, Context, Result};
use der::{
    asn1::{Any, BitString, ObjectIdentifier, OctetString, Utf8StringRef},
    Decode, Encode, Sequence, Tag, Tagged,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use spki::SubjectPublicKeyInfoOwned;
use x509_cert::ext::pkix::{name::GeneralName, SubjectAltName};

use super::cert::ValidatedChain;

const LEGACY_TCB: &str = "2.23.133.5.4.1";
const DICE_TCB: &str = "2.23.133.5.4.1.1";
const DICE_UEID: &str = "2.23.133.5.4.4";
const DMTF_DEVICE_INFO: &str = "1.3.6.1.4.1.412.274.1";

/// Identity authenticated by the certificate chain, before revocation or RIM
/// appraisal. This type deliberately does not carry a device-admission verdict.
#[derive(Debug, Clone)]
pub struct DeviceCertificateIdentity {
    pub manufacturer: String,
    pub model: String,
    pub serial: String,
    /// DICE UEID if actually present. Never manufactured from an NVML UUID.
    pub ueid: Option<Vec<u8>>,
    /// Hash of the immediate device/BROM issuer's encoded SubjectPublicKeyInfo.
    pub device_key_sha256: [u8; 32],
    /// The first FWID is the firmware code digest; subsequent entries are
    /// preserved rather than silently discarded (e.g. Blackwell configuration).
    firmware_digests: Vec<[u8; 48]>,
    pub tcb_svn: Option<u32>,
    /// Operational state of the DICE target environment. Legacy certificates
    /// and masked-out properties remain unknown, rather than becoming `false`.
    pub operational_flags: Option<DiceOperationalFlags>,
}

/// TCG DICE Attestation Architecture v1.2 sections 6.1.1.1--6.1.1.2.
/// These names retain the specification's polarity: `true` means that the
/// named adverse condition is present. Bit 31 only fixes the encoding width.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationalFlag {
    NotConfigured,
    NotSecure,
    Recovery,
    Debug,
    NotReplayProtected,
    NotIntegrityProtected,
    NotRuntimeMeasured,
    NotImmutable,
    NotTcb,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiceOperationalFlags {
    pub not_configured: Option<bool>,
    pub not_secure: Option<bool>,
    pub recovery: Option<bool>,
    pub debug: Option<bool>,
    pub not_replay_protected: Option<bool>,
    pub not_integrity_protected: Option<bool>,
    pub not_runtime_measured: Option<bool>,
    pub not_immutable: Option<bool>,
    pub not_tcb: Option<bool>,
}

impl DiceOperationalFlags {
    fn parse(flags: &BitString, mask: Option<&BitString>) -> Result<Self> {
        ensure!(flags.bit_len() <= 32, "DICE flags exceed supported width");
        if let Some(mask) = mask {
            ensure!(
                mask.bit_len() <= 32,
                "DICE flags mask exceeds supported width"
            );
        }
        // ASN.1 numbers BIT STRING bits from the most significant bit. Named
        // bits omitted by DER's trailing-zero truncation are CLEAR, not absent.
        let bit = |value: &BitString, index: usize| {
            value
                .raw_bytes()
                .get(index / 8)
                .is_some_and(|b| b & (0x80 >> (index % 8)) != 0)
        };
        let meaningful = |index| mask.is_none_or(|m| bit(m, index));
        ensure!(
            (9..31).all(|index| !meaningful(index) || !bit(flags, index)),
            "unsupported DICE operational flag"
        );
        let state = |index| meaningful(index).then(|| bit(flags, index));
        Ok(Self {
            not_configured: state(0),
            not_secure: state(1),
            recovery: state(2),
            debug: state(3),
            not_replay_protected: state(4),
            not_integrity_protected: state(5),
            not_runtime_measured: state(6),
            not_immutable: state(7),
            not_tcb: state(8),
        })
    }

    pub fn get(&self, flag: OperationalFlag) -> Option<bool> {
        match flag {
            OperationalFlag::NotConfigured => self.not_configured,
            OperationalFlag::NotSecure => self.not_secure,
            OperationalFlag::Recovery => self.recovery,
            OperationalFlag::Debug => self.debug,
            OperationalFlag::NotReplayProtected => self.not_replay_protected,
            OperationalFlag::NotIntegrityProtected => self.not_integrity_protected,
            OperationalFlag::NotRuntimeMeasured => self.not_runtime_measured,
            OperationalFlag::NotImmutable => self.not_immutable,
            OperationalFlag::NotTcb => self.not_tcb,
        }
    }
}

impl DeviceCertificateIdentity {
    pub fn firmware_digests(&self) -> &[[u8; 48]] {
        &self.firmware_digests
    }

    /// Apply explicit relying-party requirements to authenticated DICE target
    /// state. A required property missing from the certificate or masked out
    /// always fails. This does not infer GPU CC mode from DICE flags, or infer
    /// these flags from GPU CC mode or from a matching firmware digest.
    pub fn require_security_flags(&self, required: &[(OperationalFlag, bool)]) -> Result<()> {
        let mut seen = std::collections::BTreeSet::new();
        for (flag, expected) in required {
            ensure!(
                seen.insert(flag),
                "duplicate DICE operational flag requirement"
            );
            let actual = self
                .operational_flags
                .as_ref()
                .and_then(|flags| flags.get(*flag))
                .with_context(|| format!("missing authenticated DICE operational flag {flag:?}"))?;
            ensure!(
                actual == *expected,
                "authenticated DICE operational flag {flag:?} violates policy"
            );
        }
        Ok(())
    }

    /// Compare field 20 from an already signature/nonce-verified NVIDIA opaque
    /// report. A missing field must be rejected by the caller, never supplied
    /// as an empty digest or recorded as a successful firmware match.
    pub fn verify_report_fwid(&self, signed_fwid: &[u8]) -> Result<()> {
        ensure!(signed_fwid.len() == 48, "report FWID must be SHA-384");
        ensure!(
            signed_fwid == self.firmware_digests[0],
            "report FWID does not match alias certificate firmware"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Sequence)]
struct Fwid {
    hash_alg: ObjectIdentifier,
    digest: OctetString,
}

#[derive(Clone, Debug, Sequence)]
struct CompositeDeviceId {
    version: u32,
    subject_public_key_info: SubjectPublicKeyInfoOwned,
    fwid: Fwid,
}

#[derive(Clone, Debug, Sequence)]
struct WrappedCompositeDeviceId {
    oid: ObjectIdentifier,
    value: CompositeDeviceId,
}

// TCG DICE Attestation Architecture v1.2 Appendix A's normative ASN.1 tags.
#[derive(Clone, Debug, Sequence)]
struct DiceTcbInfo {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    vendor: Option<String>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    model: Option<String>,
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    version: Option<String>,
    #[asn1(context_specific = "3", tag_mode = "IMPLICIT", optional = "true")]
    svn: Option<u32>,
    #[asn1(context_specific = "4", tag_mode = "IMPLICIT", optional = "true")]
    layer: Option<u32>,
    #[asn1(context_specific = "5", tag_mode = "IMPLICIT", optional = "true")]
    index: Option<u32>,
    #[asn1(context_specific = "6", tag_mode = "IMPLICIT", optional = "true")]
    fwids: Option<Vec<Fwid>>,
    #[asn1(context_specific = "7", tag_mode = "IMPLICIT", optional = "true")]
    flags: Option<BitString>,
    #[asn1(context_specific = "8", tag_mode = "IMPLICIT", optional = "true")]
    vendor_info: Option<OctetString>,
    #[asn1(context_specific = "9", tag_mode = "IMPLICIT", optional = "true")]
    device_type: Option<OctetString>,
    #[asn1(context_specific = "10", tag_mode = "IMPLICIT", optional = "true")]
    flags_mask: Option<BitString>,
    #[asn1(context_specific = "11", tag_mode = "IMPLICIT", optional = "true")]
    integrity_registers: Option<Vec<IntegrityRegister>>,
}

#[derive(Clone, Debug, Sequence)]
struct IntegrityRegister {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    register_name: Option<der::asn1::Ia5String>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    register_num: Option<u32>,
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT")]
    register_digests: Vec<Fwid>,
}

#[derive(Clone, Debug, Sequence)]
struct DiceUeid {
    ueid: OctetString,
}

pub fn certificate_identity(chain: &ValidatedChain) -> Result<DeviceCertificateIdentity> {
    let cert = chain.leaf();
    let issuer = chain
        .certificates()
        .get(1)
        .context("device chain has no BROM issuer")?;
    let (_, san) = cert
        .tbs_certificate
        .get::<SubjectAltName>()?
        .context("device alias certificate lacks DMTF identity SAN")?;
    let mut identities = san.0.iter().filter_map(|name| match name {
        GeneralName::OtherName(other) if other.type_id.to_string() == DMTF_DEVICE_INFO => {
            Some(other)
        }
        _ => None,
    });
    let identity = identities.next().context("missing DMTF device identity")?;
    ensure!(
        identities.next().is_none(),
        "duplicate DMTF device identity"
    );
    let text = identity.value.decode_as::<Utf8StringRef<'_>>()?;
    let parts: Vec<_> = text.as_str().split(':').collect();
    ensure!(
        parts.len() == 3 && parts[0] == "NVIDIA",
        "device identity manufacturer/format mismatch"
    );
    ensure!(
        !parts[1].is_empty()
            && parts[1].len() <= 32
            && parts[1]
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_'),
        "invalid authenticated device model"
    );
    ensure!(
        parts[2].len() == 16 && parts[2].bytes().all(|c| c.is_ascii_hexdigit()),
        "NVIDIA device serial must be a 64-bit hexadecimal identity"
    );
    ensure!(
        parts[2].bytes().any(|c| c != b'0'),
        "NVIDIA device serial is zero"
    );

    let extensions = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .context("device certificate has no extensions")?;
    let mut tcb = extensions
        .iter()
        .filter(|e| matches!(e.extn_id.to_string().as_str(), LEGACY_TCB | DICE_TCB));
    let extension = tcb
        .next()
        .context("device alias certificate lacks firmware identity")?;
    ensure!(
        tcb.next().is_none(),
        "ambiguous multiple device firmware identity extensions"
    );
    let raw = extension.extn_value.as_bytes();
    ensure!(raw.len() <= 8192, "device TCB extension exceeds size limit");
    let sequence = Any::from_der(raw)?;
    ensure!(
        sequence.tag() == Tag::Sequence,
        "device TCB extension is not a DER sequence"
    );
    let discriminator = sequence
        .value()
        .first()
        .copied()
        .context("empty device TCB extension")?;
    let (fwids, svn, operational_flags) = if extension.extn_id.to_string() == LEGACY_TCB
        && matches!(discriminator, 0x02 | 0x06)
    {
        let legacy = if discriminator == 0x02 {
            CompositeDeviceId::from_der(raw)?
        } else {
            let wrapped = WrappedCompositeDeviceId::from_der(raw)?;
            ensure!(
                wrapped.oid.to_string() == LEGACY_TCB,
                "CompositeDeviceID wrapper OID mismatch"
            );
            wrapped.value
        };
        ensure!(legacy.version == 1, "unsupported CompositeDeviceID version");
        ensure!(
            legacy.subject_public_key_info == issuer.tbs_certificate.subject_public_key_info,
            "CompositeDeviceID BROM public key differs from issuing certificate"
        );
        (vec![legacy.fwid], None, None)
    } else {
        let dice = DiceTcbInfo::from_der(raw).context("unsupported/malformed DiceTcbInfo")?;
        if let Some(vendor) = &dice.vendor {
            ensure!(
                vendor == "NVIDIA",
                "DICE vendor conflicts with certificate SAN"
            );
        }
        if let Some(model) = &dice.model {
            ensure!(
                model.split_ascii_whitespace().next() == Some(parts[1]),
                "DICE model conflicts with certificate SAN"
            );
        }
        for string in [&dice.vendor, &dice.model, &dice.version]
            .into_iter()
            .flatten()
        {
            ensure!(
                !string.is_empty() && string.len() <= 128 && !string.chars().any(char::is_control),
                "invalid DICE TCB text"
            );
        }
        ensure!(
            dice.flags.is_some() || dice.flags_mask.is_none(),
            "DICE flags mask without flags"
        );
        let flags = dice
            .flags
            .as_ref()
            .map(|flags| DiceOperationalFlags::parse(flags, dice.flags_mask.as_ref()))
            .transpose()?;
        // Integrity-register appraisal is outside this fixed GPU FWID profile.
        // Do not silently claim these extra measurements were checked.
        ensure!(
            dice.integrity_registers.is_none(),
            "DICE integrity-register profile is not supported"
        );
        (
            dice.fwids.context("DICE TCB has no firmware identifiers")?,
            dice.svn,
            flags,
        )
    };
    ensure!(
        !fwids.is_empty() && fwids.len() <= 16,
        "DICE firmware identifier count outside limit"
    );
    let mut firmware_digests = Vec::with_capacity(fwids.len());
    for fwid in fwids {
        ensure!(
            fwid.hash_alg.to_string() == "2.16.840.1.101.3.4.2.2",
            "GPU firmware identity must use SHA-384"
        );
        firmware_digests.push(
            fwid.digest
                .as_bytes()
                .try_into()
                .context("firmware identity digest is not 48 bytes")?,
        );
    }
    ensure!(
        firmware_digests[0] != [0; 48],
        "primary firmware digest is zero"
    );
    let ueid = extensions
        .iter()
        .find(|e| e.extn_id.to_string() == DICE_UEID)
        .map(|ext| -> Result<Vec<u8>> {
            let value = DiceUeid::from_der(ext.extn_value.as_bytes())?
                .ueid
                .into_bytes();
            // RFC 9711 treats the UEID as opaque bytes to consumers, with a bounded
            // 7..33-byte envelope. Do not infer manufacturer from its EUI bits.
            ensure!(
                (7..=33).contains(&value.len()),
                "DICE UEID size outside RFC 9711 limits"
            );
            Ok(value)
        })
        .transpose()?;
    Ok(DeviceCertificateIdentity {
        manufacturer: parts[0].to_owned(),
        model: parts[1].to_owned(),
        serial: parts[2].to_ascii_uppercase(),
        ueid,
        device_key_sha256: Sha256::digest(issuer.tbs_certificate.subject_public_key_info.to_der()?)
            .into(),
        firmware_digests,
        tcb_svn: svn,
        operational_flags,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dice_named_bits_use_asn1_order_and_preserve_unknown_masks() {
        let flags = BitString::from_bytes(&[0x90, 0, 0, 1]).unwrap();
        let states = DiceOperationalFlags::parse(&flags, None).unwrap();
        assert_eq!(states.not_configured, Some(true));
        assert_eq!(states.debug, Some(true));
        assert_eq!(states.not_secure, Some(false));
        assert_eq!(states.not_tcb, Some(false));

        let mask = BitString::from_bytes(&[0x40]).unwrap();
        let masked = DiceOperationalFlags::parse(&flags, Some(&mask)).unwrap();
        assert_eq!(masked.not_secure, Some(false));
        assert_eq!(masked.debug, None);
        assert_eq!(masked.not_configured, None);
        assert_eq!(masked.not_tcb, None);
    }

    #[test]
    fn dice_trailing_zeroes_fixed_width_and_unknown_flags() {
        // DER may omit trailing CLEAR named bits. Their meaning is still
        // false when the mask is absent, per section 6.1.1.1.
        let truncated = BitString::new(7, [0x80]).unwrap();
        let states = DiceOperationalFlags::parse(&truncated, None).unwrap();
        assert_eq!(states.debug, Some(false));
        let fixed = BitString::from_bytes(&[0x80, 0, 0, 1]).unwrap();
        assert_eq!(states, DiceOperationalFlags::parse(&fixed, None).unwrap());
        let unknown = BitString::from_bytes(&[0, 0x40, 0, 1]).unwrap();
        assert!(DiceOperationalFlags::parse(&unknown, None).is_err());
        let mask = BitString::from_bytes(&[0xff, 0x80]).unwrap();
        assert!(DiceOperationalFlags::parse(&unknown, Some(&mask)).is_ok());
        let too_wide = BitString::from_bytes(&[0; 5]).unwrap();
        assert!(DiceOperationalFlags::parse(&too_wide, None).is_err());
        assert!(DiceOperationalFlags::parse(&fixed, Some(&too_wide)).is_err());
    }
}
