//! AMD KDS endorsement appraisal (57230 tables 9–11; SNP ABI 56860 §2.2/§7.3).
//! Endorsement SPLs must equal REPORTED_TCB, and current/committed/launch TCBs
//! must satisfy independent verifier minima. AMD's KDS revocation profile uses
//! an ARK-signed product CRL for ASK/ASVK; version-derived endorsement leaves
//! are governed by those issuer revocations and component security versions.
//! No caller-supplied certificate root, URL, or claimed security minimum is trusted.

use super::verify::pki;
use anyhow::{bail, ensure, Context, Result};
use der::{
    asn1::{Ia5StringRef, OctetStringRef},
    Decode,
};
use serde::{Deserialize, Serialize};
use x509_cert::Certificate;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnpCollateral {
    /// DER endorsement (VCEK/VLEK), ASK/ASVK, then pinned ARK, leaf first.
    pub certificate_chain: Vec<Vec<u8>>,
    /// Complete, current ARK-signed CRL for this product and endorsement role.
    pub product_crl: Vec<u8>,
}
impl SnpCollateral {
    pub(crate) fn validate_bounds(&self) -> Result<()> {
        ensure!(
            self.certificate_chain.len() == 3,
            "AMD collateral requires exactly three certificates"
        );
        let total = self
            .certificate_chain
            .iter()
            .try_fold(0usize, |n, c| n.checked_add(c.len()))
            .context("AMD chain length overflow")?;
        ensure!(
            total <= 256 * 1024 && self.certificate_chain.iter().all(|c| !c.is_empty()),
            "AMD certificate path size outside limit"
        );
        ensure!(
            !self.product_crl.is_empty() && self.product_crl.len() <= 4 * 1024 * 1024,
            "AMD product CRL size outside limit"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnpProduct {
    Milan,
    Genoa,
    Turin,
}
impl SnpProduct {
    pub fn name(self) -> &'static str {
        match self {
            Self::Milan => "Milan",
            Self::Genoa => "Genoa",
            Self::Turin => "Turin",
        }
    }
    fn pin(self) -> &'static str {
        match self {
            Self::Milan => super::roots::AMD_ARK_MILAN_SHA256,
            Self::Genoa => super::roots::AMD_ARK_GENOA_SHA256,
            Self::Turin => super::roots::AMD_ARK_TURIN_SHA256,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnpTcbVersion {
    /// Required only for Turin; must be None on Milan/Genoa.
    pub fmc: Option<u8>,
    pub boot_loader: u8,
    pub tee: u8,
    pub snp: u8,
    pub microcode: u8,
}
impl SnpTcbVersion {
    fn validate(self, product: SnpProduct) -> Result<()> {
        ensure!(
            self.fmc.is_some() == (product == SnpProduct::Turin),
            "AMD FMC/profile mismatch"
        );
        ensure!(
            self.fmc.unwrap_or(0) <= 127
                && self.boot_loader <= 127
                && self.tee <= 127
                && self.snp <= 127,
            "AMD component SPL exceeds documented 0..127 range"
        );
        Ok(())
    }
    fn at_least(self, floor: Self) -> bool {
        self.fmc.is_some() == floor.fmc.is_some()
            && self.fmc.unwrap_or(0) >= floor.fmc.unwrap_or(0)
            && self.boot_loader >= floor.boot_loader
            && self.tee >= floor.tee
            && self.snp >= floor.snp
            && self.microcode >= floor.microcode
    }
}

/// Independent operator policy. There is no default accepting version and no
/// option to permit debug, migration-agent ownership or provisional firmware.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnpTcbPolicy {
    pub product: SnpProduct,
    pub minimum_tcb: SnpTcbVersion,
    pub minimum_guest_svn: u32,
    pub expected_vmpl: u8,
    pub require_smt_disabled: bool,
    pub require_alias_check_complete: bool,
    pub minimum_launch_mitigation_vector: u64,
    pub minimum_current_mitigation_vector: u64,
    /// Exact authenticated CSP IDs authorized to supply VLEK endorsements.
    /// Empty means VLEK evidence is unacceptable. Does not affect VCEK reports.
    pub allowed_vlek_csp_ids: Vec<String>,
}
impl SnpTcbPolicy {
    pub(crate) fn validate(&self) -> Result<()> {
        self.minimum_tcb.validate(self.product)?;
        ensure!(
            self.minimum_tcb.boot_loader != 0
                || self.minimum_tcb.tee != 0
                || self.minimum_tcb.snp != 0
                || self.minimum_tcb.microcode != 0
                || self.minimum_tcb.fmc.unwrap_or(0) != 0,
            "AMD minimum TCB cannot be all zero"
        );
        ensure!(self.expected_vmpl <= 3, "AMD expected VMPL outside 0..3");
        ensure!(
            self.allowed_vlek_csp_ids.len() <= 32,
            "too many AMD CSP IDs"
        );
        let mut seen = std::collections::HashSet::new();
        for id in &self.allowed_vlek_csp_ids {
            ensure!(
                !id.is_empty() && id.len() <= 256 && id.bytes().all(|b| (0x21..=0x7e).contains(&b)),
                "invalid AMD CSP ID"
            );
            ensure!(seen.insert(id), "duplicate AMD CSP ID");
        }
        Ok(())
    }
}

pub(crate) fn appraise_snp(
    raw: &[u8],
    collateral: &SnpCollateral,
    policy: &SnpTcbPolicy,
    now: u64,
) -> Result<()> {
    collateral.validate_bounds()?;
    policy.validate()?;
    ensure!(
        raw.len() >= 1184 && raw.len() <= 8 * 1024 * 1024,
        "AMD report length outside limit"
    );
    let certs = pki::validate_chain(
        &collateral.certificate_chain,
        policy.product.pin(),
        now,
        pki::Curve::AmdEndorsement,
    )?;
    pki::check_crl(&collateral.product_crl, &certs[1], &certs[2], now)?;
    let vlek = ((le32(raw, 0x48) >> 2) & 7) == 1;
    let role = if vlek { "SEV-VLEK" } else { "SEV" };
    // AMD issuer CNs distinguish the VCEK and VLEK certificate hierarchies.
    let expected_issuer = format!("{role}-{}", policy.product.name());
    ensure!(
        common_name(&certs[1])? == expected_issuer,
        "AMD endorsement issuer role/product mismatch"
    );
    ensure!(
        common_name(&certs[0])? == if vlek { "SEV-VLEK" } else { "SEV-VCEK" },
        "AMD endorsement leaf role mismatch"
    );
    ensure!(
        certs[0].signature_algorithm.oid.to_string() == "1.2.840.113549.1.1.10",
        "AMD endorsement requires RSA-PSS SHA384"
    );
    let endorsed = endorsement(&certs[0], policy.product, vlek, policy)?;
    appraise_claims(raw, policy, endorsed)?;
    Ok(())
}

fn common_name(cert: &Certificate) -> Result<String> {
    let mut names = cert
        .tbs_certificate
        .subject
        .0
        .iter()
        .flat_map(|rdn| rdn.0.iter())
        .filter(|attr| attr.oid.to_string() == "2.5.4.3");
    let attr = names.next().context("AMD certificate missing commonName")?;
    ensure!(
        names.next().is_none(),
        "AMD certificate duplicate commonName"
    );
    let v = std::str::from_utf8(attr.value.value())?;
    ensure!(v.is_ascii(), "non-ASCII AMD certificate commonName");
    Ok(v.to_owned())
}

struct Endorsement {
    tcb: SnpTcbVersion,
    hwid: Option<Vec<u8>>,
    stepping: Option<u8>,
}
fn endorsement(
    cert: &Certificate,
    product: SnpProduct,
    vlek: bool,
    policy: &SnpTcbPolicy,
) -> Result<Endorsement> {
    let mut map = std::collections::BTreeMap::new();
    for ext in cert.tbs_certificate.extensions.iter().flatten() {
        let oid = ext.extn_id.to_string();
        if let Some(suffix) = oid.strip_prefix("1.3.6.1.4.1.3704.1.") {
            ensure!(!ext.critical, "unexpected critical AMD KDS extension");
            ensure!(
                map.insert(suffix.to_owned(), ext.extn_value.as_bytes())
                    .is_none(),
                "duplicate AMD KDS extension"
            );
        }
    }
    let expected: &[&str] = if product == SnpProduct::Turin {
        &[
            "1", "2", "3.9", "3.1", "3.2", "3.3", "3.5", "3.6", "3.7", "3.8",
        ]
    } else {
        &[
            "1", "2", "3.1", "3.2", "3.3", "3.4", "3.5", "3.6", "3.7", "3.8",
        ]
    };
    ensure!(
        map.len() == expected.len() + 1 && expected.iter().all(|k| map.contains_key(*k)),
        "AMD KDS extension set mismatch"
    );
    let integer =
        |key: &str| -> Result<u8> { Ok(u8::from_der(map.get(key).context("missing AMD SPL")?)?) };
    ensure!(
        integer("1")? == u8::from(product == SnpProduct::Turin),
        "AMD KDS structure version mismatch"
    );
    let product_name = Ia5StringRef::from_der(map["2"])?.as_str().to_owned();
    // VCEK productName includes the stepping; VLEK is product-wide. Exact
    // stepping is authenticated by the certificate; no manufacturing-error bypass.
    if vlek {
        ensure!(product_name == product.name(), "AMD VLEK product mismatch");
    } else {
        let suffix = product_name
            .strip_prefix(&format!("{}-", product.name()))
            .context("AMD VCEK product/stepping missing")?;
        ensure!(
            suffix.len() == 2
                && suffix.as_bytes()[0].is_ascii_uppercase()
                && suffix.as_bytes()[1].is_ascii_digit(),
            "invalid AMD VCEK stepping encoding"
        );
    }
    for key in ["3.4", "3.5", "3.6", "3.7"] {
        if map.contains_key(key) {
            ensure!(integer(key)? == 0, "AMD reserved SPL is nonzero");
        }
    }
    let tcb = SnpTcbVersion {
        fmc: if product == SnpProduct::Turin {
            Some(integer("3.9")?)
        } else {
            None
        },
        boot_loader: integer("3.1")?,
        tee: integer("3.2")?,
        snp: integer("3.3")?,
        microcode: integer("3.8")?,
    };
    tcb.validate(product)?;
    let hwid = if vlek {
        ensure!(
            map.contains_key("5") && !map.contains_key("4"),
            "AMD VLEK must have CSP ID and no HWID"
        );
        let csp = Ia5StringRef::from_der(map["5"])?;
        ensure!(
            policy
                .allowed_vlek_csp_ids
                .iter()
                .any(|id| id == csp.as_str()),
            "AMD VLEK CSP is not enrolled"
        );
        None
    } else {
        ensure!(
            map.contains_key("4") && !map.contains_key("5"),
            "AMD VCEK must have HWID and no CSP ID"
        );
        let expected_length = if product == SnpProduct::Turin { 8 } else { 64 };
        let bytes = map["4"];
        // AMD KDS historically emits bare octets; newer DER OCTET STRING
        // encoding carries the same fixed-width HWID. The two lengths differ.
        let hwid = if bytes.len() == expected_length {
            bytes.to_vec()
        } else {
            OctetStringRef::from_der(bytes)?.as_bytes().to_vec()
        };
        ensure!(
            hwid.len() == expected_length && hwid.iter().any(|b| *b != 0),
            "AMD invalid/zero HWID"
        );
        Some(hwid)
    };
    let stepping = if vlek {
        None
    } else {
        Some(product_name.as_bytes()[product_name.len() - 1] - b'0')
    };
    Ok(Endorsement {
        tcb,
        hwid,
        stepping,
    })
}

fn appraise_claims(raw: &[u8], policy: &SnpTcbPolicy, endorsed: Endorsement) -> Result<()> {
    let version = le32(raw, 0);
    ensure!(matches!(version, 2 | 5), "unsupported AMD report version");
    if version == 2 {
        ensure!(
            policy.product != SnpProduct::Turin && raw[0x188..0x1a0].iter().all(|b| *b == 0),
            "AMD legacy report/profile mismatch"
        );
    } else {
        let expected = match (raw[0x188], raw[0x189]) {
            (0x19, 0x00..=0x0f) => SnpProduct::Milan,
            (0x19, 0x10..=0x1f) => SnpProduct::Genoa,
            (0x1a, 0x00..=0x1f) => SnpProduct::Turin,
            _ => bail!("unsupported AMD CPUID family/model"),
        };
        ensure!(
            expected == policy.product,
            "AMD CPUID/product policy mismatch"
        );
        if let Some(stepping) = endorsed.stepping {
            ensure!(
                raw[0x18a] == stepping,
                "AMD certificate/report stepping mismatch"
            );
        }
        ensure!(
            raw[0x18b..0x1a0].iter().all(|b| *b == 0),
            "AMD reserved CPUID bytes nonzero"
        );
    }
    let key_info = le32(raw, 0x48);
    ensure!(
        key_info & !0x1f == 0 && key_info & 2 == 0 && ((key_info >> 2) & 7) <= 1,
        "AMD invalid/masked signing key"
    );
    if let Some(hwid) = endorsed.hwid {
        ensure!(
            raw[0x1a0..0x1a0 + hwid.len()] == hwid
                && raw[0x1a0 + hwid.len()..0x1e0].iter().all(|b| *b == 0),
            "AMD VCEK HWID does not match signed CHIP_ID"
        );
    }
    let reported = report_tcb(raw, 0x180, policy.product)?;
    let current = report_tcb(raw, 0x38, policy.product)?;
    let committed = report_tcb(raw, 0x1e0, policy.product)?;
    let launch = report_tcb(raw, 0x1f0, policy.product)?;
    ensure!(
        reported == endorsed.tcb,
        "AMD endorsement SPLs differ from signed REPORTED_TCB"
    );
    ensure!(
        current.at_least(reported) && committed.at_least(reported),
        "AMD reported TCB exceeds installed/committed TCB"
    );
    ensure!(
        current == committed && raw[0x1e8..0x1eb] == raw[0x1ec..0x1ef],
        "AMD provisional firmware is unacceptable"
    );
    ensure!(
        [reported, current, committed, launch]
            .iter()
            .all(|t| t.at_least(policy.minimum_tcb)),
        "AMD component TCB below policy minimum"
    );
    ensure!(
        le32(raw, 4) >= policy.minimum_guest_svn,
        "AMD guest SVN below policy minimum"
    );
    ensure!(
        le32(raw, 0x30) == u32::from(policy.expected_vmpl),
        "AMD VMPL mismatch"
    );
    let guest_policy = le64(raw, 8);
    ensure!(guest_policy & (1 << 19) == 0, "AMD debug-enabled guest");
    ensure!(
        guest_policy & (1 << 18) == 0,
        "AMD migration-agent guest policy is unsupported"
    );
    ensure!(
        guest_policy & (1 << 17) != 0 && guest_policy >> 26 == 0,
        "AMD guest policy reserved bits invalid"
    );
    let platform_info = le64(raw, 0x40);
    ensure!(
        platform_info & !0xbf == 0,
        "AMD platform info reserved bits nonzero"
    );
    if policy.require_smt_disabled {
        ensure!(
            platform_info & 1 == 0 && guest_policy & (1 << 16) == 0,
            "AMD SMT is enabled/permitted"
        );
    }
    if policy.require_alias_check_complete {
        ensure!(
            version >= 3 && platform_info & (1 << 5) != 0,
            "AMD alias-check mitigation missing"
        );
    }
    if version == 2 {
        ensure!(
            policy.minimum_launch_mitigation_vector == 0
                && policy.minimum_current_mitigation_vector == 0,
            "AMD legacy report lacks required mitigation vectors"
        );
        ensure!(
            raw[0x1f8..0x2a0].iter().all(|b| *b == 0),
            "AMD legacy reserved report bytes nonzero"
        );
    } else {
        ensure!(
            le64(raw, 0x1f8) & policy.minimum_launch_mitigation_vector
                == policy.minimum_launch_mitigation_vector,
            "AMD launch mitigation vector lacks required bits"
        );
        ensure!(
            le64(raw, 0x200) & policy.minimum_current_mitigation_vector
                == policy.minimum_current_mitigation_vector,
            "AMD current mitigation vector lacks required bits"
        );
        ensure!(
            raw[0x208..0x2a0].iter().all(|b| *b == 0),
            "AMD reserved report bytes nonzero"
        );
    }
    ensure!(
        raw[0x4c..0x50].iter().all(|b| *b == 0) && raw[0x1eb] == 0 && raw[0x1ef] == 0,
        "AMD reserved report bytes nonzero"
    );
    Ok(())
}
fn report_tcb(raw: &[u8], offset: usize, product: SnpProduct) -> Result<SnpTcbVersion> {
    let b = &raw[offset..offset + 8];
    let tcb = if product == SnpProduct::Turin {
        ensure!(b[4..7] == [0; 3], "AMD reserved Turin TCB bytes nonzero");
        SnpTcbVersion {
            fmc: Some(b[0]),
            boot_loader: b[1],
            tee: b[2],
            snp: b[3],
            microcode: b[7],
        }
    } else {
        ensure!(b[2..6] == [0; 4], "AMD reserved TCB bytes nonzero");
        SnpTcbVersion {
            fmc: None,
            boot_loader: b[0],
            tee: b[1],
            snp: b[6],
            microcode: b[7],
        }
    };
    tcb.validate(product)?;
    Ok(tcb)
}
fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn le64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    const NOW: u64 = 1_791_849_600;
    const REPORT: &[u8] =
        include_bytes!("../../testdata/snp-collateral/google-milan-debug-report.bin");
    fn collateral() -> SnpCollateral {
        let mut chain =
            vec![include_bytes!("../../testdata/snp-collateral/google-milan-vcek.der").to_vec()];
        chain.extend(
            pki::parse_pem_chain(include_bytes!(
                "../../testdata/snp-collateral/amd-milan-chain.pem"
            ))
            .unwrap(),
        );
        SnpCollateral {
            certificate_chain: chain,
            product_crl: include_bytes!("../../testdata/snp-collateral/amd-milan-2026-09.crl")
                .to_vec(),
        }
    }
    fn policy() -> SnpTcbPolicy {
        SnpTcbPolicy {
            product: SnpProduct::Milan,
            minimum_tcb: SnpTcbVersion {
                fmc: None,
                boot_loader: 2,
                tee: 0,
                snp: 5,
                microcode: 68,
            },
            minimum_guest_svn: 0,
            expected_vmpl: 0,
            require_smt_disabled: false,
            require_alias_check_complete: false,
            minimum_launch_mitigation_vector: 0,
            minimum_current_mitigation_vector: 0,
            allowed_vlek_csp_ids: vec![],
        }
    }
    fn leaf() -> Certificate {
        Certificate::from_der(&collateral().certificate_chain[0]).unwrap()
    }

    #[test]
    fn authentic_amd_endorsement_chain_and_crl_verify_but_debug_report_fails_admission() {
        let c = collateral();
        let p = policy();
        let chain = pki::validate_chain(
            &c.certificate_chain,
            p.product.pin(),
            NOW,
            pki::Curve::AmdEndorsement,
        )
        .unwrap();
        pki::check_crl(&c.product_crl, &chain[1], &chain[2], NOW).unwrap();
        let err = appraise_snp(REPORT, &c, &p, NOW).unwrap_err().to_string();
        assert!(err.contains("debug-enabled"), "{err}");
    }

    #[test]
    fn authentic_amd_crl_expires_and_mutated_crl_signature_fails() {
        let c = collateral();
        let chain = pki::validate_chain(
            &c.certificate_chain,
            SnpProduct::Milan.pin(),
            NOW,
            pki::Curve::AmdEndorsement,
        )
        .unwrap();
        assert!(pki::check_crl(&c.product_crl, &chain[1], &chain[2], NOW + 60 * 86400).is_err());
        assert!(pki::check_crl(&c.product_crl, &chain[1], &chain[2], 1_600_000_000).is_err());
        let mut bad = c.product_crl;
        *bad.last_mut().unwrap() ^= 1;
        assert!(pki::check_crl(&bad, &chain[1], &chain[2], NOW).is_err());
    }

    #[test]
    fn authenticated_endorsement_values_bind_hwid_and_each_reported_spl() {
        let p = policy();
        // Claim-only test: clearing the captured debug bit does NOT create a
        // valid signed report; full quote verification must still reject it.
        let mut claims = REPORT.to_vec();
        claims[10] &= !8;
        appraise_claims(
            &claims,
            &p,
            endorsement(&leaf(), p.product, false, &p).unwrap(),
        )
        .unwrap();
        for offset in [0x1a0, 0x180, 0x181, 0x186, 0x187, 0x30, 0x48, 0x1e0, 0x1f0] {
            let mut bad = claims.clone();
            if offset == 0x1f0 {
                bad[offset] = 1;
            } else {
                bad[offset] ^= if offset == 0x48 { 2 } else { 1 };
            }
            assert!(
                appraise_claims(
                    &bad,
                    &p,
                    endorsement(&leaf(), p.product, false, &p).unwrap()
                )
                .is_err(),
                "offset {offset:#x}"
            );
        }
        let mut stronger = p.clone();
        stronger.minimum_tcb.snp += 1;
        assert!(appraise_claims(
            &claims,
            &stronger,
            endorsement(&leaf(), p.product, false, &p).unwrap()
        )
        .is_err());
        stronger = p.clone();
        stronger.require_alias_check_complete = true;
        assert!(appraise_claims(
            &claims,
            &stronger,
            endorsement(&leaf(), p.product, false, &p).unwrap()
        )
        .is_err());
        stronger = p.clone();
        stronger.minimum_launch_mitigation_vector = 1;
        assert!(appraise_claims(
            &claims,
            &stronger,
            endorsement(&leaf(), p.product, false, &p).unwrap()
        )
        .is_err());
    }

    #[test]
    fn malformed_amd_extensions_and_untrusted_minima_are_rejected() {
        use der::{asn1::OctetString, Encode};
        let p = policy();
        for oid in [
            "1.3.6.1.4.1.3704.1.1",
            "1.3.6.1.4.1.3704.1.3.4",
            "1.3.6.1.4.1.3704.1.2",
        ] {
            let mut cert = leaf();
            let ext = cert
                .tbs_certificate
                .extensions
                .as_mut()
                .unwrap()
                .iter_mut()
                .find(|e| e.extn_id.to_string() == oid)
                .unwrap();
            ext.extn_value = OctetString::new(1u8.to_der().unwrap()).unwrap();
            assert!(endorsement(&cert, p.product, false, &p).is_err());
        }
        let mut p = p;
        p.minimum_tcb = SnpTcbVersion {
            fmc: None,
            boot_loader: 0,
            tee: 0,
            snp: 0,
            microcode: 0,
        };
        assert!(p.validate().is_err());
        let text = serde_json::to_string(&collateral())
            .unwrap()
            .replace("\"product_crl\":", "\"minimum_tcb\":0,\"product_crl\":");
        assert!(serde_json::from_str::<SnpCollateral>(&text).is_err());
    }

    #[test]
    fn turin_profile_uses_epyc_cpuid_models_and_binds_certificate_stepping() {
        // Claim-parser unit data only: this array is unsigned and cannot pass
        // the public quote/admission verifier. AMD 58251/58730 define these FMS.
        let mut p = policy();
        p.product = SnpProduct::Turin;
        p.minimum_tcb = SnpTcbVersion {
            fmc: Some(1),
            boot_loader: 2,
            tee: 3,
            snp: 4,
            microcode: 5,
        };
        let mut raw = vec![0u8; 1184];
        raw[0..4].copy_from_slice(&5u32.to_le_bytes());
        raw[8..16].copy_from_slice(&(1u64 << 17).to_le_bytes());
        raw[0x188] = 0x1a;
        raw[0x1a0..0x1a8].fill(42);
        for offset in [0x38, 0x180, 0x1e0, 0x1f0] {
            raw[offset..offset + 8].copy_from_slice(&[1, 2, 3, 4, 0, 0, 0, 5]);
        }
        for (model, stepping) in [(2, 1), (0x11, 0)] {
            raw[0x189] = model;
            raw[0x18a] = stepping;
            let endorsed = || Endorsement {
                tcb: p.minimum_tcb,
                hwid: Some(vec![42; 8]),
                stepping: Some(stepping),
            };
            appraise_claims(&raw, &p, endorsed()).unwrap();
            let mut bad = raw.clone();
            bad[0x18a] ^= 1;
            assert!(appraise_claims(&bad, &p, endorsed()).is_err());
            for (family, model) in [(0x19, 2), (0x1a, 0x90), (0x1a, 0x20), (0, 0)] {
                let mut bad = raw.clone();
                bad[0x188] = family;
                bad[0x189] = model;
                assert!(appraise_claims(&bad, &p, endorsed()).is_err());
            }
        }
    }

    #[test]
    fn turin_tcb_layout_is_distinct_and_componentwise() {
        let mut data = [0u8; 8];
        data.copy_from_slice(&[7, 8, 9, 10, 0, 0, 0, 222]);
        assert_eq!(
            report_tcb(&data, 0, SnpProduct::Turin).unwrap(),
            SnpTcbVersion {
                fmc: Some(7),
                boot_loader: 8,
                tee: 9,
                snp: 10,
                microcode: 222
            }
        );
        assert!(report_tcb(&data, 0, SnpProduct::Milan).is_err());
        data[5] = 1;
        assert!(report_tcb(&data, 0, SnpProduct::Turin).is_err());
    }
}
