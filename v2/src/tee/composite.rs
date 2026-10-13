//! Explicit compound CPU/TPM evidence profiles. A shared signed challenge binds
//! the evidence to one transaction; it does not prove physical co-location.
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

/// The profile is chosen by the caller, never inferred from evidence bytes.
#[derive(Debug, Clone, Default)]
pub enum CpuCollectionProfile {
    #[default]
    Direct,
    AzureSnpVtpm {
        pcr_indices: Vec<u8>,
    },
    AwsSnpNitroTpm,
}
impl CpuCollectionProfile {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Direct => Ok(()),
            Self::AzureSnpVtpm { pcr_indices } => {
                ensure!(
                    cfg!(feature = "sev-snp"),
                    "Azure collection requires sev-snp support"
                );
                ensure!(
                    !pcr_indices.is_empty()
                        && pcr_indices.len() <= 16
                        && pcr_indices.iter().all(|p| *p <= 15)
                        && pcr_indices.windows(2).all(|p| p[0] < p[1]),
                    "Azure PCR indices must be sorted, unique, and within 0..15"
                );
                Ok(())
            }
            Self::AwsSnpNitroTpm => {
                ensure!(
                    cfg!(all(feature = "sev-snp", feature = "nitro", unix)),
                    "AWS SNP/NitroTPM collection requires Unix and sev-snp,nitro support"
                );
                Ok(())
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsSnpNitroTpmEvidence {
    pub version: u16,
    pub snp_report: Vec<u8>,
    pub nitrotpm_document: Vec<u8>,
}
impl AwsSnpNitroTpmEvidence {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1,
            "unsupported AWS composite evidence version"
        );
        ensure!(
            (1184..=1024 * 1024).contains(&self.snp_report.len()),
            "SNP report size outside limit"
        );
        ensure!(
            !self.nitrotpm_document.is_empty() && self.nitrotpm_document.len() <= 64 * 1024,
            "NitroTPM document size outside limit"
        );
        Ok(())
    }
    pub fn from_json(raw: &[u8]) -> Result<Self> {
        ensure!(
            raw.len() <= 4 * 1024 * 1024,
            "AWS composite evidence exceeds byte limit"
        );
        let evidence: Self = serde_json::from_slice(raw)?;
        evidence.validate()?;
        Ok(evidence)
    }
}
