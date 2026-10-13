pub mod roots;
#[cfg(feature = "sev-snp")]
pub mod snp_collateral;
#[cfg(feature = "tdx")]
pub mod tdx_collateral;
pub mod verify;

use serde::{Deserialize, Serialize};

/// TEE platform identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Platform {
    Nitro = 1,
    SevSnp = 2,
    Tdx = 3,
    /// SNP-endorsed Azure vTPM AK plus a fresh AK-signed quote.
    AzureSnpVtpm = 4,
    /// Direct SNP report plus an independently verified AWS NitroTPM document.
    AwsSnpNitroTpm = 5,
}
