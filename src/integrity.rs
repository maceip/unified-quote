//! Runtime integrity monitor — TOCTOU defense.
//!
//! After boot, the shim has a known-good Value X computed from the runner
//! directory. This module periodically re-computes Value X and detects
//! if anything on disk has changed.
//!
//! On TDX, it extends RTMR2 via configfs-tsm when a change is detected,
//! making the modification visible in all future attestation quotes.
//! On other platforms, it logs and flags the change.
//!
//! This prevents the TOCTOU attack where:
//! 1. TEE boots with clean code → gets attested
//! 2. Host swaps files on disk via I/O interception
//! 3. TEE continues running with tampered code
//!
//! Defense: if disk contents change, the integrity monitor catches it
//! and either alerts (all platforms) or extends the runtime measurement
//! register (TDX), making the change visible in the next quote.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

use crate::quote::value_x;

/// Integrity status shared across threads.
#[derive(Debug, Clone)]
pub struct IntegrityStatus {
    /// The boot-time Value X (known-good).
    pub boot_value_x: [u8; 48],
    /// The most recent re-computed Value X.
    pub current_value_x: [u8; 48],
    /// Whether the current value matches boot-time.
    pub integrity_ok: bool,
    /// Number of integrity checks performed.
    pub check_count: u64,
    /// Timestamp of last check.
    pub last_check: u64,
    /// Whether an RTMR extension was triggered.
    pub rtmr_extended: bool,
}

/// Shared integrity state.
pub type SharedIntegrity = Arc<RwLock<IntegrityStatus>>;

/// Start the background integrity monitor.
///
/// Returns a shared handle to the integrity status that can be
/// queried by the attestation endpoint.
pub fn start_integrity_monitor(
    runner_dir: &Path,
    boot_value_x: [u8; 48],
    interval: Duration,
    tampered: Arc<AtomicBool>,
) -> SharedIntegrity {
    let status = Arc::new(RwLock::new(IntegrityStatus {
        boot_value_x,
        current_value_x: boot_value_x,
        integrity_ok: true,
        check_count: 0,
        last_check: now_secs(),
        rtmr_extended: false,
    }));

    let status_clone = status.clone();
    let dir = runner_dir.to_path_buf();

    tokio::spawn(async move {
        let mut check_interval = tokio::time::interval(interval);
        loop {
            check_interval.tick().await;

            // Re-compute Value X from disk
            let current_x = match value_x::compute_value_x(&dir) {
                Ok(x) => x,
                Err(e) => {
                    eprintln!("[uq/integrity] ERROR re-computing Value X: {e}");
                    continue;
                }
            };

            let integrity_ok = current_x == boot_value_x;
            let mut guard = status_clone.write().await;
            guard.current_value_x = current_x;
            guard.integrity_ok = integrity_ok;
            guard.check_count += 1;
            guard.last_check = now_secs();

            if !integrity_ok {
                tampered.store(true, Ordering::SeqCst);
                eprintln!(
                    "[uq/integrity] ALERT: Value X changed!\n  boot: {}\n  now:  {}",
                    hex::encode(boot_value_x),
                    hex::encode(current_x)
                );

                // On TDX, extend RTMR2 to make the change visible in quotes
                if !guard.rtmr_extended {
                    if let Err(e) = extend_rtmr2(&current_x) {
                        eprintln!("[uq/integrity] Failed to extend RTMR2: {e}");
                    } else {
                        eprintln!("[uq/integrity] RTMR2 extended — future quotes will reflect the change");
                        guard.rtmr_extended = true;
                    }
                }
            }
        }
    });

    status
}

/// Attempt to extend RTMR2 with a hash of the changed Value X.
///
/// STATUS: NOT YET FUNCTIONAL — logs the intent but cannot actually extend.
///
/// On TDX, RTMR extension requires TDG.MR.RTMR.EXTEND TDCALL, which is
/// not exposed via configfs-tsm as of Linux 6.17. No userspace interface
/// exists yet. When available, this will write to a kernel interface.
///
/// Current defense: the `integrity_ok=false` flag in the EAT token signals
/// tampering to verifiers. This is a software-level signal, not a
/// hardware-level measurement change.
fn extend_rtmr2(new_value_x: &[u8; 48]) -> Result<(), String> {
    let hash = Sha256::digest(new_value_x);
    eprintln!(
        "[uq/integrity] RTMR2 extension NOT AVAILABLE (no kernel interface). \
         Tamper hash: {}. Defense: integrity_ok=false in EAT token.",
        hex::encode(hash)
    );
    // Return Err to signal that RTMR was NOT actually extended.
    // The caller should rely on integrity_ok flag instead.
    Err("RTMR extension not available — no kernel interface for TDG.MR.RTMR.EXTEND".into())
}

/// Generate a heartbeat quote — a fresh attestation on a timer.
///
/// This ensures verifiers can detect gaps in attestation coverage.
/// If the TEE stops producing heartbeats, something is wrong.
pub fn start_heartbeat(
    refresh_fn: Arc<dyn Fn() -> Result<crate::quote::UnifiedQuote, String> + Send + Sync>,
    quote_store: Arc<RwLock<Option<crate::quote::UnifiedQuote>>>,
    interval: Duration,
) {
    tokio::spawn(async move {
        let mut heartbeat = tokio::time::interval(interval);
        loop {
            heartbeat.tick().await;
            match refresh_fn() {
                Ok(q) => {
                    let ts = q.timestamp;
                    let mut guard = quote_store.write().await;
                    *guard = Some(q);
                    eprintln!("[uq/heartbeat] Quote refreshed at {ts}");
                }
                Err(e) => {
                    eprintln!("[uq/heartbeat] Failed to refresh: {e}");
                }
            }
        }
    });
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs()
}
