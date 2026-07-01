//! Value X computation — the LATTE Layer 1 application measurement.
//!
//! Value X = sha384 over a deterministic manifest of the runner image.
//! This is the same regardless of which TEE platform hosts the runner.
//!
//! The manifest includes:
//! - Sorted hashes of all files in the runner directory
//! - The runner configuration (minus platform-specific env vars)
//! - The shim binary hash itself
//!
//! This means:
//! - User A builds the runner image → computes X from the manifest
//! - User B builds from the same source → gets the same X
//! - The TEE binds X into its attestation report
//! - Anyone can verify X matches across builds and running instances

use sha2::{Digest, Sha384};
use std::path::Path;

/// Compute Value X for a runner installation directory.
///
/// Walks the directory, hashes each file, sorts the (path, hash) pairs,
/// and produces a single sha384 over the sorted list.
pub fn compute_value_x(runner_dir: &Path) -> std::io::Result<[u8; 48]> {
    let mut entries: Vec<(String, [u8; 48])> = Vec::new();

    collect_file_hashes(runner_dir, runner_dir, &mut entries)?;
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut hasher = Sha384::new();

    // The shim binary is NOT included in Value X.
    // The shim is measured by the TEE hardware (MRTD/MEASUREMENT/PCR0).
    // Value X measures the runner payload — the files the shim manages.
    // See INVARIANT.md: check #1 covers the shim, check #2 covers Value X.

    // Hash all runner files in deterministic order
    for (rel_path, file_hash) in &entries {
        hasher.update(rel_path.as_bytes());
        hasher.update(b":");
        hasher.update(file_hash);
        hasher.update(b"\n");
    }

    Ok(hasher.finalize().into())
}

/// Recursively collect (relative_path, sha384_hash) for all files.
fn collect_file_hashes(
    base: &Path,
    dir: &Path,
    entries: &mut Vec<(String, [u8; 48])>,
) -> std::io::Result<()> {
    let mut dir_entries: Vec<_> = std::fs::read_dir(dir)?.filter_map(|e| e.ok()).collect();
    dir_entries.sort_by_key(|e| e.file_name());

    for entry in dir_entries {
        let path = entry.path();

        // Skip platform-specific runtime artifacts that vary across hosts
        if should_skip(&path) {
            continue;
        }

        if path.is_dir() {
            collect_file_hashes(base, &path, entries)?;
        } else if path.is_file() {
            let bytes = std::fs::read(&path)?;
            let hash = sha384(&bytes);
            let rel = path
                .strip_prefix(base)
                .unwrap()
                .to_string_lossy()
                .to_string();
            entries.push((rel, hash));
        }
    }
    Ok(())
}

/// Skip files that are expected to differ across platforms/runs
/// but don't affect the runner's behavior.
fn should_skip(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    // Skip logs, caches, runtime state, platform-specific configs
    matches!(
        name,
        "_diag" | "_work" | ".runner" | ".credentials" | ".env" | "svc.sh"
    ) || name.ends_with(".log")
        || name.ends_with(".pid")
}

fn sha384(data: &[u8]) -> [u8; 48] {
    let mut h = Sha384::new();
    h.update(data);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn value_x_is_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"hello").unwrap();
        fs::write(dir.path().join("b.txt"), b"world").unwrap();

        let x1 = compute_value_x(dir.path()).unwrap();
        let x2 = compute_value_x(dir.path()).unwrap();
        assert_eq!(x1, x2);
    }

    #[test]
    fn value_x_changes_with_content() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"hello").unwrap();
        let x1 = compute_value_x(dir.path()).unwrap();

        fs::write(dir.path().join("a.txt"), b"modified").unwrap();
        let x2 = compute_value_x(dir.path()).unwrap();
        assert_ne!(x1, x2);
    }
}
