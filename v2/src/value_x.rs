//! Value X: a directory tree hash used as the application-layer identity
//! across bountynet. Promoted from `main.rs` so consumers like
//! `bountynet-shadow`'s in-TEE agent can reuse the same primitive instead
//! of reimplementing it (and drifting).

use std::path::Path;

use sha2::{Digest, Sha384};

/// Directories to skip while hashing. These contain build artifacts,
/// dependency caches, VCS state, or IDE scratch that are not part of the
/// canonical source identity.
pub const SKIP_NAMES: &[&str] = &[".git", "target", "node_modules", ".DS_Store", "out"];

/// Compute the canonical source tree hash (Value X).
///
/// The hash is a Sha384 over a sorted list of `(relative_path, file_hash)`
/// pairs. Each entry is encoded as `path:hash\n` where `hash` is the
/// file's Sha384. Directories listed in [`SKIP_NAMES`] are elided.
///
/// Ordering is deterministic: entries are sorted by path before hashing,
/// so two runs against identical contents always produce the same digest
/// regardless of filesystem readdir order.
pub fn compute_tree_hash(dir: &Path) -> std::io::Result<[u8; 48]> {
    let mut entries: Vec<(String, [u8; 48])> = Vec::new();
    collect_hashes(dir, dir, &mut entries)?;
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut hasher = Sha384::new();
    for (path, hash) in &entries {
        hasher.update(path.as_bytes());
        hasher.update(b":");
        hasher.update(hash);
        hasher.update(b"\n");
    }
    Ok(hasher.finalize().into())
}

fn collect_hashes(
    base: &Path,
    dir: &Path,
    out: &mut Vec<(String, [u8; 48])>,
) -> std::io::Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let metadata = std::fs::symlink_metadata(&path)?;
        let file_type = metadata.file_type();

        if SKIP_NAMES.contains(&name) {
            continue;
        }

        if file_type.is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "source identity cannot include symlinks: {}",
                    path.display()
                ),
            ));
        }

        if file_type.is_dir() {
            collect_hashes(base, &path, out)?;
        } else if file_type.is_file() {
            let bytes = std::fs::read(&path)?;
            let hash: [u8; 48] = Sha384::digest(&bytes).into();
            let rel = path
                .strip_prefix(base)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            out.push((rel, hash));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_dir_hashes_deterministically() {
        let tmp = tempfile::tempdir().unwrap();
        let a = compute_tree_hash(tmp.path()).unwrap();
        let b = compute_tree_hash(tmp.path()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn file_change_changes_hash() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.txt"), b"one").unwrap();
        let a = compute_tree_hash(tmp.path()).unwrap();
        std::fs::write(tmp.path().join("a.txt"), b"two").unwrap();
        let b = compute_tree_hash(tmp.path()).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn skipped_dirs_dont_affect_hash() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.txt"), b"one").unwrap();
        let before = compute_tree_hash(tmp.path()).unwrap();
        std::fs::create_dir(tmp.path().join("target")).unwrap();
        std::fs::write(tmp.path().join("target").join("junk"), b"xxx").unwrap();
        let after = compute_tree_hash(tmp.path()).unwrap();
        assert_eq!(before, after);
    }
}
