//! Explicit immutable-system-closure identity, separate from source-tree Value X
//! and from dm-verity's block-device Merkle tree. No directories are silently
//! excluded. Symlinks and nonregular files are rejected, including path parents.

use serde::Serialize;
use sha2::{Digest, Sha384};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum ClosureError {
    #[error("closure I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid closure path: {0}")]
    InvalidPath(String),
    #[error("closure exceeds {0} limit")]
    Limit(&'static str),
    #[error("closure file changed while being measured: {0}")]
    FileChanged(String),
    #[error("closure root does not match expected SHA-384 identity")]
    RootMismatch,
    #[error("secure closure filesystem traversal is unavailable on this platform")]
    UnsupportedPlatform,
}

#[derive(Clone, Copy, Debug)]
pub struct ClosureLimits {
    pub max_files: usize,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
}
impl Default for ClosureLimits {
    fn default() -> Self {
        Self {
            max_files: 100_000,
            max_file_bytes: 8 * 1024 * 1024 * 1024,
            max_total_bytes: 64 * 1024 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ClosureEntry {
    pub relative_path: String,
    pub length: u64,
    /// POSIX access and special bits. Ownership and timestamps are deliberately
    /// excluded for reproducibility; ownership policy needs a separate check.
    pub mode: u32,
    pub content_sha384: String,
}

/// Versioned encoding so callers cannot confuse this identity with the legacy
/// source-tree hash or dm-verity. Verification requires an externally pinned root.
#[derive(Debug, Serialize)]
pub struct ClosureManifest {
    format: &'static str,
    files: Vec<ClosureEntry>,
    root_sha384: String,
}

impl ClosureManifest {
    pub fn files(&self) -> &[ClosureEntry] {
        &self.files
    }
    pub fn root_sha384(&self) -> &str {
        &self.root_sha384
    }
    pub fn verify_expected_root(&self, expected: &[u8; 48]) -> Result<(), ClosureError> {
        if self.root_sha384 != hex::encode(expected) {
            return Err(ClosureError::RootMismatch);
        }
        Ok(())
    }
}

/// Measure an explicit list of regular files rooted under an immutable tree.
/// Every component is opened with O_NOFOLLOW, files stream through SHA-384, and
/// before/after metadata detects changes during the read. The caller must arrange
/// the read-only mount; measuring a mutable tree cannot establish future integrity.
pub fn measure_closure(
    root: &Path,
    files: &[PathBuf],
    limits: ClosureLimits,
) -> Result<ClosureManifest, ClosureError> {
    if files.is_empty() || files.len() > limits.max_files {
        return Err(ClosureError::Limit("file count"));
    }
    let mut names = BTreeSet::new();
    for path in files {
        let text = path
            .to_str()
            .ok_or_else(|| ClosureError::InvalidPath("non-UTF-8 path".into()))?;
        if text.is_empty()
            || text.len() > 4096
            || text.contains('\0')
            || text.contains('\\')
            || text
                .split('/')
                .any(|p| p.is_empty() || p == "." || p == "..")
            || path
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
        {
            return Err(ClosureError::InvalidPath(text.into()));
        }
        if !names.insert(text.to_owned()) {
            return Err(ClosureError::InvalidPath(format!("duplicate {text}")));
        }
    }
    let root = open_root(root)?;
    let mut total = 0u64;
    let mut entries = Vec::with_capacity(names.len());
    let mut leaves = Vec::with_capacity(names.len());
    for name in names {
        let mut file = open_beneath(&root, Path::new(&name))?;
        let before = file.metadata()?;
        if !before.is_file() {
            return Err(ClosureError::InvalidPath(format!("nonregular file {name}")));
        }
        if before.len() > limits.max_file_bytes {
            return Err(ClosureError::Limit("file bytes"));
        }
        total = total
            .checked_add(before.len())
            .ok_or(ClosureError::Limit("total bytes"))?;
        if total > limits.max_total_bytes {
            return Err(ClosureError::Limit("total bytes"));
        }
        let mut hasher = Sha384::new();
        let mut buffer = [0u8; 64 * 1024];
        let mut read = 0u64;
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            read = read
                .checked_add(count as u64)
                .ok_or(ClosureError::Limit("file bytes"))?;
            if read > before.len() {
                return Err(ClosureError::FileChanged(name));
            }
            hasher.update(&buffer[..count]);
        }
        let after = file.metadata()?;
        if read != before.len() || !same_metadata(&before, &after) {
            return Err(ClosureError::FileChanged(name));
        }
        let content_hash: [u8; 48] = hasher.finalize().into();
        let mode = file_mode(&before);
        let mut leaf = Sha384::new();
        leaf.update(b"uq-system-closure-v1\0leaf\0");
        leaf.update((name.len() as u32).to_be_bytes());
        leaf.update(name.as_bytes());
        leaf.update(mode.to_be_bytes());
        leaf.update(read.to_be_bytes());
        leaf.update(content_hash);
        leaves.push(<[u8; 48]>::from(leaf.finalize()));
        entries.push(ClosureEntry {
            relative_path: name,
            length: read,
            mode,
            content_sha384: hex::encode(content_hash),
        });
    }
    while leaves.len() > 1 {
        leaves = leaves
            .chunks(2)
            .map(|pair| {
                let mut branch = Sha384::new();
                branch.update(b"uq-system-closure-v1\0branch\0");
                branch.update([pair.len() as u8]);
                for value in pair {
                    branch.update(value);
                }
                <[u8; 48]>::from(branch.finalize())
            })
            .collect();
    }
    let mut root_hash = Sha384::new();
    root_hash.update(b"uq-system-closure-v1\0root\0");
    root_hash.update((entries.len() as u64).to_be_bytes());
    root_hash.update(leaves[0]);
    Ok(ClosureManifest {
        format: "uq-system-closure-v1",
        files: entries,
        root_sha384: hex::encode(root_hash.finalize()),
    })
}

#[cfg(unix)]
fn open_root(root: &Path) -> Result<File, ClosureError> {
    use std::os::unix::fs::OpenOptionsExt;
    // Open each component from / or . so intermediate root symlinks cannot
    // evade O_NOFOLLOW on only the final root component.
    let base = if root.is_absolute() {
        Path::new("/")
    } else {
        Path::new(".")
    };
    let mut current = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(base)?;
    for component in root.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => current = open_child(&current, name, true)?,
            _ => return Err(ClosureError::InvalidPath(root.display().to_string())),
        }
    }
    Ok(current)
}

#[cfg(unix)]
fn open_child(
    parent: &File,
    name: &std::ffi::OsStr,
    directory: bool,
) -> Result<File, ClosureError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    let c_name = std::ffi::CString::new(name.as_bytes())
        .map_err(|_| ClosureError::InvalidPath("embedded NUL".into()))?;
    let flags = libc::O_RDONLY
        | libc::O_NOFOLLOW
        | libc::O_CLOEXEC
        | libc::O_NONBLOCK
        | if directory { libc::O_DIRECTORY } else { 0 };
    // SAFETY: parent and C string remain live; openat returns a newly owned fd.
    let fd = unsafe { libc::openat(parent.as_raw_fd(), c_name.as_ptr(), flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn open_beneath(root: &File, path: &Path) -> Result<File, ClosureError> {
    let mut parent = root.try_clone()?;
    let components: Vec<_> = path.components().collect();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            return Err(ClosureError::InvalidPath(path.display().to_string()));
        };
        parent = open_child(&parent, name, index + 1 != components.len())?;
    }
    Ok(parent)
}

#[cfg(unix)]
fn file_mode(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    meta.mode() & 0o7777
}

#[cfg(unix)]
fn same_metadata(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.mode() == b.mode()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}

#[cfg(not(unix))]
fn open_root(_: &Path) -> Result<File, ClosureError> {
    Err(ClosureError::UnsupportedPlatform)
}
#[cfg(not(unix))]
fn open_beneath(_: &File, _: &Path) -> Result<File, ClosureError> {
    Err(ClosureError::UnsupportedPlatform)
}
#[cfg(not(unix))]
fn file_mode(_: &std::fs::Metadata) -> u32 {
    0
}
#[cfg(not(unix))]
fn same_metadata(_: &std::fs::Metadata, _: &std::fs::Metadata) -> bool {
    false
}
