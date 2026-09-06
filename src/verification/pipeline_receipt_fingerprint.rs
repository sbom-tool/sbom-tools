use std::{
    fs,
    path::{Path, PathBuf},
};

use super::{
    pipeline_receipt::{ReceiptError, Sha256Digest},
    pipeline_receipt_paths::validate_relative_path,
};

/// Compute a deterministic digest of source files, excluding generated and receipt directories.
pub fn source_fingerprint(root: &Path) -> Result<Sha256Digest, ReceiptError> {
    let metadata = fs::symlink_metadata(root).map_err(|source| ReceiptError::Io {
        path: root.into(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ReceiptError::Contract(
            "source root must be a regular directory".into(),
        ));
    }
    let mut files = Vec::new();
    collect_source_files(root, root, &mut files)?;
    fingerprint_files(root, files)
}

/// Compute a deterministic digest of explicitly selected lock files.
pub fn lock_fingerprint(root: &Path, paths: &[PathBuf]) -> Result<Sha256Digest, ReceiptError> {
    if paths.is_empty() {
        return Err(ReceiptError::Contract(
            "lock input list must not be empty".into(),
        ));
    }
    let mut files = Vec::new();
    for path in paths {
        let value = path
            .to_str()
            .ok_or_else(|| ReceiptError::Contract("lock path must be UTF-8".into()))?;
        validate_relative_path(value, "lock path")?;
        let full = root.join(path);
        let meta = fs::symlink_metadata(&full).map_err(|source| ReceiptError::Io {
            path: full.clone(),
            source,
        })?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err(ReceiptError::Contract(
                "lock input must be a regular file".into(),
            ));
        }
        files.push(full);
    }
    fingerprint_files(root, files)
}

fn collect_source_files(
    root: &Path,
    dir: &Path,
    out: &mut Vec<PathBuf>,
) -> Result<(), ReceiptError> {
    for entry in fs::read_dir(dir).map_err(|source| ReceiptError::Io {
        path: dir.into(),
        source,
    })? {
        let path = entry
            .map_err(|source| ReceiptError::Io {
                path: dir.into(),
                source,
            })?
            .path();
        let rel = path
            .strip_prefix(root)
            .map_err(|_| ReceiptError::Contract("path escaped root".into()))?;
        if rel.components().any(|component| {
            matches!(
                component.as_os_str().to_str(),
                Some(".git" | "target" | "receipts")
            )
        }) {
            continue;
        }
        let metadata = fs::symlink_metadata(&path).map_err(|source| ReceiptError::Io {
            path: path.clone(),
            source,
        })?;
        if metadata.file_type().is_symlink() {
            return Err(ReceiptError::Contract("symlink in source tree".into()));
        }
        if rel.to_str().is_none_or(|value| value.is_empty()) {
            return Err(ReceiptError::Contract("non-UTF8 source path".into()));
        }
        if metadata.is_dir() {
            collect_source_files(root, &path, out)?;
        } else if metadata.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

fn fingerprint_files(root: &Path, mut files: Vec<PathBuf>) -> Result<Sha256Digest, ReceiptError> {
    files.sort_by(|a, b| {
        a.strip_prefix(root)
            .map_or(Path::new(""), |path| path)
            .cmp(b.strip_prefix(root).map_or(Path::new(""), |path| path))
    });
    let mut input = Vec::new();
    for path in files {
        let rel = path
            .strip_prefix(root)
            .map_err(|_| ReceiptError::Contract("path escaped root".into()))?
            .to_str()
            .ok_or_else(|| ReceiptError::Contract("non-UTF8 source path".into()))?;
        let bytes = fs::read(&path).map_err(|source| ReceiptError::Io {
            path: path.clone(),
            source,
        })?;
        input.extend_from_slice(&(rel.len() as u64).to_be_bytes());
        input.extend_from_slice(rel.as_bytes());
        input.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        input.extend_from_slice(&bytes);
    }
    Ok(Sha256Digest::from_bytes(&input))
}
