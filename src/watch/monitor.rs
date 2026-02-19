//! File system monitor using mtime-based polling.
//!
//! Scans watched directories for known SBOM file extensions and detects
//! additions, modifications, and removals by comparing mtime and file size.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Known SBOM file extensions to monitor.
const SBOM_EXTENSIONS: &[&str] = &[
    ".cdx.json",
    ".cdx.xml",
    ".spdx.json",
    ".spdx",
    ".spdx.rdf.xml",
    ".spdx.xml",
    ".spdx.yml",
    ".spdx.yaml",
];

/// A detected file change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FileChange {
    Added(PathBuf),
    Modified(PathBuf),
    Removed(PathBuf),
}

/// Per-file tracked metadata.
#[derive(Debug, Clone)]
struct FileState {
    mtime: SystemTime,
    size: u64,
    /// xxh3 content hash — only recomputed when mtime or size changes.
    content_hash: u64,
}

/// Polls directories for SBOM file changes by comparing mtime and size.
#[derive(Debug)]
pub(crate) struct FileMonitor {
    tracked: HashMap<PathBuf, FileState>,
    watch_dirs: Vec<PathBuf>,
}

impl FileMonitor {
    /// Create a new `FileMonitor` watching the given directories.
    pub(crate) fn new(watch_dirs: Vec<PathBuf>) -> Self {
        Self {
            tracked: HashMap::new(),
            watch_dirs,
        }
    }

    /// Poll all watched directories and return a list of changes since the last poll.
    ///
    /// On the first call, every discovered file is reported as [`FileChange::Added`].
    /// Uses mtime+size as a fast check; when those change, computes xxh3 content hash
    /// to confirm real changes (avoids false positives from `touch` or metadata-only updates).
    pub(crate) fn poll(&mut self) -> Vec<FileChange> {
        let mut changes = Vec::new();
        let mut seen = HashMap::new();

        for dir in &self.watch_dirs {
            Self::scan_dir_metadata(dir, &mut seen);
        }

        // Detect additions and modifications
        for (path, state) in &mut seen {
            match self.tracked.get(path) {
                None => {
                    // New file — compute hash for future comparisons
                    state.content_hash = hash_file_content(path);
                    changes.push(FileChange::Added(path.clone()));
                }
                Some(prev) if prev.mtime != state.mtime || prev.size != state.size => {
                    // Mtime/size changed — hash to verify content actually changed
                    state.content_hash = hash_file_content(path);
                    if prev.content_hash != state.content_hash {
                        changes.push(FileChange::Modified(path.clone()));
                    }
                }
                Some(prev) => {
                    // No metadata change — carry forward existing hash (no I/O)
                    state.content_hash = prev.content_hash;
                }
            }
        }

        // Detect removals (tracked but no longer on disk)
        for path in self.tracked.keys() {
            if !seen.contains_key(path) {
                changes.push(FileChange::Removed(path.clone()));
            }
        }

        self.tracked = seen;
        changes
    }

    /// Number of currently tracked files.
    pub(crate) fn tracked_count(&self) -> usize {
        self.tracked.len()
    }

    /// Recursively scan a directory, collecting SBOM files with mtime and size.
    ///
    /// Content hashing is deferred to `poll()` and only performed when mtime/size change.
    fn scan_dir_metadata(dir: &Path, out: &mut HashMap<PathBuf, FileState>) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("Cannot read directory {}: {}", dir.display(), e);
                return;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                Self::scan_dir_metadata(&path, out);
            } else if is_sbom_file(&path)
                && let Ok(meta) = std::fs::metadata(&path)
            {
                let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                out.insert(
                    path,
                    FileState {
                        mtime,
                        size: meta.len(),
                        content_hash: 0, // filled lazily in poll()
                    },
                );
            }
        }
    }
}

/// Compute an xxh3 hash of file contents. Returns 0 on read failure.
fn hash_file_content(path: &Path) -> u64 {
    match std::fs::read(path) {
        Ok(data) => xxhash_rust::xxh3::xxh3_64(&data),
        Err(_) => 0,
    }
}

/// Check whether a path has a known SBOM file extension.
fn is_sbom_file(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let lower = name.to_lowercase();
    SBOM_EXTENSIONS.iter().any(|ext| lower.ends_with(ext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_sbom_file() {
        assert!(is_sbom_file(Path::new("app.cdx.json")));
        assert!(is_sbom_file(Path::new("firmware.spdx.json")));
        assert!(is_sbom_file(Path::new("lib.spdx")));
        assert!(is_sbom_file(Path::new("APP.CDX.JSON")));
        assert!(!is_sbom_file(Path::new("readme.md")));
        assert!(!is_sbom_file(Path::new("data.json")));
        assert!(!is_sbom_file(Path::new("config.yaml")));
    }

    #[test]
    fn test_monitor_empty_dir() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let mut monitor = FileMonitor::new(vec![dir.path().to_path_buf()]);
        let changes = monitor.poll();
        assert!(changes.is_empty());
        assert_eq!(monitor.tracked_count(), 0);
    }

    #[test]
    fn test_monitor_detects_new_file() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let mut monitor = FileMonitor::new(vec![dir.path().to_path_buf()]);

        // First poll — empty
        assert!(monitor.poll().is_empty());

        // Create an SBOM file
        let file_path = dir.path().join("test.cdx.json");
        std::fs::write(&file_path, "{}").expect("write file");

        let changes = monitor.poll();
        assert_eq!(changes.len(), 1);
        assert!(matches!(&changes[0], FileChange::Added(p) if p == &file_path));
    }

    #[test]
    fn test_monitor_detects_modification() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let file_path = dir.path().join("test.cdx.json");
        std::fs::write(&file_path, "{}").expect("write file");

        let mut monitor = FileMonitor::new(vec![dir.path().to_path_buf()]);
        monitor.poll(); // initial scan

        // Modify the file (change size to ensure detection even if mtime granularity is coarse)
        std::fs::write(&file_path, r#"{"components":[]}"#).expect("write file");

        let changes = monitor.poll();
        assert!(
            changes
                .iter()
                .any(|c| matches!(c, FileChange::Modified(p) if p == &file_path)),
            "expected Modified, got {changes:?}"
        );
    }

    #[test]
    fn test_monitor_detects_removal() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let file_path = dir.path().join("test.cdx.json");
        std::fs::write(&file_path, "{}").expect("write file");

        let mut monitor = FileMonitor::new(vec![dir.path().to_path_buf()]);
        monitor.poll(); // initial scan
        assert_eq!(monitor.tracked_count(), 1);

        std::fs::remove_file(&file_path).expect("remove file");

        let changes = monitor.poll();
        assert_eq!(changes.len(), 1);
        assert!(matches!(&changes[0], FileChange::Removed(p) if p == &file_path));
        assert_eq!(monitor.tracked_count(), 0);
    }

    #[test]
    fn test_monitor_filters_by_extension() {
        let dir = tempfile::tempdir().expect("create temp dir");
        std::fs::write(dir.path().join("readme.md"), "# readme").expect("write");
        std::fs::write(dir.path().join("data.json"), "{}").expect("write");
        std::fs::write(dir.path().join("app.cdx.json"), "{}").expect("write");

        let mut monitor = FileMonitor::new(vec![dir.path().to_path_buf()]);
        let changes = monitor.poll();
        assert_eq!(changes.len(), 1);
        assert!(
            matches!(&changes[0], FileChange::Added(p) if p.file_name().unwrap() == "app.cdx.json")
        );
    }

    #[test]
    fn test_monitor_no_change_on_repeated_poll() {
        let dir = tempfile::tempdir().expect("create temp dir");
        std::fs::write(dir.path().join("test.cdx.json"), "{}").expect("write");

        let mut monitor = FileMonitor::new(vec![dir.path().to_path_buf()]);
        monitor.poll(); // initial
        let changes = monitor.poll(); // no change
        assert!(changes.is_empty());
    }
}
