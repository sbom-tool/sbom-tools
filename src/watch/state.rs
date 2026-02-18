//! Watch state management.
//!
//! Tracks per-SBOM monitoring state, diff history snapshots, and
//! aggregate statistics for the watch session.

use crate::model::NormalizedSbom;
use indexmap::IndexMap;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Top-level state for an active watch session.
#[derive(Debug)]
pub(crate) struct WatchState {
    /// Per-SBOM monitoring state, keyed by canonical path.
    pub sboms: IndexMap<PathBuf, SbomMonitorState>,
    /// When the watch session started.
    pub started_at: Instant,
    /// Total number of polling cycles completed.
    pub poll_count: u64,
    /// Cumulative number of file changes detected.
    pub total_changes: u64,
    /// Timestamp of most recent poll cycle.
    pub last_poll: Option<Instant>,
    /// Timestamp of most recent enrichment cycle.
    pub last_enrichment: Option<Instant>,
    /// Maximum number of diff snapshots retained per SBOM.
    max_snapshots: usize,
}

impl WatchState {
    pub(crate) fn new(max_snapshots: usize) -> Self {
        Self {
            sboms: IndexMap::new(),
            started_at: Instant::now(),
            poll_count: 0,
            total_changes: 0,
            last_poll: None,
            last_enrichment: None,
            max_snapshots,
        }
    }

    /// Get or create the monitor state for a given path.
    pub(crate) fn get_or_insert(&mut self, path: &Path) -> &mut SbomMonitorState {
        let key = path.to_path_buf();
        if !self.sboms.contains_key(&key) {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();
            self.sboms.insert(
                key.clone(),
                SbomMonitorState {
                    path: key.clone(),
                    name,
                    current_sbom: None,
                    last_parsed: None,
                    last_enriched: None,
                    diff_history: VecDeque::new(),
                    vuln_count: 0,
                    eol_count: 0,
                    component_count: 0,
                    status: MonitorStatus::Pending,
                    last_error: None,
                },
            );
        }
        self.sboms.get_mut(&key).expect("just inserted")
    }

    /// Record a diff snapshot for a given SBOM, evicting the oldest if at capacity.
    pub(crate) fn record_snapshot(&mut self, path: &Path, snapshot: DiffSnapshot) {
        let max = self.max_snapshots;
        let entry = self.get_or_insert(path);
        if entry.diff_history.len() >= max {
            entry.diff_history.pop_front();
        }
        entry.diff_history.push_back(snapshot);
    }

    /// Mark a file as removed.
    pub(crate) fn mark_removed(&mut self, path: &Path) {
        if let Some(entry) = self.sboms.get_mut(path) {
            entry.status = MonitorStatus::Removed;
            entry.current_sbom = None;
        }
    }

    /// Count SBOMs in a given status.
    pub(crate) fn count_status(&self, status: MonitorStatus) -> usize {
        self.sboms.values().filter(|s| s.status == status).count()
    }

    /// Sum of vulnerability counts across all tracked SBOMs.
    pub(crate) fn total_vulns(&self) -> usize {
        self.sboms.values().map(|s| s.vuln_count).sum()
    }
}

/// Per-SBOM monitoring state.
#[derive(Debug)]
pub(crate) struct SbomMonitorState {
    /// Canonical path (used as key, read by TUI dashboard).
    #[allow(dead_code)]
    pub path: PathBuf,
    /// Display name derived from filename (used by TUI dashboard).
    #[allow(dead_code)]
    pub name: String,
    pub current_sbom: Option<NormalizedSbom>,
    pub last_parsed: Option<Instant>,
    pub last_enriched: Option<Instant>,
    pub diff_history: VecDeque<DiffSnapshot>,
    pub vuln_count: usize,
    pub eol_count: usize,
    pub component_count: usize,
    pub status: MonitorStatus,
    pub last_error: Option<String>,
}

/// A lightweight summary of a diff between two snapshots of the same SBOM.
#[derive(Debug, Clone)]
pub(crate) struct DiffSnapshot {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub components_added: usize,
    pub components_removed: usize,
    pub components_modified: usize,
    pub new_vulns: Vec<String>,
    pub resolved_vulns: Vec<String>,
    pub new_eol: Vec<String>,
}

impl DiffSnapshot {
    /// Whether this snapshot recorded any meaningful changes.
    pub(crate) fn has_changes(&self) -> bool {
        self.components_added > 0
            || self.components_removed > 0
            || self.components_modified > 0
            || !self.new_vulns.is_empty()
            || !self.resolved_vulns.is_empty()
            || !self.new_eol.is_empty()
    }
}

/// Lifecycle status of a monitored SBOM file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MonitorStatus {
    Pending,
    Healthy,
    Updating,
    Error,
    Removed,
}

impl std::fmt::Display for MonitorStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "WAIT"),
            Self::Healthy => write!(f, "OK"),
            Self::Updating => write!(f, "SYNC"),
            Self::Error => write!(f, "ERR"),
            Self::Removed => write!(f, "GONE"),
        }
    }
}

/// Summary of the current watch session, passed to alert sinks.
#[derive(Debug, Clone)]
pub(crate) struct WatchSummary {
    pub tracked_count: usize,
    pub healthy_count: usize,
    pub error_count: usize,
    pub total_vulns: usize,
    pub total_changes: u64,
    pub uptime_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_new() {
        let state = WatchState::new(10);
        assert_eq!(state.poll_count, 0);
        assert_eq!(state.total_changes, 0);
        assert!(state.sboms.is_empty());
    }

    #[test]
    fn test_state_get_or_insert_creates_entry() {
        let mut state = WatchState::new(10);
        let path = PathBuf::from("/tmp/test.cdx.json");
        let entry = state.get_or_insert(&path);
        assert_eq!(entry.name, "test.cdx.json");
        assert_eq!(entry.status, MonitorStatus::Pending);
        assert_eq!(state.sboms.len(), 1);
    }

    #[test]
    fn test_state_get_or_insert_idempotent() {
        let mut state = WatchState::new(10);
        let path = PathBuf::from("/tmp/test.cdx.json");
        state.get_or_insert(&path);
        state.get_or_insert(&path);
        assert_eq!(state.sboms.len(), 1);
    }

    #[test]
    fn test_state_record_snapshot_bounded() {
        let mut state = WatchState::new(3);
        let path = PathBuf::from("/tmp/test.cdx.json");
        state.get_or_insert(&path);

        for i in 0..5 {
            state.record_snapshot(
                &path,
                DiffSnapshot {
                    timestamp: chrono::Utc::now(),
                    components_added: i,
                    components_removed: 0,
                    components_modified: 0,
                    new_vulns: vec![],
                    resolved_vulns: vec![],
                    new_eol: vec![],
                },
            );
        }

        let entry = state.sboms.get(&path).unwrap();
        assert_eq!(entry.diff_history.len(), 3);
        // Oldest should have been evicted — first remaining should be index 2
        assert_eq!(entry.diff_history[0].components_added, 2);
    }

    #[test]
    fn test_state_mark_removed() {
        let mut state = WatchState::new(10);
        let path = PathBuf::from("/tmp/test.cdx.json");
        {
            let entry = state.get_or_insert(&path);
            entry.status = MonitorStatus::Healthy;
        }
        state.mark_removed(&path);
        assert_eq!(
            state.sboms.get(&path).unwrap().status,
            MonitorStatus::Removed
        );
    }

    #[test]
    fn test_state_count_status() {
        let mut state = WatchState::new(10);
        state.get_or_insert(Path::new("/a.cdx.json")).status = MonitorStatus::Healthy;
        state.get_or_insert(Path::new("/b.cdx.json")).status = MonitorStatus::Healthy;
        state.get_or_insert(Path::new("/c.cdx.json")).status = MonitorStatus::Error;
        assert_eq!(state.count_status(MonitorStatus::Healthy), 2);
        assert_eq!(state.count_status(MonitorStatus::Error), 1);
    }

    #[test]
    fn test_diff_snapshot_has_changes() {
        let empty = DiffSnapshot {
            timestamp: chrono::Utc::now(),
            components_added: 0,
            components_removed: 0,
            components_modified: 0,
            new_vulns: vec![],
            resolved_vulns: vec![],
            new_eol: vec![],
        };
        assert!(!empty.has_changes());

        let with_add = DiffSnapshot {
            components_added: 1,
            ..empty.clone()
        };
        assert!(with_add.has_changes());

        let with_vulns = DiffSnapshot {
            new_vulns: vec!["CVE-2026-0001".to_string()],
            ..empty
        };
        assert!(with_vulns.has_changes());
    }

    #[test]
    fn test_monitor_status_display() {
        assert_eq!(MonitorStatus::Healthy.to_string(), "OK");
        assert_eq!(MonitorStatus::Error.to_string(), "ERR");
        assert_eq!(MonitorStatus::Removed.to_string(), "GONE");
    }
}
