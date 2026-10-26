//! The SBOM fixtures under `tests/fixtures`, for tests that run a writer over
//! every one of them (as tests/compliance_snapshots.rs and
//! tests/oscal_schema_tests.rs do).

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use sbom_tools::model::{CraSidecarMetadata, NormalizedSbom};
use sbom_tools::parse_sbom_str;
use sbom_tools::quality::{ComplianceChecker, ComplianceLevel, ComplianceResult};

pub const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// Fixture directories that hold SBOMs (as in tests/compliance_snapshots.rs).
pub const SBOM_DIRS: &[&str] = &[
    "aibom",
    "compliance/regressions",
    "cra",
    "cyclonedx",
    "showcase",
    "spdx",
    "spdx3",
];

/// Levels the CLI hands a CRA sidecar to (see `cli/validate.rs`).
pub const SIDECAR_LEVELS: &[ComplianceLevel] = &[
    ComplianceLevel::CraPhase1,
    ComplianceLevel::CraPhase2,
    ComplianceLevel::CraOssSteward,
    ComplianceLevel::EuccSubstantial,
    ComplianceLevel::EuAiAct,
];

/// The pinned evaluation instant of the snapshot harnesses.
pub fn as_of() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-10-12T00:00:00Z")
        .expect("valid instant")
        .with_timezone(&chrono::Utc)
}

/// Files under the SBOM directories that are not SBOMs (sidecars, docs,
/// scanner configs).
pub fn is_non_sbom(rel: &str) -> bool {
    [
        ".cra.json",
        ".cra.yaml",
        ".md",
        ".toml",
        "corpus.json",
        ".openvex.json",
    ]
    .iter()
    .any(|suffix| rel.ends_with(suffix))
}

/// A parseable SBOM fixture: its path relative to `tests/fixtures`, its
/// path, its text, the parsed SBOM and the auto-discovered CRA sidecar.
pub struct Fixture {
    pub rel: String,
    pub path: PathBuf,
    pub raw: String,
    pub sbom: NormalizedSbom,
    pub sidecar: Option<CraSidecarMetadata>,
}

impl Fixture {
    /// `level` checked at the pinned instant, with the sidecar for the levels
    /// the CLI hands one to.
    pub fn check(&self, level: ComplianceLevel) -> ComplianceResult {
        let mut checker = ComplianceChecker::new(level).with_as_of(as_of());
        if let Some(sc) = self.sidecar.as_ref()
            && SIDECAR_LEVELS.contains(&level)
        {
            checker = checker.with_sidecar(sc.clone());
        }
        checker.check(&self.sbom)
    }
}

/// Every parseable SBOM fixture, sorted by path.
pub fn fixtures() -> Vec<Fixture> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.push(path);
            }
        }
    }
    let root = Path::new(FIXTURES_DIR);
    let mut paths = Vec::new();
    for dir in SBOM_DIRS {
        walk(&root.join(dir), &mut paths);
    }
    paths.sort();
    paths
        .into_iter()
        .filter_map(|path| {
            let rel = path.strip_prefix(root).ok()?.to_string_lossy().into_owned();
            if is_non_sbom(&rel) {
                return None;
            }
            let raw = std::fs::read_to_string(&path).ok()?;
            let sbom = parse_sbom_str(&raw).ok()?;
            let sidecar = CraSidecarMetadata::discover_for_sbom(&path)
                .unwrap_or_else(|e| panic!("{rel}: sidecar does not load: {e}"));
            Some(Fixture {
                rel,
                path,
                raw,
                sbom,
                sidecar,
            })
        })
        .collect()
}
