//! Pinned evaluation clock for compliance tests.
//!
//! Deadline-sensitive checks (CRA Art. 14 readiness, SBOM age, EUCC
//! certificate validity, attestation evidence windows) read the wall clock
//! unless the checker is pinned, so an unpinned test changes meaning when a
//! date passes: the 2026-09-11 Art. 14 gate broke snapshot tests (#369).
//! Build checkers with [`checker`], or pin a deliberate instant with
//! `.with_as_of(...)` in the same expression; `tests/pinned_clock_tests.rs`
//! fails on any other `ComplianceChecker::new` in a test.

// Each test binary uses a subset of these helpers (mirrors the
// tests/common/ffi_helpers.rs posture).
#![allow(dead_code)]

use sbom_tools::quality::{ComplianceChecker, ComplianceLevel};

/// Evaluation instant for tests that do not exercise a date boundary: the
/// v0.3.0 review date, shared with the snapshot harness and the regression
/// corpus.
pub const AS_OF: &str = "2026-10-12T00:00:00Z";

/// [`AS_OF`] as a timestamp, for fixture dates relative to it.
pub fn as_of() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(AS_OF)
        .expect("valid AS_OF")
        .with_timezone(&chrono::Utc)
}

/// A compliance checker that evaluates at [`AS_OF`].
pub fn checker(level: ComplianceLevel) -> ComplianceChecker {
    ComplianceChecker::new(level).with_as_of(as_of())
}
