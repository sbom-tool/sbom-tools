//! Unit tests that run SBOMs through `ComplianceChecker::check()`. Each
//! module covers one standard family; `check` covers the checker itself.
//! The helpers here pin the clock.

use super::*;

mod bsi;
mod check;
mod cra;
mod crypto;
mod eo14028_ssdf;
mod ntia_fda;

/// The shared test clock (tests/common/clock.rs). Tests that cross a
/// date gate pin their own instant instead.
fn as_of() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-10-12T00:00:00Z")
        .expect("valid instant")
        .with_timezone(&chrono::Utc)
}

fn checker(level: ComplianceLevel) -> ComplianceChecker {
    ComplianceChecker::new(level).with_as_of(as_of())
}
