//! Unit tests that run SBOMs through `ComplianceChecker::check()`. Each
//! module covers one standard family; `check` covers the checker itself.
//! The helpers here pin the clock.
//!
//! Every module is declared `#[cfg(test)]` too, so that
//! tests/pinned_clock_tests.rs reads its file as test code.

use super::*;

#[cfg(test)]
mod bsi;
#[cfg(test)]
mod check;
#[cfg(test)]
mod cra;
#[cfg(test)]
mod crypto;
#[cfg(test)]
mod eo14028_ssdf;
#[cfg(test)]
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
