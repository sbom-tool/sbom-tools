//! Whether a value an SBOM gives carries information.
//!
//! Generators write placeholders (`TBD`, `N/A`) and sentinels (`NOASSERTION`,
//! `NONE`, `UNKNOWN`) where they have no value. The compliance checks never
//! count one as the element they ask for (`quality::compliance`'s
//! `value_state` classifies with these helpers), and the merge of a
//! component's entries never keeps one over a real value.

/// Placeholder values generators write instead of data (`TBD`, `N/A`, …).
/// Unlike the explicit sentinels (see [`is_declared_unknown`]) they declare
/// nothing, so they never satisfy an element in any standard. Curated
/// conservatively so genuine values are never flagged; CISA FSCT §2.3.1
/// calls these "ambiguous".
const PLACEHOLDERS: &[&str] = &[
    "tbd",
    "to be determined",
    "todo",
    "n/a",
    "n.a.",
    "placeholder",
    "unspecified",
    "not specified",
    "not available",
    "unavailable",
    "null",
    "nil",
    "undefined",
    "xxx",
    "-",
    "--",
    "?",
];

/// Whether `value` is a placeholder that declares nothing.
pub(crate) fn is_placeholder(value: &str) -> bool {
    let lower = value.trim().to_ascii_lowercase();
    PLACEHOLDERS.contains(&lower.as_str())
}

/// Whether `value` is one of the explicit sentinels SPDX and CycloneDX
/// producers write to assert that a value is unknown or absent
/// (`NOASSERTION`, `NONE`, `UNKNOWN`).
pub(crate) fn is_declared_unknown(value: &str) -> bool {
    let v = value.trim();
    v.eq_ignore_ascii_case("NOASSERTION")
        || v.eq_ignore_ascii_case("NONE")
        || v.eq_ignore_ascii_case("UNKNOWN")
}

/// Whether `value` carries information: it is not empty or blank, not a
/// sentinel ([`is_declared_unknown`]) and not a placeholder
/// ([`is_placeholder`]).
pub(crate) fn is_known(value: &str) -> bool {
    let v = value.trim();
    !v.is_empty() && !is_placeholder(v) && !is_declared_unknown(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sentinels_placeholders_and_blanks_are_not_known() {
        for value in [
            "",
            "  ",
            "NOASSERTION",
            "none",
            "Unknown",
            "TBD",
            "n/a",
            "-",
            " null ",
        ] {
            assert!(!is_known(value), "{value:?}");
        }
        for value in [
            "MIT",
            "Acme Corp",
            "1.0.0",
            "none-such",
            "pkg:npm/none@1.0.0",
        ] {
            assert!(is_known(value), "{value:?}");
        }
    }
}
