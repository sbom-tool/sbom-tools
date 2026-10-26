//! Small shared helpers reused across the compliance checkers.

use super::{Violation, ViolationCategory, ViolationSeverity};
use crate::model::{Component, ComponentType, NormalizedSbom};

/// The components package rules apply to: everything except files,
/// snippets, cryptographic assets and services (see
/// [`ComponentType::is_package_scoped`]). Every per-component package check
/// iterates through this, so no standard can forget the carve-out.
pub(crate) fn package_components(sbom: &NormalizedSbom) -> impl Iterator<Item = &Component> {
    sbom.components
        .values()
        .filter(|c| c.component_type.is_package_scoped())
}

/// The inventory-absent finding for `rule_id`, or `None` when the SBOM lists
/// at least one package-scoped component.
///
/// Package rules (version, supplier, identifier, hash, license) only judge
/// package-scoped components, so a document with no components at all — or
/// with only files, snippets or cryptographic assets — used to pass them
/// vacuously, scoring like a perfect SBOM. Every standard that judges a
/// software inventory reports that instead, as PCI DSS already did. The
/// primary component counts: a leaf application with no dependencies is a
/// legitimate inventory.
pub(crate) fn inventory_absent_violation(
    sbom: &NormalizedSbom,
    rule_id: &'static str,
    requirement: &str,
) -> Option<Violation> {
    if package_components(sbom).next().is_some() {
        return None;
    }
    let total = sbom.components.len();
    let message = if total == 0 {
        "SBOM lists no components; an empty document is not a software inventory".to_string()
    } else {
        let all_crypto = sbom
            .components
            .values()
            .all(|c| c.component_type == ComponentType::Cryptographic);
        let what = if all_crypto {
            "cryptographic assets"
        } else {
            "files, snippets, services or cryptographic assets"
        };
        let mut message = format!(
            "SBOM lists no software components, only {total} {what}; it is not a software inventory"
        );
        if all_crypto {
            message.push_str(" (validate a CBOM with --standard cnsa2 or pqc)");
        }
        message
    };
    Some(Violation {
        severity: ViolationSeverity::Error,
        category: ViolationCategory::DocumentMetadata,
        message,
        element: None,
        requirement: requirement.to_string(),
        rule_id,
        component_id: None,
        counts: None,
        standard_refs: Vec::new(),
        remediation: None,
        finding_detail: None,
    })
}

/// The freshness finding for an SBOM dated in the future, or `None` when its
/// creation timestamp is missing or not later than `as_of`.
///
/// Freshness checks measure the document's age at the evaluation instant. A
/// timestamp after that instant gave a negative age, which read as "just
/// generated" and passed every staleness threshold. A future-dated SBOM shows
/// nothing about when the inventory was last updated (usually the generator's
/// clock or time zone is wrong), so it is reported at the severity both
/// freshness rules give a missing timestamp: Warning, because clock-skewed
/// generators are common and the rest of the document is unaffected. There is
/// no skew tolerance, as for attestation evidence created after `as_of`.
/// `citation` prefixes the message, e.g. `"[PCI DSS 6.3.2]"`.
pub(crate) fn future_timestamp_violation(
    sbom: &NormalizedSbom,
    as_of: chrono::DateTime<chrono::Utc>,
    rule_id: &'static str,
    citation: &str,
    requirement: &str,
) -> Option<Violation> {
    let created = sbom.document.created;
    if !sbom.document.has_known_timestamp() || created <= as_of {
        return None;
    }
    // The message names only the document's timestamp: the evaluation
    // instant is the wall clock unless pinned, and would make the text
    // differ on every run.
    Some(Violation {
        severity: ViolationSeverity::Warning,
        category: ViolationCategory::DocumentMetadata,
        message: format!(
            "{citation} SBOM creation timestamp {} is later than the evaluation instant; a \
             future-dated SBOM does not show when the inventory was last updated (check the \
             generator's clock and time zone)",
            created.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        ),
        element: None,
        requirement: requirement.to_string(),
        rule_id,
        component_id: None,
        counts: None,
        standard_refs: Vec::new(),
        remediation: None,
        finding_detail: None,
    })
}

/// Components whose external references can carry manufacturer-level
/// evidence (security contact, CVD policy, disclosure process): the primary
/// component when one is identified, otherwise the root components (no
/// incoming dependency edge).
///
/// SBOM generators routinely copy upstream registry metadata — a third-party
/// dependency's own GitHub advisories or support URL — onto dependency
/// components; such references say nothing about the *manufacturer's*
/// obligations and must not satisfy them.
pub(crate) fn manufacturer_scope_components(sbom: &NormalizedSbom) -> Vec<&Component> {
    let mut incoming = std::collections::HashSet::new();
    for edge in &sbom.edges {
        incoming.insert(&edge.to);
    }
    let primary = sbom.primary_component_id.as_ref();
    // The primary component plus every root (no incoming edge): an SPDX
    // document can DESCRIBE several sibling products, and each is
    // manufacturer-scoped evidence — not just the first one the parser
    // happened to promote to primary.
    let scope: Vec<&Component> = sbom
        .components
        .iter()
        .filter(|(id, _)| primary.is_some_and(|p| p == *id) || !incoming.contains(id))
        .map(|(_, c)| c)
        .collect();
    if scope.is_empty() {
        // Fully cyclic graph with no identified primary: no component is
        // provably a dependency-only node, so fall back to scanning all
        // components rather than making manufacturer evidence unsatisfiable.
        return sbom.components.values().collect();
    }
    scope
}

/// Whether a component's name is real. Empty/whitespace and the SPDX
/// `NOASSERTION` sentinel never count. `none`/`unknown` are placeholder-ish
/// but are also genuine package names (npm ships both), so they count when
/// corroborated by a unique identifier whose name segment matches.
pub(crate) fn known_component_name(comp: &Component) -> bool {
    let name = comp.name.trim();
    if name.is_empty() || name.eq_ignore_ascii_case("NOASSERTION") {
        return false;
    }
    if !(name.eq_ignore_ascii_case("NONE") || name.eq_ignore_ascii_case("UNKNOWN")) {
        return true;
    }
    // Suspicious placeholder spelling: require a corroborating identifier
    // (e.g. pkg:npm/none@1.0.0 corroborates a component named "none").
    comp.identifiers.purl.as_deref().is_some_and(|purl| {
        purl.rsplit('/')
            .next()
            .and_then(|seg| seg.split('@').next())
            .is_some_and(|purl_name| purl_name.eq_ignore_ascii_case(name))
    })
}

/// Render a slice of names as a comma-separated list, truncated with
/// "…and N more" once `max` items are emitted. Keeps long-tail violation
/// messages bounded for terminal/SARIF output.
pub(crate) fn truncate_list(items: &[String], max: usize) -> String {
    if items.len() <= max {
        items.join(", ")
    } else {
        let head = items[..max].join(", ");
        let rest = items.len() - max;
        format!("{head}, …and {rest} more")
    }
}

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

/// What a field says about a required element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ValueState {
    /// A real value.
    Known,
    /// An explicit sentinel (`NOASSERTION`, `NONE`, `UNKNOWN`): the author
    /// states the value is unknown. CISA 2026 and FSCT accept this where
    /// their texts allow an explicit unknown; every other standard does not.
    DeclaredUnknown,
    /// Absent, empty, or a placeholder such as `TBD` or `N/A`. Never
    /// satisfies an element.
    Missing,
}

/// Classify a field value; see [`ValueState`].
pub(crate) fn value_state(value: Option<&str>) -> ValueState {
    match value.map(str::trim) {
        None => ValueState::Missing,
        Some(v) if v.is_empty() || is_placeholder(v) => ValueState::Missing,
        Some(v) if is_declared_unknown(v) => ValueState::DeclaredUnknown,
        Some(_) => ValueState::Known,
    }
}

/// Return the trimmed value only when it carries real information
/// ([`ValueState::Known`]): not empty, not a sentinel such as `NOASSERTION`,
/// and not a placeholder such as `TBD`. This is the presence test for every
/// element that needs a real value.
pub(crate) fn known_value(value: Option<&str>) -> Option<&str> {
    let v = value?.trim();
    (value_state(Some(v)) == ValueState::Known).then_some(v)
}

/// `known_value` convenience for `Option<String>` model fields.
pub(crate) fn has_known_value(value: &Option<String>) -> bool {
    known_value(value.as_deref()).is_some()
}

/// Whether a component carries real producer attribution: a supplier or
/// manufacturer organization, or an author, whose name is not a placeholder
/// sentinel. CycloneDX 1.6+ names the creating organization `manufacturer`
/// (and people `authors`, folded into `author` by the parser); both identify
/// "the entity that creates, defines, and identifies components" as well as
/// a supplier does.
pub(crate) fn has_known_producer(comp: &crate::model::Component) -> bool {
    let known_org = |org: &Option<crate::model::Organization>| {
        org.as_ref()
            .is_some_and(|o| known_value(Some(o.name.as_str())).is_some())
    };
    known_org(&comp.supplier) || known_org(&comp.manufacturer) || has_known_value(&comp.author)
}

/// Whether the component carries at least one real license expression,
/// declared or concluded (sentinels and placeholders do not count).
pub(crate) fn has_known_license(comp: &Component) -> bool {
    comp.licenses
        .all_licenses()
        .iter()
        .any(|l| known_value(Some(l.expression.as_str())).is_some())
}

/// Whether a creator identifies a real entity: a known name, or failing
/// that a known email address.
pub(crate) fn creator_identified(creator: &crate::model::Creator) -> bool {
    known_value(Some(creator.name.as_str())).is_some()
        || known_value(creator.email.as_deref()).is_some()
}

/// Simple email format validation (checks basic structure, not full RFC 5322)
pub(crate) fn is_valid_email_format(email: &str) -> bool {
    // Basic checks: contains @, has local and domain parts, no spaces
    if email.contains(' ') || email.is_empty() {
        return false;
    }

    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return false;
    }

    let local = parts[0];
    let domain = parts[1];

    // Local part must not be empty
    if local.is_empty() {
        return false;
    }

    // Domain must contain at least one dot and not start/end with dot
    if domain.is_empty()
        || !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
    {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_state_separates_known_declared_unknown_and_missing() {
        for known in ["1.2.3", "Acme Corp", "0", "none-of-the-above"] {
            assert_eq!(value_state(Some(known)), ValueState::Known, "{known:?}");
        }
        for declared in ["NOASSERTION", "noassertion", "NONE", "Unknown", " UNKNOWN "] {
            assert_eq!(
                value_state(Some(declared)),
                ValueState::DeclaredUnknown,
                "{declared:?}"
            );
        }
        for missing in [
            "", "   ", "TBD", "tbd", "N/A", "n.a.", "TODO", "-", "?", "null",
        ] {
            assert_eq!(
                value_state(Some(missing)),
                ValueState::Missing,
                "{missing:?}"
            );
        }
        assert_eq!(value_state(None), ValueState::Missing);
        assert_eq!(known_value(Some(" 1.0 ")), Some("1.0"));
        assert_eq!(known_value(Some("N/A")), None);
        assert_eq!(known_value(Some("NOASSERTION")), None);
    }

    #[test]
    fn only_a_timestamp_after_the_evaluation_instant_is_future_dated() {
        let ts = |s: &str| {
            chrono::DateTime::parse_from_rfc3339(s)
                .expect("test timestamp must parse")
                .with_timezone(&chrono::Utc)
        };
        let as_of = ts("2026-10-12T00:00:00Z");
        let dated = |created: chrono::DateTime<chrono::Utc>| {
            let mut sbom = NormalizedSbom::default();
            sbom.document.created = created;
            future_timestamp_violation(&sbom, as_of, "SBOM-PCI-6-3-2-FRESHNESS", "[PCI]", "req")
        };

        let future = dated(ts("2026-10-12T00:00:01Z")).expect("one second later is future");
        assert_eq!(future.severity, ViolationSeverity::Warning);
        assert_eq!(future.rule_id, "SBOM-PCI-6-3-2-FRESHNESS");
        assert!(
            future
                .message
                .starts_with("[PCI] SBOM creation timestamp 2026-10-12T00:00:01Z"),
            "the message names the document's timestamp: {}",
            future.message
        );
        assert!(
            !future.message.contains("2026-10-12T00:00:00Z"),
            "the evaluation instant stays out of the message: {}",
            future.message
        );

        // The instant itself and anything earlier are not in the future, and
        // a missing timestamp (the parsers' epoch sentinel) is reported by
        // the missing-timestamp branch instead.
        assert!(dated(as_of).is_none());
        assert!(dated(ts("2026-01-01T00:00:00Z")).is_none());
        assert!(dated(chrono::DateTime::UNIX_EPOCH).is_none());
    }
}
