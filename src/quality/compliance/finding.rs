//! Stable identity of a compliance finding.
//!
//! A finding is one [`Violation`] reported under one standard. Its key names
//! what the finding is about, never how it is worded:
//!
//! ```text
//! <standard>|<rule id>|<subject>
//! ```
//!
//! - `<standard>` is the canonical `validate --standard` value of the level
//!   (see [`standard_key`]).
//! - `<rule id>` is the stable internal [`Violation::rule_id`], not the
//!   `sarif_rule_id`: dozens of registry keys alias a shared SARIF rule (the
//!   ten `SBOM-BSIAI-MODEL-*` checks all report as `SBOM-BSIAI-MODEL`), so a
//!   SARIF-keyed id would merge distinct findings about the same component.
//! - `<subject>` is the offending component's canonical id
//!   ([`Violation::component_id`]), or [`DOCUMENT_SUBJECT`] for document-level
//!   and aggregate findings. A finding about one dependency edge would use
//!   `edge:<from>-><to>`, but no rule reports a single edge today, so that
//!   form is reserved.
//!
//! Neither the standard key nor a rule id contains `|`, so the subject is
//! everything after the second `|`. Severity, message, element label,
//! requirement text, counts and standard references are not part of the key:
//! rewording a message or recalibrating a severity keeps the id. The canonical
//! id is derived from the document's own identifiers (purl, CPE, SWHID, SWID,
//! then bom-ref/SPDXID), so the same SBOM yields the same keys on every run,
//! and a key changes exactly when its component's canonical id does — a purl
//! added or changed, a bom-ref renamed.
//!
//! [`finding_id`] digests the key into a fixed-length opaque id for SARIF
//! fingerprints and baselines.

use super::{ComplianceLevel, Violation};
use std::fmt::Write as _;

/// Subject of a finding that is about the document rather than a component.
pub const DOCUMENT_SUBJECT: &str = "document";

/// Prefix of every [`finding_id`]. The version changes only if the key
/// scheme does.
pub const FINDING_ID_PREFIX: &str = "sbomtools:v1:";

/// The canonical `validate --standard` value for `level`: the `<standard>`
/// part of a finding key and the `standard` field of `validate -o json`.
///
/// The three levels `--standard` cannot select (they back `quality
/// --profile`) use their lowercase level name.
#[must_use]
pub const fn standard_key(level: ComplianceLevel) -> &'static str {
    match level {
        ComplianceLevel::Minimum => "minimum",
        ComplianceLevel::Standard => "standard",
        ComplianceLevel::NtiaMinimum => "ntia",
        ComplianceLevel::CraPhase1 => "cra-phase1",
        ComplianceLevel::CraPhase2 => "cra",
        ComplianceLevel::FdaMedicalDevice => "fda",
        ComplianceLevel::NistSsdf => "ssdf",
        ComplianceLevel::Eo14028 => "eo14028",
        ComplianceLevel::Cnsa2 => "cnsa2",
        ComplianceLevel::NistPqc => "pqc",
        ComplianceLevel::BsiTr03183_2 => "bsi",
        ComplianceLevel::CraOssSteward => "oss-steward",
        ComplianceLevel::EuccSubstantial => "eucc",
        ComplianceLevel::EuAiAct => "ai-act",
        ComplianceLevel::BsiSbomForAi => "bsi-ai",
        ComplianceLevel::Cisa2026 => "cisa-2026",
        ComplianceLevel::PciDss632 => "pci-dss",
        ComplianceLevel::Fsct => "fsct",
        ComplianceLevel::Comprehensive => "comprehensive",
    }
}

/// What `violation` is about: the offending component's canonical id, or
/// [`DOCUMENT_SUBJECT`].
#[must_use]
pub fn finding_subject(violation: &Violation) -> &str {
    violation
        .component_id
        .as_deref()
        .unwrap_or(DOCUMENT_SUBJECT)
}

/// The finding key `<standard>|<rule id>|<subject>` of `violation` reported
/// under `level`.
#[must_use]
pub fn finding_key(level: ComplianceLevel, violation: &Violation) -> String {
    format!(
        "{}|{}|{}",
        standard_key(level),
        violation.rule_id,
        finding_subject(violation)
    )
}

/// The opaque id of a finding key: [`FINDING_ID_PREFIX`] followed by the
/// first 16 lowercase hex digits of SHA-256 of the key's UTF-8 bytes.
#[must_use]
pub fn finding_id(finding_key: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(finding_key.as_bytes());
    let mut id = String::with_capacity(FINDING_ID_PREFIX.len() + 16);
    id.push_str(FINDING_ID_PREFIX);
    for byte in &digest[..8] {
        let _ = write!(id, "{byte:02x}");
    }
    id
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Component, DocumentMetadata, NormalizedSbom};
    use crate::quality::{ComplianceChecker, StandardSelector, ViolationSeverity};
    use clap::ValueEnum as _;

    fn as_of() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-10-12T00:00:00Z")
            .expect("valid instant")
            .with_timezone(&chrono::Utc)
    }

    /// NTIA findings for an SBOM with no author and one supplier-less
    /// component: a document-level and a component-level finding.
    fn ntia_violations() -> Vec<Violation> {
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        sbom.add_component(
            Component::new("lodash".to_string(), "lodash-ref".to_string())
                .with_version("4.17.21".to_string())
                .with_purl("pkg:npm/lodash@4.17.21".to_string()),
        );
        ComplianceChecker::new(ComplianceLevel::NtiaMinimum)
            .with_as_of(as_of())
            .check(&sbom)
            .violations
    }

    fn find<'a>(violations: &'a [Violation], rule_id: &str) -> &'a Violation {
        violations
            .iter()
            .find(|v| v.rule_id == rule_id)
            .unwrap_or_else(|| panic!("expected a {rule_id} finding in {violations:?}"))
    }

    #[test]
    fn key_is_standard_rule_and_subject() {
        let violations = ntia_violations();
        let author = find(&violations, "SBOM-NTIA-AUTHOR");
        assert_eq!(
            finding_key(ComplianceLevel::NtiaMinimum, author),
            "ntia|SBOM-NTIA-AUTHOR|document"
        );
        let supplier = find(&violations, "SBOM-NTIA-SUPPLIER");
        assert_eq!(
            finding_key(ComplianceLevel::NtiaMinimum, supplier),
            "ntia|SBOM-NTIA-SUPPLIER|pkg:npm/lodash@4.17.21"
        );
    }

    /// Known answers pin the digest, the truncation and the prefix, so the
    /// ids a baseline stores cannot drift with a refactor.
    #[test]
    fn id_is_prefixed_truncated_sha256_of_the_key() {
        assert_eq!(
            finding_id("ntia|SBOM-NTIA-AUTHOR|document"),
            "sbomtools:v1:60072ae05d1ef4b8"
        );
        assert_eq!(
            finding_id("ntia|SBOM-NTIA-SUPPLIER|pkg:npm/lodash@4.17.21"),
            "sbomtools:v1:f863b422f8675d3b"
        );
    }

    #[test]
    fn same_inputs_give_the_same_id() {
        let first = ntia_violations();
        let second = ntia_violations();
        assert_eq!(first.len(), second.len());
        for (a, b) in first.iter().zip(&second) {
            let (ka, kb) = (
                finding_key(ComplianceLevel::NtiaMinimum, a),
                finding_key(ComplianceLevel::NtiaMinimum, b),
            );
            assert_eq!(ka, kb);
            assert_eq!(finding_id(&ka), finding_id(&kb));
        }
    }

    #[test]
    fn wording_severity_and_metadata_do_not_change_the_id() {
        let violations = ntia_violations();
        let original = find(&violations, "SBOM-NTIA-SUPPLIER");
        let key = finding_key(ComplianceLevel::NtiaMinimum, original);

        let mut edited = original.clone();
        edited.message = "reworded message".to_string();
        edited.severity = ViolationSeverity::Info;
        edited.element = Some("another label".to_string());
        edited.requirement = "another requirement".to_string();
        edited.standard_refs.clear();
        edited.counts = None;
        let edited_key = finding_key(ComplianceLevel::NtiaMinimum, &edited);
        assert_eq!(edited_key, key);
        assert_eq!(finding_id(&edited_key), finding_id(&key));
    }

    #[test]
    fn standard_rule_and_subject_each_change_the_id() {
        let violations = ntia_violations();
        let original = find(&violations, "SBOM-NTIA-SUPPLIER");
        let id = finding_id(&finding_key(ComplianceLevel::NtiaMinimum, original));

        let other_standard = finding_id(&finding_key(ComplianceLevel::Cisa2026, original));
        let mut other_rule = original.clone();
        other_rule.rule_id = "SBOM-NTIA-VERSION";
        let mut other_subject = original.clone();
        other_subject.component_id = Some("pkg:npm/lodash@4.17.22".to_string());
        let mut document = original.clone();
        document.component_id = None;

        for (what, changed) in [
            ("standard", other_standard),
            (
                "rule",
                finding_id(&finding_key(ComplianceLevel::NtiaMinimum, &other_rule)),
            ),
            (
                "subject",
                finding_id(&finding_key(ComplianceLevel::NtiaMinimum, &other_subject)),
            ),
            (
                "document subject",
                finding_id(&finding_key(ComplianceLevel::NtiaMinimum, &document)),
            ),
        ] {
            assert_ne!(changed, id, "a different {what} must change the id");
        }
    }

    #[test]
    fn standard_key_is_the_canonical_selector_name() {
        for selector in StandardSelector::value_variants() {
            assert_eq!(
                standard_key(selector.level()),
                selector.canonical_name(),
                "{selector:?}"
            );
        }
    }

    /// The subject is everything after the second `|` only while neither the
    /// standard key nor a rule id can contain one.
    #[test]
    fn key_separator_never_appears_before_the_subject() {
        for level in ComplianceLevel::all() {
            assert!(!standard_key(*level).contains('|'), "{level:?}");
        }
        for rule_id in crate::quality::all_rule_ids() {
            assert!(!rule_id.contains('|'), "{rule_id}");
        }
    }
}
