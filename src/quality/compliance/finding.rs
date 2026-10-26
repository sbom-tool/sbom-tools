//! Stable identity of a compliance finding.
//!
//! A finding is one check reported under one standard: a [`Violation`], or
//! any other type that implements [`FindingIdentity`]. Its key names what
//! the finding is about, never how it is worded:
//!
//! ```text
//! <standard>|<rule id>|<subject>
//! <standard>|<rule id>:<detail>|<subject>
//! ```
//!
//! - `<standard>` is the canonical `validate --standard` value of the level
//!   (see [`standard_key`]).
//! - `<rule id>` is the stable internal [`Violation::rule_id`]. Since v0.4.0
//!   every check is its own SARIF rule, so it equals the `sarif_rule_id` of
//!   every registered rule; until then dozens of keys shared a SARIF rule
//!   (the ten `SBOM-BSIAI-MODEL-*` checks all reported as
//!   `SBOM-BSIAI-MODEL`), and the key was built from the internal id so that
//!   distinct findings about one component never merged.
//! - `<detail>` is the [`Violation::finding_detail`] of a rule that reports
//!   several findings on one subject (the vulnerability id, the cipher
//!   suite, …), with `%`, `|` and `:` percent-encoded as `%25`, `%7C` and
//!   `%3A`. Without a detail the `:` is omitted too.
//! - `<subject>` is the offending component's canonical id
//!   ([`Violation::component_id`]), or [`DOCUMENT_SUBJECT`] for document-level
//!   and aggregate findings. A finding about one dependency edge would use
//!   `edge:<from>-><to>`, but no rule reports a single edge today, so that
//!   form is reserved. A canonical id that would read as one of those forms
//!   — `document` itself, or one starting with `edge:` — gets `component:`
//!   prepended, as does one already starting with `component:`, so a
//!   component never shares the document's subject (see
//!   [`finding_subject`]).
//!
//! Neither the standard key nor a rule id contains `|` or `:`, and the
//! encoded detail contains neither, so the key splits unambiguously: the
//! standard is everything before the first `|`, the rule id runs to the
//! first `:` or `|` after it, the detail (if any) to the second `|`, and the
//! subject is everything after that. Severity, message, element label,
//! requirement text, counts and standard references are not part of the key:
//! rewording a message or recalibrating a severity keeps the id. The canonical
//! id is derived from the document's own identifiers (purl, CPE, SWHID, SWID,
//! then bom-ref/SPDXID), so the same SBOM yields the same keys on every run,
//! and a key changes exactly when its component's canonical id does — a purl
//! added or changed, a bom-ref renamed.
//!
//! No two findings of one result share a key: every distinct check has a
//! rule id of its own, a rule reports at most one finding per subject unless
//! it sets a detail, and `number_repeated_details` numbers the detail of an
//! entry the SBOM lists twice. tests/finding_identity_tests.rs checks this
//! for every fixture at every level.
//!
//! [`finding_id`] digests the key into a fixed-length opaque id for SARIF
//! fingerprints and baselines.

use super::{ComplianceLevel, Violation};
use std::borrow::Cow;
use std::fmt::Write as _;

/// The parts of a reported check that its finding key is built from: the
/// rule, the detail that tells the rule's findings on one subject apart, and
/// the component the check is about. Severity, wording and every other field
/// stay out of the key.
pub trait FindingIdentity {
    /// The stable internal rule key ([`Violation::rule_id`]).
    fn rule_id(&self) -> &'static str;
    /// What tells this finding apart from the rule's other findings on the
    /// same subject ([`Violation::finding_detail`]); `None` for a rule that
    /// reports at most one finding per subject.
    fn finding_detail(&self) -> Option<&str>;
    /// Canonical id of the component the finding is about
    /// ([`Violation::component_id`]); `None` for the document and for
    /// aggregate findings.
    fn component_id(&self) -> Option<&str>;
}

impl FindingIdentity for Violation {
    fn rule_id(&self) -> &'static str {
        self.rule_id
    }

    fn finding_detail(&self) -> Option<&str> {
        self.finding_detail.as_deref()
    }

    fn component_id(&self) -> Option<&str> {
        self.component_id.as_deref()
    }
}

/// A finding whose detail [`number_repeated_details`] may rewrite.
pub(crate) trait NumberedDetail: FindingIdentity {
    /// Replace the finding's detail.
    fn set_finding_detail(&mut self, detail: String);
}

impl NumberedDetail for Violation {
    fn set_finding_detail(&mut self, detail: String) {
        self.finding_detail = Some(detail);
    }
}

/// Subject of a finding that is about the document rather than a component.
pub const DOCUMENT_SUBJECT: &str = "document";

/// Prefix of the reserved dependency-edge subject form.
const EDGE_SUBJECT_PREFIX: &str = "edge:";

/// Prepended to a component's canonical id that would otherwise read as the
/// document subject or an edge subject (or as an id prefixed this way).
const COMPONENT_SUBJECT_PREFIX: &str = "component:";

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

/// What `finding` is about, the `<subject>` of its finding key: the
/// offending component's canonical id, or [`DOCUMENT_SUBJECT`]. Several
/// findings of one rule on one subject are told apart by their
/// [`FindingIdentity::finding_detail`], not by the subject.
///
/// A canonical id falls back to the bom-ref or SPDXID, which can be any
/// string, so a component id that reads `document`, or starts with `edge:` or
/// `component:`, is written with `component:` prepended: a component with the
/// bom-ref `document` must not share the subject of a rule's document-level
/// finding.
#[must_use]
pub fn finding_subject<F: FindingIdentity + ?Sized>(finding: &F) -> Cow<'_, str> {
    subject_of(finding.component_id())
}

/// The `<subject>` of a finding about the component whose canonical id is
/// `component_id`, or about the document when it is `None`.
fn subject_of(component_id: Option<&str>) -> Cow<'_, str> {
    match component_id {
        None => Cow::Borrowed(DOCUMENT_SUBJECT),
        Some(id)
            if id == DOCUMENT_SUBJECT
                || id.starts_with(EDGE_SUBJECT_PREFIX)
                || id.starts_with(COMPONENT_SUBJECT_PREFIX) =>
        {
            Cow::Owned(format!("{COMPONENT_SUBJECT_PREFIX}{id}"))
        }
        Some(id) => Cow::Borrowed(id),
    }
}

/// The finding key of `finding` reported under `level`:
/// `<standard>|<rule id>|<subject>`, or `<standard>|<rule id>:<detail>|<subject>`
/// when it carries a [`FindingIdentity::finding_detail`] (percent-encoded,
/// see the module docs).
#[must_use]
pub fn finding_key<F: FindingIdentity + ?Sized>(level: ComplianceLevel, finding: &F) -> String {
    compose_finding_key(
        standard_key(level),
        finding.rule_id(),
        finding.finding_detail(),
        finding.component_id(),
    )
}

/// A key in the shape of [`finding_key`] from its parts: `scope` in place of
/// the standard (SARIF results that are not compliance findings use a
/// surface name such as `diff` or `view`), the rule id, the optional detail
/// (percent-encoded) and the canonical id of the component the result is
/// about, or `None` for the document.
pub(crate) fn compose_finding_key(
    scope: &str,
    rule_id: &str,
    detail: Option<&str>,
    component_id: Option<&str>,
) -> String {
    let mut key = format!("{scope}|{rule_id}");
    if let Some(detail) = detail {
        key.push(':');
        for c in detail.chars() {
            match c {
                '%' => key.push_str("%25"),
                '|' => key.push_str("%7C"),
                ':' => key.push_str("%3A"),
                c => key.push(c),
            }
        }
    }
    key.push('|');
    key.push_str(&subject_of(component_id));
    key
}

/// Number the repeats among `findings` that carry the same rule, subject
/// and [`FindingIdentity::finding_detail`]: the second gets `#2` appended to
/// its detail, the third `#3`, and so on, in report order, skipping a
/// numbered detail another finding already carries. Findings without a
/// detail are left alone.
///
/// A repeat means the SBOM lists one entry twice — two CycloneDX
/// `vulnerabilities[]` entries with the same id for one component, two
/// SPDX 3.0 Vulnerability elements with the same id attached to one
/// component, or SPDX 3.0 statements about one vulnerability and component
/// that contradict each other (an `AFFECTS` relationship and a
/// `not_affected` assessment) — and both entries are reported. (Statements
/// that agree, such as an `AFFECTS` relationship and an `affected` or CVSS
/// assessment, are one entry: the parser merges them.) Numbering keeps a
/// finding key per finding, and the first occurrence keeps the plain
/// detail. `ComplianceChecker::check()` runs this on every result.
pub(crate) fn number_repeated_details<F: NumberedDetail>(findings: &mut [F]) {
    use std::collections::HashSet;
    // Rule, subject and detail as the finding key spells them.
    type Identity = (&'static str, String, String);
    let identity = |f: &F, detail: String| -> Identity {
        (f.rule_id(), finding_subject(f).into_owned(), detail)
    };
    let taken: HashSet<Identity> = findings
        .iter()
        .filter_map(|f| Some(identity(f, f.finding_detail()?.to_string())))
        .collect();
    let mut seen: HashSet<Identity> = HashSet::new();
    for f in findings.iter_mut() {
        let Some(detail) = f.finding_detail().map(str::to_string) else {
            continue;
        };
        if seen.insert(identity(f, detail.clone())) {
            continue;
        }
        let numbered = (2..)
            .map(|n| format!("{detail}#{n}"))
            .find(|candidate| {
                let candidate = identity(f, candidate.clone());
                !taken.contains(&candidate) && !seen.contains(&candidate)
            })
            .expect("an unbounded range yields a free number");
        seen.insert(identity(f, numbered.clone()));
        f.set_finding_detail(numbered);
    }
}

/// The opaque id of a finding key: [`FINDING_ID_PREFIX`] followed by the
/// first 16 lowercase hex digits of SHA-256 of the key's UTF-8 bytes.
#[must_use]
pub fn finding_id(finding_key: &str) -> String {
    let fingerprint = finding_fingerprint(finding_key);
    let mut id = String::with_capacity(FINDING_ID_PREFIX.len() + 16);
    id.push_str(FINDING_ID_PREFIX);
    id.push_str(&fingerprint[..16]);
    id
}

/// The full fingerprint of a finding key: the 64 lowercase hex digits of
/// SHA-256 of the key's UTF-8 bytes. SARIF output carries it as the
/// `sbomToolsFinding/v1` partial fingerprint; [`finding_id`] is its first 16
/// digits behind a prefix.
#[must_use]
pub fn finding_fingerprint(finding_key: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(finding_key.as_bytes());
    let mut hex = String::with_capacity(64);
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
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

    #[test]
    fn detail_follows_the_rule_id_after_a_colon() {
        let violations = ntia_violations();
        let mut supplier = find(&violations, "SBOM-NTIA-SUPPLIER").clone();
        supplier.finding_detail = Some("CVE-2026-0001".to_string());
        assert_eq!(
            finding_key(ComplianceLevel::NtiaMinimum, &supplier),
            "ntia|SBOM-NTIA-SUPPLIER:CVE-2026-0001|pkg:npm/lodash@4.17.21"
        );
        let mut author = find(&violations, "SBOM-NTIA-AUTHOR").clone();
        author.finding_detail = Some(String::new());
        assert_eq!(
            finding_key(ComplianceLevel::NtiaMinimum, &author),
            "ntia|SBOM-NTIA-AUTHOR:|document",
            "an empty detail still differs from none"
        );
    }

    #[test]
    fn detail_percent_encodes_the_separators() {
        let violations = ntia_violations();
        let mut v = find(&violations, "SBOM-NTIA-AUTHOR").clone();
        v.finding_detail = Some("100%|a:b".to_string());
        assert_eq!(
            finding_key(ComplianceLevel::NtiaMinimum, &v),
            "ntia|SBOM-NTIA-AUTHOR:100%25%7Ca%3Ab|document"
        );
    }

    /// The parse the module docs describe: standard before the first `|`,
    /// rule id up to the first `:` or `|` after it, the encoded detail up to
    /// the second `|`, the subject after it.
    fn split_key(key: &str) -> (&str, &str, Option<String>, &str) {
        let (standard, rest) = key.split_once('|').expect("first separator");
        let (head, subject) = rest.split_once('|').expect("second separator");
        let (rule_id, detail) = match head.split_once(':') {
            Some((rule_id, encoded)) => (
                rule_id,
                Some(
                    encoded
                        .replace("%7C", "|")
                        .replace("%3A", ":")
                        .replace("%25", "%"),
                ),
            ),
            None => (head, None),
        };
        (standard, rule_id, detail, subject)
    }

    /// Whatever the detail and subject contain, the key splits back into
    /// exactly its parts, so two findings share a key only when standard,
    /// rule, detail and subject are all equal.
    #[test]
    fn keys_split_back_into_their_parts() {
        let violations = ntia_violations();
        let base = find(&violations, "SBOM-NTIA-SUPPLIER");
        let mut keys = std::collections::BTreeSet::new();
        let details = [
            None,
            Some(""),
            Some("TLS_AES_256_GCM_SHA384"),
            Some("a|b"),
            Some("a:b"),
            Some("100%"),
            Some("%7C"),
            Some("%3A|:%25"),
        ];
        let subjects = [
            None,
            Some("pkg:npm/x@1"),
            Some("a|b:c"),
            Some("b|c"),
            Some("document"),
            Some("edge:a->b"),
            Some("component:document"),
        ];
        for detail in details {
            for subject in subjects {
                let mut v = base.clone();
                v.finding_detail = detail.map(str::to_string);
                v.component_id = subject.map(str::to_string);
                let key = finding_key(ComplianceLevel::Cisa2026, &v);
                let (standard, rule_id, parsed_detail, parsed_subject) = split_key(&key);
                assert_eq!(standard, "cisa-2026", "{key}");
                assert_eq!(rule_id, "SBOM-NTIA-SUPPLIER", "{key}");
                assert_eq!(parsed_detail.as_deref(), detail, "{key}");
                let component = parsed_subject.strip_prefix("component:");
                let expected = match subject {
                    None => DOCUMENT_SUBJECT,
                    Some(id) if component.is_some() => {
                        assert_eq!(component, Some(id), "{key}");
                        parsed_subject
                    }
                    Some(id) => id,
                };
                assert_eq!(parsed_subject, expected, "{key}");
                assert!(keys.insert(key.clone()), "two inputs share {key}");
            }
        }
    }

    /// A component's canonical id falls back to its bom-ref, which can read
    /// `document` or `edge:…`: such an id is prefixed, so the component never
    /// shares the subject of a document-level (or edge) finding.
    #[test]
    fn component_ids_never_read_as_another_kind_of_subject() {
        let violations = ntia_violations();
        let mut v = find(&violations, "SBOM-NTIA-SUPPLIER").clone();
        for (component_id, subject) in [
            (None, "document"),
            (Some("document"), "component:document"),
            (Some("edge:a->b"), "component:edge:a->b"),
            (Some("component:document"), "component:component:document"),
            (Some("pkg:npm/lodash@4.17.21"), "pkg:npm/lodash@4.17.21"),
            (Some("documents"), "documents"),
        ] {
            v.component_id = component_id.map(str::to_string);
            assert_eq!(finding_subject(&v), subject, "{component_id:?}");
        }
    }

    fn with_detail(base: &Violation, detail: Option<&str>, subject: Option<&str>) -> Violation {
        let mut v = base.clone();
        v.finding_detail = detail.map(str::to_string);
        v.component_id = subject.map(str::to_string);
        v
    }

    fn details(violations: &[Violation]) -> Vec<Option<&str>> {
        violations
            .iter()
            .map(|v| v.finding_detail.as_deref())
            .collect()
    }

    /// A repeat of rule, subject and detail is numbered in report order; the
    /// first occurrence, other subjects and findings without a detail keep
    /// theirs.
    #[test]
    fn repeated_details_are_numbered_in_report_order() {
        let violations = ntia_violations();
        let base = find(&violations, "SBOM-NTIA-SUPPLIER");
        let mut repeated = vec![
            with_detail(base, Some("CVE-1"), Some("pkg:a")),
            with_detail(base, Some("CVE-1"), Some("pkg:b")),
            with_detail(base, Some("CVE-1"), Some("pkg:a")),
            with_detail(base, None, Some("pkg:a")),
            with_detail(base, Some("CVE-1"), Some("pkg:a")),
            with_detail(base, Some("CVE-2"), Some("pkg:a")),
        ];
        number_repeated_details(&mut repeated);
        assert_eq!(
            details(&repeated),
            [
                Some("CVE-1"),
                Some("CVE-1"),
                Some("CVE-1#2"),
                None,
                Some("CVE-1#3"),
                Some("CVE-2"),
            ]
        );
    }

    /// A number another finding's detail already spells is skipped, so the
    /// numbered repeat cannot collide with it.
    #[test]
    fn numbering_skips_details_already_taken() {
        let violations = ntia_violations();
        let base = find(&violations, "SBOM-NTIA-SUPPLIER");
        let mut repeated = vec![
            with_detail(base, Some("suite"), None),
            with_detail(base, Some("suite"), None),
            with_detail(base, Some("suite#2"), None),
        ];
        number_repeated_details(&mut repeated);
        assert_eq!(
            details(&repeated),
            [Some("suite"), Some("suite#3"), Some("suite#2")]
        );
        let keys: std::collections::BTreeSet<String> = repeated
            .iter()
            .map(|v| finding_key(ComplianceLevel::NtiaMinimum, v))
            .collect();
        assert_eq!(keys.len(), repeated.len(), "{keys:?}");
    }

    /// A passed check is keyed exactly like a violation, and its repeats
    /// are numbered the same way.
    #[test]
    fn passed_checks_share_the_key_scheme_and_the_numbering() {
        use crate::quality::PassedCheck;
        let pass = |detail: Option<&str>| PassedCheck {
            rule_id: "SBOM-PQC-009",
            message: "'ML-KEM-1024' uses NIST-approved PQC algorithm".to_string(),
            element: Some("ML-KEM-1024".to_string()),
            component_id: Some("crypto/algorithm/ml-kem-1024".to_string()),
            finding_detail: detail.map(str::to_string),
            requirement: "FIPS 203/204/205: approved".to_string(),
            standard_refs: Vec::new(),
        };
        assert_eq!(
            finding_key(ComplianceLevel::NistPqc, &pass(None)),
            "pqc|SBOM-PQC-009|crypto/algorithm/ml-kem-1024"
        );
        assert_eq!(
            finding_key(ComplianceLevel::NistPqc, &pass(Some("a:b"))),
            "pqc|SBOM-PQC-009:a%3Ab|crypto/algorithm/ml-kem-1024"
        );
        let mut repeated = vec![pass(Some("a")), pass(Some("a")), pass(None)];
        number_repeated_details(&mut repeated);
        let details: Vec<Option<&str>> = repeated
            .iter()
            .map(|p| p.finding_detail.as_deref())
            .collect();
        assert_eq!(details, [Some("a"), Some("a#2"), None]);
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

    /// The fingerprint is the whole digest the id is cut from.
    #[test]
    fn fingerprint_is_the_full_sha256_of_the_key() {
        let key = "ntia|SBOM-NTIA-AUTHOR|document";
        let fingerprint = finding_fingerprint(key);
        assert_eq!(fingerprint.len(), 64);
        assert!(fingerprint.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(fingerprint.starts_with("60072ae05d1ef4b8"), "{fingerprint}");
        assert_eq!(
            finding_id(key),
            format!("{FINDING_ID_PREFIX}{}", &fingerprint[..16])
        );
    }

    /// The composed key of a violation's parts is its finding key.
    #[test]
    fn composed_keys_match_finding_keys() {
        let violations = ntia_violations();
        for v in &violations {
            assert_eq!(
                compose_finding_key(
                    standard_key(ComplianceLevel::NtiaMinimum),
                    v.rule_id,
                    v.finding_detail.as_deref(),
                    v.component_id.as_deref(),
                ),
                finding_key(ComplianceLevel::NtiaMinimum, v)
            );
        }
        assert_eq!(
            compose_finding_key("diff", "SBOM-TOOLS-005", Some("CVE-1:x"), Some("document")),
            "diff|SBOM-TOOLS-005:CVE-1%3Ax|component:document"
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
    fn standard_rule_detail_and_subject_each_change_the_id() {
        let violations = ntia_violations();
        let original = find(&violations, "SBOM-NTIA-SUPPLIER");
        let id = finding_id(&finding_key(ComplianceLevel::NtiaMinimum, original));

        let other_standard = finding_id(&finding_key(ComplianceLevel::Cisa2026, original));
        let mut other_rule = original.clone();
        other_rule.rule_id = "SBOM-NTIA-VERSION";
        let mut with_detail = original.clone();
        with_detail.finding_detail = Some("CVE-2026-0001".to_string());
        let mut other_detail = original.clone();
        other_detail.finding_detail = Some("CVE-2026-0002".to_string());
        let detail_id = finding_id(&finding_key(ComplianceLevel::NtiaMinimum, &with_detail));
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
            ("detail", detail_id.clone()),
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
        assert_ne!(
            finding_id(&finding_key(ComplianceLevel::NtiaMinimum, &other_detail)),
            detail_id,
            "a different detail must change the id"
        );
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

    /// The key splits unambiguously only while neither the standard key nor
    /// a rule id can contain a `|` or a `:`.
    #[test]
    fn key_separators_never_appear_in_standards_or_rule_ids() {
        for level in ComplianceLevel::all() {
            let standard = standard_key(*level);
            assert!(!standard.contains(['|', ':']), "{level:?}");
        }
        for rule_id in crate::quality::all_rule_ids() {
            assert!(!rule_id.contains(['|', ':']), "{rule_id}");
        }
    }
}
