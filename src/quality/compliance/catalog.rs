//! The rule catalogue: what the registry records about each compliance rule,
//! as data. `sbom-tools rules` prints it; its JSON form, the
//! `sbom-tools/rules/v1` document (`reports::generate_rule_catalog_json`),
//! is the same for every caller.
//!
//! An entry joins a rule's [`RuleMeta`](super::RuleMeta) with the standards
//! whose checks report it ([`rules_for_level`]) and resolves each standard
//! reference to the label and URL the SARIF help shows.

use super::registry::lookup_static_rule_id;
use super::{
    ComplianceLevel, FieldAdvice, FormatAdvice, RemediationFormat, RuleKind, StandardKind,
    StandardRef, StandardSelector, ViolationSeverity, all_rule_ids, generic_rule_id_for_level,
    rule_kind, rule_meta, rules_for_level, standard_key,
};
use serde::{Serialize, Serializer};

/// One rule of the catalogue: everything the registry records about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct RuleCatalogEntry {
    /// The rule id: a violation's `rule_id`, a SARIF result's `ruleId`.
    pub id: &'static str,
    /// PascalCase name, the SARIF `reportingDescriptor.name`.
    pub name: &'static str,
    /// What the check looks for, the SARIF `shortDescription`.
    pub description: &'static str,
    /// The severity the rule reports at. A check may escalate or relax it by
    /// product class, CRA phase or context.
    pub default_severity: ViolationSeverity,
    /// Whether the rule reports findings or checks the SBOM passed.
    #[serde(serialize_with = "serialize_kind")]
    pub kind: RuleKind,
    /// Whether this is a family fallback rule: no check emits it, and the
    /// SARIF writer files a finding without a registered rule under it.
    pub fallback: bool,
    /// The standards whose reports carry the rule, as canonical `--standard`
    /// values (`minimum`, `standard` and `comprehensive` for the quality
    /// profiles), in [`ComplianceLevel::all`] order. For a fallback rule, the
    /// standards it is the fallback of.
    pub standards: Vec<&'static str>,
    /// The clauses the rule implements, in display order.
    pub references: Vec<RuleReference>,
    /// The rule's documentation link: the URL of the first reference that
    /// has one, else the page of the rule's standard.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help_uri: Option<String>,
    /// How to fix a finding, in words that hold for every SBOM format.
    pub remediation: &'static str,
    /// The first sentence of [`Self::remediation`].
    pub remediation_summary: &'static str,
    /// Where the fix goes in each SBOM format; `None` when the fix is the
    /// same in every format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advice: Option<RuleAdvice>,
}

/// A clause a rule implements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct RuleReference {
    /// The referenced standard, as a violation's `standard_refs` name it.
    pub standard: StandardKind,
    /// The clause within the standard, e.g. `Art. 24`.
    pub id: &'static str,
    /// The reference as a reader cites it, e.g. `CRA Art. 24`.
    pub label: String,
    /// The standard's canonical URL, when one is known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help_uri: Option<String>,
}

/// Where a rule's fix goes in each SBOM format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct RuleAdvice {
    /// CycloneDX (JSON or XML).
    pub cyclonedx: RuleFormatAdvice,
    /// SPDX 2.x (JSON, tag-value or RDF/XML).
    pub spdx2: RuleFormatAdvice,
    /// SPDX 3.0 (JSON-LD).
    pub spdx3: RuleFormatAdvice,
}

/// Where a rule's fix goes in one SBOM format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct RuleFormatAdvice {
    /// The fix in this format, written to follow the format's label
    /// ("CycloneDX: set components[].supplier.name.").
    pub text: &'static str,
    /// The field to set, in the format's own shape; `None` when the format
    /// has no field the check reads.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<&'static str>,
}

impl RuleAdvice {
    /// The advice for `format`.
    #[must_use]
    pub const fn get(&self, format: RemediationFormat) -> &RuleFormatAdvice {
        match format {
            RemediationFormat::CycloneDx => &self.cyclonedx,
            RemediationFormat::Spdx2 => &self.spdx2,
            RemediationFormat::Spdx3 => &self.spdx3,
        }
    }
}

impl From<&FormatAdvice> for RuleAdvice {
    fn from(advice: &FormatAdvice) -> Self {
        let format = |field: &FieldAdvice| RuleFormatAdvice {
            text: field.text,
            field: field.field,
        };
        Self {
            cyclonedx: format(&advice.cyclonedx),
            spdx2: format(&advice.spdx2),
            spdx3: format(&advice.spdx3),
        }
    }
}

/// Which rules [`rule_catalog`] returns.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleCatalogFilter {
    levels: Vec<ComplianceLevel>,
}

impl RuleCatalogFilter {
    /// Every registered rule, in registry order.
    #[must_use]
    pub fn all() -> Self {
        Self::default()
    }

    /// The rules of `levels`: each level's list in the order given, then the
    /// fallback rule of each level. A level given twice counts once.
    #[must_use]
    pub fn for_levels(levels: impl IntoIterator<Item = ComplianceLevel>) -> Self {
        let mut unique = Vec::new();
        for level in levels {
            if !unique.contains(&level) {
                unique.push(level);
            }
        }
        Self { levels: unique }
    }

    /// The rules of the standards `standards` names, as
    /// [`for_levels`](Self::for_levels) orders them.
    #[must_use]
    pub fn for_standards(standards: impl IntoIterator<Item = StandardSelector>) -> Self {
        Self::for_levels(standards.into_iter().map(StandardSelector::level))
    }

    /// The selected levels; empty when every rule is selected.
    #[must_use]
    pub fn levels(&self) -> &[ComplianceLevel] {
        &self.levels
    }
}

/// The catalogue entries `filter` selects.
///
/// Without levels: every registered rule, in registry order. With levels:
/// the rules each level's checks report, in the order of the levels and of
/// each level's list ([`rules_for_level`]), then each level's fallback rule;
/// a rule two levels share appears once. This is the order of the `rules[]`
/// of a SARIF run that checks those levels, which declares a fallback rule
/// only when it has a finding without a registered rule.
#[must_use]
pub fn rule_catalog(filter: &RuleCatalogFilter) -> Vec<RuleCatalogEntry> {
    if filter.levels.is_empty() {
        return all_rule_ids()
            .iter()
            .filter_map(|id| rule_catalog_entry(id))
            .collect();
    }
    let mut ids: Vec<&'static str> = Vec::new();
    let fallbacks = filter
        .levels
        .iter()
        .map(|level| generic_rule_id_for_level(*level));
    for id in filter
        .levels
        .iter()
        .flat_map(|level| rules_for_level(*level).iter().copied())
        .chain(fallbacks)
    {
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    ids.into_iter().filter_map(rule_catalog_entry).collect()
}

/// The catalogue entry of the registered rule `rule_id`; `None` for an id
/// the registry does not know.
#[must_use]
pub fn rule_catalog_entry(rule_id: &str) -> Option<RuleCatalogEntry> {
    let id = lookup_static_rule_id(rule_id)?;
    let meta = rule_meta(id)?;
    let fallback = is_fallback(id);
    let standards = ComplianceLevel::all()
        .iter()
        .filter(|level| {
            if fallback {
                generic_rule_id_for_level(**level) == id
            } else {
                rules_for_level(**level).contains(&id)
            }
        })
        .map(|level| standard_key(*level))
        .collect();
    let references: Vec<RuleReference> = meta
        .refs
        .iter()
        .map(|(standard, clause)| RuleReference::new(*standard, clause))
        .collect();
    let help_uri = references
        .iter()
        .find_map(|r| r.help_uri.clone())
        .or_else(|| rule_family_help_uri(id).map(str::to_string));
    Some(RuleCatalogEntry {
        id,
        name: meta.name,
        description: meta.short_description,
        default_severity: meta.default_severity,
        kind: rule_kind(id).unwrap_or(RuleKind::Finding),
        fallback,
        standards,
        references,
        help_uri,
        remediation: meta.remediation,
        remediation_summary: first_sentence(meta.remediation),
        advice: meta.advice.map(RuleAdvice::from),
    })
}

impl RuleReference {
    fn new(standard: StandardKind, id: &'static str) -> Self {
        let reference = StandardRef::new(standard, id);
        Self {
            standard,
            id,
            label: reference.citation(),
            help_uri: reference.help_uri,
        }
    }
}

impl StandardRef {
    /// The reference as a reader cites it: `CRA Art. 13(7)`, `CRA Annex I
    /// Part II (1)`, `NTIA Minimum Elements`, `prEN 40000-1-3: PRE-7-RQ-04`.
    /// The clause alone when it already names its standard.
    #[must_use]
    pub fn citation(&self) -> String {
        let label = self.standard.label();
        match self.standard {
            StandardKind::CraArticle | StandardKind::CraAnnex => format!("CRA {}", self.id),
            _ if self.id.starts_with(label) => self.id.clone(),
            _ if label.ends_with(self.id.as_str()) => label.to_string(),
            _ => format!("{label}: {}", self.id),
        }
    }
}

/// Whether `id` is a family fallback rule (`generic_rule_id_for_level`).
fn is_fallback(id: &str) -> bool {
    ComplianceLevel::all()
        .iter()
        .any(|level| generic_rule_id_for_level(*level) == id)
}

/// The first sentence of `text`: up to the first full stop that a space and
/// a capital letter or `§` follow, or all of `text`. An abbreviation such as
/// `Art. 13` or `e.g. as` is followed by a digit or a lower-case word, so it
/// ends no sentence.
fn first_sentence(text: &'static str) -> &'static str {
    for (at, _) in text.match_indices(". ") {
        if text[at + 2..].starts_with(|c: char| c.is_ascii_uppercase() || c == '§') {
            return &text[..=at];
        }
    }
    text
}

fn serialize_kind<S: Serializer>(kind: &RuleKind, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(match kind {
        RuleKind::Finding => "finding",
        RuleKind::Pass => "pass",
    })
}

/// Canonical URL for a rule family, derived from the rule ID's prefix: the
/// page a rule links when none of its references has a URL. `None` for rule
/// families that do not map to a single regulation or specification (e.g.,
/// the `SBOM-TOOLS-*` change-tracking rules).
pub(crate) fn rule_family_help_uri(rule_id: &str) -> Option<&'static str> {
    // EUCC before any more-generic prefix: these rules cite Implementing
    // Regulation (EU) 2024/482, not the CRA regulation.
    if rule_id.starts_with("SBOM-EUCC") {
        Some("https://eur-lex.europa.eu/eli/reg_impl/2024/482/oj/eng")
    } else if rule_id.starts_with("SBOM-CRA-") {
        Some("https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng")
    } else if rule_id.starts_with("SBOM-BSI-") {
        // BSI's stable English shortlink for TR-03183 (printed in the
        // v2.1.0 document imprint).
        Some("https://bsi.bund.de/dok/TR-03183-en")
    } else if rule_id.starts_with("SBOM-NIST-SSDF-") || rule_id.starts_with("SBOM-SSDF-") {
        Some("https://doi.org/10.6028/NIST.SP.800-218")
    } else if rule_id.starts_with("SBOM-EO14028-") || rule_id.starts_with("SBOM-EO-14028-") {
        Some("https://www.federalregister.gov/d/2021-10460")
    } else if rule_id.starts_with("SBOM-FDA-") {
        // Current edition: "Quality Management System Considerations…"
        // (final, 2026-02-03); FDA's media id is the stable handle.
        Some("https://www.fda.gov/media/119933/download")
    } else if rule_id.starts_with("SBOM-NTIA-") {
        Some("https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom")
    } else if rule_id.starts_with("SBOM-PQC-") || rule_id.starts_with("SBOM-NIST-PQC-") {
        Some("https://csrc.nist.gov/projects/post-quantum-cryptography")
    } else if rule_id.starts_with("SBOM-QUALITY-") {
        // Tool-defined quality rules (Minimum / Standard / Comprehensive)
        // follow no external standard; link the tool's own documentation.
        Some(concat!(env!("CARGO_PKG_REPOSITORY"), "#validate"))
    } else if rule_id.starts_with("SBOM-CNSA2-") {
        Some(
            "https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF",
        )
    } else if rule_id.starts_with("SBOM-CSAF-") {
        Some("https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html")
    } else if rule_id.starts_with("SBOM-AIBOM-") {
        Some("https://cyclonedx.org/capabilities/mlbom/")
    } else if rule_id.starts_with("SBOM-AIACT-") {
        Some("https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng")
    } else if rule_id.starts_with("SBOM-BSIAI-") {
        Some(
            "https://www.cisa.gov/resources-tools/resources/software-bill-materials-ai-minimum-elements",
        )
    } else if rule_id.starts_with("SBOM-CISA2026-") {
        // 2026 Minimum Elements for an SBOM — CISA's resource page is the
        // stable handle (the PDF path under /sites/default/files churns).
        Some(
            "https://www.cisa.gov/resources-tools/resources/2026-minimum-elements-software-bill-materials-sbom",
        )
    } else if rule_id.starts_with("SBOM-PCI-") {
        // PCI DSS v4.0.1 is license-gated; the document library is the
        // stable public home.
        Some("https://www.pcisecuritystandards.org/document_library/")
    } else if rule_id.starts_with("SBOM-FSCT-") {
        // CISA Framing Software Component Transparency (3rd ed., 2024).
        Some(
            "https://www.cisa.gov/resources-tools/resources/framing-software-component-transparency-2024",
        )
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_sentence_stops_at_a_sentence_end_only() {
        assert_eq!(
            first_sentence("Reference the policy (Art. 13(8)). Set the key."),
            "Reference the policy (Art. 13(8))."
        );
        assert_eq!(
            first_sentence("Publish it separately (e.g. as CSAF advisories). Done."),
            "Publish it separately (e.g. as CSAF advisories)."
        );
        assert_eq!(
            first_sentence("Add a SHA-512 hash. §3.2.1 permits omission."),
            "Add a SHA-512 hash."
        );
        assert_eq!(first_sentence("One sentence only."), "One sentence only.");
    }

    /// Every summary is a whole sentence: it ends where the remediation's
    /// first sentence ends, never inside an abbreviation.
    #[test]
    fn remediation_summaries_are_whole_sentences() {
        for entry in rule_catalog(&RuleCatalogFilter::all()) {
            let summary = entry.remediation_summary;
            assert!(
                entry.remediation.starts_with(summary) && summary.ends_with('.'),
                "{}: {summary}",
                entry.id
            );
            for abbreviation in [" e.g.", " i.e.", " Art.", " Rev.", " No.", " cf.", " vs."] {
                assert!(
                    !summary.ends_with(abbreviation),
                    "{}: the summary ends inside {abbreviation:?}: {summary}",
                    entry.id
                );
            }
        }
    }

    #[test]
    fn the_unfiltered_catalogue_is_the_registry() {
        let ids: Vec<&str> = rule_catalog(&RuleCatalogFilter::all())
            .iter()
            .map(|e| e.id)
            .collect();
        assert_eq!(ids, all_rule_ids());
    }

    /// A filtered catalogue lists each level's rules in list order, a rule
    /// two levels share once, then the levels' fallback rules.
    #[test]
    fn a_filtered_catalogue_follows_the_level_lists() {
        let filter = RuleCatalogFilter::for_levels([
            ComplianceLevel::CraPhase2,
            ComplianceLevel::CraOssSteward,
            ComplianceLevel::CraPhase2,
        ]);
        assert_eq!(
            filter.levels(),
            [ComplianceLevel::CraPhase2, ComplianceLevel::CraOssSteward]
        );
        let ids: Vec<&str> = rule_catalog(&filter).iter().map(|e| e.id).collect();
        let mut expected: Vec<&str> = rules_for_level(ComplianceLevel::CraPhase2).to_vec();
        expected.extend(["SBOM-CRA-ART-24", "SBOM-CRA-ART-24-SUPPLIER"]);
        expected.push("SBOM-CRA-GENERAL");
        assert_eq!(ids, expected);
    }

    #[test]
    fn an_entry_carries_the_registry_metadata() {
        let entry = rule_catalog_entry("SBOM-CRA-ART-24").expect("registered");
        let meta = rule_meta("SBOM-CRA-ART-24").expect("registered");
        assert_eq!(entry.name, meta.name);
        assert_eq!(entry.description, meta.short_description);
        assert_eq!(entry.default_severity, ViolationSeverity::Error);
        assert_eq!(entry.kind, RuleKind::Finding);
        assert!(!entry.fallback);
        assert_eq!(entry.standards, ["oss-steward"]);
        assert_eq!(entry.references.len(), 1);
        assert_eq!(entry.references[0].label, "CRA Art. 24");
        assert_eq!(
            entry.references[0].help_uri.as_deref(),
            Some("https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng")
        );
        assert_eq!(entry.help_uri, entry.references[0].help_uri);
        let advice = entry.advice.expect("format advice");
        assert_eq!(
            advice.get(RemediationFormat::CycloneDx).text,
            meta.advice.expect("format advice").cyclonedx.text
        );

        let pass = rule_catalog_entry("SBOM-PQC-009").expect("registered");
        assert_eq!(pass.kind, RuleKind::Pass);

        let fallback = rule_catalog_entry("SBOM-CRA-GENERAL").expect("registered");
        assert!(fallback.fallback);
        assert_eq!(fallback.standards, ["cra-phase1", "cra", "oss-steward"]);
        assert!(rule_catalog_entry("SBOM-NO-SUCH-RULE").is_none());
    }
}
