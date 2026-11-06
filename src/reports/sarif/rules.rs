//! The SARIF rule catalogue: one `reportingDescriptor` per rule a run can
//! report, with the help a code-scanning UI shows for it.
//!
//! Compliance rules come from the rule registry (`rule_meta`): name, short
//! description, default level, standard references and remediation. The
//! change-tracking, vulnerability, end-of-life, quality-recommendation and
//! AI-readiness rules are written here. Every descriptor carries a
//! `fullDescription`, a `help` text in plain text and Markdown, and a
//! `helpUri` when the rule has a canonical home.

use super::{Pending, SarifConfiguration, SarifLevel, SarifMessage};
use crate::quality::{
    ComplianceLevel, RemediationFormat, RuleMeta, StandardRef, ViolationSeverity, rule_meta,
    rules_for_level,
};
use crate::reports::escape::{escape_markdown_inline, markdown_link_destination};
use serde::Serialize;

/// Canonical URL for a SARIF rule, derived from its ID prefix. Returns
/// `None` for rule families that do not map to a single regulation /
/// specification (e.g., `SBOM-TOOLS-*` change-tracking rules). Registry
/// rules prefer the URL of their first standard reference.
pub(super) use crate::quality::rule_family_help_uri as rule_help_uri;

/// GitHub code scanning truncates longer `fullDescription` texts.
const MAX_FULL_DESCRIPTION: usize = 1024;

/// One SARIF `reportingDescriptor`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SarifRule {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) short_description: SarifMessage,
    pub(super) full_description: SarifMessage,
    pub(super) default_configuration: SarifConfiguration,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) help_uri: Option<String>,
    pub(super) help: SarifHelp,
}

/// A rule's `help`: the same guidance as plain text and as Markdown.
#[derive(Serialize)]
pub(super) struct SarifHelp {
    pub(super) text: String,
    pub(super) markdown: String,
}

impl SarifRule {
    /// A rule whose texts are written in this module rather than taken from
    /// the rule registry. `help` is one plain-text paragraph.
    fn tool(id: &str, name: &str, short: &str, level: SarifLevel, full: &str, help: &str) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            short_description: SarifMessage::new(short),
            full_description: SarifMessage::new(full),
            default_configuration: SarifConfiguration { level },
            help_uri: rule_help_uri(id).map(str::to_string),
            help: SarifHelp {
                text: help.to_string(),
                markdown: escape_markdown_inline(help),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Rules written here
// ---------------------------------------------------------------------------

/// (id, name, short description, level, full description, help) of the
/// change-tracking and end-of-life rules of `diff -o sarif`.
const DIFF_RULES: &[(&str, &str, &str, SarifLevel, &str, &str)] = &[
    (
        "SBOM-TOOLS-001",
        "ComponentAdded",
        "A new component was added to the SBOM",
        SarifLevel::Note,
        "A component of the new SBOM has no match in the old SBOM.",
        "Confirm that the added component is an intended dependency, and review its license, supplier and known vulnerabilities before release.",
    ),
    (
        "SBOM-TOOLS-002",
        "ComponentRemoved",
        "A component was removed from the SBOM",
        SarifLevel::Warning,
        "A component of the old SBOM has no match in the new SBOM.",
        "Confirm that the component was removed on purpose. An unexpected removal can mean that the SBOM generator missed part of the build.",
    ),
    (
        "SBOM-TOOLS-003",
        "VersionChanged",
        "A component version was changed",
        SarifLevel::Note,
        "A component matched across the two SBOMs changed its version or another field.",
        "Review the change: read the component's release notes, and check the new version's license and known vulnerabilities.",
    ),
    (
        "SBOM-TOOLS-004",
        "LicenseChanged",
        "A license was added or changed",
        SarifLevel::Warning,
        "A license expression that no component of the old SBOM declared appears in the new SBOM.",
        "Check the new license against the project's license policy (sbom-tools license-check) before release.",
    ),
    (
        "SBOM-TOOLS-005",
        "VulnerabilityIntroduced",
        "A new vulnerability was introduced",
        SarifLevel::Error,
        "A vulnerability affects a component of the new SBOM that it did not affect in the old SBOM.",
        "Upgrade or patch the affected component, or record in a VEX statement why the vulnerability does not affect the product.",
    ),
    (
        "SBOM-TOOLS-006",
        "VulnerabilityResolved",
        "A vulnerability was resolved",
        SarifLevel::Note,
        "A vulnerability that affected a component of the old SBOM no longer affects the new SBOM.",
        "No action is needed: the result records the fix.",
    ),
    (
        "SBOM-TOOLS-007",
        "SupplierChanged",
        "A component supplier was changed",
        SarifLevel::Warning,
        "A component matched across the two SBOMs names a different supplier.",
        "Confirm that the new supplier is expected: a supplier change can signal a fork, a change of maintainer or a substituted package.",
    ),
    (
        "SBOM-TOOLS-008",
        "MetadataChanged",
        "A document-level metadata field was changed",
        SarifLevel::Note,
        "A document-level field (name, spec version, creation time, creator tool, lifecycle phase, signature, ...) differs between the two SBOMs.",
        "Confirm that the change is expected, for example a regenerated SBOM or an upgraded generator.",
    ),
    (
        "SBOM-EOL-001",
        "ComponentEndOfLife",
        "A component has reached end-of-life",
        SarifLevel::Error,
        "End-of-life data marks the component's version as no longer supported.",
        "Upgrade to a supported release or replace the component: an end-of-life version receives no security updates.",
    ),
    (
        "SBOM-EOL-002",
        "ComponentApproachingEol",
        "A component is approaching end-of-life",
        SarifLevel::Warning,
        "End-of-life data shows the component's version reaching end-of-life soon.",
        "Plan the upgrade to a supported release before the end-of-life date.",
    ),
];

/// The rule catalogue of `diff -o sarif`: the change-tracking and
/// end-of-life rules, then the rules of `compliance`, the standard the new
/// SBOM was checked against (CRA Phase 2).
pub(super) fn diff_rules(compliance: ComplianceLevel) -> Vec<SarifRule> {
    let mut rules: Vec<SarifRule> = DIFF_RULES
        .iter()
        .map(|(id, name, short, level, full, help)| {
            SarifRule::tool(id, name, short, *level, full, help)
        })
        .collect();
    rules.extend(rules_for_standard(compliance));
    rules
}

/// The rule catalogue of `view -o sarif`: the vulnerability rule, then the
/// rules of `compliance`, the standard the SBOM was checked against (CRA
/// Phase 2).
pub(super) fn view_rules(compliance: ComplianceLevel) -> Vec<SarifRule> {
    let mut rules = vec![SarifRule::tool(
        "SBOM-VIEW-001",
        "VulnerabilityPresent",
        "A vulnerability is present in a component",
        SarifLevel::Warning,
        "A vulnerability affects a component of the SBOM.",
        "Upgrade or patch the affected component, or record in a VEX statement why the vulnerability does not affect the product.",
    )];
    rules.extend(rules_for_standard(compliance));
    rules
}

/// The descriptor of the `SBOM-QUALITY-REC-<CATEGORY>` rule a quality
/// recommendation of `category` reports under.
pub(super) fn quality_recommendation_rule(id: &str, category: &str) -> SarifRule {
    SarifRule::tool(
        id,
        &format!("QualityRecommendation{}", category.replace(' ', "")),
        &format!("Quality recommendation: {category}"),
        SarifLevel::Note,
        &format!(
            "A recommendation of the sbom-tools quality score in the {category} category: \
             the SBOM loses points there."
        ),
        &format!(
            "Follow the recommendation in the result message; it raises the SBOM's {category} \
             score. The result's properties give the number of affected components and the \
             estimated score impact."
        ),
    )
}

/// Map an AI-readiness check ID (`AI-001`..`AI-011`) to its SARIF rule ID.
/// Unknown IDs fall back to the `SBOM-AIBOM-GENERAL` rule so a future check
/// never silently drops (`AiCheck`/`AiReadinessMetrics` are `#[non_exhaustive]`).
pub(super) fn ai_check_to_rule_id(check_id: &str) -> &'static str {
    match check_id {
        "AI-001" => "SBOM-AIBOM-001",
        "AI-002" => "SBOM-AIBOM-002",
        "AI-003" => "SBOM-AIBOM-003",
        "AI-004" => "SBOM-AIBOM-004",
        "AI-005" => "SBOM-AIBOM-005",
        "AI-006" => "SBOM-AIBOM-006",
        "AI-007" => "SBOM-AIBOM-007",
        "AI-008" => "SBOM-AIBOM-008",
        "AI-009" => "SBOM-AIBOM-009",
        "AI-010" => "SBOM-AIBOM-010",
        "AI-011" => "SBOM-AIBOM-011",
        _ => "SBOM-AIBOM-GENERAL",
    }
}

/// Default SARIF severity for each AI-readiness check. AI transparency is a
/// best-practice (not a mandated minimum element), so there are no hard
/// `error`s; documentation gaps are `warning`, softer/contextual gaps `note`.
/// This is the single source of truth shared by the rule table and the results.
pub(super) fn aibom_level(check_id: &str) -> SarifLevel {
    match check_id {
        // AI-010 is the weight-hash integrity check and AI-011 the
        // exploitability/advisory-reference check: both are load-bearing
        // security signals (tamper verification and vulnerability tooling
        // linkage), so they are `warning` like the other load-bearing checks
        // rather than a soft `note`.
        "AI-001" | "AI-002" | "AI-003" | "AI-005" | "AI-009" | "AI-010" | "AI-011" => {
            SarifLevel::Warning
        }
        _ => SarifLevel::Note,
    }
}

/// (rule id, AI check id for the level lookup, PascalCase name, short
/// description, help) of the AI BOM model-card completeness rules. The short
/// descriptions match the scorer's `CHECK_DEFS` names exactly.
const AIBOM_RULES: &[(&str, &str, &str, &str, &str)] = &[
    (
        "SBOM-AIBOM-001",
        "AI-001",
        "AibomModelCardUrl",
        "Model card URL present",
        "Reference each machine-learning model's model card: in CycloneDX, an externalReferences entry of type model-card on the model component.",
    ),
    (
        "SBOM-AIBOM-002",
        "AI-002",
        "AibomArchitectureFamily",
        "Architecture family declared",
        "Declare each model's architecture family: in CycloneDX, modelCard.modelParameters.architectureFamily.",
    ),
    (
        "SBOM-AIBOM-003",
        "AI-003",
        "AibomTrainingDatasets",
        "Training datasets referenced",
        "Reference the datasets each model was trained on: in CycloneDX, modelCard.modelParameters.datasets, or nested data components that carry a data[] block.",
    ),
    (
        "SBOM-AIBOM-004",
        "AI-004",
        "AibomQuantitativeAnalysis",
        "Quantitative analysis present",
        "Record each model's performance metrics: in CycloneDX, modelCard.quantitativeAnalysis.performanceMetrics.",
    ),
    (
        "SBOM-AIBOM-005",
        "AI-005",
        "AibomFairnessAssessment",
        "Fairness assessments included",
        "Include each model's fairness assessments: in CycloneDX, modelCard.considerations.fairnessAssessments.",
    ),
    (
        "SBOM-AIBOM-006",
        "AI-006",
        "AibomEnergyConsumption",
        "Energy consumption disclosed",
        "Disclose the energy consumed to train each model: in CycloneDX, modelCard.considerations.environmentalConsiderations.energyConsumptions.",
    ),
    (
        "SBOM-AIBOM-007",
        "AI-007",
        "AibomUseCases",
        "Use-cases documented",
        "Document each model's intended use cases: in CycloneDX, modelCard.considerations.useCases.",
    ),
    (
        "SBOM-AIBOM-008",
        "AI-008",
        "AibomLimitations",
        "Known limitations stated",
        "State each model's known limitations: in CycloneDX, modelCard.considerations.technicalLimitations.",
    ),
    (
        "SBOM-AIBOM-009",
        "AI-009",
        "AibomEthicalConsiderations",
        "Ethical considerations present",
        "Record each model's ethical considerations: in CycloneDX, modelCard.considerations.ethicalConsiderations.",
    ),
    (
        "SBOM-AIBOM-010",
        "AI-010",
        "AibomModelWeightHashes",
        "Model weight hashes present",
        "Give each model component a hash of its weights, SHA-256 or stronger, so the weights can be verified against tampering: in CycloneDX, components[].hashes.",
    ),
    (
        "SBOM-AIBOM-011",
        "AI-011",
        "AibomExploitabilityReference",
        "Exploitability/advisory reference present",
        "Connect each model to vulnerability tooling: a vulnerability entry that affects it, or a security or advisory external reference an analyst can follow.",
    ),
    (
        "SBOM-AIBOM-GENERAL",
        "AI-GENERAL",
        "AibomGeneral",
        "AI BOM model-card completeness",
        "Complete the model card the result's message names: the check is newer than this rule catalogue.",
    ),
];

/// The rule catalogue of the AI-readiness profile of `quality -o sarif`.
pub(super) fn aibom_rules() -> Vec<SarifRule> {
    AIBOM_RULES
        .iter()
        .map(|(rule_id, check_id, name, desc, help)| {
            SarifRule::tool(
                rule_id,
                name,
                desc,
                aibom_level(check_id),
                &format!(
                    "AI-readiness check {check_id} of sbom-tools quality --profile ai-readiness: \
                     {desc} for every machine-learning model."
                ),
                help,
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Registry rules
// ---------------------------------------------------------------------------

/// The registry rule catalogue a standard's report declares: exactly the
/// rules the standard's checks can report ([`rules_for_level`]). A run adds
/// the standard's fallback rule only when it has a finding without a
/// registered rule ([`complete_rule_catalogue`]).
pub(super) fn rules_for_standard(level: ComplianceLevel) -> Vec<SarifRule> {
    registry_sarif_rules(rules_for_level(level))
}

/// Render SARIF reportingDescriptors for a curated slice of registry rule
/// ids. The registry — not a hand-maintained table — is the single source of
/// truth for descriptor id, name, shortDescription, help and default level,
/// so the catalogue can no longer drift from `rule_meta`. Slice ids must be
/// self-descriptors (`rule_meta(id).sarif_id == id`); this is enforced by
/// `sarif_rule_slices_are_self_descriptors` in the registry tests.
pub(super) fn registry_sarif_rules(ids: &[&str]) -> Vec<SarifRule> {
    ids.iter()
        .filter_map(|id| {
            let Some(meta) = rule_meta(id) else {
                debug_assert!(false, "SARIF rule slice id {id} missing from registry");
                return None;
            };
            debug_assert_eq!(
                meta.sarif_id, *id,
                "SARIF rule slices must list self-descriptor ids"
            );
            Some(registry_sarif_rule(id, &meta))
        })
        .collect()
}

/// Build one SARIF reportingDescriptor from its registry metadata.
///
/// - `fullDescription`: the short description and the standard clauses the
///   rule implements.
/// - `help`: the remediation, where the fix goes in each SBOM format, and the
///   references, as plain text and as Markdown.
/// - `helpUri`: the canonical URL of the first reference that has one (as
///   `help_uri` on a violation), else the rule family's home.
fn registry_sarif_rule(id: &str, meta: &RuleMeta) -> SarifRule {
    let refs: Vec<StandardRef> = meta
        .refs
        .iter()
        .map(|(kind, clause)| StandardRef::new(*kind, *clause))
        .collect();
    let help_uri = refs
        .iter()
        .find_map(|r| r.help_uri.clone())
        .or_else(|| rule_help_uri(id).map(str::to_string));
    SarifRule {
        id: id.to_string(),
        name: meta.name.to_string(),
        short_description: SarifMessage::new(meta.short_description),
        full_description: SarifMessage::new(full_description(meta.short_description, &refs)),
        default_configuration: SarifConfiguration {
            level: severity_level(meta.default_severity),
        },
        help_uri,
        help: registry_help(meta, &refs),
    }
}

/// The short description as a sentence, followed by the references.
fn full_description(short: &str, refs: &[StandardRef]) -> String {
    let mut text = short.trim_end_matches('.').to_string();
    text.push('.');
    if !refs.is_empty() {
        text.push_str(" References: ");
        text.push_str(
            &refs
                .iter()
                .map(StandardRef::citation)
                .collect::<Vec<_>>()
                .join("; "),
        );
        text.push('.');
    }
    truncate_chars(text, MAX_FULL_DESCRIPTION)
}

/// `text` cut to at most `max` characters, on a character boundary, with an
/// ellipsis when it was cut.
fn truncate_chars(text: String, max: usize) -> String {
    if text.chars().count() <= max {
        return text;
    }
    let mut cut: String = text.chars().take(max - 1).collect();
    cut.push('…');
    cut
}

/// The registry remediation of a rule as help text and Markdown. Registry
/// text is trusted, but it is still escaped for Markdown: field names such
/// as `components[].hashes` or `<value>` placeholders would otherwise render
/// as syntax.
fn registry_help(meta: &RuleMeta, refs: &[StandardRef]) -> SarifHelp {
    let mut text = meta.remediation.to_string();
    let mut markdown = escape_markdown_inline(meta.remediation);
    if let Some(advice) = meta.advice {
        text.push_str("\n\nWhere the fix goes:");
        markdown.push_str("\n\n**Where the fix goes**\n");
        for format in RemediationFormat::ALL {
            let advice = advice.get(format).text;
            text.push_str(&format!("\n- {}: {advice}", format.label()));
            markdown.push_str(&format!(
                "\n- **{}:** {}",
                format.label(),
                escape_markdown_inline(advice)
            ));
        }
    }
    if !refs.is_empty() {
        text.push_str("\n\nReferences:");
        markdown.push_str("\n\n**References**\n");
        for r in refs {
            let label = r.citation();
            match &r.help_uri {
                Some(uri) => {
                    text.push_str(&format!("\n- {label} ({uri})"));
                    markdown.push_str(&format!(
                        "\n- [{}]({})",
                        escape_markdown_inline(&label),
                        markdown_link_destination(uri)
                    ));
                }
                None => {
                    text.push_str(&format!("\n- {label}"));
                    markdown.push_str(&format!("\n- {}", escape_markdown_inline(&label)));
                }
            }
        }
    }
    SarifHelp { text, markdown }
}

const fn severity_level(severity: ViolationSeverity) -> SarifLevel {
    match severity {
        ViolationSeverity::Error => SarifLevel::Error,
        ViolationSeverity::Warning => SarifLevel::Warning,
        ViolationSeverity::Info => SarifLevel::Note,
    }
}

/// Dedup the rule catalogue by id and synthesize a reportingDescriptor for
/// any result ruleId the per-standard tables don't declare. SARIF 2.1.0
/// requires descriptor ids to be unique, and GitHub code scanning drops rule
/// metadata for results whose ruleId has no descriptor — this guarantees
/// both invariants no matter which checks fired. Added descriptors follow
/// the order the results first name them, so the catalogue is deterministic.
pub(super) fn complete_rule_catalogue(
    mut rules: Vec<SarifRule>,
    results: &[Pending<'_>],
) -> Vec<SarifRule> {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    rules.retain(|r| seen.insert(r.id.clone()));
    for res in results {
        let rule_id = res.rule_id();
        if seen.contains(rule_id) {
            continue;
        }
        seen.insert(rule_id.to_string());
        // Prefer the registry's descriptor identity when the emitted ruleId
        // is a registered self-descriptor (a rule in no per-standard slice,
        // such as the quality profiles' checks or a family fallback rule).
        if let Some(meta) = rule_meta(rule_id)
            && meta.sarif_id == rule_id
        {
            rules.push(registry_sarif_rule(rule_id, &meta));
            continue;
        }
        // CamelCase-ish name derived from the id (SBOM-EO14028-NAME → SbomEo14028Name)
        let name: String = rule_id
            .split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|seg| !seg.is_empty())
            .map(|seg| {
                let mut cs = seg.chars();
                cs.next()
                    .map(|f| f.to_ascii_uppercase().to_string() + &cs.as_str().to_ascii_lowercase())
                    .unwrap_or_default()
            })
            .collect();
        rules.push(SarifRule::tool(
            rule_id,
            &name,
            &format!("Compliance rule {rule_id}"),
            res.level(),
            "A compliance finding whose rule is not in the sbom-tools rule registry.",
            "No specific guidance exists for this rule: fix the element its requirement and message name.",
        ));
    }
    rules
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quality::all_rule_ids;

    /// The registry's `default_severity` and the SARIF rule catalogues must
    /// agree — the registry is documentation, the catalogue is what GitHub
    /// code scanning displays, and they had already drifted apart once
    /// (audit finding: registry.rs default_severity dead + wrong).
    #[test]
    fn registry_severity_matches_sarif_catalogue() {
        let mut mismatches = Vec::new();
        for level in ComplianceLevel::all() {
            for rule in rules_for_standard(*level) {
                let meta = rule_meta(&rule.id).expect("catalogue rules are registered");
                let expected = severity_level(meta.default_severity);
                if expected != rule.default_configuration.level {
                    mismatches.push(format!(
                        "{level:?}: {} registry={expected:?} catalogue={:?}",
                        rule.id, rule.default_configuration.level
                    ));
                }
            }
        }
        assert!(
            mismatches.is_empty(),
            "registry default_severity and SARIF catalogue drifted:\n{}",
            mismatches.join("\n")
        );
    }

    /// Every registry rule's descriptor carries a full description, help in
    /// both forms, and a helpUri, and stays inside GitHub's length limit.
    #[test]
    fn every_registry_rule_has_help_and_a_help_uri() {
        for id in all_rule_ids() {
            let meta = rule_meta(id).expect("listed id resolves");
            let rule = registry_sarif_rule(id, &meta);
            assert!(
                rule.full_description
                    .text
                    .starts_with(meta.short_description),
                "{id}: {}",
                rule.full_description.text
            );
            assert!(rule.full_description.text.chars().count() <= MAX_FULL_DESCRIPTION);
            assert!(
                rule.help.text.starts_with(meta.remediation),
                "{id}: help must open with the remediation"
            );
            assert!(!rule.help.markdown.is_empty(), "{id}");
            assert!(
                rule.help_uri
                    .as_deref()
                    .is_some_and(|u| u.starts_with("https://")),
                "{id} has no helpUri"
            );
        }
    }

    /// The help names where the fix goes in every format, and its Markdown
    /// links every reference that has a URL.
    #[test]
    fn registry_help_lists_format_advice_and_linked_references() {
        let meta = rule_meta("SBOM-CRA-COMPONENT-VERSION").expect("registered");
        let rule = registry_sarif_rule("SBOM-CRA-COMPONENT-VERSION", &meta);
        for label in ["CycloneDX", "SPDX 2.x", "SPDX 3.0"] {
            assert!(rule.help.text.contains(&format!("- {label}: ")), "{label}");
            assert!(
                rule.help.markdown.contains(&format!("- **{label}:** ")),
                "{label}"
            );
        }
        assert!(
            rule.help.markdown.contains(
                "- [CRA Annex I Part II (1)](<https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng>)"
            ),
            "{}",
            rule.help.markdown
        );
        assert!(
            rule.help.markdown.contains("- prEN 40000-1-3: PRE-7-RQ-06"),
            "a reference without a URL is plain text: {}",
            rule.help.markdown
        );
        assert_eq!(
            rule.help_uri.as_deref(),
            Some("https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng")
        );
    }

    /// Registry text is escaped for Markdown: a `<value>` placeholder must
    /// not become an HTML tag, nor `[]` a link.
    #[test]
    fn registry_text_is_escaped_in_markdown() {
        let markdown = registry_help(
            &rule_meta("SBOM-BSI-TR-03183-2-5-4").expect("registered"),
            &[],
        )
        .markdown;
        assert!(!markdown.contains("<value>"), "{markdown}");
        assert!(markdown.contains("\\<value\\>"), "{markdown}");
        assert!(!markdown.contains("checksums[]"), "{markdown}");
    }

    /// A reference-derived helpUri wins over the family prefix: the EUCC
    /// references point at Implementing Regulation (EU) 2024/482, and a rule
    /// whose only reference has no URL (prEN 40000-1-3) falls back to its
    /// family's home.
    #[test]
    fn help_uri_comes_from_the_first_reference_with_a_url() {
        let eucc = registry_sarif_rule(
            "SBOM-EUCC-PP",
            &rule_meta("SBOM-EUCC-PP").expect("registered"),
        );
        assert_eq!(
            eucc.help_uri.as_deref(),
            Some("https://eur-lex.europa.eu/eli/reg_impl/2024/482/oj/eng")
        );
        let hardware = registry_sarif_rule(
            "SBOM-CRA-PRE-8-RQ-02-PRODUCER",
            &rule_meta("SBOM-CRA-PRE-8-RQ-02-PRODUCER").expect("registered"),
        );
        assert_eq!(
            hardware.help_uri.as_deref(),
            Some("https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng")
        );
    }

    #[test]
    fn tool_rules_have_help() {
        for rule in diff_rules(ComplianceLevel::CraPhase2)
            .into_iter()
            .chain(view_rules(ComplianceLevel::CraPhase2))
            .chain(aibom_rules())
            .chain(std::iter::once(quality_recommendation_rule(
                "SBOM-QUALITY-REC-COMPLETENESS",
                "Completeness",
            )))
        {
            assert!(!rule.full_description.text.is_empty(), "{}", rule.id);
            assert!(!rule.help.text.is_empty(), "{}", rule.id);
            assert!(!rule.help.markdown.is_empty(), "{}", rule.id);
        }
    }

    #[test]
    fn references_read_the_way_they_are_cited() {
        use crate::quality::StandardKind as K;
        for (kind, clause, label) in [
            (K::CraArticle, "Art. 13(7)", "CRA Art. 13(7)"),
            (
                K::CraAnnex,
                "Annex I Part II (1)",
                "CRA Annex I Part II (1)",
            ),
            (
                K::NtiaMinimum,
                "NTIA Minimum Elements",
                "NTIA Minimum Elements",
            ),
            (K::Cnsa2, "CNSA 2.0", "CNSA 2.0"),
            (K::Cnsa2, "CNSSP 15", "CNSA 2.0: CNSSP 15"),
            (K::EnisaSbomAdvisory, "§2.1.1", "ENISA SBOM TA: §2.1.1"),
            (K::BsiTr03183_2, "TR-03183-2", "BSI TR-03183-2"),
            (K::BsiTr03183_2, "§5.2.2", "BSI TR-03183-2: §5.2.2"),
            (
                K::Pren40000_1_3,
                "PRE-7-RQ-04",
                "prEN 40000-1-3: PRE-7-RQ-04",
            ),
        ] {
            assert_eq!(StandardRef::new(kind, clause).citation(), label);
        }
    }

    #[test]
    fn long_full_descriptions_are_cut_on_a_character_boundary() {
        let long = "é".repeat(MAX_FULL_DESCRIPTION + 10);
        let cut = truncate_chars(long, MAX_FULL_DESCRIPTION);
        assert_eq!(cut.chars().count(), MAX_FULL_DESCRIPTION);
        assert!(cut.ends_with('…'));
    }
}
