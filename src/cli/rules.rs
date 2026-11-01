//! `rules` command handler: the compliance rule catalogue.
//!
//! `sbom-tools rules` lists the rules the registry records — every rule, or
//! the rules of the standards `--standard` names — and `sbom-tools rules
//! explain <RULE_ID>` shows one rule in full. Text and Markdown are rendered
//! here; `-o json` prints the `sbom-tools/rules/v1` document
//! ([`generate_rule_catalog_json`]), the same one the library returns.

use crate::quality::{
    ComplianceLevel, RemediationFormat, RuleCatalogEntry, RuleCatalogFilter, RuleKind,
    StandardSelector, resolve_rule_id, rule_catalog, rule_catalog_entry, standard_key,
};
use crate::reports::escape::{escape_markdown_inline, markdown_link_destination};
use crate::reports::generate_rule_catalog_json;
use anyhow::Result;
use std::fmt::Write as _;

/// Output format of `sbom-tools rules` and `sbom-tools rules explain`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RulesOutputFormat {
    /// Human-readable text.
    Text,
    /// The `sbom-tools/rules/v1` JSON document.
    Json,
    /// A Markdown table (a rule list) or section (one rule).
    Markdown,
}

/// Run `sbom-tools rules`: print the rules of `standards`, or every rule
/// when it is empty.
pub fn run_rules(standards: &[StandardSelector], format: RulesOutputFormat) -> Result<()> {
    let filter = RuleCatalogFilter::for_standards(standards.iter().copied());
    let entries = rule_catalog(&filter);
    print!("{}", render_rules(&filter, &entries, format)?);
    Ok(())
}

/// Run `sbom-tools rules explain`: print everything the registry records
/// about `rule_id`. The CLI resolves the id with [`parse_rule_id`] first, so
/// an unknown id never reaches this function from the command line.
pub fn run_rules_explain(rule_id: &str, format: RulesOutputFormat) -> Result<()> {
    let entry = rule_catalog_entry(rule_id)
        .ok_or_else(|| anyhow::anyhow!("unknown rule id '{rule_id}'"))?;
    print!("{}", render_explain(&entry, format)?);
    Ok(())
}

/// Resolve a rule id typed on the command line to the registry's own
/// spelling, ignoring case (see [`resolve_rule_id`]). The error says how to
/// list the rule ids and names the closest one, if one is close.
pub fn parse_rule_id(value: &str) -> std::result::Result<&'static str, String> {
    resolve_rule_id(value)
}

/// Render a rule list in `format`.
fn render_rules(
    filter: &RuleCatalogFilter,
    entries: &[RuleCatalogEntry],
    format: RulesOutputFormat,
) -> Result<String> {
    Ok(match format {
        RulesOutputFormat::Json => format!("{}\n", generate_rule_catalog_json(entries)?),
        RulesOutputFormat::Text => rules_text(filter, entries),
        RulesOutputFormat::Markdown => rules_markdown(filter, entries),
    })
}

/// Render one rule in full in `format`.
fn render_explain(entry: &RuleCatalogEntry, format: RulesOutputFormat) -> Result<String> {
    Ok(match format {
        RulesOutputFormat::Json => format!(
            "{}\n",
            generate_rule_catalog_json(std::slice::from_ref(entry))?
        ),
        RulesOutputFormat::Text => explain_text(entry),
        RulesOutputFormat::Markdown => explain_markdown(entry),
    })
}

/// The level whose canonical `--standard` value (or quality-profile key) is
/// `key`.
fn level_of(key: &str) -> Option<ComplianceLevel> {
    ComplianceLevel::all()
        .iter()
        .copied()
        .find(|level| standard_key(*level) == key)
}

/// What a list holds: "every rule in the registry", or the rules of the
/// standards selected.
fn scope(filter: &RuleCatalogFilter, entries: &[RuleCatalogEntry]) -> String {
    let n = entries.len();
    if filter.levels().is_empty() {
        return format!("every rule in the registry ({n})");
    }
    let standards: Vec<String> = filter
        .levels()
        .iter()
        .map(|level| format!("{} ({})", standard_key(*level), level.name()))
        .collect();
    format!("{n} rules of {}", standards.join(", "))
}

/// The marker a rule's heading carries after its severity.
fn kind_marker(entry: &RuleCatalogEntry) -> &'static str {
    if entry.fallback {
        " · fallback"
    } else if entry.kind == RuleKind::Pass {
        " · passed checks"
    } else {
        ""
    }
}

/// What a rule reports, in words.
fn reports(entry: &RuleCatalogEntry) -> &'static str {
    if entry.fallback {
        "findings without a registered rule (a fallback rule: no check emits it; the SARIF writer files such a finding here)"
    } else if entry.kind == RuleKind::Pass {
        "checks the SBOM passed (listed under passed[], never a violation)"
    } else {
        "findings"
    }
}

/// The line that names a rule's standards.
fn standards_line(entry: &RuleCatalogEntry) -> String {
    let label = if entry.fallback {
        "Fallback of:"
    } else {
        "Standards: "
    };
    let standards = if entry.standards.is_empty() {
        "none".to_string()
    } else {
        entry.standards.join(", ")
    };
    format!("{label} {standards}")
}

fn rules_text(filter: &RuleCatalogFilter, entries: &[RuleCatalogEntry]) -> String {
    let mut out = format!("Compliance rules: {}\n", scope(filter, entries));
    for entry in entries {
        let _ = write!(
            out,
            "\n{} · {} · {}{}\n  {}\n  {}\n",
            entry.id,
            entry.name,
            entry.default_severity.name(),
            kind_marker(entry),
            entry.description,
            standards_line(entry),
        );
        if entry.references.is_empty() {
            out.push_str("  References: none\n");
        }
        for (i, reference) in entry.references.iter().enumerate() {
            let label = if i == 0 { "References:" } else { "           " };
            match &reference.help_uri {
                Some(uri) => {
                    let _ = writeln!(out, "  {label} {} <{uri}>", reference.label);
                }
                None => {
                    let _ = writeln!(out, "  {label} {}", reference.label);
                }
            }
        }
        let _ = writeln!(out, "  Fix:        {}", entry.remediation_summary);
    }
    out.push_str("\n`sbom-tools rules explain <RULE_ID>` shows a rule in full.\n");
    out
}

fn rules_markdown(filter: &RuleCatalogFilter, entries: &[RuleCatalogEntry]) -> String {
    let mut out = format!(
        "# Compliance rules\n\n{}.\n\n\
         | Rule | Name | Default severity | Standards | References | Remediation |\n\
         |---|---|---|---|---|---|\n",
        escape_markdown_inline(&capitalized(&scope(filter, entries)))
    );
    for entry in entries {
        let severity = format!(
            "{}{}",
            entry.default_severity.name(),
            kind_marker(entry).replace(" · ", ", ")
        );
        let _ = writeln!(
            out,
            "| `{}` | {} | {} | {} | {} | {} |",
            entry.id,
            entry.name,
            severity,
            markdown_standards(entry),
            markdown_references(entry, "; "),
            escape_markdown_inline(entry.remediation_summary),
        );
    }
    out
}

/// `text` with its first letter in upper case.
fn capitalized(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

/// A rule's standards as Markdown code spans, a fallback rule's marked.
fn markdown_standards(entry: &RuleCatalogEntry) -> String {
    let standards = entry
        .standards
        .iter()
        .map(|key| format!("`{key}`"))
        .collect::<Vec<_>>()
        .join(", ");
    if entry.fallback {
        format!("fallback of {standards}")
    } else {
        standards
    }
}

/// A rule's references as Markdown, each linked when it has a URL.
fn markdown_references(entry: &RuleCatalogEntry, separator: &str) -> String {
    if entry.references.is_empty() {
        return "—".to_string();
    }
    entry
        .references
        .iter()
        .map(|reference| match &reference.help_uri {
            Some(uri) => format!(
                "[{}]({})",
                escape_markdown_inline(&reference.label),
                markdown_link_destination(uri)
            ),
            None => escape_markdown_inline(&reference.label),
        })
        .collect::<Vec<_>>()
        .join(separator)
}

fn explain_text(entry: &RuleCatalogEntry) -> String {
    let mut out = format!(
        "{} · {}\n{}\n\nDefault severity: {}\nReports:          {}\n",
        entry.id,
        entry.name,
        entry.description,
        entry.default_severity.name(),
        reports(entry),
    );
    let heading = if entry.fallback {
        "Fallback of:"
    } else {
        "Standards:"
    };
    let _ = writeln!(out, "{heading}");
    if entry.standards.is_empty() {
        out.push_str("  none\n");
    }
    let width = entry.standards.iter().map(|k| k.len()).max().unwrap_or(0);
    for key in &entry.standards {
        let name = level_of(key).map_or("", |level| level.name());
        let _ = writeln!(out, "  {key:<width$}  {name}");
    }
    out.push_str("References:\n");
    if entry.references.is_empty() {
        out.push_str("  none\n");
    }
    for reference in &entry.references {
        match &reference.help_uri {
            Some(uri) => {
                let _ = writeln!(out, "  {} <{uri}>", reference.label);
            }
            None => {
                let _ = writeln!(out, "  {}", reference.label);
            }
        }
    }
    if let Some(uri) = &entry.help_uri {
        let _ = writeln!(out, "Help:             {uri}");
    }
    let _ = write!(out, "\nRemediation:\n  {}\n", entry.remediation);
    if let Some(advice) = &entry.advice {
        out.push_str("\nWhere the fix goes:\n");
        for format in RemediationFormat::ALL {
            let advice = advice.get(format);
            let _ = writeln!(out, "  {}: {}", format.label(), advice.text);
            if let Some(field) = advice.field {
                let _ = writeln!(out, "    field: {field}");
            }
        }
    }
    out
}

fn explain_markdown(entry: &RuleCatalogEntry) -> String {
    let standards = entry
        .standards
        .iter()
        .map(|key| {
            level_of(key).map_or_else(
                || format!("`{key}`"),
                |level| format!("`{key}` ({})", escape_markdown_inline(level.name())),
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let standards_label = if entry.fallback {
        "Fallback of"
    } else {
        "Standards"
    };
    let mut out = format!(
        "## `{}` {}\n\n{}\n\n- **Default severity:** {}\n- **Reports:** {}\n- **{standards_label}:** {}\n- **References:** {}\n",
        entry.id,
        entry.name,
        escape_markdown_inline(entry.description),
        entry.default_severity.name(),
        escape_markdown_inline(reports(entry)),
        if standards.is_empty() {
            "none".to_string()
        } else {
            standards
        },
        markdown_references(entry, ", "),
    );
    if let Some(uri) = &entry.help_uri {
        let _ = writeln!(out, "- **Help:** {}", markdown_link_destination(uri));
    }
    let _ = write!(
        out,
        "\n**Remediation**\n\n{}\n",
        escape_markdown_inline(entry.remediation)
    );
    if let Some(advice) = &entry.advice {
        out.push_str("\n**Where the fix goes**\n\n");
        for format in RemediationFormat::ALL {
            let advice = advice.get(format);
            let field = advice
                .field
                .map_or_else(String::new, |field| format!(" (field `{field}`)"));
            let _ = writeln!(
                out,
                "- **{}:** {}{field}",
                format.label(),
                escape_markdown_inline(advice.text)
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_ids_parse_ignoring_case_and_unknown_ids_get_a_hint() {
        assert_eq!(parse_rule_id("SBOM-CRA-ART-24"), Ok("SBOM-CRA-ART-24"));
        assert_eq!(parse_rule_id(" sbom-cra-art-24 "), Ok("SBOM-CRA-ART-24"));
        let err = parse_rule_id("SBOM-CRA-ART-25").unwrap_err();
        assert!(err.contains("did you mean SBOM-CRA-ART-24?"), "{err}");
        assert!(err.contains("`sbom-tools rules`"), "{err}");
        let err = parse_rule_id("cra-art-24").unwrap_err();
        assert!(err.contains("did you mean SBOM-CRA-ART-24?"), "{err}");
        let err = parse_rule_id("completely-unrelated").unwrap_err();
        assert!(!err.contains("did you mean"), "{err}");
    }

    #[test]
    fn the_text_list_names_every_field_the_listing_promises() {
        let filter = RuleCatalogFilter::for_levels([ComplianceLevel::CraOssSteward]);
        let entries = rule_catalog(&filter);
        let text = rules_text(&filter, &entries);
        assert!(
            text.starts_with(
                "Compliance rules: 16 rules of oss-steward (CRA OSS Steward (Art. 24))\n"
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "\nSBOM-CRA-ART-24 · CraStewardVulnerabilityHandling · Error\n  \
                 CRA Art. 24: Open-source steward vulnerability-handling process (security contact or disclosure URL)\n  \
                 Standards:  oss-steward\n  \
                 References: CRA Art. 24 <https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng>\n  \
                 Fix:        Show the open-source steward's vulnerability-handling process (Art. 24): "
            ),
            "{text}"
        );
        assert!(
            text.contains("\nSBOM-CRA-GENERAL · CraGeneralRequirement · Warning · fallback\n"),
            "{text}"
        );
        assert!(
            text.contains("  Fallback of: cra-phase1, cra, oss-steward\n"),
            "{text}"
        );
    }

    #[test]
    fn the_markdown_list_is_one_table_row_per_rule() {
        let filter = RuleCatalogFilter::for_levels([ComplianceLevel::EuccSubstantial]);
        let entries = rule_catalog(&filter);
        let markdown = rules_markdown(&filter, &entries);
        let rows: Vec<&str> = markdown
            .lines()
            .filter(|line| line.starts_with("| `SBOM-"))
            .collect();
        assert_eq!(rows.len(), entries.len(), "{markdown}");
        assert!(
            rows[0].starts_with(
                "| `SBOM-EUCC-PP` | EuccProtectionProfile | Error | `eucc` | \
                 [EUCC: Protection Profile](<https://eur-lex.europa.eu/eli/reg_impl/2024/482/oj/eng>) | "
            ),
            "{}",
            rows[0]
        );
        assert!(
            markdown.contains("| `SBOM-EUCC-GENERAL` | EuccGeneralRequirement | Warning, fallback | fallback of `eucc` |"),
            "{markdown}"
        );
    }

    #[test]
    fn explain_shows_the_full_entry() {
        let entry = rule_catalog_entry("SBOM-CRA-COMPONENT-VERSION").expect("registered");
        let text = explain_text(&entry);
        for expected in [
            "SBOM-CRA-COMPONENT-VERSION · CraComponentVersion\nCRA Annex I Part II (1): Component version identification\n",
            "Default severity: Error\nReports:          findings\n",
            "Standards:\n  cra-phase1   EU CRA Phase 1 (2026)\n  cra          EU CRA Phase 2 (2027)\n  oss-steward  CRA OSS Steward (Art. 24)\n",
            "References:\n  CRA Annex I Part II (1) <https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng>\n  prEN 40000-1-3: PRE-7-RQ-06\n  ENISA SBOM TA: §2.1.1 <https://www.enisa.europa.eu/publications/enisa-technical-advisory-for-software-bill-of-materials>\n",
            "Help:             https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng\n",
            "\nRemediation:\n  Every component must have a version string.",
            "\nWhere the fix goes:\n  CycloneDX: set components[].version.\n    field: components[].version\n",
            "  SPDX 3.0: set software_packageVersion on the package.\n    field: software_packageVersion\n",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
        }
        let markdown = explain_markdown(&entry);
        for expected in [
            "## `SBOM-CRA-COMPONENT-VERSION` CraComponentVersion\n",
            "- **Standards:** `cra-phase1` (EU CRA Phase 1 (2026)), `cra` (EU CRA Phase 2 (2027)), `oss-steward` (CRA OSS Steward (Art. 24))\n",
            "- **References:** [CRA Annex I Part II (1)](<https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng>), prEN 40000-1-3: PRE-7-RQ-06, [ENISA SBOM TA: §2.1.1](<https://www.enisa.europa.eu/publications/enisa-technical-advisory-for-software-bill-of-materials>)\n",
            "- **CycloneDX:** set components\\[\\].version. (field `components[].version`)\n",
        ] {
            assert!(
                markdown.contains(expected),
                "missing {expected:?} in:\n{markdown}"
            );
        }
    }

    #[test]
    fn explain_says_what_a_fallback_or_pass_rule_reports() {
        let fallback = explain_text(&rule_catalog_entry("SBOM-NTIA-GENERAL").expect("registered"));
        assert!(
            fallback
                .contains("Reports:          findings without a registered rule (a fallback rule"),
            "{fallback}"
        );
        assert!(
            fallback.contains("Fallback of:\n  ntia  NTIA Minimum Elements\n"),
            "{fallback}"
        );
        let pass = explain_text(&rule_catalog_entry("SBOM-PQC-009").expect("registered"));
        assert!(
            pass.contains("Reports:          checks the SBOM passed"),
            "{pass}"
        );
    }
}
