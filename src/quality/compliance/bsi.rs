//! BSI TR-03183-2 (German national CRA-aligned SBOM guideline) checks.
//!
//! Implements BSI TR-03183-2 **v2.1.0 (2025-08-20)**. Canonical document:
//! <https://bsi.bund.de/dok/TR-03183-en>.
//!
//! The checks read the run's evidence (see [`super::evidence`]), never the
//! SBOM itself; the run's own inputs (the excluded-scope choice) come from
//! the checker.

use super::shared::unparseable_timestamp_of;
use super::*;

impl ComplianceChecker {
    // ════════════════════════════════════════════════════════════════════
    // BSI TR-03183-2 v2.1.0 (German national SBOM guideline)
    // ════════════════════════════════════════════════════════════════════

    /// BSI TR-03183-2 compliance checks.
    ///
    /// TR-03183-2 is the German Federal Office for Information Security's
    /// SBOM technical guideline, free and ENISA-cited. It is functionally
    /// aligned with the CRA Annex I Part II SBOM obligations but stricter
    /// on eligible formats and hashes.
    ///
    /// Reference: BSI TR-03183-2 v2.1.0 (2025-08-20) — §4 (eligible
    /// formats), §5.2.1 (required document-level fields), §5.2.2 (required
    /// per-component fields), §5.2.4 (additional per-component fields),
    /// §6.1 (licence identifiers), §3.1 (no vulnerability information).
    #[allow(clippy::too_many_lines)]
    pub(crate) fn check_bsi_tr_03183_2(
        &self,
        ctx: &ComplianceContext<'_, '_>,
        findings: &mut Findings,
    ) {
        use crate::model::{CompletenessDeclaration, CreatorType, SbomFormat};

        let ev = ctx.ev;
        let doc = ev.document();
        let Findings {
            violations,
            not_evaluated,
            ..
        } = findings;

        // §5.2.2 per-component fields have nothing to judge without a
        // package-scoped component.
        violations.extend(ctx.inventory_absent_violation(
            "SBOM-BSI-TR-03183-2-INVENTORY",
            "BSI TR-03183-2 §5.2.2: component inventory",
        ));

        // §4 — Format eligibility gate. A newly generated or updated SBOM
        // MUST be CycloneDX >= 1.6 or SPDX >= 3.0.1 (JSON or XML). The §7
        // transitional grace for the immediately preceding TR version
        // (v2.0.0: CycloneDX 1.5 / SPDX 2.2.1) ended 2026-02-20; previously
        // *delivered* compliant SBOMs stay compliant, but this checker
        // assesses the document as newly generated. Versions are compared
        // numerically (not by string prefix); an empty or unparseable
        // spec_version skips the gate rather than false-failing synthetic
        // documents, and the result lists it as not evaluated.
        let minimum = match doc.format {
            SbomFormat::CycloneDx => crate::model::SpecVersion::new(1, 6, 0),
            SbomFormat::Spdx => crate::model::SpecVersion::new(3, 0, 1),
        };
        let parsed = doc.spec_version;
        if parsed.is_none() {
            not_evaluated.push("SBOM-BSI-TR-03183-2-4", SPEC_VERSION_UNPARSED);
        }
        if parsed.is_some_and(|actual| actual < minimum) {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::FormatSpecific,
                message: format!(
                    "[BSI TR-03183-2 §4] {} {} is not an eligible format for newly generated or \
                     updated SBOMs: CycloneDX >= 1.6 or SPDX >= 3.0.1 is required (the §7 \
                     transitional grace for v2.0.0 formats ended 2026-02-20)",
                    doc.format, doc.spec_version_raw
                ),
                element: None,
                requirement: "BSI TR-03183-2 §4: Eligible SBOM format and version".to_string(),
                rule_id: "SBOM-BSI-TR-03183-2-4",
                component_id: None,
                counts: None,
                standard_refs: Cow::Borrowed(&[]),
                remediation: None,
                finding_detail: None,
                severity_override: None,
                deadline: None,
                field: None,
                observed: observed(&format!("{} {}", doc.format, doc.spec_version_raw)),
            });
        }

        // §5.2.1 — Creator of the SBOM (required): the email address of the
        // creating entity, or a URL when no email is available. No creator
        // at all is an Error; a creator without a discernible email or URL
        // is a Warning — contact detection is best-effort because the SPDX
        // parser keeps "Person: Name (email)" strings intact in the creator
        // name, and CycloneDX tools carry no contact at all.
        //
        // Note: v2.1.0 does NOT require identifying the generation tool in
        // any tier (the "Creator of the SBOM" maps to Person/Organization /
        // metadata.manufacturer, not metadata.tools), so the former
        // tool-identification Error is intentionally gone. For the same
        // reason Tool creators cannot SATISFY the field either: a tools-only
        // SBOM (the default output of common generators) has no creator in
        // the TR's sense, so both the presence Error and the contact Warning
        // consider only non-Tool (Person/Organization) creators.
        if !doc.has_non_tool_creator {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::DocumentMetadata,
                message: "[BSI TR-03183-2 §5.2.1] Creator of the SBOM missing (email address, or \
                          URL if no email is available); generation tools (metadata.tools) do \
                          not satisfy the field — provide a Person/Organization creator (e.g. \
                          CycloneDX metadata.authors or metadata.manufacturer)"
                    .to_string(),
                element: None,
                requirement: "BSI TR-03183-2 §5.2.1: Creator of the SBOM".to_string(),
                rule_id: "SBOM-BSI-TR-03183-2-5-1",
                component_id: None,
                counts: None,
                standard_refs: Cow::Borrowed(&[]),
                remediation: None,
                finding_detail: None,
                severity_override: None,
                deadline: None,
                field: None,
                observed: None,
            });
        } else {
            // The email, or the address or URL a creator's name carries,
            // must reach someone (see `known_contact`), as every other
            // contact check judges one.
            let contacts = || {
                doc.creators
                    .iter()
                    .map(|c| c.creator)
                    .filter(|c| c.creator_type != CreatorType::Tool)
                    .flat_map(creator_contacts)
            };
            if !contacts().any(|contact| known_contact(Some(contact))) {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::DocumentMetadata,
                    message: format!(
                        "[BSI TR-03183-2 §5.2.1] SBOM creator carries neither an email \
                         address nor a URL{}",
                        unreachable_creator_note(contacts())
                    ),
                    element: None,
                    requirement: "BSI TR-03183-2 §5.2.1: Creator of the SBOM (email or URL)"
                        .to_string(),
                    rule_id: "SBOM-BSI-TR-03183-2-5-1-CONTACT",
                    component_id: None,
                    counts: None,
                    standard_refs: Cow::Borrowed(&[]),
                    remediation: None,
                    finding_detail: None,
                    severity_override: None,
                    deadline: None,
                    field: None,
                    observed: unreachable_creator(contacts()).and_then(observed),
                });
            }
        }

        // §5.2.1 — Timestamp (required): date and time of the SBOM data
        // compilation. Parsers substitute the UNIX_EPOCH sentinel for a
        // missing/invalid timestamp (see `DocumentMetadata::has_known_timestamp`).
        if !doc.has_known_timestamp {
            let message = unparseable_timestamp_of(doc.created_unparsed).map_or_else(
                || "[BSI TR-03183-2 §5.2.1] SBOM creation timestamp missing or invalid".to_string(),
                |gap| format!("[BSI TR-03183-2 §5.2.1] SBOM has {gap}"),
            );
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::DocumentMetadata,
                message,
                element: None,
                requirement: "BSI TR-03183-2 §5.2.1: Timestamp".to_string(),
                rule_id: "SBOM-BSI-TR-03183-2-5-2",
                component_id: None,
                counts: None,
                standard_refs: Cow::Borrowed(&[]),
                remediation: None,
                finding_detail: None,
                severity_override: None,
                deadline: None,
                field: None,
                observed: doc.created_unparsed.and_then(observed),
            });
        }

        // §5.2.2 — Required per-component fields, collected in one pass.
        //
        // Fields the TR requires but the model does not yet carry — no
        // violation is emitted for these (checking would be vacuous):
        //   - Filename of the component (SPDX PackageFileName / CycloneDX
        //     `bsi:component:filename` property): not modeled on `Component`.
        //   - Executable / archive / structured properties (CycloneDX
        //     `bsi:component:executable|archive|structured` taxonomy): not
        //     modeled.
        // Names (§5.2.2) and the §3.1 vulnerability prohibition apply to
        // every component; the package fields (version, licence, creator,
        // hash, identifier) only to package-scoped components — files,
        // crypto assets and services carry none of them.
        let total = ev.component_count();
        let package_total = ctx.package_count();
        let mut nameless = 0usize;
        let mut without_version: Vec<String> = Vec::new();
        let mut without_license: Vec<String> = Vec::new();
        let mut non_spdx_license: Vec<String> = Vec::new();
        // The first licence that is no SPDX expression, as written.
        let mut first_non_spdx: Option<&str> = None;
        let mut without_creator = 0usize;
        let mut sha512_missing: Vec<String> = Vec::new();
        let mut without_hash = 0usize;
        let mut without_identifier: Vec<String> = Vec::new();
        let mut with_vulnerabilities = 0usize;

        for comp in ev.components() {
            if !comp.name_known() {
                nameless += 1;
            }
            // §3.1 vulnerability-information prohibition.
            if comp.has_vulnerabilities() {
                with_vulnerabilities += 1;
            }
            if !ctx.judges_package(&comp) {
                continue;
            }
            if !comp.version().is_known() {
                without_version.push(comp.name().to_string());
            }

            // Distribution licences (§5.2.2) named per §6.1 by SPDX
            // identifier/expression. `is_valid_spdx` is computed once at
            // parse time (lax mode), so the §6.1 naming check is cheap.
            if !comp.licenses().is_known() {
                without_license.push(comp.name().to_string());
            } else if let Some(license) = comp.first_non_spdx_license() {
                non_spdx_license.push(comp.name().to_string());
                first_non_spdx.get_or_insert(license);
            }

            // Component creator (§5.2.2). The TR wants an email address (or
            // URL fallback) of the creating/maintaining entity; the model
            // carries supplier/author presence but not reliably their
            // contact, so this is a presence-level check only — hence
            // Warning, not Error.
            if !comp.producer().is_known() {
                without_creator += 1;
            }

            // Hash of the deployable component (§5.2.2): the normative
            // clause names the algorithm — "as SHA-512" — so SHA-256 (or any
            // other algorithm) alone does not satisfy the field. Only
            // author-attested hashes count: enrichment-fetched hashes are
            // not part of the document under assessment. The SHA-512 must be
            // a plausible digest (128 hex characters, see
            // `plausible_digest`): an empty or garbage value is a present
            // field that fails, named with the reason, not an omission.
            let authored = comp.authored_hashes();
            if !authored.facts.present {
                without_hash += 1;
            } else if !authored.facts.plausible_sha512 {
                sha512_missing.push(name_with_digest_problems(comp.name(), authored.iter()));
            }

            // Other unique identifiers (§5.2.4, ADDITIONAL tier).
            if !comp.ids().any() {
                without_identifier.push(comp.name().to_string());
            }
        }

        // §5.2.2 — Component name (required; fallback: the actual filename).
        // The BsiTr03183_2 level dispatches ONLY to this checker (not the
        // generic component check), so the name requirement must be enforced
        // here.
        if nameless > 0 {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::ComponentIdentification,
                message: format!(
                    "[BSI TR-03183-2 §5.2.2] {nameless}/{total} component(s) missing a name \
                     (if no name is assigned this MUST be the actual filename)"
                ),
                element: None,
                requirement: "BSI TR-03183-2 §5.2.2: Component name".to_string(),
                rule_id: "SBOM-BSI-TR-03183-2-5-3",
                component_id: None,
                counts: Some(ViolationCounts {
                    affected: nameless,
                    total,
                }),
                standard_refs: Cow::Borrowed(&[]),
                remediation: None,
                finding_detail: None,
                severity_override: None,
                deadline: None,
                field: None,
                observed: None,
            });
        }

        // §5.2.2 — Component version (required; fallback: RFC 3339 file
        // modification date).
        if !without_version.is_empty() {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::ComponentIdentification,
                message: format!(
                    "[BSI TR-03183-2 §5.2.2] {}/{package_total} component(s) missing a version (if no \
                     version is assigned this MUST be the RFC 3339 modification date of the \
                     file): {}",
                    without_version.len(),
                    truncate_list(&without_version, 5)
                ),
                element: None,
                requirement: "BSI TR-03183-2 §5.2.2: Component version".to_string(),
                rule_id: "SBOM-BSI-TR-03183-2-VERSION",
                component_id: None,
                counts: Some(ViolationCounts {
                    affected: without_version.len(),
                    total: package_total,
                }),
                standard_refs: Cow::Borrowed(&[]),
                remediation: None,
                finding_detail: None,
                severity_override: None,
                deadline: None,
                field: None,
                observed: None,
            });
        }

        // §5.2.2 — Distribution licences (required).
        if !without_license.is_empty() {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::LicenseInfo,
                message: format!(
                    "[BSI TR-03183-2 §5.2.2] {}/{package_total} component(s) missing distribution \
                     licence(s): {}",
                    without_license.len(),
                    truncate_list(&without_license, 5)
                ),
                element: None,
                requirement: "BSI TR-03183-2 §5.2.2: Distribution licences".to_string(),
                rule_id: "SBOM-BSI-TR-03183-2-LICENSE",
                component_id: None,
                counts: Some(ViolationCounts {
                    affected: without_license.len(),
                    total: package_total,
                }),
                standard_refs: Cow::Borrowed(&[]),
                remediation: None,
                finding_detail: None,
                severity_override: None,
                deadline: None,
                field: None,
                observed: None,
            });
        }

        // §6.1 — Licences MUST be named by SPDX identifier or expression;
        // licence text is not a substitute.
        if !non_spdx_license.is_empty() {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::LicenseInfo,
                message: format!(
                    "[BSI TR-03183-2 §6.1] {}/{package_total} component(s) name licences that are not \
                     valid SPDX identifiers/expressions (licence text is not a substitute): {}",
                    non_spdx_license.len(),
                    truncate_list(&non_spdx_license, 5)
                ),
                element: None,
                requirement: "BSI TR-03183-2 §6.1: Licence identifiers and expressions".to_string(),
                rule_id: "SBOM-BSI-TR-03183-2-LICENSE-SPDX",
                component_id: None,
                counts: Some(ViolationCounts {
                    affected: non_spdx_license.len(),
                    total: package_total,
                }),
                standard_refs: Cow::Borrowed(&[]),
                remediation: None,
                finding_detail: None,
                severity_override: None,
                deadline: None,
                field: None,
                observed: first_non_spdx.and_then(observed),
            });
        }

        // §5.2.2 — Component creator (required; presence-level check, see
        // the loop comment for why this is a Warning).
        if without_creator > 0 {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::SupplierInfo,
                message: format!(
                    "[BSI TR-03183-2 §5.2.2] {without_creator}/{package_total} component(s) missing a \
                     component creator (supplier/author with email, or URL if no email)"
                ),
                element: None,
                requirement: "BSI TR-03183-2 §5.2.2: Component creator".to_string(),
                rule_id: "SBOM-BSI-TR-03183-2-CREATOR",
                component_id: None,
                counts: Some(ViolationCounts {
                    affected: without_creator,
                    total: package_total,
                }),
                standard_refs: Cow::Borrowed(&[]),
                remediation: None,
                finding_detail: None,
                severity_override: None,
                deadline: None,
                field: None,
                observed: None,
            });
        }

        // §5.2.2 — Hash of the deployable component as SHA-512.
        if !sha512_missing.is_empty() {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::IntegrityInfo,
                message: format!(
                    "[BSI TR-03183-2 §5.2.2] {}/{package_total} component(s) carry hashes but none is \
                     a valid SHA-512 digest (the TR names the algorithm; SHA-256 or others alone \
                     do not satisfy the required field): {}",
                    sha512_missing.len(),
                    truncate_list(&sha512_missing, 5)
                ),
                element: None,
                requirement: "BSI TR-03183-2 §5.2.2: Hash of the deployable component (SHA-512)"
                    .to_string(),
                rule_id: "SBOM-BSI-TR-03183-2-5-4",
                component_id: None,
                counts: Some(ViolationCounts {
                    affected: sha512_missing.len(),
                    total: package_total,
                }),
                standard_refs: Cow::Borrowed(&[]),
                remediation: None,
                finding_detail: None,
                severity_override: None,
                deadline: None,
                field: None,
                observed: None,
            });
        }
        // No hash at all: §3.2.1 legitimately allows omitting even required
        // fields when the information cannot exist for the way a component
        // is assembled (e.g. logical components) — a Warning, not an Error,
        // because the omission is not machine-distinguishable from a
        // violation.
        if without_hash > 0 {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::IntegrityInfo,
                message: format!(
                    "[BSI TR-03183-2 §5.2.2] {without_hash}/{package_total} component(s) have no hash of \
                     the deployable form; required as SHA-512 unless the information is \
                     unavailable due to the way the component is assembled (§3.2.1)"
                ),
                element: None,
                requirement: "BSI TR-03183-2 §5.2.2: Hash of the deployable component".to_string(),
                rule_id: "SBOM-BSI-TR-03183-2-5-4-MISSING",
                component_id: None,
                counts: Some(ViolationCounts {
                    affected: without_hash,
                    total: package_total,
                }),
                standard_refs: Cow::Borrowed(&[]),
                remediation: None,
                finding_detail: None,
                severity_override: None,
                deadline: None,
                field: None,
                observed: None,
            });
        }

        // §5.2.2 — Dependencies on other components (required): explicit
        // relationship graph.
        if !ev.has_edges() && package_total > 1 {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::DependencyInfo,
                message: "[BSI TR-03183-2 §5.2.2] SBOM declares multiple components but no \
                          dependency relationships"
                    .to_string(),
                element: None,
                requirement: "BSI TR-03183-2 §5.2.2: Dependencies on other components".to_string(),
                rule_id: "SBOM-BSI-TR-03183-2-5-5",
                component_id: None,
                counts: None,
                standard_refs: Cow::Borrowed(&[]),
                remediation: None,
                finding_detail: None,
                severity_override: None,
                deadline: None,
                field: None,
                observed: None,
            });
        }

        // §5.2.2 — "the completeness of this enumeration MUST be clearly
        // indicated". CycloneDX carries this via compositions.aggregate;
        // SPDX 3.0+ via the relationships' explicit `completeness` property
        // (both mapped into the model). SPDX 2.x has no equivalent field
        // and stays Unknown, so it warns here — the indication is genuinely
        // absent from the document.
        if matches!(
            doc.completeness,
            CompletenessDeclaration::Unknown | CompletenessDeclaration::NotSpecified
        ) {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::DependencyInfo,
                message: "[BSI TR-03183-2 §5.2.2] Completeness of the dependency enumeration is \
                          not clearly indicated (CycloneDX compositions.aggregate / SPDX 3 \
                          relationship completeness)"
                    .to_string(),
                element: None,
                requirement: "BSI TR-03183-2 §5.2.2: Completeness of the dependency enumeration"
                    .to_string(),
                rule_id: "SBOM-BSI-TR-03183-2-5-5-COMPLETENESS",
                component_id: None,
                counts: None,
                standard_refs: Cow::Borrowed(&[]),
                remediation: None,
                finding_detail: None,
                severity_override: None,
                deadline: None,
                field: None,
                observed: None,
            });
        }

        // §5.2.4 — Other unique identifiers (purl/CPE) are ADDITIONAL tier:
        // "MUST additionally be provided, if it exists". Whether an
        // identifier exists upstream is not machine-verifiable from the
        // document alone, so absence is a Warning, not a gating Error.
        if !without_identifier.is_empty() {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::ComponentIdentification,
                message: format!(
                    "[BSI TR-03183-2 §5.2.4] {}/{package_total} component(s) missing a unique identifier \
                     (purl/CPE/SWHID/SWID) — an additional-tier field that MUST be provided when \
                     one exists: {}",
                    without_identifier.len(),
                    truncate_list(&without_identifier, 5)
                ),
                element: None,
                requirement: "BSI TR-03183-2 §5.2.4: Other unique identifiers".to_string(),
                rule_id: "SBOM-BSI-TR-03183-2-5-2-4",
                component_id: None,
                counts: Some(ViolationCounts {
                    affected: without_identifier.len(),
                    total: package_total,
                }),
                standard_refs: Cow::Borrowed(&[]),
                remediation: None,
                finding_detail: None,
                severity_override: None,
                deadline: None,
                field: None,
                observed: None,
            });
        }

        // §3.1 — An SBOM MUST NOT contain vulnerability information; a
        // combined SBOM+vulnerability document does not conform. Warning
        // rather than Error: `Component::vulnerabilities` carries no
        // provenance flag, and enrichment (e.g. OSV) attaches findings to
        // the same field post-parse, so on an enriched pipeline this can
        // reflect tool output rather than the source document.
        if with_vulnerabilities > 0 {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::SecurityInfo,
                message: format!(
                    "[BSI TR-03183-2 §3.1] SBOM carries vulnerability information on \
                     {with_vulnerabilities}/{total} component(s); a document containing both \
                     SBOM and vulnerability information does not conform — publish advisories \
                     separately (e.g. CSAF). Ignore if the data was attached by enrichment \
                     rather than present in the source document."
                ),
                element: None,
                requirement: "BSI TR-03183-2 §3.1: No vulnerability information in the SBOM"
                    .to_string(),
                rule_id: "SBOM-BSI-TR-03183-2-3-1",
                component_id: None,
                counts: Some(ViolationCounts {
                    affected: with_vulnerabilities,
                    total,
                }),
                standard_refs: Cow::Borrowed(&[]),
                remediation: None,
                finding_detail: None,
                severity_override: None,
                deadline: None,
                field: None,
                observed: None,
            });
        }
    }
}
