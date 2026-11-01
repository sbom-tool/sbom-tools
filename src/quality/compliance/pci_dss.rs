//! PCI DSS v4.0.1 Requirement 6.3.2 software-inventory profile checks.
//!
//! Standard: PCI DSS v4.0.1 (PCI Security Standards Council, 11 June 2024)
//! Requirement 6.3.2 — "An inventory of bespoke and custom software, and
//! third-party software components incorporated into bespoke and custom
//! software is maintained to facilitate vulnerability and patch management."
//! New in v4.0; a best practice until 31 March 2025 and required in
//! assessments thereafter. Companion controls 6.3.1 (risk ranking of
//! identified vulnerabilities) and 11.3.1.1 (management of non-high-risk
//! vulnerabilities) are covered as proxies where the SBOM embeds
//! vulnerability data. Requirement text is cited against v4.0.1 only.
//!
//! PCI DSS prescribes no SBOM format or field schema; a parseable
//! CycloneDX/SPDX document is the industry-consensus evidence format (not a
//! PCI SSC-mandated one), so no format gate applies. Testing procedures
//! 6.3.2.a/6.3.2.b are assessor work (interviews, comparison against the
//! real software) — the profile checks only the document-level evidence.
//!
//! **Scope of a verdict**: PCI DSS is a binding standard, but the
//! SBOM-as-inventory mapping implemented here is guidance-derived. A passing
//! run is evidence that the Req. 6.3.2 inventory exists and is technically
//! usable for vulnerability and patch management — it is NOT a PCI DSS
//! compliance certification, and it cannot verify the organizational half of
//! the requirement (that the inventory *is used*, that risk rankings feed a
//! targeted risk analysis, or that the software in scope is bespoke/custom
//! payment software in the CDE).
//!
//! The rule catalogue for this profile lives in the registry (`SBOM-PCI-*`,
//! see `PCIDSS_SARIF_RULE_IDS`).

use super::*;
use crate::model::{CompletenessDeclaration, ExternalRefType, Severity};

/// Tool-policy staleness threshold for the Req. 6.3.2 "is maintained"
/// advisory. PCI DSS text prescribes no regeneration cadence; this cutoff is
/// tool policy and the emitted message labels it as such.
const PCI_STALE_AFTER_DAYS: i64 = 365;

impl ComplianceChecker {
    // ════════════════════════════════════════════════════════════════════
    // PCI DSS v4.0.1 Requirement 6.3.2 (+ companions 6.3.1 / 11.3.1.1)
    // ════════════════════════════════════════════════════════════════════

    /// Entry point for `ComplianceLevel::PciDss632` (dispatched via
    /// `PciDss632Checker` in context.rs). Runs the document-level inventory
    /// checks, the per-component attribute checks, and the
    /// vulnerability-management proxies.
    pub(crate) fn check_pci_dss_6_3_2(
        &self,
        sbom: &NormalizedSbom,
        violations: &mut Vec<Violation>,
    ) {
        self.check_pci_inventory(sbom, violations);
        self.check_pci_components(sbom, violations);
        self.check_pci_third_party(sbom, violations);
        self.check_pci_completeness(sbom, violations);
        self.check_pci_freshness(sbom, violations);
        self.check_pci_vuln_evidence(sbom, violations);
        self.check_pci_risk_ranking(sbom, violations);
    }

    /// SBOM-PCI-6-3-2-INVENTORY (Error): the document must be a non-empty
    /// inventory that identifies the bespoke/custom application it
    /// describes. An empty or headless document cannot serve as the
    /// Req. 6.3.2 inventory.
    fn check_pci_inventory(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        // A file- or crypto-only document is no software inventory either:
        // the per-component rules exempt those entries, so it used to pass.
        if let Some(mut absent) = self.inventory_absent_violation(
            sbom,
            "SBOM-PCI-6-3-2-INVENTORY",
            "PCI DSS v4.0.1 Req. 6.3.2 / TP 6.3.2.b: non-empty software inventory",
        ) {
            absent.message = format!("[PCI DSS 6.3.2] {}", absent.message);
            violations.push(absent);
        } else if sbom.primary_component().is_none() {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::DocumentMetadata,
                message: "[PCI DSS 6.3.2] SBOM does not identify the bespoke/custom application \
                          it describes (no resolvable primary component — CycloneDX: \
                          metadata.component; SPDX: documentDescribes)"
                    .to_string(),
                element: None,
                requirement: "PCI DSS v4.0.1 Req. 6.3.2 / TP 6.3.2.b: resolvable primary component"
                    .to_string(),
                rule_id: "SBOM-PCI-6-3-2-INVENTORY",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                severity_override: None,
                deadline: None,
                field: None,
                observed: None,
            });
        }
    }

    /// Per-component attribute checks:
    /// SBOM-PCI-6-3-2-NAME (Error), SBOM-PCI-6-3-2-VERSION (Error),
    /// SBOM-PCI-6-3-2-IDENTIFIER (Warning), SBOM-PCI-6-3-2-SUPPLIER
    /// (Warning, non-primary components only).
    ///
    /// File/snippet inventory entries are name+hash records, not packages:
    /// per the registry's rule text ("every inventoried (non-file)
    /// component") all four per-component rules exempt them, so a
    /// file-cataloguing SBOM does not auto-fail the profile. This mirrors
    /// the generic-path carve-out for SBOM-NTIA-*/SBOM-CRA-COMPONENT-*
    /// (generic.rs), except that the PCI registry text extends the
    /// exemption to the name rule as well.
    fn check_pci_components(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        let primary_id = sbom.primary_component_id.as_ref();
        for (id, comp) in &sbom.components {
            if !self.judges_package(sbom, comp) {
                continue;
            }

            // Name: an unnamed entry cannot be correlated with vendor
            // advisories or patches.
            if !known_component_name(comp) {
                violations.push(Violation {
                    severity: ViolationSeverity::Error,
                    category: ViolationCategory::ComponentIdentification,
                    message: format!(
                        "[PCI DSS 6.3.2] Inventoried component '{}' has no usable name; an \
                         unnamed entry cannot be correlated with vendor advisories or patches",
                        comp.identifiers.format_id
                    ),
                    element: Some(comp.identifiers.format_id.clone()),
                    requirement: "PCI DSS v4.0.1 Req. 6.3.2: component name".to_string(),
                    rule_id: "SBOM-PCI-6-3-2-NAME",
                    component_id: Some(comp.canonical_id.value().to_string()),
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    severity_override: None,
                    deadline: None,
                    field: None,
                    observed: observed(&comp.name),
                });
            }

            // Version: patch management — the requirement's stated purpose —
            // is impossible without versions. A version range is acceptable
            // only for external (environment-provided) components.
            let version_ok = has_known_value(&comp.version)
                || (comp.is_external && has_known_value(&comp.version_range));
            if !version_ok {
                violations.push(Violation {
                    severity: ViolationSeverity::Error,
                    category: ViolationCategory::ComponentIdentification,
                    message: format!(
                        "[PCI DSS 6.3.2] Component '{}' has no concrete version; patch \
                         management — the requirement's stated purpose — is impossible \
                         without one",
                        comp.name
                    ),
                    element: Some(comp.name.clone()),
                    requirement: "PCI DSS v4.0.1 Req. 6.3.2: component version".to_string(),
                    rule_id: "SBOM-PCI-6-3-2-VERSION",
                    component_id: Some(comp.canonical_id.value().to_string()),
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    severity_override: None,
                    deadline: None,
                    field: None,
                    observed: comp.version.as_deref().and_then(observed),
                });
            }

            // Unique identifier: enabling evidence for the "facilitate
            // vulnerability and patch management" clause. PCI DSS prescribes
            // no identifier scheme, hence Warning, not Error.
            if !comp.identifiers.has_cra_identifier() {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::ComponentIdentification,
                    message: format!(
                        "[PCI DSS 6.3.2 / TP 6.3.2.a] Component '{}' carries no stable unique \
                         identifier (PURL/CPE/SWHID/SWID), so the inventory cannot be \
                         machine-correlated with vulnerability sources; PCI DSS prescribes no \
                         identifier scheme — this is enabling evidence, not a mandated field",
                        comp.name
                    ),
                    element: Some(comp.name.clone()),
                    requirement: "PCI DSS v4.0.1 Req. 6.3.2 / TP 6.3.2.a: unique identifier for \
                         vulnerability correlation"
                        .to_string(),
                    rule_id: "SBOM-PCI-6-3-2-IDENTIFIER",
                    component_id: Some(comp.canonical_id.value().to_string()),
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    severity_override: None,
                    deadline: None,
                    field: None,
                    observed: None,
                });
            }

            // Supplier/source: needed to monitor vendor security-patch
            // availability. The primary component is the entity's own
            // bespoke/custom application, so it is exempt; the SBOM model
            // cannot express bespoke-ness for the rest, so every non-primary
            // entry is treated as potentially third-party and the finding
            // stays an evidence-limited Warning.
            let is_primary = primary_id.is_some_and(|p| p == id);
            let supplier_evidence = has_known_producer(comp)
                || has_known_value(&comp.group)
                || comp.ecosystem.is_some();
            if !is_primary && !supplier_evidence {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::SupplierInfo,
                    message: format!(
                        "[PCI DSS 6.3.2] Component '{}' identifies no supplier/source (no \
                         supplier, author, group, or ecosystem-bearing PURL), so vendor \
                         security-patch availability cannot be monitored; the SBOM model \
                         cannot mark entries as bespoke, so this is inferred for every \
                         non-primary component",
                        comp.name
                    ),
                    element: Some(comp.name.clone()),
                    requirement: "PCI DSS v4.0.1 Req. 6.3.2: third-party component \
                                  supplier/source"
                        .to_string(),
                    rule_id: "SBOM-PCI-6-3-2-SUPPLIER",
                    component_id: Some(comp.canonical_id.value().to_string()),
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    severity_override: None,
                    deadline: None,
                    field: None,
                    observed: observed_producer(comp),
                });
            }
        }
    }

    /// SBOM-PCI-6-3-2-THIRD-PARTY (Warning): the inventory must actually
    /// enumerate incorporated third-party components, not just the
    /// application itself. Inference only — TP 6.3.2.b's real comparison
    /// against the software is assessor work — and suppressed when the
    /// document self-declares the inventory Complete (a genuinely
    /// dependency-free application).
    fn check_pci_third_party(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        // Headless/empty documents already fail SBOM-PCI-6-3-2-INVENTORY;
        // this inference is only meaningful once a primary application
        // component is identified.
        let Some(primary_id) = sbom.primary_component_id.as_ref() else {
            return;
        };
        if sbom.primary_component().is_none() {
            return;
        }
        if sbom.document.completeness_declaration == CompletenessDeclaration::Complete {
            return;
        }

        // File/snippet records are not package inventory entries; only
        // package-level components count as enumerated third-party software.
        let non_primary: Vec<_> = sbom
            .components
            .iter()
            .filter(|(id, comp)| *id != primary_id && self.judges_package(sbom, comp))
            .map(|(_, comp)| comp)
            .collect();

        let (message, requirement) = if non_primary.is_empty() {
            (
                "[PCI DSS TP 6.3.2.b] SBOM inventories only the application itself — no \
                 incorporated third-party components are enumerated. This is an inference from \
                 document content (a dependency-free application should declare its inventory \
                 Complete); the real comparison against the software is assessor work",
                "PCI DSS v4.0.1 Req. 6.3.2 / TP 6.3.2.b: third-party components enumerated",
            )
        } else if !non_primary
            .iter()
            .any(|comp| has_known_producer(comp) || comp.ecosystem.is_some() || comp.is_external)
        {
            (
                "[PCI DSS TP 6.3.2.b] No component beyond the primary carries supplier, \
                 ecosystem, or external-dependency evidence, so third-party components cannot \
                 be distinguished from the entity's own software. This is an inference from \
                 document content; the real comparison against the software is assessor work",
                "PCI DSS v4.0.1 Req. 6.3.2 / TP 6.3.2.b: third-party components distinguishable",
            )
        } else {
            return;
        };

        violations.push(Violation {
            severity: ViolationSeverity::Warning,
            category: ViolationCategory::ComponentIdentification,
            message: message.to_string(),
            element: None,
            requirement: requirement.to_string(),
            rule_id: "SBOM-PCI-6-3-2-THIRD-PARTY",
            component_id: None,
            counts: None,
            standard_refs: Vec::new(),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        });
    }

    /// SBOM-PCI-6-3-2-COMPLETENESS: self-declared completeness against
    /// TP 6.3.2.b. Explicit `Incomplete*` declarations warn (self-declared
    /// inventory gap, fail closed); `Unknown` (no declaration made, or an
    /// explicitly unknown aggregate) and `NotSpecified` (completeness was
    /// declared but with an unrecognized value, or a no-assertion value) are
    /// informational.
    fn check_pci_completeness(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        let declaration = &sbom.document.completeness_declaration;
        let (severity, message) = match declaration {
            CompletenessDeclaration::Complete => return,
            CompletenessDeclaration::Incomplete
            | CompletenessDeclaration::IncompleteFirstPartyOnly
            | CompletenessDeclaration::IncompleteThirdPartyOnly => (
                ViolationSeverity::Warning,
                format!(
                    "[PCI DSS TP 6.3.2.b] SBOM self-declares its inventory '{declaration}' — a \
                     declared gap against the testing procedure's completeness comparison"
                ),
            ),
            CompletenessDeclaration::Unknown => (
                ViolationSeverity::Info,
                "[PCI DSS TP 6.3.2.b] SBOM makes no completeness declaration (or declares it \
                 explicitly unknown); declaring the inventory Complete (CycloneDX compositions \
                 aggregate) would evidence the completeness comparison"
                    .to_string(),
            ),
            CompletenessDeclaration::NotSpecified => (
                ViolationSeverity::Info,
                "[PCI DSS TP 6.3.2.b] SBOM declares completeness with an unrecognized or \
                 no-assertion value; declaring the inventory Complete (CycloneDX compositions \
                 aggregate) would evidence the completeness comparison"
                    .to_string(),
            ),
        };
        violations.push(Violation {
            severity,
            category: ViolationCategory::DocumentMetadata,
            message,
            element: None,
            requirement: "PCI DSS v4.0.1 TP 6.3.2.b: completeness declaration".to_string(),
            rule_id: "SBOM-PCI-6-3-2-COMPLETENESS",
            component_id: None,
            counts: None,
            standard_refs: Vec::new(),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        });
    }

    /// SBOM-PCI-6-3-2-FRESHNESS: "is maintained" — the document must carry a
    /// creation timestamp (Warning when missing: maintenance cadence is
    /// unverifiable). A timestamp later than the evaluation instant evidences
    /// no more than a missing one and warns the same way. A stale-but-present
    /// timestamp is an Info advisory only, and the threshold is explicitly
    /// tool policy, not PCI DSS text: the SBOM proves generation time, not the
    /// inventory process.
    fn check_pci_freshness(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        if !sbom.document.has_known_timestamp() {
            let gap =
                unparseable_timestamp(sbom).unwrap_or_else(|| "no creation timestamp".to_string());
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::DocumentMetadata,
                message: format!(
                    "[PCI DSS 6.3.2] SBOM has {gap}, so nothing evidences when the inventory \
                     was last maintained"
                ),
                element: None,
                requirement: "PCI DSS v4.0.1 Req. 6.3.2: inventory 'is maintained' — creation \
                              timestamp"
                    .to_string(),
                rule_id: "SBOM-PCI-6-3-2-FRESHNESS",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                severity_override: None,
                deadline: None,
                field: None,
                observed: observed_unparsed_timestamp(sbom),
            });
            return;
        }
        let now = self.now();
        if let Some(future) = future_timestamp_violation(
            sbom,
            now,
            "SBOM-PCI-6-3-2-FRESHNESS",
            "[PCI DSS 6.3.2]",
            "PCI DSS v4.0.1 Req. 6.3.2: inventory 'is maintained' — creation timestamp",
        ) {
            violations.push(future);
            return;
        }
        let age_days = (now - sbom.document.created).num_days();
        if age_days > PCI_STALE_AFTER_DAYS {
            violations.push(Violation {
                severity: ViolationSeverity::Info,
                category: ViolationCategory::DocumentMetadata,
                message: format!(
                    "[PCI DSS 6.3.2] SBOM was generated {age_days} days ago; the \
                     {PCI_STALE_AFTER_DAYS}-day staleness threshold is tool policy, not PCI DSS \
                     text — the SBOM proves generation time, not the inventory process"
                ),
                element: None,
                requirement: "PCI DSS v4.0.1 Req. 6.3.2: inventory 'is maintained' — staleness \
                              (tool policy)"
                    .to_string(),
                rule_id: "SBOM-PCI-6-3-2-FRESHNESS",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                severity_override: None,
                deadline: None,
                field: None,
                observed: observed(
                    &sbom
                        .document
                        .created
                        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                ),
            });
        }
    }

    /// SBOM-PCI-6-3-2-VULN-EVIDENCE (Info): proxy for TP 6.3.2.a's "used to
    /// identify and address vulnerabilities". Satisfied by any
    /// vulnerability-management hook: embedded vulnerability entries, an
    /// Advisories / vulnerability-assertion / linked-BOM (VDR) /
    /// security-contact external reference, a document security contact, or
    /// a disclosure URL. Absence is NOT a Req. 6.3.2 failure — the inventory
    /// may feed an external scanner, and actual use is assessor-verified —
    /// so the rule only surfaces the missing hooks at Info.
    fn check_pci_vuln_evidence(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        let has_embedded_vulns = sbom
            .components
            .values()
            .any(|c| !c.vulnerabilities.is_empty());
        // A contact (an advisories or security-contact reference, the
        // document's security contact or disclosure URL) counts only when it
        // reaches someone (`known_contact`), as for the CRA and EO 14028
        // checks; a VDR or linked BOM is a document, not a contact.
        let has_hook_ref = sbom.components.values().any(|c| {
            c.external_refs.iter().any(|r| match r.ref_type {
                ExternalRefType::Advisories | ExternalRefType::SecurityContact => {
                    is_contact_reference(r)
                }
                ExternalRefType::VulnerabilityAssertion | ExternalRefType::Bom => true,
                _ => false,
            })
        });
        let has_contact = known_contact(sbom.document.security_contact.as_deref())
            || known_contact(sbom.document.vulnerability_disclosure_url.as_deref());
        if has_embedded_vulns || has_hook_ref || has_contact {
            return;
        }
        violations.push(Violation {
            severity: ViolationSeverity::Info,
            category: ViolationCategory::SecurityInfo,
            message: format!(
                "[PCI DSS TP 6.3.2.a] SBOM carries no vulnerability-management hooks (no \
                 embedded vulnerability data, no advisories / vulnerability-assertion / \
                 linked-VDR external reference, no security contact or disclosure URL); this \
                 is not a Req. 6.3.2 failure — the inventory may feed an external scanner, and \
                 actual use of the inventory is assessor-verified{}",
                unreachable_contact_note(sbom)
            ),
            element: None,
            requirement: "PCI DSS v4.0.1 TP 6.3.2.a: vulnerability-management hooks".to_string(),
            rule_id: "SBOM-PCI-6-3-2-VULN-EVIDENCE",
            component_id: None,
            counts: None,
            standard_refs: Vec::new(),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: unreachable_contact(sbom).and_then(observed),
        });
    }

    /// SBOM-PCI-11-3-1-1-SEVERITY (Warning): where the SBOM embeds
    /// vulnerability data, every entry must carry a risk ranking so
    /// non-high-risk findings can be managed per the entity's Req. 6.3.1
    /// rankings and the 11.3.1.1 targeted risk analysis.
    ///
    /// "Ranked" is evaluated per entry as an explicit
    /// Critical/High/Medium/Low severity OR a CVSS score. This deliberately
    /// does NOT reuse `NormalizedSbom::vulnerability_counts()`, whose
    /// `unknown` bucket ignores CVSS entirely and also absorbs
    /// `Some(Severity::Info | None | Unknown)` — an entry with only a CVSS
    /// score would be miscounted as unranked there.
    ///
    /// Emitted only when vulnerability data is present: with none, the rule
    /// is not applicable and stays silent (no vacuous pass/fail).
    fn check_pci_risk_ranking(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        let all = sbom.all_vulnerabilities();
        // A vulnerability whose own VEX statement is a justified
        // not_affected does not apply to the product, so it needs no risk
        // ranking to be managed: the CRA and FDA vulnerability checks skip
        // it the same way (`justified_not_affected`). Until v0.4.0 every
        // entry counted, whatever its VEX state.
        let open: Vec<_> = all
            .iter()
            .filter(|(_, vuln)| !justified_not_affected(vuln))
            .collect();
        if open.is_empty() {
            return;
        }
        let unranked: Vec<String> = open
            .iter()
            .filter(|(_, vuln)| {
                !matches!(
                    vuln.severity,
                    Some(Severity::Critical | Severity::High | Severity::Medium | Severity::Low)
                ) && vuln.cvss.is_empty()
            })
            .map(|(comp, vuln)| format!("{} ({})", vuln.id, comp.name))
            .collect();
        if unranked.is_empty() {
            return;
        }
        let not_affected_note = match all.len() - open.len() {
            0 => String::new(),
            1 => "; 1 more entry has a justified not_affected VEX statement and needs none"
                .to_string(),
            n => format!(
                "; {n} more entries have a justified not_affected VEX statement and need none"
            ),
        };
        violations.push(Violation {
            severity: ViolationSeverity::Warning,
            category: ViolationCategory::SecurityInfo,
            message: format!(
                "[PCI DSS 6.3.1 / 11.3.1.1] {affected}/{total} embedded vulnerability entries \
                 carry no risk ranking (no Critical/High/Medium/Low severity and no CVSS \
                 score): {list} — unranked entries cannot be managed per the entity's \
                 Req. 6.3.1 risk rankings and the Req. 11.3.1.1 targeted risk \
                 analysis{not_affected_note}",
                affected = unranked.len(),
                total = open.len(),
                list = truncate_list(&unranked, 5),
            ),
            element: None,
            requirement: "PCI DSS v4.0.1 Req. 6.3.1 / 11.3.1.1: vulnerability risk ranking"
                .to_string(),
            rule_id: "SBOM-PCI-11-3-1-1-SEVERITY",
            component_id: None,
            counts: Some(ViolationCounts {
                affected: unranked.len(),
                total: open.len(),
            }),
            standard_refs: Vec::new(),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Component, CvssScore, CvssVersion, ExternalReference, Organization, VulnerabilityRef,
        VulnerabilitySource,
    };

    fn ts(s: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(s)
            .expect("test timestamp must parse")
            .with_timezone(&chrono::Utc)
    }

    /// Pinned to the shared test clock (tests/common/clock.rs).
    fn checker() -> ComplianceChecker {
        ComplianceChecker::new(ComplianceLevel::PciDss632).with_as_of(ts("2026-10-12T00:00:00Z"))
    }

    fn run(sbom: &NormalizedSbom) -> Vec<Violation> {
        checker().check(sbom).violations
    }

    fn rules_of(violations: &[Violation]) -> Vec<&'static str> {
        violations.iter().map(|v| v.rule_id).collect()
    }

    fn conforming_component(name: &str) -> Component {
        let mut comp = Component::new(name.to_string(), format!("ref-{name}"))
            .with_purl(format!("pkg:npm/{name}@1.0.0"))
            .with_version("1.0.0".to_string());
        comp.supplier = Some(Organization::new("Acme Components Ltd".to_string()));
        comp
    }

    fn push(sbom: &mut NormalizedSbom, comp: Component) {
        sbom.components.insert(comp.canonical_id.clone(), comp);
    }

    /// A document that satisfies every PCI check: named/versioned/identified
    /// primary + third-party components with suppliers, a Complete
    /// declaration, a fresh timestamp, and a security contact.
    fn conforming_sbom() -> NormalizedSbom {
        let mut sbom = NormalizedSbom::default();
        // The day before the pinned clock: fresh, and not future-dated.
        sbom.document.created = ts("2026-10-11T00:00:00Z");
        sbom.document.completeness_declaration = CompletenessDeclaration::Complete;
        sbom.document.security_contact = Some("security@acme.example".to_string());
        let primary = conforming_component("acme-payments");
        let primary_id = primary.canonical_id.clone();
        push(&mut sbom, primary);
        push(&mut sbom, conforming_component("libalpha"));
        push(&mut sbom, conforming_component("libbeta"));
        sbom.set_primary_component(primary_id);
        sbom
    }

    #[test]
    fn conforming_sbom_is_clean_and_compliant() {
        let result = checker().check(&conforming_sbom());
        assert!(
            result.violations.is_empty() && result.is_compliant,
            "conforming SBOM must be clean, got {:?}",
            rules_of(&result.violations)
        );
    }

    #[test]
    fn empty_and_headless_documents_fail_inventory() {
        let mut empty = NormalizedSbom::default();
        empty.document.completeness_declaration = CompletenessDeclaration::Complete;
        let violations = run(&empty);
        assert!(
            violations
                .iter()
                .any(|v| v.rule_id == "SBOM-PCI-6-3-2-INVENTORY"
                    && v.severity == ViolationSeverity::Error),
            "empty inventory must fail, got {:?}",
            rules_of(&violations)
        );

        let mut headless = conforming_sbom();
        headless.primary_component_id = None;
        let violations = run(&headless);
        assert!(
            violations
                .iter()
                .any(|v| v.rule_id == "SBOM-PCI-6-3-2-INVENTORY"
                    && v.severity == ViolationSeverity::Error),
            "headless inventory must fail, got {:?}",
            rules_of(&violations)
        );
    }

    /// File/snippet inventory records are exempt from all four
    /// per-component rules (registry: "every inventoried (non-file)
    /// component"), so a file-cataloguing SBOM does not auto-fail.
    #[test]
    fn file_components_are_exempt_from_per_component_rules() {
        let mut sbom = conforming_sbom();
        let mut file = Component::new("src/main.c".to_string(), "ref-file-1".to_string());
        file.component_type = crate::model::ComponentType::File;
        // No version, no identifier, no supplier — and still clean.
        push(&mut sbom, file);
        let violations = run(&sbom);
        assert!(
            violations.is_empty(),
            "file entries must not trip per-component rules, got {:?}",
            rules_of(&violations)
        );
    }

    #[test]
    fn placeholder_name_and_missing_version_fire_errors() {
        let mut sbom = conforming_sbom();
        let mut comp = Component::new("unknown".to_string(), "ref-mystery".to_string());
        comp.version = None;
        push(&mut sbom, comp);
        let violations = run(&sbom);
        for rule in ["SBOM-PCI-6-3-2-NAME", "SBOM-PCI-6-3-2-VERSION"] {
            assert!(
                violations
                    .iter()
                    .any(|v| v.rule_id == rule && v.severity == ViolationSeverity::Error),
                "{rule} must fire at Error, got {:?}",
                rules_of(&violations)
            );
        }
    }

    #[test]
    fn version_range_is_accepted_only_for_external_components() {
        let mut sbom = conforming_sbom();
        let mut ext = conforming_component("host-openssl");
        ext.version = None;
        ext.is_external = true;
        ext.version_range = Some("vers:generic/>=3.0|<4.0".to_string());
        push(&mut sbom, ext);
        let violations = run(&sbom);
        assert!(
            !violations
                .iter()
                .any(|v| v.rule_id == "SBOM-PCI-6-3-2-VERSION"),
            "external component with a version range must pass, got {:?}",
            rules_of(&violations)
        );

        let mut sbom = conforming_sbom();
        let mut bundled = conforming_component("bundled-lib");
        bundled.version = None;
        bundled.version_range = Some("vers:generic/>=3.0|<4.0".to_string());
        push(&mut sbom, bundled);
        let violations = run(&sbom);
        assert!(
            violations
                .iter()
                .any(|v| v.rule_id == "SBOM-PCI-6-3-2-VERSION"),
            "a version range on a bundled (non-external) component must not satisfy the \
             version rule, got {:?}",
            rules_of(&violations)
        );
    }

    #[test]
    fn supplier_fallback_evidence_is_accepted() {
        // Author, group, or an ecosystem-bearing PURL each substitute for a
        // missing supplier organization on non-primary components.
        for mutate in [
            (|c: &mut Component| c.author = Some("Jane Maintainer".to_string()))
                as fn(&mut Component),
            |c| c.group = Some("org.acme".to_string()),
            |c| c.set_purl("pkg:npm/fallback-lib@1.0.0".to_string()),
        ] {
            let mut sbom = conforming_sbom();
            let mut comp = Component::new("fallback-lib".to_string(), "ref-fb".to_string())
                .with_version("1.0.0".to_string());
            mutate(&mut comp);
            push(&mut sbom, comp);
            let violations = run(&sbom);
            assert!(
                !violations
                    .iter()
                    .any(|v| v.rule_id == "SBOM-PCI-6-3-2-SUPPLIER"),
                "fallback evidence must satisfy the supplier rule, got {:?}",
                rules_of(&violations)
            );
        }

        // No evidence at all fires — but only for non-primary components.
        let mut sbom = conforming_sbom();
        let comp = Component::new("bare-lib".to_string(), "ref-bare".to_string())
            .with_version("1.0.0".to_string());
        push(&mut sbom, comp);
        let violations = run(&sbom);
        assert!(
            violations
                .iter()
                .any(|v| v.rule_id == "SBOM-PCI-6-3-2-SUPPLIER"
                    && v.severity == ViolationSeverity::Warning),
            "supplier rule must fire without any source evidence, got {:?}",
            rules_of(&violations)
        );
    }

    #[test]
    fn primary_component_is_exempt_from_supplier_rule() {
        let mut sbom = conforming_sbom();
        let primary_id = sbom.primary_component_id.clone().expect("primary set");
        let primary = sbom
            .components
            .get_mut(&primary_id)
            .expect("primary resolves");
        primary.supplier = None;
        primary.author = None;
        primary.group = None;
        primary.ecosystem = None;
        let violations = run(&sbom);
        assert!(
            !violations
                .iter()
                .any(|v| v.rule_id == "SBOM-PCI-6-3-2-SUPPLIER"),
            "the primary (the entity's own application) must not trip the supplier rule, \
             got {:?}",
            rules_of(&violations)
        );
    }

    #[test]
    fn primary_only_sbom_warns_unless_declared_complete() {
        let mut sbom = NormalizedSbom::default();
        sbom.document.security_contact = Some("security@acme.example".to_string());
        let primary = conforming_component("acme-payments");
        let primary_id = primary.canonical_id.clone();
        push(&mut sbom, primary);
        sbom.set_primary_component(primary_id);

        let violations = run(&sbom);
        assert!(
            violations
                .iter()
                .any(|v| v.rule_id == "SBOM-PCI-6-3-2-THIRD-PARTY"
                    && v.severity == ViolationSeverity::Warning),
            "primary-only inventory must warn, got {:?}",
            rules_of(&violations)
        );

        // A Complete declaration marks a genuinely dependency-free
        // application: the inference is suppressed.
        sbom.document.completeness_declaration = CompletenessDeclaration::Complete;
        let violations = run(&sbom);
        assert!(
            !violations
                .iter()
                .any(|v| v.rule_id == "SBOM-PCI-6-3-2-THIRD-PARTY"),
            "Complete declaration must suppress the third-party inference, got {:?}",
            rules_of(&violations)
        );
    }

    #[test]
    fn indistinguishable_components_fire_third_party_warning() {
        let mut sbom = NormalizedSbom::default();
        sbom.document.security_contact = Some("security@acme.example".to_string());
        let primary = conforming_component("acme-payments");
        let primary_id = primary.canonical_id.clone();
        push(&mut sbom, primary);
        sbom.set_primary_component(primary_id);
        // Components beyond the primary, but nothing marks any of them as
        // third-party (no supplier/author, no ecosystem, not external).
        for name in ["module-a", "module-b"] {
            let comp = Component::new(name.to_string(), format!("ref-{name}"))
                .with_version("1.0.0".to_string());
            push(&mut sbom, comp);
        }
        let violations = run(&sbom);
        assert!(
            violations
                .iter()
                .any(|v| v.rule_id == "SBOM-PCI-6-3-2-THIRD-PARTY"
                    && v.severity == ViolationSeverity::Warning),
            "indistinguishable inventory must warn, got {:?}",
            rules_of(&violations)
        );
    }

    #[test]
    fn completeness_variants_map_to_documented_severities() {
        use CompletenessDeclaration as D;
        let cases = [
            (D::Complete, None),
            (D::Incomplete, Some(ViolationSeverity::Warning)),
            (
                D::IncompleteFirstPartyOnly,
                Some(ViolationSeverity::Warning),
            ),
            (
                D::IncompleteThirdPartyOnly,
                Some(ViolationSeverity::Warning),
            ),
            (D::Unknown, Some(ViolationSeverity::Info)),
            (D::NotSpecified, Some(ViolationSeverity::Info)),
        ];
        for (declaration, expected) in cases {
            let mut sbom = conforming_sbom();
            sbom.document.completeness_declaration = declaration.clone();
            let violations = run(&sbom);
            let hit = violations
                .iter()
                .find(|v| v.rule_id == "SBOM-PCI-6-3-2-COMPLETENESS");
            match expected {
                None => assert!(
                    hit.is_none(),
                    "{declaration:?} must stay silent, got {:?}",
                    rules_of(&violations)
                ),
                Some(severity) => {
                    let v = hit.unwrap_or_else(|| {
                        panic!(
                            "{declaration:?} must fire the completeness rule, got {:?}",
                            rules_of(&violations)
                        )
                    });
                    assert_eq!(v.severity, severity, "{declaration:?} severity");
                }
            }
        }
    }

    /// The NotSpecified message must describe a declared-but-unrecognized /
    /// no-assertion value — not the absence of a declaration (that is
    /// `Unknown`, the serde default).
    #[test]
    fn not_specified_message_is_distinct_from_absent_declaration() {
        let mut sbom = conforming_sbom();
        sbom.document.completeness_declaration = CompletenessDeclaration::NotSpecified;
        let violations = run(&sbom);
        let v = violations
            .iter()
            .find(|v| v.rule_id == "SBOM-PCI-6-3-2-COMPLETENESS")
            .expect("NotSpecified fires");
        assert!(
            v.message.contains("unrecognized") && !v.message.contains("no completeness"),
            "NotSpecified wording must not claim absence: {}",
            v.message
        );
    }

    #[test]
    fn missing_timestamp_warns_and_stale_timestamp_is_tool_policy_info() {
        let mut sbom = conforming_sbom();
        sbom.document.created = chrono::DateTime::UNIX_EPOCH; // parser sentinel
        let violations = run(&sbom);
        assert!(
            violations
                .iter()
                .any(|v| v.rule_id == "SBOM-PCI-6-3-2-FRESHNESS"
                    && v.severity == ViolationSeverity::Warning),
            "missing timestamp must warn, got {:?}",
            rules_of(&violations)
        );

        // Stale (beyond the tool-policy threshold, pinned clock — no wall
        // clock in tests): Info, and the message labels the threshold as
        // tool policy.
        let mut sbom = conforming_sbom();
        sbom.document.created = ts("2026-01-01T00:00:00Z");
        let result = checker()
            .with_as_of(ts("2027-06-01T00:00:00Z"))
            .check(&sbom);
        let v = result
            .violations
            .iter()
            .find(|v| v.rule_id == "SBOM-PCI-6-3-2-FRESHNESS")
            .expect("stale timestamp fires");
        assert_eq!(v.severity, ViolationSeverity::Info);
        assert!(
            v.message.contains("tool policy"),
            "staleness message must label the threshold as tool policy: {}",
            v.message
        );

        // Recent enough at the pinned clock: silent.
        let result = checker()
            .with_as_of(ts("2026-06-01T00:00:00Z"))
            .check(&sbom);
        assert!(
            !result
                .violations
                .iter()
                .any(|v| v.rule_id == "SBOM-PCI-6-3-2-FRESHNESS"),
            "fresh timestamp must stay silent"
        );
    }

    /// A timestamp after the evaluation instant gave a negative age and
    /// passed as fresh (review finding V14). It evidences no more than a
    /// missing timestamp, so it warns like one.
    #[test]
    fn future_timestamp_warns_instead_of_counting_as_fresh() {
        let mut sbom = conforming_sbom();
        sbom.document.created = ts("2026-10-13T00:00:00Z");
        let result = checker()
            .with_as_of(ts("2026-10-12T00:00:00Z"))
            .check(&sbom);
        let freshness: Vec<_> = result
            .violations
            .iter()
            .filter(|v| v.rule_id == "SBOM-PCI-6-3-2-FRESHNESS")
            .collect();
        assert_eq!(
            freshness.len(),
            1,
            "exactly one freshness finding, got {:?}",
            rules_of(&result.violations)
        );
        assert_eq!(freshness[0].severity, ViolationSeverity::Warning);
        assert!(
            freshness[0]
                .message
                .contains("later than the evaluation instant"),
            "{}",
            freshness[0].message
        );
        // Warning, not Error: the inventory itself is still compliant.
        assert!(result.is_compliant);

        // The same document evaluated after its timestamp is fresh again.
        let result = checker()
            .with_as_of(ts("2026-10-14T00:00:00Z"))
            .check(&sbom);
        assert!(
            result.violations.is_empty(),
            "got {:?}",
            rules_of(&result.violations)
        );
    }

    #[test]
    fn each_vulnerability_management_hook_satisfies_the_evidence_rule() {
        let strip_hooks = |sbom: &mut NormalizedSbom| {
            sbom.document.security_contact = None;
            sbom.document.vulnerability_disclosure_url = None;
        };

        let mut bare = conforming_sbom();
        strip_hooks(&mut bare);
        let violations = run(&bare);
        assert!(
            violations
                .iter()
                .any(|v| v.rule_id == "SBOM-PCI-6-3-2-VULN-EVIDENCE"
                    && v.severity == ViolationSeverity::Info),
            "no hooks must surface the Info finding, got {:?}",
            rules_of(&violations)
        );

        // Hook 1: an advisories external reference on any component.
        let mut sbom = conforming_sbom();
        strip_hooks(&mut sbom);
        let primary_id = sbom.primary_component_id.clone().expect("primary set");
        sbom.components
            .get_mut(&primary_id)
            .expect("primary resolves")
            .external_refs
            .push(ExternalReference {
                ref_type: ExternalRefType::Advisories,
                url: "https://acme.example/security/advisories".to_string(),
                comment: None,
                hashes: Vec::new(),
            });
        assert!(
            !run(&sbom)
                .iter()
                .any(|v| v.rule_id == "SBOM-PCI-6-3-2-VULN-EVIDENCE"),
            "advisories reference must satisfy the rule"
        );

        // Hook 2: embedded vulnerability data.
        let mut sbom = conforming_sbom();
        strip_hooks(&mut sbom);
        let primary_id = sbom.primary_component_id.clone().expect("primary set");
        let mut vuln = VulnerabilityRef::new("CVE-2026-0001".to_string(), VulnerabilitySource::Nvd);
        vuln.severity = Some(Severity::Medium);
        sbom.components
            .get_mut(&primary_id)
            .expect("primary resolves")
            .vulnerabilities
            .push(vuln);
        assert!(
            !run(&sbom)
                .iter()
                .any(|v| v.rule_id == "SBOM-PCI-6-3-2-VULN-EVIDENCE"),
            "embedded vulnerability data must satisfy the rule"
        );

        // Hook 3: a disclosure URL.
        let mut sbom = conforming_sbom();
        strip_hooks(&mut sbom);
        sbom.document.vulnerability_disclosure_url =
            Some("https://acme.example/.well-known/security.txt".to_string());
        assert!(
            !run(&sbom)
                .iter()
                .any(|v| v.rule_id == "SBOM-PCI-6-3-2-VULN-EVIDENCE"),
            "disclosure URL must satisfy the rule"
        );
    }

    /// Risk-ranking must be computed per entry from severity OR CVSS — not
    /// via `vulnerability_counts()`, whose `unknown` bucket ignores CVSS and
    /// absorbs `Some(Info|None|Unknown)` severities.
    #[test]
    fn risk_ranking_counts_cvss_only_entries_as_ranked() {
        let with_vuln = |vuln: VulnerabilityRef| {
            let mut sbom = conforming_sbom();
            let primary_id = sbom.primary_component_id.clone().expect("primary set");
            sbom.components
                .get_mut(&primary_id)
                .expect("primary resolves")
                .vulnerabilities
                .push(vuln);
            sbom
        };

        // CVSS score but no ranked severity: RANKED (the counts() helper
        // would miscount this as unknown).
        let mut cvss_only =
            VulnerabilityRef::new("CVE-2026-1000".to_string(), VulnerabilitySource::Nvd);
        cvss_only.cvss.push(CvssScore::new(CvssVersion::V31, 5.3));
        cvss_only.severity = None;
        assert!(
            !run(&with_vuln(cvss_only))
                .iter()
                .any(|v| v.rule_id == "SBOM-PCI-11-3-1-1-SEVERITY"),
            "a CVSS-only entry is ranked"
        );

        // Some(Severity::Unknown) and no CVSS: UNRANKED despite is_some().
        let mut unknown_sev =
            VulnerabilityRef::new("CVE-2026-1001".to_string(), VulnerabilitySource::Nvd);
        unknown_sev.severity = Some(Severity::Unknown);
        let violations = run(&with_vuln(unknown_sev));
        let v = violations
            .iter()
            .find(|v| v.rule_id == "SBOM-PCI-11-3-1-1-SEVERITY")
            .expect("unranked entry fires");
        assert_eq!(v.severity, ViolationSeverity::Warning);
        assert_eq!(
            v.counts,
            Some(ViolationCounts {
                affected: 1,
                total: 1
            })
        );

        // Ranked severity, no CVSS: silent.
        let mut ranked =
            VulnerabilityRef::new("CVE-2026-1002".to_string(), VulnerabilitySource::Nvd);
        ranked.severity = Some(Severity::Low);
        assert!(
            !run(&with_vuln(ranked))
                .iter()
                .any(|v| v.rule_id == "SBOM-PCI-11-3-1-1-SEVERITY"),
            "a severity-ranked entry is ranked"
        );
    }

    /// An entry whose own VEX statement is a justified not_affected needs no
    /// ranking: it is left out of the counts, and the message says how many
    /// were. A bare not_affected claim still needs one.
    #[test]
    fn risk_ranking_leaves_out_justified_not_affected_entries() {
        use crate::model::{VexJustification, VexState, VexStatus};
        let unranked = |id: &str| {
            let mut vuln = VulnerabilityRef::new(id.to_string(), VulnerabilitySource::Nvd);
            vuln.severity = Some(Severity::Unknown);
            vuln
        };
        let not_affected = |id: &str, justified: bool| {
            let mut vex = VexStatus::new(VexState::NotAffected);
            if justified {
                vex.justification = Some(VexJustification::VulnerableCodeNotInExecutePath);
            }
            let mut vuln = unranked(id);
            vuln.vex_status = Some(vex);
            vuln
        };
        let finding = |vulns: Vec<VulnerabilityRef>| {
            let mut sbom = conforming_sbom();
            let primary_id = sbom.primary_component_id.clone().expect("primary set");
            sbom.components
                .get_mut(&primary_id)
                .expect("primary resolves")
                .vulnerabilities
                .extend(vulns);
            run(&sbom)
                .into_iter()
                .find(|v| v.rule_id == "SBOM-PCI-11-3-1-1-SEVERITY")
        };

        // Nothing is open, so nothing needs a ranking.
        assert!(finding(vec![not_affected("CVE-2026-2000", true)]).is_none());

        let bare = finding(vec![not_affected("CVE-2026-2001", false)])
            .expect("a bare not_affected claim needs a ranking");
        assert_eq!(
            bare.counts,
            Some(ViolationCounts {
                affected: 1,
                total: 1
            })
        );

        let mut ranked =
            VulnerabilityRef::new("CVE-2026-2003".to_string(), VulnerabilitySource::Nvd);
        ranked.severity = Some(Severity::Low);
        let mixed = finding(vec![
            unranked("CVE-2026-2002"),
            ranked,
            not_affected("CVE-2026-2004", true),
        ])
        .expect("the open unranked entry fires");
        assert_eq!(
            mixed.counts,
            Some(ViolationCounts {
                affected: 1,
                total: 2
            })
        );
        assert!(
            mixed.message.contains("1/2 embedded vulnerability entries")
                && mixed.message.ends_with(
                    "; 1 more entry has a justified not_affected VEX statement and needs none"
                )
                && !mixed.message.contains("CVE-2026-2004"),
            "{}",
            mixed.message
        );
    }

    #[test]
    fn risk_ranking_is_not_applicable_without_vulnerability_data() {
        // No vulnerability data anywhere: the rule must stay silent (not
        // applicable), never a vacuous pass/fail.
        let violations = run(&conforming_sbom());
        assert!(
            !violations
                .iter()
                .any(|v| v.rule_id == "SBOM-PCI-11-3-1-1-SEVERITY"),
            "rule must be silent without vulnerability data"
        );
    }
}
