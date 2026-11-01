//! EU Cyber Resilience Act checks: Annex/Article gap analysis, hardware
//! (HBOM) components, Article 14 reporting readiness, product-class module
//! attestation / EUCC references, the Annex VIII conformity summary, and the
//! Article 24 open-source-steward profile.

use super::ssdf::{cdxa_note, standard_references_eucc};
use super::*;
use crate::model::{AttestationRuleFamily, EvidenceLevel};

impl ComplianceChecker {
    /// Build the per-route evidence checklist (CRA-P4.3). Each route lists
    /// the external references manufacturers are expected to attach to
    /// satisfy Annex VIII; the `satisfied` flag is computed by scanning the
    /// SBOM's `external_refs` and the attached sidecar — and, when the
    /// document carries CDXA declarations, resolved fresh attestation
    /// evidence targeting a CRA-classified standard satisfies the
    /// attestation/DoC rows at Structural/SignaturePresent level while the
    /// presence bits keep satisfying at SelfDeclared.
    pub(crate) fn build_conformity_summary(
        &self,
        sbom: &NormalizedSbom,
    ) -> ConformityAssessmentSummary {
        use crate::model::{ConformityRoute, ExternalRefType};
        let class = self.effective_product_class();
        let route = self.effective_route();

        // CDXA attestation evidence classified into the CRA family, fresh
        // and fully resolved at the injectable clock. Empty for documents
        // without declarations, leaving every row exactly as before.
        let ctx = ComplianceContext::new(self, sbom);
        let cra_evidence = ctx.evidence_for(AttestationRuleFamily::Cra);
        let cdxa_level = cra_evidence.iter().map(|s| s.evidence_level).max();
        let cdxa_eucc_level = cra_evidence
            .iter()
            .filter(|s| standard_references_eucc(s.standard))
            .map(|s| s.evidence_level)
            .max();
        // Strengthen a checklist row with CDXA evidence: the row becomes
        // satisfied and the detail names the evidence level; without CDXA
        // evidence the legacy (SelfDeclared) verdict passes through.
        let cdxa = |satisfied: bool, level: Option<EvidenceLevel>, detail: &str| match level {
            Some(level) => (
                true,
                format!(
                    "{detail} Satisfied by machine-readable CDXA attestation ({level} evidence); external-reference/sidecar presence remains the self-declared fallback."
                ),
            ),
            None => (satisfied, detail.to_string()),
        };

        // The rows read the same manufacturer-scope references as the
        // Annex V / Annex VIII / Annex IV checks: a dependency's own
        // certificate or attestation is not the product's.
        let any_ext = |needles: &[ExternalRefType]| -> bool {
            manufacturer_reference(sbom, |r| {
                needles
                    .iter()
                    .any(|n| std::mem::discriminant(&r.ref_type) == std::mem::discriminant(n))
            })
        };

        // Annex V (and the Module C statement): the manufacturer's own
        // declaration, so an attestation counts as well as a certification
        // reference or the sidecar CE-marking reference.
        let doc_or_ce = any_ext(&[ExternalRefType::Attestation, ExternalRefType::Certification])
            || self
                .sidecar
                .as_ref()
                .is_some_and(|s| s.ce_marking_reference.is_some());

        // Annex VIII routes beyond Module A rest on notified-body or
        // certification-body evidence: only a certification reference
        // (CycloneDX certification-report, SPDX 3.0 certificationReport)
        // shows it. An attestation may be a self-attestation, so it does not
        // count here; the same predicate gates SBOM-CRA-ANNEX-VIII
        // (check_class_module_attestation).
        let certificate_present = any_ext(&[ExternalRefType::Certification]);

        // The EUCC reference the Annex IV check and SBOM-EUCC-CERTREF read
        // (`is_eucc_reference`).
        let eucc_present = self
            .sidecar
            .as_ref()
            .is_some_and(|s| s.has_live_eucc_evidence_at(self.now()))
            || manufacturer_reference(sbom, is_eucc_reference);

        let mut evidence: Vec<ConformityEvidence> = Vec::new();
        let (satisfied, detail) = cdxa(
            doc_or_ce,
            cdxa_level,
            "Annex V — manufacturer's signed declaration. Provide via Attestation/Certification external ref or sidecar ceMarkingReference.",
        );
        evidence.push(ConformityEvidence {
            label: "EU Declaration of Conformity".to_string(),
            detail,
            satisfied,
        });

        match route {
            ConformityRoute::ModuleA => {
                evidence.push(ConformityEvidence {
                    label: "Internal-control technical file".to_string(),
                    detail: "Module A — manufacturer holds the technical file at their premises. No external attestation required.".to_string(),
                    satisfied: true,
                });
            }
            ConformityRoute::ModuleBC => {
                let (satisfied, detail) = cdxa(
                    certificate_present,
                    cdxa_level,
                    "Notified-body certificate of EU-type examination — Certification external ref (an attestation does not count).",
                );
                evidence.push(ConformityEvidence {
                    label: "EU-type examination certificate (Module B)".to_string(),
                    detail,
                    satisfied,
                });
                let (satisfied, detail) = cdxa(
                    doc_or_ce,
                    cdxa_level,
                    "Manufacturer's declaration that production conforms to the type examined under Module B.",
                );
                evidence.push(ConformityEvidence {
                    label: "Production conformity statement (Module C)".to_string(),
                    detail,
                    satisfied,
                });
            }
            ConformityRoute::ModuleH => {
                let (satisfied, detail) = cdxa(
                    certificate_present,
                    cdxa_level,
                    "Notified-body QMS certification (typically ISO 9001 / ISO/IEC 27001 family) — Certification external ref (an attestation does not count).",
                );
                evidence.push(ConformityEvidence {
                    label: "Quality-management-system certification (Module H)".to_string(),
                    detail,
                    satisfied,
                });
                let (satisfied, detail) = cdxa(
                    certificate_present,
                    cdxa_level,
                    "Notified-body surveillance / re-assessment record — Certification external ref (an attestation does not count).",
                );
                evidence.push(ConformityEvidence {
                    label: "QMS surveillance plan".to_string(),
                    detail,
                    satisfied,
                });
            }
            ConformityRoute::Eucc => {
                // EUCC rows require the stricter subset: CDXA standards
                // that both classify as CRA and name EUCC/Common Criteria.
                let (satisfied, detail) = cdxa(
                    eucc_present,
                    cdxa_eucc_level,
                    "Common Criteria certificate from an EUCC-accredited ITSEF — Certification or Attestation external ref whose URL contains eucc, common-criteria or commoncriteria.",
                );
                evidence.push(ConformityEvidence {
                    label: "EUCC / Common Criteria certificate".to_string(),
                    detail,
                    satisfied,
                });
                let (satisfied, detail) = cdxa(
                    eucc_present,
                    cdxa_eucc_level,
                    "Reference to the ToE (and Protection Profile, when applicable) that the EUCC certificate covers.",
                );
                evidence.push(ConformityEvidence {
                    label: "Target of Evaluation reference".to_string(),
                    detail,
                    satisfied,
                });
            }
        }

        // Article 14 channels are required at all conformity routes once the
        // 2026-09-11 deadline applies; surface as evidence rows for
        // notified-body checklists.
        // A placeholder PSIRT URL reaches nobody (`known_contact`).
        let psirt = self
            .sidecar
            .as_ref()
            .is_some_and(|s| known_contact(s.psirt_url.as_deref()));
        evidence.push(ConformityEvidence {
            label: "PSIRT contact (Art. 14)".to_string(),
            detail: "Public PSIRT URL for receiving external vulnerability reports.".to_string(),
            satisfied: psirt,
        });

        let _ = class; // already encoded into the route; keep on the summary
        ConformityAssessmentSummary {
            product_class: class,
            route,
            evidence,
        }
    }

    /// CRA gap checks: SBOM freshness (Art. 13(7)), 13(5), 13(9), Annex I Part II supply chain, document integrity
    pub(crate) fn check_cra_gaps(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        // B1: Art. 13(7) / Annex I Part II (1) — SBOM freshness. Keeping the
        // documented component inventory current is the systematic-
        // documentation duty applied to the SBOM element. A missing
        // timestamp (epoch sentinel) is a freshness gap in its own right, but
        // must be reported as "missing", not as a bogus ~20000-day age. A
        // timestamp after the evaluation instant is no evidence of currency
        // either and warns like a missing one, instead of passing as fresh.
        let now = self.now();
        if !sbom.document.has_known_timestamp() {
            let gap =
                unparseable_timestamp(sbom).unwrap_or_else(|| "no creation timestamp".to_string());
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::DocumentMetadata,
                message: format!(
                    "[CRA Art. 13(7) / Annex I Part II (1)] SBOM has {gap}; keep the documented \
                     component inventory current when components change"
                ),
                element: None,
                requirement: "CRA Art. 13(7) / Annex I Part II (1): SBOM freshness".to_string(),
                rule_id: "SBOM-CRA-SBOM-FRESHNESS",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                deadline: None,
            });
        } else if let Some(future) = future_timestamp_violation(
            sbom,
            now,
            "SBOM-CRA-SBOM-FRESHNESS",
            "[CRA Art. 13(7) / Annex I Part II (1)]",
            "CRA Art. 13(7) / Annex I Part II (1): SBOM freshness",
        ) {
            violations.push(future);
        } else {
            let age_days = (now - sbom.document.created).num_days();
            if age_days > 90 {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::DocumentMetadata,
                    message: format!(
                        "[CRA Art. 13(7) / Annex I Part II (1)] SBOM is {age_days} days old; keep the documented component inventory current when components change"
                    ),
                    element: None,
                    requirement: "CRA Art. 13(7) / Annex I Part II (1): SBOM freshness".to_string(),
                    rule_id: "SBOM-CRA-SBOM-FRESHNESS",
                    component_id: None,
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            } else if age_days > 30 {
                violations.push(Violation {
                    severity: ViolationSeverity::Info,
                    category: ViolationCategory::DocumentMetadata,
                    message: format!(
                        "[CRA Art. 13(7) / Annex I Part II (1)] SBOM is {age_days} days old; consider regenerating after component changes"
                    ),
                    element: None,
                    requirement: "CRA Art. 13(7) / Annex I Part II (1): SBOM freshness".to_string(),
                    rule_id: "SBOM-CRA-SBOM-FRESHNESS",
                    component_id: None,
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            }
        }

        // B2: Art. 13(5) — Third-party due diligence. The CRA does not list
        // licences as an SBOM element; licence data is evidence that the
        // manufacturer exercised due diligence on integrated third-party
        // components.
        // Licence evidence and the supply-chain cohorts below concern
        // package-scoped components: crypto assets, files and services are
        // not third-party components with licences or suppliers.
        let packages: Vec<_> = package_components(sbom).collect();
        let total = packages.len();
        let without_license = packages.iter().filter(|c| !has_known_license(c)).count();
        if without_license > 0 {
            let pct = (without_license * 100) / total.max(1);
            let severity = if pct > 50 {
                ViolationSeverity::Warning
            } else {
                ViolationSeverity::Info
            };
            violations.push(Violation {
                severity,
                category: ViolationCategory::LicenseInfo,
                message: format!(
                    "[CRA Art. 13(5)] {without_license}/{total} components ({pct}%) missing license information needed to evidence third-party due diligence"
                ),
                element: None,
                requirement: "CRA Art. 13(5): Third-party due diligence (license tracking)"
                    .to_string(),
                rule_id: "SBOM-CRA-ART-13-5",
                component_id: None,
                counts: Some(ViolationCounts {
                    affected: without_license,
                    total,
                }),
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                deadline: None,
            });
        }

        // B3: Annex I Part II (1) — documented vulnerability information.
        // (Formerly cited Art. 13(9), which is actually the 10-year
        // security-update availability obligation.)
        // SBOM should either contain vulnerability data or explicitly indicate "none known"
        let has_vuln_data = sbom
            .components
            .values()
            .any(|c| !c.vulnerabilities.is_empty());
        let has_vuln_assertion = sbom.components.values().any(|comp| {
            comp.external_refs.iter().any(|r| {
                matches!(
                    r.ref_type,
                    crate::model::ExternalRefType::VulnerabilityAssertion
                        | crate::model::ExternalRefType::ExploitabilityStatement
                )
            })
        });
        if !has_vuln_data && !has_vuln_assertion {
            violations.push(Violation {
                severity: ViolationSeverity::Info,
                category: ViolationCategory::SecurityInfo,
                message:
                    "[CRA Annex I Part II (1)] No vulnerability data or vulnerability assertion found; \
                    include vulnerability information or a statement of no known vulnerabilities"
                        .to_string(),
                element: None,
                requirement: "CRA Annex I Part II (1): Documented vulnerability information"
                    .to_string(),
                rule_id: "SBOM-CRA-VULN-STATEMENT",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                deadline: None,
            });
        }

        // B4: Annex I Part II — Supply-chain transparency.
        //
        // prEN 40000-1-3 [PRE-7-RQ-03] makes direct dependencies *mandatory*
        // and transitive dependencies *recommended*. We split the cohort
        // accordingly:
        // - direct (1 hop from the primary component) missing supplier:
        //   Error under CraPhase2, Warning otherwise.
        // - transitive missing supplier: Warning under CraPhase2 if >30%,
        //   Info otherwise.
        if !sbom.edges.is_empty() {
            // Direct dependencies that are packages: a TLS protocol or an
            // algorithm the product uses is not a supplier-bearing
            // dependency.
            let direct_ids: std::collections::HashSet<_> = sbom
                .direct_dependency_ids()
                .into_iter()
                .filter(|id| {
                    sbom.components
                        .get(id)
                        .is_some_and(|c| c.component_type.is_package_scoped())
                })
                .collect();
            let mut direct_missing: Vec<String> = Vec::new();
            let mut transitive_missing: Vec<String> = Vec::new();
            for comp in &packages {
                // A NOASSERTION or placeholder supplier names nobody: the
                // raw presence test let it satisfy this mandatory rule while
                // SBOM-CRA-COMPONENT-SUPPLIER reported the same supplier
                // missing.
                if has_known_producer(comp) {
                    continue;
                }
                if direct_ids.contains(&comp.canonical_id) {
                    direct_missing.push(comp.name.clone());
                } else {
                    transitive_missing.push(comp.name.clone());
                }
            }

            if !direct_missing.is_empty() {
                let severity = if matches!(self.level, ComplianceLevel::CraPhase2) {
                    ViolationSeverity::Error
                } else {
                    ViolationSeverity::Warning
                };
                let n = direct_missing.len();
                violations.push(Violation {
                    severity,
                    category: ViolationCategory::SupplierInfo,
                    message: format!(
                        "[CRA Annex I Part II / [PRE-7-RQ-03]] {n} direct dependencies missing supplier (mandatory): {}",
                        truncate_list(&direct_missing, 5)
                    ),
                    element: None,
                    requirement: "CRA Annex I Part II / prEN 40000-1-3 [PRE-7-RQ-03]: Direct dependency supplier (mandatory)"
                        .to_string(),
                    rule_id: "SBOM-CRA-ANNEX-I-SUPPLY-CHAIN",
                    component_id: None,
                    // The message prints only the affected count; the cohort
                    // is the set of direct dependencies.
                    counts: Some(ViolationCounts {
                        affected: n,
                        total: direct_ids.len(),
                    }),
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            }

            let transitive_n = transitive_missing.len();
            if transitive_n > 0 {
                let denom = total.max(1);
                let pct = (transitive_n * 100) / denom;
                let severity = if matches!(self.level, ComplianceLevel::CraPhase2) && pct > 30 {
                    ViolationSeverity::Warning
                } else {
                    ViolationSeverity::Info
                };
                violations.push(Violation {
                    severity,
                    category: ViolationCategory::SupplierInfo,
                    message: format!(
                        "[CRA Annex I Part II / [PRE-7-RQ-03]] {transitive_n}/{denom} transitive dependencies ({pct}%) missing supplier (recommended): {}",
                        truncate_list(&transitive_missing, 5)
                    ),
                    element: None,
                    requirement: "CRA Annex I Part II / prEN 40000-1-3 [PRE-7-RQ-03]: Transitive dependency supplier (recommended)"
                        .to_string(),
                    rule_id: "SBOM-CRA-ANNEX-I-SUPPLY-CHAIN-TRANSITIVE",
                    component_id: None,
                    counts: Some(ViolationCounts {
                        affected: transitive_n,
                        total: denom,
                    }),
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            }
        }

        // B4b: prEN 40000-1-3 [PRE-7-RQ-07-RE] — vendor hash carry-through
        // Vendor-supplied components (those with a supplier, manufacturer or
        // author and a PURL/CPE/SWHID/SWID) must carry the upstream-supplied
        // cryptographic hash through into the SBOM. Components without one of
        // those identifiers are excluded because nothing ties them to an
        // upstream artefact.
        {
            let metrics = crate::quality::HashQualityMetrics::from_sbom(sbom);
            if let Some(coverage) = metrics.vendor_hash_coverage() {
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                let pct = (coverage * 100.0).round() as usize;

                // Phase-based thresholds are the floor; a pinned CRA product
                // class can only escalate (tighter threshold or stronger
                // severity), never weaken the phase gate — supplying MORE
                // information must not relax enforcement.
                let phase_gate = match self.level {
                    ComplianceLevel::CraPhase2 if coverage < 0.50 => {
                        Some((ViolationSeverity::Error, "below 50% threshold".to_string()))
                    }
                    ComplianceLevel::CraPhase2 if coverage < 0.80 => Some((
                        ViolationSeverity::Warning,
                        "below 80% threshold".to_string(),
                    )),
                    ComplianceLevel::CraPhase1 if coverage < 0.50 => Some((
                        ViolationSeverity::Warning,
                        "below 50% threshold".to_string(),
                    )),
                    _ => None,
                };
                let class_gate = if self.has_explicit_product_class()
                    && coverage < self.vendor_hash_threshold()
                {
                    let sev = self
                        .class_severity(ClassCheck::VendorHashCoverage)
                        .unwrap_or(ViolationSeverity::Warning);
                    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                    let thr_pct = (self.vendor_hash_threshold() * 100.0).round() as usize;
                    Some((
                        sev,
                        format!(
                            "below {thr_pct}% threshold for product class {}",
                            self.effective_product_class().label()
                        ),
                    ))
                } else {
                    None
                };
                const fn rank(s: ViolationSeverity) -> u8 {
                    match s {
                        ViolationSeverity::Error => 2,
                        ViolationSeverity::Warning => 1,
                        ViolationSeverity::Info => 0,
                    }
                }
                let (severity, threshold_msg) = match (phase_gate, class_gate) {
                    // Whichever gate produced the stronger severity also
                    // supplies the message, so the finding states the
                    // threshold that was actually breached at that severity.
                    (Some(p), Some(c)) => {
                        if rank(p.0) > rank(c.0) {
                            p
                        } else {
                            c
                        }
                    }
                    (Some(p), None) => p,
                    (None, Some(c)) => c,
                    (None, None) => (ViolationSeverity::Info, String::new()),
                };
                if !threshold_msg.is_empty() {
                    // The metric counts only plausible digests; name the
                    // vendor components whose present hashes did not count.
                    // All components: the same vendor cohort the metric
                    // classifies (a known producer and an identifier).
                    let mut message = format!(
                        "[CRA Annex I, Part II / [PRE-7-RQ-07-RE]] Only {}/{} vendor-supplied components ({pct}%) carry an upstream hash — {threshold_msg}",
                        metrics.vendor_components_with_hash, metrics.vendor_components_total
                    );
                    message.push_str(&invalid_digest_note(sbom.components.values().filter(|c| {
                        has_known_producer(c)
                            && c.identifiers.has_cra_identifier()
                            && !c
                                .hashes
                                .iter()
                                .any(|h| plausible_digest(&h.algorithm, &h.value))
                    })));
                    violations.push(Violation {
                        severity,
                        category: ViolationCategory::IntegrityInfo,
                        message,
                        element: None,
                        requirement: "CRA Annex I Part II / prEN 40000-1-3 [PRE-7-RQ-07-RE]: Vendor hash carry-through".to_string(),
                        rule_id: "SBOM-CRA-PRE-7-RQ-07-RE",
                        component_id: None,
                        // Coverage finding: mirrors the "X/Y carry an
                        // upstream hash" numbers printed in the message.
                        counts: Some(ViolationCounts {
                            affected: metrics.vendor_components_with_hash,
                            total: metrics.vendor_components_total,
                        }),
                        standard_refs: Vec::new(),
                        remediation: None,
                        finding_detail: None,
                        deadline: None,
                    });
                }
            }
        }

        // B5: Annex I Part I (2)(f) — Document signature/integrity. The
        // clause asks to "protect the integrity of stored, transmitted or
        // otherwise processed data ... against any manipulation or
        // modification not authorised by the user" (it does not mention
        // authenticity). Integrity evidence is a document signature with a
        // value (`document_signed`), or an attestation or certification
        // reference on the described product that carries a plausible
        // digest of the referenced document. A serial number identifies the
        // document but protects nothing: until v0.4.0 it satisfied the check
        // on its own, the document signature was not read, and any
        // component's reference with any hash value counted.
        let hashed_attestation = manufacturer_reference(sbom, |r| {
            matches!(
                r.ref_type,
                crate::model::ExternalRefType::Attestation
                    | crate::model::ExternalRefType::Certification
            ) && r
                .hashes
                .iter()
                .any(|h| plausible_digest(&h.algorithm, &h.value))
        });
        if !document_signed(sbom) && !hashed_attestation {
            let mut message = "[CRA Annex I Part I (2)(f)] SBOM carries no integrity protection: \
                               sign the document, or reference from the product an attestation \
                               or certification that carries its hash (a serial number \
                               identifies the document but does not protect it)"
                .to_string();
            if sbom.document.signature.is_some() {
                message.push_str("; the document signature has no value");
            }
            violations.push(Violation {
                severity: ViolationSeverity::Info,
                category: ViolationCategory::IntegrityInfo,
                message,
                element: None,
                requirement: "CRA Annex I Part I (2)(f): Document signature/integrity".to_string(),
                rule_id: "SBOM-CRA-DOC-INTEGRITY",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                deadline: None,
            });
        }

        // B5b: Art. 13(2) — Documented risk-assessment reference
        // The CRA requires manufacturers to perform and document a risk
        // assessment. The SBOM (or sidecar) must reference it; absence is a
        // soft Warning under CraPhase2 (Annex V technical-doc requirement).
        if matches!(self.level, ComplianceLevel::CraPhase2) {
            // The product's own risk assessment: a reference on the
            // described product, not a dependency's.
            let has_ref_in_sbom = manufacturer_reference(sbom, |r| {
                matches!(r.ref_type, crate::model::ExternalRefType::RiskAssessment)
            }) || sbom.document.creators.iter().any(|c| {
                // Some SBOMs encode the methodology in the creator comment
                c.name.to_lowercase().contains("risk assessment")
            });
            let sidecar_has_ref = self
                .sidecar
                .as_ref()
                .is_some_and(|s| s.risk_assessment_url.is_some());
            if !has_ref_in_sbom && !sidecar_has_ref {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::DocumentMetadata,
                    message: "[CRA Art. 13(2)] No documented risk assessment referenced — add an externalReference of type 'risk-assessment' or supply riskAssessmentUrl in the CRA sidecar".to_string(),
                    element: None,
                    requirement: "CRA Art. 13(2): Documented risk assessment".to_string(),
                    rule_id: "SBOM-CRA-ART-13-2",
                    component_id: None,
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            }
        }

        // B5c: Art. 14 reporting-readiness
        // Manufacturers must operate channels to:
        // - 24-hour early-warn ENISA / CSIRT for actively-exploited vulnerabilities (14(1))
        // - 72-hour incident report (14(2))
        // - Route through the ENISA single reporting platform (14(7))
        // Obligations apply from 11 September 2026; before that, missing
        // channels surface as Info ("prepare ahead"); after that, Warning.
        if self.level.is_cra() {
            self.check_article_14_readiness_at(self.now(), violations);
        }

        // B6: Art. 13(8) / Annex II (7) — Component lifecycle / EOL detection
        // If EOL enrichment data is present, warn about EOL components
        let eol_count = package_components(sbom)
            .filter(|c| {
                c.eol
                    .as_ref()
                    .is_some_and(|e| e.status == crate::model::EolStatus::EndOfLife)
            })
            .count();
        if eol_count > 0 {
            let severity = if self.has_explicit_product_class() {
                self.class_severity(ClassCheck::EolComponents)
                    .unwrap_or(ViolationSeverity::Warning)
            } else {
                ViolationSeverity::Warning
            };
            violations.push(Violation {
                severity,
                category: ViolationCategory::SecurityInfo,
                message: format!(
                    "[CRA Art. 13(8)] {eol_count} component(s) have reached end-of-life and no longer receive security updates"
                ),
                element: None,
                requirement: "CRA Art. 13(8): Support period / lifecycle management".to_string(),
                rule_id: "SBOM-CRA-ART-13-8-EOL",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                deadline: None,
            });
        }

        let approaching_eol_count = package_components(sbom)
            .filter(|c| {
                c.eol
                    .as_ref()
                    .is_some_and(|e| e.status == crate::model::EolStatus::ApproachingEol)
            })
            .count();
        if approaching_eol_count > 0 {
            violations.push(Violation {
                severity: ViolationSeverity::Info,
                category: ViolationCategory::SecurityInfo,
                message: format!(
                    "[CRA Art. 13(8) / Annex II (7)] {approaching_eol_count} component(s) are approaching end-of-life within 6 months"
                ),
                element: None,
                requirement: "CRA Annex II (7): Component lifecycle monitoring".to_string(),
                rule_id: "SBOM-CRA-LIFECYCLE-APPROACHING-EOL",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                deadline: None,
            });
        }

        // SPDX 3.0 profile conformance checks (Phase 6)
        if sbom.document.format == crate::model::SbomFormat::Spdx
            && sbom.document.spec_version.starts_with("3.")
        {
            // Check if Security profile is declared when vulnerabilities are present
            let has_vulns = sbom
                .components
                .values()
                .any(|c| !c.vulnerabilities.is_empty());
            // The declared profiles (`DocumentMetadata::profile_conformance`;
            // until v0.4.0 read from the distribution classification).
            let has_security_profile = sbom
                .document
                .profile_conformance
                .iter()
                .any(|p| p.to_lowercase().contains("security"));

            if has_vulns && !has_security_profile {
                violations.push(Violation {
                    severity: ViolationSeverity::Info,
                    category: ViolationCategory::DocumentMetadata,
                    message:
                        "[CRA Annex I Part II (4)] SPDX 3.0 document contains vulnerabilities but does not declare Security profile conformance; declare profileConformance: [\"security\"] so vulnerability information is conveyed completely"
                            .to_string(),
                    element: None,
                    requirement: "CRA Annex I Part II (4): SPDX 3.0 Security profile conformance"
                        .to_string(),
                    rule_id: "SBOM-CRA-VULN-METADATA-PROFILE",
                    component_id: None,
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            }

            // Check if SimpleLicensing profile is declared when licenses are tracked
            let has_licenses = sbom
                .components
                .values()
                .any(|c| !c.licenses.declared.is_empty() || c.licenses.concluded.is_some());
            let has_licensing_profile = sbom
                .document
                .profile_conformance
                .iter()
                .any(|p| p.to_lowercase().contains("licensing"));

            if has_licenses && !has_licensing_profile {
                violations.push(Violation {
                    severity: ViolationSeverity::Info,
                    category: ViolationCategory::LicenseInfo,
                    message:
                        "[CRA Art. 13(5)] SPDX 3.0 document tracks licenses but does not declare SimpleLicensing profile conformance; declare profileConformance: [\"simpleLicensing\"] to support third-party due diligence"
                            .to_string(),
                    element: None,
                    requirement: "CRA Art. 13(5): SPDX 3.0 SimpleLicensing profile conformance"
                        .to_string(),
                    rule_id: "SBOM-CRA-ART-13-5-PROFILE",
                    component_id: None,
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            }
        }

        // CRA-P3.2: Class-conditional EUCC and Module-attestation references
        // (only fire when the operator pinned a product class — preserves
        // pre-P3.2 behavior for callers that didn't opt in).
        if self.has_explicit_product_class() {
            self.check_class_eucc_reference(sbom, violations);
            self.check_class_module_attestation(sbom, violations);
        }

        // CRA-P5.5: prEN 40000-1-2/1-4 controls-assertion sanity checks.
        // Only fires when the sidecar provides an annex_i_part_i_controls
        // block; otherwise the section is silently skipped.
        self.check_controls_assertion(violations);
    }

    /// Cross-check the sidecar `annex_i_part_i_controls` block. A control
    /// claimed `satisfied = true` without an `evidence_url` produces a
    /// Warning (un-evidenced claim); claimed `satisfied = false` is fine
    /// (manufacturer is being honest about a gap).
    pub(crate) fn check_controls_assertion(&self, violations: &mut Vec<Violation>) {
        let Some(sidecar) = self.sidecar.as_ref() else {
            return;
        };
        if sidecar.annex_i_part_i_controls.is_empty() {
            return;
        }
        // One finding per un-evidenced control, told apart by the control id.
        for (id, claim) in &sidecar.annex_i_part_i_controls {
            if claim.satisfied && claim.evidence_url.is_none() {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::DocumentMetadata,
                    message: format!(
                        "[CRA Annex I Part I {id}] Sidecar claims control satisfied but provides no `evidence_url` — un-evidenced claims should be reviewed before submission"
                    ),
                    element: None,
                    requirement: format!(
                        "CRA Annex I Part I {id}: controls-assertion evidence (prEN 40000-1-2)"
                    ),
                    rule_id: "SBOM-CRA-ANNEX-I-CONTROLS",
                    component_id: None,
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: Some(id.clone()),
                    deadline: None,
                });
            }
        }
    }

    /// EUCC (Common Criteria) certificate / Target-of-Evaluation reference.
    ///
    /// `ImportantClass2` → Info if missing (recommended); `Critical` → Error
    /// if missing (Annex IV mandates EUCC). Lower classes: skipped.
    pub(crate) fn check_class_eucc_reference(
        &self,
        sbom: &NormalizedSbom,
        violations: &mut Vec<Violation>,
    ) {
        let Some(severity) = self.class_severity(ClassCheck::EuccReference) else {
            return;
        };
        // The sidecar's dedicated EUCC evidence fields are authoritative;
        // the URL-substring scan over external refs is only a fallback.
        // Empty strings and expired validity dates do not count.
        let sidecar_has_eucc = self
            .sidecar
            .as_ref()
            .is_some_and(|s| s.has_live_eucc_evidence_at(self.now()));
        // Fresh, fully-resolved CDXA attestation of a CRA-classified
        // standard naming EUCC/Common Criteria satisfies at Structural/
        // SignaturePresent level; sidecar fields and URL-substring refs
        // remain valid SelfDeclared fallbacks.
        let ctx = ComplianceContext::new(self, sbom);
        let cdxa_eucc_attested = ctx
            .evidence_for(AttestationRuleFamily::Cra)
            .iter()
            .any(|s| standard_references_eucc(s.standard));
        // A reference counts on the described product only: a
        // dependency's own EUCC certificate does not cover the product.
        // The URL keywords are the ones SBOM-EUCC-CERTREF and the
        // conformity summary read (`is_eucc_reference`).
        let has_eucc_ref = sidecar_has_eucc
            || cdxa_eucc_attested
            || manufacturer_reference(sbom, is_eucc_reference);
        if !has_eucc_ref {
            let mut message = format!(
                "[CRA Annex IV / EUCC] Product class {} requires (or strongly recommends) a reference to a Common Criteria / EUCC certificate or Target of Evaluation",
                self.effective_product_class().label()
            );
            if let Some(note) = cdxa_note(
                ctx.attestation_declarations(),
                AttestationRuleFamily::Cra,
                &|s, _| standard_references_eucc(s),
                self.now(),
                "an EUCC / Common Criteria certification",
            ) {
                message.push_str(&note);
            }
            violations.push(Violation {
                severity,
                category: ViolationCategory::DocumentMetadata,
                message,
                element: None,
                requirement: "CRA Annex IV: EUCC reference (Common Criteria certificate)"
                    .to_string(),
                rule_id: "SBOM-CRA-ANNEX-IV",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                deadline: None,
            });
        }
    }

    /// Conformity-assessment-module certificate reference.
    ///
    /// Module B+C / H / EUCC routes rest on notified-body or
    /// certification-body evidence — the EU-type examination certificate,
    /// the quality-system approval or the EUCC certificate — so they require
    /// a certification external reference (CycloneDX `certification-report`,
    /// SPDX 3.0 `certificationReport`). An attestation reference (CycloneDX
    /// `attestation`, SPDX 3.0 `secureSoftwareAttestation`) may be a
    /// self-attestation and does not count here, though it still serves as
    /// the Annex V DoC reference. Module A (self-assessment) is skipped.
    /// Severity scales with class.
    pub(crate) fn check_class_module_attestation(
        &self,
        sbom: &NormalizedSbom,
        violations: &mut Vec<Violation>,
    ) {
        use crate::model::ConformityRoute as R;
        let Some(severity) = self.class_severity(ClassCheck::ModuleAttestation) else {
            return;
        };
        let route = self.effective_route();
        if matches!(route, R::ModuleA) {
            return; // Module A self-assessment doesn't require external attestation
        }
        // The product's certificate: a dependency's own certification
        // reference does not cover the product.
        let has_certificate = manufacturer_reference(sbom, |r| {
            matches!(r.ref_type, crate::model::ExternalRefType::Certification)
        });
        if !has_certificate {
            violations.push(Violation {
                severity,
                category: ViolationCategory::DocumentMetadata,
                message: format!(
                    "[CRA Annex VIII / {}] No certification external reference found — the {} conformity route needs the notified-body or certification-body certificate; an attestation reference does not count",
                    route.label(),
                    route.label()
                ),
                element: None,
                requirement: format!(
                    "CRA Annex VIII: {} certificate reference",
                    route.label()
                ),
                rule_id: "SBOM-CRA-ANNEX-VIII",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                deadline: None,
            });
        }
    }

    /// CRA Article 14 reporting-readiness check.
    ///
    /// Verifies the manufacturer has documented channels for the obligations
    /// that apply from 11 September 2026:
    /// - 14(1) 24-hour early warning to ENISA/CSIRTs on actively-exploited vulns
    /// - 14(2) 72-hour incident report
    /// - 14(7) routing through the ENISA single reporting platform
    ///
    /// Pre-deadline: missing channels surface as Info (preparation guidance).
    /// Post-deadline: missing channels become Warning. The CRA never demands
    /// the channel reside *inside* the SBOM — most manufacturers will set
    /// these via `CraSidecarMetadata`. The ENISA platform finding follows
    /// the same dates but never becomes an Error (see below).
    /// Internal entry point taking an explicit `now` so tests can pin it.
    pub(crate) fn check_article_14_readiness_at(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        violations: &mut Vec<Violation>,
    ) {
        // Article 14 reporting-obligation deadline.
        // CRA enters into force 2024-12-10; reporting obligations apply
        // 21 months later on 2026-09-11.
        let deadline: chrono::DateTime<chrono::Utc> =
            chrono::DateTime::parse_from_rfc3339("2026-09-11T00:00:00Z")
                .expect("hard-coded deadline literal is RFC-3339")
                .into();
        let art_14_active = now >= deadline;
        // Severity escalation by product class: when class is explicitly set
        // and ≥ ImportantClass2, post-deadline missing channels become Errors
        // rather than Warnings ([CRA-P3.2 calibration]).
        let post_deadline_severity = if art_14_active {
            if self.has_explicit_product_class() {
                self.class_severity(ClassCheck::Psirt)
                    .unwrap_or(ViolationSeverity::Warning)
            } else {
                ViolationSeverity::Warning
            }
        } else {
            ViolationSeverity::Info
        };

        let sidecar = self.sidecar.as_ref();

        // A channel counts only when it reaches someone (`known_contact`):
        // a placeholder such as TBD or an example.com address is no channel,
        // and the finding names it (`unreachable_sidecar_note`).

        let psirt = sidecar.and_then(|s| s.psirt_url.as_deref());
        if !known_contact(psirt) {
            let prefix = if art_14_active {
                "[CRA Art. 14] PSIRT URL missing — required to handle external vulnerability reports"
            } else {
                "[CRA Art. 14] PSIRT URL missing — Article 14 obligations begin 2026-09-11; document the PSIRT channel ahead of the deadline"
            };
            violations.push(Violation {
                severity: post_deadline_severity,
                category: ViolationCategory::SecurityInfo,
                message: format!("{prefix}{}", unreachable_sidecar_note(psirt)),
                element: None,
                requirement: "CRA Art. 14: PSIRT contact for external vulnerability reports"
                    .to_string(),
                rule_id: "SBOM-CRA-ART-14-PSIRT",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                deadline: None,
            });
        }

        let early_warning = sidecar.and_then(|s| s.early_warning_contact.as_deref());
        if !known_contact(early_warning) {
            let msg = if art_14_active {
                "[CRA Art. 14(2)(a)] 24-hour early-warning channel missing — required when an actively-exploited vulnerability is identified"
            } else {
                "[CRA Art. 14(2)(a)] 24-hour early-warning channel missing — document the ENISA/CSIRT contact before 2026-09-11"
            };
            violations.push(Violation {
                severity: post_deadline_severity,
                category: ViolationCategory::SecurityInfo,
                message: format!("{msg}{}", unreachable_sidecar_note(early_warning)),
                element: None,
                requirement: "CRA Art. 14(2)(a): 24-hour early-warning channel".to_string(),
                rule_id: "SBOM-CRA-ART-14-EARLY-WARNING",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                deadline: None,
            });
        }

        let incident_report = sidecar.and_then(|s| s.incident_report_contact.as_deref());
        if !known_contact(incident_report) {
            let msg = if art_14_active {
                "[CRA Art. 14(2)(b) / 14(4)(b)] 72-hour notification channel missing — required for actively exploited vulnerabilities and severe incidents"
            } else {
                "[CRA Art. 14(2)(b) / 14(4)(b)] 72-hour notification channel missing — document this contact before 2026-09-11"
            };
            violations.push(Violation {
                severity: post_deadline_severity,
                category: ViolationCategory::SecurityInfo,
                message: format!("{msg}{}", unreachable_sidecar_note(incident_report)),
                element: None,
                requirement: "CRA Art. 14(2)(b): 72-hour notification channel".to_string(),
                rule_id: "SBOM-CRA-ART-14-NOTIFICATION",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                deadline: None,
            });
        }

        // ENISA single reporting platform (Art. 14(7)). Art. 14(1) and (3)
        // require every notification "via the single reporting platform
        // established pursuant to Article 16", and Art. 14(7) through the
        // end-point of the CSIRT designated as coordinator; like the rest of
        // Art. 14 that applies from 11 September 2026 (Art. 71(2)), the day
        // ENISA launched the platform. So the finding follows the channel
        // dates — Info before, Warning from then on — but stays a Warning at
        // every product class: the CRA names no platform identifier, and
        // ENISA advises registering only when a notification is due.
        let enisa_present = sidecar.is_some_and(|s| s.enisa_reporting_platform_id.is_some());
        if !enisa_present {
            let (severity, message) = if art_14_active {
                (
                    ViolationSeverity::Warning,
                    "[CRA Art. 14(7)] No record of how the manufacturer reaches the ENISA single reporting platform — every Art. 14 notification goes through it; set `enisaReportingPlatformId` in the CRA sidecar",
                )
            } else {
                (
                    ViolationSeverity::Info,
                    "[CRA Art. 14(7)] No record of how the manufacturer reaches the ENISA single reporting platform — Art. 14 notifications go through it from 2026-09-11; set `enisaReportingPlatformId` in the CRA sidecar",
                )
            };
            violations.push(Violation {
                severity,
                category: ViolationCategory::SecurityInfo,
                message: message.to_string(),
                element: None,
                requirement: "CRA Art. 14(7): ENISA single reporting platform".to_string(),
                rule_id: "SBOM-CRA-ART-14-ENISA",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                deadline: None,
            });
        }
    }

    /// Hardware-SBOM (HBOM) compliance check.
    ///
    /// Implements CRA prEN 40000-1-3 `[PRE-8-RQ-02]`: hardware components must
    /// carry producer, component name, unique identifier, and firmware version
    /// where applicable. Operates on components classified as
    /// `Device`, `Firmware`, or `DeviceDriver`. The check is silent when the
    /// SBOM contains no hardware components, so software-only SBOMs are
    /// unaffected.
    pub(crate) fn check_hardware_components(
        &self,
        sbom: &NormalizedSbom,
        violations: &mut Vec<Violation>,
    ) {
        use crate::model::ComponentType;

        let is_hardware_kind = |t: &ComponentType| {
            matches!(
                t,
                ComponentType::Device | ComponentType::Firmware | ComponentType::DeviceDriver
            )
        };

        // All components: the filter selects hardware kinds by type.
        let hardware_components: Vec<_> = sbom
            .components
            .values()
            .filter(|c| is_hardware_kind(&c.component_type))
            .collect();

        if hardware_components.is_empty() {
            return;
        }

        for comp in hardware_components {
            // 1) Producer (supplier or author) must be set
            if !has_known_producer(comp) {
                violations.push(Violation {
                    severity: ViolationSeverity::Error,
                    category: ViolationCategory::SupplierInfo,
                    message: format!(
                        "[CRA prEN 40000-1-3 [PRE-8-RQ-02]] Hardware component '{}' missing producer (supplier or author)",
                        comp.name
                    ),
                    element: Some(comp.name.clone()),
                    requirement: "CRA prEN 40000-1-3 [PRE-8-RQ-02]: Hardware producer".to_string(),
                    rule_id: "SBOM-CRA-PRE-8-RQ-02-PRODUCER",
                    component_id: Some(comp.canonical_id.value().to_string()),
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            }

            // 2) A unique identifier: a PURL, CPE, SWHID or SWID, as the
            // other CRA identifier checks require. Read the identifiers, not
            // the canonical id's source: a component re-keyed after a
            // canonical-id collision has a format-specific canonical id and
            // still has its purl.
            if !comp.identifiers.has_cra_identifier() {
                violations.push(Violation {
                    severity: ViolationSeverity::Error,
                    category: ViolationCategory::ComponentIdentification,
                    message: format!(
                        "[CRA prEN 40000-1-3 [PRE-8-RQ-02]] Hardware component '{}' missing unique identifier (PURL/CPE/SWHID/SWID)",
                        comp.name
                    ),
                    element: Some(comp.name.clone()),
                    requirement: "CRA prEN 40000-1-3 [PRE-8-RQ-02]: Hardware identifier".to_string(),
                    rule_id: "SBOM-CRA-PRE-8-RQ-02-IDENTIFIER",
                    component_id: Some(comp.canonical_id.value().to_string()),
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            }

            // 3) Firmware components must carry a version (the firmware version itself).
            if matches!(comp.component_type, ComponentType::Firmware) && comp.version.is_none() {
                violations.push(Violation {
                    severity: ViolationSeverity::Error,
                    category: ViolationCategory::ComponentIdentification,
                    message: format!(
                        "[CRA prEN 40000-1-3 [PRE-8-RQ-02]] Firmware component '{}' missing firmware version",
                        comp.name
                    ),
                    element: Some(comp.name.clone()),
                    requirement: "CRA prEN 40000-1-3 [PRE-8-RQ-02]: Firmware version".to_string(),
                    rule_id: "SBOM-CRA-PRE-8-RQ-02-FIRMWARE-VERSION",
                    component_id: Some(comp.canonical_id.value().to_string()),
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            }

            // 4) Devices: should declare a version, OR depend on a Firmware component.
            if matches!(comp.component_type, ComponentType::Device) && comp.version.is_none() {
                let has_firmware_dep = sbom.edges.iter().any(|e| {
                    e.from == comp.canonical_id
                        && sbom.components.get(&e.to).is_some_and(|child| {
                            matches!(child.component_type, ComponentType::Firmware)
                        })
                });
                if !has_firmware_dep {
                    violations.push(Violation {
                        severity: ViolationSeverity::Warning,
                        category: ViolationCategory::ComponentIdentification,
                        message: format!(
                            "[CRA prEN 40000-1-3 [PRE-8-RQ-02]] Device component '{}' has no version and no associated firmware component",
                            comp.name
                        ),
                        element: Some(comp.name.clone()),
                        requirement: "CRA prEN 40000-1-3 [PRE-8-RQ-02]: Device firmware association".to_string(),
                        rule_id: "SBOM-CRA-PRE-8-RQ-02-DEVICE-FIRMWARE",
                        component_id: Some(comp.canonical_id.value().to_string()),
                        counts: None,
                        standard_refs: Vec::new(),
                        remediation: None,
                        finding_detail: None,
                        deadline: None,
                    });
                }
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════
    // CRA Article 24 — Open-source software steward profile
    // ════════════════════════════════════════════════════════════════════
    //
    // Stewards (e.g., Eclipse Foundation, Apache, Linux Foundation) supply
    // software under the CRA but with reduced obligations:
    //
    // | Obligation                        | Manufacturer (Phase1/2) | Steward (Art. 24) |
    // |-----------------------------------|-------------------------|-------------------|
    // | SBOM                              | Required                | Required          |
    // | Vulnerability handling process    | Required (Annex I II)   | Required          |
    // | Coordinated disclosure policy     | Required (Annex I II (5)) | Required        |
    // | Manufacturer email contact        | Required (Art. 13(16))  | NOT required      |
    // | EU Declaration of Conformity      | Required                | NOT required      |
    // | Conformity-assessment module      | Required                | NOT applied       |
    // | Article 14 reporting channels     | Required                | NOT applied       |
    // | Vendor-hash carry-through         | Required (Phase 2)      | Recommended only  |
    //
    // The check below runs the must-have subset and skips the rest.

    pub(crate) fn check_cra_oss_steward(
        &self,
        sbom: &NormalizedSbom,
        violations: &mut Vec<Violation>,
    ) {
        // -- Must-haves (Article 24 floor) ----------------------------------

        // SBOM completeness — basic structural requirements (re-uses the
        // standard component check; manufacturer-only sub-checks are gated
        // off because we don't run check_cra_gaps for stewards).
        self.check_components(sbom, violations);
        self.check_dependencies(sbom, violations);

        // Vulnerability-handling process (Annex I Part II): require either
        // a vulnerability-disclosure URL on the document or a SecurityContact
        // / Advisories / VulnerabilityAssertion external reference on the
        // described product, OR sidecar-supplied PSIRT URL. A contact
        // counts only when it reaches someone (`known_contact`); a VDR
        // reference is a document, not a contact.
        let has_vuln_handling =
            known_contact(sbom.document.vulnerability_disclosure_url.as_deref())
                || known_contact(sbom.document.security_contact.as_deref())
                || manufacturer_reference(sbom, |r| match r.ref_type {
                    crate::model::ExternalRefType::SecurityContact
                    | crate::model::ExternalRefType::Advisories => is_contact_reference(r),
                    crate::model::ExternalRefType::VulnerabilityAssertion => true,
                    _ => false,
                })
                || self.sidecar.as_ref().is_some_and(|s| {
                    known_contact(s.psirt_url.as_deref())
                        || known_contact(s.vulnerability_disclosure_url.as_deref())
                });
        if !has_vuln_handling {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::SecurityInfo,
                message: "[CRA Art. 24 / Annex I Part II] OSS steward must operate a vulnerability-handling process — set a document-level security contact or vulnerability-disclosure URL, declare a SecurityContact / Advisories external reference, or set psirt_url / vulnerability_disclosure_url in the sidecar".to_string(),
                element: None,
                requirement: "CRA Art. 24: Vulnerability-handling process (steward floor)"
                    .to_string(),
                rule_id: "SBOM-CRA-ART-24",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                deadline: None,
            });
        }

        // Coordinated vulnerability disclosure policy (Annex I Part II (5)):
        // require either an Advisories reference on the described product
        // or sidecar-supplied coordinated_disclosure_policy_url.
        let has_cvd_policy = manufacturer_reference(sbom, |r| {
            matches!(r.ref_type, crate::model::ExternalRefType::Advisories)
                && is_contact_reference(r)
        }) || self
            .sidecar
            .as_ref()
            .is_some_and(|s| known_contact(s.coordinated_disclosure_policy_url.as_deref()));
        if !has_cvd_policy {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::SecurityInfo,
                message: "[CRA Annex I Part II (5)] OSS steward should publish a coordinated vulnerability disclosure (CVD) policy — add an Advisories external reference or set coordinated_disclosure_policy_url in the sidecar".to_string(),
                element: None,
                requirement: "CRA Annex I Part II (5): Coordinated vulnerability disclosure policy"
                    .to_string(),
                rule_id: "SBOM-CRA-CVD-POLICY",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                deadline: None,
            });
        }

        // Format-specific (CycloneDX/SPDX integrity, e.g., bomFormat field)
        self.check_format_specific(sbom, violations);

        // -- Explicitly NOT enforced ----------------------------------------
        // - Manufacturer email contact (Art. 13(16))
        // - EU Declaration of Conformity reference (Annex V)
        // - Conformity-assessment module attestation
        // - Article 14 reporting channels (24h / 72h / ENISA)
        // - Hardware component requirements
        // - Vendor-hash carry-through threshold
        // - Document metadata (check_document_metadata): the SBOM creator,
        //   timestamp and serial number, like the Art. 13 product
        //   identification it bundles, are manufacturer documentation duties;
        //   pinned by steward_profile_runs_no_document_metadata_check in
        //   tests/rule_matrix_cra.rs
    }
}
