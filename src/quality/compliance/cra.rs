//! EU Cyber Resilience Act checks: Annex/Article gap analysis, hardware
//! (HBOM) components, Article 14 reporting readiness, product-class module
//! attestation / EUCC references, the Annex VIII conformity summary, and the
//! Article 24 open-source-steward profile.

use super::*;

impl ComplianceChecker {
    /// Build the per-route evidence checklist (CRA-P4.3). Each route lists
    /// the external references manufacturers are expected to attach to
    /// satisfy Annex VIII; the `satisfied` flag is computed by scanning the
    /// SBOM's `external_refs` and the attached sidecar.
    pub(crate) fn build_conformity_summary(
        &self,
        sbom: &NormalizedSbom,
    ) -> ConformityAssessmentSummary {
        use crate::model::{ConformityRoute, ExternalRefType};
        let class = self.effective_product_class();
        let route = self.effective_route();

        let any_ext = |needles: &[ExternalRefType]| -> bool {
            sbom.components.values().any(|c| {
                c.external_refs.iter().any(|r| {
                    needles
                        .iter()
                        .any(|n| std::mem::discriminant(&r.ref_type) == std::mem::discriminant(n))
                })
            })
        };
        let any_ext_url_contains = |types: &[ExternalRefType], substr: &str| -> bool {
            sbom.components.values().any(|c| {
                c.external_refs.iter().any(|r| {
                    types
                        .iter()
                        .any(|t| std::mem::discriminant(&r.ref_type) == std::mem::discriminant(t))
                        && r.url.to_lowercase().contains(substr)
                })
            })
        };

        let doc_or_ce = any_ext(&[ExternalRefType::Attestation, ExternalRefType::Certification])
            || self
                .sidecar
                .as_ref()
                .is_some_and(|s| s.ce_marking_reference.is_some());

        let attestation_present =
            any_ext(&[ExternalRefType::Attestation, ExternalRefType::Certification]);

        let eucc_present = any_ext_url_contains(
            &[ExternalRefType::Certification, ExternalRefType::Attestation],
            "eucc",
        ) || any_ext_url_contains(
            &[ExternalRefType::Certification, ExternalRefType::Attestation],
            "common-criteria",
        );

        let mut evidence: Vec<ConformityEvidence> = Vec::new();
        evidence.push(ConformityEvidence {
            label: "EU Declaration of Conformity".to_string(),
            detail: "Annex V — manufacturer's signed declaration. Provide via Attestation/Certification external ref or sidecar ceMarkingReference.".to_string(),
            satisfied: doc_or_ce,
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
                evidence.push(ConformityEvidence {
                    label: "EU-type examination certificate (Module B)".to_string(),
                    detail: "Notified-body certificate of EU-type examination — Attestation/Certification external ref.".to_string(),
                    satisfied: attestation_present,
                });
                evidence.push(ConformityEvidence {
                    label: "Production conformity statement (Module C)".to_string(),
                    detail: "Manufacturer's declaration that production conforms to the type examined under Module B.".to_string(),
                    satisfied: doc_or_ce,
                });
            }
            ConformityRoute::ModuleH => {
                evidence.push(ConformityEvidence {
                    label: "Quality-management-system certification (Module H)".to_string(),
                    detail: "Notified-body QMS certification (typically ISO 9001 / ISO/IEC 27001 family) — Certification external ref.".to_string(),
                    satisfied: attestation_present,
                });
                evidence.push(ConformityEvidence {
                    label: "QMS surveillance plan".to_string(),
                    detail: "Notified-body surveillance / re-assessment record — referenced via Attestation external ref.".to_string(),
                    satisfied: attestation_present,
                });
            }
            ConformityRoute::Eucc => {
                evidence.push(ConformityEvidence {
                    label: "EUCC / Common Criteria certificate".to_string(),
                    detail: "Common Criteria certificate from an EUCC-accredited ITSEF — Certification external ref whose URL references EUCC or common-criteria.".to_string(),
                    satisfied: eucc_present,
                });
                evidence.push(ConformityEvidence {
                    label: "Target of Evaluation reference".to_string(),
                    detail: "Reference to the ToE (and Protection Profile, when applicable) that the EUCC certificate covers.".to_string(),
                    satisfied: eucc_present,
                });
            }
        }

        // Article 14 channels are required at all conformity routes once the
        // 2026-09-11 deadline applies; surface as evidence rows for
        // notified-body checklists.
        let psirt = self.sidecar.as_ref().is_some_and(|s| s.psirt_url.is_some());
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

    /// CRA gap checks: Art. 13(3), 13(5), 13(9), Annex I Part III, Annex III
    pub(crate) fn check_cra_gaps(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        // B1: Art. 13(3) — Update frequency / SBOM freshness
        let age_days = (chrono::Utc::now() - sbom.document.created).num_days();
        if age_days > 90 {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::DocumentMetadata,
                message: format!(
                    "[CRA Art. 13(3)] SBOM is {age_days} days old; CRA requires timely updates when components change"
                ),
                element: None,
                requirement: "CRA Art. 13(3): SBOM update frequency".to_string(),
                rule_id: "SBOM-CRA-ART-13-3",
                standard_refs: Vec::new(),
            });
        } else if age_days > 30 {
            violations.push(Violation {
                severity: ViolationSeverity::Info,
                category: ViolationCategory::DocumentMetadata,
                message: format!(
                    "[CRA Art. 13(3)] SBOM is {age_days} days old; consider regenerating after component changes"
                ),
                element: None,
                requirement: "CRA Art. 13(3): SBOM update frequency".to_string(),
                rule_id: "SBOM-CRA-ART-13-3",
                standard_refs: Vec::new(),
            });
        }

        // B2: Art. 13(5) — Licensed component tracking (all components should have license info)
        let total = sbom.components.len();
        let without_license = sbom
            .components
            .values()
            .filter(|c| c.licenses.declared.is_empty() && c.licenses.concluded.is_none())
            .count();
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
                    "[CRA Art. 13(5)] {without_license}/{total} components ({pct}%) missing license information"
                ),
                element: None,
                requirement: "CRA Art. 13(5): Licensed component tracking".to_string(),
                rule_id: "SBOM-CRA-ART-13-5",
                standard_refs: Vec::new(),
            });
        }

        // B3: Art. 13(9) — Known vulnerabilities statement
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
                    "[CRA Art. 13(9)] No vulnerability data or vulnerability assertion found; \
                    include vulnerability information or a statement of no known vulnerabilities"
                        .to_string(),
                element: None,
                requirement: "CRA Art. 13(9): Known vulnerabilities statement".to_string(),
                rule_id: "SBOM-CRA-ART-13-9",
                standard_refs: Vec::new(),
            });
        }

        // B4: Annex I Part III — Supply-chain transparency.
        //
        // prEN 40000-1-3 [PRE-7-RQ-03] makes direct dependencies *mandatory*
        // and transitive dependencies *recommended*. We split the cohort
        // accordingly:
        // - direct (1 hop from the primary component) missing supplier:
        //   Error under CraPhase2, Warning otherwise.
        // - transitive missing supplier: Warning under CraPhase2 if >30%,
        //   Info otherwise.
        if !sbom.edges.is_empty() {
            let direct_ids = sbom.direct_dependency_ids();
            let mut direct_missing: Vec<String> = Vec::new();
            let mut transitive_missing: Vec<String> = Vec::new();
            for comp in sbom.components.values() {
                if comp.supplier.is_some() || comp.author.is_some() {
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
                        "[CRA Annex I, Part III / [PRE-7-RQ-03]] {n} direct dependencies missing supplier (mandatory): {}",
                        truncate_list(&direct_missing, 5)
                    ),
                    element: None,
                    requirement: "CRA Annex I, Part III / prEN 40000-1-3 [PRE-7-RQ-03]: Direct dependency supplier (mandatory)"
                        .to_string(),
                    rule_id: "SBOM-CRA-ANNEX-I-SUPPLY-CHAIN",
                    standard_refs: Vec::new(),
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
                        "[CRA Annex I, Part III / [PRE-7-RQ-03]] {transitive_n}/{denom} transitive dependencies ({pct}%) missing supplier (recommended): {}",
                        truncate_list(&transitive_missing, 5)
                    ),
                    element: None,
                    requirement: "CRA Annex I, Part III / prEN 40000-1-3 [PRE-7-RQ-03]: Transitive dependency supplier (recommended)"
                        .to_string(),
                    rule_id: "SBOM-CRA-ANNEX-I-SUPPLY-CHAIN",
                    standard_refs: Vec::new(),
                });
            }
        }

        // B4b: prEN 40000-1-3 [PRE-7-RQ-07-RE] — vendor hash carry-through
        // Vendor-supplied components (those with supplier/author and a non-synthetic
        // identifier) must carry the upstream-supplied cryptographic hash through
        // into the SBOM. Synthetic / format-specific IDs are excluded because they
        // typically aren't tied to an upstream artefact at all.
        {
            let metrics = crate::quality::HashQualityMetrics::from_sbom(sbom);
            if let Some(coverage) = metrics.vendor_hash_coverage() {
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                let pct = (coverage * 100.0).round() as usize;

                // Class-driven calibration overrides phase-based defaults
                // when the operator pinned a CRA product class. Otherwise,
                // fall through to the original Phase1/Phase2 thresholds for
                // backwards compatibility.
                let (severity, threshold_msg) = if self.has_explicit_product_class() {
                    let threshold = self.vendor_hash_threshold();
                    if coverage < threshold {
                        let sev = self
                            .class_severity(ClassCheck::VendorHashCoverage)
                            .unwrap_or(ViolationSeverity::Warning);
                        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                        let thr_pct = (threshold * 100.0).round() as usize;
                        (
                            sev,
                            format!(
                                "below {thr_pct}% threshold for product class {}",
                                self.effective_product_class().label()
                            ),
                        )
                    } else {
                        (ViolationSeverity::Info, String::new())
                    }
                } else {
                    match self.level {
                        ComplianceLevel::CraPhase2 if coverage < 0.50 => {
                            (ViolationSeverity::Error, "below 50% threshold".to_string())
                        }
                        ComplianceLevel::CraPhase2 if coverage < 0.80 => (
                            ViolationSeverity::Warning,
                            "below 80% threshold".to_string(),
                        ),
                        ComplianceLevel::CraPhase1 if coverage < 0.50 => (
                            ViolationSeverity::Warning,
                            "below 50% threshold".to_string(),
                        ),
                        _ => (ViolationSeverity::Info, String::new()),
                    }
                };
                if !threshold_msg.is_empty() {
                    violations.push(Violation {
                        severity,
                        category: ViolationCategory::IntegrityInfo,
                        message: format!(
                            "[CRA Annex I, Part II / [PRE-7-RQ-07-RE]] Only {}/{} vendor-supplied components ({pct}%) carry an upstream hash — {threshold_msg}",
                            metrics.vendor_components_with_hash, metrics.vendor_components_total
                        ),
                        element: None,
                        requirement: "CRA Annex I Part II / prEN 40000-1-3 [PRE-7-RQ-07-RE]: Vendor hash carry-through".to_string(),
                        rule_id: "SBOM-CRA-PRE-7-RQ-07-RE",
                        standard_refs: Vec::new(),
                    });
                }
            }
        }

        // B5: Annex III — Document signature/integrity
        // Check for document-level hash, signature, or attestation
        let has_doc_integrity = sbom.document.serial_number.is_some()
            || sbom.components.values().any(|comp| {
                comp.external_refs.iter().any(|r| {
                    matches!(
                        r.ref_type,
                        crate::model::ExternalRefType::Attestation
                            | crate::model::ExternalRefType::Certification
                    ) && !r.hashes.is_empty()
                })
            });
        if !has_doc_integrity {
            violations.push(Violation {
                severity: ViolationSeverity::Info,
                category: ViolationCategory::IntegrityInfo,
                message: "[CRA Annex III] Consider adding document-level integrity metadata \
                    (serial number, digital signature, or attestation with hash)"
                    .to_string(),
                element: None,
                requirement: "CRA Annex III: Document signature/integrity".to_string(),
                rule_id: "SBOM-CRA-ANNEX-III",
                standard_refs: Vec::new(),
            });
        }

        // B5b: Art. 13(2) — Documented risk-assessment reference
        // The CRA requires manufacturers to perform and document a risk
        // assessment. The SBOM (or sidecar) must reference it; absence is a
        // soft Warning under CraPhase2 (Annex V technical-doc requirement).
        if matches!(self.level, ComplianceLevel::CraPhase2) {
            let has_ref_in_sbom = sbom.components.values().any(|comp| {
                comp.external_refs
                    .iter()
                    .any(|r| matches!(r.ref_type, crate::model::ExternalRefType::RiskAssessment))
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
                    standard_refs: Vec::new(),
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
            self.check_article_14_readiness_at(chrono::Utc::now(), violations);
        }

        // B6: Art. 13(8) / Art. 13(11) — Component lifecycle / EOL detection
        // If EOL enrichment data is present, warn about EOL components
        let eol_count = sbom
            .components
            .values()
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
                rule_id: "SBOM-CRA-ART-13-8",
                standard_refs: Vec::new(),
            });
        }

        let approaching_eol_count = sbom
            .components
            .values()
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
                    "[CRA Art. 13(11)] {approaching_eol_count} component(s) are approaching end-of-life within 6 months"
                ),
                element: None,
                requirement: "CRA Art. 13(11): Component lifecycle monitoring".to_string(),
                rule_id: "SBOM-CRA-ART-13-11",
                standard_refs: Vec::new(),
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
            let has_security_profile = sbom
                .document
                .distribution_classification
                .as_ref()
                .is_some_and(|p| p.to_lowercase().contains("security"));

            if has_vulns && !has_security_profile {
                violations.push(Violation {
                    severity: ViolationSeverity::Info,
                    category: ViolationCategory::DocumentMetadata,
                    message:
                        "[CRA Art. 13(6)] SPDX 3.0 document contains vulnerabilities but does not declare Security profile conformance; declare profileConformance: [\"security\"] for CRA Art. 13(6) compliance"
                            .to_string(),
                    element: None,
                    requirement: "CRA Art. 13(6): SPDX 3.0 Security profile conformance"
                        .to_string(),
                    rule_id: "SBOM-CRA-ART-13-6-CONTACT",
                    standard_refs: Vec::new(),
                });
            }

            // Check if SimpleLicensing profile is declared when licenses are tracked
            let has_licenses = sbom
                .components
                .values()
                .any(|c| !c.licenses.declared.is_empty() || c.licenses.concluded.is_some());
            let has_licensing_profile = sbom
                .document
                .distribution_classification
                .as_ref()
                .is_some_and(|p| {
                    p.to_lowercase().contains("simplelicensing")
                        || p.to_lowercase().contains("licensing")
                });

            if has_licenses && !has_licensing_profile {
                violations.push(Violation {
                    severity: ViolationSeverity::Info,
                    category: ViolationCategory::LicenseInfo,
                    message:
                        "[CRA Art. 13(5)] SPDX 3.0 document tracks licenses but does not declare SimpleLicensing profile conformance; declare profileConformance: [\"simpleLicensing\"] for completeness"
                            .to_string(),
                    element: None,
                    requirement: "CRA Art. 13(5): SPDX 3.0 SimpleLicensing profile conformance"
                        .to_string(),
                    rule_id: "SBOM-CRA-ART-13-5",
                    standard_refs: Vec::new(),
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
                    standard_refs: Vec::new(),
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
        let has_eucc_ref = sbom.components.values().any(|comp| {
            comp.external_refs.iter().any(|r| {
                let url_lower = r.url.to_lowercase();
                matches!(
                    r.ref_type,
                    crate::model::ExternalRefType::Certification
                        | crate::model::ExternalRefType::Attestation
                ) && (url_lower.contains("eucc")
                    || url_lower.contains("common-criteria")
                    || url_lower.contains("commoncriteria"))
            })
        });
        if !has_eucc_ref {
            violations.push(Violation {
                severity,
                category: ViolationCategory::DocumentMetadata,
                message: format!(
                    "[CRA Annex IV / EUCC] Product class {} requires (or strongly recommends) a reference to a Common Criteria / EUCC certificate or Target of Evaluation",
                    self.effective_product_class().label()
                ),
                element: None,
                requirement: "CRA Annex IV: EUCC reference (Common Criteria certificate)"
                    .to_string(),
                rule_id: "SBOM-CRA-ANNEX-IV",
                standard_refs: Vec::new(),
            });
        }
    }

    /// Conformity-assessment-module attestation reference.
    ///
    /// Module B+C / H / EUCC routes require an attestation external reference
    /// (notified-body certificate, QA-system certification, EUCC certificate).
    /// Module A (self-assessment) is skipped. Severity scales with class.
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
        let has_attestation = sbom.components.values().any(|comp| {
            comp.external_refs.iter().any(|r| {
                matches!(
                    r.ref_type,
                    crate::model::ExternalRefType::Attestation
                        | crate::model::ExternalRefType::Certification
                )
            })
        });
        if !has_attestation {
            violations.push(Violation {
                severity,
                category: ViolationCategory::DocumentMetadata,
                message: format!(
                    "[CRA Annex VIII / {}] No attestation or certification external reference found — required for the {} conformity route",
                    route.label(),
                    route.label()
                ),
                element: None,
                requirement: format!(
                    "CRA Annex VIII: {} attestation reference",
                    route.label()
                ),
                rule_id: "SBOM-CRA-ANNEX-VIII",
                standard_refs: Vec::new(),
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
    /// these via `CraSidecarMetadata`.
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

        let psirt_present = sidecar.is_some_and(|s| s.psirt_url.is_some());
        if !psirt_present {
            let prefix = if art_14_active {
                "[CRA Art. 14] PSIRT URL missing — required to handle external vulnerability reports"
            } else {
                "[CRA Art. 14] PSIRT URL missing — Article 14 obligations begin 2026-09-11; document the PSIRT channel ahead of the deadline"
            };
            violations.push(Violation {
                severity: post_deadline_severity,
                category: ViolationCategory::SecurityInfo,
                message: prefix.to_string(),
                element: None,
                requirement: "CRA Art. 14: PSIRT contact for external vulnerability reports"
                    .to_string(),
                rule_id: "SBOM-CRA-ART-14",
                standard_refs: Vec::new(),
            });
        }

        let ew_present = sidecar.is_some_and(|s| s.early_warning_contact.is_some());
        if !ew_present {
            let msg = if art_14_active {
                "[CRA Art. 14(1)] 24-hour early-warning channel missing — required when an actively-exploited vulnerability is identified"
            } else {
                "[CRA Art. 14(1)] 24-hour early-warning channel missing — document the ENISA/CSIRT contact before 2026-09-11"
            };
            violations.push(Violation {
                severity: post_deadline_severity,
                category: ViolationCategory::SecurityInfo,
                message: msg.to_string(),
                element: None,
                requirement: "CRA Art. 14(1): 24-hour early-warning channel".to_string(),
                rule_id: "SBOM-CRA-ART-14",
                standard_refs: Vec::new(),
            });
        }

        let ir_present = sidecar.is_some_and(|s| s.incident_report_contact.is_some());
        if !ir_present {
            let msg = if art_14_active {
                "[CRA Art. 14(2)] 72-hour incident-report channel missing — required for severe incidents impacting product security"
            } else {
                "[CRA Art. 14(2)] 72-hour incident-report channel missing — document this contact before 2026-09-11"
            };
            violations.push(Violation {
                severity: post_deadline_severity,
                category: ViolationCategory::SecurityInfo,
                message: msg.to_string(),
                element: None,
                requirement: "CRA Art. 14(2): 72-hour incident-report channel".to_string(),
                rule_id: "SBOM-CRA-ART-14",
                standard_refs: Vec::new(),
            });
        }

        // ENISA single reporting platform (Art. 14(7)) — the official URL is
        // not yet published. We accept any sidecar identifier as a forward-
        // compatible placeholder and only surface as Info regardless of date.
        let enisa_present = sidecar.is_some_and(|s| s.enisa_reporting_platform_id.is_some());
        if !enisa_present {
            violations.push(Violation {
                severity: ViolationSeverity::Info,
                category: ViolationCategory::SecurityInfo,
                message: "[CRA Art. 14(7)] No ENISA single reporting platform identifier — track ENISA publication and add `enisaReportingPlatformId` to the CRA sidecar when available"
                    .to_string(),
                element: None,
                requirement: "CRA Art. 14(7): ENISA single reporting platform".to_string(),
                rule_id: "SBOM-CRA-ART-14",
                standard_refs: Vec::new(),
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
        use crate::model::{ComponentType, IdSource};

        let is_hardware_kind = |t: &ComponentType| {
            matches!(
                t,
                ComponentType::Device | ComponentType::Firmware | ComponentType::DeviceDriver
            )
        };

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
            if comp.supplier.is_none() && comp.author.is_none() {
                violations.push(Violation {
                    severity: ViolationSeverity::Error,
                    category: ViolationCategory::SupplierInfo,
                    message: format!(
                        "[CRA prEN 40000-1-3 [PRE-8-RQ-02]] Hardware component '{}' missing producer (supplier or author)",
                        comp.name
                    ),
                    element: Some(comp.name.clone()),
                    requirement: "CRA prEN 40000-1-3 [PRE-8-RQ-02]: Hardware producer".to_string(),
                    rule_id: "SBOM-CRA-PRE-8-RQ-02",
                    standard_refs: Vec::new(),
                });
            }

            // 2) Identifier must be a real (non-synthetic / non-format-specific) one
            if matches!(
                comp.canonical_id.source(),
                IdSource::Synthetic | IdSource::FormatSpecific
            ) {
                violations.push(Violation {
                    severity: ViolationSeverity::Error,
                    category: ViolationCategory::ComponentIdentification,
                    message: format!(
                        "[CRA prEN 40000-1-3 [PRE-8-RQ-02]] Hardware component '{}' missing unique identifier (PURL/CPE/SWHID/SWID)",
                        comp.name
                    ),
                    element: Some(comp.name.clone()),
                    requirement: "CRA prEN 40000-1-3 [PRE-8-RQ-02]: Hardware identifier".to_string(),
                    rule_id: "SBOM-CRA-PRE-8-RQ-02",
                    standard_refs: Vec::new(),
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
                    rule_id: "SBOM-CRA-PRE-8-RQ-02",
                    standard_refs: Vec::new(),
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
                        rule_id: "SBOM-CRA-PRE-8-RQ-02",
                        standard_refs: Vec::new(),
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
    // | Coordinated disclosure policy     | Required (Art. 13(7))   | Required          |
    // | Manufacturer email contact        | Required (Art. 13(15))  | NOT required      |
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
        // / Advisories external reference on at least one component, OR
        // sidecar-supplied PSIRT URL.
        let has_vuln_handling = sbom.components.values().any(|c| {
            c.external_refs.iter().any(|r| {
                matches!(
                    r.ref_type,
                    crate::model::ExternalRefType::SecurityContact
                        | crate::model::ExternalRefType::Advisories
                        | crate::model::ExternalRefType::VulnerabilityAssertion
                )
            })
        }) || self
            .sidecar
            .as_ref()
            .is_some_and(|s| s.psirt_url.is_some() || s.vulnerability_disclosure_url.is_some());
        if !has_vuln_handling {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::SecurityInfo,
                message: "[CRA Art. 24 / Annex I Part II] OSS steward must operate a vulnerability-handling process — declare a SecurityContact / Advisories external reference, or set psirt_url / vulnerability_disclosure_url in the sidecar".to_string(),
                element: None,
                requirement: "CRA Art. 24: Vulnerability-handling process (steward floor)"
                    .to_string(),
                rule_id: "SBOM-CRA-ART-24",
                standard_refs: Vec::new(),
            });
        }

        // Coordinated vulnerability disclosure policy (Art. 13(7)): require
        // either an Advisories reference or sidecar-supplied
        // coordinated_disclosure_policy_url.
        let has_cvd_policy = sbom.components.values().any(|c| {
            c.external_refs
                .iter()
                .any(|r| matches!(r.ref_type, crate::model::ExternalRefType::Advisories))
        }) || self
            .sidecar
            .as_ref()
            .is_some_and(|s| s.coordinated_disclosure_policy_url.is_some());
        if !has_cvd_policy {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::SecurityInfo,
                message: "[CRA Art. 13(7)] OSS steward should publish a coordinated vulnerability disclosure (CVD) policy — add an Advisories external reference or set coordinated_disclosure_policy_url in the sidecar".to_string(),
                element: None,
                requirement: "CRA Art. 13(7): Coordinated vulnerability disclosure policy"
                    .to_string(),
                rule_id: "SBOM-CRA-ART-13-7",
                standard_refs: Vec::new(),
            });
        }

        // Format-specific (CycloneDX/SPDX integrity, e.g., bomFormat field)
        self.check_format_specific(sbom, violations);

        // -- Explicitly NOT enforced ----------------------------------------
        // - Manufacturer email contact (Art. 13(15))
        // - EU Declaration of Conformity reference (Annex VII)
        // - Conformity-assessment module attestation
        // - Article 14 reporting channels (24h / 72h / ENISA)
        // - Hardware component requirements
        // - Vendor-hash carry-through threshold
    }
}
