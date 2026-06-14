//! EU AI Act (Regulation (EU) 2024/1689) Annex IV technical-documentation
//! READINESS checks.
//!
//! Annex IV of the AI Act enumerates the technical documentation a provider of
//! a high-risk AI system must draw up. Several of those items are, in practice,
//! an AI-BOM mandate: a general description of the model (§1), the
//! characteristics of the training data (§2(d)), and the validation/testing
//! metrics used (§2(g)). This module maps those Annex IV items onto the
//! AI-BOM metadata sbom-tools already parses ([`MlModelInfo`], [`DatasetInfo`])
//! and reports which are present.
//!
//! Scope and framing:
//! - This is a *documentation-readiness* assessment, not a legal-conformity
//!   guarantee. Passing every check does not make a system AI-Act compliant,
//!   and the tool does not itself classify a system as high-risk.
//! - When the SBOM carries no ML-model or dataset metadata the profile is
//!   *not applicable* and returns a single informational finding rather than
//!   failing every non-AI SBOM (mirrors the EUCC reference-only precedent in
//!   `compliance/eucc.rs`).
//! - When the CRA sidecar `is_high_risk_ai` flag is set, missing-documentation
//!   findings escalate from Info/Warning to Error: Annex IV is mandatory for
//!   high-risk systems, so gaps are blocking rather than advisory.

use super::*;
use crate::model::ComponentType;

impl ComplianceChecker {
    // ════════════════════════════════════════════════════════════════════
    // EU AI Act Annex IV technical-documentation readiness (AI3)
    // ════════════════════════════════════════════════════════════════════

    pub(crate) fn check_eu_ai_act(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        let high_risk = self.sidecar.as_ref().is_some_and(|s| s.is_high_risk_ai);

        // ML-model and dataset components drive the readiness checks.
        let ml_components: Vec<_> = sbom
            .components
            .values()
            .filter(|c| c.component_type == ComponentType::MachineLearningModel)
            .collect();
        let dataset_components: Vec<_> = sbom
            .components
            .values()
            .filter(|c| c.dataset.is_some() || c.component_type == ComponentType::Data)
            .collect();

        // N/A gate: no AI/ML content at all → single informational finding,
        // never a failure (a non-AI SBOM is simply out of scope here).
        if ml_components.is_empty() && dataset_components.is_empty() {
            violations.push(Violation {
                severity: ViolationSeverity::Info,
                category: ViolationCategory::DocumentMetadata,
                message: "[AI-Act] Not applicable: SBOM contains no machine-learning-model or \
                          dataset components, so EU AI Act Annex IV technical-documentation \
                          readiness cannot be assessed (readiness profile, not a legal-conformity \
                          guarantee)"
                    .to_string(),
                element: None,
                requirement: "EU AI Act Annex IV: applicability".to_string(),
                rule_id: "SBOM-AIACT-NA",
                standard_refs: Vec::new(),
            });
            return;
        }

        // The severity a missing-documentation finding takes. For declared
        // high-risk systems every Annex IV gap is blocking (Error); otherwise
        // gaps are surfaced as readiness Warnings.
        let missing_severity = if high_risk {
            ViolationSeverity::Error
        } else {
            ViolationSeverity::Warning
        };

        self.check_ai_act_general_description(&ml_components, missing_severity, violations);
        self.check_ai_act_training_data(
            &ml_components,
            &dataset_components,
            missing_severity,
            violations,
        );
        self.check_ai_act_validation_metrics(&ml_components, missing_severity, violations);
        self.check_ai_act_limitations(&ml_components, high_risk, violations);
        self.check_ai_act_personal_data(&dataset_components, high_risk, violations);
        self.check_ai_act_energy(&ml_components, violations);
    }

    /// Annex IV §1 — general description of the AI system: architecture and the
    /// intended purpose / use-cases, ideally with a model card to point at.
    fn check_ai_act_general_description(
        &self,
        ml_components: &[&crate::model::Component],
        missing_severity: ViolationSeverity,
        violations: &mut Vec<Violation>,
    ) {
        let mut without_description = Vec::new();
        let mut without_use_cases = Vec::new();
        for c in ml_components {
            let ml = c.ml_model.as_ref();
            let has_general = ml.is_some_and(|m| {
                m.architecture_family.is_some()
                    || m.architecture_name.is_some()
                    || m.model_card_url.is_some()
                    || c.description.is_some()
            });
            if !has_general {
                without_description.push(c.name.clone());
            }
            let has_use_cases = ml.is_some_and(|m| !m.use_cases.is_empty());
            if !has_use_cases {
                without_use_cases.push(c.name.clone());
            }
        }

        if !without_description.is_empty() {
            violations.push(Violation {
                severity: missing_severity,
                category: ViolationCategory::DocumentMetadata,
                message: format!(
                    "[AI-Act] Annex IV §1 readiness: {} model component(s) lack a general \
                     description (architecture / model-card): {}",
                    without_description.len(),
                    truncate_list(&without_description, 5)
                ),
                element: without_description.first().cloned(),
                requirement: "EU AI Act Annex IV §1: general description of the AI system"
                    .to_string(),
                rule_id: "SBOM-AIACT-ANNEX-IV-1-DESCRIPTION",
                standard_refs: Vec::new(),
            });
        }

        if !without_use_cases.is_empty() {
            violations.push(Violation {
                severity: missing_severity,
                category: ViolationCategory::DocumentMetadata,
                message: format!(
                    "[AI-Act] Annex IV §1 readiness: {} model component(s) declare no intended \
                     purpose / use-cases: {}",
                    without_use_cases.len(),
                    truncate_list(&without_use_cases, 5)
                ),
                element: without_use_cases.first().cloned(),
                requirement: "EU AI Act Annex IV §1: intended purpose / use-cases".to_string(),
                rule_id: "SBOM-AIACT-ANNEX-IV-1-PURPOSE",
                standard_refs: Vec::new(),
            });
        }
    }

    /// Annex IV §2(d) — training-data characteristics: which datasets a model
    /// was trained on, and whether datasets carry sensitivity classifications.
    fn check_ai_act_training_data(
        &self,
        ml_components: &[&crate::model::Component],
        dataset_components: &[&crate::model::Component],
        missing_severity: ViolationSeverity,
        violations: &mut Vec<Violation>,
    ) {
        // Every model should reference the dataset(s) it was trained on.
        let mut without_datasets = Vec::new();
        for c in ml_components {
            let has_datasets = c
                .ml_model
                .as_ref()
                .is_some_and(|m| !m.training_datasets.is_empty());
            if !has_datasets {
                without_datasets.push(c.name.clone());
            }
        }
        if !without_datasets.is_empty() {
            violations.push(Violation {
                severity: missing_severity,
                category: ViolationCategory::DependencyInfo,
                message: format!(
                    "[AI-Act] Annex IV §2(d) readiness: {} model component(s) reference no \
                     training datasets: {}",
                    without_datasets.len(),
                    truncate_list(&without_datasets, 5)
                ),
                element: without_datasets.first().cloned(),
                requirement: "EU AI Act Annex IV §2(d): training-data provenance".to_string(),
                rule_id: "SBOM-AIACT-ANNEX-IV-2D-DATASETS",
                standard_refs: Vec::new(),
            });
        }

        // Datasets should declare a sensitivity classification so a
        // personal-data / GDPR overlap can be reasoned about (§2(d) data
        // characteristics). A classification of "none" still counts as a
        // declaration.
        let mut undeclared_sensitivity = Vec::new();
        for c in dataset_components {
            let declared = c
                .dataset
                .as_ref()
                .is_some_and(|d| !d.sensitivity_classifications.is_empty());
            if !declared {
                undeclared_sensitivity.push(c.name.clone());
            }
        }
        if !undeclared_sensitivity.is_empty() {
            // Sensitivity classification is informative readiness; never harder
            // than the base missing-severity.
            violations.push(Violation {
                severity: missing_severity,
                category: ViolationCategory::DocumentMetadata,
                message: format!(
                    "[AI-Act] Annex IV §2(d) readiness: {} dataset component(s) declare no \
                     sensitivity classification (e.g. personal-data / PII disclosure): {}",
                    undeclared_sensitivity.len(),
                    truncate_list(&undeclared_sensitivity, 5)
                ),
                element: undeclared_sensitivity.first().cloned(),
                requirement: "EU AI Act Annex IV §2(d): training-data sensitivity classification"
                    .to_string(),
                rule_id: "SBOM-AIACT-ANNEX-IV-2D-SENSITIVITY",
                standard_refs: Vec::new(),
            });
        }
    }

    /// Annex IV §2(g) — validation and testing procedures and the metrics used
    /// to measure accuracy/robustness. Reads AI1's typed `performance_metrics`
    /// with a raw-pointer fallback for SBOMs parsed before typed extraction.
    fn check_ai_act_validation_metrics(
        &self,
        ml_components: &[&crate::model::Component],
        missing_severity: ViolationSeverity,
        violations: &mut Vec<Violation>,
    ) {
        let mut without_metrics = Vec::new();
        for c in ml_components {
            let typed = c
                .ml_model
                .as_ref()
                .is_some_and(|m| !m.performance_metrics.is_empty());
            // Raw-pointer fallback: quantitative analysis preserved in
            // Component.extensions.raw but not surfaced into the typed model.
            let raw_fallback = !typed
                && c.extensions.raw.as_ref().is_some_and(|raw| {
                    [
                        "/modelCard/quantitativeAnalysis",
                        "/mlModel/modelCard/quantitativeAnalysis",
                    ]
                    .iter()
                    .filter_map(|p| raw.pointer(p))
                    .any(|v| match v {
                        serde_json::Value::Null => false,
                        serde_json::Value::Array(a) => !a.is_empty(),
                        serde_json::Value::Object(o) => !o.is_empty(),
                        _ => true,
                    })
                });
            if !typed && !raw_fallback {
                without_metrics.push(c.name.clone());
            }
        }
        if !without_metrics.is_empty() {
            violations.push(Violation {
                severity: missing_severity,
                category: ViolationCategory::SecurityInfo,
                message: format!(
                    "[AI-Act] Annex IV §2(g) readiness: {} model component(s) provide no \
                     quantitative validation/testing metrics (accuracy / robustness): {}",
                    without_metrics.len(),
                    truncate_list(&without_metrics, 5)
                ),
                element: without_metrics.first().cloned(),
                requirement: "EU AI Act Annex IV §2(g): validation/testing metrics".to_string(),
                rule_id: "SBOM-AIACT-ANNEX-IV-2G-METRICS",
                standard_refs: Vec::new(),
            });
        }
    }

    /// Annex IV §3 — foreseeable limitations / risks. Surfaced from the typed
    /// `limitations` field and any ethical considerations declared.
    fn check_ai_act_limitations(
        &self,
        ml_components: &[&crate::model::Component],
        high_risk: bool,
        violations: &mut Vec<Violation>,
    ) {
        let mut without_limitations = Vec::new();
        for c in ml_components {
            let ml = c.ml_model.as_ref();
            let declared = ml.is_some_and(|m| {
                m.limitations.is_some()
                    || !m.ethical_considerations.is_empty()
                    || !m.fairness.is_empty()
            });
            if !declared {
                without_limitations.push(c.name.clone());
            }
        }
        if !without_limitations.is_empty() {
            // Limitations are advisory readiness for non-high-risk systems;
            // blocking for declared high-risk systems.
            let severity = if high_risk {
                ViolationSeverity::Error
            } else {
                ViolationSeverity::Info
            };
            violations.push(Violation {
                severity,
                category: ViolationCategory::DocumentMetadata,
                message: format!(
                    "[AI-Act] Annex IV §3 readiness: {} model component(s) state no foreseeable \
                     limitations / ethical or fairness considerations: {}",
                    without_limitations.len(),
                    truncate_list(&without_limitations, 5)
                ),
                element: without_limitations.first().cloned(),
                requirement: "EU AI Act Annex IV §3: foreseeable limitations and risks".to_string(),
                rule_id: "SBOM-AIACT-ANNEX-IV-3-LIMITATIONS",
                standard_refs: Vec::new(),
            });
        }
    }

    /// Personal-data disclosure (Annex IV §2(d) + GDPR overlap). When a dataset
    /// is classified as carrying personal data / PII, that fact is surfaced as
    /// an informational readiness note so the provider documents the GDPR
    /// interaction; escalated to a Warning for declared high-risk systems.
    fn check_ai_act_personal_data(
        &self,
        dataset_components: &[&crate::model::Component],
        high_risk: bool,
        violations: &mut Vec<Violation>,
    ) {
        let mut personal_data = Vec::new();
        for c in dataset_components {
            let carries_personal = c.dataset.as_ref().is_some_and(|d| {
                d.sensitivity_classifications.iter().any(|s| {
                    let s = s.to_lowercase();
                    s.contains("personal")
                        || s.contains("pii")
                        || s.contains("sensitive")
                        || s.contains("confidential")
                })
            });
            if carries_personal {
                personal_data.push(c.name.clone());
            }
        }
        // Sidecar-level personal-data flag also raises the disclosure note even
        // when no per-dataset classification is set.
        let sidecar_personal = self
            .sidecar
            .as_ref()
            .is_some_and(|s| s.processes_personal_data);

        if !personal_data.is_empty() || sidecar_personal {
            let severity = if high_risk {
                ViolationSeverity::Warning
            } else {
                ViolationSeverity::Info
            };
            let detail = if personal_data.is_empty() {
                "CRA sidecar declares the product processes personal data".to_string()
            } else {
                format!(
                    "dataset(s) classified as personal/sensitive: {}",
                    truncate_list(&personal_data, 5)
                )
            };
            violations.push(Violation {
                severity,
                category: ViolationCategory::DocumentMetadata,
                message: format!(
                    "[AI-Act] Annex IV §2(d) readiness: training data involves personal data — \
                     document the GDPR interaction and lawful basis ({detail})"
                ),
                element: personal_data.first().cloned(),
                requirement: "EU AI Act Annex IV §2(d): personal-data disclosure".to_string(),
                rule_id: "SBOM-AIACT-ANNEX-IV-2D-PERSONAL-DATA",
                standard_refs: Vec::new(),
            });
        }
    }

    /// Energy / environmental disclosure (Annex IV §2(g) computational
    /// resources). Informational: surfaced only when no training energy is
    /// modeled on any ML component.
    fn check_ai_act_energy(
        &self,
        ml_components: &[&crate::model::Component],
        violations: &mut Vec<Violation>,
    ) {
        let any_energy = ml_components.iter().any(|c| {
            c.ml_model
                .as_ref()
                .is_some_and(|m| m.energy_kwh_training.is_some())
        });
        if !any_energy {
            violations.push(Violation {
                severity: ViolationSeverity::Info,
                category: ViolationCategory::DocumentMetadata,
                message: "[AI-Act] Annex IV §2(g) readiness: no training energy consumption is \
                          modeled (computational-resources disclosure recommended)"
                    .to_string(),
                element: None,
                requirement: "EU AI Act Annex IV §2(g): computational resources / energy"
                    .to_string(),
                rule_id: "SBOM-AIACT-ANNEX-IV-2G-ENERGY",
                standard_refs: Vec::new(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Component, CraSidecarMetadata, DatasetInfo, DatasetRef, MetricEntry, MlModelInfo,
    };

    fn full_ml_component(name: &str) -> Component {
        let mut c =
            Component::new(name.to_string(), name.to_string()).with_version("1.0.0".to_string());
        c.component_type = ComponentType::MachineLearningModel;
        c.description = Some("A documented model".to_string());
        c.ml_model = Some(MlModelInfo {
            architecture_family: Some("transformer".to_string()),
            model_card_url: Some("https://example.test/card".to_string()),
            use_cases: vec!["sentiment-analysis".to_string()],
            training_datasets: vec![DatasetRef {
                reference: Some("data-1".to_string()),
                name: Some("reviews".to_string()),
                purl: None,
            }],
            performance_metrics: vec![MetricEntry {
                metric_type: Some("accuracy".to_string()),
                value: Some("0.97".to_string()),
                slice: None,
            }],
            limitations: Some("English only".to_string()),
            energy_kwh_training: Some(1500.0),
            ..MlModelInfo::default()
        });
        c
    }

    fn bare_ml_component(name: &str) -> Component {
        let mut c =
            Component::new(name.to_string(), name.to_string()).with_version("1.0.0".to_string());
        c.component_type = ComponentType::MachineLearningModel;
        c.ml_model = Some(MlModelInfo::default());
        c
    }

    fn dataset_component(name: &str, sensitivity: &[&str]) -> Component {
        let mut c = Component::new(name.to_string(), name.to_string());
        c.component_type = ComponentType::Data;
        c.dataset = Some(DatasetInfo {
            dataset_type: Some("training".to_string()),
            sensitivity_classifications: sensitivity.iter().map(|s| (*s).to_string()).collect(),
            governance_owners: Vec::new(),
            ..DatasetInfo::default()
        });
        c
    }

    fn add(sbom: &mut NormalizedSbom, c: Component) {
        sbom.components.insert(c.canonical_id.clone(), c);
    }

    #[test]
    fn non_ai_sbom_returns_not_applicable_and_does_not_fail() {
        let mut sbom = NormalizedSbom::default();
        let mut sw =
            Component::new("lib".to_string(), "lib".to_string()).with_version("1.0.0".to_string());
        sw.component_type = ComponentType::Library;
        add(&mut sbom, sw);

        let result = ComplianceChecker::new(ComplianceLevel::EuAiAct).check(&sbom);
        assert!(result.is_compliant, "non-AI SBOM must not fail AI-Act");
        assert_eq!(result.error_count, 0);
        assert_eq!(
            result.violations.len(),
            1,
            "exactly one informational N/A finding"
        );
        let v = &result.violations[0];
        assert_eq!(v.rule_id, "SBOM-AIACT-NA");
        assert_eq!(v.severity, ViolationSeverity::Info);
    }

    #[test]
    fn fully_documented_ai_sbom_has_no_readiness_warnings() {
        let mut sbom = NormalizedSbom::default();
        add(&mut sbom, full_ml_component("model-a"));
        add(&mut sbom, dataset_component("data-1", &["none"]));

        let result = ComplianceChecker::new(ComplianceLevel::EuAiAct).check(&sbom);
        assert!(result.is_compliant);
        assert_eq!(
            result.warning_count, 0,
            "fully documented AI SBOM should raise no Annex IV warnings, got {:?}",
            result.violations
        );
    }

    #[test]
    fn bare_ai_sbom_flags_specific_annex_iv_checks() {
        let mut sbom = NormalizedSbom::default();
        add(&mut sbom, bare_ml_component("model-a"));

        let result = ComplianceChecker::new(ComplianceLevel::EuAiAct).check(&sbom);
        let ids: Vec<_> = result.violations.iter().map(|v| v.rule_id).collect();
        assert!(ids.contains(&"SBOM-AIACT-ANNEX-IV-1-DESCRIPTION"));
        assert!(ids.contains(&"SBOM-AIACT-ANNEX-IV-1-PURPOSE"));
        assert!(ids.contains(&"SBOM-AIACT-ANNEX-IV-2D-DATASETS"));
        assert!(ids.contains(&"SBOM-AIACT-ANNEX-IV-2G-METRICS"));
        assert!(ids.contains(&"SBOM-AIACT-ANNEX-IV-3-LIMITATIONS"));
    }

    #[test]
    fn high_risk_flag_escalates_findings_to_error() {
        let mut sbom = NormalizedSbom::default();
        add(&mut sbom, bare_ml_component("model-a"));

        // Without the flag: §1/§2 gaps are Warnings (not blocking).
        let baseline = ComplianceChecker::new(ComplianceLevel::EuAiAct).check(&sbom);
        assert!(baseline.is_compliant, "non-high-risk gaps are advisory");
        assert!(baseline.warning_count > 0);

        // With is_high_risk_ai: the same gaps become Errors.
        let sidecar = CraSidecarMetadata {
            is_high_risk_ai: true,
            ..Default::default()
        };
        let escalated = ComplianceChecker::new(ComplianceLevel::EuAiAct)
            .with_sidecar(sidecar)
            .check(&sbom);
        assert!(
            !escalated.is_compliant,
            "high-risk AI SBOM with Annex IV gaps must fail"
        );
        assert!(escalated.error_count > 0);
        // Limitations check (Info → Error under high-risk) should now be an Error.
        assert!(
            escalated.violations.iter().any(|v| {
                v.rule_id == "SBOM-AIACT-ANNEX-IV-3-LIMITATIONS"
                    && v.severity == ViolationSeverity::Error
            }),
            "limitations gap should escalate to Error under high-risk"
        );
    }

    #[test]
    fn personal_data_sensitivity_raises_disclosure_note() {
        let mut sbom = NormalizedSbom::default();
        add(&mut sbom, full_ml_component("model-a"));
        add(&mut sbom, dataset_component("data-1", &["pii"]));

        let result = ComplianceChecker::new(ComplianceLevel::EuAiAct).check(&sbom);
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.rule_id == "SBOM-AIACT-ANNEX-IV-2D-PERSONAL-DATA"),
            "PII-classified dataset should raise the personal-data disclosure note"
        );
    }

    #[test]
    fn validation_metrics_raw_pointer_fallback() {
        // A model with no typed performance_metrics but quantitativeAnalysis
        // preserved in extensions.raw must satisfy the §2(g) metrics check.
        let mut sbom = NormalizedSbom::default();
        let mut c = bare_ml_component("model-a");
        c.extensions.raw = Some(serde_json::json!({
            "modelCard": {
                "quantitativeAnalysis": {
                    "performanceMetrics": [{ "type": "accuracy", "value": "0.9" }]
                }
            }
        }));
        add(&mut sbom, c);

        let result = ComplianceChecker::new(ComplianceLevel::EuAiAct).check(&sbom);
        assert!(
            !result
                .violations
                .iter()
                .any(|v| v.rule_id == "SBOM-AIACT-ANNEX-IV-2G-METRICS"),
            "raw-pointer quantitativeAnalysis should satisfy the metrics check"
        );
    }

    #[test]
    fn all_emitted_rule_ids_are_registered() {
        let mut sbom = NormalizedSbom::default();
        add(&mut sbom, bare_ml_component("model-a"));
        add(&mut sbom, dataset_component("data-1", &[]));
        let result = ComplianceChecker::new(ComplianceLevel::EuAiAct).check(&sbom);
        for v in &result.violations {
            assert!(
                super::rule_meta(v.rule_id).is_some(),
                "rule_id {:?} must be registered",
                v.rule_id
            );
            assert!(
                v.rule_id.starts_with("SBOM-AIACT-"),
                "all AI-Act rule ids start with SBOM-AIACT-, got {:?}",
                v.rule_id
            );
        }
    }
}
