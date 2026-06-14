//! BSI/G7 "SBOM for AI — Minimum Elements" (Feb 2026) minimum-elements
//! READINESS checks.
//!
//! The BSI/G7 guidance enumerates the minimum elements an AI-BOM should carry,
//! grouped into seven clusters: document **Metadata**, **System-Level**
//! description, **Models**, **Datasets**, **Infrastructure**, and **Security**.
//! This module maps each minimum element onto the AI-BOM metadata sbom-tools
//! already parses ([`MlModelInfo`], [`DatasetInfo`], [`DocumentMetadata`]) and
//! reports, element-by-element, which are present.
//!
//! Scope and framing:
//! - This is a *minimum-elements readiness* assessment, not a legal-conformity
//!   guarantee. Passing every check does not certify an AI-BOM as BSI/G7
//!   conformant; it reports which minimum elements are declared.
//! - When the SBOM carries no ML-model or dataset metadata the profile is
//!   *not applicable* and returns a single informational finding rather than
//!   failing every non-AI SBOM (mirrors the EU-AI-Act non-AI guard exactly).
//! - Some clusters (data-flow, AI-specific security controls, exploitability
//!   references) have no home in the model yet; those elements emit an
//!   informational "not declared" finding so the readiness scorecard stays
//!   complete rather than silently omitting them.
//!
//! Severity is tuned to the BSI/G7 normative language: MUST elements are
//! Errors, SHOULD elements are Warnings, and discretionary / not-yet-modeled
//! elements are informational.

use super::*;
use crate::model::{ComponentType, CreatorType, HashAlgorithm};

impl ComplianceChecker {
    // ════════════════════════════════════════════════════════════════════
    // BSI/G7 SBOM-for-AI Minimum Elements readiness
    // ════════════════════════════════════════════════════════════════════

    pub(crate) fn check_bsi_sbom_for_ai(
        &self,
        sbom: &NormalizedSbom,
        violations: &mut Vec<Violation>,
    ) {
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
        // never a failure (a non-AI SBOM is simply out of scope here). Mirrors
        // the EU-AI-Act non-AI guard exactly.
        if ml_components.is_empty() && dataset_components.is_empty() {
            violations.push(Violation {
                severity: ViolationSeverity::Info,
                category: ViolationCategory::DocumentMetadata,
                message: "[BSI-AI] Not applicable: SBOM contains no machine-learning-model or \
                          dataset components, so BSI/G7 SBOM-for-AI minimum-elements readiness \
                          cannot be assessed (readiness profile, not a legal-conformity guarantee)"
                    .to_string(),
                element: None,
                requirement: "BSI/G7 SBOM-for-AI: applicability".to_string(),
                rule_id: "SBOM-BSIAI-NA",
                standard_refs: Vec::new(),
            });
            return;
        }

        self.check_bsiai_metadata_cluster(sbom, violations);
        self.check_bsiai_system_level_cluster(sbom, &ml_components, violations);
        self.check_bsiai_models_cluster(&ml_components, violations);
        self.check_bsiai_datasets_cluster(&dataset_components, violations);
        self.check_bsiai_infrastructure_cluster(sbom, &ml_components, violations);
        self.check_bsiai_security_cluster(violations);
    }

    /// Metadata cluster — the document-level minimum elements: author/creator,
    /// data-format name + version, timestamp, ≥1 tool creator, and a signature
    /// (informational when absent).
    fn check_bsiai_metadata_cluster(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        let doc = &sbom.document;

        // Author / creator present (MUST).
        if doc.creators.is_empty() {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::DocumentMetadata,
                message: "[BSI-AI] Metadata readiness: SBOM declares no author/creator".to_string(),
                element: None,
                requirement: "BSI/G7 SBOM-for-AI — Metadata / Author".to_string(),
                rule_id: "SBOM-BSIAI-META-AUTHOR",
                standard_refs: Vec::new(),
            });
        }

        // Data-format name + version present (MUST). NormalizedSbom always knows
        // its format; the practical gap is a missing format_version string.
        if doc.format_version.is_empty() && doc.spec_version.is_empty() {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::DocumentMetadata,
                message: format!(
                    "[BSI-AI] Metadata readiness: SBOM data-format version is not declared \
                     (format: {})",
                    doc.format
                ),
                element: None,
                requirement: "BSI/G7 SBOM-for-AI — Metadata / Data format name + version"
                    .to_string(),
                rule_id: "SBOM-BSIAI-META-FORMAT",
                standard_refs: Vec::new(),
            });
        }

        // Timestamp present (MUST). DocumentMetadata::created is DateTime<Utc>,
        // always ISO-8601; the risk is the source SBOM not carrying one (which
        // surfaces as a unix-epoch / pre-epoch fallback).
        if doc.created.timestamp() <= 0 {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::DocumentMetadata,
                message: "[BSI-AI] Metadata readiness: SBOM creation timestamp missing or invalid"
                    .to_string(),
                element: None,
                requirement: "BSI/G7 SBOM-for-AI — Metadata / Timestamp".to_string(),
                rule_id: "SBOM-BSIAI-META-TIMESTAMP",
                standard_refs: Vec::new(),
            });
        }

        // At least one tool creator (SHOULD).
        let has_tool_creator = doc
            .creators
            .iter()
            .any(|c| c.creator_type == CreatorType::Tool);
        if !has_tool_creator {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::DocumentMetadata,
                message: "[BSI-AI] Metadata readiness: SBOM does not identify the generation tool"
                    .to_string(),
                element: None,
                requirement: "BSI/G7 SBOM-for-AI — Metadata / Generation tool".to_string(),
                rule_id: "SBOM-BSIAI-META-TOOL",
                standard_refs: Vec::new(),
            });
        }

        // Signature present (informational when absent — discretionary element).
        if doc.signature.is_none() {
            violations.push(Violation {
                severity: ViolationSeverity::Info,
                category: ViolationCategory::IntegrityInfo,
                message: "[BSI-AI] Metadata readiness: SBOM carries no document signature \
                          (integrity attestation recommended)"
                    .to_string(),
                element: None,
                requirement: "BSI/G7 SBOM-for-AI — Metadata / Signature".to_string(),
                rule_id: "SBOM-BSIAI-META-SIGNATURE",
                standard_refs: Vec::new(),
            });
        }
    }

    /// System-Level cluster — a primary AI-system component must be
    /// identifiable, and a producer/supplier should be declared. Data-flow /
    /// usage / I/O elements have no model home yet → informational.
    fn check_bsiai_system_level_cluster(
        &self,
        sbom: &NormalizedSbom,
        ml_components: &[&crate::model::Component],
        violations: &mut Vec<Violation>,
    ) {
        // A primary AI-system component is identifiable when either the SBOM's
        // primary component is an ML model / application, or — failing an
        // explicit primary — at least one ML component exists to anchor the
        // system description.
        let primary_is_ai_system = sbom.primary_component().is_some_and(|c| {
            matches!(
                c.component_type,
                ComponentType::MachineLearningModel | ComponentType::Application
            )
        });
        let has_ai_anchor = primary_is_ai_system || !ml_components.is_empty();
        if !has_ai_anchor {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::ComponentIdentification,
                message: "[BSI-AI] System-Level readiness: no primary AI-system component is \
                          identifiable (expected a MachineLearningModel or primary Application)"
                    .to_string(),
                element: None,
                requirement: "BSI/G7 SBOM-for-AI — System-Level / Primary AI system".to_string(),
                rule_id: "SBOM-BSIAI-SYS-PRIMARY",
                standard_refs: Vec::new(),
            });
        }

        // Producer / supplier of the AI system (SHOULD). Satisfied when the
        // primary component (or, lacking one, any ML component) declares a
        // supplier/author, or the document carries an organization creator.
        let producer_known = sbom
            .primary_component()
            .is_some_and(|c| c.supplier.is_some() || c.author.is_some())
            || ml_components
                .iter()
                .any(|c| c.supplier.is_some() || c.author.is_some())
            || sbom
                .document
                .creators
                .iter()
                .any(|c| c.creator_type == CreatorType::Organization);
        if !producer_known {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::SupplierInfo,
                message: "[BSI-AI] System-Level readiness: no producer/supplier of the AI system \
                          is declared"
                    .to_string(),
                element: None,
                requirement: "BSI/G7 SBOM-for-AI — System-Level / Producer".to_string(),
                rule_id: "SBOM-BSIAI-SYS-PRODUCER",
                standard_refs: Vec::new(),
            });
        }

        // Data-flow / usage / input-output description: not modeled yet →
        // informational "not declared" so the scorecard is complete.
        violations.push(Violation {
            severity: ViolationSeverity::Info,
            category: ViolationCategory::DocumentMetadata,
            message: "[BSI-AI] System-Level readiness: AI-system data-flow / usage / input-output \
                      description is not declared (no SBOM field carries it today)"
                .to_string(),
            element: None,
            requirement: "BSI/G7 SBOM-for-AI — System-Level / Data flow & usage".to_string(),
            rule_id: "SBOM-BSIAI-SYS-DATAFLOW",
            standard_refs: Vec::new(),
        });
    }

    /// Models cluster — the strongest cluster: per ML component, check name,
    /// version, identifier, weight hash, NIST-approved hash algorithm, model
    /// card, architecture, training datasets, limitations, and license.
    fn check_bsiai_models_cluster(
        &self,
        ml_components: &[&crate::model::Component],
        violations: &mut Vec<Violation>,
    ) {
        let mut without_name = Vec::new();
        let mut without_version = Vec::new();
        let mut without_identifier = Vec::new();
        let mut without_hash = Vec::new();
        let mut weak_hash = Vec::new();
        let mut without_model_card = Vec::new();
        let mut without_architecture = Vec::new();
        let mut without_datasets = Vec::new();
        let mut without_limitations = Vec::new();
        let mut without_license = Vec::new();

        for c in ml_components {
            let ml = c.ml_model.as_ref();
            if c.name.trim().is_empty() {
                without_name.push(c.canonical_id.to_string());
            }
            if c.version.as_ref().is_none_or(|v| v.trim().is_empty()) {
                without_version.push(c.name.clone());
            }
            if !c.identifiers.has_cra_identifier() {
                without_identifier.push(c.name.clone());
            }

            // Weight hash present (AI-010 logic: any hash on the component).
            if c.hashes.is_empty() {
                without_hash.push(c.name.clone());
            } else if !c.hashes.iter().any(|h| nist_approved_hash(&h.algorithm)) {
                // Hash present but none use a NIST-approved algorithm
                // (reuses the bsi.rs SHA-256+ gate).
                weak_hash.push(c.name.clone());
            }

            // Model card URL (AI-001).
            if ml.and_then(|m| m.model_card_url.as_ref()).is_none() {
                without_model_card.push(c.name.clone());
            }
            // Architecture declared (AI-002).
            let has_architecture = ml
                .is_some_and(|m| m.architecture_family.is_some() || m.architecture_name.is_some());
            if !has_architecture {
                without_architecture.push(c.name.clone());
            }
            // Training datasets referenced (AI-003).
            if ml.is_none_or(|m| m.training_datasets.is_empty()) {
                without_datasets.push(c.name.clone());
            }
            // Limitations stated (AI-008).
            if ml.and_then(|m| m.limitations.as_ref()).is_none() {
                without_limitations.push(c.name.clone());
            }
            // License present.
            if c.licenses.declared.is_empty() && c.licenses.concluded.is_none() {
                without_license.push(c.name.clone());
            }
        }

        // MUST elements (Error).
        push_model_finding(
            violations,
            ViolationSeverity::Error,
            ViolationCategory::ComponentIdentification,
            &without_name,
            "declare no name",
            "BSI/G7 SBOM-for-AI — Models / Model name",
            "SBOM-BSIAI-MODEL-NAME",
        );
        push_model_finding(
            violations,
            ViolationSeverity::Error,
            ViolationCategory::ComponentIdentification,
            &without_version,
            "declare no version",
            "BSI/G7 SBOM-for-AI — Models / Model version",
            "SBOM-BSIAI-MODEL-VERSION",
        );
        push_model_finding(
            violations,
            ViolationSeverity::Error,
            ViolationCategory::ComponentIdentification,
            &without_identifier,
            "carry no unique identifier (PURL/CPE/SWHID/SWID)",
            "BSI/G7 SBOM-for-AI — Models / Model identifier",
            "SBOM-BSIAI-MODEL-IDENTIFIER",
        );
        push_model_finding(
            violations,
            ViolationSeverity::Error,
            ViolationCategory::IntegrityInfo,
            &without_hash,
            "carry no model-weight hash value",
            "BSI/G7 SBOM-for-AI — Models / Model hash value",
            "SBOM-BSIAI-MODEL-HASH",
        );
        push_model_finding(
            violations,
            ViolationSeverity::Error,
            ViolationCategory::IntegrityInfo,
            &weak_hash,
            "use no NIST-approved hash algorithm (SHA-256+) for their weights",
            "BSI/G7 SBOM-for-AI — Models / Hash algorithm",
            "SBOM-BSIAI-MODEL-HASH-ALGO",
        );

        // SHOULD elements (Warning).
        push_model_finding(
            violations,
            ViolationSeverity::Warning,
            ViolationCategory::DocumentMetadata,
            &without_model_card,
            "reference no model card",
            "BSI/G7 SBOM-for-AI — Models / Model card",
            "SBOM-BSIAI-MODEL-CARD",
        );
        push_model_finding(
            violations,
            ViolationSeverity::Warning,
            ViolationCategory::DocumentMetadata,
            &without_architecture,
            "declare no architecture",
            "BSI/G7 SBOM-for-AI — Models / Architecture",
            "SBOM-BSIAI-MODEL-ARCHITECTURE",
        );
        push_model_finding(
            violations,
            ViolationSeverity::Warning,
            ViolationCategory::DependencyInfo,
            &without_datasets,
            "reference no training datasets",
            "BSI/G7 SBOM-for-AI — Models / Training datasets",
            "SBOM-BSIAI-MODEL-DATASETS",
        );
        push_model_finding(
            violations,
            ViolationSeverity::Warning,
            ViolationCategory::DocumentMetadata,
            &without_limitations,
            "state no limitations",
            "BSI/G7 SBOM-for-AI — Models / Limitations",
            "SBOM-BSIAI-MODEL-LIMITATIONS",
        );
        push_model_finding(
            violations,
            ViolationSeverity::Warning,
            ViolationCategory::LicenseInfo,
            &without_license,
            "declare no license",
            "BSI/G7 SBOM-for-AI — Models / Model license",
            "SBOM-BSIAI-MODEL-LICENSE",
        );
    }

    /// Datasets cluster — per Data component: name, identifier, hash, license,
    /// sensitivity classification, and provenance / intended-use (now available
    /// from the SPDX dataset-field wiring).
    fn check_bsiai_datasets_cluster(
        &self,
        dataset_components: &[&crate::model::Component],
        violations: &mut Vec<Violation>,
    ) {
        let mut without_name = Vec::new();
        let mut without_identifier = Vec::new();
        let mut without_hash = Vec::new();
        let mut without_license = Vec::new();
        let mut without_sensitivity = Vec::new();
        let mut without_provenance = Vec::new();

        for c in dataset_components {
            if c.name.trim().is_empty() {
                without_name.push(c.canonical_id.to_string());
            }
            if !c.identifiers.has_cra_identifier() {
                without_identifier.push(c.name.clone());
            }
            if c.hashes.is_empty() {
                without_hash.push(c.name.clone());
            }
            if c.licenses.declared.is_empty() && c.licenses.concluded.is_none() {
                without_license.push(c.name.clone());
            }
            let ds = c.dataset.as_ref();
            // Sensitivity classification present (a classification of "none"
            // still counts as a declaration).
            let has_sensitivity = ds.is_some_and(|d| {
                !d.sensitivity_classifications.is_empty() || d.confidentiality_level.is_some()
            });
            if !has_sensitivity {
                without_sensitivity.push(c.name.clone());
            }
            // Provenance / intended-use (now available from Part 1: intended
            // use, preprocessing, anonymization, or governance owners).
            let has_provenance = ds.is_some_and(|d| {
                d.intended_use.is_some()
                    || !d.preprocessing.is_empty()
                    || !d.anonymization.is_empty()
                    || !d.governance_owners.is_empty()
            });
            if !has_provenance {
                without_provenance.push(c.name.clone());
            }
        }

        // MUST elements (Error).
        push_model_finding(
            violations,
            ViolationSeverity::Error,
            ViolationCategory::ComponentIdentification,
            &without_name,
            "declare no name",
            "BSI/G7 SBOM-for-AI — Datasets / Dataset name",
            "SBOM-BSIAI-DATASET-NAME",
        );
        push_model_finding(
            violations,
            ViolationSeverity::Error,
            ViolationCategory::ComponentIdentification,
            &without_identifier,
            "carry no unique identifier (PURL/CPE/SWHID/SWID)",
            "BSI/G7 SBOM-for-AI — Datasets / Dataset identifier",
            "SBOM-BSIAI-DATASET-IDENTIFIER",
        );

        // SHOULD elements (Warning).
        push_model_finding(
            violations,
            ViolationSeverity::Warning,
            ViolationCategory::IntegrityInfo,
            &without_hash,
            "carry no hash value",
            "BSI/G7 SBOM-for-AI — Datasets / Dataset hash value",
            "SBOM-BSIAI-DATASET-HASH",
        );
        push_model_finding(
            violations,
            ViolationSeverity::Warning,
            ViolationCategory::LicenseInfo,
            &without_license,
            "declare no license",
            "BSI/G7 SBOM-for-AI — Datasets / Dataset license",
            "SBOM-BSIAI-DATASET-LICENSE",
        );
        push_model_finding(
            violations,
            ViolationSeverity::Warning,
            ViolationCategory::DocumentMetadata,
            &without_sensitivity,
            "declare no sensitivity classification",
            "BSI/G7 SBOM-for-AI — Datasets / Sensitivity classification",
            "SBOM-BSIAI-DATASET-SENSITIVITY",
        );
        push_model_finding(
            violations,
            ViolationSeverity::Warning,
            ViolationCategory::DocumentMetadata,
            &without_provenance,
            "declare no provenance / intended-use",
            "BSI/G7 SBOM-for-AI — Datasets / Provenance & intended use",
            "SBOM-BSIAI-DATASET-PROVENANCE",
        );
    }

    /// Infrastructure cluster — an ML component should link to its runtime /
    /// framework dependencies (a BOM / HBOM link, or any dependency edge).
    /// Informational when no such link exists.
    fn check_bsiai_infrastructure_cluster(
        &self,
        sbom: &NormalizedSbom,
        ml_components: &[&crate::model::Component],
        violations: &mut Vec<Violation>,
    ) {
        use crate::model::ExternalRefType;

        // Does any ML component participate in a dependency edge, or carry an
        // ExternalRefType::Bom link to a runtime/framework BOM?
        let has_infra_link = ml_components.iter().any(|c| {
            let in_edges = sbom
                .edges
                .iter()
                .any(|e| e.from == c.canonical_id || e.to == c.canonical_id);
            let has_bom_ref = c
                .external_refs
                .iter()
                .any(|r| r.ref_type == ExternalRefType::Bom);
            in_edges || has_bom_ref
        });

        if !has_infra_link {
            violations.push(Violation {
                severity: ViolationSeverity::Info,
                category: ViolationCategory::DependencyInfo,
                message: "[BSI-AI] Infrastructure readiness: no ML component links to its runtime \
                          / framework dependencies (no dependency edge or BOM/HBOM reference)"
                    .to_string(),
                element: None,
                requirement: "BSI/G7 SBOM-for-AI — Infrastructure / Runtime & framework"
                    .to_string(),
                rule_id: "SBOM-BSIAI-INFRA-RUNTIME",
                standard_refs: Vec::new(),
            });
        }
    }

    /// Security cluster — AI-specific security controls and exploitability
    /// references have no model home yet, so both elements emit an
    /// informational "not declared" finding to keep the scorecard complete.
    fn check_bsiai_security_cluster(&self, violations: &mut Vec<Violation>) {
        violations.push(Violation {
            severity: ViolationSeverity::Info,
            category: ViolationCategory::SecurityInfo,
            message: "[BSI-AI] Security readiness: no AI-specific security controls are declared \
                      (no SBOM field carries them today)"
                .to_string(),
            element: None,
            requirement: "BSI/G7 SBOM-for-AI — Security / AI security controls".to_string(),
            rule_id: "SBOM-BSIAI-SEC-CONTROLS",
            standard_refs: Vec::new(),
        });
        violations.push(Violation {
            severity: ViolationSeverity::Info,
            category: ViolationCategory::SecurityInfo,
            message: "[BSI-AI] Security readiness: no exploitability reference is declared \
                      (no SBOM field carries it today)"
                .to_string(),
            element: None,
            requirement: "BSI/G7 SBOM-for-AI — Security / Exploitability reference".to_string(),
            rule_id: "SBOM-BSIAI-SEC-EXPLOITABILITY",
            standard_refs: Vec::new(),
        });
    }
}

/// NIST-approved cryptographic hash gate (SHA-256 or stronger). Reuses the
/// same allowlist as the BSI TR-03183-2 §5.4 check in [`super::bsi`].
fn nist_approved_hash(a: &HashAlgorithm) -> bool {
    matches!(
        a,
        HashAlgorithm::Sha256
            | HashAlgorithm::Sha384
            | HashAlgorithm::Sha512
            | HashAlgorithm::Sha3_256
            | HashAlgorithm::Sha3_384
            | HashAlgorithm::Sha3_512
            | HashAlgorithm::Blake2b256
            | HashAlgorithm::Blake2b384
            | HashAlgorithm::Blake2b512
            | HashAlgorithm::Blake3
    )
}

/// Push a per-component readiness finding when `failing` is non-empty. `verb`
/// completes the sentence "N component(s) <verb>: <list>".
fn push_model_finding(
    violations: &mut Vec<Violation>,
    severity: ViolationSeverity,
    category: ViolationCategory,
    failing: &[String],
    verb: &str,
    requirement: &str,
    rule_id: &'static str,
) {
    if failing.is_empty() {
        return;
    }
    violations.push(Violation {
        severity,
        category,
        message: format!(
            "[BSI-AI] {} readiness: {} component(s) {}: {}",
            requirement.rsplit('/').next().unwrap_or(requirement).trim(),
            failing.len(),
            verb,
            truncate_list(failing, 5)
        ),
        element: failing.first().cloned(),
        requirement: requirement.to_string(),
        rule_id,
        standard_refs: Vec::new(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Component, DatasetInfo, DatasetRef, Hash, HashAlgorithm, MlModelInfo, Organization,
    };

    fn full_ml_component(name: &str) -> Component {
        let mut c = Component::new(name.to_string(), name.to_string())
            .with_version("1.0.0".to_string())
            .with_purl(format!("pkg:huggingface/{name}@1.0.0"));
        c.component_type = ComponentType::MachineLearningModel;
        c.description = Some("A documented model".to_string());
        c.licenses.declared = vec![crate::model::LicenseExpression::new(
            "Apache-2.0".to_string(),
        )];
        c.hashes.push(Hash::new(
            HashAlgorithm::Sha256,
            "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        ));
        c.ml_model = Some(MlModelInfo {
            architecture_family: Some("transformer".to_string()),
            model_card_url: Some("https://example.test/card".to_string()),
            use_cases: vec!["sentiment-analysis".to_string()],
            training_datasets: vec![DatasetRef {
                reference: Some("data-1".to_string()),
                name: Some("reviews".to_string()),
                purl: None,
            }],
            limitations: Some("English only".to_string()),
            ..MlModelInfo::default()
        });
        c
    }

    fn bare_ml_component(name: &str) -> Component {
        let mut c = Component::new(name.to_string(), name.to_string());
        c.component_type = ComponentType::MachineLearningModel;
        c.ml_model = Some(MlModelInfo::default());
        c
    }

    fn full_dataset_component(name: &str) -> Component {
        let mut c = Component::new(name.to_string(), name.to_string())
            .with_purl(format!("pkg:generic/{name}"));
        c.component_type = ComponentType::Data;
        c.supplier = Some(Organization::new("DataCorp".to_string()));
        c.licenses.declared = vec![crate::model::LicenseExpression::new(
            "CC-BY-4.0".to_string(),
        )];
        c.hashes.push(Hash::new(
            HashAlgorithm::Sha256,
            "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
        ));
        c.dataset = Some(DatasetInfo {
            dataset_type: Some("training".to_string()),
            sensitivity_classifications: vec!["none".to_string()],
            intended_use: Some("model fine-tuning".to_string()),
            governance_owners: vec!["Data Team".to_string()],
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

        let result = ComplianceChecker::new(ComplianceLevel::BsiSbomForAi).check(&sbom);
        assert!(result.is_compliant, "non-AI SBOM must not fail BSI-AI");
        assert_eq!(result.error_count, 0);
        assert_eq!(
            result.violations.len(),
            1,
            "exactly one informational N/A finding"
        );
        let v = &result.violations[0];
        assert_eq!(v.rule_id, "SBOM-BSIAI-NA");
        assert_eq!(v.severity, ViolationSeverity::Info);
    }

    #[test]
    fn fully_documented_aibom_passes_model_and_dataset_checks() {
        use crate::model::{Creator, CreatorType, DependencyEdge, DependencyType};
        let mut sbom = NormalizedSbom::default();
        sbom.document.format_version = "1.6".to_string();
        sbom.document.creators.push(Creator {
            creator_type: CreatorType::Tool,
            name: "sbom-tools".to_string(),
            email: None,
        });
        let model = full_ml_component("model-a");
        let dataset = full_dataset_component("data-1");
        let model_id = model.canonical_id.clone();
        let dataset_id = dataset.canonical_id.clone();
        add(&mut sbom, model);
        add(&mut sbom, dataset);
        // Give the model an infrastructure (runtime) dependency edge.
        sbom.edges.push(DependencyEdge::new(
            model_id,
            dataset_id,
            DependencyType::DependsOn,
        ));

        let result = ComplianceChecker::new(ComplianceLevel::BsiSbomForAi).check(&sbom);
        // No Error-severity (MUST) findings on a well-documented AI-BOM.
        assert!(
            result.is_compliant,
            "well-documented AI-BOM should pass all MUST checks; violations: {:?}",
            result
                .violations
                .iter()
                .filter(|v| v.severity == ViolationSeverity::Error)
                .collect::<Vec<_>>()
        );
        // The Models / Datasets MUST element checks must not appear.
        let ids: Vec<_> = result.violations.iter().map(|v| v.rule_id).collect();
        for must in [
            "SBOM-BSIAI-MODEL-NAME",
            "SBOM-BSIAI-MODEL-VERSION",
            "SBOM-BSIAI-MODEL-IDENTIFIER",
            "SBOM-BSIAI-MODEL-HASH",
            "SBOM-BSIAI-MODEL-HASH-ALGO",
            "SBOM-BSIAI-DATASET-NAME",
            "SBOM-BSIAI-DATASET-IDENTIFIER",
        ] {
            assert!(!ids.contains(&must), "unexpected MUST finding {must}");
        }
    }

    #[test]
    fn sparse_aibom_flags_specific_element_checks() {
        let mut sbom = NormalizedSbom::default();
        add(&mut sbom, bare_ml_component("model-a"));

        let result = ComplianceChecker::new(ComplianceLevel::BsiSbomForAi).check(&sbom);
        let ids: Vec<_> = result.violations.iter().map(|v| v.rule_id).collect();
        // Bare model has no version, identifier, hash, model card, architecture,
        // datasets, limitations, or license.
        assert!(ids.contains(&"SBOM-BSIAI-MODEL-VERSION"));
        assert!(ids.contains(&"SBOM-BSIAI-MODEL-IDENTIFIER"));
        assert!(ids.contains(&"SBOM-BSIAI-MODEL-HASH"));
        assert!(ids.contains(&"SBOM-BSIAI-MODEL-CARD"));
        assert!(ids.contains(&"SBOM-BSIAI-MODEL-ARCHITECTURE"));
        assert!(ids.contains(&"SBOM-BSIAI-MODEL-DATASETS"));
        assert!(ids.contains(&"SBOM-BSIAI-MODEL-LIMITATIONS"));
        assert!(ids.contains(&"SBOM-BSIAI-MODEL-LICENSE"));
        // Document metadata gaps too (no creators/timestamp default is valid).
        assert!(ids.contains(&"SBOM-BSIAI-META-AUTHOR"));
        // MUST gaps make it non-compliant.
        assert!(!result.is_compliant);
    }

    #[test]
    fn weak_hash_algorithm_flags_hash_algo_element() {
        let mut sbom = NormalizedSbom::default();
        let mut c = full_ml_component("model-a");
        // Replace the SHA-256 weight hash with a weak MD5 one.
        c.hashes.clear();
        c.hashes
            .push(Hash::new(HashAlgorithm::Md5, "abc".to_string()));
        add(&mut sbom, c);

        let result = ComplianceChecker::new(ComplianceLevel::BsiSbomForAi).check(&sbom);
        let ids: Vec<_> = result.violations.iter().map(|v| v.rule_id).collect();
        assert!(
            ids.contains(&"SBOM-BSIAI-MODEL-HASH-ALGO"),
            "MD5 weight hash should flag the hash-algorithm element"
        );
        // A hash IS present, so the missing-hash element must not fire.
        assert!(!ids.contains(&"SBOM-BSIAI-MODEL-HASH"));
    }

    #[test]
    fn dataset_provenance_available_from_spdx_fields() {
        let mut sbom = NormalizedSbom::default();
        let mut c = Component::new("data-x".to_string(), "data-x".to_string())
            .with_purl("pkg:generic/data-x".to_string());
        c.component_type = ComponentType::Data;
        c.dataset = Some(DatasetInfo {
            // Provenance via preprocessing only (no governance owners).
            preprocessing: vec!["dedup".to_string()],
            sensitivity_classifications: vec!["none".to_string()],
            ..DatasetInfo::default()
        });
        add(&mut sbom, c);

        let result = ComplianceChecker::new(ComplianceLevel::BsiSbomForAi).check(&sbom);
        assert!(
            !result
                .violations
                .iter()
                .any(|v| v.rule_id == "SBOM-BSIAI-DATASET-PROVENANCE"),
            "preprocessing should satisfy the dataset provenance element"
        );
    }

    #[test]
    fn all_emitted_rule_ids_are_registered_and_prefixed() {
        let mut sbom = NormalizedSbom::default();
        add(&mut sbom, bare_ml_component("model-a"));
        add(&mut sbom, {
            let mut c = Component::new("data-1".to_string(), "data-1".to_string());
            c.component_type = ComponentType::Data;
            c.dataset = Some(DatasetInfo::default());
            c
        });
        let result = ComplianceChecker::new(ComplianceLevel::BsiSbomForAi).check(&sbom);
        for v in &result.violations {
            assert!(
                super::super::rule_meta(v.rule_id).is_some(),
                "rule_id {:?} must be registered",
                v.rule_id
            );
            assert!(
                v.rule_id.starts_with("SBOM-BSIAI-"),
                "all BSI-AI rule ids start with SBOM-BSIAI-, got {:?}",
                v.rule_id
            );
        }
    }
}
