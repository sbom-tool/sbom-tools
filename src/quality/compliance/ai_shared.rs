//! Shared applicability gate and component classification for the AI-BOM
//! compliance profiles (EU AI Act Annex IV, BSI/G7 SBOM-for-AI).
//!
//! Both profiles must scope identically: which components count as ML models,
//! which count as AI datasets, and whether the SBOM is in scope at all. The
//! logic was previously duplicated in `eu_ai_act.rs` and `bsi_sbom_for_ai.rs`
//! and leaked in both directions:
//!
//! - any `type: data` component (a config bundle, or SPDX 3.0
//!   primary-purpose "documentation", which maps to [`ComponentType::Data`])
//!   was enrolled as an AI training dataset, making plain non-AI SBOMs fail
//!   the BSI-AI MUST dataset elements with blocking Errors;
//! - a component carrying a full CycloneDX modelCard (the parser sets
//!   [`Component::ml_model`] regardless of the declared type) but typed
//!   `application`/`library` was invisible, so genuine AI SBOMs were declared
//!   "Not applicable" and passed vacuously.
//!
//! Centralizing the classification here keeps the two profiles consistent by
//! construction: an ML component requires the `machine-learning-model` type
//! or parsed ML-model metadata; an AI dataset requires real dataset evidence
//! (`Component::dataset`), never the bare component type. Components that
//! merely *look* like ML content (a `pkg:huggingface` PURL or a `model-card`
//! external reference) without either signal — and without dataset evidence,
//! since HuggingFace hosts datasets as well as models — are collected
//! separately so the profiles stay applicable and can surface a mistyped-ML
//! warning instead of letting "untype your models" evade the assessment.

use super::{Violation, ViolationCategory, ViolationSeverity, truncate_list};
use crate::model::{Component, ComponentType, DependencyType, ExternalRefType, NormalizedSbom};

/// The AI-BOM scope of an SBOM, as seen by the AI compliance profiles.
pub(crate) struct AiBomScope<'a> {
    /// ML-model components: typed `machine-learning-model`, or carrying
    /// parsed ML-model metadata (CycloneDX modelCard / SPDX 3.0 AI profile)
    /// regardless of the declared component type.
    pub ml_components: Vec<&'a Component>,
    /// AI-dataset components: require real dataset evidence
    /// ([`Component::dataset`]). A bare `type: data` component is NOT an AI
    /// dataset — CycloneDX `data` covers configurations and source-of-truth
    /// data generally, and SPDX 3.0 maps primary-purpose "documentation" to
    /// [`ComponentType::Data`].
    pub dataset_components: Vec<&'a Component>,
    /// Components that look like ML content (a `pkg:huggingface` PURL or a
    /// `model-card` external reference) but are neither typed
    /// `machine-learning-model` nor carry ML-model metadata. Components with
    /// dataset evidence are exempt: a HuggingFace-hosted dataset is already
    /// correctly classified via [`Self::dataset_components`], not a mistyped
    /// model. Their presence keeps the SBOM applicable; each profile surfaces
    /// them via its mistyped-ML warning rule (`SBOM-AIACT-UNTYPED-ML` /
    /// `SBOM-BSIAI-UNTYPED-ML`).
    pub untyped_ml_components: Vec<&'a Component>,
}

impl AiBomScope<'_> {
    /// Whether the AI profiles apply to this SBOM at all. Non-applicable
    /// SBOMs get the single informational N/A finding
    /// (`SBOM-AIACT-NA` / `SBOM-BSIAI-NA`) and never fail.
    pub(crate) fn is_applicable(&self) -> bool {
        !self.ml_components.is_empty()
            || !self.dataset_components.is_empty()
            || !self.untyped_ml_components.is_empty()
    }
}

/// Classify the SBOM's components for the AI-BOM compliance profiles.
///
/// Iteration follows the SBOM's component order (`IndexMap`), so violation
/// messages built from these lists are deterministic.
pub(crate) fn ai_bom_scope(sbom: &NormalizedSbom) -> AiBomScope<'_> {
    let mut scope = AiBomScope {
        ml_components: Vec::new(),
        dataset_components: Vec::new(),
        untyped_ml_components: Vec::new(),
    };
    for c in sbom.components.values() {
        let is_ml = c.component_type == ComponentType::MachineLearningModel || c.ml_model.is_some();
        if is_ml {
            scope.ml_components.push(c);
        }
        if c.dataset.is_some() {
            scope.dataset_components.push(c);
        }
        // Dataset-evidenced components are exempt from the untyped-ML
        // heuristic: pkg:huggingface hosts datasets too, and such components
        // are already enrolled as datasets above — flagging them as mistyped
        // models would prescribe the wrong remediation (retyping a correctly
        // typed dataset as machine-learning-model).
        if !is_ml && c.dataset.is_none() && looks_like_ml_content(c) {
            scope.untyped_ml_components.push(c);
        }
    }
    scope
}

/// Whether an ML model declares its training datasets.
///
/// Two spec-legal shapes count:
///
/// 1. `modelCard.modelParameters.datasets` (or the SPDX 3.0 `trainedOn`
///    relationship) — parsed into [`crate::model::MlModelInfo::training_datasets`].
/// 2. Dataset components nested under the model (CycloneDX `component.components`,
///    surfaced as a `contains` edge) that carry real dataset evidence
///    ([`Component::dataset`], i.e. a `data[]` block). Generators such as
///    Manifest `aibom-gen` emit datasets this way instead of via `modelParameters`.
///
/// A bare nested `type: data` component with no `data[]` block is **not**
/// accepted, consistent with [`ai_bom_scope`]: CycloneDX `data` also covers
/// configuration bundles, so the type alone is not dataset evidence.
pub(crate) fn declares_training_datasets(sbom: &NormalizedSbom, model: &Component) -> bool {
    if model
        .ml_model
        .as_ref()
        .is_some_and(|m| !m.training_datasets.is_empty())
    {
        return true;
    }
    sbom.get_dependencies(&model.canonical_id)
        .into_iter()
        .filter(|e| e.relationship == DependencyType::Contains)
        .any(|e| {
            sbom.components
                .get(&e.to)
                .is_some_and(|child| child.dataset.is_some())
        })
}

/// Whether a component references a model card via an external reference
/// (`externalReferences[{type:"model-card"}]`) — a spec-valid alternative to
/// an inline CycloneDX modelCard object. The parser only copies the URL into
/// [`crate::model::MlModelInfo::model_card_url`] when a modelCard object
/// exists, so checks that credit model cards must consult this too.
pub(crate) fn has_model_card_ref(c: &Component) -> bool {
    c.external_refs
        .iter()
        .any(|r| r.ref_type == ExternalRefType::ModelCard)
}

/// Heuristic ML-content detection for components that are not declared as
/// models: a HuggingFace package URL or a model-card external reference is a
/// strong signal that the component is an ML model. Callers must exempt
/// components carrying dataset evidence (`Component::dataset`) first —
/// HuggingFace hosts datasets as well as models, and those are legitimate
/// AI-BOM content, not evasion suspects.
fn looks_like_ml_content(c: &Component) -> bool {
    let hf_purl = c.identifiers.purl.as_deref().is_some_and(|p| {
        p.get(..16)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("pkg:huggingface/"))
    });
    hf_purl || has_model_card_ref(c)
}

/// Push the shared mistyped-ML warning when the scope contains ML-looking
/// components that are neither typed `machine-learning-model` nor carry
/// ML-model metadata. `profile_tag` is the message prefix (`AI-Act` /
/// `BSI-AI`); `rule_id` must be the per-profile registered rule
/// (`SBOM-AIACT-UNTYPED-ML` / `SBOM-BSIAI-UNTYPED-ML`).
pub(crate) fn push_untyped_ml_warning(
    scope: &AiBomScope<'_>,
    profile_tag: &str,
    requirement: &str,
    rule_id: &'static str,
    violations: &mut Vec<Violation>,
) {
    if scope.untyped_ml_components.is_empty() {
        return;
    }
    let names: Vec<String> = scope
        .untyped_ml_components
        .iter()
        .map(|c| c.name.clone())
        .collect();
    violations.push(Violation {
        severity: ViolationSeverity::Warning,
        category: ViolationCategory::ComponentIdentification,
        message: format!(
            "[{profile_tag}] ML content detected but not typed machine-learning-model: \
             {} component(s) carry ML signals (pkg:huggingface PURL or model-card \
             reference) without ML-model metadata: {}",
            names.len(),
            truncate_list(&names, 5)
        ),
        element: names.first().cloned(),
        requirement: requirement.to_string(),
        rule_id,
        component_id: None,
        counts: None,
        standard_refs: Vec::new(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DatasetInfo, ExternalReference, MlModelInfo};

    fn component(name: &str) -> Component {
        Component::new(name.to_string(), name.to_string()).with_version("1.0.0".to_string())
    }

    fn add(sbom: &mut NormalizedSbom, c: Component) {
        sbom.components.insert(c.canonical_id.clone(), c);
    }

    #[test]
    fn bare_data_component_is_not_an_ai_dataset() {
        // A `type: data` config bundle without dataset evidence must not make
        // the AI profiles applicable (the flagship over-match fix).
        let mut sbom = NormalizedSbom::default();
        let mut cfg = component("app-config");
        cfg.component_type = ComponentType::Data;
        add(&mut sbom, cfg);

        let scope = ai_bom_scope(&sbom);
        assert!(scope.dataset_components.is_empty());
        assert!(!scope.is_applicable());
    }

    #[test]
    fn nested_dataset_with_evidence_satisfies_training_datasets() {
        use crate::model::DependencyEdge;
        let mut sbom = NormalizedSbom::default();
        let mut model = component("llm");
        model.component_type = ComponentType::MachineLearningModel;
        let model_id = model.canonical_id.clone();
        let mut data = component("alpaca");
        data.component_type = ComponentType::Data;
        data.dataset = Some(DatasetInfo::default());
        let data_id = data.canonical_id.clone();
        add(&mut sbom, model);
        add(&mut sbom, data);
        sbom.add_edge(DependencyEdge::new(
            model_id.clone(),
            data_id,
            DependencyType::Contains,
        ));

        let model = &sbom.components[&model_id];
        assert!(
            declares_training_datasets(&sbom, model),
            "a contained dataset component with evidence must count as a training dataset"
        );
    }

    #[test]
    fn bare_nested_data_component_does_not_satisfy_training_datasets() {
        use crate::model::DependencyEdge;
        // The Manifest aibom-gen shape: `type: data` children with properties
        // only and no `data[]` block. Consistent with ai_bom_scope, the type
        // alone is not dataset evidence.
        let mut sbom = NormalizedSbom::default();
        let mut model = component("llm");
        model.component_type = ComponentType::MachineLearningModel;
        let model_id = model.canonical_id.clone();
        let mut data = component("alpaca");
        data.component_type = ComponentType::Data;
        let data_id = data.canonical_id.clone();
        add(&mut sbom, model);
        add(&mut sbom, data);
        sbom.add_edge(DependencyEdge::new(
            model_id.clone(),
            data_id,
            DependencyType::Contains,
        ));

        let model = &sbom.components[&model_id];
        assert!(!declares_training_datasets(&sbom, model));
    }

    #[test]
    fn model_parameters_datasets_satisfy_training_datasets() {
        let mut sbom = NormalizedSbom::default();
        let mut model = component("llm");
        model.component_type = ComponentType::MachineLearningModel;
        let mut ml = MlModelInfo::default();
        ml.training_datasets.push(crate::model::DatasetRef {
            reference: Some("ds-1".into()),
            name: None,
            purl: None,
        });
        model.ml_model = Some(ml);
        let model_id = model.canonical_id.clone();
        add(&mut sbom, model);
        assert!(declares_training_datasets(
            &sbom,
            &sbom.components[&model_id]
        ));
    }

    #[test]
    fn dataset_evidence_counts_regardless_of_type() {
        let mut sbom = NormalizedSbom::default();
        let mut data = component("training-data");
        data.component_type = ComponentType::Data;
        data.dataset = Some(DatasetInfo::default());
        add(&mut sbom, data);

        let scope = ai_bom_scope(&sbom);
        assert_eq!(scope.dataset_components.len(), 1);
        assert!(scope.is_applicable());
    }

    #[test]
    fn ml_metadata_counts_even_when_mistyped() {
        // application-typed component carrying a parsed modelCard must be an
        // ML component (the under-match / evasion fix).
        let mut sbom = NormalizedSbom::default();
        let mut app = component("sentiment-model");
        app.component_type = ComponentType::Application;
        app.ml_model = Some(MlModelInfo::default());
        add(&mut sbom, app);

        let scope = ai_bom_scope(&sbom);
        assert_eq!(scope.ml_components.len(), 1);
        assert!(scope.untyped_ml_components.is_empty());
        assert!(scope.is_applicable());
    }

    #[test]
    fn huggingface_purl_without_ml_metadata_is_an_untyped_suspect() {
        let mut sbom = NormalizedSbom::default();
        let hf = component("bert-base-uncased")
            .with_purl("pkg:huggingface/google-bert/bert-base-uncased@1.0.0".to_string());
        add(&mut sbom, hf);

        let scope = ai_bom_scope(&sbom);
        assert!(scope.ml_components.is_empty());
        assert_eq!(scope.untyped_ml_components.len(), 1);
        assert!(scope.is_applicable());
    }

    #[test]
    fn huggingface_dataset_with_evidence_is_not_an_untyped_suspect() {
        // A HuggingFace-hosted dataset — typed `data`, carrying real dataset
        // evidence — is correctly classified as a dataset and must NOT be
        // flagged as a mistyped ML model (the HF-dataset false-warning fix).
        let mut sbom = NormalizedSbom::default();
        let mut ds = component("imdb").with_purl("pkg:huggingface/datasets/imdb@1.0.0".to_string());
        ds.component_type = ComponentType::Data;
        ds.dataset = Some(DatasetInfo::default());
        add(&mut sbom, ds);

        let scope = ai_bom_scope(&sbom);
        assert_eq!(scope.dataset_components.len(), 1);
        assert!(
            scope.untyped_ml_components.is_empty(),
            "dataset evidence must exempt the component from the untyped-ML heuristic"
        );
        assert!(scope.is_applicable());
    }

    #[test]
    fn huggingface_purl_with_dataset_evidence_but_untyped_is_not_a_suspect() {
        // Even without ComponentType::Data, dataset evidence alone exempts
        // the component from the mistyped-model warning.
        let mut sbom = NormalizedSbom::default();
        let mut ds =
            component("common-voice").with_purl("pkg:huggingface/datasets/cv@2.0.0".to_string());
        ds.dataset = Some(DatasetInfo::default());
        add(&mut sbom, ds);

        let scope = ai_bom_scope(&sbom);
        assert_eq!(scope.dataset_components.len(), 1);
        assert!(scope.untyped_ml_components.is_empty());
    }

    #[test]
    fn model_card_ref_without_ml_metadata_is_an_untyped_suspect() {
        let mut sbom = NormalizedSbom::default();
        let mut c = component("mystery-model");
        c.external_refs.push(ExternalReference {
            ref_type: ExternalRefType::ModelCard,
            url: "https://example.test/card".to_string(),
            comment: None,
            hashes: Vec::new(),
        });
        add(&mut sbom, c);

        let scope = ai_bom_scope(&sbom);
        assert!(has_model_card_ref(scope.untyped_ml_components[0]));
        assert!(scope.is_applicable());
    }

    #[test]
    fn plain_library_sbom_is_not_applicable() {
        let mut sbom = NormalizedSbom::default();
        let lib = component("express").with_purl("pkg:npm/express@4.19.2".to_string());
        add(&mut sbom, lib);

        let scope = ai_bom_scope(&sbom);
        assert!(!scope.is_applicable());
    }
}
