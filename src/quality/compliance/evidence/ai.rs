//! AI-BOM facts: which components the AI profiles judge as ML models, AI
//! datasets or mistyped models, which models nest a dataset, and what a
//! model or a dataset documents.
//!
//! The EU AI Act and BSI/G7 SBOM-for-AI profiles judge some of the same
//! documentation with different acceptance sets (a model card, the
//! limitations, a dataset's sensitivity). Each acceptance set is a fact of
//! its own here, named for what it accepts, so neither profile's reading
//! moves.

use super::super::ai_shared::{ai_bom_scope, has_model_card_ref};
use super::super::shared::{is_placeholder, known_component_name};
use super::{ComponentIx, ComponentView};
use crate::model::{Component, DependencyType, ExternalRefType, NormalizedSbom};

/// The AI-BOM scope of an SBOM (see `ai_shared::ai_bom_scope`): the
/// components the AI profiles judge, by position, in inventory order.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AiFacts {
    /// The ML-model components: typed `machine-learning-model`, or carrying
    /// parsed ML-model metadata whatever their type.
    pub(crate) models: Box<[ComponentIx]>,
    /// The AI-dataset components: those with dataset evidence, whatever
    /// their type.
    pub(crate) datasets: Box<[ComponentIx]>,
    /// The components that look like ML models (a `pkg:huggingface` PURL or
    /// a model-card reference) without being typed or described as one, and
    /// without dataset evidence.
    pub(crate) untyped_models: Box<[ComponentIx]>,
    /// Whether the AI profiles apply: the scope holds a component.
    pub(crate) applicable: bool,
    /// How many components the scope holds; a model with dataset evidence
    /// counts once.
    pub(crate) component_count: usize,
}

impl AiFacts {
    pub(super) fn collect(sbom: &NormalizedSbom) -> Self {
        let scope = ai_bom_scope(sbom);
        Self {
            models: positions(sbom, &scope.ml_components),
            datasets: positions(sbom, &scope.dataset_components),
            untyped_models: positions(sbom, &scope.untyped_ml_components),
            applicable: scope.is_applicable(),
            component_count: scope.component_count(),
        }
    }
}

/// The positions of `listed`, components of `sbom` listed in inventory
/// order, as `ai_bom_scope` lists them.
fn positions(sbom: &NormalizedSbom, listed: &[&Component]) -> Box<[ComponentIx]> {
    let mut found = Vec::with_capacity(listed.len());
    let mut rest = listed.iter().peekable();
    // All components: the walk finds the positions of components the AI
    // scope already selected, of any type.
    for (ix, component) in sbom.components.values().enumerate() {
        let Some(next) = rest.peek() else {
            break;
        };
        if std::ptr::eq(**next, component) {
            found.push(ComponentIx(ix));
            rest.next();
        }
    }
    debug_assert!(
        rest.peek().is_none(),
        "a listed component is in the inventory"
    );
    found.into_boxed_slice()
}

/// Per component: whether a `contains` relationship leads from it to a
/// component with dataset evidence, a dataset nested under it. One pass
/// over the edges, where asking each model cost a pass of its own.
pub(super) fn dataset_containers(sbom: &NormalizedSbom) -> Box<[bool]> {
    let mut contains = vec![false; sbom.components.len()];
    for edge in &sbom.edges {
        if edge.relationship != DependencyType::Contains {
            continue;
        }
        let to_dataset = sbom
            .components
            .get(&edge.to)
            .is_some_and(|c| c.dataset.is_some());
        if to_dataset && let Some(from) = sbom.components.get_index_of(&edge.from) {
            contains[from] = true;
        }
    }
    contains.into_boxed_slice()
}

/// What a model or a dataset documents. Each fact is one profile's
/// acceptance set; where the two profiles judge one element differently,
/// the doc comment names the sibling fact.
impl ComponentView<'_, '_> {
    /// Whether the component's name is real and not a placeholder such as
    /// `TBD` or `N/A`. The BSI/G7 SBOM-for-AI name checks ask this; the
    /// other name checks accept a placeholder ([`Self::name_known`]).
    pub(crate) fn name_known_not_placeholder(&self) -> bool {
        known_component_name(self.component) && !is_placeholder(&self.component.name)
    }

    /// Whether the model names its training datasets: in its model card
    /// (`modelParameters.datasets`, the SPDX 3 `trainedOn` relationship),
    /// or as a nested component with dataset evidence (see
    /// `ai_shared::declares_training_datasets`). Both AI profiles ask this.
    pub(crate) fn declares_training_datasets(&self) -> bool {
        self.component
            .ml_model
            .as_ref()
            .is_some_and(|m| !m.training_datasets.is_empty())
            || self.ev.dataset_containers()[self.ix.0]
    }

    /// Whether the model has a general description in the EU AI Act's
    /// sense (Annex IV §1): a description, a model-card reference, an
    /// architecture or a model-card URL.
    pub(crate) fn has_general_description(&self) -> bool {
        self.component.description.is_some()
            || has_model_card_ref(self.component)
            || self.component.ml_model.as_ref().is_some_and(|m| {
                m.architecture_family.is_some()
                    || m.architecture_name.is_some()
                    || m.model_card_url.is_some()
            })
    }

    /// Whether the model declares its intended use-cases.
    pub(crate) fn declares_use_cases(&self) -> bool {
        self.component
            .ml_model
            .as_ref()
            .is_some_and(|m| !m.use_cases.is_empty())
    }

    /// Whether the model gives validation or testing metrics, as the EU AI
    /// Act's Annex IV §2(g) check reads them: typed performance metrics, or
    /// a model card's `quantitativeAnalysis` kept in the raw extensions that
    /// is not null and not an empty list or object.
    pub(crate) fn declares_validation_metrics(&self) -> bool {
        let typed = self
            .component
            .ml_model
            .as_ref()
            .is_some_and(|m| !m.performance_metrics.is_empty());
        typed
            || self.component.extensions.raw.as_ref().is_some_and(|raw| {
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
            })
    }

    /// Whether the model states its limitations, or ethical or fairness
    /// considerations: what the EU AI Act's Annex IV §3 check accepts. The
    /// BSI/G7 check accepts only the limitations
    /// ([`Self::states_limitations`]).
    pub(crate) fn states_limitations_or_considerations(&self) -> bool {
        self.component.ml_model.as_ref().is_some_and(|m| {
            m.limitations.is_some()
                || !m.ethical_considerations.is_empty()
                || !m.fairness.is_empty()
        })
    }

    /// Whether the model states the energy its training consumed.
    pub(crate) fn declares_training_energy(&self) -> bool {
        self.component
            .ml_model
            .as_ref()
            .is_some_and(|m| m.energy_kwh_training.is_some())
    }

    /// Whether the model references a model card: a URL from its model
    /// card, or a `model-card` external reference. The BSI/G7 check asks
    /// this; the EU AI Act accepts more as a general description
    /// ([`Self::has_general_description`]).
    pub(crate) fn references_model_card(&self) -> bool {
        self.component
            .ml_model
            .as_ref()
            .and_then(|m| m.model_card_url.as_ref())
            .is_some()
            || has_model_card_ref(self.component)
    }

    /// Whether the model declares its architecture: a family or a name.
    pub(crate) fn declares_architecture(&self) -> bool {
        self.component
            .ml_model
            .as_ref()
            .is_some_and(|m| m.architecture_family.is_some() || m.architecture_name.is_some())
    }

    /// Whether the model states its limitations. The BSI/G7 check asks
    /// this; the EU AI Act accepts ethical or fairness considerations too
    /// ([`Self::states_limitations_or_considerations`]).
    pub(crate) fn states_limitations(&self) -> bool {
        self.component
            .ml_model
            .as_ref()
            .and_then(|m| m.limitations.as_ref())
            .is_some()
    }

    /// Whether the component references a BOM (a runtime, framework or
    /// hardware BOM).
    pub(crate) fn references_bom(&self) -> bool {
        self.component
            .external_refs
            .iter()
            .any(|r| r.ref_type == ExternalRefType::Bom)
    }

    /// Whether the dataset lists a sensitivity classification, `none`
    /// included. The EU AI Act check asks this; the BSI/G7 check accepts a
    /// confidentiality level too
    /// ([`Self::declares_sensitivity_or_confidentiality`]).
    pub(crate) fn classifies_sensitivity(&self) -> bool {
        self.component
            .dataset
            .as_ref()
            .is_some_and(|d| !d.sensitivity_classifications.is_empty())
    }

    /// Whether a sensitivity classification of the dataset names personal,
    /// PII, sensitive or confidential data, in any case.
    pub(crate) fn classifies_personal_data(&self) -> bool {
        self.component.dataset.as_ref().is_some_and(|d| {
            d.sensitivity_classifications.iter().any(|s| {
                let s = s.to_lowercase();
                s.contains("personal")
                    || s.contains("pii")
                    || s.contains("sensitive")
                    || s.contains("confidential")
            })
        })
    }

    /// Whether the dataset lists a sensitivity classification or gives a
    /// confidentiality level. The BSI/G7 check asks this; the EU AI Act
    /// check reads only the classifications
    /// ([`Self::classifies_sensitivity`]).
    pub(crate) fn declares_sensitivity_or_confidentiality(&self) -> bool {
        self.component.dataset.as_ref().is_some_and(|d| {
            !d.sensitivity_classifications.is_empty() || d.confidentiality_level.is_some()
        })
    }

    /// Whether the dataset declares its provenance or intended use: an
    /// intended use, preprocessing, anonymization or governance owners.
    pub(crate) fn declares_dataset_provenance(&self) -> bool {
        self.component.dataset.as_ref().is_some_and(|d| {
            d.intended_use.is_some()
                || !d.preprocessing.is_empty()
                || !d.anonymization.is_empty()
                || !d.governance_owners.is_empty()
        })
    }
}
