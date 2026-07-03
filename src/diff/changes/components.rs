//! Component change computer implementation.

use crate::diff::traits::{ChangeComputer, ComponentChangeSet, ComponentMatches};
use crate::diff::{ComponentChange, CostModel, FieldChange};
use crate::model::{
    Component, CryptoAssetType, CryptoProperties, DatasetInfo, DatasetRef, MlModelInfo,
    NormalizedSbom,
};
use std::collections::HashSet;

/// Computes component-level changes between SBOMs.
pub struct ComponentChangeComputer {
    cost_model: CostModel,
}

impl ComponentChangeComputer {
    /// Create a new component change computer with the given cost model.
    #[must_use]
    pub const fn new(cost_model: CostModel) -> Self {
        Self { cost_model }
    }

    /// Compute individual field changes between two components.
    fn compute_field_changes(&self, old: &Component, new: &Component) -> (Vec<FieldChange>, u32) {
        let mut changes = Vec::new();
        let mut total_cost = 0u32;

        // Version change
        if old.version != new.version {
            changes.push(FieldChange {
                field: "version".to_string(),
                old_value: old.version.clone(),
                new_value: new.version.clone(),
            });
            total_cost += self
                .cost_model
                .version_change_cost(&old.semver, &new.semver);
        }

        // License change
        let old_licenses: HashSet<_> = old
            .licenses
            .declared
            .iter()
            .map(|l| &l.expression)
            .collect();
        let new_licenses: HashSet<_> = new
            .licenses
            .declared
            .iter()
            .map(|l| &l.expression)
            .collect();
        if old_licenses != new_licenses {
            changes.push(FieldChange {
                field: "licenses".to_string(),
                old_value: Some(
                    old.licenses
                        .declared
                        .iter()
                        .map(|l| l.expression.clone())
                        .collect::<Vec<_>>()
                        .join(", "),
                ),
                new_value: Some(
                    new.licenses
                        .declared
                        .iter()
                        .map(|l| l.expression.clone())
                        .collect::<Vec<_>>()
                        .join(", "),
                ),
            });
            total_cost += self.cost_model.license_changed;
        }

        // Supplier change
        if old.supplier != new.supplier {
            changes.push(FieldChange {
                field: "supplier".to_string(),
                old_value: old.supplier.as_ref().map(|s| s.name.clone()),
                new_value: new.supplier.as_ref().map(|s| s.name.clone()),
            });
            total_cost += self.cost_model.supplier_changed;
        }

        // Hash change (same version but different hash = integrity concern)
        if old.version == new.version && !old.hashes.is_empty() && !new.hashes.is_empty() {
            let old_hashes: HashSet<_> = old.hashes.iter().map(|h| &h.value).collect();
            let new_hashes: HashSet<_> = new.hashes.iter().map(|h| &h.value).collect();
            if old_hashes.is_disjoint(&new_hashes) {
                changes.push(FieldChange {
                    field: "hashes".to_string(),
                    old_value: Some(
                        old.hashes
                            .first()
                            .map(|h| h.value.clone())
                            .unwrap_or_default(),
                    ),
                    new_value: Some(
                        new.hashes
                            .first()
                            .map(|h| h.value.clone())
                            .unwrap_or_default(),
                    ),
                });
                total_cost += self.cost_model.hash_mismatch;
            }
        }

        // ML model metadata changes (granular, prefixed per-field)
        if old.ml_model != new.ml_model {
            total_cost += Self::compute_ml_changes(&self.cost_model, old, new, &mut changes);
        }

        // Dataset metadata changes (granular, prefixed per-field)
        if old.dataset != new.dataset {
            total_cost += Self::compute_dataset_changes(&self.cost_model, old, new, &mut changes);
        }

        // Cryptographic property changes
        if old.crypto_properties != new.crypto_properties {
            total_cost += Self::compute_crypto_changes(&self.cost_model, old, new, &mut changes);
        }

        (changes, total_cost)
    }

    /// Push a scalar `Option<String>` field change when the values differ.
    fn push_scalar_change(
        changes: &mut Vec<FieldChange>,
        field: &str,
        old: &Option<String>,
        new: &Option<String>,
        cost: &mut u32,
        field_cost: u32,
    ) {
        if old != new {
            changes.push(FieldChange {
                field: field.to_string(),
                old_value: old.clone(),
                new_value: new.clone(),
            });
            *cost += field_cost;
        }
    }

    /// Stable identity key for a training-dataset reference: prefer the BOM-ref,
    /// then the name, then the PURL. Used to detect added/removed datasets across
    /// two model revisions.
    fn dataset_ref_key(reference: &DatasetRef) -> Option<&str> {
        reference
            .reference
            .as_deref()
            .or(reference.name.as_deref())
            .or(reference.purl.as_deref())
    }

    /// Compute ML-model-specific field changes between two components.
    ///
    /// Emits granular, prefixed `ml_*` field changes (approach, architecture, task,
    /// quantization, model card) plus per-dataset `ml_training_dataset` add/remove
    /// entries, rather than one opaque serialized blob. This surfaces model-swap
    /// signals such as `fp32 -> int4` re-quantization or training-data provenance loss.
    fn compute_ml_changes(
        cost_model: &CostModel,
        old: &Component,
        new: &Component,
        changes: &mut Vec<FieldChange>,
    ) -> u32 {
        let mut cost = 0u32;

        match (&old.ml_model, &new.ml_model) {
            (Some(old_ml), Some(new_ml)) => {
                cost += Self::compute_ml_sub_changes(cost_model, old_ml, new_ml, changes);
            }
            (None, Some(_)) | (Some(_), None) => {
                // Model metadata appeared or disappeared wholesale.
                changes.push(FieldChange {
                    field: "ml_model".to_string(),
                    old_value: old.ml_model.as_ref().map(|_| "present".to_string()),
                    new_value: new.ml_model.as_ref().map(|_| "present".to_string()),
                });
                cost += cost_model.ml_model_changed;
            }
            (None, None) => {}
        }

        cost
    }

    fn compute_ml_sub_changes(
        cost_model: &CostModel,
        old: &MlModelInfo,
        new: &MlModelInfo,
        changes: &mut Vec<FieldChange>,
    ) -> u32 {
        let mut cost = 0u32;

        Self::push_scalar_change(
            changes,
            "ml_approach",
            &old.approach,
            &new.approach,
            &mut cost,
            cost_model.ml_approach_changed,
        );

        // Architecture family and name are reported under a single prefixed field
        // so a "resnet -> bert" or "cnn -> transformer" swap reads as one signal.
        let old_arch = Self::join_architecture(old);
        let new_arch = Self::join_architecture(new);
        Self::push_scalar_change(
            changes,
            "ml_architecture",
            &old_arch,
            &new_arch,
            &mut cost,
            cost_model.ml_architecture_changed,
        );

        Self::push_scalar_change(
            changes,
            "ml_task",
            &old.task,
            &new.task,
            &mut cost,
            cost_model.ml_task_changed,
        );
        Self::push_scalar_change(
            changes,
            "ml_quantization",
            &old.quantization,
            &new.quantization,
            &mut cost,
            cost_model.ml_quantization_changed,
        );
        Self::push_scalar_change(
            changes,
            "ml_model_card",
            &old.model_card_url,
            &new.model_card_url,
            &mut cost,
            cost_model.ml_model_card_changed,
        );

        cost += Self::compute_training_dataset_changes(cost_model, old, new, changes);
        cost += Self::compute_performance_metric_changes(old, new, changes);

        cost
    }

    fn compute_performance_metric_changes(
        old: &MlModelInfo,
        new: &MlModelInfo,
        changes: &mut Vec<FieldChange>,
    ) -> u32 {
        let key = |metric: &crate::model::MetricEntry| {
            metric.metric_type.as_ref().map(|kind| {
                format!(
                    "{}{}",
                    kind.to_ascii_lowercase(),
                    metric
                        .slice
                        .as_ref()
                        .map(|slice| format!("@{slice}"))
                        .unwrap_or_default()
                )
            })
        };
        let old_metrics: std::collections::HashMap<_, _> = old
            .performance_metrics
            .iter()
            .filter_map(|metric| key(metric).map(|key| (key, metric.value.clone())))
            .collect();
        let new_metrics: std::collections::HashMap<_, _> = new
            .performance_metrics
            .iter()
            .filter_map(|metric| key(metric).map(|key| (key, metric.value.clone())))
            .collect();

        let mut keys: Vec<_> = old_metrics
            .keys()
            .filter(|key| new_metrics.contains_key(*key))
            .cloned()
            .collect();
        keys.sort();
        let mut changed = 0;
        for key in keys {
            if old_metrics[&key] != new_metrics[&key] {
                changes.push(FieldChange {
                    field: format!("ml_metric:{key}"),
                    old_value: old_metrics[&key].clone(),
                    new_value: new_metrics[&key].clone(),
                });
                changed += 1;
            }
        }
        changed
    }

    /// Combine architecture family and name into a single display value.
    fn join_architecture(ml: &MlModelInfo) -> Option<String> {
        match (&ml.architecture_family, &ml.architecture_name) {
            (Some(family), Some(name)) => Some(format!("{family}/{name}")),
            (Some(value), None) | (None, Some(value)) => Some(value.clone()),
            (None, None) => None,
        }
    }

    /// Emit per-dataset `ml_training_dataset` add/remove changes keyed by
    /// `DatasetRef.reference`-or-`name`. Training-dataset removal is treated as a
    /// provenance-loss signal and carries a high cost.
    fn compute_training_dataset_changes(
        cost_model: &CostModel,
        old: &MlModelInfo,
        new: &MlModelInfo,
        changes: &mut Vec<FieldChange>,
    ) -> u32 {
        let mut cost = 0u32;

        let old_keys: HashSet<&str> = old
            .training_datasets
            .iter()
            .filter_map(Self::dataset_ref_key)
            .collect();
        let new_keys: HashSet<&str> = new
            .training_datasets
            .iter()
            .filter_map(Self::dataset_ref_key)
            .collect();

        // Removed training datasets (present in old, absent in new). Sorted for
        // deterministic output.
        let mut removed: Vec<&str> = old_keys.difference(&new_keys).copied().collect();
        removed.sort_unstable();
        for key in removed {
            changes.push(FieldChange {
                field: "ml_training_dataset".to_string(),
                old_value: Some(key.to_string()),
                new_value: None,
            });
            cost += cost_model.ml_training_dataset_removed;
        }

        // Added training datasets (absent in old, present in new).
        let mut added: Vec<&str> = new_keys.difference(&old_keys).copied().collect();
        added.sort_unstable();
        for key in added {
            changes.push(FieldChange {
                field: "ml_training_dataset".to_string(),
                old_value: None,
                new_value: Some(key.to_string()),
            });
            cost += cost_model.ml_training_dataset_added;
        }

        cost
    }

    /// Compute dataset-component-specific field changes between two components.
    ///
    /// Emits granular, prefixed `dataset_*` field changes: type, per-classification
    /// sensitivity add/remove, and governance. Gaining a sensitivity classification
    /// (e.g. a dataset newly tagged `pii`) is a data-governance signal and carries
    /// a high cost.
    fn compute_dataset_changes(
        cost_model: &CostModel,
        old: &Component,
        new: &Component,
        changes: &mut Vec<FieldChange>,
    ) -> u32 {
        let mut cost = 0u32;

        match (&old.dataset, &new.dataset) {
            (Some(old_ds), Some(new_ds)) => {
                cost += Self::compute_dataset_sub_changes(cost_model, old_ds, new_ds, changes);
            }
            (None, Some(_)) | (Some(_), None) => {
                changes.push(FieldChange {
                    field: "dataset".to_string(),
                    old_value: old.dataset.as_ref().map(|_| "present".to_string()),
                    new_value: new.dataset.as_ref().map(|_| "present".to_string()),
                });
                cost += cost_model.dataset_changed;
            }
            (None, None) => {}
        }

        cost
    }

    fn compute_dataset_sub_changes(
        cost_model: &CostModel,
        old: &DatasetInfo,
        new: &DatasetInfo,
        changes: &mut Vec<FieldChange>,
    ) -> u32 {
        let mut cost = 0u32;

        Self::push_scalar_change(
            changes,
            "dataset_type",
            &old.dataset_type,
            &new.dataset_type,
            &mut cost,
            cost_model.dataset_type_changed,
        );

        // Sensitivity classifications: emit per-classification add/remove so a
        // dataset newly gaining "pii" is visible and costly.
        let old_sens: HashSet<&str> = old
            .sensitivity_classifications
            .iter()
            .map(String::as_str)
            .collect();
        let new_sens: HashSet<&str> = new
            .sensitivity_classifications
            .iter()
            .map(String::as_str)
            .collect();

        let mut added: Vec<&str> = new_sens.difference(&old_sens).copied().collect();
        added.sort_unstable();
        for class in added {
            changes.push(FieldChange {
                field: "dataset_sensitivity".to_string(),
                old_value: None,
                new_value: Some(class.to_string()),
            });
            cost += cost_model.dataset_sensitivity_added;
        }

        let mut removed: Vec<&str> = old_sens.difference(&new_sens).copied().collect();
        removed.sort_unstable();
        for class in removed {
            changes.push(FieldChange {
                field: "dataset_sensitivity".to_string(),
                old_value: Some(class.to_string()),
                new_value: None,
            });
            cost += cost_model.dataset_sensitivity_removed;
        }

        // Governance owners: report a single change when the owner set differs.
        let old_gov: HashSet<&str> = old.governance_owners.iter().map(String::as_str).collect();
        let new_gov: HashSet<&str> = new.governance_owners.iter().map(String::as_str).collect();
        if old_gov != new_gov {
            changes.push(FieldChange {
                field: "dataset_governance".to_string(),
                old_value: Self::join_sorted(&old.governance_owners),
                new_value: Self::join_sorted(&new.governance_owners),
            });
            cost += cost_model.dataset_governance_changed;
        }

        cost
    }

    /// Join a list of strings into a deterministic, comma-separated display value,
    /// or `None` when empty.
    fn join_sorted(values: &[String]) -> Option<String> {
        if values.is_empty() {
            return None;
        }
        let mut sorted: Vec<&str> = values.iter().map(String::as_str).collect();
        sorted.sort_unstable();
        Some(sorted.join(", "))
    }

    /// Compute crypto-specific field changes between two components.
    fn compute_crypto_changes(
        cost_model: &CostModel,
        old: &Component,
        new: &Component,
        changes: &mut Vec<FieldChange>,
    ) -> u32 {
        let mut cost = 0u32;

        match (&old.crypto_properties, &new.crypto_properties) {
            (Some(old_cp), Some(new_cp)) => {
                cost += Self::compute_crypto_sub_changes(cost_model, old_cp, new_cp, changes);
            }
            (None, Some(new_cp)) => {
                changes.push(FieldChange {
                    field: "crypto_properties".to_string(),
                    old_value: None,
                    new_value: Some(new_cp.asset_type.to_string()),
                });
                cost += cost_model.crypto_algorithm_changed;
            }
            (Some(old_cp), None) => {
                changes.push(FieldChange {
                    field: "crypto_properties".to_string(),
                    old_value: Some(old_cp.asset_type.to_string()),
                    new_value: None,
                });
                cost += cost_model.crypto_algorithm_changed;
            }
            (None, None) => {}
        }

        cost
    }

    fn compute_crypto_sub_changes(
        cost_model: &CostModel,
        old: &CryptoProperties,
        new: &CryptoProperties,
        changes: &mut Vec<FieldChange>,
    ) -> u32 {
        let mut cost = 0u32;

        // Algorithm property changes
        if let (Some(old_algo), Some(new_algo)) =
            (&old.algorithm_properties, &new.algorithm_properties)
        {
            // Algorithm family change
            if old_algo.algorithm_family != new_algo.algorithm_family {
                changes.push(FieldChange {
                    field: "crypto_algorithm".to_string(),
                    old_value: old_algo.algorithm_family.clone(),
                    new_value: new_algo.algorithm_family.clone(),
                });
                cost += cost_model.crypto_algorithm_changed;
            }

            // Quantum security level change
            if old_algo.nist_quantum_security_level != new_algo.nist_quantum_security_level {
                changes.push(FieldChange {
                    field: "crypto_quantum_level".to_string(),
                    old_value: old_algo.nist_quantum_security_level.map(|l| l.to_string()),
                    new_value: new_algo.nist_quantum_security_level.map(|l| l.to_string()),
                });
                cost += cost_model.crypto_quantum_level_changed;
            }

            // Security downgrade detection: classical security level decreased
            if let (Some(old_bits), Some(new_bits)) = (
                old_algo.classical_security_level,
                new_algo.classical_security_level,
            ) && new_bits < old_bits
            {
                changes.push(FieldChange {
                    field: "crypto_downgrade".to_string(),
                    old_value: Some(format!("{old_bits} bits")),
                    new_value: Some(format!("{new_bits} bits")),
                });
                cost += cost_model.crypto_downgrade;
            }
        }

        // Key material state changes
        if let (Some(old_mat), Some(new_mat)) = (
            &old.related_crypto_material_properties,
            &new.related_crypto_material_properties,
        ) && old_mat.state != new_mat.state
        {
            changes.push(FieldChange {
                field: "crypto_key_state".to_string(),
                old_value: old_mat.state.as_ref().map(|s| s.to_string()),
                new_value: new_mat.state.as_ref().map(|s| s.to_string()),
            });
            cost += cost_model.crypto_key_rotated;
        }

        // Certificate expiry changes
        if let (Some(old_cert), Some(new_cert)) =
            (&old.certificate_properties, &new.certificate_properties)
            && old_cert.not_valid_after != new_cert.not_valid_after
        {
            changes.push(FieldChange {
                field: "crypto_cert_expiry".to_string(),
                old_value: old_cert.not_valid_after.map(|d| d.to_rfc3339()),
                new_value: new_cert.not_valid_after.map(|d| d.to_rfc3339()),
            });
            cost += cost_model.crypto_cert_expiry_changed;
        }

        // Protocol version changes
        if let (Some(old_proto), Some(new_proto)) =
            (&old.protocol_properties, &new.protocol_properties)
            && old_proto.version != new_proto.version
        {
            changes.push(FieldChange {
                field: "crypto_protocol_version".to_string(),
                old_value: old_proto.version.clone(),
                new_value: new_proto.version.clone(),
            });
            cost += cost_model.crypto_protocol_changed;
        }

        // Asset type change (e.g., algorithm → protocol)
        if old.asset_type != new.asset_type
            && old.asset_type != CryptoAssetType::Other("unknown".to_string())
        {
            changes.push(FieldChange {
                field: "crypto_asset_type".to_string(),
                old_value: Some(old.asset_type.to_string()),
                new_value: Some(new.asset_type.to_string()),
            });
            cost += cost_model.crypto_algorithm_changed;
        }

        cost
    }
}

impl Default for ComponentChangeComputer {
    fn default() -> Self {
        Self::new(CostModel::default())
    }
}

impl ChangeComputer for ComponentChangeComputer {
    type ChangeSet = ComponentChangeSet;

    fn compute(
        &self,
        old: &NormalizedSbom,
        new: &NormalizedSbom,
        matches: &ComponentMatches,
    ) -> ComponentChangeSet {
        let mut result = ComponentChangeSet::new();
        let matched_new_ids: HashSet<_> = matches
            .values()
            .filter_map(std::clone::Clone::clone)
            .collect();

        // Find removed components
        for (old_id, new_id_opt) in matches {
            if new_id_opt.is_none()
                && let Some(old_comp) = old.components.get(old_id)
            {
                result.removed.push(ComponentChange::removed(
                    old_comp,
                    self.cost_model.component_removed,
                ));
            }
        }

        // Find added components
        for new_id in new.components.keys() {
            if !matched_new_ids.contains(new_id)
                && let Some(new_comp) = new.components.get(new_id)
            {
                result.added.push(ComponentChange::added(
                    new_comp,
                    self.cost_model.component_added,
                ));
            }
        }

        // Find modified components
        for (old_id, new_id_opt) in matches {
            if let Some(new_id) = new_id_opt
                && let (Some(old_comp), Some(new_comp)) =
                    (old.components.get(old_id), new.components.get(new_id))
            {
                // Check if component was actually modified
                if old_comp.content_hash != new_comp.content_hash {
                    let (field_changes, cost) = self.compute_field_changes(old_comp, new_comp);
                    if !field_changes.is_empty() {
                        result.modified.push(ComponentChange::modified(
                            old_comp,
                            new_comp,
                            field_changes,
                            cost,
                        ));
                    }
                }
            }
        }

        // Removed/modified are collected from hash-map iteration; sort by ID
        // for deterministic output ordering
        result.removed.sort_by(|a, b| a.id.cmp(&b.id));
        result.modified.sort_by(|a, b| a.id.cmp(&b.id));

        result
    }

    fn name(&self) -> &'static str {
        "ComponentChangeComputer"
    }
}

#[cfg(test)]
mod tests {
    // `DatasetInfo`, `DatasetRef`, and `MlModelInfo` are re-exported via the
    // parent module's `use crate::model::{...}`.
    use super::*;

    #[test]
    fn test_component_change_computer_default() {
        let computer = ComponentChangeComputer::default();
        assert_eq!(computer.name(), "ComponentChangeComputer");
    }

    #[test]
    fn test_empty_sboms() {
        let computer = ComponentChangeComputer::default();
        let old = NormalizedSbom::default();
        let new = NormalizedSbom::default();
        let matches = ComponentMatches::new();

        let result = computer.compute(&old, &new, &matches);
        assert!(result.is_empty());
    }

    /// Locate the single field change with the given field name, asserting it exists.
    fn find_change<'a>(changes: &'a [FieldChange], field: &str) -> &'a FieldChange {
        changes
            .iter()
            .find(|c| c.field == field)
            .unwrap_or_else(|| panic!("expected a `{field}` field change, got {changes:?}"))
    }

    #[test]
    fn test_ml_quantization_change_is_granular() {
        let computer = ComponentChangeComputer::default();
        let mut old = Component::new("model".to_string(), "model@1".to_string());
        let mut new = old.clone();

        old.ml_model = Some(MlModelInfo {
            quantization: Some("fp32".to_string()),
            ..MlModelInfo::default()
        });
        new.ml_model = Some(MlModelInfo {
            quantization: Some("int4".to_string()),
            ..MlModelInfo::default()
        });

        let (changes, total_cost) = computer.compute_field_changes(&old, &new);

        // The opaque "ml_model" blob is gone; a prefixed ml_quantization change appears.
        assert!(changes.iter().all(|c| c.field != "ml_model"));
        let change = find_change(&changes, "ml_quantization");
        assert_eq!(change.old_value.as_deref(), Some("fp32"));
        assert_eq!(change.new_value.as_deref(), Some("int4"));
        assert_eq!(total_cost, CostModel::default().ml_quantization_changed);
    }

    #[test]
    fn test_ml_architecture_and_task_changes_are_granular() {
        let computer = ComponentChangeComputer::default();
        let mut old = Component::new("model".to_string(), "model@1".to_string());
        let mut new = old.clone();

        old.ml_model = Some(MlModelInfo {
            architecture_family: Some("cnn".to_string()),
            architecture_name: Some("resnet".to_string()),
            task: Some("computer-vision".to_string()),
            ..MlModelInfo::default()
        });
        new.ml_model = Some(MlModelInfo {
            architecture_family: Some("transformer".to_string()),
            architecture_name: Some("bert".to_string()),
            task: Some("nlp".to_string()),
            ..MlModelInfo::default()
        });

        let (changes, _) = computer.compute_field_changes(&old, &new);

        let arch = find_change(&changes, "ml_architecture");
        assert_eq!(arch.old_value.as_deref(), Some("cnn/resnet"));
        assert_eq!(arch.new_value.as_deref(), Some("transformer/bert"));
        let task = find_change(&changes, "ml_task");
        assert_eq!(task.old_value.as_deref(), Some("computer-vision"));
        assert_eq!(task.new_value.as_deref(), Some("nlp"));
    }

    #[test]
    fn test_ml_training_dataset_removed_has_high_cost() {
        let computer = ComponentChangeComputer::default();
        let mut old = Component::new("model".to_string(), "model@1".to_string());
        let mut new = old.clone();

        old.ml_model = Some(MlModelInfo {
            training_datasets: vec![
                DatasetRef {
                    reference: Some("ds-imagenet".to_string()),
                    name: Some("imagenet".to_string()),
                    purl: None,
                },
                DatasetRef {
                    reference: Some("ds-coco".to_string()),
                    name: Some("coco".to_string()),
                    purl: None,
                },
            ],
            ..MlModelInfo::default()
        });
        new.ml_model = Some(MlModelInfo {
            training_datasets: vec![DatasetRef {
                reference: Some("ds-imagenet".to_string()),
                name: Some("imagenet".to_string()),
                purl: None,
            }],
            ..MlModelInfo::default()
        });

        let (changes, total_cost) = computer.compute_field_changes(&old, &new);

        let removed = find_change(&changes, "ml_training_dataset");
        assert_eq!(removed.old_value.as_deref(), Some("ds-coco"));
        assert_eq!(removed.new_value, None);
        assert_eq!(total_cost, CostModel::default().ml_training_dataset_removed);
    }

    #[test]
    fn test_dataset_sensitivity_escalation_has_high_cost() {
        let computer = ComponentChangeComputer::default();
        let mut old = Component::new("dataset".to_string(), "dataset@1".to_string());
        let mut new = old.clone();

        old.dataset = Some(DatasetInfo {
            dataset_type: Some("training".to_string()),
            sensitivity_classifications: vec!["public".to_string()],
            ..DatasetInfo::default()
        });
        new.dataset = Some(DatasetInfo {
            dataset_type: Some("training".to_string()),
            sensitivity_classifications: vec!["public".to_string(), "pii".to_string()],
            ..DatasetInfo::default()
        });

        let (changes, total_cost) = computer.compute_field_changes(&old, &new);

        // No opaque "dataset" blob; a prefixed dataset_sensitivity add appears.
        assert!(changes.iter().all(|c| c.field != "dataset"));
        let escalation = find_change(&changes, "dataset_sensitivity");
        assert_eq!(escalation.old_value, None);
        assert_eq!(escalation.new_value.as_deref(), Some("pii"));
        assert_eq!(total_cost, CostModel::default().dataset_sensitivity_added);
    }

    #[test]
    fn test_dataset_type_and_governance_changes_are_granular() {
        let computer = ComponentChangeComputer::default();
        let mut old = Component::new("dataset".to_string(), "dataset@1".to_string());
        let mut new = old.clone();

        old.dataset = Some(DatasetInfo {
            dataset_type: Some("training".to_string()),
            governance_owners: vec!["alice".to_string()],
            ..DatasetInfo::default()
        });
        new.dataset = Some(DatasetInfo {
            dataset_type: Some("validation".to_string()),
            governance_owners: vec!["bob".to_string()],
            ..DatasetInfo::default()
        });

        let (changes, _) = computer.compute_field_changes(&old, &new);

        let ty = find_change(&changes, "dataset_type");
        assert_eq!(ty.old_value.as_deref(), Some("training"));
        assert_eq!(ty.new_value.as_deref(), Some("validation"));
        let gov = find_change(&changes, "dataset_governance");
        assert_eq!(gov.old_value.as_deref(), Some("alice"));
        assert_eq!(gov.new_value.as_deref(), Some("bob"));
    }

    #[test]
    fn test_security_focused_escalates_ml_and_dataset_costs() {
        let secure = ComponentChangeComputer::new(CostModel::security_focused());
        let default = ComponentChangeComputer::default();

        let mut old = Component::new("dataset".to_string(), "dataset@1".to_string());
        let mut new = old.clone();
        old.dataset = Some(DatasetInfo {
            sensitivity_classifications: vec![],
            ..DatasetInfo::default()
        });
        new.dataset = Some(DatasetInfo {
            sensitivity_classifications: vec!["pii".to_string()],
            ..DatasetInfo::default()
        });

        let (_, secure_cost) = secure.compute_field_changes(&old, &new);
        let (_, default_cost) = default.compute_field_changes(&old, &new);
        assert!(
            secure_cost > default_cost,
            "security profile should weight PII escalation higher (secure={secure_cost}, default={default_cost})"
        );
    }
}
