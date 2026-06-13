//! Component change computer implementation.

use crate::diff::traits::{ChangeComputer, ComponentChangeSet, ComponentMatches};
use crate::diff::{ComponentChange, CostModel, FieldChange};
use crate::model::{Component, CryptoAssetType, CryptoProperties, NormalizedSbom};
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

    fn serialize_optional<T: serde::Serialize>(value: &Option<T>) -> Option<String> {
        value.as_ref().map(|value| {
            serde_json::to_string(value).expect("serializing diff value should be infallible")
        })
    }

    fn push_structured_change<T: serde::Serialize + PartialEq>(
        changes: &mut Vec<FieldChange>,
        field: &str,
        old: &Option<T>,
        new: &Option<T>,
        total_cost: &mut u32,
        field_cost: u32,
    ) {
        if old != new {
            changes.push(FieldChange {
                field: field.to_string(),
                old_value: Self::serialize_optional(old),
                new_value: Self::serialize_optional(new),
            });
            *total_cost += field_cost;
        }
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

        Self::push_structured_change(
            &mut changes,
            "ml_model",
            &old.ml_model,
            &new.ml_model,
            &mut total_cost,
            self.cost_model.ml_model_changed,
        );
        Self::push_structured_change(
            &mut changes,
            "dataset",
            &old.dataset,
            &new.dataset,
            &mut total_cost,
            self.cost_model.dataset_changed,
        );

        // Cryptographic property changes
        if old.crypto_properties != new.crypto_properties {
            total_cost += Self::compute_crypto_changes(&self.cost_model, old, new, &mut changes);
        }

        (changes, total_cost)
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
    use super::*;
    use crate::model::{DatasetInfo, MlModelInfo};

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

    #[test]
    fn test_ml_model_change_uses_dedicated_cost() {
        let computer = ComponentChangeComputer::new(CostModel {
            ml_model_changed: 42,
            ..CostModel::default()
        });
        let mut old = Component::new("model".to_string(), "model@1".to_string());
        let mut new = old.clone();

        old.ml_model = Some(MlModelInfo {
            quantization: Some("fp32".to_string()),
            ..MlModelInfo::default()
        });
        new.ml_model = Some(MlModelInfo {
            quantization: Some("int8".to_string()),
            ..MlModelInfo::default()
        });

        let (changes, total_cost) = computer.compute_field_changes(&old, &new);

        assert_eq!(total_cost, 42);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].field, "ml_model");
    }

    #[test]
    fn test_dataset_change_uses_dedicated_cost() {
        let computer = ComponentChangeComputer::new(CostModel {
            dataset_changed: 17,
            ..CostModel::default()
        });
        let mut old = Component::new("dataset".to_string(), "dataset@1".to_string());
        let mut new = old.clone();

        old.dataset = Some(DatasetInfo {
            dataset_type: Some("training".to_string()),
            ..DatasetInfo::default()
        });
        new.dataset = Some(DatasetInfo {
            dataset_type: Some("validation".to_string()),
            ..DatasetInfo::default()
        });

        let (changes, total_cost) = computer.compute_field_changes(&old, &new);

        assert_eq!(total_cost, 17);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].field, "dataset");
    }
}
