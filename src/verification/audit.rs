//! Component hash auditing.
//!
//! Analyzes hash coverage and strength across all components in an SBOM,
//! producing a detailed audit report.

use crate::model::{HashAlgorithm, NormalizedSbom};
use serde::{Deserialize, Serialize};

/// Status of a component's hash coverage
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAuditResult {
    /// Component has at least one strong hash (SHA-256+)
    Strong,
    /// Component only has weak hashes (MD5, SHA-1)
    WeakOnly,
    /// Component has no hashes at all
    Missing,
}

/// Audit report for a single component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHashAudit {
    /// Component name
    pub name: String,
    /// Component version
    pub version: Option<String>,
    /// Audit result
    pub result: HashAuditResult,
    /// Algorithms present
    pub algorithms: Vec<String>,
}

/// Overall hash audit report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashAuditReport {
    /// Total components analyzed
    pub total_components: usize,
    /// Components with strong hashes
    pub strong_count: usize,
    /// Components with only weak hashes
    pub weak_only_count: usize,
    /// Components with no hashes
    pub missing_count: usize,
    /// Per-component audit details
    pub components: Vec<ComponentHashAudit>,
}

impl HashAuditReport {
    /// Overall pass rate (components with strong hashes / total)
    #[must_use]
    pub fn pass_rate(&self) -> f64 {
        if self.total_components == 0 {
            return 100.0;
        }
        (self.strong_count as f64 / self.total_components as f64) * 100.0
    }
}

/// Returns true if a hash algorithm is considered strong (SHA-256 or better)
fn is_strong_algorithm(alg: &HashAlgorithm) -> bool {
    matches!(
        alg,
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

/// Audit all component hashes in an SBOM.
///
/// Returns a detailed report of hash coverage and strength.
#[must_use]
pub fn audit_component_hashes(sbom: &NormalizedSbom) -> HashAuditReport {
    let mut strong_count = 0;
    let mut weak_only_count = 0;
    let mut missing_count = 0;
    let mut components = Vec::new();

    for comp in sbom.components.values() {
        let algorithms: Vec<String> = comp
            .hashes
            .iter()
            .map(|h| format!("{}", h.algorithm))
            .collect();

        let result = if comp.hashes.is_empty() {
            missing_count += 1;
            HashAuditResult::Missing
        } else if comp
            .hashes
            .iter()
            .any(|h| is_strong_algorithm(&h.algorithm))
        {
            strong_count += 1;
            HashAuditResult::Strong
        } else {
            weak_only_count += 1;
            HashAuditResult::WeakOnly
        };

        components.push(ComponentHashAudit {
            name: comp.name.clone(),
            version: comp.version.clone(),
            result,
            algorithms,
        });
    }

    HashAuditReport {
        total_components: sbom.components.len(),
        strong_count,
        weak_only_count,
        missing_count,
        components,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Component, Hash, NormalizedSbom};

    fn make_sbom_with_hashes(hash_specs: &[Vec<HashAlgorithm>]) -> NormalizedSbom {
        let mut sbom = NormalizedSbom::default();
        for (i, algs) in hash_specs.iter().enumerate() {
            let mut comp = Component::new(format!("comp-{i}"), format!("id-{i}"));
            for alg in algs {
                comp.hashes
                    .push(Hash::new(alg.clone(), "deadbeef".to_string()));
            }
            sbom.components.insert(comp.canonical_id.clone(), comp);
        }
        sbom
    }

    #[test]
    fn audit_empty_sbom() {
        let sbom = NormalizedSbom::default();
        let report = audit_component_hashes(&sbom);
        assert_eq!(report.total_components, 0);
        assert_eq!(report.pass_rate(), 100.0);
    }

    #[test]
    fn audit_all_strong() {
        let sbom =
            make_sbom_with_hashes(&[vec![HashAlgorithm::Sha256], vec![HashAlgorithm::Sha512]]);
        let report = audit_component_hashes(&sbom);
        assert_eq!(report.strong_count, 2);
        assert_eq!(report.missing_count, 0);
        assert_eq!(report.pass_rate(), 100.0);
    }

    #[test]
    fn audit_mixed() {
        let sbom = make_sbom_with_hashes(&[
            vec![HashAlgorithm::Sha256],
            vec![HashAlgorithm::Md5],
            vec![],
        ]);
        let report = audit_component_hashes(&sbom);
        assert_eq!(report.strong_count, 1);
        assert_eq!(report.weak_only_count, 1);
        assert_eq!(report.missing_count, 1);
    }

    #[test]
    fn audit_weak_with_strong_upgrade() {
        let sbom = make_sbom_with_hashes(&[vec![HashAlgorithm::Sha1, HashAlgorithm::Sha256]]);
        let report = audit_component_hashes(&sbom);
        assert_eq!(report.strong_count, 1);
        assert_eq!(report.weak_only_count, 0);
    }
}
