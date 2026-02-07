//! License conflict detection for SBOM analysis.
//!
//! This module provides enhanced license conflict detection with specific
//! rules for common license incompatibilities.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Conflict rule defining an incompatibility
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictRule {
    /// Pattern to match first license
    pub license_a_pattern: String,
    /// Pattern to match second license
    pub license_b_pattern: String,
    /// Type of conflict
    pub conflict_type: ConflictType,
    /// Severity of the conflict
    pub severity: ConflictSeverity,
    /// Human-readable description
    pub description: String,
    /// Remediation advice
    pub remediation: String,
}

/// Type of license conflict
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConflictType {
    /// Licenses cannot coexist in same binary
    BinaryIncompatible,
    /// Licenses cannot be combined in same project
    ProjectIncompatible,
    /// Network copyleft triggers source disclosure
    NetworkCopyleft,
    /// Patent clause conflict
    PatentConflict,
    /// Copyleft strength mismatch
    CopyleftMismatch,
}

impl std::fmt::Display for ConflictType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BinaryIncompatible => write!(f, "Binary Incompatible"),
            Self::ProjectIncompatible => write!(f, "Project Incompatible"),
            Self::NetworkCopyleft => write!(f, "Network Copyleft"),
            Self::PatentConflict => write!(f, "Patent Conflict"),
            Self::CopyleftMismatch => write!(f, "Copyleft Mismatch"),
        }
    }
}

/// Severity of a conflict
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ConflictSeverity {
    /// Informational - may need review
    Info,
    /// Warning - should address
    Warning,
    /// Error - cannot proceed legally
    Error,
}

impl std::fmt::Display for ConflictSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "Info"),
            Self::Warning => write!(f, "Warning"),
            Self::Error => write!(f, "Error"),
        }
    }
}

/// A detected license conflict
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedConflict {
    /// The rule that was matched
    pub rule: ConflictRule,
    /// First license involved
    pub license_a: String,
    /// Second license involved
    pub license_b: String,
    /// Components affected
    pub affected_components: Vec<String>,
    /// Context of the conflict
    pub context: ConflictContext,
}

/// Context in which the conflict occurs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConflictContext {
    /// In same linked binary
    SameBinary,
    /// In same project/codebase
    SameProject,
    /// Through transitive dependency
    TransitiveDependency,
}

impl std::fmt::Display for ConflictContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SameBinary => write!(f, "Same Binary"),
            Self::SameProject => write!(f, "Same Project"),
            Self::TransitiveDependency => write!(f, "Transitive Dependency"),
        }
    }
}

/// License conflict detector
pub struct ConflictDetector {
    rules: Vec<ConflictRule>,
}

impl ConflictDetector {
    /// Create detector with default rules
    pub(crate) fn new() -> Self {
        Self {
            rules: Self::default_rules(),
        }
    }

    /// Get default conflict rules
    pub(crate) fn default_rules() -> Vec<ConflictRule> {
        vec![
            // GPL + Proprietary
            ConflictRule {
                license_a_pattern: "GPL".to_string(),
                license_b_pattern: "Proprietary".to_string(),
                conflict_type: ConflictType::BinaryIncompatible,
                severity: ConflictSeverity::Error,
                description: "GPL licenses require derivative works to be GPL-licensed. Proprietary code cannot be combined with GPL in the same binary.".to_string(),
                remediation: "Remove proprietary components or replace GPL dependencies with permissively-licensed alternatives.".to_string(),
            },
            // AGPL + Proprietary
            ConflictRule {
                license_a_pattern: "AGPL".to_string(),
                license_b_pattern: "Proprietary".to_string(),
                conflict_type: ConflictType::BinaryIncompatible,
                severity: ConflictSeverity::Error,
                description: "AGPL is even stricter than GPL and extends to network use. Cannot combine with proprietary code.".to_string(),
                remediation: "Remove proprietary components or replace AGPL dependencies with permissively-licensed alternatives.".to_string(),
            },
            // Apache-2.0 + GPL-2.0
            ConflictRule {
                license_a_pattern: "Apache-2.0".to_string(),
                license_b_pattern: "GPL-2.0".to_string(),
                conflict_type: ConflictType::PatentConflict,
                severity: ConflictSeverity::Error,
                description: "Apache 2.0's patent termination clause conflicts with GPL 2.0. GPL 2.0 does not have compatible patent provisions.".to_string(),
                remediation: "Upgrade to GPL-3.0 which is compatible with Apache 2.0, or use different dependencies.".to_string(),
            },
            // GPL-2.0-only + GPL-3.0
            ConflictRule {
                license_a_pattern: "GPL-2.0-only".to_string(),
                license_b_pattern: "GPL-3.0".to_string(),
                conflict_type: ConflictType::CopyleftMismatch,
                severity: ConflictSeverity::Error,
                description: "GPL-2.0-only is not compatible with GPL-3.0. The 'only' designation prevents upgrading to later versions.".to_string(),
                remediation: "Replace GPL-2.0-only components with GPL-2.0-or-later or GPL-3.0 compatible versions.".to_string(),
            },
            // LGPL static linking
            ConflictRule {
                license_a_pattern: "LGPL".to_string(),
                license_b_pattern: "Proprietary".to_string(),
                conflict_type: ConflictType::BinaryIncompatible,
                severity: ConflictSeverity::Warning,
                description: "LGPL allows proprietary use only through dynamic linking. Static linking requires LGPL compliance.".to_string(),
                remediation: "Ensure LGPL dependencies are dynamically linked, or comply with LGPL requirements for static linking.".to_string(),
            },
            // AGPL network copyleft warning
            ConflictRule {
                license_a_pattern: "AGPL".to_string(),
                license_b_pattern: "*".to_string(), // Any other license
                conflict_type: ConflictType::NetworkCopyleft,
                severity: ConflictSeverity::Warning,
                description: "AGPL requires source disclosure for network services. Any service using AGPL code must provide source access.".to_string(),
                remediation: "Ensure compliance with AGPL source distribution requirements, or replace with non-AGPL alternatives.".to_string(),
            },
            // BSD-4-Clause advertising
            ConflictRule {
                license_a_pattern: "BSD-4-Clause".to_string(),
                license_b_pattern: "GPL".to_string(),
                conflict_type: ConflictType::ProjectIncompatible,
                severity: ConflictSeverity::Error,
                description: "BSD-4-Clause's advertising clause is incompatible with GPL. The FSF considers this a non-free addition.".to_string(),
                remediation: "Replace BSD-4-Clause components with BSD-3-Clause or other GPL-compatible licenses.".to_string(),
            },
            // CDDL + GPL
            ConflictRule {
                license_a_pattern: "CDDL".to_string(),
                license_b_pattern: "GPL".to_string(),
                conflict_type: ConflictType::BinaryIncompatible,
                severity: ConflictSeverity::Error,
                description: "CDDL and GPL have incompatible copyleft requirements. Both require derivative works under their respective licenses.".to_string(),
                remediation: "Use separate binaries for CDDL and GPL code, or replace one set of dependencies.".to_string(),
            },
            // MPL-1.1 + GPL
            ConflictRule {
                license_a_pattern: "MPL-1.1".to_string(),
                license_b_pattern: "GPL".to_string(),
                conflict_type: ConflictType::CopyleftMismatch,
                severity: ConflictSeverity::Warning,
                description: "MPL 1.1 has file-level copyleft which may conflict with GPL's broader copyleft.".to_string(),
                remediation: "Use MPL 2.0 which has explicit GPL compatibility, or keep MPL code in separate files.".to_string(),
            },
            // EPL + GPL
            ConflictRule {
                license_a_pattern: "EPL".to_string(),
                license_b_pattern: "GPL".to_string(),
                conflict_type: ConflictType::BinaryIncompatible,
                severity: ConflictSeverity::Error,
                description: "Eclipse Public License and GPL have incompatible copyleft terms.".to_string(),
                remediation: "Use EPL-2.0 with Secondary License option for GPL compatibility, or use separate binaries.".to_string(),
            },
        ]
    }

    /// Check if a license matches a pattern
    fn matches_pattern(&self, license: &str, pattern: &str) -> bool {
        if pattern == "*" {
            return true;
        }

        let license_upper = license.to_uppercase();
        let pattern_upper = pattern.to_uppercase();

        // Direct match
        if license_upper == pattern_upper {
            return true;
        }

        // Contains match (e.g., "GPL" matches "GPL-3.0", "AGPL-3.0")
        if license_upper.contains(&pattern_upper) {
            return true;
        }

        // Handle SPDX expressions with variations
        let license_normalized = license_upper
            .replace("-ONLY", "")
            .replace("-OR-LATER", "")
            .replace('+', "");

        license_normalized.contains(&pattern_upper)
    }

    /// Detect conflicts in a set of licenses
    pub(crate) fn detect_conflicts(
        &self,
        license_map: &HashMap<String, Vec<String>>, // license -> components
    ) -> Vec<DetectedConflict> {
        let mut conflicts = Vec::new();
        let licenses: Vec<&String> = license_map.keys().collect();

        // Check all pairs of licenses
        for i in 0..licenses.len() {
            for j in (i + 1)..licenses.len() {
                let license_a = licenses[i];
                let license_b = licenses[j];

                // Check against all rules
                for rule in &self.rules {
                    let a_matches_a = self.matches_pattern(license_a, &rule.license_a_pattern);
                    let b_matches_b = self.matches_pattern(license_b, &rule.license_b_pattern);
                    let a_matches_b = self.matches_pattern(license_a, &rule.license_b_pattern);
                    let b_matches_a = self.matches_pattern(license_b, &rule.license_a_pattern);

                    // Check both orderings
                    if (a_matches_a && b_matches_b) || (a_matches_b && b_matches_a) {
                        // Skip if pattern B is "*" and checking same license
                        if rule.license_b_pattern == "*" && license_a == license_b {
                            continue;
                        }

                        // Collect affected components
                        let mut affected = Vec::new();
                        if let Some(comps) = license_map.get(license_a) {
                            affected.extend(comps.clone());
                        }
                        if let Some(comps) = license_map.get(license_b) {
                            affected.extend(comps.clone());
                        }
                        affected.sort();
                        affected.dedup();

                        conflicts.push(DetectedConflict {
                            rule: rule.clone(),
                            license_a: license_a.clone(),
                            license_b: license_b.clone(),
                            affected_components: affected,
                            context: ConflictContext::SameProject,
                        });
                    }
                }
            }
        }

        // Sort by severity (errors first)
        conflicts.sort_by(|a, b| b.rule.severity.cmp(&a.rule.severity));

        conflicts
    }

}

impl Default for ConflictDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_matching() {
        let detector = ConflictDetector::new();

        assert!(detector.matches_pattern("GPL-3.0", "GPL"));
        assert!(detector.matches_pattern("AGPL-3.0-or-later", "AGPL"));
        assert!(detector.matches_pattern("Apache-2.0", "Apache-2.0"));
        assert!(detector.matches_pattern("MIT", "*"));
        assert!(!detector.matches_pattern("MIT", "GPL"));
    }

    #[test]
    fn test_gpl_proprietary_conflict() {
        let detector = ConflictDetector::new();

        let mut license_map = HashMap::new();
        license_map.insert("GPL-3.0".to_string(), vec!["dep1".to_string()]);
        license_map.insert("Proprietary".to_string(), vec!["main".to_string()]);

        let conflicts = detector.detect_conflicts(&license_map);

        assert!(!conflicts.is_empty());
        assert_eq!(conflicts[0].rule.conflict_type, ConflictType::BinaryIncompatible);
        assert_eq!(conflicts[0].rule.severity, ConflictSeverity::Error);
    }

    #[test]
    fn test_apache_gpl2_conflict() {
        let detector = ConflictDetector::new();

        let mut license_map = HashMap::new();
        license_map.insert("Apache-2.0".to_string(), vec!["lib1".to_string()]);
        license_map.insert("GPL-2.0".to_string(), vec!["lib2".to_string()]);

        let conflicts = detector.detect_conflicts(&license_map);

        assert!(!conflicts.is_empty());
        let patent_conflict = conflicts
            .iter()
            .find(|c| c.rule.conflict_type == ConflictType::PatentConflict);
        assert!(patent_conflict.is_some());
    }

    #[test]
    fn test_no_conflicts() {
        let detector = ConflictDetector::new();

        let mut license_map = HashMap::new();
        license_map.insert("MIT".to_string(), vec!["lib1".to_string()]);
        license_map.insert("Apache-2.0".to_string(), vec!["lib2".to_string()]);
        license_map.insert("BSD-3-Clause".to_string(), vec!["lib3".to_string()]);

        let conflicts = detector.detect_conflicts(&license_map);

        assert!(conflicts.is_empty());
    }

}
