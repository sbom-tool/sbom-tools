//! VEX (Vulnerability Exploitability eXchange) enrichment.
//!
//! Parses external VEX documents (OpenVEX and CycloneDX VEX formats) and
//! applies VEX status to matching vulnerabilities in an SBOM.

pub(crate) mod cyclonedx_vex;
pub(crate) mod openvex;

use crate::model::{NormalizedSbom, VexStatus};
use cyclonedx_vex::{is_cyclonedx_vex, parse_cyclonedx_vex};
use openvex::{VexParseError, extract_product_purl, parse_openvex, vex_status_from_statement};
use std::collections::HashMap;
use std::path::PathBuf;

/// Statistics from VEX enrichment.
#[derive(Debug, Clone, Default)]
pub struct VexEnrichmentStats {
    /// Number of VEX documents loaded
    pub documents_loaded: usize,
    /// Number of VEX statements parsed
    pub statements_parsed: usize,
    /// Number of vulnerabilities matched to VEX statements
    pub vulns_matched: usize,
    /// Number of components with at least one VEX-enriched vulnerability
    pub components_with_vex: usize,
}

/// VEX enricher that applies external VEX document data to SBOM vulnerabilities.
///
/// Maintains two lookup tables:
/// - `lookup`: keyed by `(vuln_id, purl)` for product-specific VEX
/// - `vuln_only`: keyed by `vuln_id` for statements without product scope
///
/// Later files override earlier entries for the same key.
pub struct VexEnricher {
    /// (vuln_id, purl) -> VexStatus for product-scoped statements
    lookup: HashMap<(String, String), VexStatus>,
    /// vuln_id -> VexStatus for statements with no product filter
    vuln_only: HashMap<String, VexStatus>,
    stats: VexEnrichmentStats,
}

impl VexEnricher {
    /// Load VEX data from one or more VEX files.
    ///
    /// Supports both OpenVEX and CycloneDX VEX formats (auto-detected).
    /// Files are processed in order; later files override earlier entries
    /// for the same `(vuln_id, purl)` key.
    pub fn from_files(paths: &[PathBuf]) -> Result<Self, VexParseError> {
        let mut lookup = HashMap::new();
        let mut vuln_only = HashMap::new();
        let mut documents_loaded = 0;
        let mut statements_parsed = 0;

        for path in paths {
            // Auto-detect format by peeking at file content
            let content = std::fs::read_to_string(path)?;

            if is_cyclonedx_vex(&content) {
                let result = parse_cyclonedx_vex(&content)?;
                documents_loaded += 1;
                statements_parsed += result.statements_parsed;

                // CycloneDX VEX uses bom-ref as key (often a PURL)
                for ((vuln_id, bom_ref), status) in result.scoped {
                    lookup.insert((vuln_id, bom_ref), status);
                }
                for (vuln_id, status) in result.unscoped {
                    vuln_only.insert(vuln_id, status);
                }
            } else {
                // Default: try OpenVEX
                let doc = parse_openvex(&content)?;
                documents_loaded += 1;

                for stmt in &doc.statements {
                    statements_parsed += 1;
                    let vuln_id = &stmt.vulnerability.name;

                    // Skip statements with empty vulnerability names
                    if vuln_id.is_empty() {
                        tracing::warn!("skipping OpenVEX statement with empty vulnerability name");
                        continue;
                    }

                    let status = vex_status_from_statement(stmt);

                    if stmt.products.is_empty() {
                        vuln_only.insert(vuln_id.clone(), status.clone());
                        for alias in &stmt.vulnerability.aliases {
                            vuln_only.insert(alias.clone(), status.clone());
                        }
                    } else {
                        for product in &stmt.products {
                            if let Some(purl) = extract_product_purl(product) {
                                lookup.insert((vuln_id.clone(), purl.to_string()), status.clone());
                                for alias in &stmt.vulnerability.aliases {
                                    lookup
                                        .insert((alias.clone(), purl.to_string()), status.clone());
                                }
                            }
                            // Products without PURLs are skipped — don't promote
                            // scoped statements to global scope, as that could
                            // apply VEX status to unintended components.
                        }
                    }
                }
            }
        }

        Ok(Self {
            lookup,
            vuln_only,
            stats: VexEnrichmentStats {
                documents_loaded,
                statements_parsed,
                ..Default::default()
            },
        })
    }

    /// Get current enrichment statistics.
    #[must_use]
    pub fn stats(&self) -> &VexEnrichmentStats {
        &self.stats
    }

    /// Enrich an SBOM by applying VEX status to matching vulnerabilities.
    ///
    /// Matching priority:
    /// 1. Exact `(vuln_id, component_purl)` match
    /// 2. Vuln-only match (no product scope)
    pub fn enrich_sbom(&mut self, sbom: &mut NormalizedSbom) -> VexEnrichmentStats {
        let mut vulns_matched = 0;
        let mut components_with_vex = 0;

        // Collect keys first to avoid borrow issues
        let comp_keys: Vec<_> = sbom.components.keys().cloned().collect();

        for key in comp_keys {
            let comp = match sbom.components.get_mut(&key) {
                Some(c) => c,
                None => continue,
            };

            let comp_purl = comp.identifiers.purl.clone();
            let mut comp_had_vex = false;

            for vuln in &mut comp.vulnerabilities {
                // Skip if already has VEX status
                if vuln.vex_status.is_some() {
                    comp_had_vex = true;
                    continue;
                }

                // Try (vuln_id, purl) match first
                let matched = comp_purl
                    .as_ref()
                    .and_then(|purl| self.lookup.get(&(vuln.id.clone(), purl.clone())))
                    .cloned()
                    .or_else(|| self.vuln_only.get(&vuln.id).cloned());

                if let Some(status) = matched {
                    vuln.vex_status = Some(status);
                    vulns_matched += 1;
                    comp_had_vex = true;
                }
            }

            if comp_had_vex {
                components_with_vex += 1;
            }
        }

        self.stats.vulns_matched = vulns_matched;
        self.stats.components_with_vex = components_with_vex;
        self.stats.clone()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Component, VexState, VulnerabilityRef, VulnerabilitySource};

    fn make_sbom_with_vulns() -> NormalizedSbom {
        let mut sbom = NormalizedSbom::default();

        // Component with PURL and vulnerability
        let mut comp1 = Component::new("log4j-core".to_string(), "log4j-core@2.14.1".to_string());
        comp1.version = Some("2.14.1".to_string());
        comp1.identifiers.purl =
            Some("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1".to_string());
        comp1.vulnerabilities.push(VulnerabilityRef::new(
            "CVE-2021-44228".to_string(),
            VulnerabilitySource::Osv,
        ));
        sbom.add_component(comp1);

        // Component with vulnerability but no PURL
        let mut comp2 = Component::new("my-lib".to_string(), "my-lib@1.0.0".to_string());
        comp2.version = Some("1.0.0".to_string());
        comp2.vulnerabilities.push(VulnerabilityRef::new(
            "CVE-2024-0001".to_string(),
            VulnerabilitySource::Cve,
        ));
        sbom.add_component(comp2);

        sbom
    }

    #[test]
    fn test_enricher_from_files_with_fixture() {
        let fixture = std::path::PathBuf::from("tests/fixtures/vex/openvex-sample.json");
        if !fixture.exists() {
            // Skip if fixture doesn't exist yet
            return;
        }
        let enricher = VexEnricher::from_files(&[fixture]).expect("should parse");
        assert_eq!(enricher.stats.documents_loaded, 1);
        assert!(enricher.stats.statements_parsed > 0);
    }

    #[test]
    fn test_enricher_match_by_vuln_and_purl() {
        // Build lookup manually
        let mut lookup = HashMap::new();
        lookup.insert(
            (
                "CVE-2021-44228".to_string(),
                "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1".to_string(),
            ),
            VexStatus::new(VexState::NotAffected),
        );

        let mut enricher = VexEnricher {
            lookup,
            vuln_only: HashMap::new(),
            stats: VexEnrichmentStats::default(),
        };

        let mut sbom = make_sbom_with_vulns();
        let stats = enricher.enrich_sbom(&mut sbom);

        assert_eq!(stats.vulns_matched, 1);
        assert_eq!(stats.components_with_vex, 1);

        // Verify the specific vuln got VEX status
        for comp in sbom.components.values() {
            if comp.name == "log4j-core" {
                let vuln = &comp.vulnerabilities[0];
                assert!(vuln.vex_status.is_some());
                assert_eq!(
                    vuln.vex_status.as_ref().unwrap().status,
                    VexState::NotAffected
                );
            }
        }
    }

    #[test]
    fn test_enricher_vuln_only_fallback() {
        let mut vuln_only = HashMap::new();
        vuln_only.insert(
            "CVE-2024-0001".to_string(),
            VexStatus::new(VexState::UnderInvestigation),
        );

        let mut enricher = VexEnricher {
            lookup: HashMap::new(),
            vuln_only,
            stats: VexEnrichmentStats::default(),
        };

        let mut sbom = make_sbom_with_vulns();
        let stats = enricher.enrich_sbom(&mut sbom);

        assert_eq!(stats.vulns_matched, 1);

        for comp in sbom.components.values() {
            if comp.name == "my-lib" {
                let vuln = &comp.vulnerabilities[0];
                assert!(vuln.vex_status.is_some());
                assert_eq!(
                    vuln.vex_status.as_ref().unwrap().status,
                    VexState::UnderInvestigation
                );
            }
        }
    }

    #[test]
    fn test_enricher_no_match() {
        let enricher_lookup = HashMap::new();
        let mut enricher = VexEnricher {
            lookup: enricher_lookup,
            vuln_only: HashMap::new(),
            stats: VexEnrichmentStats::default(),
        };

        let mut sbom = make_sbom_with_vulns();
        let stats = enricher.enrich_sbom(&mut sbom);

        assert_eq!(stats.vulns_matched, 0);
        assert_eq!(stats.components_with_vex, 0);
    }

    #[test]
    fn test_enricher_later_files_override() {
        let mut lookup = HashMap::new();
        let key = (
            "CVE-2021-44228".to_string(),
            "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1".to_string(),
        );

        // First "file" says affected
        lookup.insert(key.clone(), VexStatus::new(VexState::Affected));
        // Override: second "file" says not_affected
        lookup.insert(key, VexStatus::new(VexState::NotAffected));

        let mut enricher = VexEnricher {
            lookup,
            vuln_only: HashMap::new(),
            stats: VexEnrichmentStats::default(),
        };

        let mut sbom = make_sbom_with_vulns();
        enricher.enrich_sbom(&mut sbom);

        for comp in sbom.components.values() {
            if comp.name == "log4j-core" {
                let vuln = &comp.vulnerabilities[0];
                assert_eq!(
                    vuln.vex_status.as_ref().unwrap().status,
                    VexState::NotAffected,
                    "later file should override"
                );
            }
        }
    }

    #[test]
    fn test_enricher_skips_existing_vex() {
        let mut vuln_only = HashMap::new();
        vuln_only.insert(
            "CVE-2021-44228".to_string(),
            VexStatus::new(VexState::Affected),
        );

        let mut enricher = VexEnricher {
            lookup: HashMap::new(),
            vuln_only,
            stats: VexEnrichmentStats::default(),
        };

        let mut sbom = make_sbom_with_vulns();

        // Pre-set VEX on the vuln
        for comp in sbom.components.values_mut() {
            if comp.name == "log4j-core" {
                comp.vulnerabilities[0].vex_status = Some(VexStatus::new(VexState::NotAffected));
            }
        }

        let stats = enricher.enrich_sbom(&mut sbom);

        // Should not overwrite existing VEX
        for comp in sbom.components.values() {
            if comp.name == "log4j-core" {
                assert_eq!(
                    comp.vulnerabilities[0].vex_status.as_ref().unwrap().status,
                    VexState::NotAffected,
                    "should not overwrite existing VEX"
                );
            }
        }
        // The log4j vuln had existing VEX so wasn't "matched" by enricher
        // my-lib CVE-2024-0001 has no VEX and no lookup entry
        assert_eq!(stats.vulns_matched, 0);
    }

    #[test]
    fn test_scoped_match_takes_priority_over_vuln_only() {
        let purl = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1";

        // Scoped says NotAffected
        let mut lookup = HashMap::new();
        lookup.insert(
            ("CVE-2021-44228".to_string(), purl.to_string()),
            VexStatus::new(VexState::NotAffected),
        );

        // vuln_only says Affected (less specific, should lose)
        let mut vuln_only = HashMap::new();
        vuln_only.insert(
            "CVE-2021-44228".to_string(),
            VexStatus::new(VexState::Affected),
        );

        let mut enricher = VexEnricher {
            lookup,
            vuln_only,
            stats: VexEnrichmentStats::default(),
        };

        let mut sbom = make_sbom_with_vulns();
        enricher.enrich_sbom(&mut sbom);

        for comp in sbom.components.values() {
            if comp.name == "log4j-core" {
                assert_eq!(
                    comp.vulnerabilities[0].vex_status.as_ref().unwrap().status,
                    VexState::NotAffected,
                    "scoped (vuln_id, purl) match should take priority over vuln_only"
                );
            }
        }
    }
}
