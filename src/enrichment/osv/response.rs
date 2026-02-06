//! OSV API response types.
//!
//! These types model the OSV API response format.
//! See: https://google.github.io/osv.dev/api/

use serde::{Deserialize, Serialize};

/// OSV batch query request.
#[derive(Debug, Clone, Serialize)]
pub struct OsvBatchRequest {
    pub queries: Vec<OsvQuery>,
}

/// Individual OSV query.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum OsvQuery {
    /// Query by PURL
    Purl {
        #[serde(rename = "package")]
        package: OsvPackagePurl,
    },
    /// Query by package name, ecosystem, and version
    Package {
        #[serde(rename = "package")]
        package: OsvPackageInfo,
        version: String,
    },
}

/// Package info with PURL.
#[derive(Debug, Clone, Serialize)]
pub struct OsvPackagePurl {
    pub purl: String,
}

/// Package info with name and ecosystem.
#[derive(Debug, Clone, Serialize)]
pub struct OsvPackageInfo {
    pub name: String,
    pub ecosystem: String,
}

/// OSV batch query response.
#[derive(Debug, Clone, Deserialize)]
pub struct OsvBatchResponse {
    pub results: Vec<OsvBatchResult>,
}

/// Result for a single query in batch.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct OsvBatchResult {
    #[serde(default)]
    pub vulns: Vec<OsvVulnerability>,
}

/// OSV vulnerability entry.
#[derive(Debug, Clone, Deserialize)]
pub struct OsvVulnerability {
    /// Vulnerability ID (e.g., "GHSA-xxx", "CVE-xxx")
    pub id: String,

    /// Brief summary
    #[serde(default)]
    pub summary: Option<String>,

    /// Detailed description
    #[serde(default)]
    pub details: Option<String>,

    /// Aliases (e.g., CVE IDs)
    #[serde(default)]
    pub aliases: Vec<String>,

    /// Publication date
    #[serde(default)]
    pub published: Option<String>,

    /// Last modification date
    #[serde(default)]
    pub modified: Option<String>,

    /// Severity information
    #[serde(default)]
    pub severity: Vec<OsvSeverity>,

    /// Affected packages and versions
    #[serde(default)]
    pub affected: Vec<OsvAffected>,

    /// References
    #[serde(default)]
    pub references: Vec<OsvReference>,

    /// Database-specific fields
    #[serde(default)]
    pub database_specific: Option<serde_json::Value>,
}

/// OSV severity information.
#[derive(Debug, Clone, Deserialize)]
pub struct OsvSeverity {
    /// Severity type (e.g., "CVSS_V3")
    #[serde(rename = "type")]
    pub severity_type: String,

    /// Score or vector string
    pub score: String,
}

/// OSV affected package information.
#[derive(Debug, Clone, Deserialize)]
pub struct OsvAffected {
    /// Package information
    #[serde(default)]
    pub package: Option<OsvAffectedPackage>,

    /// Affected version ranges
    #[serde(default)]
    pub ranges: Vec<OsvRange>,

    /// Specific affected versions
    #[serde(default)]
    pub versions: Vec<String>,

    /// Ecosystem-specific info
    #[serde(default)]
    pub ecosystem_specific: Option<serde_json::Value>,

    /// Database-specific info
    #[serde(default)]
    pub database_specific: Option<serde_json::Value>,
}

/// Package in affected section.
#[derive(Debug, Clone, Deserialize)]
pub struct OsvAffectedPackage {
    pub name: String,
    pub ecosystem: String,
    #[serde(default)]
    pub purl: Option<String>,
}

/// Version range in affected section.
#[derive(Debug, Clone, Deserialize)]
pub struct OsvRange {
    /// Range type (e.g., "SEMVER", "ECOSYSTEM", "GIT")
    #[serde(rename = "type")]
    pub range_type: String,

    /// Events defining the range
    #[serde(default)]
    pub events: Vec<OsvRangeEvent>,
}

/// Event in a version range.
#[derive(Debug, Clone, Deserialize)]
pub struct OsvRangeEvent {
    #[serde(default)]
    pub introduced: Option<String>,
    #[serde(default)]
    pub fixed: Option<String>,
    #[serde(default)]
    pub last_affected: Option<String>,
    #[serde(default)]
    pub limit: Option<String>,
}

/// Reference link.
#[derive(Debug, Clone, Deserialize)]
pub struct OsvReference {
    /// Reference type
    #[serde(rename = "type")]
    pub ref_type: String,

    /// URL
    pub url: String,
}

impl OsvQuery {
    /// Create a PURL-based query.
    pub fn from_purl(purl: String) -> Self {
        Self::Purl {
            package: OsvPackagePurl { purl },
        }
    }

    /// Create a package-based query.
    pub fn from_package(name: String, ecosystem: String, version: String) -> Self {
        Self::Package {
            package: OsvPackageInfo { name, ecosystem },
            version,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_osv_query_from_purl() {
        let query = OsvQuery::from_purl("pkg:npm/lodash@4.17.21".into());
        match &query {
            OsvQuery::Purl { package } => {
                assert_eq!(package.purl, "pkg:npm/lodash@4.17.21");
            }
            OsvQuery::Package { .. } => panic!("Expected Purl variant"),
        }
        // Verify it serializes correctly
        let json = serde_json::to_string(&query).unwrap();
        assert!(json.contains("pkg:npm/lodash@4.17.21"));
    }

    #[test]
    fn test_osv_query_from_package() {
        let query = OsvQuery::from_package("lodash".into(), "npm".into(), "4.17.21".into());
        match &query {
            OsvQuery::Package { package, version } => {
                assert_eq!(package.name, "lodash");
                assert_eq!(package.ecosystem, "npm");
                assert_eq!(version, "4.17.21");
            }
            OsvQuery::Purl { .. } => panic!("Expected Package variant"),
        }
    }

    #[test]
    fn test_osv_batch_response_deser() {
        let json = r#"{
            "results": [
                {
                    "vulns": [
                        {
                            "id": "GHSA-test-1234",
                            "summary": "Test vulnerability",
                            "aliases": ["CVE-2024-0001"],
                            "severity": [{"type": "CVSS_V3", "score": "7.5"}],
                            "affected": []
                        }
                    ]
                }
            ]
        }"#;
        let response: OsvBatchResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.results.len(), 1);
        assert_eq!(response.results[0].vulns.len(), 1);
        assert_eq!(response.results[0].vulns[0].id, "GHSA-test-1234");
        assert_eq!(
            response.results[0].vulns[0].summary.as_deref(),
            Some("Test vulnerability")
        );
        assert_eq!(response.results[0].vulns[0].aliases, vec!["CVE-2024-0001"]);
    }

    #[test]
    fn test_osv_batch_response_empty() {
        let json = r#"{"results": [{"vulns": []}, {}]}"#;
        let response: OsvBatchResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.results.len(), 2);
        assert!(response.results[0].vulns.is_empty());
        assert!(response.results[1].vulns.is_empty());
    }

    #[test]
    fn test_osv_vulnerability_deser() {
        let json = r#"{
            "id": "CVE-2024-0001",
            "summary": "Buffer overflow",
            "details": "A buffer overflow in...",
            "published": "2024-01-15T00:00:00Z",
            "modified": "2024-01-20T00:00:00Z",
            "references": [{"type": "WEB", "url": "https://example.com"}]
        }"#;
        let vuln: OsvVulnerability = serde_json::from_str(json).unwrap();
        assert_eq!(vuln.id, "CVE-2024-0001");
        assert_eq!(vuln.details.as_deref(), Some("A buffer overflow in..."));
        assert_eq!(vuln.references.len(), 1);
        assert_eq!(vuln.references[0].ref_type, "WEB");
    }

    #[test]
    fn test_osv_severity_deser() {
        let json = r#"{
            "id": "TEST-001",
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
                {"type": "CVSS_V2", "score": "10.0"}
            ]
        }"#;
        let vuln: OsvVulnerability = serde_json::from_str(json).unwrap();
        assert_eq!(vuln.severity.len(), 2);
        assert_eq!(vuln.severity[0].severity_type, "CVSS_V3");
        assert_eq!(vuln.severity[1].score, "10.0");
    }

    #[test]
    fn test_osv_affected_deser() {
        let json = r#"{
            "id": "TEST-002",
            "affected": [{
                "package": {"name": "lodash", "ecosystem": "npm", "purl": "pkg:npm/lodash"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
                "versions": ["4.17.20", "4.17.19"]
            }]
        }"#;
        let vuln: OsvVulnerability = serde_json::from_str(json).unwrap();
        assert_eq!(vuln.affected.len(), 1);
        let affected = &vuln.affected[0];
        assert_eq!(affected.package.as_ref().unwrap().name, "lodash");
        assert_eq!(affected.ranges.len(), 1);
        assert_eq!(affected.ranges[0].events.len(), 2);
        assert_eq!(affected.ranges[0].events[0].introduced.as_deref(), Some("0"));
        assert_eq!(
            affected.ranges[0].events[1].fixed.as_deref(),
            Some("4.17.21")
        );
        assert_eq!(affected.versions.len(), 2);
    }

    #[test]
    fn test_osv_batch_result_default() {
        let result = OsvBatchResult::default();
        assert!(result.vulns.is_empty());
    }
}
