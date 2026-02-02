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
        OsvQuery::Purl {
            package: OsvPackagePurl { purl },
        }
    }

    /// Create a package-based query.
    pub fn from_package(name: String, ecosystem: String, version: String) -> Self {
        OsvQuery::Package {
            package: OsvPackageInfo { name, ecosystem },
            version,
        }
    }
}
