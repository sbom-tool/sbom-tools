//! CISA KEV (Known Exploited Vulnerabilities) catalog data structures.

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// CISA KEV catalog response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KevCatalogResponse {
    /// Catalog title
    pub title: String,
    /// Catalog version
    #[serde(rename = "catalogVersion")]
    pub catalog_version: String,
    /// Date catalog was generated
    #[serde(rename = "dateReleased")]
    pub date_released: String,
    /// Total vulnerabilities in catalog
    pub count: usize,
    /// List of vulnerabilities
    pub vulnerabilities: Vec<KevVulnerability>,
}

/// Individual KEV entry from CISA
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KevVulnerability {
    /// CVE ID
    #[serde(rename = "cveID")]
    pub cve_id: String,
    /// Vendor/project name
    #[serde(rename = "vendorProject")]
    pub vendor_project: String,
    /// Product name
    pub product: String,
    /// Vulnerability name
    #[serde(rename = "vulnerabilityName")]
    pub vulnerability_name: String,
    /// Date added to KEV catalog
    #[serde(rename = "dateAdded")]
    pub date_added: String,
    /// Short description
    #[serde(rename = "shortDescription")]
    pub short_description: String,
    /// Required action
    #[serde(rename = "requiredAction")]
    pub required_action: String,
    /// Due date for remediation
    #[serde(rename = "dueDate")]
    pub due_date: String,
    /// Known ransomware campaign use
    #[serde(rename = "knownRansomwareCampaignUse")]
    pub known_ransomware_campaign_use: String,
    /// Notes (optional)
    pub notes: Option<String>,
}

/// Processed KEV entry for internal use
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KevEntry {
    /// CVE ID
    pub cve_id: String,
    /// Vendor/project name
    pub vendor_project: String,
    /// Product name
    pub product: String,
    /// Vulnerability name
    pub vulnerability_name: String,
    /// Date added to KEV catalog
    pub date_added: DateTime<Utc>,
    /// Short description
    pub description: String,
    /// Required action
    pub required_action: String,
    /// Due date for remediation
    pub due_date: DateTime<Utc>,
    /// Whether known to be used in ransomware campaigns
    pub known_ransomware_use: bool,
    /// Additional notes
    pub notes: Option<String>,
}

impl KevEntry {
    /// Create from raw KEV vulnerability
    pub fn from_raw(raw: &KevVulnerability) -> Option<Self> {
        let date_added = parse_kev_date(&raw.date_added)?;
        let due_date = parse_kev_date(&raw.due_date)?;
        let known_ransomware_use = raw.known_ransomware_campaign_use.to_lowercase() == "known";

        Some(Self {
            cve_id: raw.cve_id.clone(),
            vendor_project: raw.vendor_project.clone(),
            product: raw.product.clone(),
            vulnerability_name: raw.vulnerability_name.clone(),
            date_added,
            description: raw.short_description.clone(),
            required_action: raw.required_action.clone(),
            due_date,
            known_ransomware_use,
            notes: raw.notes.clone(),
        })
    }

    /// Check if remediation is overdue
    pub fn is_overdue(&self) -> bool {
        Utc::now() > self.due_date
    }

    /// Days until due date (negative if overdue)
    pub fn days_until_due(&self) -> i64 {
        (self.due_date - Utc::now()).num_days()
    }
}

/// In-memory KEV catalog for fast lookups
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KevCatalog {
    /// Entries indexed by CVE ID
    entries: HashMap<String, KevEntry>,
    /// Catalog version
    pub version: String,
    /// When the catalog was last updated
    pub last_updated: DateTime<Utc>,
    /// Total count of entries
    pub count: usize,
}

impl KevCatalog {
    /// Create an empty catalog
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            version: String::new(),
            last_updated: Utc::now(),
            count: 0,
        }
    }

    /// Create from catalog response
    pub fn from_response(response: KevCatalogResponse) -> Self {
        let mut entries = HashMap::new();

        for vuln in &response.vulnerabilities {
            if let Some(entry) = KevEntry::from_raw(vuln) {
                entries.insert(entry.cve_id.clone(), entry);
            }
        }

        let count = entries.len();

        Self {
            entries,
            version: response.catalog_version,
            last_updated: Utc::now(),
            count,
        }
    }

    /// Check if a CVE ID is in the KEV catalog
    pub fn contains(&self, cve_id: &str) -> bool {
        // Normalize the CVE ID for lookup
        let normalized = normalize_cve_id(cve_id);
        self.entries.contains_key(&normalized)
    }

    /// Get entry for a CVE ID
    pub fn get(&self, cve_id: &str) -> Option<&KevEntry> {
        let normalized = normalize_cve_id(cve_id);
        self.entries.get(&normalized)
    }

    /// Check if CVE is known to be used in ransomware
    pub fn is_ransomware_related(&self, cve_id: &str) -> bool {
        self.get(cve_id)
            .is_some_and(|e| e.known_ransomware_use)
    }

    /// Get all ransomware-related CVEs
    pub fn ransomware_cves(&self) -> Vec<&KevEntry> {
        self.entries
            .values()
            .filter(|e| e.known_ransomware_use)
            .collect()
    }

    /// Get all overdue CVEs
    pub fn overdue_cves(&self) -> Vec<&KevEntry> {
        self.entries.values().filter(|e| e.is_overdue()).collect()
    }

    /// Get all entries
    pub fn all_entries(&self) -> impl Iterator<Item = &KevEntry> {
        self.entries.values()
    }

    /// Get entry count
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if catalog is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for KevCatalog {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse KEV date format (YYYY-MM-DD) to DateTime<Utc>
fn parse_kev_date(date_str: &str) -> Option<DateTime<Utc>> {
    NaiveDate::parse_from_str(date_str, "%Y-%m-%d")
        .ok()
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|dt| DateTime::from_naive_utc_and_offset(dt, Utc))
}

/// Normalize CVE ID for consistent lookup
fn normalize_cve_id(cve_id: &str) -> String {
    cve_id.to_uppercase().trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_kev_date() {
        let date = parse_kev_date("2024-01-15").unwrap();
        assert_eq!(date.format("%Y-%m-%d").to_string(), "2024-01-15");
    }

    #[test]
    fn test_normalize_cve_id() {
        assert_eq!(normalize_cve_id("cve-2024-1234"), "CVE-2024-1234");
        assert_eq!(normalize_cve_id("  CVE-2024-1234  "), "CVE-2024-1234");
    }

    #[test]
    fn test_kev_entry_from_raw() {
        let raw = KevVulnerability {
            cve_id: "CVE-2024-1234".to_string(),
            vendor_project: "Test Vendor".to_string(),
            product: "Test Product".to_string(),
            vulnerability_name: "Test Vuln".to_string(),
            date_added: "2024-01-01".to_string(),
            short_description: "Test description".to_string(),
            required_action: "Apply patch".to_string(),
            due_date: "2024-02-01".to_string(),
            known_ransomware_campaign_use: "Known".to_string(),
            notes: None,
        };

        let entry = KevEntry::from_raw(&raw).unwrap();
        assert_eq!(entry.cve_id, "CVE-2024-1234");
        assert!(entry.known_ransomware_use);
    }

    #[test]
    fn test_catalog_contains() {
        let mut catalog = KevCatalog::new();
        catalog.entries.insert(
            "CVE-2024-1234".to_string(),
            KevEntry {
                cve_id: "CVE-2024-1234".to_string(),
                vendor_project: "Test".to_string(),
                product: "Test".to_string(),
                vulnerability_name: "Test".to_string(),
                date_added: Utc::now(),
                description: "Test".to_string(),
                required_action: "Test".to_string(),
                due_date: Utc::now(),
                known_ransomware_use: false,
                notes: None,
            },
        );

        assert!(catalog.contains("CVE-2024-1234"));
        assert!(catalog.contains("cve-2024-1234")); // Case insensitive
        assert!(!catalog.contains("CVE-2024-5678"));
    }
}
