//! EOL API client and enricher for the endoflife.date API.

use super::mapping::ProductMapper;
use crate::enrichment::stats::EnrichmentError;
use crate::model::{Component, EolInfo, EolStatus};
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

// ============================================================================
// API response types
// ============================================================================

/// Union type for endoflife.date fields that can be a date string or boolean.
///
/// The API returns `"eol": "2025-04-30"` or `"eol": true` or `"eol": false`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DateOrBool {
    /// A date string (e.g., "2025-04-30")
    Date(String),
    /// A boolean (true = already reached, false = not yet)
    Bool(bool),
}

impl DateOrBool {
    /// Parse as a `NaiveDate`, if the value is a date string.
    #[must_use]
    pub fn as_date(&self) -> Option<NaiveDate> {
        match self {
            Self::Date(s) => NaiveDate::parse_from_str(s, "%Y-%m-%d").ok(),
            Self::Bool(_) => None,
        }
    }

    /// Whether the milestone has been reached.
    ///
    /// - `Bool(true)` → reached
    /// - `Bool(false)` → not reached
    /// - `Date(d)` → reached if date is in the past
    #[must_use]
    pub fn is_reached(&self) -> bool {
        match self {
            Self::Bool(b) => *b,
            Self::Date(s) => {
                if let Ok(date) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
                    let today = chrono::Utc::now().date_naive();
                    date <= today
                } else {
                    false
                }
            }
        }
    }
}

/// A release cycle from the endoflife.date API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EolCycle {
    /// Release cycle identifier (e.g., "3.11", "22")
    pub cycle: String,
    /// Release date of this cycle
    pub release_date: Option<String>,
    /// EOL status/date
    pub eol: DateOrBool,
    /// Latest version in this cycle
    pub latest: Option<String>,
    /// Date of latest release
    pub latest_release_date: Option<String>,
    /// LTS status/date
    pub lts: Option<DateOrBool>,
    /// Active support end status/date
    pub support: Option<DateOrBool>,
    /// Extended support end status/date
    pub extended_support: Option<DateOrBool>,
}

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the EOL client.
#[derive(Debug, Clone)]
pub struct EolClientConfig {
    /// Cache directory for EOL data
    pub cache_dir: PathBuf,
    /// Cache TTL for per-product cycle data
    pub cache_ttl: Duration,
    /// Cache TTL for the product list
    pub product_list_ttl: Duration,
    /// HTTP request timeout
    pub timeout: Duration,
    /// Bypass cache and fetch fresh data
    pub bypass_cache: bool,
    /// Base URL for the API
    pub base_url: String,
}

impl Default for EolClientConfig {
    fn default() -> Self {
        Self {
            cache_dir: default_cache_dir(),
            cache_ttl: Duration::from_secs(24 * 3600),      // 24 hours
            product_list_ttl: Duration::from_secs(7 * 24 * 3600), // 7 days
            timeout: Duration::from_secs(15),
            bypass_cache: false,
            base_url: "https://endoflife.date".to_string(),
        }
    }
}

fn default_cache_dir() -> PathBuf {
    dirs_cache_dir()
        .unwrap_or_else(|| PathBuf::from(".cache"))
        .join("sbom-tools")
        .join("eol")
}

fn dirs_cache_dir() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        std::env::var("HOME")
            .ok()
            .map(|h| PathBuf::from(h).join("Library").join("Caches"))
    }
    #[cfg(target_os = "linux")]
    {
        std::env::var("XDG_CACHE_HOME")
            .ok()
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var("HOME")
                    .ok()
                    .map(|h| PathBuf::from(h).join(".cache"))
            })
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var("LOCALAPPDATA").ok().map(PathBuf::from)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        std::env::var("HOME")
            .ok()
            .map(|h| PathBuf::from(h).join(".cache"))
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Statistics from EOL enrichment.
#[derive(Debug, Default)]
pub struct EolEnrichmentStats {
    /// Number of components checked
    pub components_checked: usize,
    /// Number of components successfully enriched
    pub components_enriched: usize,
    /// Components with EOL status
    pub eol_count: usize,
    /// Components approaching EOL
    pub approaching_eol_count: usize,
    /// Components fully supported
    pub supported_count: usize,
    /// Components in security-only phase
    pub security_only_count: usize,
    /// Components with unknown cycle match
    pub unknown_count: usize,
    /// API calls made
    pub api_calls: usize,
    /// Cache hits
    pub cache_hits: usize,
    /// Errors encountered
    pub errors: Vec<String>,
    /// Skipped (no product mapping)
    pub skipped_count: usize,
}

// ============================================================================
// Client
// ============================================================================

/// HTTP client for the endoflife.date API with file-based caching.
struct EolClient {
    config: EolClientConfig,
}

impl EolClient {
    fn new(config: EolClientConfig) -> Self {
        Self { config }
    }

    /// Fetch the list of all known products.
    #[cfg(feature = "enrichment")]
    fn fetch_product_list(&self, stats: &mut EolEnrichmentStats) -> Result<Vec<String>, EnrichmentError> {
        let cache_key = "eol_products";
        if self.is_cache_valid(cache_key, self.config.product_list_ttl) {
            if let Some(products) = self.load_from_cache::<Vec<String>>(cache_key) {
                stats.cache_hits += 1;
                return Ok(products);
            }
        }

        let url = format!("{}/api/all.json", self.config.base_url);
        let client = reqwest::blocking::Client::builder()
            .timeout(self.config.timeout)
            .build()
            .map_err(|e| EnrichmentError::ApiError(e.to_string()))?;

        stats.api_calls += 1;
        let response = client
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .map_err(|e| EnrichmentError::ApiError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(EnrichmentError::ApiError(format!(
                "endoflife.date API returned {}",
                response.status()
            )));
        }

        let products: Vec<String> = response
            .json()
            .map_err(|e| EnrichmentError::ParseError(e.to_string()))?;

        self.save_to_cache(cache_key, &products)?;
        Ok(products)
    }

    #[cfg(not(feature = "enrichment"))]
    fn fetch_product_list(&self, _stats: &mut EolEnrichmentStats) -> Result<Vec<String>, EnrichmentError> {
        Err(EnrichmentError::ApiError(
            "enrichment feature not enabled".to_string(),
        ))
    }

    /// Fetch release cycles for a product.
    #[cfg(feature = "enrichment")]
    fn fetch_cycles(
        &self,
        product: &str,
        stats: &mut EolEnrichmentStats,
    ) -> Result<Vec<EolCycle>, EnrichmentError> {
        let cache_key = format!("eol_{product}");
        if self.is_cache_valid(&cache_key, self.config.cache_ttl) {
            if let Some(cycles) = self.load_from_cache::<Vec<EolCycle>>(&cache_key) {
                stats.cache_hits += 1;
                return Ok(cycles);
            }
        }

        let url = format!("{}/api/{}.json", self.config.base_url, product);
        let client = reqwest::blocking::Client::builder()
            .timeout(self.config.timeout)
            .build()
            .map_err(|e| EnrichmentError::ApiError(e.to_string()))?;

        stats.api_calls += 1;
        let response = client
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .map_err(|e| EnrichmentError::ApiError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(EnrichmentError::ApiError(format!(
                "endoflife.date API returned {} for product '{product}'",
                response.status()
            )));
        }

        let cycles: Vec<EolCycle> = response
            .json()
            .map_err(|e| EnrichmentError::ParseError(e.to_string()))?;

        self.save_to_cache(&cache_key, &cycles)?;
        Ok(cycles)
    }

    #[cfg(not(feature = "enrichment"))]
    fn fetch_cycles(
        &self,
        _product: &str,
        _stats: &mut EolEnrichmentStats,
    ) -> Result<Vec<EolCycle>, EnrichmentError> {
        Err(EnrichmentError::ApiError(
            "enrichment feature not enabled".to_string(),
        ))
    }

    // ---- Cache helpers ----

    fn cache_file(&self, key: &str) -> PathBuf {
        let safe_key = key.replace(['/', ':'], "_");
        self.config.cache_dir.join(format!("{safe_key}.json"))
    }

    fn is_cache_valid(&self, key: &str, ttl: Duration) -> bool {
        if self.config.bypass_cache {
            return false;
        }
        let cache_path = self.cache_file(key);
        if !cache_path.exists() {
            return false;
        }
        if let Ok(metadata) = fs::metadata(&cache_path) {
            if let Ok(modified) = metadata.modified() {
                if let Ok(elapsed) = SystemTime::now().duration_since(modified) {
                    return elapsed < ttl;
                }
            }
        }
        false
    }

    fn load_from_cache<T: serde::de::DeserializeOwned>(&self, key: &str) -> Option<T> {
        let cache_path = self.cache_file(key);
        let content = fs::read_to_string(&cache_path).ok()?;
        serde_json::from_str(&content).ok()
    }

    fn save_to_cache<T: serde::Serialize>(
        &self,
        key: &str,
        data: &T,
    ) -> Result<(), EnrichmentError> {
        let cache_path = self.cache_file(key);
        if let Some(parent) = cache_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| EnrichmentError::CacheError(e.to_string()))?;
        }
        let content = serde_json::to_string(data)
            .map_err(|e| EnrichmentError::CacheError(e.to_string()))?;
        fs::write(&cache_path, content)
            .map_err(|e| EnrichmentError::CacheError(e.to_string()))?;
        Ok(())
    }
}

// ============================================================================
// Enricher
// ============================================================================

/// Enriches SBOM components with end-of-life information.
pub struct EolEnricher {
    client: EolClient,
    mapper: ProductMapper,
    /// Cache of fetched cycles per product slug
    cycle_cache: HashMap<String, Vec<EolCycle>>,
}

impl EolEnricher {
    /// Create a new EOL enricher.
    ///
    /// Fetches the product list from the API (or cache) and initializes the mapper.
    pub fn new(config: EolClientConfig) -> Result<Self, EnrichmentError> {
        let client = EolClient::new(config);
        let mut stats = EolEnrichmentStats::default();
        let product_list = client.fetch_product_list(&mut stats)?;
        let mapper = ProductMapper::new(product_list);

        Ok(Self {
            client,
            mapper,
            cycle_cache: HashMap::new(),
        })
    }

    /// Enrich components with EOL information.
    pub fn enrich_components(
        &mut self,
        components: &mut [Component],
    ) -> Result<EolEnrichmentStats, EnrichmentError> {
        let mut stats = EolEnrichmentStats::default();

        for component in components.iter_mut() {
            stats.components_checked += 1;

            let resolved = match self.mapper.resolve(component) {
                Some(r) => r,
                None => {
                    stats.skipped_count += 1;
                    continue;
                }
            };

            let cycles = self.get_cycles(&resolved.product, &mut stats)?;
            if cycles.is_empty() {
                stats.skipped_count += 1;
                continue;
            }

            let matched_cycle = match match_cycle(&resolved.version, &cycles) {
                Some(c) => c,
                None => {
                    // Product found but could not match version to a cycle
                    component.eol = Some(EolInfo {
                        status: EolStatus::Unknown,
                        product: resolved.product,
                        cycle: String::new(),
                        eol_date: None,
                        support_end_date: None,
                        is_lts: false,
                        latest_in_cycle: None,
                        latest_release_date: None,
                        days_until_eol: None,
                    });
                    stats.components_enriched += 1;
                    stats.unknown_count += 1;
                    continue;
                }
            };

            let eol_info = compute_eol_info(&resolved.product, matched_cycle);

            match eol_info.status {
                EolStatus::Supported => stats.supported_count += 1,
                EolStatus::SecurityOnly => stats.security_only_count += 1,
                EolStatus::ApproachingEol => stats.approaching_eol_count += 1,
                EolStatus::EndOfLife => stats.eol_count += 1,
                EolStatus::Unknown => stats.unknown_count += 1,
            }

            component.eol = Some(eol_info);
            stats.components_enriched += 1;
        }

        Ok(stats)
    }

    /// Get cycles for a product, using local cache or fetching from API.
    fn get_cycles(
        &mut self,
        product: &str,
        stats: &mut EolEnrichmentStats,
    ) -> Result<Vec<EolCycle>, EnrichmentError> {
        if let Some(cycles) = self.cycle_cache.get(product) {
            return Ok(cycles.clone());
        }

        match self.client.fetch_cycles(product, stats) {
            Ok(cycles) => {
                self.cycle_cache.insert(product.to_string(), cycles.clone());
                Ok(cycles)
            }
            Err(e) => {
                stats.errors.push(format!("{product}: {e}"));
                // Return empty on error rather than failing the whole enrichment
                Ok(vec![])
            }
        }
    }
}

// ============================================================================
// Version-to-cycle matching
// ============================================================================

/// Match a version string to the best release cycle.
///
/// Strategies:
/// 1. Exact match: version == cycle name
/// 2. major.minor match: "3.11.5" → "3.11"
/// 3. major-only match: "22.0.1" → "22"
fn match_cycle<'a>(version: &str, cycles: &'a [EolCycle]) -> Option<&'a EolCycle> {
    // 1. Exact match
    if let Some(cycle) = cycles.iter().find(|c| c.cycle == version) {
        return Some(cycle);
    }

    // Parse version parts
    let parts: Vec<&str> = version.split('.').collect();

    // 2. major.minor match (e.g., "3.11.5" → "3.11")
    if parts.len() >= 2 {
        let major_minor = format!("{}.{}", parts[0], parts[1]);
        if let Some(cycle) = cycles.iter().find(|c| c.cycle == major_minor) {
            return Some(cycle);
        }
    }

    // 3. major-only match (e.g., "22.0.1" → "22")
    if !parts.is_empty() {
        let major = parts[0];
        if let Some(cycle) = cycles.iter().find(|c| c.cycle == major) {
            return Some(cycle);
        }
    }

    None
}

/// Compute EOL status and info from a matched cycle.
fn compute_eol_info(product: &str, cycle: &EolCycle) -> EolInfo {
    let today = chrono::Utc::now().date_naive();
    let eol_date = cycle.eol.as_date();
    let support_end_date = cycle.support.as_ref().and_then(DateOrBool::as_date);
    let latest_release_date = cycle
        .latest_release_date
        .as_ref()
        .and_then(|s| NaiveDate::parse_from_str(s, "%Y-%m-%d").ok());

    let is_lts = cycle
        .lts
        .as_ref()
        .is_some_and(|v| match v {
            DateOrBool::Bool(b) => *b,
            DateOrBool::Date(_) => true, // If there's an LTS date, it's LTS
        });

    let days_until_eol = eol_date.map(|d| (d - today).num_days());

    let status = compute_eol_status(&cycle.eol, cycle.support.as_ref(), days_until_eol);

    EolInfo {
        status,
        product: product.to_string(),
        cycle: cycle.cycle.clone(),
        eol_date,
        support_end_date,
        is_lts,
        latest_in_cycle: cycle.latest.clone(),
        latest_release_date,
        days_until_eol,
    }
}

/// Determine the EOL status from cycle data.
///
/// Priority:
/// 1. `cycle.eol.is_reached()` → `EndOfLife`
/// 2. EOL date within 180 days → `ApproachingEol`
/// 3. `cycle.support.is_reached()` → `SecurityOnly`
/// 4. Otherwise → `Supported`
fn compute_eol_status(
    eol: &DateOrBool,
    support: Option<&DateOrBool>,
    days_until_eol: Option<i64>,
) -> EolStatus {
    // 1. Past EOL
    if eol.is_reached() {
        return EolStatus::EndOfLife;
    }

    // 2. Approaching EOL (within 180 days)
    if let Some(days) = days_until_eol {
        if (0..=180).contains(&days) {
            return EolStatus::ApproachingEol;
        }
    }

    // 3. Active support ended → security-only phase
    if let Some(support) = support {
        if support.is_reached() {
            return EolStatus::SecurityOnly;
        }
    }

    // 4. Fully supported
    EolStatus::Supported
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_date_or_bool_date() {
        let d = DateOrBool::Date("2025-04-30".to_string());
        assert_eq!(
            d.as_date(),
            Some(NaiveDate::from_ymd_opt(2025, 4, 30).unwrap())
        );
    }

    #[test]
    fn test_date_or_bool_bool_true() {
        let d = DateOrBool::Bool(true);
        assert!(d.is_reached());
        assert!(d.as_date().is_none());
    }

    #[test]
    fn test_date_or_bool_bool_false() {
        let d = DateOrBool::Bool(false);
        assert!(!d.is_reached());
    }

    #[test]
    fn test_date_or_bool_past_date() {
        let d = DateOrBool::Date("2020-01-01".to_string());
        assert!(d.is_reached());
    }

    #[test]
    fn test_date_or_bool_future_date() {
        let d = DateOrBool::Date("2099-12-31".to_string());
        assert!(!d.is_reached());
    }

    #[test]
    fn test_date_or_bool_deserialization() {
        let date: DateOrBool = serde_json::from_str("\"2025-04-30\"").unwrap();
        assert!(matches!(date, DateOrBool::Date(_)));

        let bool_true: DateOrBool = serde_json::from_str("true").unwrap();
        assert!(matches!(bool_true, DateOrBool::Bool(true)));

        let bool_false: DateOrBool = serde_json::from_str("false").unwrap();
        assert!(matches!(bool_false, DateOrBool::Bool(false)));
    }

    #[test]
    fn test_eol_cycle_deserialization() {
        let json = r#"{
            "cycle": "3.11",
            "releaseDate": "2022-10-24",
            "eol": "2027-10-31",
            "latest": "3.11.8",
            "latestReleaseDate": "2024-02-06",
            "lts": false,
            "support": "2024-04-01"
        }"#;
        let cycle: EolCycle = serde_json::from_str(json).unwrap();
        assert_eq!(cycle.cycle, "3.11");
        assert_eq!(cycle.latest.as_deref(), Some("3.11.8"));
        assert!(!cycle.eol.is_reached()); // 2027 is in the future
    }

    #[test]
    fn test_match_cycle_exact() {
        let cycles = vec![
            make_cycle("3.12", "2099-12-31"),
            make_cycle("3.11", "2027-10-31"),
            make_cycle("3.10", "2026-10-31"),
        ];
        let matched = match_cycle("3.11", &cycles);
        assert_eq!(matched.unwrap().cycle, "3.11");
    }

    #[test]
    fn test_match_cycle_major_minor() {
        let cycles = vec![
            make_cycle("3.12", "2099-12-31"),
            make_cycle("3.11", "2027-10-31"),
        ];
        let matched = match_cycle("3.11.5", &cycles);
        assert_eq!(matched.unwrap().cycle, "3.11");
    }

    #[test]
    fn test_match_cycle_major_only() {
        let cycles = vec![
            make_cycle("22", "2099-12-31"),
            make_cycle("20", "2026-04-30"),
            make_cycle("18", "2025-04-30"),
        ];
        let matched = match_cycle("22.0.1", &cycles);
        assert_eq!(matched.unwrap().cycle, "22");
    }

    #[test]
    fn test_match_cycle_no_match() {
        let cycles = vec![make_cycle("3.11", "2027-10-31")];
        assert!(match_cycle("4.0.0", &cycles).is_none());
    }

    #[test]
    fn test_compute_eol_status_supported() {
        let status = compute_eol_status(
            &DateOrBool::Date("2099-12-31".to_string()),
            Some(&DateOrBool::Date("2099-06-01".to_string())),
            Some(27000),
        );
        assert_eq!(status, EolStatus::Supported);
    }

    #[test]
    fn test_compute_eol_status_eol() {
        let status = compute_eol_status(
            &DateOrBool::Bool(true),
            None,
            None,
        );
        assert_eq!(status, EolStatus::EndOfLife);
    }

    #[test]
    fn test_compute_eol_status_eol_past_date() {
        let status = compute_eol_status(
            &DateOrBool::Date("2020-01-01".to_string()),
            None,
            Some(-1800),
        );
        assert_eq!(status, EolStatus::EndOfLife);
    }

    #[test]
    fn test_compute_eol_status_approaching() {
        let status = compute_eol_status(
            &DateOrBool::Date("2099-01-01".to_string()), // Won't be reached
            None,
            Some(90), // 90 days until EOL
        );
        assert_eq!(status, EolStatus::ApproachingEol);
    }

    #[test]
    fn test_compute_eol_status_security_only() {
        let status = compute_eol_status(
            &DateOrBool::Date("2099-12-31".to_string()), // Far future EOL
            Some(&DateOrBool::Bool(true)),                // Support ended
            Some(27000),
        );
        assert_eq!(status, EolStatus::SecurityOnly);
    }

    fn make_cycle(cycle: &str, eol: &str) -> EolCycle {
        EolCycle {
            cycle: cycle.to_string(),
            release_date: None,
            eol: DateOrBool::Date(eol.to_string()),
            latest: None,
            latest_release_date: None,
            lts: None,
            support: None,
            extended_support: None,
        }
    }
}
