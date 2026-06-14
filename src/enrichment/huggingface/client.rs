//! HuggingFace Hub model-info enrichment client with caching support.
//!
//! Resolves `MachineLearningModel` components to a HuggingFace model id (via a
//! `pkg:huggingface/...` PURL or a `huggingface.co` model-card URL), fetches
//! `GET /api/models/{id}?blobs=true`, and maps only high-confidence fields onto
//! the component:
//!
//! - `siblings[].lfs.sha256` → component `hashes` (feeds integrity scoring /
//!   AI-010 and `verify --model-dir`),
//! - `pipeline_tag`           → `MlModelInfo.task`,
//! - `lastModified`           → a `StalenessInfo` signal,
//! - `license`                → declared license, **only when none is declared**.
//!
//! The freeform `cardData` YAML is intentionally never scraped, and quantization
//! is not inferred (the API does not reliably expose it).

use super::api::HfModelInfo;
use crate::enrichment::source::{JsonCache, namespaced_cache_dir};
use crate::enrichment::stats::EnrichmentError;
use crate::model::{
    Component, ComponentType, Hash, HashAlgorithm, LicenseExpression, StalenessInfo,
};
use std::path::PathBuf;
use std::time::Duration;

/// Default HuggingFace Hub API base URL (no trailing slash).
pub const HUGGINGFACE_API_URL: &str = "https://huggingface.co";

/// Filesystem-safe cache file name for a model id (`org/name` → `org_name.json`).
fn cache_filename(model_id: &str) -> String {
    let safe = model_id.replace(['/', ':', '@'], "_");
    format!("{safe}.json")
}

/// HuggingFace enrichment client configuration.
#[derive(Debug, Clone)]
pub struct HuggingFaceConfig {
    /// Cache directory.
    pub cache_dir: PathBuf,
    /// Cache time-to-live.
    pub cache_ttl: Duration,
    /// API base URL (test seam; defaults to [`HUGGINGFACE_API_URL`]).
    pub api_url: String,
    /// Request timeout.
    pub timeout: Duration,
    /// Bypass cache and fetch fresh data.
    pub bypass_cache: bool,
}

impl Default for HuggingFaceConfig {
    fn default() -> Self {
        Self {
            cache_dir: default_cache_dir(),
            // Model metadata is stable; a week keeps the API quiet.
            cache_ttl: Duration::from_secs(7 * 24 * 3600),
            api_url: HUGGINGFACE_API_URL.to_string(),
            timeout: Duration::from_secs(30),
            bypass_cache: false,
        }
    }
}

fn default_cache_dir() -> PathBuf {
    namespaced_cache_dir("huggingface")
}

/// HuggingFace enrichment statistics.
#[derive(Debug, Default, Clone)]
pub struct HuggingFaceEnrichmentStats {
    /// ML components inspected.
    pub models_checked: usize,
    /// Components successfully resolved to a HuggingFace model id.
    pub models_resolved: usize,
    /// Components enriched with at least one mapped field.
    pub models_enriched: usize,
    /// Weight hashes injected across all components.
    pub hashes_added: usize,
    /// Components that received a `task` from `pipeline_tag`.
    pub tasks_added: usize,
    /// Components that received a synthesized `pkg:huggingface` PURL (resolved
    /// via a model-card URL but lacking a PURL), making them resolvable to
    /// `Ecosystem::HuggingFace` for vulnerability enrichment.
    pub purls_added: usize,
    /// Components that received a license (only when none was declared).
    pub licenses_added: usize,
    /// API calls performed (cache misses).
    pub api_calls: usize,
    /// Cache hits.
    pub cache_hits: usize,
    /// Non-fatal per-component errors.
    pub errors: Vec<String>,
}

/// HuggingFace Hub enrichment client.
pub struct HuggingFaceClient {
    config: HuggingFaceConfig,
}

impl HuggingFaceClient {
    /// Create a new client.
    #[must_use]
    pub const fn new(config: HuggingFaceConfig) -> Self {
        Self { config }
    }

    /// Create with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(HuggingFaceConfig::default())
    }

    /// Open the shared file cache for model-info payloads.
    fn cache(&self) -> Result<JsonCache<HfModelInfo>, EnrichmentError> {
        JsonCache::new(self.config.cache_dir.clone(), self.config.cache_ttl)
            .map_err(|e| EnrichmentError::CacheError(e.to_string()))
    }

    /// Load model info from disk cache.
    fn load_from_cache(&self, model_id: &str) -> Option<HfModelInfo> {
        if self.config.bypass_cache {
            return None;
        }
        self.cache().ok()?.get_named(&cache_filename(model_id))
    }

    /// Save model info to disk cache.
    fn save_to_cache(&self, model_id: &str, info: &HfModelInfo) -> Result<(), EnrichmentError> {
        self.cache()?
            .set_named(&cache_filename(model_id), info)
            .map_err(|e| EnrichmentError::CacheError(e.to_string()))
    }

    /// Fetch model info from the HuggingFace API.
    #[cfg(feature = "enrichment")]
    fn fetch_from_api(&self, model_id: &str) -> Result<Option<HfModelInfo>, EnrichmentError> {
        let url = format!(
            "{}/api/models/{model_id}?blobs=true",
            self.config.api_url.trim_end_matches('/')
        );

        let client = crate::enrichment::source::http_client(self.config.timeout)
            .map_err(|e| EnrichmentError::ApiError(e.to_string()))?;

        // `get_with_retry` applies the offline guard up front and the shared
        // 429/Retry-After backoff policy.
        let response = crate::enrichment::source::get_with_retry(&client, &url, 3)
            .map_err(|e| EnrichmentError::ApiError(e.to_string()))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            // A private/removed model is not an error — just no enrichment.
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(EnrichmentError::ApiError(format!(
                "HuggingFace API returned status {}",
                response.status()
            )));
        }

        // Bound the body before buffering it so a hostile endpoint cannot OOM us.
        let bytes = crate::enrichment::source::read_bounded(response)
            .map_err(|e| EnrichmentError::ApiError(e.to_string()))?;

        let info: HfModelInfo = serde_json::from_slice(&bytes)
            .map_err(|e| EnrichmentError::ParseError(e.to_string()))?;
        Ok(Some(info))
    }

    /// Fetch model info (stub for non-enrichment builds).
    #[cfg(not(feature = "enrichment"))]
    fn fetch_from_api(&self, _model_id: &str) -> Result<Option<HfModelInfo>, EnrichmentError> {
        Err(EnrichmentError::ApiError(
            "Enrichment feature not enabled".to_string(),
        ))
    }

    /// Resolve model info for a model id, consulting the cache first.
    fn resolve(
        &self,
        model_id: &str,
        stats: &mut HuggingFaceEnrichmentStats,
    ) -> Result<Option<HfModelInfo>, EnrichmentError> {
        if let Some(cached) = self.load_from_cache(model_id) {
            stats.cache_hits += 1;
            return Ok(Some(cached));
        }
        stats.api_calls += 1;
        let info = self.fetch_from_api(model_id)?;
        if let Some(ref info) = info {
            let _ = self.save_to_cache(model_id, info);
        }
        Ok(info)
    }

    /// Enrich the `MachineLearningModel` components of an SBOM in place.
    ///
    /// Non-ML components are skipped. Components that cannot be resolved to a
    /// HuggingFace model id are skipped. Per-component fetch failures are
    /// recorded in `stats.errors` and do not abort the run.
    pub fn enrich_components(
        &mut self,
        components: &mut [Component],
    ) -> Result<HuggingFaceEnrichmentStats, EnrichmentError> {
        let mut stats = HuggingFaceEnrichmentStats::default();

        for component in components.iter_mut() {
            if component.component_type != ComponentType::MachineLearningModel {
                continue;
            }
            stats.models_checked += 1;

            let Some(model_id) = resolve_model_id(component) else {
                continue;
            };
            stats.models_resolved += 1;

            // Ensure a `pkg:huggingface/...` PURL is present so the component is
            // resolvable to `Ecosystem::HuggingFace` and routed through the
            // vulnerability/exploitability enrichment stack (OSV PURL query +
            // KEV/advisory linkage). When the model was resolved only via a
            // model-card URL it has no PURL; synthesize one from the model id.
            if ensure_huggingface_purl(component, &model_id) {
                stats.purls_added += 1;
            }

            let info = match self.resolve(&model_id, &mut stats) {
                Ok(Some(info)) => info,
                Ok(None) => continue,
                Err(e) => {
                    stats.errors.push(format!("{model_id}: {e}"));
                    continue;
                }
            };

            if apply_model_info(component, &info, &mut stats) {
                stats.models_enriched += 1;
            }
        }

        Ok(stats)
    }
}

/// Resolve a HuggingFace model id (`{org}/{name}`) for a component.
///
/// Preference order:
/// 1. a `pkg:huggingface/{org}/{name}[@version]` PURL,
/// 2. a `huggingface.co/{org}/{name}` model-card URL (from `MlModelInfo` or an
///    external reference).
#[must_use]
pub fn resolve_model_id(component: &Component) -> Option<String> {
    if let Some(purl) = &component.identifiers.purl
        && let Some(id) = model_id_from_purl(purl)
    {
        return Some(id);
    }

    // Model-card URL recorded on the ML metadata.
    if let Some(ml) = &component.ml_model
        && let Some(url) = &ml.model_card_url
        && let Some(id) = model_id_from_hf_url(url)
    {
        return Some(id);
    }

    // Any external reference pointing at huggingface.co.
    component
        .external_refs
        .iter()
        .find_map(|r| model_id_from_hf_url(&r.url))
}

/// Ensure the component carries a `pkg:huggingface/{model_id}` PURL.
///
/// Returns `true` if a PURL was synthesized. A component already carrying any
/// PURL is left untouched (we never overwrite an existing identifier). The
/// synthesized PURL makes the component resolvable to `Ecosystem::HuggingFace`,
/// routing it through the OSV/KEV exploitability enrichment stack.
fn ensure_huggingface_purl(component: &mut Component, model_id: &str) -> bool {
    if component.identifiers.purl.is_some() {
        return false;
    }
    component.set_purl(format!("pkg:huggingface/{model_id}"));
    true
}

/// Extract `{org}/{name}` from a `pkg:huggingface/...` PURL.
///
/// Handles `pkg:huggingface/org/name@rev`, `pkg:huggingface/name@rev`, and
/// strips any qualifiers/subpath (`?...` / `#...`).
#[must_use]
fn model_id_from_purl(purl: &str) -> Option<String> {
    let rest = purl.strip_prefix("pkg:huggingface/")?;
    // Drop qualifiers (`?a=b`) and subpath (`#frag`).
    let rest = rest.split(['?', '#']).next().unwrap_or(rest);
    // Drop the version (`@rev`) from the LAST path segment only.
    let (path, _version) = rest.rsplit_once('@').map_or((rest, ""), |(p, v)| (p, v));
    let path = path.trim_matches('/');
    if path.is_empty() {
        return None;
    }
    Some(path.to_string())
}

/// Extract `{org}/{name}` from a `huggingface.co` URL.
#[must_use]
fn model_id_from_hf_url(url: &str) -> Option<String> {
    // Normalize: strip scheme and a leading `www.`.
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let without_scheme = without_scheme
        .strip_prefix("www.")
        .unwrap_or(without_scheme);
    let rest = without_scheme.strip_prefix("huggingface.co/")?;

    let rest = rest.split(['?', '#']).next().unwrap_or(rest);
    let segments: Vec<&str> = rest.trim_matches('/').split('/').collect();
    // HuggingFace model URLs are `/{org}/{name}` or canonical `/{name}`. Anything
    // under a known non-model namespace (datasets/spaces/etc.) is not a model.
    match segments.as_slice() {
        [name] if !name.is_empty() => Some((*name).to_string()),
        [org, name, ..]
            if !org.is_empty()
                && !name.is_empty()
                && !matches!(*org, "datasets" | "spaces" | "models" | "api") =>
        {
            Some(format!("{org}/{name}"))
        }
        _ => None,
    }
}

/// Apply the mapped HuggingFace fields onto a component, returning whether any
/// field was changed.
fn apply_model_info(
    component: &mut Component,
    info: &HfModelInfo,
    stats: &mut HuggingFaceEnrichmentStats,
) -> bool {
    let mut changed = false;

    // 1. Weight hashes (integrity / AI-010). De-dupe against existing hashes so a
    //    re-run is idempotent.
    for sha in info.weight_sha256s() {
        let hash = Hash::new(HashAlgorithm::Sha256, sha.to_lowercase());
        if !component.hashes.contains(&hash) {
            component.hashes.push(hash);
            stats.hashes_added += 1;
            changed = true;
        }
    }

    // 2. pipeline_tag → task (only fills an empty task).
    if let Some(tag) = &info.pipeline_tag
        && !tag.is_empty()
    {
        let ml = component
            .ml_model
            .get_or_insert_with(crate::model::MlModelInfo::default);
        if ml.task.is_none() {
            ml.task = Some(tag.clone());
            stats.tasks_added += 1;
            changed = true;
        }
    }

    // 3. lastModified → staleness signal (only when not already populated).
    if component.staleness.is_none()
        && let Some(ts) = &info.last_modified
        && let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts)
    {
        component.staleness = Some(StalenessInfo::from_date(dt.with_timezone(&chrono::Utc)));
        changed = true;
    }

    // 4. license → declared license ONLY WHEN ABSENT (never overwrite).
    if component.licenses.declared.is_empty()
        && let Some(license) = &info.license
        && !license.is_empty()
    {
        component
            .licenses
            .declared
            .push(LicenseExpression::new(license.clone()));
        stats.licenses_added += 1;
        changed = true;
    }

    changed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ExternalRefType, ExternalReference, MlModelInfo};

    fn ml_component(purl: Option<&str>) -> Component {
        let mut c = Component::new("bert".to_string(), "ml-1".to_string());
        c.component_type = ComponentType::MachineLearningModel;
        if let Some(p) = purl {
            c = c.with_purl(p.to_string());
        }
        c
    }

    #[test]
    fn resolve_id_from_purl_with_org_and_version() {
        let c = ml_component(Some("pkg:huggingface/google-bert/bert-base-uncased@abc123"));
        assert_eq!(
            resolve_model_id(&c).as_deref(),
            Some("google-bert/bert-base-uncased")
        );
    }

    #[test]
    fn resolve_id_from_purl_canonical_no_org() {
        let c = ml_component(Some("pkg:huggingface/gpt2"));
        assert_eq!(resolve_model_id(&c).as_deref(), Some("gpt2"));
    }

    #[test]
    fn resolve_id_from_purl_strips_qualifiers() {
        let c = ml_component(Some("pkg:huggingface/org/name@v1?download=true"));
        assert_eq!(resolve_model_id(&c).as_deref(), Some("org/name"));
    }

    #[test]
    fn resolve_id_from_model_card_url() {
        let mut c = ml_component(None);
        c.ml_model = Some(MlModelInfo {
            model_card_url: Some(
                "https://huggingface.co/google-bert/bert-base-uncased".to_string(),
            ),
            ..MlModelInfo::default()
        });
        assert_eq!(
            resolve_model_id(&c).as_deref(),
            Some("google-bert/bert-base-uncased")
        );
    }

    #[test]
    fn resolve_id_from_external_ref() {
        let mut c = ml_component(None);
        c.external_refs.push(ExternalReference {
            ref_type: ExternalRefType::ModelCard,
            url: "https://huggingface.co/distilbert/distilbert-base-uncased".to_string(),
            comment: None,
            hashes: Vec::new(),
        });
        assert_eq!(
            resolve_model_id(&c).as_deref(),
            Some("distilbert/distilbert-base-uncased")
        );
    }

    #[test]
    fn dataset_and_spaces_urls_are_not_models() {
        assert!(model_id_from_hf_url("https://huggingface.co/datasets/squad").is_none());
        assert!(model_id_from_hf_url("https://huggingface.co/spaces/foo/bar").is_none());
        assert!(model_id_from_hf_url("https://example.com/foo/bar").is_none());
    }

    #[test]
    fn non_ml_component_resolves_nothing_useful() {
        let mut c = Component::new("lib".to_string(), "lib-1".to_string())
            .with_purl("pkg:npm/lodash@4.17.21".to_string());
        c.component_type = ComponentType::Library;
        assert!(resolve_model_id(&c).is_none());
    }

    #[test]
    fn apply_maps_hashes_task_license_and_staleness() {
        let mut c = ml_component(Some("pkg:huggingface/org/name"));
        let info: HfModelInfo = serde_json::from_str(
            r#"{
                "pipeline_tag": "text-classification",
                "lastModified": "2020-01-01T00:00:00.000Z",
                "license": "mit",
                "siblings": [
                    { "rfilename": "model.safetensors", "lfs": { "sha256": "AABB" } }
                ]
            }"#,
        )
        .unwrap();

        let mut stats = HuggingFaceEnrichmentStats::default();
        assert!(apply_model_info(&mut c, &info, &mut stats));

        // sha256 lower-cased and added as a SHA-256 hash.
        assert_eq!(c.hashes.len(), 1);
        assert_eq!(c.hashes[0].algorithm, HashAlgorithm::Sha256);
        assert_eq!(c.hashes[0].value, "aabb");
        // pipeline_tag → task.
        assert_eq!(
            c.ml_model.as_ref().unwrap().task.as_deref(),
            Some("text-classification")
        );
        // license applied when none declared.
        assert_eq!(c.licenses.declared.len(), 1);
        assert_eq!(c.licenses.declared[0].expression, "mit");
        // staleness derived from an old lastModified.
        assert!(c.staleness.is_some());
        assert_eq!(stats.hashes_added, 1);
        assert_eq!(stats.tasks_added, 1);
        assert_eq!(stats.licenses_added, 1);
    }

    #[test]
    fn apply_never_overwrites_declared_license_or_task() {
        let mut c = ml_component(Some("pkg:huggingface/org/name"));
        c.licenses
            .declared
            .push(LicenseExpression::new("Apache-2.0".to_string()));
        c.ml_model = Some(MlModelInfo {
            task: Some("nlp".to_string()),
            ..MlModelInfo::default()
        });

        let info: HfModelInfo =
            serde_json::from_str(r#"{ "pipeline_tag": "image-classification", "license": "mit" }"#)
                .unwrap();

        let mut stats = HuggingFaceEnrichmentStats::default();
        apply_model_info(&mut c, &info, &mut stats);

        // Declared license preserved.
        assert_eq!(c.licenses.declared.len(), 1);
        assert_eq!(c.licenses.declared[0].expression, "Apache-2.0");
        // Existing task preserved.
        assert_eq!(c.ml_model.as_ref().unwrap().task.as_deref(), Some("nlp"));
        assert_eq!(stats.licenses_added, 0);
        assert_eq!(stats.tasks_added, 0);
    }

    #[test]
    fn ensure_purl_synthesizes_from_model_card_url() {
        use crate::model::Ecosystem;
        // Model resolved via a model-card URL, no PURL.
        let mut c = ml_component(None);
        c.ml_model = Some(MlModelInfo {
            model_card_url: Some(
                "https://huggingface.co/google-bert/bert-base-uncased".to_string(),
            ),
            ..MlModelInfo::default()
        });
        let model_id = resolve_model_id(&c).expect("resolvable via URL");

        assert!(ensure_huggingface_purl(&mut c, &model_id));
        assert_eq!(
            c.identifiers.purl.as_deref(),
            Some("pkg:huggingface/google-bert/bert-base-uncased")
        );
        // The synthesized PURL must resolve to the HuggingFace ecosystem so the
        // component is routed through vulnerability enrichment.
        assert_eq!(c.ecosystem, Some(Ecosystem::HuggingFace));
    }

    #[test]
    fn ensure_purl_never_overwrites_existing() {
        let mut c = ml_component(Some("pkg:huggingface/org/name@v1"));
        assert!(!ensure_huggingface_purl(&mut c, "org/name"));
        assert_eq!(
            c.identifiers.purl.as_deref(),
            Some("pkg:huggingface/org/name@v1"),
            "an existing PURL must be preserved verbatim"
        );
    }

    #[test]
    fn apply_is_idempotent_for_hashes() {
        let mut c = ml_component(Some("pkg:huggingface/org/name"));
        let info: HfModelInfo = serde_json::from_str(
            r#"{ "siblings": [ { "rfilename": "m.bin", "lfs": { "sha256": "abcd" } } ] }"#,
        )
        .unwrap();

        let mut stats = HuggingFaceEnrichmentStats::default();
        apply_model_info(&mut c, &info, &mut stats);
        apply_model_info(&mut c, &info, &mut stats);
        assert_eq!(c.hashes.len(), 1, "the same hash must not be added twice");
    }
}
