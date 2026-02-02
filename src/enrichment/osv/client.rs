//! OSV API HTTP client.

use super::response::{OsvBatchRequest, OsvBatchResponse, OsvQuery};
use crate::error::{EnrichmentErrorKind, Result, SbomDiffError};
use reqwest::blocking::Client;
use std::time::Duration;

/// OSV API client configuration.
#[derive(Debug, Clone)]
pub struct OsvClientConfig {
    /// Base URL for OSV API
    pub api_base: String,
    /// Request timeout
    pub timeout: Duration,
    /// Maximum retries for failed requests
    pub max_retries: u8,
    /// Maximum queries per batch request
    pub batch_size: usize,
}

impl Default for OsvClientConfig {
    fn default() -> Self {
        Self {
            api_base: "https://api.osv.dev".to_string(),
            timeout: Duration::from_secs(30),
            max_retries: 3,
            batch_size: 1000, // OSV API limit
        }
    }
}

/// HTTP client for OSV API.
pub struct OsvClient {
    client: Client,
    config: OsvClientConfig,
}

/// Helper to convert reqwest errors to enrichment errors
fn network_error(msg: &str, err: reqwest::Error) -> SbomDiffError {
    SbomDiffError::enrichment(msg, EnrichmentErrorKind::NetworkError(err.to_string()))
}

/// Helper to create API errors
fn api_error(msg: impl Into<String>) -> SbomDiffError {
    SbomDiffError::enrichment("API request", EnrichmentErrorKind::ApiError(msg.into()))
}

impl OsvClient {
    /// Create a new OSV client.
    pub fn new(config: OsvClientConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(config.timeout)
            .user_agent(concat!(
                env!("CARGO_PKG_NAME"),
                "/",
                env!("CARGO_PKG_VERSION")
            ))
            .build()
            .map_err(|e| network_error("Failed to create HTTP client", e))?;

        Ok(Self { client, config })
    }

    /// Check if the OSV API is available.
    pub fn health_check(&self) -> Result<bool> {
        let url = format!("{}/v1/vulns/OSV-2020-1", self.config.api_base);
        let response = self
            .client
            .get(&url)
            .send()
            .map_err(|e| network_error("Health check request failed", e))?;
        Ok(response.status().is_success() || response.status().as_u16() == 404)
    }

    /// Query vulnerabilities for a batch of packages.
    ///
    /// Automatically handles chunking if queries exceed batch_size.
    pub fn query_batch(&self, queries: &[OsvQuery]) -> Result<Vec<OsvBatchResponse>> {
        if queries.is_empty() {
            return Ok(vec![]);
        }

        let mut results = Vec::new();

        for chunk in queries.chunks(self.config.batch_size) {
            let response = self.query_batch_internal(chunk)?;
            results.push(response);
        }

        Ok(results)
    }

    /// Internal batch query implementation with retries.
    fn query_batch_internal(&self, queries: &[OsvQuery]) -> Result<OsvBatchResponse> {
        let url = format!("{}/v1/querybatch", self.config.api_base);
        let request_body = OsvBatchRequest {
            queries: queries.to_vec(),
        };

        let mut last_error = None;

        for attempt in 0..=self.config.max_retries {
            if attempt > 0 {
                // Exponential backoff: 1s, 2s, 4s, ...
                let delay = Duration::from_secs(1 << (attempt - 1));
                std::thread::sleep(delay);
                tracing::debug!("Retry attempt {} after {:?}", attempt, delay);
            }

            match self.send_batch_request(&url, &request_body) {
                Ok(response) => return Ok(response),
                Err(e) => {
                    tracing::debug!("Batch request attempt {} failed: {}", attempt + 1, e);
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| api_error("Unknown error")))
    }

    /// Send a single batch request.
    fn send_batch_request(
        &self,
        url: &str,
        request_body: &OsvBatchRequest,
    ) -> Result<OsvBatchResponse> {
        let response = self
            .client
            .post(url)
            .json(request_body)
            .send()
            .map_err(|e| network_error("Failed to send batch request", e))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().unwrap_or_default();
            return Err(api_error(format!(
                "OSV API returned error status {}: {}",
                status.as_u16(),
                body
            )));
        }

        let batch_response: OsvBatchResponse = response.json().map_err(|e| {
            SbomDiffError::enrichment(
                "parsing response",
                EnrichmentErrorKind::InvalidResponse(e.to_string()),
            )
        })?;

        Ok(batch_response)
    }

    /// Query a single vulnerability by ID.
    pub fn get_vulnerability(
        &self,
        vuln_id: &str,
    ) -> Result<Option<super::response::OsvVulnerability>> {
        let url = format!("{}/v1/vulns/{}", self.config.api_base, vuln_id);

        let response = self
            .client
            .get(&url)
            .send()
            .map_err(|e| network_error("Failed to fetch vulnerability", e))?;

        if response.status().as_u16() == 404 {
            return Ok(None);
        }

        if !response.status().is_success() {
            return Err(api_error(format!(
                "OSV API returned error status {}",
                response.status().as_u16()
            )));
        }

        let vuln = response.json().map_err(|e| {
            SbomDiffError::enrichment(
                "parsing vulnerability",
                EnrichmentErrorKind::InvalidResponse(e.to_string()),
            )
        })?;

        Ok(Some(vuln))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_config_defaults() {
        let config = OsvClientConfig::default();
        assert_eq!(config.api_base, "https://api.osv.dev");
        assert_eq!(config.batch_size, 1000);
    }

    #[test]
    fn test_query_construction() {
        let query = OsvQuery::from_purl("pkg:npm/lodash@4.17.21".to_string());
        let json = serde_json::to_string(&query).unwrap();
        assert!(json.contains("lodash"));
    }
}
