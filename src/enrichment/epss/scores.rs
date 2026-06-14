//! FIRST EPSS (Exploit Prediction Scoring System) data structures.
//!
//! EPSS assigns every CVE a probability (0..1) that it will be exploited in the
//! wild over the next 30 days, plus a percentile rank within the dataset. It is
//! a triage signal complementary to CISA KEV: KEV says "exploited", EPSS says
//! "how likely to be exploited".

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A single EPSS scoring entry for one CVE.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct EpssEntry {
    /// Probability of exploitation in the next 30 days (0.0 - 1.0).
    pub score: f64,
    /// Percentile rank of this score within the dataset (0.0 - 1.0).
    pub percentile: f64,
}

/// In-memory EPSS dataset indexed by CVE ID for fast lookups.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpssScores {
    /// Entries indexed by normalized CVE ID.
    entries: HashMap<String, EpssEntry>,
    /// Score date from the dataset header (e.g. `2024-01-15`), if parsed.
    pub score_date: Option<String>,
    /// Model version from the dataset header (e.g. `v2023.03.01`), if parsed.
    pub model_version: Option<String>,
}

impl EpssScores {
    /// Create an empty dataset.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            score_date: None,
            model_version: None,
        }
    }

    /// Parse the FIRST EPSS CSV body.
    ///
    /// The body has the shape:
    /// ```text
    /// #model_version:v2023.03.01,score_date:2024-01-15T00:00:00+0000
    /// cve,epss,percentile
    /// CVE-2024-0001,0.00042,0.10024
    /// ...
    /// ```
    /// The leading `#`-comment line and the `cve,epss,percentile` header row are
    /// both skipped; remaining lines are split on the fixed 3-column format.
    #[must_use]
    pub fn from_csv(body: &str) -> Self {
        let mut entries = HashMap::new();
        let mut score_date = None;
        let mut model_version = None;

        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // The metadata comment line, e.g.
            // "#model_version:v2023.03.01,score_date:2024-01-15T00:00:00+0000"
            if let Some(meta) = line.strip_prefix('#') {
                for field in meta.split(',') {
                    if let Some((key, value)) = field.split_once(':') {
                        match key.trim() {
                            "model_version" => model_version = Some(value.trim().to_string()),
                            "score_date" => score_date = Some(value.trim().to_string()),
                            _ => {}
                        }
                    }
                }
                continue;
            }

            // The column header row.
            if line.eq_ignore_ascii_case("cve,epss,percentile") {
                continue;
            }

            // Fixed 3-column data row: cve,epss,percentile.
            let mut cols = line.split(',');
            let (Some(cve), Some(score), Some(percentile)) =
                (cols.next(), cols.next(), cols.next())
            else {
                continue;
            };
            let (Ok(score), Ok(percentile)) = (
                score.trim().parse::<f64>(),
                percentile.trim().parse::<f64>(),
            ) else {
                continue;
            };
            entries.insert(normalize_cve_id(cve), EpssEntry { score, percentile });
        }

        Self {
            entries,
            score_date,
            model_version,
        }
    }

    /// Look up the EPSS entry for a CVE ID (case-insensitive).
    #[must_use]
    pub fn get(&self, cve_id: &str) -> Option<EpssEntry> {
        self.entries.get(&normalize_cve_id(cve_id)).copied()
    }

    /// Number of CVEs in the dataset.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the dataset is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for EpssScores {
    fn default() -> Self {
        Self::new()
    }
}

/// Normalize a CVE ID for consistent lookup (uppercase, trimmed).
fn normalize_cve_id(cve_id: &str) -> String {
    cve_id.trim().to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_CSV: &str = "\
#model_version:v2023.03.01,score_date:2024-01-15T00:00:00+0000
cve,epss,percentile
CVE-2024-0001,0.00042,0.10024
CVE-2024-0002,0.97331,0.99988
";

    #[test]
    fn parses_comment_and_header() {
        let scores = EpssScores::from_csv(SAMPLE_CSV);
        assert_eq!(scores.len(), 2);
        assert_eq!(scores.model_version.as_deref(), Some("v2023.03.01"));
        assert_eq!(
            scores.score_date.as_deref(),
            Some("2024-01-15T00:00:00+0000")
        );
    }

    #[test]
    fn looks_up_scores_case_insensitively() {
        let scores = EpssScores::from_csv(SAMPLE_CSV);
        let hi = scores.get("cve-2024-0002").expect("entry present");
        assert!((hi.score - 0.97331).abs() < 1e-9);
        assert!((hi.percentile - 0.99988).abs() < 1e-9);
        assert!(scores.get("CVE-2099-9999").is_none());
    }

    #[test]
    fn skips_malformed_rows() {
        let csv = "\
#model_version:v1,score_date:2024-01-15
cve,epss,percentile
CVE-2024-0003,not-a-number,0.5
CVE-2024-0004,0.5
CVE-2024-0005,0.12345,0.54321
";
        let scores = EpssScores::from_csv(csv);
        assert_eq!(scores.len(), 1);
        assert!(scores.get("CVE-2024-0005").is_some());
    }
}
