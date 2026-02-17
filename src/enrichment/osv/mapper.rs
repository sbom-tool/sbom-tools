//! Mapper from OSV responses to internal `VulnerabilityRef`.

use super::response::{OsvAffected, OsvSeverity, OsvVulnerability};
use crate::model::{
    CvssScore, CvssVersion, Remediation, RemediationType, Severity, VulnerabilityRef,
    VulnerabilitySource,
};
use chrono::{DateTime, Utc};

/// Map an OSV vulnerability to our internal `VulnerabilityRef`.
pub fn map_osv_to_vulnerability_ref(osv: &OsvVulnerability) -> VulnerabilityRef {
    VulnerabilityRef {
        id: osv.id.clone(),
        source: VulnerabilitySource::Osv,
        severity: extract_severity(&osv.severity),
        cvss: extract_cvss_scores(&osv.severity),
        affected_versions: extract_affected_versions(&osv.affected),
        remediation: extract_remediation(&osv.affected),
        description: osv.details.clone().or_else(|| osv.summary.clone()),
        cwes: extract_cwes(osv.database_specific.as_ref()),
        published: parse_datetime(osv.published.as_ref()),
        modified: parse_datetime(osv.modified.as_ref()),
        is_kev: false,  // Will be enriched by KEV client
        kev_info: None,
        vex_status: None,
    }
}

/// Extract severity from OSV severity array.
fn extract_severity(severities: &[OsvSeverity]) -> Option<Severity> {
    // Try to find a CVSS score to derive severity
    for sev in severities {
        if let Some(score) = parse_cvss_score(&sev.score) {
            return Some(Severity::from_cvss(score));
        }
    }
    None
}

/// Extract CVSS scores from OSV severity array.
fn extract_cvss_scores(severities: &[OsvSeverity]) -> Vec<CvssScore> {
    severities
        .iter()
        .filter_map(|sev| {
            let version = match sev.severity_type.as_str() {
                "CVSS_V2" => Some(CvssVersion::V2),
                "CVSS_V3" => Some(CvssVersion::V3),
                "CVSS_V31" => Some(CvssVersion::V31),
                "CVSS_V4" => Some(CvssVersion::V4),
                _ => None,
            }?;

            // Score might be a number or a CVSS vector string
            let base_score = parse_cvss_score(&sev.score)?;

            Some(CvssScore {
                version,
                base_score,
                vector: if sev.score.contains(':') {
                    Some(sev.score.clone())
                } else {
                    None
                },
                exploitability_score: None,
                impact_score: None,
            })
        })
        .collect()
}

/// Parse a CVSS score from a string (either numeric or vector).
fn parse_cvss_score(score_str: &str) -> Option<f32> {
    // Try direct numeric parse first
    if let Ok(score) = score_str.parse::<f32>() {
        return Some(score);
    }

    // Try to extract score from CVSS vector string
    // Format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (score at end or calculated)
    // Some vectors have /score:X.X at the end
    if score_str.contains('/') {
        // Look for explicit score field
        for part in score_str.split('/') {
            if part.to_lowercase().starts_with("score:") {
                if let Ok(score) = part[6..].parse::<f32>() {
                    return Some(score);
                }
            }
        }
    }

    None
}

/// Extract affected versions from OSV affected array.
fn extract_affected_versions(affected: &[OsvAffected]) -> Vec<String> {
    let mut versions = Vec::new();

    for aff in affected {
        // Add specific versions
        versions.extend(aff.versions.iter().cloned());

        // Add version ranges as strings
        for range in &aff.ranges {
            for event in &range.events {
                if let Some(ref introduced) = event.introduced {
                    if introduced != "0" {
                        versions.push(format!(">= {introduced}"));
                    }
                }
                if let Some(ref fixed) = event.fixed {
                    versions.push(format!("< {fixed} (fixed)"));
                }
                if let Some(ref last) = event.last_affected {
                    versions.push(format!("<= {last}"));
                }
            }
        }
    }

    versions
}

/// Extract remediation information (fixed version).
fn extract_remediation(affected: &[OsvAffected]) -> Option<Remediation> {
    // Find the first fixed version
    for aff in affected {
        for range in &aff.ranges {
            for event in &range.events {
                if let Some(ref fixed) = event.fixed {
                    return Some(Remediation {
                        remediation_type: RemediationType::Upgrade,
                        description: Some(format!("Upgrade to version {fixed} or later")),
                        fixed_version: Some(fixed.clone()),
                    });
                }
            }
        }
    }
    None
}

/// Extract CWE identifiers from `database_specific`.
fn extract_cwes(database_specific: Option<&serde_json::Value>) -> Vec<String> {
    let mut cwes = Vec::new();

    if let Some(db_specific) = database_specific {
        // Try common patterns for CWE fields
        if let Some(cwe_ids) = db_specific.get("cwe_ids").and_then(|v| v.as_array()) {
            for cwe in cwe_ids {
                if let Some(cwe_str) = cwe.as_str() {
                    cwes.push(cwe_str.to_string());
                }
            }
        }

        // GHSA format
        if let Some(cwes_arr) = db_specific.get("cwes").and_then(|v| v.as_array()) {
            for cwe in cwes_arr {
                if let Some(cwe_id) = cwe.get("cweId").and_then(|v| v.as_str()) {
                    cwes.push(cwe_id.to_string());
                }
            }
        }
    }

    cwes
}

/// Parse a datetime string to `DateTime`<Utc>.
fn parse_datetime(dt_str: Option<&String>) -> Option<DateTime<Utc>> {
    dt_str.map(String::as_str).and_then(|s| {
        // OSV uses RFC 3339 format
        DateTime::parse_from_rfc3339(s)
            .map(|dt| dt.with_timezone(&Utc))
            .ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cvss_score() {
        assert_eq!(parse_cvss_score("7.5"), Some(7.5));
        assert_eq!(parse_cvss_score("10.0"), Some(10.0));
        assert_eq!(parse_cvss_score("invalid"), None);
    }

    #[test]
    fn test_severity_from_score() {
        assert_eq!(Severity::from_cvss(9.5), Severity::Critical);
        assert_eq!(Severity::from_cvss(7.5), Severity::High);
        assert_eq!(Severity::from_cvss(5.0), Severity::Medium);
        assert_eq!(Severity::from_cvss(2.0), Severity::Low);
    }
}
