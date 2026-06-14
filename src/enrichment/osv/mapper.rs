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
        severity: extract_severity(&osv.severity)
            .or_else(|| extract_database_severity(osv.database_specific.as_ref())),
        cvss: extract_cvss_scores(&osv.severity),
        affected_versions: extract_affected_versions(&osv.affected),
        remediation: extract_remediation(&osv.affected),
        description: osv.details.clone().or_else(|| osv.summary.clone()),
        cwes: extract_cwes(osv.database_specific.as_ref()),
        published: parse_datetime(osv.published.as_ref()),
        modified: parse_datetime(osv.modified.as_ref()),
        is_kev: false, // Will be enriched by KEV client
        kev_info: None,
        epss_score: None, // Will be enriched by EPSS client
        epss_percentile: None,
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

    // OSV severity entries normally carry the raw vector string
    // (e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    if score_str.starts_with("CVSS:3") {
        return cvss_v3_base_score(score_str);
    }

    // Some vectors have /score:X.X at the end
    if score_str.contains('/') {
        // Look for explicit score field
        for part in score_str.split('/') {
            if part.to_lowercase().starts_with("score:")
                && let Ok(score) = part[6..].parse::<f32>()
            {
                return Some(score);
            }
        }
    }

    None
}

/// Compute the CVSS 3.x base score from a vector string.
///
/// Implements the base-score equations from the FIRST CVSS v3.1
/// specification (section 7.1), including the Roundup function from
/// Appendix A. CVSS v3.0 vectors use the same equations.
fn cvss_v3_base_score(vector: &str) -> Option<f32> {
    let mut metrics = std::collections::HashMap::new();
    for part in vector.split('/').skip(1) {
        let (name, value) = part.split_once(':')?;
        metrics.insert(name, value);
    }
    let metric = |name: &str| metrics.get(name).copied();

    let scope_changed = match metric("S")? {
        "C" => true,
        "U" => false,
        _ => return None,
    };
    let attack_vector = match metric("AV")? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => return None,
    };
    let attack_complexity = match metric("AC")? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    let privileges_required = match (metric("PR")?, scope_changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return None,
    };
    let user_interaction = match metric("UI")? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };
    let impact_weight = |value: &str| -> Option<f64> {
        match value {
            "H" => Some(0.56),
            "L" => Some(0.22),
            "N" => Some(0.0),
            _ => None,
        }
    };
    let conf = impact_weight(metric("C")?)?;
    let integ = impact_weight(metric("I")?)?;
    let avail = impact_weight(metric("A")?)?;

    let iss = 1.0 - (1.0 - conf) * (1.0 - integ) * (1.0 - avail);
    let impact = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15)
    } else {
        6.42 * iss
    };
    if impact <= 0.0 {
        return Some(0.0);
    }

    let exploitability =
        8.22 * attack_vector * attack_complexity * privileges_required * user_interaction;
    let base = if scope_changed {
        1.08 * (impact + exploitability)
    } else {
        impact + exploitability
    };

    Some(round_up(base.min(10.0)) as f32)
}

/// CVSS v3.1 Roundup: smallest value with one decimal place that is equal
/// to or higher than the input (Appendix A of the specification).
fn round_up(value: f64) -> f64 {
    let scaled = (value * 100_000.0).round() as i64;
    if scaled % 10_000 == 0 {
        scaled as f64 / 100_000.0
    } else {
        (scaled / 10_000 + 1) as f64 / 10.0
    }
}

/// Extract a severity label from `database_specific` (e.g. GHSA's "HIGH",
/// Ubuntu's "Medium") when no CVSS-derived severity is available.
fn extract_database_severity(database_specific: Option<&serde_json::Value>) -> Option<Severity> {
    let label = database_specific?.get("severity")?.as_str()?;
    label
        .parse::<Severity>()
        .ok()
        .filter(|severity| *severity != Severity::Unknown)
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
                if let Some(ref introduced) = event.introduced
                    && introduced != "0"
                {
                    versions.push(format!(">= {introduced}"));
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

    fn assert_score(vector: &str, expected: f32) {
        let score = parse_cvss_score(vector).unwrap();
        assert!(
            (score - expected).abs() < 1e-4,
            "{vector}: expected {expected}, got {score}"
        );
    }

    #[test]
    fn test_parse_cvss_v31_vector_scope_unchanged() {
        assert_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8);
        assert_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3);
    }

    #[test]
    fn test_parse_cvss_v31_vector_scope_changed() {
        assert_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4);
        assert_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0);
    }

    #[test]
    fn test_parse_cvss_v30_vector() {
        assert_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8);
    }

    #[test]
    fn test_parse_cvss_v3_vector_zero_impact() {
        assert_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0);
    }

    #[test]
    fn test_parse_cvss_v3_vector_invalid() {
        assert_eq!(
            parse_cvss_score("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            None
        );
        assert_eq!(parse_cvss_score("CVSS:3.1/AV:N/AC:L"), None);
        assert_eq!(
            parse_cvss_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
            None
        );
    }

    #[test]
    fn test_map_vector_severity_and_cvss() {
        let json = r#"{
            "id": "GHSA-test-1234",
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
            ]
        }"#;
        let osv: OsvVulnerability = serde_json::from_str(json).unwrap();
        let vuln = map_osv_to_vulnerability_ref(&osv);
        assert_eq!(vuln.severity, Some(Severity::Critical));
        assert_eq!(vuln.cvss.len(), 1);
        assert!((vuln.cvss[0].base_score - 9.8).abs() < 1e-4);
        assert_eq!(
            vuln.cvss[0].vector.as_deref(),
            Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        );
    }

    #[test]
    fn test_database_specific_severity_fallback() {
        let json = r#"{
            "id": "GHSA-test-5678",
            "database_specific": {"severity": "MODERATE"}
        }"#;
        let osv: OsvVulnerability = serde_json::from_str(json).unwrap();
        let vuln = map_osv_to_vulnerability_ref(&osv);
        assert_eq!(vuln.severity, Some(Severity::Medium));
        assert!(vuln.cvss.is_empty());
    }

    #[test]
    fn test_database_specific_severity_unknown_label() {
        let json = r#"{
            "id": "GHSA-test-9999",
            "database_specific": {"severity": "bogus"}
        }"#;
        let osv: OsvVulnerability = serde_json::from_str(json).unwrap();
        let vuln = map_osv_to_vulnerability_ref(&osv);
        assert_eq!(vuln.severity, None);
    }
}
