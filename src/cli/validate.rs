//! Validate command handler.
//!
//! Implements the `validate` subcommand for validating SBOMs against compliance standards.

use crate::model::{CreatorType, ExternalRefType, HashAlgorithm, NormalizedSbom, Severity};
use crate::pipeline::{parse_sbom_with_context, write_output, OutputTarget};
use crate::quality::{ComplianceChecker, ComplianceLevel, ComplianceResult, ViolationSeverity};
use crate::reports::{generate_compliance_sarif, ReportFormat};
use anyhow::{bail, Result};
use std::collections::HashSet;
use std::path::PathBuf;

/// Run the validate command
pub fn run_validate(
    sbom_path: PathBuf,
    standard: String,
    output: ReportFormat,
    output_file: Option<PathBuf>,
) -> Result<()> {
    let parsed = parse_sbom_with_context(&sbom_path, false)?;

    match standard.to_lowercase().as_str() {
        "ntia" => validate_ntia_elements(parsed.sbom())?,
        "fda" => validate_fda_elements(parsed.sbom())?,
        "cra" => {
            let checker = ComplianceChecker::new(ComplianceLevel::CraPhase2);
            let result = checker.check(parsed.sbom());
            write_compliance_output(&result, output, output_file)?;
        }
        _ => {
            bail!("Unknown validation standard: {standard}");
        }
    }

    Ok(())
}

fn write_compliance_output(
    result: &ComplianceResult,
    output: ReportFormat,
    output_file: Option<PathBuf>,
) -> Result<()> {
    let target = OutputTarget::from_option(output_file);

    let content = match output {
        ReportFormat::Json => serde_json::to_string_pretty(result)
            .map_err(|e| anyhow::anyhow!("Failed to serialize compliance JSON: {e}"))?,
        ReportFormat::Sarif => generate_compliance_sarif(result)?,
        _ => format_compliance_text(result),
    };

    write_output(&content, &target, false)?;
    Ok(())
}

fn format_compliance_text(result: &ComplianceResult) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "Compliance ({})",
        result.level.name()
    ));
    lines.push(format!(
        "Status: {} ({} errors, {} warnings, {} info)",
        if result.is_compliant {
            "COMPLIANT"
        } else {
            "NON-COMPLIANT"
        },
        result.error_count,
        result.warning_count,
        result.info_count
    ));
    lines.push(String::new());

    if result.violations.is_empty() {
        lines.push("No violations found.".to_string());
        return lines.join("\n");
    }

    for v in &result.violations {
        let severity = match v.severity {
            ViolationSeverity::Error => "ERROR",
            ViolationSeverity::Warning => "WARN",
            ViolationSeverity::Info => "INFO",
        };
        let element = v.element.as_deref().unwrap_or("-");
        lines.push(format!(
            "[{}] {} | {} | {}",
            severity,
            v.category.name(),
            v.requirement,
            element
        ));
        lines.push(format!("  {}", v.message));
    }

    lines.join("\n")
}

/// Validate SBOM against NTIA minimum elements
pub fn validate_ntia_elements(sbom: &NormalizedSbom) -> Result<()> {
    let mut issues = Vec::new();

    // Check document-level requirements
    if sbom.document.creators.is_empty() {
        issues.push("Missing author/creator information");
    }

    // Check component-level requirements
    for (_id, comp) in &sbom.components {
        if comp.name.is_empty() {
            issues.push("Component missing name");
        }
        if comp.version.is_none() {
            tracing::warn!("Component '{}' missing version", comp.name);
        }
        if comp.supplier.is_none() {
            tracing::warn!("Component '{}' missing supplier", comp.name);
        }
        if comp.identifiers.purl.is_none()
            && comp.identifiers.cpe.is_empty()
            && comp.identifiers.swid.is_none()
        {
            tracing::warn!(
                "Component '{}' missing unique identifier (PURL/CPE/SWID)",
                comp.name
            );
        }
    }

    if sbom.edges.is_empty() && sbom.component_count() > 1 {
        issues.push("Missing dependency relationships");
    }

    if issues.is_empty() {
        tracing::info!("SBOM passes NTIA minimum elements validation");
        println!("NTIA Validation: PASSED");
    } else {
        tracing::warn!("SBOM has {} NTIA validation issues", issues.len());
        println!("NTIA Validation: FAILED");
        for issue in &issues {
            println!("  - {issue}");
        }
    }

    Ok(())
}

/// FDA validation issue severity
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
enum FdaSeverity {
    Error,   // Must fix - will likely cause FDA rejection
    Warning, // Should fix - may cause FDA questions
    Info,    // Recommendation for improvement
}

impl std::fmt::Display for FdaSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Error => write!(f, "ERROR"),
            Self::Warning => write!(f, "WARNING"),
            Self::Info => write!(f, "INFO"),
        }
    }
}

/// FDA validation issue
struct FdaIssue {
    severity: FdaSeverity,
    category: &'static str,
    message: String,
}

/// Validate SBOM against FDA medical device requirements
pub fn validate_fda_elements(sbom: &NormalizedSbom) -> Result<()> {
    let mut issues: Vec<FdaIssue> = Vec::new();

    // Document-level requirements
    validate_fda_document(sbom, &mut issues);

    // Component-level requirements
    let component_stats = validate_fda_components(sbom, &mut issues);

    // Relationship requirements
    validate_fda_relationships(sbom, &mut issues);

    // Vulnerability information
    validate_fda_vulnerabilities(sbom, &mut issues);

    // Output results
    output_fda_results(sbom, &mut issues, &component_stats);

    Ok(())
}

/// Component validation statistics
struct ComponentStats {
    total: usize,
    without_version: usize,
    without_supplier: usize,
    without_hash: usize,
    without_strong_hash: usize,
    without_identifier: usize,
    without_support_info: usize,
}

fn validate_fda_document(sbom: &NormalizedSbom, issues: &mut Vec<FdaIssue>) {
    // Manufacturer/Author Information
    if sbom.document.creators.is_empty() {
        issues.push(FdaIssue {
            severity: FdaSeverity::Error,
            category: "Document",
            message: "Missing SBOM author/manufacturer information".to_string(),
        });
    } else {
        let has_org = sbom
            .document
            .creators
            .iter()
            .any(|c| c.creator_type == CreatorType::Organization);
        if !has_org {
            issues.push(FdaIssue {
                severity: FdaSeverity::Warning,
                category: "Document",
                message: "No organization/manufacturer listed as SBOM creator".to_string(),
            });
        }

        let has_contact = sbom.document.creators.iter().any(|c| c.email.is_some());
        if !has_contact {
            issues.push(FdaIssue {
                severity: FdaSeverity::Warning,
                category: "Document",
                message: "No contact email provided for SBOM creators".to_string(),
            });
        }
    }

    // SBOM Name/Title
    if sbom.document.name.is_none() {
        issues.push(FdaIssue {
            severity: FdaSeverity::Warning,
            category: "Document",
            message: "Missing SBOM document name/title".to_string(),
        });
    }

    // Serial Number/Namespace
    if sbom.document.serial_number.is_none() {
        issues.push(FdaIssue {
            severity: FdaSeverity::Warning,
            category: "Document",
            message: "Missing SBOM serial number or document namespace".to_string(),
        });
    }
}

fn validate_fda_components(sbom: &NormalizedSbom, issues: &mut Vec<FdaIssue>) -> ComponentStats {
    let mut stats = ComponentStats {
        total: sbom.component_count(),
        without_version: 0,
        without_supplier: 0,
        without_hash: 0,
        without_strong_hash: 0,
        without_identifier: 0,
        without_support_info: 0,
    };

    for (_id, comp) in &sbom.components {
        if comp.name.is_empty() {
            issues.push(FdaIssue {
                severity: FdaSeverity::Error,
                category: "Component",
                message: "Component has empty name".to_string(),
            });
        }

        if comp.version.is_none() {
            stats.without_version += 1;
        }

        if comp.supplier.is_none() {
            stats.without_supplier += 1;
        }

        if comp.hashes.is_empty() {
            stats.without_hash += 1;
        } else {
            let has_strong_hash = comp.hashes.iter().any(|h| {
                matches!(
                    h.algorithm,
                    HashAlgorithm::Sha256
                        | HashAlgorithm::Sha384
                        | HashAlgorithm::Sha512
                        | HashAlgorithm::Sha3_256
                        | HashAlgorithm::Sha3_384
                        | HashAlgorithm::Sha3_512
                        | HashAlgorithm::Blake2b256
                        | HashAlgorithm::Blake2b384
                        | HashAlgorithm::Blake2b512
                        | HashAlgorithm::Blake3
                )
            });
            if !has_strong_hash {
                stats.without_strong_hash += 1;
            }
        }

        if comp.identifiers.purl.is_none()
            && comp.identifiers.cpe.is_empty()
            && comp.identifiers.swid.is_none()
        {
            stats.without_identifier += 1;
        }

        let has_support_info = comp.external_refs.iter().any(|r| {
            matches!(
                r.ref_type,
                ExternalRefType::Support
                    | ExternalRefType::Website
                    | ExternalRefType::SecurityContact
                    | ExternalRefType::Advisories
            )
        });
        if !has_support_info {
            stats.without_support_info += 1;
        }
    }

    // Add component issues
    if stats.without_version > 0 {
        issues.push(FdaIssue {
            severity: FdaSeverity::Error,
            category: "Component",
            message: format!(
                "{}/{} components missing version information",
                stats.without_version, stats.total
            ),
        });
    }

    if stats.without_supplier > 0 {
        issues.push(FdaIssue {
            severity: FdaSeverity::Error,
            category: "Component",
            message: format!(
                "{}/{} components missing supplier/manufacturer information",
                stats.without_supplier, stats.total
            ),
        });
    }

    if stats.without_hash > 0 {
        issues.push(FdaIssue {
            severity: FdaSeverity::Error,
            category: "Component",
            message: format!(
                "{}/{} components missing cryptographic hash",
                stats.without_hash, stats.total
            ),
        });
    }

    if stats.without_strong_hash > 0 {
        issues.push(FdaIssue {
            severity: FdaSeverity::Warning,
            category: "Component",
            message: format!(
                "{}/{} components have only weak hash algorithms (MD5/SHA-1). FDA recommends SHA-256 or stronger",
                stats.without_strong_hash, stats.total
            ),
        });
    }

    if stats.without_identifier > 0 {
        issues.push(FdaIssue {
            severity: FdaSeverity::Error,
            category: "Component",
            message: format!(
                "{}/{} components missing unique identifier (PURL/CPE/SWID)",
                stats.without_identifier, stats.total
            ),
        });
    }

    if stats.without_support_info > 0 && stats.total > 0 {
        let percentage = (stats.without_support_info as f64 / stats.total as f64) * 100.0;
        if percentage > 50.0 {
            issues.push(FdaIssue {
                severity: FdaSeverity::Info,
                category: "Component",
                message: format!(
                    "{}/{} components ({:.0}%) lack support/contact information",
                    stats.without_support_info, stats.total, percentage
                ),
            });
        }
    }

    stats
}

fn validate_fda_relationships(sbom: &NormalizedSbom, issues: &mut Vec<FdaIssue>) {
    let total = sbom.component_count();

    if sbom.edges.is_empty() && total > 1 {
        issues.push(FdaIssue {
            severity: FdaSeverity::Error,
            category: "Dependency",
            message: format!(
                "No dependency relationships defined for {total} components"
            ),
        });
    }

    // Check for orphan components
    if !sbom.edges.is_empty() {
        let mut connected: HashSet<String> = HashSet::new();
        for edge in &sbom.edges {
            connected.insert(edge.from.value().to_string());
            connected.insert(edge.to.value().to_string());
        }
        let orphan_count = sbom
            .components
            .keys()
            .filter(|id| !connected.contains(id.value()))
            .count();

        if orphan_count > 0 && orphan_count < total {
            issues.push(FdaIssue {
                severity: FdaSeverity::Warning,
                category: "Dependency",
                message: format!(
                    "{orphan_count}/{total} components have no dependency relationships (orphaned)"
                ),
            });
        }
    }
}

fn validate_fda_vulnerabilities(sbom: &NormalizedSbom, issues: &mut Vec<FdaIssue>) {
    let vuln_info = sbom.all_vulnerabilities();
    if !vuln_info.is_empty() {
        let critical_vulns = vuln_info
            .iter()
            .filter(|(_, v)| matches!(v.severity, Some(Severity::Critical)))
            .count();
        let high_vulns = vuln_info
            .iter()
            .filter(|(_, v)| matches!(v.severity, Some(Severity::High)))
            .count();

        if critical_vulns > 0 || high_vulns > 0 {
            issues.push(FdaIssue {
                severity: FdaSeverity::Warning,
                category: "Security",
                message: format!(
                    "SBOM contains {critical_vulns} critical and {high_vulns} high severity vulnerabilities"
                ),
            });
        }
    }
}

fn output_fda_results(sbom: &NormalizedSbom, issues: &mut [FdaIssue], _stats: &ComponentStats) {
    // Sort issues by severity
    issues.sort_by(|a, b| a.severity.cmp(&b.severity));

    let error_count = issues
        .iter()
        .filter(|i| i.severity == FdaSeverity::Error)
        .count();
    let warning_count = issues
        .iter()
        .filter(|i| i.severity == FdaSeverity::Warning)
        .count();
    let info_count = issues
        .iter()
        .filter(|i| i.severity == FdaSeverity::Info)
        .count();

    // Print header
    println!();
    println!("===================================================================");
    println!("  FDA Medical Device SBOM Validation Report");
    println!("===================================================================");
    println!();

    // Print summary
    println!(
        "SBOM: {}",
        sbom.document.name.as_deref().unwrap_or("(unnamed)")
    );
    println!(
        "Format: {} {}",
        sbom.document.format, sbom.document.format_version
    );
    println!("Components: {}", sbom.component_count());
    println!("Dependencies: {}", sbom.edges.len());
    println!();

    // Print issues
    if issues.is_empty() {
        println!("PASSED - SBOM meets FDA premarket submission requirements");
        println!();
    } else {
        if error_count > 0 {
            println!(
                "FAILED - {error_count} error(s), {warning_count} warning(s), {info_count} info"
            );
        } else {
            println!(
                "PASSED with warnings - {warning_count} warning(s), {info_count} info"
            );
        }
        println!();

        // Group by category
        let categories: Vec<&str> = issues
            .iter()
            .map(|i| i.category)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        for category in categories {
            println!("--- {category} ---");
            for issue in issues.iter().filter(|i| i.category == category) {
                let symbol = match issue.severity {
                    FdaSeverity::Error => "X",
                    FdaSeverity::Warning => "!",
                    FdaSeverity::Info => "i",
                };
                println!("  {} [{}] {}", symbol, issue.severity, issue.message);
            }
            println!();
        }
    }

    // Print FDA reference
    println!("-------------------------------------------------------------------");
    println!("Reference: FDA \"Cybersecurity in Medical Devices\" Guidance (2023)");
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fda_severity_order() {
        assert!(FdaSeverity::Error < FdaSeverity::Warning);
        assert!(FdaSeverity::Warning < FdaSeverity::Info);
    }

    #[test]
    fn test_fda_severity_display() {
        assert_eq!(format!("{}", FdaSeverity::Error), "ERROR");
        assert_eq!(format!("{}", FdaSeverity::Warning), "WARNING");
        assert_eq!(format!("{}", FdaSeverity::Info), "INFO");
    }

    #[test]
    fn test_validate_empty_sbom() {
        let sbom = NormalizedSbom::default();
        // Should not panic
        let _ = validate_ntia_elements(&sbom);
    }

    #[test]
    fn test_fda_document_validation() {
        let sbom = NormalizedSbom::default();
        let mut issues = Vec::new();
        validate_fda_document(&sbom, &mut issues);
        // Should find missing creator issue
        assert!(!issues.is_empty());
    }
}
