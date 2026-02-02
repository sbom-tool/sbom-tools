//! SBOM Compliance checking module.
//!
//! Validates SBOMs against format requirements and industry standards.

use crate::model::{NormalizedSbom, SbomFormat};
use serde::{Deserialize, Serialize};

/// CRA enforcement phase
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CraPhase {
    /// Phase 1: Reporting obligations — deadline 11 December 2027
    /// Basic SBOM requirements: product/component identification, manufacturer, version, format
    Phase1,
    /// Phase 2: Full compliance — deadline 11 December 2029
    /// Adds: vulnerability metadata, lifecycle/end-of-support, disclosure policy, EU DoC
    Phase2,
}

impl CraPhase {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Phase1 => "Phase 1 (2027)",
            Self::Phase2 => "Phase 2 (2029)",
        }
    }

    pub fn deadline(&self) -> &'static str {
        match self {
            Self::Phase1 => "11 December 2027",
            Self::Phase2 => "11 December 2029",
        }
    }
}

/// Compliance level/profile
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComplianceLevel {
    /// Minimum viable SBOM (basic identification)
    Minimum,
    /// Standard compliance (recommended fields)
    Standard,
    /// NTIA Minimum Elements compliance
    NtiaMinimum,
    /// EU CRA Phase 1 — Reporting obligations (deadline: 11 Dec 2027)
    CraPhase1,
    /// EU CRA Phase 2 — Full compliance (deadline: 11 Dec 2029)
    CraPhase2,
    /// FDA Medical Device SBOM requirements
    FdaMedicalDevice,
    /// Comprehensive compliance (all recommended fields)
    Comprehensive,
}

impl ComplianceLevel {
    /// Get human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            Self::Minimum => "Minimum",
            Self::Standard => "Standard",
            Self::NtiaMinimum => "NTIA Minimum Elements",
            Self::CraPhase1 => "EU CRA Phase 1 (2027)",
            Self::CraPhase2 => "EU CRA Phase 2 (2029)",
            Self::FdaMedicalDevice => "FDA Medical Device",
            Self::Comprehensive => "Comprehensive",
        }
    }

    /// Get description of what this level checks
    pub fn description(&self) -> &'static str {
        match self {
            Self::Minimum => "Basic component identification only",
            Self::Standard => "Recommended fields for general use",
            Self::NtiaMinimum => "NTIA minimum elements for software transparency",
            Self::CraPhase1 => "CRA reporting obligations — product ID, SBOM format, manufacturer (deadline: 11 Dec 2027)",
            Self::CraPhase2 => "Full CRA compliance — adds vulnerability metadata, lifecycle, disclosure (deadline: 11 Dec 2029)",
            Self::FdaMedicalDevice => "FDA premarket submission requirements for medical devices",
            Self::Comprehensive => "All recommended fields and best practices",
        }
    }

    /// Get all compliance levels
    pub fn all() -> &'static [ComplianceLevel] {
        &[
            Self::Minimum,
            Self::Standard,
            Self::NtiaMinimum,
            Self::CraPhase1,
            Self::CraPhase2,
            Self::FdaMedicalDevice,
            Self::Comprehensive,
        ]
    }

    /// Whether this level is a CRA check (either phase)
    pub fn is_cra(&self) -> bool {
        matches!(self, Self::CraPhase1 | Self::CraPhase2)
    }

    /// Get CRA phase, if applicable
    pub fn cra_phase(&self) -> Option<CraPhase> {
        match self {
            Self::CraPhase1 => Some(CraPhase::Phase1),
            Self::CraPhase2 => Some(CraPhase::Phase2),
            _ => None,
        }
    }
}

/// A compliance violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Violation {
    /// Severity: error, warning, info
    pub severity: ViolationSeverity,
    /// Category of the violation
    pub category: ViolationCategory,
    /// Human-readable message
    pub message: String,
    /// Component or element that violated (if applicable)
    pub element: Option<String>,
    /// Standard/requirement being violated
    pub requirement: String,
}

impl Violation {
    /// Return remediation guidance for this violation based on the requirement.
    pub fn remediation_guidance(&self) -> &'static str {
        let req = self.requirement.to_lowercase();
        if req.contains("art. 13(4)") {
            "Ensure the SBOM is produced in CycloneDX 1.4+ (JSON or XML) or SPDX 2.3+ (JSON or tag-value). Older format versions may not be recognized as machine-readable under the CRA."
        } else if req.contains("art. 13(6)") && req.contains("vulnerability metadata") {
            "Add severity (e.g., CVSS score) and remediation details to each vulnerability entry. CycloneDX: use vulnerability.ratings[].score and vulnerability.analysis. SPDX: use annotation or externalRef."
        } else if req.contains("art. 13(6)") {
            "Add a security contact or vulnerability disclosure URL. CycloneDX: add a component externalReference with type 'security-contact' or set metadata.manufacturer.contact. SPDX: add an SECURITY external reference."
        } else if req.contains("art. 13(7)") {
            "Reference a coordinated vulnerability disclosure policy. CycloneDX: add an externalReference of type 'advisories' linking to your disclosure policy. SPDX: add an external document reference."
        } else if req.contains("art. 13(8)") {
            "Specify when security updates will no longer be provided. CycloneDX 1.5+: use component.releaseNotes or metadata properties. SPDX: use an annotation with end-of-support date."
        } else if req.contains("art. 13(11)") {
            "Include lifecycle or end-of-support metadata for components. CycloneDX: use component properties (e.g., cdx:lifecycle:status). SPDX: use annotations."
        } else if req.contains("art. 13(12)") && req.contains("version") {
            "Every component must have a version string. Use the actual release version (e.g., '1.2.3'), not a range or placeholder."
        } else if req.contains("art. 13(12)") {
            "The SBOM must identify the product by name. CycloneDX: set metadata.component.name. SPDX: set documentDescribes with the primary package name."
        } else if req.contains("art. 13(15)") && req.contains("email") {
            "Provide a valid contact email for the manufacturer. The email must contain an @ sign with valid local and domain parts."
        } else if req.contains("art. 13(15)") {
            "Identify the manufacturer/supplier. CycloneDX: set metadata.manufacturer or component.supplier. SPDX: set PackageSupplier."
        } else if req.contains("annex vii") {
            "Reference the EU Declaration of Conformity. CycloneDX: add an externalReference of type 'attestation' or 'certification'. SPDX: add an external document reference."
        } else if req.contains("annex i") && req.contains("identifier") {
            "Add a PURL, CPE, or SWID tag to each component for unique identification. PURLs are preferred (e.g., pkg:npm/lodash@4.17.21)."
        } else if req.contains("annex i") && req.contains("dependency") {
            "Add dependency relationships between components. CycloneDX: use the dependencies array. SPDX: use DEPENDS_ON relationships."
        } else if req.contains("annex i") && req.contains("primary") {
            "Identify the top-level product component. CycloneDX: set metadata.component. SPDX: use documentDescribes to point to the primary package."
        } else if req.contains("annex i") && req.contains("hash") {
            "Add cryptographic hashes (SHA-256 or stronger) to components for integrity verification."
        } else if req.contains("annex i") && req.contains("traceability") {
            "The primary product component needs a stable unique identifier (PURL or CPE) that persists across software updates for traceability."
        } else {
            "Review the requirement and update the SBOM accordingly. Consult the EU CRA regulation (EU 2024/2847) for detailed guidance."
        }
    }
}

/// Severity of a compliance violation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ViolationSeverity {
    /// Must be fixed for compliance
    Error,
    /// Should be fixed, but not strictly required
    Warning,
    /// Informational recommendation
    Info,
}

/// Category of compliance violation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ViolationCategory {
    /// Document metadata issue
    DocumentMetadata,
    /// Component identification issue
    ComponentIdentification,
    /// Dependency information issue
    DependencyInfo,
    /// License information issue
    LicenseInfo,
    /// Supplier information issue
    SupplierInfo,
    /// Hash/integrity issue
    IntegrityInfo,
    /// Security/vulnerability disclosure info
    SecurityInfo,
    /// Format-specific requirement
    FormatSpecific,
}

impl ViolationCategory {
    pub fn name(&self) -> &'static str {
        match self {
            Self::DocumentMetadata => "Document Metadata",
            Self::ComponentIdentification => "Component Identification",
            Self::DependencyInfo => "Dependency Information",
            Self::LicenseInfo => "License Information",
            Self::SupplierInfo => "Supplier Information",
            Self::IntegrityInfo => "Integrity Information",
            Self::SecurityInfo => "Security Information",
            Self::FormatSpecific => "Format-Specific",
        }
    }
}

/// Result of compliance checking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceResult {
    /// Overall compliance status
    pub is_compliant: bool,
    /// Compliance level checked against
    pub level: ComplianceLevel,
    /// All violations found
    pub violations: Vec<Violation>,
    /// Error count
    pub error_count: usize,
    /// Warning count
    pub warning_count: usize,
    /// Info count
    pub info_count: usize,
}

impl ComplianceResult {
    /// Create a new compliance result
    pub fn new(level: ComplianceLevel, violations: Vec<Violation>) -> Self {
        let error_count = violations
            .iter()
            .filter(|v| v.severity == ViolationSeverity::Error)
            .count();
        let warning_count = violations
            .iter()
            .filter(|v| v.severity == ViolationSeverity::Warning)
            .count();
        let info_count = violations
            .iter()
            .filter(|v| v.severity == ViolationSeverity::Info)
            .count();

        Self {
            is_compliant: error_count == 0,
            level,
            violations,
            error_count,
            warning_count,
            info_count,
        }
    }

    /// Get violations filtered by severity
    pub fn violations_by_severity(&self, severity: ViolationSeverity) -> Vec<&Violation> {
        self.violations
            .iter()
            .filter(|v| v.severity == severity)
            .collect()
    }

    /// Get violations filtered by category
    pub fn violations_by_category(&self, category: ViolationCategory) -> Vec<&Violation> {
        self.violations
            .iter()
            .filter(|v| v.category == category)
            .collect()
    }
}

/// Compliance checker for SBOMs
#[derive(Debug, Clone)]
pub struct ComplianceChecker {
    /// Compliance level to check
    level: ComplianceLevel,
}

impl ComplianceChecker {
    /// Create a new compliance checker
    pub fn new(level: ComplianceLevel) -> Self {
        Self { level }
    }

    /// Check an SBOM for compliance
    pub fn check(&self, sbom: &NormalizedSbom) -> ComplianceResult {
        let mut violations = Vec::new();

        // Check document-level requirements
        self.check_document_metadata(sbom, &mut violations);

        // Check component requirements
        self.check_components(sbom, &mut violations);

        // Check dependency requirements
        self.check_dependencies(sbom, &mut violations);

        // Check vulnerability metadata (CRA readiness)
        self.check_vulnerability_metadata(sbom, &mut violations);

        // Check format-specific requirements
        self.check_format_specific(sbom, &mut violations);

        ComplianceResult::new(self.level, violations)
    }

    fn check_document_metadata(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        use crate::model::{CreatorType, ExternalRefType};

        // All levels require creator information
        if sbom.document.creators.is_empty() {
            violations.push(Violation {
                severity: match self.level {
                    ComplianceLevel::Minimum => ViolationSeverity::Warning,
                    _ => ViolationSeverity::Error,
                },
                category: ViolationCategory::DocumentMetadata,
                message: "SBOM must have creator/tool information".to_string(),
                element: None,
                requirement: "Document creator identification".to_string(),
            });
        }

        // CRA: Manufacturer identification and product name
        if self.level.is_cra() {
            let has_org = sbom
                .document
                .creators
                .iter()
                .any(|c| c.creator_type == CreatorType::Organization);
            if !has_org {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::DocumentMetadata,
                    message: "[CRA Art. 13(15)] SBOM should identify the manufacturer (organization)"
                        .to_string(),
                    element: None,
                    requirement: "CRA Art. 13(15): Manufacturer identification".to_string(),
                });
            }

            // Validate manufacturer email format if present
            for creator in &sbom.document.creators {
                if creator.creator_type == CreatorType::Organization {
                    if let Some(email) = &creator.email {
                        if !is_valid_email_format(email) {
                            violations.push(Violation {
                                severity: ViolationSeverity::Warning,
                                category: ViolationCategory::DocumentMetadata,
                                message: format!(
                                    "[CRA Art. 13(15)] Manufacturer email '{}' appears invalid",
                                    email
                                ),
                                element: None,
                                requirement: "CRA Art. 13(15): Valid contact information".to_string(),
                            });
                        }
                    }
                }
            }

            if sbom.document.name.is_none() {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::DocumentMetadata,
                    message: "[CRA Art. 13(12)] SBOM should include the product name".to_string(),
                    element: None,
                    requirement: "CRA Art. 13(12): Product identification".to_string(),
                });
            }

            // CRA: Security contact / vulnerability disclosure point
            // First check document-level security contact (preferred)
            let has_doc_security_contact = sbom.document.security_contact.is_some()
                || sbom.document.vulnerability_disclosure_url.is_some();

            // Fallback: check component-level external refs
            let has_component_security_contact = sbom.components.values().any(|comp| {
                comp.external_refs.iter().any(|r| {
                    matches!(
                        r.ref_type,
                        ExternalRefType::SecurityContact
                            | ExternalRefType::Support
                            | ExternalRefType::Advisories
                    )
                })
            });

            if !has_doc_security_contact && !has_component_security_contact {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::SecurityInfo,
                    message: "[CRA Art. 13(6)] SBOM should include a security contact or vulnerability disclosure reference".to_string(),
                    element: None,
                    requirement: "CRA Art. 13(6): Vulnerability disclosure contact".to_string(),
                });
            }

            // CRA: Check for primary/root product component identification
            if sbom.primary_component_id.is_none() && sbom.components.len() > 1 {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::DocumentMetadata,
                    message: "[CRA Annex I] SBOM should identify the primary product component (CycloneDX metadata.component or SPDX documentDescribes)".to_string(),
                    element: None,
                    requirement: "CRA Annex I: Primary product identification".to_string(),
                });
            }

            // CRA: Check for support end date (informational)
            if sbom.document.support_end_date.is_none() {
                violations.push(Violation {
                    severity: ViolationSeverity::Info,
                    category: ViolationCategory::SecurityInfo,
                    message: "[CRA Art. 13(8)] Consider specifying a support end date for security updates".to_string(),
                    element: None,
                    requirement: "CRA Art. 13(8): Support period disclosure".to_string(),
                });
            }

            // CRA Art. 13(4): Machine-readable SBOM format validation
            // The CRA requires SBOMs in a "commonly used and machine-readable" format.
            // CycloneDX 1.4+ and SPDX 2.3+ are widely accepted as machine-readable.
            let format_ok = match sbom.document.format {
                SbomFormat::CycloneDx => {
                    let v = &sbom.document.spec_version;
                    !(v.starts_with("1.0")
                        || v.starts_with("1.1")
                        || v.starts_with("1.2")
                        || v.starts_with("1.3"))
                }
                SbomFormat::Spdx => {
                    let v = &sbom.document.spec_version;
                    v.starts_with("2.3") || v.starts_with("3.")
                }
            };
            if !format_ok {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::FormatSpecific,
                    message: format!(
                        "[CRA Art. 13(4)] SBOM format version {} {} may not meet CRA machine-readable requirements; use CycloneDX 1.4+ or SPDX 2.3+",
                        sbom.document.format, sbom.document.spec_version
                    ),
                    element: None,
                    requirement: "CRA Art. 13(4): Machine-readable SBOM format".to_string(),
                });
            }

            // CRA Annex I, Part II, 1: Unique product identifier traceability
            // The primary/root component should have a stable unique identifier (PURL or CPE)
            // that can be traced across software updates.
            if let Some(ref primary_id) = sbom.primary_component_id {
                if let Some(primary) = sbom.components.get(primary_id) {
                    if primary.identifiers.purl.is_none() && primary.identifiers.cpe.is_empty() {
                        violations.push(Violation {
                            severity: ViolationSeverity::Warning,
                            category: ViolationCategory::ComponentIdentification,
                            message: format!(
                                "[CRA Annex I, Part II] Primary component '{}' missing unique identifier (PURL/CPE) for cross-update traceability",
                                primary.name
                            ),
                            element: Some(primary.name.clone()),
                            requirement: "CRA Annex I, Part II, 1: Product identifier traceability across updates".to_string(),
                        });
                    }
                }
            }
        }

        // CRA Phase 2-only checks (deadline: 11 Dec 2029)
        if matches!(self.level, ComplianceLevel::CraPhase2) {
            // CRA Art. 13(7): Coordinated vulnerability disclosure policy reference
            // Check for a vulnerability disclosure policy URL or advisories reference
            let has_vuln_disclosure_policy = sbom.document.vulnerability_disclosure_url.is_some()
                || sbom.components.values().any(|comp| {
                    comp.external_refs
                        .iter()
                        .any(|r| matches!(r.ref_type, ExternalRefType::Advisories))
                });
            if !has_vuln_disclosure_policy {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::SecurityInfo,
                    message: "[CRA Art. 13(7)] SBOM should reference a coordinated vulnerability disclosure policy (advisories URL or disclosure URL)".to_string(),
                    element: None,
                    requirement: "CRA Art. 13(7): Coordinated vulnerability disclosure policy".to_string(),
                });
            }

            // CRA Art. 13(11): Component lifecycle status
            // Check whether the primary component (or any top-level component) has end-of-life
            // or lifecycle information. Currently we check support_end_date at doc level.
            // Also check for lifecycle properties on components.
            let has_lifecycle_info = sbom.document.support_end_date.is_some()
                || sbom.components.values().any(|comp| {
                    comp.extensions.properties.iter().any(|p| {
                        let name_lower = p.name.to_lowercase();
                        name_lower.contains("lifecycle")
                            || name_lower.contains("end-of-life")
                            || name_lower.contains("eol")
                            || name_lower.contains("end-of-support")
                    })
                });
            if !has_lifecycle_info {
                violations.push(Violation {
                    severity: ViolationSeverity::Info,
                    category: ViolationCategory::SecurityInfo,
                    message: "[CRA Art. 13(11)] Consider including component lifecycle/end-of-support information".to_string(),
                    element: None,
                    requirement: "CRA Art. 13(11): Component lifecycle status".to_string(),
                });
            }

            // CRA Annex VII: EU Declaration of Conformity reference
            // Check for an attestation, certification, or declaration-of-conformity reference
            let has_conformity_ref = sbom.components.values().any(|comp| {
                comp.external_refs.iter().any(|r| {
                    matches!(
                        r.ref_type,
                        ExternalRefType::Attestation | ExternalRefType::Certification
                    ) || (matches!(r.ref_type, ExternalRefType::Other(ref s) if s.to_lowercase().contains("declaration-of-conformity"))
                    )
                })
            });
            if !has_conformity_ref {
                violations.push(Violation {
                    severity: ViolationSeverity::Info,
                    category: ViolationCategory::DocumentMetadata,
                    message: "[CRA Annex VII] Consider including a reference to the EU Declaration of Conformity (attestation or certification external reference)".to_string(),
                    element: None,
                    requirement: "CRA Annex VII: EU Declaration of Conformity reference".to_string(),
                });
            }
        }

        // FDA requires manufacturer (organization) as creator
        if matches!(self.level, ComplianceLevel::FdaMedicalDevice) {
            let has_org = sbom
                .document
                .creators
                .iter()
                .any(|c| c.creator_type == CreatorType::Organization);
            if !has_org {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::DocumentMetadata,
                    message: "FDA: SBOM should have manufacturer (organization) as creator"
                        .to_string(),
                    element: None,
                    requirement: "FDA: Manufacturer identification".to_string(),
                });
            }

            // FDA recommends contact information
            let has_contact = sbom.document.creators.iter().any(|c| c.email.is_some());
            if !has_contact {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::DocumentMetadata,
                    message: "FDA: SBOM creators should include contact email".to_string(),
                    element: None,
                    requirement: "FDA: Contact information".to_string(),
                });
            }

            // FDA: Document name required
            if sbom.document.name.is_none() {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::DocumentMetadata,
                    message: "FDA: SBOM should have a document name/title".to_string(),
                    element: None,
                    requirement: "FDA: Document identification".to_string(),
                });
            }
        }

        // NTIA requires timestamp
        if matches!(
            self.level,
            ComplianceLevel::NtiaMinimum | ComplianceLevel::Comprehensive
        ) {
            // Timestamp is always set in our model, but check if it's meaningful
            // For now, we'll skip this check as we always set a timestamp
        }

        // Standard+ requires serial number/document ID
        if matches!(
            self.level,
            ComplianceLevel::Standard
                | ComplianceLevel::FdaMedicalDevice
                | ComplianceLevel::CraPhase1
                | ComplianceLevel::CraPhase2
                | ComplianceLevel::Comprehensive
        ) && sbom.document.serial_number.is_none()
        {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::DocumentMetadata,
                message: "SBOM should have a serial number/unique identifier".to_string(),
                element: None,
                requirement: "Document unique identification".to_string(),
            });
        }
    }

    fn check_components(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        use crate::model::HashAlgorithm;

        for comp in sbom.components.values() {
            // All levels: component must have a name
            // (Always true in our model, but check anyway)
            if comp.name.is_empty() {
                violations.push(Violation {
                    severity: ViolationSeverity::Error,
                    category: ViolationCategory::ComponentIdentification,
                    message: "Component must have a name".to_string(),
                    element: Some(comp.identifiers.format_id.clone()),
                    requirement: "Component name (required)".to_string(),
                });
            }

            // NTIA minimum & FDA: version required
            if matches!(
                self.level,
                ComplianceLevel::NtiaMinimum
                    | ComplianceLevel::FdaMedicalDevice
                    | ComplianceLevel::Standard
                    | ComplianceLevel::CraPhase1
                    | ComplianceLevel::CraPhase2
                    | ComplianceLevel::Comprehensive
            ) && comp.version.is_none()
            {
                let (req, msg) = match self.level {
                    ComplianceLevel::FdaMedicalDevice => (
                        "FDA: Component version".to_string(),
                        format!("Component '{}' missing version", comp.name),
                    ),
                    ComplianceLevel::CraPhase1 | ComplianceLevel::CraPhase2 => (
                        "CRA Art. 13(12): Component version".to_string(),
                        format!("[CRA Art. 13(12)] Component '{}' missing version", comp.name),
                    ),
                    _ => (
                        "NTIA: Component version".to_string(),
                        format!("Component '{}' missing version", comp.name),
                    ),
                };
                violations.push(Violation {
                    severity: ViolationSeverity::Error,
                    category: ViolationCategory::ComponentIdentification,
                    message: msg,
                    element: Some(comp.name.clone()),
                    requirement: req,
                });
            }

            // Standard+ & FDA: should have PURL or CPE
            if matches!(
                self.level,
                ComplianceLevel::Standard
                    | ComplianceLevel::FdaMedicalDevice
                    | ComplianceLevel::CraPhase1
                    | ComplianceLevel::CraPhase2
                    | ComplianceLevel::Comprehensive
            ) && comp.identifiers.purl.is_none()
                && comp.identifiers.cpe.is_empty()
                && comp.identifiers.swid.is_none()
            {
                let severity = if matches!(
                    self.level,
                    ComplianceLevel::FdaMedicalDevice | ComplianceLevel::CraPhase1 | ComplianceLevel::CraPhase2
                ) {
                    ViolationSeverity::Error
                } else {
                    ViolationSeverity::Warning
                };
                let (message, requirement) = match self.level {
                    ComplianceLevel::FdaMedicalDevice => (
                        format!(
                            "Component '{}' missing unique identifier (PURL/CPE/SWID)",
                            comp.name
                        ),
                        "FDA: Unique component identifier".to_string(),
                    ),
                    ComplianceLevel::CraPhase1 | ComplianceLevel::CraPhase2 => (
                        format!(
                            "[CRA Annex I] Component '{}' missing unique identifier (PURL/CPE/SWID)",
                            comp.name
                        ),
                        "CRA Annex I: Unique component identifier (PURL/CPE/SWID)".to_string(),
                    ),
                    _ => (
                        format!(
                            "Component '{}' missing unique identifier (PURL/CPE/SWID)",
                            comp.name
                        ),
                        "Standard identifier (PURL/CPE)".to_string(),
                    ),
                };
                violations.push(Violation {
                    severity,
                    category: ViolationCategory::ComponentIdentification,
                    message,
                    element: Some(comp.name.clone()),
                    requirement,
                });
            }

            // NTIA minimum & FDA: supplier required
            if matches!(
                self.level,
                ComplianceLevel::NtiaMinimum
                    | ComplianceLevel::FdaMedicalDevice
                    | ComplianceLevel::CraPhase1
                    | ComplianceLevel::CraPhase2
                    | ComplianceLevel::Comprehensive
            ) && comp.supplier.is_none()
                && comp.author.is_none()
            {
                let severity = match self.level {
                    ComplianceLevel::CraPhase1 | ComplianceLevel::CraPhase2 => ViolationSeverity::Warning,
                    _ => ViolationSeverity::Error,
                };
                let (message, requirement) = match self.level {
                    ComplianceLevel::FdaMedicalDevice => (
                        format!("Component '{}' missing supplier/manufacturer", comp.name),
                        "FDA: Supplier/manufacturer information".to_string(),
                    ),
                    ComplianceLevel::CraPhase1 | ComplianceLevel::CraPhase2 => (
                        format!(
                            "[CRA Art. 13(15)] Component '{}' missing supplier/manufacturer",
                            comp.name
                        ),
                        "CRA Art. 13(15): Supplier/manufacturer information".to_string(),
                    ),
                    _ => (
                        format!("Component '{}' missing supplier/manufacturer", comp.name),
                        "NTIA: Supplier information".to_string(),
                    ),
                };
                violations.push(Violation {
                    severity,
                    category: ViolationCategory::SupplierInfo,
                    message,
                    element: Some(comp.name.clone()),
                    requirement,
                });
            }

            // Standard+: should have license information
            if matches!(
                self.level,
                ComplianceLevel::Standard | ComplianceLevel::Comprehensive
            ) && comp.licenses.declared.is_empty()
                && comp.licenses.concluded.is_none()
            {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::LicenseInfo,
                    message: format!(
                        "Component '{}' should have license information",
                        comp.name
                    ),
                    element: Some(comp.name.clone()),
                    requirement: "License declaration".to_string(),
                });
            }

            // FDA & Comprehensive: must have cryptographic hashes
            if matches!(
                self.level,
                ComplianceLevel::FdaMedicalDevice | ComplianceLevel::Comprehensive
            ) {
                if comp.hashes.is_empty() {
                    violations.push(Violation {
                        severity: if self.level == ComplianceLevel::FdaMedicalDevice {
                            ViolationSeverity::Error
                        } else {
                            ViolationSeverity::Warning
                        },
                        category: ViolationCategory::IntegrityInfo,
                        message: format!("Component '{}' missing cryptographic hash", comp.name),
                        element: Some(comp.name.clone()),
                        requirement: if self.level == ComplianceLevel::FdaMedicalDevice {
                            "FDA: Cryptographic hash for integrity".to_string()
                        } else {
                            "Integrity verification (hashes)".to_string()
                        },
                    });
                } else if self.level == ComplianceLevel::FdaMedicalDevice {
                    // FDA: Check for strong hash algorithm (SHA-256 or better)
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
                        violations.push(Violation {
                            severity: ViolationSeverity::Warning,
                            category: ViolationCategory::IntegrityInfo,
                            message: format!(
                                "Component '{}' has only weak hash algorithm (use SHA-256+)",
                                comp.name
                            ),
                            element: Some(comp.name.clone()),
                            requirement: "FDA: Strong cryptographic hash (SHA-256 or better)"
                                .to_string(),
                        });
                    }
                }
            }

            // CRA: hashes are recommended for integrity verification
            if self.level.is_cra() && comp.hashes.is_empty() {
                violations.push(Violation {
                    severity: ViolationSeverity::Info,
                    category: ViolationCategory::IntegrityInfo,
                    message: format!(
                        "[CRA Annex I] Component '{}' missing cryptographic hash (recommended for integrity)",
                        comp.name
                    ),
                    element: Some(comp.name.clone()),
                    requirement: "CRA Annex I: Component integrity information (hash)".to_string(),
                });
            }
        }
    }

    fn check_dependencies(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        // NTIA & FDA require dependency relationships
        if matches!(
            self.level,
            ComplianceLevel::NtiaMinimum
                | ComplianceLevel::FdaMedicalDevice
                | ComplianceLevel::CraPhase1
                | ComplianceLevel::CraPhase2
                | ComplianceLevel::Comprehensive
        ) {
            let has_deps = !sbom.edges.is_empty();
            let has_multiple_components = sbom.components.len() > 1;

            if has_multiple_components && !has_deps {
                let (message, requirement) = match self.level {
                    ComplianceLevel::CraPhase1 | ComplianceLevel::CraPhase2 => (
                        "[CRA Annex I] SBOM with multiple components must include dependency relationships".to_string(),
                        "CRA Annex I: Dependency relationships".to_string(),
                    ),
                    _ => (
                        "SBOM with multiple components must include dependency relationships".to_string(),
                        "NTIA: Dependency relationships".to_string(),
                    ),
                };
                violations.push(Violation {
                    severity: ViolationSeverity::Error,
                    category: ViolationCategory::DependencyInfo,
                    message,
                    element: None,
                    requirement,
                });
            }
        }

        // CRA: warn if multiple root components (no incoming edges) and no primary component set
        if self.level.is_cra()
            && sbom.components.len() > 1
            && sbom.primary_component_id.is_none()
        {
            use std::collections::HashSet;
            let mut incoming: HashSet<&crate::model::CanonicalId> = HashSet::new();
            for edge in &sbom.edges {
                incoming.insert(&edge.to);
            }
            let root_count = sbom.components.len().saturating_sub(incoming.len());
            if root_count > 1 {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::DependencyInfo,
                    message: "[CRA Annex I] SBOM appears to have multiple root components; identify a primary product component for top-level dependencies".to_string(),
                    element: None,
                    requirement: "CRA Annex I: Top-level dependency clarity".to_string(),
                });
            }
        }
    }

    fn check_vulnerability_metadata(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        if !matches!(self.level, ComplianceLevel::CraPhase2) {
            return;
        }

        for (comp, vuln) in sbom.all_vulnerabilities() {
            if vuln.severity.is_none() && vuln.cvss.is_empty() {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::SecurityInfo,
                    message: format!(
                        "[CRA Art. 13(6)] Vulnerability '{}' in '{}' lacks severity or CVSS score",
                        vuln.id, comp.name
                    ),
                    element: Some(comp.name.clone()),
                    requirement: "CRA Art. 13(6): Vulnerability metadata completeness".to_string(),
                });
            }

            if let Some(remediation) = &vuln.remediation {
                if remediation.fixed_version.is_none() && remediation.description.is_none() {
                    violations.push(Violation {
                        severity: ViolationSeverity::Info,
                        category: ViolationCategory::SecurityInfo,
                        message: format!(
                            "[CRA Art. 13(6)] Vulnerability '{}' in '{}' has remediation without details",
                            vuln.id, comp.name
                        ),
                        element: Some(comp.name.clone()),
                        requirement: "CRA Art. 13(6): Remediation detail".to_string(),
                    });
                }
            }
        }
    }

    fn check_format_specific(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        match sbom.document.format {
            SbomFormat::CycloneDx => {
                self.check_cyclonedx_specific(sbom, violations);
            }
            SbomFormat::Spdx => {
                self.check_spdx_specific(sbom, violations);
            }
        }
    }

    fn check_cyclonedx_specific(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        // CycloneDX specific checks
        let version = &sbom.document.spec_version;

        // Warn about older versions
        if version.starts_with("1.3") || version.starts_with("1.2") {
            violations.push(Violation {
                severity: ViolationSeverity::Info,
                category: ViolationCategory::FormatSpecific,
                message: format!(
                    "CycloneDX {} is outdated, consider upgrading to 1.5+",
                    version
                ),
                element: None,
                requirement: "Current CycloneDX version".to_string(),
            });
        }

        // Check for bom-ref on components (important for CycloneDX)
        for comp in sbom.components.values() {
            if comp.identifiers.format_id == comp.name {
                // Likely missing bom-ref
                violations.push(Violation {
                    severity: ViolationSeverity::Info,
                    category: ViolationCategory::FormatSpecific,
                    message: format!("Component '{}' may be missing bom-ref", comp.name),
                    element: Some(comp.name.clone()),
                    requirement: "CycloneDX: bom-ref for dependency tracking".to_string(),
                });
            }
        }
    }

    fn check_spdx_specific(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        // SPDX specific checks
        let version = &sbom.document.spec_version;

        // Check version
        if !version.starts_with("2.") && !version.starts_with("3.") {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::FormatSpecific,
                message: format!("Unknown SPDX version: {}", version),
                element: None,
                requirement: "Valid SPDX version".to_string(),
            });
        }

        // SPDX requires SPDXID for each element
        for comp in sbom.components.values() {
            if !comp.identifiers.format_id.starts_with("SPDXRef-") {
                violations.push(Violation {
                    severity: ViolationSeverity::Info,
                    category: ViolationCategory::FormatSpecific,
                    message: format!("Component '{}' has non-standard SPDXID format", comp.name),
                    element: Some(comp.name.clone()),
                    requirement: "SPDX: SPDXRef- identifier format".to_string(),
                });
            }
        }
    }
}

impl Default for ComplianceChecker {
    fn default() -> Self {
        Self::new(ComplianceLevel::Standard)
    }
}

/// Simple email format validation (checks basic structure, not full RFC 5322)
fn is_valid_email_format(email: &str) -> bool {
    // Basic checks: contains @, has local and domain parts, no spaces
    if email.contains(' ') || email.is_empty() {
        return false;
    }

    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return false;
    }

    let local = parts[0];
    let domain = parts[1];

    // Local part must not be empty
    if local.is_empty() {
        return false;
    }

    // Domain must contain at least one dot and not start/end with dot
    if domain.is_empty()
        || !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
    {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compliance_level_names() {
        assert_eq!(ComplianceLevel::Minimum.name(), "Minimum");
        assert_eq!(ComplianceLevel::NtiaMinimum.name(), "NTIA Minimum Elements");
        assert_eq!(ComplianceLevel::CraPhase1.name(), "EU CRA Phase 1 (2027)");
        assert_eq!(ComplianceLevel::CraPhase2.name(), "EU CRA Phase 2 (2029)");
    }

    #[test]
    fn test_compliance_result_counts() {
        let violations = vec![
            Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::ComponentIdentification,
                message: "Error 1".to_string(),
                element: None,
                requirement: "Test".to_string(),
            },
            Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::LicenseInfo,
                message: "Warning 1".to_string(),
                element: None,
                requirement: "Test".to_string(),
            },
            Violation {
                severity: ViolationSeverity::Info,
                category: ViolationCategory::FormatSpecific,
                message: "Info 1".to_string(),
                element: None,
                requirement: "Test".to_string(),
            },
        ];

        let result = ComplianceResult::new(ComplianceLevel::Standard, violations);
        assert!(!result.is_compliant);
        assert_eq!(result.error_count, 1);
        assert_eq!(result.warning_count, 1);
        assert_eq!(result.info_count, 1);
    }
}
