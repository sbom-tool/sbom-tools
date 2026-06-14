//! Generic-path compliance checks shared across the non-dedicated
//! profiles (Minimum, Standard, NTIA, CRA phases, FDA, Comprehensive):
//! document metadata, components, dependencies, vulnerability metadata,
//! and format-specific (CycloneDX / SPDX) requirements.

use super::*;

impl ComplianceChecker {
    pub(crate) fn check_document_metadata(
        &self,
        sbom: &NormalizedSbom,
        violations: &mut Vec<Violation>,
    ) {
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
                rule_id: "SBOM-CRA-GENERAL",
                standard_refs: Vec::new(),
            });
        }

        // CRA: Manufacturer identification and product name
        if self.level.is_cra() {
            let has_org = sbom
                .document
                .creators
                .iter()
                .any(|c| c.creator_type == CreatorType::Organization);
            let sidecar_has_manufacturer = self
                .sidecar
                .as_ref()
                .is_some_and(|s| s.manufacturer_name.is_some());
            if !has_org {
                if sidecar_has_manufacturer {
                    violations.push(Violation {
                        severity: ViolationSeverity::Info,
                        category: ViolationCategory::DocumentMetadata,
                        message:
                            "[CRA Art. 13(15)] Manufacturer identified via CRA sidecar (consider adding to the SBOM directly for portability)"
                                .to_string(),
                        element: None,
                        requirement: "CRA Art. 13(15): Manufacturer identification".to_string(),
                        rule_id: "SBOM-CRA-ART-13-15",
                        standard_refs: Vec::new(),
                    });
                } else {
                    violations.push(Violation {
                        severity: ViolationSeverity::Warning,
                        category: ViolationCategory::DocumentMetadata,
                        message:
                            "[CRA Art. 13(15)] SBOM should identify the manufacturer (organization)"
                                .to_string(),
                        element: None,
                        requirement: "CRA Art. 13(15): Manufacturer identification".to_string(),
                        rule_id: "SBOM-CRA-ART-13-15",
                        standard_refs: Vec::new(),
                    });
                }
            }

            // Validate manufacturer email format if present
            for creator in &sbom.document.creators {
                if creator.creator_type == CreatorType::Organization
                    && let Some(email) = &creator.email
                    && !is_valid_email_format(email)
                {
                    violations.push(Violation {
                        severity: ViolationSeverity::Warning,
                        category: ViolationCategory::DocumentMetadata,
                        message: format!(
                            "[CRA Art. 13(15)] Manufacturer email '{email}' appears invalid"
                        ),
                        element: None,
                        requirement: "CRA Art. 13(15): Valid contact information".to_string(),
                        rule_id: "SBOM-CRA-ART-13-15-EMAIL",
                        standard_refs: Vec::new(),
                    });
                }
            }

            if sbom.document.name.is_none() {
                let sidecar_has_product_name = self
                    .sidecar
                    .as_ref()
                    .is_some_and(|s| s.product_name.is_some());
                if sidecar_has_product_name {
                    violations.push(Violation {
                        severity: ViolationSeverity::Info,
                        category: ViolationCategory::DocumentMetadata,
                        message: "[CRA Art. 13(12)] Product name provided via CRA sidecar (consider adding metadata.component.name to the SBOM)".to_string(),
                        element: None,
                        requirement: "CRA Art. 13(12): Product identification".to_string(),
                        rule_id: "SBOM-CRA-ART-13-12-PRODUCT",
                        standard_refs: Vec::new(),
                    });
                } else {
                    violations.push(Violation {
                        severity: ViolationSeverity::Warning,
                        category: ViolationCategory::DocumentMetadata,
                        message: "[CRA Art. 13(12)] SBOM should include the product name"
                            .to_string(),
                        element: None,
                        requirement: "CRA Art. 13(12): Product identification".to_string(),
                        rule_id: "SBOM-CRA-ART-13-12-PRODUCT",
                        standard_refs: Vec::new(),
                    });
                }
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
                let sidecar_has_security = self.sidecar.as_ref().is_some_and(|s| {
                    s.security_contact.is_some() || s.vulnerability_disclosure_url.is_some()
                });
                if sidecar_has_security {
                    violations.push(Violation {
                        severity: ViolationSeverity::Info,
                        category: ViolationCategory::SecurityInfo,
                        message: "[CRA Art. 13(6)] Security contact provided via CRA sidecar (consider adding a security-contact externalReference to the SBOM)".to_string(),
                        element: None,
                        requirement: "CRA Art. 13(6): Vulnerability disclosure contact".to_string(),
                        rule_id: "SBOM-CRA-ART-13-6-CONTACT",
                        standard_refs: Vec::new(),
                    });
                } else {
                    violations.push(Violation {
                        severity: ViolationSeverity::Warning,
                        category: ViolationCategory::SecurityInfo,
                        message: "[CRA Art. 13(6)] SBOM should include a security contact or vulnerability disclosure reference".to_string(),
                        element: None,
                        requirement: "CRA Art. 13(6): Vulnerability disclosure contact".to_string(),
                        rule_id: "SBOM-CRA-ART-13-6-CONTACT",
                        standard_refs: Vec::new(),
                    });
                }
            }

            // CRA: Check for primary/root product component identification
            if sbom.primary_component_id.is_none() && sbom.components.len() > 1 {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::DocumentMetadata,
                    message: "[CRA Annex I] SBOM should identify the primary product component (CycloneDX metadata.component or SPDX documentDescribes)".to_string(),
                    element: None,
                    requirement: "CRA Annex I: Primary product identification".to_string(),
                    rule_id: "SBOM-CRA-ANNEX-I-PRIMARY",
                    standard_refs: Vec::new(),
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
                    rule_id: "SBOM-CRA-ART-13-8",
                    standard_refs: Vec::new(),
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
                        "[CRA Art. 13(4)] SBOM format version {} {} may not meet CRA machine-readable requirements; use CycloneDX 1.4+, SPDX 2.3+, or SPDX 3.0+",
                        sbom.document.format, sbom.document.spec_version
                    ),
                    element: None,
                    requirement: "CRA Art. 13(4): Machine-readable SBOM format".to_string(),
                    rule_id: "SBOM-CRA-ART-13-4",
                    standard_refs: Vec::new(),
                });
            }

            // CRA Annex I, Part II, 1: Unique product identifier traceability
            // The primary/root component should have a stable unique identifier (PURL or CPE)
            // that can be traced across software updates.
            if let Some(ref primary_id) = sbom.primary_component_id
                && let Some(primary) = sbom.components.get(primary_id)
                && primary.identifiers.purl.is_none()
                && primary.identifiers.cpe.is_empty()
            {
                violations.push(Violation {
                            severity: ViolationSeverity::Warning,
                            category: ViolationCategory::ComponentIdentification,
                            message: format!(
                                "[CRA Annex I, Part II] Primary component '{}' missing unique identifier (PURL/CPE) for cross-update traceability",
                                primary.name
                            ),
                            element: Some(primary.name.clone()),
                            requirement: "CRA Annex I, Part II, 1: Product identifier traceability across updates".to_string(),
                            rule_id: "SBOM-CRA-ANNEX-I-TRACEABILITY",
                            standard_refs: Vec::new(),
                        });
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
                let sidecar_has_cvd = self
                    .sidecar
                    .as_ref()
                    .is_some_and(|s| s.vulnerability_disclosure_url.is_some());
                if sidecar_has_cvd {
                    violations.push(Violation {
                        severity: ViolationSeverity::Info,
                        category: ViolationCategory::SecurityInfo,
                        message: "[CRA Art. 13(7)] CVD policy URL provided via CRA sidecar (consider adding an advisories externalReference to the SBOM)".to_string(),
                        element: None,
                        requirement: "CRA Art. 13(7): Coordinated vulnerability disclosure policy".to_string(),
                        rule_id: "SBOM-CRA-ART-13-7",
                        standard_refs: Vec::new(),
                    });
                } else {
                    violations.push(Violation {
                        severity: ViolationSeverity::Warning,
                        category: ViolationCategory::SecurityInfo,
                        message: "[CRA Art. 13(7)] SBOM should reference a coordinated vulnerability disclosure policy (advisories URL or disclosure URL)".to_string(),
                        element: None,
                        requirement: "CRA Art. 13(7): Coordinated vulnerability disclosure policy".to_string(),
                        rule_id: "SBOM-CRA-ART-13-7",
                        standard_refs: Vec::new(),
                    });
                }
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
                    rule_id: "SBOM-CRA-ART-13-11",
                    standard_refs: Vec::new(),
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
            let sidecar_has_doc_ref = self
                .sidecar
                .as_ref()
                .is_some_and(|s| s.ce_marking_reference.is_some());
            if !has_conformity_ref && !sidecar_has_doc_ref {
                let severity = self
                    .class_severity(ClassCheck::DocReference)
                    .unwrap_or(ViolationSeverity::Info);
                violations.push(Violation {
                    severity,
                    category: ViolationCategory::DocumentMetadata,
                    message: format!(
                        "[CRA Annex VII] Missing reference to the EU Declaration of Conformity (attestation or certification external reference) for product class {}",
                        self.effective_product_class().label()
                    ),
                    element: None,
                    requirement: "CRA Annex VII: EU Declaration of Conformity reference".to_string(),
                    rule_id: "SBOM-CRA-ANNEX-VII",
                    standard_refs: Vec::new(),
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
                    rule_id: "SBOM-FDA-SUPPLIER",
                    standard_refs: Vec::new(),
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
                    rule_id: "SBOM-FDA-SUPPORT",
                    standard_refs: Vec::new(),
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
                    rule_id: "SBOM-FDA-NAME",
                    standard_refs: Vec::new(),
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
                rule_id: "SBOM-CRA-GENERAL",
                standard_refs: Vec::new(),
            });
        }
    }

    pub(crate) fn check_components(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
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
                    rule_id: "SBOM-CRA-GENERAL",
                    standard_refs: Vec::new(),
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
                let (req, msg, rule_id) = match self.level {
                    ComplianceLevel::FdaMedicalDevice => (
                        "FDA: Component version".to_string(),
                        format!("Component '{}' missing version", comp.name),
                        "SBOM-FDA-VERSION",
                    ),
                    ComplianceLevel::CraPhase1 | ComplianceLevel::CraPhase2 => (
                        "CRA Art. 13(12): Component version".to_string(),
                        format!(
                            "[CRA Art. 13(12)] Component '{}' missing version",
                            comp.name
                        ),
                        "SBOM-CRA-ART-13-12-VERSION",
                    ),
                    _ => (
                        "NTIA: Component version".to_string(),
                        format!("Component '{}' missing version", comp.name),
                        "SBOM-NTIA-VERSION",
                    ),
                };
                violations.push(Violation {
                    severity: ViolationSeverity::Error,
                    category: ViolationCategory::ComponentIdentification,
                    message: msg,
                    element: Some(comp.name.clone()),
                    requirement: req,
                    rule_id,
                    standard_refs: Vec::new(),
                });
            }

            // Standard+ & FDA: should have PURL/CPE/SWHID/SWID
            // CRA prEN 40000-1-3 [PRE-7-RQ-07] explicitly names PURL, CPE, SWHID
            if matches!(
                self.level,
                ComplianceLevel::Standard
                    | ComplianceLevel::FdaMedicalDevice
                    | ComplianceLevel::CraPhase1
                    | ComplianceLevel::CraPhase2
                    | ComplianceLevel::Comprehensive
            ) && !comp.identifiers.has_cra_identifier()
            {
                let severity = if matches!(
                    self.level,
                    ComplianceLevel::FdaMedicalDevice
                        | ComplianceLevel::CraPhase1
                        | ComplianceLevel::CraPhase2
                ) {
                    ViolationSeverity::Error
                } else {
                    ViolationSeverity::Warning
                };
                let (message, requirement, rule_id) = match self.level {
                    ComplianceLevel::FdaMedicalDevice => (
                        format!(
                            "Component '{}' missing unique identifier (PURL/CPE/SWHID/SWID)",
                            comp.name
                        ),
                        "FDA: Unique component identifier".to_string(),
                        "SBOM-FDA-IDENTIFIER",
                    ),
                    ComplianceLevel::CraPhase1 | ComplianceLevel::CraPhase2 => (
                        format!(
                            "[CRA Annex I, [PRE-7-RQ-07]] Component '{}' missing unique identifier (PURL/CPE/SWHID/SWID)",
                            comp.name
                        ),
                        "CRA Annex I / prEN 40000-1-3 [PRE-7-RQ-07]: Unique component identifier (PURL/CPE/SWHID/SWID)".to_string(),
                        "SBOM-CRA-ANNEX-I-IDENTIFIER",
                    ),
                    _ => (
                        format!(
                            "Component '{}' missing unique identifier (PURL/CPE/SWHID/SWID)",
                            comp.name
                        ),
                        "Standard identifier (PURL/CPE/SWHID)".to_string(),
                        "SBOM-CRA-GENERAL",
                    ),
                };
                violations.push(Violation {
                    severity,
                    category: ViolationCategory::ComponentIdentification,
                    message,
                    element: Some(comp.name.clone()),
                    requirement,
                    rule_id,
                    standard_refs: Vec::new(),
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
                    ComplianceLevel::CraPhase1 | ComplianceLevel::CraPhase2 => {
                        ViolationSeverity::Warning
                    }
                    _ => ViolationSeverity::Error,
                };
                let (message, requirement, rule_id) = match self.level {
                    ComplianceLevel::FdaMedicalDevice => (
                        format!("Component '{}' missing supplier/manufacturer", comp.name),
                        "FDA: Supplier/manufacturer information".to_string(),
                        "SBOM-FDA-SUPPLIER",
                    ),
                    ComplianceLevel::CraPhase1 | ComplianceLevel::CraPhase2 => (
                        format!(
                            "[CRA Art. 13(15)] Component '{}' missing supplier/manufacturer",
                            comp.name
                        ),
                        "CRA Art. 13(15): Supplier/manufacturer information".to_string(),
                        "SBOM-CRA-ART-13-15",
                    ),
                    _ => (
                        format!("Component '{}' missing supplier/manufacturer", comp.name),
                        "NTIA: Supplier information".to_string(),
                        "SBOM-NTIA-SUPPLIER",
                    ),
                };
                violations.push(Violation {
                    severity,
                    category: ViolationCategory::SupplierInfo,
                    message,
                    element: Some(comp.name.clone()),
                    requirement,
                    rule_id,
                    standard_refs: Vec::new(),
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
                    message: format!("Component '{}' should have license information", comp.name),
                    element: Some(comp.name.clone()),
                    requirement: "License declaration".to_string(),
                    rule_id: "SBOM-CRA-GENERAL",
                    standard_refs: Vec::new(),
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
                        rule_id: if self.level == ComplianceLevel::FdaMedicalDevice {
                            "SBOM-FDA-HASH"
                        } else {
                            "SBOM-CRA-GENERAL"
                        },
                        standard_refs: Vec::new(),
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
                                | HashAlgorithm::Streebog256
                                | HashAlgorithm::Streebog512
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
                            rule_id: "SBOM-FDA-HASH",
                            standard_refs: Vec::new(),
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
                    rule_id: "SBOM-CRA-ANNEX-I-INTEGRITY",
                    standard_refs: Vec::new(),
                });
            }
        }
    }

    pub(crate) fn check_dependencies(
        &self,
        sbom: &NormalizedSbom,
        violations: &mut Vec<Violation>,
    ) {
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
                let (message, requirement, rule_id) = match self.level {
                    ComplianceLevel::CraPhase1 | ComplianceLevel::CraPhase2 => (
                        "[CRA Annex I] SBOM with multiple components must include dependency relationships".to_string(),
                        "CRA Annex I: Dependency relationships".to_string(),
                        "SBOM-CRA-ANNEX-I-DEPENDENCY",
                    ),
                    _ => (
                        "SBOM with multiple components must include dependency relationships".to_string(),
                        "NTIA: Dependency relationships".to_string(),
                        "SBOM-NTIA-DEPENDENCY",
                    ),
                };
                violations.push(Violation {
                    severity: ViolationSeverity::Error,
                    category: ViolationCategory::DependencyInfo,
                    message,
                    element: None,
                    requirement,
                    rule_id,
                    standard_refs: Vec::new(),
                });
            }
        }

        // CRA: warn if multiple root components (no incoming edges) and no primary component set
        if self.level.is_cra() && sbom.components.len() > 1 && sbom.primary_component_id.is_none() {
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
                    rule_id: "SBOM-CRA-ANNEX-I-DEPENDENCY",
                    standard_refs: Vec::new(),
                });
            }
        }
    }

    pub(crate) fn check_vulnerability_metadata(
        &self,
        sbom: &NormalizedSbom,
        violations: &mut Vec<Violation>,
    ) {
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
                    rule_id: "SBOM-CRA-ART-13-6-METADATA",
                    standard_refs: Vec::new(),
                });
            }

            if let Some(remediation) = &vuln.remediation
                && remediation.fixed_version.is_none()
                && remediation.description.is_none()
            {
                violations.push(Violation {
                        severity: ViolationSeverity::Info,
                        category: ViolationCategory::SecurityInfo,
                        message: format!(
                            "[CRA Art. 13(6)] Vulnerability '{}' in '{}' has remediation without details",
                            vuln.id, comp.name
                        ),
                        element: Some(comp.name.clone()),
                        requirement: "CRA Art. 13(6): Remediation detail".to_string(),
                        rule_id: "SBOM-CRA-ART-13-6-METADATA",
                        standard_refs: Vec::new(),
                    });
            }
        }
    }

    pub(crate) fn check_format_specific(
        &self,
        sbom: &NormalizedSbom,
        violations: &mut Vec<Violation>,
    ) {
        match sbom.document.format {
            SbomFormat::CycloneDx => {
                self.check_cyclonedx_specific(sbom, violations);
            }
            SbomFormat::Spdx => {
                self.check_spdx_specific(sbom, violations);
            }
        }
    }

    pub(crate) fn check_cyclonedx_specific(
        &self,
        sbom: &NormalizedSbom,
        violations: &mut Vec<Violation>,
    ) {
        // CycloneDX specific checks
        let version = &sbom.document.spec_version;

        // Warn about older versions
        if version.starts_with("1.3") || version.starts_with("1.2") || version.starts_with("1.1") {
            violations.push(Violation {
                severity: ViolationSeverity::Info,
                category: ViolationCategory::FormatSpecific,
                message: format!("CycloneDX {version} is outdated, consider upgrading to 1.7+"),
                element: None,
                requirement: "Current CycloneDX version".to_string(),
                rule_id: "SBOM-CRA-GENERAL",
                standard_refs: Vec::new(),
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
                    rule_id: "SBOM-CRA-GENERAL",
                    standard_refs: Vec::new(),
                });
            }
        }
    }

    pub(crate) fn check_spdx_specific(
        &self,
        sbom: &NormalizedSbom,
        violations: &mut Vec<Violation>,
    ) {
        // SPDX specific checks
        let version = &sbom.document.spec_version;

        // Check version
        if !version.starts_with("2.") && !version.starts_with("3.") {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::FormatSpecific,
                message: format!("Unknown SPDX version: {version}"),
                element: None,
                requirement: "Valid SPDX version".to_string(),
                rule_id: "SBOM-CRA-GENERAL",
                standard_refs: Vec::new(),
            });
        }

        // SPDX requires element identifiers
        // SPDX 2.x uses SPDXRef- prefix; SPDX 3.0 uses URN-style IDs (e.g., urn:spdx:...)
        let is_spdx3 = version.starts_with("3.");
        for comp in sbom.components.values() {
            let valid_id = if is_spdx3 {
                // SPDX 3.0 uses URN/IRI identifiers
                comp.identifiers.format_id.contains(':')
            } else {
                comp.identifiers.format_id.starts_with("SPDXRef-")
            };
            if !valid_id {
                let expected = if is_spdx3 {
                    "SPDX 3.0: URN/IRI identifier format"
                } else {
                    "SPDX 2.x: SPDXRef- identifier format"
                };
                violations.push(Violation {
                    severity: ViolationSeverity::Info,
                    category: ViolationCategory::FormatSpecific,
                    message: format!(
                        "Component '{}' has non-standard SPDX identifier format",
                        comp.name
                    ),
                    element: Some(comp.name.clone()),
                    requirement: expected.to_string(),
                    rule_id: "SBOM-CRA-GENERAL",
                    standard_refs: Vec::new(),
                });
            }
        }
    }
}
