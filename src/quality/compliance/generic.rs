//! Generic-path compliance checks shared across the non-dedicated
//! profiles (Minimum, Standard, NTIA, CRA phases, FDA, Comprehensive):
//! document metadata, components, dependencies, vulnerability metadata,
//! and format-specific (CycloneDX / SPDX) requirements.

use super::*;

/// One format-level check's rule id per profile family. The generic path
/// runs the spec-version and element-identifier checks for the quality
/// profiles, NTIA, the CRA profiles and FDA, and each family reports every
/// check under an id of its own, so two checks on one subject never share a
/// finding key.
struct FamilyRuleIds {
    /// Minimum, Standard and Comprehensive.
    quality: &'static str,
    ntia: &'static str,
    /// CRA Phase 1, Phase 2 and the Art. 24 steward profile.
    cra: &'static str,
    fda: &'static str,
}

impl FamilyRuleIds {
    /// The id `level` reports the check under. A level outside the four
    /// families falls back to its family's generic rule.
    const fn get(&self, level: ComplianceLevel) -> &'static str {
        match level {
            ComplianceLevel::Minimum
            | ComplianceLevel::Standard
            | ComplianceLevel::Comprehensive => self.quality,
            ComplianceLevel::NtiaMinimum => self.ntia,
            ComplianceLevel::CraPhase1
            | ComplianceLevel::CraPhase2
            | ComplianceLevel::CraOssSteward => self.cra,
            ComplianceLevel::FdaMedicalDevice => self.fda,
            _ => generic_rule_id_for_level(level),
        }
    }
}

/// A spec version outside the range sbom-tools reads: CycloneDX older than
/// 1.4 or newer than 1.7, SPDX newer than 3.0.
const SPEC_VERSION_RULES: FamilyRuleIds = FamilyRuleIds {
    quality: "SBOM-QUALITY-SPEC-VERSION",
    ntia: "SBOM-NTIA-SPEC-VERSION",
    cra: "SBOM-CRA-SPEC-VERSION",
    fda: "SBOM-FDA-SPEC-VERSION",
};

/// An SPDX version that is neither 2.x nor 3.x (an SPDX 4.0 document is
/// also newer than sbom-tools reads, a second finding on the document).
const SPEC_VERSION_UNKNOWN_RULES: FamilyRuleIds = FamilyRuleIds {
    quality: "SBOM-QUALITY-SPEC-VERSION-UNKNOWN",
    ntia: "SBOM-NTIA-SPEC-VERSION-UNKNOWN",
    cra: "SBOM-CRA-SPEC-VERSION-UNKNOWN",
    fda: "SBOM-FDA-SPEC-VERSION-UNKNOWN",
};

/// A component without a well-formed format identifier (CycloneDX bom-ref,
/// SPDX SPDXID or spdxId).
const ELEMENT_ID_RULES: FamilyRuleIds = FamilyRuleIds {
    quality: "SBOM-QUALITY-ELEMENT-ID",
    ntia: "SBOM-NTIA-ELEMENT-ID",
    cra: "SBOM-CRA-ELEMENT-ID",
    fda: "SBOM-FDA-ELEMENT-ID",
};

/// Components the document lists more than once: entries that share a
/// canonical id, name and version, which the parser merged. One finding per
/// document.
const DUPLICATE_COMPONENT_RULES: FamilyRuleIds = FamilyRuleIds {
    quality: "SBOM-QUALITY-DUPLICATE-COMPONENT",
    ntia: "SBOM-NTIA-DUPLICATE-COMPONENT",
    cra: "SBOM-CRA-DUPLICATE-COMPONENT",
    fda: "SBOM-FDA-DUPLICATE-COMPONENT",
};

/// How many duplicated components a duplicate finding names before it
/// counts the rest.
const MAX_NAMED_DUPLICATES: usize = 5;

impl ComplianceChecker {
    pub(crate) fn check_document_metadata(
        &self,
        sbom: &NormalizedSbom,
        violations: &mut Vec<Violation>,
    ) {
        use crate::model::{CreatorType, ExternalRefType};

        // All levels require creator information
        if sbom.document.creators.is_empty() {
            let (requirement, rule_id) = match self.level {
                ComplianceLevel::NtiaMinimum => (
                    "NTIA Minimum Elements: Author".to_string(),
                    "SBOM-NTIA-AUTHOR",
                ),
                ComplianceLevel::FdaMedicalDevice => (
                    "FDA: SBOM creator/manufacturer identification".to_string(),
                    "SBOM-FDA-CREATOR",
                ),
                _ => (
                    "Document creator identification".to_string(),
                    if self.level.is_cra() {
                        "SBOM-CRA-CREATOR"
                    } else {
                        "SBOM-QUALITY-CREATOR"
                    },
                ),
            };
            violations.push(Violation {
                severity: match self.level {
                    ComplianceLevel::Minimum => ViolationSeverity::Warning,
                    _ => ViolationSeverity::Error,
                },
                category: ViolationCategory::DocumentMetadata,
                message: "SBOM must have creator/tool information".to_string(),
                element: None,
                requirement,
                rule_id,
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                deadline: None,
            });
        }

        // CRA: Manufacturer identification and product name. An
        // organization creator, the product's supplier (metadata.supplier)
        // or the described product's own manufacturer or supplier names the
        // manufacturer (see `manufacturer_identified`).
        if self.level.is_cra() {
            let sidecar_has_manufacturer = self
                .sidecar
                .as_ref()
                .is_some_and(|s| s.manufacturer_name.is_some());
            if !manufacturer_identified(sbom) {
                if sidecar_has_manufacturer {
                    violations.push(Violation {
                        severity: ViolationSeverity::Info,
                        category: ViolationCategory::DocumentMetadata,
                        message:
                            "[CRA Art. 13(16)] Manufacturer identified via CRA sidecar (consider adding to the SBOM directly for portability)"
                                .to_string(),
                        element: None,
                        requirement: "CRA Art. 13(16): Manufacturer identification".to_string(),
                        rule_id: "SBOM-CRA-ART-13-16",
                        component_id: None,
                        counts: None,
                        standard_refs: Vec::new(),
                        remediation: None,
                        finding_detail: None,
                        deadline: None,
                    });
                } else {
                    violations.push(Violation {
                        severity: ViolationSeverity::Warning,
                        category: ViolationCategory::DocumentMetadata,
                        message:
                            "[CRA Art. 13(16)] SBOM should identify the manufacturer (organization)"
                                .to_string(),
                        element: None,
                        requirement: "CRA Art. 13(16): Manufacturer identification".to_string(),
                        rule_id: "SBOM-CRA-ART-13-16",
                        component_id: None,
                        counts: None,
                        standard_refs: Vec::new(),
                        remediation: None,
                        finding_detail: None,
                        deadline: None,
                    });
                }
            }

            // Validate manufacturer email format if present: one finding per
            // invalid address, told apart by the address itself.
            for creator in &sbom.document.creators {
                if creator.creator_type == CreatorType::Organization
                    && let Some(email) = &creator.email
                    && !is_valid_email_format(email)
                {
                    violations.push(Violation {
                        severity: ViolationSeverity::Warning,
                        category: ViolationCategory::DocumentMetadata,
                        message: format!(
                            "[CRA Art. 13(16)] Manufacturer email '{email}' appears invalid"
                        ),
                        element: None,
                        requirement: "CRA Art. 13(16): Valid contact information".to_string(),
                        rule_id: "SBOM-CRA-ART-13-16-EMAIL",
                        component_id: None,
                        counts: None,
                        standard_refs: Vec::new(),
                        remediation: None,
                        finding_detail: Some(email.clone()),
                        deadline: None,
                    });
                }
            }

            // An empty or placeholder name names no product (an SPDX 2.x
            // document always has a DocumentName field, maybe empty).
            if !has_known_value(&sbom.document.name) {
                let sidecar_has_product_name = self
                    .sidecar
                    .as_ref()
                    .is_some_and(|s| s.product_name.is_some());
                if sidecar_has_product_name {
                    violations.push(Violation {
                        severity: ViolationSeverity::Info,
                        category: ViolationCategory::DocumentMetadata,
                        message: "[CRA Art. 13(15)] Product name provided via CRA sidecar (consider adding metadata.component.name to the SBOM)".to_string(),
                        element: None,
                        requirement: "CRA Art. 13(15): Product identification".to_string(),
                        rule_id: "SBOM-CRA-ART-13-15-PRODUCT",
                        component_id: None,
                        counts: None,
                        standard_refs: Vec::new(),
                        remediation: None,
                        finding_detail: None,
                        deadline: None,
                    });
                } else {
                    violations.push(Violation {
                        severity: ViolationSeverity::Warning,
                        category: ViolationCategory::DocumentMetadata,
                        message: "[CRA Art. 13(15)] SBOM should include the product name"
                            .to_string(),
                        element: None,
                        requirement: "CRA Art. 13(15): Product identification".to_string(),
                        rule_id: "SBOM-CRA-ART-13-15-PRODUCT",
                        component_id: None,
                        counts: None,
                        standard_refs: Vec::new(),
                        remediation: None,
                        finding_detail: None,
                        deadline: None,
                    });
                }
            }

            // CRA: Security contact / vulnerability disclosure point
            // First check document-level security contact (preferred). A
            // contact counts only when it reaches someone (`known_contact`):
            // NOASSERTION, n/a or an example.com address is no contact, as
            // for the EO 14028 and PCI DSS checks.
            let has_doc_security_contact = known_contact(sbom.document.security_contact.as_deref())
                || known_contact(sbom.document.vulnerability_disclosure_url.as_deref());

            // Fallback: check component-level external refs — but only on the
            // described product components. A third-party dependency's
            // upstream advisories or support URL is not the manufacturer's
            // contact.
            let has_component_security_contact = manufacturer_reference(sbom, is_contact_reference);

            if !has_doc_security_contact && !has_component_security_contact {
                let sidecar_has_security = self.sidecar.as_ref().is_some_and(|s| {
                    known_contact(s.security_contact.as_deref())
                        || known_contact(s.vulnerability_disclosure_url.as_deref())
                });
                if sidecar_has_security {
                    violations.push(Violation {
                        severity: ViolationSeverity::Info,
                        category: ViolationCategory::SecurityInfo,
                        message: "[CRA Art. 13(17)] Security contact provided via CRA sidecar (consider adding a security-contact externalReference to the SBOM)".to_string(),
                        element: None,
                        requirement: "CRA Art. 13(17): Vulnerability disclosure contact"
                            .to_string(),
                        rule_id: "SBOM-CRA-ART-13-17-CONTACT",
                        component_id: None,
                        counts: None,
                        standard_refs: Vec::new(),
                        remediation: None,
                        finding_detail: None,
                        deadline: None,
                    });
                } else {
                    violations.push(Violation {
                        severity: ViolationSeverity::Warning,
                        category: ViolationCategory::SecurityInfo,
                        message: format!(
                            "[CRA Art. 13(17)] SBOM should include a security contact or vulnerability disclosure reference{}{}{}",
                            unreachable_contact_note(sbom),
                            unreachable_sidecar_note(
                                self.sidecar.as_ref().and_then(|s| s.security_contact.as_deref())
                            ),
                            unreachable_sidecar_note(
                                self.sidecar
                                    .as_ref()
                                    .and_then(|s| s.vulnerability_disclosure_url.as_deref())
                            ),
                        ),
                        element: None,
                        requirement: "CRA Art. 13(17): Vulnerability disclosure contact"
                            .to_string(),
                        rule_id: "SBOM-CRA-ART-13-17-CONTACT",
                        component_id: None,
                        counts: None,
                        standard_refs: Vec::new(),
                        remediation: None,
                        finding_detail: None,
                        deadline: None,
                    });
                }
            }

            // CRA: Check for primary/root product component identification
            if sbom.primary_component_id.is_none() && package_components(sbom).nth(1).is_some() {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::DocumentMetadata,
                    message: "[CRA Annex I] SBOM should identify the primary product component (CycloneDX metadata.component or SPDX documentDescribes)".to_string(),
                    element: None,
                    requirement: "CRA Annex I: Primary product identification".to_string(),
                    rule_id: "SBOM-CRA-ANNEX-I-PRIMARY",
                    component_id: None,
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            }

            // CRA: Check for support end date (informational). The support
            // period is determined under Art. 13(8); its end date must be
            // disclosed at purchase (Art. 13(19)) and accompany the product
            // (Annex II (7)). The CRA sidecar's `supportEndDate` declares it
            // too: ignoring it asked for a date the run already had.
            let support_end_declared = sbom.document.support_end_date.is_some()
                || self
                    .sidecar
                    .as_ref()
                    .is_some_and(|s| s.support_end_date.is_some());
            if !support_end_declared {
                violations.push(Violation {
                    severity: ViolationSeverity::Info,
                    category: ViolationCategory::SecurityInfo,
                    message: "[CRA Art. 13(8) / 13(19)] Consider specifying a support end date for security updates".to_string(),
                    element: None,
                    requirement: "CRA Art. 13(8) / 13(19): Support period disclosure".to_string(),
                    rule_id: "SBOM-CRA-ART-13-8",
                    component_id: None,
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            }

            // CRA Annex I Part II (1): Machine-readable SBOM format validation
            // The CRA requires SBOMs in a "commonly used and machine-readable"
            // format (Annex I Part II (1)) but names no versions, so the floor
            // is tool policy: CycloneDX 1.4+, and SPDX 2.3+, the first SPDX
            // release whose package release / valid-until dates can carry the
            // support period. (EO 14028 accepts SPDX 2.2, which the NTIA
            // report it defers to names.) Versions compare numerically; an
            // absent or unparseable version skips the gate instead of
            // false-failing.
            let minimum = match sbom.document.format {
                SbomFormat::CycloneDx => crate::model::SpecVersion::new(1, 4, 0),
                SbomFormat::Spdx => crate::model::SpecVersion::new(2, 3, 0),
            };
            let format_ok = sbom
                .document
                .spec_version_parsed()
                .is_none_or(|v| v >= minimum);
            if !format_ok {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::FormatSpecific,
                    message: format!(
                        "[CRA Annex I Part II (1)] SBOM format version {} {} may not meet the CRA machine-readable requirement; use CycloneDX 1.4+, SPDX 2.3+, or SPDX 3.0+",
                        sbom.document.format, sbom.document.spec_version
                    ),
                    element: None,
                    requirement: "CRA Annex I Part II (1): Machine-readable SBOM format"
                        .to_string(),
                    rule_id: "SBOM-CRA-MACHINE-READABLE",
                    component_id: None,
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            }

            // CRA Annex I Part II (1): Unique product identifier traceability
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
                                "[CRA Annex I Part II (1)] Primary component '{}' missing unique identifier (PURL/CPE) for cross-update traceability",
                                primary.name
                            ),
                            element: Some(primary.name.clone()),
                            requirement: "CRA Annex I Part II (1): Product identifier traceability across updates".to_string(),
                            rule_id: "SBOM-CRA-ANNEX-I-TRACEABILITY",
                            component_id: Some(primary.canonical_id.value().to_string()),
                            counts: None,
                            standard_refs: Vec::new(),
                            remediation: None,
                            finding_detail: None,
                            deadline: None,
                        });
            }
        }

        // CRA Phase 2-only checks (full application of the regulation: 11 Dec 2027)
        if matches!(self.level, ComplianceLevel::CraPhase2) {
            // CRA Annex I Part II (5): Coordinated vulnerability disclosure policy reference
            // Check for a vulnerability disclosure policy URL or advisories reference
            // Component-level Advisories refs count only on the described
            // product components — a dependency's upstream advisories URL is
            // not the manufacturer's CVD policy. The disclosure URL comes from
            // the primary's URL-shaped advisories reference only: a support
            // link is no disclosure policy. A placeholder URL is no policy
            // either (`known_contact`).
            let has_vuln_disclosure_policy =
                known_contact(sbom.document.vulnerability_disclosure_url.as_deref())
                    || manufacturer_reference(sbom, |r| {
                        matches!(r.ref_type, ExternalRefType::Advisories) && is_contact_reference(r)
                    });
            if !has_vuln_disclosure_policy {
                let sidecar_has_cvd = self
                    .sidecar
                    .as_ref()
                    .is_some_and(|s| known_contact(s.vulnerability_disclosure_url.as_deref()));
                if sidecar_has_cvd {
                    violations.push(Violation {
                        severity: ViolationSeverity::Info,
                        category: ViolationCategory::SecurityInfo,
                        message: "[CRA Annex I Part II (5)] CVD policy URL provided via CRA sidecar (consider adding an advisories externalReference to the SBOM)".to_string(),
                        element: None,
                        requirement: "CRA Annex I Part II (5): Coordinated vulnerability disclosure policy".to_string(),
                        rule_id: "SBOM-CRA-CVD-POLICY",
                        component_id: None,
                        counts: None,
                        standard_refs: Vec::new(),
                        remediation: None,
                        finding_detail: None,
                        deadline: None,
                    });
                } else {
                    violations.push(Violation {
                        severity: ViolationSeverity::Warning,
                        category: ViolationCategory::SecurityInfo,
                        message: "[CRA Annex I Part II (5)] SBOM should reference a coordinated vulnerability disclosure policy (advisories URL or disclosure URL)".to_string(),
                        element: None,
                        requirement: "CRA Annex I Part II (5): Coordinated vulnerability disclosure policy".to_string(),
                        rule_id: "SBOM-CRA-CVD-POLICY",
                        component_id: None,
                        counts: None,
                        standard_refs: Vec::new(),
                        remediation: None,
                        finding_detail: None,
                        deadline: None,
                    });
                }
            }

            // CRA Art. 13(8) / Annex II (7): Component lifecycle status
            // Check whether the primary component (or any top-level component) has end-of-life
            // or lifecycle information. Currently we check support_end_date at doc level.
            // Also check for lifecycle properties on components.
            if !self.has_support_lifecycle_evidence(sbom) {
                violations.push(Violation {
                    severity: ViolationSeverity::Info,
                    category: ViolationCategory::SecurityInfo,
                    message: "[CRA Art. 13(8) / Annex II (7)] Consider including component lifecycle/end-of-support information".to_string(),
                    element: None,
                    requirement: "CRA Annex II (7): Component lifecycle status".to_string(),
                    rule_id: "SBOM-CRA-LIFECYCLE",
                    component_id: None,
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            }

            // CRA Annex V: EU Declaration of Conformity reference
            // Check for an attestation, certification, or declaration-of-conformity
            // reference on the described product: a dependency's own
            // certification or attestation is not the product's declaration.
            let has_conformity_ref = manufacturer_reference(sbom, |r| {
                matches!(
                    r.ref_type,
                    ExternalRefType::Attestation | ExternalRefType::Certification
                ) || (matches!(r.ref_type, ExternalRefType::Other(ref s) if s.to_lowercase().contains("declaration-of-conformity")))
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
                        "[CRA Annex V] Missing reference to the EU Declaration of Conformity (attestation or certification external reference) for product class {}",
                        self.effective_product_class().label()
                    ),
                    element: None,
                    requirement: "CRA Annex V: EU Declaration of Conformity reference".to_string(),
                    rule_id: "SBOM-CRA-ANNEX-V",
                    component_id: None,
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            }
        }

        // FDA requires the device manufacturer: an organization creator, or
        // the product's own manufacturer or supplier (see
        // `manufacturer_identified`).
        if matches!(self.level, ComplianceLevel::FdaMedicalDevice) {
            if !manufacturer_identified(sbom) {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::DocumentMetadata,
                    message: "FDA: SBOM should identify the device manufacturer (an organization \
                              creator, or the manufacturer or supplier of the primary component)"
                        .to_string(),
                    element: None,
                    requirement: "FDA: Manufacturer identification".to_string(),
                    rule_id: "SBOM-FDA-SUPPLIER",
                    component_id: None,
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
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
                    rule_id: "SBOM-FDA-CONTACT",
                    component_id: None,
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            }

            // FDA: Document name required; an empty or placeholder name is
            // no name.
            if !has_known_value(&sbom.document.name) {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::DocumentMetadata,
                    message: "FDA: SBOM should have a document name/title".to_string(),
                    element: None,
                    requirement: "FDA: Document identification".to_string(),
                    rule_id: "SBOM-FDA-NAME",
                    component_id: None,
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            }

            // FDA 2023 premarket guidance / FD&C §524B: beyond the NTIA
            // baseline, the SBOM package must convey each component's level
            // of support and end-of-support date. The guidance allows this
            // to accompany the SBOM, so absence is a Warning (not a gating
            // Error): we accept a document-level support end date, component
            // lifecycle/EOL properties, or the sidecar's support end date as
            // evidence. (A run hands the CRA sidecar to the CRA, EUCC and AI
            // Act profiles only, see `ComplianceRunConfig::checker`, so in the
            // CLI FDA judges the SBOM's own lifecycle data.)
            if !self.has_support_lifecycle_evidence(sbom) {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::SecurityInfo,
                    message: "FDA: no level-of-support or end-of-support information found \
                        (required by the premarket cybersecurity guidance / FD&C §524B; \
                        add component lifecycle/end-of-support data or provide it alongside the SBOM)"
                        .to_string(),
                    element: None,
                    requirement: "FDA: Level of support and end-of-support date".to_string(),
                    rule_id: "SBOM-FDA-SUPPORT",
                    component_id: None,
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            }
        }

        // NTIA "Timestamp" is one of the seven required minimum data fields,
        // and the FDA premarket guidance incorporates the NTIA baseline.
        // `DocumentMetadata::created` is never None, but a missing/invalid
        // source timestamp is stored as the UNIX_EPOCH sentinel (see
        // `has_known_timestamp`), so gate on that rather than assuming it is
        // always meaningful. An invalid one is quoted, not called missing.
        if matches!(
            self.level,
            ComplianceLevel::NtiaMinimum
                | ComplianceLevel::FdaMedicalDevice
                | ComplianceLevel::Comprehensive
        ) && !sbom.document.has_known_timestamp()
        {
            let requirement = if self.level == ComplianceLevel::FdaMedicalDevice {
                "FDA (NTIA baseline): Timestamp".to_string()
            } else {
                "NTIA Minimum Elements: Timestamp".to_string()
            };
            let message = unparseable_timestamp(sbom).map_or_else(
                || "SBOM is missing a creation timestamp (NTIA required data field)".to_string(),
                |gap| format!("SBOM has {gap} (NTIA required data field)"),
            );
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::DocumentMetadata,
                message,
                element: None,
                requirement,
                rule_id: "SBOM-NTIA-TIMESTAMP",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                deadline: None,
            });
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
            let rule_id = if self.level == ComplianceLevel::FdaMedicalDevice {
                "SBOM-FDA-NAMESPACE"
            } else if self.level.is_cra() {
                "SBOM-CRA-SERIAL"
            } else {
                "SBOM-QUALITY-SERIAL"
            };
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::DocumentMetadata,
                message: "SBOM should have a serial number/unique identifier".to_string(),
                element: None,
                requirement: "Document unique identification".to_string(),
                rule_id,
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                deadline: None,
            });
        }
    }

    /// Whether the SBOM (or its sidecar) carries any support-lifecycle
    /// evidence: a document-level support end date, component
    /// lifecycle/end-of-life/end-of-support properties, or a sidecar
    /// support end date. Shared by the CRA lifecycle (Art. 13(8) /
    /// Annex II (7)) and FDA level-of-support checks.
    fn has_support_lifecycle_evidence(&self, sbom: &NormalizedSbom) -> bool {
        sbom.document.support_end_date.is_some()
            || self
                .sidecar
                .as_ref()
                .is_some_and(|s| s.support_end_date.is_some())
            || sbom.components.values().any(|comp| {
                comp.extensions.properties.iter().any(|p| {
                    // Token-match the property name — a bare substring test
                    // let "geolocation" satisfy the lifecycle element via
                    // its embedded "eol" — and require a real value.
                    let name_lower = p.name.to_lowercase();
                    let is_lifecycle_name = name_lower
                        .split(|c: char| !c.is_ascii_alphanumeric())
                        .any(|t| t == "eol" || t == "lifecycle")
                        || name_lower.contains("end-of-life")
                        || name_lower.contains("end-of-support")
                        || name_lower.contains("endoflife")
                        || name_lower.contains("endofsupport");
                    is_lifecycle_name && known_value(Some(p.value.as_str())).is_some()
                })
            })
    }

    pub(crate) fn check_components(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        use crate::model::HashAlgorithm;

        // No package-scoped component means the per-component rules below
        // have nothing to judge; that is a finding, not a pass.
        let (inventory_requirement, inventory_rule) = match self.level {
            ComplianceLevel::NtiaMinimum => (
                "NTIA Minimum Elements: component inventory",
                "SBOM-NTIA-INVENTORY",
            ),
            ComplianceLevel::FdaMedicalDevice => (
                "FDA: inventory of the device's software components",
                "SBOM-FDA-INVENTORY",
            ),
            level if level.is_cra() => (
                "CRA Annex I Part II (1): SBOM of the product's components",
                "SBOM-CRA-INVENTORY",
            ),
            _ => ("Component inventory", "SBOM-QUALITY-INVENTORY"),
        };
        violations.extend(inventory_absent_violation(
            sbom,
            inventory_rule,
            inventory_requirement,
        ));

        // All components: names apply to every component; the package
        // carve-out follows the name check below.
        for comp in sbom.components.values() {
            // All levels: component must have a name. Whitespace-only names
            // and placeholder sentinels count as missing, but genuine
            // packages named "none"/"unknown" (corroborated by their PURL)
            // do not (see `known_component_name`).
            if !known_component_name(comp) {
                let (requirement, rule_id) = match self.level {
                    ComplianceLevel::NtiaMinimum => (
                        "NTIA Minimum Elements: Component Name".to_string(),
                        "SBOM-NTIA-NAME",
                    ),
                    ComplianceLevel::FdaMedicalDevice => (
                        "FDA: Component name (required)".to_string(),
                        "SBOM-FDA-COMPONENT-NAME",
                    ),
                    _ => (
                        "Component name (required)".to_string(),
                        if self.level.is_cra() {
                            "SBOM-CRA-COMPONENT-NAME"
                        } else {
                            "SBOM-QUALITY-NAME"
                        },
                    ),
                };
                violations.push(Violation {
                    severity: ViolationSeverity::Error,
                    category: ViolationCategory::ComponentIdentification,
                    message: "Component must have a name".to_string(),
                    element: Some(comp.identifiers.format_id.clone()),
                    requirement,
                    rule_id,
                    component_id: Some(comp.canonical_id.value().to_string()),
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            }

            // File/snippet inventory entries and cryptographic assets are not
            // packages: the version / unique-identifier / supplier / license
            // / hash requirements below do not apply to them (NTIA scopes
            // those to components). Without this carve-out, a file-cataloguing
            // SBOM emits thousands of spurious Errors and a CBOM fails on
            // package fields its algorithms and protocols cannot have.
            if !comp.component_type.is_package_scoped() {
                continue;
            }

            // NTIA minimum & FDA: version required (the CRA levels include
            // the Art. 24 steward profile — steward SBOMs still need
            // versioned components)
            if matches!(
                self.level,
                ComplianceLevel::NtiaMinimum
                    | ComplianceLevel::FdaMedicalDevice
                    | ComplianceLevel::Standard
                    | ComplianceLevel::CraPhase1
                    | ComplianceLevel::CraPhase2
                    | ComplianceLevel::CraOssSteward
                    | ComplianceLevel::Comprehensive
            ) && !has_known_value(&comp.version)
            {
                let (req, msg, rule_id) = match self.level {
                    ComplianceLevel::FdaMedicalDevice => (
                        "FDA: Component version".to_string(),
                        format!("Component '{}' missing version", comp.name),
                        "SBOM-FDA-VERSION",
                    ),
                    ComplianceLevel::CraPhase1
                    | ComplianceLevel::CraPhase2
                    | ComplianceLevel::CraOssSteward => (
                        "CRA Annex I Part II (1): Component version".to_string(),
                        format!(
                            "[CRA Annex I Part II (1)] Component '{}' missing version",
                            comp.name
                        ),
                        "SBOM-CRA-COMPONENT-VERSION",
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
                    component_id: Some(comp.canonical_id.value().to_string()),
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            }

            // NTIA, Standard+ & FDA: should have PURL/CPE/SWHID/SWID
            // "Other Unique Identifiers" is one of the seven NTIA minimum
            // data fields; CRA prEN 40000-1-3 [PRE-7-RQ-07] explicitly names
            // PURL, CPE, SWHID
            if matches!(
                self.level,
                ComplianceLevel::NtiaMinimum
                    | ComplianceLevel::Standard
                    | ComplianceLevel::FdaMedicalDevice
                    | ComplianceLevel::CraPhase1
                    | ComplianceLevel::CraPhase2
                    | ComplianceLevel::CraOssSteward
                    | ComplianceLevel::Comprehensive
            ) && !comp.identifiers.has_cra_identifier()
            {
                let severity = if matches!(
                    self.level,
                    ComplianceLevel::NtiaMinimum
                        | ComplianceLevel::FdaMedicalDevice
                        | ComplianceLevel::CraPhase1
                        | ComplianceLevel::CraPhase2
                        | ComplianceLevel::CraOssSteward
                ) {
                    ViolationSeverity::Error
                } else {
                    ViolationSeverity::Warning
                };
                let (message, requirement, rule_id) = match self.level {
                    ComplianceLevel::NtiaMinimum => (
                        format!(
                            "Component '{}' missing unique identifier (PURL/CPE/SWHID/SWID)",
                            comp.name
                        ),
                        "NTIA Minimum Elements: Other Unique Identifiers".to_string(),
                        "SBOM-NTIA-IDENTIFIER",
                    ),
                    ComplianceLevel::FdaMedicalDevice => (
                        format!(
                            "Component '{}' missing unique identifier (PURL/CPE/SWHID/SWID)",
                            comp.name
                        ),
                        "FDA: Unique component identifier".to_string(),
                        "SBOM-FDA-IDENTIFIER",
                    ),
                    ComplianceLevel::CraPhase1
                    | ComplianceLevel::CraPhase2
                    | ComplianceLevel::CraOssSteward => (
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
                        "SBOM-QUALITY-IDENTIFIER",
                    ),
                };
                violations.push(Violation {
                    severity,
                    category: ViolationCategory::ComponentIdentification,
                    message,
                    element: Some(comp.name.clone()),
                    requirement,
                    rule_id,
                    component_id: Some(comp.canonical_id.value().to_string()),
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            }

            // NTIA minimum & FDA: supplier required
            if matches!(
                self.level,
                ComplianceLevel::NtiaMinimum
                    | ComplianceLevel::FdaMedicalDevice
                    | ComplianceLevel::CraPhase1
                    | ComplianceLevel::CraPhase2
                    | ComplianceLevel::CraOssSteward
                    | ComplianceLevel::Comprehensive
            ) && !has_known_producer(comp)
            {
                let severity = match self.level {
                    ComplianceLevel::CraPhase1
                    | ComplianceLevel::CraPhase2
                    | ComplianceLevel::CraOssSteward => ViolationSeverity::Warning,
                    _ => ViolationSeverity::Error,
                };
                let (message, requirement, rule_id) = match self.level {
                    ComplianceLevel::FdaMedicalDevice => (
                        format!("Component '{}' missing supplier/manufacturer", comp.name),
                        "FDA: Supplier/manufacturer information".to_string(),
                        "SBOM-FDA-SUPPLIER",
                    ),
                    // Component suppliers are part of the Annex I Part II (1)
                    // SBOM inventory — distinct from the document-level
                    // Art. 13(16) manufacturer-identification obligation.
                    ComplianceLevel::CraPhase1 | ComplianceLevel::CraPhase2 => (
                        format!(
                            "[CRA Annex I Part II (1)] Component '{}' missing supplier/manufacturer",
                            comp.name
                        ),
                        "CRA Annex I Part II (1): Component supplier information".to_string(),
                        "SBOM-CRA-COMPONENT-SUPPLIER",
                    ),
                    // Steward profile: component supplier info is part of the
                    // Art. 24 SBOM floor, but stewards are exempt from the
                    // Art. 13(16) manufacturer-identification obligation, so
                    // the citation must not reference it.
                    ComplianceLevel::CraOssSteward => (
                        format!(
                            "[CRA Art. 24] Component '{}' missing supplier/manufacturer",
                            comp.name
                        ),
                        "CRA Art. 24 (steward): Component supplier information".to_string(),
                        "SBOM-CRA-ART-24-SUPPLIER",
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
                    component_id: Some(comp.canonical_id.value().to_string()),
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            }

            // Standard+: should have license information. The licence test
            // every standard shares (`has_known_license`): a sentinel such as
            // NOASSERTION or a placeholder such as TBD names no licence, as
            // under CRA Art. 13(5) (until v0.4.0 any value passed here).
            if matches!(
                self.level,
                ComplianceLevel::Standard | ComplianceLevel::Comprehensive
            ) && !has_known_license(comp)
            {
                let present: Vec<&str> = comp
                    .licenses
                    .all_licenses()
                    .iter()
                    .map(|l| l.expression.trim())
                    .filter(|e| !e.is_empty())
                    .collect();
                let message = if present.is_empty() {
                    format!("Component '{}' should have license information", comp.name)
                } else {
                    format!(
                        "Component '{}' should have license information: '{}' names no license",
                        comp.name,
                        present.join("', '")
                    )
                };
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::LicenseInfo,
                    message,
                    element: Some(comp.name.clone()),
                    requirement: "License declaration".to_string(),
                    rule_id: "SBOM-QUALITY-LICENSE",
                    component_id: Some(comp.canonical_id.value().to_string()),
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            }

            // Only plausible digests count (see `plausible_digest`): an empty
            // or garbage value carries no integrity information, and the
            // finding names why each present hash did not count.
            let plausible: Vec<_> = comp
                .hashes
                .iter()
                .filter(|h| plausible_digest(&h.algorithm, &h.value))
                .collect();
            let no_valid_hash = |citation: &str, note: &str| {
                if comp.hashes.is_empty() {
                    format!(
                        "{citation}Component '{}' missing cryptographic hash{note}",
                        comp.name
                    )
                } else {
                    format!(
                        "{citation}Component '{}' has no valid cryptographic hash{note}: {}",
                        comp.name,
                        digest_problems(&comp.hashes).join("; ")
                    )
                }
            };

            // FDA & Comprehensive: must have cryptographic hashes
            if matches!(
                self.level,
                ComplianceLevel::FdaMedicalDevice | ComplianceLevel::Comprehensive
            ) {
                if plausible.is_empty() {
                    violations.push(Violation {
                        severity: if self.level == ComplianceLevel::FdaMedicalDevice {
                            ViolationSeverity::Error
                        } else {
                            ViolationSeverity::Warning
                        },
                        category: ViolationCategory::IntegrityInfo,
                        message: no_valid_hash("", ""),
                        element: Some(comp.name.clone()),
                        requirement: if self.level == ComplianceLevel::FdaMedicalDevice {
                            "FDA: Cryptographic hash for integrity".to_string()
                        } else {
                            "Integrity verification (hashes)".to_string()
                        },
                        rule_id: if self.level == ComplianceLevel::FdaMedicalDevice {
                            "SBOM-FDA-HASH"
                        } else {
                            "SBOM-QUALITY-HASH"
                        },
                        component_id: Some(comp.canonical_id.value().to_string()),
                        counts: None,
                        standard_refs: Vec::new(),
                        remediation: None,
                        finding_detail: None,
                        deadline: None,
                    });
                } else if self.level == ComplianceLevel::FdaMedicalDevice {
                    // FDA: Check for strong hash algorithm (SHA-256 or better)
                    let has_strong_hash = plausible.iter().any(|h| {
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
                        let mut message = format!(
                            "Component '{}' has only weak hash algorithm (use SHA-256+)",
                            comp.name
                        );
                        let problems = digest_problems(&comp.hashes);
                        if !problems.is_empty() {
                            message.push_str("; ");
                            message.push_str(&problems.join("; "));
                        }
                        violations.push(Violation {
                            severity: ViolationSeverity::Warning,
                            category: ViolationCategory::IntegrityInfo,
                            message,
                            element: Some(comp.name.clone()),
                            requirement: "FDA: Strong cryptographic hash (SHA-256 or better)"
                                .to_string(),
                            rule_id: "SBOM-FDA-HASH",
                            component_id: Some(comp.canonical_id.value().to_string()),
                            counts: None,
                            standard_refs: Vec::new(),
                            remediation: None,
                            finding_detail: None,
                            deadline: None,
                        });
                    }
                }
            }

            // CRA: hashes are recommended for integrity verification
            if self.level.is_cra() && plausible.is_empty() {
                violations.push(Violation {
                    severity: ViolationSeverity::Info,
                    category: ViolationCategory::IntegrityInfo,
                    message: no_valid_hash(
                        "[CRA Annex I Part I (2)(f)] ",
                        " (recommended for integrity)",
                    ),
                    element: Some(comp.name.clone()),
                    requirement:
                        "CRA Annex I Part I (2)(f): Component integrity information (hash)"
                            .to_string(),
                    rule_id: "SBOM-CRA-ANNEX-I-INTEGRITY",
                    component_id: Some(comp.canonical_id.value().to_string()),
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            }
        }
    }

    pub(crate) fn check_dependencies(
        &self,
        sbom: &NormalizedSbom,
        violations: &mut Vec<Violation>,
    ) {
        // NTIA & FDA require dependency relationships (the CRA levels
        // include the Art. 24 steward profile)
        if matches!(
            self.level,
            ComplianceLevel::NtiaMinimum
                | ComplianceLevel::FdaMedicalDevice
                | ComplianceLevel::CraPhase1
                | ComplianceLevel::CraPhase2
                | ComplianceLevel::CraOssSteward
                | ComplianceLevel::Comprehensive
        ) {
            // Dependency relationships are a package-graph element: crypto
            // assets, files and services need not appear in it.
            let has_deps = !sbom.edges.is_empty();
            let package_total = package_components(sbom).count();
            let has_multiple_components = package_total > 1;

            let (requirement, rule_id) = match self.level {
                ComplianceLevel::CraPhase1
                | ComplianceLevel::CraPhase2
                | ComplianceLevel::CraOssSteward => (
                    "CRA Annex I: Dependency relationships",
                    "SBOM-CRA-ANNEX-I-DEPENDENCY",
                ),
                ComplianceLevel::FdaMedicalDevice => {
                    ("FDA: Dependency relationships", "SBOM-FDA-DEPENDENCY")
                }
                _ => ("NTIA: Dependency relationships", "SBOM-NTIA-DEPENDENCY"),
            };

            if has_multiple_components && !has_deps {
                let message = match self.level {
                    ComplianceLevel::CraPhase1
                    | ComplianceLevel::CraPhase2
                    | ComplianceLevel::CraOssSteward =>
                        "[CRA Annex I] SBOM with multiple components must include dependency relationships".to_string(),
                    _ =>
                        "SBOM with multiple components must include dependency relationships".to_string(),
                };
                violations.push(Violation {
                    severity: ViolationSeverity::Error,
                    category: ViolationCategory::DependencyInfo,
                    message,
                    element: None,
                    requirement: requirement.to_string(),
                    rule_id,
                    component_id: None,
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            } else if has_multiple_components {
                // Edges exist — check the graph is more than a token gesture.
                // A single edge among N components used to satisfy the
                // "dependency relationships" element for the whole SBOM.
                use std::collections::HashSet;
                let mut connected: HashSet<&crate::model::CanonicalId> = HashSet::new();
                for edge in &sbom.edges {
                    connected.insert(&edge.from);
                    connected.insert(&edge.to);
                }

                // A component that appears in the CycloneDX dependencies
                // array with an explicitly empty dependsOn has positively
                // declared "no dependencies" — that is documentation, not a
                // gap (the parser marks it with a synthetic property).
                let declares_no_deps = |c: &crate::model::Component| {
                    c.extensions
                        .properties
                        .iter()
                        .any(|p| p.name == crate::parsers::DECLARED_NO_DEPENDENCIES_PROPERTY)
                };

                // The primary product component must participate in the
                // dependency graph — an SBOM whose root has no declared
                // relationships does not describe the product's dependencies.
                if let Some(primary_id) = &sbom.primary_component_id
                    && let Some(primary) = sbom.components.get(primary_id)
                    && !connected.contains(primary_id)
                    && !declares_no_deps(primary)
                {
                    violations.push(Violation {
                        severity: ViolationSeverity::Warning,
                        category: ViolationCategory::DependencyInfo,
                        message: format!(
                            "Primary component '{}' participates in no dependency relationship",
                            primary.name
                        ),
                        element: Some(primary.name.clone()),
                        requirement: requirement.to_string(),
                        rule_id,
                        component_id: Some(primary.canonical_id.value().to_string()),
                        counts: None,
                        standard_refs: Vec::new(),
                        remediation: None,
                        finding_detail: None,
                        deadline: None,
                    });
                }

                // Most components disconnected from the graph → the
                // dependency information is likely incomplete. Suppressed
                // when the SBOM explicitly declares an incomplete inventory.
                use crate::model::CompletenessDeclaration as CD;
                let declared_incomplete = matches!(
                    sbom.document.completeness_declaration,
                    CD::Incomplete | CD::IncompleteFirstPartyOnly | CD::IncompleteThirdPartyOnly
                );
                let total = package_total;
                let orphans = package_components(sbom)
                    .filter(|c| !connected.contains(&c.canonical_id) && !declares_no_deps(c))
                    .count();
                // FDA keeps the retired fast-path's any-orphan sensitivity
                // ("each component's dependencies"); other standards warn
                // only when orphans form a majority.
                let fda = self.level == ComplianceLevel::FdaMedicalDevice;
                if !declared_incomplete
                    && ((fda && orphans >= 1) || (orphans >= 2 && orphans * 2 > total))
                {
                    let pct = (orphans * 100) / total.max(1);
                    violations.push(Violation {
                        severity: ViolationSeverity::Warning,
                        category: ViolationCategory::DependencyInfo,
                        message: format!(
                            "{orphans}/{total} components ({pct}%) participate in no dependency relationship; dependency information appears incomplete"
                        ),
                        element: None,
                        requirement: requirement.to_string(),
                        rule_id,
                        component_id: None,
                        counts: Some(ViolationCounts {
                            affected: orphans,
                            total,
                        }),
                        standard_refs: Vec::new(),
                        remediation: None,
                        finding_detail: None,
                        deadline: None,
                    });
                }
            }
        }

        // CRA product-class calibration: dependency cycles undermine the
        // reliability of the SBOM's dependency graph (Annex I Part II (1)
        // requires the SBOM to cover the product's dependencies). Severity
        // scales with the CRA product class (`ClassCheck::Cycles`). The
        // cycles are counted in linear time over the edges, for a graph of
        // any size: reading them from DependencyMetrics skipped (and passed)
        // every graph above its 1,000,000-edge analysis limit.
        if self.level.is_cra() && !sbom.edges.is_empty() {
            let cycle_count = crate::quality::cycles::dependency_cycle_count(sbom);
            if cycle_count > 0
                && let Some(severity) = self.class_severity(ClassCheck::Cycles)
            {
                violations.push(Violation {
                    severity,
                    category: ViolationCategory::DependencyInfo,
                    message: format!(
                        "[CRA Annex I Part II (1)] Dependency graph contains {cycle_count} cycle(s); cyclic dependency declarations make the component inventory ambiguous"
                    ),
                    element: None,
                    requirement: "CRA Annex I Part II (1): Dependency graph consistency"
                        .to_string(),
                    rule_id: "SBOM-CRA-CYCLES",
                    component_id: None,
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            }
        }

        // CRA: warn if multiple root components (no incoming edges) and no primary component set
        if self.level.is_cra()
            && package_components(sbom).nth(1).is_some()
            && sbom.primary_component_id.is_none()
        {
            use std::collections::HashSet;
            let mut incoming: HashSet<&crate::model::CanonicalId> = HashSet::new();
            for edge in &sbom.edges {
                incoming.insert(&edge.to);
            }
            // Count roots among the components that actually exist — edges
            // may reference ids that are not in the component map, so
            // `len() - incoming.len()` would undercount.
            let root_count = sbom
                .components
                .keys()
                .filter(|id| !incoming.contains(id))
                .count();
            if root_count > 1 {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::DependencyInfo,
                    message: "[CRA Annex I] SBOM appears to have multiple root components; identify a primary product component for top-level dependencies".to_string(),
                    element: None,
                    requirement: "CRA Annex I: Top-level dependency clarity".to_string(),
                    rule_id: "SBOM-CRA-ANNEX-I-DEPENDENCY-ROOTS",
                    component_id: None,
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            }
        }
    }

    pub(crate) fn check_vulnerability_metadata(
        &self,
        sbom: &NormalizedSbom,
        violations: &mut Vec<Violation>,
    ) {
        // FDA: surface unresolved critical/high vulnerabilities — premarket
        // submissions must address known vulnerabilities.
        if matches!(self.level, ComplianceLevel::FdaMedicalDevice) {
            use crate::model::Severity;
            use std::collections::HashSet;
            // Count distinct vulnerability ids — one CVE affecting five
            // components is one vulnerability, not five. A vulnerability
            // whose own VEX statement is a justified not_affected is not
            // unresolved: it documents why the device is not affected, as
            // the CRA Phase 2 checks below accept (`justified_not_affected`).
            // Until v0.4.0 every entry counted, whatever its VEX state.
            let vulns: Vec<_> = sbom
                .all_vulnerabilities()
                .into_iter()
                .filter(|(_, v)| !justified_not_affected(v))
                .collect();
            let critical = vulns
                .iter()
                .filter(|(_, v)| matches!(v.severity, Some(Severity::Critical)))
                .map(|(_, v)| v.id.as_str())
                .collect::<HashSet<_>>()
                .len();
            let high = vulns
                .iter()
                .filter(|(_, v)| matches!(v.severity, Some(Severity::High)))
                .map(|(_, v)| v.id.as_str())
                .collect::<HashSet<_>>()
                .len();
            if critical > 0 || high > 0 {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::SecurityInfo,
                    message: format!(
                        "SBOM contains {critical} critical and {high} high severity vulnerabilities"
                    ),
                    element: None,
                    requirement: "FDA: Known vulnerability assessment".to_string(),
                    rule_id: "SBOM-FDA-SECURITY",
                    component_id: None,
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            }
        }

        if !matches!(self.level, ComplianceLevel::CraPhase2) {
            return;
        }

        // One finding per vulnerability of a component: the vulnerability id
        // tells a component's findings apart.
        for (comp, vuln) in sbom.all_vulnerabilities() {
            // A justified VEX `not_affected` statement documents why the
            // vulnerability needs no fix (see `justified_not_affected`), so
            // neither check below asks anything more of the entry.
            if justified_not_affected(vuln) {
                continue;
            }

            if vuln.severity.is_none() && vuln.cvss.is_empty() {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::SecurityInfo,
                    message: format!(
                        "[CRA Annex I Part II (4)] Vulnerability '{}' in '{}' lacks severity or CVSS score",
                        vuln.id, comp.name
                    ),
                    element: Some(comp.name.clone()),
                    requirement: "CRA Annex I Part II (4): Vulnerability metadata completeness"
                        .to_string(),
                    rule_id: "SBOM-CRA-VULN-METADATA",
                    component_id: Some(comp.canonical_id.value().to_string()),
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: Some(vuln.id.clone()),
                    deadline: None,
                });
            }

            // A remediation declared without a fixed version or any text that
            // tells users how to apply it (Annex I Part II (4) asks for
            // information that helps them remediate). CycloneDX reaches this
            // through an analysis.response of update / workaround_available
            // with neither a recommendation nor a workaround (see the
            // parser's cdx_remediation). The other sources cannot, by
            // construction: SPDX 2.x carries no vulnerability data; the
            // SPDX 3.0 parser builds no remediation record (a VEX
            // actionStatement stays in the VEX status); the CSAF, OpenVEX and
            // CycloneDX VEX overlays set VEX status only; and OSV enrichment
            // always records both a fixed version and a description.
            if let Some(remediation) = &vuln.remediation
                && remediation.fixed_version.is_none()
                && remediation.description.is_none()
            {
                violations.push(Violation {
                        severity: ViolationSeverity::Info,
                        category: ViolationCategory::SecurityInfo,
                        message: format!(
                            "[CRA Annex I Part II (4)] Vulnerability '{}' in '{}' has remediation without details",
                            vuln.id, comp.name
                        ),
                        element: Some(comp.name.clone()),
                        requirement: "CRA Annex I Part II (4): Remediation detail".to_string(),
                        rule_id: "SBOM-CRA-VULN-METADATA-REMEDIATION",
                        component_id: Some(comp.canonical_id.value().to_string()),
                        counts: None,
                        standard_refs: Vec::new(),
                        remediation: None,
                        finding_detail: Some(vuln.id.clone()),
                        deadline: None,
                    });
            }
        }
    }

    pub(crate) fn check_format_specific(
        &self,
        sbom: &NormalizedSbom,
        violations: &mut Vec<Violation>,
    ) {
        self.check_duplicate_components(sbom, violations);
        match sbom.document.format {
            SbomFormat::CycloneDx => {
                self.check_cyclonedx_specific(sbom, violations);
            }
            SbomFormat::Spdx => {
                self.check_spdx_specific(sbom, violations);
            }
        }
    }

    /// The components the document lists more than once, as one Info
    /// finding: an entry that repeats a component's canonical id, name and
    /// version was merged into it at parse time (see
    /// `NormalizedSbom::add_component`), so the verdicts do not depend on
    /// the entries' order, but the user should know. The finding names the
    /// first [`MAX_NAMED_DUPLICATES`] such components in inventory order,
    /// counts the rest, and lists the fields their entries disagree on.
    fn check_duplicate_components(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        let duplicated: Vec<&crate::model::DuplicateComponent> = sbom
            .components
            .keys()
            .filter_map(|id| sbom.duplicate_components.get(id))
            .collect();
        if duplicated.is_empty() {
            return;
        }
        let total = sbom.components.len();
        let entries: usize = duplicated.iter().map(|d| d.entries).sum();
        let named: Vec<String> = duplicated
            .iter()
            .map(|d| format!("{} ({} entries)", d.canonical_id.value(), d.entries))
            .collect();
        let mut message = format!(
            "{}/{total} components are listed more than once ({entries} entries), and the \
             entries of each were merged into one: {}",
            duplicated.len(),
            truncate_list(&named, MAX_NAMED_DUPLICATES)
        );
        let conflicts: std::collections::BTreeSet<&str> = duplicated
            .iter()
            .flat_map(|d| d.conflicts.iter().map(String::as_str))
            .collect();
        if !conflicts.is_empty() {
            let fields: Vec<&str> = conflicts.into_iter().collect();
            message.push_str(&format!(
                "; the entries disagree on {}, and the value that sorts first is kept",
                fields.join(", ")
            ));
        }
        violations.push(Violation {
            severity: ViolationSeverity::Info,
            category: ViolationCategory::ComponentIdentification,
            message,
            element: None,
            requirement: "Component inventory: each component listed once".to_string(),
            rule_id: DUPLICATE_COMPONENT_RULES.get(self.level),
            component_id: None,
            counts: Some(ViolationCounts {
                affected: duplicated.len(),
                total,
            }),
            standard_refs: Vec::new(),
            remediation: None,
            finding_detail: None,
            deadline: None,
        });
    }

    pub(crate) fn check_cyclonedx_specific(
        &self,
        sbom: &NormalizedSbom,
        violations: &mut Vec<Violation>,
    ) {
        // CycloneDX specific checks
        let version = &sbom.document.spec_version;
        use crate::model::SpecVersion;

        // Versions compare numerically: string prefixes read "1.10" as
        // "1.1" and never flagged 1.0.
        match sbom.document.spec_version_parsed() {
            Some(v) if v < SpecVersion::new(1, 4, 0) => {
                violations.push(Violation {
                    severity: ViolationSeverity::Info,
                    category: ViolationCategory::FormatSpecific,
                    message: format!("CycloneDX {version} is outdated, consider upgrading to 1.7+"),
                    element: None,
                    requirement: "Current CycloneDX version".to_string(),
                    rule_id: SPEC_VERSION_RULES.get(self.level),
                    component_id: None,
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            }
            // A version newer than any this tool reads (CycloneDX 2.0 is
            // expected): say so once, rather than let version gates guess.
            Some(v) if v.major > 1 || v.minor > 7 => {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::FormatSpecific,
                    message: format!(
                        "CycloneDX {version} is newer than the latest version sbom-tools \
                         reads (1.7); elements it introduces are not evaluated"
                    ),
                    element: None,
                    requirement: "Supported CycloneDX version".to_string(),
                    rule_id: SPEC_VERSION_RULES.get(self.level),
                    component_id: None,
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            }
            _ => {}
        }

        // Check for bom-ref on components (important for CycloneDX).
        // All components: every CycloneDX element should carry a bom-ref.
        for comp in sbom.components.values() {
            if comp.identifiers.format_id == comp.name {
                // Likely missing bom-ref
                violations.push(Violation {
                    severity: ViolationSeverity::Info,
                    category: ViolationCategory::FormatSpecific,
                    message: format!("Component '{}' may be missing bom-ref", comp.name),
                    element: Some(comp.name.clone()),
                    requirement: "CycloneDX: bom-ref for dependency tracking".to_string(),
                    rule_id: ELEMENT_ID_RULES.get(self.level),
                    component_id: Some(comp.canonical_id.value().to_string()),
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
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
        let parsed = sbom.document.spec_version_parsed();

        // A version newer than any this tool reads: say so once.
        if let Some(v) = parsed
            && (v.major > 3 || (v.major == 3 && v.minor > 0))
        {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::FormatSpecific,
                message: format!(
                    "SPDX {version} is newer than the latest version sbom-tools reads (3.0); \
                     elements it introduces are not evaluated"
                ),
                element: None,
                requirement: "Supported SPDX version".to_string(),
                rule_id: SPEC_VERSION_RULES.get(self.level),
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                deadline: None,
            });
        }

        // Check version
        if !parsed.is_some_and(|v| v.major == 2 || v.major == 3) {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::FormatSpecific,
                message: format!("Unknown SPDX version: {version}"),
                element: None,
                requirement: "Valid SPDX version".to_string(),
                rule_id: SPEC_VERSION_UNKNOWN_RULES.get(self.level),
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                deadline: None,
            });
        }

        // SPDX requires element identifiers
        // SPDX 2.x uses SPDXRef- prefix; SPDX 3.0 uses URN-style IDs (e.g., urn:spdx:...)
        let is_spdx3 = parsed.is_some_and(|v| v.major == 3);
        // All components: every SPDX element needs a valid identifier.
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
                    rule_id: ELEMENT_ID_RULES.get(self.level),
                    component_id: Some(comp.canonical_id.value().to_string()),
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            }
        }
    }
}
