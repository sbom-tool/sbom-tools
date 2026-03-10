//! SPDX 3.0 SBOM parser.
//!
//! Supports SPDX 3.0 documents in JSON-LD format. This is a separate parser
//! from the SPDX 2.x parser because the data model is fundamentally different:
//! SPDX 3.0 uses an element-based graph model with typed elements and
//! relationships as first-class objects.
//!
//! Supported profiles: Core, Software, Security, SimpleLicensing.

use crate::model::{
    Annotation, CanonicalId, Component, ComponentType, Creator, CreatorType, CvssScore,
    CvssVersion, DependencyEdge, DependencyType, DocumentMetadata, ExternalRefType,
    ExternalReference, Hash, HashAlgorithm, LicenseExpression, NormalizedSbom, Organization,
    SbomFormat, Severity, SignatureInfo, VexJustification, VexResponse, VexState, VexStatus,
    VulnerabilityRef, VulnerabilitySource,
};
use crate::parsers::traits::{FormatConfidence, FormatDetection, ParseError, SbomParser};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};

/// Parser for SPDX 3.0 SBOM format (JSON-LD)
pub struct Spdx3Parser {
    /// Whether to validate strictly
    #[allow(dead_code)]
    strict: bool,
}

impl Spdx3Parser {
    /// Create a new SPDX 3.0 parser
    #[must_use]
    pub const fn new() -> Self {
        Self { strict: false }
    }

    /// Parse SPDX 3.0 JSON-LD content
    fn parse_json_ld(&self, content: &str) -> Result<NormalizedSbom, ParseError> {
        let doc: Spdx3Document =
            serde_json::from_str(content).map_err(|e| ParseError::JsonError(e.to_string()))?;

        Ok(self.convert_to_normalized(doc))
    }

    /// Parse from a JSON reader (streaming)
    pub fn parse_json_reader<R: std::io::Read>(
        &self,
        reader: R,
    ) -> Result<NormalizedSbom, ParseError> {
        let doc: Spdx3Document =
            serde_json::from_reader(reader).map_err(|e| ParseError::JsonError(e.to_string()))?;

        Ok(self.convert_to_normalized(doc))
    }

    /// Convert SPDX 3.0 document to normalized representation
    fn convert_to_normalized(&self, mut doc: Spdx3Document) -> NormalizedSbom {
        let mut agent_map: HashMap<String, Spdx3Agent> = HashMap::new();
        let mut vuln_map: HashMap<String, Spdx3Vulnerability> = HashMap::new();
        let mut relationships: Vec<Spdx3Relationship> = Vec::new();
        let mut packages: Vec<Spdx3Package> = Vec::new();
        let mut files: Vec<Spdx3File> = Vec::new();
        let mut snippets: Vec<Spdx3Snippet> = Vec::new();
        let mut annotations: Vec<Spdx3Annotation> = Vec::new();
        let mut vuln_assessments: Vec<Spdx3VulnAssessment> = Vec::new();
        let mut license_elements: HashMap<String, String> = HashMap::new();
        let mut seen_ids: HashSet<String> = HashSet::new();
        let mut duplicate_count: usize = 0;

        // First pass: categorize elements by type (move, not clone)
        if let Some(elements) = doc.element.take() {
            for element in elements {
                // Track duplicate element IDs
                let element_id = match &element {
                    Spdx3Element::Package(pkg) => pkg.spdx_id.clone(),
                    Spdx3Element::File(file) => file.spdx_id.clone(),
                    Spdx3Element::Relationship(rel) => rel.spdx_id.clone(),
                    Spdx3Element::Vulnerability(vuln) => vuln.spdx_id.clone(),
                    Spdx3Element::Snippet(s) => s.spdx_id.clone(),
                    Spdx3Element::Annotation(a) => a.spdx_id.clone(),
                    Spdx3Element::VexAffected(va)
                    | Spdx3Element::VexFixed(va)
                    | Spdx3Element::VexNotAffected(va)
                    | Spdx3Element::VexUnderInvestigation(va)
                    | Spdx3Element::CvssV3Assessment(va)
                    | Spdx3Element::CvssV4Assessment(va)
                    | Spdx3Element::EpssAssessment(va)
                    | Spdx3Element::SsvcAssessment(va) => va.spdx_id.clone(),
                    Spdx3Element::Person(a)
                    | Spdx3Element::Organization(a)
                    | Spdx3Element::Tool(a)
                    | Spdx3Element::SoftwareAgent(a) => a.spdx_id.clone(),
                    Spdx3Element::LicenseExpression(l) => l.spdx_id.clone(),
                    Spdx3Element::SimpleLicensingText(l) => l.spdx_id.clone(),
                    _ => None,
                };
                if let Some(id) = &element_id {
                    if !seen_ids.insert(id.clone()) {
                        duplicate_count += 1;
                        tracing::warn!(id = %id, "duplicate SPDX 3.0 element ID");
                    }
                }

                match element {
                    Spdx3Element::Package(pkg) => packages.push(*pkg),
                    Spdx3Element::File(file) => files.push(*file),
                    Spdx3Element::Snippet(snippet) => snippets.push(snippet),
                    Spdx3Element::Relationship(rel)
                    | Spdx3Element::LifecycleScopedRelationship(rel) => {
                        relationships.push(rel);
                    }
                    Spdx3Element::Person(agent)
                    | Spdx3Element::Organization(agent)
                    | Spdx3Element::Tool(agent)
                    | Spdx3Element::SoftwareAgent(agent) => {
                        if let Some(id) = &agent.spdx_id {
                            agent_map.insert(id.clone(), agent);
                        }
                    }
                    Spdx3Element::Vulnerability(vuln) => {
                        if let Some(id) = &vuln.spdx_id {
                            let id = id.clone();
                            vuln_map.insert(id, *vuln);
                        }
                    }
                    Spdx3Element::VexAffected(mut a) => {
                        a.resolved_vex_state = Some(VexState::Affected);
                        vuln_assessments.push(a);
                    }
                    Spdx3Element::VexFixed(mut a) => {
                        a.resolved_vex_state = Some(VexState::Fixed);
                        vuln_assessments.push(a);
                    }
                    Spdx3Element::VexNotAffected(mut a) => {
                        a.resolved_vex_state = Some(VexState::NotAffected);
                        vuln_assessments.push(a);
                    }
                    Spdx3Element::VexUnderInvestigation(mut a) => {
                        a.resolved_vex_state = Some(VexState::UnderInvestigation);
                        vuln_assessments.push(a);
                    }
                    Spdx3Element::CvssV3Assessment(mut a) => {
                        a.resolved_cvss_version = Some(CvssVersion::V3);
                        vuln_assessments.push(a);
                    }
                    Spdx3Element::CvssV4Assessment(mut a) => {
                        a.resolved_cvss_version = Some(CvssVersion::V4);
                        vuln_assessments.push(a);
                    }
                    Spdx3Element::EpssAssessment(a) | Spdx3Element::SsvcAssessment(a) => {
                        vuln_assessments.push(a);
                    }
                    Spdx3Element::Annotation(annotation) => {
                        annotations.push(annotation);
                    }
                    Spdx3Element::LicenseExpression(lic) => {
                        if let (Some(id), Some(expr)) = (lic.spdx_id, lic.license_expression) {
                            license_elements.insert(id, expr);
                        }
                    }
                    Spdx3Element::SimpleLicensingText(lic) => {
                        if let Some(id) = lic.spdx_id {
                            let text = lic.license_text.unwrap_or_default();
                            license_elements.insert(id, text);
                        }
                    }
                    _ => {} // Skip unknown element types
                }
            }
        }

        if duplicate_count > 0 {
            tracing::info!(
                duplicate_count,
                "SPDX 3.0 document contains duplicate element IDs"
            );
        }

        // Build document metadata
        let document = self.convert_metadata(&doc, &agent_map);
        let mut sbom = NormalizedSbom::new(document);

        // Convert packages to components
        let mut id_map: HashMap<String, CanonicalId> = HashMap::new();

        for pkg in &packages {
            let comp = self.convert_package(pkg, &agent_map);
            let spdx_id = pkg.spdx_id.clone().unwrap_or_else(|| comp.name.clone());
            id_map.insert(spdx_id, comp.canonical_id.clone());
            sbom.add_component(comp);
        }

        // Convert files to components
        for file in &files {
            let comp = self.convert_file(file);
            let spdx_id = file.spdx_id.clone().unwrap_or_else(|| comp.name.clone());
            id_map.insert(spdx_id, comp.canonical_id.clone());
            sbom.add_component(comp);
        }

        // Convert snippets to components (Phase 2)
        for snippet in &snippets {
            let comp = self.convert_snippet(snippet);
            let spdx_id = snippet.spdx_id.clone().unwrap_or_else(|| comp.name.clone());
            id_map.insert(spdx_id, comp.canonical_id.clone());
            sbom.add_component(comp);
        }

        // Set primary component from rootElement
        if let Some(root_elements) = &doc.root_element {
            for root_id in root_elements {
                if let Some(canonical_id) = id_map.get(root_id) {
                    sbom.set_primary_component(canonical_id.clone());
                    break; // Use first root element as primary
                }
            }
        }

        // Process relationships
        for rel in &relationships {
            self.process_relationship(rel, &id_map, &mut sbom, &vuln_map, &license_elements);
        }

        // Process vulnerability assessments (Phase 1: Security Profile)
        for assessment in &vuln_assessments {
            self.process_vuln_assessment(assessment, &id_map, &mut sbom, &vuln_map);
        }

        // Process annotations → attach to components (Phase 2)
        for annotation in &annotations {
            self.process_annotation(annotation, &id_map, &mut sbom);
        }

        // Store SPDX 3.0-specific data in extensions (Phases 2, 4)
        let mut spdx_ext = serde_json::Map::new();
        if let Some(data_license) = &doc.data_license {
            spdx_ext.insert(
                "dataLicense".to_string(),
                serde_json::Value::String(data_license.clone()),
            );
        }
        if let Some(ns_map) = &doc.namespace_map {
            if !ns_map.is_empty() {
                let ns_entries: Vec<_> = ns_map
                    .iter()
                    .filter_map(|ns| {
                        Some(serde_json::json!({
                            "prefix": ns.prefix.as_deref()?,
                            "namespace": ns.namespace.as_deref()?
                        }))
                    })
                    .collect();
                if !ns_entries.is_empty() {
                    spdx_ext.insert(
                        "namespaceMap".to_string(),
                        serde_json::Value::Array(ns_entries),
                    );
                }
            }
        }
        if let Some(imports) = &doc.imports {
            if !imports.is_empty() {
                let import_entries: Vec<_> = imports
                    .iter()
                    .filter_map(|imp| {
                        Some(serde_json::json!({
                            "externalSpdxId": imp.external_spdx_id.as_deref()?,
                            "locationHint": imp.location_hint
                        }))
                    })
                    .collect();
                if !import_entries.is_empty() {
                    spdx_ext.insert(
                        "imports".to_string(),
                        serde_json::Value::Array(import_entries),
                    );
                }
            }
        }
        if !spdx_ext.is_empty() {
            sbom.extensions.spdx = Some(serde_json::Value::Object(spdx_ext));
        }

        sbom.calculate_content_hash();
        sbom
    }

    /// Convert SPDX 3.0 document metadata
    fn convert_metadata(
        &self,
        doc: &Spdx3Document,
        agent_map: &HashMap<String, Spdx3Agent>,
    ) -> DocumentMetadata {
        let created = doc
            .creation_info
            .as_ref()
            .and_then(|ci| ci.created.as_ref())
            .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
            .map_or_else(Utc::now, |dt| dt.with_timezone(&Utc));

        let mut creators = Vec::new();
        if let Some(ci) = &doc.creation_info {
            // Resolve created_by agent references
            if let Some(created_by) = &ci.created_by {
                for agent_ref in created_by {
                    if let Some(agent) = agent_map.get(agent_ref) {
                        let (creator_type, type_str) = agent.agent_type();
                        creators.push(Creator {
                            creator_type,
                            name: agent
                                .name
                                .clone()
                                .unwrap_or_else(|| format!("Unknown {type_str}")),
                            email: None,
                        });
                    } else {
                        // Agent not in element list, use ref as name
                        creators.push(Creator {
                            creator_type: CreatorType::Tool,
                            name: agent_ref.clone(),
                            email: None,
                        });
                    }
                }
            }
            // Resolve created_using tool references
            if let Some(created_using) = &ci.created_using {
                for tool_ref in created_using {
                    if let Some(agent) = agent_map.get(tool_ref) {
                        creators.push(Creator {
                            creator_type: CreatorType::Tool,
                            name: agent
                                .name
                                .clone()
                                .unwrap_or_else(|| "Unknown Tool".to_string()),
                            email: None,
                        });
                    }
                }
            }
        }

        let spec_version = doc
            .creation_info
            .as_ref()
            .and_then(|ci| ci.spec_version.clone())
            .unwrap_or_else(|| "3.0".to_string());

        // Extract profile conformance
        let profile_conformance = doc.profile_conformance.as_ref().map(|ps| ps.join(", "));

        // Signature from document if present
        let signature = doc.verified_using.as_ref().and_then(|methods| {
            methods.iter().find_map(|m| {
                if m.method_type.as_deref() == Some("signature") {
                    Some(SignatureInfo {
                        algorithm: m.algorithm.clone().unwrap_or_else(|| "unknown".to_string()),
                        has_value: m.hash_value.is_some(),
                    })
                } else {
                    None
                }
            })
        });

        DocumentMetadata {
            format: SbomFormat::Spdx,
            format_version: spec_version.clone(),
            spec_version,
            serial_number: doc.spdx_id.clone(),
            created,
            creators,
            name: doc.name.clone(),
            security_contact: None,
            vulnerability_disclosure_url: None,
            support_end_date: None,
            lifecycle_phase: None,
            completeness_declaration: crate::model::CompletenessDeclaration::Unknown,
            signature,
            distribution_classification: profile_conformance,
            citations_count: 0,
        }
    }

    /// Convert an SPDX 3.0 Package element to a normalized Component
    fn convert_package(
        &self,
        pkg: &Spdx3Package,
        agent_map: &HashMap<String, Spdx3Agent>,
    ) -> Component {
        let format_id = pkg
            .spdx_id
            .clone()
            .unwrap_or_else(|| pkg.name.clone().unwrap_or_default());
        let name = pkg.name.clone().unwrap_or_default();
        let mut comp = Component::new(name, format_id);

        // Set version
        if let Some(version) = &pkg.package_version {
            comp = comp.with_version(version.clone());
        }

        // Set PURL (first-class field in SPDX 3.0)
        if let Some(purl) = &pkg.package_url {
            comp = comp.with_purl(purl.clone());
        }

        // Extract identifiers from external_identifier
        if let Some(ext_ids) = &pkg.external_identifier {
            for ext_id in ext_ids {
                match ext_id.external_identifier_type.as_deref() {
                    Some("cpe23") | Some("cpe22") => {
                        comp.identifiers.cpe.push(ext_id.identifier.clone());
                    }
                    Some("swid") => {
                        comp.identifiers.swid = Some(ext_id.identifier.clone());
                    }
                    Some("packageUrl") if comp.identifiers.purl.is_none() => {
                        comp = comp.with_purl(ext_id.identifier.clone());
                    }
                    _ => {}
                }
            }
        }

        // Set component type from primary_purpose
        if let Some(purpose) = &pkg.primary_purpose {
            comp.component_type = match purpose.to_lowercase().as_str() {
                "application" => ComponentType::Application,
                "framework" => ComponentType::Framework,
                "library" => ComponentType::Library,
                "container" => ComponentType::Container,
                "operatingsystem" | "operating-system" => ComponentType::OperatingSystem,
                "device" => ComponentType::Device,
                "firmware" => ComponentType::Firmware,
                "file" | "source" | "archive" => ComponentType::File,
                "data" | "documentation" => ComponentType::Data,
                "platform" => ComponentType::Platform,
                other => ComponentType::Other(other.to_string()),
            };
        }

        // Set hashes from verified_using
        if let Some(methods) = &pkg.verified_using {
            for method in methods {
                if let (Some(algo_str), Some(value)) = (&method.algorithm, &method.hash_value) {
                    let algorithm = map_spdx3_hash_algorithm(algo_str);
                    comp.hashes.push(Hash::new(algorithm, value.clone()));
                }
            }
        }

        // Set supplier from supplied_by agent references
        if let Some(supplied_by) = &pkg.supplied_by {
            for supplier_ref in supplied_by {
                if let Some(agent) = agent_map.get(supplier_ref) {
                    comp.supplier = Some(Organization::new(
                        agent.name.clone().unwrap_or_else(|| supplier_ref.clone()),
                    ));
                    break;
                }
            }
        }

        // Set external references
        if let Some(ext_refs) = &pkg.external_ref {
            for ext_ref in ext_refs {
                let ref_type = ext_ref.external_ref_type.as_deref().map_or(
                    ExternalRefType::Other("unknown".to_string()),
                    |t| match t.to_lowercase().as_str() {
                        "securityadvisory" | "advisories" => ExternalRefType::Advisories,
                        "documentation" => ExternalRefType::Documentation,
                        "vcs" => ExternalRefType::Vcs,
                        "issuetracker" | "issue-tracker" => ExternalRefType::IssueTracker,
                        "bom" => ExternalRefType::Bom,
                        other => ExternalRefType::Other(other.to_string()),
                    },
                );
                if let Some(locators) = &ext_ref.locator {
                    for url in locators {
                        comp.external_refs.push(ExternalReference {
                            ref_type: ref_type.clone(),
                            url: url.clone(),
                            comment: ext_ref.comment.clone(),
                            hashes: Vec::new(),
                        });
                    }
                }
            }
        }

        // Set description and copyright
        comp.description.clone_from(&pkg.description);
        comp.copyright.clone_from(&pkg.copyright_text);

        comp.calculate_content_hash();
        comp
    }

    /// Convert an SPDX 3.0 File element to a normalized Component
    fn convert_file(&self, file: &Spdx3File) -> Component {
        let format_id = file
            .spdx_id
            .clone()
            .unwrap_or_else(|| file.name.clone().unwrap_or_default());
        let name = file.name.clone().unwrap_or_default();
        let mut comp = Component::new(name, format_id);
        comp.component_type = ComponentType::File;

        // Set hashes
        if let Some(methods) = &file.verified_using {
            for method in methods {
                if let (Some(algo_str), Some(value)) = (&method.algorithm, &method.hash_value) {
                    let algorithm = map_spdx3_hash_algorithm(algo_str);
                    comp.hashes.push(Hash::new(algorithm, value.clone()));
                }
            }
        }

        comp.copyright.clone_from(&file.copyright_text);
        comp.description.clone_from(&file.description);

        comp.calculate_content_hash();
        comp
    }

    /// Convert an SPDX 3.0 Snippet element to a normalized Component (Phase 2)
    fn convert_snippet(&self, snippet: &Spdx3Snippet) -> Component {
        let format_id = snippet
            .spdx_id
            .clone()
            .unwrap_or_else(|| snippet.name.clone().unwrap_or_default());
        let name = snippet.name.clone().unwrap_or_default();
        let mut comp = Component::new(name, format_id);
        comp.component_type = ComponentType::File; // Snippets map to file-like components

        // Store byte/line range in description if present
        let mut range_info = Vec::new();
        if let Some(byte_range) = &snippet.byte_range {
            range_info.push(format!("bytes {byte_range}"));
        }
        if let Some(line_range) = &snippet.line_range {
            range_info.push(format!("lines {line_range}"));
        }
        if !range_info.is_empty() {
            comp.description = Some(format!("Snippet ({})", range_info.join(", ")));
        }

        // Set hashes
        if let Some(methods) = &snippet.verified_using {
            for method in methods {
                if let (Some(algo_str), Some(value)) = (&method.algorithm, &method.hash_value) {
                    let algorithm = map_spdx3_hash_algorithm(algo_str);
                    comp.hashes.push(Hash::new(algorithm, value.clone()));
                }
            }
        }

        comp.copyright.clone_from(&snippet.copyright_text);

        comp.calculate_content_hash();
        comp
    }

    /// Process a VulnAssessment element (Phase 1: Security Profile)
    ///
    /// Maps CVSS scores, VEX status, justifications, and action statements
    /// from VulnAssessment relationship elements to the affected components.
    fn process_vuln_assessment(
        &self,
        assessment: &Spdx3VulnAssessment,
        id_map: &HashMap<String, CanonicalId>,
        sbom: &mut NormalizedSbom,
        vuln_map: &HashMap<String, Spdx3Vulnerability>,
    ) {
        // The assessment's `from` field references the Vulnerability element
        // The `assessedElement` or `to` field references the affected component
        let vuln_ref_id = assessment.from.as_deref();
        let assessed_id = assessment.assessed_element.as_deref().or_else(|| {
            assessment
                .to
                .as_ref()
                .and_then(|to| to.first().map(String::as_str))
        });

        let Some(assessed_id) = assessed_id else {
            return;
        };
        let Some(canonical_id) = id_map.get(assessed_id) else {
            return;
        };

        // Use resolved VEX state from enum variant discrimination
        let vex_state = assessment.resolved_vex_state.clone();

        // Extract CVSS score if present
        let cvss_score = assessment.score.map(|score| {
            // Infer version from vector string (more precise), fallback to variant type
            let version = assessment.vector.as_deref().map_or_else(
                || {
                    assessment
                        .resolved_cvss_version
                        .clone()
                        .unwrap_or(CvssVersion::V3)
                },
                |v| {
                    if v.starts_with("CVSS:4") {
                        CvssVersion::V4
                    } else if v.starts_with("CVSS:3.1") {
                        CvssVersion::V31
                    } else if v.starts_with("CVSS:3") {
                        CvssVersion::V3
                    } else if v.starts_with("CVSS:2") || v.starts_with("AV:") {
                        CvssVersion::V2
                    } else {
                        assessment
                            .resolved_cvss_version
                            .clone()
                            .unwrap_or(CvssVersion::V3)
                    }
                },
            );
            let mut cs = CvssScore::new(version, score);
            cs.vector.clone_from(&assessment.vector);
            cs
        });

        // Map justification string to enum
        let justification = assessment.justification.as_deref().map(|j| {
            match j.to_lowercase().replace(['-', '_'], "").as_str() {
                "componentnotpresent" => VexJustification::ComponentNotPresent,
                "vulnerablecodenotpresent" => VexJustification::VulnerableCodeNotPresent,
                "vulnerablecodenotinexecutepath" => {
                    VexJustification::VulnerableCodeNotInExecutePath
                }
                "vulnerablecodecannotbecontrolledbyadversary" => {
                    VexJustification::VulnerableCodeCannotBeControlledByAdversary
                }
                "inlinemitigationsalreadyexist" => VexJustification::InlineMitigationsAlreadyExist,
                _ => VexJustification::VulnerableCodeNotPresent, // fallback
            }
        });

        // Map response string to enum
        let responses: Vec<VexResponse> = assessment
            .action_statement
            .as_deref()
            .and_then(|a| {
                let lower = a.to_lowercase();
                if lower.contains("update") || lower.contains("upgrade") {
                    Some(VexResponse::Update)
                } else if lower.contains("rollback") {
                    Some(VexResponse::Rollback)
                } else if lower.contains("workaround") {
                    Some(VexResponse::Workaround)
                } else if lower.contains("will not fix") || lower.contains("wontfix") {
                    Some(VexResponse::WillNotFix)
                } else if lower.contains("cannot fix") || lower.contains("can not fix") {
                    Some(VexResponse::CanNotFix)
                } else {
                    None
                }
            })
            .into_iter()
            .collect();

        // Build VEX status
        let vex_status = vex_state.map(|status| VexStatus {
            status,
            justification: justification.clone(),
            action_statement: assessment.action_statement.clone(),
            impact_statement: assessment.impact_statement.clone(),
            responses,
            detail: assessment.status_notes.clone(),
        });

        // Look up the vulnerability element for the full VulnerabilityRef
        if let Some(vuln_id) = vuln_ref_id {
            if let Some(vuln) = vuln_map.get(vuln_id) {
                let mut vuln_ref = self.convert_vulnerability(vuln);

                // Add CVSS score from the assessment
                if let Some(cs) = cvss_score {
                    vuln_ref.severity = Some(Severity::from_cvss(cs.base_score));
                    vuln_ref.cvss.push(cs);
                }

                // Set VEX status on the vulnerability ref
                vuln_ref.vex_status = vex_status.clone();

                if let Some(comp) = sbom.components.get_mut(canonical_id) {
                    comp.vulnerabilities.push(vuln_ref);
                    if let Some(vs) = vex_status {
                        comp.vex_status = Some(vs);
                    }
                }
            }
        } else if let Some(comp) = sbom.components.get_mut(canonical_id) {
            // Assessment without a specific vulnerability reference (standalone VEX)
            if let Some(vs) = vex_status {
                comp.vex_status = Some(vs);
            }
        }
    }

    /// Process an Annotation element → attach to referenced component (Phase 2)
    fn process_annotation(
        &self,
        annotation: &Spdx3Annotation,
        id_map: &HashMap<String, CanonicalId>,
        sbom: &mut NormalizedSbom,
    ) {
        let Some(subject) = &annotation.subject else {
            return;
        };
        let Some(canonical_id) = id_map.get(subject) else {
            return;
        };
        let Some(comp) = sbom.components.get_mut(canonical_id) else {
            return;
        };

        let ann_type = annotation
            .annotation_type
            .clone()
            .unwrap_or_else(|| "OTHER".to_string());
        let statement = annotation.statement.clone().unwrap_or_default();

        comp.extensions.annotations.push(Annotation {
            annotator: annotation
                .spdx_id
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            annotation_date: Utc::now(), // SPDX 3.0 annotations don't always have timestamps
            annotation_type: ann_type,
            comment: statement,
        });
    }

    /// Process a Relationship element
    fn process_relationship(
        &self,
        rel: &Spdx3Relationship,
        id_map: &HashMap<String, CanonicalId>,
        sbom: &mut NormalizedSbom,
        vuln_map: &HashMap<String, Spdx3Vulnerability>,
        license_elements: &HashMap<String, String>,
    ) {
        let rel_type = rel.relationship_type.as_deref().unwrap_or("");

        match rel_type.to_uppercase().as_str() {
            // Dependency relationships -> DependencyEdge
            "DEPENDS_ON" | "DEPENDENCY_OF" => {
                self.add_dependency_edge(rel, id_map, sbom, DependencyType::DependsOn);
            }
            "DEV_DEPENDENCY_OF" | "DEV_DEPENDS_ON" => {
                self.add_dependency_edge(rel, id_map, sbom, DependencyType::DevDependsOn);
            }
            "BUILD_DEPENDENCY_OF" | "BUILD_DEPENDS_ON" | "BUILD_TOOL_OF" => {
                self.add_dependency_edge(rel, id_map, sbom, DependencyType::BuildDependsOn);
            }
            "TEST_DEPENDENCY_OF" | "TEST_DEPENDS_ON" | "TEST_TOOL_OF" => {
                self.add_dependency_edge(rel, id_map, sbom, DependencyType::TestDependsOn);
            }
            "RUNTIME_DEPENDENCY_OF" | "RUNTIME_DEPENDS_ON" => {
                self.add_dependency_edge(rel, id_map, sbom, DependencyType::RuntimeDependsOn);
            }
            "OPTIONAL_DEPENDENCY_OF" | "OPTIONAL_DEPENDS_ON" => {
                self.add_dependency_edge(rel, id_map, sbom, DependencyType::OptionalDependsOn);
            }
            "PROVIDED_DEPENDENCY_OF" => {
                self.add_dependency_edge(rel, id_map, sbom, DependencyType::ProvidedDependsOn);
            }
            "CONTAINS" => {
                self.add_dependency_edge(rel, id_map, sbom, DependencyType::Contains);
            }
            "DESCRIBES" => {
                self.add_dependency_edge(rel, id_map, sbom, DependencyType::Describes);
            }
            "GENERATES" | "GENERATED_FROM" => {
                self.add_dependency_edge(rel, id_map, sbom, DependencyType::Generates);
            }
            "ANCESTOR_OF" => {
                self.add_dependency_edge(rel, id_map, sbom, DependencyType::AncestorOf);
            }
            "VARIANT_OF" => {
                self.add_dependency_edge(rel, id_map, sbom, DependencyType::VariantOf);
            }
            "DISTRIBUTION_ARTIFACT" => {
                self.add_dependency_edge(rel, id_map, sbom, DependencyType::DistributionArtifact);
            }
            "PATCH_FOR" | "PATCH_APPLIED" => {
                self.add_dependency_edge(rel, id_map, sbom, DependencyType::PatchFor);
            }
            "COPY_OF" | "EXPANDED_FROM_ARCHIVE" => {
                self.add_dependency_edge(rel, id_map, sbom, DependencyType::CopyOf);
            }
            "DYNAMIC_LINK" => {
                self.add_dependency_edge(rel, id_map, sbom, DependencyType::DynamicLink);
            }
            "STATIC_LINK" => {
                self.add_dependency_edge(rel, id_map, sbom, DependencyType::StaticLink);
            }

            // License relationships -> populate Component.licenses
            "HAS_DECLARED_LICENSE" | "HAS_CONCLUDED_LICENSE" => {
                if let Some(from_ref) = &rel.from {
                    if let Some(canonical_id) = id_map.get(from_ref) {
                        if let Some(to_refs) = &rel.to {
                            for to_ref in to_refs {
                                if let Some(expr) = license_elements.get(to_ref) {
                                    if let Some(comp) = sbom.components.get_mut(canonical_id) {
                                        let lic = LicenseExpression::new(expr.clone());
                                        if rel_type.to_uppercase().contains("CONCLUDED") {
                                            comp.licenses.concluded = Some(lic);
                                        } else {
                                            comp.licenses.add_declared(lic);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Vulnerability relationships
            "AFFECTS" => {
                // Vulnerability affects Package
                if let Some(from_ref) = &rel.from {
                    if let Some(vuln) = vuln_map.get(from_ref) {
                        if let Some(to_refs) = &rel.to {
                            for to_ref in to_refs {
                                if let Some(canonical_id) = id_map.get(to_ref) {
                                    let vuln_ref = self.convert_vulnerability(vuln);
                                    if let Some(comp) = sbom.components.get_mut(canonical_id) {
                                        comp.vulnerabilities.push(vuln_ref);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            "FIXED_IN" => {
                // Vulnerability fixed in Package@version
                if let Some(from_ref) = &rel.from {
                    if let Some(vuln) = vuln_map.get(from_ref) {
                        if let Some(to_refs) = &rel.to {
                            for to_ref in to_refs {
                                if let Some(canonical_id) = id_map.get(to_ref) {
                                    let mut vuln_ref = self.convert_vulnerability(vuln);
                                    vuln_ref.vex_status = Some(VexStatus {
                                        status: VexState::Fixed,
                                        justification: None,
                                        action_statement: None,
                                        impact_statement: None,
                                        responses: Vec::new(),
                                        detail: None,
                                    });
                                    if let Some(comp) = sbom.components.get_mut(canonical_id) {
                                        comp.vulnerabilities.push(vuln_ref);
                                        comp.vex_status = Some(VexStatus {
                                            status: VexState::Fixed,
                                            justification: None,
                                            action_statement: None,
                                            impact_statement: None,
                                            responses: Vec::new(),
                                            detail: None,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // VEX assessment relationships — handled via VulnAssessment elements
            "HAS_ASSESSMENT_FOR" => {
                // These are processed in process_vuln_assessment()
            }

            _ => {
                // Unknown relationship type - store as Other if it connects known components
                if !rel_type.is_empty() {
                    self.add_dependency_edge(
                        rel,
                        id_map,
                        sbom,
                        DependencyType::Other(rel_type.to_string()),
                    );
                }
            }
        }
    }

    /// Add a dependency edge from a relationship
    fn add_dependency_edge(
        &self,
        rel: &Spdx3Relationship,
        id_map: &HashMap<String, CanonicalId>,
        sbom: &mut NormalizedSbom,
        dep_type: DependencyType,
    ) {
        if let Some(from_ref) = &rel.from {
            if let Some(from_id) = id_map.get(from_ref) {
                if let Some(to_refs) = &rel.to {
                    for to_ref in to_refs {
                        if let Some(to_id) = id_map.get(to_ref) {
                            sbom.add_edge(DependencyEdge::new(
                                from_id.clone(),
                                to_id.clone(),
                                dep_type.clone(),
                            ));
                        }
                    }
                }
            }
        }
    }

    /// Convert SPDX 3.0 Vulnerability element to VulnerabilityRef
    fn convert_vulnerability(&self, vuln: &Spdx3Vulnerability) -> VulnerabilityRef {
        // Extract CVE/GHSA ID from external identifiers
        let id = vuln
            .external_identifier
            .as_ref()
            .and_then(|ids| {
                ids.iter()
                    .find_map(|id| match id.external_identifier_type.as_deref() {
                        Some("cve") | Some("securityOther") => Some(id.identifier.clone()),
                        _ => None,
                    })
            })
            .or_else(|| vuln.name.clone())
            .unwrap_or_else(|| {
                vuln.spdx_id
                    .clone()
                    .unwrap_or_else(|| "UNKNOWN".to_string())
            });

        let source = if id.starts_with("CVE-") {
            VulnerabilitySource::Cve
        } else if id.starts_with("GHSA-") {
            VulnerabilitySource::Ghsa
        } else {
            VulnerabilitySource::Other("SPDX".to_string())
        };

        let mut vuln_ref = VulnerabilityRef::new(id, source);
        vuln_ref.description.clone_from(&vuln.description);

        // Parse published/modified times
        if let Some(t) = &vuln.published_time {
            vuln_ref.published = DateTime::parse_from_rfc3339(t)
                .ok()
                .map(|dt| dt.with_timezone(&Utc));
        }
        if let Some(t) = &vuln.modified_time {
            vuln_ref.modified = DateTime::parse_from_rfc3339(t)
                .ok()
                .map(|dt| dt.with_timezone(&Utc));
        }

        vuln_ref
    }
}

impl Default for Spdx3Parser {
    fn default() -> Self {
        Self::new()
    }
}

impl SbomParser for Spdx3Parser {
    fn parse_str(&self, content: &str) -> Result<NormalizedSbom, ParseError> {
        self.parse_json_ld(content)
    }

    fn supported_versions(&self) -> Vec<&str> {
        vec!["3.0", "3.0.1"]
    }

    fn format_name(&self) -> &'static str {
        "SPDX"
    }

    fn detect(&self, content: &str) -> FormatDetection {
        let trimmed = content.trim();

        if !trimmed.starts_with('{') {
            return FormatDetection::no_match();
        }

        // SPDX 3.0 indicators
        let has_context = content.contains("\"@context\"");
        let has_spdx3_context = content.contains("spdx.org/rdf/3")
            || content.contains("spdx.org/rdf/v3")
            || content.contains("spdx3");
        let has_type_spdx_document =
            content.contains("\"type\"") && content.contains("\"SpdxDocument\"");
        let has_spdx_id = content.contains("\"spdxId\"");
        let has_creation_info = content.contains("\"creationInfo\"");
        let has_element = content.contains("\"element\"");
        let has_root_element = content.contains("\"rootElement\"");

        // Extract version
        let version = Self::extract_spec_version(content);

        if has_context && has_spdx3_context {
            // Definitely SPDX 3.0 JSON-LD
            let mut detection =
                FormatDetection::with_confidence(FormatConfidence::CERTAIN).variant("JSON-LD");
            if let Some(v) = version {
                detection = detection.version(&v);
            }
            return detection;
        }

        if has_type_spdx_document && has_spdx_id {
            // Very likely SPDX 3.0
            let mut detection =
                FormatDetection::with_confidence(FormatConfidence::HIGH).variant("JSON-LD");
            if let Some(v) = version {
                detection = detection.version(&v);
            }
            return detection;
        }

        if has_context && (has_creation_info || has_element || has_root_element) {
            // Might be SPDX 3.0
            let mut detection = FormatDetection::with_confidence(FormatConfidence::MEDIUM)
                .variant("JSON-LD")
                .warning("Missing SpdxDocument type marker");
            if let Some(v) = version {
                detection = detection.version(&v);
            }
            return detection;
        }

        FormatDetection::no_match()
    }
}

impl Spdx3Parser {
    /// Extract spec version from JSON content
    fn extract_spec_version(content: &str) -> Option<String> {
        // Look for specVersion in creationInfo
        if let Some(idx) = content.find("\"specVersion\"") {
            let after = &content[idx..];
            if let Some(colon_idx) = after.find(':') {
                let value_part = &after[colon_idx + 1..];
                if let Some(quote_start) = value_part.find('"') {
                    let after_quote = &value_part[quote_start + 1..];
                    if let Some(quote_end) = after_quote.find('"') {
                        let version = &after_quote[..quote_end];
                        if version.starts_with("3.") {
                            return Some(version.to_string());
                        }
                    }
                }
            }
        }
        None
    }
}

/// Map SPDX 3.0 hash algorithm names to our enum
fn map_spdx3_hash_algorithm(algo: &str) -> HashAlgorithm {
    match algo.to_uppercase().as_str() {
        "MD5" => HashAlgorithm::Md5,
        "SHA1" | "SHA-1" => HashAlgorithm::Sha1,
        "SHA256" | "SHA-256" => HashAlgorithm::Sha256,
        "SHA384" | "SHA-384" => HashAlgorithm::Sha384,
        "SHA512" | "SHA-512" => HashAlgorithm::Sha512,
        "SHA3-256" | "SHA3_256" => HashAlgorithm::Sha3_256,
        "SHA3-384" | "SHA3_384" => HashAlgorithm::Sha3_384,
        "SHA3-512" | "SHA3_512" => HashAlgorithm::Sha3_512,
        "BLAKE2B-256" | "BLAKE2B256" => HashAlgorithm::Blake2b256,
        "BLAKE2B-384" | "BLAKE2B384" => HashAlgorithm::Blake2b384,
        "BLAKE2B-512" | "BLAKE2B512" => HashAlgorithm::Blake2b512,
        "BLAKE3" => HashAlgorithm::Blake3,
        "STREEBOG-256" | "STREEBOG256" => HashAlgorithm::Streebog256,
        "STREEBOG-512" | "STREEBOG512" => HashAlgorithm::Streebog512,
        other => HashAlgorithm::Other(other.to_string()),
    }
}

// =============================================================================
// SPDX 3.0 JSON-LD serde models
// =============================================================================

/// Top-level SPDX 3.0 document
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct Spdx3Document {
    /// JSON-LD context (ignored for parsing)
    #[serde(rename = "@context")]
    context: Option<serde_json::Value>,
    /// Document URI identifier
    spdx_id: Option<String>,
    /// Element type (should be "SpdxDocument")
    #[serde(rename = "type")]
    type_: Option<String>,
    /// Document name
    name: Option<String>,
    /// Creation info
    creation_info: Option<Spdx3CreationInfo>,
    /// Data license (always CC0-1.0)
    data_license: Option<String>,
    /// Namespace map for cross-document references (Phase 4)
    namespace_map: Option<Vec<Spdx3NamespaceMap>>,
    /// External document imports (Phase 4)
    #[serde(rename = "import")]
    imports: Option<Vec<Spdx3ExternalMap>>,
    /// Root elements (URIs of primary elements)
    root_element: Option<Vec<String>>,
    /// All elements in the document
    element: Option<Vec<Spdx3Element>>,
    /// Profile conformance declarations
    profile_conformance: Option<Vec<String>>,
    /// Integrity methods (hash/signature)
    verified_using: Option<Vec<Spdx3IntegrityMethod>>,
    /// Description
    description: Option<String>,
}

/// Creation info for SPDX 3.0 elements
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct Spdx3CreationInfo {
    /// Creation timestamp
    created: Option<String>,
    /// References to Agent elements who created this
    created_by: Option<Vec<String>>,
    /// References to Tool elements used to create this
    created_using: Option<Vec<String>>,
    /// Specification version (e.g., "3.0.1")
    spec_version: Option<String>,
    /// Comment
    comment: Option<String>,
}

/// Polymorphic SPDX 3.0 element
#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "type")]
#[allow(dead_code)]
enum Spdx3Element {
    #[serde(alias = "software_Package", alias = "Software_Package")]
    Package(Box<Spdx3Package>),
    #[serde(alias = "software_File", alias = "Software_File")]
    File(Box<Spdx3File>),
    #[serde(alias = "software_Snippet", alias = "Software_Snippet")]
    Snippet(Spdx3Snippet),
    Relationship(Spdx3Relationship),
    #[serde(alias = "security_Vulnerability")]
    Vulnerability(Box<Spdx3Vulnerability>),
    Annotation(Spdx3Annotation),
    Person(Spdx3Agent),
    Organization(Spdx3Agent),
    Tool(Spdx3Agent),
    SoftwareAgent(Spdx3Agent),
    Bom(Spdx3Collection),
    Bundle(Spdx3Collection),
    /// SPDX 3.0 license expression element
    #[serde(
        alias = "simplelicensing_LicenseExpression",
        alias = "SimpleLicensingLicenseExpression"
    )]
    LicenseExpression(Spdx3LicenseExpression),
    /// SPDX 3.0 simple licensing text
    #[serde(alias = "simplelicensing_SimpleLicensingText", alias = "CustomLicense")]
    SimpleLicensingText(Spdx3SimpleLicensingText),
    /// VEX Affected assessment
    #[serde(
        alias = "security_VexAffectedVulnAssessmentRelationship",
        alias = "VexAffectedVulnAssessmentRelationship"
    )]
    VexAffected(Spdx3VulnAssessment),
    /// VEX Fixed assessment
    #[serde(
        alias = "security_VexFixedVulnAssessmentRelationship",
        alias = "VexFixedVulnAssessmentRelationship"
    )]
    VexFixed(Spdx3VulnAssessment),
    /// VEX Not Affected assessment
    #[serde(
        alias = "security_VexNotAffectedVulnAssessmentRelationship",
        alias = "VexNotAffectedVulnAssessmentRelationship"
    )]
    VexNotAffected(Spdx3VulnAssessment),
    /// VEX Under Investigation assessment
    #[serde(
        alias = "security_VexUnderInvestigationVulnAssessmentRelationship",
        alias = "VexUnderInvestigationVulnAssessmentRelationship"
    )]
    VexUnderInvestigation(Spdx3VulnAssessment),
    /// CVSS v3 assessment
    #[serde(
        alias = "security_CvssV3VulnAssessmentRelationship",
        alias = "CvssV3VulnAssessmentRelationship"
    )]
    CvssV3Assessment(Spdx3VulnAssessment),
    /// CVSS v4 assessment
    #[serde(
        alias = "security_CvssV4VulnAssessmentRelationship",
        alias = "CvssV4VulnAssessmentRelationship"
    )]
    CvssV4Assessment(Spdx3VulnAssessment),
    /// EPSS assessment
    #[serde(
        alias = "security_EpssVulnAssessmentRelationship",
        alias = "EpssVulnAssessmentRelationship"
    )]
    EpssAssessment(Spdx3VulnAssessment),
    /// SSVC assessment
    #[serde(
        alias = "security_SsvcVulnAssessmentRelationship",
        alias = "SsvcVulnAssessmentRelationship"
    )]
    SsvcAssessment(Spdx3VulnAssessment),
    /// Lifecycle-scoped relationship
    LifecycleScopedRelationship(Spdx3Relationship),
    /// Catch-all for unknown types (deserialized as raw JSON)
    #[serde(other)]
    Unknown,
}

/// SPDX 3.0 Package (Software profile)
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct Spdx3Package {
    spdx_id: Option<String>,
    name: Option<String>,
    package_version: Option<String>,
    package_url: Option<String>,
    download_location: Option<String>,
    home_page: Option<String>,
    copyright_text: Option<String>,
    description: Option<String>,
    supplied_by: Option<Vec<String>>,
    originated_by: Option<Vec<String>>,
    verified_using: Option<Vec<Spdx3IntegrityMethod>>,
    external_identifier: Option<Vec<Spdx3ExternalIdentifier>>,
    external_ref: Option<Vec<Spdx3ExternalRef>>,
    primary_purpose: Option<String>,
    additional_purpose: Option<Vec<String>>,
    content_identifier: Option<String>,
    attribution_text: Option<Vec<String>>,
    support_level: Option<String>,
    valid_until_time: Option<String>,
    built_time: Option<String>,
    release_time: Option<String>,
    creation_info: Option<Spdx3CreationInfo>,
}

/// SPDX 3.0 File (Software profile)
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct Spdx3File {
    spdx_id: Option<String>,
    name: Option<String>,
    copyright_text: Option<String>,
    description: Option<String>,
    verified_using: Option<Vec<Spdx3IntegrityMethod>>,
    file_kind: Option<String>,
    creation_info: Option<Spdx3CreationInfo>,
}

/// SPDX 3.0 Snippet (Software profile)
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct Spdx3Snippet {
    spdx_id: Option<String>,
    name: Option<String>,
    copyright_text: Option<String>,
    description: Option<String>,
    /// Byte range within the containing file (e.g., "310:420")
    byte_range: Option<String>,
    /// Line range within the containing file (e.g., "5:23")
    line_range: Option<String>,
    /// Containing file reference
    snippet_from_file: Option<String>,
    /// Integrity methods (hashes)
    verified_using: Option<Vec<Spdx3IntegrityMethod>>,
    creation_info: Option<Spdx3CreationInfo>,
}

/// SPDX 3.0 Relationship (first-class element)
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct Spdx3Relationship {
    spdx_id: Option<String>,
    from: Option<String>,
    to: Option<Vec<String>>,
    relationship_type: Option<String>,
    start_time: Option<String>,
    end_time: Option<String>,
    completeness: Option<String>,
    creation_info: Option<Spdx3CreationInfo>,
}

/// SPDX 3.0 Vulnerability (Security profile)
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct Spdx3Vulnerability {
    spdx_id: Option<String>,
    name: Option<String>,
    description: Option<String>,
    published_time: Option<String>,
    modified_time: Option<String>,
    withdrawn_time: Option<String>,
    external_identifier: Option<Vec<Spdx3ExternalIdentifier>>,
    external_ref: Option<Vec<Spdx3ExternalRef>>,
    creation_info: Option<Spdx3CreationInfo>,
}

/// SPDX 3.0 Vulnerability Assessment Relationship
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct Spdx3VulnAssessment {
    spdx_id: Option<String>,
    from: Option<String>,
    to: Option<Vec<String>>,
    assessed_element: Option<String>,
    published_time: Option<String>,
    modified_time: Option<String>,
    supplied_by: Option<String>,
    /// CVSS fields
    score: Option<f32>,
    severity: Option<String>,
    vector: Option<String>,
    /// VEX fields
    status_notes: Option<String>,
    justification: Option<String>,
    impact_statement: Option<String>,
    action_statement: Option<String>,
    vex_version: Option<String>,
    /// Resolved VEX state (set during first-pass from enum variant)
    #[serde(skip)]
    resolved_vex_state: Option<VexState>,
    /// Resolved CVSS version (set during first-pass from enum variant)
    #[serde(skip)]
    resolved_cvss_version: Option<CvssVersion>,
}

/// SPDX 3.0 Annotation
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct Spdx3Annotation {
    spdx_id: Option<String>,
    subject: Option<String>,
    annotation_type: Option<String>,
    statement: Option<String>,
    content_type: Option<String>,
}

/// SPDX 3.0 Agent (Person, Organization, Tool, SoftwareAgent)
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct Spdx3Agent {
    spdx_id: Option<String>,
    name: Option<String>,
    description: Option<String>,
    /// The original type tag for discriminating agent types
    #[serde(rename = "type")]
    agent_type_tag: Option<String>,
}

impl Spdx3Agent {
    /// Get the creator type based on the agent's type tag
    fn agent_type(&self) -> (CreatorType, &'static str) {
        match self.agent_type_tag.as_deref() {
            Some("Person") => (CreatorType::Person, "Person"),
            Some("Organization") => (CreatorType::Organization, "Organization"),
            Some("Tool") | Some("SoftwareAgent") => (CreatorType::Tool, "Tool"),
            _ => (CreatorType::Tool, "Agent"),
        }
    }
}

/// SPDX 3.0 Collection (Bom, Bundle)
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct Spdx3Collection {
    spdx_id: Option<String>,
    name: Option<String>,
    element: Option<Vec<String>>,
    root_element: Option<Vec<String>>,
    context: Option<String>,
}

/// SPDX 3.0 Integrity Method (Hash or Signature)
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct Spdx3IntegrityMethod {
    /// Type discriminator
    #[serde(rename = "type")]
    method_type: Option<String>,
    /// Hash algorithm (for Hash type)
    algorithm: Option<String>,
    /// Hash value (for Hash type)
    hash_value: Option<String>,
    /// Comment
    comment: Option<String>,
}

/// SPDX 3.0 External Identifier
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct Spdx3ExternalIdentifier {
    /// Identifier value
    identifier: String,
    /// Identifier type (cpe22, cpe23, cve, packageUrl, swid, etc.)
    external_identifier_type: Option<String>,
    /// Where to look up the identifier
    identifier_locator: Option<Vec<String>>,
    /// Issuing authority
    issuing_authority: Option<String>,
    /// Comment
    comment: Option<String>,
}

/// SPDX 3.0 External Reference
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct Spdx3ExternalRef {
    /// Locator URLs
    locator: Option<Vec<String>>,
    /// Reference type
    external_ref_type: Option<String>,
    /// Content type
    content_type: Option<String>,
    /// Comment
    comment: Option<String>,
}

/// SPDX 3.0 License Expression element (SimpleLicensing profile)
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct Spdx3LicenseExpression {
    spdx_id: Option<String>,
    license_expression: Option<String>,
    license_list_version: Option<String>,
}

/// SPDX 3.0 Simple Licensing Text element
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct Spdx3SimpleLicensingText {
    spdx_id: Option<String>,
    license_text: Option<String>,
    license_name: Option<String>,
}

/// SPDX 3.0 Namespace Map entry (Phase 4: cross-document references)
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct Spdx3NamespaceMap {
    /// Namespace prefix (short alias)
    prefix: Option<String>,
    /// Full namespace URI
    namespace: Option<String>,
}

/// SPDX 3.0 External Map entry (imports from other documents) (Phase 4)
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct Spdx3ExternalMap {
    /// External SPDX element ID
    external_spdx_id: Option<String>,
    /// Location URL of the external document
    location_hint: Option<String>,
    /// Integrity verification for the external document
    verified_using: Option<Vec<Spdx3IntegrityMethod>>,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spdx3_detection_with_context() {
        let parser = Spdx3Parser::new();
        let content = r#"{"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld", "type": "SpdxDocument"}"#;
        let detection = parser.detect(content);
        assert!(detection.confidence.value() >= 0.95);
        assert_eq!(detection.variant, Some("JSON-LD".to_string()));
    }

    #[test]
    fn test_spdx3_detection_without_context() {
        let parser = Spdx3Parser::new();
        let content = r#"{"type": "SpdxDocument", "spdxId": "urn:spdx:document:test"}"#;
        let detection = parser.detect(content);
        assert!(detection.confidence.value() >= 0.5);
    }

    #[test]
    fn test_spdx3_detection_not_spdx() {
        let parser = Spdx3Parser::new();
        let content = r#"{"bomFormat": "CycloneDX", "specVersion": "1.7"}"#;
        let detection = parser.detect(content);
        assert!(detection.confidence.value() < 0.25);
    }

    #[test]
    fn test_spdx3_detection_spdx2_not_matched() {
        let parser = Spdx3Parser::new();
        let content = r#"{"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT"}"#;
        let detection = parser.detect(content);
        assert!(detection.confidence.value() < 0.25);
    }

    #[test]
    fn test_spdx3_supported_versions() {
        let parser = Spdx3Parser::new();
        assert!(parser.supported_versions().contains(&"3.0"));
        assert!(parser.supported_versions().contains(&"3.0.1"));
    }
}
