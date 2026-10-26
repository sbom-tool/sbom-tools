//! SPDX 3.0 SBOM parser.
//!
//! Supports SPDX 3.0 documents in JSON-LD format. This is a separate parser
//! from the SPDX 2.x parser because the data model is fundamentally different:
//! SPDX 3.0 uses an element-based graph model with typed elements and
//! relationships as first-class objects.
//!
//! Supported profiles: Core, Software, Security, SimpleLicensing, AI, Dataset.

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
        let content = super::strip_bom(content);
        let mut doc: Spdx3Document =
            serde_json::from_str(content).map_err(|e| ParseError::JsonError(e.to_string()))?;

        // The official 3.0.1 JSON schema also permits a document that IS a
        // single bare element (no @graph, no element array — the schema's
        // else-branch; e.g. the spdx-3-model person1/tool1 examples). Such
        // a document deserializes above as an empty Spdx3Document; re-read
        // it as the one element it is.
        if Self::is_bare_element(&doc) {
            let element: Spdx3Element =
                serde_json::from_str(content).map_err(|e| ParseError::JsonError(e.to_string()))?;
            doc.element = Some(vec![element]);
        }

        Ok(self.convert_to_normalized(doc))
    }

    /// Whether a parsed top-level document is actually a bare single
    /// element (typed, but with no element/@graph payload and not an
    /// SpdxDocument envelope).
    fn is_bare_element(doc: &Spdx3Document) -> bool {
        doc.element.is_none()
            && doc.graph.is_none()
            && doc.type_.as_deref().is_some_and(|t| t != "SpdxDocument")
    }

    /// Parse from a JSON reader (streaming)
    pub fn parse_json_reader<R: std::io::Read>(
        &self,
        reader: R,
    ) -> Result<NormalizedSbom, ParseError> {
        // Buffer into a Value so the rare bare-single-element form (see
        // parse_json_ld) can be re-read as an element without a second
        // pass over the stream. The clone below only happens for that form
        // — a single element, so it stays small.
        let value: serde_json::Value =
            serde_json::from_reader(reader).map_err(|e| ParseError::JsonError(e.to_string()))?;
        let is_bare = value.get("element").is_none()
            && value.get("@graph").is_none()
            && value
                .get("type")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|t| t != "SpdxDocument");
        let bare_element = if is_bare {
            Some(
                serde_json::from_value::<Spdx3Element>(value.clone())
                    .map_err(|e| ParseError::JsonError(e.to_string()))?,
            )
        } else {
            None
        };
        let mut doc: Spdx3Document =
            serde_json::from_value(value).map_err(|e| ParseError::JsonError(e.to_string()))?;

        if let Some(element) = bare_element {
            doc.element = Some(vec![element]);
        }

        Ok(self.convert_to_normalized(doc))
    }

    /// Convert SPDX 3.0 document to normalized representation
    fn convert_to_normalized(&self, mut doc: Spdx3Document) -> NormalizedSbom {
        let mut agent_map: HashMap<String, Spdx3Agent> = HashMap::new();
        let mut vuln_map: HashMap<String, Spdx3Vulnerability> = HashMap::new();
        let mut relationships: Vec<Spdx3Relationship> = Vec::new();
        let mut packages: Vec<(Spdx3Package, PackageKind)> = Vec::new();
        let mut files: Vec<Spdx3File> = Vec::new();
        let mut snippets: Vec<Spdx3Snippet> = Vec::new();
        let mut annotations: Vec<Spdx3Annotation> = Vec::new();
        let mut vuln_assessments: Vec<Spdx3VulnAssessment> = Vec::new();
        let mut license_elements: HashMap<String, String> = HashMap::new();
        // Standalone CreationInfo `@graph` nodes, keyed by their blank-node
        // `@id`: canonical SPDX 3.0.1 puts one CreationInfo node in the graph
        // and every element references it as `"creationInfo": "_:..."`.
        let mut creation_info_map: HashMap<String, Spdx3CreationInfo> = HashMap::new();
        // Bom / software_Sbom / Bundle collections, kept so the document's
        // rootElement can be chased through an Sbom container to the package.
        let mut collection_map: HashMap<String, Spdx3Collection> = HashMap::new();
        let mut seen_ids: HashSet<String> = HashSet::new();
        let mut duplicate_count: usize = 0;

        // First pass: categorize elements by type (move, not clone).
        // Elements may be provided inline (`element`) or as a JSON-LD flat
        // graph (`@graph`); handle both, chained.
        let elements = doc
            .element
            .take()
            .into_iter()
            .flatten()
            .chain(doc.graph.take().into_iter().flatten());
        {
            for element in elements {
                // Track duplicate element IDs
                let element_id = match &element {
                    Spdx3Element::Package(pkg)
                    | Spdx3Element::AiPackage(pkg)
                    | Spdx3Element::DatasetPackage(pkg) => pkg.spdx_id.clone(),
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
                    Spdx3Element::Bom(c) | Spdx3Element::Bundle(c) => c.spdx_id.clone(),
                    // CreationInfo is not an Element; its blank-node "@id"
                    // ("_:...") cannot collide with element spdxIds (IRIs).
                    Spdx3Element::CreationInfo(ci) => ci.id.clone(),
                    _ => None,
                };
                if let Some(id) = &element_id
                    && !seen_ids.insert(id.clone())
                {
                    duplicate_count += 1;
                    tracing::warn!(id = %id, "duplicate SPDX 3.0 element ID");
                }

                match element {
                    Spdx3Element::Package(pkg) => packages.push((*pkg, PackageKind::Software)),
                    Spdx3Element::AiPackage(pkg) => packages.push((*pkg, PackageKind::AiModel)),
                    Spdx3Element::DatasetPackage(pkg) => {
                        packages.push((*pkg, PackageKind::Dataset));
                    }
                    Spdx3Element::File(file) => files.push(*file),
                    Spdx3Element::Snippet(snippet) => snippets.push(snippet),
                    Spdx3Element::Relationship(rel)
                    | Spdx3Element::LifecycleScopedRelationship(rel) => {
                        relationships.push(rel);
                    }
                    // The agent kind lives in the enum variant: serde's
                    // internally-tagged enum consumes the `type` key, so a
                    // #[serde(rename = "type")] field on Spdx3Agent was never
                    // populated and every creator classified as a Tool.
                    // Record the variant here, before that information is lost.
                    Spdx3Element::Person(mut agent) => {
                        agent.resolved_type_tag = Some("Person");
                        if let Some(id) = &agent.spdx_id {
                            agent_map.insert(id.clone(), agent);
                        }
                    }
                    Spdx3Element::Organization(mut agent) => {
                        agent.resolved_type_tag = Some("Organization");
                        if let Some(id) = &agent.spdx_id {
                            agent_map.insert(id.clone(), agent);
                        }
                    }
                    Spdx3Element::Tool(mut agent) => {
                        agent.resolved_type_tag = Some("Tool");
                        if let Some(id) = &agent.spdx_id {
                            agent_map.insert(id.clone(), agent);
                        }
                    }
                    Spdx3Element::SoftwareAgent(mut agent) => {
                        agent.resolved_type_tag = Some("SoftwareAgent");
                        if let Some(id) = &agent.spdx_id {
                            agent_map.insert(id.clone(), agent);
                        }
                    }
                    Spdx3Element::CreationInfo(ci) => {
                        if let Some(id) = &ci.id {
                            creation_info_map.insert(id.clone(), ci);
                        }
                    }
                    Spdx3Element::Bom(coll) | Spdx3Element::Bundle(coll) => {
                        if let Some(id) = &coll.spdx_id {
                            collection_map.insert(id.clone(), coll);
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
                    Spdx3Element::SpdxDocument(inner) => {
                        // In @graph serialization the document metadata lives
                        // on a node inside the graph, not the top level.
                        // Lift it (without clobbering an already-populated
                        // top-level document, e.g. a mixed serialization).
                        let inner = *inner;
                        if doc.name.is_none() {
                            doc.name = inner.name;
                        }
                        if doc.creation_info.is_none() {
                            doc.creation_info = inner.creation_info;
                        }
                        if doc.root_element.is_none() {
                            doc.root_element = inner.root_element;
                        }
                        if doc.spdx_id.is_none() {
                            doc.spdx_id = inner.spdx_id;
                        }
                        if doc.description.is_none() {
                            doc.description = inner.description;
                        }
                        if doc.profile_conformance.is_none() {
                            doc.profile_conformance = inner.profile_conformance;
                        }
                        if doc.data_license.is_none() {
                            doc.data_license = inner.data_license;
                        }
                        if doc.namespace_map.is_none() {
                            doc.namespace_map = inner.namespace_map;
                        }
                        if doc.imports.is_none() {
                            doc.imports = inner.imports;
                        }
                        if doc.verified_using.is_none() {
                            doc.verified_using = inner.verified_using;
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
        let mut document = self.convert_metadata(&doc, &agent_map, &creation_info_map);
        // BSI TR-03183-2 §5.2.2 requires the completeness of the dependency
        // enumeration to be clearly indicated; SPDX 3 carries it per
        // relationship.
        document.completeness_declaration = derive_completeness_declaration(&relationships);
        let mut sbom = NormalizedSbom::new(document);

        // Convert packages to components
        let mut id_map: HashMap<String, CanonicalId> = HashMap::new();

        for (pkg, kind) in &packages {
            let mut comp = self.convert_package(pkg, *kind, &agent_map);
            let spdx_id = pkg.spdx_id.clone().unwrap_or_else(|| comp.name.clone());
            id_map.insert(spdx_id, sbom.claim_canonical_id(&mut comp));
            sbom.add_component(comp);
        }

        // Convert files to components
        for file in &files {
            let mut comp = self.convert_file(file);
            let spdx_id = file.spdx_id.clone().unwrap_or_else(|| comp.name.clone());
            id_map.insert(spdx_id, sbom.claim_canonical_id(&mut comp));
            sbom.add_component(comp);
        }

        // Convert snippets to components (Phase 2)
        for snippet in &snippets {
            let mut comp = self.convert_snippet(snippet);
            let spdx_id = snippet.spdx_id.clone().unwrap_or_else(|| comp.name.clone());
            id_map.insert(spdx_id, sbom.claim_canonical_id(&mut comp));
            sbom.add_component(comp);
        }

        // Set primary component from rootElement. Canonical documents chain
        // SpdxDocument.rootElement → software_Sbom/Bom collection →
        // collection.rootElement → package, so when the direct lookup misses,
        // follow exactly one level of collection indirection (bounded, no
        // recursion — a reference cycle cannot loop).
        if let Some(root_elements) = &doc.root_element {
            'roots: for root_id in root_elements {
                if let Some(canonical_id) = id_map.get(root_id) {
                    sbom.set_primary_component(canonical_id.clone());
                    break; // Use first resolvable root element as primary
                }
                if let Some(coll) = collection_map.get(root_id) {
                    for inner_id in coll.root_element.iter().flatten() {
                        if let Some(canonical_id) = id_map.get(inner_id) {
                            sbom.set_primary_component(canonical_id.clone());
                            break 'roots;
                        }
                    }
                }
            }
        }

        // The AFFECTS and FIXED_IN relationships and the assessments that
        // name one vulnerability and one component add to one record while
        // they agree (see `attach_vulnerability`).
        let mut vuln_records = VulnRecords::new();

        // Process relationships
        for rel in &relationships {
            self.process_relationship(
                rel,
                &id_map,
                &mut sbom,
                &vuln_map,
                &license_elements,
                &mut vuln_records,
            );
        }

        // Process vulnerability assessments (Phase 1: Security Profile)
        for assessment in &vuln_assessments {
            self.process_vuln_assessment(
                assessment,
                &id_map,
                &mut sbom,
                &vuln_map,
                &mut vuln_records,
            );
        }

        // Vulnerabilities/VEX were attached after component conversion
        // computed each content hash; recompute the affected hashes so
        // vulnerability content is reflected in them (and in the SBOM hash
        // below) — same rule as the CycloneDX parser.
        for comp in sbom.components.values_mut() {
            if !comp.vulnerabilities.is_empty() || comp.vex_status.is_some() {
                comp.calculate_content_hash();
            }
        }

        // Process annotations → attach to components (Phase 2)
        for annotation in &annotations {
            self.process_annotation(annotation, &id_map, &mut sbom);
        }

        // Store SPDX 3.0-specific data in extensions (Phases 2, 4)
        let mut spdx_ext = serde_json::Map::new();
        if let Some(data_license) = &doc.data_license {
            // Canonical 3.0.1 dataLicense is an IRI ref to a
            // simplelicensing_LicenseExpression element — resolve it to the
            // expression ("CC0-1.0"). Unresolvable values (inline literals,
            // NoAssertion consts) keep the raw string.
            let resolved = license_elements
                .get(data_license)
                .cloned()
                .unwrap_or_else(|| data_license.clone());
            spdx_ext.insert(
                "dataLicense".to_string(),
                serde_json::Value::String(resolved),
            );
        }
        if let Some(ns_map) = &doc.namespace_map
            && !ns_map.is_empty()
        {
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
        if let Some(imports) = &doc.imports
            && !imports.is_empty()
        {
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
        ci_map: &HashMap<String, Spdx3CreationInfo>,
    ) -> DocumentMetadata {
        // Resolve the document's creationInfo: canonical @graph documents
        // store a string ref to a standalone CreationInfo node; the inline
        // object form resolves to itself. A document whose SpdxDocument-level
        // creationInfo is absent or unresolvable but whose graph holds
        // exactly ONE CreationInfo node unambiguously uses that one (with
        // several, guessing would misattribute creators).
        let creation_info = doc
            .creation_info
            .as_ref()
            .and_then(|ci_ref| ci_ref.resolve(ci_map))
            .or_else(|| {
                if ci_map.len() == 1 {
                    ci_map.values().next()
                } else {
                    None
                }
            });

        let created = creation_info
            .and_then(|ci| ci.created.as_ref())
            .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
            // Deterministic fallback: a document with a missing/invalid
            // timestamp must hash identically on every parse (created is
            // folded into the content hash; Utc::now() here made every
            // parse of such a document content-unique, defeating diff
            // identity and the incremental cache). Epoch is an honest
            // "unknown" sentinel rather than a fabricated parse time.
            .map_or(DateTime::UNIX_EPOCH, |dt| dt.with_timezone(&Utc));

        let mut creators = Vec::new();
        if let Some(ci) = creation_info {
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

        let spec_version = creation_info
            .and_then(|ci| ci.spec_version.clone())
            .unwrap_or_else(|| "3.0".to_string());

        // Extract profile conformance
        let profile_conformance = doc.profile_conformance.as_ref().map(|ps| ps.join(", "));

        // Signature from document if present. An empty value is no value,
        // as for the CycloneDX JSF and XML-DSig signatures.
        let signature = doc.verified_using.as_ref().and_then(|methods| {
            methods.iter().find_map(|m| {
                if m.method_type.as_deref() == Some("signature") {
                    Some(SignatureInfo {
                        algorithm: m.algorithm.clone().unwrap_or_else(|| "unknown".to_string()),
                        has_value: m.hash_value.as_deref().is_some_and(|v| !v.is_empty()),
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
            doc_version: None, // SPDX has no document revision counter
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
        kind: PackageKind,
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
                        comp.add_cpe(ext_id.identifier.clone());
                    }
                    Some("swid") => {
                        comp.identifiers.swid = Some(ext_id.identifier.clone());
                    }
                    // SPDX 3.0 names this externalIdentifierType "swhid"
                    // (CRA prEN 40000-1-3 [PRE-7-RQ-07])
                    Some("swhid") => {
                        comp = comp.with_swhid(ext_id.identifier.clone());
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
                // A package whose purpose is file, source or archive is
                // still a package; software_File elements become `File`.
                "file" | "source" | "archive" => ComponentType::Other(purpose.to_lowercase()),
                "data" | "documentation" => ComponentType::Data,
                "model" => ComponentType::MachineLearningModel,
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
                    map_spdx3_external_ref_type,
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

        // ── SPDX 3.0 AI / Dataset profile extraction ──
        // The element `type` (kind) is authoritative; override whatever
        // primary_purpose inferred so an ai_AIPackage/dataset_DatasetPackage
        // always maps to the right ComponentType.
        match kind {
            PackageKind::AiModel => {
                comp.component_type = ComponentType::MachineLearningModel;
                // SPDX 3.0 has no model-card-URL property; approximate AI-001 from
                // a `documentation` external reference.
                let model_card_url = comp
                    .external_refs
                    .iter()
                    .find(|r| r.ref_type == ExternalRefType::Documentation)
                    .map(|r| r.url.clone());
                // Map the closest SPDX 3.0 AI-profile signals into the SAME typed
                // MlModelInfo fields the CycloneDX parser populates, so AI scoring
                // is symmetric across formats. Each is an approximation of the
                // nearest SPDX field; only non-empty values are emitted.

                // AI-005 fairness: explainability + safety-risk assessment narratives.
                let fairness: Vec<crate::model::FairnessAssessment> = pkg
                    .ai_model_explainability
                    .clone()
                    .unwrap_or_default()
                    .into_iter()
                    .chain(pkg.ai_safety_risk_assessment.clone())
                    .map(|text| crate::model::FairnessAssessment {
                        group_at_risk: Some(text),
                        ..Default::default()
                    })
                    .collect();

                // AI-007 use-cases: application info + declared domains.
                let use_cases: Vec<String> = pkg
                    .ai_information_about_application
                    .clone()
                    .into_iter()
                    .chain(pkg.ai_domain.clone().unwrap_or_default())
                    .collect();

                // AI-009 ethical: standards compliance + sensitive-PII disclosure.
                let ethical: Vec<crate::model::EthicalConsideration> = pkg
                    .ai_standard_compliance
                    .clone()
                    .unwrap_or_default()
                    .into_iter()
                    .chain(pkg.ai_use_sensitive_personal_information.clone())
                    .map(|text| crate::model::EthicalConsideration {
                        name: Some(text),
                        mitigation_strategy: None,
                    })
                    .collect();

                // AI-004 quantitative: ai_metric / ai_metricDecisionThreshold entries.
                // SPDX `ai_metric` items are objects (often `{ ai_name, ai_value }`);
                // map name→type and stringify the value, preserving precision.
                let performance_metrics: Vec<crate::model::MetricEntry> = pkg
                    .ai_metric
                    .clone()
                    .unwrap_or_default()
                    .into_iter()
                    .chain(pkg.ai_metric_decision_threshold.clone().unwrap_or_default())
                    .map(spdx3_metric_to_entry)
                    .collect();

                comp.ml_model = Some(crate::model::MlModelInfo {
                    // ai_typeOfModel is a free-string list; treat the first as the
                    // family (cross-format approximation — see metadata.rs docs).
                    architecture_family: pkg
                        .ai_type_of_model
                        .as_ref()
                        .and_then(|v| v.first().cloned()),
                    limitations: pkg.ai_limitation.clone(),
                    energy_kwh_training: pkg
                        .ai_energy_consumption
                        .as_ref()
                        .and_then(Spdx3EnergyConsumption::training_energy_kwh),
                    model_card_url,
                    fairness,
                    ethical_considerations: ethical,
                    use_cases,
                    performance_metrics,
                    // Data-preprocessing steps (BSI/G7 SBOM-for-AI Models cluster).
                    data_preprocessing: pkg.ai_model_data_preprocessing.clone().unwrap_or_default(),
                    // training_datasets are linked via TRAINED_ON relationships in
                    // SPDX (populated in process_relationship), not an inline field.
                    ..Default::default()
                });
            }
            PackageKind::Dataset => {
                comp.component_type = ComponentType::Data;
                let mut sensitivity = Vec::new();
                // Only an explicit "yes" implies PII; "no"/"noAssertion" do not.
                if pkg.dataset_has_sensitive_personal_information.as_deref() == Some("yes") {
                    sensitivity.push("pii".to_string());
                }
                if let Some(level) = &pkg.dataset_confidentiality_level {
                    sensitivity.push(level.clone());
                }
                // Governance owners: supplied_by ∪ originated_by agent names.
                let mut owners: Vec<String> = Vec::new();
                for refs in [pkg.supplied_by.as_ref(), pkg.originated_by.as_ref()]
                    .into_iter()
                    .flatten()
                {
                    for agent_ref in refs {
                        if let Some(name) = agent_map.get(agent_ref).and_then(|a| a.name.clone())
                            && !owners.contains(&name)
                        {
                            owners.push(name);
                        }
                    }
                }
                comp.dataset = Some(crate::model::DatasetInfo {
                    // SPDX dataset_datasetType is a data MODALITY (text/image/…),
                    // not a train/test split — a documented cross-format divergence.
                    dataset_type: pkg
                        .dataset_dataset_type
                        .as_ref()
                        .and_then(|v| v.first().cloned()),
                    sensitivity_classifications: sensitivity,
                    governance_owners: owners,
                    // BSI/G7 SBOM-for-AI Datasets cluster provenance / intended-use.
                    intended_use: pkg.dataset_intended_use.clone(),
                    confidentiality_level: pkg.dataset_confidentiality_level.clone(),
                    preprocessing: pkg.dataset_data_preprocessing.clone().unwrap_or_default(),
                    anonymization: pkg
                        .dataset_anonymization_method_used
                        .clone()
                        .unwrap_or_default(),
                });
            }
            PackageKind::Software => {}
        }

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
    /// The assessment adds to the record that an AFFECTS or FIXED_IN
    /// relationship or an earlier assessment attached for the same
    /// vulnerability and component, when their statements agree (see
    /// `attach_vulnerability`).
    fn process_vuln_assessment(
        &self,
        assessment: &Spdx3VulnAssessment,
        id_map: &HashMap<String, CanonicalId>,
        sbom: &mut NormalizedSbom,
        vuln_map: &HashMap<String, Spdx3Vulnerability>,
        vuln_records: &mut VulnRecords,
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

        // Extract CVSS score if present. Reject non-finite (NaN/inf) scores
        // so a hostile value can't reach severity derivation.
        let cvss_score = assessment.score.filter(|s| s.is_finite()).map(|score| {
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

        // Map justification string to enum. Unknown/unrecognized yields None,
        // never fabricating a strong not-affected justification from hostile
        // or malformed input.
        let justification = assessment.justification.as_deref().and_then(|j| {
            match j.to_lowercase().replace(['-', '_'], "").as_str() {
                "componentnotpresent" => Some(VexJustification::ComponentNotPresent),
                "vulnerablecodenotpresent" => Some(VexJustification::VulnerableCodeNotPresent),
                "vulnerablecodenotinexecutepath" => {
                    Some(VexJustification::VulnerableCodeNotInExecutePath)
                }
                "vulnerablecodecannotbecontrolledbyadversary" => {
                    Some(VexJustification::VulnerableCodeCannotBeControlledByAdversary)
                }
                "inlinemitigationsalreadyexist" => {
                    Some(VexJustification::InlineMitigationsAlreadyExist)
                }
                _ => None,
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

                let statement = VulnStatement {
                    vuln_id,
                    source: assessment.spdx_id.as_deref(),
                    record: &vuln_ref,
                    affects: false,
                };
                attach_vulnerability(sbom, vuln_records, canonical_id, &statement);
                if let Some(vs) = vex_status
                    && let Some(comp) = sbom.components.get_mut(canonical_id)
                {
                    comp.vex_status = Some(vs);
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
            // Deterministic: annotations without timestamps must not make
            // serialized output differ run-to-run.
            annotation_date: DateTime::UNIX_EPOCH,
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
        vuln_records: &mut VulnRecords,
    ) {
        let rel_type = rel.relationship_type.as_deref().unwrap_or("");
        // SPDX 3.0 JSON-LD serializes relationship types in camelCase
        // ("dependsOn", "hasDeclaredLicense", "fixedIn"); older/underscore
        // forms ("DEPENDS_ON") also occur. Normalize BOTH to UPPER_SNAKE so
        // spec-compliant camelCase documents don't parse to zero edges (a
        // bare to_uppercase() turned "dependsOn" into "DEPENDSON", matching
        // no arm).
        let normalized = normalize_relationship_type(rel_type);
        // Inverse (`*_OF` / `GENERATED_FROM` / `*_TOOL_OF`) relationships
        // read "A is a dependency of B" = B depends on A, so their edge is
        // swapped relative to the forward form. Types with a dedicated
        // DependencyType (ContainedBy/AncestorOf/VariantOf/Patch/Copy/…)
        // keep from→to, since the type itself encodes the direction.
        let swap = is_inverse_dependency(&normalized);

        match normalized.as_str() {
            // Dependency relationships -> DependencyEdge
            "DEPENDS_ON" | "DEPENDENCY_OF" => {
                self.add_dependency_edge(rel, id_map, sbom, DependencyType::DependsOn, swap);
            }
            "DEV_DEPENDENCY_OF" | "DEV_DEPENDS_ON" => {
                self.add_dependency_edge(rel, id_map, sbom, DependencyType::DevDependsOn, swap);
            }
            "BUILD_DEPENDENCY_OF" | "BUILD_DEPENDS_ON" | "BUILD_TOOL_OF" => {
                self.add_dependency_edge(rel, id_map, sbom, DependencyType::BuildDependsOn, swap);
            }
            "TEST_DEPENDENCY_OF" | "TEST_DEPENDS_ON" | "TEST_TOOL_OF" => {
                self.add_dependency_edge(rel, id_map, sbom, DependencyType::TestDependsOn, swap);
            }
            "RUNTIME_DEPENDENCY_OF" | "RUNTIME_DEPENDS_ON" => {
                self.add_dependency_edge(rel, id_map, sbom, DependencyType::RuntimeDependsOn, swap);
            }
            "OPTIONAL_DEPENDENCY_OF" | "OPTIONAL_DEPENDS_ON" => {
                self.add_dependency_edge(
                    rel,
                    id_map,
                    sbom,
                    DependencyType::OptionalDependsOn,
                    swap,
                );
            }
            "PROVIDED_DEPENDENCY_OF" => {
                self.add_dependency_edge(
                    rel,
                    id_map,
                    sbom,
                    DependencyType::ProvidedDependsOn,
                    swap,
                );
            }
            "CONTAINS" => {
                self.add_dependency_edge(rel, id_map, sbom, DependencyType::Contains, false);
            }
            "DESCRIBES" => {
                self.add_dependency_edge(rel, id_map, sbom, DependencyType::Describes, false);
            }
            "GENERATES" | "GENERATED_FROM" => {
                self.add_dependency_edge(rel, id_map, sbom, DependencyType::Generates, swap);
            }
            "ANCESTOR_OF" => {
                self.add_dependency_edge(rel, id_map, sbom, DependencyType::AncestorOf, false);
            }
            "VARIANT_OF" => {
                self.add_dependency_edge(rel, id_map, sbom, DependencyType::VariantOf, false);
            }
            "DISTRIBUTION_ARTIFACT" => {
                self.add_dependency_edge(
                    rel,
                    id_map,
                    sbom,
                    DependencyType::DistributionArtifact,
                    false,
                );
            }
            "PATCH_FOR" | "PATCH_APPLIED" => {
                // Both have from=patch, to=target (same direction per spec).
                self.add_dependency_edge(rel, id_map, sbom, DependencyType::PatchFor, false);
            }
            "COPY_OF" | "EXPANDED_FROM_ARCHIVE" => {
                self.add_dependency_edge(rel, id_map, sbom, DependencyType::CopyOf, false);
            }
            "DYNAMIC_LINK" => {
                self.add_dependency_edge(rel, id_map, sbom, DependencyType::DynamicLink, false);
            }
            "STATIC_LINK" => {
                self.add_dependency_edge(rel, id_map, sbom, DependencyType::StaticLink, false);
            }

            // License relationships -> populate Component.licenses
            "HAS_DECLARED_LICENSE" | "HAS_CONCLUDED_LICENSE" => {
                if let Some(from_ref) = &rel.from
                    && let Some(canonical_id) = id_map.get(from_ref)
                    && let Some(to_refs) = &rel.to
                {
                    for to_ref in to_refs {
                        if let Some(expr) = license_elements.get(to_ref)
                            && let Some(comp) = sbom.components.get_mut(canonical_id)
                        {
                            let lic = LicenseExpression::new(expr.clone());
                            if normalized.contains("CONCLUDED") {
                                comp.licenses.concluded = Some(lic);
                            } else {
                                comp.licenses.add_declared(lic);
                            }
                        }
                    }
                }
            }

            // Vulnerability relationships
            "AFFECTS" => {
                // Vulnerability affects Package
                if let Some(from_ref) = &rel.from
                    && let Some(vuln) = vuln_map.get(from_ref)
                    && let Some(to_refs) = &rel.to
                {
                    // Convert ONCE (capped description) and clone per target,
                    // deduped: rebuilding per `to` entry re-clones the
                    // attacker-controlled description — a memory-amplification
                    // DoS from one relationship with a huge `to` array.
                    let vuln_ref = self.convert_vulnerability(vuln);
                    let statement = VulnStatement {
                        vuln_id: from_ref,
                        source: rel.spdx_id.as_deref(),
                        record: &vuln_ref,
                        affects: true,
                    };
                    let mut seen: HashSet<&CanonicalId> = HashSet::new();
                    for to_ref in to_refs {
                        if let Some(canonical_id) = id_map.get(to_ref)
                            && seen.insert(canonical_id)
                        {
                            attach_vulnerability(sbom, vuln_records, canonical_id, &statement);
                        }
                    }
                }
            }

            "FIXED_IN" => {
                // Vulnerability fixed in Package@version
                if let Some(from_ref) = &rel.from
                    && let Some(vuln) = vuln_map.get(from_ref)
                    && let Some(to_refs) = &rel.to
                {
                    let mut base = self.convert_vulnerability(vuln);
                    base.vex_status = Some(VexStatus::new(VexState::Fixed));
                    let statement = VulnStatement {
                        vuln_id: from_ref,
                        source: rel.spdx_id.as_deref(),
                        record: &base,
                        affects: false,
                    };
                    let mut seen: HashSet<&CanonicalId> = HashSet::new();
                    for to_ref in to_refs {
                        if let Some(canonical_id) = id_map.get(to_ref)
                            && seen.insert(canonical_id)
                        {
                            attach_vulnerability(sbom, vuln_records, canonical_id, &statement);
                            if let Some(comp) = sbom.components.get_mut(canonical_id) {
                                comp.vex_status = Some(VexStatus::new(VexState::Fixed));
                            }
                        }
                    }
                }
            }

            // VEX assessment relationships — handled via VulnAssessment elements
            "HAS_ASSESSMENT_FOR" => {
                // These are processed in process_vuln_assessment()
            }

            // AI profile: an ai_AIPackage TRAINED_ON a dataset (SPDX 3.0
            // JSON-LD "trainedOn"). The SPDX equivalent of CycloneDX
            // `modelParameters.datasets`; populate the model's typed
            // `training_datasets` so AI-003 passes for SPDX too. `testedOn`
            // is intentionally not treated as a training dataset.
            "TRAINED_ON" => {
                if let Some(from_ref) = &rel.from
                    && let Some(from_id) = id_map.get(from_ref)
                    && let Some(to_refs) = &rel.to
                {
                    for to_ref in to_refs {
                        // Prefer the resolved component's name; fall back to the raw ref.
                        let name = id_map
                            .get(to_ref)
                            .and_then(|cid| sbom.components.get(cid))
                            .map(|c| c.name.clone())
                            .filter(|n| !n.is_empty());
                        if let Some(comp) = sbom.components.get_mut(from_id) {
                            let ml = comp.ml_model.get_or_insert_with(Default::default);
                            ml.training_datasets.push(crate::model::DatasetRef {
                                reference: Some(to_ref.clone()),
                                name,
                                purl: None,
                            });
                        }
                    }
                }
            }

            _ => {
                // Unknown relationship type - store as Other if it connects known components
                if !rel_type.is_empty() {
                    self.add_dependency_edge(
                        rel,
                        id_map,
                        sbom,
                        DependencyType::Other(rel_type.to_string()),
                        false,
                    );
                }
            }
        }
    }

    /// Add a dependency edge from a relationship.
    ///
    /// `swap` reverses the edge direction for inverse relationship types
    /// (`*_OF`): SPDX "A DEPENDENCY_OF B" means B depends on A, so the edge
    /// runs to→from rather than from→to.
    fn add_dependency_edge(
        &self,
        rel: &Spdx3Relationship,
        id_map: &HashMap<String, CanonicalId>,
        sbom: &mut NormalizedSbom,
        dep_type: DependencyType,
        swap: bool,
    ) {
        if let Some(from_ref) = &rel.from
            && let Some(from_id) = id_map.get(from_ref)
            && let Some(to_refs) = &rel.to
        {
            for to_ref in to_refs {
                if let Some(to_id) = id_map.get(to_ref) {
                    let (src, dst) = if swap {
                        (to_id.clone(), from_id.clone())
                    } else {
                        (from_id.clone(), to_id.clone())
                    };
                    sbom.add_edge(DependencyEdge::new(src, dst, dep_type.clone()));
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
        vuln_ref.description = super::capped_description(&vuln.description);

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
        use crate::parsers::contains_json_key;

        let content = super::strip_bom(content);
        let trimmed = content.trim();

        if !trimmed.starts_with('{') {
            return FormatDetection::no_match();
        }

        // SPDX 3.0 indicators. Marker keys must appear as actual JSON keys
        // (see contains_json_key), not a coincidental string value elsewhere.
        // The bare "spdx3" substring (no namespace URL, no quoting) was
        // dropped: real SPDX 3.0 JSON-LD documents always carry one of the
        // two spdx.org/rdf/{3,v3} context URLs below, and the bare word was
        // the exact vector for an unrelated document (e.g. one that mentions
        // "spdx3" in a description or property) to be misrouted here.
        let has_context = contains_json_key(content, "@context");
        let has_spdx3_context =
            content.contains("spdx.org/rdf/3") || content.contains("spdx.org/rdf/v3");
        let has_type_spdx_document =
            contains_json_key(content, "type") && content.contains("\"SpdxDocument\"");
        let has_spdx_id = contains_json_key(content, "spdxId");
        let has_creation_info = contains_json_key(content, "creationInfo");
        let has_element = contains_json_key(content, "element");
        let has_root_element = contains_json_key(content, "rootElement");

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

/// The vulnerability records attached so far, keyed by the `spdxId` of the
/// Vulnerability element and the component. A pair has one record unless
/// its statements contradict each other (see [`attach_vulnerability`]).
type VulnRecords = HashMap<(String, CanonicalId), Vec<AttachedRecord>>;

/// One record of a (Vulnerability element, component) pair.
struct AttachedRecord {
    /// Where the record sits in the component's `vulnerabilities`.
    position: usize,
    /// The `spdxId`s of the relationships and assessments merged into it.
    sources: Vec<String>,
    /// Whether a plain AFFECTS relationship is among them: an `affected`
    /// claim that the record's VEX status does not spell out.
    affects: bool,
}

/// What one AFFECTS or FIXED_IN relationship, or one assessment, states
/// about a vulnerability on a component.
struct VulnStatement<'a> {
    /// The `spdxId` of the Vulnerability element.
    vuln_id: &'a str,
    /// The `spdxId` of the relationship or assessment, when it has one.
    source: Option<&'a str>,
    /// The record the statement gives: the vulnerability, with the
    /// assessment's CVSS score and VEX status when it has them.
    record: &'a VulnerabilityRef,
    /// Whether the statement is a plain AFFECTS relationship, which claims
    /// `affected` without giving a VEX status.
    affects: bool,
}

/// The claim of a plain AFFECTS relationship. It decides agreement only:
/// the relationship gives no VEX status, so none is written for it.
static AFFECTED: VexStatus = VexStatus::new(VexState::Affected);

/// The VEX claim of a record or statement whose VEX status is `vex`: that
/// status, else `affected` for a plain AFFECTS relationship. A CVSS, EPSS
/// or SSVC assessment claims nothing.
fn vex_claim(vex: Option<&VexStatus>, affects: bool) -> Option<&VexStatus> {
    vex.or_else(|| affects.then_some(&AFFECTED))
}

/// Attach `statement` to the component `canonical_id`.
///
/// The first statement about a pair starts its record. A later one joins a
/// record when it is the same element read again (one relationship or
/// assessment met through two paths) and its VEX status fits the record's,
/// or when their VEX claims agree: one of them claims nothing (a CVSS, EPSS
/// or SSVC assessment), or both claim the same state and set no field to
/// different values. A plain AFFECTS relationship claims `affected` without
/// giving a VEX status; FIXED_IN claims and gives `fixed`, as it always
/// has. So an AFFECTS relationship and an `affected`
/// assessment are one record, and so are FIXED_IN and a `fixed` one, while
/// AFFECTS and FIXED_IN, or AFFECTS and a `not_affected`, `fixed` or
/// `under_investigation` assessment of another element, keep a record
/// each: the document contradicts itself, and merging would settle the
/// vulnerability on the word of one side. A statement that joins no record
/// starts its own, a copy of the pair's record with the statement's VEX
/// status.
///
/// Nothing a statement carries is dropped. Its scores and other data reach
/// every record of the pair, since they describe the vulnerability, not its
/// status, and the more severe severity wins. Its VEX status fills the VEX
/// fields the record it joins leaves unset. A record carries only the VEX
/// status its statements give; AFFECTS's `affected` is never written out.
///
/// Two Vulnerability elements with one CVE id are two pairs and keep two
/// records: the document lists the vulnerability twice, as a CycloneDX
/// document that repeats a `vulnerabilities[]` entry does.
fn attach_vulnerability(
    sbom: &mut NormalizedSbom,
    records: &mut VulnRecords,
    canonical_id: &CanonicalId,
    statement: &VulnStatement<'_>,
) {
    let Some(comp) = sbom.components.get_mut(canonical_id) else {
        return;
    };
    let attached = records
        .entry((statement.vuln_id.to_string(), canonical_id.clone()))
        .or_default();
    let vex = statement.record.vex_status.as_ref();
    for entry in attached.iter() {
        merge_vulnerability_data(&mut comp.vulnerabilities[entry.position], statement.record);
    }
    let vulnerabilities = &comp.vulnerabilities;
    let current = |entry: &AttachedRecord| vulnerabilities[entry.position].vex_status.as_ref();
    let same_element = |entry: &AttachedRecord| {
        statement
            .source
            .is_some_and(|source| entry.sources.iter().any(|known| known == source))
    };
    let joined = attached
        .iter()
        .position(|entry| same_element(entry) && vex_agrees(current(entry), vex))
        .or_else(|| {
            let claim = vex_claim(vex, statement.affects);
            attached
                .iter()
                .position(|entry| vex_agrees(vex_claim(current(entry), entry.affects), claim))
        });
    if let Some(i) = joined {
        let entry = &mut attached[i];
        if let Some(vex) = vex {
            merge_vex(&mut comp.vulnerabilities[entry.position].vex_status, vex);
        }
        entry.affects |= statement.affects;
        if let Some(source) = statement.source
            && !entry.sources.iter().any(|known| known == source)
        {
            entry.sources.push(source.to_string());
        }
        return;
    }
    let own = match attached.first() {
        Some(first) => {
            let mut own = comp.vulnerabilities[first.position].clone();
            own.vex_status = statement.record.vex_status.clone();
            own
        }
        None => statement.record.clone(),
    };
    attached.push(AttachedRecord {
        position: comp.vulnerabilities.len(),
        sources: statement.source.map(str::to_string).into_iter().collect(),
        affects: statement.affects,
    });
    comp.vulnerabilities.push(own);
}

/// Add to `record` what `incoming`, a later statement about the same
/// vulnerability, carries besides its VEX status (see [`merge_vex`]).
fn merge_vulnerability_data(record: &mut VulnerabilityRef, incoming: &VulnerabilityRef) {
    // Every field is named, so a field added to the model later cannot be
    // dropped here unnoticed.
    let VulnerabilityRef {
        // Both records were converted from the same Vulnerability element.
        id: _,
        source: _,
        severity,
        cvss,
        affected_versions,
        remediation,
        description,
        cwes,
        published,
        modified,
        is_kev,
        kev_info,
        epss_score,
        epss_percentile,
        vex_status: _,
    } = incoming;
    if let Some(severity) = severity
        && record
            .severity
            .as_ref()
            .is_none_or(|current| severity.priority() < current.priority())
    {
        record.severity = Some(severity.clone());
    }
    for score in cvss {
        if !record.cvss.iter().any(|known| same_cvss(known, score)) {
            record.cvss.push(score.clone());
        }
    }
    for version in affected_versions {
        if !record.affected_versions.contains(version) {
            record.affected_versions.push(version.clone());
        }
    }
    for cwe in cwes {
        if !record.cwes.contains(cwe) {
            record.cwes.push(cwe.clone());
        }
    }
    fill(&mut record.remediation, remediation.as_ref());
    fill(&mut record.description, description.as_ref());
    fill(&mut record.published, published.as_ref());
    fill(&mut record.modified, modified.as_ref());
    record.is_kev |= *is_kev;
    fill(&mut record.kev_info, kev_info.as_ref());
    fill(&mut record.epss_score, epss_score.as_ref());
    fill(&mut record.epss_percentile, epss_percentile.as_ref());
}

/// Whether `a` and `b` are the same CVSS score.
fn same_cvss(a: &CvssScore, b: &CvssScore) -> bool {
    let CvssScore {
        version,
        base_score,
        vector,
        exploitability_score,
        impact_score,
    } = a;
    let bits = |score: Option<f32>| score.map(f32::to_bits);
    *version == b.version
        && base_score.to_bits() == b.base_score.to_bits()
        && *vector == b.vector
        && bits(*exploitability_score) == bits(b.exploitability_score)
        && bits(*impact_score) == bits(b.impact_score)
}

/// Whether two VEX statements agree: one of them is absent, or both have the
/// same state and set no field to different values.
fn vex_agrees(a: Option<&VexStatus>, b: Option<&VexStatus>) -> bool {
    fn agree<T: PartialEq>(a: Option<&T>, b: Option<&T>) -> bool {
        a.is_none() || b.is_none() || a == b
    }
    let (Some(a), Some(b)) = (a, b) else {
        return true;
    };
    a.status == b.status
        && agree(a.justification.as_ref(), b.justification.as_ref())
        && agree(a.action_statement.as_ref(), b.action_statement.as_ref())
        && agree(a.impact_statement.as_ref(), b.impact_statement.as_ref())
        && agree(a.detail.as_ref(), b.detail.as_ref())
}

/// Fold the VEX statement `incoming` into `slot`, which holds none or one
/// that [`vex_agrees`] with it: unset fields take its values, and its
/// responses join the record's.
fn merge_vex(slot: &mut Option<VexStatus>, incoming: &VexStatus) {
    let Some(current) = slot.as_mut() else {
        *slot = Some(incoming.clone());
        return;
    };
    let VexStatus {
        status: _,
        justification,
        action_statement,
        impact_statement,
        responses,
        detail,
    } = incoming;
    fill(&mut current.justification, justification.as_ref());
    fill(&mut current.action_statement, action_statement.as_ref());
    fill(&mut current.impact_statement, impact_statement.as_ref());
    fill(&mut current.detail, detail.as_ref());
    for response in responses {
        if !current.responses.contains(response) {
            current.responses.push(response.clone());
        }
    }
}

/// Set `slot` to `value` when it is unset.
fn fill<T: Clone>(slot: &mut Option<T>, value: Option<&T>) {
    if slot.is_none() {
        *slot = value.cloned();
    }
}

/// Normalize a relationship type to UPPER_SNAKE_CASE.
///
/// Accepts both the SPDX 3.0 JSON-LD camelCase form ("dependsOn") and the
/// underscore form ("DEPENDS_ON"): a `_` is inserted at each lower→upper
/// camelCase boundary and the whole string uppercased, so both map to the
/// same key. Without this, camelCase types uppercased to "DEPENDSON" and
/// matched no arm, so spec-compliant documents parsed with zero edges.
fn normalize_relationship_type(rel_type: &str) -> String {
    let mut out = String::with_capacity(rel_type.len() + 4);
    let mut prev_lower_or_digit = false;
    for ch in rel_type.chars() {
        if ch.is_ascii_uppercase() && prev_lower_or_digit {
            out.push('_');
        }
        // Underscores already present pass through; runs won't double because
        // an existing '_' resets prev_lower_or_digit to false.
        out.push(ch.to_ascii_uppercase());
        prev_lower_or_digit = ch.is_ascii_lowercase() || ch.is_ascii_digit();
    }
    out
}

/// Whether a (normalized) relationship type is the inverse of a forward
/// dependency and therefore needs its edge direction swapped.
fn is_inverse_dependency(normalized: &str) -> bool {
    matches!(
        normalized,
        "DEPENDENCY_OF"
            | "DEV_DEPENDENCY_OF"
            | "BUILD_DEPENDENCY_OF"
            | "TEST_DEPENDENCY_OF"
            | "RUNTIME_DEPENDENCY_OF"
            | "OPTIONAL_DEPENDENCY_OF"
            | "PROVIDED_DEPENDENCY_OF"
            | "BUILD_TOOL_OF"
            | "TEST_TOOL_OF"
            | "GENERATED_FROM"
    )
}

/// Fold per-relationship `completeness` assertions (SPDX 3) into the
/// document-level [`CompletenessDeclaration`]. Only dependency-family
/// relationships count; any `incomplete` wins, then `complete`, then
/// `noAssertion` (NotSpecified), else Unknown.
fn derive_completeness_declaration(
    relationships: &[Spdx3Relationship],
) -> crate::model::CompletenessDeclaration {
    use crate::model::CompletenessDeclaration;

    let mut any_complete = false;
    let mut any_no_assertion = false;
    for rel in relationships {
        let Some(completeness) = rel.completeness.as_deref() else {
            continue;
        };
        let normalized =
            normalize_relationship_type(rel.relationship_type.as_deref().unwrap_or(""));
        let is_dependency = matches!(
            normalized.as_str(),
            "DEPENDS_ON"
                | "DEV_DEPENDS_ON"
                | "BUILD_DEPENDS_ON"
                | "TEST_DEPENDS_ON"
                | "RUNTIME_DEPENDS_ON"
                | "OPTIONAL_DEPENDS_ON"
                | "DEPENDENCY_OF"
                | "DEV_DEPENDENCY_OF"
                | "BUILD_DEPENDENCY_OF"
                | "TEST_DEPENDENCY_OF"
                | "RUNTIME_DEPENDENCY_OF"
                | "OPTIONAL_DEPENDENCY_OF"
                | "PROVIDED_DEPENDENCY_OF"
        );
        if !is_dependency {
            continue;
        }
        match completeness.trim().to_ascii_lowercase().as_str() {
            "incomplete" => return CompletenessDeclaration::Incomplete,
            "complete" => any_complete = true,
            "noassertion" => any_no_assertion = true,
            _ => {}
        }
    }
    if any_complete {
        CompletenessDeclaration::Complete
    } else if any_no_assertion {
        CompletenessDeclaration::NotSpecified
    } else {
        CompletenessDeclaration::Unknown
    }
}

/// Map an SPDX 3.0 `externalRefType` to the normalized enum, whose variants
/// follow the CycloneDX vocabulary.
///
/// The vocabulary is SPDX 3.0.1 `Core/ExternalRefType`
/// (<https://spdx.org/rdf/3.0.1/terms/Core/ExternalRefType>, 46 values). A
/// value may be the compact term (`securityAdvisory`) or the full vocabulary
/// IRI; matching ignores case. A term maps to a variant only where its
/// definition matches the CycloneDX type the variant stands for:
///
/// | SPDX 3.0.1 term                         | CycloneDX type             |
/// |-----------------------------------------|----------------------------|
/// | `vcs`, `issueTracker`, `documentation`  | same name                  |
/// | `securityAdvisory`                      | `advisories`               |
/// | `buildMeta`, `buildSystem`              | `build-meta`, `build-system` |
/// | `certificationReport`                   | `certification-report`     |
/// | `riskAssessment`                        | `risk-assessment`          |
/// | `secureSoftwareAttestation`             | `attestation`              |
/// | `vulnerabilityDisclosureReport` (VDR)   | `vulnerability-assertion`  |
/// | `vulnerabilityExploitabilityAssessment` (VEX) | `exploitability-statement` |
/// | `securityPolicy` (how to report vulnerabilities) | `security-contact` |
/// | `securityThreatModel`, `securityAdversaryModel` | `threat-model`, `adversary-model` |
/// | `securityPenTestReport`                 | `pentest-report`           |
/// | `staticAnalysisReport`, `dynamicAnalysisReport`, `runtimeAnalysisReport`, `componentAnalysisReport` | the `*-analysis-report` types |
/// | `metrics`, `qualityAssessmentReport`    | `quality-metrics`          |
/// | `releaseNotes`, `license`, `support`, `chat`, `mailingList`, `socialMedia` | `release-notes`, `license`, `support`, `chat`, `mailing-list`, `social` |
///
/// The other terms have no counterpart and stay `Other`, keeping the term:
/// the package-manager locators (`bower`, `mavenCentral`, `npm`, `nuget`),
/// `cwe`, `securityFix`, `securityOther`, `eolNotice`, `funding`,
/// `exportControlAssessment`, `privacyAssessment`, `purchaseOrder`,
/// `productMetadata`, `releaseHistory`, `binaryArtifact`, `sourceArtifact`
/// and `other`. `altDownloadLocation` and `altWebPage` are alternatives the
/// model has no slot for; as `SourceDistribution` or `Website` the SPDX
/// writer would promote them to a package's download location.
///
/// `advisories`, `issue-tracker` and `bom` are not SPDX 3.0 terms; they are
/// accepted for producers that write the CycloneDX names.
fn map_spdx3_external_ref_type(value: &str) -> ExternalRefType {
    const VOCABULARY: &str = "/ExternalRefType/";
    let term = value
        .rfind(VOCABULARY)
        .map_or(value, |at| &value[at + VOCABULARY.len()..]);
    match term.to_ascii_lowercase().as_str() {
        "vcs" => ExternalRefType::Vcs,
        "issuetracker" | "issue-tracker" => ExternalRefType::IssueTracker,
        "documentation" => ExternalRefType::Documentation,
        "securityadvisory" | "advisories" => ExternalRefType::Advisories,
        "bom" => ExternalRefType::Bom,
        "buildmeta" => ExternalRefType::BuildMeta,
        "buildsystem" => ExternalRefType::BuildSystem,
        "certificationreport" => ExternalRefType::Certification,
        "riskassessment" => ExternalRefType::RiskAssessment,
        "securesoftwareattestation" => ExternalRefType::Attestation,
        "vulnerabilitydisclosurereport" => ExternalRefType::VulnerabilityAssertion,
        "vulnerabilityexploitabilityassessment" => ExternalRefType::ExploitabilityStatement,
        "securitypolicy" => ExternalRefType::SecurityContact,
        "securitythreatmodel" => ExternalRefType::ThreatModel,
        "securityadversarymodel" => ExternalRefType::AdversaryModel,
        "securitypentestreport" => ExternalRefType::Pentest,
        "staticanalysisreport" => ExternalRefType::StaticAnalysis,
        "dynamicanalysisreport" => ExternalRefType::DynamicAnalysis,
        "runtimeanalysisreport" => ExternalRefType::RuntimeAnalysis,
        "componentanalysisreport" => ExternalRefType::ComponentAnalysis,
        "metrics" | "qualityassessmentreport" => ExternalRefType::QualityMetrics,
        "releasenotes" => ExternalRefType::ReleaseNotes,
        "license" => ExternalRefType::License,
        "support" => ExternalRefType::Support,
        "chat" => ExternalRefType::Chat,
        "mailinglist" => ExternalRefType::MailingList,
        "socialmedia" => ExternalRefType::Social,
        _ => ExternalRefType::Other(term.to_string()),
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
    creation_info: Option<Spdx3CreationInfoRef>,
    /// Data license (always CC0-1.0)
    data_license: Option<String>,
    /// Namespace map for cross-document references (Phase 4)
    namespace_map: Option<Vec<Spdx3NamespaceMap>>,
    /// External document imports (Phase 4)
    #[serde(rename = "import")]
    imports: Option<Vec<Spdx3ExternalMap>>,
    /// Root elements (URIs of primary elements)
    root_element: Option<Vec<String>>,
    /// All elements in the document (embedded serialization)
    element: Option<Vec<Spdx3Element>>,
    /// JSON-LD `@graph` node set. The canonical SPDX 3.0/3.0.1 serialization
    /// (pyspdx and the spec examples) is a flat graph — `{"@graph":[ …all
    /// elements…, {"type":"SpdxDocument", …} ]}` — rather than an
    /// SpdxDocument with an inline `element` array. Without this the parser
    /// only read `element` and produced a silently empty SBOM for
    /// spec-conformant documents.
    #[serde(rename = "@graph")]
    graph: Option<Vec<Spdx3Element>>,
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
    /// Blank-node identifier (`"@id": "_:creationinfo"`) carried when this
    /// appears as a standalone `@graph` node (the canonical serialization);
    /// inline objects have none. CreationInfo is not an Element, so it is
    /// identified by `@id`, never `spdxId`.
    #[serde(rename = "@id")]
    id: Option<String>,
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

/// Element `creationInfo`: the SPDX 3.0.1 schema allows either an inline
/// CreationInfo object or a string reference (blank node / IRI) to a
/// standalone CreationInfo node in `@graph`. Canonical serializations (the
/// spec examples, tools-java, the official Python bindings) always use the
/// string form — typing this as a plain struct made every spec-canonical
/// document fail to parse with "invalid type: string, expected struct"
/// (issue #305).
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
enum Spdx3CreationInfoRef {
    Inline(Spdx3CreationInfo),
    Ref(String),
}

impl Spdx3CreationInfoRef {
    /// Resolve to concrete creation info: inline objects resolve to
    /// themselves; string refs look up the indexed standalone node.
    fn resolve<'a>(
        &'a self,
        ci_map: &'a HashMap<String, Spdx3CreationInfo>,
    ) -> Option<&'a Spdx3CreationInfo> {
        match self {
            Self::Inline(ci) => Some(ci),
            Self::Ref(id) => ci_map.get(id),
        }
    }
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
    /// SPDX 3.0 AI profile package (deserializes into the shared Package struct,
    /// which it extends with `ai_*` fields).
    #[serde(alias = "ai_AIPackage", alias = "AIPackage")]
    AiPackage(Box<Spdx3Package>),
    /// SPDX 3.0 Dataset profile package.
    #[serde(alias = "dataset_DatasetPackage", alias = "DatasetPackage")]
    DatasetPackage(Box<Spdx3Package>),
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
    /// Bom / software_Sbom collection: not a component itself, but its
    /// rootElement links the SpdxDocument to the primary package (canonical
    /// documents chain SpdxDocument → Sbom → package).
    #[serde(alias = "software_Sbom", alias = "Sbom")]
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
    /// An SpdxDocument node appearing INSIDE a JSON-LD `@graph` (its
    /// metadata is lifted into the top-level document, which is empty in
    /// that serialization). Its `element`/`rootElement` are ID-reference
    /// strings, so it uses a metadata-only struct rather than the full
    /// `Spdx3Document` (whose `element` is objects).
    SpdxDocument(Box<Spdx3DocumentMeta>),
    /// Standalone CreationInfo node in a JSON-LD `@graph` (the canonical
    /// serialization): elements point at it via `"creationInfo": "_:..."`
    /// string refs. Previously fell into `Unknown`, silently discarding the
    /// document's created timestamp, creators, and spec version.
    CreationInfo(Spdx3CreationInfo),
    /// Catch-all for unknown types (deserialized as raw JSON)
    #[serde(other)]
    Unknown,
}

/// Metadata-only view of an SpdxDocument node inside a JSON-LD `@graph`.
/// Deliberately omits `element` (string ID refs there, not objects), which
/// serde then ignores.
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Spdx3DocumentMeta {
    spdx_id: Option<String>,
    name: Option<String>,
    creation_info: Option<Spdx3CreationInfoRef>,
    root_element: Option<Vec<String>>,
    description: Option<String>,
    profile_conformance: Option<Vec<String>>,
    /// AnyLicenseInfo reference — in canonical documents an IRI string
    /// pointing at a simplelicensing_LicenseExpression element (resolved
    /// against the graph when emitting extensions), not a bare literal.
    data_license: Option<String>,
    namespace_map: Option<Vec<Spdx3NamespaceMap>>,
    #[serde(rename = "import")]
    imports: Option<Vec<Spdx3ExternalMap>>,
    verified_using: Option<Vec<Spdx3IntegrityMethod>>,
}

/// SPDX 3.0 Package (Software profile)
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct Spdx3Package {
    spdx_id: Option<String>,
    name: Option<String>,
    // Software-profile properties: canonical JSON-LD serializes them with
    // the `software_` prefix (the @context defines the prefixed names, and
    // the official examples use them exclusively); the unprefixed aliases
    // stay accepted for pre-existing compact producers.
    #[serde(alias = "software_packageVersion")]
    package_version: Option<String>,
    #[serde(alias = "software_packageUrl")]
    package_url: Option<String>,
    #[serde(alias = "software_downloadLocation")]
    download_location: Option<String>,
    #[serde(alias = "software_homePage")]
    home_page: Option<String>,
    #[serde(alias = "software_copyrightText")]
    copyright_text: Option<String>,
    description: Option<String>,
    #[serde(default, deserialize_with = "de_string_or_seq_opt")]
    supplied_by: Option<Vec<String>>,
    originated_by: Option<Vec<String>>,
    verified_using: Option<Vec<Spdx3IntegrityMethod>>,
    external_identifier: Option<Vec<Spdx3ExternalIdentifier>>,
    external_ref: Option<Vec<Spdx3ExternalRef>>,
    #[serde(alias = "software_primaryPurpose")]
    primary_purpose: Option<String>,
    #[serde(alias = "software_additionalPurpose")]
    additional_purpose: Option<Vec<String>>,
    // Deliberately NOT aliased to "software_contentIdentifier": the canonical
    // property is an ARRAY of ContentIdentifier objects, so binding it to
    // this (unused) string field would hard-fail spec-valid documents.
    content_identifier: Option<String>,
    #[serde(alias = "software_attributionText")]
    attribution_text: Option<Vec<String>>,
    support_level: Option<String>,
    valid_until_time: Option<String>,
    built_time: Option<String>,
    release_time: Option<String>,
    creation_info: Option<Spdx3CreationInfoRef>,
    // ── AI profile (ai_AIPackage). camelCase rename_all would drop the `ai_`
    //    prefix, so each key is renamed explicitly. ──
    #[serde(rename = "ai_typeOfModel")]
    ai_type_of_model: Option<Vec<String>>,
    #[serde(rename = "ai_energyConsumption")]
    ai_energy_consumption: Option<Spdx3EnergyConsumption>,
    #[serde(rename = "ai_informationAboutTraining")]
    ai_information_about_training: Option<String>,
    #[serde(rename = "ai_informationAboutApplication")]
    ai_information_about_application: Option<String>,
    #[serde(rename = "ai_limitation")]
    ai_limitation: Option<String>,
    #[serde(rename = "ai_modelExplainability")]
    ai_model_explainability: Option<Vec<String>>,
    #[serde(rename = "ai_safetyRiskAssessment")]
    ai_safety_risk_assessment: Option<String>,
    #[serde(rename = "ai_domain")]
    ai_domain: Option<Vec<String>>,
    #[serde(rename = "ai_standardCompliance")]
    ai_standard_compliance: Option<Vec<String>>,
    #[serde(rename = "ai_metric")]
    ai_metric: Option<Vec<serde_json::Value>>,
    #[serde(rename = "ai_metricDecisionThreshold")]
    ai_metric_decision_threshold: Option<Vec<serde_json::Value>>,
    #[serde(rename = "ai_useSensitivePersonalInformation")]
    ai_use_sensitive_personal_information: Option<String>,
    #[serde(rename = "ai_modelDataPreprocessing")]
    ai_model_data_preprocessing: Option<Vec<String>>,
    // ── Dataset profile (dataset_DatasetPackage). ──
    #[serde(rename = "dataset_datasetType")]
    dataset_dataset_type: Option<Vec<String>>,
    #[serde(rename = "dataset_hasSensitivePersonalInformation")]
    dataset_has_sensitive_personal_information: Option<String>,
    #[serde(rename = "dataset_confidentialityLevel")]
    dataset_confidentiality_level: Option<String>,
    #[serde(rename = "dataset_intendedUse")]
    dataset_intended_use: Option<String>,
    #[serde(rename = "dataset_knownBias")]
    dataset_known_bias: Option<Vec<String>>,
    #[serde(rename = "dataset_anonymizationMethodUsed")]
    dataset_anonymization_method_used: Option<Vec<String>>,
    #[serde(rename = "dataset_dataPreprocessing")]
    dataset_data_preprocessing: Option<Vec<String>>,
}

/// Element kind, tracked from the SPDX 3.0 `type` so the converter can map an
/// `ai_AIPackage`/`dataset_DatasetPackage` (which share `Spdx3Package`) to the
/// right normalized `ComponentType` and extraction path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PackageKind {
    Software,
    AiModel,
    Dataset,
}

/// SPDX 3.0 AI profile `EnergyConsumption`.
#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
struct Spdx3EnergyConsumption {
    #[serde(rename = "ai_trainingEnergyConsumption")]
    ai_training_energy_consumption: Option<Vec<Spdx3EnergyConsumptionDescription>>,
    #[serde(rename = "ai_finetuningEnergyConsumption")]
    ai_finetuning_energy_consumption: Option<Vec<Spdx3EnergyConsumptionDescription>>,
    #[serde(rename = "ai_inferenceEnergyConsumption")]
    ai_inference_energy_consumption: Option<Vec<Spdx3EnergyConsumptionDescription>>,
}

/// One `EnergyConsumptionDescription` (`ai_energyQuantity` + `ai_energyUnit`).
#[derive(Debug, Deserialize, Clone)]
struct Spdx3EnergyConsumptionDescription {
    #[serde(
        rename = "ai_energyQuantity",
        default,
        deserialize_with = "de_string_or_number_opt"
    )]
    ai_energy_quantity: Option<f64>,
    #[serde(rename = "ai_energyUnit")]
    ai_energy_unit: Option<String>,
}

impl Spdx3EnergyConsumption {
    /// Total training energy in kWh, or `None` if no quantifiable entry exists.
    /// Unlike the CycloneDX path (which delegates to `CdxEnergyMeasure::as_kwh`),
    /// SPDX uses `EnergyUnitType` strings; unknown units are skipped rather than
    /// summed in the wrong unit.
    fn training_energy_kwh(&self) -> Option<f64> {
        let entries = self.ai_training_energy_consumption.as_ref()?;
        let total: f64 = entries
            .iter()
            .filter_map(Spdx3EnergyConsumptionDescription::as_kwh)
            .sum();
        (total > 0.0).then_some(total)
    }
}

impl Spdx3EnergyConsumptionDescription {
    fn as_kwh(&self) -> Option<f64> {
        let value = self.ai_energy_quantity?;
        let kwh = match self.ai_energy_unit.as_deref() {
            Some("kilowattHour") | None => value,
            Some("wattHour") => value / 1_000.0,
            Some("megawattHour") => value * 1_000.0,
            Some("joule") => value / 3_600_000.0,
            Some("kilojoule") => value / 3_600.0,
            Some("megajoule") => value / 3.6,
            // Unknown unit: skip rather than corrupt the kWh sum.
            Some(_) => return None,
        };
        Some(kwh)
    }
}

/// Deserialize an optional `f64` that the SPDX spec examples sometimes serialize
/// as a JSON string (e.g. `"36.5"`).
fn de_string_or_number_opt<'de, D>(deserializer: D) -> Result<Option<f64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StrOrNum {
        Num(f64),
        Str(String),
    }
    Ok(match Option::<StrOrNum>::deserialize(deserializer)? {
        None => None,
        Some(StrOrNum::Num(n)) => Some(n),
        Some(StrOrNum::Str(s)) => s.trim().parse::<f64>().ok(),
    })
}

/// Deserialize a snippet range that is either the compact string form
/// ("310:420") or the canonical SPDX 3.0.1 PositiveIntegerRange object
/// (`{"beginIntegerRange": 310, "endIntegerRange": 420}`). Unknown shapes
/// yield `None` rather than failing the whole document — a mistyped range
/// must never make an otherwise-valid SBOM unreadable.
fn de_range_opt<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(value.and_then(|v| match v {
        serde_json::Value::String(s) => Some(s),
        serde_json::Value::Object(map) => {
            let get = |k: &str| map.get(k).and_then(serde_json::Value::as_u64);
            match (get("beginIntegerRange"), get("endIntegerRange")) {
                (Some(begin), Some(end)) => Some(format!("{begin}:{end}")),
                (Some(begin), None) => Some(format!("{begin}:")),
                (None, Some(end)) => Some(format!(":{end}")),
                (None, None) => None,
            }
        }
        _ => None,
    }))
}

/// Deserialize an optional `Vec<String>` field that may be supplied as
/// either a single string (cardinality 0..1) or a JSON array of strings.
fn de_string_or_seq_opt<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }

    Ok(match Option::<OneOrMany>::deserialize(deserializer)? {
        None => None,
        Some(OneOrMany::One(s)) => Some(vec![s]),
        Some(OneOrMany::Many(v)) => Some(v),
    })
}

/// Normalize one SPDX 3.0 `ai_metric` value into the typed `MetricEntry`.
///
/// SPDX metric entries are commonly objects such as `{ "ai_name": "accuracy",
/// "ai_value": "0.97" }`, but the property is loosely typed, so plain strings
/// and numbers are also accepted. `name`/`key`/`type` map to the metric type and
/// `value` is stringified to preserve precision and non-numeric values. The
/// canonical SPDX 3.0.1 form is a DictionaryEntry
/// (`{ "type": "DictionaryEntry", "key": "accuracy", "value": "0.97" }`), whose
/// `type` names the class, not the metric: `key` is read before `type`.
fn spdx3_metric_to_entry(value: serde_json::Value) -> crate::model::MetricEntry {
    let stringify = |v: &serde_json::Value| -> Option<String> {
        match v {
            serde_json::Value::Null => None,
            serde_json::Value::String(text) => Some(text.clone()),
            other => Some(other.to_string()),
        }
    };
    match value {
        serde_json::Value::Object(map) => {
            let pick = |keys: &[&str]| keys.iter().find_map(|k| map.get(*k).and_then(stringify));
            crate::model::MetricEntry {
                metric_type: pick(&["ai_name", "name", "key", "type", "ai_type"]),
                value: pick(&["ai_value", "value", "ai_decisionThreshold"]),
                slice: pick(&["ai_slice", "slice"]),
            }
        }
        serde_json::Value::String(text) => crate::model::MetricEntry {
            value: Some(text),
            ..Default::default()
        },
        serde_json::Value::Null => crate::model::MetricEntry::default(),
        other => crate::model::MetricEntry {
            value: Some(other.to_string()),
            ..Default::default()
        },
    }
}

/// SPDX 3.0 File (Software profile)
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct Spdx3File {
    spdx_id: Option<String>,
    name: Option<String>,
    #[serde(alias = "software_copyrightText")]
    copyright_text: Option<String>,
    description: Option<String>,
    verified_using: Option<Vec<Spdx3IntegrityMethod>>,
    #[serde(alias = "software_fileKind")]
    file_kind: Option<String>,
    creation_info: Option<Spdx3CreationInfoRef>,
}

/// SPDX 3.0 Snippet (Software profile)
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct Spdx3Snippet {
    spdx_id: Option<String>,
    name: Option<String>,
    #[serde(alias = "software_copyrightText")]
    copyright_text: Option<String>,
    description: Option<String>,
    /// Byte range within the containing file. Compact producers emit a
    /// "310:420" string; canonical 3.0.1 emits a PositiveIntegerRange object
    /// — both normalize to the "begin:end" string form.
    #[serde(
        alias = "software_byteRange",
        default,
        deserialize_with = "de_range_opt"
    )]
    byte_range: Option<String>,
    /// Line range within the containing file (same dual form as byte_range)
    #[serde(
        alias = "software_lineRange",
        default,
        deserialize_with = "de_range_opt"
    )]
    line_range: Option<String>,
    /// Containing file reference
    #[serde(alias = "software_snippetFromFile")]
    snippet_from_file: Option<String>,
    /// Integrity methods (hashes)
    verified_using: Option<Vec<Spdx3IntegrityMethod>>,
    creation_info: Option<Spdx3CreationInfoRef>,
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
    creation_info: Option<Spdx3CreationInfoRef>,
}

/// SPDX 3.0 Vulnerability (Security profile)
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct Spdx3Vulnerability {
    spdx_id: Option<String>,
    name: Option<String>,
    description: Option<String>,
    // Canonical 3.0.1 serializes the Security-profile timestamps with the
    // security_ prefix (the @context defines only the prefixed names).
    #[serde(alias = "security_publishedTime")]
    published_time: Option<String>,
    #[serde(alias = "security_modifiedTime")]
    modified_time: Option<String>,
    #[serde(alias = "security_withdrawnTime")]
    withdrawn_time: Option<String>,
    external_identifier: Option<Vec<Spdx3ExternalIdentifier>>,
    external_ref: Option<Vec<Spdx3ExternalRef>>,
    creation_info: Option<Spdx3CreationInfoRef>,
}

/// SPDX 3.0 Vulnerability Assessment Relationship
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct Spdx3VulnAssessment {
    spdx_id: Option<String>,
    from: Option<String>,
    to: Option<Vec<String>>,
    // Canonical 3.0.1 serializes Security-profile payload properties with
    // the security_ prefix; two also differ at the base name (vectorString,
    // justificationType). Without these aliases the type-tag aliases routed
    // canonical assessments to the right variant but every field parsed as
    // None — CVSS scores and VEX justifications silently vanished.
    #[serde(alias = "security_assessedElement")]
    assessed_element: Option<String>,
    #[serde(alias = "security_publishedTime")]
    published_time: Option<String>,
    #[serde(alias = "security_modifiedTime")]
    modified_time: Option<String>,
    supplied_by: Option<String>,
    /// CVSS fields
    #[serde(alias = "security_score")]
    score: Option<f32>,
    #[serde(alias = "security_severity")]
    severity: Option<String>,
    #[serde(alias = "security_vectorString", alias = "vectorString")]
    vector: Option<String>,
    /// VEX fields
    #[serde(alias = "security_statusNotes")]
    status_notes: Option<String>,
    #[serde(alias = "security_justificationType", alias = "justificationType")]
    justification: Option<String>,
    #[serde(alias = "security_impactStatement")]
    impact_statement: Option<String>,
    #[serde(alias = "security_actionStatement")]
    action_statement: Option<String>,
    #[serde(alias = "security_vexVersion")]
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
    /// Agent kind, resolved from the matched `Spdx3Element` variant during
    /// the first pass. NOT deserialized: serde's internally-tagged enum
    /// consumes the `type` key before the payload struct sees it, so a
    /// `#[serde(rename = "type")]` field here was always `None` and every
    /// agent was misclassified as a Tool.
    #[serde(skip)]
    resolved_type_tag: Option<&'static str>,
}

impl Spdx3Agent {
    /// Get the creator type based on the resolved agent kind
    fn agent_type(&self) -> (CreatorType, &'static str) {
        match self.resolved_type_tag {
            Some("Person") => (CreatorType::Person, "Person"),
            Some("Organization") => (CreatorType::Organization, "Organization"),
            Some("Tool" | "SoftwareAgent") => (CreatorType::Tool, "Tool"),
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
    #[serde(alias = "simplelicensing_licenseExpression")]
    license_expression: Option<String>,
    #[serde(alias = "simplelicensing_licenseListVersion")]
    license_list_version: Option<String>,
}

/// SPDX 3.0 Simple Licensing Text element
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct Spdx3SimpleLicensingText {
    spdx_id: Option<String>,
    #[serde(alias = "simplelicensing_licenseText")]
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

    #[test]
    fn test_spdx3_ai_dataset_type_tags_deserialize() {
        // Guard against alias typos silently routing to Spdx3Element::Unknown.
        let ai: Spdx3Element =
            serde_json::from_str(r#"{"type": "ai_AIPackage", "spdxId": "urn:x:m", "name": "m"}"#)
                .expect("ai_AIPackage should deserialize");
        assert!(matches!(ai, Spdx3Element::AiPackage(_)));

        let ds: Spdx3Element = serde_json::from_str(
            r#"{"type": "dataset_DatasetPackage", "spdxId": "urn:x:d", "name": "d"}"#,
        )
        .expect("dataset_DatasetPackage should deserialize");
        assert!(matches!(ds, Spdx3Element::DatasetPackage(_)));
    }

    #[test]
    fn test_spdx3_dataset_provenance_fields_mapped() {
        // The Dataset profile provenance fields (intended use, confidentiality
        // level, preprocessing, anonymization) must be carried into DatasetInfo,
        // not dropped — they feed the BSI/G7 SBOM-for-AI Datasets cluster.
        let pkg: Spdx3Package = serde_json::from_str(
            r#"{
                "type": "dataset_DatasetPackage",
                "spdxId": "urn:x:d",
                "name": "reviews",
                "dataset_intendedUse": "model fine-tuning",
                "dataset_confidentialityLevel": "amber",
                "dataset_dataPreprocessing": ["dedup", "normalize"],
                "dataset_anonymizationMethodUsed": ["k-anonymity"],
                "dataset_hasSensitivePersonalInformation": "no"
            }"#,
        )
        .expect("dataset package should deserialize");
        let converter = Spdx3Parser::new();
        let comp = converter.convert_package(&pkg, PackageKind::Dataset, &HashMap::new());
        let ds = comp.dataset.expect("dataset info present");
        assert_eq!(ds.intended_use.as_deref(), Some("model fine-tuning"));
        assert_eq!(ds.confidentiality_level.as_deref(), Some("amber"));
        assert_eq!(ds.preprocessing, vec!["dedup", "normalize"]);
        assert_eq!(ds.anonymization, vec!["k-anonymity"]);
        // Confidentiality level is also folded into sensitivity for AI-Act scoring.
        assert!(
            ds.sensitivity_classifications
                .contains(&"amber".to_string())
        );
    }

    #[test]
    fn test_spdx3_supplied_by_accepts_bare_string() {
        // Real-world producers (e.g. Yocto) emit suppliedBy as a single
        // string even though the type is nominally Vec<String>; suppliedBy's
        // spec cardinality is 0..1, so a bare string must parse the same as
        // a one-element array instead of failing with a "expected a sequence"
        // JSON error (see issue #348).
        let pkg: Spdx3Package = serde_json::from_str(
            r#"{"type": "software_Package", "spdxId": "urn:x:p", "name": "p",
                "suppliedBy": "urn:spdx:agent:Test_Supplier"}"#,
        )
        .expect("bare-string suppliedBy should deserialize");
        assert_eq!(
            pkg.supplied_by,
            Some(vec!["urn:spdx:agent:Test_Supplier".to_string()])
        );

        let pkg_array: Spdx3Package = serde_json::from_str(
            r#"{"type": "software_Package", "spdxId": "urn:x:p", "name": "p",
                "suppliedBy": ["urn:spdx:agent:a", "urn:spdx:agent:b"]}"#,
        )
        .expect("array suppliedBy should still deserialize");
        assert_eq!(
            pkg_array.supplied_by,
            Some(vec![
                "urn:spdx:agent:a".to_string(),
                "urn:spdx:agent:b".to_string()
            ])
        );

        let pkg_absent: Spdx3Package = serde_json::from_str(
            r#"{"type": "software_Package", "spdxId": "urn:x:p", "name": "p"}"#,
        )
        .expect("missing suppliedBy should deserialize");
        assert_eq!(pkg_absent.supplied_by, None);
    }

    fn spdx3_lib(elements: &str) -> NormalizedSbom {
        let doc = format!(
            r#"{{
              "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
              "type": "SpdxDocument", "spdxId": "urn:doc",
              "element": [
                {{"type": "software_Package", "spdxId": "urn:pkg:lib", "name": "lib",
                 "software_packageVersion": "1.0",
                 "software_packageUrl": "pkg:npm/lib@1.0"}},
                {{"type": "security_Vulnerability", "spdxId": "urn:vuln:cve",
                 "name": "CVE-2025-9999", "description": "boom"}},
                {elements}
              ]
            }}"#
        );
        Spdx3Parser::new().parse_str(&doc).expect("parse")
    }

    fn spdx3_component<'a>(sbom: &'a NormalizedSbom, name: &str) -> &'a Component {
        sbom.components
            .values()
            .find(|c| c.name == name)
            .expect("component present")
    }

    #[test]
    fn normalize_relationship_type_handles_camel_and_snake() {
        assert_eq!(normalize_relationship_type("dependsOn"), "DEPENDS_ON");
        assert_eq!(normalize_relationship_type("DEPENDS_ON"), "DEPENDS_ON");
        assert_eq!(normalize_relationship_type("dependencyOf"), "DEPENDENCY_OF");
        assert_eq!(
            normalize_relationship_type("hasDeclaredLicense"),
            "HAS_DECLARED_LICENSE"
        );
        assert_eq!(normalize_relationship_type("fixedIn"), "FIXED_IN");
        assert_eq!(normalize_relationship_type("buildToolOf"), "BUILD_TOOL_OF");
        assert!(is_inverse_dependency("DEPENDENCY_OF"));
        assert!(is_inverse_dependency("GENERATED_FROM"));
        assert!(!is_inverse_dependency("DEPENDS_ON"));
        assert!(!is_inverse_dependency("CONTAINS"));
    }

    fn edge_between<'a>(sbom: &'a NormalizedSbom, from_name: &str, to_name: &str) -> bool {
        let id = |name: &str| {
            sbom.components
                .iter()
                .find(|(_, c)| c.name == name)
                .map(|(id, _)| id.clone())
        };
        let (Some(f), Some(t)) = (id(from_name), id(to_name)) else {
            return false;
        };
        sbom.edges.iter().any(|e| e.from == f && e.to == t)
    }

    /// SPDX 3.0 JSON-LD camelCase `dependsOn` must produce a dependency edge
    /// (a bare to_uppercase turned it into "DEPENDSON", matching no arm →
    /// zero edges for spec-compliant documents).
    #[test]
    fn spdx3_camelcase_relationship_produces_edge() {
        let doc = r#"{
          "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
          "type": "SpdxDocument", "spdxId": "urn:doc",
          "element": [
            {"type": "software_Package", "spdxId": "urn:app", "name": "app",
             "software_packageUrl": "pkg:npm/app@1.0"},
            {"type": "software_Package", "spdxId": "urn:lib", "name": "lib",
             "software_packageUrl": "pkg:npm/lib@1.0"},
            {"type": "Relationship", "spdxId": "urn:rel",
             "relationshipType": "dependsOn", "from": "urn:app", "to": ["urn:lib"]}
          ]
        }"#;
        let sbom = Spdx3Parser::new().parse_str(doc).expect("parse");
        assert!(
            edge_between(&sbom, "app", "lib"),
            "camelCase dependsOn must yield app→lib, edges={:?}",
            sbom.edges
        );
    }

    /// An inverse `dependencyOf` relationship must be direction-swapped:
    /// "lib dependencyOf app" means app depends on lib → edge app→lib.
    #[test]
    fn spdx3_inverse_dependency_swaps_direction() {
        let doc = r#"{
          "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
          "type": "SpdxDocument", "spdxId": "urn:doc",
          "element": [
            {"type": "software_Package", "spdxId": "urn:app", "name": "app",
             "software_packageUrl": "pkg:npm/app@1.0"},
            {"type": "software_Package", "spdxId": "urn:lib", "name": "lib",
             "software_packageUrl": "pkg:npm/lib@1.0"},
            {"type": "Relationship", "spdxId": "urn:rel",
             "relationshipType": "dependencyOf", "from": "urn:lib", "to": ["urn:app"]}
          ]
        }"#;
        let sbom = Spdx3Parser::new().parse_str(doc).expect("parse");
        assert!(
            edge_between(&sbom, "app", "lib"),
            "dependencyOf must swap to app→lib, edges={:?}",
            sbom.edges
        );
        assert!(
            !edge_between(&sbom, "lib", "app"),
            "the un-swapped lib→app edge must not exist"
        );
    }

    /// The canonical @graph JSON-LD serialization must parse to a populated
    /// SBOM (was silently empty — only the inline `element` array was read).
    #[test]
    fn spdx3_graph_envelope_is_not_empty() {
        let doc = r#"{
          "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
          "@graph": [
            {"type": "SpdxDocument", "spdxId": "urn:doc", "name": "d",
             "rootElement": ["urn:app"], "element": ["urn:app", "urn:lib", "urn:rel"]},
            {"type": "software_Package", "spdxId": "urn:app", "name": "app",
             "software_packageUrl": "pkg:npm/app@1.0"},
            {"type": "software_Package", "spdxId": "urn:lib", "name": "lib",
             "software_packageUrl": "pkg:npm/lib@1.0"},
            {"type": "Relationship", "spdxId": "urn:rel",
             "relationshipType": "dependsOn", "from": "urn:app", "to": ["urn:lib"]}
          ]
        }"#;
        let sbom = Spdx3Parser::new().parse_str(doc).expect("parse");
        assert_eq!(sbom.component_count(), 2, "@graph elements must be parsed");
        assert!(edge_between(&sbom, "app", "lib"));
        // Document metadata and the primary component are lifted from the
        // in-@graph SpdxDocument node (CRA compliance keys on the primary).
        assert_eq!(sbom.document.name.as_deref(), Some("d"));
        assert_eq!(
            sbom.primary_component().map(|c| c.name.as_str()),
            Some("app"),
            "rootElement must designate the primary component in @graph mode"
        );
    }

    /// An AFFECTS relationship with a duplicated `to` target must attach the
    /// vuln once (dedup, bounding the memory-amplification fan-out).
    #[test]
    fn spdx3_affects_dedups_duplicate_targets() {
        let sbom = spdx3_lib(
            r#"{"type": "Relationship", "spdxId": "urn:rel:affects",
                "relationshipType": "AFFECTS", "from": "urn:vuln:cve",
                "to": ["urn:pkg:lib", "urn:pkg:lib", "urn:pkg:lib"]}"#,
        );
        assert_eq!(
            spdx3_component(&sbom, "lib").vulnerabilities.len(),
            1,
            "duplicated AFFECTS targets must dedup, not attach N times"
        );
    }

    /// An unknown VEX justification must yield None, never fabricate the
    /// strong VulnerableCodeNotPresent not-affected claim.
    #[test]
    fn spdx3_unknown_vex_justification_is_none() {
        let sbom = spdx3_lib(
            r#"{"type": "security_VexNotAffectedVulnAssessmentRelationship",
                "spdxId": "urn:assess:vex", "from": "urn:vuln:cve",
                "assessedElement": "urn:pkg:lib",
                "security_justificationType": "totally_made_up"}"#,
        );
        if let Some(vex) = &spdx3_component(&sbom, "lib").vex_status {
            assert_eq!(
                vex.justification, None,
                "unknown justification must not fabricate a strong claim"
            );
        }
    }

    /// The plain AFFECTS relationship that attaches CVE-2025-9999 to lib.
    const AFFECTS: &str = r#"{"type": "Relationship", "spdxId": "urn:rel:affects",
        "relationshipType": "AFFECTS", "from": "urn:vuln:cve", "to": ["urn:pkg:lib"]}"#;

    /// The VEX states of lib's records, in order.
    fn vex_states(sbom: &NormalizedSbom) -> Vec<Option<VexState>> {
        spdx3_component(sbom, "lib")
            .vulnerabilities
            .iter()
            .map(|v| v.vex_status.as_ref().map(|s| s.status.clone()))
            .collect()
    }

    /// An AFFECTS relationship and an `affected` assessment of one
    /// vulnerability and one component agree, so they are one record: the
    /// vulnerability the relationship attaches, with the assessment's VEX
    /// status. They were two, and every per-vulnerability finding counted
    /// the vulnerability twice. Document order does not matter.
    #[test]
    fn spdx3_affects_and_affected_assessment_attach_one_record() {
        let assessment = r#"{"type": "security_VexAffectedVulnAssessmentRelationship",
            "spdxId": "urn:assess:vex", "from": "urn:vuln:cve",
            "assessedElement": "urn:pkg:lib", "actionStatement": "Upgrade to 2.0",
            "impactStatement": "remote code execution", "statusNotes": "triaged"}"#;
        for elements in [
            format!("{AFFECTS}, {assessment}"),
            format!("{assessment}, {AFFECTS}"),
        ] {
            let sbom = spdx3_lib(&elements);
            let lib = spdx3_component(&sbom, "lib");
            assert_eq!(
                lib.vulnerabilities.len(),
                1,
                "one record per vulnerability and component: {:?}",
                lib.vulnerabilities
            );
            let record = &lib.vulnerabilities[0];
            assert_eq!(record.id, "CVE-2025-9999");
            assert_eq!(record.description.as_deref(), Some("boom"));
            let vex = record.vex_status.as_ref().expect("the assessment's VEX");
            assert_eq!(vex.status, VexState::Affected);
            assert_eq!(vex.action_statement.as_deref(), Some("Upgrade to 2.0"));
            assert_eq!(
                vex.impact_statement.as_deref(),
                Some("remote code execution")
            );
            assert_eq!(vex.detail.as_deref(), Some("triaged"));
            assert_eq!(vex.responses, [VexResponse::Update]);
        }
    }

    /// An AFFECTS relationship and a `not_affected` assessment of another
    /// element contradict each other, so each keeps its record: merging
    /// would close the vulnerability on the assessment's word alone. The
    /// AFFECTS record gets no VEX status: `affected` decides agreement and
    /// is not written out.
    #[test]
    fn spdx3_affects_and_not_affected_assessment_keep_two_records() {
        let sbom = spdx3_lib(&format!(
            r#"{AFFECTS},
               {{"type": "security_VexNotAffectedVulnAssessmentRelationship",
                "spdxId": "urn:assess:vex", "from": "urn:vuln:cve",
                "assessedElement": "urn:pkg:lib",
                "justification": "vulnerable_code_not_in_execute_path",
                "impactStatement": "not reachable", "statusNotes": "audited"}}"#
        ));
        assert_eq!(vex_states(&sbom), [None, Some(VexState::NotAffected)]);
        let lib = spdx3_component(&sbom, "lib");
        let vex = lib.vulnerabilities[1].vex_status.as_ref().expect("VEX");
        assert_eq!(
            vex.justification,
            Some(VexJustification::VulnerableCodeNotInExecutePath)
        );
        assert_eq!(vex.impact_statement.as_deref(), Some("not reachable"));
        assert_eq!(vex.detail.as_deref(), Some("audited"));
        assert_eq!(
            lib.vex_status.as_ref().map(|v| &v.status),
            Some(&VexState::NotAffected)
        );
    }

    /// AFFECTS claims `affected` and FIXED_IN `fixed`: one vulnerability and
    /// component named by both keep a record each, in either order.
    #[test]
    fn spdx3_affects_and_fixed_in_keep_two_records() {
        let fixed_in = r#"{"type": "Relationship", "spdxId": "urn:rel:fixed",
            "relationshipType": "fixedIn", "from": "urn:vuln:cve", "to": ["urn:pkg:lib"]}"#;
        assert_eq!(
            vex_states(&spdx3_lib(&format!("{AFFECTS}, {fixed_in}"))),
            [None, Some(VexState::Fixed)]
        );
        assert_eq!(
            vex_states(&spdx3_lib(&format!("{fixed_in}, {AFFECTS}"))),
            [Some(VexState::Fixed), None]
        );
    }

    /// A relationship and an assessment that are one element (one `spdxId`
    /// met through two paths) are one statement and one record, although
    /// AFFECTS's `affected` and the assessment's `not_affected` would not
    /// agree as two elements.
    #[test]
    fn spdx3_one_element_met_twice_is_one_record() {
        let sbom = spdx3_lib(&format!(
            r#"{AFFECTS},
               {{"type": "security_VexNotAffectedVulnAssessmentRelationship",
                "spdxId": "urn:rel:affects", "from": "urn:vuln:cve",
                "assessedElement": "urn:pkg:lib",
                "justification": "component_not_present"}}"#
        ));
        assert_eq!(vex_states(&sbom), [Some(VexState::NotAffected)]);
    }

    /// A CVSS assessment claims no VEX state, so it joins the record of a VEX
    /// statement about the same pair, whatever that statement claims.
    #[test]
    fn spdx3_score_joins_the_vex_record() {
        let sbom = spdx3_lib(
            r#"{"type": "security_CvssV3VulnAssessmentRelationship",
                "spdxId": "urn:assess:cvss", "from": "urn:vuln:cve",
                "assessedElement": "urn:pkg:lib", "score": 7.5},
               {"type": "security_VexNotAffectedVulnAssessmentRelationship",
                "spdxId": "urn:assess:vex", "from": "urn:vuln:cve",
                "assessedElement": "urn:pkg:lib",
                "justification": "component_not_present"}"#,
        );
        assert_eq!(vex_states(&sbom), [Some(VexState::NotAffected)]);
        let record = &spdx3_component(&sbom, "lib").vulnerabilities[0];
        assert_eq!(record.cvss.len(), 1, "{record:?}");
        assert_eq!(record.severity, Some(Severity::High));
    }

    /// Assessments that agree with the AFFECTS relationship add to its
    /// record: both CVSS scores (which claim no VEX state), the more severe
    /// severity, and the `affected` statement with its action.
    #[test]
    fn spdx3_assessments_of_one_pair_share_its_record() {
        let sbom = spdx3_lib(
            r#"{"type": "Relationship", "spdxId": "urn:rel:affects",
                "relationshipType": "AFFECTS", "from": "urn:vuln:cve", "to": ["urn:pkg:lib"]},
               {"type": "security_CvssV3VulnAssessmentRelationship",
                "spdxId": "urn:assess:v3", "from": "urn:vuln:cve",
                "assessedElement": "urn:pkg:lib", "score": 6.5,
                "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"},
               {"type": "security_CvssV4VulnAssessmentRelationship",
                "spdxId": "urn:assess:v4", "from": "urn:vuln:cve",
                "assessedElement": "urn:pkg:lib", "score": 9.3,
                "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
               {"type": "security_VexAffectedVulnAssessmentRelationship",
                "spdxId": "urn:assess:vex", "from": "urn:vuln:cve",
                "assessedElement": "urn:pkg:lib", "actionStatement": "Upgrade to 2.0"}"#,
        );
        let lib = spdx3_component(&sbom, "lib");
        assert_eq!(lib.vulnerabilities.len(), 1, "{:?}", lib.vulnerabilities);
        let record = &lib.vulnerabilities[0];
        let versions: Vec<&CvssVersion> = record.cvss.iter().map(|c| &c.version).collect();
        assert_eq!(versions, [&CvssVersion::V31, &CvssVersion::V4]);
        assert_eq!(record.severity, Some(Severity::Critical));
        let vex = record.vex_status.as_ref().expect("the assessment's VEX");
        assert_eq!(vex.status, VexState::Affected);
        assert_eq!(vex.action_statement.as_deref(), Some("Upgrade to 2.0"));
        assert_eq!(vex.responses, [VexResponse::Update]);
    }

    /// A FIXED_IN relationship and a VEX fixed assessment of one pair are one
    /// record that keeps the assessment's notes.
    #[test]
    fn spdx3_fixed_in_and_vex_fixed_attach_one_record() {
        let sbom = spdx3_lib(
            r#"{"type": "Relationship", "spdxId": "urn:rel:fixed",
                "relationshipType": "fixedIn", "from": "urn:vuln:cve", "to": ["urn:pkg:lib"]},
               {"type": "security_VexFixedVulnAssessmentRelationship",
                "spdxId": "urn:assess:vex", "from": "urn:vuln:cve",
                "assessedElement": "urn:pkg:lib", "statusNotes": "fixed in 1.0"}"#,
        );
        let lib = spdx3_component(&sbom, "lib");
        assert_eq!(lib.vulnerabilities.len(), 1, "{:?}", lib.vulnerabilities);
        let vex = lib.vulnerabilities[0].vex_status.as_ref().expect("VEX");
        assert_eq!(vex.status, VexState::Fixed);
        assert_eq!(vex.detail.as_deref(), Some("fixed in 1.0"));
    }

    /// Statements of one pair that contradict each other are not merged, so
    /// none is lost: AFFECTS (`affected`), an `under_investigation` and a
    /// `not_affected` assessment keep a record each, and the pair's score
    /// reaches all three.
    #[test]
    fn spdx3_contradicting_vex_statements_keep_a_record_each() {
        let sbom = spdx3_lib(&format!(
            r#"{AFFECTS},
               {{"type": "security_VexUnderInvestigationVulnAssessmentRelationship",
                "spdxId": "urn:assess:investigating", "from": "urn:vuln:cve",
                "assessedElement": "urn:pkg:lib"}},
               {{"type": "security_VexNotAffectedVulnAssessmentRelationship",
                "spdxId": "urn:assess:not-affected", "from": "urn:vuln:cve",
                "assessedElement": "urn:pkg:lib", "justification": "component_not_present"}},
               {{"type": "security_CvssV3VulnAssessmentRelationship",
                "spdxId": "urn:assess:cvss", "from": "urn:vuln:cve",
                "assessedElement": "urn:pkg:lib", "score": 7.5}}"#
        ));
        assert_eq!(
            vex_states(&sbom),
            [
                None,
                Some(VexState::UnderInvestigation),
                Some(VexState::NotAffected)
            ]
        );
        for record in &spdx3_component(&sbom, "lib").vulnerabilities {
            assert_eq!(record.id, "CVE-2025-9999");
            assert_eq!(record.cvss.len(), 1, "{record:?}");
            assert_eq!(record.severity, Some(Severity::High));
        }
    }

    /// Two Vulnerability elements with one CVE id are the document listing
    /// the vulnerability twice, and each keeps its record; a second AFFECTS
    /// relationship of one element adds none.
    #[test]
    fn spdx3_two_vulnerability_elements_with_one_id_keep_two_records() {
        let sbom = spdx3_lib(
            r#"{"type": "security_Vulnerability", "spdxId": "urn:vuln:cve-again",
                "name": "CVE-2025-9999"},
               {"type": "Relationship", "spdxId": "urn:rel:affects",
                "relationshipType": "AFFECTS", "from": "urn:vuln:cve", "to": ["urn:pkg:lib"]},
               {"type": "Relationship", "spdxId": "urn:rel:affects-repeated",
                "relationshipType": "AFFECTS", "from": "urn:vuln:cve", "to": ["urn:pkg:lib"]},
               {"type": "Relationship", "spdxId": "urn:rel:affects-again",
                "relationshipType": "AFFECTS", "from": "urn:vuln:cve-again",
                "to": ["urn:pkg:lib"]}"#,
        );
        let ids: Vec<&str> = spdx3_component(&sbom, "lib")
            .vulnerabilities
            .iter()
            .map(|v| v.id.as_str())
            .collect();
        assert_eq!(ids, ["CVE-2025-9999", "CVE-2025-9999"]);
    }

    #[test]
    fn test_spdx3_model_data_preprocessing_mapped() {
        let pkg: Spdx3Package = serde_json::from_str(
            r#"{
                "type": "ai_AIPackage",
                "spdxId": "urn:x:m",
                "name": "model",
                "ai_modelDataPreprocessing": ["tokenize", "truncate"]
            }"#,
        )
        .expect("ai package should deserialize");
        let converter = Spdx3Parser::new();
        let comp = converter.convert_package(&pkg, PackageKind::AiModel, &HashMap::new());
        let ml = comp.ml_model.expect("ml model info present");
        assert_eq!(ml.data_preprocessing, vec!["tokenize", "truncate"]);
    }

    #[test]
    fn test_spdx3_training_energy_kwh_sum_and_units() {
        // Only training entries count; unknown units are skipped; megajoule converts.
        let ec: Spdx3EnergyConsumption = serde_json::from_str(
            r#"{
                "ai_trainingEnergyConsumption": [
                    {"ai_energyQuantity": "100", "ai_energyUnit": "kilowattHour"},
                    {"ai_energyQuantity": 3.6, "ai_energyUnit": "megajoule"}
                ],
                "ai_inferenceEnergyConsumption": [
                    {"ai_energyQuantity": 999, "ai_energyUnit": "kilowattHour"}
                ]
            }"#,
        )
        .expect("energy consumption should deserialize");
        // 100 kWh + (3.6 MJ -> 1.0 kWh) = 101.0; inference is excluded; the
        // string quantity "100" parses.
        let total = ec.training_energy_kwh().expect("training energy");
        assert!((total - 101.0).abs() < 1e-9, "got {total}");
    }

    /// The verbatim minimal reproducer from issue #305: canonical SPDX 3.0.1
    /// @graph serialization with string creationInfo refs, a standalone
    /// CreationInfo node, a software_Sbom container between document and
    /// package, and software_-prefixed property names. Must parse to one
    /// component with full document metadata (was: 0 components in v0.1.22,
    /// hard serde error after the first @graph fix).
    #[test]
    fn spdx3_issue_305_canonical_reproducer_parses() {
        let doc = r#"{
          "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
          "@graph": [
            { "type": "CreationInfo", "@id": "_:ci", "specVersion": "3.0.1",
              "created": "2026-07-10T15:23:05Z",
              "createdBy": ["urn:example:creator"], "createdUsing": ["urn:example:tool"] },
            { "type": "Organization", "spdxId": "urn:example:creator",
              "creationInfo": "_:ci", "name": "Example Org" },
            { "type": "Tool", "spdxId": "urn:example:tool",
              "creationInfo": "_:ci", "name": "ExampleTool" },
            { "type": "SpdxDocument", "spdxId": "urn:example:document",
              "creationInfo": "_:ci", "name": "example",
              "profileConformance": ["core", "software", "simpleLicensing"],
              "dataLicense": "urn:example:license-cc0",
              "rootElement": ["urn:example:sbom"] },
            { "type": "simplelicensing_LicenseExpression",
              "spdxId": "urn:example:license-cc0", "creationInfo": "_:ci",
              "simplelicensing_licenseExpression": "CC0-1.0" },
            { "type": "software_Sbom", "spdxId": "urn:example:sbom",
              "creationInfo": "_:ci", "rootElement": ["urn:example:package"],
              "software_sbomType": ["source"] },
            { "type": "software_Package", "spdxId": "urn:example:package",
              "creationInfo": "_:ci", "name": "example-package",
              "software_packageVersion": "1.0.0",
              "software_primaryPurpose": "source" }
          ]
        }"#;
        let sbom = Spdx3Parser::new()
            .parse_str(doc)
            .expect("canonical SPDX 3.0.1 JSON-LD must parse");

        assert_eq!(sbom.component_count(), 1, "the software_Package must parse");
        let pkg = spdx3_component(&sbom, "example-package");
        assert_eq!(pkg.version.as_deref(), Some("1.0.0"));

        assert_eq!(sbom.document.name.as_deref(), Some("example"));
        assert_eq!(sbom.document.spec_version, "3.0.1");
        assert_eq!(
            sbom.document.created,
            DateTime::parse_from_rfc3339("2026-07-10T15:23:05Z")
                .expect("valid RFC3339")
                .with_timezone(&Utc)
        );
        assert!(
            sbom.document
                .creators
                .iter()
                .any(|c| matches!(c.creator_type, CreatorType::Organization)
                    && c.name == "Example Org"),
            "createdBy must resolve through the CreationInfo node to the \
             Organization agent, got {:?}",
            sbom.document.creators
        );
        assert!(
            sbom.document
                .creators
                .iter()
                .any(|c| matches!(c.creator_type, CreatorType::Tool) && c.name == "ExampleTool"),
            "createdUsing must resolve to the Tool agent, got {:?}",
            sbom.document.creators
        );
        assert_eq!(
            sbom.primary_component().map(|c| c.name.as_str()),
            Some("example-package"),
            "rootElement must resolve through the software_Sbom container"
        );
        assert_eq!(
            sbom.document.distribution_classification.as_deref(),
            Some("core, software, simpleLicensing"),
            "profileConformance must lift from the @graph SpdxDocument node"
        );
        let ext = sbom
            .extensions
            .spdx
            .as_ref()
            .expect("spdx extensions present");
        assert_eq!(
            ext.get("dataLicense").and_then(|v| v.as_str()),
            Some("CC0-1.0"),
            "dataLicense IRI ref must resolve through the LicenseExpression element"
        );
    }

    /// A bare single-element document (no @graph, no element array) is
    /// valid per the official 3.0.1 JSON schema's else-branch (e.g. the
    /// spdx-3-model person1/tool1 examples) and must parse to that element
    /// on both the string and reader paths.
    #[test]
    fn spdx3_bare_single_element_document_parses() {
        let doc = r#"{
          "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
          "type": "software_Package", "spdxId": "urn:pkg", "name": "solo",
          "software_packageVersion": "3.2.1",
          "creationInfo": {"specVersion": "3.0.1", "created": "2026-01-01T00:00:00Z"}
        }"#;
        let sbom = Spdx3Parser::new()
            .parse_str(doc)
            .expect("bare element must parse");
        assert_eq!(sbom.component_count(), 1);
        let pkg = spdx3_component(&sbom, "solo");
        assert_eq!(pkg.version.as_deref(), Some("3.2.1"));

        let sbom2 = Spdx3Parser::new()
            .parse_json_reader(doc.as_bytes())
            .expect("reader path must parse the bare element too");
        assert_eq!(sbom2.component_count(), 1);
    }

    /// The other schema-valid creationInfo form — an inline object (the
    /// 3.0.1 schema's CreationInfo_derived is anyOf [object, ref]) — must
    /// keep working alongside the string-ref form.
    #[test]
    fn spdx3_creation_info_inline_object_form_parses() {
        let doc = r#"{
          "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
          "@graph": [
            {"type": "Organization", "spdxId": "urn:org", "name": "Acme"},
            {"type": "SpdxDocument", "spdxId": "urn:doc", "name": "d",
             "creationInfo": {"specVersion": "3.0.1",
               "created": "2026-01-01T00:00:00Z", "createdBy": ["urn:org"]},
             "rootElement": ["urn:pkg"]},
            {"type": "software_Package", "spdxId": "urn:pkg", "name": "p",
             "creationInfo": {"specVersion": "3.0.1", "created": "2026-01-01T00:00:00Z"}}
          ]
        }"#;
        let sbom = Spdx3Parser::new().parse_str(doc).expect("parse");
        assert_eq!(sbom.component_count(), 1);
        assert_eq!(sbom.document.spec_version, "3.0.1");
        assert!(
            sbom.document
                .creators
                .iter()
                .any(|c| matches!(c.creator_type, CreatorType::Organization) && c.name == "Acme"),
            "inline creationInfo createdBy must resolve, got {:?}",
            sbom.document.creators
        );
    }

    /// Creator kinds come from the element variant (Person / Organization /
    /// Tool / SoftwareAgent): serde's internally-tagged enum consumes the
    /// `type` key, so the old tag-field approach classified every agent as
    /// a Tool — has_org_creator could never pass for SPDX 3.0 documents.
    #[test]
    fn spdx3_agent_kinds_resolved_from_variant() {
        let doc = r#"{
          "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
          "@graph": [
            {"type": "CreationInfo", "@id": "_:ci", "specVersion": "3.0.1",
             "created": "2026-01-01T00:00:00Z",
             "createdBy": ["urn:alice", "urn:acme"], "createdUsing": ["urn:tool"]},
            {"type": "Person", "spdxId": "urn:alice", "creationInfo": "_:ci", "name": "Alice"},
            {"type": "Organization", "spdxId": "urn:acme", "creationInfo": "_:ci", "name": "Acme"},
            {"type": "Tool", "spdxId": "urn:tool", "creationInfo": "_:ci", "name": "maker"},
            {"type": "SpdxDocument", "spdxId": "urn:doc", "creationInfo": "_:ci", "name": "d"}
          ]
        }"#;
        let sbom = Spdx3Parser::new().parse_str(doc).expect("parse");
        let kind_of = |name: &str| {
            sbom.document
                .creators
                .iter()
                .find(|c| c.name == name)
                .map(|c| c.creator_type.clone())
                .unwrap_or_else(|| panic!("creator {name} missing: {:?}", sbom.document.creators))
        };
        assert!(matches!(kind_of("Alice"), CreatorType::Person));
        assert!(matches!(kind_of("Acme"), CreatorType::Organization));
        assert!(matches!(kind_of("maker"), CreatorType::Tool));
    }

    /// Canonical software_-prefixed property names must map like their
    /// unprefixed counterparts (the JSON-LD @context defines the prefixed
    /// forms; official examples use them exclusively).
    #[test]
    fn spdx3_prefixed_software_properties_accepted() {
        let doc = r#"{
          "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
          "type": "SpdxDocument", "spdxId": "urn:doc",
          "element": [
            {"type": "software_Package", "spdxId": "urn:pkg", "name": "p",
             "software_packageVersion": "2.1.0",
             "software_packageUrl": "pkg:cargo/p@2.1.0",
             "software_copyrightText": "(c) Example",
             "software_primaryPurpose": "library"}
          ]
        }"#;
        let sbom = Spdx3Parser::new().parse_str(doc).expect("parse");
        let pkg = spdx3_component(&sbom, "p");
        assert_eq!(pkg.version.as_deref(), Some("2.1.0"));
        assert_eq!(pkg.identifiers.purl.as_deref(), Some("pkg:cargo/p@2.1.0"));
        assert_eq!(pkg.copyright.as_deref(), Some("(c) Example"));
        assert!(matches!(pkg.component_type, ComponentType::Library));
    }

    /// The simplelicensing_-prefixed license expression key must resolve
    /// through hasDeclaredLicense (was silently dropped, losing the license).
    #[test]
    fn spdx3_prefixed_license_expression_resolves() {
        let doc = r#"{
          "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
          "type": "SpdxDocument", "spdxId": "urn:doc",
          "element": [
            {"type": "software_Package", "spdxId": "urn:pkg", "name": "p"},
            {"type": "simplelicensing_LicenseExpression", "spdxId": "urn:lic",
             "simplelicensing_licenseExpression": "MIT"},
            {"type": "Relationship", "spdxId": "urn:rel",
             "relationshipType": "hasDeclaredLicense",
             "from": "urn:pkg", "to": ["urn:lic"]}
          ]
        }"#;
        let sbom = Spdx3Parser::new().parse_str(doc).expect("parse");
        let pkg = spdx3_component(&sbom, "p");
        assert!(
            pkg.licenses.declared.iter().any(|l| l.expression == "MIT"),
            "prefixed license expression must resolve, got {:?}",
            pkg.licenses.declared
        );
    }

    /// Document metadata must resolve when the graph has a single
    /// CreationInfo node but nothing references it resolvably (here: no
    /// SpdxDocument node at all) — pins the single-node fallback in
    /// convert_metadata.
    #[test]
    fn spdx3_single_creation_info_fallback_resolves_metadata() {
        let doc = r#"{
          "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
          "@graph": [
            {"type": "CreationInfo", "@id": "_:ci", "specVersion": "3.0.1",
             "created": "2026-02-02T00:00:00Z", "createdBy": ["urn:org"]},
            {"type": "Organization", "spdxId": "urn:org", "creationInfo": "_:ci", "name": "Acme"},
            {"type": "software_Package", "spdxId": "urn:pkg", "creationInfo": "_:ci", "name": "p"}
          ]
        }"#;
        let sbom = Spdx3Parser::new().parse_str(doc).expect("parse");
        assert_eq!(sbom.document.spec_version, "3.0.1");
        assert!(
            sbom.document
                .creators
                .iter()
                .any(|c| matches!(c.creator_type, CreatorType::Organization) && c.name == "Acme"),
            "the lone CreationInfo node must supply document metadata, got {:?}",
            sbom.document.creators
        );
    }

    /// Primary-component resolution must chase through a Bundle exactly
    /// like a Bom/software_Sbom (pins the Bundle half of the or-pattern).
    #[test]
    fn spdx3_bundle_rootelement_indirection_sets_primary() {
        let doc = r#"{
          "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
          "@graph": [
            {"type": "SpdxDocument", "spdxId": "urn:doc", "name": "d",
             "rootElement": ["urn:bundle"]},
            {"type": "Bundle", "spdxId": "urn:bundle", "rootElement": ["urn:pkg"]},
            {"type": "software_Package", "spdxId": "urn:pkg", "name": "p"}
          ]
        }"#;
        let sbom = Spdx3Parser::new().parse_str(doc).expect("parse");
        assert_eq!(
            sbom.primary_component().map(|c| c.name.as_str()),
            Some("p"),
            "rootElement must resolve through the Bundle"
        );
    }

    /// Canonical software_byteRange/lineRange are PositiveIntegerRange
    /// OBJECTS; they must normalize to the compact "begin:end" form and
    /// must never hard-fail the document (an alias binding them to a plain
    /// string field did exactly that).
    #[test]
    fn spdx3_canonical_snippet_ranges_accepted() {
        let doc = r#"{
          "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
          "type": "SpdxDocument", "spdxId": "urn:doc",
          "element": [
            {"type": "software_Snippet", "spdxId": "urn:snip", "name": "s",
             "software_byteRange": {"beginIntegerRange": 310, "endIntegerRange": 420},
             "software_lineRange": {"beginIntegerRange": 5, "endIntegerRange": 23}}
          ]
        }"#;
        let sbom = Spdx3Parser::new()
            .parse_str(doc)
            .expect("canonical range objects must not fail the parse");
        let snip = spdx3_component(&sbom, "s");
        let desc = snip.description.as_deref().unwrap_or_default();
        assert!(
            desc.contains("310:420") && desc.contains("5:23"),
            "ranges must normalize to begin:end, got {desc:?}"
        );
    }

    /// Canonical security_-prefixed assessment payloads must be extracted:
    /// the type-tag aliases already routed these variants, but every payload
    /// field deserialized as None — CVSS scores silently vanished.
    #[test]
    fn spdx3_canonical_security_assessment_fields_extracted() {
        let sbom = spdx3_lib(
            r#"{"type": "security_CvssV3VulnAssessmentRelationship",
                "spdxId": "urn:assess:cvss", "from": "urn:vuln:cve",
                "security_assessedElement": "urn:pkg:lib",
                "security_score": 9.8, "security_severity": "critical",
                "security_vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}"#,
        );
        let lib = spdx3_component(&sbom, "lib");
        let vuln = lib.vulnerabilities.first().expect("vulnerability attached");
        let cvss = vuln.cvss.first().expect("canonical CVSS payload extracted");
        assert!(
            (cvss.base_score - 9.8_f32).abs() < 1e-4,
            "got {}",
            cvss.base_score
        );
        assert!(matches!(cvss.version, CvssVersion::V31));
    }

    /// The 46 terms of SPDX 3.0.1 `Core/ExternalRefType`
    /// (spdx.org/rdf/3.0.1/terms/Core/ExternalRefType) with the variant
    /// each maps to; `None` keeps the term in `Other`.
    const SPDX3_EXTERNAL_REF_TYPES: &[(&str, Option<ExternalRefType>)] = &[
        ("altDownloadLocation", None),
        ("altWebPage", None),
        ("binaryArtifact", None),
        ("bower", None),
        ("buildMeta", Some(ExternalRefType::BuildMeta)),
        ("buildSystem", Some(ExternalRefType::BuildSystem)),
        ("certificationReport", Some(ExternalRefType::Certification)),
        ("chat", Some(ExternalRefType::Chat)),
        (
            "componentAnalysisReport",
            Some(ExternalRefType::ComponentAnalysis),
        ),
        ("cwe", None),
        ("documentation", Some(ExternalRefType::Documentation)),
        (
            "dynamicAnalysisReport",
            Some(ExternalRefType::DynamicAnalysis),
        ),
        ("eolNotice", None),
        ("exportControlAssessment", None),
        ("funding", None),
        ("issueTracker", Some(ExternalRefType::IssueTracker)),
        ("license", Some(ExternalRefType::License)),
        ("mailingList", Some(ExternalRefType::MailingList)),
        ("mavenCentral", None),
        ("metrics", Some(ExternalRefType::QualityMetrics)),
        ("npm", None),
        ("nuget", None),
        ("other", None),
        ("privacyAssessment", None),
        ("productMetadata", None),
        ("purchaseOrder", None),
        (
            "qualityAssessmentReport",
            Some(ExternalRefType::QualityMetrics),
        ),
        ("releaseHistory", None),
        ("releaseNotes", Some(ExternalRefType::ReleaseNotes)),
        ("riskAssessment", Some(ExternalRefType::RiskAssessment)),
        (
            "runtimeAnalysisReport",
            Some(ExternalRefType::RuntimeAnalysis),
        ),
        (
            "secureSoftwareAttestation",
            Some(ExternalRefType::Attestation),
        ),
        (
            "securityAdversaryModel",
            Some(ExternalRefType::AdversaryModel),
        ),
        ("securityAdvisory", Some(ExternalRefType::Advisories)),
        ("securityFix", None),
        ("securityOther", None),
        ("securityPenTestReport", Some(ExternalRefType::Pentest)),
        ("securityPolicy", Some(ExternalRefType::SecurityContact)),
        ("securityThreatModel", Some(ExternalRefType::ThreatModel)),
        ("socialMedia", Some(ExternalRefType::Social)),
        ("sourceArtifact", None),
        (
            "staticAnalysisReport",
            Some(ExternalRefType::StaticAnalysis),
        ),
        ("support", Some(ExternalRefType::Support)),
        ("vcs", Some(ExternalRefType::Vcs)),
        (
            "vulnerabilityDisclosureReport",
            Some(ExternalRefType::VulnerabilityAssertion),
        ),
        (
            "vulnerabilityExploitabilityAssessment",
            Some(ExternalRefType::ExploitabilityStatement),
        ),
    ];

    /// Every SPDX 3.0.1 external-reference term maps to its CycloneDX
    /// counterpart or stays `Other` with the term as written; the compact
    /// term, the vocabulary IRI and any letter case read alike.
    #[test]
    fn every_spdx3_external_ref_type_maps_or_stays_other() {
        assert_eq!(
            SPDX3_EXTERNAL_REF_TYPES.len(),
            46,
            "SPDX 3.0.1 has 46 terms"
        );
        for (term, expected) in SPDX3_EXTERNAL_REF_TYPES {
            let expected = expected
                .clone()
                .unwrap_or_else(|| ExternalRefType::Other((*term).to_string()));
            let iri = format!("https://spdx.org/rdf/3.0.1/terms/Core/ExternalRefType/{term}");
            assert_eq!(map_spdx3_external_ref_type(term), expected, "{term}");
            assert_eq!(map_spdx3_external_ref_type(&iri), expected, "{iri}");
            if !matches!(expected, ExternalRefType::Other(_)) {
                assert_eq!(
                    map_spdx3_external_ref_type(&term.to_ascii_uppercase()),
                    expected,
                    "{term} in upper case"
                );
            }
        }
    }

    /// The SPDX 3.0 evidence references reach the component model, one
    /// reference per locator.
    #[test]
    fn spdx3_evidence_external_refs_reach_the_component() {
        let sbom = spdx3_lib(
            r#"{"type": "software_Package", "spdxId": "urn:pkg:app", "name": "app",
               "software_packageUrl": "pkg:npm/app@1.0",
               "externalRef": [
                 {"externalRefType": "certificationReport",
                  "locator": ["https://certs.example/eucc/app-1.0.pdf"]},
                 {"externalRefType": "riskAssessment",
                  "locator": ["https://acme.example/ra.pdf"]},
                 {"externalRefType": "secureSoftwareAttestation",
                  "locator": ["https://acme.example/attestation.pdf"]},
                 {"externalRefType": "vulnerabilityDisclosureReport",
                  "locator": ["https://acme.example/vdr.json"]},
                 {"externalRefType": "vulnerabilityExploitabilityAssessment",
                  "locator": ["https://acme.example/vex-1.json", "https://acme.example/vex-2.json"]},
                 {"externalRefType": "buildSystem",
                  "locator": ["https://ci.acme.example/app"]}
               ]}"#,
        );
        let refs: Vec<(ExternalRefType, &str)> = spdx3_component(&sbom, "app")
            .external_refs
            .iter()
            .map(|r| (r.ref_type.clone(), r.url.as_str()))
            .collect();
        assert_eq!(
            refs,
            vec![
                (
                    ExternalRefType::Certification,
                    "https://certs.example/eucc/app-1.0.pdf"
                ),
                (
                    ExternalRefType::RiskAssessment,
                    "https://acme.example/ra.pdf"
                ),
                (
                    ExternalRefType::Attestation,
                    "https://acme.example/attestation.pdf"
                ),
                (
                    ExternalRefType::VulnerabilityAssertion,
                    "https://acme.example/vdr.json"
                ),
                (
                    ExternalRefType::ExploitabilityStatement,
                    "https://acme.example/vex-1.json"
                ),
                (
                    ExternalRefType::ExploitabilityStatement,
                    "https://acme.example/vex-2.json"
                ),
                (ExternalRefType::BuildSystem, "https://ci.acme.example/app"),
            ]
        );
    }

    /// Guard against alias typos routing Sbom containers to Unknown (the
    /// same class of bug test_spdx3_ai_dataset_type_tags_deserialize guards
    /// for AI/Dataset packages).
    #[test]
    fn spdx3_sbom_container_type_tags_deserialize() {
        for tag in ["software_Sbom", "Sbom", "Bom"] {
            let el: Spdx3Element = serde_json::from_str(&format!(
                r#"{{"type": "{tag}", "spdxId": "urn:x:bom", "rootElement": ["urn:p"]}}"#
            ))
            .unwrap_or_else(|e| panic!("{tag} should deserialize: {e}"));
            assert!(
                matches!(el, Spdx3Element::Bom(_)),
                "tag {tag} must map to the Bom collection variant"
            );
        }
    }

    /// A signature entry whose hashValue is empty carries no signature
    /// value, as an empty CycloneDX JSF `value` or XML-DSig
    /// `<SignatureValue>` does not: the rule-matrix format axis found CISA
    /// 2026 accepting the empty SPDX 3 value as signature evidence.
    #[test]
    fn spdx3_empty_signature_value_is_no_value() {
        let signature = |value: &str| {
            let doc = format!(
                r#"{{
                  "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
                  "type": "SpdxDocument", "spdxId": "urn:doc",
                  "verifiedUsing": [
                    {{"type": "signature", "algorithm": "ES256", "hashValue": "{value}"}}
                  ],
                  "element": []
                }}"#
            );
            Spdx3Parser::new()
                .parse_str(&doc)
                .expect("parse")
                .document
                .signature
                .expect("a signature entry")
        };
        assert!(signature("c2lnbmF0dXJl").has_value);
        let empty = signature("");
        assert_eq!(empty.algorithm, "ES256");
        assert!(!empty.has_value, "an empty hashValue is no signature value");
    }

    /// The canonical SPDX 3.0.1 metric is a DictionaryEntry whose `type` is
    /// the class name: the metric is its `key`, as in the compact
    /// `{ key, value }` form (found by the rule-matrix format axis, whose
    /// SPDX 3 renderer writes the canonical form).
    #[test]
    fn spdx3_dictionary_entry_metric_is_named_by_its_key() {
        for metric in [
            r#"{"type": "DictionaryEntry", "key": "accuracy", "value": "0.94"}"#,
            r#"{"key": "accuracy", "value": "0.94"}"#,
            r#"{"ai_name": "accuracy", "ai_value": "0.94"}"#,
        ] {
            let entry = spdx3_metric_to_entry(serde_json::from_str(metric).expect("JSON"));
            assert_eq!(entry.metric_type.as_deref(), Some("accuracy"), "{metric}");
            assert_eq!(entry.value.as_deref(), Some("0.94"), "{metric}");
        }
        // A bare `type` still names the metric when no key does.
        let typed = spdx3_metric_to_entry(serde_json::json!({ "type": "F1", "value": 0.9 }));
        assert_eq!(typed.metric_type.as_deref(), Some("F1"));
    }
}
