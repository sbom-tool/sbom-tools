//! SPDX SBOM parser.
//!
//! Supports SPDX versions 2.2 and 2.3 in JSON, tag-value, and RDF/XML formats.

use crate::model::{
    CanonicalId, Component, ComponentType, Creator, CreatorType, DependencyEdge, DependencyType,
    DocumentMetadata, ExternalRefType, ExternalReference, Hash, HashAlgorithm, LicenseExpression,
    NormalizedSbom, Organization, SbomFormat,
};
use crate::parsers::traits::{ParseError, SbomParser};
use chrono::{DateTime, Utc};
use quick_xml::events::Event;
use quick_xml::Reader;
use serde::Deserialize;
use std::collections::HashMap;

/// Parser for SPDX SBOM format
#[allow(dead_code)]
pub struct SpdxParser {
    /// Whether to validate strictly
    strict: bool,
}

impl SpdxParser {
    /// Create a new SPDX parser
    pub fn new() -> Self {
        Self { strict: false }
    }

    /// Create a strict parser
    pub fn strict() -> Self {
        Self { strict: true }
    }

    /// Parse SPDX JSON format
    fn parse_json(&self, content: &str) -> Result<NormalizedSbom, ParseError> {
        let spdx: SpdxDocument =
            serde_json::from_str(content).map_err(|e| ParseError::JsonError(e.to_string()))?;

        self.convert_to_normalized(spdx)
    }

    /// Parse an SPDX document from a JSON reader (streaming - doesn't buffer entire file)
    pub fn parse_json_reader<R: std::io::Read>(
        &self,
        reader: R,
    ) -> Result<NormalizedSbom, ParseError> {
        let spdx: SpdxDocument =
            serde_json::from_reader(reader).map_err(|e| ParseError::JsonError(e.to_string()))?;

        self.convert_to_normalized(spdx)
    }

    /// Parse SPDX tag-value format
    fn parse_tag_value(&self, content: &str) -> Result<NormalizedSbom, ParseError> {
        let spdx = self.parse_tag_value_format(content)?;
        self.convert_to_normalized(spdx)
    }

    /// Parse tag-value format into SpdxDocument
    fn parse_tag_value_format(&self, content: &str) -> Result<SpdxDocument, ParseError> {
        let mut doc = SpdxDocument {
            spdx_version: String::new(),
            spdx_id: String::new(),
            name: String::new(),
            data_license: String::new(),
            document_namespace: None,
            creation_info: None,
            packages: Some(Vec::new()),
            relationships: Some(Vec::new()),
            external_document_refs: None,
        };

        let mut current_package: Option<SpdxPackage> = None;
        let mut packages = Vec::new();
        let mut relationships = Vec::new();
        let mut creation_info = SpdxCreationInfo {
            created: None,
            creators: Vec::new(),
            license_list_version: None,
            comment: None,
        };

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim();
                let value = value.trim();

                match key {
                    "SPDXVersion" => doc.spdx_version = value.to_string(),
                    "SPDXID" if current_package.is_some() => {
                        if let Some(ref mut pkg) = current_package {
                            pkg.spdx_id = value.to_string();
                        }
                    }
                    "SPDXID" => doc.spdx_id = value.to_string(),
                    "DocumentName" => doc.name = value.to_string(),
                    "DataLicense" => doc.data_license = value.to_string(),
                    "DocumentNamespace" => doc.document_namespace = Some(value.to_string()),
                    "Creator" => creation_info.creators.push(value.to_string()),
                    "Created" => creation_info.created = Some(value.to_string()),
                    "LicenseListVersion" => {
                        creation_info.license_list_version = Some(value.to_string())
                    }
                    "PackageName" => {
                        // Save previous package
                        if let Some(pkg) = current_package.take() {
                            packages.push(pkg);
                        }
                        current_package = Some(SpdxPackage {
                            spdx_id: String::new(),
                            name: value.to_string(),
                            version_info: None,
                            download_location: None,
                            files_analyzed: None,
                            license_concluded: None,
                            license_declared: None,
                            copyright_text: None,
                            supplier: None,
                            originator: None,
                            checksums: None,
                            external_refs: None,
                            description: None,
                        });
                    }
                    "PackageVersion" => {
                        if let Some(ref mut pkg) = current_package {
                            pkg.version_info = Some(value.to_string());
                        }
                    }
                    "PackageDownloadLocation" => {
                        if let Some(ref mut pkg) = current_package {
                            pkg.download_location = Some(value.to_string());
                        }
                    }
                    "PackageLicenseConcluded" => {
                        if let Some(ref mut pkg) = current_package {
                            pkg.license_concluded = Some(value.to_string());
                        }
                    }
                    "PackageLicenseDeclared" => {
                        if let Some(ref mut pkg) = current_package {
                            pkg.license_declared = Some(value.to_string());
                        }
                    }
                    "PackageCopyrightText" => {
                        if let Some(ref mut pkg) = current_package {
                            pkg.copyright_text = Some(value.to_string());
                        }
                    }
                    "PackageSupplier" => {
                        if let Some(ref mut pkg) = current_package {
                            pkg.supplier = Some(value.to_string());
                        }
                    }
                    "Relationship" => {
                        if let Some(rel) = self.parse_relationship_line(value) {
                            relationships.push(rel);
                        }
                    }
                    "ExternalRef" => {
                        if let Some(ref mut pkg) = current_package {
                            if let Some(ext_ref) = self.parse_external_ref_line(value) {
                                pkg.external_refs.get_or_insert_with(Vec::new).push(ext_ref);
                            }
                        }
                    }
                    "PackageChecksum" => {
                        if let Some(ref mut pkg) = current_package {
                            if let Some(checksum) = self.parse_checksum_line(value) {
                                pkg.checksums.get_or_insert_with(Vec::new).push(checksum);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Don't forget the last package
        if let Some(pkg) = current_package {
            packages.push(pkg);
        }

        doc.creation_info = Some(creation_info);
        doc.packages = Some(packages);
        doc.relationships = Some(relationships);

        Ok(doc)
    }

    /// Parse a relationship line from tag-value format
    fn parse_relationship_line(&self, value: &str) -> Option<SpdxRelationship> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() >= 3 {
            Some(SpdxRelationship {
                spdx_element_id: parts[0].to_string(),
                relationship_type: parts[1].to_string(),
                related_spdx_element: parts[2].to_string(),
            })
        } else {
            None
        }
    }

    /// Parse an external ref line from tag-value format
    fn parse_external_ref_line(&self, value: &str) -> Option<SpdxExternalRef> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() >= 3 {
            Some(SpdxExternalRef {
                reference_category: parts[0].to_string(),
                reference_type: parts[1].to_string(),
                reference_locator: parts[2].to_string(),
            })
        } else {
            None
        }
    }

    /// Parse a checksum line from tag-value format
    fn parse_checksum_line(&self, value: &str) -> Option<SpdxChecksum> {
        let parts: Vec<&str> = value.splitn(2, ':').collect();
        if parts.len() == 2 {
            Some(SpdxChecksum {
                algorithm: parts[0].trim().to_string(),
                checksum_value: parts[1].trim().to_string(),
            })
        } else {
            None
        }
    }

    /// Parse SPDX RDF/XML format
    fn parse_rdf_xml(&self, content: &str) -> Result<NormalizedSbom, ParseError> {
        let spdx = self.parse_rdf_xml_format(content)?;
        self.convert_to_normalized(spdx)
    }

    /// Parse RDF/XML format into SpdxDocument
    fn parse_rdf_xml_format(&self, content: &str) -> Result<SpdxDocument, ParseError> {
        let mut reader = Reader::from_str(content);
        reader.config_mut().trim_text(true);

        let mut doc = SpdxDocument {
            spdx_version: String::new(),
            spdx_id: String::new(),
            name: String::new(),
            data_license: String::new(),
            document_namespace: None,
            creation_info: None,
            packages: Some(Vec::new()),
            relationships: Some(Vec::new()),
            external_document_refs: None,
        };

        let mut packages: Vec<SpdxPackage> = Vec::new();
        let mut relationships: Vec<SpdxRelationship> = Vec::new();
        let mut creation_info = SpdxCreationInfo {
            created: None,
            creators: Vec::new(),
            license_list_version: None,
            comment: None,
        };

        // Current parsing context
        let mut current_package: Option<SpdxPackage> = None;
        let mut current_relationship: Option<SpdxRelationship> = None;
        let mut current_checksum: Option<SpdxChecksum> = None;
        let mut current_external_ref: Option<SpdxExternalRef> = None;
        let mut in_creation_info = false;
        let mut in_document = false;
        let mut current_text = String::new();
        let mut element_stack: Vec<String> = Vec::new();

        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    let local_name = Self::local_name(e.name().as_ref());
                    element_stack.push(local_name.clone());
                    current_text.clear();

                    match local_name.as_str() {
                        "SpdxDocument" => {
                            in_document = true;
                            // Extract document namespace from rdf:about attribute
                            for attr in e.attributes().filter_map(std::result::Result::ok) {
                                let attr_name = Self::local_name(attr.key.as_ref());
                                if attr_name == "about" {
                                    doc.document_namespace =
                                        Some(String::from_utf8_lossy(&attr.value).to_string());
                                }
                            }
                        }
                        "CreationInfo" => {
                            in_creation_info = true;
                        }
                        "Package" => {
                            let mut pkg = SpdxPackage {
                                spdx_id: String::new(),
                                name: String::new(),
                                version_info: None,
                                download_location: None,
                                files_analyzed: None,
                                license_concluded: None,
                                license_declared: None,
                                copyright_text: None,
                                supplier: None,
                                originator: None,
                                checksums: None,
                                external_refs: None,
                                description: None,
                            };
                            // Extract package URI from rdf:about attribute for SPDX ID
                            for attr in e.attributes().filter_map(std::result::Result::ok) {
                                let attr_name = Self::local_name(attr.key.as_ref());
                                if attr_name == "about" {
                                    let uri = String::from_utf8_lossy(&attr.value).to_string();
                                    // Extract SPDX ID from URI fragment
                                    if let Some(idx) = uri.rfind('#') {
                                        pkg.spdx_id = uri[idx + 1..].to_string();
                                    } else if let Some(idx) = uri.rfind('/') {
                                        pkg.spdx_id = uri[idx + 1..].to_string();
                                    }
                                }
                            }
                            current_package = Some(pkg);
                        }
                        "Relationship" => {
                            current_relationship = Some(SpdxRelationship {
                                spdx_element_id: String::new(),
                                relationship_type: String::new(),
                                related_spdx_element: String::new(),
                            });
                        }
                        "Checksum" => {
                            current_checksum = Some(SpdxChecksum {
                                algorithm: String::new(),
                                checksum_value: String::new(),
                            });
                        }
                        "ExternalRef" => {
                            current_external_ref = Some(SpdxExternalRef {
                                reference_category: String::new(),
                                reference_type: String::new(),
                                reference_locator: String::new(),
                            });
                        }
                        _ => {}
                    }
                }
                Ok(Event::Empty(ref e)) => {
                    let local_name = Self::local_name(e.name().as_ref());

                    // Handle empty elements with rdf:resource attributes
                    match local_name.as_str() {
                        "dataLicense" => {
                            for attr in e.attributes().filter_map(std::result::Result::ok) {
                                let attr_name = Self::local_name(attr.key.as_ref());
                                if attr_name == "resource" {
                                    let uri = String::from_utf8_lossy(&attr.value).to_string();
                                    // Extract license from URI
                                    if let Some(idx) = uri.rfind('/') {
                                        doc.data_license = uri[idx + 1..].to_string();
                                    } else {
                                        doc.data_license = uri;
                                    }
                                }
                            }
                        }
                        "spdxElementId" | "relatedSpdxElement" => {
                            if let Some(ref mut rel) = current_relationship {
                                for attr in e.attributes().filter_map(std::result::Result::ok) {
                                    let attr_name = Self::local_name(attr.key.as_ref());
                                    if attr_name == "resource" {
                                        let uri = String::from_utf8_lossy(&attr.value).to_string();
                                        let id = Self::extract_spdx_id_from_uri(&uri);
                                        if local_name == "spdxElementId" {
                                            rel.spdx_element_id = id;
                                        } else {
                                            rel.related_spdx_element = id;
                                        }
                                    }
                                }
                            }
                        }
                        "licenseConcluded" | "licenseDeclared" => {
                            if let Some(ref mut pkg) = current_package {
                                for attr in e.attributes().filter_map(std::result::Result::ok) {
                                    let attr_name = Self::local_name(attr.key.as_ref());
                                    if attr_name == "resource" {
                                        let uri = String::from_utf8_lossy(&attr.value).to_string();
                                        let license = Self::extract_license_from_uri(&uri);
                                        if local_name == "licenseConcluded" {
                                            pkg.license_concluded = Some(license);
                                        } else {
                                            pkg.license_declared = Some(license);
                                        }
                                    }
                                }
                            }
                        }
                        "algorithm" => {
                            if let Some(ref mut checksum) = current_checksum {
                                for attr in e.attributes().filter_map(std::result::Result::ok) {
                                    let attr_name = Self::local_name(attr.key.as_ref());
                                    if attr_name == "resource" {
                                        let uri = String::from_utf8_lossy(&attr.value).to_string();
                                        // Extract algorithm from URI like http://spdx.org/rdf/terms#checksumAlgorithm_sha256
                                        if let Some(idx) = uri.rfind("checksumAlgorithm_") {
                                            checksum.algorithm =
                                                uri[idx + 18..].to_uppercase();
                                        } else if let Some(idx) = uri.rfind('#') {
                                            checksum.algorithm =
                                                uri[idx + 1..].to_uppercase();
                                        }
                                    }
                                }
                            }
                        }
                        "referenceCategory" => {
                            if let Some(ref mut ext_ref) = current_external_ref {
                                for attr in e.attributes().filter_map(std::result::Result::ok) {
                                    let attr_name = Self::local_name(attr.key.as_ref());
                                    if attr_name == "resource" {
                                        let uri = String::from_utf8_lossy(&attr.value).to_string();
                                        if let Some(idx) = uri.rfind("referenceCategory_") {
                                            ext_ref.reference_category =
                                                uri[idx + 18..].to_string();
                                        } else if let Some(idx) = uri.rfind('#') {
                                            ext_ref.reference_category = uri[idx + 1..].to_string();
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Event::Text(ref e)) => {
                    current_text = e.decode().unwrap_or_default().to_string();
                }
                Ok(Event::End(ref e)) => {
                    let local_name = Self::local_name(e.name().as_ref());
                    element_stack.pop();

                    match local_name.as_str() {
                        "SpdxDocument" => {
                            in_document = false;
                        }
                        "CreationInfo" => {
                            in_creation_info = false;
                        }
                        "Package" => {
                            if let Some(pkg) = current_package.take() {
                                packages.push(pkg);
                            }
                        }
                        "Relationship" => {
                            if let Some(rel) = current_relationship.take() {
                                if !rel.spdx_element_id.is_empty()
                                    && !rel.related_spdx_element.is_empty()
                                {
                                    relationships.push(rel);
                                }
                            }
                        }
                        "Checksum" => {
                            if let Some(checksum) = current_checksum.take() {
                                if let Some(ref mut pkg) = current_package {
                                    pkg.checksums.get_or_insert_with(Vec::new).push(checksum);
                                }
                            }
                        }
                        "ExternalRef" => {
                            if let Some(ext_ref) = current_external_ref.take() {
                                if let Some(ref mut pkg) = current_package {
                                    pkg.external_refs.get_or_insert_with(Vec::new).push(ext_ref);
                                }
                            }
                        }
                        // Document-level fields
                        "specVersion" | "spdxVersion" => {
                            if in_document && current_package.is_none() {
                                doc.spdx_version.clone_from(&current_text);
                            }
                        }
                        "name" => {
                            if let Some(ref mut pkg) = current_package {
                                pkg.name.clone_from(&current_text);
                            } else if in_document {
                                doc.name.clone_from(&current_text);
                            }
                        }
                        "spdxId" | "SPDXID" => {
                            if let Some(ref mut pkg) = current_package {
                                if pkg.spdx_id.is_empty() {
                                    pkg.spdx_id.clone_from(&current_text);
                                }
                            } else if in_document {
                                doc.spdx_id.clone_from(&current_text);
                            }
                        }
                        "dataLicense" => {
                            if doc.data_license.is_empty() {
                                doc.data_license.clone_from(&current_text);
                            }
                        }
                        // Creation info fields
                        "created" => {
                            if in_creation_info {
                                creation_info.created = Some(current_text.clone());
                            }
                        }
                        "creator" | "Creator" => {
                            if in_creation_info && !current_text.is_empty() {
                                creation_info.creators.push(current_text.clone());
                            }
                        }
                        "licenseListVersion" => {
                            if in_creation_info {
                                creation_info.license_list_version = Some(current_text.clone());
                            }
                        }
                        // Package fields
                        "versionInfo" => {
                            if let Some(ref mut pkg) = current_package {
                                pkg.version_info = Some(current_text.clone());
                            }
                        }
                        "downloadLocation" => {
                            if let Some(ref mut pkg) = current_package {
                                pkg.download_location = Some(current_text.clone());
                            }
                        }
                        "licenseConcluded" => {
                            if let Some(ref mut pkg) = current_package {
                                if pkg.license_concluded.is_none() && !current_text.is_empty() {
                                    pkg.license_concluded = Some(current_text.clone());
                                }
                            }
                        }
                        "licenseDeclared" => {
                            if let Some(ref mut pkg) = current_package {
                                if pkg.license_declared.is_none() && !current_text.is_empty() {
                                    pkg.license_declared = Some(current_text.clone());
                                }
                            }
                        }
                        "copyrightText" => {
                            if let Some(ref mut pkg) = current_package {
                                pkg.copyright_text = Some(current_text.clone());
                            }
                        }
                        "supplier" => {
                            if let Some(ref mut pkg) = current_package {
                                pkg.supplier = Some(current_text.clone());
                            }
                        }
                        "originator" => {
                            if let Some(ref mut pkg) = current_package {
                                pkg.originator = Some(current_text.clone());
                            }
                        }
                        "description" | "summary" => {
                            if let Some(ref mut pkg) = current_package {
                                if pkg.description.is_none() {
                                    pkg.description = Some(current_text.clone());
                                }
                            }
                        }
                        // Checksum fields
                        "checksumValue" => {
                            if let Some(ref mut checksum) = current_checksum {
                                checksum.checksum_value.clone_from(&current_text);
                            }
                        }
                        // External ref fields
                        "referenceType" => {
                            if let Some(ref mut ext_ref) = current_external_ref {
                                ext_ref.reference_type.clone_from(&current_text);
                            }
                        }
                        "referenceLocator" => {
                            if let Some(ref mut ext_ref) = current_external_ref {
                                ext_ref.reference_locator.clone_from(&current_text);
                            }
                        }
                        "referenceCategory" => {
                            if let Some(ref mut ext_ref) = current_external_ref {
                                if ext_ref.reference_category.is_empty() {
                                    ext_ref.reference_category.clone_from(&current_text);
                                }
                            }
                        }
                        // Relationship fields
                        "relationshipType" => {
                            if let Some(ref mut rel) = current_relationship {
                                // Handle URI or direct value
                                let rel_type = if current_text.contains('#') {
                                    current_text.rfind('#').map_or_else(
                                        || current_text.clone(),
                                        |idx| current_text[idx + 1..].to_string(),
                                    )
                                } else if current_text.contains("relationshipType_") {
                                    current_text.replace("relationshipType_", "").to_uppercase()
                                } else {
                                    current_text.to_uppercase()
                                };
                                rel.relationship_type = rel_type;
                            }
                        }
                        "spdxElementId" => {
                            if let Some(ref mut rel) = current_relationship {
                                if rel.spdx_element_id.is_empty() {
                                    rel.spdx_element_id =
                                        Self::extract_spdx_id_from_uri(&current_text);
                                }
                            }
                        }
                        "relatedSpdxElement" => {
                            if let Some(ref mut rel) = current_relationship {
                                if rel.related_spdx_element.is_empty() {
                                    rel.related_spdx_element =
                                        Self::extract_spdx_id_from_uri(&current_text);
                                }
                            }
                        }
                        _ => {}
                    }
                    current_text.clear();
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    return Err(ParseError::XmlError(format!(
                        "Error parsing RDF/XML at position {}: {:?}",
                        reader.buffer_position(),
                        e
                    )))
                }
                _ => {}
            }
            buf.clear();
        }

        // Set document SPDX ID if not found
        if doc.spdx_id.is_empty() {
            doc.spdx_id = "SPDXRef-DOCUMENT".to_string();
        }

        // Set creation info
        doc.creation_info = Some(creation_info);
        doc.packages = Some(packages);
        doc.relationships = Some(relationships);

        Ok(doc)
    }

    /// Extract local name from qualified XML name (strips namespace prefix)
    fn local_name(name: &[u8]) -> String {
        let name_str = String::from_utf8_lossy(name);
        name_str.rfind(':').map_or_else(|| name_str.to_string(), |idx| name_str[idx + 1..].to_string())
    }

    /// Extract SPDX ID from URI (e.g., "http://example.org#SPDXRef-Package" -> "SPDXRef-Package")
    fn extract_spdx_id_from_uri(uri: &str) -> String {
        uri.rfind('#').map_or_else(
            || uri.rfind('/').map_or_else(|| uri.to_string(), |idx| uri[idx + 1..].to_string()),
            |idx| uri[idx + 1..].to_string(),
        )
    }

    /// Extract license identifier from URI
    fn extract_license_from_uri(uri: &str) -> String {
        if uri.contains("NOASSERTION") || uri.contains("noassertion") {
            return "NOASSERTION".to_string();
        }
        if uri.contains("NONE") || uri.contains("none") {
            return "NONE".to_string();
        }
        // Try to extract license ID from URL like http://spdx.org/licenses/MIT
        uri.rfind('/').map_or_else(
            || uri.rfind('#').map_or_else(|| uri.to_string(), |idx| uri[idx + 1..].to_string()),
            |idx| uri[idx + 1..].to_string(),
        )
    }

    /// Convert SPDX document to normalized representation
    fn convert_to_normalized(&self, spdx: SpdxDocument) -> Result<NormalizedSbom, ParseError> {
        let document = self.convert_metadata(&spdx)?;
        let mut sbom = NormalizedSbom::new(document);

        let mut id_map: HashMap<String, CanonicalId> = HashMap::new();

        // Convert packages to components
        if let Some(packages) = &spdx.packages {
            for pkg in packages {
                let comp = self.convert_package(pkg)?;
                id_map.insert(pkg.spdx_id.clone(), comp.canonical_id.clone());
                sbom.add_component(comp);
            }
        }

        // Convert relationships to dependency edges
        // Also identify primary component from DESCRIBES relationships
        if let Some(relationships) = &spdx.relationships {
            for rel in relationships {
                // Check for DESCRIBES relationship from document to identify primary component
                // SPDX format: "SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package"
                if rel.relationship_type == "DESCRIBES"
                    && (rel.spdx_element_id == spdx.spdx_id
                        || rel.spdx_element_id == "SPDXRef-DOCUMENT")
                {
                    // Set the first described package as primary component
                    if sbom.primary_component_id.is_none() {
                        if let Some(primary_id) = id_map.get(&rel.related_spdx_element) {
                            sbom.set_primary_component(primary_id.clone());

                            // Try to extract security contact from primary component
                            if let Some(comp) = sbom.components.get(primary_id) {
                                for ext_ref in &comp.external_refs {
                                    if matches!(ext_ref.ref_type, ExternalRefType::Advisories)
                                        && sbom.document.vulnerability_disclosure_url.is_none()
                                    {
                                        sbom.document.vulnerability_disclosure_url =
                                            Some(ext_ref.url.clone());
                                    }
                                }
                            }
                        }
                    }
                }

                let dep_type = match rel.relationship_type.as_str() {
                    "DEPENDS_ON" => Some(DependencyType::DependsOn),
                    "DEV_DEPENDENCY_OF" => Some(DependencyType::DevDependsOn),
                    "BUILD_DEPENDENCY_OF" => Some(DependencyType::BuildDependsOn),
                    "TEST_DEPENDENCY_OF" => Some(DependencyType::TestDependsOn),
                    "RUNTIME_DEPENDENCY_OF" => Some(DependencyType::RuntimeDependsOn),
                    "OPTIONAL_DEPENDENCY_OF" => Some(DependencyType::OptionalDependsOn),
                    "CONTAINS" => Some(DependencyType::Contains),
                    "DESCRIBES" => Some(DependencyType::Describes),
                    "GENERATES" => Some(DependencyType::Generates),
                    "ANCESTOR_OF" => Some(DependencyType::AncestorOf),
                    "VARIANT_OF" => Some(DependencyType::VariantOf),
                    "DISTRIBUTION_ARTIFACT" => Some(DependencyType::DistributionArtifact),
                    "PATCH_FOR" => Some(DependencyType::PatchFor),
                    "COPY_OF" => Some(DependencyType::CopyOf),
                    "FILE_ADDED" => Some(DependencyType::FileAdded),
                    "FILE_DELETED" => Some(DependencyType::FileDeleted),
                    "FILE_MODIFIED" => Some(DependencyType::FileModified),
                    "DYNAMIC_LINK" => Some(DependencyType::DynamicLink),
                    "STATIC_LINK" => Some(DependencyType::StaticLink),
                    _ => None,
                };

                if let Some(dep_type) = dep_type {
                    if let (Some(from_id), Some(to_id)) = (
                        id_map.get(&rel.spdx_element_id),
                        id_map.get(&rel.related_spdx_element),
                    ) {
                        sbom.add_edge(DependencyEdge::new(
                            from_id.clone(),
                            to_id.clone(),
                            dep_type,
                        ));
                    }
                }
            }
        }

        sbom.calculate_content_hash();
        Ok(sbom)
    }

    /// Convert SPDX creation info to DocumentMetadata
    fn convert_metadata(&self, spdx: &SpdxDocument) -> Result<DocumentMetadata, ParseError> {
        let version = spdx
            .spdx_version
            .strip_prefix("SPDX-")
            .unwrap_or(&spdx.spdx_version)
            .to_string();

        let created = spdx
            .creation_info
            .as_ref()
            .and_then(|ci| ci.created.as_ref())
            .and_then(|c| DateTime::parse_from_rfc3339(c).ok()).map_or_else(Utc::now, |dt| dt.with_timezone(&Utc));

        let mut creators = Vec::new();
        if let Some(creation_info) = &spdx.creation_info {
            for creator_str in &creation_info.creators {
                // Parse creator type and name from SPDX format "Type: Name"
                let (creator_type, name) = creator_str.strip_prefix("Tool:").map_or_else(
                    || creator_str.strip_prefix("Organization:").map_or_else(
                        || creator_str.strip_prefix("Person:").map_or_else(
                            || {
                                // Unknown format, treat as tool
                                (CreatorType::Tool, creator_str.as_str())
                            },
                            |name| (CreatorType::Person, name.trim()),
                        ),
                        |name| (CreatorType::Organization, name.trim()),
                    ),
                    |name| (CreatorType::Tool, name.trim()),
                );

                creators.push(Creator {
                    creator_type,
                    name: name.to_string(),
                    email: None,
                });
            }
        }

        Ok(DocumentMetadata {
            format: SbomFormat::Spdx,
            format_version: version.clone(),
            spec_version: version,
            serial_number: spdx.document_namespace.clone(),
            created,
            creators,
            name: Some(spdx.name.clone()),
            security_contact: None,
            vulnerability_disclosure_url: None,
            support_end_date: None,
        })
    }

    /// Convert SPDX package to normalized Component
    fn convert_package(&self, pkg: &SpdxPackage) -> Result<Component, ParseError> {
        let mut comp = Component::new(pkg.name.clone(), pkg.spdx_id.clone());

        // Set version
        if let Some(version) = &pkg.version_info {
            comp = comp.with_version(version.clone());
        }

        // Extract PURL from external refs
        if let Some(ext_refs) = &pkg.external_refs {
            for ext_ref in ext_refs {
                if (ext_ref.reference_type == "purl"
                    || ext_ref.reference_category == "PACKAGE-MANAGER")
                    && ext_ref.reference_locator.starts_with("pkg:")
                {
                    comp = comp.with_purl(ext_ref.reference_locator.clone());
                    break;
                }
            }
        }

        // Set component type (SPDX doesn't have explicit types, default to library)
        comp.component_type = ComponentType::Library;

        // Set licenses
        if let Some(declared) = &pkg.license_declared {
            if declared != "NOASSERTION" && declared != "NONE" {
                comp.licenses
                    .add_declared(LicenseExpression::new(declared.clone()));
            }
        }
        if let Some(concluded) = &pkg.license_concluded {
            if concluded != "NOASSERTION" && concluded != "NONE" {
                comp.licenses.concluded = Some(LicenseExpression::new(concluded.clone()));
            }
        }

        // Set supplier
        if let Some(supplier) = &pkg.supplier {
            let name = supplier
                .strip_prefix("Organization:")
                .or_else(|| supplier.strip_prefix("Person:"))
                .unwrap_or(supplier)
                .trim()
                .to_string();
            if name != "NOASSERTION" {
                comp.supplier = Some(Organization::new(name));
            }
        }

        // Set hashes
        if let Some(checksums) = &pkg.checksums {
            for checksum in checksums {
                let algorithm = match checksum.algorithm.to_uppercase().as_str() {
                    "MD5" => HashAlgorithm::Md5,
                    "SHA1" => HashAlgorithm::Sha1,
                    "SHA256" => HashAlgorithm::Sha256,
                    "SHA384" => HashAlgorithm::Sha384,
                    "SHA512" => HashAlgorithm::Sha512,
                    "SHA3-256" => HashAlgorithm::Sha3_256,
                    "SHA3-384" => HashAlgorithm::Sha3_384,
                    "SHA3-512" => HashAlgorithm::Sha3_512,
                    "BLAKE2B-256" => HashAlgorithm::Blake2b256,
                    "BLAKE2B-384" => HashAlgorithm::Blake2b384,
                    "BLAKE2B-512" => HashAlgorithm::Blake2b512,
                    other => HashAlgorithm::Other(other.to_string()),
                };
                comp.hashes
                    .push(Hash::new(algorithm, checksum.checksum_value.clone()));
            }
        }

        // Set external references
        if let Some(ext_refs) = &pkg.external_refs {
            for ext_ref in ext_refs {
                let ref_type = match ext_ref.reference_category.as_str() {
                    "SECURITY" => ExternalRefType::Advisories,
                    "PACKAGE-MANAGER" => ExternalRefType::Website,
                    "PERSISTENT-ID" => ExternalRefType::Other("persistent-id".to_string()),
                    "OTHER" => ExternalRefType::Other(ext_ref.reference_type.clone()),
                    other => ExternalRefType::Other(other.to_string()),
                };
                comp.external_refs.push(ExternalReference {
                    ref_type,
                    url: ext_ref.reference_locator.clone(),
                    comment: None,
                    hashes: Vec::new(),
                });
            }
        }

        // Set other fields
        comp.description.clone_from(&pkg.description);
        comp.copyright.clone_from(&pkg.copyright_text);

        comp.calculate_content_hash();
        Ok(comp)
    }
}

impl Default for SpdxParser {
    fn default() -> Self {
        Self::new()
    }
}

impl SbomParser for SpdxParser {
    fn parse_str(&self, content: &str) -> Result<NormalizedSbom, ParseError> {
        let trimmed = content.trim();
        if trimmed.starts_with('{') {
            self.parse_json(content)
        } else if trimmed.starts_with("SPDXVersion:") || trimmed.contains("\nSPDXVersion:") {
            self.parse_tag_value(content)
        } else if trimmed.starts_with('<')
            && (content.contains("spdx.org/rdf/terms")
                || content.contains("SpdxDocument")
                || content.contains("spdx:Package"))
        {
            self.parse_rdf_xml(content)
        } else {
            Err(ParseError::UnknownFormat(
                "Expected JSON, tag-value, or RDF/XML SPDX format".to_string(),
            ))
        }
    }

    fn supported_versions(&self) -> Vec<&str> {
        vec!["2.2", "2.3"]
    }

    fn format_name(&self) -> &str {
        "SPDX"
    }

    fn detect(&self, content: &str) -> crate::parsers::traits::FormatDetection {
        use crate::parsers::traits::{FormatConfidence, FormatDetection};

        let trimmed = content.trim();

        // Check for JSON SPDX
        if trimmed.starts_with('{') {
            let has_spdx_version = content.contains("\"spdxVersion\"");
            let has_spdx_id = content.contains("\"SPDXID\"");
            let has_data_license = content.contains("\"dataLicense\"");
            let has_packages = content.contains("\"packages\"");

            // Extract version if possible
            let version = Self::extract_spdx_version(content);

            if has_spdx_version && has_spdx_id {
                // Definitely SPDX JSON
                let mut detection =
                    FormatDetection::with_confidence(FormatConfidence::CERTAIN).variant("JSON");
                if let Some(v) = version {
                    detection = detection.version(&v);
                }
                return detection;
            } else if has_spdx_version || (has_spdx_id && has_data_license) {
                // Likely SPDX JSON
                let mut detection =
                    FormatDetection::with_confidence(FormatConfidence::HIGH).variant("JSON");
                if let Some(v) = version {
                    detection = detection.version(&v);
                }
                return detection;
            } else if has_packages && has_data_license {
                // Might be SPDX JSON
                return FormatDetection::with_confidence(FormatConfidence::MEDIUM)
                    .variant("JSON")
                    .warning("Missing spdxVersion field");
            }
        }

        // Check for tag-value SPDX
        if trimmed.starts_with("SPDXVersion:") || trimmed.contains("\nSPDXVersion:") {
            // Extract version from tag-value format
            let version = Self::extract_tag_value_version(content);

            let has_spdx_id = content.contains("SPDXID:");
            let has_data_license = content.contains("DataLicense:");

            if has_spdx_id && has_data_license {
                let mut detection = FormatDetection::with_confidence(FormatConfidence::CERTAIN)
                    .variant("tag-value");
                if let Some(v) = version {
                    detection = detection.version(&v);
                }
                return detection;
            } else {
                let mut detection =
                    FormatDetection::with_confidence(FormatConfidence::HIGH).variant("tag-value");
                if let Some(v) = version {
                    detection = detection.version(&v);
                }
                return detection;
            }
        }

        // Check for RDF/XML SPDX
        if trimmed.starts_with('<')
            && (content.contains("spdx.org/rdf/terms")
                || content.contains("SpdxDocument")
                || content.contains("spdx:Package"))
        {
            return FormatDetection::with_confidence(FormatConfidence::HIGH).variant("RDF/XML");
        }

        FormatDetection::no_match()
    }
}

impl SpdxParser {
    /// Extract SPDX version from JSON content (quick heuristic)
    fn extract_spdx_version(content: &str) -> Option<String> {
        // Look for "spdxVersion": "SPDX-X.Y"
        if let Some(idx) = content.find("\"spdxVersion\"") {
            let after = &content[idx..];
            if let Some(colon_idx) = after.find(':') {
                let value_part = &after[colon_idx + 1..];
                if let Some(quote_start) = value_part.find('"') {
                    let after_quote = &value_part[quote_start + 1..];
                    if let Some(quote_end) = after_quote.find('"') {
                        let version_str = &after_quote[..quote_end];
                        // Strip "SPDX-" prefix if present
                        return Some(
                            version_str
                                .strip_prefix("SPDX-")
                                .unwrap_or(version_str)
                                .to_string(),
                        );
                    }
                }
            }
        }
        None
    }

    /// Extract SPDX version from tag-value content
    fn extract_tag_value_version(content: &str) -> Option<String> {
        for line in content.lines() {
            if let Some(rest) = line.strip_prefix("SPDXVersion:") {
                let version_str = rest.trim();
                // Strip "SPDX-" prefix if present
                return Some(
                    version_str
                        .strip_prefix("SPDX-")
                        .unwrap_or(version_str)
                        .to_string(),
                );
            }
        }
        None
    }
}

// SPDX JSON structures for deserialization

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxDocument {
    spdx_version: String,
    #[serde(rename = "SPDXID")]
    spdx_id: String,
    name: String,
    data_license: String,
    document_namespace: Option<String>,
    creation_info: Option<SpdxCreationInfo>,
    packages: Option<Vec<SpdxPackage>>,
    relationships: Option<Vec<SpdxRelationship>>,
    #[allow(dead_code)]
    external_document_refs: Option<Vec<SpdxExternalDocRef>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct SpdxCreationInfo {
    created: Option<String>,
    creators: Vec<String>,
    license_list_version: Option<String>,
    comment: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct SpdxPackage {
    #[serde(rename = "SPDXID")]
    spdx_id: String,
    name: String,
    version_info: Option<String>,
    download_location: Option<String>,
    files_analyzed: Option<bool>,
    license_concluded: Option<String>,
    license_declared: Option<String>,
    copyright_text: Option<String>,
    supplier: Option<String>,
    originator: Option<String>,
    checksums: Option<Vec<SpdxChecksum>>,
    external_refs: Option<Vec<SpdxExternalRef>>,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxChecksum {
    algorithm: String,
    checksum_value: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxExternalRef {
    reference_category: String,
    reference_type: String,
    reference_locator: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxRelationship {
    spdx_element_id: String,
    relationship_type: String,
    related_spdx_element: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct SpdxExternalDocRef {
    external_document_id: String,
    spdx_document: String,
    checksum: SpdxChecksum,
}
