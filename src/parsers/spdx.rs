//! SPDX 2.x SBOM parser.
//!
//! Supports SPDX versions 2.2 and 2.3 in JSON, tag-value, and RDF/XML formats.
//! For SPDX 3.0 (JSON-LD), see the [`super::spdx3`] module.

use crate::model::{
    CanonicalId, Component, ComponentType, Contact, Creator, CreatorType, DependencyEdge,
    DependencyType, DocumentMetadata, ExternalRefType, ExternalReference, Hash, HashAlgorithm,
    LicenseExpression, NormalizedSbom, Organization, SbomFormat,
};
use crate::parsers::traits::{ParseError, SbomParser};
use chrono::{DateTime, Utc};
use quick_xml::Reader;
use quick_xml::events::Event;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};

/// Accumulate a possibly-multi-line SPDX `<text>…</text>` value.
///
/// If `first` opens a `<text>` block that doesn't close on the same line,
/// consume subsequent lines from `rest` (joined with newlines) until the
/// closing `</text>`, then strip both markers. A single-line value (or one
/// with a matched `<text>…</text>`) is returned with markers stripped. This
/// stops inner lines of a free-form field from being reparsed as tags.
fn accumulate_text_block<'a, I: Iterator<Item = &'a str>>(first: &str, rest: &mut I) -> String {
    let Some(after_open) = first.strip_prefix("<text>") else {
        return first.to_string();
    };
    // Closes on the same line: strip both markers.
    if let Some(inner) = after_open.strip_suffix("</text>") {
        return inner.to_string();
    }
    if let Some(idx) = after_open.find("</text>") {
        return after_open[..idx].to_string();
    }
    // Multi-line: keep raw lines until the closing tag.
    let mut acc = String::from(after_open);
    for line in rest.by_ref() {
        if let Some(idx) = line.find("</text>") {
            acc.push('\n');
            acc.push_str(&line[..idx]);
            break;
        }
        acc.push('\n');
        acc.push_str(line);
    }
    acc
}

/// Parser for SPDX SBOM format
#[allow(dead_code)]
pub struct SpdxParser {
    /// Whether to validate strictly
    strict: bool,
}

impl SpdxParser {
    /// Create a new SPDX parser
    #[must_use]
    pub const fn new() -> Self {
        Self { strict: false }
    }

    /// Create a strict parser
    #[must_use]
    pub const fn strict() -> Self {
        Self { strict: true }
    }

    /// Parse SPDX JSON format
    fn parse_json(&self, content: &str) -> Result<NormalizedSbom, ParseError> {
        let spdx: SpdxDocument =
            serde_json::from_str(content).map_err(|e| ParseError::JsonError(e.to_string()))?;

        Ok(self.convert_to_normalized(&spdx))
    }

    /// Parse an SPDX document from a JSON reader (streaming - doesn't buffer entire file)
    pub fn parse_json_reader<R: std::io::Read>(
        &self,
        reader: R,
    ) -> Result<NormalizedSbom, ParseError> {
        let spdx: SpdxDocument =
            serde_json::from_reader(reader).map_err(|e| ParseError::JsonError(e.to_string()))?;

        Ok(self.convert_to_normalized(&spdx))
    }

    /// Parse SPDX tag-value format
    fn parse_tag_value(&self, content: &str) -> NormalizedSbom {
        let spdx = self.parse_tag_value_format(content);
        self.convert_to_normalized(&spdx)
    }

    /// Parse tag-value format into `SpdxDocument`
    fn parse_tag_value_format(&self, content: &str) -> SpdxDocument {
        let mut doc = SpdxDocument {
            packages: Some(Vec::new()),
            relationships: Some(Vec::new()),
            ..SpdxDocument::default()
        };

        let mut current_package: Option<SpdxPackage> = None;
        let mut current_file: Option<SpdxFile> = None;
        let mut current_extracted: Option<SpdxExtractedLicense> = None;
        let mut files: Vec<SpdxFile> = Vec::new();
        let mut extracted_licenses: Vec<SpdxExtractedLicense> = Vec::new();
        // Once a File section starts, its tags (including SPDXID) must not be
        // attributed to the enclosing package — SPDX tag-value packages have
        // no explicit terminator, so a File's SPDXID used to clobber the
        // package's.
        let mut in_file_section = false;
        let mut packages = Vec::new();
        let mut relationships = Vec::new();
        let mut creation_info = SpdxCreationInfo {
            created: None,
            creators: Vec::new(),
            license_list_version: None,
            comment: None,
        };

        let mut lines = content.lines();
        while let Some(raw) = lines.next() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim();
                // Free-form fields may be wrapped in a multi-line
                // <text>…</text> block. Accumulate until the closing tag so
                // inner lines are NOT reparsed as top-level tags (which let a
                // crafted description inject SPDXID/Created/etc.).
                let value = accumulate_text_block(value.trim(), &mut lines);
                let value = value.as_str();

                match key {
                    "SPDXVersion" => doc.spdx_version = value.to_string(),
                    "FileName" => {
                        // A File section begins: close the current package so
                        // subsequent File tags can't overwrite it, and start
                        // collecting the file (files are inventory too —
                        // relationships and DESCRIBES reference them).
                        if let Some(pkg) = current_package.take() {
                            packages.push(pkg);
                        }
                        if let Some(file) = current_file.take() {
                            files.push(file);
                        }
                        current_file = Some(SpdxFile {
                            file_name: value.to_string(),
                            ..SpdxFile::default()
                        });
                        in_file_section = true;
                    }
                    "SPDXID" if current_package.is_some() => {
                        if let Some(ref mut pkg) = current_package {
                            pkg.spdx_id = value.to_string();
                        }
                    }
                    // A File's SPDXID must not overwrite the document
                    // SPDXID — it identifies the file being collected.
                    "SPDXID" if in_file_section => {
                        if let Some(ref mut file) = current_file {
                            file.spdx_id = value.to_string();
                        }
                    }
                    "SPDXID" => doc.spdx_id = value.to_string(),
                    "FileChecksum" => {
                        if let Some(ref mut file) = current_file
                            && let Some(checksum) = self.parse_checksum_line(value)
                        {
                            file.checksums.get_or_insert_with(Vec::new).push(checksum);
                        }
                    }
                    "FileCopyrightText" => {
                        if let Some(ref mut file) = current_file {
                            file.copyright_text = Some(value.to_string());
                        }
                    }
                    // File-scoped concluded license (packages use the
                    // PackageLicenseConcluded tag, so there is no clash).
                    "LicenseConcluded" => {
                        if let Some(ref mut file) = current_file {
                            file.license_concluded = Some(value.to_string());
                        }
                    }
                    // ExtractedLicensingInfo block: the definition each
                    // LicenseRef-* token points at.
                    "LicenseID" => {
                        if let Some(lic) = current_extracted.take() {
                            extracted_licenses.push(lic);
                        }
                        current_extracted = Some(SpdxExtractedLicense {
                            license_id: value.to_string(),
                            name: None,
                            extracted_text: None,
                        });
                    }
                    "LicenseName" => {
                        if let Some(ref mut lic) = current_extracted {
                            lic.name = Some(value.to_string());
                        }
                    }
                    "ExtractedText" => {
                        if let Some(ref mut lic) = current_extracted {
                            lic.extracted_text = Some(value.to_string());
                        }
                    }
                    "DocumentName" => doc.name = value.to_string(),
                    "DataLicense" => doc.data_license = value.to_string(),
                    "DocumentNamespace" => doc.document_namespace = Some(value.to_string()),
                    "Creator" => creation_info.creators.push(value.to_string()),
                    "Created" => creation_info.created = Some(value.to_string()),
                    "LicenseListVersion" => {
                        creation_info.license_list_version = Some(value.to_string());
                    }
                    "PackageName" => {
                        // Save previous package / close a trailing file block
                        if let Some(pkg) = current_package.take() {
                            packages.push(pkg);
                        }
                        if let Some(file) = current_file.take() {
                            files.push(file);
                        }
                        in_file_section = false;
                        current_package = Some(SpdxPackage {
                            name: value.to_string(),
                            ..SpdxPackage::default()
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
                    "PackageOriginator" => {
                        if let Some(ref mut pkg) = current_package {
                            pkg.originator = Some(value.to_string());
                        }
                    }
                    "PackageDescription" => {
                        if let Some(ref mut pkg) = current_package {
                            pkg.description = Some(value.to_string());
                        }
                    }
                    "PackageSummary" => {
                        if let Some(ref mut pkg) = current_package {
                            pkg.summary = Some(value.to_string());
                        }
                    }
                    "PackageHomePage" => {
                        if let Some(ref mut pkg) = current_package {
                            pkg.homepage = Some(value.to_string());
                        }
                    }
                    "PrimaryPackagePurpose" => {
                        if let Some(ref mut pkg) = current_package {
                            pkg.primary_package_purpose = Some(value.to_string());
                        }
                    }
                    "BuiltDate" => {
                        if let Some(ref mut pkg) = current_package {
                            pkg.built_date = Some(value.to_string());
                        }
                    }
                    "ReleaseDate" => {
                        if let Some(ref mut pkg) = current_package {
                            pkg.release_date = Some(value.to_string());
                        }
                    }
                    "ValidUntilDate" => {
                        if let Some(ref mut pkg) = current_package {
                            pkg.valid_until_date = Some(value.to_string());
                        }
                    }
                    "Relationship" => {
                        if let Some(rel) = self.parse_relationship_line(value) {
                            relationships.push(rel);
                        }
                    }
                    "ExternalRef" => {
                        if let Some(ref mut pkg) = current_package
                            && let Some(ext_ref) = self.parse_external_ref_line(value)
                        {
                            pkg.external_refs.get_or_insert_with(Vec::new).push(ext_ref);
                        }
                    }
                    "PackageChecksum" => {
                        if let Some(ref mut pkg) = current_package
                            && let Some(checksum) = self.parse_checksum_line(value)
                        {
                            pkg.checksums.get_or_insert_with(Vec::new).push(checksum);
                        }
                    }
                    _ => {}
                }
            }
        }

        // Don't forget trailing blocks
        if let Some(pkg) = current_package {
            packages.push(pkg);
        }
        if let Some(file) = current_file {
            files.push(file);
        }
        if let Some(lic) = current_extracted {
            extracted_licenses.push(lic);
        }

        doc.creation_info = Some(creation_info);
        doc.packages = Some(packages);
        doc.relationships = Some(relationships);
        doc.files = (!files.is_empty()).then_some(files);
        doc.has_extracted_licensing_infos =
            (!extracted_licenses.is_empty()).then_some(extracted_licenses);

        doc
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
        Ok(self.convert_to_normalized(&spdx))
    }

    /// Parse RDF/XML format into `SpdxDocument`
    fn parse_rdf_xml_format(&self, content: &str) -> Result<SpdxDocument, ParseError> {
        let mut reader = Reader::from_str(content);
        reader.config_mut().trim_text(true);

        let mut doc = SpdxDocument {
            packages: Some(Vec::new()),
            relationships: Some(Vec::new()),
            ..SpdxDocument::default()
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
        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    let local_name = Self::local_name(e.name().as_ref());
                    current_text.clear();

                    match local_name.as_str() {
                        "SpdxDocument" => {
                            in_document = true;
                            // Extract document namespace from rdf:about attribute
                            for attr in e.attributes().filter_map(std::result::Result::ok) {
                                let attr_name = Self::local_name(attr.key.as_ref());
                                if attr_name == "about" {
                                    doc.document_namespace = Some(attr.value.to_string());
                                }
                            }
                        }
                        "CreationInfo" => {
                            in_creation_info = true;
                        }
                        "Package" => {
                            let mut pkg = SpdxPackage::default();
                            // Extract package URI from rdf:about attribute for SPDX ID
                            for attr in e.attributes().filter_map(std::result::Result::ok) {
                                let attr_name = Self::local_name(attr.key.as_ref());
                                if attr_name == "about" {
                                    let uri = attr.value.to_string();
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
                                    let uri = attr.value.to_string();
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
                                        let uri = attr.value.to_string();
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
                                        let uri = attr.value.to_string();
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
                                        let uri = attr.value.to_string();
                                        // Extract algorithm from URI like http://spdx.org/rdf/terms#checksumAlgorithm_sha256
                                        if let Some(idx) = uri.rfind("checksumAlgorithm_") {
                                            checksum.algorithm = uri[idx + 18..].to_uppercase();
                                        } else if let Some(idx) = uri.rfind('#') {
                                            checksum.algorithm = uri[idx + 1..].to_uppercase();
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
                                        let uri = attr.value.to_string();
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
                    let text: &str = e.as_ref();
                    current_text = text.to_string();
                }
                Ok(Event::End(ref e)) => {
                    let local_name = Self::local_name(e.name().as_ref());

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
                            if let Some(rel) = current_relationship.take()
                                && !rel.spdx_element_id.is_empty()
                                && !rel.related_spdx_element.is_empty()
                            {
                                relationships.push(rel);
                            }
                        }
                        "Checksum" => {
                            if let Some(checksum) = current_checksum.take()
                                && let Some(ref mut pkg) = current_package
                            {
                                pkg.checksums.get_or_insert_with(Vec::new).push(checksum);
                            }
                        }
                        "ExternalRef" => {
                            if let Some(ext_ref) = current_external_ref.take()
                                && let Some(ref mut pkg) = current_package
                            {
                                pkg.external_refs.get_or_insert_with(Vec::new).push(ext_ref);
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
                            if let Some(ref mut pkg) = current_package
                                && pkg.license_concluded.is_none()
                                && !current_text.is_empty()
                            {
                                pkg.license_concluded = Some(current_text.clone());
                            }
                        }
                        "licenseDeclared" => {
                            if let Some(ref mut pkg) = current_package
                                && pkg.license_declared.is_none()
                                && !current_text.is_empty()
                            {
                                pkg.license_declared = Some(current_text.clone());
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
                            if let Some(ref mut pkg) = current_package
                                && pkg.description.is_none()
                            {
                                pkg.description = Some(current_text.clone());
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
                            if let Some(ref mut ext_ref) = current_external_ref
                                && ext_ref.reference_category.is_empty()
                            {
                                ext_ref.reference_category.clone_from(&current_text);
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
                            if let Some(ref mut rel) = current_relationship
                                && rel.spdx_element_id.is_empty()
                            {
                                rel.spdx_element_id = Self::extract_spdx_id_from_uri(&current_text);
                            }
                        }
                        "relatedSpdxElement" => {
                            if let Some(ref mut rel) = current_relationship
                                && rel.related_spdx_element.is_empty()
                            {
                                rel.related_spdx_element =
                                    Self::extract_spdx_id_from_uri(&current_text);
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
                    )));
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
    fn local_name(name: &str) -> String {
        name.rfind(':')
            .map_or_else(|| name.to_string(), |idx| name[idx + 1..].to_string())
    }

    /// Extract SPDX ID from URI (e.g., "<http://example.org#SPDXRef-Package>" -> "SPDXRef-Package")
    fn extract_spdx_id_from_uri(uri: &str) -> String {
        uri.rfind('#').map_or_else(
            || {
                uri.rfind('/')
                    .map_or_else(|| uri.to_string(), |idx| uri[idx + 1..].to_string())
            },
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
            || {
                uri.rfind('#')
                    .map_or_else(|| uri.to_string(), |idx| uri[idx + 1..].to_string())
            },
            |idx| uri[idx + 1..].to_string(),
        )
    }

    /// Convert SPDX document to normalized representation
    fn convert_to_normalized(&self, spdx: &SpdxDocument) -> NormalizedSbom {
        let document = self.convert_metadata(spdx);
        let mut sbom = NormalizedSbom::new(document);

        let mut id_map: HashMap<String, CanonicalId> = HashMap::new();

        // LicenseRef-* definitions: the indirection target for license
        // expressions ("LicenseRef-3" → "CyberNeko License").
        let license_names: HashMap<&str, &str> = spdx
            .has_extracted_licensing_infos
            .iter()
            .flatten()
            .filter(|lic| !lic.license_id.is_empty())
            .filter_map(|lic| {
                lic.name
                    .as_deref()
                    .map(|name| (lic.license_id.as_str(), name))
            })
            .collect();

        // Convert packages to components
        let mut package_ids: HashSet<String> = HashSet::new();
        if let Some(packages) = &spdx.packages {
            for pkg in packages {
                let mut comp = self.convert_package(pkg, &license_names);
                id_map.insert(pkg.spdx_id.clone(), sbom.claim_canonical_id(&mut comp));
                package_ids.insert(pkg.spdx_id.clone());
                sbom.add_component(comp);
            }
        }

        // Convert files and snippets to components (they are inventory:
        // relationships and documentDescribes reference them by SPDXID,
        // and the SPDX 3.0 parser already treats them as components).
        if let Some(files) = &spdx.files {
            for file in files {
                // A malformed entry with neither id nor name is
                // unaddressable — skip it rather than fail or pollute.
                if file.spdx_id.is_empty() && file.file_name.is_empty() {
                    continue;
                }
                let mut comp = self.convert_file(file, &license_names);
                let canonical_id = sbom.claim_canonical_id(&mut comp);
                if !file.spdx_id.is_empty() {
                    id_map.insert(file.spdx_id.clone(), canonical_id);
                }
                sbom.add_component(comp);
            }
        }
        if let Some(snippets) = &spdx.snippets {
            for snippet in snippets {
                if snippet.spdx_id.is_empty() && snippet.name.is_none() {
                    continue;
                }
                let mut comp = self.convert_snippet(snippet, &license_names);
                let canonical_id = sbom.claim_canonical_id(&mut comp);
                if !snippet.spdx_id.is_empty() {
                    id_map.insert(snippet.spdx_id.clone(), canonical_id);
                }
                sbom.add_component(comp);
            }
        }

        // Primary component: documentDescribes and DESCRIBES/DESCRIBED_BY
        // relationships are spec-equivalent mechanisms, so gather described
        // ids from BOTH before choosing — preferring an id that names a
        // package (documents often list files first, and the primary
        // product component is what compliance keys on).
        let doc_id = |id: &str| id == spdx.spdx_id || id == "SPDXRef-DOCUMENT";
        let mut described: Vec<&String> = spdx.document_describes.iter().flatten().collect();
        for rel in spdx.relationships.iter().flatten() {
            if rel.relationship_type == "DESCRIBES" && doc_id(&rel.spdx_element_id) {
                described.push(&rel.related_spdx_element);
            } else if rel.relationship_type == "DESCRIBED_BY" && doc_id(&rel.related_spdx_element) {
                described.push(&rel.spdx_element_id);
            }
        }
        let chosen = described
            .iter()
            .find(|id| package_ids.contains(**id))
            .or_else(|| described.iter().find(|id| id_map.contains_key(**id)));
        if let Some(primary_id) = chosen.and_then(|id| id_map.get(*id)) {
            Self::set_primary_and_disclosure(&mut sbom, &primary_id.clone());
        }

        // Convert relationships to dependency edges
        if let Some(relationships) = &spdx.relationships {
            for rel in relationships {
                // Map SPDX relationship types.
                // `*_DEPENDENCY_OF` types have inverse direction:
                //   "A DEV_DEPENDENCY_OF B" means B depends on A,
                //   so edge should be from=B, to=A (swapped).
                let dep_mapping = match rel.relationship_type.as_str() {
                    "DEPENDS_ON" => Some((DependencyType::DependsOn, false)),
                    "DEV_DEPENDENCY_OF" => Some((DependencyType::DevDependsOn, true)),
                    "BUILD_DEPENDENCY_OF" => Some((DependencyType::BuildDependsOn, true)),
                    "TEST_DEPENDENCY_OF" => Some((DependencyType::TestDependsOn, true)),
                    "RUNTIME_DEPENDENCY_OF" => Some((DependencyType::RuntimeDependsOn, true)),
                    "OPTIONAL_DEPENDENCY_OF" => Some((DependencyType::OptionalDependsOn, true)),
                    "CONTAINS" => Some((DependencyType::Contains, false)),
                    "DESCRIBES" => Some((DependencyType::Describes, false)),
                    "GENERATES" => Some((DependencyType::Generates, false)),
                    "ANCESTOR_OF" => Some((DependencyType::AncestorOf, false)),
                    "VARIANT_OF" => Some((DependencyType::VariantOf, false)),
                    "DISTRIBUTION_ARTIFACT" => Some((DependencyType::DistributionArtifact, false)),
                    "PATCH_FOR" => Some((DependencyType::PatchFor, false)),
                    "COPY_OF" => Some((DependencyType::CopyOf, false)),
                    "FILE_ADDED" => Some((DependencyType::FileAdded, false)),
                    "FILE_DELETED" => Some((DependencyType::FileDeleted, false)),
                    "FILE_MODIFIED" => Some((DependencyType::FileModified, false)),
                    "DYNAMIC_LINK" => Some((DependencyType::DynamicLink, false)),
                    "STATIC_LINK" => Some((DependencyType::StaticLink, false)),
                    // SPDX 2.3 additional relationship types
                    "DEPENDENCY_OF" => Some((DependencyType::DependsOn, true)),
                    "PROVIDED_DEPENDENCY_OF" => Some((DependencyType::ProvidedDependsOn, true)),
                    "HAS_PREREQUISITE" => Some((DependencyType::DependsOn, false)),
                    "PREREQUISITE_FOR" => Some((DependencyType::DependsOn, true)),
                    "DESCRIBED_BY" => Some((DependencyType::Describes, true)),
                    "BUILD_TOOL_OF" => Some((DependencyType::BuildDependsOn, true)),
                    "DEV_TOOL_OF" => Some((DependencyType::DevDependsOn, true)),
                    "TEST_TOOL_OF" => Some((DependencyType::TestDependsOn, true)),
                    // "A DOCUMENTATION_OF B" — A documents B, matching the
                    // Describes edge direction (was inverted).
                    "DOCUMENTATION_OF" => Some((DependencyType::Describes, false)),
                    "PACKAGE_OF" => Some((DependencyType::Contains, true)),
                    "EXAMPLE_OF" => Some((DependencyType::DependsOn, true)),
                    // Inverses of already-mapped forward types: which
                    // spelling a generator picks must not decide whether
                    // the edge exists.
                    "CONTAINED_BY" => Some((DependencyType::Contains, true)),
                    "GENERATED_FROM" => Some((DependencyType::Generates, true)),
                    "DESCENDANT_OF" => Some((DependencyType::AncestorOf, true)),
                    "EXPANDED_FROM_ARCHIVE" => Some((DependencyType::CopyOf, false)),
                    _ => None,
                };

                if let Some((dep_type, swap_direction)) = dep_mapping
                    && let (Some(element_id), Some(related_id)) = (
                        id_map.get(&rel.spdx_element_id),
                        id_map.get(&rel.related_spdx_element),
                    )
                {
                    let (from_id, to_id) = if swap_direction {
                        (related_id.clone(), element_id.clone())
                    } else {
                        (element_id.clone(), related_id.clone())
                    };
                    sbom.add_edge(DependencyEdge::new(from_id, to_id, dep_type));
                }
            }
        }

        // package.hasFiles is the dominant 2.2-era package→file containment
        // mechanism; without it the file components would be graph orphans
        // in documents that never emit explicit CONTAINS relationships.
        // Deduped against relationship-derived Contains edges.
        let mut contains_edges: HashSet<(CanonicalId, CanonicalId)> = sbom
            .edges
            .iter()
            .filter(|e| matches!(e.relationship, DependencyType::Contains))
            .map(|e| (e.from.clone(), e.to.clone()))
            .collect();
        for pkg in spdx.packages.iter().flatten() {
            let Some(pkg_id) = id_map.get(&pkg.spdx_id) else {
                continue;
            };
            for file_ref in pkg.has_files.iter().flatten() {
                if let Some(file_id) = id_map.get(file_ref)
                    && contains_edges.insert((pkg_id.clone(), file_id.clone()))
                {
                    sbom.add_edge(DependencyEdge::new(
                        pkg_id.clone(),
                        file_id.clone(),
                        DependencyType::Contains,
                    ));
                }
            }
        }

        // The primary package's validUntilDate (SPDX 2.3 "end of support")
        // is the in-band source for the document's support-end date.
        if sbom.document.support_end_date.is_none()
            && let Some(primary_id) = &sbom.primary_component_id
            && let Some(packages) = &spdx.packages
            && let Some(pkg) = packages
                .iter()
                .find(|p| id_map.get(&p.spdx_id) == Some(primary_id))
            && let Some(valid_until) = &pkg.valid_until_date
            && let Ok(dt) = DateTime::parse_from_rfc3339(valid_until)
        {
            sbom.document.support_end_date = Some(dt.with_timezone(&Utc));
        }

        sbom.calculate_content_hash();
        sbom
    }

    /// Set the primary component and lift its advisory reference into the
    /// document's vulnerability-disclosure URL (shared by the
    /// documentDescribes and DESCRIBES/DESCRIBED_BY selection paths).
    fn set_primary_and_disclosure(sbom: &mut NormalizedSbom, primary_id: &CanonicalId) {
        sbom.set_primary_component(primary_id.clone());
        if let Some(comp) = sbom.components.get(primary_id) {
            for ext_ref in &comp.external_refs {
                // Only URL-shaped locators qualify — a bare CPE string or
                // other identifier must never become the disclosure URL.
                if matches!(ext_ref.ref_type, ExternalRefType::Advisories)
                    && sbom.document.vulnerability_disclosure_url.is_none()
                    && (ext_ref.url.starts_with("http://")
                        || ext_ref.url.starts_with("https://")
                        || ext_ref.url.starts_with("mailto:"))
                {
                    sbom.document.vulnerability_disclosure_url = Some(ext_ref.url.clone());
                }
            }
        }
    }

    /// Convert SPDX creation info to `DocumentMetadata`
    fn convert_metadata(&self, spdx: &SpdxDocument) -> DocumentMetadata {
        let version = spdx
            .spdx_version
            .strip_prefix("SPDX-")
            .unwrap_or(&spdx.spdx_version)
            .to_string();

        let created = spdx
            .creation_info
            .as_ref()
            .and_then(|ci| ci.created.as_ref())
            .and_then(|c| DateTime::parse_from_rfc3339(c).ok())
            // Deterministic fallback: a document with a missing/invalid
            // timestamp must hash identically on every parse (created is
            // folded into the content hash; Utc::now() here made every
            // parse of such a document content-unique, defeating diff
            // identity and the incremental cache). Epoch is an honest
            // "unknown" sentinel rather than a fabricated parse time.
            .map_or(DateTime::UNIX_EPOCH, |dt| dt.with_timezone(&Utc));

        let mut creators = Vec::new();
        if let Some(creation_info) = &spdx.creation_info {
            for creator_str in &creation_info.creators {
                // Parse creator type and name from SPDX format "Type: Name"
                let (creator_type, name) = creator_str.strip_prefix("Tool:").map_or_else(
                    || {
                        creator_str.strip_prefix("Organization:").map_or_else(
                            || {
                                creator_str.strip_prefix("Person:").map_or_else(
                                    || {
                                        // Unknown format, treat as tool
                                        (CreatorType::Tool, creator_str.as_str())
                                    },
                                    |name| (CreatorType::Person, name.trim()),
                                )
                            },
                            |name| (CreatorType::Organization, name.trim()),
                        )
                    },
                    |name| (CreatorType::Tool, name.trim()),
                );

                // SPDX 2.3 §6.8 grammar: "Person: name (email)" — split the
                // trailing parenthesized email out of the display name.
                let (name, email) = split_name_email(name);
                creators.push(Creator {
                    creator_type,
                    name,
                    email,
                });
            }
        }

        DocumentMetadata {
            format: SbomFormat::Spdx,
            format_version: version.clone(),
            spec_version: version,
            serial_number: spdx.document_namespace.clone(),
            doc_version: None, // SPDX has no document revision counter
            created,
            creators,
            name: Some(spdx.name.clone()),
            security_contact: None,
            vulnerability_disclosure_url: None,
            support_end_date: None,
            lifecycle_phase: None, // SPDX does not have lifecycle phase metadata
            completeness_declaration: crate::model::CompletenessDeclaration::Unknown,
            signature: None,
            distribution_classification: None,
            citations_count: 0,
        }
    }

    /// Convert SPDX package to normalized Component
    fn convert_package(&self, pkg: &SpdxPackage, license_names: &HashMap<&str, &str>) -> Component {
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

        // Component type from SPDX 2.3 primaryPackagePurpose (older
        // documents lack it; Library remains the default).
        comp.component_type =
            pkg.primary_package_purpose
                .as_deref()
                .map_or(ComponentType::Library, |purpose| {
                    match purpose.to_uppercase().replace('-', "_").as_str() {
                        "APPLICATION" => ComponentType::Application,
                        "FRAMEWORK" => ComponentType::Framework,
                        "LIBRARY" => ComponentType::Library,
                        "CONTAINER" => ComponentType::Container,
                        "OPERATING_SYSTEM" => ComponentType::OperatingSystem,
                        "DEVICE" => ComponentType::Device,
                        "FIRMWARE" => ComponentType::Firmware,
                        // Packages whose purpose is SOURCE, ARCHIVE or FILE
                        // are still packages (a source tarball needs a
                        // version and supplier); only SPDX File and Snippet
                        // elements are `File`.
                        "SOURCE" => ComponentType::Other("source".to_string()),
                        "ARCHIVE" => ComponentType::Other("archive".to_string()),
                        "FILE" => ComponentType::Other("file".to_string()),
                        "DATA" => ComponentType::Data,
                        other => ComponentType::Other(other.to_lowercase()),
                    }
                });

        // Set licenses, resolving bare LicenseRef-* tokens through
        // hasExtractedLicensingInfos for display.
        if let Some(declared) = &pkg.license_declared
            && declared != "NOASSERTION"
            && declared != "NONE"
        {
            comp.licenses
                .add_declared(build_license(declared, license_names));
        }
        if let Some(concluded) = &pkg.license_concluded
            && concluded != "NOASSERTION"
            && concluded != "NONE"
        {
            comp.licenses.concluded = Some(build_license(concluded, license_names));
        }

        // Set supplier: strip the type prefix and move the parenthesized
        // email into a Contact rather than discarding it.
        if let Some(supplier) = &pkg.supplier {
            let raw = supplier
                .strip_prefix("Organization:")
                .or_else(|| supplier.strip_prefix("Person:"))
                .unwrap_or(supplier)
                .trim();
            let (name, email) = split_name_email(raw);
            if name != "NOASSERTION" && !name.is_empty() {
                let mut org = Organization::new(name);
                if let Some(email) = email {
                    org.contacts.push(Contact {
                        name: None,
                        email: Some(email),
                        phone: None,
                    });
                }
                comp.supplier = Some(org);
            }
        }

        // Originator — the upstream origin of the package (dead field
        // before: deserialized but never mapped, so Component.author was
        // structurally None for SPDX).
        if let Some(originator) = &pkg.originator {
            let raw = originator
                .strip_prefix("Organization:")
                .or_else(|| originator.strip_prefix("Person:"))
                .unwrap_or(originator)
                .trim();
            let (name, _email) = split_name_email(raw);
            if name != "NOASSERTION" && !name.is_empty() {
                comp.author = Some(name);
            }
        }

        // Set hashes
        if let Some(checksums) = &pkg.checksums {
            for checksum in checksums {
                comp.hashes.push(Hash::new(
                    map_spdx_hash_algorithm(&checksum.algorithm),
                    checksum.checksum_value.clone(),
                ));
            }
        }

        // Set external references
        if let Some(ext_refs) = &pkg.external_refs {
            for ext_ref in ext_refs {
                // The SPDX 2.2 JSON schema spells the category with an
                // underscore (PERSISTENT_ID); 2.3 uses a hyphen. Normalize
                // so both promote identically.
                let category = ext_ref.reference_category.replace('_', "-");
                // Promote PERSISTENT-ID/swh refs to first-class SWHID identifiers
                // (CRA prEN 40000-1-3 [PRE-7-RQ-07] recognises SWHIDs)
                if category == "PERSISTENT-ID" && ext_ref.reference_type.eq_ignore_ascii_case("swh")
                {
                    comp = comp.with_swhid(ext_ref.reference_locator.clone());
                    continue;
                }
                // SECURITY category covers both identifiers and advisory
                // links (Annex K): cpe22Type/cpe23Type/swid are identifiers,
                // NOT advisory URLs. Treating them as Advisories leaked CPE
                // strings into the document's vulnerability-disclosure URL
                // (falsely passing EO 14028/CRA disclosure checks) and left
                // Component.identifiers.cpe permanently empty for SPDX.
                if ext_ref.reference_type.eq_ignore_ascii_case("cpe23Type")
                    || ext_ref.reference_type.eq_ignore_ascii_case("cpe22Type")
                    || ext_ref.reference_locator.starts_with("cpe:")
                {
                    comp.add_cpe(ext_ref.reference_locator.clone());
                    continue;
                }
                if ext_ref.reference_type.eq_ignore_ascii_case("swid")
                    && comp.identifiers.swid.is_none()
                {
                    comp.identifiers.swid = Some(ext_ref.reference_locator.clone());
                    continue;
                }
                // SPDX 2.3 Annex F defines four categories: SECURITY
                // (cpe22Type, cpe23Type, advisory, fix, url, swid),
                // PACKAGE-MANAGER (maven-central, npm, nuget, bower, purl),
                // PERSISTENT-ID (swh, gitoid) and OTHER (free-form). None of
                // them names an attestation, certification report, risk
                // assessment, VDR or VEX, so those stay `Other` here; SPDX 3.0
                // has terms for them (see `map_spdx3_external_ref_type`).
                let ref_type = match category.as_str() {
                    // Only advisory-shaped SECURITY refs are advisories; CPE
                    // and SWID identifiers were promoted above.
                    "SECURITY" => match ext_ref.reference_type.to_ascii_lowercase().as_str() {
                        "advisory" | "fix" | "url" => ExternalRefType::Advisories,
                        other => ExternalRefType::Other(other.to_string()),
                    },
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

        // Homepage and download location become external references
        if let Some(homepage) = &pkg.homepage
            && homepage != "NOASSERTION"
            && homepage != "NONE"
        {
            comp.external_refs.push(ExternalReference {
                ref_type: ExternalRefType::Website,
                url: homepage.clone(),
                comment: None,
                hashes: Vec::new(),
            });
        }
        if let Some(download) = &pkg.download_location
            && download != "NOASSERTION"
            && download != "NONE"
        {
            // SourceDistribution: the typed variant the SPDX emitter
            // prefers when reconstructing downloadLocation, so the field
            // round-trips instead of being displaced by the homepage.
            comp.external_refs.push(ExternalReference {
                ref_type: ExternalRefType::SourceDistribution,
                url: download.clone(),
                comment: None,
                hashes: Vec::new(),
            });
        }

        // Set other fields; summary is the fallback description
        comp.description = pkg.description.clone().or_else(|| pkg.summary.clone());
        comp.copyright.clone_from(&pkg.copyright_text);

        comp.calculate_content_hash();
        comp
    }

    /// Convert an SPDX file entry to a normalized Component (files are
    /// referenced by relationships and documentDescribes; the SPDX 3.0
    /// parser already treats them as components).
    fn convert_file(&self, file: &SpdxFile, license_names: &HashMap<&str, &str>) -> Component {
        let mut comp = Component::new(file.file_name.clone(), file.spdx_id.clone());
        comp.component_type = ComponentType::File;

        if let Some(checksums) = &file.checksums {
            for checksum in checksums {
                comp.hashes.push(Hash::new(
                    map_spdx_hash_algorithm(&checksum.algorithm),
                    checksum.checksum_value.clone(),
                ));
            }
        }
        if let Some(concluded) = &file.license_concluded
            && concluded != "NOASSERTION"
            && concluded != "NONE"
        {
            comp.licenses.concluded = Some(build_license(concluded, license_names));
        }
        comp.copyright.clone_from(&file.copyright_text);

        comp.calculate_content_hash();
        comp
    }

    /// Convert an SPDX snippet entry to a normalized Component
    fn convert_snippet(
        &self,
        snippet: &SpdxSnippet,
        license_names: &HashMap<&str, &str>,
    ) -> Component {
        let name = snippet
            .name
            .clone()
            .unwrap_or_else(|| snippet.spdx_id.clone());
        let mut comp = Component::new(name, snippet.spdx_id.clone());
        comp.component_type = ComponentType::File;

        if let Some(from_file) = &snippet.snippet_from_file {
            comp.description = Some(format!("Snippet from {from_file}"));
        }
        if let Some(concluded) = &snippet.license_concluded
            && concluded != "NOASSERTION"
            && concluded != "NONE"
        {
            comp.licenses.concluded = Some(build_license(concluded, license_names));
        }
        comp.copyright.clone_from(&snippet.copyright_text);

        comp.calculate_content_hash();
        comp
    }
}

/// Map an SPDX checksum algorithm string to the normalized enum (shared by
/// package and file conversion).
fn map_spdx_hash_algorithm(algorithm: &str) -> HashAlgorithm {
    match algorithm.to_uppercase().as_str() {
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
        "BLAKE3" => HashAlgorithm::Blake3,
        other => HashAlgorithm::Other(other.to_string()),
    }
}

/// Split an SPDX 2.3 §6.8 name string "Name (email)" into (name, email).
/// The trailing parenthesized token is treated as an email only when it
/// contains '@'; an empty "()" is stripped; anything else stays in the name.
fn split_name_email(raw: &str) -> (String, Option<String>) {
    let raw = raw.trim();
    if let Some(open) = raw.rfind('(')
        && raw.ends_with(')')
    {
        let inner = raw[open + 1..raw.len() - 1].trim();
        let name = raw[..open].trim();
        if inner.is_empty() {
            return (name.to_string(), None);
        }
        if inner.contains('@') {
            return (name.to_string(), Some(inner.to_string()));
        }
    }
    (raw.to_string(), None)
}

/// Build a `LicenseExpression`, resolving a bare LicenseRef-* token to its
/// hasExtractedLicensingInfos name for display (the raw expression remains
/// the license identity).
fn build_license(expr: &str, license_names: &HashMap<&str, &str>) -> LicenseExpression {
    let mut lic = LicenseExpression::new(expr.to_string());
    if let Some(name) = license_names.get(expr) {
        lic.resolved_name = Some((*name).to_string());
    }
    lic
}

impl Default for SpdxParser {
    fn default() -> Self {
        Self::new()
    }
}

impl SbomParser for SpdxParser {
    fn parse_str(&self, content: &str) -> Result<NormalizedSbom, ParseError> {
        let content = super::strip_bom(content);
        let trimmed = content.trim();
        if trimmed.starts_with('{') {
            self.parse_json(content)
        } else if trimmed.starts_with("SPDXVersion:") || trimmed.contains("\nSPDXVersion:") {
            Ok(self.parse_tag_value(content))
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

    fn format_name(&self) -> &'static str {
        "SPDX"
    }

    fn detect(&self, content: &str) -> crate::parsers::traits::FormatDetection {
        use crate::parsers::contains_json_key;
        use crate::parsers::traits::{FormatConfidence, FormatDetection};

        let content = super::strip_bom(content);
        let trimmed = content.trim();

        // Check for JSON SPDX. Marker keys must appear as actual JSON keys,
        // not a coincidental string VALUE elsewhere (e.g. a CycloneDX
        // component or property literally named/valued "spdxVersion" or
        // "SPDXID" previously tripped SPDX detection for an unrelated file).
        if trimmed.starts_with('{') {
            let has_spdx_version = contains_json_key(content, "spdxVersion");
            let has_spdx_id = contains_json_key(content, "SPDXID");
            let has_data_license = contains_json_key(content, "dataLicense");
            let has_packages = contains_json_key(content, "packages");

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
            }

            let mut detection =
                FormatDetection::with_confidence(FormatConfidence::HIGH).variant("tag-value");
            if let Some(v) = version {
                detection = detection.version(&v);
            }
            return detection;
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

#[derive(Debug, Default, Deserialize)]
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
    /// Files described by the document — real inventory: relationships
    /// and documentDescribes reference them by SPDXID.
    files: Option<Vec<SpdxFile>>,
    snippets: Option<Vec<SpdxSnippet>>,
    relationships: Option<Vec<SpdxRelationship>>,
    /// SPDXIDs of the elements this document describes — the 2.2-era
    /// primary-component mechanism (equivalent to DESCRIBES relationships).
    document_describes: Option<Vec<String>>,
    /// LicenseRef-* definitions (licenseId → name/extractedText)
    has_extracted_licensing_infos: Option<Vec<SpdxExtractedLicense>>,
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

#[derive(Debug, Default, Deserialize)]
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
    /// SPDX 2.3 package purpose enum (APPLICATION, LIBRARY, CONTAINER, …)
    primary_package_purpose: Option<String>,
    homepage: Option<String>,
    summary: Option<String>,
    built_date: Option<String>,
    release_date: Option<String>,
    /// End of support — the in-band SPDX source for support_end_date
    valid_until_date: Option<String>,
    /// SPDXIDs of files this package owns (the dominant 2.2-era
    /// package→file containment mechanism)
    has_files: Option<Vec<String>>,
}

/// SPDX 2.x file entry (top-level `files` array / tag-value FileName block).
/// String fields default to empty rather than being serde-required: one
/// malformed entry must not fail the whole document (converter skips
/// entries with neither an id nor a name).
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct SpdxFile {
    #[serde(rename = "SPDXID", default)]
    spdx_id: String,
    #[serde(default)]
    file_name: String,
    checksums: Option<Vec<SpdxChecksum>>,
    license_concluded: Option<String>,
    copyright_text: Option<String>,
    comment: Option<String>,
}

/// SPDX 2.x snippet entry
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct SpdxSnippet {
    #[serde(rename = "SPDXID", default)]
    spdx_id: String,
    name: Option<String>,
    snippet_from_file: Option<String>,
    license_concluded: Option<String>,
    copyright_text: Option<String>,
}

/// One hasExtractedLicensingInfos entry: the definition a LicenseRef-*
/// token points at.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct SpdxExtractedLicense {
    #[serde(default)]
    license_id: String,
    name: Option<String>,
    extracted_text: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxChecksum {
    algorithm: String,
    checksum_value: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_field_names)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::traits::SbomParser;

    fn parse_tv(content: &str) -> NormalizedSbom {
        SpdxParser::new()
            .parse_str(content)
            .expect("tag-value should parse")
    }

    fn component<'a>(sbom: &'a NormalizedSbom, name: &str) -> &'a crate::model::Component {
        sbom.components
            .values()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("component {name} not found"))
    }

    /// cpe22Type/cpe23Type SECURITY refs are component identifiers, not
    /// advisisory references: they must land in identifiers.cpe and must NOT
    /// become Advisories external refs (which satisfy security-contact and
    /// CVD compliance gates).
    #[test]
    fn json_cpe_refs_promote_to_identifiers_not_advisories() {
        let sbom = SpdxParser::new()
            .parse_str(
                r#"{
                "spdxVersion": "SPDX-2.3",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": "doc",
                "dataLicense": "CC0-1.0",
                "creationInfo": {"created": "2026-01-01T00:00:00Z", "creators": ["Tool: gen"]},
                "packages": [{
                    "name": "fw",
                    "SPDXID": "SPDXRef-fw",
                    "versionInfo": "1.0",
                    "externalRefs": [
                        {"referenceCategory": "SECURITY",
                         "referenceType": "cpe23Type",
                         "referenceLocator": "cpe:2.3:a:acme:fw:1.0:*:*:*:*:*:*:*"},
                        {"referenceCategory": "SECURITY",
                         "referenceType": "advisory",
                         "referenceLocator": "https://acme.example/advisories"}
                    ]
                }]
            }"#,
            )
            .expect("json should parse");
        let comp = component(&sbom, "fw");
        assert_eq!(
            comp.identifiers.cpe,
            vec!["cpe:2.3:a:acme:fw:1.0:*:*:*:*:*:*:*".to_string()],
            "cpe23Type must be promoted to a first-class CPE identifier"
        );
        let advisories: Vec<_> = comp
            .external_refs
            .iter()
            .filter(|r| matches!(r.ref_type, crate::model::ExternalRefType::Advisories))
            .collect();
        assert_eq!(
            advisories.len(),
            1,
            "only the advisory-shaped SECURITY ref is an Advisories ref"
        );
        assert_eq!(advisories[0].url, "https://acme.example/advisories");
    }

    /// SPDX 2.2's JSON schema spells the persistent-id category with an
    /// underscore; both spellings must promote swh refs to SWHIDs.
    #[test]
    fn json_persistent_id_underscore_promotes_swhid() {
        let sbom = SpdxParser::new()
            .parse_str(
                r#"{
                "spdxVersion": "SPDX-2.2",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": "doc",
                "dataLicense": "CC0-1.0",
                "creationInfo": {"created": "2026-01-01T00:00:00Z", "creators": ["Tool: gen"]},
                "packages": [{
                    "name": "src",
                    "SPDXID": "SPDXRef-src",
                    "versionInfo": "1.0",
                    "externalRefs": [
                        {"referenceCategory": "PERSISTENT_ID",
                         "referenceType": "swh",
                         "referenceLocator": "swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2"}
                    ]
                }]
            }"#,
            )
            .expect("json should parse");
        let comp = component(&sbom, "src");
        assert!(
            !comp.identifiers.swhid.is_empty(),
            "PERSISTENT_ID (underscore spelling) must promote swh refs to SWHIDs"
        );
    }

    /// The SPDX 2.3 JSON schema spelled the operating-system purpose
    /// `OPERATING_SYSTEM`, while the 2.3 text (7.24) spells it
    /// `OPERATING-SYSTEM`; SPDX 2.3.1 corrected the schema to the hyphen and
    /// also allows `PACKAGE_MANAGER` beside `PACKAGE-MANAGER`. Every spelling,
    /// in JSON and in tag-value, must read the same.
    #[test]
    fn operating_system_purpose_reads_in_both_spellings() {
        for purpose in ["OPERATING-SYSTEM", "OPERATING_SYSTEM"] {
            for category in ["PACKAGE-MANAGER", "PACKAGE_MANAGER"] {
                let json = format!(
                    r#"{{
                    "spdxVersion": "SPDX-2.3",
                    "SPDXID": "SPDXRef-DOCUMENT",
                    "name": "doc",
                    "dataLicense": "CC0-1.0",
                    "documentNamespace": "https://example.com/doc",
                    "creationInfo": {{"created": "2026-01-01T00:00:00Z", "creators": ["Tool: gen-1.0"]}},
                    "packages": [{{
                        "name": "os",
                        "SPDXID": "SPDXRef-os",
                        "versionInfo": "1.0",
                        "primaryPackagePurpose": "{purpose}",
                        "externalRefs": [
                            {{"referenceCategory": "{category}",
                             "referenceType": "purl",
                             "referenceLocator": "pkg:generic/os@1.0"}}
                        ]
                    }}]
                }}"#
                );
                let sbom = SpdxParser::new()
                    .parse_str(&json)
                    .expect("json should parse");
                let os = component(&sbom, "os");
                assert_eq!(
                    os.component_type,
                    ComponentType::OperatingSystem,
                    "JSON primaryPackagePurpose {purpose}"
                );
                assert_eq!(
                    os.identifiers.purl.as_deref(),
                    Some("pkg:generic/os@1.0"),
                    "JSON referenceCategory {category}"
                );
            }

            let sbom = parse_tv(&format!(
                "SPDXVersion: SPDX-2.3\n\
                 DataLicense: CC0-1.0\n\
                 SPDXID: SPDXRef-DOCUMENT\n\
                 DocumentName: doc\n\
                 DocumentNamespace: https://example.com/doc\n\
                 Creator: Tool: gen-1.0\n\
                 Created: 2026-01-01T00:00:00Z\n\
                 PackageName: os\n\
                 SPDXID: SPDXRef-os\n\
                 PackageVersion: 1.0\n\
                 PrimaryPackagePurpose: {purpose}\n"
            ));
            assert_eq!(
                component(&sbom, "os").component_type,
                ComponentType::OperatingSystem,
                "tag-value PrimaryPackagePurpose {purpose}"
            );
        }
    }

    /// A bare CPE locator must never become the document-level vulnerability
    /// disclosure URL; only URL-shaped advisory locators qualify.
    #[test]
    fn json_disclosure_url_requires_url_shape() {
        let sbom = SpdxParser::new()
            .parse_str(
                r#"{
                "spdxVersion": "SPDX-2.3",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": "doc",
                "dataLicense": "CC0-1.0",
                "creationInfo": {"created": "2026-01-01T00:00:00Z", "creators": ["Tool: gen"]},
                "packages": [{
                    "name": "fw",
                    "SPDXID": "SPDXRef-fw",
                    "versionInfo": "1.0",
                    "externalRefs": [
                        {"referenceCategory": "SECURITY",
                         "referenceType": "cpe23Type",
                         "referenceLocator": "cpe:2.3:a:acme:fw:1.0:*:*:*:*:*:*:*"}
                    ]
                }],
                "relationships": [
                    {"spdxElementId": "SPDXRef-DOCUMENT",
                     "relationshipType": "DESCRIBES",
                     "relatedSpdxElement": "SPDXRef-fw"}
                ]
            }"#,
            )
            .expect("json should parse");
        assert_eq!(
            sbom.document.vulnerability_disclosure_url, None,
            "a CPE identifier must not become the disclosure URL"
        );
    }

    /// A File section's SPDXID must not overwrite the enclosing package's
    /// SPDXID (packages have no explicit terminator in tag-value).
    #[test]
    fn tag_value_file_spdxid_does_not_clobber_package() {
        let sbom = parse_tv(
            "SPDXVersion: SPDX-2.3\n\
             SPDXID: SPDXRef-DOCUMENT\n\
             DocumentName: test\n\
             PackageName: libfoo\n\
             SPDXID: SPDXRef-Package-libfoo\n\
             PackageVersion: 1.0\n\
             FileName: ./src/main.c\n\
             SPDXID: SPDXRef-File-main\n",
        );
        let comp = component(&sbom, "libfoo");
        assert_eq!(
            comp.identifiers.format_id, "SPDXRef-Package-libfoo",
            "the File SPDXID must not overwrite the package SPDXID"
        );
    }

    /// A multi-line <text> block must be captured as one value; its inner
    /// lines must NOT be reparsed as tags (SPDXID/Created injection).
    #[test]
    fn tag_value_multiline_text_block_is_not_reparsed() {
        let sbom = parse_tv(
            "SPDXVersion: SPDX-2.3\n\
             SPDXID: SPDXRef-DOCUMENT\n\
             DocumentName: test\n\
             PackageName: libfoo\n\
             SPDXID: SPDXRef-Package-libfoo\n\
             PackageCopyrightText: <text>Copyright ACME\n\
             SPDXID: SPDXRef-INJECTED\n\
             Created: 1999-01-01T00:00:00Z</text>\n\
             PackageVersion: 2.0\n",
        );
        let comp = component(&sbom, "libfoo");
        // The injected SPDXID inside the <text> block must not have taken
        // effect; the real package id survives and the version after the
        // block still parses.
        assert_eq!(comp.identifiers.format_id, "SPDXRef-Package-libfoo");
        assert_eq!(comp.version.as_deref(), Some("2.0"));
    }

    /// The official-example JSON shape: documentDescribes (file listed
    /// first!), files array, hasExtractedLicensingInfos, SECURITY/cpe23Type
    /// refs, creator emails, primaryPackagePurpose, validUntilDate,
    /// homepage. Everything here was silently dropped or misfiled before.
    #[test]
    fn spdx_json_core_fields_extracted() {
        let sbom = SpdxParser::new()
            .parse_str(
                r#"{
              "spdxVersion": "SPDX-2.3",
              "SPDXID": "SPDXRef-DOCUMENT",
              "name": "demo",
              "dataLicense": "CC0-1.0",
              "documentNamespace": "https://example.com/demo",
              "creationInfo": {
                "created": "2026-01-01T00:00:00Z",
                "creators": [
                  "Tool: LicenseFind-1.0",
                  "Organization: ExampleCodeInspect ()",
                  "Person: Jane Doe (jane.doe@example.com)"
                ]
              },
              "documentDescribes": ["SPDXRef-File-a", "SPDXRef-Package-app"],
              "hasExtractedLicensingInfos": [
                {"licenseId": "LicenseRef-3", "name": "CyberNeko License",
                 "extractedText": "..."}
              ],
              "packages": [{
                "SPDXID": "SPDXRef-Package-app",
                "name": "app",
                "versionInfo": "1.0",
                "primaryPackagePurpose": "APPLICATION",
                "homepage": "https://app.example.com",
                "downloadLocation": "https://dl.example.com/app-1.0.tgz",
                "licenseDeclared": "LicenseRef-3",
                "originator": "Organization: Upstream Org (contact@upstream.example)",
                "supplier": "Person: Jane Doe (jane.doe@example.com)",
                "validUntilDate": "2027-06-30T00:00:00Z",
                "hasFiles": ["SPDXRef-File-a"],
                "externalRefs": [
                  {"referenceCategory": "SECURITY", "referenceType": "cpe23Type",
                   "referenceLocator": "cpe:2.3:a:example:app:1.0:*:*:*:*:*:*:*"},
                  {"referenceCategory": "SECURITY", "referenceType": "advisory",
                   "referenceLocator": "https://example.com/security"}
                ]
              }],
              "files": [{
                "SPDXID": "SPDXRef-File-a",
                "fileName": "./src/a.c",
                "checksums": [{"algorithm": "BLAKE3", "checksumValue": "deadbeef"}],
                "licenseConcluded": "MIT",
                "copyrightText": "Copyright A"
              }],
              "relationships": [
                {"spdxElementId": "SPDXRef-Package-app",
                 "relationshipType": "CONTAINS",
                 "relatedSpdxElement": "SPDXRef-File-a"}
              ]
            }"#,
            )
            .expect("parse");

        // Files are components; relationships targeting them resolve.
        assert_eq!(sbom.component_count(), 2, "package + file");
        let file = component(&sbom, "./src/a.c");
        assert!(matches!(file.component_type, ComponentType::File));
        assert!(
            matches!(
                file.hashes.first().map(|h| &h.algorithm),
                Some(HashAlgorithm::Blake3)
            ),
            "BLAKE3 must map to the typed variant"
        );

        // documentDescribes prefers the PACKAGE even though the file is
        // listed first.
        let app = component(&sbom, "app");
        assert!(matches!(app.component_type, ComponentType::Application));
        assert_eq!(
            sbom.primary_component().map(|c| c.name.as_str()),
            Some("app"),
            "documentDescribes must select the package as primary"
        );

        // SECURITY/cpe23Type is an identifier, not an advisory URL.
        assert_eq!(
            app.identifiers.cpe.first().map(String::as_str),
            Some("cpe:2.3:a:example:app:1.0:*:*:*:*:*:*:*")
        );
        assert_eq!(
            sbom.document.vulnerability_disclosure_url.as_deref(),
            Some("https://example.com/security"),
            "the advisory link, never the CPE string"
        );

        // LicenseRef resolution, originator, supplier email-cleaning.
        assert_eq!(
            app.licenses
                .declared
                .first()
                .and_then(|l| l.resolved_name.as_deref()),
            Some("CyberNeko License")
        );
        assert_eq!(app.author.as_deref(), Some("Upstream Org"));
        assert_eq!(
            app.supplier.as_ref().map(|s| s.name.as_str()),
            Some("Jane Doe"),
            "supplier email must be stripped from the display name"
        );
        assert!(
            app.external_refs
                .iter()
                .any(|r| matches!(r.ref_type, ExternalRefType::Website)
                    && r.url == "https://app.example.com"),
            "homepage must become a Website reference"
        );
        assert!(
            app.external_refs.iter().any(|r| matches!(
                r.ref_type,
                ExternalRefType::SourceDistribution
            ) && r.url == "https://dl.example.com/app-1.0.tgz"),
            "downloadLocation must be a distribution ref (round-trips on emit)"
        );
        assert_eq!(
            app.supplier
                .as_ref()
                .and_then(|s| s.contacts.first())
                .and_then(|c| c.email.as_deref()),
            Some("jane.doe@example.com"),
            "supplier email must be preserved as a contact"
        );

        // hasFiles produced the containment edge, deduped against the
        // explicit CONTAINS relationship (exactly one edge).
        let app_id = app.canonical_id.clone();
        let file_id = component(&sbom, "./src/a.c").canonical_id.clone();
        assert_eq!(
            sbom.edges
                .iter()
                .filter(|e| e.from == app_id
                    && e.to == file_id
                    && matches!(e.relationship, DependencyType::Contains))
                .count(),
            1,
            "hasFiles + CONTAINS must dedupe to one containment edge"
        );

        // Creator emails per §6.8; empty "()" stripped.
        let jane = sbom
            .document
            .creators
            .iter()
            .find(|c| c.name == "Jane Doe")
            .expect("person creator");
        assert_eq!(jane.email.as_deref(), Some("jane.doe@example.com"));
        let org = sbom
            .document
            .creators
            .iter()
            .find(|c| c.creator_type == CreatorType::Organization)
            .expect("org creator");
        assert_eq!(org.name, "ExampleCodeInspect", "empty () must be stripped");

        // Primary package validUntilDate → document support-end date.
        assert!(sbom.document.support_end_date.is_some());
    }

    /// documentDescribes and DESCRIBES relationships are spec-equivalent:
    /// the package-preferred primary rule must apply across the UNION of
    /// both, so a file listed in documentDescribes cannot displace a
    /// package named only via a relationship.
    #[test]
    fn spdx_primary_package_preferred_across_mechanisms() {
        let sbom = SpdxParser::new()
            .parse_str(
                r#"{
              "spdxVersion": "SPDX-2.3",
              "SPDXID": "SPDXRef-DOCUMENT",
              "name": "demo",
              "dataLicense": "CC0-1.0",
              "creationInfo": {"created": "2026-01-01T00:00:00Z", "creators": ["Tool: t-1"]},
              "documentDescribes": ["SPDXRef-File-readme"],
              "packages": [{"SPDXID": "SPDXRef-Package-app", "name": "app"}],
              "files": [{"SPDXID": "SPDXRef-File-readme", "fileName": "README.md"}],
              "relationships": [
                {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                 "relatedSpdxElement": "SPDXRef-Package-app"}
              ]
            }"#,
            )
            .expect("parse");
        assert_eq!(
            sbom.primary_component().map(|c| c.name.as_str()),
            Some("app"),
            "the package must win over the documentDescribes file"
        );
    }

    /// One malformed file entry (no SPDXID, no fileName) must be skipped,
    /// not fail the document or pollute the inventory.
    #[test]
    fn spdx_malformed_file_entry_is_skipped() {
        let sbom = SpdxParser::new()
            .parse_str(
                r#"{
              "spdxVersion": "SPDX-2.3",
              "SPDXID": "SPDXRef-DOCUMENT",
              "name": "demo",
              "dataLicense": "CC0-1.0",
              "creationInfo": {"created": "2026-01-01T00:00:00Z", "creators": ["Tool: t-1"]},
              "packages": [{"SPDXID": "SPDXRef-p", "name": "p"}],
              "files": [
                {"copyrightText": "orphan"},
                {"SPDXID": "SPDXRef-f", "fileName": "./ok.c"}
              ]
            }"#,
            )
            .expect("a malformed file entry must not fail the document");
        assert_eq!(sbom.component_count(), 2, "package + the valid file only");
    }

    /// Inverse relationship spellings must produce the same edges as their
    /// forward twins, and DOCUMENTATION_OF must not be direction-inverted.
    #[test]
    fn spdx_inverse_relationships_produce_edges() {
        let sbom = SpdxParser::new()
            .parse_str(
                r#"{
              "spdxVersion": "SPDX-2.3",
              "SPDXID": "SPDXRef-DOCUMENT",
              "name": "demo",
              "dataLicense": "CC0-1.0",
              "creationInfo": {"created": "2026-01-01T00:00:00Z", "creators": ["Tool: t-1"]},
              "packages": [
                {"SPDXID": "SPDXRef-a", "name": "a"},
                {"SPDXID": "SPDXRef-b", "name": "b"},
                {"SPDXID": "SPDXRef-c", "name": "c"},
                {"SPDXID": "SPDXRef-d", "name": "d"}
              ],
              "relationships": [
                {"spdxElementId": "SPDXRef-a", "relationshipType": "CONTAINED_BY",
                 "relatedSpdxElement": "SPDXRef-b"},
                {"spdxElementId": "SPDXRef-c", "relationshipType": "GENERATED_FROM",
                 "relatedSpdxElement": "SPDXRef-d"},
                {"spdxElementId": "SPDXRef-a", "relationshipType": "DOCUMENTATION_OF",
                 "relatedSpdxElement": "SPDXRef-c"}
              ]
            }"#,
            )
            .expect("parse");

        let id_of = |name: &str| component(&sbom, name).canonical_id.clone();
        let edge = |from: &str, to: &str, dt: fn(&DependencyType) -> bool| {
            let (f, t) = (id_of(from), id_of(to));
            sbom.edges
                .iter()
                .any(|e| e.from == f && e.to == t && dt(&e.relationship))
        };
        // "a CONTAINED_BY b" = b contains a → edge b→a
        assert!(edge("b", "a", |d| matches!(d, DependencyType::Contains)));
        // "c GENERATED_FROM d" = d generates c → edge d→c
        assert!(edge("d", "c", |d| matches!(d, DependencyType::Generates)));
        // "a DOCUMENTATION_OF c" = a documents c → edge a→c (was inverted)
        assert!(edge("a", "c", |d| matches!(d, DependencyType::Describes)));
    }

    /// Tag-value: file blocks become components, the new package tags parse,
    /// and ExtractedLicensingInfo blocks resolve LicenseRef tokens — parity
    /// with the JSON path.
    #[test]
    fn tag_value_files_and_new_tags_parse() {
        let sbom = parse_tv(
            "SPDXVersion: SPDX-2.3\n\
             SPDXID: SPDXRef-DOCUMENT\n\
             DocumentName: test\n\
             Creator: Person: Jane Doe (jane.doe@example.com)\n\
             PackageName: libfoo\n\
             SPDXID: SPDXRef-Package-libfoo\n\
             PackageVersion: 2.0\n\
             PrimaryPackagePurpose: CONTAINER\n\
             PackageHomePage: https://libfoo.example.com\n\
             PackageOriginator: Organization: Foo Upstream ()\n\
             PackageLicenseDeclared: LicenseRef-Beerware\n\
             Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package-libfoo\n\
             FileName: ./src/foo.c\n\
             SPDXID: SPDXRef-File-foo\n\
             FileChecksum: SHA1: d6a770ba38583ed4bb4525bd96e50461655d2758\n\
             FileCopyrightText: Copyright Foo\n\
             LicenseConcluded: MIT\n\
             LicenseID: LicenseRef-Beerware\n\
             LicenseName: Beer-Ware License\n\
             ExtractedText: <text>you can buy me a beer</text>\n",
        );

        assert_eq!(sbom.component_count(), 2, "package + file");
        let pkg = component(&sbom, "libfoo");
        assert!(matches!(pkg.component_type, ComponentType::Container));
        assert_eq!(pkg.author.as_deref(), Some("Foo Upstream"));
        assert_eq!(
            pkg.licenses
                .declared
                .first()
                .and_then(|l| l.resolved_name.as_deref()),
            Some("Beer-Ware License"),
            "tag-value LicenseID blocks must resolve LicenseRef tokens"
        );
        assert!(
            pkg.external_refs
                .iter()
                .any(|r| matches!(r.ref_type, ExternalRefType::Website)),
            "PackageHomePage must become a Website reference"
        );

        let file = component(&sbom, "./src/foo.c");
        assert!(matches!(file.component_type, ComponentType::File));
        assert!(!file.hashes.is_empty(), "FileChecksum must parse");
        assert_eq!(
            file.licenses
                .concluded
                .as_ref()
                .map(|l| l.expression.as_str()),
            Some("MIT")
        );

        let jane = sbom
            .document
            .creators
            .iter()
            .find(|c| c.name == "Jane Doe")
            .expect("creator");
        assert_eq!(jane.email.as_deref(), Some("jane.doe@example.com"));
    }
}
