//! CycloneDX SBOM parser.
//!
//! Supports CycloneDX versions 1.4, 1.5, and 1.6 in JSON and XML formats.

use crate::model::{
    CanonicalId, Component, ComponentType, Creator, CreatorType, CvssScore, CvssVersion,
    DependencyEdge, DependencyType, DocumentMetadata, ExternalRefType, ExternalReference, Hash,
    HashAlgorithm, LicenseExpression, NormalizedSbom, Organization, Property, Remediation,
    RemediationType, SbomFormat, Severity, VexJustification, VexResponse, VexState, VexStatus,
    VulnerabilityRef, VulnerabilitySource,
};
use crate::parsers::traits::{ParseError, SbomParser};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::collections::HashMap;

/// Parser for CycloneDX SBOM format
#[allow(dead_code)]
pub struct CycloneDxParser {
    /// Whether to validate strictly
    strict: bool,
}

impl CycloneDxParser {
    /// Create a new CycloneDX parser
    pub fn new() -> Self {
        Self { strict: false }
    }

    /// Create a strict parser that validates more thoroughly
    pub fn strict() -> Self {
        Self { strict: true }
    }

    /// Parse a CycloneDX BOM from JSON
    fn parse_json(&self, content: &str) -> Result<NormalizedSbom, ParseError> {
        let cdx: CycloneDxBom =
            serde_json::from_str(content).map_err(|e| ParseError::JsonError(e.to_string()))?;

        self.convert_to_normalized(cdx)
    }

    /// Parse a CycloneDX BOM from a JSON reader (streaming - doesn't buffer entire file)
    pub fn parse_json_reader<R: std::io::Read>(
        &self,
        reader: R,
    ) -> Result<NormalizedSbom, ParseError> {
        let cdx: CycloneDxBom =
            serde_json::from_reader(reader).map_err(|e| ParseError::JsonError(e.to_string()))?;

        self.convert_to_normalized(cdx)
    }

    /// Parse a CycloneDX BOM from XML
    fn parse_xml(&self, content: &str) -> Result<NormalizedSbom, ParseError> {
        let cdx: CycloneDxBomXml =
            quick_xml::de::from_str(content).map_err(|e| ParseError::XmlError(e.to_string()))?;

        // Convert XML structure to common BOM structure
        let bom = CycloneDxBom {
            bom_format: Some("CycloneDX".to_string()),
            spec_version: cdx.version.unwrap_or_else(|| "1.4".to_string()),
            serial_number: cdx.serial_number,
            version: cdx.bom_version,
            metadata: cdx.metadata.map(|m| CdxMetadata {
                timestamp: m.timestamp,
                tools: m.tools.map(|t| t.tool),
                authors: None,
                component: m.component,
                lifecycles: None,
            }),
            components: cdx.components.map(|c| c.component),
            dependencies: cdx.dependencies.map(|d| d.dependency),
            vulnerabilities: cdx.vulnerabilities.map(|v| v.vulnerability),
        };

        self.convert_to_normalized(bom)
    }

    /// Convert CycloneDX BOM to normalized representation
    fn convert_to_normalized(&self, cdx: CycloneDxBom) -> Result<NormalizedSbom, ParseError> {
        let document = self.convert_metadata(&cdx)?;
        let mut sbom = NormalizedSbom::new(document);

        // Convert components
        let mut id_map: HashMap<String, CanonicalId> = HashMap::new();

        // Handle metadata.component as primary/root product component (CRA requirement)
        if let Some(meta) = &cdx.metadata {
            if let Some(meta_comp) = &meta.component {
                let comp = self.convert_component(meta_comp)?;
                let bom_ref = meta_comp
                    .bom_ref
                    .clone()
                    .unwrap_or_else(|| comp.name.clone());
                let canonical_id = comp.canonical_id.clone();
                id_map.insert(bom_ref, canonical_id.clone());

                // Set as primary component
                sbom.set_primary_component(canonical_id);

                // Extract security contact from primary component's external references
                for ext_ref in &comp.external_refs {
                    match ext_ref.ref_type {
                        ExternalRefType::SecurityContact => {
                            sbom.document.security_contact = Some(ext_ref.url.clone());
                        }
                        ExternalRefType::Advisories | ExternalRefType::Support => {
                            if sbom.document.vulnerability_disclosure_url.is_none() {
                                sbom.document.vulnerability_disclosure_url =
                                    Some(ext_ref.url.clone());
                            }
                        }
                        _ => {}
                    }
                }

                // Extract support_end_date from primary component properties
                if let Some(props) = &meta_comp.properties {
                    for prop in props {
                        let name_lower = prop.name.to_lowercase();
                        if name_lower.contains("endofsupport")
                            || name_lower.contains("end-of-support")
                            || name_lower.contains("eol")
                            || name_lower.contains("supportend")
                            || name_lower.contains("support_end")
                        {
                            if let Ok(dt) = DateTime::parse_from_rfc3339(&prop.value) {
                                sbom.document.support_end_date = Some(dt.with_timezone(&Utc));
                            } else if let Ok(dt) = chrono::NaiveDate::parse_from_str(&prop.value, "%Y-%m-%d") {
                                sbom.document.support_end_date = Some(dt.and_hms_opt(0, 0, 0).expect("midnight is always valid").and_utc());
                            }
                        }
                    }
                }

                sbom.add_component(comp);
            }
        }

        if let Some(components) = cdx.components {
            for cdx_comp in components {
                let comp = self.convert_component(&cdx_comp)?;
                let bom_ref = cdx_comp
                    .bom_ref
                    .unwrap_or_else(|| comp.name.clone());
                id_map.insert(bom_ref, comp.canonical_id.clone());
                sbom.add_component(comp);
            }
        }

        // Convert dependencies
        if let Some(deps) = cdx.dependencies {
            for dep in deps {
                if let Some(from_id) = id_map.get(&dep.ref_field) {
                    for depends_on in dep.depends_on.unwrap_or_default() {
                        if let Some(to_id) = id_map.get(&depends_on) {
                            sbom.add_edge(DependencyEdge::new(
                                from_id.clone(),
                                to_id.clone(),
                                DependencyType::DependsOn,
                            ));
                        }
                    }
                }
            }
        }

        // Convert vulnerabilities
        if let Some(vulns) = cdx.vulnerabilities {
            for vuln in vulns {
                self.apply_vulnerability(&mut sbom, &vuln, &id_map)?;
            }
        }

        sbom.calculate_content_hash();
        Ok(sbom)
    }

    /// Convert CycloneDX metadata to DocumentMetadata
    fn convert_metadata(&self, cdx: &CycloneDxBom) -> Result<DocumentMetadata, ParseError> {
        let created = cdx
            .metadata
            .as_ref()
            .and_then(|m| m.timestamp.as_ref())
            .and_then(|t| DateTime::parse_from_rfc3339(t).ok()).map_or_else(Utc::now, |dt| dt.with_timezone(&Utc));

        let mut creators = Vec::new();
        if let Some(meta) = &cdx.metadata {
            if let Some(tools) = &meta.tools {
                for tool in tools {
                    creators.push(Creator {
                        creator_type: CreatorType::Tool,
                        name: format!(
                            "{} {}",
                            tool.name.as_deref().unwrap_or("unknown"),
                            tool.version.as_deref().unwrap_or("")
                        )
                        .trim()
                        .to_string(),
                        email: None,
                    });
                }
            }
        }

        Ok(DocumentMetadata {
            format: SbomFormat::CycloneDx,
            format_version: cdx.spec_version.clone(),
            spec_version: cdx.spec_version.clone(),
            serial_number: cdx.serial_number.clone(),
            created,
            creators,
            name: cdx
                .metadata
                .as_ref()
                .and_then(|m| m.component.as_ref())
                .map(|c| c.name.clone()),
            security_contact: None,
            vulnerability_disclosure_url: None,
            support_end_date: None,
        })
    }

    /// Convert a CycloneDX component to normalized Component
    fn convert_component(&self, cdx: &CdxComponent) -> Result<Component, ParseError> {
        let format_id = cdx.bom_ref.clone().unwrap_or_else(|| cdx.name.clone());
        let mut comp = Component::new(cdx.name.clone(), format_id);

        // Set version
        if let Some(version) = &cdx.version {
            comp = comp.with_version(version.clone());
        }

        // Set PURL
        if let Some(purl) = &cdx.purl {
            comp = comp.with_purl(purl.clone());
        }

        // Set component type
        comp.component_type = match cdx.component_type.as_str() {
            "application" => ComponentType::Application,
            "framework" => ComponentType::Framework,
            "library" => ComponentType::Library,
            "container" => ComponentType::Container,
            "operating-system" => ComponentType::OperatingSystem,
            "device" => ComponentType::Device,
            "firmware" => ComponentType::Firmware,
            "file" => ComponentType::File,
            "machine-learning-model" => ComponentType::MachineLearningModel,
            "data" => ComponentType::Data,
            other => ComponentType::Other(other.to_string()),
        };

        // Set CPEs
        if let Some(cpe) = &cdx.cpe {
            comp.identifiers.cpe.push(cpe.clone());
        }

        // Set licenses
        if let Some(licenses) = &cdx.licenses {
            for lic in licenses {
                if let Some(license) = &lic.license {
                    let expr = license
                        .id
                        .clone()
                        .or_else(|| license.name.clone())
                        .unwrap_or_else(|| "NOASSERTION".to_string());
                    comp.licenses.add_declared(LicenseExpression::new(expr));
                }
                if let Some(expr) = &lic.expression {
                    comp.licenses
                        .add_declared(LicenseExpression::new(expr.clone()));
                }
            }
        }

        // Set supplier
        if let Some(supplier) = &cdx.supplier {
            comp.supplier = Some(Organization::new(supplier.name.clone()));
        }

        // Set hashes
        if let Some(hashes) = &cdx.hashes {
            for h in hashes {
                let algorithm = match h.alg.to_uppercase().as_str() {
                    "MD5" => HashAlgorithm::Md5,
                    "SHA-1" => HashAlgorithm::Sha1,
                    "SHA-256" => HashAlgorithm::Sha256,
                    "SHA-384" => HashAlgorithm::Sha384,
                    "SHA-512" => HashAlgorithm::Sha512,
                    "SHA3-256" => HashAlgorithm::Sha3_256,
                    "SHA3-384" => HashAlgorithm::Sha3_384,
                    "SHA3-512" => HashAlgorithm::Sha3_512,
                    "BLAKE2B-256" => HashAlgorithm::Blake2b256,
                    "BLAKE2B-384" => HashAlgorithm::Blake2b384,
                    "BLAKE2B-512" => HashAlgorithm::Blake2b512,
                    "BLAKE3" => HashAlgorithm::Blake3,
                    other => HashAlgorithm::Other(other.to_string()),
                };
                comp.hashes.push(Hash::new(algorithm, h.content.clone()));
            }
        }

        // Set external references
        if let Some(ext_refs) = &cdx.external_references {
            for ext_ref in ext_refs {
                let ref_type = match ext_ref.ref_type.as_str() {
                    "vcs" => ExternalRefType::Vcs,
                    "issue-tracker" => ExternalRefType::IssueTracker,
                    "website" => ExternalRefType::Website,
                    "advisories" => ExternalRefType::Advisories,
                    "bom" => ExternalRefType::Bom,
                    "documentation" => ExternalRefType::Documentation,
                    "support" => ExternalRefType::Support,
                    "security-contact" => ExternalRefType::SecurityContact,
                    "license" => ExternalRefType::License,
                    "build-meta" => ExternalRefType::BuildMeta,
                    "release-notes" => ExternalRefType::ReleaseNotes,
                    other => ExternalRefType::Other(other.to_string()),
                };
                comp.external_refs.push(ExternalReference {
                    ref_type,
                    url: ext_ref.url.clone(),
                    comment: ext_ref.comment.clone(),
                    hashes: Vec::new(),
                });
            }
        }

        // Set properties as extensions
        if let Some(props) = &cdx.properties {
            for prop in props {
                comp.extensions.properties.push(Property {
                    name: prop.name.clone(),
                    value: prop.value.clone(),
                });
            }
        }

        // Set description
        comp.description.clone_from(&cdx.description);
        comp.group.clone_from(&cdx.group);
        comp.author.clone_from(&cdx.author);
        comp.copyright.clone_from(&cdx.copyright);

        comp.calculate_content_hash();
        Ok(comp)
    }

    /// Apply vulnerability information to components
    fn apply_vulnerability(
        &self,
        sbom: &mut NormalizedSbom,
        vuln: &CdxVulnerability,
        id_map: &HashMap<String, CanonicalId>,
    ) -> Result<(), ParseError> {
        let source = vuln
            .source
            .as_ref()
            .map_or(VulnerabilitySource::Cve, |s| match s.name.to_lowercase().as_str() {
                "nvd" => VulnerabilitySource::Nvd,
                "ghsa" | "github" => VulnerabilitySource::Ghsa,
                "osv" => VulnerabilitySource::Osv,
                "snyk" => VulnerabilitySource::Snyk,
                other => VulnerabilitySource::Other(other.to_string()),
            });

        let mut vuln_ref = VulnerabilityRef::new(vuln.id.clone(), source);
        vuln_ref.description.clone_from(&vuln.description);

        // Parse CVSS scores
        if let Some(ratings) = &vuln.ratings {
            for rating in ratings {
                let version = match rating.method.as_deref() {
                    Some("CVSSv2") => CvssVersion::V2,
                    Some("CVSSv3") => CvssVersion::V3,
                    Some("CVSSv4") => CvssVersion::V4,
                    _ => CvssVersion::V31,
                };
                if let Some(score) = rating.score {
                    let mut cvss = CvssScore::new(version, score);
                    cvss.vector.clone_from(&rating.vector);
                    vuln_ref.cvss.push(cvss);
                }
                if vuln_ref.severity.is_none() {
                    vuln_ref.severity =
                        rating
                            .severity
                            .as_ref()
                            .map(|s| match s.to_lowercase().as_str() {
                                "critical" => Severity::Critical,
                                "high" => Severity::High,
                                "medium" => Severity::Medium,
                                "low" => Severity::Low,
                                "info" | "informational" => Severity::Info,
                                "none" => Severity::None,
                                _ => Severity::Unknown,
                            });
                }
            }
        }

        // Fallback: derive severity from CVSS score if no explicit severity was provided
        if vuln_ref.severity.is_none() {
            if let Some(max_score) = vuln_ref.max_cvss_score() {
                vuln_ref.severity = Some(Severity::from_cvss(max_score));
            }
        }

        // Parse CWEs
        if let Some(cwes) = &vuln.cwes {
            vuln_ref.cwes = cwes.iter().map(|c| format!("CWE-{c}")).collect();
        }

        // Parse remediation
        if let Some(recommendation) = &vuln.recommendation {
            vuln_ref.remediation = Some(Remediation {
                remediation_type: RemediationType::Upgrade,
                description: Some(recommendation.clone()),
                fixed_version: None,
            });
        }

        // Parse analysis (VEX)
        let vex_status = vuln.analysis.as_ref().map(|analysis| {
            let status = match analysis.state.as_deref() {
                Some("not_affected") => VexState::NotAffected,
                Some("affected") => VexState::Affected,
                Some("fixed") => VexState::Fixed,
                _ => VexState::UnderInvestigation,
            };

            let justification = analysis.justification.as_ref().map(|j| match j.as_str() {
                "code_not_present" => VexJustification::VulnerableCodeNotPresent,
                "code_not_reachable" => VexJustification::VulnerableCodeNotInExecutePath,
                "requires_configuration" | "requires_dependency" | "requires_environment" => {
                    VexJustification::VulnerableCodeCannotBeControlledByAdversary
                }
                "protected_by_mitigating_control" => {
                    VexJustification::InlineMitigationsAlreadyExist
                }
                _ => VexJustification::ComponentNotPresent,
            });

            let response = analysis.response.as_ref().and_then(|responses| {
                responses.first().map(|r| match r.as_str() {
                    "can_not_fix" => VexResponse::CanNotFix,
                    "will_not_fix" => VexResponse::WillNotFix,
                    "rollback" => VexResponse::Rollback,
                    "workaround_available" => VexResponse::Workaround,
                    _ => VexResponse::Update,
                })
            });

            VexStatus {
                status,
                justification,
                action_statement: None,
                impact_statement: analysis.detail.clone(),
                response,
                detail: analysis.detail.clone(),
            }
        });

        // Apply vulnerability to affected components
        if let Some(affects) = &vuln.affects {
            for affect in affects {
                if let Some(canonical_id) = id_map.get(&affect.ref_field) {
                    if let Some(comp) = sbom.components.get_mut(canonical_id) {
                        let mut v = vuln_ref.clone();
                        if let Some(versions) = &affect.versions {
                            v.affected_versions = versions
                                .iter()
                                .filter_map(|ver| ver.version.clone())
                                .collect();
                        }
                        comp.vulnerabilities.push(v);
                        if let Some(vex) = &vex_status {
                            comp.vex_status = Some(vex.clone());
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

impl Default for CycloneDxParser {
    fn default() -> Self {
        Self::new()
    }
}

impl SbomParser for CycloneDxParser {
    fn parse_str(&self, content: &str) -> Result<NormalizedSbom, ParseError> {
        let trimmed = content.trim();
        if trimmed.starts_with('{') {
            self.parse_json(content)
        } else if trimmed.starts_with('<') {
            self.parse_xml(content)
        } else {
            Err(ParseError::UnknownFormat(
                "Expected JSON or XML CycloneDX format".to_string(),
            ))
        }
    }

    fn supported_versions(&self) -> Vec<&str> {
        vec!["1.4", "1.5", "1.6"]
    }

    fn format_name(&self) -> &str {
        "CycloneDX"
    }

    fn detect(&self, content: &str) -> crate::parsers::traits::FormatDetection {
        use crate::parsers::traits::{FormatConfidence, FormatDetection};

        let trimmed = content.trim();

        // Check for JSON CycloneDX
        if trimmed.starts_with('{') {
            // Look for CycloneDX-specific markers
            let has_bom_format = content.contains("\"bomFormat\"");
            let has_cyclonedx = content.contains("CycloneDX") || content.contains("cyclonedx");
            let has_spec_version = content.contains("\"specVersion\"");
            let has_schema = content.contains("\"$schema\"") && content.contains("cyclonedx");

            // Extract version if possible
            let version = Self::extract_json_version(content);

            if has_bom_format && has_cyclonedx {
                // Definitely CycloneDX JSON
                let mut detection =
                    FormatDetection::with_confidence(FormatConfidence::CERTAIN).variant("JSON");
                if let Some(v) = version {
                    detection = detection.version(&v);
                }
                return detection;
            } else if has_bom_format || has_schema {
                // Likely CycloneDX JSON
                let mut detection =
                    FormatDetection::with_confidence(FormatConfidence::HIGH).variant("JSON");
                if let Some(v) = version {
                    detection = detection.version(&v);
                }
                return detection;
            } else if has_spec_version && content.contains("\"components\"") {
                // Might be CycloneDX JSON (missing bomFormat but has structure)
                return FormatDetection::with_confidence(FormatConfidence::MEDIUM)
                    .variant("JSON")
                    .warning("Missing bomFormat field - might not be CycloneDX");
            }
        }

        // Check for XML CycloneDX
        if trimmed.starts_with('<') {
            let has_bom_element = content.contains("<bom");
            let has_cyclonedx_ns = content.contains("cyclonedx.org");

            // Extract version from XML if possible
            let xml_version = Self::extract_xml_version(content);

            if has_bom_element && has_cyclonedx_ns {
                let mut detection =
                    FormatDetection::with_confidence(FormatConfidence::CERTAIN).variant("XML");
                if let Some(v) = xml_version {
                    detection = detection.version(&v);
                }
                return detection;
            } else if has_bom_element {
                let mut detection = FormatDetection::with_confidence(FormatConfidence::MEDIUM)
                    .variant("XML")
                    .warning("Missing CycloneDX namespace");
                if let Some(v) = xml_version {
                    detection = detection.version(&v);
                }
                return detection;
            }
        }

        FormatDetection::no_match()
    }
}

impl CycloneDxParser {
    /// Extract version from JSON content (quick heuristic, not full parse)
    fn extract_json_version(content: &str) -> Option<String> {
        // Look for "specVersion": "X.Y"
        if let Some(idx) = content.find("\"specVersion\"") {
            let after = &content[idx..];
            if let Some(colon_idx) = after.find(':') {
                let value_part = &after[colon_idx + 1..];
                // Find the quoted value
                if let Some(quote_start) = value_part.find('"') {
                    let after_quote = &value_part[quote_start + 1..];
                    if let Some(quote_end) = after_quote.find('"') {
                        return Some(after_quote[..quote_end].to_string());
                    }
                }
            }
        }
        None
    }

    /// Extract version from XML content (quick heuristic, not full parse)
    fn extract_xml_version(content: &str) -> Option<String> {
        // Look for version="X.Y" in <bom> element
        if let Some(bom_idx) = content.find("<bom") {
            let bom_part = &content[bom_idx..];
            // Find the end of the opening tag
            if let Some(gt_idx) = bom_part.find('>') {
                let attrs = &bom_part[..gt_idx];
                // Look for version attribute
                if let Some(ver_idx) = attrs.find("version=") {
                    let after_ver = &attrs[ver_idx + 8..];
                    // Handle both version="1.5" and version='1.5'
                    let quote_char = after_ver.chars().next()?;
                    if quote_char == '"' || quote_char == '\'' {
                        let after_quote = &after_ver[1..];
                        if let Some(end_idx) = after_quote.find(quote_char) {
                            return Some(after_quote[..end_idx].to_string());
                        }
                    }
                }
            }
        }
        None
    }
}

// CycloneDX JSON structures for deserialization
// Many fields are parsed but not fully utilized yet

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct CycloneDxBom {
    #[serde(alias = "bomFormat")]
    bom_format: Option<String>,
    spec_version: String,
    serial_number: Option<String>,
    version: Option<u32>,
    metadata: Option<CdxMetadata>,
    components: Option<Vec<CdxComponent>>,
    dependencies: Option<Vec<CdxDependency>>,
    vulnerabilities: Option<Vec<CdxVulnerability>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct CdxMetadata {
    timestamp: Option<String>,
    /// Tools field - can be either array (1.4/1.5) or object with components (1.6)
    #[serde(default, deserialize_with = "deserialize_tools")]
    tools: Option<Vec<CdxTool>>,
    /// Authors field (1.6+)
    authors: Option<Vec<CdxAuthor>>,
    component: Option<CdxComponent>,
    /// Lifecycles field (1.5+) - contains phases like end-of-support dates
    lifecycles: Option<Vec<CdxLifecycle>>,
}

/// CycloneDX lifecycle entry (1.5+)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct CdxLifecycle {
    /// Lifecycle phase: design, pre-build, build, post-build, operations, discovery, decommission
    phase: Option<String>,
    /// Name of the lifecycle phase (for custom phases)
    name: Option<String>,
    /// Description of the lifecycle phase
    description: Option<String>,
}

/// CycloneDX 1.6 tools object format
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct CdxToolsObject {
    components: Option<Vec<CdxToolComponent>>,
    services: Option<Vec<CdxToolService>>,
}

/// Tool component in CycloneDX 1.6 format
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct CdxToolComponent {
    name: Option<String>,
    version: Option<String>,
    #[serde(alias = "bom-ref")]
    bom_ref: Option<String>,
}

/// Tool service in CycloneDX 1.6 format
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct CdxToolService {
    name: Option<String>,
    version: Option<String>,
}

/// Author in CycloneDX 1.6 format
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct CdxAuthor {
    name: Option<String>,
    email: Option<String>,
    #[serde(alias = "bom-ref")]
    bom_ref: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxTool {
    name: Option<String>,
    version: Option<String>,
}

/// Custom deserializer to handle both CycloneDX 1.4/1.5 (array) and 1.6 (object) tool formats
fn deserialize_tools<'de, D>(deserializer: D) -> Result<Option<Vec<CdxTool>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, MapAccess, SeqAccess, Visitor};
    use std::fmt;

    struct ToolsVisitor;

    impl<'de> Visitor<'de> for ToolsVisitor {
        type Value = Option<Vec<CdxTool>>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("an array of tools or an object with components/services")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            // CycloneDX 1.4/1.5 format: array of tools
            let mut tools = Vec::new();
            while let Some(tool) = seq.next_element::<CdxTool>()? {
                tools.push(tool);
            }
            Ok(Some(tools))
        }

        fn visit_map<M>(self, map: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            // CycloneDX 1.6 format: object with components/services
            let tools_obj: CdxToolsObject =
                serde::Deserialize::deserialize(de::value::MapAccessDeserializer::new(map))?;

            let mut tools = Vec::new();

            // Convert components to tools
            if let Some(components) = tools_obj.components {
                for comp in components {
                    tools.push(CdxTool {
                        name: comp.name,
                        version: comp.version,
                    });
                }
            }

            // Convert services to tools
            if let Some(services) = tools_obj.services {
                for svc in services {
                    tools.push(CdxTool {
                        name: svc.name,
                        version: svc.version,
                    });
                }
            }

            Ok(if tools.is_empty() { None } else { Some(tools) })
        }
    }

    deserializer.deserialize_any(ToolsVisitor)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxComponent {
    #[serde(rename = "type")]
    component_type: String,
    #[serde(alias = "bom-ref")]
    bom_ref: Option<String>,
    name: String,
    version: Option<String>,
    group: Option<String>,
    purl: Option<String>,
    cpe: Option<String>,
    description: Option<String>,
    author: Option<String>,
    copyright: Option<String>,
    licenses: Option<Vec<CdxLicenseChoice>>,
    supplier: Option<CdxSupplier>,
    hashes: Option<Vec<CdxHash>>,
    external_references: Option<Vec<CdxExternalReference>>,
    properties: Option<Vec<CdxProperty>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxLicenseChoice {
    license: Option<CdxLicense>,
    expression: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct CdxLicense {
    id: Option<String>,
    name: Option<String>,
    url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct CdxSupplier {
    name: String,
    url: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxHash {
    alg: String,
    content: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct CdxExternalReference {
    #[serde(rename = "type")]
    ref_type: String,
    url: String,
    comment: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxProperty {
    name: String,
    value: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxDependency {
    #[serde(rename = "ref")]
    ref_field: String,
    depends_on: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxVulnerability {
    id: String,
    source: Option<CdxVulnSource>,
    description: Option<String>,
    recommendation: Option<String>,
    ratings: Option<Vec<CdxRating>>,
    cwes: Option<Vec<u32>>,
    affects: Option<Vec<CdxAffects>>,
    analysis: Option<CdxAnalysis>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct CdxVulnSource {
    name: String,
    url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxRating {
    score: Option<f32>,
    severity: Option<String>,
    method: Option<String>,
    vector: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxAffects {
    #[serde(rename = "ref")]
    ref_field: String,
    versions: Option<Vec<CdxVersionAffected>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct CdxVersionAffected {
    version: Option<String>,
    range: Option<String>,
    status: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxAnalysis {
    state: Option<String>,
    justification: Option<String>,
    response: Option<Vec<String>>,
    detail: Option<String>,
}

// =============================================================================
// CycloneDX XML structures for deserialization
// XML uses wrapper elements for collections (e.g., <components><component>...)
// =============================================================================

/// Root BOM element for XML format
#[derive(Debug, Deserialize)]
#[serde(rename = "bom")]
struct CycloneDxBomXml {
    /// Version attribute on bom element (e.g., version="1.5")
    #[serde(rename = "@version")]
    version: Option<String>,
    /// Serial number attribute
    #[serde(rename = "@serialNumber")]
    serial_number: Option<String>,
    /// BOM version (integer)
    #[serde(rename = "@bomVersion")]
    bom_version: Option<u32>,
    /// Metadata element
    metadata: Option<CdxMetadataXml>,
    /// Components wrapper element
    components: Option<CdxComponentsXml>,
    /// Dependencies wrapper element
    dependencies: Option<CdxDependenciesXml>,
    /// Vulnerabilities wrapper element
    vulnerabilities: Option<CdxVulnerabilitiesXml>,
}

/// Metadata element for XML format
#[derive(Debug, Deserialize)]
struct CdxMetadataXml {
    timestamp: Option<String>,
    tools: Option<CdxToolsXml>,
    component: Option<CdxComponent>,
}

/// Tools wrapper element for XML format
#[derive(Debug, Deserialize)]
struct CdxToolsXml {
    #[serde(rename = "tool", default)]
    tool: Vec<CdxTool>,
}

/// Components wrapper element for XML format
#[derive(Debug, Deserialize)]
struct CdxComponentsXml {
    #[serde(rename = "component", default)]
    component: Vec<CdxComponent>,
}

/// Component element for XML format (reuses JSON struct with additional XML attributes)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct CdxComponentXml {
    /// Type attribute (e.g., type="library")
    #[serde(rename = "@type")]
    component_type: String,
    /// bom-ref attribute
    #[serde(rename = "@bom-ref")]
    bom_ref: Option<String>,
    name: String,
    version: Option<String>,
    group: Option<String>,
    purl: Option<String>,
    cpe: Option<String>,
    description: Option<String>,
    author: Option<String>,
    copyright: Option<String>,
    licenses: Option<CdxLicensesXml>,
    supplier: Option<CdxSupplier>,
    hashes: Option<CdxHashesXml>,
    #[serde(rename = "externalReferences")]
    external_references: Option<CdxExternalReferencesXml>,
    properties: Option<CdxPropertiesXml>,
}

/// Licenses wrapper element for XML format
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CdxLicensesXml {
    #[serde(rename = "$value", default)]
    licenses: Vec<CdxLicenseChoiceXml>,
}

/// License choice for XML format (can be license or expression element)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct CdxLicenseChoiceXml {
    license: Option<CdxLicense>,
    expression: Option<String>,
}

/// Hashes wrapper element for XML format
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CdxHashesXml {
    #[serde(rename = "hash", default)]
    hash: Vec<CdxHashXml>,
}

/// Hash element for XML format
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CdxHashXml {
    #[serde(rename = "@alg")]
    alg: String,
    #[serde(rename = "$value")]
    content: String,
}

/// External references wrapper element for XML format
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CdxExternalReferencesXml {
    #[serde(rename = "reference", default)]
    reference: Vec<CdxExternalReferenceXml>,
}

/// External reference element for XML format
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CdxExternalReferenceXml {
    #[serde(rename = "@type")]
    ref_type: String,
    url: String,
    comment: Option<String>,
}

/// Properties wrapper element for XML format
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CdxPropertiesXml {
    #[serde(rename = "property", default)]
    property: Vec<CdxPropertyXml>,
}

/// Property element for XML format
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CdxPropertyXml {
    #[serde(rename = "@name")]
    name: String,
    #[serde(rename = "$value")]
    value: String,
}

/// Dependencies wrapper element for XML format
#[derive(Debug, Deserialize)]
struct CdxDependenciesXml {
    #[serde(rename = "dependency", default)]
    dependency: Vec<CdxDependency>,
}

/// Dependency element for XML format
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CdxDependencyXml {
    #[serde(rename = "@ref")]
    ref_field: String,
    #[serde(rename = "dependency", default)]
    depends_on: Vec<CdxDependencyRefXml>,
}

/// Dependency reference for XML nested dependencies
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CdxDependencyRefXml {
    #[serde(rename = "@ref")]
    ref_field: String,
}

/// Vulnerabilities wrapper element for XML format
#[derive(Debug, Deserialize)]
struct CdxVulnerabilitiesXml {
    #[serde(rename = "vulnerability", default)]
    vulnerability: Vec<CdxVulnerability>,
}
