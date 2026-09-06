//! `CycloneDX` SBOM parser.
//!
//! Supports `CycloneDX` versions 1.4, 1.5, 1.6, and 1.7 in JSON and XML formats.

use crate::model::{
    AffirmationSignatory, AttestationAssertion, AttestationDeclarations, AttestationMapEntry,
    CdxaRef, CdxaResolution, Contact, DeclarationTarget, DeclarationTargets, DeclaredAffirmation,
    DeclaredAssessor, DeclaredClaim, DeclaredEvidence, DefinedRequirement, DefinedStandard,
    EvidenceDataItem, SignaturePresence,
};
use crate::model::{
    AlgorithmProperties, CanonicalId, CertificateProperties, CertificationLevel, CipherSuite,
    CompletenessDeclaration, Component, ComponentType, Creator, CreatorType, CryptoAssetType,
    CryptoFunction, CryptoMaterialState, CryptoMaterialType, CryptoMode, CryptoPadding,
    CryptoPrimitive, CryptoProperties, CvssScore, CvssVersion, DependencyEdge, DependencyScope,
    DependencyType, DocumentMetadata, ExecutionEnvironment, ExternalRefType, ExternalReference,
    Hash, HashAlgorithm, Ikev2TransformTypes, ImplementationPlatform, LicenseExpression,
    NormalizedSbom, Organization, Property, ProtocolProperties, ProtocolType,
    RelatedCryptoMaterialProperties, Remediation, RemediationType, SbomFormat, SecuredBy, Severity,
    SignatureInfo, VexJustification, VexResponse, VexState, VexStatus, VulnerabilityRef,
    VulnerabilitySource,
};
use crate::parsers::traits::{ParseError, SbomParser};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};

/// Parser for `CycloneDX` SBOM format
#[allow(dead_code)]
pub struct CycloneDxParser {
    /// Whether to validate strictly
    strict: bool,
}

impl CycloneDxParser {
    /// Create a new `CycloneDX` parser
    #[must_use]
    pub const fn new() -> Self {
        Self { strict: false }
    }

    /// Create a strict parser that validates more thoroughly
    #[must_use]
    pub const fn strict() -> Self {
        Self { strict: true }
    }

    /// Parse a `CycloneDX` BOM from JSON
    fn parse_json(&self, content: &str) -> Result<NormalizedSbom, ParseError> {
        let cdx: CycloneDxBom =
            serde_json::from_str(content).map_err(|e| ParseError::JsonError(e.to_string()))?;

        Ok(self.convert_to_normalized(cdx))
    }

    /// Parse a `CycloneDX` BOM from a JSON reader (streaming - doesn't buffer entire file)
    pub fn parse_json_reader<R: std::io::Read>(
        &self,
        reader: R,
    ) -> Result<NormalizedSbom, ParseError> {
        let cdx: CycloneDxBom =
            serde_json::from_reader(reader).map_err(|e| ParseError::JsonError(e.to_string()))?;

        Ok(self.convert_to_normalized(cdx))
    }

    /// Parse a `CycloneDX` BOM from XML
    fn parse_xml(&self, content: &str) -> Result<NormalizedSbom, ParseError> {
        // The component/service XML models are recursive (nested
        // assemblies), and quick-xml's serde deserializer recurses with
        // no depth limit — without this bound a crafted deeply-nested
        // document aborts the process by stack overflow instead of
        // returning an error. serde_json caps the JSON path at ~128
        // levels; enforce the equivalent here with an iterative pre-scan.
        xml_depth_within_limit(content)?;
        let cdx: CycloneDxBomXml =
            quick_xml::de::from_str(content).map_err(|e| ParseError::XmlError(e.to_string()))?;

        // Convert XML structure to common BOM structure
        let bom = CycloneDxBom {
            bom_format: Some("CycloneDX".to_string()),
            spec_version: xml_spec_version(cdx.xmlns.as_deref(), cdx.version.as_deref()),
            serial_number: cdx.serial_number,
            version: cdx.version.as_deref().and_then(|v| v.parse().ok()),
            metadata: cdx.metadata.map(|m| CdxMetadata {
                timestamp: m.timestamp,
                tools: m.tools.map(|t| t.tool),
                authors: None,
                manufacturer: None,
                manufacture: None,
                component: m.component.map(Into::into),
                lifecycles: None,
                distribution_constraints: None,
            }),
            components: cdx
                .components
                .map(|c| c.component.into_iter().map(Into::into).collect()),
            services: cdx
                .services
                .map(|s| s.service.into_iter().map(Into::into).collect()),
            dependencies: cdx
                .dependencies
                .map(|d| d.dependency.into_iter().map(Into::into).collect()),
            vulnerabilities: cdx
                .vulnerabilities
                .map(|v| v.vulnerability.into_iter().map(Into::into).collect()),
            compositions: None,
            signature: None,
            citations: None,
            // CDXA declarations exist in the 1.6 XML schema too, but their
            // XML normalization is deferred: phase 1 ingests JSON only.
            declarations: None,
            definitions: None,
        };

        Ok(self.convert_to_normalized(bom))
    }

    /// Convert `CycloneDX` BOM to normalized representation
    fn convert_to_normalized(&self, mut cdx: CycloneDxBom) -> NormalizedSbom {
        let document = self.convert_metadata(&cdx);
        let mut sbom = NormalizedSbom::new(document);

        // Convert components
        let mut id_map: HashMap<String, CanonicalId> = HashMap::new();
        // Secondary ref-resolution keys: real-world emitters frequently use a
        // component's purl (not its bom-ref) in dependencies[].ref/dependsOn
        // and vulnerabilities[].affects[].ref — especially when components
        // declare no bom-ref at all. Collected during the component walk and
        // merged into `id_map` afterwards so genuine bom-refs always win.
        let mut purl_fallbacks: Vec<(String, CanonicalId)> = Vec::new();

        // Nested assemblies of the primary component join the component
        // walk below, parented to it.
        let meta_children = cdx
            .metadata
            .as_mut()
            .and_then(|m| m.component.as_mut())
            .and_then(|c| c.components.take());
        let mut primary_id: Option<CanonicalId> = None;

        // Handle metadata.component as primary/root product component (CRA requirement)
        if let Some(meta) = &cdx.metadata
            && let Some(meta_comp) = &meta.component
        {
            let comp = self.convert_component(meta_comp);
            let bom_ref = meta_comp
                .bom_ref
                .clone()
                .unwrap_or_else(|| comp.name.clone());
            let canonical_id = comp.canonical_id.clone();
            id_map.insert(bom_ref, canonical_id.clone());
            if let Some(purl) = &meta_comp.purl {
                purl_fallbacks.push((purl.clone(), canonical_id.clone()));
            }
            primary_id = Some(canonical_id.clone());

            // Set as primary component
            sbom.set_primary_component(canonical_id);

            // Extract security contact from primary component's external references
            for ext_ref in &comp.external_refs {
                match ext_ref.ref_type {
                    ExternalRefType::SecurityContact => {
                        sbom.document.security_contact = Some(ext_ref.url.clone());
                    }
                    ExternalRefType::Advisories | ExternalRefType::Support
                        if sbom.document.vulnerability_disclosure_url.is_none() =>
                    {
                        sbom.document.vulnerability_disclosure_url = Some(ext_ref.url.clone());
                    }
                    _ => {}
                }
            }

            // Extract support_end_date from primary component properties
            if let Some(props) = &meta_comp.properties {
                for prop in props {
                    // `name`/`value` are optional in the schema; entries
                    // missing either cannot carry a support-end date.
                    let (Some(name), Some(value)) = (&prop.name, &prop.value) else {
                        continue;
                    };
                    let name_lower = name.to_lowercase();
                    if name_lower.contains("endofsupport")
                        || name_lower.contains("end-of-support")
                        || name_lower.contains("eol")
                        || name_lower.contains("supportend")
                        || name_lower.contains("support_end")
                    {
                        if let Ok(dt) = DateTime::parse_from_rfc3339(value) {
                            sbom.document.support_end_date = Some(dt.with_timezone(&Utc));
                        } else if let Ok(dt) = chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d")
                        {
                            sbom.document.support_end_date = Some(
                                dt.and_hms_opt(0, 0, 0)
                                    .expect("midnight is always valid")
                                    .and_utc(),
                            );
                        }
                    }
                }
            }

            sbom.add_component(comp);
        }

        // Build scope map from bom-ref to DependencyScope
        let mut scope_map: HashMap<String, DependencyScope> = HashMap::new();

        // Convert components, walking nested assemblies (component.components)
        // with an explicit worklist: nested components are real inventory and
        // their bom-refs participate in dependencies and vulnerability
        // affects — dropping them undercounted the SBOM and silently
        // discarded the edges and vulns that referenced them. Iteration is
        // bounded by element count (no recursion, so hostile nesting depth
        // cannot overflow the stack). Each entry carries its container's id
        // so the assembly hierarchy is preserved as Contains edges.
        let mut comp_stack: Vec<(Option<CanonicalId>, CdxComponent)> = Vec::new();
        if let Some(components) = cdx.components.take() {
            for c in components.into_iter().rev() {
                comp_stack.push((None, c));
            }
        }
        if let Some(children) = meta_children {
            for child in children.into_iter().rev() {
                comp_stack.push((primary_id.clone(), child));
            }
        }
        while let Some((parent, mut cdx_comp)) = comp_stack.pop() {
            let children = cdx_comp.components.take();
            let comp = self.convert_component(&cdx_comp);
            let bom_ref = cdx_comp
                .bom_ref
                .clone()
                .unwrap_or_else(|| comp.name.clone());
            if let Some(scope_str) = &cdx_comp.scope {
                let scope = match scope_str.to_lowercase().as_str() {
                    "optional" => DependencyScope::Optional,
                    "excluded" => DependencyScope::Excluded,
                    _ => DependencyScope::Required,
                };
                scope_map.insert(bom_ref.clone(), scope);
            }
            let canonical_id = comp.canonical_id.clone();
            id_map.insert(bom_ref, canonical_id.clone());
            if let Some(purl) = &cdx_comp.purl {
                purl_fallbacks.push((purl.clone(), canonical_id.clone()));
            }
            if let Some(parent_id) = parent {
                sbom.add_edge(DependencyEdge::new(
                    parent_id,
                    canonical_id.clone(),
                    DependencyType::Contains,
                ));
            }
            sbom.add_component(comp);
            for child in children.into_iter().flatten().rev() {
                comp_stack.push((Some(canonical_id.clone()), child));
            }
        }

        // Convert services (SaaSBOM, 1.4+): they carry bom-refs that
        // participate in dependencies and vulnerability affects, so they
        // must join the inventory and id_map like components. Nested
        // services walk the same worklist pattern.
        let mut svc_stack: Vec<(Option<CanonicalId>, CdxService)> = Vec::new();
        if let Some(services) = cdx.services.take() {
            for s in services.into_iter().rev() {
                svc_stack.push((None, s));
            }
        }
        while let Some((parent, mut svc)) = svc_stack.pop() {
            let children = svc.services.take();
            let comp = self.convert_service(&svc);
            let bom_ref = svc.bom_ref.clone().unwrap_or_else(|| comp.name.clone());
            let canonical_id = comp.canonical_id.clone();
            id_map.insert(bom_ref, canonical_id.clone());
            if let Some(parent_id) = parent {
                sbom.add_edge(DependencyEdge::new(
                    parent_id,
                    canonical_id.clone(),
                    DependencyType::Contains,
                ));
            }
            sbom.add_component(comp);
            for child in children.into_iter().flatten().rev() {
                svc_stack.push((Some(canonical_id.clone()), child));
            }
        }

        // Merge purl fallback keys now that every bom-ref is registered:
        // a purl key must never shadow a real bom-ref, and the earliest
        // component wins among purl duplicates (deterministic walk order).
        for (purl, cid) in purl_fallbacks {
            id_map.entry(purl).or_insert(cid);
        }

        // CDXA (CycloneDX 1.6+): normalize `declarations` and
        // `definitions.standards` into the typed attestation-evidence model.
        // Gated on specVersion >= 1.6 — CDXA was introduced in 1.6 and
        // parsers must not probe for it on earlier documents (its absence is
        // never a violation; attestation evidence is additive). Runs after
        // the purl-fallback merge so claim targets resolve through the same
        // id_map as dependencies and vulnerability affects. Documents
        // without these sections keep `extensions.declarations = None`, so
        // their serialized output is unchanged.
        if cdx_supports_cdxa(&cdx.spec_version)
            && (cdx.declarations.is_some()
                || cdx
                    .definitions
                    .as_ref()
                    .is_some_and(|d| d.standards.as_ref().is_some_and(|s| !s.is_empty())))
        {
            sbom.extensions.declarations = Some(convert_declarations(
                cdx.declarations.take(),
                cdx.definitions.take(),
                &id_map,
            ));
        }

        // Convert dependencies, attaching scope from component metadata
        if let Some(deps) = cdx.dependencies {
            for dep in deps {
                if let Some(from_id) = id_map.get(&dep.ref_field) {
                    // CycloneDX: an entry with an empty dependsOn positively
                    // asserts "this component has no dependencies". Preserve
                    // that assertion so graph-completeness checks don't
                    // mistake it for a missing relationship.
                    let declared_empty = dep.depends_on.as_ref().is_none_or(Vec::is_empty)
                        && dep.provides.as_ref().is_none_or(Vec::is_empty);
                    if declared_empty && let Some(comp) = sbom.components.get_mut(from_id) {
                        comp.extensions.properties.push(crate::model::Property {
                            name: super::DECLARED_NO_DEPENDENCIES_PROPERTY.to_string(),
                            value: "true".to_string(),
                        });
                    }
                    for depends_on in dep.depends_on.unwrap_or_default() {
                        if let Some(to_id) = id_map.get(&depends_on) {
                            // Infer relationship type from scope when available.
                            // CycloneDX scope "optional" → OptionalDependsOn,
                            // "excluded" → DependsOn (kept as marker via scope field).
                            let dep_type = scope_map.get(&depends_on).map_or(
                                DependencyType::DependsOn,
                                |scope| match scope {
                                    DependencyScope::Optional => DependencyType::OptionalDependsOn,
                                    _ => DependencyType::DependsOn,
                                },
                            );
                            let mut edge =
                                DependencyEdge::new(from_id.clone(), to_id.clone(), dep_type);
                            if let Some(scope) = scope_map.get(&depends_on) {
                                edge = edge.with_scope(scope.clone());
                            }
                            sbom.add_edge(edge);
                        }
                    }
                    // CycloneDX 1.7: "provides" — library implements/contains crypto assets
                    for provided in dep.provides.unwrap_or_default() {
                        if let Some(to_id) = id_map.get(&provided) {
                            sbom.add_edge(DependencyEdge::new(
                                from_id.clone(),
                                to_id.clone(),
                                DependencyType::Provides,
                            ));
                        }
                    }
                }
            }
        }

        // Convert vulnerabilities
        if let Some(vulns) = cdx.vulnerabilities {
            for (index, vuln) in vulns.iter().enumerate() {
                self.apply_vulnerability(&mut sbom, vuln, index, &id_map);
            }
            // Vulnerabilities and VEX were attached AFTER component
            // conversion computed each content hash; recompute the affected
            // hashes so vulnerability content is reflected in them (and in
            // the SBOM hash derived from them below). Without this,
            // vulnerability-only changes were invisible to the diff's
            // modified-component gate and the incremental cache key.
            for comp in sbom.components.values_mut() {
                if !comp.vulnerabilities.is_empty() || comp.vex_status.is_some() {
                    comp.calculate_content_hash();
                }
            }
        }

        // Store citations in format extensions for lossless preservation (1.7+)
        if let Some(citations) = &cdx.citations
            && !citations.is_empty()
            && let Ok(citations_json) = serde_json::to_value(
                citations
                    .iter()
                    .map(|c| {
                        serde_json::json!({
                            "timestamp": c.timestamp,
                            "attributedTo": c.attributed_to,
                            "process": c.process,
                            "note": c.note,
                            "pointers": c.pointers,
                            "expressions": c.expressions,
                        })
                    })
                    .collect::<Vec<_>>(),
            )
        {
            sbom.extensions.cyclonedx = Some(serde_json::json!({ "citations": citations_json }));
        }

        sbom.calculate_content_hash();
        sbom
    }

    /// Convert `CycloneDX` metadata to `DocumentMetadata`
    fn convert_metadata(&self, cdx: &CycloneDxBom) -> DocumentMetadata {
        let created = cdx
            .metadata
            .as_ref()
            .and_then(|m| m.timestamp.as_ref())
            .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
            // Deterministic fallback: a document with a missing/invalid
            // timestamp must hash identically on every parse (created is
            // folded into the content hash; Utc::now() here made every
            // parse of such a document content-unique, defeating diff
            // identity and the incremental cache). Epoch is an honest
            // "unknown" sentinel rather than a fabricated parse time.
            .map_or(DateTime::UNIX_EPOCH, |dt| dt.with_timezone(&Utc));

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
            // metadata.authors are the people/orgs responsible for the document.
            // Preserve them as Person creators so document-level author changes
            // surface in the diff (previously these were parsed but dropped).
            if let Some(authors) = &meta.authors {
                for author in authors {
                    let name = author
                        .name
                        .clone()
                        .or_else(|| author.email.clone())
                        .unwrap_or_else(|| "unknown".to_string());
                    creators.push(Creator {
                        creator_type: CreatorType::Person,
                        name,
                        email: author.email.clone(),
                    });
                }
            }
            // metadata.manufacturer (1.5+; deprecated pre-1.6 spelling:
            // metadata.manufacture) is the organization that created the BOM
            // — BSI TR-03183-2 v2.1.0 Table 8's canonical CycloneDX mapping
            // for the required "Creator of the SBOM". Map it to an
            // Organization creator; previously it was silently dropped, so
            // documents expressing their creator exactly as the TR
            // prescribes false-failed the §5.2.1 gate.
            if let Some(manufacturer) = meta.manufacturer.as_ref().or(meta.manufacture.as_ref()) {
                let email = manufacturer
                    .contact
                    .as_ref()
                    .and_then(|cs| cs.iter().find_map(|c| c.email.clone()));
                let mut name = manufacturer
                    .name
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string());
                // Creators carry no URL field: when no contact email exists,
                // fold the first URL into the name so the TR's email-or-URL
                // fallback stays discernible downstream (BSI §5.2.1 contact
                // detection looks for "://" in the creator name).
                if email.is_none()
                    && let Some(url) = manufacturer
                        .url
                        .as_ref()
                        .and_then(|urls| urls.iter().find(|u| !u.is_empty()))
                {
                    name = format!("{name} ({url})");
                }
                creators.push(Creator {
                    creator_type: CreatorType::Organization,
                    name,
                    email,
                });
            }
        }

        // Extract lifecycle phase from CycloneDX 1.5+ metadata
        let lifecycle_phase = cdx
            .metadata
            .as_ref()
            .and_then(|m| m.lifecycles.as_ref())
            .and_then(|lcs| lcs.first())
            .and_then(|lc| lc.phase.clone().or_else(|| lc.name.clone()));

        // Extract completeness declaration from compositions
        let completeness_declaration = cdx
            .compositions
            .as_ref()
            .and_then(|comps| comps.first())
            .and_then(|comp| comp.aggregate.as_deref())
            .map_or(CompletenessDeclaration::Unknown, |agg| match agg {
                "complete" => CompletenessDeclaration::Complete,
                "incomplete" => CompletenessDeclaration::Incomplete,
                "incomplete_first_party_only" => CompletenessDeclaration::IncompleteFirstPartyOnly,
                "incomplete_third_party_only" => CompletenessDeclaration::IncompleteThirdPartyOnly,
                "unknown" => CompletenessDeclaration::Unknown,
                "not_specified" => CompletenessDeclaration::NotSpecified,
                _ => CompletenessDeclaration::Unknown,
            });

        // Extract signature info
        let signature = cdx.signature.as_ref().map(|sig| SignatureInfo {
            algorithm: sig
                .algorithm
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            has_value: sig.value.as_ref().is_some_and(|v| !v.is_empty()),
        });

        // Extract distribution classification from 1.7+ metadata
        let distribution_classification = cdx
            .metadata
            .as_ref()
            .and_then(|m| m.distribution_constraints.as_ref())
            .and_then(|dc| dc.tlp.clone());

        // Count citations for provenance tracking (1.7+)
        let citations_count = cdx.citations.as_ref().map_or(0, Vec::len);

        DocumentMetadata {
            format: SbomFormat::CycloneDx,
            format_version: cdx.spec_version.clone(),
            spec_version: cdx.spec_version.clone(),
            serial_number: cdx.serial_number.clone(),
            // Top-level `version`: the BOM revision counter (defaults to 1 in
            // the spec, but absence is preserved as None rather than invented).
            doc_version: cdx.version,
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
            lifecycle_phase,
            completeness_declaration,
            signature,
            distribution_classification,
            citations_count,
        }
    }

    /// Convert a `CycloneDX` component to normalized Component
    fn convert_component(&self, cdx: &CdxComponent) -> Component {
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
            "platform" => ComponentType::Platform,
            "device-driver" => ComponentType::DeviceDriver,
            "cryptographic" | "cryptographic-asset" => ComponentType::Cryptographic,
            other => ComponentType::Other(other.to_string()),
        };

        // Set CPEs
        if let Some(cpe) = &cdx.cpe {
            comp.identifiers.cpe.push(cpe.clone());
        }

        // Set SWHIDs (CycloneDX 1.6+, CRA [PRE-7-RQ-07])
        for swhid in &cdx.swhid {
            comp = comp.with_swhid(swhid.clone());
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

        // Set supplier. organizationalEntity has no required fields, so a
        // supplier may carry only a URL — fall back to it as the name
        // rather than failing or dropping the organization.
        if let Some(supplier) = &cdx.supplier
            && let Some(name) = supplier
                .name
                .clone()
                .or_else(|| supplier.url.as_ref().and_then(|u| u.first().cloned()))
        {
            comp.supplier = Some(Organization::new(name));
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
                    "STREEBOG-256" => HashAlgorithm::Streebog256,
                    "STREEBOG-512" => HashAlgorithm::Streebog512,
                    other => HashAlgorithm::Other(other.to_string()),
                };
                comp.hashes.push(Hash::new(algorithm, h.content.clone()));
            }
        }

        // Set external references
        if let Some(ext_refs) = &cdx.external_references {
            for ext_ref in ext_refs {
                comp.external_refs.push(ExternalReference {
                    ref_type: map_cdx_external_ref_type(&ext_ref.ref_type),
                    url: ext_ref.url.clone(),
                    comment: ext_ref.comment.clone(),
                    hashes: Vec::new(),
                });
            }
        }

        // Set properties as extensions. Both fields are optional in the
        // schema: value-less properties keep their name; name-less ones
        // are unaddressable and skipped.
        if let Some(props) = &cdx.properties {
            for prop in props {
                let Some(name) = prop.name.clone() else {
                    continue;
                };
                comp.extensions.properties.push(Property {
                    name,
                    value: prop.value.clone().unwrap_or_default(),
                });
            }
        }

        // Set description
        comp.description.clone_from(&cdx.description);
        comp.group.clone_from(&cdx.group);
        comp.author.clone_from(&cdx.author);
        comp.copyright.clone_from(&cdx.copyright);

        // Set 1.7+ fields
        comp.is_external = cdx.is_external;
        comp.version_range.clone_from(&cdx.version_range);

        // Set ML model metadata (CycloneDX 1.5+)
        if let Some(model_card) = &cdx.model_card {
            let mut ml_info = crate::model::MlModelInfo::default();

            // Per the CycloneDX 1.6 schema, `approach`, `architectureFamily`,
            // `modelArchitecture`, `task` and `datasets` all live under `modelParameters`.
            if let Some(model_params) = &model_card.model_parameters {
                if let Some(approach) = &model_params.approach {
                    ml_info.approach = approach.approach_type.clone();
                }
                ml_info.architecture_family = model_params.architecture_family.clone();
                ml_info.task = model_params.task.clone();

                // Spec: `modelArchitecture` is a string; fall back to the non-spec
                // `architecture.name` object only if the string form is absent.
                ml_info.architecture_name = model_params.model_architecture.clone().or_else(|| {
                    model_params
                        .architecture
                        .as_ref()
                        .and_then(|arch| arch.name.clone())
                });

                for dataset in &model_params.datasets {
                    ml_info.training_datasets.push(dataset.to_model());
                }
            }

            // `quantization` has no home in the CycloneDX 1.6 modelCard schema, so it is
            // intentionally not parsed (left as None) rather than read from a non-existent field.

            if let Some(considerations) = &model_card.considerations {
                // Spec: limitations live in `considerations.technicalLimitations` (array).
                if !considerations.technical_limitations.is_empty() {
                    ml_info.limitations = Some(considerations.technical_limitations.join("; "));
                }

                if let Some(env_considerations) = &considerations.environmental_considerations {
                    let total_training_energy: f64 = env_considerations
                        .energy_consumptions
                        .iter()
                        .filter(|energy| energy.activity.as_deref() == Some("training"))
                        .filter_map(CdxEnergyConsumption::training_energy_kwh)
                        .sum();

                    if total_training_energy > 0.0 {
                        ml_info.energy_kwh_training = Some(total_training_energy);
                    }
                }

                ml_info.fairness = considerations
                    .fairness_assessments
                    .iter()
                    .map(CdxFairnessAssessment::to_model)
                    .collect();
                ml_info.ethical_considerations = considerations
                    .ethical_considerations
                    .iter()
                    .map(CdxEthicalConsideration::to_model)
                    .collect();
                ml_info.use_cases.clone_from(&considerations.use_cases);
            }

            if let Some(quant) = &model_card.quantitative_analysis {
                ml_info.performance_metrics = quant
                    .performance_metrics
                    .iter()
                    .map(CdxPerformanceMetric::to_model)
                    .collect();
            }

            // Extract model card URL from external references
            for ext_ref in &comp.external_refs {
                if ext_ref.ref_type == ExternalRefType::ModelCard {
                    ml_info.model_card_url = Some(ext_ref.url.clone());
                    break;
                }
            }

            comp.ml_model = Some(ml_info);
        }

        // Set dataset metadata (CycloneDX 1.5+). Per spec `component.data` is an array of
        // componentData; a `data` component is represented by its first entry.
        if let Some(data_component) = cdx.data_components.first() {
            let governance_owners =
                data_component
                    .governance
                    .as_ref()
                    .map_or_else(Vec::new, |governance| {
                        governance
                            .owners
                            .iter()
                            .chain(governance.custodians.iter())
                            .chain(governance.stewards.iter())
                            .filter_map(CdxGovParty::display_name)
                            .collect()
                    });

            comp.dataset = Some(crate::model::DatasetInfo {
                dataset_type: data_component.data_type.clone(),
                sensitivity_classifications: data_component.sensitivity_data.clone(),
                governance_owners,
                // intended_use / confidentiality_level / preprocessing /
                // anonymization have no CycloneDX `componentData` analogue; they
                // are SPDX-3.0-only and left unset here.
                ..Default::default()
            });
        }

        // Set cryptographic properties (1.6+)
        if let Some(cdx_crypto) = &cdx.crypto_properties {
            comp.crypto_properties = Some(Self::convert_crypto_properties(cdx_crypto));
        }

        comp.calculate_content_hash();
        comp
    }

    /// Convert CycloneDX crypto properties to canonical model.
    fn convert_crypto_properties(cdx: &CdxCryptoProperties) -> CryptoProperties {
        let asset_type =
            cdx.asset_type
                .as_deref()
                .map_or(CryptoAssetType::Other("unknown".to_string()), |s| match s {
                    "algorithm" => CryptoAssetType::Algorithm,
                    "certificate" => CryptoAssetType::Certificate,
                    "related-crypto-material" => CryptoAssetType::RelatedCryptoMaterial,
                    "protocol" => CryptoAssetType::Protocol,
                    other => CryptoAssetType::Other(other.to_string()),
                });

        let mut props = CryptoProperties::new(asset_type);
        props.oid.clone_from(&cdx.oid);

        if let Some(algo) = &cdx.algorithm_properties {
            props.algorithm_properties = Some(Self::convert_algorithm_properties(algo));
        }
        if let Some(cert) = &cdx.certificate_properties {
            props.certificate_properties = Some(Self::convert_certificate_properties(cert));
        }
        if let Some(mat) = &cdx.related_crypto_material_properties {
            props.related_crypto_material_properties =
                Some(Self::convert_related_crypto_material_properties(mat));
        }
        if let Some(proto) = &cdx.protocol_properties {
            props.protocol_properties = Some(Self::convert_protocol_properties(proto));
        }

        props
    }

    fn convert_algorithm_properties(cdx: &CdxAlgorithmProperties) -> AlgorithmProperties {
        let primitive = cdx
            .primitive
            .as_deref()
            .map_or(CryptoPrimitive::Unknown, |s| match s {
                "ae" => CryptoPrimitive::Ae,
                "block-cipher" => CryptoPrimitive::BlockCipher,
                "stream-cipher" => CryptoPrimitive::StreamCipher,
                "hash" => CryptoPrimitive::Hash,
                "mac" => CryptoPrimitive::Mac,
                "signature" => CryptoPrimitive::Signature,
                "pke" => CryptoPrimitive::Pke,
                "kem" => CryptoPrimitive::Kem,
                "kdf" => CryptoPrimitive::Kdf,
                "key-agree" => CryptoPrimitive::KeyAgree,
                "xof" => CryptoPrimitive::Xof,
                "drbg" => CryptoPrimitive::Drbg,
                "combiner" => CryptoPrimitive::Combiner,
                "unknown" => CryptoPrimitive::Unknown,
                other => CryptoPrimitive::Other(other.to_string()),
            });

        let mut algo = AlgorithmProperties::new(primitive);
        algo.algorithm_family.clone_from(&cdx.algorithm_family);
        algo.parameter_set_identifier
            .clone_from(&cdx.parameter_set_identifier);
        algo.classical_security_level = cdx.classical_security_level;
        algo.nist_quantum_security_level = cdx.nist_quantum_security_level;
        algo.elliptic_curve.clone_from(&cdx.elliptic_curve);

        if let Some(mode) = cdx.mode.as_deref() {
            algo.mode = Some(match mode {
                "ecb" => CryptoMode::Ecb,
                "cbc" => CryptoMode::Cbc,
                "ofb" => CryptoMode::Ofb,
                "cfb" => CryptoMode::Cfb,
                "ctr" => CryptoMode::Ctr,
                "gcm" => CryptoMode::Gcm,
                "ccm" => CryptoMode::Ccm,
                "xts" => CryptoMode::Xts,
                other => CryptoMode::Other(other.to_string()),
            });
        }

        if let Some(padding) = cdx.padding.as_deref() {
            algo.padding = Some(match padding {
                "pkcs5" => CryptoPadding::Pkcs5,
                "oaep" => CryptoPadding::Oaep,
                "pss" => CryptoPadding::Pss,
                other => CryptoPadding::Other(other.to_string()),
            });
        }

        if let Some(funcs) = &cdx.crypto_functions {
            algo.crypto_functions = funcs
                .iter()
                .map(|s| match s.as_str() {
                    "keygen" => CryptoFunction::Keygen,
                    "encrypt" => CryptoFunction::Encrypt,
                    "decrypt" => CryptoFunction::Decrypt,
                    "sign" => CryptoFunction::Sign,
                    "verify" => CryptoFunction::Verify,
                    "digest" => CryptoFunction::Digest,
                    "tag" => CryptoFunction::Tag,
                    "keyderive" => CryptoFunction::KeyDerive,
                    "encapsulate" => CryptoFunction::Encapsulate,
                    "decapsulate" => CryptoFunction::Decapsulate,
                    "wrap" => CryptoFunction::Wrap,
                    "unwrap" => CryptoFunction::Unwrap,
                    other => CryptoFunction::Other(other.to_string()),
                })
                .collect();
        }

        if let Some(env) = cdx.execution_environment.as_deref() {
            algo.execution_environment = Some(match env {
                "software-plain-ram" => ExecutionEnvironment::SoftwarePlainRam,
                "software-encrypted-ram" => ExecutionEnvironment::SoftwareEncryptedRam,
                "software-tee" => ExecutionEnvironment::SoftwareTee,
                "hardware" => ExecutionEnvironment::Hardware,
                other => ExecutionEnvironment::Other(other.to_string()),
            });
        }

        if let Some(platform) = cdx.implementation_platform.as_deref() {
            algo.implementation_platform = Some(match platform {
                "x86_32" => ImplementationPlatform::X86_32,
                "x86_64" => ImplementationPlatform::X86_64,
                "armv7-a" => ImplementationPlatform::Armv7A,
                "armv7-m" => ImplementationPlatform::Armv7M,
                "armv8-a" => ImplementationPlatform::Armv8A,
                "s390x" => ImplementationPlatform::S390x,
                "generic" => ImplementationPlatform::Generic,
                other => ImplementationPlatform::Other(other.to_string()),
            });
        }

        if let Some(levels) = &cdx.certification_level {
            algo.certification_level = levels
                .iter()
                .map(|s| match s.as_str() {
                    "none" => CertificationLevel::None,
                    "fips140-1-l1" => CertificationLevel::Fips140_1L1,
                    "fips140-1-l2" => CertificationLevel::Fips140_1L2,
                    "fips140-1-l3" => CertificationLevel::Fips140_1L3,
                    "fips140-1-l4" => CertificationLevel::Fips140_1L4,
                    "fips140-2-l1" => CertificationLevel::Fips140_2L1,
                    "fips140-2-l2" => CertificationLevel::Fips140_2L2,
                    "fips140-2-l3" => CertificationLevel::Fips140_2L3,
                    "fips140-2-l4" => CertificationLevel::Fips140_2L4,
                    "fips140-3-l1" => CertificationLevel::Fips140_3L1,
                    "fips140-3-l2" => CertificationLevel::Fips140_3L2,
                    "fips140-3-l3" => CertificationLevel::Fips140_3L3,
                    "fips140-3-l4" => CertificationLevel::Fips140_3L4,
                    "cc-eal1" => CertificationLevel::CcEal1,
                    "cc-eal2" => CertificationLevel::CcEal2,
                    "cc-eal3" => CertificationLevel::CcEal3,
                    "cc-eal4" => CertificationLevel::CcEal4,
                    "cc-eal5" => CertificationLevel::CcEal5,
                    "cc-eal6" => CertificationLevel::CcEal6,
                    "cc-eal7" => CertificationLevel::CcEal7,
                    other => CertificationLevel::Other(other.to_string()),
                })
                .collect();
        }

        algo
    }

    fn convert_certificate_properties(cdx: &CdxCertificateProperties) -> CertificateProperties {
        let mut cert = CertificateProperties::new();
        cert.subject_name.clone_from(&cdx.subject_name);
        cert.issuer_name.clone_from(&cdx.issuer_name);
        cert.not_valid_before = cdx
            .not_valid_before
            .as_deref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc));
        cert.not_valid_after = cdx
            .not_valid_after
            .as_deref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc));
        cert.signature_algorithm_ref
            .clone_from(&cdx.signature_algorithm_ref);
        cert.subject_public_key_ref
            .clone_from(&cdx.subject_public_key_ref);
        cert.certificate_format.clone_from(&cdx.certificate_format);
        cert.certificate_extension
            .clone_from(&cdx.certificate_extension);
        cert
    }

    fn convert_related_crypto_material_properties(
        cdx: &CdxRelatedCryptoMaterialProperties,
    ) -> RelatedCryptoMaterialProperties {
        let material_type = cdx
            .material_type
            .as_deref()
            .map_or(CryptoMaterialType::Unknown, |s| match s {
                "public-key" => CryptoMaterialType::PublicKey,
                "private-key" => CryptoMaterialType::PrivateKey,
                "symmetric-key" => CryptoMaterialType::SymmetricKey,
                "secret-key" => CryptoMaterialType::SecretKey,
                "key-pair" => CryptoMaterialType::KeyPair,
                "ciphertext" => CryptoMaterialType::Ciphertext,
                "signature" => CryptoMaterialType::Signature,
                "digest" => CryptoMaterialType::Digest,
                "initialization-vector" => CryptoMaterialType::Iv,
                "nonce" => CryptoMaterialType::Nonce,
                "seed" => CryptoMaterialType::Seed,
                "salt" => CryptoMaterialType::Salt,
                "shared-secret" => CryptoMaterialType::SharedSecret,
                "tag" => CryptoMaterialType::Tag,
                "password" => CryptoMaterialType::Password,
                "credential" => CryptoMaterialType::Credential,
                "token" => CryptoMaterialType::Token,
                "unknown" => CryptoMaterialType::Unknown,
                other => CryptoMaterialType::Other(other.to_string()),
            });

        let mut mat = RelatedCryptoMaterialProperties::new(material_type);
        mat.id.clone_from(&cdx.id);
        mat.size = cdx.size;
        mat.algorithm_ref.clone_from(&cdx.algorithm_ref);
        mat.format.clone_from(&cdx.format);

        if let Some(state) = cdx.state.as_deref() {
            // Unknown/unrecognized state stays None: defaulting to Active
            // asserts key material is live/usable, a dangerous claim to
            // fabricate from a typo or hostile value.
            mat.state = match state {
                "pre-activation" => Some(CryptoMaterialState::PreActivation),
                "active" => Some(CryptoMaterialState::Active),
                "suspended" => Some(CryptoMaterialState::Suspended),
                "deactivated" => Some(CryptoMaterialState::Deactivated),
                "compromised" => Some(CryptoMaterialState::Compromised),
                "destroyed" => Some(CryptoMaterialState::Destroyed),
                _ => None,
            };
        }

        if let Some(sb) = &cdx.secured_by {
            mat.secured_by = Some(SecuredBy {
                mechanism: sb.mechanism.clone().unwrap_or_default(),
                algorithm_ref: sb.algorithm_ref.clone(),
            });
        }

        let parse_dt = |s: &Option<String>| -> Option<DateTime<Utc>> {
            s.as_deref()
                .and_then(|v| DateTime::parse_from_rfc3339(v).ok())
                .map(|dt| dt.with_timezone(&Utc))
        };
        mat.creation_date = parse_dt(&cdx.creation_date);
        mat.activation_date = parse_dt(&cdx.activation_date);
        mat.update_date = parse_dt(&cdx.update_date);
        mat.expiration_date = parse_dt(&cdx.expiration_date);

        mat
    }

    fn convert_protocol_properties(cdx: &CdxProtocolProperties) -> ProtocolProperties {
        let protocol_type =
            cdx.protocol_type
                .as_deref()
                .map_or(ProtocolType::Unknown, |s| match s {
                    "tls" => ProtocolType::Tls,
                    "dtls" => ProtocolType::Dtls,
                    "ipsec" => ProtocolType::Ipsec,
                    "ssh" => ProtocolType::Ssh,
                    "srtp" => ProtocolType::Srtp,
                    "wireguard" => ProtocolType::Wireguard,
                    "ikev1" => ProtocolType::Ikev1,
                    "ikev2" => ProtocolType::Ikev2,
                    "zrtp" => ProtocolType::Zrtp,
                    "mikey" => ProtocolType::Mikey,
                    "unknown" => ProtocolType::Unknown,
                    other => ProtocolType::Other(other.to_string()),
                });

        let mut proto = ProtocolProperties::new(protocol_type);
        proto.version.clone_from(&cdx.version);

        if let Some(suites) = &cdx.cipher_suites {
            proto.cipher_suites = suites
                .iter()
                .map(|s| CipherSuite {
                    name: s.name.clone(),
                    algorithms: s.algorithms.clone().unwrap_or_default(),
                    identifiers: s.identifiers.clone().unwrap_or_default(),
                })
                .collect();
        }

        if let Some(ike) = &cdx.ikev2_transform_types {
            proto.ikev2_transform_types = Some(Ikev2TransformTypes {
                encr: ike.encr.clone().unwrap_or_default(),
                prf: ike.prf.clone().unwrap_or_default(),
                integ: ike.integ.clone().unwrap_or_default(),
                ke: ike.ke.clone().unwrap_or_default(),
            });
        }

        proto.crypto_ref_array = cdx.crypto_ref_array.clone().unwrap_or_default();
        proto
    }

    /// Convert a `CycloneDX` service (SaaSBOM, 1.4+) to a normalized
    /// Component. The normalized model has no first-class service kind, so
    /// services map to `ComponentType::Other("service")`, with provider →
    /// supplier and endpoints preserved as external references.
    fn convert_service(&self, svc: &CdxService) -> Component {
        let format_id = svc.bom_ref.clone().unwrap_or_else(|| svc.name.clone());
        let mut comp = Component::new(svc.name.clone(), format_id);
        comp.component_type = ComponentType::Other("service".to_string());

        if let Some(version) = &svc.version {
            comp = comp.with_version(version.clone());
        }
        comp.description.clone_from(&svc.description);
        comp.group.clone_from(&svc.group);

        if let Some(provider) = &svc.provider
            && let Some(name) = provider
                .name
                .clone()
                .or_else(|| provider.url.as_ref().and_then(|u| u.first().cloned()))
        {
            comp.supplier = Some(Organization::new(name));
        }

        // Declared service licenses (same licenseChoice shape as components)
        if let Some(licenses) = &svc.licenses {
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

        for endpoint in svc.endpoints.iter().flatten() {
            comp.external_refs.push(ExternalReference {
                ref_type: ExternalRefType::Other("endpoint".to_string()),
                url: endpoint.clone(),
                comment: None,
                hashes: Vec::new(),
            });
        }
        if let Some(ext_refs) = &svc.external_references {
            for ext_ref in ext_refs {
                comp.external_refs.push(ExternalReference {
                    ref_type: map_cdx_external_ref_type(&ext_ref.ref_type),
                    url: ext_ref.url.clone(),
                    comment: ext_ref.comment.clone(),
                    hashes: Vec::new(),
                });
            }
        }
        if let Some(props) = &svc.properties {
            for prop in props {
                let Some(name) = prop.name.clone() else {
                    continue;
                };
                comp.extensions.properties.push(Property {
                    name,
                    value: prop.value.clone().unwrap_or_default(),
                });
            }
        }

        comp.calculate_content_hash();
        comp
    }

    /// Apply vulnerability information to components. `index` is the
    /// entry's position in the document's vulnerabilities array, used to
    /// disambiguate fully-anonymous records.
    fn apply_vulnerability(
        &self,
        sbom: &mut NormalizedSbom,
        vuln: &CdxVulnerability,
        index: usize,
        id_map: &HashMap<String, CanonicalId>,
    ) {
        // vulnerability.id is optional per the schema (a record may be
        // identified via references or source only): fall back to the
        // first reference that carries an id — and in that case take THAT
        // reference's source too, so the id isn't attributed to the wrong
        // database. A fully-anonymous record gets an index-disambiguated
        // UNKNOWN-{n} id: a shared literal would collide in id-keyed
        // consumers and silently merge distinct vulnerabilities.
        let fallback_ref = if vuln.id.is_none() {
            vuln.references.iter().flatten().find(|r| r.id.is_some())
        } else {
            None
        };
        let id = vuln
            .id
            .clone()
            .or_else(|| fallback_ref.and_then(|r| r.id.clone()))
            .unwrap_or_else(|| format!("UNKNOWN-{index}"));

        // vulnerabilitySource has no required fields: a source may carry
        // only a URL — keep it rather than fabricating a name.
        let source_field = vuln
            .source
            .as_ref()
            .or_else(|| fallback_ref.and_then(|r| r.source.as_ref()));
        let source = source_field.map_or(VulnerabilitySource::Cve, |s| {
            match s.name.as_deref().map(str::to_lowercase).as_deref() {
                Some("nvd") => VulnerabilitySource::Nvd,
                Some("ghsa" | "github") => VulnerabilitySource::Ghsa,
                Some("osv") => VulnerabilitySource::Osv,
                Some("snyk") => VulnerabilitySource::Snyk,
                Some(other) => VulnerabilitySource::Other(other.to_string()),
                None => VulnerabilitySource::Other(
                    s.url.clone().unwrap_or_else(|| "unknown".to_string()),
                ),
            }
        });
        let mut vuln_ref = VulnerabilityRef::new(id, source);
        vuln_ref.description = super::capped_description(&vuln.description);

        // Parse CVSS scores
        if let Some(ratings) = &vuln.ratings {
            for rating in ratings {
                // Only CVSS methods produce a CVSS score; OWASP/SSVC/etc. are
                // different scoring systems and must not be mislabeled as CVSS.
                let version = match rating.method.as_deref() {
                    Some("CVSSv2") => Some(CvssVersion::V2),
                    Some("CVSSv3") => Some(CvssVersion::V3),
                    Some("CVSSv31") => Some(CvssVersion::V31),
                    Some("CVSSv4") => Some(CvssVersion::V4),
                    // Unmethoded ratings historically defaulted to v3.1.
                    None => Some(CvssVersion::V31),
                    Some(_) => None,
                };
                if let (Some(version), Some(score)) = (version, rating.score)
                    // The XML path parses score text with str::parse, which
                    // accepts NaN/inf; reject non-finite so a hostile score
                    // can't reach Severity::from_cvss and forge Critical.
                    && score.is_finite()
                {
                    let mut cvss = CvssScore::new(version, score);
                    cvss.vector.clone_from(&rating.vector);
                    vuln_ref.cvss.push(cvss);
                }
                // Take the HIGHEST severity across ratings, not the first:
                // otherwise a leading rating with severity "none"/"low" freezes
                // the value and suppresses a higher CVSS score in a later one.
                // (priority() is lower-is-more-severe.)
                if let Some(sev) =
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
                        })
                {
                    let more_severe = vuln_ref
                        .severity
                        .as_ref()
                        .is_none_or(|cur| sev.priority() < cur.priority());
                    if more_severe {
                        vuln_ref.severity = Some(sev);
                    }
                }
            }
        }

        // Fallback: derive severity from CVSS score if no explicit severity was provided
        if vuln_ref.severity.is_none()
            && let Some(max_score) = vuln_ref.max_cvss_score()
        {
            vuln_ref.severity = Some(Severity::from_cvss(max_score));
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
            // CycloneDX impactAnalysisState. "exploitable" must NOT collapse
            // to UnderInvestigation (that would understate a live threat);
            // unknown states stay UnderInvestigation (an honest "we don't
            // know", not a fabricated safe claim).
            let status = match analysis.state.as_deref() {
                Some("not_affected") | Some("false_positive") => VexState::NotAffected,
                Some("affected") | Some("exploitable") => VexState::Affected,
                Some("fixed") | Some("resolved") | Some("resolved_with_pedigree") => {
                    VexState::Fixed
                }
                _ => VexState::UnderInvestigation,
            };

            // Unknown/unrecognized justification must NOT fabricate a
            // not-affected claim: an unrecognized string yields None, never
            // ComponentNotPresent (the strongest "it isn't even here" claim).
            let justification = analysis
                .justification
                .as_ref()
                .and_then(|j| match j.as_str() {
                    "code_not_present" => Some(VexJustification::VulnerableCodeNotPresent),
                    "code_not_reachable" => Some(VexJustification::VulnerableCodeNotInExecutePath),
                    "requires_configuration" | "requires_dependency" | "requires_environment" => {
                        Some(VexJustification::VulnerableCodeCannotBeControlledByAdversary)
                    }
                    "protected_by_mitigating_control" => {
                        Some(VexJustification::InlineMitigationsAlreadyExist)
                    }
                    _ => None,
                });

            let responses: Vec<VexResponse> = analysis
                .response
                .as_ref()
                .map(|rs| {
                    rs.iter()
                        .map(|r| match r.as_str() {
                            "can_not_fix" => VexResponse::CanNotFix,
                            "will_not_fix" => VexResponse::WillNotFix,
                            "rollback" => VexResponse::Rollback,
                            "workaround_available" => VexResponse::Workaround,
                            _ => VexResponse::Update,
                        })
                        .collect()
                })
                .unwrap_or_default();

            VexStatus {
                status,
                justification,
                action_statement: None,
                impact_statement: analysis.detail.clone(),
                responses,
                detail: analysis.detail.clone(),
            }
        });

        // Apply vulnerability to affected components. Dedup targets by
        // canonical id: the same component listed twice in affects[] must not
        // receive the vulnerability twice (and, with a capped description,
        // caps this vuln's total memory at O(distinct components)).
        if let Some(affects) = &vuln.affects {
            let mut seen: HashSet<&CanonicalId> = HashSet::new();
            for affect in affects {
                if let Some(canonical_id) = id_map.get(&affect.ref_field)
                    && seen.insert(canonical_id)
                    && let Some(comp) = sbom.components.get_mut(canonical_id)
                {
                    // Per-entry version status also gates the attachment
                    // itself: a component whose concrete version is
                    // explicitly declared "unaffected" must not receive the
                    // vulnerability. Only exact `version` matches skip —
                    // `range` entries are not evaluated (no vers-range
                    // parsing), and a component without a version always
                    // attaches: false positives are safer here.
                    if let (Some(versions), Some(comp_version)) =
                        (&affect.versions, comp.version.as_deref())
                        && versions.iter().any(|ver| {
                            ver.status.as_deref() == Some("unaffected")
                                && ver.version.as_deref() == Some(comp_version)
                        })
                    {
                        continue;
                    }
                    let mut v = vuln_ref.clone();
                    if let Some(versions) = &affect.versions {
                        // Respect per-entry status: only "affected" (or
                        // absent — the spec default) entries name affected
                        // versions. "unaffected"/"unknown" must never be
                        // reported as affected. Range entries (vers syntax)
                        // are kept, not dropped.
                        v.affected_versions = versions
                            .iter()
                            .filter(|ver| matches!(ver.status.as_deref(), None | Some("affected")))
                            .filter_map(|ver| ver.version.clone().or_else(|| ver.range.clone()))
                            .collect();
                    }
                    if let Some(vex) = &vex_status {
                        v.vex_status = Some(vex.clone());
                        // Component-level VEX is a single slot: keep the
                        // HIGHEST-risk status across all vulns, so a trailing
                        // fabricated `not_affected` cannot erase a real
                        // `affected` from an earlier vulnerability.
                        if comp.vex_status.as_ref().is_none_or(|cur| {
                            vex_state_risk(&vex.status) > vex_state_risk(&cur.status)
                        }) {
                            comp.vex_status = Some(vex.clone());
                        }
                    }
                    comp.vulnerabilities.push(v);
                }
            }
        }
    }
}

/// Maximum XML element nesting depth accepted before deserialization.
/// Matches the effective serde_json recursion cap on the JSON path; no
/// legitimate SBOM assembly tree approaches it.
const MAX_XML_DEPTH: usize = 128;

/// Reject XML nested deeper than [`MAX_XML_DEPTH`] with an iterative
/// event scan (constant stack), so the recursive serde models can never
/// be driven to a stack overflow by hostile input. Malformed XML passes
/// through — the real parser reports it (shallow input cannot overflow).
fn xml_depth_within_limit(content: &str) -> Result<(), ParseError> {
    let mut reader = quick_xml::Reader::from_str(content);
    let mut depth: usize = 0;
    loop {
        match reader.read_event() {
            Ok(quick_xml::events::Event::Start(_)) => {
                depth += 1;
                if depth > MAX_XML_DEPTH {
                    return Err(ParseError::XmlError(format!(
                        "XML nesting depth exceeds the {MAX_XML_DEPTH} limit"
                    )));
                }
            }
            Ok(quick_xml::events::Event::End(_)) => depth = depth.saturating_sub(1),
            Ok(quick_xml::events::Event::Eof) | Err(_) => return Ok(()),
            Ok(_) => {}
        }
    }
}

/// Map a CycloneDX external-reference type string to the normalized enum.
/// Shared by the component and service conversion paths.
fn map_cdx_external_ref_type(ref_type: &str) -> ExternalRefType {
    match ref_type {
        "vcs" => ExternalRefType::Vcs,
        "issue-tracker" => ExternalRefType::IssueTracker,
        "website" => ExternalRefType::Website,
        "advisories" => ExternalRefType::Advisories,
        "bom" => ExternalRefType::Bom,
        "model-card" => ExternalRefType::ModelCard,
        "documentation" => ExternalRefType::Documentation,
        "support" => ExternalRefType::Support,
        "security-contact" => ExternalRefType::SecurityContact,
        "license" => ExternalRefType::License,
        "build-meta" => ExternalRefType::BuildMeta,
        "release-notes" => ExternalRefType::ReleaseNotes,
        "citation" => ExternalRefType::Citation,
        "patent" => ExternalRefType::Patent,
        "patent-assertion" => ExternalRefType::PatentAssertion,
        "patent-family" => ExternalRefType::PatentFamily,
        other => ExternalRefType::Other(other.to_string()),
    }
}

/// Risk ordering for component-level VEX resolution: higher = more actionable.
/// Affected outranks the uncertain state, which outranks the not-actionable
/// states, so a later low-risk claim never overwrites a higher-risk one.
const fn vex_state_risk(state: &VexState) -> u8 {
    match state {
        VexState::Affected => 3,
        VexState::UnderInvestigation => 2,
        VexState::NotAffected | VexState::Fixed => 1,
    }
}

impl Default for CycloneDxParser {
    fn default() -> Self {
        Self::new()
    }
}

impl SbomParser for CycloneDxParser {
    fn parse_str(&self, content: &str) -> Result<NormalizedSbom, ParseError> {
        let content = super::strip_bom(content);
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
        vec!["1.4", "1.5", "1.6", "1.7"]
    }

    fn format_name(&self) -> &'static str {
        "CycloneDX"
    }

    fn detect(&self, content: &str) -> crate::parsers::traits::FormatDetection {
        use crate::parsers::contains_json_key;
        use crate::parsers::traits::{FormatConfidence, FormatDetection};

        let content = super::strip_bom(content);
        let trimmed = content.trim();

        // Check for JSON CycloneDX
        if trimmed.starts_with('{') {
            // Look for CycloneDX-specific markers. Marker keys (bomFormat,
            // specVersion, $schema, components) must appear as actual JSON
            // keys, not merely as a coincidental string VALUE elsewhere in
            // the document (e.g. a component literally named "specVersion").
            let has_bom_format = contains_json_key(content, "bomFormat");
            let has_cyclonedx = content.contains("CycloneDX") || content.contains("cyclonedx");
            let has_spec_version = contains_json_key(content, "specVersion");
            let has_schema = contains_json_key(content, "$schema") && content.contains("cyclonedx");

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
            } else if has_spec_version && contains_json_key(content, "components") {
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
    /// Services (SaaSBOM, 1.4+) — inventory alongside components
    services: Option<Vec<CdxService>>,
    dependencies: Option<Vec<CdxDependency>>,
    vulnerabilities: Option<Vec<CdxVulnerability>>,
    compositions: Option<Vec<CdxComposition>>,
    signature: Option<CdxSignature>,
    /// Data provenance citations (1.7+)
    citations: Option<Vec<CdxCitation>>,
    /// CDXA attestation declarations (1.6+)
    declarations: Option<CdxDeclarations>,
    /// Reusable definitions (1.6+) — carries the `standards` encodings that
    /// CDXA attestations map their requirements into
    definitions: Option<CdxDefinitions>,
}

/// CycloneDX composition entry (1.4+)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct CdxComposition {
    /// Aggregate completeness: complete, incomplete, incomplete_first_party_only,
    /// incomplete_third_party_only, unknown, not_specified
    aggregate: Option<String>,
    /// References to components included in this composition
    assemblies: Option<Vec<String>>,
}

/// CycloneDX citation for data provenance (1.7+)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct CdxCitation {
    /// BOM reference
    #[serde(alias = "bom-ref")]
    bom_ref: Option<String>,
    /// JSON Pointers (RFC 6901) identifying attributed BOM fields
    pointers: Option<Vec<String>>,
    /// Path expressions (JSONPath/XPath) identifying attributed BOM fields
    expressions: Option<Vec<String>>,
    /// When the attribution was made
    timestamp: Option<String>,
    /// Reference to the entity that supplied the data
    attributed_to: Option<String>,
    /// Reference to a formulation/workflow/task that generated the data
    process: Option<String>,
    /// Freeform description
    note: Option<String>,
}

/// CycloneDX distribution constraints (1.7+)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct CdxDistributionConstraints {
    /// Traffic Light Protocol classification
    tlp: Option<String>,
}

// ---------------------------------------------------------------------------
// CDXA (CycloneDX 1.6 Attestations): raw `declarations` / `definitions`
// deserialization structures, coded from the frozen 1.6 schema tag
// (https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema/bom-1.6.schema.json).
//
// Verification scope (phase 1): STRUCTURAL ONLY. JSF signature slots are
// captured as raw JSON so their presence and named signatory (algorithm,
// keyId, signer count) can be recorded — the signatures are NEVER
// cryptographically verified, and the normalized model caps the reported
// evidence level at `EvidenceLevel::SignaturePresent`.
// ---------------------------------------------------------------------------

/// Root `declarations` object (1.6+, `additionalProperties: false` in the
/// schema; unknown keys are ignored here per the parser's tolerance
/// conventions).
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxDeclarations {
    assessors: Option<Vec<CdxAssessor>>,
    attestations: Option<Vec<CdxAttestation>>,
    claims: Option<Vec<CdxClaim>>,
    evidence: Option<Vec<CdxDeclEvidence>>,
    targets: Option<CdxDeclTargets>,
    affirmation: Option<CdxAffirmation>,
    signature: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxAssessor {
    #[serde(alias = "bom-ref")]
    bom_ref: Option<String>,
    third_party: Option<bool>,
    organization: Option<CdxOrgEntity>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxAttestation {
    summary: Option<String>,
    /// refLink into `declarations.assessors[]`
    assessor: Option<String>,
    map: Option<Vec<CdxAttestationMap>>,
    signature: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxAttestationMap {
    /// refLink to the requirement being attested to
    requirement: Option<String>,
    claims: Option<Vec<String>>,
    counter_claims: Option<Vec<String>>,
    conformance: Option<CdxConformance>,
    confidence: Option<CdxConfidence>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxConformance {
    /// `0..=1`, where 1 is 100% conformance
    score: Option<f64>,
    rationale: Option<String>,
    mitigation_strategies: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxConfidence {
    /// `0..=1`, where 1 is 100% confidence
    score: Option<f64>,
    rationale: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxClaim {
    #[serde(alias = "bom-ref")]
    bom_ref: Option<String>,
    /// refLink to the claim's target
    target: Option<String>,
    predicate: Option<String>,
    mitigation_strategies: Option<Vec<String>>,
    reasoning: Option<String>,
    evidence: Option<Vec<String>>,
    counter_evidence: Option<Vec<String>>,
    external_references: Option<Vec<CdxExternalReference>>,
    signature: Option<serde_json::Value>,
}

/// `declarations.evidence[]` entry (distinct from component `evidence`).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxDeclEvidence {
    #[serde(alias = "bom-ref")]
    bom_ref: Option<String>,
    property_name: Option<String>,
    description: Option<String>,
    data: Option<Vec<CdxEvidenceData>>,
    created: Option<String>,
    expires: Option<String>,
    author: Option<CdxOrgContact>,
    reviewer: Option<CdxOrgContact>,
    signature: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxEvidenceData {
    name: Option<String>,
    contents: Option<CdxEvidenceDataContents>,
    classification: Option<String>,
    sensitive_data: Option<Vec<String>>,
    /// dataGovernance block — normalized to a presence bit in phase 1
    governance: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxEvidenceDataContents {
    /// Inline attachment — normalized to a presence bit in phase 1
    attachment: Option<serde_json::Value>,
    url: Option<String>,
}

/// Tolerant identity subset of the `declarations.targets` entries. The
/// schema types them as full organizationalEntity / component / service
/// objects; only bom-ref (for claim-target resolution) and name are
/// normalized — the entries are claim targets, not BOM inventory.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxTargetEntry {
    #[serde(alias = "bom-ref")]
    bom_ref: Option<String>,
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxDeclTargets {
    organizations: Option<Vec<CdxTargetEntry>>,
    components: Option<Vec<CdxTargetEntry>>,
    services: Option<Vec<CdxTargetEntry>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxAffirmation {
    statement: Option<String>,
    signatories: Option<Vec<CdxSignatory>>,
    signature: Option<serde_json::Value>,
}

/// Affirmation signatory. The schema's `oneOf` (signature XOR
/// externalReference+organization) is not enforced at parse time — the
/// normalized model records completeness via
/// `AffirmationSignatory::has_complete_identity` so rules can flag it.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxSignatory {
    name: Option<String>,
    role: Option<String>,
    signature: Option<serde_json::Value>,
    organization: Option<CdxOrgEntity>,
    external_reference: Option<CdxExternalReference>,
}

/// Root `definitions` object (1.6+).
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxDefinitions {
    standards: Option<Vec<CdxStandard>>,
}

/// `definitions.standards[]` entry. `levels` and requirement `properties`
/// are not normalized in phase 1.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxStandard {
    #[serde(alias = "bom-ref")]
    bom_ref: Option<String>,
    name: Option<String>,
    version: Option<String>,
    description: Option<String>,
    owner: Option<String>,
    requirements: Option<Vec<CdxRequirementDef>>,
    signature: Option<serde_json::Value>,
}

/// `definitions.standards[].requirements[]` entry. Per the frozen 1.6
/// schema: `text` is a plain string and `descriptions` is a PLURAL array of
/// supplemental strings.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxRequirementDef {
    #[serde(alias = "bom-ref")]
    bom_ref: Option<String>,
    identifier: Option<String>,
    title: Option<String>,
    text: Option<String>,
    descriptions: Option<Vec<String>>,
    open_cre: Option<Vec<String>>,
    parent: Option<String>,
    external_references: Option<Vec<CdxExternalReference>>,
}

/// True when `specVersion` is 1.6 or later. CDXA `declarations` and
/// `definitions` were introduced in CycloneDX 1.6; parsers must not probe
/// for them on earlier documents (their absence is never a violation —
/// attestation evidence is additive, not a new mandatory element).
fn cdx_supports_cdxa(spec_version: &str) -> bool {
    let mut parts = spec_version.trim().split('.');
    let major: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let minor: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    major > 1 || (major == 1 && minor >= 6)
}

/// Normalize CDXA `declarations` + `definitions.standards` into the typed
/// attestation-evidence model.
///
/// Reference resolution reuses the id_map pattern established for
/// `dependencies[].ref`/`dependsOn` and `vulnerabilities[].affects[].ref`:
/// declarations-local bom-refs (claims, evidence, assessors, standards and
/// their requirements, `declarations.targets` entries) are indexed first,
/// then the BOM inventory `id_map` — whose purl-fallback keys already let a
/// claim target name a component by purl, with genuine bom-refs always
/// winning. Unresolvable refs are kept and marked `Dangling` (the parser's
/// tolerance convention — never an error); the model fails closed on them
/// at query time.
///
/// STRUCTURAL ONLY: JSF signatures become `SignaturePresence` records
/// (algorithm, keyId, signer count) with no cryptographic verification.
fn convert_declarations(
    declarations: Option<CdxDeclarations>,
    definitions: Option<CdxDefinitions>,
    id_map: &HashMap<String, CanonicalId>,
) -> AttestationDeclarations {
    let decls = declarations.unwrap_or_default();
    let standards_src: Vec<CdxStandard> = definitions.and_then(|d| d.standards).unwrap_or_default();

    // Declarations-local ref universe, by kind.
    let mut claim_refs: HashSet<&str> = HashSet::new();
    for claim in decls.claims.iter().flatten() {
        if let Some(r) = claim.bom_ref.as_deref() {
            claim_refs.insert(r);
        }
    }
    let mut evidence_refs: HashSet<&str> = HashSet::new();
    for evidence in decls.evidence.iter().flatten() {
        if let Some(r) = evidence.bom_ref.as_deref() {
            evidence_refs.insert(r);
        }
    }
    let mut assessor_refs: HashSet<&str> = HashSet::new();
    for assessor in decls.assessors.iter().flatten() {
        if let Some(r) = assessor.bom_ref.as_deref() {
            assessor_refs.insert(r);
        }
    }
    let mut requirement_refs: HashSet<&str> = HashSet::new();
    for standard in &standards_src {
        if let Some(r) = standard.bom_ref.as_deref() {
            requirement_refs.insert(r);
        }
        for requirement in standard.requirements.iter().flatten() {
            if let Some(r) = requirement.bom_ref.as_deref() {
                requirement_refs.insert(r);
            }
        }
    }
    let mut target_refs: HashSet<&str> = HashSet::new();
    if let Some(targets) = &decls.targets {
        for entry in [
            &targets.organizations,
            &targets.components,
            &targets.services,
        ]
        .into_iter()
        .flat_map(|list| list.iter().flatten())
        {
            if let Some(r) = entry.bom_ref.as_deref() {
                target_refs.insert(r);
            }
        }
    }

    let resolve = |raw: &str| -> CdxaResolution {
        if claim_refs.contains(raw) {
            CdxaResolution::Claim
        } else if evidence_refs.contains(raw) {
            CdxaResolution::Evidence
        } else if assessor_refs.contains(raw) {
            CdxaResolution::Assessor
        } else if requirement_refs.contains(raw) {
            CdxaResolution::Requirement
        } else if target_refs.contains(raw) {
            CdxaResolution::Target
        } else if let Some(id) = id_map.get(raw) {
            CdxaResolution::Inventory(id.clone())
        } else {
            CdxaResolution::Dangling
        }
    };
    let mk_ref = |raw: &String| CdxaRef {
        raw: raw.clone(),
        resolution: resolve(raw),
    };
    let mk_refs = |list: &Option<Vec<String>>| -> Vec<CdxaRef> {
        list.iter().flatten().map(mk_ref).collect()
    };

    let parse_dt = |value: &Option<String>| -> Option<DateTime<Utc>> {
        value
            .as_deref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
    };
    // Structural signature-presence only — never verifies the JSF signature.
    let jsf = |value: &Option<serde_json::Value>| -> Option<SignaturePresence> {
        value.as_ref().and_then(SignaturePresence::from_jsf)
    };
    let contact = |c: &CdxOrgContact| Contact {
        name: c.name.clone(),
        email: c.email.clone(),
        phone: c.phone.clone(),
    };
    let org = |o: &CdxOrgEntity| {
        let mut organization = Organization::new(o.name.clone().unwrap_or_default());
        organization.urls = o.url.clone().unwrap_or_default();
        organization.contacts = o.contact.iter().flatten().map(contact).collect();
        organization
    };
    let ext_ref = |r: &CdxExternalReference| ExternalReference {
        ref_type: map_cdx_external_ref_type(&r.ref_type),
        url: r.url.clone(),
        comment: r.comment.clone(),
        hashes: Vec::new(),
    };
    let ext_refs = |list: &Option<Vec<CdxExternalReference>>| -> Vec<ExternalReference> {
        list.iter().flatten().map(ext_ref).collect()
    };
    let target_entry = |t: &CdxTargetEntry| DeclarationTarget {
        bom_ref: t.bom_ref.clone(),
        name: t.name.clone(),
    };

    let assessors = decls
        .assessors
        .iter()
        .flatten()
        .map(|a| DeclaredAssessor {
            bom_ref: a.bom_ref.clone(),
            third_party: a.third_party,
            organization: a.organization.as_ref().map(org),
        })
        .collect();

    let attestations = decls
        .attestations
        .iter()
        .flatten()
        .map(|a| AttestationAssertion {
            summary: a.summary.clone(),
            assessor: a.assessor.as_ref().map(mk_ref),
            map: a
                .map
                .iter()
                .flatten()
                .map(|m| AttestationMapEntry {
                    requirement: m.requirement.as_ref().map(mk_ref),
                    claims: mk_refs(&m.claims),
                    counter_claims: mk_refs(&m.counter_claims),
                    conformance_score: m.conformance.as_ref().and_then(|c| c.score),
                    conformance_rationale: m.conformance.as_ref().and_then(|c| c.rationale.clone()),
                    conformance_mitigation_strategies: mk_refs(
                        &m.conformance
                            .as_ref()
                            .and_then(|c| c.mitigation_strategies.clone()),
                    ),
                    confidence_score: m.confidence.as_ref().and_then(|c| c.score),
                    confidence_rationale: m.confidence.as_ref().and_then(|c| c.rationale.clone()),
                })
                .collect(),
            signature: jsf(&a.signature),
        })
        .collect();

    let claims = decls
        .claims
        .iter()
        .flatten()
        .map(|c| DeclaredClaim {
            bom_ref: c.bom_ref.clone(),
            target: c.target.as_ref().map(mk_ref),
            predicate: c.predicate.clone(),
            mitigation_strategies: mk_refs(&c.mitigation_strategies),
            reasoning: c.reasoning.clone(),
            evidence: mk_refs(&c.evidence),
            counter_evidence: mk_refs(&c.counter_evidence),
            external_refs: ext_refs(&c.external_references),
            signature: jsf(&c.signature),
        })
        .collect();

    let evidence = decls
        .evidence
        .iter()
        .flatten()
        .map(|e| DeclaredEvidence {
            bom_ref: e.bom_ref.clone(),
            property_name: e.property_name.clone(),
            description: e.description.clone(),
            data: e
                .data
                .iter()
                .flatten()
                .map(|d| EvidenceDataItem {
                    name: d.name.clone(),
                    url: d.contents.as_ref().and_then(|c| c.url.clone()),
                    has_attachment: d.contents.as_ref().is_some_and(|c| c.attachment.is_some()),
                    classification: d.classification.clone(),
                    sensitive_data: d.sensitive_data.clone().unwrap_or_default(),
                    has_governance: d.governance.is_some(),
                })
                .collect(),
            created: parse_dt(&e.created),
            expires: parse_dt(&e.expires),
            author: e.author.as_ref().map(contact),
            reviewer: e.reviewer.as_ref().map(contact),
            signature: jsf(&e.signature),
        })
        .collect();

    let targets = decls.targets.as_ref().map(|t| DeclarationTargets {
        organizations: t.organizations.iter().flatten().map(target_entry).collect(),
        components: t.components.iter().flatten().map(target_entry).collect(),
        services: t.services.iter().flatten().map(target_entry).collect(),
    });

    let affirmation = decls.affirmation.as_ref().map(|a| DeclaredAffirmation {
        statement: a.statement.clone(),
        signatories: a
            .signatories
            .iter()
            .flatten()
            .map(|s| AffirmationSignatory {
                name: s.name.clone(),
                role: s.role.clone(),
                signature: jsf(&s.signature),
                organization: s.organization.as_ref().map(org),
                external_reference: s.external_reference.as_ref().map(ext_ref),
            })
            .collect(),
        signature: jsf(&a.signature),
    });

    let standards = standards_src
        .iter()
        .map(|s| DefinedStandard {
            bom_ref: s.bom_ref.clone(),
            name: s.name.clone(),
            version: s.version.clone(),
            description: s.description.clone(),
            owner: s.owner.clone(),
            requirements: s
                .requirements
                .iter()
                .flatten()
                .map(|r| DefinedRequirement {
                    bom_ref: r.bom_ref.clone(),
                    identifier: r.identifier.clone(),
                    title: r.title.clone(),
                    text: r.text.clone(),
                    descriptions: r.descriptions.clone().unwrap_or_default(),
                    open_cre: r.open_cre.clone().unwrap_or_default(),
                    parent: r.parent.clone(),
                    external_refs: ext_refs(&r.external_references),
                })
                .collect(),
            signature: jsf(&s.signature),
        })
        .collect();

    AttestationDeclarations {
        assessors,
        attestations,
        claims,
        evidence,
        targets,
        affirmation,
        signature: jsf(&decls.signature),
        standards,
    }
}

/// CycloneDX JSF signature (JSON Signature Format)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct CdxSignature {
    /// Signature algorithm (e.g., "ES256", "RS256", "Ed25519")
    algorithm: Option<String>,
    /// Signature value (base64 encoded)
    value: Option<String>,
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
    /// Organization that created the BOM (1.5+). BSI TR-03183-2 v2.1.0
    /// Table 8 maps the required "Creator of the SBOM" to this field.
    manufacturer: Option<CdxOrgEntity>,
    /// Deprecated pre-1.6 spelling: manufacturer of the described component,
    /// historically also used for the BOM creator. Accepted as a fallback.
    manufacture: Option<CdxOrgEntity>,
    component: Option<CdxComponent>,
    /// Lifecycles field (1.5+) - contains phases like end-of-support dates
    lifecycles: Option<Vec<CdxLifecycle>>,
    /// Distribution constraints (1.7+) with TLP classification
    distribution_constraints: Option<CdxDistributionConstraints>,
}

/// `CycloneDX` organizational entity (`metadata.manufacturer` /
/// deprecated `metadata.manufacture`).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct CdxOrgEntity {
    name: Option<String>,
    url: Option<Vec<String>>,
    contact: Option<Vec<CdxOrgContact>>,
}

/// Contact entry of a `CycloneDX` organizational entity.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct CdxOrgContact {
    name: Option<String>,
    email: Option<String>,
    phone: Option<String>,
}

/// `CycloneDX` lifecycle entry (1.5+)
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

/// `CycloneDX` 1.6 tools object format
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct CdxToolsObject {
    components: Option<Vec<CdxToolComponent>>,
    services: Option<Vec<CdxToolService>>,
}

/// Tool component in `CycloneDX` 1.6 format
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct CdxToolComponent {
    name: Option<String>,
    version: Option<String>,
    #[serde(alias = "bom-ref")]
    bom_ref: Option<String>,
}

/// Tool service in `CycloneDX` 1.6 format
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct CdxToolService {
    name: Option<String>,
    version: Option<String>,
}

/// Author in `CycloneDX` 1.6 format
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

/// Custom deserializer to handle both `CycloneDX` 1.4/1.5 (array) and 1.6 (object) tool formats
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
    scope: Option<String>,
    purl: Option<String>,
    cpe: Option<String>,
    /// Software Heritage persistent identifiers (1.6+).
    /// CRA prEN 40000-1-3 `[PRE-7-RQ-07]` names SWHID alongside PURL/CPE.
    #[serde(default)]
    swhid: Vec<String>,
    description: Option<String>,
    author: Option<String>,
    copyright: Option<String>,
    licenses: Option<Vec<CdxLicenseChoice>>,
    supplier: Option<CdxSupplier>,
    hashes: Option<Vec<CdxHash>>,
    external_references: Option<Vec<CdxExternalReference>>,
    properties: Option<Vec<CdxProperty>>,
    /// Whether this component is external (1.7+)
    #[serde(default)]
    is_external: bool,
    /// Package URL Version Range syntax (1.7+, mutually exclusive with version)
    version_range: Option<String>,
    /// ML Model metadata (CycloneDX 1.5+)
    #[serde(rename = "modelCard")]
    model_card: Option<CdxMlModelCard>,
    /// Dataset metadata (CycloneDX 1.5+). Per spec `data` is an array of componentData;
    /// a single object is also accepted for non-spec emitters.
    #[serde(
        rename = "data",
        default,
        deserialize_with = "deserialize_component_data"
    )]
    data_components: Vec<CdxDataComponent>,
    /// Cryptographic properties (1.6+)
    crypto_properties: Option<CdxCryptoProperties>,
    /// Nested component assemblies (recursive since 1.0). Real inventory:
    /// their bom-refs participate in dependencies and vulnerability affects.
    components: Option<Vec<CdxComponent>>,
}

/// CycloneDX service (SaaSBOM, 1.4+). Only `name` is required per the
/// schema; services nest recursively like component assemblies.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct CdxService {
    #[serde(alias = "bom-ref")]
    bom_ref: Option<String>,
    provider: Option<CdxSupplier>,
    group: Option<String>,
    name: String,
    version: Option<String>,
    description: Option<String>,
    endpoints: Option<Vec<String>>,
    licenses: Option<Vec<CdxLicenseChoice>>,
    external_references: Option<Vec<CdxExternalReference>>,
    properties: Option<Vec<CdxProperty>>,
    services: Option<Vec<CdxService>>,
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
    /// Optional per the schema: organizationalEntity has NO required
    /// fields — a supplier may carry only a URL or contact.
    name: Option<String>,
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
    /// Optional: bom-1.6+ requires `name`, but 1.4/1.5 have NO required
    /// list at all — name-less entries must not fail the document (they
    /// are skipped, being unaddressable).
    name: Option<String>,
    /// Optional in every schema version.
    value: Option<String>,
}

// ML Model and Dataset structures (CycloneDX 1.5+ AI/ML BOM support)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxMlModelCard {
    model_parameters: Option<CdxModelParameters>,
    considerations: Option<CdxConsiderations>,
    /// Spec: `modelCard.quantitativeAnalysis` (performance metrics, graphics).
    quantitative_analysis: Option<CdxQuantitativeAnalysis>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxMlApproach {
    #[serde(rename = "type")]
    approach_type: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxModelParameters {
    approach: Option<CdxMlApproach>,
    task: Option<String>,
    architecture_family: Option<String>,
    /// Spec: `modelArchitecture` is a string (e.g. "ResNet-50").
    model_architecture: Option<String>,
    /// Non-spec object form `{ name }`, retained as a fallback only.
    architecture: Option<CdxModelArchitecture>,
    #[serde(default)]
    datasets: Vec<CdxDatasetChoice>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxModelArchitecture {
    name: Option<String>,
}

/// A `modelParameters.datasets` item: the spec data-reference form `{ "ref": ... }`, or an
/// inline dataset (spec `componentData` carrying a `name`, or the non-spec `{ name, purl }`).
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CdxDatasetChoice {
    Reference {
        #[serde(rename = "ref")]
        reference: String,
    },
    Inline(CdxDatasetInline),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxDatasetInline {
    name: Option<String>,
    /// Non-spec; spec `componentData` datasets have no purl.
    purl: Option<String>,
}

impl CdxDatasetChoice {
    fn to_model(&self) -> crate::model::DatasetRef {
        match self {
            Self::Reference { reference } => crate::model::DatasetRef {
                reference: Some(reference.clone()),
                name: None,
                purl: None,
            },
            Self::Inline(inline) => crate::model::DatasetRef {
                reference: None,
                name: inline.name.clone(),
                purl: inline.purl.clone(),
            },
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxConsiderations {
    #[serde(default)]
    technical_limitations: Vec<String>,
    environmental_considerations: Option<CdxEnvironmentalConsiderations>,
    /// Spec (CDX 1.5+): `considerations.fairnessAssessments` is an array of objects.
    /// The non-spec `fairnessConsiderations` (a string array used by some emitters)
    /// is accepted via alias and coerced into the structured form.
    #[serde(
        rename = "fairnessAssessments",
        alias = "fairnessConsiderations",
        default,
        deserialize_with = "deserialize_fairness"
    )]
    fairness_assessments: Vec<CdxFairnessAssessment>,
    /// Spec: `considerations.ethicalConsiderations` is an array of objects
    /// `{ name, mitigationStrategy }`; a bare string is accepted for non-spec emitters.
    #[serde(default)]
    ethical_considerations: Vec<CdxEthicalConsideration>,
    /// Spec: `considerations.useCases` is a string array.
    #[serde(default)]
    use_cases: Vec<String>,
}

/// One `considerations.fairnessAssessments` entry. Per spec these are objects;
/// a bare string (non-spec `fairnessConsiderations`) is accepted and lands in
/// `group_at_risk` so it is still surfaced.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CdxFairnessAssessment {
    Text(String),
    Structured(CdxFairnessObj),
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct CdxFairnessObj {
    group_at_risk: Option<String>,
    benefits: Option<String>,
    harms: Option<String>,
    mitigation_strategy: Option<String>,
}

impl CdxFairnessAssessment {
    fn to_model(&self) -> crate::model::FairnessAssessment {
        match self {
            Self::Text(text) => crate::model::FairnessAssessment {
                group_at_risk: Some(text.clone()),
                ..Default::default()
            },
            Self::Structured(obj) => crate::model::FairnessAssessment {
                group_at_risk: obj.group_at_risk.clone(),
                benefits: obj.benefits.clone(),
                harms: obj.harms.clone(),
                mitigation_strategy: obj.mitigation_strategy.clone(),
            },
        }
    }
}

/// Accept `fairnessAssessments` as either the spec object array or a non-spec string array.
fn deserialize_fairness<'de, D>(deserializer: D) -> Result<Vec<CdxFairnessAssessment>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<Vec<CdxFairnessAssessment>>::deserialize(deserializer)?.unwrap_or_default())
}

/// One `considerations.ethicalConsiderations` entry: the spec object
/// `{ name, mitigationStrategy }`, or a bare string for non-spec emitters.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CdxEthicalConsideration {
    Text(String),
    Structured(CdxEthicalObj),
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct CdxEthicalObj {
    name: Option<String>,
    mitigation_strategy: Option<String>,
}

impl CdxEthicalConsideration {
    fn to_model(&self) -> crate::model::EthicalConsideration {
        match self {
            Self::Text(text) => crate::model::EthicalConsideration {
                name: Some(text.clone()),
                mitigation_strategy: None,
            },
            Self::Structured(obj) => crate::model::EthicalConsideration {
                name: obj.name.clone(),
                mitigation_strategy: obj.mitigation_strategy.clone(),
            },
        }
    }
}

/// `modelCard.quantitativeAnalysis` — performance metrics for the model.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxQuantitativeAnalysis {
    #[serde(default)]
    performance_metrics: Vec<CdxPerformanceMetric>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct CdxPerformanceMetric {
    #[serde(rename = "type")]
    metric_type: Option<String>,
    /// Spec `value` is a string; a JSON number is also accepted and stringified.
    #[serde(default, deserialize_with = "de_metric_value")]
    value: Option<String>,
    slice: Option<String>,
}

impl CdxPerformanceMetric {
    fn to_model(&self) -> crate::model::MetricEntry {
        crate::model::MetricEntry {
            metric_type: self.metric_type.clone(),
            value: self.value.clone(),
            slice: self.slice.clone(),
        }
    }
}

/// A performance-metric `value` per spec is a string, but numbers appear in the
/// wild; accept both and normalize to the string form.
fn de_metric_value<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match Option::<serde_json::Value>::deserialize(deserializer)? {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(text)) => Ok(Some(text)),
        Some(serde_json::Value::Number(number)) => Ok(Some(number.to_string())),
        Some(serde_json::Value::Bool(flag)) => Ok(Some(flag.to_string())),
        Some(other) => Ok(Some(other.to_string())),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxEnvironmentalConsiderations {
    #[serde(default)]
    energy_consumptions: Vec<CdxEnergyConsumption>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxEnergyConsumption {
    #[serde(alias = "type")]
    activity: Option<String>,
    /// Spec: `activityEnergyCost` is an energyMeasure `{ value, unit }`.
    activity_energy_cost: Option<CdxEnergyMeasure>,
    /// Non-spec flat kWh value; fallback only.
    #[serde(rename = "energyKwh", alias = "value")]
    energy_kwh: Option<f64>,
}

impl CdxEnergyConsumption {
    /// Training energy in kWh: prefer the spec `activityEnergyCost` (unit-normalized),
    /// otherwise the non-spec flat value.
    fn training_energy_kwh(&self) -> Option<f64> {
        self.activity_energy_cost
            .as_ref()
            .map(CdxEnergyMeasure::as_kwh)
            .or(self.energy_kwh)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxEnergyMeasure {
    value: f64,
    unit: Option<String>,
}

impl CdxEnergyMeasure {
    /// Normalize the measure to kWh based on its unit (defaults to kWh when unspecified).
    fn as_kwh(&self) -> f64 {
        match self.unit.as_deref() {
            Some("Wh") => self.value / 1_000.0,
            Some("MWh") => self.value * 1_000.0,
            Some("J") => self.value / 3_600_000.0,
            Some("kJ") => self.value / 3_600.0,
            Some("MJ") => self.value / 3.6,
            _ => self.value,
        }
    }
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct CdxDataComponent {
    #[serde(rename = "type")]
    data_type: Option<String>,
    /// Spec key is `sensitiveData`; `sensitivityData` accepted for non-spec emitters.
    #[serde(rename = "sensitiveData", alias = "sensitivityData", default)]
    sensitivity_data: Vec<String>,
    governance: Option<CdxDataGovernance>,
}

/// Accept `component.data` as either the spec array of componentData or a single object.
fn deserialize_component_data<'de, D>(deserializer: D) -> Result<Vec<CdxDataComponent>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        Many(Vec<CdxDataComponent>),
        One(CdxDataComponent),
    }

    Ok(match Option::<OneOrMany>::deserialize(deserializer)? {
        None => Vec::new(),
        Some(OneOrMany::Many(items)) => items,
        Some(OneOrMany::One(item)) => vec![item],
    })
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct CdxDataGovernance {
    #[serde(default)]
    owners: Vec<CdxGovParty>,
    #[serde(default)]
    custodians: Vec<CdxGovParty>,
    #[serde(default)]
    stewards: Vec<CdxGovParty>,
}

/// A data-governance responsible party: the spec object `{ organization | contact }`,
/// or a bare string for non-spec emitters.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CdxGovParty {
    Text(String),
    Structured(CdxGovPartyObj),
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct CdxGovPartyObj {
    organization: Option<CdxGovOrganization>,
    contact: Option<CdxGovContact>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxGovOrganization {
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxGovContact {
    name: Option<String>,
    email: Option<String>,
}

impl CdxGovParty {
    /// A human-readable display name for a governance party.
    fn display_name(&self) -> Option<String> {
        match self {
            Self::Text(text) => Some(text.clone()),
            Self::Structured(party) => party
                .organization
                .as_ref()
                .and_then(|org| org.name.clone())
                .or_else(|| {
                    party
                        .contact
                        .as_ref()
                        .and_then(|contact| contact.name.clone().or_else(|| contact.email.clone()))
                }),
        }
    }
}

// ── CycloneDX Crypto Deserialization Structs (1.6+) ─────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxCryptoProperties {
    asset_type: Option<String>,
    oid: Option<String>,
    algorithm_properties: Option<CdxAlgorithmProperties>,
    certificate_properties: Option<CdxCertificateProperties>,
    related_crypto_material_properties: Option<CdxRelatedCryptoMaterialProperties>,
    protocol_properties: Option<CdxProtocolProperties>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxAlgorithmProperties {
    primitive: Option<String>,
    algorithm_family: Option<String>,
    parameter_set_identifier: Option<String>,
    mode: Option<String>,
    padding: Option<String>,
    crypto_functions: Option<Vec<String>>,
    execution_environment: Option<String>,
    implementation_platform: Option<String>,
    certification_level: Option<Vec<String>>,
    classical_security_level: Option<u32>,
    nist_quantum_security_level: Option<u8>,
    elliptic_curve: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxCertificateProperties {
    subject_name: Option<String>,
    issuer_name: Option<String>,
    not_valid_before: Option<String>,
    not_valid_after: Option<String>,
    signature_algorithm_ref: Option<String>,
    subject_public_key_ref: Option<String>,
    certificate_format: Option<String>,
    certificate_extension: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxRelatedCryptoMaterialProperties {
    #[serde(rename = "type")]
    material_type: Option<String>,
    id: Option<String>,
    state: Option<String>,
    size: Option<u32>,
    algorithm_ref: Option<String>,
    secured_by: Option<CdxSecuredBy>,
    format: Option<String>,
    creation_date: Option<String>,
    activation_date: Option<String>,
    update_date: Option<String>,
    expiration_date: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxSecuredBy {
    mechanism: Option<String>,
    algorithm_ref: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxProtocolProperties {
    #[serde(rename = "type")]
    protocol_type: Option<String>,
    version: Option<String>,
    cipher_suites: Option<Vec<CdxCipherSuite>>,
    ikev2_transform_types: Option<CdxIkev2TransformTypes>,
    crypto_ref_array: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxCipherSuite {
    name: Option<String>,
    algorithms: Option<Vec<String>>,
    identifiers: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxIkev2TransformTypes {
    encr: Option<Vec<String>>,
    prf: Option<Vec<String>>,
    integ: Option<Vec<String>>,
    ke: Option<Vec<String>>,
}

// ── Dependencies ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxDependency {
    #[serde(rename = "ref")]
    ref_field: String,
    depends_on: Option<Vec<String>>,
    /// CycloneDX 1.7: components this ref provides/implements
    provides: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxVulnerability {
    /// Optional per the schema: the vulnerability definition has NO
    /// required properties — a record may be identified via references
    /// or source only.
    id: Option<String>,
    source: Option<CdxVulnSource>,
    /// Alternate identifiers in other sources (id fallback)
    references: Option<Vec<CdxVulnReference>>,
    description: Option<String>,
    recommendation: Option<String>,
    ratings: Option<Vec<CdxRating>>,
    cwes: Option<Vec<u32>>,
    affects: Option<Vec<CdxAffects>>,
    analysis: Option<CdxAnalysis>,
}

/// Entry of vulnerability.references: an id in another source
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct CdxVulnReference {
    id: Option<String>,
    source: Option<CdxVulnSource>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct CdxVulnSource {
    /// Optional per the schema: vulnerabilitySource has NO required
    /// fields — a source may be given as a URL only.
    name: Option<String>,
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

/// Derive the spec version of an XML BOM.
///
/// Spec-conformant documents carry it in the xmlns namespace URI
/// (e.g., `http://cyclonedx.org/schema/bom/1.5`); the `version` attribute is
/// the integer BOM document version. Documents that put a dotted spec version
/// in the `version` attribute are accepted for back-compat.
fn xml_spec_version(xmlns: Option<&str>, version_attr: Option<&str>) -> String {
    if let Some(ns) = xmlns
        && ns.contains("cyclonedx.org/schema/bom/")
        && let Some(segment) = ns.rsplit('/').next()
        && !segment.is_empty()
    {
        return segment.to_string();
    }
    if let Some(v) = version_attr
        && v.contains('.')
    {
        return v.to_string();
    }
    "1.4".to_string()
}

/// Root BOM element for XML format
#[derive(Debug, Deserialize)]
#[serde(rename = "bom")]
struct CycloneDxBomXml {
    /// Namespace attribute carrying the spec version (e.g., `.../schema/bom/1.5`)
    #[serde(rename = "@xmlns")]
    xmlns: Option<String>,
    /// Version attribute on bom element: the integer BOM document version
    #[serde(rename = "@version")]
    version: Option<String>,
    /// Serial number attribute
    #[serde(rename = "@serialNumber")]
    serial_number: Option<String>,
    /// Metadata element
    metadata: Option<CdxMetadataXml>,
    /// Components wrapper element
    components: Option<CdxComponentsXml>,
    /// Services wrapper element (SaaSBOM, 1.4+)
    services: Option<CdxServicesXml>,
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
    component: Option<CdxComponentXml>,
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
    component: Vec<CdxComponentXml>,
}

/// Component element for XML format (attributes plus wrapper child elements)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
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
    scope: Option<String>,
    purl: Option<String>,
    cpe: Option<String>,
    /// Software Heritage persistent identifiers (1.6+)
    #[serde(default)]
    swhid: Vec<String>,
    description: Option<String>,
    author: Option<String>,
    copyright: Option<String>,
    licenses: Option<CdxLicensesXml>,
    supplier: Option<CdxSupplier>,
    hashes: Option<CdxHashesXml>,
    #[serde(rename = "externalReferences")]
    external_references: Option<CdxExternalReferencesXml>,
    properties: Option<CdxPropertiesXml>,
    /// Package URL Version Range syntax (1.7+)
    version_range: Option<String>,
    /// Dataset metadata (CycloneDX 1.5+): repeated `<data>` componentData
    /// elements directly under `<component>` (no wrapper element in XML).
    #[serde(rename = "data", default)]
    data: Vec<CdxDataXml>,
    /// Cryptographic properties (1.6+, camelCase in XML)
    #[serde(rename = "cryptoProperties")]
    crypto_properties: Option<CdxCryptoProperties>,
    /// Nested component assemblies (recursive)
    components: Option<CdxComponentsXml>,
}

impl From<CdxComponentXml> for CdxComponent {
    fn from(xml: CdxComponentXml) -> Self {
        let licenses = xml.licenses.map(|wrapper| {
            wrapper
                .licenses
                .into_iter()
                .map(|choice| match choice {
                    CdxLicenseChoiceXml::License(license) => CdxLicenseChoice {
                        license: Some(license),
                        expression: None,
                    },
                    CdxLicenseChoiceXml::Expression(expression) => CdxLicenseChoice {
                        license: None,
                        expression: Some(expression),
                    },
                })
                .collect()
        });

        let hashes = xml.hashes.map(|wrapper| {
            wrapper
                .hash
                .into_iter()
                .map(|h| CdxHash {
                    alg: h.alg,
                    content: h.content,
                })
                .collect()
        });

        let external_references = xml.external_references.map(|wrapper| {
            wrapper
                .reference
                .into_iter()
                .map(|r| CdxExternalReference {
                    ref_type: r.ref_type,
                    url: r.url,
                    comment: r.comment,
                })
                .collect()
        });

        let properties = xml.properties.map(|wrapper| {
            wrapper
                .property
                .into_iter()
                .map(|p| CdxProperty {
                    // XSD requires the @name attribute
                    name: Some(p.name),
                    value: p.value,
                })
                .collect()
        });

        Self {
            component_type: xml.component_type,
            bom_ref: xml.bom_ref,
            name: xml.name,
            version: xml.version,
            group: xml.group,
            scope: xml.scope,
            purl: xml.purl,
            cpe: xml.cpe,
            swhid: xml.swhid,
            description: xml.description,
            author: xml.author,
            copyright: xml.copyright,
            licenses,
            supplier: xml.supplier,
            hashes,
            external_references,
            properties,
            is_external: false,
            version_range: xml.version_range,
            // XML deserialization of modelCard is not supported yet; ML-model
            // metadata is only parsed from JSON documents. Dataset evidence
            // (`<data>` componentData) IS parsed, so the AI compliance gates
            // see XML AI-BOM datasets exactly like their JSON equivalents.
            model_card: None,
            data_components: xml.data.into_iter().map(CdxDataComponent::from).collect(),
            crypto_properties: xml.crypto_properties,
            components: xml
                .components
                .map(|w| w.component.into_iter().map(Into::into).collect()),
        }
    }
}

/// Licenses wrapper element for XML format
#[derive(Debug, Deserialize)]
struct CdxLicensesXml {
    #[serde(rename = "$value", default)]
    licenses: Vec<CdxLicenseChoiceXml>,
}

/// License choice for XML format: either a `<license>` or `<expression>` element
#[derive(Debug, Deserialize)]
enum CdxLicenseChoiceXml {
    #[serde(rename = "license")]
    License(CdxLicense),
    #[serde(rename = "expression")]
    Expression(String),
}

/// Hashes wrapper element for XML format
#[derive(Debug, Deserialize)]
struct CdxHashesXml {
    #[serde(rename = "hash", default)]
    hash: Vec<CdxHashXml>,
}

/// Hash element for XML format
#[derive(Debug, Deserialize)]
struct CdxHashXml {
    #[serde(rename = "@alg")]
    alg: String,
    #[serde(rename = "$value")]
    content: String,
}

/// External references wrapper element for XML format
#[derive(Debug, Deserialize)]
struct CdxExternalReferencesXml {
    #[serde(rename = "reference", default)]
    reference: Vec<CdxExternalReferenceXml>,
}

/// External reference element for XML format
#[derive(Debug, Deserialize)]
struct CdxExternalReferenceXml {
    #[serde(rename = "@type")]
    ref_type: String,
    url: String,
    comment: Option<String>,
}

/// Properties wrapper element for XML format
#[derive(Debug, Deserialize)]
struct CdxPropertiesXml {
    #[serde(rename = "property", default)]
    property: Vec<CdxPropertyXml>,
}

/// Property element for XML format
#[derive(Debug, Deserialize)]
struct CdxPropertyXml {
    #[serde(rename = "@name")]
    name: String,
    /// Optional: a self-closing `<property name="x"/>` is schema-valid
    #[serde(rename = "$value", default)]
    value: Option<String>,
}

/// componentData element for XML format (CycloneDX 1.5+ `<data>` child of
/// `<component>`): `<type>` / repeated `<sensitiveData>` / `<governance>`
/// child elements instead of JSON object keys.
#[derive(Debug, Deserialize)]
struct CdxDataXml {
    #[serde(rename = "type")]
    data_type: Option<String>,
    #[serde(rename = "sensitiveData", default)]
    sensitive_data: Vec<String>,
    governance: Option<CdxDataGovernanceXml>,
}

impl From<CdxDataXml> for CdxDataComponent {
    fn from(xml: CdxDataXml) -> Self {
        Self {
            data_type: xml.data_type,
            sensitivity_data: xml.sensitive_data,
            governance: xml.governance.map(CdxDataGovernance::from),
        }
    }
}

/// dataGovernance element for XML format: unlike JSON, each responsible-party
/// list is wrapped (`<owners><owner>…</owner></owners>` etc.).
#[derive(Debug, Deserialize)]
struct CdxDataGovernanceXml {
    owners: Option<CdxGovOwnersXml>,
    custodians: Option<CdxGovCustodiansXml>,
    stewards: Option<CdxGovStewardsXml>,
}

impl From<CdxDataGovernanceXml> for CdxDataGovernance {
    fn from(xml: CdxDataGovernanceXml) -> Self {
        Self {
            owners: xml
                .owners
                .map_or_else(Vec::new, |w| w.owner.into_iter().map(Into::into).collect()),
            custodians: xml.custodians.map_or_else(Vec::new, |w| {
                w.custodian.into_iter().map(Into::into).collect()
            }),
            stewards: xml.stewards.map_or_else(Vec::new, |w| {
                w.steward.into_iter().map(Into::into).collect()
            }),
        }
    }
}

/// Owners wrapper element for XML data governance
#[derive(Debug, Deserialize)]
struct CdxGovOwnersXml {
    #[serde(rename = "owner", default)]
    owner: Vec<CdxGovPartyXml>,
}

/// Custodians wrapper element for XML data governance
#[derive(Debug, Deserialize)]
struct CdxGovCustodiansXml {
    #[serde(rename = "custodian", default)]
    custodian: Vec<CdxGovPartyXml>,
}

/// Stewards wrapper element for XML data governance
#[derive(Debug, Deserialize)]
struct CdxGovStewardsXml {
    #[serde(rename = "steward", default)]
    steward: Vec<CdxGovPartyXml>,
}

/// Responsible-party element for XML data governance: a choice of
/// `<organization>` or `<contact>` (spec `dataGovernanceResponsiblePartyType`).
#[derive(Debug, Deserialize)]
struct CdxGovPartyXml {
    organization: Option<CdxGovOrganization>,
    contact: Option<CdxGovContact>,
}

impl From<CdxGovPartyXml> for CdxGovParty {
    fn from(xml: CdxGovPartyXml) -> Self {
        Self::Structured(CdxGovPartyObj {
            organization: xml.organization,
            contact: xml.contact,
        })
    }
}

/// Dependencies wrapper element for XML format
#[derive(Debug, Deserialize)]
struct CdxDependenciesXml {
    #[serde(rename = "dependency", default)]
    dependency: Vec<CdxDependencyXml>,
}

/// Dependency element for XML format
#[derive(Debug, Deserialize)]
struct CdxDependencyXml {
    #[serde(rename = "@ref")]
    ref_field: String,
    #[serde(rename = "dependency", default)]
    depends_on: Vec<CdxDependencyRefXml>,
    /// CycloneDX 1.7: components this ref provides/implements
    #[serde(rename = "provides", default)]
    provides: Vec<CdxDependencyRefXml>,
}

/// Dependency reference for XML nested dependencies
#[derive(Debug, Deserialize)]
struct CdxDependencyRefXml {
    #[serde(rename = "@ref")]
    ref_field: String,
}

impl From<CdxDependencyXml> for CdxDependency {
    fn from(xml: CdxDependencyXml) -> Self {
        let depends_on: Vec<String> = xml.depends_on.into_iter().map(|d| d.ref_field).collect();
        let provides: Vec<String> = xml.provides.into_iter().map(|p| p.ref_field).collect();
        Self {
            ref_field: xml.ref_field,
            depends_on: (!depends_on.is_empty()).then_some(depends_on),
            provides: (!provides.is_empty()).then_some(provides),
        }
    }
}

/// Vulnerabilities wrapper element for XML format
#[derive(Debug, Deserialize)]
struct CdxVulnerabilitiesXml {
    #[serde(rename = "vulnerability", default)]
    vulnerability: Vec<CdxVulnerabilityXml>,
}

/// Vulnerability element for XML format
#[derive(Debug, Deserialize)]
struct CdxVulnerabilityXml {
    /// Optional per the spec (minOccurs="0" in the XSD)
    id: Option<String>,
    source: Option<CdxVulnSource>,
    /// References wrapper (alternate ids in other sources)
    references: Option<CdxVulnReferencesXml>,
    description: Option<String>,
    recommendation: Option<String>,
    ratings: Option<CdxRatingsXml>,
    cwes: Option<CdxCwesXml>,
    affects: Option<CdxAffectsXml>,
    analysis: Option<CdxAnalysisXml>,
}

/// References wrapper element for XML vulnerabilities
#[derive(Debug, Deserialize)]
struct CdxVulnReferencesXml {
    #[serde(rename = "reference", default)]
    reference: Vec<CdxVulnReference>,
}

/// Ratings wrapper element for XML format
#[derive(Debug, Deserialize)]
struct CdxRatingsXml {
    #[serde(rename = "rating", default)]
    rating: Vec<CdxRating>,
}

/// CWEs wrapper element for XML format
#[derive(Debug, Deserialize)]
struct CdxCwesXml {
    #[serde(rename = "cwe", default)]
    cwe: Vec<u32>,
}

/// Affects wrapper element for XML format
#[derive(Debug, Deserialize)]
struct CdxAffectsXml {
    #[serde(rename = "target", default)]
    target: Vec<CdxAffectsTargetXml>,
}

/// Affects target element for XML format
#[derive(Debug, Deserialize)]
struct CdxAffectsTargetXml {
    #[serde(rename = "ref")]
    ref_field: String,
    versions: Option<CdxVersionsXml>,
}

/// Affected versions wrapper element for XML format
#[derive(Debug, Deserialize)]
struct CdxVersionsXml {
    #[serde(rename = "version", default)]
    version: Vec<CdxVersionAffected>,
}

/// Analysis element for XML format
#[derive(Debug, Deserialize)]
struct CdxAnalysisXml {
    state: Option<String>,
    justification: Option<String>,
    detail: Option<String>,
    responses: Option<CdxResponsesXml>,
}

/// Analysis responses wrapper element for XML format
#[derive(Debug, Deserialize)]
struct CdxResponsesXml {
    #[serde(rename = "response", default)]
    response: Vec<String>,
}

impl From<CdxVulnerabilityXml> for CdxVulnerability {
    fn from(xml: CdxVulnerabilityXml) -> Self {
        Self {
            id: xml.id,
            source: xml.source,
            references: xml.references.map(|r| r.reference),
            description: xml.description,
            recommendation: xml.recommendation,
            ratings: xml.ratings.map(|r| r.rating),
            cwes: xml.cwes.map(|c| c.cwe),
            affects: xml.affects.map(|a| {
                a.target
                    .into_iter()
                    .map(|t| CdxAffects {
                        ref_field: t.ref_field,
                        versions: t.versions.map(|v| v.version),
                    })
                    .collect()
            }),
            analysis: xml.analysis.map(|a| CdxAnalysis {
                state: a.state,
                justification: a.justification,
                response: a.responses.map(|r| r.response),
                detail: a.detail,
            }),
        }
    }
}

/// Services wrapper element for XML format
#[derive(Debug, Deserialize)]
struct CdxServicesXml {
    #[serde(rename = "service", default)]
    service: Vec<CdxServiceXml>,
}

/// Service element for XML format
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxServiceXml {
    #[serde(rename = "@bom-ref")]
    bom_ref: Option<String>,
    provider: Option<CdxSupplier>,
    group: Option<String>,
    name: String,
    version: Option<String>,
    description: Option<String>,
    endpoints: Option<CdxEndpointsXml>,
    licenses: Option<CdxLicensesXml>,
    #[serde(rename = "externalReferences")]
    external_references: Option<CdxExternalReferencesXml>,
    properties: Option<CdxPropertiesXml>,
    /// Nested services (recursive)
    services: Option<CdxServicesXml>,
}

/// Endpoints wrapper element for XML services
#[derive(Debug, Deserialize)]
struct CdxEndpointsXml {
    #[serde(rename = "endpoint", default)]
    endpoint: Vec<String>,
}

impl From<CdxServiceXml> for CdxService {
    fn from(xml: CdxServiceXml) -> Self {
        Self {
            bom_ref: xml.bom_ref,
            provider: xml.provider,
            group: xml.group,
            name: xml.name,
            version: xml.version,
            description: xml.description,
            endpoints: xml.endpoints.map(|e| e.endpoint),
            licenses: xml.licenses.map(|wrapper| {
                wrapper
                    .licenses
                    .into_iter()
                    .map(|choice| match choice {
                        CdxLicenseChoiceXml::License(license) => CdxLicenseChoice {
                            license: Some(license),
                            expression: None,
                        },
                        CdxLicenseChoiceXml::Expression(expression) => CdxLicenseChoice {
                            license: None,
                            expression: Some(expression),
                        },
                    })
                    .collect()
            }),
            external_references: xml.external_references.map(|wrapper| {
                wrapper
                    .reference
                    .into_iter()
                    .map(|r| CdxExternalReference {
                        ref_type: r.ref_type,
                        url: r.url,
                        comment: r.comment,
                    })
                    .collect()
            }),
            properties: xml.properties.map(|wrapper| {
                wrapper
                    .property
                    .into_iter()
                    .map(|p| CdxProperty {
                        // XSD requires the @name attribute
                        name: Some(p.name),
                        value: p.value,
                    })
                    .collect()
            }),
            services: xml
                .services
                .map(|w| w.service.into_iter().map(Into::into).collect()),
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(xml: &str) -> NormalizedSbom {
        CycloneDxParser::new()
            .parse_str(xml)
            .expect("XML should parse")
    }

    /// CDXA was introduced in 1.6: the gate must reject every earlier or
    /// unparseable specVersion and accept 1.6+.
    #[test]
    fn cdxa_version_gate() {
        assert!(!cdx_supports_cdxa("1.4"));
        assert!(!cdx_supports_cdxa("1.5"));
        assert!(cdx_supports_cdxa("1.6"));
        assert!(cdx_supports_cdxa("1.7"));
        assert!(cdx_supports_cdxa("2.0"));
        assert!(!cdx_supports_cdxa(""));
        assert!(!cdx_supports_cdxa("not-a-version"));
    }

    fn component<'a>(sbom: &'a NormalizedSbom, name: &str) -> &'a Component {
        sbom.components
            .values()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("component {name} not found"))
    }

    /// A hostile leading rating (severity "none") must not freeze severity and
    /// suppress a later CVSS-10 rating — highest severity across ratings wins.
    #[test]
    fn severity_takes_max_across_ratings_not_first() {
        let sbom = parse_json(
            r#"{"bomFormat":"CycloneDX","specVersion":"1.5",
                "components":[{"type":"library","bom-ref":"c","name":"libc","version":"1.0","purl":"pkg:npm/libc@1.0"}],
                "vulnerabilities":[{"id":"CVE-1","affects":[{"ref":"c"}],
                    "ratings":[{"severity":"none"},{"method":"CVSSv3","score":10.0,"severity":"critical"}]}]}"#,
        );
        let comp = component(&sbom, "libc");
        assert_eq!(comp.vulnerabilities.len(), 1);
        assert_eq!(comp.vulnerabilities[0].severity, Some(Severity::Critical));
    }

    /// An unknown/misspelled VEX justification must yield None, never fabricate
    /// ComponentNotPresent (the strongest "it isn't even here" claim).
    #[test]
    fn unknown_vex_justification_is_none_not_component_not_present() {
        let sbom = parse_json(
            r#"{"bomFormat":"CycloneDX","specVersion":"1.5",
                "components":[{"type":"library","bom-ref":"c","name":"libc","version":"1.0","purl":"pkg:npm/libc@1.0"}],
                "vulnerabilities":[{"id":"CVE-1","affects":[{"ref":"c"}],
                    "analysis":{"state":"not_affected","justification":"totally_made_up"}}]}"#,
        );
        let comp = component(&sbom, "libc");
        let vex = comp.vulnerabilities[0].vex_status.as_ref().unwrap();
        assert_eq!(vex.justification, None);
    }

    /// A trailing fabricated `not_affected` must not erase an earlier real
    /// `affected` at the component-level VEX slot.
    #[test]
    fn component_vex_keeps_highest_risk_not_last_wins() {
        let sbom = parse_json(
            r#"{"bomFormat":"CycloneDX","specVersion":"1.5",
                "components":[{"type":"library","bom-ref":"c","name":"libc","version":"1.0","purl":"pkg:npm/libc@1.0"}],
                "vulnerabilities":[
                    {"id":"CVE-REAL","affects":[{"ref":"c"}],"analysis":{"state":"affected"}},
                    {"id":"CVE-FAKE","affects":[{"ref":"c"}],"analysis":{"state":"not_affected"}}]}"#,
        );
        let comp = component(&sbom, "libc");
        assert_eq!(
            comp.vex_status.as_ref().map(|v| &v.status),
            Some(&VexState::Affected),
            "a fabricated not_affected must not override a real affected"
        );
    }

    /// `exploitable` must map to Affected, not collapse to UnderInvestigation.
    #[test]
    fn exploitable_state_maps_to_affected() {
        let sbom = parse_json(
            r#"{"bomFormat":"CycloneDX","specVersion":"1.5",
                "components":[{"type":"library","bom-ref":"c","name":"libc","version":"1.0","purl":"pkg:npm/libc@1.0"}],
                "vulnerabilities":[{"id":"CVE-1","affects":[{"ref":"c"}],"analysis":{"state":"exploitable"}}]}"#,
        );
        let comp = component(&sbom, "libc");
        assert_eq!(
            comp.vulnerabilities[0]
                .vex_status
                .as_ref()
                .map(|v| &v.status),
            Some(&VexState::Affected)
        );
    }

    /// A huge vulnerability description must be capped, and repeated affects
    /// targets deduped — bounding the memory-amplification fan-out.
    #[test]
    fn huge_description_is_capped_and_affects_deduped() {
        let big = "A".repeat(2 * 1024 * 1024); // 2 MiB
        let json = format!(
            r#"{{"bomFormat":"CycloneDX","specVersion":"1.5",
                "components":[{{"type":"library","bom-ref":"c","name":"libc","version":"1.0","purl":"pkg:npm/libc@1.0"}}],
                "vulnerabilities":[{{"id":"CVE-1","description":"{big}",
                    "affects":[{{"ref":"c"}},{{"ref":"c"}},{{"ref":"c"}}]}}]}}"#
        );
        let sbom = parse_json(&json);
        let comp = component(&sbom, "libc");
        assert_eq!(
            comp.vulnerabilities.len(),
            1,
            "duplicate affects must dedup"
        );
        let desc = comp.vulnerabilities[0].description.as_ref().unwrap();
        assert!(
            desc.len() <= super::super::MAX_VULN_DESCRIPTION_BYTES + 32,
            "description must be capped, got {} bytes",
            desc.len()
        );
    }

    /// affects[].versions per-entry status must gate the attachment itself:
    /// a component whose exact version is listed "unaffected" gets no vuln,
    /// while one whose version is listed "affected" still does.
    #[test]
    fn unaffected_version_status_skips_vuln_attachment() {
        let vulns = r#""vulnerabilities":[{"id":"CVE-1","affects":[{"ref":"c","versions":[
            {"version":"1.2.3","status":"affected"},
            {"version":"2.0.0","status":"unaffected"}]}]}]"#;
        let json = |version: &str| {
            format!(
                r#"{{"bomFormat":"CycloneDX","specVersion":"1.5",
                    "components":[{{"type":"library","bom-ref":"c","name":"libc","version":"{version}","purl":"pkg:npm/libc@{version}"}}],
                    {vulns}}}"#
            )
        };

        let affected = parse_json(&json("1.2.3"));
        assert_eq!(
            component(&affected, "libc").vulnerabilities.len(),
            1,
            "version listed as affected must receive the vuln"
        );

        let unaffected = parse_json(&json("2.0.0"));
        assert_eq!(
            component(&unaffected, "libc").vulnerabilities.len(),
            0,
            "version explicitly listed as unaffected must not receive the vuln"
        );

        // Unlisted version: conservative — attach.
        let unlisted = parse_json(&json("3.0.0"));
        assert_eq!(component(&unlisted, "libc").vulnerabilities.len(), 1);
    }

    /// Range entries and versionless components never trigger the
    /// "unaffected" skip — no vers-range parsing, false positives are safer.
    #[test]
    fn unaffected_skip_ignores_ranges_and_versionless_components() {
        let ranged = parse_json(
            r#"{"bomFormat":"CycloneDX","specVersion":"1.5",
                "components":[{"type":"library","bom-ref":"c","name":"libc","version":"2.0.0","purl":"pkg:npm/libc@2.0.0"}],
                "vulnerabilities":[{"id":"CVE-1","affects":[{"ref":"c","versions":[
                    {"range":"vers:npm/>=2.0.0","status":"unaffected"}]}]}]}"#,
        );
        assert_eq!(
            component(&ranged, "libc").vulnerabilities.len(),
            1,
            "unaffected range entries must not skip (no range parsing)"
        );

        let versionless = parse_json(
            r#"{"bomFormat":"CycloneDX","specVersion":"1.5",
                "components":[{"type":"library","bom-ref":"c","name":"libc"}],
                "vulnerabilities":[{"id":"CVE-1","affects":[{"ref":"c","versions":[
                    {"version":"2.0.0","status":"unaffected"}]}]}]}"#,
        );
        assert_eq!(
            component(&versionless, "libc").vulnerabilities.len(),
            1,
            "a component without a concrete version always attaches"
        );
    }

    /// Non-CVSS rating methods (OWASP/SSVC) must not be mislabeled as CVSS.
    #[test]
    fn non_cvss_rating_method_produces_no_cvss_score() {
        let sbom = parse_json(
            r#"{"bomFormat":"CycloneDX","specVersion":"1.5",
                "components":[{"type":"library","bom-ref":"c","name":"libc","version":"1.0","purl":"pkg:npm/libc@1.0"}],
                "vulnerabilities":[{"id":"CVE-1","affects":[{"ref":"c"}],
                    "ratings":[{"method":"OWASP","score":5.0}]}]}"#,
        );
        let comp = component(&sbom, "libc");
        assert!(
            comp.vulnerabilities[0].cvss.is_empty(),
            "an OWASP rating must not become a CVSS score"
        );
    }

    #[test]
    fn test_xml_component_attributes_parse() {
        let sbom = parse(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">
  <components>
    <component type="library" bom-ref="pkg:npm/lodash@4.17.21">
      <name>lodash</name>
      <version>4.17.21</version>
      <purl>pkg:npm/lodash@4.17.21</purl>
    </component>
  </components>
</bom>"#,
        );

        assert_eq!(sbom.component_count(), 1);
        let comp = component(&sbom, "lodash");
        assert_eq!(comp.component_type, ComponentType::Library);
        assert_eq!(comp.version.as_deref(), Some("4.17.21"));
        assert_eq!(
            comp.identifiers.purl.as_deref(),
            Some("pkg:npm/lodash@4.17.21")
        );
        assert_eq!(comp.identifiers.format_id, "pkg:npm/lodash@4.17.21");
    }

    #[test]
    fn test_xml_license_choice() {
        let sbom = parse(
            r#"<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">
  <components>
    <component type="library">
      <name>lib-a</name>
      <licenses>
        <license><id>MIT</id></license>
        <license><name>Custom License</name></license>
        <expression>Apache-2.0 OR MIT</expression>
      </licenses>
    </component>
  </components>
</bom>"#,
        );

        let declared: Vec<&str> = component(&sbom, "lib-a")
            .licenses
            .declared
            .iter()
            .map(|l| l.expression.as_str())
            .collect();
        assert_eq!(declared, vec!["MIT", "Custom License", "Apache-2.0 OR MIT"]);
    }

    #[test]
    fn test_xml_sha256_hash_parses() {
        let sbom = parse(
            r#"<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">
  <components>
    <component type="library">
      <name>lib-a</name>
      <hashes>
        <hash alg="SHA-256">d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592</hash>
      </hashes>
    </component>
  </components>
</bom>"#,
        );

        let comp = component(&sbom, "lib-a");
        assert_eq!(comp.hashes.len(), 1);
        assert_eq!(comp.hashes[0].algorithm, HashAlgorithm::Sha256);
        assert_eq!(
            comp.hashes[0].value,
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        );
    }

    #[test]
    fn test_xml_nested_dependencies_produce_edges() {
        let sbom = parse(
            r#"<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">
  <components>
    <component type="application" bom-ref="app">
      <name>app</name>
    </component>
    <component type="library" bom-ref="lib-a">
      <name>lib-a</name>
    </component>
    <component type="library" bom-ref="lib-b">
      <name>lib-b</name>
    </component>
  </components>
  <dependencies>
    <dependency ref="app">
      <dependency ref="lib-a"/>
      <dependency ref="lib-b"/>
    </dependency>
    <dependency ref="lib-a">
      <dependency ref="lib-b"/>
    </dependency>
  </dependencies>
</bom>"#,
        );

        assert_eq!(sbom.edges.len(), 3);
        let app_id = &component(&sbom, "app").canonical_id;
        let lib_b_id = &component(&sbom, "lib-b").canonical_id;
        assert!(
            sbom.edges
                .iter()
                .any(|e| &e.from == app_id && &e.to == lib_b_id)
        );
    }

    #[test]
    fn test_xml_metadata_component_becomes_primary() {
        let sbom = parse(
            r#"<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">
  <metadata>
    <timestamp>2024-01-15T10:00:00Z</timestamp>
    <component type="application" bom-ref="acme-app">
      <name>acme-app</name>
      <version>1.0.0</version>
    </component>
  </metadata>
  <components>
    <component type="library">
      <name>lib-a</name>
    </component>
  </components>
</bom>"#,
        );

        assert_eq!(sbom.component_count(), 2);
        let primary_id = sbom
            .primary_component_id
            .as_ref()
            .expect("primary component should be set");
        assert_eq!(
            sbom.components.get(primary_id).map(|c| c.name.as_str()),
            Some("acme-app")
        );
    }

    #[test]
    fn test_xml_spec_version_from_xmlns() {
        let sbom = parse(
            r#"<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="3">
  <components>
    <component type="library">
      <name>lib-a</name>
      <swhid>swh:1:rel:22ece559cc7cc2364edc5e5593d63ae8bd229f9f</swhid>
    </component>
  </components>
</bom>"#,
        );

        assert_eq!(sbom.document.spec_version, "1.6");
        assert!(
            component(&sbom, "lib-a")
                .identifiers
                .swhid
                .iter()
                .any(|s| s.to_string().contains("swh:1:rel:"))
        );
    }

    /// XML `<data>` componentData must populate `Component::dataset` exactly
    /// like the JSON `component.data` path, so the AI compliance dataset gates
    /// (`dataset.is_some()`) see XML AI-BOMs. Regression: the XML converter
    /// previously hardcoded `data_components: Vec::new()`, silently dropping
    /// spec-valid `<data>` evidence and the entire BSI-AI Datasets cluster.
    #[test]
    fn test_xml_component_data_populates_dataset() {
        let sbom = parse(
            r#"<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1">
  <components>
    <component type="data" bom-ref="dataset-1">
      <name>training-corpus</name>
      <version>1.0.0</version>
      <data>
        <type>dataset</type>
        <sensitiveData>pii</sensitiveData>
        <sensitiveData>phi</sensitiveData>
        <governance>
          <custodians>
            <custodian>
              <organization>
                <name>ML Ops</name>
              </organization>
            </custodian>
          </custodians>
          <stewards>
            <steward>
              <contact>
                <email>steward@example.com</email>
              </contact>
            </steward>
          </stewards>
          <owners>
            <owner>
              <organization>
                <name>Data Platform Team</name>
              </organization>
            </owner>
            <owner>
              <contact>
                <name>Jane Doe</name>
                <email>jane@example.com</email>
              </contact>
            </owner>
          </owners>
        </governance>
      </data>
    </component>
    <component type="data" bom-ref="config-1">
      <name>app-config</name>
      <version>1.0.0</version>
    </component>
  </components>
</bom>"#,
        );

        let dataset = component(&sbom, "training-corpus")
            .dataset
            .as_ref()
            .expect("XML <data> element must populate Component::dataset");
        assert_eq!(dataset.dataset_type.as_deref(), Some("dataset"));
        assert_eq!(
            dataset.sensitivity_classifications,
            vec!["pii".to_string(), "phi".to_string()]
        );
        // Owners, custodians and stewards all contribute governance names,
        // matching the JSON conversion.
        assert_eq!(
            dataset.governance_owners,
            vec![
                "Data Platform Team".to_string(),
                "Jane Doe".to_string(),
                "ML Ops".to_string(),
                "steward@example.com".to_string(),
            ]
        );

        // A bare `type: data` component without a <data> element stays out of
        // the AI dataset scope, exactly like the JSON de-scoping.
        assert!(
            component(&sbom, "app-config").dataset.is_none(),
            "no <data> evidence must mean no DatasetInfo"
        );
    }

    #[test]
    fn test_xml_spec_version_helper_fallbacks() {
        assert_eq!(
            xml_spec_version(Some("http://cyclonedx.org/schema/bom/1.5"), Some("1")),
            "1.5"
        );
        assert_eq!(xml_spec_version(None, Some("1.4")), "1.4");
        assert_eq!(xml_spec_version(None, Some("1")), "1.4");
        assert_eq!(
            xml_spec_version(Some("http://example.com/other"), None),
            "1.4"
        );
    }

    #[test]
    fn test_xml_vulnerability_attaches_to_component() {
        let sbom = parse(
            r#"<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">
  <components>
    <component type="library" bom-ref="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1">
      <name>log4j-core</name>
      <version>2.14.1</version>
    </component>
  </components>
  <vulnerabilities>
    <vulnerability>
      <id>CVE-2021-44228</id>
      <source>
        <name>NVD</name>
        <url>https://nvd.nist.gov/vuln/detail/CVE-2021-44228</url>
      </source>
      <ratings>
        <rating>
          <score>10.0</score>
          <severity>critical</severity>
          <method>CVSSv31</method>
          <vector>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H</vector>
        </rating>
      </ratings>
      <affects>
        <target>
          <ref>pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1</ref>
          <versions>
            <version>
              <version>2.14.1</version>
              <status>affected</status>
            </version>
          </versions>
        </target>
      </affects>
    </vulnerability>
  </vulnerabilities>
</bom>"#,
        );

        let comp = component(&sbom, "log4j-core");
        assert_eq!(comp.vulnerabilities.len(), 1);
        let vuln = &comp.vulnerabilities[0];
        assert_eq!(vuln.id, "CVE-2021-44228");
        assert_eq!(vuln.severity, Some(Severity::Critical));
        assert_eq!(vuln.affected_versions, vec!["2.14.1".to_string()]);
        assert_eq!(sbom.vulnerability_counts().critical, 1);
    }

    /// Vulnerabilities are attached after component conversion, so the
    /// content hashes must be recomputed afterwards — otherwise the same
    /// document with and without its vulnerability section produces
    /// identical component (and SBOM) hashes, making vulnerability-only
    /// changes invisible to the diff gate and the incremental cache.
    #[test]
    fn test_vulnerabilities_are_reflected_in_content_hashes() {
        let without_vuln = r#"<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">
  <components>
    <component type="library" bom-ref="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1">
      <name>log4j-core</name>
      <version>2.14.1</version>
    </component>
  </components>
</bom>"#;
        let with_vuln = r#"<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">
  <components>
    <component type="library" bom-ref="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1">
      <name>log4j-core</name>
      <version>2.14.1</version>
    </component>
  </components>
  <vulnerabilities>
    <vulnerability>
      <id>CVE-2021-44228</id>
      <affects>
        <target>
          <ref>pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1</ref>
        </target>
      </affects>
    </vulnerability>
  </vulnerabilities>
</bom>"#;

        let clean = parse(without_vuln);
        let vulnerable = parse(with_vuln);

        assert_ne!(
            component(&clean, "log4j-core").content_hash,
            component(&vulnerable, "log4j-core").content_hash,
            "component content hash must reflect attached vulnerabilities"
        );
        assert_ne!(
            clean.content_hash, vulnerable.content_hash,
            "SBOM content hash must reflect attached vulnerabilities"
        );
    }

    fn parse_json(json: &str) -> NormalizedSbom {
        CycloneDxParser::new()
            .parse_str(json)
            .expect("JSON should parse")
    }

    /// Real-world emitters (and the repo's own demo fixtures) reference
    /// components by purl in `dependencies[].ref`/`dependsOn` when components
    /// declare no bom-ref. Those edges must resolve, not silently vanish.
    #[test]
    fn dependencies_resolve_by_purl_when_no_bom_ref() {
        let sbom = parse_json(
            r#"{"bomFormat":"CycloneDX","specVersion":"1.5",
                "components":[
                    {"type":"library","name":"express","version":"4.18.2","purl":"pkg:npm/express@4.18.2"},
                    {"type":"library","name":"body-parser","version":"1.20.1","purl":"pkg:npm/body-parser@1.20.1"}],
                "dependencies":[{"ref":"pkg:npm/express@4.18.2","dependsOn":["pkg:npm/body-parser@1.20.1"]}]}"#,
        );
        let from = component(&sbom, "express").canonical_id.clone();
        let to = component(&sbom, "body-parser").canonical_id.clone();
        assert!(
            sbom.edges.iter().any(|e| e.from == from && e.to == to),
            "purl-shaped dependency refs must resolve to components: {:?}",
            sbom.edges
        );
    }

    /// `vulnerabilities[].affects[].ref` given as a purl must attach to the
    /// matching component — a dropped critical CVE is a silent lie.
    #[test]
    fn vulnerability_affects_resolve_by_purl() {
        let sbom = parse_json(
            r#"{"bomFormat":"CycloneDX","specVersion":"1.5",
                "components":[{"type":"library","name":"axios","version":"1.4.0","purl":"pkg:npm/axios@1.4.0"}],
                "vulnerabilities":[{"id":"CVE-2023-45857","affects":[{"ref":"pkg:npm/axios@1.4.0"}],
                    "ratings":[{"method":"CVSSv31","score":9.8,"severity":"critical"}]}]}"#,
        );
        let comp = component(&sbom, "axios");
        assert_eq!(comp.vulnerabilities.len(), 1);
        assert_eq!(comp.vulnerabilities[0].id, "CVE-2023-45857");
    }

    /// A purl fallback key must never shadow a genuine bom-ref: when one
    /// component's bom-ref equals another component's purl, the bom-ref wins.
    #[test]
    fn bom_ref_wins_over_colliding_purl() {
        let sbom = parse_json(
            r#"{"bomFormat":"CycloneDX","specVersion":"1.5",
                "components":[
                    {"type":"library","bom-ref":"pkg:npm/shared@1.0","name":"left","version":"1.0","purl":"pkg:npm/left@1.0"},
                    {"type":"library","name":"impostor","version":"9.9","purl":"pkg:npm/shared@1.0"},
                    {"type":"library","bom-ref":"t","name":"target","version":"1.0"}],
                "dependencies":[{"ref":"pkg:npm/shared@1.0","dependsOn":["t"]}]}"#,
        );
        let left = component(&sbom, "left").canonical_id.clone();
        let impostor = component(&sbom, "impostor").canonical_id.clone();
        let target = component(&sbom, "target").canonical_id.clone();
        assert!(
            sbom.edges.iter().any(|e| e.from == left && e.to == target),
            "edge must anchor at the bom-ref owner"
        );
        assert!(
            !sbom.edges.iter().any(|e| e.from == impostor),
            "purl fallback must not shadow a real bom-ref"
        );
    }

    #[test]
    fn test_json_ml_model_card_typed_fields() {
        // Uses the SPEC field names: considerations.fairnessAssessments (objects),
        // ethicalConsiderations (objects), useCases, and
        // modelCard.quantitativeAnalysis.performanceMetrics.
        let sbom = parse_json(
            r#"{
              "bomFormat": "CycloneDX",
              "specVersion": "1.6",
              "version": 1,
              "components": [{
                "bom-ref": "m1",
                "type": "machine-learning-model",
                "name": "m1",
                "modelCard": {
                  "quantitativeAnalysis": {
                    "performanceMetrics": [
                      { "type": "accuracy", "value": "0.97", "slice": "overall" },
                      { "type": "F1", "value": 0.95 }
                    ]
                  },
                  "considerations": {
                    "useCases": ["triage", "moderation"],
                    "ethicalConsiderations": [
                      { "name": "bias risk", "mitigationStrategy": "human review" }
                    ],
                    "fairnessAssessments": [
                      { "groupAtRisk": "minors", "mitigationStrategy": "age gating" }
                    ]
                  }
                }
              }]
            }"#,
        );

        let ml = component(&sbom, "m1")
            .ml_model
            .as_ref()
            .expect("ml_model missing");
        assert_eq!(ml.performance_metrics.len(), 2);
        assert_eq!(
            ml.performance_metrics[0].metric_type.as_deref(),
            Some("accuracy")
        );
        assert_eq!(ml.performance_metrics[0].value.as_deref(), Some("0.97"));
        assert_eq!(ml.performance_metrics[0].slice.as_deref(), Some("overall"));
        // Numeric `value` is normalized to its string form.
        assert_eq!(ml.performance_metrics[1].value.as_deref(), Some("0.95"));
        assert_eq!(ml.use_cases, vec!["triage", "moderation"]);
        assert_eq!(ml.ethical_considerations.len(), 1);
        assert_eq!(
            ml.ethical_considerations[0].mitigation_strategy.as_deref(),
            Some("human review")
        );
        assert_eq!(ml.fairness.len(), 1);
        assert_eq!(ml.fairness[0].group_at_risk.as_deref(), Some("minors"));
    }

    #[test]
    fn test_json_ml_fairness_non_spec_string_alias() {
        // The non-spec `fairnessConsiderations` string-array variant is accepted
        // via serde alias and coerced into the structured form.
        let sbom = parse_json(
            r#"{
              "bomFormat": "CycloneDX",
              "specVersion": "1.5",
              "version": 1,
              "components": [{
                "bom-ref": "m1",
                "type": "machine-learning-model",
                "name": "m1",
                "modelCard": {
                  "considerations": {
                    "fairnessConsiderations": ["assessed for demographic parity"]
                  }
                }
              }]
            }"#,
        );

        let ml = component(&sbom, "m1")
            .ml_model
            .as_ref()
            .expect("ml_model missing");
        assert_eq!(ml.fairness.len(), 1);
        assert_eq!(
            ml.fairness[0].group_at_risk.as_deref(),
            Some("assessed for demographic parity")
        );
    }

    /// BSI TR-03183-2 v2.1.0 Table 8 maps the required "Creator of the SBOM"
    /// to CycloneDX metadata.manufacturer — it must become an Organization
    /// creator with its contact email (previously it was silently dropped
    /// and manufacturer-only SBOMs false-failed the §5.2.1 gate).
    #[test]
    fn metadata_manufacturer_maps_to_organization_creator() {
        let sbom = parse_json(
            r#"{
              "bomFormat": "CycloneDX",
              "specVersion": "1.6",
              "version": 1,
              "metadata": {
                "manufacturer": {
                  "name": "Demo Corp",
                  "url": ["https://demo.example"],
                  "contact": [{"name": "SBOM desk", "email": "sbom@demo.example"}]
                }
              },
              "components": []
            }"#,
        );
        let org = sbom
            .document
            .creators
            .iter()
            .find(|c| c.creator_type == CreatorType::Organization)
            .expect("manufacturer must map to an Organization creator");
        assert_eq!(org.name, "Demo Corp");
        assert_eq!(org.email.as_deref(), Some("sbom@demo.example"));
    }

    /// When the manufacturer has no contact email, the first URL is folded
    /// into the creator name so the BSI §5.2.1 email-or-URL fallback stays
    /// discernible ("://" heuristic).
    #[test]
    fn metadata_manufacturer_url_fallback_folds_into_name() {
        let sbom = parse_json(
            r#"{
              "bomFormat": "CycloneDX",
              "specVersion": "1.6",
              "version": 1,
              "metadata": {
                "manufacturer": {"name": "Demo Corp", "url": ["https://demo.example"]}
              },
              "components": []
            }"#,
        );
        let org = sbom
            .document
            .creators
            .iter()
            .find(|c| c.creator_type == CreatorType::Organization)
            .expect("manufacturer must map to an Organization creator");
        assert_eq!(org.name, "Demo Corp (https://demo.example)");
        assert_eq!(org.email, None);
    }

    /// The deprecated pre-1.6 `metadata.manufacture` spelling is accepted as
    /// a fallback.
    #[test]
    fn deprecated_metadata_manufacture_spelling_accepted() {
        let sbom = parse_json(
            r#"{
              "bomFormat": "CycloneDX",
              "specVersion": "1.5",
              "version": 1,
              "metadata": {
                "manufacture": {
                  "name": "Legacy Corp",
                  "contact": [{"email": "sbom@legacy.example"}]
                }
              },
              "components": []
            }"#,
        );
        let org = sbom
            .document
            .creators
            .iter()
            .find(|c| c.creator_type == CreatorType::Organization)
            .expect("deprecated manufacture must map to an Organization creator");
        assert_eq!(org.name, "Legacy Corp");
        assert_eq!(org.email.as_deref(), Some("sbom@legacy.example"));
    }

    /// Silent side: a tools-only metadata block yields Tool creators only —
    /// no Organization creator is fabricated.
    #[test]
    fn no_manufacturer_yields_no_organization_creator() {
        let sbom = parse_json(
            r#"{
              "bomFormat": "CycloneDX",
              "specVersion": "1.5",
              "version": 1,
              "metadata": {"tools": [{"name": "sbom-gen", "version": "1.0"}]},
              "components": []
            }"#,
        );
        assert!(
            sbom.document
                .creators
                .iter()
                .all(|c| c.creator_type == CreatorType::Tool),
            "tools-only metadata must produce only Tool creators, got {:?}",
            sbom.document.creators
        );
    }

    // ── Spec-valid optional fields must not hard-fail the document ──
    // organizationalEntity / vulnerability / vulnerabilitySource have NO
    // required properties, and property requires only `name` (verified
    // against bom-1.4..1.7 schemas). Each previously aborted the parse.

    /// A supplier with only a URL is schema-valid; the URL becomes the
    /// organization name rather than the document failing.
    #[test]
    fn supplier_without_name_parses() {
        let sbom = parse_json(
            r#"{"bomFormat":"CycloneDX","specVersion":"1.6",
                "components":[{"type":"library","bom-ref":"c","name":"lib","version":"1.0",
                    "supplier":{"url":["https://example.com"]}}]}"#,
        );
        let comp = component(&sbom, "lib");
        assert_eq!(
            comp.supplier.as_ref().map(|s| s.name.as_str()),
            Some("https://example.com"),
            "URL-only supplier must fall back to the URL as name"
        );
    }

    /// Properties are fully optional in bom-1.4/1.5 (no required list) and
    /// value-less in 1.6+: neither shape may fail the document. Value-less
    /// entries keep their name; name-less entries are skipped.
    #[test]
    fn property_without_value_parses() {
        let sbom = parse_json(
            r#"{"bomFormat":"CycloneDX","specVersion":"1.6",
                "components":[{"type":"library","bom-ref":"c","name":"lib","version":"1.0",
                    "properties":[{"name":"internal:reviewed"},{"value":"orphan"}]}]}"#,
        );
        let comp = component(&sbom, "lib");
        assert!(
            comp.extensions
                .properties
                .iter()
                .any(|p| p.name == "internal:reviewed"),
            "value-less property must be kept by name"
        );
        assert_eq!(
            comp.extensions.properties.len(),
            1,
            "name-less property is unaddressable and skipped"
        );
    }

    /// A vulnerability without `id` is schema-valid: the first reference id
    /// (with ITS source) is used, else an index-disambiguated UNKNOWN-{n}
    /// (a shared literal would merge distinct anonymous vulnerabilities in
    /// id-keyed consumers) — never a parse failure.
    #[test]
    fn vulnerability_without_id_parses() {
        let sbom = parse_json(
            r#"{"bomFormat":"CycloneDX","specVersion":"1.6",
                "components":[{"type":"library","bom-ref":"c","name":"lib","version":"1.0"}],
                "vulnerabilities":[
                    {"references":[{"id":"GHSA-xxxx-yyyy-zzzz","source":{"name":"GHSA"}}],
                     "affects":[{"ref":"c"}]},
                    {"description":"anonymous one","affects":[{"ref":"c"}]},
                    {"description":"anonymous two","affects":[{"ref":"c"}]}
                ]}"#,
        );
        let comp = component(&sbom, "lib");
        let ids: Vec<&str> = comp.vulnerabilities.iter().map(|v| v.id.as_str()).collect();
        assert!(
            ids.contains(&"GHSA-xxxx-yyyy-zzzz"),
            "reference id fallback, got {ids:?}"
        );
        let ghsa = comp
            .vulnerabilities
            .iter()
            .find(|v| v.id == "GHSA-xxxx-yyyy-zzzz")
            .expect("ghsa vuln");
        assert!(
            matches!(ghsa.source, VulnerabilitySource::Ghsa),
            "id borrowed from a reference must carry that reference's source"
        );
        assert!(
            ids.contains(&"UNKNOWN-1") && ids.contains(&"UNKNOWN-2"),
            "anonymous vulns must get distinct ids, got {ids:?}"
        );
    }

    /// Hostile deeply-nested XML must produce an error, not a stack-overflow
    /// process abort: the recursive component/service XML models are only
    /// reachable behind an iterative depth pre-scan.
    #[test]
    fn xml_nesting_depth_is_bounded() {
        let mut doc =
            String::from(r#"<bom xmlns="http://cyclonedx.org/schema/bom/1.6"><components>"#);
        for _ in 0..(MAX_XML_DEPTH + 100) {
            doc.push_str(r#"<component type="library"><name>x</name><components>"#);
        }
        let result = CycloneDxParser::new().parse_str(&doc);
        assert!(
            result.is_err(),
            "deeply nested XML must error before recursive deserialization"
        );
    }

    /// A vulnerability source given only as a URL is schema-valid and keeps
    /// the URL rather than failing or fabricating a name.
    #[test]
    fn vulnerability_source_url_only_parses() {
        let sbom = parse_json(
            r#"{"bomFormat":"CycloneDX","specVersion":"1.6",
                "components":[{"type":"library","bom-ref":"c","name":"lib","version":"1.0"}],
                "vulnerabilities":[{"id":"CVE-2024-1234",
                    "source":{"url":"https://osv.dev/CVE-2024-1234"},
                    "affects":[{"ref":"c"}]}]}"#,
        );
        let comp = component(&sbom, "lib");
        assert_eq!(comp.vulnerabilities.len(), 1);
    }

    /// Nested component assemblies are real inventory: all levels parse,
    /// hierarchy becomes Contains edges, and dependencies/vulnerabilities
    /// that reference nested bom-refs resolve instead of silently vanishing.
    #[test]
    fn nested_components_parse_with_edges_and_vulns() {
        let sbom = parse_json(
            r#"{"bomFormat":"CycloneDX","specVersion":"1.6",
                "metadata":{"component":{"type":"application","bom-ref":"app","name":"app","version":"1.0",
                    "components":[{"type":"library","bom-ref":"inner-meta","name":"inner-meta","version":"1.0"}]}},
                "components":[
                    {"type":"container","bom-ref":"outer","name":"outer","version":"1.0",
                     "components":[
                        {"type":"library","bom-ref":"mid","name":"mid","version":"1.0",
                         "components":[{"type":"library","bom-ref":"leaf","name":"leaf","version":"1.0"}]}]}],
                "dependencies":[{"ref":"app","dependsOn":["leaf"]}],
                "vulnerabilities":[{"id":"CVE-2024-9999","affects":[{"ref":"mid"}]}]}"#,
        );
        for name in ["app", "inner-meta", "outer", "mid", "leaf"] {
            component(&sbom, name);
        }
        assert_eq!(sbom.component_count(), 5, "all nesting levels must parse");
        let vuln_carrier = component(&sbom, "mid");
        assert_eq!(
            vuln_carrier.vulnerabilities.len(),
            1,
            "vulnerability targeting a nested bom-ref must attach"
        );
        let leaf_id = component(&sbom, "leaf").canonical_id.clone();
        let app_id = component(&sbom, "app").canonical_id.clone();
        assert!(
            sbom.edges
                .iter()
                .any(|e| e.from == app_id && e.to == leaf_id),
            "dependency to a nested bom-ref must resolve"
        );
        let outer_id = component(&sbom, "outer").canonical_id.clone();
        let mid_id = component(&sbom, "mid").canonical_id.clone();
        assert!(
            sbom.edges.iter().any(|e| e.from == outer_id
                && e.to == mid_id
                && matches!(e.relationship, DependencyType::Contains)),
            "assembly hierarchy must become Contains edges"
        );
    }

    /// Top-level services (SaaSBOM) join the inventory with their bom-refs
    /// resolvable from dependencies; nested services parse too.
    #[test]
    fn services_parse_as_components() {
        let sbom = parse_json(
            r#"{"bomFormat":"CycloneDX","specVersion":"1.6",
                "components":[{"type":"application","bom-ref":"app","name":"app","version":"1.0"}],
                "services":[
                    {"bom-ref":"svc-api","name":"api-gateway","version":"2.1",
                     "provider":{"name":"Acme SaaS"},
                     "licenses":[{"expression":"Apache-2.0"}],
                     "endpoints":["https://api.example.com/v1"],
                     "services":[{"bom-ref":"svc-auth","name":"auth"}]}],
                "dependencies":[{"ref":"app","dependsOn":["svc-api"]}]}"#,
        );
        assert_eq!(sbom.component_count(), 3, "app + 2 services");
        let svc = component(&sbom, "api-gateway");
        assert!(matches!(&svc.component_type, ComponentType::Other(t) if t == "service"));
        assert_eq!(
            svc.supplier.as_ref().map(|s| s.name.as_str()),
            Some("Acme SaaS")
        );
        assert!(
            svc.licenses
                .declared
                .iter()
                .any(|l| l.expression == "Apache-2.0"),
            "declared service licenses must be kept"
        );
        component(&sbom, "auth");
        let app_id = component(&sbom, "app").canonical_id.clone();
        let svc_id = svc.canonical_id.clone();
        assert!(
            sbom.edges
                .iter()
                .any(|e| e.from == app_id && e.to == svc_id),
            "dependency on a service bom-ref must resolve"
        );
    }

    /// affects[].versions status must be respected: only "affected" (or
    /// absent — the spec default) entries are reported; "unaffected" and
    /// "unknown" are not, and range entries are kept rather than dropped.
    #[test]
    fn affects_versions_status_respected() {
        let sbom = parse_json(
            r#"{"bomFormat":"CycloneDX","specVersion":"1.6",
                "components":[{"type":"library","bom-ref":"c","name":"lib","version":"1.0"}],
                "vulnerabilities":[{"id":"CVE-2024-1111","affects":[{"ref":"c","versions":[
                    {"version":"1.0.0","status":"affected"},
                    {"version":"2.0.0","status":"unaffected"},
                    {"version":"3.0.0","status":"unknown"},
                    {"range":"vers:npm/>=4.0.0|<4.2.0"},
                    {"version":"5.0.0"}
                ]}]}]}"#,
        );
        let comp = component(&sbom, "lib");
        assert_eq!(
            comp.vulnerabilities[0].affected_versions,
            vec![
                "1.0.0".to_string(),
                "vers:npm/>=4.0.0|<4.2.0".to_string(),
                "5.0.0".to_string()
            ],
            "unaffected/unknown excluded; explicit+default affected and ranges kept"
        );
    }

    /// XML twins of the hard-fail fixes: name-less supplier, value-less
    /// property, id-less vulnerability, nested assemblies, and services all
    /// parse from XML too.
    #[test]
    fn xml_optional_fields_and_nesting_parse() {
        let sbom = parse(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1">
  <components>
    <component type="container" bom-ref="outer">
      <name>outer</name>
      <version>1.0</version>
      <supplier><url>https://example.com</url></supplier>
      <properties><property name="internal:reviewed"/></properties>
      <components>
        <component type="library" bom-ref="inner">
          <name>inner</name>
          <version>1.0</version>
        </component>
      </components>
    </component>
  </components>
  <services>
    <service bom-ref="svc">
      <name>api</name>
      <endpoints><endpoint>https://api.example.com</endpoint></endpoints>
    </service>
  </services>
  <vulnerabilities>
    <vulnerability>
      <references><reference><id>GHSA-aaaa-bbbb-cccc</id></reference></references>
      <affects><target><ref>inner</ref></target></affects>
    </vulnerability>
  </vulnerabilities>
</bom>"#,
        );
        assert_eq!(sbom.component_count(), 3, "outer + inner + service");
        let outer = component(&sbom, "outer");
        assert_eq!(
            outer.supplier.as_ref().map(|s| s.name.as_str()),
            Some("https://example.com")
        );
        let inner = component(&sbom, "inner");
        assert_eq!(
            inner.vulnerabilities.first().map(|v| v.id.as_str()),
            Some("GHSA-aaaa-bbbb-cccc"),
            "id-less vulnerability must fall back to its reference id"
        );
        component(&sbom, "api");
    }
}
