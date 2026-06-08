//! `CycloneDX` SBOM parser.
//!
//! Supports `CycloneDX` versions 1.4, 1.5, 1.6, and 1.7 in JSON and XML formats.

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
use std::collections::HashMap;

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
                distribution_constraints: None,
            }),
            components: cdx.components.map(|c| c.component),
            dependencies: cdx.dependencies.map(|d| d.dependency),
            vulnerabilities: cdx.vulnerabilities.map(|v| v.vulnerability),
            compositions: None,
            signature: None,
            citations: None,
        };

        Ok(self.convert_to_normalized(bom))
    }

    /// Convert `CycloneDX` BOM to normalized representation
    fn convert_to_normalized(&self, cdx: CycloneDxBom) -> NormalizedSbom {
        let document = self.convert_metadata(&cdx);
        let mut sbom = NormalizedSbom::new(document);

        // Convert components
        let mut id_map: HashMap<String, CanonicalId> = HashMap::new();

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
                            sbom.document.vulnerability_disclosure_url = Some(ext_ref.url.clone());
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
                        } else if let Ok(dt) =
                            chrono::NaiveDate::parse_from_str(&prop.value, "%Y-%m-%d")
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

        if let Some(components) = cdx.components {
            for cdx_comp in components {
                let comp = self.convert_component(&cdx_comp);
                let bom_ref = cdx_comp.bom_ref.unwrap_or_else(|| comp.name.clone());
                if let Some(scope_str) = &cdx_comp.scope {
                    let scope = match scope_str.to_lowercase().as_str() {
                        "optional" => DependencyScope::Optional,
                        "excluded" => DependencyScope::Excluded,
                        _ => DependencyScope::Required,
                    };
                    scope_map.insert(bom_ref.clone(), scope);
                }
                id_map.insert(bom_ref, comp.canonical_id.clone());
                sbom.add_component(comp);
            }
        }

        // Convert dependencies, attaching scope from component metadata
        if let Some(deps) = cdx.dependencies {
            for dep in deps {
                if let Some(from_id) = id_map.get(&dep.ref_field) {
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
            for vuln in vulns {
                self.apply_vulnerability(&mut sbom, &vuln, &id_map);
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
            .map_or_else(Utc::now, |dt| dt.with_timezone(&Utc));

        let mut creators = Vec::new();
        if let Some(meta) = &cdx.metadata
            && let Some(tools) = &meta.tools
        {
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
                let ref_type = match ext_ref.ref_type.as_str() {
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
            mat.state = Some(match state {
                "pre-activation" => CryptoMaterialState::PreActivation,
                "active" => CryptoMaterialState::Active,
                "suspended" => CryptoMaterialState::Suspended,
                "deactivated" => CryptoMaterialState::Deactivated,
                "compromised" => CryptoMaterialState::Compromised,
                "destroyed" => CryptoMaterialState::Destroyed,
                _ => CryptoMaterialState::Active,
            });
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

    /// Apply vulnerability information to components
    fn apply_vulnerability(
        &self,
        sbom: &mut NormalizedSbom,
        vuln: &CdxVulnerability,
        id_map: &HashMap<String, CanonicalId>,
    ) {
        let source = vuln.source.as_ref().map_or(VulnerabilitySource::Cve, |s| {
            match s.name.to_lowercase().as_str() {
                "nvd" => VulnerabilitySource::Nvd,
                "ghsa" | "github" => VulnerabilitySource::Ghsa,
                "osv" => VulnerabilitySource::Osv,
                "snyk" => VulnerabilitySource::Snyk,
                other => VulnerabilitySource::Other(other.to_string()),
            }
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

        // Apply vulnerability to affected components
        if let Some(affects) = &vuln.affects {
            for affect in affects {
                if let Some(canonical_id) = id_map.get(&affect.ref_field)
                    && let Some(comp) = sbom.components.get_mut(canonical_id)
                {
                    let mut v = vuln_ref.clone();
                    if let Some(versions) = &affect.versions {
                        v.affected_versions = versions
                            .iter()
                            .filter_map(|ver| ver.version.clone())
                            .collect();
                    }
                    if let Some(vex) = &vex_status {
                        v.vex_status = Some(vex.clone());
                    }
                    comp.vulnerabilities.push(v);
                    if let Some(vex) = &vex_status {
                        comp.vex_status = Some(vex.clone());
                    }
                }
            }
        }
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
        vec!["1.4", "1.5", "1.6", "1.7"]
    }

    fn format_name(&self) -> &'static str {
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
    compositions: Option<Vec<CdxComposition>>,
    signature: Option<CdxSignature>,
    /// Data provenance citations (1.7+)
    citations: Option<Vec<CdxCitation>>,
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
    component: Option<CdxComponent>,
    /// Lifecycles field (1.5+) - contains phases like end-of-support dates
    lifecycles: Option<Vec<CdxLifecycle>>,
    /// Distribution constraints (1.7+) with TLP classification
    distribution_constraints: Option<CdxDistributionConstraints>,
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

// ML Model and Dataset structures (CycloneDX 1.5+ AI/ML BOM support)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdxMlModelCard {
    model_parameters: Option<CdxModelParameters>,
    considerations: Option<CdxConsiderations>,
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
    /// Cryptographic properties (1.6+, camelCase in XML)
    #[serde(rename = "cryptoProperties")]
    crypto_properties: Option<CdxCryptoProperties>,
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
