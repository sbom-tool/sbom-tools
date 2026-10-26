//! Compliance rule registry: the single source of truth for SARIF rule
//! IDs, harmonised-standard cross-references, and remediation text, keyed
//! by the stable internal `Violation::rule_id`.

use super::{StandardKind, ViolationSeverity};
use crate::model::{DocumentMetadata, SbomFormat};

/// Static metadata attached to a compliance rule. The `rule_id` on every
/// [`Violation`] indexes into [`rule_meta`]; the registry — not the
/// human-readable message — is the single source of truth for the
/// externally-visible SARIF rule ID, the harmonised-standard cross-references,
/// and the remediation text. Rewording a message can no longer silently
/// re-bucket a GitHub code-scanning rule or drop a prEN/BSI reference.
#[derive(Debug, Clone, Copy)]
pub struct RuleMeta {
    /// Externally-visible SARIF rule ID (e.g., `SBOM-CRA-MACHINE-READABLE`).
    /// GitHub code scanning dedups on this value, so it must stay stable.
    ///
    /// Every registered key is its own SARIF rule: `sarif_id` equals the key
    /// (`every_rule_is_its_own_sarif_rule` checks it), so each check has
    /// help text of its own. Until v0.4.0 dozens of keys shared a bucket
    /// rule such as `SBOM-QUALITY-GENERAL` or `SBOM-CRA-ANNEX-I`.
    pub sarif_id: &'static str,
    /// PascalCase SARIF `reportingDescriptor.name` of the rule. Unique
    /// across the registry.
    pub name: &'static str,
    /// SARIF `reportingDescriptor.shortDescription` text of the rule: what
    /// the check looks for. Unique across the registry.
    pub short_description: &'static str,
    /// Documentation-default severity for the rule. Push sites may still
    /// escalate/relax the concrete [`Violation::severity`] by product class or
    /// CRA phase. The SARIF rule catalogue is generated from this value (see
    /// `registry_severity_matches_sarif_catalogue` in
    /// src/reports/sarif/rules.rs).
    pub default_severity: ViolationSeverity,
    /// Harmonised-standard / regulation cross-references, in display order.
    pub refs: &'static [(StandardKind, &'static str)],
    /// Format-neutral remediation guidance: what to fix and why. Render it
    /// through [`RuleMeta::remediation_for`], which appends
    /// [`RuleMeta::advice`] for the input format.
    pub remediation: &'static str,
    /// Where the fix goes in each SBOM format. `None` when the fix is the
    /// same in every format (an algorithm choice, a CRA sidecar key, …).
    pub advice: Option<&'static FormatAdvice>,
}

impl RuleMeta {
    /// Remediation for a violation found in an SBOM of `format`: the
    /// format-neutral guidance followed by where the fix goes in that
    /// format, e.g. "… SPDX 2.x: set packages[].supplier …".
    #[must_use]
    pub fn remediation_for(&self, format: RemediationFormat) -> String {
        match self.advice {
            Some(advice) => format!(
                "{} {}: {}",
                self.remediation,
                format.label(),
                advice.get(format).text
            ),
            None => self.remediation.to_string(),
        }
    }

    /// Remediation when the input format is unknown (a violation built
    /// outside `ComplianceChecker::check()`): the format-neutral guidance
    /// followed by the advice for every format.
    #[must_use]
    pub fn remediation_all_formats(&self) -> String {
        let mut text = self.remediation.to_string();
        if let Some(advice) = self.advice {
            for format in RemediationFormat::ALL {
                text.push(' ');
                text.push_str(format.label());
                text.push_str(": ");
                text.push_str(advice.get(format).text);
            }
        }
        text
    }
}

/// The SBOM format family a remediation is phrased for. The same element
/// lives in different fields per format — a component supplier is
/// `components[].supplier.name` in CycloneDX, `packages[].supplier` in
/// SPDX 2.x and `suppliedBy` in SPDX 3.0 — so advice is chosen per format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RemediationFormat {
    /// CycloneDX (JSON or XML).
    CycloneDx,
    /// SPDX 2.x (JSON, tag-value or RDF/XML).
    Spdx2,
    /// SPDX 3.0 (JSON-LD).
    Spdx3,
}

impl RemediationFormat {
    /// Every format, in the order [`RuleMeta::remediation_all_formats`]
    /// lists them.
    pub const ALL: [Self; 3] = [Self::CycloneDx, Self::Spdx2, Self::Spdx3];

    /// The format family of a parsed document. An SPDX document whose spec
    /// version does not parse counts as SPDX 2.x.
    #[must_use]
    pub fn of(document: &DocumentMetadata) -> Self {
        match document.format {
            SbomFormat::CycloneDx => Self::CycloneDx,
            SbomFormat::Spdx if document.spec_version_parsed().is_some_and(|v| v.major >= 3) => {
                Self::Spdx3
            }
            SbomFormat::Spdx => Self::Spdx2,
        }
    }

    /// Label that introduces this format's advice in a remediation text.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::CycloneDx => "CycloneDX",
            Self::Spdx2 => "SPDX 2.x",
            Self::Spdx3 => "SPDX 3.0",
        }
    }
}

/// Where a rule's fix goes in one SBOM format.
#[derive(Debug, Clone, Copy)]
pub struct FieldAdvice {
    /// The fix in this format, written to follow the format label
    /// ("set components[].supplier.name …"). Names [`FieldAdvice::field`]
    /// when there is one.
    pub text: &'static str,
    /// Path of the field to set, in the format's own JSON shape: a CycloneDX
    /// path such as `components[].supplier.name`, an SPDX 2.x path such as
    /// `packages[].supplier`, or an SPDX 3.0 property such as `suppliedBy`.
    /// `None` when the format has no field the check reads.
    pub field: Option<&'static str>,
}

/// Per-format advice for a rule whose fix lives in a format-specific field.
#[derive(Debug, Clone, Copy)]
pub struct FormatAdvice {
    /// CycloneDX advice.
    pub cyclonedx: FieldAdvice,
    /// SPDX 2.x advice.
    pub spdx2: FieldAdvice,
    /// SPDX 3.0 advice.
    pub spdx3: FieldAdvice,
}

impl FormatAdvice {
    /// The advice for `format`.
    #[must_use]
    pub const fn get(&self, format: RemediationFormat) -> &FieldAdvice {
        match format {
            RemediationFormat::CycloneDx => &self.cyclonedx,
            RemediationFormat::Spdx2 => &self.spdx2,
            RemediationFormat::Spdx3 => &self.spdx3,
        }
    }
}

/// NIST PQC readiness remediation, shared by the SBOM-PQC-* rules.
///
/// NIST IR 8547 is cited as its Initial Public Draft (Nov 2024) — still a
/// draft as of 2026-07; SP 800-131A is at Rev. 2 (Rev. 3 is draft-only).
const REMEDIATION_PQC: &str = "Migrate quantum-vulnerable algorithms per NIST IR 8547 ipd (Transition to Post-Quantum Cryptography Standards): adopt ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205) or SP 800-208 stateful hash-based signatures, and retire algorithms disallowed by SP 800-131A Rev. 2.";

/// Remediation for a violation whose rule id the registry does not know (one
/// built outside the checkers): the registry has no guidance for it, so the
/// finding itself is all there is to go on.
pub(crate) const REMEDIATION_UNREGISTERED: &str = "This finding's rule is not in the sbom-tools rule registry, so no specific guidance exists: fix the element its requirement and message name.";

/// SSDF practices share one remediation paragraph.
const REMEDIATION_SSDF: &str = "Follow NIST SP 800-218 SSDF practices: include tool provenance, source VCS references, build metadata, and cryptographic hashes for all components.";

/// EO 14028 §4 requirements share one remediation paragraph.
const REMEDIATION_EO14028: &str = "Follow EO 14028 Section 4(e) requirements: use a machine-readable format (CycloneDX 1.4+, SPDX 2.2+, or SPDX 3.0+), auto-generate the SBOM, include unique identifiers, versions, hashes, dependencies, and supplier information.";

/// EU AI Act not-applicable remediation.
/// Remediation for every `*-INVENTORY` rule: the document must list the
/// software components it describes.
const REMEDIATION_INVENTORY: &str = "List the software components the product is made of. A document with no components, or with only files, snippets or cryptographic assets, is not a software inventory; validate a CBOM with --standard cnsa2 or pqc instead.";

/// Remediation for the generic path's document-creator checks
/// (SBOM-QUALITY-CREATOR, SBOM-CRA-CREATOR).
const REMEDIATION_CREATOR: &str = "Identify who created the SBOM: a person, organization or tool.";

/// Remediation for the generic path's document-identifier checks
/// (SBOM-QUALITY-SERIAL, SBOM-CRA-SERIAL).
const REMEDIATION_SERIAL: &str = "Give the SBOM a unique document identifier.";

/// Remediation for the generic path's component-name checks
/// (SBOM-QUALITY-NAME, SBOM-CRA-COMPONENT-NAME).
const REMEDIATION_COMPONENT_NAME: &str =
    "Give every component a name; empty names and placeholders such as NOASSERTION do not count.";

/// Remediation for the generic path's spec-version range checks
/// (SBOM-{QUALITY,NTIA,CRA,FDA}-SPEC-VERSION).
const REMEDIATION_SPEC_VERSION: &str = "Use a spec version sbom-tools reads: CycloneDX 1.4–1.7, SPDX 2.x or 3.0. An older version lacks fields the checks read, and what a newer version adds is not evaluated.";

/// Remediation for the generic path's unknown-SPDX-version checks
/// (SBOM-{QUALITY,NTIA,CRA,FDA}-SPEC-VERSION-UNKNOWN).
const REMEDIATION_SPEC_VERSION_UNKNOWN: &str =
    "Declare a valid SPDX version, 2.x or 3.0, so the document is read as the version it is.";

/// Remediation for the generic path's element-identifier checks
/// (SBOM-{QUALITY,NTIA,CRA,FDA}-ELEMENT-ID).
const REMEDIATION_ELEMENT_ID: &str =
    "Give every element its own well-formed identifier, the one dependency relationships refer to.";

const REMEDIATION_AIACT_NA: &str = "EU AI Act Annex IV readiness applies only to SBOMs that describe AI/ML systems. Add machine-learning-model or dataset components to enable the assessment.";

/// BSI/G7 SBOM-for-AI not-applicable remediation.
const REMEDIATION_BSIAI_NA: &str = "BSI/G7 SBOM-for-AI minimum-elements readiness applies only to SBOMs that describe AI/ML systems. Add machine-learning-model or dataset components to enable the assessment.";

/// Mistyped-ML remediation, shared by the EU AI Act and BSI/G7 SBOM-for-AI
/// applicability guards.
const REMEDIATION_UNTYPED_ML: &str = "Components with pkg:huggingface PURLs or model-card references look like ML models; leaving them untyped hides them from every AI-BOM readiness check. Type them as machine-learning models and attach the AI metadata.";

/// BSI/G7 SBOM-for-AI Models-cluster remediation.
const REMEDIATION_BSIAI_MODELS: &str = "Declare the BSI/G7 SBOM-for-AI Models minimum elements for each MachineLearningModel component: name, version, a unique identifier (PURL/CPE/SWHID/SWID), a model-weight hash using a NIST-approved algorithm (SHA-256+), a model card, the architecture, training datasets, limitations, and a license.";

/// BSI/G7 SBOM-for-AI Datasets-cluster remediation.
const REMEDIATION_BSIAI_DATASETS: &str = "Declare the BSI/G7 SBOM-for-AI Datasets minimum elements for each Data component: name, a unique identifier, a hash value, a license, a sensitivity classification, and provenance / intended use.";

/// BSI/G7 SBOM-for-AI document/metadata/system/infra/security remediation.
const REMEDIATION_BSIAI_GENERAL: &str = "Declare the BSI/G7 SBOM-for-AI minimum elements: document author, data-format name + version, timestamp, generation tool, and signature; the primary AI system, its producer, and its data-flow/usage; runtime/framework infrastructure links; and AI-specific security controls / exploitability references where they can be expressed.";

/// EUCC Substantial remediation, shared by the EUCC evidence rules.
const REMEDIATION_EUCC: &str = "Provide the Common Criteria evidence Implementing Regulation (EU) 2024/482 (EUCC) expects alongside the SBOM: set euccProtectionProfileId (Protection Profile), euccTargetOfEvaluation (ToE), euccItsefIdentifier (evaluating ITSEF) and euccValidUntil (certificate validity) in the CRA sidecar.";

/// CNSA 2.0 allowlist remediation, shared by the CNSA rules.
const REMEDIATION_CNSA2: &str = "Migrate to the CNSA 2.0 suite: AES-256, SHA-384/SHA-512, ML-KEM-1024, ML-DSA-87, or SP 800-208 stateful hash-based signatures (LMS/XMSS/HSS); use TLS 1.3 for network protocols. Unclassifiable algorithms cannot be verified — declare an algorithmFamily, OID, or recognizable name.";

/// NIST PQC protocol remediation.
const REMEDIATION_PQC_PROTO: &str = "Disable SSL and TLS versions below 1.2 (SP 800-52 Rev. 2) and remove broken (SP 800-131A) or quantum-vulnerable (IR 8547) algorithms from negotiated cipher suites and IKEv2 transforms.";

/// NIST PQC certificate remediation.
const REMEDIATION_PQC_CERT: &str = "Re-issue the certificate with a NIST-approved post-quantum signature algorithm (FIPS 204 ML-DSA, FIPS 205 SLH-DSA, or SP 800-208 LMS/XMSS/HSS).";

/// Remediation for unverifiable crypto evidence under the PQC standard.
const REMEDIATION_PQC_UNKNOWN: &str = "Declare the asset's algorithm identity (algorithmFamily, OID, or a recognizable name), make bom-refs resolvable within the SBOM, and use parseable protocol versions so signature algorithms, cipher suites, and protocol references can be verified for PQC readiness.";

/// Component producer: a supplier, manufacturer or author (`has_known_producer`).
const ADVICE_PRODUCER: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "set components[].supplier.name (or manufacturer.name, or authors[].name).",
        field: Some("components[].supplier.name"),
    },
    spdx2: FieldAdvice {
        text: "set packages[].supplier (PackageSupplier), e.g. \"Organization: Example Ltd\", or packages[].originator (PackageOriginator); a NOASSERTION value is read as absent.",
        field: Some("packages[].supplier"),
    },
    spdx3: FieldAdvice {
        text: "set suppliedBy on the package to the spdxId of an Organization or Person element.",
        field: Some("suppliedBy"),
    },
};

/// Component supplier only (FSCT §2.2.2.3 reads the supplier field alone).
const ADVICE_SUPPLIER: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "set components[].supplier.name.",
        field: Some("components[].supplier.name"),
    },
    spdx2: FieldAdvice {
        text: "set packages[].supplier (PackageSupplier), e.g. \"Organization: Example Ltd\"; a NOASSERTION value is read as absent, so write an unknown supplier as \"Organization: unknown\".",
        field: Some("packages[].supplier"),
    },
    spdx3: FieldAdvice {
        text: "set suppliedBy on the package to an Organization or Person element.",
        field: Some("suppliedBy"),
    },
};

/// Component version.
const ADVICE_VERSION: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "set components[].version.",
        field: Some("components[].version"),
    },
    spdx2: FieldAdvice {
        text: "set packages[].versionInfo (PackageVersion).",
        field: Some("packages[].versionInfo"),
    },
    spdx3: FieldAdvice {
        text: "set software_packageVersion on the package.",
        field: Some("software_packageVersion"),
    },
};

/// Component name.
const ADVICE_NAME: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "set components[].name.",
        field: Some("components[].name"),
    },
    spdx2: FieldAdvice {
        text: "set packages[].name (PackageName), or files[].fileName for files.",
        field: Some("packages[].name"),
    },
    spdx3: FieldAdvice {
        text: "set name on the element.",
        field: Some("name"),
    },
};

/// Unique component identifier: PURL, CPE, SWHID or SWID (`has_cra_identifier`).
const ADVICE_IDENTIFIER: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "set components[].purl (or cpe, or swhid[]).",
        field: Some("components[].purl"),
    },
    spdx2: FieldAdvice {
        text: "add a packages[].externalRefs[] entry with referenceCategory PACKAGE-MANAGER, referenceType purl and a pkg: locator (or a SECURITY cpe23Type, or a PERSISTENT-ID swh entry).",
        field: Some("packages[].externalRefs[]"),
    },
    spdx3: FieldAdvice {
        text: "set software_packageUrl, or add an externalIdentifier[] entry with externalIdentifierType packageUrl, cpe23, swhid or swid.",
        field: Some("software_packageUrl"),
    },
};

/// PURL or CPE on the primary component (CRA traceability).
const ADVICE_PRIMARY_IDENTIFIER: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "set metadata.component.purl (or cpe).",
        field: Some("metadata.component.purl"),
    },
    spdx2: FieldAdvice {
        text: "add a PACKAGE-MANAGER purl or SECURITY cpe23Type packages[].externalRefs[] entry to the described package.",
        field: Some("packages[].externalRefs[]"),
    },
    spdx3: FieldAdvice {
        text: "set software_packageUrl on the rootElement package, or add a cpe23 externalIdentifier[] entry to it.",
        field: Some("software_packageUrl"),
    },
};

/// Component hashes; the examples name SHA-2 algorithms every hash rule accepts.
const ADVICE_HASH: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "add components[].hashes[] entries with alg SHA-256, SHA-384 or SHA-512 and the content.",
        field: Some("components[].hashes[]"),
    },
    spdx2: FieldAdvice {
        text: "add packages[].checksums[] entries with algorithm SHA256, SHA384 or SHA512 and the checksumValue (PackageChecksum).",
        field: Some("packages[].checksums[]"),
    },
    spdx3: FieldAdvice {
        text: "add verifiedUsing[] Hash entries with algorithm sha256, sha384 or sha512 and the hashValue.",
        field: Some("verifiedUsing[]"),
    },
};

/// SHA-512 component hash (BSI TR-03183-2 §5.2.2 names the algorithm).
const ADVICE_HASH_SHA512: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "add a components[].hashes[] entry with alg SHA-512.",
        field: Some("components[].hashes[]"),
    },
    spdx2: FieldAdvice {
        text: "add a packages[].checksums[] entry with algorithm SHA512 (PackageChecksum: SHA512: <value>).",
        field: Some("packages[].checksums[]"),
    },
    spdx3: FieldAdvice {
        text: "add a verifiedUsing[] Hash entry with algorithm sha512.",
        field: Some("verifiedUsing[]"),
    },
};

/// Declared or concluded component licence.
const ADVICE_LICENSE: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "add components[].licenses[] entries (license.id with an SPDX identifier, or an expression).",
        field: Some("components[].licenses[]"),
    },
    spdx2: FieldAdvice {
        text: "set packages[].licenseDeclared (PackageLicenseDeclared) or packages[].licenseConcluded; NOASSERTION and NONE are read as absent.",
        field: Some("packages[].licenseDeclared"),
    },
    spdx3: FieldAdvice {
        text: "add a hasDeclaredLicense (or hasConcludedLicense) Relationship from the package to a simplelicensing_LicenseExpression element.",
        field: Some("hasDeclaredLicense"),
    },
};

/// SPDX 3.0 SimpleLicensing profile declaration; the check runs on SPDX 3.0 only.
const ADVICE_LICENSING_PROFILE: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "the check does not run on CycloneDX input.",
        field: None,
    },
    spdx2: FieldAdvice {
        text: "the check does not run on SPDX 2.x input.",
        field: None,
    },
    spdx3: FieldAdvice {
        text: "list simpleLicensing in the SpdxDocument's profileConformance.",
        field: Some("profileConformance"),
    },
};

/// Concluded-licence attestation (FSCT §2.2.2.7 aspirational tier); the check runs on SPDX input only.
const ADVICE_LICENSE_CONCLUDED: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "licenses[].acknowledgement is not read, so the check does not run on CycloneDX input.",
        field: None,
    },
    spdx2: FieldAdvice {
        text: "record a concluded licence in packages[].licenseConcluded (PackageLicenseConcluded).",
        field: Some("packages[].licenseConcluded"),
    },
    spdx3: FieldAdvice {
        text: "add a hasConcludedLicense Relationship recording the concluded licence.",
        field: Some("hasConcludedLicense"),
    },
};

/// Component copyright notice.
const ADVICE_COPYRIGHT: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "set components[].copyright.",
        field: Some("components[].copyright"),
    },
    spdx2: FieldAdvice {
        text: "set packages[].copyrightText (PackageCopyrightText); NOASSERTION does not count.",
        field: Some("packages[].copyrightText"),
    },
    spdx3: FieldAdvice {
        text: "set software_copyrightText on the package.",
        field: Some("software_copyrightText"),
    },
};

/// Dependency relationships between components.
const ADVICE_DEPENDENCIES: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "add dependencies[] entries (ref plus dependsOn[]); an entry with an empty dependsOn records a component that has no dependencies.",
        field: Some("dependencies[]"),
    },
    spdx2: FieldAdvice {
        text: "add relationships[] entries such as DEPENDS_ON (or DEPENDENCY_OF, CONTAINS) between the packages.",
        field: Some("relationships[]"),
    },
    spdx3: FieldAdvice {
        text: "add Relationship elements with relationshipType dependsOn (or contains) between the packages.",
        field: Some("relationshipType"),
    },
};

/// Primary (top-level product) component.
const ADVICE_PRIMARY: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "set metadata.component to the product's component.",
        field: Some("metadata.component"),
    },
    spdx2: FieldAdvice {
        text: "name the product package in documentDescribes (or add a DESCRIBES relationship from SPDXRef-DOCUMENT).",
        field: Some("documentDescribes"),
    },
    spdx3: FieldAdvice {
        text: "set rootElement on the SpdxDocument to the product package.",
        field: Some("rootElement"),
    },
};

/// Software component inventory.
const ADVICE_INVENTORY: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "set metadata.component and list the components in components[].",
        field: Some("components[]"),
    },
    spdx2: FieldAdvice {
        text: "list the packages in packages[] and name the product in documentDescribes.",
        field: Some("packages[]"),
    },
    spdx3: FieldAdvice {
        text: "add software_Package elements and set the SpdxDocument's rootElement to the product package.",
        field: Some("software_Package"),
    },
};

/// Any SBOM creator: a person, organization or tool.
const ADVICE_CREATORS: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "add metadata.authors[] (name, email), metadata.manufacturer or metadata.tools.",
        field: Some("metadata.authors[]"),
    },
    spdx2: FieldAdvice {
        text: "add creationInfo.creators[] entries such as \"Organization: Example Ltd (sbom@example.com)\" or \"Tool: generator-1.0\".",
        field: Some("creationInfo.creators[]"),
    },
    spdx3: FieldAdvice {
        text: "set creationInfo.createdBy to a Person or Organization element, or createdUsing to a Tool element.",
        field: Some("creationInfo.createdBy"),
    },
};

/// A person or organization SBOM creator; tool creators do not count.
const ADVICE_PERSON_ORG_CREATOR: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "add metadata.authors[] (name, email) or metadata.manufacturer (name, contact[].email); metadata.tools entries do not count.",
        field: Some("metadata.authors[]"),
    },
    spdx2: FieldAdvice {
        text: "add a creationInfo.creators[] entry such as \"Person: Jane Doe (jane@example.com)\" or \"Organization: Example Ltd (sbom@example.com)\"; Tool: entries do not count.",
        field: Some("creationInfo.creators[]"),
    },
    spdx3: FieldAdvice {
        text: "set creationInfo.createdBy to a Person or Organization element that has a name; createdUsing tools do not count.",
        field: Some("creationInfo.createdBy"),
    },
};

/// The manufacturer as an organization creator of the SBOM.
const ADVICE_ORG_CREATOR: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "set metadata.manufacturer (name, contact[].email).",
        field: Some("metadata.manufacturer"),
    },
    spdx2: FieldAdvice {
        text: "add a creationInfo.creators[] entry \"Organization: Example Ltd (contact@example.com)\".",
        field: Some("creationInfo.creators[]"),
    },
    spdx3: FieldAdvice {
        text: "set creationInfo.createdBy to an Organization element.",
        field: Some("creationInfo.createdBy"),
    },
};

/// The manufacturer's contact email.
const ADVICE_ORG_EMAIL: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "correct the metadata.manufacturer.contact[].email address.",
        field: Some("metadata.manufacturer.contact[].email"),
    },
    spdx2: FieldAdvice {
        text: "correct the address in the \"Organization: Name (email)\" creationInfo.creators[] entry.",
        field: Some("creationInfo.creators[]"),
    },
    spdx3: FieldAdvice {
        text: "agent emails are not read from SPDX 3.0 documents, so this check does not apply.",
        field: None,
    },
};

/// An email address or URL on the SBOM creator (BSI TR-03183-2 §5.2.1).
const ADVICE_CREATOR_CONTACT: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "add metadata.authors[].email, or a metadata.manufacturer contact[].email or url.",
        field: Some("metadata.authors[].email"),
    },
    spdx2: FieldAdvice {
        text: "append the address to the creationInfo.creators[] entry, e.g. \"Person: Jane Doe (jane@example.com)\".",
        field: Some("creationInfo.creators[]"),
    },
    spdx3: FieldAdvice {
        text: "agent emails are not read, but a creationInfo.createdBy element whose name includes an email address or URL counts.",
        field: Some("creationInfo.createdBy"),
    },
};

/// The generation tool and its version.
const ADVICE_TOOL: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "add metadata.tools with the tool's name and version.",
        field: Some("metadata.tools"),
    },
    spdx2: FieldAdvice {
        text: "add a creationInfo.creators[] entry \"Tool: <name>-<version>\".",
        field: Some("creationInfo.creators[]"),
    },
    spdx3: FieldAdvice {
        text: "set creationInfo.createdUsing to a Tool element whose name includes the version.",
        field: Some("creationInfo.createdUsing"),
    },
};

/// Creation timestamp.
const ADVICE_TIMESTAMP: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "set metadata.timestamp (RFC 3339, e.g. 2026-01-15T10:00:00Z).",
        field: Some("metadata.timestamp"),
    },
    spdx2: FieldAdvice {
        text: "set creationInfo.created (Created).",
        field: Some("creationInfo.created"),
    },
    spdx3: FieldAdvice {
        text: "set creationInfo.created on the SpdxDocument.",
        field: Some("creationInfo.created"),
    },
};

/// Document serial number or namespace.
const ADVICE_SERIAL: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "set serialNumber (urn:uuid:…).",
        field: Some("serialNumber"),
    },
    spdx2: FieldAdvice {
        text: "set documentNamespace (DocumentNamespace) to a unique URI.",
        field: Some("documentNamespace"),
    },
    spdx3: FieldAdvice {
        text: "give the SpdxDocument a unique spdxId.",
        field: Some("spdxId"),
    },
};

/// The document's own version, or a version-distinguishing serial identifier.
const ADVICE_DOC_VERSION: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "set the top-level version (or serialNumber).",
        field: Some("version"),
    },
    spdx2: FieldAdvice {
        text: "set documentNamespace (the format has no document-version field).",
        field: Some("documentNamespace"),
    },
    spdx3: FieldAdvice {
        text: "give the SpdxDocument an spdxId, which is read as its serial identifier.",
        field: Some("spdxId"),
    },
};

/// Document (product) name.
const ADVICE_DOC_NAME: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "set metadata.component.name.",
        field: Some("metadata.component.name"),
    },
    spdx2: FieldAdvice {
        text: "set the document name (DocumentName).",
        field: Some("name"),
    },
    spdx3: FieldAdvice {
        text: "set name on the SpdxDocument.",
        field: Some("name"),
    },
};

/// Security contact or vulnerability-disclosure reference on the product component.
const ADVICE_SECURITY_CONTACT: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "add a metadata.component.externalReferences[] entry of type security-contact (or advisories).",
        field: Some("metadata.component.externalReferences[]"),
    },
    spdx2: FieldAdvice {
        text: "add a packages[].externalRefs[] entry with referenceCategory SECURITY and referenceType advisory (or url) to the described package.",
        field: Some("packages[].externalRefs[]"),
    },
    spdx3: FieldAdvice {
        text: "add an externalRef[] entry with externalRefType securityAdvisory to the root package.",
        field: Some("externalRef[]"),
    },
};

/// Coordinated vulnerability disclosure policy reference on the product component.
const ADVICE_CVD: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "add a metadata.component.externalReferences[] entry of type advisories linking the policy.",
        field: Some("metadata.component.externalReferences[]"),
    },
    spdx2: FieldAdvice {
        text: "add a packages[].externalRefs[] entry with referenceCategory SECURITY and referenceType advisory (or url) linking the policy to the described package.",
        field: Some("packages[].externalRefs[]"),
    },
    spdx3: FieldAdvice {
        text: "add an externalRef[] entry with externalRefType securityAdvisory linking the policy to the root package.",
        field: Some("externalRef[]"),
    },
};

/// Support end date; SPDX 3.0 has no field the reader takes.
const ADVICE_SUPPORT_END: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "add a metadata.component.properties[] entry named end-of-support whose value is the date (RFC 3339 or YYYY-MM-DD).",
        field: Some("metadata.component.properties[]"),
    },
    spdx2: FieldAdvice {
        text: "set packages[].validUntilDate (ValidUntilDate) on the described package as an RFC 3339 date-time.",
        field: Some("packages[].validUntilDate"),
    },
    spdx3: FieldAdvice {
        text: "validUntilTime and supportLevel are not read, so use supportEndDate in the CRA sidecar.",
        field: None,
    },
};

/// Component lifecycle or end-of-support evidence.
const ADVICE_LIFECYCLE: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "add an eol, lifecycle or end-of-support entry to components[].properties[] (or an end-of-support date to metadata.component.properties[]).",
        field: Some("components[].properties[]"),
    },
    spdx2: FieldAdvice {
        text: "set packages[].validUntilDate (ValidUntilDate) on the described package as an RFC 3339 date-time.",
        field: Some("packages[].validUntilDate"),
    },
    spdx3: FieldAdvice {
        text: "validUntilTime and supportLevel are not read, so use supportEndDate in the CRA sidecar.",
        field: None,
    },
};

/// FDA level-of-support / end-of-support evidence.
const ADVICE_FDA_SUPPORT: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "add an end-of-support date to metadata.component.properties[], or eol / lifecycle entries to components[].properties[].",
        field: Some("components[].properties[]"),
    },
    spdx2: FieldAdvice {
        text: "set packages[].validUntilDate (ValidUntilDate) on the described package as an RFC 3339 date-time.",
        field: Some("packages[].validUntilDate"),
    },
    spdx3: FieldAdvice {
        text: "validUntilTime is not read from SPDX 3.0, so this check cannot be satisfied from the document.",
        field: None,
    },
};

/// FDA SBOM creator contact email.
const ADVICE_FDA_CONTACT: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "add metadata.authors[].email (or a metadata.manufacturer contact[].email).",
        field: Some("metadata.authors[].email"),
    },
    spdx2: FieldAdvice {
        text: "append the email to a creationInfo.creators[] entry (\"Organization: Name (email)\").",
        field: Some("creationInfo.creators[]"),
    },
    spdx3: FieldAdvice {
        text: "creator emails are not read from SPDX 3.0, so this check cannot be satisfied from the document.",
        field: None,
    },
};

/// FDA manufacturer creator and component suppliers (both SBOM-FDA-SUPPLIER findings).
const ADVICE_FDA_SUPPLIER: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "set metadata.manufacturer for the SBOM, and components[].supplier.name (or manufacturer.name, or authors[].name) on each component.",
        field: Some("components[].supplier.name"),
    },
    spdx2: FieldAdvice {
        text: "add an \"Organization: Name (email)\" creationInfo.creators[] entry, and packages[].supplier (or packages[].originator) on each package.",
        field: Some("packages[].supplier"),
    },
    spdx3: FieldAdvice {
        text: "set creationInfo.createdBy to an Organization element, and suppliedBy on each package.",
        field: Some("suppliedBy"),
    },
};

/// Completeness declaration; SPDX 2.x has no field for it.
const ADVICE_COMPLETENESS: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "set compositions[].aggregate (complete, incomplete, incomplete_first_party_only, …); the first composition is read.",
        field: Some("compositions[].aggregate"),
    },
    spdx2: FieldAdvice {
        text: "no field records completeness.",
        field: None,
    },
    spdx3: FieldAdvice {
        text: "set completeness (complete or incomplete) on the dependsOn Relationship elements.",
        field: Some("completeness"),
    },
};

/// SBOM lifecycle phase / type; read from CycloneDX only.
const ADVICE_LIFECYCLE_PHASE: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "set metadata.lifecycles[].phase, e.g. build (the first entry is read).",
        field: Some("metadata.lifecycles[]"),
    },
    spdx2: FieldAdvice {
        text: "no field records the lifecycle phase.",
        field: None,
    },
    spdx3: FieldAdvice {
        text: "software_sbomType is not read, so no field records the phase here.",
        field: None,
    },
};

/// In-document SBOM signature; SPDX 2.x has none.
const ADVICE_SIGNATURE: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "sign the BOM: in JSON, a JSF signature object (algorithm and value) at the document root; in XML, an enveloped XML-DSig <Signature> element on <bom>.",
        field: Some("signature"),
    },
    spdx2: FieldAdvice {
        text: "no in-document signature field exists.",
        field: None,
    },
    spdx3: FieldAdvice {
        text: "add a verifiedUsing[] entry of type signature (algorithm, hashValue) to the SpdxDocument.",
        field: Some("verifiedUsing[]"),
    },
};

/// Risk ranking on embedded vulnerability entries.
const ADVICE_VULN_SEVERITY: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "set vulnerabilities[].ratings[] on each entry with a severity (critical, high, medium, low) or a CVSS score.",
        field: Some("vulnerabilities[].ratings[]"),
    },
    spdx2: FieldAdvice {
        text: "documents in this format carry no vulnerability data, so these entries were attached by enrichment.",
        field: None,
    },
    spdx3: FieldAdvice {
        text: "add a security_CvssV3VulnAssessmentRelationship (security_score, security_vectorString) for each vulnerability.",
        field: Some("security_score"),
    },
};

/// A fixed version or fix description on each vulnerability remediation.
/// Only CycloneDX input reaches the check: an `analysis.response` of
/// `update` or `workaround_available` with no text (see the parser's
/// `cdx_remediation`). OSV enrichment records a fixed version with every
/// remediation it adds, and no other source builds one without details.
const ADVICE_VULN_REMEDIATION: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "an entry whose analysis.response declares update or workaround_available needs the details: set vulnerabilities[].recommendation to the fix (a fixed version or the steps to take), or vulnerabilities[].workaround to the workaround.",
        field: Some("vulnerabilities[].recommendation"),
    },
    spdx2: FieldAdvice {
        text: "documents in this format carry no vulnerability data, and enrichment records a fixed version with every remediation it adds, so the check does not fire on SPDX 2.x input.",
        field: None,
    },
    spdx3: FieldAdvice {
        text: "the parser builds no remediation from this format, and enrichment records a fixed version with every remediation it adds, so the check does not fire on SPDX 3.0 input.",
        field: None,
    },
};

/// SPDX 3.0 Security profile declaration; the check runs on SPDX 3.0 only.
const ADVICE_SECURITY_PROFILE: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "the check does not run on CycloneDX input.",
        field: None,
    },
    spdx2: FieldAdvice {
        text: "the check does not run on SPDX 2.x input.",
        field: None,
    },
    spdx3: FieldAdvice {
        text: "list security in the SpdxDocument's profileConformance.",
        field: Some("profileConformance"),
    },
};

/// Embedded vulnerability data, or a reference to a published VDR / VEX.
const ADVICE_VULN_DATA: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "list them in vulnerabilities[] with affects[].ref pointing at the affected components, or reference the published VDR or VEX from an externalReferences[] entry of type vulnerability-assertion or exploitability-statement.",
        field: Some("vulnerabilities[]"),
    },
    spdx2: FieldAdvice {
        text: "no field carries vulnerability data, and no external reference category names a VDR or VEX.",
        field: None,
    },
    spdx3: FieldAdvice {
        text: "add security_Vulnerability elements linked to the affected packages by affects Relationships, or reference the published VDR or VEX from an externalRef[] entry with externalRefType vulnerabilityDisclosureReport or vulnerabilityExploitabilityAssessment.",
        field: Some("security_Vulnerability"),
    },
};

/// Removing embedded vulnerability data.
const ADVICE_REMOVE_VULNS: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "remove the vulnerabilities[] array.",
        field: Some("vulnerabilities[]"),
    },
    spdx2: FieldAdvice {
        text: "documents in this format carry no vulnerability data, so these entries were attached by enrichment.",
        field: None,
    },
    spdx3: FieldAdvice {
        text: "remove the security_Vulnerability elements and their affects and assessment Relationships.",
        field: Some("security_Vulnerability"),
    },
};

/// Source repository (VCS) reference.
const ADVICE_VCS: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "add a components[].externalReferences[] entry of type vcs.",
        field: Some("components[].externalReferences[]"),
    },
    spdx2: FieldAdvice {
        text: "no field is read as a VCS reference (downloadLocation counts as a source distribution).",
        field: None,
    },
    spdx3: FieldAdvice {
        text: "add an externalRef[] entry with externalRefType vcs.",
        field: Some("externalRef[]"),
    },
};

/// Build metadata reference.
const ADVICE_BUILD: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "add a components[].externalReferences[] entry of type build-meta or build-system, or a CycloneDX 1.6+ attestation of SSDF practice PO.3.",
        field: Some("components[].externalReferences[]"),
    },
    spdx2: FieldAdvice {
        text: "no field is read as build metadata.",
        field: None,
    },
    spdx3: FieldAdvice {
        text: "add an externalRef[] entry with externalRefType buildMeta or buildSystem.",
        field: Some("externalRef[]"),
    },
};

/// Upstream supplier SBOM data for direct dependencies.
const ADVICE_UPSTREAM_BOM: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "add a components[].externalReferences[] entry of type bom linking the supplier's SBOM, or a dependencies[] entry for the dependency itself (an empty dependsOn records that it has none).",
        field: Some("components[].externalReferences[]"),
    },
    spdx2: FieldAdvice {
        text: "declare the dependency's own DEPENDS_ON relationships[] entries (no reference is read as a linked SBOM).",
        field: Some("relationships[]"),
    },
    spdx3: FieldAdvice {
        text: "declare the dependency's own Relationship elements with relationshipType dependsOn.",
        field: Some("relationshipType"),
    },
};

/// Dynamic, runtime or provided dependency relationships (the check runs on SPDX input only).
const ADVICE_DYNAMIC_DEPS: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "the check does not run on CycloneDX input.",
        field: None,
    },
    spdx2: FieldAdvice {
        text: "add relationships[] entries of type DYNAMIC_LINK, RUNTIME_DEPENDENCY_OF or PROVIDED_DEPENDENCY_OF.",
        field: Some("relationships[]"),
    },
    spdx3: FieldAdvice {
        text: "hasDynamicLink and hasProvidedDependency relationships are not yet mapped to dynamic dependencies, so SPDX 3.0 input cannot clear this note.",
        field: None,
    },
};

/// A device's version, or its dependency on the firmware it runs.
const ADVICE_DEVICE_FIRMWARE: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "set components[].version on the device, or add a dependencies[] entry from the device to its firmware component.",
        field: Some("components[].version"),
    },
    spdx2: FieldAdvice {
        text: "set packages[].versionInfo on the device package, or add a DEPENDS_ON relationships[] entry from it to its firmware package.",
        field: Some("packages[].versionInfo"),
    },
    spdx3: FieldAdvice {
        text: "set software_packageVersion on the device package, or add a dependsOn Relationship from it to its firmware package.",
        field: Some("software_packageVersion"),
    },
};

/// EU Declaration of Conformity reference: an attestation or certification
/// external reference, or (SPDX 2.x) an OTHER reference naming the DoC.
const ADVICE_DOC_REF: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "a metadata.component.externalReferences[] entry of type attestation or certification-report pointing at the DoC also counts.",
        field: Some("metadata.component.externalReferences[]"),
    },
    spdx2: FieldAdvice {
        text: "a packages[].externalRefs[] entry with referenceCategory OTHER and referenceType declaration-of-conformity also counts.",
        field: Some("packages[].externalRefs[]"),
    },
    spdx3: FieldAdvice {
        text: "no reference type names a Declaration of Conformity, but an externalRef[] entry with externalRefType certificationReport or secureSoftwareAttestation pointing at the DoC also counts.",
        field: Some("externalRef[]"),
    },
};

/// In-SBOM alternatives to the sidecar EUCC evidence (CRA Annex IV): a
/// certification or attestation reference whose URL names EUCC, or (CycloneDX
/// 1.6+) a CDXA attestation.
const ADVICE_EUCC_ALT: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "an externalReferences[] entry of type certification-report or attestation whose URL contains eucc, common-criteria or commoncriteria is also accepted, as is a fresh, fully conformant attestation in declarations (CycloneDX 1.6+) of a CRA standard that names EUCC or Common Criteria.",
        field: Some("externalReferences[]"),
    },
    spdx2: FieldAdvice {
        text: "no field is recognized as an EUCC reference, so use the sidecar keys.",
        field: None,
    },
    spdx3: FieldAdvice {
        text: "an externalRef[] entry with externalRefType certificationReport or secureSoftwareAttestation whose locator contains eucc, common-criteria or commoncriteria is also accepted.",
        field: Some("externalRef[]"),
    },
};

/// In-SBOM EUCC certificate reference: a certification or attestation
/// reference whose URL names EUCC, or (CycloneDX 1.6+) a CDXA attestation.
const ADVICE_EUCC_CERTREF: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "add an externalReferences[] entry of type certification-report (or attestation) whose URL contains eucc or common-criteria, or a fresh, fully conformant attestation in declarations (CycloneDX 1.6+) of a CRA standard that names EUCC or Common Criteria.",
        field: Some("externalReferences[]"),
    },
    spdx2: FieldAdvice {
        text: "no field is recognized as an EUCC certificate reference.",
        field: None,
    },
    spdx3: FieldAdvice {
        text: "add an externalRef[] entry with externalRefType certificationReport (or secureSoftwareAttestation) whose locator contains eucc or common-criteria.",
        field: Some("externalRef[]"),
    },
};

/// Documented risk-assessment reference (CRA Art. 13(2)).
const ADVICE_RISK_ASSESSMENT: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "a metadata.component.externalReferences[] entry of type risk-assessment pointing at it also counts.",
        field: Some("metadata.component.externalReferences[]"),
    },
    spdx2: FieldAdvice {
        text: "no external reference category names a risk assessment, so use the sidecar key.",
        field: None,
    },
    spdx3: FieldAdvice {
        text: "an externalRef[] entry with externalRefType riskAssessment pointing at it also counts.",
        field: Some("externalRef[]"),
    },
};

/// Notified-body evidence for the conformity-assessment route (CRA Annex
/// VIII): a certification reference only, since an attestation may be a
/// self-attestation.
const ADVICE_CONFORMITY_EVIDENCE: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "add a metadata.component.externalReferences[] entry of type certification-report; an attestation entry does not count.",
        field: Some("metadata.component.externalReferences[]"),
    },
    spdx2: FieldAdvice {
        text: "no external reference category names a certificate, so the check cannot be satisfied from the document.",
        field: None,
    },
    spdx3: FieldAdvice {
        text: "add an externalRef[] entry with externalRefType certificationReport to the root package; secureSoftwareAttestation does not count.",
        field: Some("externalRef[]"),
    },
};

/// AI-BOM content: ML-model and dataset components.
const ADVICE_AI_COMPONENTS: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "set components[].type to machine-learning-model (with a modelCard) for models, and give dataset components a data[] block.",
        field: Some("components[].type"),
    },
    spdx2: FieldAdvice {
        text: "no AI or dataset profile exists in this format; use CycloneDX 1.5+ or SPDX 3.0.",
        field: None,
    },
    spdx3: FieldAdvice {
        text: "describe models as ai_AIPackage and datasets as dataset_DatasetPackage elements.",
        field: Some("ai_AIPackage"),
    },
};

/// Typing a component that looks like an ML model.
const ADVICE_UNTYPED_ML: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "set components[].type to machine-learning-model and add a modelCard.",
        field: Some("components[].type"),
    },
    spdx2: FieldAdvice {
        text: "no AI or dataset profile exists in this format; use CycloneDX 1.5+ or SPDX 3.0.",
        field: None,
    },
    spdx3: FieldAdvice {
        text: "make the element an ai_AIPackage (or set software_primaryPurpose to model).",
        field: Some("ai_AIPackage"),
    },
};

/// AI model general description.
const ADVICE_AI_DESCRIPTION: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "set components[].description or modelCard.modelParameters.architectureFamily (or modelArchitecture), or add a model-card externalReferences[] entry.",
        field: Some("modelCard.modelParameters.architectureFamily"),
    },
    spdx2: FieldAdvice {
        text: "no AI or dataset profile exists in this format; use CycloneDX 1.5+ or SPDX 3.0.",
        field: None,
    },
    spdx3: FieldAdvice {
        text: "set description or ai_typeOfModel on the ai_AIPackage, or add a documentation externalRef[] entry.",
        field: Some("ai_typeOfModel"),
    },
};

/// AI model intended purpose / use cases.
const ADVICE_AI_PURPOSE: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "set modelCard.considerations.useCases[].",
        field: Some("modelCard.considerations.useCases[]"),
    },
    spdx2: FieldAdvice {
        text: "no AI or dataset profile exists in this format; use CycloneDX 1.5+ or SPDX 3.0.",
        field: None,
    },
    spdx3: FieldAdvice {
        text: "set ai_informationAboutApplication (or ai_domain) on the ai_AIPackage.",
        field: Some("ai_informationAboutApplication"),
    },
};

/// Training-dataset references (EU AI Act).
const ADVICE_AI_DATASETS: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "list modelCard.modelParameters.datasets[] entries with a ref to each data component.",
        field: Some("modelCard.modelParameters.datasets[]"),
    },
    spdx2: FieldAdvice {
        text: "no AI or dataset profile exists in this format; use CycloneDX 1.5+ or SPDX 3.0.",
        field: None,
    },
    spdx3: FieldAdvice {
        text: "add a trainedOn Relationship from the ai_AIPackage to each dataset_DatasetPackage.",
        field: Some("trainedOn"),
    },
};

/// Training-dataset references, including datasets nested under the model (BSI/G7).
const ADVICE_AI_TRAINING_DATASETS: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "list modelCard.modelParameters.datasets[] entries with a ref to each data component, or nest the data components (with their data[] block) under the model.",
        field: Some("modelCard.modelParameters.datasets[]"),
    },
    spdx2: FieldAdvice {
        text: "no AI or dataset profile exists in this format; use CycloneDX 1.5+ or SPDX 3.0.",
        field: None,
    },
    spdx3: FieldAdvice {
        text: "add a trainedOn (or contains) Relationship from the ai_AIPackage to each dataset_DatasetPackage.",
        field: Some("trainedOn"),
    },
};

/// Dataset sensitivity classification.
const ADVICE_AI_SENSITIVITY: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "set data[].sensitiveData[] on each data component (the first data[] entry is read).",
        field: Some("data[].sensitiveData[]"),
    },
    spdx2: FieldAdvice {
        text: "no AI or dataset profile exists in this format; use CycloneDX 1.5+ or SPDX 3.0.",
        field: None,
    },
    spdx3: FieldAdvice {
        text: "set dataset_confidentialityLevel on each dataset_DatasetPackage (dataset_hasSensitivePersonalInformation yes also counts).",
        field: Some("dataset_confidentialityLevel"),
    },
};

/// AI model validation / testing metrics.
const ADVICE_AI_METRICS: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "add modelCard.quantitativeAnalysis.performanceMetrics[] entries (type, value).",
        field: Some("modelCard.quantitativeAnalysis.performanceMetrics[]"),
    },
    spdx2: FieldAdvice {
        text: "no AI or dataset profile exists in this format; use CycloneDX 1.5+ or SPDX 3.0.",
        field: None,
    },
    spdx3: FieldAdvice {
        text: "set ai_metric (or ai_metricDecisionThreshold) on the ai_AIPackage.",
        field: Some("ai_metric"),
    },
};

/// AI model training energy consumption.
const ADVICE_AI_ENERGY: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "add modelCard.considerations.environmentalConsiderations.energyConsumptions[] entries with activity training and an activityEnergyCost.",
        field: Some("modelCard.considerations.environmentalConsiderations.energyConsumptions[]"),
    },
    spdx2: FieldAdvice {
        text: "no AI or dataset profile exists in this format; use CycloneDX 1.5+ or SPDX 3.0.",
        field: None,
    },
    spdx3: FieldAdvice {
        text: "set ai_energyConsumption with ai_trainingEnergyConsumption entries (ai_energyQuantity, ai_energyUnit) on the ai_AIPackage.",
        field: Some("ai_energyConsumption"),
    },
};

/// AI model limitations, ethical and fairness considerations (EU AI Act Annex IV §3).
const ADVICE_AI_LIMITATIONS: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "set modelCard.considerations.technicalLimitations[] (or ethicalConsiderations[], or fairnessAssessments[]).",
        field: Some("modelCard.considerations.technicalLimitations[]"),
    },
    spdx2: FieldAdvice {
        text: "no AI or dataset profile exists in this format; use CycloneDX 1.5+ or SPDX 3.0.",
        field: None,
    },
    spdx3: FieldAdvice {
        text: "set ai_limitation on the ai_AIPackage (ai_safetyRiskAssessment, ai_modelExplainability or ai_standardCompliance also count).",
        field: Some("ai_limitation"),
    },
};

/// AI model limitations only (BSI/G7 reads the limitations field alone).
const ADVICE_AI_LIMITATION: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "set modelCard.considerations.technicalLimitations[].",
        field: Some("modelCard.considerations.technicalLimitations[]"),
    },
    spdx2: FieldAdvice {
        text: "no AI or dataset profile exists in this format; use CycloneDX 1.5+ or SPDX 3.0.",
        field: None,
    },
    spdx3: FieldAdvice {
        text: "set ai_limitation on the ai_AIPackage.",
        field: Some("ai_limitation"),
    },
};

/// Model-card reference.
const ADVICE_AI_MODEL_CARD: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "add a components[].externalReferences[] entry of type model-card to the model component.",
        field: Some("components[].externalReferences[]"),
    },
    spdx2: FieldAdvice {
        text: "no AI or dataset profile exists in this format; use CycloneDX 1.5+ or SPDX 3.0.",
        field: None,
    },
    spdx3: FieldAdvice {
        text: "add a documentation externalRef[] entry linking the model card to the ai_AIPackage.",
        field: Some("externalRef[]"),
    },
};

/// AI model architecture.
const ADVICE_AI_ARCHITECTURE: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "set modelCard.modelParameters.architectureFamily or modelArchitecture.",
        field: Some("modelCard.modelParameters.architectureFamily"),
    },
    spdx2: FieldAdvice {
        text: "no AI or dataset profile exists in this format; use CycloneDX 1.5+ or SPDX 3.0.",
        field: None,
    },
    spdx3: FieldAdvice {
        text: "set ai_typeOfModel on the ai_AIPackage.",
        field: Some("ai_typeOfModel"),
    },
};

/// Dataset provenance / intended use.
const ADVICE_DATASET_PROVENANCE: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "name data[].governance owners, custodians or stewards (the first data[] entry is read).",
        field: Some("data[].governance"),
    },
    spdx2: FieldAdvice {
        text: "no AI or dataset profile exists in this format; use CycloneDX 1.5+ or SPDX 3.0.",
        field: None,
    },
    spdx3: FieldAdvice {
        text: "set dataset_intendedUse, dataset_dataPreprocessing or dataset_anonymizationMethodUsed, or suppliedBy / originatedBy agents, on the dataset_DatasetPackage.",
        field: Some("dataset_intendedUse"),
    },
};

/// The quality profiles' generic findings (SBOM-QUALITY-GENERAL).
const ADVICE_QUALITY_GENERAL: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "set the creator (metadata.authors[], metadata.manufacturer or metadata.tools), serialNumber, components[] with name, purl, licenses[] and hashes[], specVersion 1.4–1.7, and a bom-ref on every component.",
        field: None,
    },
    spdx2: FieldAdvice {
        text: "set creationInfo.creators[], documentNamespace, packages[] with name, a purl externalRefs[] entry, licenseDeclared and checksums[], spdxVersion SPDX-2.x, and SPDXID values that start with SPDXRef-.",
        field: None,
    },
    spdx3: FieldAdvice {
        text: "set creationInfo.createdBy or createdUsing, the SpdxDocument spdxId, packages with name, software_packageUrl, a hasDeclaredLicense Relationship and verifiedUsing[] hashes, creationInfo.specVersion 3.0.x, and an IRI spdxId on every element.",
        field: None,
    },
};

/// The CRA profiles' generic document findings (SBOM-CRA-GENERAL).
const ADVICE_CRA_GENERAL: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "set the creator (metadata.authors[], metadata.manufacturer or metadata.tools), serialNumber, components[].name, specVersion 1.4–1.7, and a bom-ref on every component.",
        field: None,
    },
    spdx2: FieldAdvice {
        text: "set creationInfo.creators[], documentNamespace, packages[].name, spdxVersion SPDX-2.x, and SPDXID values that start with SPDXRef-.",
        field: None,
    },
    spdx3: FieldAdvice {
        text: "set creationInfo.createdBy or createdUsing, the SpdxDocument spdxId, name on every element, creationInfo.specVersion 3.0.x, and an IRI spdxId on every element.",
        field: None,
    },
};

/// The FDA profile's generic findings (SBOM-FDA-GENERAL).
const ADVICE_FDA_GENERAL: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "set components[].name, specVersion 1.4–1.7, and a bom-ref on every component.",
        field: None,
    },
    spdx2: FieldAdvice {
        text: "set packages[].name, spdxVersion SPDX-2.x, and SPDXID values that start with SPDXRef-.",
        field: None,
    },
    spdx3: FieldAdvice {
        text: "set name on every element, creationInfo.specVersion 3.0.x, and an IRI spdxId on every element.",
        field: None,
    },
};

/// Format-level findings (spec version, element identifiers).
const ADVICE_FORMAT_GENERAL: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "set specVersion 1.4–1.7 and a bom-ref on every component.",
        field: Some("specVersion"),
    },
    spdx2: FieldAdvice {
        text: "set spdxVersion SPDX-2.x and SPDXID values that start with SPDXRef-.",
        field: Some("spdxVersion"),
    },
    spdx3: FieldAdvice {
        text: "set creationInfo.specVersion 3.0.x and an IRI spdxId on every element.",
        field: Some("creationInfo.specVersion"),
    },
};

/// Document spec version.
const ADVICE_SPEC_VERSION: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "set specVersion 1.4–1.7.",
        field: Some("specVersion"),
    },
    spdx2: FieldAdvice {
        text: "set spdxVersion SPDX-2.x.",
        field: Some("spdxVersion"),
    },
    spdx3: FieldAdvice {
        text: "set creationInfo.specVersion 3.0.x.",
        field: Some("creationInfo.specVersion"),
    },
};

/// Per-element format identifier (bom-ref, SPDXID, spdxId).
const ADVICE_ELEMENT_ID: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "set a bom-ref on every component, one that differs from the component's name.",
        field: Some("bom-ref"),
    },
    spdx2: FieldAdvice {
        text: "give every element an SPDXID that starts with SPDXRef-.",
        field: Some("SPDXID"),
    },
    spdx3: FieldAdvice {
        text: "give every element an IRI spdxId.",
        field: Some("spdxId"),
    },
};
/// Look up the static [`RuleMeta`] for a stable internal rule key.
///
/// The key is the [`Violation::rule_id`] set at each check site. Returns
/// `None` for unregistered keys — the exhaustive test
/// `every_emitted_violation_has_a_registered_rule_id` guarantees no live check
/// site emits an unregistered key.
#[must_use]
pub fn rule_meta(rule_id: &str) -> Option<RuleMeta> {
    use StandardKind as K;
    const CRA: K = K::CraArticle;
    const ANNEX: K = K::CraAnnex;
    const PREN: K = K::Pren40000_1_3;
    let meta = match rule_id {
        // ---- CRA Articles ------------------------------------------------
        "SBOM-CRA-ART-13-2" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-13-2",
            name: "CraRiskAssessment",
            short_description: "CRA Art. 13(2): Reference to the documented cybersecurity risk assessment",
            default_severity: ViolationSeverity::Warning,
            refs: &[(CRA, "Art. 13(2)")],
            remediation: "Reference the documented cybersecurity risk assessment Art. 13(2) requires: set riskAssessmentUrl in the CRA sidecar to its URL or document reference.",
            advice: Some(&ADVICE_RISK_ASSESSMENT),
        },
        // SBOM freshness. Formerly cited Art. 13(3), which is the risk-
        // assessment documentation paragraph; keeping the SBOM current is
        // the Art. 13(7) systematic-documentation duty applied to the
        // Annex I Part II (1) SBOM element.
        "SBOM-CRA-SBOM-FRESHNESS" => RuleMeta {
            sarif_id: "SBOM-CRA-SBOM-FRESHNESS",
            name: "CraSbomFreshness",
            short_description: "CRA Art. 13(7) / Annex I Part II (1): SBOM freshness — timely regeneration after changes",
            default_severity: ViolationSeverity::Warning,
            refs: &[(CRA, "Art. 13(7)"), (ANNEX, "Annex I Part II (1)")],
            remediation: "Regenerate the SBOM when components are added, removed, or updated. CRA Art. 13(7) requires manufacturers to systematically document relevant cybersecurity aspects, and the Annex I Part II (1) SBOM must reflect the product's current components. A creation timestamp later than the evaluation date is reported like a missing one: correct the generator's clock or time zone.",
            advice: None,
        },
        // Machine-readable SBOM format. The mandate for a 'commonly used and
        // machine-readable format' lives in Annex I Part II (1), not in
        // Art. 13(4) (which puts the risk assessment into the technical
        // documentation).
        "SBOM-CRA-MACHINE-READABLE" => RuleMeta {
            sarif_id: "SBOM-CRA-MACHINE-READABLE",
            name: "CraMachineReadableFormat",
            short_description: "CRA Annex I Part II (1): SBOM must be in a commonly used, machine-readable format (CycloneDX 1.4+, SPDX 2.3+, or SPDX 3.0+)",
            default_severity: ViolationSeverity::Warning,
            refs: &[(ANNEX, "Annex I Part II (1)"), (PREN, "PRE-7-RQ-04")],
            remediation: "Ensure the SBOM is produced in CycloneDX 1.4+ (JSON or XML), SPDX 2.3+ (JSON or tag-value), or SPDX 3.0+ (JSON-LD). Older format versions may not be recognized as machine-readable under CRA Annex I Part II (1).",
            advice: None,
        },
        // Component licence information. The CRA does not list licences as
        // an SBOM element; they are evidence supporting the Art. 13(5)
        // third-party due-diligence obligation.
        "SBOM-CRA-ART-13-5" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-13-5",
            name: "CraLicensedComponentTracking",
            short_description: "CRA Art. 13(5): Third-party due diligence — license information for all components",
            default_severity: ViolationSeverity::Warning,
            refs: &[(CRA, "Art. 13(5)")],
            remediation: "Record license information for every component to support the Art. 13(5) due diligence on integrated third-party components.",
            advice: Some(&ADVICE_LICENSE),
        },
        // The SPDX 3.0 SimpleLicensing profile declaration, a document-level
        // check apart from the licence coverage above.
        "SBOM-CRA-ART-13-5-PROFILE" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-13-5-PROFILE",
            name: "CraLicensingProfileConformance",
            short_description: "CRA Art. 13(5): SPDX 3.0 SimpleLicensing profile declared for a document that carries license data",
            default_severity: ViolationSeverity::Info,
            refs: &[(CRA, "Art. 13(5)")],
            remediation: "Declare SPDX 3.0 SimpleLicensing profile conformance when the document carries license data, so its Art. 13(5) licence evidence is conveyed completely.",
            advice: Some(&ADVICE_LICENSING_PROFILE),
        },
        // Single point of contact for vulnerability reporting. Formerly
        // cited Art. 13(6), which is the manufacturer's duty to report
        // component vulnerabilities UPSTREAM to the component maintainer;
        // the user-facing contact is Art. 13(17) / Annex I Part II (6) /
        // Annex II (2).
        "SBOM-CRA-ART-13-17-CONTACT" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-13-17-CONTACT",
            name: "CraVulnerabilityContact",
            short_description: "CRA Art. 13(17): Single point of contact for vulnerability reporting (Annex I Part II (6), Annex II (2))",
            default_severity: ViolationSeverity::Warning,
            refs: &[
                (CRA, "Art. 13(17)"),
                (ANNEX, "Annex I Part II (6)"),
                (ANNEX, "Annex II (2)"),
            ],
            remediation: "Give the product a single point of contact for vulnerability reports (Art. 13(17)): a security contact or vulnerability-disclosure URL referenced from the product component. securityContact or vulnerabilityDisclosureUrl in the CRA sidecar lowers the finding to Info.",
            advice: Some(&ADVICE_SECURITY_CONTACT),
        },
        // Vulnerability severity/remediation metadata. Anchored to the
        // Annex I Part II (4) duty to share information about fixed
        // vulnerabilities (description, impacts, severity, remediation).
        // One finding per vulnerability of a component, told apart by the
        // vulnerability id (`finding_detail`). The remediation-detail and
        // SPDX 3.0 profile checks report under their own ids below.
        "SBOM-CRA-VULN-METADATA" => RuleMeta {
            sarif_id: "SBOM-CRA-VULN-METADATA",
            name: "CraVulnerabilityMetadata",
            short_description: "CRA Annex I Part II (4): Vulnerability entries carry a severity or CVSS score",
            default_severity: ViolationSeverity::Warning,
            refs: &[(ANNEX, "Annex I Part II (4)")],
            remediation: "Give every vulnerability entry a severity or CVSS score (Annex I Part II (4)).",
            advice: Some(&ADVICE_VULN_SEVERITY),
        },
        "SBOM-CRA-VULN-METADATA-REMEDIATION" => RuleMeta {
            sarif_id: "SBOM-CRA-VULN-METADATA-REMEDIATION",
            name: "CraVulnerabilityRemediationDetail",
            short_description: "CRA Annex I Part II (4): Vulnerability remediations name a fixed version or describe the fix",
            default_severity: ViolationSeverity::Info,
            refs: &[(ANNEX, "Annex I Part II (4)")],
            remediation: "Give every vulnerability remediation a fixed version or a description of the fix (Annex I Part II (4)).",
            advice: Some(&ADVICE_VULN_REMEDIATION),
        },
        "SBOM-CRA-VULN-METADATA-PROFILE" => RuleMeta {
            sarif_id: "SBOM-CRA-VULN-METADATA-PROFILE",
            name: "CraSecurityProfileConformance",
            short_description: "CRA Annex I Part II (4): SPDX 3.0 Security profile declared for a document that carries vulnerabilities",
            default_severity: ViolationSeverity::Info,
            refs: &[(ANNEX, "Annex I Part II (4)")],
            remediation: "Declare SPDX 3.0 Security profile conformance when the document carries vulnerabilities, so the vulnerability information it conveys is complete (Annex I Part II (4)).",
            advice: Some(&ADVICE_SECURITY_PROFILE),
        },
        // Coordinated vulnerability disclosure policy. Formerly cited
        // Art. 13(7) (systematic documentation); the CVD-policy duty is
        // Annex I Part II (5), reinforced by Art. 13(8).
        "SBOM-CRA-CVD-POLICY" => RuleMeta {
            sarif_id: "SBOM-CRA-CVD-POLICY",
            name: "CraCoordinatedDisclosure",
            short_description: "CRA Annex I Part II (5): Coordinated vulnerability disclosure policy reference",
            default_severity: ViolationSeverity::Warning,
            refs: &[
                (ANNEX, "Annex I Part II (5)"),
                (CRA, "Art. 13(8)"),
                (PREN, "RLS-2-RQ-03-RE"),
            ],
            remediation: "Reference the coordinated vulnerability disclosure policy (Annex I Part II (5)) from the product component. In the CRA sidecar, coordinatedDisclosurePolicyUrl satisfies the open-source steward profile and vulnerabilityDisclosureUrl lowers the manufacturer finding to Info.",
            advice: Some(&ADVICE_CVD),
        },
        "SBOM-CRA-ART-13-8" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-13-8",
            name: "CraSupportPeriod",
            short_description: "CRA Art. 13(8) / 13(19): Support period and security update end date (Annex II (7))",
            default_severity: ViolationSeverity::Info,
            refs: &[
                (CRA, "Art. 13(8)"),
                (CRA, "Art. 13(19)"),
                (ANNEX, "Annex II (7)"),
            ],
            remediation: "Declare when security updates end (Art. 13(8) / 13(19)): set supportEndDate in the CRA sidecar, or record the date in the SBOM.",
            advice: Some(&ADVICE_SUPPORT_END),
        },
        // Components the end-of-life data marks as no longer supported: a
        // document-level count apart from the missing support end date.
        "SBOM-CRA-ART-13-8-EOL" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-13-8-EOL",
            name: "CraEndOfLifeComponents",
            short_description: "CRA Art. 13(8): Components past end-of-life, which receive no more security updates",
            default_severity: ViolationSeverity::Warning,
            refs: &[(CRA, "Art. 13(8)")],
            remediation: "Upgrade or replace the components the end-of-life data marks as no longer supported: they receive no more security updates (Art. 13(8)).",
            advice: None,
        },
        // Documented vulnerability information. Formerly cited Art. 13(9),
        // which is actually the 10-year availability of issued security
        // updates; the documentation obligation is Annex I Part II (1).
        "SBOM-CRA-VULN-STATEMENT" => RuleMeta {
            sarif_id: "SBOM-CRA-VULN-STATEMENT",
            name: "CraKnownVulnerabilities",
            short_description: "CRA Annex I Part II (1): Documented vulnerability information — vulnerability data or assertion",
            default_severity: ViolationSeverity::Info,
            refs: &[(ANNEX, "Annex I Part II (1)")],
            remediation: "Include the product's known vulnerabilities in the SBOM, or reference the vulnerability disclosure report (VDR) or VEX that states them (Annex I Part II (1)).",
            advice: Some(&ADVICE_VULN_DATA),
        },
        // Component lifecycle / end-of-support. Formerly cited Art. 13(11),
        // which is about OPTIONAL public software archives; lifecycle
        // handling is the Art. 13(8) support-period duty plus the
        // Annex II (7) support end-date disclosure.
        "SBOM-CRA-LIFECYCLE" => RuleMeta {
            sarif_id: "SBOM-CRA-LIFECYCLE",
            name: "CraComponentLifecycle",
            short_description: "CRA Art. 13(8) / Annex II (7): Component lifecycle and end-of-support status",
            default_severity: ViolationSeverity::Info,
            refs: &[(CRA, "Art. 13(8)"), (ANNEX, "Annex II (7)")],
            remediation: "Record component lifecycle or end-of-support status (Art. 13(8) / Annex II (7)); supportEndDate in the CRA sidecar counts too.",
            advice: Some(&ADVICE_LIFECYCLE),
        },
        // Components the end-of-life data shows reaching end-of-life within
        // six months: a document-level count apart from the missing
        // lifecycle evidence.
        "SBOM-CRA-LIFECYCLE-APPROACHING-EOL" => RuleMeta {
            sarif_id: "SBOM-CRA-LIFECYCLE-APPROACHING-EOL",
            name: "CraApproachingEndOfLife",
            short_description: "CRA Art. 13(8) / Annex II (7): Components reaching end-of-life within six months",
            default_severity: ViolationSeverity::Info,
            refs: &[(CRA, "Art. 13(8)"), (ANNEX, "Annex II (7)")],
            remediation: "Plan replacements for the components the end-of-life data shows reaching end-of-life within six months (Art. 13(8) / Annex II (7)).",
            advice: None,
        },
        // Product identification. Formerly cited Art. 13(12) (technical
        // documentation + conformity assessment + DoC + CE marking); product
        // identification is Art. 13(15) plus Annex II (3).
        "SBOM-CRA-ART-13-15-PRODUCT" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-13-15-PRODUCT",
            name: "CraProductIdentification",
            short_description: "CRA Art. 13(15): Product identification (Annex II (3))",
            default_severity: ViolationSeverity::Warning,
            refs: &[(CRA, "Art. 13(15)"), (ANNEX, "Annex II (3)")],
            remediation: "Name the product the SBOM describes (Art. 13(15)); productName in the CRA sidecar lowers this to Info, but the SBOM should carry the name itself.",
            advice: Some(&ADVICE_DOC_NAME),
        },
        // Component version. Formerly cited Art. 13(12); versions are part
        // of the Annex I Part II (1) SBOM element inventory.
        "SBOM-CRA-COMPONENT-VERSION" => RuleMeta {
            sarif_id: "SBOM-CRA-COMPONENT-VERSION",
            name: "CraComponentVersion",
            short_description: "CRA Annex I Part II (1): Component version identification",
            default_severity: ViolationSeverity::Error,
            refs: &[(ANNEX, "Annex I Part II (1)"), (PREN, "PRE-7-RQ-06")],
            remediation: "Every component must have a version string. Use the actual release version (e.g., '1.2.3'), not a range or placeholder.",
            advice: Some(&ADVICE_VERSION),
        },
        "SBOM-CRA-ART-24-SUPPLIER" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-24-SUPPLIER",
            name: "CraStewardComponentSupplier",
            short_description: "CRA Art. 24: Component supplier identification (open-source steward SBOM floor)",
            default_severity: ViolationSeverity::Warning,
            refs: &[(CRA, "Art. 24")],
            remediation: "Identify each component's supplier as part of the Art. 24 steward SBOM floor.",
            advice: Some(&ADVICE_PRODUCER),
        },
        // Manufacturer identification. Formerly cited Art. 13(15), which is
        // PRODUCT identification (type/batch/serial number); manufacturer
        // identification (name + postal/email/website) is Art. 13(16) plus
        // Annex II (1).
        "SBOM-CRA-ART-13-16" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-13-16",
            name: "CraManufacturerIdentification",
            short_description: "CRA Art. 13(16): Manufacturer identification and contact information (Annex II (1))",
            default_severity: ViolationSeverity::Warning,
            refs: &[(CRA, "Art. 13(16)"), (ANNEX, "Annex II (1)")],
            remediation: "Identify the manufacturer as an organization creator of the SBOM (Art. 13(16)); manufacturerName in the CRA sidecar lowers this to Info.",
            advice: Some(&ADVICE_ORG_CREATOR),
        },
        "SBOM-CRA-ART-13-16-EMAIL" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-13-16-EMAIL",
            name: "CraManufacturerEmail",
            short_description: "CRA Art. 13(16): Valid manufacturer contact email (Annex II (1))",
            default_severity: ViolationSeverity::Warning,
            refs: &[(CRA, "Art. 13(16)"), (ANNEX, "Annex II (1)")],
            remediation: "Provide a valid contact email for the manufacturer. The email must contain an @ sign with valid local and domain parts.",
            advice: Some(&ADVICE_ORG_EMAIL),
        },
        // Per-component supplier identification. Distinct from the
        // Art. 13(16) manufacturer-identification obligation: component
        // suppliers are part of the Annex I Part II (1) SBOM inventory.
        "SBOM-CRA-COMPONENT-SUPPLIER" => RuleMeta {
            sarif_id: "SBOM-CRA-COMPONENT-SUPPLIER",
            name: "CraComponentSupplier",
            short_description: "CRA Annex I Part II (1): Component supplier identification",
            default_severity: ViolationSeverity::Warning,
            refs: &[(ANNEX, "Annex I Part II (1)"), (PREN, "PRE-7-RQ-03")],
            remediation: "Identify each component's supplier; placeholders such as NOASSERTION do not count.",
            advice: Some(&ADVICE_PRODUCER),
        },
        // Art. 14 reporting readiness: one rule per channel, each read from
        // the CRA sidecar only. Formerly one SBOM-CRA-ART-14 rule whose four
        // findings on the document shared a finding key. A missing PSIRT,
        // early-warning or notification channel is a Warning since the
        // 2026-09-11 deadline (an Info before it), escalated to Error for
        // important class II and critical products; the ENISA platform id
        // stays an Info.
        "SBOM-CRA-ART-14-PSIRT" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-14-PSIRT",
            name: "CraPsirtUrl",
            short_description: "CRA Art. 14: Public PSIRT URL that receives external vulnerability reports",
            default_severity: ViolationSeverity::Warning,
            refs: &[(CRA, "Art. 14")],
            remediation: "Document the public PSIRT URL that receives external vulnerability reports (Art. 14 reporting readiness): set psirtUrl in the CRA sidecar. This check reads only the sidecar.",
            advice: None,
        },
        "SBOM-CRA-ART-14-EARLY-WARNING" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-14-EARLY-WARNING",
            name: "CraEarlyWarningChannel",
            short_description: "CRA Art. 14(2)(a) / 14(4)(a): Channel for the 24-hour early warning",
            default_severity: ViolationSeverity::Warning,
            refs: &[(CRA, "Art. 14(2)(a)"), (CRA, "Art. 14(4)(a)")],
            remediation: "Document the channel for the 24-hour early warning of an actively exploited vulnerability or a severe incident (Art. 14(2)(a) / 14(4)(a)): set earlyWarningContact in the CRA sidecar. This check reads only the sidecar.",
            advice: None,
        },
        "SBOM-CRA-ART-14-NOTIFICATION" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-14-NOTIFICATION",
            name: "CraNotificationChannel",
            short_description: "CRA Art. 14(2)(b) / 14(4)(b): Channel for the 72-hour vulnerability and incident notifications",
            default_severity: ViolationSeverity::Warning,
            refs: &[(CRA, "Art. 14(2)(b)"), (CRA, "Art. 14(4)(b)")],
            remediation: "Document the channel for the 72-hour vulnerability and incident notifications (Art. 14(2)(b) / 14(4)(b)): set incidentReportContact in the CRA sidecar. This check reads only the sidecar.",
            advice: None,
        },
        "SBOM-CRA-ART-14-ENISA" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-14-ENISA",
            name: "CraEnisaPlatformIdentifier",
            short_description: "CRA Art. 14(7): Manufacturer identifier on the ENISA single reporting platform",
            default_severity: ViolationSeverity::Info,
            refs: &[(CRA, "Art. 14(7)")],
            remediation: "Record the manufacturer's identifier on the ENISA single reporting platform (Art. 14(7)) once ENISA publishes it: set enisaReportingPlatformId in the CRA sidecar. This check reads only the sidecar.",
            advice: None,
        },
        // The steward's vulnerability-handling floor is the one Art. 24
        // obligation the profile gates on: always an Error.
        "SBOM-CRA-ART-24" => RuleMeta {
            sarif_id: "SBOM-CRA-ART-24",
            name: "CraStewardVulnerabilityHandling",
            short_description: "CRA Art. 24: Open-source steward vulnerability-handling process (security contact or disclosure URL)",
            default_severity: ViolationSeverity::Error,
            refs: &[],
            remediation: "Show the open-source steward's vulnerability-handling process (Art. 24): reference a security contact or vulnerability-disclosure URL from the product component, or set psirtUrl or vulnerabilityDisclosureUrl in the CRA sidecar.",
            advice: Some(&ADVICE_SECURITY_CONTACT),
        },
        // ---- CRA Annexes -------------------------------------------------
        // The Annex I technical-documentation checks. They shared one SARIF
        // rule, SBOM-CRA-ANNEX-I, until v0.4.0; each is now its own.
        // Every CRA profile (both phases and the steward) emits a missing
        // component identifier as an Error.
        "SBOM-CRA-ANNEX-I-IDENTIFIER" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-I-IDENTIFIER",
            name: "CraComponentIdentifier",
            short_description: "CRA Annex I: Unique identifier (PURL, CPE, SWHID or SWID) on every component",
            default_severity: ViolationSeverity::Error,
            refs: &[(ANNEX, "Annex I"), (PREN, "PRE-7-RQ-07")],
            remediation: "Add a PURL, CPE, SWHID or SWID to each component for unique identification. PURLs are preferred (e.g., pkg:npm/lodash@4.17.21).",
            advice: Some(&ADVICE_IDENTIFIER),
        },
        "SBOM-CRA-ANNEX-I-TRACEABILITY" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-I-TRACEABILITY",
            name: "CraPrimaryTraceability",
            short_description: "CRA Annex I Part II (1): Primary product component traceable across updates by a PURL or CPE",
            default_severity: ViolationSeverity::Warning,
            refs: &[(ANNEX, "Annex I Part II"), (PREN, "PRE-7-RQ-07")],
            remediation: "Give the primary product component a PURL or CPE so it can be traced across updates (Annex I Part II (1)); a SWHID or SWID alone does not satisfy this check.",
            advice: Some(&ADVICE_PRIMARY_IDENTIFIER),
        },
        "SBOM-CRA-INVENTORY" => RuleMeta {
            sarif_id: "SBOM-CRA-INVENTORY",
            name: "CraInventory",
            short_description: "CRA Annex I Part II (1): SBOM inventories the product's software components",
            default_severity: ViolationSeverity::Error,
            refs: &[(ANNEX, "Annex I Part II (1)")],
            remediation: REMEDIATION_INVENTORY,
            advice: Some(&ADVICE_INVENTORY),
        },
        "SBOM-CRA-ANNEX-I-SUPPLY-CHAIN" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-I-SUPPLY-CHAIN",
            name: "CraDirectDependencySupplier",
            short_description: "CRA Annex I Part II: Supplier of every direct dependency identified (PRE-7-RQ-03, mandatory)",
            default_severity: ViolationSeverity::Warning,
            refs: &[
                (ANNEX, "Annex I Part II"),
                (PREN, "PRE-7-RQ-01"),
                (PREN, "PRE-7-RQ-03"),
            ],
            // Emitted only by the direct-dependency supplier check in cra.rs
            // (mandatory); the guidance must talk about suppliers, not
            // dependency relationships (#347).
            remediation: "Identify the supplier of every direct dependency, one hop from the primary component or, when none is declared, from a root of the dependency graph (mandatory under PRE-7-RQ-03).",
            advice: Some(&ADVICE_PRODUCER),
        },
        // The transitive-dependency supplier check (recommended), a second
        // document-level finding beside the direct one.
        "SBOM-CRA-ANNEX-I-SUPPLY-CHAIN-TRANSITIVE" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-I-SUPPLY-CHAIN-TRANSITIVE",
            name: "CraTransitiveDependencySupplier",
            short_description: "CRA Annex I Part II: Suppliers of transitive dependencies identified (PRE-7-RQ-03, recommended)",
            default_severity: ViolationSeverity::Info,
            refs: &[
                (ANNEX, "Annex I Part II"),
                (PREN, "PRE-7-RQ-01"),
                (PREN, "PRE-7-RQ-03"),
            ],
            remediation: "Identify the suppliers of transitive dependencies as well (recommended under PRE-7-RQ-03).",
            advice: Some(&ADVICE_PRODUCER),
        },
        "SBOM-CRA-ANNEX-I-INTEGRITY" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-I-INTEGRITY",
            name: "CraComponentHash",
            short_description: "CRA Annex I Part I (2)(f): Component hashes (SHA-256 or stronger) for integrity verification",
            default_severity: ViolationSeverity::Info,
            refs: &[(ANNEX, "Annex I Part I (2)(f)")],
            remediation: "Add cryptographic hashes (SHA-256 or stronger) to components for integrity verification.",
            advice: Some(&ADVICE_HASH),
        },
        "SBOM-CRA-ANNEX-I-DEPENDENCY" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-I-DEPENDENCY",
            name: "CraDependencyRelationships",
            short_description: "CRA Annex I: Dependency relationships connect the primary component to its dependencies",
            default_severity: ViolationSeverity::Error,
            refs: &[(ANNEX, "Annex I")],
            remediation: "Add dependency relationships between components: connect the primary component to its direct dependencies and keep most components inside the dependency graph.",
            advice: Some(&ADVICE_DEPENDENCIES),
        },
        // Several roots and no primary component: a document-level finding
        // beside the relationship gaps above.
        "SBOM-CRA-ANNEX-I-DEPENDENCY-ROOTS" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-I-DEPENDENCY-ROOTS",
            name: "CraAmbiguousDependencyRoots",
            short_description: "CRA Annex I: Primary component identified when the dependency graph has several roots",
            default_severity: ViolationSeverity::Warning,
            refs: &[(ANNEX, "Annex I")],
            remediation: "Identify the primary product component when the dependency graph has several roots, so the product's top-level dependencies are unambiguous.",
            advice: Some(&ADVICE_PRIMARY),
        },
        "SBOM-CRA-ANNEX-I-PRIMARY" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-I-PRIMARY",
            name: "CraPrimaryComponent",
            short_description: "CRA Annex I: Top-level product component identified",
            default_severity: ViolationSeverity::Warning,
            refs: &[(ANNEX, "Annex I")],
            remediation: "Identify the top-level product component.",
            advice: Some(&ADVICE_PRIMARY),
        },
        "SBOM-CRA-ANNEX-I-CONTROLS" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-I-CONTROLS",
            name: "CraAnnexIControlEvidence",
            short_description: "CRA Annex I Part I: Evidence URL for every control the CRA sidecar marks satisfied",
            default_severity: ViolationSeverity::Warning,
            refs: &[(ANNEX, "Annex I")],
            remediation: "Give every control the CRA sidecar's annexIPartIControls block marks satisfied an evidenceUrl pointing at its evidence (test report, design review, scan output), or set satisfied to false until the evidence exists.",
            advice: None,
        },
        // Document-level integrity. Formerly mis-cited Annex III (the
        // important-products class list); integrity protection is Annex I
        // Part I (2)(f). The clause covers integrity only — it does not
        // mention authenticity.
        "SBOM-CRA-DOC-INTEGRITY" => RuleMeta {
            sarif_id: "SBOM-CRA-DOC-INTEGRITY",
            name: "CraDocumentIntegrity",
            short_description: "CRA Annex I Part I (2)(f): Document integrity — serial number, hash, or digital signature",
            default_severity: ViolationSeverity::Info,
            refs: &[(ANNEX, "Annex I Part I (2)(f)")],
            remediation: "Add document-level integrity metadata (Annex I Part I (2)(f)): a unique document serial number or namespace.",
            advice: Some(&ADVICE_SERIAL),
        },
        "SBOM-CRA-ANNEX-IV" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-IV",
            name: "CraEuccCertification",
            short_description: "CRA Annex IV: EUCC (Common Criteria) certification the product class requires",
            default_severity: ViolationSeverity::Info,
            refs: &[(ANNEX, "Annex IV")],
            remediation: "Reference the EUCC (Common Criteria) certification the product class requires: set euccProtectionProfileId, euccTargetOfEvaluation, euccItsefIdentifier or an unexpired euccValidUntil in the CRA sidecar. Once euccValidUntil has passed, the certificate is expired and none of these keys counts.",
            advice: Some(&ADVICE_EUCC_ALT),
        },
        "SBOM-CRA-ANNEX-V" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-V",
            name: "CraDeclarationOfConformity",
            short_description: "CRA Annex V: EU Declaration of Conformity reference",
            default_severity: ViolationSeverity::Info,
            refs: &[(ANNEX, "Annex V")],
            remediation: "Reference the EU Declaration of Conformity (Annex V): set ceMarkingReference in the CRA sidecar to the DoC's URL or document ID.",
            advice: Some(&ADVICE_DOC_REF),
        },
        "SBOM-CRA-CYCLES" => RuleMeta {
            sarif_id: "SBOM-CRA-CYCLES",
            name: "CraDependencyCycles",
            short_description: "CRA Annex I Part II (1): Dependency graph must be an acyclic inventory — cyclic dependency declarations detected",
            default_severity: ViolationSeverity::Warning,
            refs: &[(ANNEX, "Annex I Part II (1)")],
            remediation: "Resolve cyclic dependency declarations so the SBOM's dependency graph is a directed acyclic inventory of the product's components.",
            advice: None,
        },
        // Fires only for a pinned class whose route goes beyond Module A:
        // Warning for important class I (the default here), escalated to
        // Error for important class II and critical products. Only a
        // certification reference counts: an attestation may be a
        // self-attestation (it still serves as the Annex V DoC reference).
        "SBOM-CRA-ANNEX-VIII" => RuleMeta {
            sarif_id: "SBOM-CRA-ANNEX-VIII",
            name: "CraConformityAssessment",
            short_description: "CRA Annex VIII: Conformity-assessment evidence for the resolved assessment route",
            default_severity: ViolationSeverity::Warning,
            refs: &[(ANNEX, "Annex VIII")],
            remediation: "Reference the notified-body or certification-body certificate the conformity-assessment route requires — the EU-type examination certificate (Module B+C), the quality-system approval (Module H) or the EUCC certificate — as a certification external reference on the product component. An attestation reference does not count here, since it may be a self-attestation; it still serves as the Annex V Declaration of Conformity reference.",
            advice: Some(&ADVICE_CONFORMITY_EVIDENCE),
        },
        // The four [PRE-8-RQ-02] checks on a hardware component, one id each
        // so several gaps on one component never share a finding key. They
        // shared one SARIF rule, SBOM-CRA-PRE-8-RQ-02, until v0.4.0.
        "SBOM-CRA-PRE-8-RQ-02-PRODUCER" => RuleMeta {
            sarif_id: "SBOM-CRA-PRE-8-RQ-02-PRODUCER",
            name: "CraHardwareProducer",
            short_description: "CRA prEN 40000-1-3 [PRE-8-RQ-02]: Producer of every hardware component (device, firmware, driver)",
            default_severity: ViolationSeverity::Error,
            refs: &[(PREN, "PRE-8-RQ-02")],
            remediation: "Name the producer (supplier or author) of every hardware component: device, firmware or device driver.",
            advice: Some(&ADVICE_PRODUCER),
        },
        "SBOM-CRA-PRE-8-RQ-02-IDENTIFIER" => RuleMeta {
            sarif_id: "SBOM-CRA-PRE-8-RQ-02-IDENTIFIER",
            name: "CraHardwareIdentifier",
            short_description: "CRA prEN 40000-1-3 [PRE-8-RQ-02]: Unique identifier on every hardware component",
            default_severity: ViolationSeverity::Error,
            refs: &[(PREN, "PRE-8-RQ-02")],
            remediation: "Give every hardware component a unique identifier: a PURL, CPE, SWHID or SWID.",
            advice: Some(&ADVICE_IDENTIFIER),
        },
        "SBOM-CRA-PRE-8-RQ-02-FIRMWARE-VERSION" => RuleMeta {
            sarif_id: "SBOM-CRA-PRE-8-RQ-02-FIRMWARE-VERSION",
            name: "CraFirmwareVersion",
            short_description: "CRA prEN 40000-1-3 [PRE-8-RQ-02]: Version of every firmware component",
            default_severity: ViolationSeverity::Error,
            refs: &[(PREN, "PRE-8-RQ-02")],
            remediation: "Give every firmware component its firmware version.",
            advice: Some(&ADVICE_VERSION),
        },
        "SBOM-CRA-PRE-8-RQ-02-DEVICE-FIRMWARE" => RuleMeta {
            sarif_id: "SBOM-CRA-PRE-8-RQ-02-DEVICE-FIRMWARE",
            name: "CraDeviceFirmware",
            short_description: "CRA prEN 40000-1-3 [PRE-8-RQ-02]: Every device has a version or a dependency on its firmware",
            default_severity: ViolationSeverity::Warning,
            refs: &[(PREN, "PRE-8-RQ-02")],
            remediation: "Give every device a version, or a dependency on the firmware component it runs.",
            advice: Some(&ADVICE_DEVICE_FIRMWARE),
        },
        "SBOM-CRA-PRE-7-RQ-07-RE" => RuleMeta {
            sarif_id: "SBOM-CRA-PRE-7-RQ-07-RE",
            name: "CraVendorHashCarryThrough",
            short_description: "CRA prEN 40000-1-3 [PRE-7-RQ-07-RE]: Upstream vendor-supplied component hashes must be carried through into the SBOM",
            default_severity: ViolationSeverity::Warning,
            refs: &[
                (ANNEX, "Annex I Part II"),
                (PREN, "PRE-7-RQ-07"),
                (PREN, "PRE-7-RQ-07-RE"),
            ],
            remediation: "Add cryptographic hashes (SHA-256 or stronger) to components for integrity verification.",
            advice: Some(&ADVICE_HASH),
        },
        // ---- Generic CRA / document-level (no specific article) ----------
        "SBOM-CRA-GENERAL" => RuleMeta {
            sarif_id: "SBOM-CRA-GENERAL",
            name: "CraGeneralRequirement",
            short_description: "CRA general SBOM readiness requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[],
            remediation: "Fix the document-level element the finding names. The CRA profiles' generic checks look for the SBOM's creator, a document serial number, a name on every component, a spec version sbom-tools reads (CycloneDX 1.4–1.7, SPDX 2.x or 3.0) and well-formed element identifiers.",
            advice: Some(&ADVICE_CRA_GENERAL),
        },
        // The generic path's checks under the CRA profiles, one id each so
        // that two of them on one subject never share a finding key. They
        // reported as SBOM-CRA-GENERAL until v0.4.0.
        "SBOM-CRA-CREATOR" => RuleMeta {
            sarif_id: "SBOM-CRA-CREATOR",
            name: "CraSbomCreator",
            short_description: "CRA readiness: SBOM creator identified (person, organization or tool)",
            default_severity: ViolationSeverity::Error,
            refs: &[],
            remediation: REMEDIATION_CREATOR,
            advice: Some(&ADVICE_CREATORS),
        },
        "SBOM-CRA-SERIAL" => RuleMeta {
            sarif_id: "SBOM-CRA-SERIAL",
            name: "CraDocumentIdentifier",
            short_description: "CRA readiness: SBOM carries a unique document identifier",
            default_severity: ViolationSeverity::Warning,
            refs: &[],
            remediation: REMEDIATION_SERIAL,
            advice: Some(&ADVICE_SERIAL),
        },
        "SBOM-CRA-COMPONENT-NAME" => RuleMeta {
            sarif_id: "SBOM-CRA-COMPONENT-NAME",
            name: "CraComponentName",
            short_description: "CRA readiness: Every component has a name",
            default_severity: ViolationSeverity::Error,
            refs: &[],
            remediation: REMEDIATION_COMPONENT_NAME,
            advice: Some(&ADVICE_NAME),
        },
        "SBOM-CRA-SPEC-VERSION" => RuleMeta {
            sarif_id: "SBOM-CRA-SPEC-VERSION",
            name: "CraSpecVersion",
            short_description: "CRA readiness: Spec version sbom-tools reads (CycloneDX 1.4–1.7, SPDX 2.x or 3.0)",
            default_severity: ViolationSeverity::Warning,
            refs: &[],
            remediation: REMEDIATION_SPEC_VERSION,
            advice: Some(&ADVICE_SPEC_VERSION),
        },
        "SBOM-CRA-SPEC-VERSION-UNKNOWN" => RuleMeta {
            sarif_id: "SBOM-CRA-SPEC-VERSION-UNKNOWN",
            name: "CraSpecVersionUnknown",
            short_description: "CRA readiness: SPDX document declares a valid SPDX version",
            default_severity: ViolationSeverity::Warning,
            refs: &[],
            remediation: REMEDIATION_SPEC_VERSION_UNKNOWN,
            advice: Some(&ADVICE_SPEC_VERSION),
        },
        "SBOM-CRA-ELEMENT-ID" => RuleMeta {
            sarif_id: "SBOM-CRA-ELEMENT-ID",
            name: "CraElementIdentifier",
            short_description: "CRA readiness: Every element has its own well-formed identifier",
            default_severity: ViolationSeverity::Info,
            refs: &[],
            remediation: REMEDIATION_ELEMENT_ID,
            advice: Some(&ADVICE_ELEMENT_ID),
        },
        // Fallback SARIF rule of the quality profiles
        // (Minimum/Standard/Comprehensive): no check emits it, but the SARIF
        // renderer files a finding without a registered rule here for quality
        // runs (the `SBOM-CRA-GENERAL` default included), so it never
        // surfaces under a CRA identity.
        "SBOM-QUALITY-GENERAL" => RuleMeta {
            sarif_id: "SBOM-QUALITY-GENERAL",
            name: "QualityGeneralRequirement",
            short_description: "SBOM quality: general quality-profile requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[],
            remediation: "Fix the element the finding names. The quality profiles' generic checks look for the SBOM's creator, a document serial number, a component inventory, a name, unique identifier (PURL, CPE, SWHID or SWID), license and hash on every component, a spec version sbom-tools reads (CycloneDX 1.4–1.7, SPDX 2.x or 3.0) and well-formed element identifiers.",
            advice: Some(&ADVICE_QUALITY_GENERAL),
        },
        "SBOM-QUALITY-CREATOR" => RuleMeta {
            sarif_id: "SBOM-QUALITY-CREATOR",
            name: "QualitySbomCreator",
            short_description: "SBOM quality: SBOM creator identified (person, organization or tool)",
            default_severity: ViolationSeverity::Error,
            refs: &[],
            remediation: REMEDIATION_CREATOR,
            advice: Some(&ADVICE_CREATORS),
        },
        "SBOM-QUALITY-SERIAL" => RuleMeta {
            sarif_id: "SBOM-QUALITY-SERIAL",
            name: "QualityDocumentIdentifier",
            short_description: "SBOM quality: SBOM carries a unique document identifier",
            default_severity: ViolationSeverity::Warning,
            refs: &[],
            remediation: REMEDIATION_SERIAL,
            advice: Some(&ADVICE_SERIAL),
        },
        "SBOM-QUALITY-INVENTORY" => RuleMeta {
            sarif_id: "SBOM-QUALITY-INVENTORY",
            name: "QualityInventory",
            short_description: "SBOM quality: SBOM inventories at least one software component",
            default_severity: ViolationSeverity::Error,
            refs: &[],
            remediation: REMEDIATION_INVENTORY,
            advice: Some(&ADVICE_INVENTORY),
        },
        "SBOM-QUALITY-NAME" => RuleMeta {
            sarif_id: "SBOM-QUALITY-NAME",
            name: "QualityComponentName",
            short_description: "SBOM quality: Every component has a name",
            default_severity: ViolationSeverity::Error,
            refs: &[],
            remediation: REMEDIATION_COMPONENT_NAME,
            advice: Some(&ADVICE_NAME),
        },
        "SBOM-QUALITY-IDENTIFIER" => RuleMeta {
            sarif_id: "SBOM-QUALITY-IDENTIFIER",
            name: "QualityComponentIdentifier",
            short_description: "SBOM quality: Every component has a unique identifier (PURL, CPE, SWHID or SWID)",
            default_severity: ViolationSeverity::Warning,
            refs: &[],
            remediation: "Give every component a unique identifier: a PURL, CPE, SWHID or SWID.",
            advice: Some(&ADVICE_IDENTIFIER),
        },
        "SBOM-QUALITY-LICENSE" => RuleMeta {
            sarif_id: "SBOM-QUALITY-LICENSE",
            name: "QualityComponentLicense",
            short_description: "SBOM quality: Every component records its license, declared or concluded",
            default_severity: ViolationSeverity::Warning,
            refs: &[],
            remediation: "Record every component's license, declared or concluded.",
            advice: Some(&ADVICE_LICENSE),
        },
        "SBOM-QUALITY-HASH" => RuleMeta {
            sarif_id: "SBOM-QUALITY-HASH",
            name: "QualityComponentHash",
            short_description: "SBOM quality: Every component carries a cryptographic hash",
            default_severity: ViolationSeverity::Warning,
            refs: &[],
            remediation: "Give every component a cryptographic hash, preferably SHA-256 or stronger.",
            advice: Some(&ADVICE_HASH),
        },
        "SBOM-QUALITY-SPEC-VERSION" => RuleMeta {
            sarif_id: "SBOM-QUALITY-SPEC-VERSION",
            name: "QualitySpecVersion",
            short_description: "SBOM quality: Spec version sbom-tools reads (CycloneDX 1.4–1.7, SPDX 2.x or 3.0)",
            default_severity: ViolationSeverity::Warning,
            refs: &[],
            remediation: REMEDIATION_SPEC_VERSION,
            advice: Some(&ADVICE_SPEC_VERSION),
        },
        "SBOM-QUALITY-SPEC-VERSION-UNKNOWN" => RuleMeta {
            sarif_id: "SBOM-QUALITY-SPEC-VERSION-UNKNOWN",
            name: "QualitySpecVersionUnknown",
            short_description: "SBOM quality: SPDX document declares a valid SPDX version",
            default_severity: ViolationSeverity::Warning,
            refs: &[],
            remediation: REMEDIATION_SPEC_VERSION_UNKNOWN,
            advice: Some(&ADVICE_SPEC_VERSION),
        },
        "SBOM-QUALITY-ELEMENT-ID" => RuleMeta {
            sarif_id: "SBOM-QUALITY-ELEMENT-ID",
            name: "QualityElementIdentifier",
            short_description: "SBOM quality: Every element has its own well-formed identifier",
            default_severity: ViolationSeverity::Info,
            refs: &[],
            remediation: REMEDIATION_ELEMENT_ID,
            advice: Some(&ADVICE_ELEMENT_ID),
        },
        // ---- EUCC Substantial (reference-only profile) -------------------
        "SBOM-EUCC-PP" => RuleMeta {
            sarif_id: "SBOM-EUCC-PP",
            name: "EuccProtectionProfile",
            short_description: "EUCC (Reg. (EU) 2024/482): Common Criteria Protection Profile reference — sidecar eucc_protection_profile_id",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eucc, "Protection Profile")],
            remediation: REMEDIATION_EUCC,
            advice: None,
        },
        "SBOM-EUCC-TOE" => RuleMeta {
            sarif_id: "SBOM-EUCC-TOE",
            name: "EuccTargetOfEvaluation",
            short_description: "EUCC (Reg. (EU) 2024/482): Target of Evaluation reference — sidecar eucc_target_of_evaluation",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eucc, "ToE")],
            remediation: REMEDIATION_EUCC,
            advice: None,
        },
        "SBOM-EUCC-ITSEF" => RuleMeta {
            sarif_id: "SBOM-EUCC-ITSEF",
            name: "EuccItsefIdentifier",
            short_description: "EUCC (Reg. (EU) 2024/482): ITSEF (IT Security Evaluation Facility) identifier — sidecar eucc_itsef_identifier",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eucc, "ITSEF")],
            remediation: REMEDIATION_EUCC,
            advice: None,
        },
        "SBOM-EUCC-VALIDITY" => RuleMeta {
            sarif_id: "SBOM-EUCC-VALIDITY",
            name: "EuccCertificateValidity",
            short_description: "EUCC (Reg. (EU) 2024/482): certificate valid-until date present, not expired, not near expiry — sidecar eucc_valid_until",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eucc, "Certificate validity")],
            remediation: REMEDIATION_EUCC,
            advice: None,
        },
        "SBOM-EUCC-CERTREF" => RuleMeta {
            sarif_id: "SBOM-EUCC-CERTREF",
            name: "EuccCertificationReference",
            short_description: "EUCC (Reg. (EU) 2024/482): Certification/Attestation external reference to an EUCC certificate (recommended)",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::Eucc, "Certification reference")],
            remediation: "Reference the EUCC certificate from the SBOM itself (recommended alongside the sidecar evidence).",
            advice: Some(&ADVICE_EUCC_CERTREF),
        },
        // Generic bucket for EUCC-run findings whose check site has no
        // specific registry mapping (SARIF fallback re-bucketing).
        "SBOM-EUCC-GENERAL" => RuleMeta {
            sarif_id: "SBOM-EUCC-GENERAL",
            name: "EuccGeneralRequirement",
            short_description: "EUCC (Reg. (EU) 2024/482): general SBOM evidence requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::Eucc, "Reg. (EU) 2024/482")],
            remediation: REMEDIATION_EUCC,
            advice: None,
        },
        // ---- EU AI Act Annex IV technical-documentation readiness --------
        // The per-element checks below shared one SARIF rule per Annex IV
        // paragraph (SBOM-AIACT-ANNEX-IV-1, -2C, -2D, -2G, -3) until v0.4.0.
        "SBOM-AIACT-NA" => RuleMeta {
            sarif_id: "SBOM-AIACT-NA",
            name: "AiActNotApplicable",
            short_description: "EU AI Act Annex IV readiness not applicable — SBOM has no ML-model or dataset components",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::EuAiAct, "Annex IV")],
            remediation: REMEDIATION_AIACT_NA,
            advice: Some(&ADVICE_AI_COMPONENTS),
        },
        "SBOM-AIACT-ANNEX-IV-1-DESCRIPTION" => RuleMeta {
            sarif_id: "SBOM-AIACT-ANNEX-IV-1-DESCRIPTION",
            name: "AiActModelDescription",
            short_description: "EU AI Act Annex IV §1: General description of the AI model (description, architecture or model card)",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::EuAiAct, "Annex IV §1")],
            remediation: "Add a general description of the AI model: a description, its architecture family or name, or a model-card reference.",
            advice: Some(&ADVICE_AI_DESCRIPTION),
        },
        "SBOM-AIACT-ANNEX-IV-1-PURPOSE" => RuleMeta {
            sarif_id: "SBOM-AIACT-ANNEX-IV-1-PURPOSE",
            name: "AiActIntendedPurpose",
            short_description: "EU AI Act Annex IV §1: Intended purpose and use-cases of the AI model",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::EuAiAct, "Annex IV §1")],
            remediation: "Document the intended purpose / use-cases of the AI model.",
            advice: Some(&ADVICE_AI_PURPOSE),
        },
        "SBOM-AIACT-ANNEX-IV-2D-DATASETS" => RuleMeta {
            sarif_id: "SBOM-AIACT-ANNEX-IV-2D-DATASETS",
            name: "AiActTrainingDatasets",
            short_description: "EU AI Act Annex IV §2(d): Training datasets referenced",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::EuAiAct, "Annex IV §2(d)")],
            remediation: "Reference the training datasets used.",
            advice: Some(&ADVICE_AI_DATASETS),
        },
        "SBOM-AIACT-ANNEX-IV-2D-SENSITIVITY" => RuleMeta {
            sarif_id: "SBOM-AIACT-ANNEX-IV-2D-SENSITIVITY",
            name: "AiActDatasetSensitivity",
            short_description: "EU AI Act Annex IV §2(d): Sensitivity classification of each dataset",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::EuAiAct, "Annex IV §2(d)")],
            remediation: "Declare a sensitivity classification for each dataset (e.g. 'none', 'pii', 'personal').",
            advice: Some(&ADVICE_AI_SENSITIVITY),
        },
        "SBOM-AIACT-ANNEX-IV-2D-PERSONAL-DATA" => RuleMeta {
            sarif_id: "SBOM-AIACT-ANNEX-IV-2D-PERSONAL-DATA",
            name: "AiActPersonalData",
            short_description: "EU AI Act Annex IV §2(d): Training data involving personal data (GDPR lawful basis and safeguards)",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::EuAiAct, "Annex IV §2(d)")],
            remediation: "Where training data involves personal data, document the GDPR lawful basis and data-protection measures alongside the SBOM (AI Act and GDPR apply in parallel).",
            advice: None,
        },
        "SBOM-AIACT-ANNEX-IV-2G-METRICS" => RuleMeta {
            sarif_id: "SBOM-AIACT-ANNEX-IV-2G-METRICS",
            name: "AiActValidationMetrics",
            short_description: "EU AI Act Annex IV §2(g): Validation and testing metrics (accuracy, robustness)",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::EuAiAct, "Annex IV §2(g)")],
            remediation: "Record validation/testing metrics (accuracy, robustness).",
            advice: Some(&ADVICE_AI_METRICS),
        },
        // Energy / computational-resources disclosure lives in Annex IV
        // §2(c) ("the computational resources used to develop, train, test
        // and validate the AI system"), NOT §2(g), which covers validation
        // and testing procedures/metrics. Explicit energy reporting is the
        // GPAI technical documentation (Annex XI).
        "SBOM-AIACT-ANNEX-IV-2C-ENERGY" => RuleMeta {
            sarif_id: "SBOM-AIACT-ANNEX-IV-2C-ENERGY",
            name: "AiActComputationalResources",
            short_description: "EU AI Act Annex IV §2(c): Computational resources and training-energy disclosure",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::EuAiAct, "Annex IV §2(c)")],
            remediation: "Disclose computational resources / training energy.",
            advice: Some(&ADVICE_AI_ENERGY),
        },
        "SBOM-AIACT-ANNEX-IV-3-LIMITATIONS" => RuleMeta {
            sarif_id: "SBOM-AIACT-ANNEX-IV-3-LIMITATIONS",
            name: "AiActLimitations",
            short_description: "EU AI Act Annex IV §3: Foreseeable limitations and risks of the model",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::EuAiAct, "Annex IV §3")],
            remediation: "State the foreseeable limitations and risks of the model, including ethical and fairness considerations.",
            advice: Some(&ADVICE_AI_LIMITATIONS),
        },
        "SBOM-AIACT-UNTYPED-ML" => RuleMeta {
            sarif_id: "SBOM-AIACT-UNTYPED-ML",
            name: "AiActUntypedMlContent",
            short_description: "EU AI Act readiness: ML content detected but not typed machine-learning-model",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::EuAiAct, "Annex IV: applicability")],
            remediation: REMEDIATION_UNTYPED_ML,
            advice: Some(&ADVICE_UNTYPED_ML),
        },
        // Generic bucket for EU-AI-Act-run findings whose check site has no
        // specific registry mapping (SARIF fallback re-bucketing).
        "SBOM-AIACT-GENERAL" => RuleMeta {
            sarif_id: "SBOM-AIACT-GENERAL",
            name: "AiActGeneralRequirement",
            short_description: "EU AI Act Annex IV: general documentation-readiness requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::EuAiAct, "Annex IV")],
            remediation: "Catch-all for EU AI Act Annex IV findings that have no dedicated rule (no check emits it; the SARIF writer files unmapped findings here). Document the element the finding's requirement names: each model's description and intended purpose, its training datasets and their sensitivity, validation metrics, computational resources, and limitations.",
            advice: None,
        },
        // ---- BSI/G7 SBOM-for-AI Minimum Elements readiness ---------------
        // The element-level checks below shared one SARIF rule per cluster
        // (SBOM-BSIAI-META, -SYS, -MODEL, -DATASET, -INFRA, -SEC) until
        // v0.4.0.
        "SBOM-BSIAI-NA" => RuleMeta {
            sarif_id: "SBOM-BSIAI-NA",
            name: "BsiSbomForAiNotApplicable",
            short_description: "BSI/G7 SBOM-for-AI minimum-elements readiness not applicable — SBOM has no ML-model or dataset components",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::BsiSbomForAi, "Applicability")],
            remediation: REMEDIATION_BSIAI_NA,
            advice: Some(&ADVICE_AI_COMPONENTS),
        },
        "SBOM-BSIAI-UNTYPED-ML" => RuleMeta {
            sarif_id: "SBOM-BSIAI-UNTYPED-ML",
            name: "BsiSbomForAiUntypedMlContent",
            short_description: "BSI/G7 SBOM-for-AI readiness: ML content detected but not typed machine-learning-model",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "Applicability")],
            remediation: REMEDIATION_UNTYPED_ML,
            advice: Some(&ADVICE_UNTYPED_ML),
        },
        // Metadata cluster
        "SBOM-BSIAI-META-AUTHOR" => RuleMeta {
            sarif_id: "SBOM-BSIAI-META-AUTHOR",
            name: "BsiSbomForAiAuthor",
            short_description: "BSI/G7 SBOM-for-AI Metadata: SBOM author",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiSbomForAi, "Metadata / Author")],
            remediation: REMEDIATION_BSIAI_GENERAL,
            advice: Some(&ADVICE_CREATORS),
        },
        "SBOM-BSIAI-META-FORMAT" => RuleMeta {
            sarif_id: "SBOM-BSIAI-META-FORMAT",
            name: "BsiSbomForAiDataFormat",
            short_description: "BSI/G7 SBOM-for-AI Metadata: Data-format name and version",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiSbomForAi, "Metadata / Data format name + version")],
            remediation: REMEDIATION_BSIAI_GENERAL,
            advice: None,
        },
        "SBOM-BSIAI-META-TIMESTAMP" => RuleMeta {
            sarif_id: "SBOM-BSIAI-META-TIMESTAMP",
            name: "BsiSbomForAiTimestamp",
            short_description: "BSI/G7 SBOM-for-AI Metadata: SBOM timestamp",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiSbomForAi, "Metadata / Timestamp")],
            remediation: REMEDIATION_BSIAI_GENERAL,
            advice: Some(&ADVICE_TIMESTAMP),
        },
        "SBOM-BSIAI-META-TOOL" => RuleMeta {
            sarif_id: "SBOM-BSIAI-META-TOOL",
            name: "BsiSbomForAiGenerationTool",
            short_description: "BSI/G7 SBOM-for-AI Metadata: Generation tool",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "Metadata / Generation tool")],
            remediation: REMEDIATION_BSIAI_GENERAL,
            advice: Some(&ADVICE_TOOL),
        },
        "SBOM-BSIAI-META-SIGNATURE" => RuleMeta {
            sarif_id: "SBOM-BSIAI-META-SIGNATURE",
            name: "BsiSbomForAiSignature",
            short_description: "BSI/G7 SBOM-for-AI Metadata: SBOM signature",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::BsiSbomForAi, "Metadata / Signature")],
            remediation: REMEDIATION_BSIAI_GENERAL,
            advice: Some(&ADVICE_SIGNATURE),
        },
        // System-Level cluster
        "SBOM-BSIAI-SYS-PRIMARY" => RuleMeta {
            sarif_id: "SBOM-BSIAI-SYS-PRIMARY",
            name: "BsiSbomForAiPrimarySystem",
            short_description: "BSI/G7 SBOM-for-AI System-Level: Primary AI system identified",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "System-Level / Primary AI system")],
            remediation: REMEDIATION_BSIAI_GENERAL,
            advice: Some(&ADVICE_PRIMARY),
        },
        "SBOM-BSIAI-SYS-PRODUCER" => RuleMeta {
            sarif_id: "SBOM-BSIAI-SYS-PRODUCER",
            name: "BsiSbomForAiProducer",
            short_description: "BSI/G7 SBOM-for-AI System-Level: Producer of the AI system",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "System-Level / Producer")],
            remediation: REMEDIATION_BSIAI_GENERAL,
            advice: Some(&ADVICE_PRODUCER),
        },
        "SBOM-BSIAI-SYS-DATAFLOW" => RuleMeta {
            sarif_id: "SBOM-BSIAI-SYS-DATAFLOW",
            name: "BsiSbomForAiDataFlow",
            short_description: "BSI/G7 SBOM-for-AI System-Level: Data flow and usage of the AI system",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::BsiSbomForAi, "System-Level / Data flow & usage")],
            remediation: REMEDIATION_BSIAI_GENERAL,
            advice: None,
        },
        // Models cluster
        "SBOM-BSIAI-MODEL-NAME" => RuleMeta {
            sarif_id: "SBOM-BSIAI-MODEL-NAME",
            name: "BsiSbomForAiModelName",
            short_description: "BSI/G7 SBOM-for-AI Models: Model name",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiSbomForAi, "Models / Model name")],
            remediation: REMEDIATION_BSIAI_MODELS,
            advice: Some(&ADVICE_NAME),
        },
        "SBOM-BSIAI-MODEL-VERSION" => RuleMeta {
            sarif_id: "SBOM-BSIAI-MODEL-VERSION",
            name: "BsiSbomForAiModelVersion",
            short_description: "BSI/G7 SBOM-for-AI Models: Model version",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiSbomForAi, "Models / Model version")],
            remediation: REMEDIATION_BSIAI_MODELS,
            advice: Some(&ADVICE_VERSION),
        },
        "SBOM-BSIAI-MODEL-IDENTIFIER" => RuleMeta {
            sarif_id: "SBOM-BSIAI-MODEL-IDENTIFIER",
            name: "BsiSbomForAiModelIdentifier",
            short_description: "BSI/G7 SBOM-for-AI Models: Unique model identifier (PURL, CPE, SWHID or SWID)",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiSbomForAi, "Models / Model identifier")],
            remediation: REMEDIATION_BSIAI_MODELS,
            advice: Some(&ADVICE_IDENTIFIER),
        },
        "SBOM-BSIAI-MODEL-HASH" => RuleMeta {
            sarif_id: "SBOM-BSIAI-MODEL-HASH",
            name: "BsiSbomForAiModelHash",
            short_description: "BSI/G7 SBOM-for-AI Models: Model-weight hash value",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiSbomForAi, "Models / Model hash value")],
            remediation: REMEDIATION_BSIAI_MODELS,
            advice: Some(&ADVICE_HASH),
        },
        "SBOM-BSIAI-MODEL-HASH-ALGO" => RuleMeta {
            sarif_id: "SBOM-BSIAI-MODEL-HASH-ALGO",
            name: "BsiSbomForAiModelHashAlgorithm",
            short_description: "BSI/G7 SBOM-for-AI Models: Model-weight hash uses a NIST-approved algorithm (SHA-256 or stronger)",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiSbomForAi, "Models / Hash algorithm")],
            remediation: REMEDIATION_BSIAI_MODELS,
            advice: Some(&ADVICE_HASH),
        },
        "SBOM-BSIAI-MODEL-CARD" => RuleMeta {
            sarif_id: "SBOM-BSIAI-MODEL-CARD",
            name: "BsiSbomForAiModelCard",
            short_description: "BSI/G7 SBOM-for-AI Models: Model card",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "Models / Model card")],
            remediation: REMEDIATION_BSIAI_MODELS,
            advice: Some(&ADVICE_AI_MODEL_CARD),
        },
        "SBOM-BSIAI-MODEL-ARCHITECTURE" => RuleMeta {
            sarif_id: "SBOM-BSIAI-MODEL-ARCHITECTURE",
            name: "BsiSbomForAiModelArchitecture",
            short_description: "BSI/G7 SBOM-for-AI Models: Model architecture",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "Models / Architecture")],
            remediation: REMEDIATION_BSIAI_MODELS,
            advice: Some(&ADVICE_AI_ARCHITECTURE),
        },
        "SBOM-BSIAI-MODEL-DATASETS" => RuleMeta {
            sarif_id: "SBOM-BSIAI-MODEL-DATASETS",
            name: "BsiSbomForAiModelDatasets",
            short_description: "BSI/G7 SBOM-for-AI Models: Training datasets referenced",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "Models / Training datasets")],
            remediation: REMEDIATION_BSIAI_MODELS,
            advice: Some(&ADVICE_AI_TRAINING_DATASETS),
        },
        "SBOM-BSIAI-MODEL-LIMITATIONS" => RuleMeta {
            sarif_id: "SBOM-BSIAI-MODEL-LIMITATIONS",
            name: "BsiSbomForAiModelLimitations",
            short_description: "BSI/G7 SBOM-for-AI Models: Model limitations",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "Models / Limitations")],
            remediation: REMEDIATION_BSIAI_MODELS,
            advice: Some(&ADVICE_AI_LIMITATION),
        },
        "SBOM-BSIAI-MODEL-LICENSE" => RuleMeta {
            sarif_id: "SBOM-BSIAI-MODEL-LICENSE",
            name: "BsiSbomForAiModelLicense",
            short_description: "BSI/G7 SBOM-for-AI Models: Model license",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "Models / Model license")],
            remediation: REMEDIATION_BSIAI_MODELS,
            advice: Some(&ADVICE_LICENSE),
        },
        // Datasets cluster
        "SBOM-BSIAI-DATASET-NAME" => RuleMeta {
            sarif_id: "SBOM-BSIAI-DATASET-NAME",
            name: "BsiSbomForAiDatasetName",
            short_description: "BSI/G7 SBOM-for-AI Datasets: Dataset name",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiSbomForAi, "Datasets / Dataset name")],
            remediation: REMEDIATION_BSIAI_DATASETS,
            advice: Some(&ADVICE_NAME),
        },
        "SBOM-BSIAI-DATASET-IDENTIFIER" => RuleMeta {
            sarif_id: "SBOM-BSIAI-DATASET-IDENTIFIER",
            name: "BsiSbomForAiDatasetIdentifier",
            short_description: "BSI/G7 SBOM-for-AI Datasets: Unique dataset identifier",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiSbomForAi, "Datasets / Dataset identifier")],
            remediation: REMEDIATION_BSIAI_DATASETS,
            advice: Some(&ADVICE_IDENTIFIER),
        },
        "SBOM-BSIAI-DATASET-HASH" => RuleMeta {
            sarif_id: "SBOM-BSIAI-DATASET-HASH",
            name: "BsiSbomForAiDatasetHash",
            short_description: "BSI/G7 SBOM-for-AI Datasets: Dataset hash value",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "Datasets / Dataset hash value")],
            remediation: REMEDIATION_BSIAI_DATASETS,
            advice: Some(&ADVICE_HASH),
        },
        "SBOM-BSIAI-DATASET-LICENSE" => RuleMeta {
            sarif_id: "SBOM-BSIAI-DATASET-LICENSE",
            name: "BsiSbomForAiDatasetLicense",
            short_description: "BSI/G7 SBOM-for-AI Datasets: Dataset license",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "Datasets / Dataset license")],
            remediation: REMEDIATION_BSIAI_DATASETS,
            advice: Some(&ADVICE_LICENSE),
        },
        "SBOM-BSIAI-DATASET-SENSITIVITY" => RuleMeta {
            sarif_id: "SBOM-BSIAI-DATASET-SENSITIVITY",
            name: "BsiSbomForAiDatasetSensitivity",
            short_description: "BSI/G7 SBOM-for-AI Datasets: Sensitivity classification",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "Datasets / Sensitivity classification")],
            remediation: REMEDIATION_BSIAI_DATASETS,
            advice: Some(&ADVICE_AI_SENSITIVITY),
        },
        "SBOM-BSIAI-DATASET-PROVENANCE" => RuleMeta {
            sarif_id: "SBOM-BSIAI-DATASET-PROVENANCE",
            name: "BsiSbomForAiDatasetProvenance",
            short_description: "BSI/G7 SBOM-for-AI Datasets: Provenance and intended use",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "Datasets / Provenance & intended use")],
            remediation: REMEDIATION_BSIAI_DATASETS,
            advice: Some(&ADVICE_DATASET_PROVENANCE),
        },
        // Infrastructure cluster
        "SBOM-BSIAI-INFRA-RUNTIME" => RuleMeta {
            sarif_id: "SBOM-BSIAI-INFRA-RUNTIME",
            name: "BsiSbomForAiRuntime",
            short_description: "BSI/G7 SBOM-for-AI Infrastructure: Runtime and framework dependency links",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::BsiSbomForAi, "Infrastructure / Runtime & framework")],
            remediation: REMEDIATION_BSIAI_GENERAL,
            advice: Some(&ADVICE_DEPENDENCIES),
        },
        // Security cluster
        "SBOM-BSIAI-SEC-CONTROLS" => RuleMeta {
            sarif_id: "SBOM-BSIAI-SEC-CONTROLS",
            name: "BsiSbomForAiSecurityControls",
            short_description: "BSI/G7 SBOM-for-AI Security: AI-specific security controls",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::BsiSbomForAi, "Security / AI security controls")],
            remediation: REMEDIATION_BSIAI_GENERAL,
            advice: None,
        },
        "SBOM-BSIAI-SEC-EXPLOITABILITY" => RuleMeta {
            sarif_id: "SBOM-BSIAI-SEC-EXPLOITABILITY",
            name: "BsiSbomForAiExploitability",
            short_description: "BSI/G7 SBOM-for-AI Security: Exploitability reference",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::BsiSbomForAi, "Security / Exploitability reference")],
            remediation: REMEDIATION_BSIAI_GENERAL,
            advice: None,
        },
        // Generic bucket for BSI/G7-SBOM-for-AI-run findings whose check site
        // has no specific registry mapping (SARIF fallback re-bucketing).
        "SBOM-BSIAI-GENERAL" => RuleMeta {
            sarif_id: "SBOM-BSIAI-GENERAL",
            name: "BsiSbomForAiGeneralRequirement",
            short_description: "BSI/G7 SBOM-for-AI: general minimum-elements requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "Minimum Elements")],
            remediation: REMEDIATION_BSIAI_GENERAL,
            advice: None,
        },
        // ---- NTIA --------------------------------------------------------
        "SBOM-NTIA-VERSION" => RuleMeta {
            sarif_id: "SBOM-NTIA-VERSION",
            name: "NtiaVersion",
            short_description: "NTIA Minimum Elements: Component version string",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NtiaMinimum, "NTIA Minimum Elements")],
            remediation: "Give every component the version its supplier assigned (an NTIA minimum data field); placeholders such as NOASSERTION, TBD or N/A do not count.",
            advice: Some(&ADVICE_VERSION),
        },
        "SBOM-NTIA-TIMESTAMP" => RuleMeta {
            sarif_id: "SBOM-NTIA-TIMESTAMP",
            name: "NtiaTimestamp",
            short_description: "NTIA Minimum Elements: Creation timestamp",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NtiaMinimum, "NTIA Minimum Elements")],
            remediation: "Record when the SBOM was created (the NTIA Timestamp data field).",
            advice: Some(&ADVICE_TIMESTAMP),
        },
        "SBOM-NTIA-SUPPLIER" => RuleMeta {
            sarif_id: "SBOM-NTIA-SUPPLIER",
            name: "NtiaSupplier",
            short_description: "NTIA Minimum Elements: Supplier name",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NtiaMinimum, "NTIA Minimum Elements")],
            remediation: "Name the supplier of every component, the entity that creates, defines and identifies it (an NTIA minimum data field); placeholders such as NOASSERTION do not count.",
            advice: Some(&ADVICE_PRODUCER),
        },
        "SBOM-NTIA-DEPENDENCY" => RuleMeta {
            sarif_id: "SBOM-NTIA-DEPENDENCY",
            name: "NtiaDependency",
            short_description: "NTIA Minimum Elements: Dependency relationship",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NtiaMinimum, "NTIA Minimum Elements")],
            remediation: "Declare the dependency relationships between components (an NTIA minimum data field): connect the primary component to its direct dependencies and keep most components inside the dependency graph.",
            advice: Some(&ADVICE_DEPENDENCIES),
        },
        // ---- FDA ---------------------------------------------------------
        "SBOM-FDA-SUPPLIER" => RuleMeta {
            sarif_id: "SBOM-FDA-SUPPLIER",
            name: "FdaSupplier",
            short_description: "FDA Medical Device: Component supplier/manufacturer information",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: "Identify the device manufacturer as an organization creator of the SBOM, and the supplier of every component (FDA premarket guidance, NTIA baseline); placeholders such as NOASSERTION do not count.",
            advice: Some(&ADVICE_FDA_SUPPLIER),
        },
        "SBOM-FDA-SUPPORT" => RuleMeta {
            sarif_id: "SBOM-FDA-SUPPORT",
            name: "FdaSupport",
            short_description: "FDA Medical Device: Level-of-support and end-of-support information",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: "State the components' level of support and end-of-support date (FD&C §524B); the information may also accompany the SBOM.",
            advice: Some(&ADVICE_FDA_SUPPORT),
        },
        // The creator contact-email check, a second document-level finding
        // beside the support information above.
        "SBOM-FDA-CONTACT" => RuleMeta {
            sarif_id: "SBOM-FDA-CONTACT",
            name: "FdaCreatorContact",
            short_description: "FDA Medical Device: SBOM creator contact email",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: "Give the SBOM creator a contact email (FDA premarket guidance).",
            advice: Some(&ADVICE_FDA_CONTACT),
        },
        "SBOM-FDA-NAME" => RuleMeta {
            sarif_id: "SBOM-FDA-NAME",
            name: "FdaDocumentName",
            short_description: "FDA Medical Device: SBOM document name",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: "Give the SBOM a document name (FDA premarket guidance).",
            advice: Some(&ADVICE_DOC_NAME),
        },
        "SBOM-FDA-VERSION" => RuleMeta {
            sarif_id: "SBOM-FDA-VERSION",
            name: "FdaVersion",
            short_description: "FDA Medical Device: Component version information",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: "Give every component its version (FDA premarket guidance, NTIA baseline); placeholders such as NOASSERTION do not count.",
            advice: Some(&ADVICE_VERSION),
        },
        "SBOM-FDA-IDENTIFIER" => RuleMeta {
            sarif_id: "SBOM-FDA-IDENTIFIER",
            name: "FdaIdentifier",
            short_description: "FDA Medical Device: Component unique identifier (PURL/CPE/SWID)",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: "Give every component a unique identifier, a PURL, CPE, SWHID or SWID (FDA premarket guidance, NTIA baseline).",
            advice: Some(&ADVICE_IDENTIFIER),
        },
        "SBOM-FDA-HASH" => RuleMeta {
            sarif_id: "SBOM-FDA-HASH",
            name: "FdaHash",
            short_description: "FDA Medical Device: Component cryptographic hash",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: "Give every component a cryptographic hash using SHA-256 or stronger (FDA premarket guidance); MD5 or SHA-1 alone is flagged as weak.",
            advice: Some(&ADVICE_HASH),
        },
        // FDA rules emitted by the `validate` NTIA/FDA fast-path
        // (`cli::validate`), which builds violations directly without
        // populating `standard_refs`.
        // The creator gate emits a creator-less FDA SBOM as an Error.
        "SBOM-FDA-CREATOR" => RuleMeta {
            sarif_id: "SBOM-FDA-CREATOR",
            name: "FdaCreator",
            short_description: "FDA Medical Device: SBOM creator/manufacturer information",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: "Identify who created the SBOM, the device manufacturer or the tool that generated it (FDA premarket guidance).",
            advice: Some(&ADVICE_CREATORS),
        },
        "SBOM-FDA-NAMESPACE" => RuleMeta {
            sarif_id: "SBOM-FDA-NAMESPACE",
            name: "FdaNamespace",
            short_description: "FDA Medical Device: SBOM serial number or document namespace",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: "Give the SBOM a unique document identifier (FDA premarket guidance).",
            advice: Some(&ADVICE_SERIAL),
        },
        "SBOM-FDA-DEPENDENCY" => RuleMeta {
            sarif_id: "SBOM-FDA-DEPENDENCY",
            name: "FdaDependency",
            short_description: "FDA Medical Device: Dependency relationships",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: "Declare each component's dependency relationships (FDA premarket guidance): connect the primary component to its direct dependencies, and leave no component outside the dependency graph.",
            advice: Some(&ADVICE_DEPENDENCIES),
        },
        "SBOM-FDA-SECURITY" => RuleMeta {
            sarif_id: "SBOM-FDA-SECURITY",
            name: "FdaSecurity",
            short_description: "FDA Medical Device: Security vulnerability information",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: "Address every critical and high-severity vulnerability the SBOM lists before the premarket submission: upgrade the affected components, and document your assessment of any that remain. The finding counts these vulnerabilities whatever their VEX state.",
            advice: None,
        },
        "SBOM-FDA-INVENTORY" => RuleMeta {
            sarif_id: "SBOM-FDA-INVENTORY",
            name: "FdaInventory",
            short_description: "FDA Medical Device: SBOM inventories the device's software components",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: REMEDIATION_INVENTORY,
            advice: Some(&ADVICE_INVENTORY),
        },
        "SBOM-FDA-GENERAL" => RuleMeta {
            sarif_id: "SBOM-FDA-GENERAL",
            name: "FdaGeneralRequirement",
            short_description: "FDA Medical Device: General SBOM requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: "Fix the element the finding names: give every component a name (an NTIA baseline element the FDA guidance incorporates), use a spec version sbom-tools reads (CycloneDX 1.4–1.7, SPDX 2.x or 3.0), and give every element a well-formed identifier.",
            advice: Some(&ADVICE_FDA_GENERAL),
        },
        // The generic path's checks under FDA that have no FDA rule of their
        // own, one id each; they reported as SBOM-FDA-GENERAL until v0.4.0.
        "SBOM-FDA-COMPONENT-NAME" => RuleMeta {
            sarif_id: "SBOM-FDA-COMPONENT-NAME",
            name: "FdaComponentName",
            short_description: "FDA Medical Device: Every component has a name (NTIA baseline element)",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: "Give every component a name (an NTIA baseline element the FDA guidance incorporates); empty names and placeholders such as NOASSERTION do not count.",
            advice: Some(&ADVICE_NAME),
        },
        "SBOM-FDA-SPEC-VERSION" => RuleMeta {
            sarif_id: "SBOM-FDA-SPEC-VERSION",
            name: "FdaSpecVersion",
            short_description: "FDA Medical Device: Spec version sbom-tools reads (CycloneDX 1.4–1.7, SPDX 2.x or 3.0)",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: REMEDIATION_SPEC_VERSION,
            advice: Some(&ADVICE_SPEC_VERSION),
        },
        "SBOM-FDA-SPEC-VERSION-UNKNOWN" => RuleMeta {
            sarif_id: "SBOM-FDA-SPEC-VERSION-UNKNOWN",
            name: "FdaSpecVersionUnknown",
            short_description: "FDA Medical Device: SPDX document declares a valid SPDX version",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: REMEDIATION_SPEC_VERSION_UNKNOWN,
            advice: Some(&ADVICE_SPEC_VERSION),
        },
        "SBOM-FDA-ELEMENT-ID" => RuleMeta {
            sarif_id: "SBOM-FDA-ELEMENT-ID",
            name: "FdaElementIdentifier",
            short_description: "FDA Medical Device: Every element has its own well-formed identifier",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::FdaPremarket, "FDA Premarket")],
            remediation: REMEDIATION_ELEMENT_ID,
            advice: Some(&ADVICE_ELEMENT_ID),
        },
        // NTIA rules emitted by the `validate` fast-path.
        "SBOM-NTIA-AUTHOR" => RuleMeta {
            sarif_id: "SBOM-NTIA-AUTHOR",
            name: "NtiaAuthor",
            short_description: "NTIA Minimum Elements: Author/creator information",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NtiaMinimum, "NTIA Minimum Elements")],
            remediation: "Identify who created the SBOM (the NTIA Author data field): a person, organization or tool.",
            advice: Some(&ADVICE_CREATORS),
        },
        "SBOM-NTIA-NAME" => RuleMeta {
            sarif_id: "SBOM-NTIA-NAME",
            name: "NtiaComponentName",
            short_description: "NTIA Minimum Elements: Component name",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NtiaMinimum, "NTIA Minimum Elements")],
            remediation: "Give every component a name (an NTIA minimum data field); empty names and NOASSERTION do not count.",
            advice: Some(&ADVICE_NAME),
        },
        "SBOM-NTIA-IDENTIFIER" => RuleMeta {
            sarif_id: "SBOM-NTIA-IDENTIFIER",
            name: "NtiaUniqueIdentifier",
            short_description: "NTIA Minimum Elements: Unique identifier (PURL/CPE/SWID)",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NtiaMinimum, "NTIA Minimum Elements")],
            remediation: "Give every component another unique identifier (an NTIA minimum data field): a PURL, CPE, SWHID or SWID.",
            advice: Some(&ADVICE_IDENTIFIER),
        },
        "SBOM-NTIA-INVENTORY" => RuleMeta {
            sarif_id: "SBOM-NTIA-INVENTORY",
            name: "NtiaInventory",
            short_description: "NTIA Minimum Elements: SBOM inventories at least one software component",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NtiaMinimum, "NTIA Minimum Elements")],
            remediation: REMEDIATION_INVENTORY,
            advice: Some(&ADVICE_INVENTORY),
        },
        "SBOM-NTIA-GENERAL" => RuleMeta {
            sarif_id: "SBOM-NTIA-GENERAL",
            name: "NtiaGeneralRequirement",
            short_description: "NTIA Minimum Elements: General requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NtiaMinimum, "NTIA Minimum Elements")],
            remediation: "Fix the format-level issue the finding names: use a spec version sbom-tools reads (CycloneDX 1.4–1.7, SPDX 2.x or 3.0) and give every element a well-formed identifier.",
            advice: Some(&ADVICE_FORMAT_GENERAL),
        },
        // The generic path's format-level checks under NTIA, one id each;
        // they reported as SBOM-NTIA-GENERAL until v0.4.0.
        "SBOM-NTIA-SPEC-VERSION" => RuleMeta {
            sarif_id: "SBOM-NTIA-SPEC-VERSION",
            name: "NtiaSpecVersion",
            short_description: "NTIA Minimum Elements: Spec version sbom-tools reads (CycloneDX 1.4–1.7, SPDX 2.x or 3.0)",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NtiaMinimum, "NTIA Minimum Elements")],
            remediation: REMEDIATION_SPEC_VERSION,
            advice: Some(&ADVICE_SPEC_VERSION),
        },
        "SBOM-NTIA-SPEC-VERSION-UNKNOWN" => RuleMeta {
            sarif_id: "SBOM-NTIA-SPEC-VERSION-UNKNOWN",
            name: "NtiaSpecVersionUnknown",
            short_description: "NTIA Minimum Elements: SPDX document declares a valid SPDX version",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NtiaMinimum, "NTIA Minimum Elements")],
            remediation: REMEDIATION_SPEC_VERSION_UNKNOWN,
            advice: Some(&ADVICE_SPEC_VERSION),
        },
        "SBOM-NTIA-ELEMENT-ID" => RuleMeta {
            sarif_id: "SBOM-NTIA-ELEMENT-ID",
            name: "NtiaElementIdentifier",
            short_description: "NTIA Minimum Elements: Every element has its own well-formed identifier",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::NtiaMinimum, "NTIA Minimum Elements")],
            remediation: REMEDIATION_ELEMENT_ID,
            advice: Some(&ADVICE_ELEMENT_ID),
        },
        // Catch-all rule keys for the SSDF / EO 14028 profiles; not currently
        // emitted by any check site but kept so the registry mirrors the full
        // SARIF rule catalogue.
        "SBOM-SSDF-GENERAL" => RuleMeta {
            sarif_id: "SBOM-SSDF-GENERAL",
            name: "SsdfGeneralRequirement",
            short_description: "NIST SSDF: General secure development requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NistSsdf, "SP 800-218")],
            remediation: REMEDIATION_SSDF,
            advice: None,
        },
        "SBOM-EO14028-GENERAL" => RuleMeta {
            sarif_id: "SBOM-EO14028-GENERAL",
            name: "Eo14028GeneralRequirement",
            short_description: "EO 14028: General SBOM requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
            advice: None,
        },
        // ---- NIST SSDF ---------------------------------------------------
        "SBOM-SSDF-PS1" => RuleMeta {
            sarif_id: "SBOM-SSDF-PS1",
            name: "SsdfProvenance",
            short_description: "NIST SSDF PS.1: Provenance — SBOM creator identified",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NistSsdf, "PS.1")],
            remediation: REMEDIATION_SSDF,
            advice: Some(&ADVICE_CREATORS),
        },
        // The PS.1 generation-tool check, a second document-level finding
        // beside the creator check above.
        "SBOM-SSDF-PS1-TOOL" => RuleMeta {
            sarif_id: "SBOM-SSDF-PS1-TOOL",
            name: "SsdfGenerationTool",
            short_description: "NIST SSDF PS.1: Tool that generated the SBOM identified",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NistSsdf, "PS.1")],
            remediation: "Identify the tool that generated the SBOM, so its provenance shows how it was produced (NIST SSDF PS.1).",
            advice: Some(&ADVICE_TOOL),
        },
        "SBOM-SSDF-PS2" => RuleMeta {
            sarif_id: "SBOM-SSDF-PS2",
            name: "SsdfBuildIntegrity",
            short_description: "NIST SSDF PS.2: Build integrity — component cryptographic hashes",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NistSsdf, "PS.2")],
            remediation: REMEDIATION_SSDF,
            advice: Some(&ADVICE_HASH),
        },
        "SBOM-SSDF-INVENTORY" => RuleMeta {
            sarif_id: "SBOM-SSDF-INVENTORY",
            name: "SsdfInventory",
            short_description: "NIST SSDF PS.3.2: provenance data (SBOM) lists the release's components",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NistSsdf, "PS.3.2")],
            remediation: REMEDIATION_INVENTORY,
            advice: Some(&ADVICE_INVENTORY),
        },
        "SBOM-SSDF-PS3" => RuleMeta {
            sarif_id: "SBOM-SSDF-PS3",
            name: "SsdfSupplierIdentification",
            short_description: "NIST SSDF PS.3: Supplier identification for components",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NistSsdf, "PS.3")],
            remediation: REMEDIATION_SSDF,
            advice: Some(&ADVICE_PRODUCER),
        },
        "SBOM-SSDF-PO1" => RuleMeta {
            sarif_id: "SBOM-SSDF-PO1",
            name: "SsdfSourceProvenance",
            short_description: "NIST SSDF PO.1: Source code provenance — VCS references",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NistSsdf, "PO.1")],
            remediation: REMEDIATION_SSDF,
            advice: Some(&ADVICE_VCS),
        },
        "SBOM-SSDF-PO3" => RuleMeta {
            sarif_id: "SBOM-SSDF-PO3",
            name: "SsdfBuildMetadata",
            short_description: "NIST SSDF PO.3: Build provenance — build system metadata",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::NistSsdf, "PO.3")],
            remediation: REMEDIATION_SSDF,
            advice: Some(&ADVICE_BUILD),
        },
        "SBOM-SSDF-PW4" => RuleMeta {
            sarif_id: "SBOM-SSDF-PW4",
            name: "SsdfDependencyManagement",
            short_description: "NIST SSDF PW.4: Dependency management — relationships",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NistSsdf, "PW.4")],
            remediation: REMEDIATION_SSDF,
            advice: Some(&ADVICE_DEPENDENCIES),
        },
        "SBOM-SSDF-PW6" => RuleMeta {
            sarif_id: "SBOM-SSDF-PW6",
            name: "SsdfVulnerabilityInfo",
            short_description: "NIST SSDF PW.6: Vulnerability information and security references",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::NistSsdf, "PW.6")],
            remediation: REMEDIATION_SSDF,
            advice: Some(&ADVICE_SECURITY_CONTACT),
        },
        "SBOM-SSDF-RV1" => RuleMeta {
            sarif_id: "SBOM-SSDF-RV1",
            name: "SsdfComponentIdentification",
            short_description: "NIST SSDF RV.1: Component identification — unique identifiers",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NistSsdf, "RV.1")],
            remediation: REMEDIATION_SSDF,
            advice: Some(&ADVICE_IDENTIFIER),
        },
        // ---- EO 14028 ----------------------------------------------------
        "SBOM-EO14028-FORMAT" => RuleMeta {
            sarif_id: "SBOM-EO14028-FORMAT",
            name: "Eo14028MachineReadable",
            short_description: "EO 14028 Sec 4(e): Machine-readable SBOM format requirement",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
            advice: None,
        },
        "SBOM-EO14028-AUTOGEN" => RuleMeta {
            sarif_id: "SBOM-EO14028-AUTOGEN",
            name: "Eo14028AutoGeneration",
            short_description: "EO 14028 Sec 4(e): Automated SBOM generation",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
            advice: Some(&ADVICE_TOOL),
        },
        "SBOM-EO14028-CREATOR" => RuleMeta {
            sarif_id: "SBOM-EO14028-CREATOR",
            name: "Eo14028Creator",
            short_description: "EO 14028 Sec 4(e): SBOM creator identification",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
            advice: Some(&ADVICE_CREATORS),
        },
        "SBOM-EO14028-IDENTIFIER" => RuleMeta {
            sarif_id: "SBOM-EO14028-IDENTIFIER",
            name: "Eo14028Identifier",
            short_description: "EO 14028 Sec 4(e): Component unique identification",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
            advice: Some(&ADVICE_IDENTIFIER),
        },
        "SBOM-EO14028-DEPENDENCY" => RuleMeta {
            sarif_id: "SBOM-EO14028-DEPENDENCY",
            name: "Eo14028Dependency",
            short_description: "EO 14028 Sec 4(e): Dependency relationship information",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
            advice: Some(&ADVICE_DEPENDENCIES),
        },
        "SBOM-EO14028-INVENTORY" => RuleMeta {
            sarif_id: "SBOM-EO14028-INVENTORY",
            name: "Eo14028Inventory",
            short_description: "EO 14028 Sec 4(e): SBOM lists the software's components",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_INVENTORY,
            advice: Some(&ADVICE_INVENTORY),
        },
        "SBOM-EO14028-VERSION" => RuleMeta {
            sarif_id: "SBOM-EO14028-VERSION",
            name: "Eo14028Version",
            short_description: "EO 14028 Sec 4(e): Component version information",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
            advice: Some(&ADVICE_VERSION),
        },
        "SBOM-EO14028-INTEGRITY" => RuleMeta {
            sarif_id: "SBOM-EO14028-INTEGRITY",
            name: "Eo14028Integrity",
            short_description: "EO 14028 Sec 4(e): Component integrity verification (hashes)",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
            advice: Some(&ADVICE_HASH),
        },
        "SBOM-EO14028-DISCLOSURE" => RuleMeta {
            sarif_id: "SBOM-EO14028-DISCLOSURE",
            name: "Eo14028Disclosure",
            short_description: "EO 14028 Sec 4(g): Vulnerability disclosure process",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
            advice: Some(&ADVICE_SECURITY_CONTACT),
        },
        "SBOM-EO14028-SUPPLIER" => RuleMeta {
            sarif_id: "SBOM-EO14028-SUPPLIER",
            name: "Eo14028Supplier",
            short_description: "EO 14028 Sec 4(e): Supplier identification",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eo14028, "EO 14028 §4")],
            remediation: REMEDIATION_EO14028,
            advice: Some(&ADVICE_PRODUCER),
        },
        "SBOM-EO14028-TIMESTAMP" => RuleMeta {
            sarif_id: "SBOM-EO14028-TIMESTAMP",
            name: "Eo14028Timestamp",
            short_description: "EO 14028 Sec 4(e): SBOM creation timestamp (NTIA baseline)",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Eo14028, "EO 14028 §4"), (K::NtiaMinimum, "Timestamp")],
            remediation: REMEDIATION_EO14028,
            advice: Some(&ADVICE_TIMESTAMP),
        },
        "SBOM-EO14028-NAME" => RuleMeta {
            sarif_id: "SBOM-EO14028-NAME",
            name: "Eo14028ComponentName",
            short_description: "EO 14028 Sec 4(e): Component name (NTIA baseline)",
            default_severity: ViolationSeverity::Error,
            refs: &[
                (K::Eo14028, "EO 14028 §4"),
                (K::NtiaMinimum, "Component Name"),
            ],
            remediation: REMEDIATION_EO14028,
            advice: Some(&ADVICE_NAME),
        },
        // ---- BSI TR-03183-2 (v2.1.0, 2025-08-20) --------------------------
        "SBOM-BSI-TR-03183-2-4" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-4",
            name: "BsiTr03183FormatEligibility",
            short_description: "BSI TR-03183-2 v2.1.0 §4: Newly generated/updated SBOMs must be CycloneDX 1.6+ or SPDX 3.0.1+",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiTr03183_2, "§4"), (K::BsiTr03183_2, "§7")],
            remediation: "Regenerate the SBOM as CycloneDX 1.6+ or SPDX 3.0.1+ in JSON or XML. TR-03183-2 v2.1.0 §4 lists the eligible specifications for newly generated or updated SBOMs; the §7 transitional grace for the v2.0.0 minimums (CycloneDX 1.5 / SPDX 2.2.1) ended 2026-02-20.",
            advice: None,
        },
        "SBOM-BSI-TR-03183-2-5-1" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-5-1",
            name: "BsiTr03183SbomCreator",
            short_description: "BSI TR-03183-2 §5.2.1: Creator of the SBOM (email, or URL if no email)",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiTr03183_2, "§5.2.1")],
            remediation: "Identify the SBOM creator with an email address, or a URL (e.g. the creator's home page) if no email is available; generation tools do not count as the creator.",
            advice: Some(&ADVICE_PERSON_ORG_CREATOR),
        },
        "SBOM-BSI-TR-03183-2-5-1-CONTACT" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-5-1-CONTACT",
            name: "BsiTr03183SbomCreatorContact",
            short_description: "BSI TR-03183-2 §5.2.1: SBOM creator must carry an email address or URL",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiTr03183_2, "§5.2.1")],
            remediation: "Add an email address to the SBOM creator entry, or a URL (creator home page / project web page) when no email exists — a bare name does not satisfy §5.2.1.",
            advice: Some(&ADVICE_CREATOR_CONTACT),
        },
        "SBOM-BSI-TR-03183-2-5-2" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-5-2",
            name: "BsiTr03183Timestamp",
            short_description: "BSI TR-03183-2 §5.2.1: Timestamp of the SBOM data compilation",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiTr03183_2, "§5.2.1")],
            remediation: "Add the date and time of the SBOM data compilation (UTC 'Zulu' timestamps recommended).",
            advice: Some(&ADVICE_TIMESTAMP),
        },
        "SBOM-BSI-TR-03183-2-5-3" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-5-3",
            name: "BsiTr03183ComponentName",
            short_description: "BSI TR-03183-2 §5.2.2: Component name (fallback: actual filename)",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiTr03183_2, "§5.2.2")],
            remediation: "Name every component. When the component creator assigned no name, the actual filename MUST be used instead.",
            advice: Some(&ADVICE_NAME),
        },
        "SBOM-BSI-TR-03183-2-INVENTORY" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-INVENTORY",
            name: "BsiTr03183Inventory",
            short_description: "BSI TR-03183-2 §5.2.2: SBOM lists at least one component",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiTr03183_2, "§5.2.2")],
            remediation: REMEDIATION_INVENTORY,
            advice: Some(&ADVICE_INVENTORY),
        },
        "SBOM-BSI-TR-03183-2-VERSION" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-VERSION",
            name: "BsiTr03183ComponentVersion",
            short_description: "BSI TR-03183-2 §5.2.2: Component version (fallback: RFC 3339 modification date)",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiTr03183_2, "§5.2.2")],
            remediation: "Version every component (SemVer/CalVer recommended). When no version is assigned, the modification date of the file as RFC 3339 date-time MUST be used instead.",
            advice: Some(&ADVICE_VERSION),
        },
        "SBOM-BSI-TR-03183-2-LICENSE" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-LICENSE",
            name: "BsiTr03183DistributionLicence",
            short_description: "BSI TR-03183-2 §5.2.2: Distribution licence(s) per component",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiTr03183_2, "§5.2.2"), (K::BsiTr03183_2, "§6.1")],
            remediation: "Declare the distribution licence(s) of every component, named by SPDX licence identifier or expression (§6.1).",
            advice: Some(&ADVICE_LICENSE),
        },
        "SBOM-BSI-TR-03183-2-LICENSE-SPDX" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-LICENSE-SPDX",
            name: "BsiTr03183SpdxLicenceNaming",
            short_description: "BSI TR-03183-2 §6.1: Licences must be named by SPDX identifier/expression",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiTr03183_2, "§6.1")],
            remediation: "Name licences by SPDX identifier or expression; consult Scancode LicenseDB (LicenseRef-scancode-*) or use LicenseRef-<entity>-* for unlisted licences. Licence text MUST NOT be used as a substitute for an identifier.",
            advice: None,
        },
        "SBOM-BSI-TR-03183-2-CREATOR" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-CREATOR",
            name: "BsiTr03183ComponentCreator",
            short_description: "BSI TR-03183-2 §5.2.2: Component creator (email, or URL if no email)",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiTr03183_2, "§5.2.2")],
            remediation: "Record the component creator: the email address (or URL if no email) of the entity that created or maintains the component.",
            advice: Some(&ADVICE_PRODUCER),
        },
        "SBOM-BSI-TR-03183-2-5-4" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-5-4",
            name: "BsiTr03183ComponentHash",
            short_description: "BSI TR-03183-2 §5.2.2: Hash of the deployable component as SHA-512",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiTr03183_2, "§5.2.2")],
            remediation: "Provide the hash of the deployed/deployable component as SHA-512 — §5.2.2 names the algorithm, so SHA-256 or other algorithms alone do not satisfy the required field (additional hashes may coexist).",
            advice: Some(&ADVICE_HASH_SHA512),
        },
        "SBOM-BSI-TR-03183-2-5-4-MISSING" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-5-4-MISSING",
            name: "BsiTr03183ComponentHashMissing",
            short_description: "BSI TR-03183-2 §5.2.2/§3.2.1: Component has no hash of the deployable form",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiTr03183_2, "§5.2.2"), (K::BsiTr03183_2, "§3.2.1")],
            remediation: "Add a SHA-512 hash of the deployable component. §3.2.1 permits omission only when the information cannot exist due to the way the component is assembled (e.g. logical components).",
            advice: Some(&ADVICE_HASH_SHA512),
        },
        "SBOM-BSI-TR-03183-2-5-5" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-5-5",
            name: "BsiTr03183Dependencies",
            short_description: "BSI TR-03183-2 §5.2.2: Dependencies on other components",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiTr03183_2, "§5.2.2")],
            remediation: "Enumerate all direct dependencies of each component.",
            advice: Some(&ADVICE_DEPENDENCIES),
        },
        "SBOM-BSI-TR-03183-2-5-5-COMPLETENESS" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-5-5-COMPLETENESS",
            name: "BsiTr03183DependencyCompleteness",
            short_description: "BSI TR-03183-2 §5.2.2: Completeness of the dependency enumeration must be clearly indicated",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiTr03183_2, "§5.2.2")],
            remediation: "Clearly indicate the completeness of the dependency enumeration (complete or incomplete).",
            advice: Some(&ADVICE_COMPLETENESS),
        },
        "SBOM-BSI-TR-03183-2-5-2-4" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-5-2-4",
            name: "BsiTr03183UniqueIdentifier",
            short_description: "BSI TR-03183-2 §5.2.4: Other unique identifiers (purl/CPE) — additional tier",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiTr03183_2, "§5.2.4")],
            remediation: "Add unique identifiers (purl, CPE) to components. §5.2.4 is the additional tier: the field MUST be provided when an identifier exists for the component.",
            advice: Some(&ADVICE_IDENTIFIER),
        },
        "SBOM-BSI-TR-03183-2-3-1" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-3-1",
            name: "BsiTr03183NoVulnerabilityInfo",
            short_description: "BSI TR-03183-2 §3.1: An SBOM must not contain vulnerability information",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiTr03183_2, "§3.1")],
            remediation: "Remove vulnerability information from the SBOM and publish it separately (e.g. as CSAF advisories); a document containing both SBOM and vulnerability information does not conform to TR-03183-2.",
            advice: Some(&ADVICE_REMOVE_VULNS),
        },
        // Catch-all descriptor for the BSI TR-03183-2 profile; not emitted by
        // any check site, kept so the registry-generated SARIF catalogue
        // mirrors the historical hand-maintained rule table.
        "SBOM-BSI-TR-03183-2-GENERAL" => RuleMeta {
            sarif_id: "SBOM-BSI-TR-03183-2-GENERAL",
            name: "BsiTr03183General",
            short_description: "BSI TR-03183-2 general SBOM requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiTr03183_2, "TR-03183-2")],
            remediation: "Catch-all for BSI TR-03183-2 findings that have no dedicated rule (no check emits it; the SARIF writer files unmapped findings here). Set the field the finding's requirement names: the SBOM creator with an email or URL, the timestamp, and per component the name, version, distribution licence as an SPDX identifier, creator, SHA-512 hash, dependencies and their completeness, and a unique identifier.",
            advice: None,
        },
        // ---- CNSA 2.0 ----------------------------------------------------
        "SBOM-CNSA2-000" => RuleMeta {
            sarif_id: "SBOM-CNSA2-000",
            name: "Cnsa2CryptoInventory",
            short_description: "CNSA 2.0: cryptographic inventory (CBOM) with evaluable assets required — compliance cannot be verified without one",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, "CNSA 2.0")],
            remediation: REMEDIATION_CNSA2,
            advice: None,
        },
        "SBOM-CNSA2-ALG-001" => RuleMeta {
            sarif_id: "SBOM-CNSA2-ALG-001",
            name: "Cnsa2SymmetricAlgorithm",
            short_description: "CNSA 2.0: symmetric encryption must be AES-256",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, "CNSA 2.0")],
            remediation: REMEDIATION_CNSA2,
            advice: None,
        },
        "SBOM-CNSA2-ALG-002" => RuleMeta {
            sarif_id: "SBOM-CNSA2-ALG-002",
            name: "Cnsa2HashAlgorithm",
            short_description: "CNSA 2.0: hashing must be SHA-384 or SHA-512",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, "CNSA 2.0")],
            remediation: REMEDIATION_CNSA2,
            advice: None,
        },
        "SBOM-CNSA2-ALG-003" => RuleMeta {
            sarif_id: "SBOM-CNSA2-ALG-003",
            name: "Cnsa2KeyEstablishment",
            short_description: "CNSA 2.0: key establishment must be ML-KEM-1024",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, "CNSA 2.0")],
            remediation: REMEDIATION_CNSA2,
            advice: None,
        },
        "SBOM-CNSA2-ALG-004" => RuleMeta {
            sarif_id: "SBOM-CNSA2-ALG-004",
            name: "Cnsa2SignatureAlgorithm",
            short_description: "CNSA 2.0: digital signatures must be ML-DSA-87 or SP 800-208 stateful hash-based signatures",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, "CNSA 2.0")],
            remediation: REMEDIATION_CNSA2,
            advice: None,
        },
        "SBOM-CNSA2-ALG-006" => RuleMeta {
            sarif_id: "SBOM-CNSA2-ALG-006",
            name: "Cnsa2QuantumVulnerable",
            short_description: "CNSA 2.0: quantum-vulnerable classical algorithm must migrate to the CNSA 2.0 suite",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, "CNSA 2.0")],
            remediation: REMEDIATION_CNSA2,
            advice: None,
        },
        "SBOM-CNSA2-ALG-007" => RuleMeta {
            sarif_id: "SBOM-CNSA2-ALG-007",
            name: "Cnsa2QuantumSecurityLevel",
            short_description: "CNSA 2.0: declared quantum security level below Level 5",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, "CNSA 2.0")],
            remediation: REMEDIATION_CNSA2,
            advice: None,
        },
        // Broken/legacy algorithm (SHA-1, MD5, DES, RC4, ...) under the CNSA
        // 2.0 allowlist.
        "SBOM-CNSA2-ALG-005" => RuleMeta {
            sarif_id: "SBOM-CNSA2-ALG-005",
            name: "Cnsa2BrokenAlgorithm",
            short_description: "CNSA 2.0: broken legacy algorithm (SHA-1, MD5, DES, RC4, …) in use",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, "CNSA 2.0")],
            remediation: REMEDIATION_CNSA2,
            advice: None,
        },
        // Recognized algorithm that is simply not on the CNSA 2.0 allowlist
        // (ChaCha20, Camellia, SHA-3, SLH-DSA, Falcon, ...).
        "SBOM-CNSA2-ALG-008" => RuleMeta {
            sarif_id: "SBOM-CNSA2-ALG-008",
            name: "Cnsa2UnapprovedAlgorithm",
            short_description: "CNSA 2.0: recognized algorithm that is not on the CNSA 2.0 allowlist",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, "CNSA 2.0")],
            remediation: REMEDIATION_CNSA2,
            advice: None,
        },
        // Unclassifiable algorithm asset — CNSA 2.0 compliance cannot be
        // verified (Warning, never a silent pass).
        "SBOM-CNSA2-ALG-UNKNOWN" => RuleMeta {
            sarif_id: "SBOM-CNSA2-ALG-UNKNOWN",
            name: "Cnsa2UnclassifiableAlgorithm",
            short_description: "CNSA 2.0: algorithm cannot be classified, so it cannot be shown to be on the allowlist",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, "CNSA 2.0")],
            remediation: REMEDIATION_CNSA2,
            advice: None,
        },
        "SBOM-CNSA2-CERT-001" => RuleMeta {
            sarif_id: "SBOM-CNSA2-CERT-001",
            name: "Cnsa2CertificateSignature",
            short_description: "CNSA 2.0: certificate signature algorithm must be CNSA 2.0 approved",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, "CNSA 2.0")],
            remediation: REMEDIATION_CNSA2,
            advice: None,
        },
        // Certificate signature-algorithm ref cannot be resolved/classified —
        // CNSA 2.0 compliance cannot be verified (Warning, never a silent
        // pass).
        "SBOM-CNSA2-CERT-UNKNOWN" => RuleMeta {
            sarif_id: "SBOM-CNSA2-CERT-UNKNOWN",
            name: "Cnsa2CertificateUnverifiable",
            short_description: "CNSA 2.0: certificate signature algorithm cannot be resolved, so it cannot be shown to be on the allowlist",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, "CNSA 2.0")],
            remediation: REMEDIATION_CNSA2,
            advice: None,
        },
        // Protocol version gate: CNSA 2.0 network protocols require TLS 1.3.
        "SBOM-CNSA2-PROTO-001" => RuleMeta {
            sarif_id: "SBOM-CNSA2-PROTO-001",
            name: "Cnsa2ProtocolVersion",
            short_description: "CNSA 2.0: network protocols must use TLS 1.3",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, "CNSA 2.0")],
            remediation: REMEDIATION_CNSA2,
            advice: None,
        },
        // Protocol cipher suites / IKEv2 transforms / crypto refs must use
        // CNSA 2.0 algorithms.
        "SBOM-CNSA2-PROTO-002" => RuleMeta {
            sarif_id: "SBOM-CNSA2-PROTO-002",
            name: "Cnsa2ProtocolAlgorithms",
            short_description: "CNSA 2.0: protocol cipher suites / IKEv2 transforms must use CNSA 2.0 algorithms",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, "CNSA 2.0")],
            remediation: REMEDIATION_CNSA2,
            advice: None,
        },
        // Protocol asset with unresolvable/unclassifiable crypto references,
        // or with nothing evaluable at all — CNSA 2.0 compliance cannot be
        // verified (Warning, never a silent pass).
        "SBOM-CNSA2-PROTO-UNKNOWN" => RuleMeta {
            sarif_id: "SBOM-CNSA2-PROTO-UNKNOWN",
            name: "Cnsa2ProtocolUnverifiable",
            short_description: "CNSA 2.0: protocol names no algorithm the classifier can identify, so it cannot be shown to be on the allowlist",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::Cnsa2, "CNSA 2.0")],
            remediation: REMEDIATION_CNSA2,
            advice: None,
        },
        // Generic bucket for CNSA-2.0-run findings whose check site has no
        // specific registry mapping (SARIF fallback re-bucketing).
        "SBOM-CNSA2-GENERAL" => RuleMeta {
            sarif_id: "SBOM-CNSA2-GENERAL",
            name: "Cnsa2GeneralRequirement",
            short_description: "CNSA 2.0: general algorithm-suite requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::Cnsa2, "CNSA 2.0")],
            remediation: REMEDIATION_CNSA2,
            advice: None,
        },
        // ---- NIST PQC ----------------------------------------------------
        "SBOM-PQC-000" => RuleMeta {
            sarif_id: "SBOM-PQC-000",
            name: "PqcCryptoInventory",
            short_description: "NIST PQC: cryptographic inventory (CBOM) with evaluable assets required — readiness cannot be verified without one",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NistPqc, "IR 8547 ipd")],
            remediation: REMEDIATION_PQC,
            advice: None,
        },
        "SBOM-PQC-001" => RuleMeta {
            sarif_id: "SBOM-PQC-001",
            name: "PqcQuantumVulnerable",
            short_description: "NIST IR 8547: quantum-vulnerable algorithm must migrate to a NIST PQC standard",
            default_severity: ViolationSeverity::Error,
            refs: &[
                (K::NistPqc, "IR 8547 ipd"),
                (K::NistPqc, "SP 800-131A Rev. 2"),
            ],
            remediation: REMEDIATION_PQC,
            advice: None,
        },
        "SBOM-PQC-012" => RuleMeta {
            sarif_id: "SBOM-PQC-012",
            name: "PqcQuantumAssessmentMissing",
            short_description: "NIST IR 8547: missing quantum security level assessment (nistQuantumSecurityLevel)",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NistPqc, "IR 8547 ipd")],
            remediation: REMEDIATION_PQC,
            advice: None,
        },
        // A PQ/T hybrid (hybrid key exchange or composite signature) whose
        // post-quantum part NIST approves: an approved combination (SP
        // 800-227 §4.6.2 key combiners, IR 8547 ipd §3.2.2 composite
        // signatures). Informational, as every check site emits it.
        "SBOM-PQC-010" => RuleMeta {
            sarif_id: "SBOM-PQC-010",
            name: "PqcHybridCombiner",
            short_description: "NIST PQC: PQ/T hybrid with a NIST-approved post-quantum part — approved combination (SP 800-227, IR 8547)",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::NistPqc, "SP 800-227"), (K::NistPqc, "IR 8547 ipd")],
            remediation: REMEDIATION_PQC,
            advice: None,
        },
        "SBOM-PQC-005" => RuleMeta {
            sarif_id: "SBOM-PQC-005",
            name: "PqcDisallowedAlgorithm",
            short_description: "NIST SP 800-131A: disallowed (broken) algorithm in use",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NistPqc, "SP 800-131A Rev. 2")],
            remediation: REMEDIATION_PQC,
            advice: None,
        },
        "SBOM-PQC-008" => RuleMeta {
            sarif_id: "SBOM-PQC-008",
            name: "PqcEcbModeDisallowed",
            short_description: "NIST SP 800-131A: ECB mode of operation disallowed",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NistPqc, "SP 800-131A Rev. 2")],
            remediation: REMEDIATION_PQC,
            advice: None,
        },
        "SBOM-PQC-009" => RuleMeta {
            sarif_id: "SBOM-PQC-009",
            name: "PqcApprovedAlgorithm",
            short_description: "NIST PQC: NIST-approved post-quantum algorithm in use (FIPS 203/204/205, SP 800-208)",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::NistPqc, "FIPS 203/204/205"), (K::NistPqc, "SP 800-208")],
            remediation: REMEDIATION_PQC,
            advice: None,
        },
        "SBOM-PQC-KEY-001" => RuleMeta {
            sarif_id: "SBOM-PQC-KEY-001",
            name: "PqcMinimumKeySize",
            short_description: "NIST SP 800-131A: key size below the approved minimum",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NistPqc, "SP 800-131A Rev. 2")],
            remediation: REMEDIATION_PQC,
            advice: None,
        },
        // Certificate signed with a broken or quantum-vulnerable algorithm.
        "SBOM-PQC-CERT-001" => RuleMeta {
            sarif_id: "SBOM-PQC-CERT-001",
            name: "PqcCertificateSignature",
            short_description: "NIST IR 8547: certificate signed with a broken or quantum-vulnerable algorithm",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NistPqc, "IR 8547 ipd")],
            remediation: REMEDIATION_PQC_CERT,
            advice: None,
        },
        // Certificate signature-algorithm ref cannot be resolved/classified —
        // PQC readiness cannot be verified (Warning, never a silent pass).
        "SBOM-PQC-ALG-UNKNOWN" => RuleMeta {
            sarif_id: "SBOM-PQC-ALG-UNKNOWN",
            name: "PqcUnclassifiableAlgorithm",
            short_description: "NIST PQC: algorithm cannot be classified — readiness cannot be verified",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NistPqc, "IR 8547 ipd")],
            remediation: REMEDIATION_PQC_UNKNOWN,
            advice: None,
        },
        "SBOM-PQC-CERT-UNKNOWN" => RuleMeta {
            sarif_id: "SBOM-PQC-CERT-UNKNOWN",
            name: "PqcCertificateUnverifiable",
            short_description: "NIST PQC: certificate signature algorithm cannot be resolved — readiness cannot be verified",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NistPqc, "IR 8547 ipd")],
            remediation: REMEDIATION_PQC_UNKNOWN,
            advice: None,
        },
        // Protocol version gate: SSL / TLS below 1.2 disallowed.
        "SBOM-PQC-PROTO-001" => RuleMeta {
            sarif_id: "SBOM-PQC-PROTO-001",
            name: "PqcProtocolVersion",
            short_description: "NIST SP 800-52 Rev. 2: SSL and TLS below 1.2 are disallowed",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NistPqc, "SP 800-52 Rev. 2")],
            remediation: REMEDIATION_PQC_PROTO,
            advice: None,
        },
        // Protocol cipher suites / IKEv2 transforms / crypto refs contain
        // broken or quantum-vulnerable algorithms.
        "SBOM-PQC-PROTO-002" => RuleMeta {
            sarif_id: "SBOM-PQC-PROTO-002",
            name: "PqcProtocolAlgorithms",
            short_description: "NIST PQC: protocol negotiates broken or quantum-vulnerable algorithms (SP 800-131A / IR 8547)",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::NistPqc, "SP 800-131A / IR 8547")],
            remediation: REMEDIATION_PQC_PROTO,
            advice: None,
        },
        // Protocol asset with unresolvable/unclassifiable crypto references,
        // an unparseable TLS version, or nothing evaluable at all — PQC
        // readiness cannot be verified (Warning, never a silent pass).
        "SBOM-PQC-PROTO-UNKNOWN" => RuleMeta {
            sarif_id: "SBOM-PQC-PROTO-UNKNOWN",
            name: "PqcProtocolUnverifiable",
            short_description: "NIST PQC: protocol crypto references cannot be verified — readiness cannot be verified",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NistPqc, "IR 8547 ipd")],
            remediation: REMEDIATION_PQC_UNKNOWN,
            advice: None,
        },
        // Generic bucket for NIST-PQC-run findings whose check site has no
        // specific registry mapping (SARIF fallback re-bucketing).
        "SBOM-PQC-GENERAL" => RuleMeta {
            sarif_id: "SBOM-PQC-GENERAL",
            name: "PqcGeneralRequirement",
            short_description: "NIST PQC: general post-quantum readiness requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::NistPqc, "IR 8547 ipd")],
            remediation: REMEDIATION_PQC,
            advice: None,
        },
        // ---- CISA 2026 Minimum Elements (v2.1, July 29, 2026) --------------
        // Successor to the NTIA 2021 Minimum Elements. Severity convention
        // mirrors the NTIA profile: required data fields = Error;
        // evidence-limited / practice checks = Warning (CISA assigns none).
        "SBOM-CISA2026-AUTHOR" => RuleMeta {
            sarif_id: "SBOM-CISA2026-AUTHOR",
            name: "Cisa2026SbomAuthor",
            short_description: "CISA 2026: SBOM Author — a person or organization (not tool-only) created the SBOM data",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaMinimum2026, "SBOM Author")],
            remediation: "Add a Person or Organization creator naming the entity that created the SBOM data — the entity operating the generation tool, not the tool itself, so tool-only creator lists do not satisfy the element. Use full names, no acronyms.",
            advice: Some(&ADVICE_PERSON_ORG_CREATOR),
        },
        "SBOM-CISA2026-SIGNATURE" => RuleMeta {
            sarif_id: "SBOM-CISA2026-SIGNATURE",
            name: "Cisa2026AuthorSignature",
            short_description: "CISA 2026: SBOM Author Signature — digital signature attributable to the SBOM author",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::CisaMinimum2026, "SBOM Author Signature")],
            remediation: "Sign the SBOM with a digital signature attributable to the SBOM author, using an algorithm approved per NIST DSS, ISO/IEC 14888-4:2024, or the ENISA Agreed Cryptographic Mechanisms. Detached signatures are invisible to this check, and not every format can carry one in-document — hence Warning, not Error. SPDX 2.x has no in-document signature field, so the rule is not evaluated for SPDX 2.x documents.",
            advice: Some(&ADVICE_SIGNATURE),
        },
        "SBOM-CISA2026-FORMAT" => RuleMeta {
            sarif_id: "SBOM-CISA2026-FORMAT",
            name: "Cisa2026DataFormat",
            short_description: "CISA 2026: SBOM Data Format Name/Version — machine-processable format, no deprecated format versions",
            default_severity: ViolationSeverity::Warning,
            refs: &[
                (K::CisaMinimum2026, "SBOM Data Format Name"),
                (K::CisaMinimum2026, "SBOM Data Format Version"),
                (K::CisaMinimum2026, "Machine-Processable Data"),
            ],
            remediation: "Produce the SBOM in a widely used machine-processable format — SPDX (ISO/IEC 5962:2021) or CycloneDX (ECMA-424); SWID tags were dropped from the 2026 format list — and avoid format versions declared deprecated by the format maintainers. CISA names no deprecated versions: the enforced floor (CycloneDX 1.4+ / SPDX 2.2+, mirroring the repo's EO 14028 gate) is tool policy, not CISA text. Unparseable spec versions skip the gate rather than false-failing.",
            advice: None,
        },
        "SBOM-CISA2026-GENERATION-CONTEXT" => RuleMeta {
            sarif_id: "SBOM-CISA2026-GENERATION-CONTEXT",
            name: "Cisa2026GenerationContext",
            short_description: "CISA 2026: SBOM Generation Context — software lifecycle phase at SBOM generation",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::CisaMinimum2026, "SBOM Generation Context")],
            remediation: "Declare the lifecycle phase the SBOM was generated in — 'before build', 'build', 'after build', or a more specific identifier. Warning, not Error: not every format can carry the phase. SPDX 2.x has no standard field for it, so the rule is not evaluated for SPDX 2.x documents.",
            advice: Some(&ADVICE_LIFECYCLE_PHASE),
        },
        "SBOM-CISA2026-TIMESTAMP" => RuleMeta {
            sarif_id: "SBOM-CISA2026-TIMESTAMP",
            name: "Cisa2026Timestamp",
            short_description: "CISA 2026: SBOM Timestamp — date and time of the most recent update to the SBOM data",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaMinimum2026, "SBOM Timestamp")],
            remediation: "Record the date and time of the most recent update to the SBOM data; the 2026 element targets RFC 9557 syntax (source-syntax conformance is not verified by this check — parsers normalize timestamps).",
            advice: Some(&ADVICE_TIMESTAMP),
        },
        "SBOM-CISA2026-TOOL" => RuleMeta {
            sarif_id: "SBOM-CISA2026-TOOL",
            name: "Cisa2026ToolName",
            short_description: "CISA 2026: SBOM Tool Name — tool used to generate or amend the SBOM",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaMinimum2026, "SBOM Tool Name")],
            remediation: "Identify the tool used by the SBOM author to generate or amend the SBOM (full name, no acronyms unless official).",
            advice: Some(&ADVICE_TOOL),
        },
        "SBOM-CISA2026-TOOL-VERSION" => RuleMeta {
            sarif_id: "SBOM-CISA2026-TOOL-VERSION",
            name: "Cisa2026ToolVersion",
            short_description: "CISA 2026: SBOM Tool Version — version of the SBOM generation tool (or explicit unknown)",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::CisaMinimum2026, "SBOM Tool Version")],
            remediation: "Declare the version of the tool named in SBOM Tool Name, or explicitly indicate it is unknown. Parsers concatenate tool name and version into one creator name, so the check is heuristic (a trailing version-like token or explicit unknown marker satisfies it) until the model grows a dedicated tool-version field.",
            advice: Some(&ADVICE_TOOL),
        },
        "SBOM-CISA2026-SBOM-VERSION" => RuleMeta {
            sarif_id: "SBOM-CISA2026-SBOM-VERSION",
            name: "Cisa2026SbomVersion",
            short_description: "CISA 2026: SBOM Version — the document declares its own version",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::CisaMinimum2026, "SBOM Version")],
            remediation: "Declare the SBOM document's own version, or a version-distinguishing serial identifier (RFC 9562-style UUIDs). An omitted version is treated as undeclared, not backfilled with a format default; Warning because SPDX 2.x has no dedicated document-version field.",
            advice: Some(&ADVICE_DOC_VERSION),
        },
        "SBOM-CISA2026-PRODUCER" => RuleMeta {
            sarif_id: "SBOM-CISA2026-PRODUCER",
            name: "Cisa2026ComponentProducer",
            short_description: "CISA 2026: Component Producer — entity that creates, defines, and identifies the component",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaMinimum2026, "Component Producer")],
            remediation: "Identify each component's producer (the 2026 rename of the ambiguous Supplier Name): the entity that created the component is preferred, its supplier or manufacturer is accepted; if no clear producer exists, explicitly mark the component as of unknown provenance. File-type entries are exempt.",
            advice: Some(&ADVICE_PRODUCER),
        },
        "SBOM-CISA2026-INVENTORY" => RuleMeta {
            sarif_id: "SBOM-CISA2026-INVENTORY",
            name: "Cisa2026Inventory",
            short_description: "CISA 2026: SBOM enumerates at least one software component",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaMinimum2026, "Coverage")],
            remediation: REMEDIATION_INVENTORY,
            advice: Some(&ADVICE_INVENTORY),
        },
        "SBOM-CISA2026-NAME" => RuleMeta {
            sarif_id: "SBOM-CISA2026-NAME",
            name: "Cisa2026ComponentName",
            short_description: "CISA 2026: Component Name — name assigned by the component producer",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaMinimum2026, "Component Name")],
            remediation: "Give every enumerated component the name assigned by its producer (full names, no acronyms); alternate names belong in alias/identifier fields, which the 2026 element allows as multiple entries.",
            advice: Some(&ADVICE_NAME),
        },
        "SBOM-CISA2026-VERSION" => RuleMeta {
            sarif_id: "SBOM-CISA2026-VERSION",
            name: "Cisa2026ComponentVersion",
            short_description: "CISA 2026: Component Version — version present or explicitly marked unknown",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaMinimum2026, "Component Version")],
            remediation: "Declare each component's version; when the producer provides none, explicitly indicate the version is unknown (NOASSERTION/'unknown') per the 2026 escape hatch. An explicit unknown passes this rule — silent absence fails.",
            advice: Some(&ADVICE_VERSION),
        },
        "SBOM-CISA2026-IDENTIFIER" => RuleMeta {
            sarif_id: "SBOM-CISA2026-IDENTIFIER",
            name: "Cisa2026ComponentIdentifiers",
            short_description: "CISA 2026: Component Identifiers — at least one machine-processable identifier (PURL/CPE/SWHID/SWID)",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaMinimum2026, "Component Identifiers")],
            remediation: "Add at least one common machine-processable identifier per component — the document names CPE and PURL (ECMA-427); UUIDs, organization-specific identifiers, commit hashes, and intrinsic identifiers (OmniBOR, SWHID / ISO/IEC 18670:2025) also qualify. Include all known identifiers.",
            advice: Some(&ADVICE_IDENTIFIER),
        },
        "SBOM-CISA2026-HASH" => RuleMeta {
            sarif_id: "SBOM-CISA2026-HASH",
            name: "Cisa2026ComponentHash",
            short_description: "CISA 2026: Component Hash Value — cryptographic hash of the executable component artifact",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaMinimum2026, "Component Hash Value")],
            remediation: "Provide an ASCII-hexadecimal cryptographic hash of each executable component artifact; when the SBOM author lacks access to the artifact, explicitly indicate the value is unknown.",
            advice: Some(&ADVICE_HASH),
        },
        "SBOM-CISA2026-HASH-ALGO" => RuleMeta {
            sarif_id: "SBOM-CISA2026-HASH-ALGO",
            name: "Cisa2026HashAlgorithm",
            short_description: "CISA 2026: Component Hash Algorithm — recognized, authority-approved hash algorithm",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::CisaMinimum2026, "Component Hash Algorithm")],
            remediation: "Identify hash algorithms using IANA Hash Function Textual Names, and use algorithms approved by a relevant authority such as NIST: MD5 is not NIST-approved; SHA-1 is deprecated and slated for withdrawal by 2030 — use SHA-256 or stronger. A component that carries one such hash passes even when it also lists MD5 or SHA-1 digests.",
            advice: Some(&ADVICE_HASH),
        },
        "SBOM-CISA2026-LICENSE" => RuleMeta {
            sarif_id: "SBOM-CISA2026-LICENSE",
            name: "Cisa2026ComponentLicense",
            short_description: "CISA 2026: Component License — license identifier, license pointer, or explicit unknown",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaMinimum2026, "Component License")],
            remediation: "Declare each component's license(s), preferring machine-processable SPDX license identifiers; a LicenseRef-* expression or a pointer to where the full license details are available also satisfies the element, and an explicit unknown (NOASSERTION) is required when the author is unaware. Silent absence fails.",
            advice: Some(&ADVICE_LICENSE),
        },
        "SBOM-CISA2026-DEPENDENCY" => RuleMeta {
            sarif_id: "SBOM-CISA2026-DEPENDENCY",
            name: "Cisa2026DependencyRelationship",
            short_description: "CISA 2026: Component Dependency Relationship — dependency graph or external SBOM links",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaMinimum2026, "Component Dependency Relationship")],
            remediation: "Declare the relationships where one component is necessary for the operation of the other. Links to separate SBOM documents per dependency are acceptable alternative evidence.",
            advice: Some(&ADVICE_DEPENDENCIES),
        },
        "SBOM-CISA2026-COVERAGE" => RuleMeta {
            sarif_id: "SBOM-CISA2026-COVERAGE",
            name: "Cisa2026Coverage",
            short_description: "CISA 2026: Coverage / Explicitly Identifying Unknown Information — completeness declaration present",
            default_severity: ViolationSeverity::Warning,
            refs: &[
                (K::CisaMinimum2026, "Coverage"),
                (
                    K::CisaMinimum2026,
                    "Explicitly Identifying Unknown Information",
                ),
            ],
            remediation: "Declare the SBOM's completeness: the 2026 Coverage element expects all components including transitive dependencies, and information gaps must be explicitly stated as unknown or deliberately withheld. This rule verifies the declaration, not actual completeness — the document itself points to external repositories / binary analysis for that. SPDX 2.x has no completeness declaration, so the rule is not evaluated for SPDX 2.x documents.",
            advice: Some(&ADVICE_COMPLETENESS),
        },
        // Generic bucket for CISA-2026-run findings whose check site has no
        // specific registry mapping (SARIF fallback re-bucketing).
        "SBOM-CISA2026-GENERAL" => RuleMeta {
            sarif_id: "SBOM-CISA2026-GENERAL",
            name: "Cisa2026GeneralRequirement",
            short_description: "CISA 2026 Minimum Elements: general requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::CisaMinimum2026, "Minimum Elements")],
            remediation: "Catch-all for CISA 2026 Minimum Elements findings that have no dedicated rule (no check emits it; the SARIF writer files unmapped findings here). Set the element the finding's requirement names: the SBOM author, signature, format, generation context, timestamp, tool name and version, SBOM version, and per component the producer, name, version, identifiers, hash, license and dependencies.",
            advice: None,
        },
        "SBOM-PCI-6-3-2-INVENTORY" => RuleMeta {
            sarif_id: "SBOM-PCI-6-3-2-INVENTORY",
            name: "PciDssInventory",
            short_description: "PCI DSS Req. 6.3.2: SBOM is a non-empty inventory with a resolvable primary component",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::PciDss4, "Req. 6.3.2"), (K::PciDss4, "TP 6.3.2.b")],
            remediation: "The SBOM must inventory at least one component and identify the bespoke/custom application it describes as its primary component. An empty or headless document cannot serve as the Req. 6.3.2 inventory.",
            advice: Some(&ADVICE_INVENTORY),
        },
        "SBOM-PCI-6-3-2-NAME" => RuleMeta {
            sarif_id: "SBOM-PCI-6-3-2-NAME",
            name: "PciDssComponentName",
            short_description: "PCI DSS Req. 6.3.2: every inventoried (non-file) component has a name",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::PciDss4, "Req. 6.3.2")],
            remediation: "Name every inventoried component — an unnamed entry cannot be correlated with vendor advisories or patches. File/snippet inventory records are exempt, so a file-cataloguing SBOM does not auto-fail the profile.",
            advice: Some(&ADVICE_NAME),
        },
        "SBOM-PCI-6-3-2-VERSION" => RuleMeta {
            sarif_id: "SBOM-PCI-6-3-2-VERSION",
            name: "PciDssComponentVersion",
            short_description: "PCI DSS Req. 6.3.2: every inventoried (non-file) component has a concrete version",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::PciDss4, "Req. 6.3.2")],
            remediation: "Declare a concrete release version for every inventoried component (a version range is acceptable only for external components) — patch management, the requirement's stated purpose, is impossible without versions. File/snippet inventory records are exempt.",
            advice: Some(&ADVICE_VERSION),
        },
        "SBOM-PCI-6-3-2-SUPPLIER" => RuleMeta {
            sarif_id: "SBOM-PCI-6-3-2-SUPPLIER",
            name: "PciDssComponentSupplier",
            short_description: "PCI DSS Req. 6.3.2: third-party components identify their supplier/source",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::PciDss4, "Req. 6.3.2")],
            remediation: "Identify each third-party component's supplier, or fall back to author / group / ecosystem-bearing PURL evidence, so vendor security-patch availability can be monitored.",
            advice: Some(&ADVICE_PRODUCER),
        },
        "SBOM-PCI-6-3-2-IDENTIFIER" => RuleMeta {
            sarif_id: "SBOM-PCI-6-3-2-IDENTIFIER",
            name: "PciDssComponentIdentifier",
            short_description: "PCI DSS Req. 6.3.2: components carry a stable unique identifier for vulnerability correlation",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::PciDss4, "Req. 6.3.2"), (K::PciDss4, "TP 6.3.2.a")],
            remediation: "Add a stable unique identifier (PURL preferred, else CPE/SWID) so the inventory can be machine-correlated with vulnerability sources per the 'facilitate vulnerability and patch management' clause. PCI DSS prescribes no identifier scheme — this is enabling evidence, not a mandated field.",
            advice: Some(&ADVICE_IDENTIFIER),
        },
        "SBOM-PCI-6-3-2-THIRD-PARTY" => RuleMeta {
            sarif_id: "SBOM-PCI-6-3-2-THIRD-PARTY",
            name: "PciDssThirdPartyComponents",
            short_description: "PCI DSS TP 6.3.2.b: inventory enumerates incorporated third-party components, not just the application",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::PciDss4, "Req. 6.3.2"), (K::PciDss4, "TP 6.3.2.b")],
            remediation: "Enumerate the third-party components incorporated into the bespoke/custom software, not only the application itself; a primary-only SBOM passes only when its completeness declaration is Complete (a genuinely dependency-free application). This is an inference — TP 6.3.2.b's real comparison against the software is assessor work.",
            advice: None,
        },
        "SBOM-PCI-6-3-2-COMPLETENESS" => RuleMeta {
            sarif_id: "SBOM-PCI-6-3-2-COMPLETENESS",
            name: "PciDssCompleteness",
            short_description: "PCI DSS TP 6.3.2.b: completeness declaration — self-declared inventory gaps flagged",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::PciDss4, "TP 6.3.2.b")],
            remediation: "Declare the inventory Complete. Explicit Incomplete* declarations warn as self-declared gaps against TP 6.3.2.b; Unknown (no declaration made / explicitly unknown) and NotSpecified (declared but unrecognized, or a no-assertion value) are informational.",
            advice: Some(&ADVICE_COMPLETENESS),
        },
        "SBOM-PCI-6-3-2-FRESHNESS" => RuleMeta {
            sarif_id: "SBOM-PCI-6-3-2-FRESHNESS",
            name: "PciDssFreshness",
            short_description: "PCI DSS Req. 6.3.2: 'is maintained' — the SBOM carries a creation timestamp",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::PciDss4, "Req. 6.3.2"), (K::PciDss4, "TP 6.3.2.a")],
            remediation: "Carry a creation timestamp so the inventory's maintenance can be evidenced. The SBOM proves generation time, not the inventory process — a stale timestamp is advisory only. A timestamp later than the evaluation date is reported like a missing one: correct the generator's clock or time zone.",
            advice: Some(&ADVICE_TIMESTAMP),
        },
        "SBOM-PCI-6-3-2-VULN-EVIDENCE" => RuleMeta {
            sarif_id: "SBOM-PCI-6-3-2-VULN-EVIDENCE",
            name: "PciDssVulnerabilityEvidence",
            short_description: "PCI DSS TP 6.3.2.a: vulnerability-management hooks (embedded data, advisory refs, or security contact)",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::PciDss4, "TP 6.3.2.a")],
            remediation: "Surface vulnerability-management hooks: embedded vulnerability entries, an Advisories / vulnerability-assertion / linked-VDR external reference, a security contact, or a disclosure URL. Absence is not a Req. 6.3.2 failure — the inventory may feed an external scanner; actual use of the inventory is assessor-verified.",
            advice: Some(&ADVICE_SECURITY_CONTACT),
        },
        "SBOM-PCI-11-3-1-1-SEVERITY" => RuleMeta {
            sarif_id: "SBOM-PCI-11-3-1-1-SEVERITY",
            name: "PciDssVulnerabilityRiskRanking",
            short_description: "PCI DSS Req. 6.3.1 / 11.3.1.1: embedded vulnerability entries carry a risk ranking",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::PciDss4, "Req. 11.3.1.1"), (K::PciDss4, "Req. 6.3.1")],
            remediation: "Give every embedded vulnerability entry a risk ranking — a Critical/High/Medium/Low severity or a CVSS score (an entry with only Info/None/Unknown severity and no CVSS is unranked) — so non-high-risk findings can be managed per the entity's Req. 6.3.1 rankings and the 11.3.1.1 targeted risk analysis. Emitted only when vulnerability data is present (no vacuous pass/fail).",
            advice: Some(&ADVICE_VULN_SEVERITY),
        },
        // Generic bucket for PCI-DSS-run findings whose check site has no
        // specific registry mapping (SARIF fallback re-bucketing).
        "SBOM-PCI-GENERAL" => RuleMeta {
            sarif_id: "SBOM-PCI-GENERAL",
            name: "PciDssGeneralRequirement",
            short_description: "PCI DSS v4.0.1 Req. 6.3.2: general software-inventory requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::PciDss4, "Req. 6.3.2")],
            remediation: "Catch-all for PCI DSS Req. 6.3.2 findings that have no dedicated rule (no check emits it; the SARIF writer files unmapped findings here). Make the SBOM a usable inventory: identify the bespoke application as the primary component, and give every component a name, version, supplier and unique identifier.",
            advice: None,
        },
        "SBOM-FSCT-AUTHOR" => RuleMeta {
            sarif_id: "SBOM-FSCT-AUTHOR",
            name: "FsctAuthorName",
            short_description: "CISA FSCT 3e §2.2.1.1 (Minimum): Author Name — person/organization author, not tool-only",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaFsct, "§2.2.1.1")],
            remediation: "Name the entity that prompted the SBOM's creation (organization, project team, or individual) with unique identification (email address or website) where possible — a tool-only creator list does not satisfy the element.",
            advice: Some(&ADVICE_PERSON_ORG_CREATOR),
        },
        "SBOM-FSCT-AUTHOR-TOOL" => RuleMeta {
            sarif_id: "SBOM-FSCT-AUTHOR-TOOL",
            name: "FsctAuthorTool",
            short_description: "CISA FSCT 3e §2.2.1.1 (Recommended): tool(s) and version(s) that assisted SBOM creation",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::CisaFsct, "§2.2.1.1")],
            remediation: "In addition to the authoring entity, identify the tool(s) and version(s) that assisted in creating the SBOM.",
            advice: Some(&ADVICE_TOOL),
        },
        "SBOM-FSCT-TIMESTAMP" => RuleMeta {
            sarif_id: "SBOM-FSCT-TIMESTAMP",
            name: "FsctTimestamp",
            short_description: "CISA FSCT 3e §2.2.1.2 (Minimum): creation timestamp in a common international format (ISO 8601)",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaFsct, "§2.2.1.2")],
            remediation: "Record the date and time the SBOM was produced in a common international format such as ISO 8601 (e.g., 2024-05-23T13:51:37Z), consistent across time zones and locales.",
            advice: Some(&ADVICE_TIMESTAMP),
        },
        "SBOM-FSCT-SBOM-TYPE" => RuleMeta {
            sarif_id: "SBOM-FSCT-SBOM-TYPE",
            name: "FsctSbomType",
            short_description: "CISA FSCT 3e §2.2.1.3 (optional/aspirational): SBOM Type declared (design/source/build/analyzed/deployed/runtime)",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::CisaFsct, "§2.2.1.3")],
            remediation: "Declare how/why the SBOM was created per the 'Types of SBOM' taxonomy (design, source, build, analyzed, deployed, runtime). The check runs on CycloneDX input only: this tool parses neither the SPDX 2.x CreatorComment mapping nor SPDX 3.0 sbomType.",
            advice: Some(&ADVICE_LIFECYCLE_PHASE),
        },
        "SBOM-FSCT-PRIMARY" => RuleMeta {
            sarif_id: "SBOM-FSCT-PRIMARY",
            name: "FsctPrimaryComponent",
            short_description: "CISA FSCT 3e §2.2.1.4: Primary Component (root of dependencies) identified as the subject of the SBOM",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaFsct, "§2.2.1.4")],
            remediation: "Identify the Primary Component the SBOM is about.",
            advice: Some(&ADVICE_PRIMARY),
        },
        "SBOM-FSCT-DIRECT-DEPS" => RuleMeta {
            sarif_id: "SBOM-FSCT-DIRECT-DEPS",
            name: "FsctDirectDependencies",
            short_description: "CISA FSCT 3e §2.2.2 / §2.3.3 (Minimum): all static direct dependencies of the Primary Component identified",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaFsct, "§2.2.2"), (K::CisaFsct, "§2.3.3")],
            remediation: "Identify all static, direct dependencies of the Primary Component (or carry an explicit completeness declaration covering their absence), and indicate when the dependency list is incomplete. 'All' is not verifiable from the document alone — the check uses dependency edges from the primary plus the completeness declaration as its evidence.",
            advice: Some(&ADVICE_DEPENDENCIES),
        },
        "SBOM-FSCT-TRANSITIVE-DEPS" => RuleMeta {
            sarif_id: "SBOM-FSCT-TRANSITIVE-DEPS",
            name: "FsctTransitiveDependencies",
            short_description: "CISA FSCT 3e §2.2.2 (Recommended): subcomponent levels beyond direct dependencies identified",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::CisaFsct, "§2.2.2")],
            remediation: "Identify as many levels of subcomponents beyond the direct dependencies as possible, or declare their absence via the completeness declaration. Heuristic: 'as many as possible' is not crisply verifiable — the depth>=2 threshold is profile policy.",
            advice: Some(&ADVICE_DEPENDENCIES),
        },
        "SBOM-FSCT-DYNAMIC-DEPS" => RuleMeta {
            sarif_id: "SBOM-FSCT-DYNAMIC-DEPS",
            name: "FsctDynamicDependencies",
            short_description: "CISA FSCT 3e §2.2.2 / §2.2.2.6 (Aspirational): dynamic and/or remote dependencies uniquely identified",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::CisaFsct, "§2.2.2"), (K::CisaFsct, "§2.2.2.6")],
            remediation: "Make efforts to uniquely and unambiguously identify dependencies that are dynamic and/or remote. The check runs on SPDX input only (CycloneDX's parsed model cannot express the signal); absence surfaces as an informational readiness note, never a failure.",
            advice: Some(&ADVICE_DYNAMIC_DEPS),
        },
        "SBOM-FSCT-COMPONENT-NAME" => RuleMeta {
            sarif_id: "SBOM-FSCT-COMPONENT-NAME",
            name: "FsctComponentName",
            short_description: "CISA FSCT 3e §2.2.2.1 (Minimum): commonly used public name declared for every component",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaFsct, "§2.2.2.1")],
            remediation: "Declare the commonly used public name for every component (a namespace:name construct is acceptable for conveying the supplier); placeholder values do not satisfy the element.",
            advice: Some(&ADVICE_NAME),
        },
        "SBOM-FSCT-VERSION" => RuleMeta {
            sarif_id: "SBOM-FSCT-VERSION",
            name: "FsctComponentVersion",
            short_description: "CISA FSCT 3e §2.2.2.2 (Minimum): supplier-provided version string (or authored hash as the documented fallback)",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaFsct, "§2.2.2.2")],
            remediation: "Record the version string as provided by the Supplier (semantic versioning preferred; accurate transcription is the primary goal). A component without a unique version passes only when an author-provided cryptographic hash is present — the element's documented fallback.",
            advice: Some(&ADVICE_VERSION),
        },
        "SBOM-FSCT-SUPPLIER" => RuleMeta {
            sarif_id: "SBOM-FSCT-SUPPLIER",
            name: "FsctSupplierName",
            short_description: "CISA FSCT 3e §2.2.2.3 (Minimum): Supplier Name declared for all components (explicit 'unknown' permitted)",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaFsct, "§2.2.2.3")],
            remediation: "Declare the Supplier Name for all components: the upstream supplier's legal-entity name (commercial) or project name (OSS); the domain URL / PURL namespace or an explicit 'unknown' are permitted last resorts. Silent absence fails; an explicit 'unknown' declaration satisfies the letter of the clause.",
            advice: Some(&ADVICE_SUPPLIER),
        },
        "SBOM-FSCT-IDENTIFIER" => RuleMeta {
            sarif_id: "SBOM-FSCT-IDENTIFIER",
            name: "FsctUniqueIdentifier",
            short_description: "CISA FSCT 3e §2.2.2.4 (Minimum): globally unique identifier per component (PURL/CPE/SWID/SWHID; hash accepted)",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaFsct, "§2.2.2.4")],
            remediation: "Declare a globally unique identifier for each component — PURL, CPE, SWID, SWHID, UUID/GUID, or OmniBOR Artifact ID; a cryptographic hash also functions as an intrinsic identifier. Profile policy: the document's letter is satisfied by format-native IDs (SPDX namespace + SPDXID, CycloneDX serialNumber + version) and only 'prefers' global uniqueness — this profile deliberately enforces the preferred clause.",
            advice: Some(&ADVICE_IDENTIFIER),
        },
        "SBOM-FSCT-IDENTIFIER-MULTI" => RuleMeta {
            sarif_id: "SBOM-FSCT-IDENTIFIER-MULTI",
            name: "FsctIdentifierMultiplicity",
            short_description: "CISA FSCT 3e §2.2.2.4 (Recommended): as many globally unique identifiers as available",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::CisaFsct, "§2.2.2.4")],
            remediation: "List as many globally unique identifiers as are available for the component. Heuristic: the >=2-distinct-identifier-kinds (PURL/CPE/SWHID/SWID) threshold is profile policy — 'as available' is unverifiable from the document alone.",
            advice: Some(&ADVICE_IDENTIFIER),
        },
        "SBOM-FSCT-HASH" => RuleMeta {
            sarif_id: "SBOM-FSCT-HASH",
            name: "FsctCryptographicHash",
            short_description: "CISA FSCT 3e §2.2.2.5 (Minimum): author-provided cryptographic hash with algorithm, or explicit unknown",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaFsct, "§2.2.2.5")],
            remediation: "Provide a hash (with its algorithm, for reproducibility) for any component whose hash was provided or can be generated; otherwise indicate it as unknown. Accepted at this tier: MD5, SHA1, and SHA2 families — MD5/SHA1 are no longer recommended and are formally discontinued in 2030. Only author-provided hashes count; tool-enriched hashes are not author evidence.",
            advice: Some(&ADVICE_HASH),
        },
        "SBOM-FSCT-HASH-PRIMARY-SHA2" => RuleMeta {
            sarif_id: "SBOM-FSCT-HASH-PRIMARY-SHA2",
            name: "FsctPrimaryHashSha2",
            short_description: "CISA FSCT 3e §2.2.2.5 (Recommended): Primary Component hashed; SHA-256-or-stronger SHA-2 hash on hashed components",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::CisaFsct, "§2.2.2.5")],
            remediation: "Provide at least one hash of the Primary Component, and use the cryptographically secure SHA-2 family (SHA-256 and higher) for hashed components; wherever less-secure hashes (MD5/SHA1) appear, add an additional cryptographically secure hash.",
            advice: Some(&ADVICE_HASH),
        },
        "SBOM-FSCT-RELATIONSHIP" => RuleMeta {
            sarif_id: "SBOM-FSCT-RELATIONSHIP",
            name: "FsctRelationship",
            short_description: "CISA FSCT 3e §2.2.2.6 (Minimum): relationships declared for the Primary Component and its direct dependencies",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaFsct, "§2.2.2.6")],
            remediation: "Declare relationships (primary, included-in/includes) and relationship completeness for the Primary Component and its direct dependencies — the primary must be identified and connected to its direct dependencies in the edge set.",
            advice: Some(&ADVICE_DEPENDENCIES),
        },
        "SBOM-FSCT-RELATIONSHIP-ALL" => RuleMeta {
            sarif_id: "SBOM-FSCT-RELATIONSHIP-ALL",
            name: "FsctRelationshipAll",
            short_description: "CISA FSCT 3e §2.2.2.6 (Recommended): relationships declared for ALL included components (no orphans)",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::CisaFsct, "§2.2.2.6")],
            remediation: "Declare relationships and relationship completeness for all included components — components that appear in the inventory but in no dependency edge are orphans.",
            advice: Some(&ADVICE_DEPENDENCIES),
        },
        "SBOM-FSCT-COMPLETENESS" => RuleMeta {
            sarif_id: "SBOM-FSCT-COMPLETENESS",
            name: "FsctRelationshipCompleteness",
            short_description: "CISA FSCT 3e §2.2.2.6.4 (supplemental/optional): relationship-completeness assertion recorded",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::CisaFsct, "§2.2.2.6.4"), (K::CisaFsct, "§2.3.3")],
            remediation: "Record a relationship-completeness assertion (Unknown/None/Partial/Known) — mapped to the document-level completeness declaration. Warning, not Error: the document labels the attribute supplemental and optional, with Unknown as the open-world default.",
            advice: Some(&ADVICE_COMPLETENESS),
        },
        "SBOM-FSCT-LICENSE-PRIMARY" => RuleMeta {
            sarif_id: "SBOM-FSCT-LICENSE-PRIMARY",
            name: "FsctLicensePrimary",
            short_description: "CISA FSCT 3e §2.2.2.7 (Minimum): license information for the Primary Component",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaFsct, "§2.2.2.7")],
            remediation: "Provide license information for the Primary Component, using SPDX license identifiers in standard form where available; NOASSERTION placeholders do not satisfy this check.",
            advice: Some(&ADVICE_LICENSE),
        },
        "SBOM-FSCT-LICENSE-COVERAGE" => RuleMeta {
            sarif_id: "SBOM-FSCT-LICENSE-COVERAGE",
            name: "FsctLicenseCoverage",
            short_description: "CISA FSCT 3e §2.2.2.7 (Recommended): license information for as many components as possible",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::CisaFsct, "§2.2.2.7")],
            remediation: "Provide license information for as many components as possible. The coverage threshold is profile policy — 'as possible' is unverifiable from the document alone.",
            advice: Some(&ADVICE_LICENSE),
        },
        "SBOM-FSCT-LICENSE-ALL" => RuleMeta {
            sarif_id: "SBOM-FSCT-LICENSE-ALL",
            name: "FsctLicenseAll",
            short_description: "CISA FSCT 3e §2.2.2.7 (Aspirational): license information for ALL listed components",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::CisaFsct, "§2.2.2.7")],
            remediation: "Provide license information for all listed components.",
            advice: Some(&ADVICE_LICENSE),
        },
        // The concluded-licence attestation, a second document-level finding
        // beside the all-components coverage above.
        "SBOM-FSCT-LICENSE-CONCLUDED" => RuleMeta {
            sarif_id: "SBOM-FSCT-LICENSE-CONCLUDED",
            name: "FsctConcludedLicense",
            short_description: "CISA FSCT 3e §2.2.2.7 (Aspirational): concluded-license attestation alongside declared licenses",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::CisaFsct, "§2.2.2.7")],
            remediation: "Record a concluded-license attestation for the listed components, alongside their declared license information.",
            advice: Some(&ADVICE_LICENSE_CONCLUDED),
        },
        "SBOM-FSCT-COPYRIGHT-PRIMARY" => RuleMeta {
            sarif_id: "SBOM-FSCT-COPYRIGHT-PRIMARY",
            name: "FsctCopyrightPrimary",
            short_description: "CISA FSCT 3e §2.2.2.8 (Minimum): copyright notice for the Primary Component",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaFsct, "§2.2.2.8")],
            remediation: "Provide the copyright notice for the Primary Component — it identifies the legal rights holder, and conveying notices is a standard condition of many OSS licenses.",
            advice: Some(&ADVICE_COPYRIGHT),
        },
        "SBOM-FSCT-COPYRIGHT-COVERAGE" => RuleMeta {
            sarif_id: "SBOM-FSCT-COPYRIGHT-COVERAGE",
            name: "FsctCopyrightCoverage",
            short_description: "CISA FSCT 3e §2.2.2.8 (Recommended): copyright notices for as many components as possible",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::CisaFsct, "§2.2.2.8")],
            remediation: "Provide copyright notices for as many components as possible. The coverage threshold is profile policy — 'as possible' is unverifiable from the document alone.",
            advice: Some(&ADVICE_COPYRIGHT),
        },
        "SBOM-FSCT-COPYRIGHT-ALL" => RuleMeta {
            sarif_id: "SBOM-FSCT-COPYRIGHT-ALL",
            name: "FsctCopyrightAll",
            short_description: "CISA FSCT 3e §2.2.2.8 (Aspirational): copyright notice on every listed component",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::CisaFsct, "§2.2.2.8")],
            remediation: "Provide a copyright notice for every listed SBOM component.",
            advice: Some(&ADVICE_COPYRIGHT),
        },
        "SBOM-FSCT-NOASSERTION" => RuleMeta {
            sarif_id: "SBOM-FSCT-NOASSERTION",
            name: "FsctNoAssertion",
            short_description: "CISA FSCT 3e §2.3.1 (Minimum): baseline attributes populated or explicitly declared no-assertion/no-value",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::CisaFsct, "§2.3.1")],
            remediation: "Provide every baseline attribute, or explicitly differentiate 'no assertion' (data missing) from 'no value' (not applicable). This rule fires only where an attribute is neither populated nor explicitly (or format-default) declared — the document sanctions explicit declarations as the recommended graceful handling and lets formats treat missing attributes as default no-assertion. Placeholders never satisfy the other SBOM-FSCT-* checks.",
            advice: None,
        },
        "SBOM-FSCT-UPSTREAM-SBOM" => RuleMeta {
            sarif_id: "SBOM-FSCT-UPSTREAM-SBOM",
            name: "FsctUpstreamSbom",
            short_description: "CISA FSCT 3e §2.3.3 (Recommended): upstream supplier SBOM data provided or linked for third-party direct dependencies",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::CisaFsct, "§2.3.3")],
            remediation: "Obtain the upstream Supplier's SBOM and provide the component data nested within the Primary Component's SBOM or linked separately. Advisory heuristic — contacting suppliers is unobservable in the document.",
            advice: Some(&ADVICE_UPSTREAM_BOM),
        },
        "SBOM-FSCT-SIGNATURE" => RuleMeta {
            sarif_id: "SBOM-FSCT-SIGNATURE",
            name: "FsctSignature",
            short_description: "CISA FSCT 3e §2.4 (supplemental): SBOM carries a verifiable digital signature",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::CisaFsct, "§2.4")],
            remediation: "Digitally sign the SBOM so consumers can verify authenticity and integrity (requires a digital signature plus PKI). Info severity: §2.4 is a supplemental element, not a Baseline Attribute; the check runs on CycloneDX input only.",
            advice: Some(&ADVICE_SIGNATURE),
        },
        // Generic bucket for FSCT-run findings whose check site has no
        // specific registry mapping (SARIF fallback re-bucketing).
        "SBOM-FSCT-GENERAL" => RuleMeta {
            sarif_id: "SBOM-FSCT-GENERAL",
            name: "FsctGeneralRequirement",
            short_description: "CISA FSCT 3e: general baseline-attribute requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::CisaFsct, "Baseline Attributes")],
            remediation: "Catch-all for CISA FSCT 3e findings that have no dedicated rule (no check emits it; the SARIF writer files unmapped findings here). Set the baseline attribute the finding's requirement names: author, timestamp, primary component, and per component the name, version, supplier, unique identifier, hash, relationships, license and copyright.",
            advice: None,
        },
        _ => return None,
    };
    Some(meta)
}

/// Every stable internal rule key with a `rule_meta` match arm, in match-arm
/// order. Kept adjacent to [`rule_meta`]; the `all_rule_ids_matches_the_registry`
/// test asserts the list and the match arms stay in lockstep.
const ALL_RULE_IDS: &[&str] = &[
    "SBOM-CRA-ART-13-2",
    "SBOM-CRA-SBOM-FRESHNESS",
    "SBOM-CRA-MACHINE-READABLE",
    "SBOM-CRA-ART-13-5",
    "SBOM-CRA-ART-13-5-PROFILE",
    "SBOM-CRA-ART-13-17-CONTACT",
    "SBOM-CRA-VULN-METADATA",
    "SBOM-CRA-VULN-METADATA-REMEDIATION",
    "SBOM-CRA-VULN-METADATA-PROFILE",
    "SBOM-CRA-CVD-POLICY",
    "SBOM-CRA-ART-13-8",
    "SBOM-CRA-ART-13-8-EOL",
    "SBOM-CRA-VULN-STATEMENT",
    "SBOM-CRA-LIFECYCLE",
    "SBOM-CRA-LIFECYCLE-APPROACHING-EOL",
    "SBOM-CRA-ART-13-15-PRODUCT",
    "SBOM-CRA-COMPONENT-VERSION",
    "SBOM-CRA-ART-24-SUPPLIER",
    "SBOM-CRA-ART-13-16",
    "SBOM-CRA-ART-13-16-EMAIL",
    "SBOM-CRA-COMPONENT-SUPPLIER",
    "SBOM-CRA-ART-14-PSIRT",
    "SBOM-CRA-ART-14-EARLY-WARNING",
    "SBOM-CRA-ART-14-NOTIFICATION",
    "SBOM-CRA-ART-14-ENISA",
    "SBOM-CRA-ART-24",
    "SBOM-CRA-ANNEX-I-IDENTIFIER",
    "SBOM-CRA-ANNEX-I-TRACEABILITY",
    "SBOM-CRA-ANNEX-I-SUPPLY-CHAIN",
    "SBOM-CRA-ANNEX-I-SUPPLY-CHAIN-TRANSITIVE",
    "SBOM-CRA-INVENTORY",
    "SBOM-CRA-ANNEX-I-INTEGRITY",
    "SBOM-CRA-ANNEX-I-DEPENDENCY",
    "SBOM-CRA-ANNEX-I-DEPENDENCY-ROOTS",
    "SBOM-CRA-ANNEX-I-PRIMARY",
    "SBOM-CRA-ANNEX-I-CONTROLS",
    "SBOM-CRA-DOC-INTEGRITY",
    "SBOM-CRA-ANNEX-IV",
    "SBOM-CRA-ANNEX-V",
    "SBOM-CRA-CYCLES",
    "SBOM-CRA-ANNEX-VIII",
    "SBOM-CRA-PRE-8-RQ-02-PRODUCER",
    "SBOM-CRA-PRE-8-RQ-02-IDENTIFIER",
    "SBOM-CRA-PRE-8-RQ-02-FIRMWARE-VERSION",
    "SBOM-CRA-PRE-8-RQ-02-DEVICE-FIRMWARE",
    "SBOM-CRA-PRE-7-RQ-07-RE",
    "SBOM-CRA-GENERAL",
    "SBOM-CRA-CREATOR",
    "SBOM-CRA-SERIAL",
    "SBOM-CRA-COMPONENT-NAME",
    "SBOM-CRA-SPEC-VERSION",
    "SBOM-CRA-SPEC-VERSION-UNKNOWN",
    "SBOM-CRA-ELEMENT-ID",
    "SBOM-QUALITY-GENERAL",
    "SBOM-QUALITY-CREATOR",
    "SBOM-QUALITY-SERIAL",
    "SBOM-QUALITY-INVENTORY",
    "SBOM-QUALITY-NAME",
    "SBOM-QUALITY-IDENTIFIER",
    "SBOM-QUALITY-LICENSE",
    "SBOM-QUALITY-HASH",
    "SBOM-QUALITY-SPEC-VERSION",
    "SBOM-QUALITY-SPEC-VERSION-UNKNOWN",
    "SBOM-QUALITY-ELEMENT-ID",
    "SBOM-EUCC-PP",
    "SBOM-EUCC-TOE",
    "SBOM-EUCC-ITSEF",
    "SBOM-EUCC-VALIDITY",
    "SBOM-EUCC-CERTREF",
    "SBOM-EUCC-GENERAL",
    "SBOM-AIACT-NA",
    "SBOM-AIACT-ANNEX-IV-1-DESCRIPTION",
    "SBOM-AIACT-ANNEX-IV-1-PURPOSE",
    "SBOM-AIACT-ANNEX-IV-2D-DATASETS",
    "SBOM-AIACT-ANNEX-IV-2D-SENSITIVITY",
    "SBOM-AIACT-ANNEX-IV-2D-PERSONAL-DATA",
    "SBOM-AIACT-ANNEX-IV-2G-METRICS",
    "SBOM-AIACT-ANNEX-IV-2C-ENERGY",
    "SBOM-AIACT-ANNEX-IV-3-LIMITATIONS",
    "SBOM-AIACT-UNTYPED-ML",
    "SBOM-AIACT-GENERAL",
    "SBOM-BSIAI-NA",
    "SBOM-BSIAI-UNTYPED-ML",
    "SBOM-BSIAI-META-AUTHOR",
    "SBOM-BSIAI-META-FORMAT",
    "SBOM-BSIAI-META-TIMESTAMP",
    "SBOM-BSIAI-META-TOOL",
    "SBOM-BSIAI-META-SIGNATURE",
    "SBOM-BSIAI-SYS-PRIMARY",
    "SBOM-BSIAI-SYS-PRODUCER",
    "SBOM-BSIAI-SYS-DATAFLOW",
    "SBOM-BSIAI-MODEL-NAME",
    "SBOM-BSIAI-MODEL-VERSION",
    "SBOM-BSIAI-MODEL-IDENTIFIER",
    "SBOM-BSIAI-MODEL-HASH",
    "SBOM-BSIAI-MODEL-HASH-ALGO",
    "SBOM-BSIAI-MODEL-CARD",
    "SBOM-BSIAI-MODEL-ARCHITECTURE",
    "SBOM-BSIAI-MODEL-DATASETS",
    "SBOM-BSIAI-MODEL-LIMITATIONS",
    "SBOM-BSIAI-MODEL-LICENSE",
    "SBOM-BSIAI-DATASET-NAME",
    "SBOM-BSIAI-DATASET-IDENTIFIER",
    "SBOM-BSIAI-DATASET-HASH",
    "SBOM-BSIAI-DATASET-LICENSE",
    "SBOM-BSIAI-DATASET-SENSITIVITY",
    "SBOM-BSIAI-DATASET-PROVENANCE",
    "SBOM-BSIAI-INFRA-RUNTIME",
    "SBOM-BSIAI-SEC-CONTROLS",
    "SBOM-BSIAI-SEC-EXPLOITABILITY",
    "SBOM-BSIAI-GENERAL",
    "SBOM-NTIA-VERSION",
    "SBOM-NTIA-TIMESTAMP",
    "SBOM-NTIA-SUPPLIER",
    "SBOM-NTIA-DEPENDENCY",
    "SBOM-FDA-SUPPLIER",
    "SBOM-FDA-SUPPORT",
    "SBOM-FDA-CONTACT",
    "SBOM-FDA-NAME",
    "SBOM-FDA-VERSION",
    "SBOM-FDA-IDENTIFIER",
    "SBOM-FDA-HASH",
    "SBOM-FDA-CREATOR",
    "SBOM-FDA-INVENTORY",
    "SBOM-FDA-NAMESPACE",
    "SBOM-FDA-DEPENDENCY",
    "SBOM-FDA-SECURITY",
    "SBOM-FDA-GENERAL",
    "SBOM-FDA-COMPONENT-NAME",
    "SBOM-FDA-SPEC-VERSION",
    "SBOM-FDA-SPEC-VERSION-UNKNOWN",
    "SBOM-FDA-ELEMENT-ID",
    "SBOM-NTIA-AUTHOR",
    "SBOM-NTIA-INVENTORY",
    "SBOM-NTIA-NAME",
    "SBOM-NTIA-IDENTIFIER",
    "SBOM-NTIA-GENERAL",
    "SBOM-NTIA-SPEC-VERSION",
    "SBOM-NTIA-SPEC-VERSION-UNKNOWN",
    "SBOM-NTIA-ELEMENT-ID",
    "SBOM-SSDF-GENERAL",
    "SBOM-EO14028-GENERAL",
    "SBOM-SSDF-PS1",
    "SBOM-SSDF-PS1-TOOL",
    "SBOM-SSDF-PS2",
    "SBOM-SSDF-PS3",
    "SBOM-SSDF-INVENTORY",
    "SBOM-SSDF-PO1",
    "SBOM-SSDF-PO3",
    "SBOM-SSDF-PW4",
    "SBOM-SSDF-PW6",
    "SBOM-SSDF-RV1",
    "SBOM-EO14028-FORMAT",
    "SBOM-EO14028-AUTOGEN",
    "SBOM-EO14028-CREATOR",
    "SBOM-EO14028-IDENTIFIER",
    "SBOM-EO14028-DEPENDENCY",
    "SBOM-EO14028-VERSION",
    "SBOM-EO14028-INTEGRITY",
    "SBOM-EO14028-DISCLOSURE",
    "SBOM-EO14028-SUPPLIER",
    "SBOM-EO14028-INVENTORY",
    "SBOM-EO14028-TIMESTAMP",
    "SBOM-EO14028-NAME",
    "SBOM-BSI-TR-03183-2-4",
    "SBOM-BSI-TR-03183-2-5-1",
    "SBOM-BSI-TR-03183-2-5-1-CONTACT",
    "SBOM-BSI-TR-03183-2-5-2",
    "SBOM-BSI-TR-03183-2-5-3",
    "SBOM-BSI-TR-03183-2-VERSION",
    "SBOM-BSI-TR-03183-2-INVENTORY",
    "SBOM-BSI-TR-03183-2-LICENSE",
    "SBOM-BSI-TR-03183-2-LICENSE-SPDX",
    "SBOM-BSI-TR-03183-2-CREATOR",
    "SBOM-BSI-TR-03183-2-5-4",
    "SBOM-BSI-TR-03183-2-5-4-MISSING",
    "SBOM-BSI-TR-03183-2-5-5",
    "SBOM-BSI-TR-03183-2-5-5-COMPLETENESS",
    "SBOM-BSI-TR-03183-2-5-2-4",
    "SBOM-BSI-TR-03183-2-3-1",
    "SBOM-BSI-TR-03183-2-GENERAL",
    "SBOM-CNSA2-000",
    "SBOM-CNSA2-ALG-001",
    "SBOM-CNSA2-ALG-002",
    "SBOM-CNSA2-ALG-003",
    "SBOM-CNSA2-ALG-004",
    "SBOM-CNSA2-ALG-006",
    "SBOM-CNSA2-ALG-007",
    "SBOM-CNSA2-ALG-005",
    "SBOM-CNSA2-ALG-008",
    "SBOM-CNSA2-ALG-UNKNOWN",
    "SBOM-CNSA2-CERT-001",
    "SBOM-CNSA2-CERT-UNKNOWN",
    "SBOM-CNSA2-PROTO-001",
    "SBOM-CNSA2-PROTO-002",
    "SBOM-CNSA2-PROTO-UNKNOWN",
    "SBOM-CNSA2-GENERAL",
    "SBOM-PQC-000",
    "SBOM-PQC-001",
    "SBOM-PQC-012",
    "SBOM-PQC-ALG-UNKNOWN",
    "SBOM-PQC-010",
    "SBOM-PQC-005",
    "SBOM-PQC-008",
    "SBOM-PQC-009",
    "SBOM-PQC-KEY-001",
    "SBOM-PQC-CERT-001",
    "SBOM-PQC-CERT-UNKNOWN",
    "SBOM-PQC-PROTO-001",
    "SBOM-PQC-PROTO-002",
    "SBOM-PQC-PROTO-UNKNOWN",
    "SBOM-PQC-GENERAL",
    "SBOM-CISA2026-AUTHOR",
    "SBOM-CISA2026-SIGNATURE",
    "SBOM-CISA2026-FORMAT",
    "SBOM-CISA2026-GENERATION-CONTEXT",
    "SBOM-CISA2026-TIMESTAMP",
    "SBOM-CISA2026-TOOL",
    "SBOM-CISA2026-TOOL-VERSION",
    "SBOM-CISA2026-SBOM-VERSION",
    "SBOM-CISA2026-PRODUCER",
    "SBOM-CISA2026-INVENTORY",
    "SBOM-CISA2026-NAME",
    "SBOM-CISA2026-VERSION",
    "SBOM-CISA2026-IDENTIFIER",
    "SBOM-CISA2026-HASH",
    "SBOM-CISA2026-HASH-ALGO",
    "SBOM-CISA2026-LICENSE",
    "SBOM-CISA2026-DEPENDENCY",
    "SBOM-CISA2026-COVERAGE",
    "SBOM-CISA2026-GENERAL",
    "SBOM-PCI-6-3-2-INVENTORY",
    "SBOM-PCI-6-3-2-NAME",
    "SBOM-PCI-6-3-2-VERSION",
    "SBOM-PCI-6-3-2-SUPPLIER",
    "SBOM-PCI-6-3-2-IDENTIFIER",
    "SBOM-PCI-6-3-2-THIRD-PARTY",
    "SBOM-PCI-6-3-2-COMPLETENESS",
    "SBOM-PCI-6-3-2-FRESHNESS",
    "SBOM-PCI-6-3-2-VULN-EVIDENCE",
    "SBOM-PCI-11-3-1-1-SEVERITY",
    "SBOM-PCI-GENERAL",
    "SBOM-FSCT-AUTHOR",
    "SBOM-FSCT-AUTHOR-TOOL",
    "SBOM-FSCT-TIMESTAMP",
    "SBOM-FSCT-SBOM-TYPE",
    "SBOM-FSCT-PRIMARY",
    "SBOM-FSCT-DIRECT-DEPS",
    "SBOM-FSCT-TRANSITIVE-DEPS",
    "SBOM-FSCT-DYNAMIC-DEPS",
    "SBOM-FSCT-COMPONENT-NAME",
    "SBOM-FSCT-VERSION",
    "SBOM-FSCT-SUPPLIER",
    "SBOM-FSCT-IDENTIFIER",
    "SBOM-FSCT-IDENTIFIER-MULTI",
    "SBOM-FSCT-HASH",
    "SBOM-FSCT-HASH-PRIMARY-SHA2",
    "SBOM-FSCT-RELATIONSHIP",
    "SBOM-FSCT-RELATIONSHIP-ALL",
    "SBOM-FSCT-COMPLETENESS",
    "SBOM-FSCT-LICENSE-PRIMARY",
    "SBOM-FSCT-LICENSE-COVERAGE",
    "SBOM-FSCT-LICENSE-ALL",
    "SBOM-FSCT-LICENSE-CONCLUDED",
    "SBOM-FSCT-COPYRIGHT-PRIMARY",
    "SBOM-FSCT-COPYRIGHT-COVERAGE",
    "SBOM-FSCT-COPYRIGHT-ALL",
    "SBOM-FSCT-NOASSERTION",
    "SBOM-FSCT-UPSTREAM-SBOM",
    "SBOM-FSCT-SIGNATURE",
    "SBOM-FSCT-GENERAL",
];

/// Enumerate every registered internal rule key, in registry order.
#[must_use]
pub fn all_rule_ids() -> &'static [&'static str] {
    ALL_RULE_IDS
}

/// Map an owned rule-id string back to the registry's `&'static str` key.
/// Used when deserializing payloads that carry a serialized `rule_id`, so a
/// round-tripped violation keeps its registry identity instead of collapsing
/// to the generic default.
#[must_use]
pub(crate) fn lookup_static_rule_id(rule_id: &str) -> Option<&'static str> {
    ALL_RULE_IDS.iter().find(|k| **k == rule_id).copied()
}

// ---------------------------------------------------------------------------
// Per-standard SARIF rule catalogues.
//
// Each slice lists, in display order, the externally-visible SARIF rule ids a
// standard's report declares as reportingDescriptors: one per check the
// standard runs. Every id must be a registry key whose `sarif_id` equals the
// key itself (a self-descriptor); the `sarif_rule_slices_are_self_descriptors`
// test enforces this. The SARIF generator (src/reports/sarif.rs) renders
// these through `rule_meta`, so name / shortDescription /
// defaultConfiguration.level can no longer drift from the registry.
//
// The `SBOM-<FAMILY>-GENERAL` fallback rules are in no slice: no check emits
// one. The SARIF generator files a finding without a registered rule under
// its family's fallback (`generic_rule_id_for_level` in mod.rs) and declares
// that rule when it does.
// ---------------------------------------------------------------------------

/// NTIA Minimum Elements SARIF rule catalogue.
pub const NTIA_SARIF_RULE_IDS: &[&str] = &[
    "SBOM-NTIA-AUTHOR",
    "SBOM-NTIA-INVENTORY",
    "SBOM-NTIA-NAME",
    "SBOM-NTIA-VERSION",
    "SBOM-NTIA-SUPPLIER",
    "SBOM-NTIA-IDENTIFIER",
    "SBOM-NTIA-DEPENDENCY",
    "SBOM-NTIA-TIMESTAMP",
    "SBOM-NTIA-SPEC-VERSION",
    "SBOM-NTIA-SPEC-VERSION-UNKNOWN",
    "SBOM-NTIA-ELEMENT-ID",
];

/// FDA premarket SARIF rule catalogue. The FDA baseline check reuses the
/// NTIA timestamp rule id (the FDA guidance incorporates the NTIA minimum
/// elements).
pub const FDA_SARIF_RULE_IDS: &[&str] = &[
    "SBOM-NTIA-TIMESTAMP",
    "SBOM-FDA-INVENTORY",
    "SBOM-FDA-CREATOR",
    "SBOM-FDA-NAMESPACE",
    "SBOM-FDA-NAME",
    "SBOM-FDA-SUPPLIER",
    "SBOM-FDA-HASH",
    "SBOM-FDA-IDENTIFIER",
    "SBOM-FDA-VERSION",
    "SBOM-FDA-DEPENDENCY",
    "SBOM-FDA-SUPPORT",
    "SBOM-FDA-CONTACT",
    "SBOM-FDA-SECURITY",
    "SBOM-FDA-COMPONENT-NAME",
    "SBOM-FDA-SPEC-VERSION",
    "SBOM-FDA-SPEC-VERSION-UNKNOWN",
    "SBOM-FDA-ELEMENT-ID",
];

/// NIST SSDF (SP 800-218) SARIF rule catalogue.
pub const SSDF_SARIF_RULE_IDS: &[&str] = &[
    "SBOM-SSDF-PS1",
    "SBOM-SSDF-PS1-TOOL",
    "SBOM-SSDF-PS2",
    "SBOM-SSDF-PS3",
    "SBOM-SSDF-INVENTORY",
    "SBOM-SSDF-PO1",
    "SBOM-SSDF-PO3",
    "SBOM-SSDF-PW4",
    "SBOM-SSDF-PW6",
    "SBOM-SSDF-RV1",
];

/// EO 14028 Section 4 SARIF rule catalogue.
pub const EO14028_SARIF_RULE_IDS: &[&str] = &[
    "SBOM-EO14028-TIMESTAMP",
    "SBOM-EO14028-NAME",
    "SBOM-EO14028-FORMAT",
    "SBOM-EO14028-AUTOGEN",
    "SBOM-EO14028-CREATOR",
    "SBOM-EO14028-IDENTIFIER",
    "SBOM-EO14028-DEPENDENCY",
    "SBOM-EO14028-VERSION",
    "SBOM-EO14028-INTEGRITY",
    "SBOM-EO14028-DISCLOSURE",
    "SBOM-EO14028-SUPPLIER",
    "SBOM-EO14028-INVENTORY",
];

/// Shared CRA / EUCC / BSI TR-03183-2 / EU AI Act / BSI-G7 SBOM-for-AI SARIF
/// rule catalogue (the default for CRA-family and readiness profiles).
pub const COMPLIANCE_SARIF_RULE_IDS: &[&str] = &[
    "SBOM-CRA-SBOM-FRESHNESS",
    "SBOM-CRA-MACHINE-READABLE",
    "SBOM-CRA-ART-13-17-CONTACT",
    "SBOM-CRA-VULN-METADATA",
    "SBOM-CRA-VULN-METADATA-REMEDIATION",
    "SBOM-CRA-VULN-METADATA-PROFILE",
    "SBOM-CRA-ART-13-5",
    "SBOM-CRA-ART-13-5-PROFILE",
    "SBOM-CRA-CVD-POLICY",
    "SBOM-CRA-ART-13-8",
    "SBOM-CRA-ART-13-8-EOL",
    "SBOM-CRA-LIFECYCLE",
    "SBOM-CRA-LIFECYCLE-APPROACHING-EOL",
    "SBOM-CRA-ART-13-15-PRODUCT",
    "SBOM-CRA-COMPONENT-VERSION",
    "SBOM-CRA-ART-13-16",
    "SBOM-CRA-ART-13-16-EMAIL",
    "SBOM-CRA-COMPONENT-SUPPLIER",
    "SBOM-CRA-VULN-STATEMENT",
    "SBOM-CRA-ANNEX-I-IDENTIFIER",
    "SBOM-CRA-ANNEX-I-TRACEABILITY",
    "SBOM-CRA-ANNEX-I-SUPPLY-CHAIN",
    "SBOM-CRA-ANNEX-I-SUPPLY-CHAIN-TRANSITIVE",
    "SBOM-CRA-ANNEX-I-INTEGRITY",
    "SBOM-CRA-ANNEX-I-DEPENDENCY",
    "SBOM-CRA-ANNEX-I-DEPENDENCY-ROOTS",
    "SBOM-CRA-ANNEX-I-PRIMARY",
    "SBOM-CRA-ANNEX-I-CONTROLS",
    "SBOM-CRA-INVENTORY",
    "SBOM-CRA-DOC-INTEGRITY",
    "SBOM-CRA-ANNEX-V",
    "SBOM-CRA-ART-13-2",
    "SBOM-CRA-ART-14-PSIRT",
    "SBOM-CRA-ART-14-EARLY-WARNING",
    "SBOM-CRA-ART-14-NOTIFICATION",
    "SBOM-CRA-ART-14-ENISA",
    "SBOM-CRA-ART-24",
    "SBOM-CRA-ANNEX-IV",
    "SBOM-CRA-CREATOR",
    "SBOM-CRA-SERIAL",
    "SBOM-CRA-COMPONENT-NAME",
    "SBOM-CRA-SPEC-VERSION",
    "SBOM-CRA-SPEC-VERSION-UNKNOWN",
    "SBOM-CRA-ELEMENT-ID",
    "SBOM-CRA-PRE-8-RQ-02-PRODUCER",
    "SBOM-CRA-PRE-8-RQ-02-IDENTIFIER",
    "SBOM-CRA-PRE-8-RQ-02-FIRMWARE-VERSION",
    "SBOM-CRA-PRE-8-RQ-02-DEVICE-FIRMWARE",
    "SBOM-CRA-PRE-7-RQ-07-RE",
    "SBOM-EUCC-PP",
    "SBOM-EUCC-TOE",
    "SBOM-EUCC-ITSEF",
    "SBOM-EUCC-VALIDITY",
    "SBOM-EUCC-CERTREF",
    "SBOM-BSI-TR-03183-2-4",
    "SBOM-BSI-TR-03183-2-5-1",
    "SBOM-BSI-TR-03183-2-5-1-CONTACT",
    "SBOM-BSI-TR-03183-2-5-2",
    "SBOM-BSI-TR-03183-2-5-3",
    "SBOM-BSI-TR-03183-2-VERSION",
    "SBOM-BSI-TR-03183-2-INVENTORY",
    "SBOM-BSI-TR-03183-2-LICENSE",
    "SBOM-BSI-TR-03183-2-LICENSE-SPDX",
    "SBOM-BSI-TR-03183-2-CREATOR",
    "SBOM-BSI-TR-03183-2-5-4",
    "SBOM-BSI-TR-03183-2-5-4-MISSING",
    "SBOM-BSI-TR-03183-2-5-5",
    "SBOM-BSI-TR-03183-2-5-5-COMPLETENESS",
    "SBOM-BSI-TR-03183-2-5-2-4",
    "SBOM-BSI-TR-03183-2-3-1",
    "SBOM-AIACT-NA",
    "SBOM-AIACT-ANNEX-IV-1-DESCRIPTION",
    "SBOM-AIACT-ANNEX-IV-1-PURPOSE",
    "SBOM-AIACT-ANNEX-IV-2D-DATASETS",
    "SBOM-AIACT-ANNEX-IV-2D-SENSITIVITY",
    "SBOM-AIACT-ANNEX-IV-2D-PERSONAL-DATA",
    "SBOM-AIACT-ANNEX-IV-2G-METRICS",
    "SBOM-AIACT-ANNEX-IV-2C-ENERGY",
    "SBOM-AIACT-ANNEX-IV-3-LIMITATIONS",
    "SBOM-AIACT-UNTYPED-ML",
    "SBOM-BSIAI-NA",
    "SBOM-BSIAI-META-AUTHOR",
    "SBOM-BSIAI-META-FORMAT",
    "SBOM-BSIAI-META-TIMESTAMP",
    "SBOM-BSIAI-META-TOOL",
    "SBOM-BSIAI-META-SIGNATURE",
    "SBOM-BSIAI-SYS-PRIMARY",
    "SBOM-BSIAI-SYS-PRODUCER",
    "SBOM-BSIAI-SYS-DATAFLOW",
    "SBOM-BSIAI-MODEL-NAME",
    "SBOM-BSIAI-MODEL-VERSION",
    "SBOM-BSIAI-MODEL-IDENTIFIER",
    "SBOM-BSIAI-MODEL-HASH",
    "SBOM-BSIAI-MODEL-HASH-ALGO",
    "SBOM-BSIAI-MODEL-CARD",
    "SBOM-BSIAI-MODEL-ARCHITECTURE",
    "SBOM-BSIAI-MODEL-DATASETS",
    "SBOM-BSIAI-MODEL-LIMITATIONS",
    "SBOM-BSIAI-MODEL-LICENSE",
    "SBOM-BSIAI-DATASET-NAME",
    "SBOM-BSIAI-DATASET-IDENTIFIER",
    "SBOM-BSIAI-DATASET-HASH",
    "SBOM-BSIAI-DATASET-LICENSE",
    "SBOM-BSIAI-DATASET-SENSITIVITY",
    "SBOM-BSIAI-DATASET-PROVENANCE",
    "SBOM-BSIAI-INFRA-RUNTIME",
    "SBOM-BSIAI-SEC-CONTROLS",
    "SBOM-BSIAI-SEC-EXPLOITABILITY",
    "SBOM-BSIAI-UNTYPED-ML",
];

/// NSA CNSA 2.0 SARIF rule catalogue: every `SBOM-CNSA2-*` self-descriptor
/// in the registry. The `cnsa2_and_pqc_slices_cover_their_rule_families`
/// test keeps this slice in lockstep with the registry, so a CNSA 2.0 run
/// declares its own rule family instead of the CRA-family catalogue.
pub const CNSA2_SARIF_RULE_IDS: &[&str] = &[
    "SBOM-CNSA2-000",
    "SBOM-CNSA2-ALG-001",
    "SBOM-CNSA2-ALG-002",
    "SBOM-CNSA2-ALG-003",
    "SBOM-CNSA2-ALG-004",
    "SBOM-CNSA2-ALG-005",
    "SBOM-CNSA2-ALG-006",
    "SBOM-CNSA2-ALG-007",
    "SBOM-CNSA2-ALG-008",
    "SBOM-CNSA2-ALG-UNKNOWN",
    "SBOM-CNSA2-CERT-001",
    "SBOM-CNSA2-CERT-UNKNOWN",
    "SBOM-CNSA2-PROTO-001",
    "SBOM-CNSA2-PROTO-002",
    "SBOM-CNSA2-PROTO-UNKNOWN",
];

/// NIST PQC readiness SARIF rule catalogue: every `SBOM-PQC-*`
/// self-descriptor in the registry. Same lockstep guarantee as
/// [`CNSA2_SARIF_RULE_IDS`].
pub const PQC_SARIF_RULE_IDS: &[&str] = &[
    "SBOM-PQC-000",
    "SBOM-PQC-001",
    "SBOM-PQC-005",
    "SBOM-PQC-008",
    "SBOM-PQC-009",
    "SBOM-PQC-010",
    "SBOM-PQC-012",
    "SBOM-PQC-ALG-UNKNOWN",
    "SBOM-PQC-KEY-001",
    "SBOM-PQC-CERT-001",
    "SBOM-PQC-CERT-UNKNOWN",
    "SBOM-PQC-PROTO-001",
    "SBOM-PQC-PROTO-002",
    "SBOM-PQC-PROTO-UNKNOWN",
];

/// CISA 2026 Minimum Elements SARIF rule catalogue: every `SBOM-CISA2026-*`
/// self-descriptor in the registry. The
/// `p4_profile_slices_cover_their_rule_families` test keeps this slice in
/// lockstep with the registry.
pub const CISA2026_SARIF_RULE_IDS: &[&str] = &[
    "SBOM-CISA2026-AUTHOR",
    "SBOM-CISA2026-SIGNATURE",
    "SBOM-CISA2026-FORMAT",
    "SBOM-CISA2026-GENERATION-CONTEXT",
    "SBOM-CISA2026-TIMESTAMP",
    "SBOM-CISA2026-TOOL",
    "SBOM-CISA2026-TOOL-VERSION",
    "SBOM-CISA2026-SBOM-VERSION",
    "SBOM-CISA2026-PRODUCER",
    "SBOM-CISA2026-INVENTORY",
    "SBOM-CISA2026-NAME",
    "SBOM-CISA2026-VERSION",
    "SBOM-CISA2026-IDENTIFIER",
    "SBOM-CISA2026-HASH",
    "SBOM-CISA2026-HASH-ALGO",
    "SBOM-CISA2026-LICENSE",
    "SBOM-CISA2026-DEPENDENCY",
    "SBOM-CISA2026-COVERAGE",
];

/// PCI DSS v4.0.1 Req. 6.3.2 SARIF rule catalogue: every `SBOM-PCI-*`
/// self-descriptor in the registry. Same lockstep guarantee as
/// [`CISA2026_SARIF_RULE_IDS`].
pub const PCIDSS_SARIF_RULE_IDS: &[&str] = &[
    "SBOM-PCI-6-3-2-INVENTORY",
    "SBOM-PCI-6-3-2-NAME",
    "SBOM-PCI-6-3-2-VERSION",
    "SBOM-PCI-6-3-2-SUPPLIER",
    "SBOM-PCI-6-3-2-IDENTIFIER",
    "SBOM-PCI-6-3-2-THIRD-PARTY",
    "SBOM-PCI-6-3-2-COMPLETENESS",
    "SBOM-PCI-6-3-2-FRESHNESS",
    "SBOM-PCI-6-3-2-VULN-EVIDENCE",
    "SBOM-PCI-11-3-1-1-SEVERITY",
];

/// CISA FSCT 3rd-edition SARIF rule catalogue: every `SBOM-FSCT-*`
/// self-descriptor in the registry. Same lockstep guarantee as
/// [`CISA2026_SARIF_RULE_IDS`].
pub const FSCT_SARIF_RULE_IDS: &[&str] = &[
    "SBOM-FSCT-AUTHOR",
    "SBOM-FSCT-AUTHOR-TOOL",
    "SBOM-FSCT-TIMESTAMP",
    "SBOM-FSCT-SBOM-TYPE",
    "SBOM-FSCT-PRIMARY",
    "SBOM-FSCT-DIRECT-DEPS",
    "SBOM-FSCT-TRANSITIVE-DEPS",
    "SBOM-FSCT-DYNAMIC-DEPS",
    "SBOM-FSCT-COMPONENT-NAME",
    "SBOM-FSCT-VERSION",
    "SBOM-FSCT-SUPPLIER",
    "SBOM-FSCT-IDENTIFIER",
    "SBOM-FSCT-IDENTIFIER-MULTI",
    "SBOM-FSCT-HASH",
    "SBOM-FSCT-HASH-PRIMARY-SHA2",
    "SBOM-FSCT-RELATIONSHIP",
    "SBOM-FSCT-RELATIONSHIP-ALL",
    "SBOM-FSCT-COMPLETENESS",
    "SBOM-FSCT-LICENSE-PRIMARY",
    "SBOM-FSCT-LICENSE-COVERAGE",
    "SBOM-FSCT-LICENSE-ALL",
    "SBOM-FSCT-LICENSE-CONCLUDED",
    "SBOM-FSCT-COPYRIGHT-PRIMARY",
    "SBOM-FSCT-COPYRIGHT-COVERAGE",
    "SBOM-FSCT-COPYRIGHT-ALL",
    "SBOM-FSCT-NOASSERTION",
    "SBOM-FSCT-UPSTREAM-SBOM",
    "SBOM-FSCT-SIGNATURE",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// `ALL_RULE_IDS` and the `rule_meta` match arms must stay in lockstep:
    /// every listed id resolves, every match arm is listed, no duplicates.
    /// The match arms are recovered from the source text of this file, so a
    /// new arm cannot land without being enumerated.
    #[test]
    fn all_rule_ids_matches_the_registry() {
        let src = include_str!("registry.rs");
        let mut match_arms = Vec::new();
        for line in src.lines() {
            let t = line.trim();
            if let Some(rest) = t.strip_prefix('"')
                && let Some(id) = rest.strip_suffix("\" => RuleMeta {")
            {
                match_arms.push(id.to_string());
            }
        }
        let listed: Vec<&str> = all_rule_ids().to_vec();
        let listed_set: std::collections::BTreeSet<&str> = listed.iter().copied().collect();
        assert_eq!(
            listed.len(),
            listed_set.len(),
            "ALL_RULE_IDS contains duplicates"
        );
        let arm_set: std::collections::BTreeSet<&str> =
            match_arms.iter().map(String::as_str).collect();
        assert_eq!(
            arm_set, listed_set,
            "rule_meta match arms and ALL_RULE_IDS drifted apart"
        );
        for id in listed {
            assert!(rule_meta(id).is_some(), "listed id {id:?} does not resolve");
        }
    }

    /// Whether a remediation text is a generic fallback rather than guidance:
    /// the unregistered-rule text, or a "review the requirement and update
    /// the SBOM accordingly" stub that names no field.
    fn is_generic_remediation(text: &str) -> bool {
        text == REMEDIATION_UNREGISTERED
            || text.starts_with("Review the ")
            || text.contains("update the SBOM accordingly")
            || text.contains("metadata accordingly")
    }

    /// Every registered rule carries specific remediation — in its
    /// format-neutral guidance and in the text rendered for every input
    /// format. A rule that falls back to a generic "review the requirement"
    /// text leaves the user with nothing to act on.
    #[test]
    fn every_rule_has_specific_remediation() {
        let generic: Vec<&str> = all_rule_ids()
            .iter()
            .copied()
            .filter(|id| {
                let meta = rule_meta(id).expect("listed id resolves");
                std::iter::once(meta.remediation_all_formats())
                    .chain(RemediationFormat::ALL.map(|f| meta.remediation_for(f)))
                    .any(|text| is_generic_remediation(&text))
            })
            .collect();
        assert!(
            generic.is_empty(),
            "{} rules fall back to a generic remediation text: {generic:?}",
            generic.len()
        );
    }

    /// Remediation texts are sentences, so the composed "<guidance>
    /// <Format>: <advice>" reads as prose; per-format advice names its
    /// field.
    #[test]
    fn advice_names_its_field_and_texts_are_sentences() {
        for id in all_rule_ids() {
            let meta = rule_meta(id).expect("listed id resolves");
            assert!(
                meta.remediation.ends_with('.'),
                "{id}: remediation must end with a full stop: {}",
                meta.remediation
            );
            let Some(advice) = meta.advice else {
                continue;
            };
            for format in RemediationFormat::ALL {
                let field_advice = advice.get(format);
                assert!(
                    field_advice.text.ends_with('.'),
                    "{id} ({format:?}): advice must end with a full stop: {}",
                    field_advice.text
                );
                if let Some(field) = field_advice.field {
                    assert!(
                        field_advice.text.contains(field),
                        "{id} ({format:?}): advice must name its field {field:?}: {}",
                        field_advice.text
                    );
                }
            }
        }
    }

    /// The remediation rendered for one format never sends the user to
    /// another format's fields — SPDX input used to get CycloneDX advice.
    #[test]
    fn remediation_names_only_the_input_formats_fields() {
        const CYCLONEDX: &[&str] = &[
            "components[]",
            "metadata.component",
            "metadata.authors",
            "metadata.tools",
            "metadata.manufacturer",
            "metadata.timestamp",
            "metadata.lifecycles",
            "externalReferences",
            "compositions",
            "modelCard",
        ];
        const SPDX2: &[&str] = &[
            "packages[]",
            "creationInfo.creators",
            "PackageSupplier",
            "documentNamespace",
            "documentDescribes",
            "relationships[]",
            "externalRefs[]",
        ];
        const SPDX3: &[&str] = &[
            "suppliedBy",
            "software_",
            "verifiedUsing",
            "rootElement",
            "externalIdentifier",
            "externalRef[]",
            "createdBy",
            "simplelicensing_",
            "ai_",
            "dataset_",
        ];
        for id in all_rule_ids() {
            let meta = rule_meta(id).expect("listed id resolves");
            for (format, foreign) in [
                (RemediationFormat::CycloneDx, [SPDX2, SPDX3].concat()),
                (RemediationFormat::Spdx2, [CYCLONEDX, SPDX3].concat()),
                (RemediationFormat::Spdx3, [CYCLONEDX, SPDX2].concat()),
            ] {
                let text = meta.remediation_for(format);
                for marker in foreign {
                    assert!(
                        !text.contains(marker),
                        "{id} ({format:?}) names another format's field {marker:?}: {text}"
                    );
                }
            }
        }
    }

    /// Every CRA sidecar key a remediation cites is accepted by the sidecar
    /// loader, which denies unknown fields: a snake_case spelling such as
    /// `eucc_valid_until` would send the user to a load error.
    #[test]
    fn cited_sidecar_keys_load() {
        const CITED: &[(&str, &[&str])] = &[
            ("SBOM-CRA-ART-13-2", &["riskAssessmentUrl"]),
            ("SBOM-CRA-ART-14-PSIRT", &["psirtUrl"]),
            ("SBOM-CRA-ART-14-EARLY-WARNING", &["earlyWarningContact"]),
            ("SBOM-CRA-ART-14-NOTIFICATION", &["incidentReportContact"]),
            ("SBOM-CRA-ART-14-ENISA", &["enisaReportingPlatformId"]),
            (
                "SBOM-CRA-ART-24",
                &["psirtUrl", "vulnerabilityDisclosureUrl"],
            ),
            (
                "SBOM-CRA-ART-13-17-CONTACT",
                &["securityContact", "vulnerabilityDisclosureUrl"],
            ),
            (
                "SBOM-CRA-CVD-POLICY",
                &[
                    "coordinatedDisclosurePolicyUrl",
                    "vulnerabilityDisclosureUrl",
                ],
            ),
            ("SBOM-CRA-ART-13-8", &["supportEndDate"]),
            ("SBOM-CRA-LIFECYCLE", &["supportEndDate"]),
            ("SBOM-CRA-ART-13-15-PRODUCT", &["productName"]),
            ("SBOM-CRA-ART-13-16", &["manufacturerName"]),
            ("SBOM-CRA-ANNEX-I-CONTROLS", &["annexIPartIControls"]),
            (
                "SBOM-CRA-ANNEX-IV",
                &[
                    "euccProtectionProfileId",
                    "euccTargetOfEvaluation",
                    "euccItsefIdentifier",
                    "euccValidUntil",
                ],
            ),
            ("SBOM-CRA-ANNEX-V", &["ceMarkingReference"]),
            (
                "SBOM-EUCC-PP",
                &[
                    "euccProtectionProfileId",
                    "euccTargetOfEvaluation",
                    "euccItsefIdentifier",
                    "euccValidUntil",
                ],
            ),
        ];
        for (id, keys) in CITED {
            let text = rule_meta(id).expect("listed id resolves").remediation;
            for key in *keys {
                assert!(text.contains(key), "{id} must cite {key:?}: {text}");
                let value = match *key {
                    "supportEndDate" | "euccValidUntil" => {
                        serde_json::json!("2030-01-01T00:00:00Z")
                    }
                    "annexIPartIControls" => serde_json::json!({
                        "1.a": { "satisfied": true, "evidenceUrl": "https://example.com/evidence" }
                    }),
                    _ => serde_json::json!("x"),
                };
                let sidecar = serde_json::json!({ *key: value });
                assert!(
                    serde_json::from_value::<crate::model::CraSidecarMetadata>(sidecar).is_ok(),
                    "{id}: sidecar key {key:?} does not load"
                );
            }
        }
        // ANNEX-I-CONTROLS also cites the per-control evidenceUrl key.
        assert!(
            rule_meta("SBOM-CRA-ANNEX-I-CONTROLS")
                .expect("listed id resolves")
                .remediation
                .contains("evidenceUrl")
        );
    }

    /// CNSA 2.0 rules must remediate with CNSA 2.0 guidance, not the generic
    /// fallback: SBOM-CNSA2-ALG-001..004/006/007, -000 and -CERT-001 used
    /// `REMEDIATION_GENERIC`, which cites the EU CRA (EU 2024/2847) — a US
    /// NSA CNSA 2.0 finding pointed the user at an EU regulation.
    #[test]
    fn cnsa2_rules_cite_cnsa_not_eu_cra() {
        for id in all_rule_ids().iter().filter(|id| id.contains("CNSA2")) {
            let meta = rule_meta(id).expect("listed id resolves");
            assert!(
                !meta.remediation.contains("EU CRA"),
                "{id}: a CNSA 2.0 rule must not cite the EU CRA as its remediation source"
            );
            assert!(
                meta.remediation.contains("CNSA 2.0"),
                "{id}: CNSA 2.0 rules should carry CNSA 2.0 migration guidance"
            );
        }
    }

    /// Non-CRA standards must not fall back to the CRA-citing generic
    /// remediation: an NTIA/FDA/AI-Act/BSI finding that points the user at
    /// EU 2024/2847 cites the wrong regulation (same defect class as the
    /// CNSA case above). CRA rules keep the CRA citation.
    #[test]
    fn non_cra_rules_do_not_cite_eu_cra_as_generic_fallback() {
        for id in all_rule_ids()
            .iter()
            .filter(|id| id.contains("NTIA") || id.contains("FDA") || id.contains("AIACT"))
        {
            let meta = rule_meta(id).expect("listed id resolves");
            assert!(
                !meta.remediation.contains("EU CRA regulation"),
                "{id}: a non-CRA rule must not cite the EU CRA as its generic remediation"
            );
        }
        let bsi = rule_meta("SBOM-BSI-TR-03183-2-GENERAL").expect("BSI general rule resolves");
        assert!(
            bsi.remediation.contains("TR-03183-2"),
            "BSI general rule should cite TR-03183-2, got: {}",
            bsi.remediation
        );
    }

    /// Every id in a per-standard SARIF slice must be a self-descriptor:
    /// a registry key whose `sarif_id` is the key itself. The SARIF
    /// generator relies on this to render descriptors without aliasing.
    #[test]
    fn sarif_rule_slices_are_self_descriptors() {
        for (label, slice) in [
            ("ntia", NTIA_SARIF_RULE_IDS),
            ("fda", FDA_SARIF_RULE_IDS),
            ("ssdf", SSDF_SARIF_RULE_IDS),
            ("eo14028", EO14028_SARIF_RULE_IDS),
            ("compliance", COMPLIANCE_SARIF_RULE_IDS),
            ("cnsa2", CNSA2_SARIF_RULE_IDS),
            ("pqc", PQC_SARIF_RULE_IDS),
            ("cisa2026", CISA2026_SARIF_RULE_IDS),
            ("pci-dss", PCIDSS_SARIF_RULE_IDS),
            ("fsct", FSCT_SARIF_RULE_IDS),
        ] {
            let mut seen = std::collections::BTreeSet::new();
            for id in slice {
                assert!(seen.insert(*id), "[{label}] duplicate slice id {id}");
                let meta = rule_meta(id)
                    .unwrap_or_else(|| panic!("[{label}] slice id {id} not in registry"));
                assert_eq!(
                    meta.sarif_id, *id,
                    "[{label}] slice id {id} aliases to {}; slices must list self-descriptors",
                    meta.sarif_id
                );
            }
        }
    }

    /// Whether `id` is a family fallback rule: the rule the SARIF writer
    /// files a finding without a registered rule under. No check emits one.
    fn is_fallback(id: &str) -> bool {
        super::super::ComplianceLevel::all()
            .iter()
            .any(|level| super::super::generic_rule_id_for_level(*level) == id)
    }

    /// The CNSA 2.0 / PQC catalogues must enumerate their entire rule
    /// family: a registry rule missing from its slice would only surface via
    /// the catalogue-completion backfill when it happens to fire, putting
    /// SARIF consumers' suppressions/baselines back on an incomplete
    /// catalogue. The family's fallback rule is the one exception.
    #[test]
    fn cnsa2_and_pqc_slices_cover_their_rule_families() {
        for (prefix, slice) in [
            ("SBOM-CNSA2-", CNSA2_SARIF_RULE_IDS),
            ("SBOM-PQC-", PQC_SARIF_RULE_IDS),
        ] {
            let expected: std::collections::BTreeSet<&str> = all_rule_ids()
                .iter()
                .copied()
                .filter(|id| id.starts_with(prefix) && !is_fallback(id))
                .collect();
            let actual: std::collections::BTreeSet<&str> = slice.iter().copied().collect();
            assert_eq!(
                actual, expected,
                "{prefix}* SARIF slice drifted from the registry"
            );
        }
    }

    /// The CISA 2026 / PCI DSS / FSCT catalogues must enumerate their entire
    /// rule family but its fallback rule (same guarantee as the CNSA 2.0 /
    /// PQC test above): the parallel checker wave adds check sites but may
    /// not touch this file, so a family rule missing from its slice would
    /// silently fall off the upfront-declared SARIF catalogue.
    #[test]
    fn p4_profile_slices_cover_their_rule_families() {
        for (prefix, slice) in [
            ("SBOM-CISA2026-", CISA2026_SARIF_RULE_IDS),
            ("SBOM-PCI-", PCIDSS_SARIF_RULE_IDS),
            ("SBOM-FSCT-", FSCT_SARIF_RULE_IDS),
        ] {
            let expected: std::collections::BTreeSet<&str> = all_rule_ids()
                .iter()
                .copied()
                .filter(|id| id.starts_with(prefix) && !is_fallback(id))
                .collect();
            let actual: std::collections::BTreeSet<&str> = slice.iter().copied().collect();
            assert_eq!(
                actual, expected,
                "{prefix}* SARIF slice drifted from the registry"
            );
        }
    }

    /// No slice declares a fallback rule: no check emits one, so a standard's
    /// catalogue lists the checks it runs and nothing else.
    #[test]
    fn no_slice_lists_a_fallback_rule() {
        for slice in [
            NTIA_SARIF_RULE_IDS,
            FDA_SARIF_RULE_IDS,
            SSDF_SARIF_RULE_IDS,
            EO14028_SARIF_RULE_IDS,
            COMPLIANCE_SARIF_RULE_IDS,
            CNSA2_SARIF_RULE_IDS,
            PQC_SARIF_RULE_IDS,
            CISA2026_SARIF_RULE_IDS,
            PCIDSS_SARIF_RULE_IDS,
            FSCT_SARIF_RULE_IDS,
        ] {
            for id in slice {
                assert!(!is_fallback(id), "slice lists the fallback rule {id}");
            }
        }
    }

    /// Every check is its own SARIF rule: each key's `sarif_id` is the key,
    /// so no two checks share a rule (and its help text), and the rule names
    /// and short descriptions a code-scanning UI lists them by are unique.
    #[test]
    fn every_rule_is_its_own_sarif_rule() {
        let mut names = std::collections::BTreeMap::new();
        let mut descriptions = std::collections::BTreeMap::new();
        for id in all_rule_ids() {
            let meta = rule_meta(id).expect("listed id resolves");
            assert_eq!(meta.sarif_id, *id, "{id} reports under another rule");
            if let Some(other) = names.insert(meta.name, *id) {
                panic!("{id} and {other} share the rule name {}", meta.name);
            }
            if let Some(other) = descriptions.insert(meta.short_description, *id) {
                panic!(
                    "{id} and {other} share the short description {:?}",
                    meta.short_description
                );
            }
        }
    }
}
