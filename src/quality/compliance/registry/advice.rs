//! Per-format field advice: where a rule's field lives in CycloneDX,
//! SPDX 2.x and SPDX 3.0, and how to set it. The rule declarations of
//! every family share it.

use super::*;

/// Component producer: a supplier, manufacturer or author (`has_known_producer`).
pub(super) const ADVICE_PRODUCER: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_SUPPLIER: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_VERSION: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_NAME: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_IDENTIFIER: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_PRIMARY_IDENTIFIER: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_HASH: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_HASH_SHA512: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_LICENSE: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_LICENSING_PROFILE: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_LICENSE_CONCLUDED: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_COPYRIGHT: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_DEPENDENCIES: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_PRIMARY: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_INVENTORY: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_CREATORS: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_PERSON_ORG_CREATOR: FormatAdvice = FormatAdvice {
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

/// The manufacturer: the product component's manufacturer or supplier, or
/// an organization creator of the SBOM.
pub(super) const ADVICE_MANUFACTURER: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "set metadata.component.manufacturer (CycloneDX 1.6+) or metadata.supplier, or metadata.manufacturer for the organization that created the SBOM (name, contact[].email).",
        field: Some("metadata.component.manufacturer"),
    },
    spdx2: FieldAdvice {
        text: "set packages[].supplier on the described package, e.g. \"Organization: Example Ltd\", or add a creationInfo.creators[] entry \"Organization: Example Ltd (contact@example.com)\".",
        field: Some("packages[].supplier"),
    },
    spdx3: FieldAdvice {
        text: "set suppliedBy on the root package to an Organization element, or set creationInfo.createdBy to one.",
        field: Some("suppliedBy"),
    },
};

/// The manufacturer's contact email.
pub(super) const ADVICE_ORG_EMAIL: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_CREATOR_CONTACT: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_TOOL: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_TIMESTAMP: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_SERIAL: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_DOC_VERSION: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_DOC_NAME: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_SECURITY_CONTACT: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_CVD: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_SUPPORT_END: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_LIFECYCLE: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_FDA_SUPPORT: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_FDA_CONTACT: FormatAdvice = FormatAdvice {
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

/// Completeness declaration; SPDX 2.x has no field for it.
pub(super) const ADVICE_COMPLETENESS: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_LIFECYCLE_PHASE: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_SIGNATURE: FormatAdvice = FormatAdvice {
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

/// Document integrity (CRA Annex I Part I (2)(f)): an in-document signature,
/// or an attestation or certification reference on the product that carries
/// the hash of the referenced document.
pub(super) const ADVICE_DOC_INTEGRITY: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "sign the BOM (a JSF signature object at the document root in JSON, an enveloped XML-DSig <Signature> element on <bom> in XML), or add hashes[] to a metadata.component.externalReferences[] entry of type attestation or certification-report.",
        field: Some("signature"),
    },
    spdx2: FieldAdvice {
        text: "no in-document signature field exists and external references carry no hash, so the check cannot be satisfied from the document.",
        field: None,
    },
    spdx3: FieldAdvice {
        text: "add a verifiedUsing[] entry of type signature (algorithm, hashValue) to the SpdxDocument.",
        field: Some("verifiedUsing[]"),
    },
};

/// Risk ranking on embedded vulnerability entries.
pub(super) const ADVICE_VULN_SEVERITY: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_VULN_REMEDIATION: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_SECURITY_PROFILE: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_VULN_DATA: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_REMOVE_VULNS: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_VCS: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_BUILD: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_UPSTREAM_BOM: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_DYNAMIC_DEPS: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_DEVICE_FIRMWARE: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_DOC_REF: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_EUCC_ALT: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_EUCC_CERTREF: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "add an externalReferences[] entry of type certification-report (or attestation) whose URL contains eucc, common-criteria or commoncriteria, or a fresh, fully conformant attestation in declarations (CycloneDX 1.6+) of a CRA standard that names EUCC or Common Criteria.",
        field: Some("externalReferences[]"),
    },
    spdx2: FieldAdvice {
        text: "no field is recognized as an EUCC certificate reference.",
        field: None,
    },
    spdx3: FieldAdvice {
        text: "add an externalRef[] entry with externalRefType certificationReport (or secureSoftwareAttestation) whose locator contains eucc, common-criteria or commoncriteria.",
        field: Some("externalRef[]"),
    },
};

/// Documented risk-assessment reference (CRA Art. 13(2)).
pub(super) const ADVICE_RISK_ASSESSMENT: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_CONFORMITY_EVIDENCE: FormatAdvice = FormatAdvice {
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

/// Typing a component that looks like an ML model.
pub(super) const ADVICE_UNTYPED_ML: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_AI_DESCRIPTION: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_AI_PURPOSE: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_AI_DATASETS: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_AI_TRAINING_DATASETS: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_AI_SENSITIVITY: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_AI_METRICS: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_AI_ENERGY: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_AI_LIMITATIONS: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_AI_LIMITATION: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_AI_MODEL_CARD: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_AI_ARCHITECTURE: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_DATASET_PROVENANCE: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_QUALITY_GENERAL: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_CRA_GENERAL: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_FDA_GENERAL: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_FORMAT_GENERAL: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_SPEC_VERSION: FormatAdvice = FormatAdvice {
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
pub(super) const ADVICE_ELEMENT_ID: FormatAdvice = FormatAdvice {
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

/// One entry per component.
pub(super) const ADVICE_DUPLICATE_COMPONENT: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "list each component once in components[], under a bom-ref of its own.",
        field: Some("components[]"),
    },
    spdx2: FieldAdvice {
        text: "list each package once in packages[], under an SPDXID of its own.",
        field: Some("packages[]"),
    },
    spdx3: FieldAdvice {
        text: "describe each package in one software_Package element, under an spdxId of its own.",
        field: Some("software_Package"),
    },
};

/// The digest size of a hash algorithm asset (SBOM-PQC-HASH-001), which
/// the check reads. Only CycloneDX describes cryptographic assets.
pub(super) const ADVICE_DIGEST_SIZE: FormatAdvice = FormatAdvice {
    cyclonedx: FieldAdvice {
        text: "set components[].cryptoProperties.algorithmProperties.parameterSetIdentifier to the digest size of the hash, 256 or more.",
        field: Some("components[].cryptoProperties.algorithmProperties.parameterSetIdentifier"),
    },
    spdx2: FieldAdvice {
        text: "SPDX 2.x has no cryptographic-asset model, so the check does not run on SPDX 2.x input.",
        field: None,
    },
    spdx3: FieldAdvice {
        text: "SPDX 3.0 has no cryptographic-asset model, so the check does not run on SPDX 3.0 input.",
        field: None,
    },
};
