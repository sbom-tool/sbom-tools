//! The rules of the CISA 2026 Minimum Elements profile.

use super::*;

/// The declared [`RuleMeta`] of `rule_id` when it is a rule of this
/// family; `None` otherwise.
pub(super) fn declared_rule_meta(rule_id: &str) -> Option<RuleMeta> {
    use StandardKind as K;
    let meta = match rule_id {
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
            remediation: "Declare each component's license(s), preferring machine-processable SPDX license identifiers; a LicenseRef-* expression or a pointer to where the full license details are available also satisfies the element, and an explicit unknown (NOASSERTION) is required when the author is unaware. Silent absence and a placeholder such as TBD fail.",
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
        _ => return None,
    };
    Some(meta)
}
