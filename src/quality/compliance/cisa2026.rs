//! CISA 2026 Minimum Elements profile checks.
//!
//! Standard: "2026 Minimum Elements for a Software Bill of Materials (SBOM)",
//! Version 2.1, July 29, 2026 — jointly sealed by CISA, NSA, FBI, and 15
//! international partner agencies. Updates and replaces the NTIA "Minimum
//! Elements for an SBOM" (v1.0, July 12, 2021); the August 2025 CISA draft
//! was v2.0 of the same document. Non-binding joint guidance: it explicitly
//! does not create regulatory requirements.
//!
//! The rule catalogue for this profile lives in the registry
//! (`SBOM-CISA2026-*`, see `CISA2026_SARIF_RULE_IDS`), covering the 17 data
//! fields plus the document-checkable practices (Coverage / Explicitly
//! Identifying Unknown Information, Machine-Processable Data). The
//! organizational practices with no in-document evidence — Frequency,
//! Distribution and Delivery, Accommodation of Updates to SBOM Data — carry
//! no rules by design.
//!
//! Severity convention (CISA assigns none): required data fields = Error;
//! evidence-limited or heuristic checks = Warning. A check is
//! evidence-limited when at least one conforming way to satisfy the element
//! is invisible to a document checker (e.g., detached signatures, SPDX 2.x
//! fields that do not exist), so absence must not hard-fail the run.
//!
//! Evidence gates (as in the FSCT profile): SPDX 2.x has no field for an
//! in-document signature, the lifecycle phase, or a completeness
//! declaration, so these rules do not run on SPDX 2.x input (see
//! `is_spdx2`):
//! - `SBOM-CISA2026-SIGNATURE`
//! - `SBOM-CISA2026-GENERATION-CONTEXT`
//! - `SBOM-CISA2026-COVERAGE`
//!
//! Firing them anyway meant an SPDX 2.x SBOM could never pass
//! `--fail-on-warning`, however complete. CycloneDX and SPDX 3 input is
//! still checked.
//!
//! Escape hatches: several 2026 elements require the author to *explicitly*
//! state that information is unknown instead of omitting it (Component
//! Version, Component Producer, Component Hash Value, Component License).
//! For those rules an explicit sentinel (`NOASSERTION`/`NONE`/`UNKNOWN`)
//! satisfies the element — deliberately unlike the NTIA checks, where
//! sentinels count as missing — while silent absence fails.

use super::*;

/// Explicit-unknown sentinel: the marker an SBOM author uses to state that a
/// value is unknown rather than silently omitting it. The 2026 elements'
/// escape hatches ("the SBOM author should indicate the information is
/// unknown") make these markers *satisfy* the honesty requirement, so this
/// is deliberately the complement of `known_value` (which treats the same
/// sentinels as absent for the NTIA-style presence gates).
fn is_unknown_marker(value: &str) -> bool {
    is_declared_unknown(value)
}

/// Heuristic for the SBOM Tool Version element: whether a Tool creator's
/// name carries a version identifier (or an explicit unknown marker).
///
/// Heuristic by necessity: the parsers concatenate tool name and version
/// into one creator name — CycloneDX `metadata.tools` becomes
/// `"{name} {version}"` and the SPDX `Creator: Tool:` convention is
/// `name-version` — so there is no dedicated tool-version field to check.
/// A trailing whitespace- or hyphen-delimited segment containing an ASCII
/// digit counts as a version; a tool genuinely named with a trailing digit
/// (e.g. "syft2") is an accepted false pass, which is why the rule is a
/// Warning with heuristic wording rather than an Error.
fn tool_name_carries_version(name: &str) -> bool {
    let name = name.trim();
    // The element's escape hatch: an explicit unknown marker satisfies it.
    if name.split_whitespace().any(is_unknown_marker) {
        return true;
    }
    let last_ws = name.rsplit(char::is_whitespace).next().unwrap_or(name);
    let last_seg = last_ws.rsplit('-').next().unwrap_or(last_ws);
    last_seg.chars().any(|c| c.is_ascii_digit())
}

/// Why a hash algorithm falls short of the Component Hash Algorithm element,
/// or `None` when it is acceptable. "The algorithm should be approved by a
/// relevant authority, such as NIST": MD5 was never FIPS-approved; SHA-1 is
/// deprecated with withdrawal slated by 2030; an unrecognized algorithm
/// cannot be mapped to an IANA Hash Function Textual Name.
fn hash_algorithm_shortfall(algorithm: &crate::model::HashAlgorithm) -> Option<String> {
    use crate::model::HashAlgorithm;
    match algorithm {
        HashAlgorithm::Md5 => Some("MD5 (not NIST-approved)".to_string()),
        HashAlgorithm::Sha1 => Some("SHA-1 (deprecated; NIST withdrawal by 2030)".to_string()),
        HashAlgorithm::Other(name) => Some(format!("{name} (not a recognized hash function name)")),
        _ => None,
    }
}

/// Whether the document is SPDX 2.x, whose data model has no field for
/// three pieces of evidence the 2026 elements ask for:
/// - an in-document signature (SBOM Author Signature): SPDX 2.x defines no
///   signature field, so its signatures live in detached files or
///   envelopes, unlike CycloneDX JSF `signature` or SPDX 3 `verifiedUsing`;
/// - the lifecycle phase (SBOM Generation Context): SPDX 2.x has no
///   counterpart of CycloneDX `metadata.lifecycles` or SPDX 3 `sbomType`,
///   only free-text comments;
/// - a completeness declaration (Coverage): SPDX 2.x has no counterpart of
///   CycloneDX `compositions` or SPDX 3 relationship `completeness`; a
///   `NONE`/`NOASSERTION` relationship target speaks for one relationship,
///   not for the inventory.
///
/// The rules looking for that evidence are gated off for SPDX 2.x, as the
/// FSCT profile gates attributes a format cannot express. Unparseable SPDX
/// versions count as 2.x: the SPDX 3 parser always records a 3.x version.
fn is_spdx2(sbom: &NormalizedSbom) -> bool {
    sbom.document.format == SbomFormat::Spdx
        && sbom
            .document
            .spec_version_parsed()
            .is_none_or(|v| v.major < 3)
}

impl ComplianceChecker {
    // ════════════════════════════════════════════════════════════════════
    // CISA 2026 Minimum Elements (successor to NTIA 2021)
    // ════════════════════════════════════════════════════════════════════

    /// CISA 2026 Minimum Elements compliance checks.
    ///
    /// Document-level elements first (SBOM Author, Author Signature, Data
    /// Format, Generation Context, Timestamp, Tool Name/Version, SBOM
    /// Version), then the per-component data fields (Producer, Name,
    /// Version, Identifiers, Hash Value/Algorithm, License), then the
    /// graph-level Dependency Relationship element and the Coverage /
    /// Explicitly Identifying Unknown Information declaration check.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn check_cisa2026(&self, sbom: &NormalizedSbom, violations: &mut Vec<Violation>) {
        use crate::model::{CompletenessDeclaration, CreatorType, ExternalRefType, HashProvenance};

        // The per-component elements below have nothing to judge without a
        // package-scoped component.
        violations.extend(inventory_absent_violation(
            sbom,
            "SBOM-CISA2026-INVENTORY",
            "CISA 2026 Minimum Elements: component inventory",
        ));

        // Signature, generation context and coverage evidence cannot be
        // expressed in SPDX 2.x; those checks skip it (see module docs).
        let spdx2 = is_spdx2(sbom);

        // SBOM Author (Error) — "the name of the entity that creates the
        // SBOM data": the entity operating the generation tool, not the tool
        // itself, so a tool-only creator list fails. Deliberately stricter
        // than SBOM-NTIA-AUTHOR, which passes on any non-empty creator list.
        // The author must also be identified: an empty or placeholder name
        // (NOASSERTION, TBD) names no entity.
        let has_person_or_org = sbom
            .document
            .creators
            .iter()
            .any(|c| c.creator_type != CreatorType::Tool && creator_identified(c));
        if !has_person_or_org {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::DocumentMetadata,
                message: "[CISA 2026] SBOM Author missing: no Person or Organization creator \
                          names the entity that created the SBOM data (tool-only creator lists \
                          do not satisfy the element — the author is the entity operating the \
                          tool, not the tool itself)"
                    .to_string(),
                element: None,
                requirement: "CISA 2026 Minimum Elements: SBOM Author".to_string(),
                rule_id: "SBOM-CISA2026-AUTHOR",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                deadline: None,
            });
        }

        // SBOM Author Signature (Warning — evidence-limited). In-document
        // evidence exists only as a CycloneDX JSF signature or an SPDX 3
        // verifiedUsing signature entry; SPDX 2.x cannot express a signature
        // in-document, so the check skips it, and detached signatures are
        // invisible to a document checker, so absence must not hard-fail the
        // run. Presence is structural (algorithm + non-empty value) — nothing
        // is cryptographically verified.
        let has_signature = document_signed(sbom);
        if !has_signature && !spdx2 {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::DocumentMetadata,
                message: "[CISA 2026] No SBOM Author Signature found in the document (CycloneDX \
                          JSF signature or SPDX 3 verifiedUsing signature); SPDX 2.x cannot \
                          express one in-document and detached signatures are invisible to this \
                          check"
                    .to_string(),
                element: None,
                requirement: "CISA 2026 Minimum Elements: SBOM Author Signature".to_string(),
                rule_id: "SBOM-CISA2026-SIGNATURE",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                deadline: None,
            });
        }

        // SBOM Data Format Name / Version + Machine-Processable Data
        // (Warning). The format name is vacuously satisfied post-parse; the
        // enforceable check is the deprecated-version gate. CISA names no
        // deprecated versions ("versions declared to be deprecated by the
        // organizations maintaining the data format should not be used"), so
        // the concrete floor — CycloneDX 1.4+ / SPDX 2.2+ — is tool policy
        // mirroring the repo's EO 14028 machine-readable gate, and the
        // message says so. Unparseable/absent spec versions skip the gate
        // rather than false-failing (`DocumentMetadata::spec_version_parsed`).
        let minimum = match sbom.document.format {
            SbomFormat::CycloneDx => crate::model::SpecVersion::new(1, 4, 0),
            SbomFormat::Spdx => crate::model::SpecVersion::new(2, 2, 0),
        };
        if let Some(actual) = sbom.document.spec_version_parsed()
            && actual < minimum
        {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::FormatSpecific,
                message: format!(
                    "[CISA 2026] {} {} is an outdated release of the data format; this tool's \
                     policy floor is CycloneDX 1.4+ / SPDX 2.2+ (CISA itself names no deprecated \
                     versions — the floor mirrors the EO 14028 machine-readable gate)",
                    sbom.document.format, sbom.document.spec_version
                ),
                element: None,
                requirement: "CISA 2026 Minimum Elements: SBOM Data Format Name/Version \
                              (Machine-Processable Data)"
                    .to_string(),
                rule_id: "SBOM-CISA2026-FORMAT",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                deadline: None,
            });
        }

        // SBOM Generation Context (Warning — evidence-limited): the relative
        // lifecycle phase at generation time ("before build" / "build" /
        // "after build", or a more specific identifier — free-form names are
        // accepted per the element). Only CycloneDX 1.5+ metadata.lifecycles
        // populates the field. SPDX 2.x has no standard field, so the check
        // skips it; SPDX 3 sbomType is not parsed yet, which keeps this a
        // Warning rather than an Error.
        if !spdx2 && known_value(sbom.document.lifecycle_phase.as_deref()).is_none() {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::DocumentMetadata,
                message: "[CISA 2026] SBOM Generation Context missing: no software lifecycle \
                          phase is declared (CycloneDX 1.5+ metadata.lifecycles, e.g. \
                          'pre-build', 'build', 'post-build'; SPDX 2.x has no standard field)"
                    .to_string(),
                element: None,
                requirement: "CISA 2026 Minimum Elements: SBOM Generation Context".to_string(),
                rule_id: "SBOM-CISA2026-GENERATION-CONTEXT",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                deadline: None,
            });
        }

        // SBOM Timestamp (Error) — "date and time of the most recent update
        // to the SBOM data". Parsers normalize timestamps to DateTime<Utc>
        // and substitute the UNIX_EPOCH sentinel for a missing/unparseable
        // source value, so the check degrades to has_known_timestamp(): the
        // element's RFC 9557 source-syntax requirement is unverifiable
        // post-normalization and is NOT claimed to be checked here. A value
        // the parser could not read is quoted.
        if !sbom.document.has_known_timestamp() {
            let message = unparseable_timestamp(sbom).map_or_else(
                || {
                    "[CISA 2026] SBOM Timestamp missing or invalid: no date/time of the \
                     most recent update to the SBOM data (the element targets RFC 9557 \
                     syntax; source syntax is not verified post-normalization)"
                        .to_string()
                },
                |gap| {
                    format!(
                        "[CISA 2026] SBOM Timestamp invalid: the SBOM has {gap}, so it gives \
                         no date/time of the most recent update to the SBOM data"
                    )
                },
            );
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::DocumentMetadata,
                message,
                element: None,
                requirement: "CISA 2026 Minimum Elements: SBOM Timestamp".to_string(),
                rule_id: "SBOM-CISA2026-TIMESTAMP",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                deadline: None,
            });
        }

        // SBOM Tool Name (Error) and SBOM Tool Version (Warning —
        // heuristic). The version check only runs when a tool is identified
        // at all: with no Tool creator the TOOL rule already covers the gap,
        // and firing both would double-report one omission.
        let tool_creators: Vec<_> = sbom
            .document
            .creators
            .iter()
            .filter(|c| c.creator_type == CreatorType::Tool)
            .collect();
        if tool_creators.is_empty() {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::DocumentMetadata,
                message: "[CISA 2026] SBOM Tool Name missing: no generation tool is identified \
                          (CycloneDX metadata.tools; SPDX 'Creator: Tool:')"
                    .to_string(),
                element: None,
                requirement: "CISA 2026 Minimum Elements: SBOM Tool Name".to_string(),
                rule_id: "SBOM-CISA2026-TOOL",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                deadline: None,
            });
        } else if !tool_creators
            .iter()
            .any(|t| tool_name_carries_version(&t.name))
        {
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::DocumentMetadata,
                message: "[CISA 2026] SBOM Tool Version not discernible: no identified tool \
                          carries a version identifier or an explicit unknown marker (heuristic \
                          check — parsers concatenate tool name and version into one creator \
                          name, so a dedicated tool-version field cannot be inspected)"
                    .to_string(),
                element: None,
                requirement: "CISA 2026 Minimum Elements: SBOM Tool Version".to_string(),
                rule_id: "SBOM-CISA2026-TOOL-VERSION",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                deadline: None,
            });
        }

        // SBOM Version (Warning — evidence-limited). The document should
        // declare its own version: CycloneDX bom.version surfaces as
        // DocumentMetadata.doc_version (the parser preserves absence as None
        // — no default-1 backfill), and a version-distinguishing serial
        // identifier (CycloneDX serialNumber / SPDX documentNamespace,
        // RFC 9562-style) is accepted as alternative evidence. A CycloneDX
        // document that omits bom.version AND carries no serialNumber has
        // declared nothing version-distinguishing and fails — this check
        // deliberately does not honour the CycloneDX default of 1, because
        // the element asks the author to declare the version, not the parser
        // to assume it. Warning because SPDX 2.x has no dedicated
        // document-version field at all.
        let declares_version = sbom.document.doc_version.is_some()
            || known_value(sbom.document.serial_number.as_deref()).is_some();
        if !declares_version {
            let message = match sbom.document.format {
                SbomFormat::CycloneDx => {
                    "[CISA 2026] SBOM Version missing: the document omits bom.version (absence \
                     is not backfilled with the CycloneDX default of 1) and carries no \
                     serialNumber to distinguish document versions"
                }
                SbomFormat::Spdx => {
                    "[CISA 2026] SBOM Version missing: SPDX 2.x has no document-version field \
                     and no version-distinguishing documentNamespace is present"
                }
            };
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::DocumentMetadata,
                message: message.to_string(),
                element: None,
                requirement: "CISA 2026 Minimum Elements: SBOM Version".to_string(),
                rule_id: "SBOM-CISA2026-SBOM-VERSION",
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
                remediation: None,
                finding_detail: None,
                deadline: None,
            });
        }

        // Per-component data fields.
        for comp in sbom.components.values() {
            // Component Name (Error) — applies to every enumerated entry.
            // Placeholder sentinels count as missing unless corroborated by
            // a matching identifier (known_component_name).
            if !known_component_name(comp) {
                violations.push(Violation {
                    severity: ViolationSeverity::Error,
                    category: ViolationCategory::ComponentIdentification,
                    message: "[CISA 2026] Component must have the name assigned by its producer"
                        .to_string(),
                    element: Some(comp.identifiers.format_id.clone()),
                    requirement: "CISA 2026 Minimum Elements: Component Name".to_string(),
                    rule_id: "SBOM-CISA2026-NAME",
                    component_id: Some(comp.canonical_id.value().to_string()),
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            }

            // File/snippet inventory entries (name+hash records) and
            // cryptographic assets are not packages: the producer / version /
            // identifier / hash / license elements below do not apply to them
            // (same carve-out as the NTIA-path checks — without it a
            // file-cataloguing SBOM emits thousands of spurious Errors).
            if !comp.component_type.is_package_scoped() {
                continue;
            }

            // Component Producer (Error) — the 2026 rename of the ambiguous
            // "Supplier Name". Author/originator (SPDX PackageOriginator) is
            // the closest evidence for "the entity that creates, defines,
            // and identifies components"; supplier and manufacturer are
            // accepted; an explicit unknown-provenance marker satisfies the
            // element's escape hatch ("the SBOM author should explicitly mark
            // the component as of unknown provenance"). Only silent absence
            // fails.
            let producer_named = has_known_producer(comp);
            let producer_marked_unknown = comp
                .supplier
                .iter()
                .chain(&comp.manufacturer)
                .any(|o| is_unknown_marker(o.name.trim()))
                || comp
                    .author
                    .as_deref()
                    .is_some_and(|a| is_unknown_marker(a.trim()));
            if !producer_named && !producer_marked_unknown {
                violations.push(Violation {
                    severity: ViolationSeverity::Error,
                    category: ViolationCategory::SupplierInfo,
                    message: format!(
                        "[CISA 2026] Component '{}' names no producer (author/originator, \
                         manufacturer or supplier) and is not explicitly marked as of unknown provenance",
                        comp.name
                    ),
                    element: Some(comp.name.clone()),
                    requirement: "CISA 2026 Minimum Elements: Component Producer".to_string(),
                    rule_id: "SBOM-CISA2026-PRODUCER",
                    component_id: Some(comp.canonical_id.value().to_string()),
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            }

            // Component Version (Error). Explicit-unknown markers
            // (NOASSERTION/'unknown') satisfy the 2026 escape hatch and pass
            // — the honesty requirement is the point of the Major Update.
            // Silent absence fails, and so do placeholders such as "TBD" or
            // "N/A": they neither give a version nor state it is unknown.
            let version_declared = value_state(comp.version.as_deref()) != ValueState::Missing;
            if !version_declared {
                violations.push(Violation {
                    severity: ViolationSeverity::Error,
                    category: ViolationCategory::ComponentIdentification,
                    message: format!(
                        "[CISA 2026] Component '{}' is missing a version and does not explicitly \
                         indicate the version is unknown",
                        comp.name
                    ),
                    element: Some(comp.name.clone()),
                    requirement: "CISA 2026 Minimum Elements: Component Version".to_string(),
                    rule_id: "SBOM-CISA2026-VERSION",
                    component_id: Some(comp.canonical_id.value().to_string()),
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            }

            // Component Identifiers (Error) — at least one common,
            // machine-processable identifier. Evidence: PURL/CPE/SWHID/SWID
            // (the model's identifier set). "Include all known identifiers"
            // is unenforceable (no oracle for what the author knew) and
            // stays out of the check.
            if !comp.identifiers.has_cra_identifier() {
                violations.push(Violation {
                    severity: ViolationSeverity::Error,
                    category: ViolationCategory::ComponentIdentification,
                    message: format!(
                        "[CISA 2026] Component '{}' has no machine-processable identifier \
                         (CPE or PURL are named by the element; SWHID/SWID also qualify)",
                        comp.name
                    ),
                    element: Some(comp.name.clone()),
                    requirement: "CISA 2026 Minimum Elements: Component Identifiers".to_string(),
                    rule_id: "SBOM-CISA2026-IDENTIFIER",
                    component_id: Some(comp.canonical_id.value().to_string()),
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            }

            // Component Hash Value (Error) + Component Hash Algorithm
            // (Warning). Only author-attested hashes count: enrichment adds
            // registry-fetched hashes to the same field post-parse, and
            // those are not part of the document under assessment (same
            // provenance posture as the BSI §5.2.2 hash check). The value
            // must be ASCII-hexadecimal per the element, and as long as the
            // algorithm's digest (the shared `plausible_digest` check every
            // hash rule uses); an explicit unknown marker satisfies the
            // escape hatch for authors without access to the executable
            // artifact.
            let authored: Vec<_> = comp
                .hashes
                .iter()
                .filter(|h| h.provenance == HashProvenance::Authored)
                .collect();
            let has_hex_value = authored
                .iter()
                .any(|h| plausible_digest(&h.algorithm, &h.value));
            let hash_marked_unknown = authored.iter().any(|h| is_unknown_marker(h.value.trim()));
            if authored.is_empty() {
                violations.push(Violation {
                    severity: ViolationSeverity::Error,
                    category: ViolationCategory::IntegrityInfo,
                    message: format!(
                        "[CISA 2026] Component '{}' carries no cryptographic hash of the \
                         executable component artifact (explicitly indicate the value is \
                         unknown when the artifact is not available to the SBOM author)",
                        comp.name
                    ),
                    element: Some(comp.name.clone()),
                    requirement: "CISA 2026 Minimum Elements: Component Hash Value".to_string(),
                    rule_id: "SBOM-CISA2026-HASH",
                    component_id: Some(comp.canonical_id.value().to_string()),
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            } else if !has_hex_value && !hash_marked_unknown {
                violations.push(Violation {
                    severity: ViolationSeverity::Error,
                    category: ViolationCategory::IntegrityInfo,
                    message: format!(
                        "[CISA 2026] Component '{}' declares hash value(s) that are not \
                         ASCII-hexadecimal digests of their algorithm, as the element requires: {}",
                        comp.name,
                        digest_problems(authored.iter().copied()).join("; ")
                    ),
                    element: Some(comp.name.clone()),
                    requirement: "CISA 2026 Minimum Elements: Component Hash Value".to_string(),
                    rule_id: "SBOM-CISA2026-HASH",
                    component_id: Some(comp.canonical_id.value().to_string()),
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            } else {
                // Hash-value evidence is sound — assess the algorithms (see
                // `hash_algorithm_shortfall`). "Should be approved by a
                // relevant authority" is a 'should', hence Warning. One
                // strong hash (an acceptable algorithm with a plausible
                // digest) satisfies the element: the cyclonedx-maven-plugin,
                // for one, emits MD5 and SHA-1 beside SHA-256 and SHA-512 by
                // default, and weak digests next to a strong one take nothing
                // away. Components with only weak hashes still warn.
                let offending: Vec<String> = authored
                    .iter()
                    .filter_map(|h| hash_algorithm_shortfall(&h.algorithm))
                    .collect();
                let has_strong_hash = authored.iter().any(|h| {
                    hash_algorithm_shortfall(&h.algorithm).is_none()
                        && plausible_digest(&h.algorithm, &h.value)
                });
                if !offending.is_empty() && !has_strong_hash {
                    violations.push(Violation {
                        severity: ViolationSeverity::Warning,
                        category: ViolationCategory::IntegrityInfo,
                        message: format!(
                            "[CISA 2026] Component '{}' declares hash algorithm(s) that are not \
                             approved by a relevant authority or not identifiable by an IANA \
                             Hash Function Textual Name: {}",
                            comp.name,
                            truncate_list(&offending, 5)
                        ),
                        element: Some(comp.name.clone()),
                        requirement: "CISA 2026 Minimum Elements: Component Hash Algorithm"
                            .to_string(),
                        rule_id: "SBOM-CISA2026-HASH-ALGO",
                        component_id: Some(comp.canonical_id.value().to_string()),
                        counts: None,
                        standard_refs: Vec::new(),
                        remediation: None,
                        finding_detail: None,
                        deadline: None,
                    });
                }
            }

            // Component License (Error). Any real declared/concluded
            // expression counts: SPDX identifiers are preferred, but
            // LicenseRef-* expressions, license names, and URL pointers all
            // satisfy "indicate through other means where the full license
            // details are available", and NOASSERTION is the element's
            // explicit unknown. The licence test is the one every standard
            // shares (`license_state`), which also accepts the explicit
            // unknown here: absence and a placeholder such as TBD fail, as
            // everywhere (until v0.4.0 any non-empty value passed).
            let has_license_info = license_state(comp) != ValueState::Missing;
            if !has_license_info {
                violations.push(Violation {
                    severity: ViolationSeverity::Error,
                    category: ViolationCategory::LicenseInfo,
                    message: format!(
                        "[CISA 2026] Component '{}' has no license information and no explicit \
                         unknown indication (prefer SPDX identifiers; use NOASSERTION when the \
                         license is unknown to the author)",
                        comp.name
                    ),
                    element: Some(comp.name.clone()),
                    requirement: "CISA 2026 Minimum Elements: Component License".to_string(),
                    rule_id: "SBOM-CISA2026-LICENSE",
                    component_id: Some(comp.canonical_id.value().to_string()),
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            }
        }

        // Component Dependency Relationship (Error) — "the relationship
        // between two components, where one component is necessary for the
        // operation of the other". A single-component SBOM has no
        // relationships to express; a multi-component SBOM must declare a
        // dependency graph, or link to separate SBOM documents per
        // dependency (the element's linking allowance — an external
        // reference of BOM type is accepted as alternative evidence).
        // Dependency relationships between packages: crypto assets, files
        // and services need not join the graph.
        if package_components(sbom).nth(1).is_some() && sbom.edges.is_empty() {
            let has_external_sbom_link = sbom.components.values().any(|c| {
                c.external_refs
                    .iter()
                    .any(|r| matches!(r.ref_type, ExternalRefType::Bom))
            });
            if !has_external_sbom_link {
                violations.push(Violation {
                    severity: ViolationSeverity::Error,
                    category: ViolationCategory::DependencyInfo,
                    message: "[CISA 2026] SBOM enumerates multiple components but declares no \
                              dependency relationships and links no external SBOM documents"
                        .to_string(),
                    element: None,
                    requirement: "CISA 2026 Minimum Elements: Component Dependency Relationship"
                        .to_string(),
                    rule_id: "SBOM-CISA2026-DEPENDENCY",
                    component_id: None,
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            }
        }

        // Coverage / Explicitly Identifying Unknown Information (Warning) —
        // document-level honesty check for the two partially-checkable
        // practices: the SBOM should declare its completeness (CycloneDX
        // compositions aggregate). This rule verifies the *declaration*, not
        // actual completeness — the 2026 document itself points to external
        // repositories / binary analysis for that. A declared-incomplete
        // inventory still warns (the 2026 Coverage element expects all
        // components including transitive dependencies) but with a message
        // acknowledging the declaration is honest. SPDX 2.x cannot declare
        // completeness at all, so the check skips it.
        match sbom.document.completeness_declaration {
            _ if spdx2 => {}
            CompletenessDeclaration::Unknown | CompletenessDeclaration::NotSpecified => {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::DependencyInfo,
                    message: "[CISA 2026] Coverage: the SBOM does not declare its completeness \
                              (CycloneDX compositions aggregate); information gaps must be \
                              explicitly stated as unknown or deliberately withheld"
                        .to_string(),
                    element: None,
                    requirement: "CISA 2026 Minimum Elements: Coverage / Explicitly Identifying \
                                  Unknown Information"
                        .to_string(),
                    rule_id: "SBOM-CISA2026-COVERAGE",
                    component_id: None,
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            }
            CompletenessDeclaration::Incomplete
            | CompletenessDeclaration::IncompleteFirstPartyOnly
            | CompletenessDeclaration::IncompleteThirdPartyOnly => {
                violations.push(Violation {
                    severity: ViolationSeverity::Warning,
                    category: ViolationCategory::DependencyInfo,
                    message: format!(
                        "[CISA 2026] Coverage: the SBOM declares an incomplete inventory \
                         ({}); the declaration is honest, but the 2026 Coverage element expects \
                         all components including transitive dependencies — close the gap or \
                         link the missing SBOM documents",
                        sbom.document.completeness_declaration
                    ),
                    element: None,
                    requirement: "CISA 2026 Minimum Elements: Coverage / Explicitly Identifying \
                                  Unknown Information"
                        .to_string(),
                    rule_id: "SBOM-CISA2026-COVERAGE",
                    component_id: None,
                    counts: None,
                    standard_refs: Vec::new(),
                    remediation: None,
                    finding_detail: None,
                    deadline: None,
                });
            }
            CompletenessDeclaration::Complete => {}
        }
    }
}
