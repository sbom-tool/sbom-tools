//! CISA Framing Software Component Transparency (3rd ed.) profile checks.
//!
//! Standard: "Framing Software Component Transparency: Establishing a Common
//! Software Bill of Materials (SBOM)", Third Edition (SBOM Tooling and
//! Implementation Working Group, hosted by CISA; document date 2024-09-03,
//! published 2024-10-15). Community-consensus, non-regulatory guidance —
//! distinct from the CISA "Minimum Elements" document line.
//!
//! The document's maturity tiers map onto severities: Minimum Expected →
//! Error, Recommended Practice → Warning, Aspirational Goal → Info. The
//! tier structure is asymmetric and must be preserved: Timestamp, Component
//! Name, Version, and Supplier Name are untiered (untiered text = Minimum
//! Expected); Author Name, Unique Identifier, and Cryptographic Hash have
//! no Aspirational tier; SBOM Type (§2.2.1.3) is wholly optional/
//! aspirational; Redacted Components (§2.3.2) has no rule (the model cannot
//! represent redaction markers).
//!
//! Evidence gates (checks constrained to formats whose parsed model can
//! carry the evidence, so absence never false-fails a format that cannot
//! express the attribute):
//! - `SBOM-FSCT-SBOM-TYPE`: `document.lifecycle_phase` is populated only by
//!   the CycloneDX parser (`metadata.lifecycles`). SPDX 2.x maps SBOM Type
//!   via `CreatorComment` per Table 1 and SPDX 3.0 via `Software.Sbom
//!   .sbomType`, but neither evidence path is parsed here — the check is
//!   gated to CycloneDX input.
//! - `SBOM-FSCT-SIGNATURE`: SPDX 2.x has no in-band signature field, so the
//!   check skips it (see `is_spdx2`); CycloneDX (JSF or XML-DSig
//!   `signature`) and SPDX 3 (`verifiedUsing` signature) are checked, as
//!   `SBOM-CISA2026-SIGNATURE` checks them.
//! - `SBOM-FSCT-DYNAMIC-DEPS`: dynamic/runtime/provided link relationships
//!   are parsed only from SPDX relationships (`DYNAMIC_LINK`,
//!   `RUNTIME_DEPENDENCY_OF`, `PROVIDED_DEPENDENCY_OF`); CycloneDX's
//!   dependency graph cannot express the positive signal, so the readiness
//!   note is gated to SPDX input.
//! - `SBOM-FSCT-LICENSE-CONCLUDED` (the concluded-attestation prong of
//!   `SBOM-FSCT-LICENSE-ALL`): concluded licenses are parsed only from SPDX
//!   `PackageLicenseConcluded`; the CycloneDX 1.6
//!   `licenses[].acknowledgement` field is not parsed, so the prong is gated
//!   to SPDX input.
//!
//! A gated check is listed as not evaluated on the formats it skips, so its
//! silence there does not read as a pass.
//!
//! Profile-policy heuristics (documented as policy, not standard text —
//! "as many as possible"-style tiers are not crisply verifiable from the
//! document alone): the ≥2-identifier-kinds threshold
//! (`SBOM-FSCT-IDENTIFIER-MULTI`), the ≥50% license/copyright coverage
//! floors (`SBOM-FSCT-LICENSE-COVERAGE` / `SBOM-FSCT-COPYRIGHT-COVERAGE`),
//! the depth≥2 transitive threshold (`SBOM-FSCT-TRANSITIVE-DEPS`), and the
//! strict global-identifier requirement (`SBOM-FSCT-IDENTIFIER` — §2.2.2.4
//! only "prefers" global uniqueness and Table 1 accepts format-native IDs;
//! this profile deliberately enforces the preferred clause, per the
//! registry's remediation text).
//!
//! §2.3.1 posture (corrected reading): a baseline attribute is satisfied
//! when populated OR explicitly declared no-assertion/no-value (the
//! `NOASSERTION`/`NONE`/`UNKNOWN` sentinels), and formats may treat missing
//! attributes as default no-assertion. `SBOM-FSCT-NOASSERTION` therefore
//! fires only on AMBIGUOUS placeholders ("TBD", "N/A", …) that neither
//! populate the attribute nor explicitly declare no-assertion. Placeholder
//! sentinels still never satisfy the other `SBOM-FSCT-*` checks (mirrors
//! the repo's P0 placeholder-NOASSERTION fix), with one documented
//! exception: §2.2.2.3 explicitly permits a declared `unknown` Supplier.
//!
//! The rule catalogue for this profile lives in the registry
//! (`SBOM-FSCT-*`, see `FSCT_SARIF_RULE_IDS`).
//!
//! The checks read the run's evidence (see [`super::evidence`]), never the
//! SBOM itself.

use super::evidence::SbomEvidence;
use super::shared::unparseable_timestamp_of;
use super::*;
use crate::model::{CompletenessDeclaration, CreatorType, SbomFormat};

impl ComplianceChecker {
    // ════════════════════════════════════════════════════════════════════
    // CISA FSCT 3rd Edition — baseline attributes across maturity tiers
    // ════════════════════════════════════════════════════════════════════

    /// CISA FSCT 3e compliance checks: one evidence pass over the document,
    /// then per-tier emission (Minimum Expected → Error, Recommended
    /// Practice → Warning, Aspirational Goal → Info).
    pub(crate) fn check_fsct(&self, ctx: &ComplianceContext<'_, '_>, findings: &mut Findings) {
        let Findings {
            violations,
            not_evaluated,
            ..
        } = findings;
        let evidence = FsctEvidence::collect(ctx);
        fsct_minimum_expected(ctx.ev, &evidence, violations);
        fsct_recommended_practice(ctx.ev, &evidence, violations);
        fsct_aspirational_goals(ctx.ev, &evidence, violations, not_evaluated);
    }
}

/// Why SBOM-FSCT-DYNAMIC-DEPS did not run on CycloneDX (see the module docs).
const CYCLONEDX_NO_DYNAMIC_DEPS: &str =
    "a CycloneDX dependency graph cannot mark a dependency dynamic, runtime or provided";

/// Why SBOM-FSCT-LICENSE-CONCLUDED did not run on CycloneDX.
const CYCLONEDX_CONCLUDED_NOT_READ: &str = "sbom-tools reads concluded licenses from SPDX \
     (PackageLicenseConcluded) only, not the CycloneDX licenses[].acknowledgement";

/// Why SBOM-FSCT-SBOM-TYPE did not run on SPDX.
const SPDX_SBOM_TYPE_NOT_READ: &str = "sbom-tools reads the SBOM type from CycloneDX \
     metadata.lifecycles only, not from an SPDX document";

/// Whether the completeness of the dependency enumeration is genuinely
/// undeclared (no recorded assertion). Any explicit declaration — including
/// `Incomplete` — counts as the §2.2.2.6.4 / §2.3.3 "indicates when the
/// dependency list is incomplete" signal.
const fn completeness_undeclared(declaration: &CompletenessDeclaration) -> bool {
    matches!(
        declaration,
        CompletenessDeclaration::Unknown | CompletenessDeclaration::NotSpecified
    )
}

// Ambiguous placeholders (§2.3.1) are `shared::is_placeholder`: values that
// neither populate a baseline attribute nor explicitly declare
// no-assertion/no-value. The explicit sentinels (`NOASSERTION`, `NONE`,
// `UNKNOWN`) are deliberately not on that list — §2.3.1 sanctions them as
// the graceful way to differentiate "no assertion" (data missing) from "no
// value" (not applicable).

/// FSCT's view of the run's evidence: the lists and flags the three tier
/// emitters below read, built in one walk over the inventory, in its order.
struct FsctEvidence {
    /// All components (including File/snippet inventory entries).
    total: usize,
    /// Package-like components — File/snippet inventory entries are
    /// name+hash records, not packages, and are exempt from the
    /// version/supplier/identifier/hash/license/copyright attributes
    /// (mirrors the generic checker's File carve-out).
    pkg_total: usize,
    /// Components without a real public name (§2.2.2.1).
    nameless: usize,
    /// Package components with neither a version nor the documented
    /// authored-hash fallback (§2.2.2.2).
    without_version: Vec<String>,
    /// Package components with no Supplier declaration at all — an explicit
    /// `unknown` counts as declared per §2.2.2.3 (§ text: permitted last
    /// resort), silent absence does not.
    without_supplier: Vec<String>,
    /// Package components with no globally unique identifier and no
    /// authored hash (accepted as intrinsic identifier per §2.2.2.4).
    without_identifier: Vec<String>,
    /// Package components declaring fewer than two identifier kinds, of
    /// the §2.2.2.4 named schemes the model carries (PURL / CPE / SWHID /
    /// SWID) (§2.2.2.4 Recommended, profile-policy threshold).
    fewer_than_two_identifier_kinds: Vec<String>,
    /// Package components with no author-provided, plausible hash
    /// (§2.2.2.5 — enrichment-fetched hashes are not author evidence), each
    /// named with why its present hashes did not count.
    without_hash: Vec<String>,
    /// Package components that carry authored hashes but none from the
    /// SHA-2 ≥256 family (§2.2.2.5 Recommended), named as `without_hash`.
    weak_hash_only: Vec<String>,
    /// Package components with no real license expression (§2.2.2.7).
    without_license: Vec<String>,
    /// Package components with no real copyright notice (§2.2.2.8).
    without_copyright: Vec<String>,
    /// Components carrying ambiguous placeholder attribute values
    /// (§2.3.1), rendered as "name (field, …)".
    ambiguous_placeholders: Vec<String>,
    /// The first ambiguous placeholder value read, as written ("TBD").
    first_placeholder: Option<String>,
    /// Whether any component carries a concluded license (SPDX
    /// `PackageLicenseConcluded` — the §2.2.2.7 Aspirational attestation).
    has_concluded_license: bool,
    /// Whether `primary_component_id` resolves to a component.
    primary_resolvable: bool,
    /// Outgoing edges from the primary component.
    direct_edge_count: usize,
    /// Direct-dependency edge targets that resolve to no component in the
    /// inventory (§2.2.2 Minimum: direct dependencies must be identified).
    unresolved_direct: Vec<String>,
    /// Whether the primary positively asserted it has no dependencies.
    primary_declared_no_deps: bool,
    /// Whether any edge starts at a direct dependency (depth ≥ 2).
    has_depth2_edges: bool,
    /// Whether every resolvable direct dependency positively asserted it
    /// has no dependencies (explains the absence of depth-2 edges).
    all_direct_declared_leaf: bool,
    /// Whether the primary participates in the edge set at all.
    primary_in_edge_set: bool,
    /// Non-primary package components that appear in no dependency edge,
    /// whether or not they assert they have no dependencies.
    orphans: Vec<String>,
    /// Whether any edge carries a dynamic/runtime/provided relationship
    /// (the §2.2.2 / §2.2.2.6 Aspirational positive signal).
    has_dynamic_edge: bool,
    /// Direct dependencies with neither nested transitive data (children
    /// edges or a declared-empty assertion) nor a BOM-type external
    /// reference linking the upstream supplier's SBOM (§2.3.3 Recommended).
    direct_without_upstream: Vec<String>,
}

impl FsctEvidence {
    #[allow(clippy::too_many_lines)]
    fn collect(ctx: &ComplianceContext<'_, '_>) -> Self {
        let ev = ctx.ev;
        let total = ev.component_count();
        let mut pkg_total = 0usize;
        let mut nameless = 0usize;
        let mut without_version = Vec::new();
        let mut without_supplier = Vec::new();
        let mut without_identifier = Vec::new();
        let mut fewer_than_two_identifier_kinds = Vec::new();
        let mut without_hash = Vec::new();
        let mut weak_hash_only = Vec::new();
        let mut without_license = Vec::new();
        let mut without_copyright = Vec::new();
        let mut ambiguous_placeholders = Vec::new();
        let mut first_placeholder = None;
        let mut has_concluded_license = false;
        let mut orphans = Vec::new();

        for comp in ev.components() {
            // §2.2.2.1 applies to every inventory entry, File records
            // included (a file's name is exactly what identifies it).
            if !comp.name_known() {
                nameless += 1;
            }

            // File/snippet entries and cryptographic assets are exempt from
            // the remaining per-component baseline attributes (see field doc
            // above).
            if !ctx.judges_package(&comp) {
                continue;
            }
            pkg_total += 1;

            // Only author-provided, plausible digests count (see
            // `plausible_digest`): an empty or garbage value is neither a
            // hash nor an intrinsic identifier, and the findings name why.
            // §2.2.2.5 Recommended names the "SHA-2 family (SHA-256 and
            // higher)". Deliberate literal reading: SHA-3 / BLAKE /
            // Streebog are not counted — accepting them would extend beyond
            // the document's text.
            let authored = comp.authored_hashes();
            let has_authored_hash = authored.facts.plausible;
            let has_sha2_256_plus = authored.facts.plausible_sha2_256_plus;
            let named = || name_with_digest_problems(comp.name(), authored.iter());

            // §2.2.2.2: version, with the documented fallback — a component
            // without a unique version passes only via an authored hash.
            if !comp.version().is_known() && !has_authored_hash {
                without_version.push(comp.name().to_string());
            }

            // §2.2.2.3: Supplier declared. Raw presence counts — an
            // explicit `unknown`/`NOASSERTION` is a permitted (discouraged)
            // declaration that must be distinguished from silent absence.
            if !comp.supplier_declared() {
                without_supplier.push(comp.name().to_string());
            }

            // §2.2.2.4 Minimum: globally unique identifier (PURL/CPE/SWHID/
            // SWID) or the cryptographic hash as intrinsic identifier.
            let ids = comp.ids();
            if !ids.any() && !has_authored_hash {
                without_identifier.push(comp.name().to_string());
            }
            // §2.2.2.4 Recommended: ≥2 identifier kinds (profile policy).
            if ids.count() < 2 {
                fewer_than_two_identifier_kinds.push(comp.name().to_string());
            }

            // §2.2.2.5: authored hash present; weak-only inventory for the
            // Recommended tier.
            if has_authored_hash {
                if !has_sha2_256_plus {
                    weak_hash_only.push(named());
                }
            } else {
                without_hash.push(named());
            }

            // §2.2.2.7 / §2.2.2.8 coverage inputs.
            if !comp.licenses().is_known() {
                without_license.push(comp.name().to_string());
            }
            if comp.concluded_license().is_known() {
                has_concluded_license = true;
            }
            if !comp.copyright().is_known() {
                without_copyright.push(comp.name().to_string());
            }

            // §2.3.1: ambiguous placeholders (see `is_placeholder`).
            let found = comp.placeholders();
            let mut fields = Vec::new();
            let mut placeholders: Vec<&str> = Vec::new();
            for (field, value) in [
                ("version", found.version),
                ("supplier", found.supplier),
                ("license", found.license),
                ("copyright", found.copyright),
            ] {
                if let Some(value) = value {
                    fields.push(field);
                    placeholders.push(value);
                }
            }
            if first_placeholder.is_none() {
                first_placeholder = placeholders.first().map(|p| (*p).to_string());
            }
            if !fields.is_empty() {
                ambiguous_placeholders.push(format!("{} ({})", comp.name(), fields.join(", ")));
            }

            // Relationships are a package-graph element: files, crypto
            // assets and services need not appear in the dependency graph.
            if !comp.touched() && !comp.is_primary() {
                orphans.push(comp.name().to_string());
            }
        }

        // Graph evidence, scoped to the primary component (§2.2.1.4 makes
        // the primary the subject; when it is missing or unresolvable,
        // SBOM-FSCT-PRIMARY fires and the primary-scoped graph checks have
        // no subject to reason about). The direct dependencies are in edge
        // order, so findings come out in the same order on every run.
        let graph = ev.graph();
        let primary = ev.primary();
        let primary_resolvable = primary.is_some();
        let primary_declared_no_deps = primary.is_some_and(|p| p.declares_no_dependencies());
        let primary_in_edge_set = primary.is_some_and(|p| p.touched());
        let direct = || graph.direct.iter().map(|ix| ev.component(*ix));
        let unresolved_direct = graph
            .unresolved_direct
            .iter()
            .map(|id| id.value().to_string())
            .collect();
        let has_depth2_edges = direct().any(|d| d.has_outgoing());
        let all_direct_declared_leaf =
            !graph.direct.is_empty() && direct().all(|d| d.declares_no_dependencies());

        // §2.3.3 Recommended: a direct dependency's upstream SBOM data is
        // evidenced by nested transitive data (children edges, or a positive
        // no-dependencies assertion) or a BOM-type external reference.
        let direct_without_upstream = direct()
            .filter(|d| {
                ctx.judges_package(d)
                    && !d.has_outgoing()
                    && !d.declares_no_dependencies()
                    && !d.bom_reference()
            })
            .map(|d| d.name().to_string())
            .collect();

        Self {
            total,
            pkg_total,
            nameless,
            without_version,
            without_supplier,
            without_identifier,
            fewer_than_two_identifier_kinds,
            without_hash,
            weak_hash_only,
            without_license,
            without_copyright,
            ambiguous_placeholders,
            first_placeholder,
            has_concluded_license,
            primary_resolvable,
            direct_edge_count: graph.direct_edge_count,
            unresolved_direct,
            primary_declared_no_deps,
            has_depth2_edges,
            all_direct_declared_leaf,
            primary_in_edge_set,
            orphans,
            has_dynamic_edge: graph.dynamic_edge,
            direct_without_upstream,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════
// Tier 1 — Minimum Expected (Error)
//
// §2.2.1.1 Author Name, §2.2.1.2 Timestamp, §2.2.1.4 Primary Component,
// §2.2.2/§2.3.3 direct dependencies, §2.2.2.1 Component Name, §2.2.2.2
// Version, §2.2.2.3 Supplier Name, §2.2.2.4 Unique Identifier, §2.2.2.5
// Cryptographic Hash, §2.2.2.6 Relationship, §2.2.2.7 License (primary),
// §2.2.2.8 Copyright (primary), §2.3.1 undeclared data.
//
// "Error" means "fails the profile's Minimum Expected tier" — the document
// is non-regulatory community guidance, not law.
// ════════════════════════════════════════════════════════════════════════

#[allow(clippy::too_many_lines)]
fn fsct_minimum_expected(
    ev: &SbomEvidence<'_>,
    evidence: &FsctEvidence,
    violations: &mut Vec<Violation>,
) {
    let total = evidence.total;
    let pkg_total = evidence.pkg_total;
    let doc = ev.document();

    // §2.2.1.1 (Minimum) — Author Name: the entity that prompted the SBOM's
    // creation. A tool-only creator list does not satisfy the element, and
    // neither does an empty or placeholder name.
    if !doc.has_identified_non_tool_creator {
        violations.push(Violation {
            severity: ViolationSeverity::Error,
            category: ViolationCategory::DocumentMetadata,
            message: "[CISA FSCT 3e §2.2.1.1] SBOM names no person/organization author — a \
                      tool-only creator list does not satisfy the Author Name attribute \
                      (CycloneDX: metadata.authors/manufacturer; SPDX: Creator: \
                      Person/Organization)"
                .to_string(),
            element: None,
            requirement: "CISA FSCT 3e §2.2.1.1: Author Name (Minimum Expected)".to_string(),
            rule_id: "SBOM-FSCT-AUTHOR",
            component_id: None,
            counts: None,
            standard_refs: Cow::Borrowed(&[]),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: doc
                .creators
                .iter()
                .find(|c| c.creator.creator_type != CreatorType::Tool)
                .and_then(|c| observed(&c.creator.name)),
        });
    }

    // §2.2.1.2 (untiered = Minimum) — Timestamp. Parsers substitute the
    // UNIX_EPOCH sentinel for missing/unparseable timestamps, so the epoch
    // reads as ABSENT, not as 1970. An unparseable value is quoted.
    if !doc.has_known_timestamp {
        let message = unparseable_timestamp_of(doc.created_unparsed).map_or_else(
            || {
                "[CISA FSCT 3e §2.2.1.2] SBOM creation timestamp missing or unparseable \
                 (ISO 8601-style international format expected)"
                    .to_string()
            },
            |gap| {
                format!(
                    "[CISA FSCT 3e §2.2.1.2] SBOM has {gap} (ISO 8601-style international \
                     format expected)"
                )
            },
        );
        violations.push(Violation {
            severity: ViolationSeverity::Error,
            category: ViolationCategory::DocumentMetadata,
            message,
            element: None,
            requirement: "CISA FSCT 3e §2.2.1.2: Timestamp (Minimum Expected)".to_string(),
            rule_id: "SBOM-FSCT-TIMESTAMP",
            component_id: None,
            counts: None,
            standard_refs: Cow::Borrowed(&[]),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: doc.created_unparsed.and_then(observed),
        });
    }

    // §2.2.1.4 — Primary Component: the subject of the SBOM must be
    // identified and resolve to a component in the inventory.
    let primary = ev.primary();
    if primary.is_none() {
        violations.push(Violation {
            severity: ViolationSeverity::Error,
            category: ViolationCategory::DocumentMetadata,
            message: "[CISA FSCT 3e §2.2.1.4] Primary Component (root of dependencies) is not \
                      identified (CycloneDX: metadata.component; SPDX 2.x: documentDescribes / \
                      DESCRIBES; SPDX 3.0: Software.Sbom.rootElement)"
                .to_string(),
            element: None,
            requirement: "CISA FSCT 3e §2.2.1.4: Primary Component (Minimum Expected)".to_string(),
            rule_id: "SBOM-FSCT-PRIMARY",
            component_id: None,
            counts: None,
            standard_refs: Cow::Borrowed(&[]),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        });
    }

    // §2.2.2 / §2.3.3 (Minimum) — all static direct dependencies of the
    // primary identified. "All" is not verifiable from the document alone;
    // the checkable evidence is direct-dependency edges (or a positive
    // no-dependencies assertion, or an explicit completeness declaration
    // covering the absence).
    if evidence.primary_resolvable
        && evidence.direct_edge_count == 0
        && !evidence.primary_declared_no_deps
        && completeness_undeclared(doc.completeness)
    {
        violations.push(Violation {
            severity: ViolationSeverity::Error,
            category: ViolationCategory::DependencyInfo,
            message: "[CISA FSCT 3e §2.2.2/§2.3.3] No direct dependencies of the Primary \
                      Component are identified, and no completeness declaration covers their \
                      absence — identify all static direct dependencies or declare the \
                      enumeration's completeness"
                .to_string(),
            element: None,
            requirement: "CISA FSCT 3e §2.2.2/§2.3.3: Direct dependencies (Minimum Expected)"
                .to_string(),
            rule_id: "SBOM-FSCT-DIRECT-DEPS",
            component_id: None,
            counts: None,
            standard_refs: Cow::Borrowed(&[]),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        });
    }
    // Direct-dependency edges whose target is not in the inventory: the
    // dependency is referenced but not identified.
    if !evidence.unresolved_direct.is_empty() {
        violations.push(Violation {
            severity: ViolationSeverity::Error,
            category: ViolationCategory::DependencyInfo,
            message: format!(
                "[CISA FSCT 3e §2.2.2/§2.3.3] {} direct dependency reference(s) of the Primary \
                 Component resolve to no component in the inventory: {}",
                evidence.unresolved_direct.len(),
                truncate_list(&evidence.unresolved_direct, 5)
            ),
            element: None,
            requirement: "CISA FSCT 3e §2.2.2/§2.3.3: Direct dependencies (Minimum Expected)"
                .to_string(),
            rule_id: "SBOM-FSCT-DIRECT-DEPS",
            component_id: None,
            counts: None,
            standard_refs: Cow::Borrowed(&[]),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        });
    }

    // §2.2.2.1 (untiered = Minimum) — Component Name for every entry.
    if evidence.nameless > 0 {
        violations.push(Violation {
            severity: ViolationSeverity::Error,
            category: ViolationCategory::ComponentIdentification,
            message: format!(
                "[CISA FSCT 3e §2.2.2.1] {}/{total} component(s) missing the commonly used \
                 public name (placeholder values do not satisfy the attribute)",
                evidence.nameless
            ),
            element: None,
            requirement: "CISA FSCT 3e §2.2.2.1: Component Name (Minimum Expected)".to_string(),
            rule_id: "SBOM-FSCT-COMPONENT-NAME",
            component_id: None,
            counts: Some(ViolationCounts {
                affected: evidence.nameless,
                total,
            }),
            standard_refs: Cow::Borrowed(&[]),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        });
    }

    // §2.2.2.2 (untiered = Minimum) — Version, with the documented
    // authored-hash fallback for components without a unique version.
    if !evidence.without_version.is_empty() {
        violations.push(Violation {
            severity: ViolationSeverity::Error,
            category: ViolationCategory::ComponentIdentification,
            message: format!(
                "[CISA FSCT 3e §2.2.2.2] {}/{pkg_total} component(s) declare neither a \
                 supplier-provided version nor the documented fallback of an author-provided \
                 cryptographic hash: {}",
                evidence.without_version.len(),
                truncate_list(&evidence.without_version, 5)
            ),
            element: None,
            requirement: "CISA FSCT 3e §2.2.2.2: Version (Minimum Expected)".to_string(),
            rule_id: "SBOM-FSCT-VERSION",
            component_id: None,
            counts: Some(ViolationCounts {
                affected: evidence.without_version.len(),
                total: pkg_total,
            }),
            standard_refs: Cow::Borrowed(&[]),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        });
    }

    // §2.2.2.3 (untiered = Minimum) — Supplier Name declared for all
    // components; an explicit 'unknown' satisfies the letter of the clause
    // (discouraged last resort), silent absence fails.
    if !evidence.without_supplier.is_empty() {
        violations.push(Violation {
            severity: ViolationSeverity::Error,
            category: ViolationCategory::SupplierInfo,
            message: format!(
                "[CISA FSCT 3e §2.2.2.3] {}/{pkg_total} component(s) declare no Supplier Name \
                 (an explicit 'unknown' is a permitted last resort; silent absence is not): {}",
                evidence.without_supplier.len(),
                truncate_list(&evidence.without_supplier, 5)
            ),
            element: None,
            requirement: "CISA FSCT 3e §2.2.2.3: Supplier Name (Minimum Expected)".to_string(),
            rule_id: "SBOM-FSCT-SUPPLIER",
            component_id: None,
            counts: Some(ViolationCounts {
                affected: evidence.without_supplier.len(),
                total: pkg_total,
            }),
            standard_refs: Cow::Borrowed(&[]),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        });
    }

    // §2.2.2.4 (Minimum) — unique identifier per component. Profile policy:
    // the document's letter is satisfied by format-native IDs and only
    // "prefers" global uniqueness; this profile deliberately enforces the
    // preferred clause (PURL/CPE/SWHID/SWID, or an authored hash as the
    // intrinsic identifier the section names).
    if !evidence.without_identifier.is_empty() {
        violations.push(Violation {
            severity: ViolationSeverity::Error,
            category: ViolationCategory::ComponentIdentification,
            message: format!(
                "[CISA FSCT 3e §2.2.2.4] {}/{pkg_total} component(s) declare no globally unique \
                 identifier (PURL/CPE/SWHID/SWID) and no cryptographic hash usable as an \
                 intrinsic identifier: {}",
                evidence.without_identifier.len(),
                truncate_list(&evidence.without_identifier, 5)
            ),
            element: None,
            requirement: "CISA FSCT 3e §2.2.2.4: Unique Identifier (Minimum Expected)".to_string(),
            rule_id: "SBOM-FSCT-IDENTIFIER",
            component_id: None,
            counts: Some(ViolationCounts {
                affected: evidence.without_identifier.len(),
                total: pkg_total,
            }),
            standard_refs: Cow::Borrowed(&[]),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        });
    }

    // §2.2.2.5 (Minimum) — author-provided hash (with its algorithm — the
    // model always carries one) for every component. MD5/SHA-1/SHA-2 are
    // all accepted at this tier (stronger algorithms satisfy a fortiori);
    // the model has no way to express the section's "indicate as unknown"
    // escape, so the check degrades to presence.
    if !evidence.without_hash.is_empty() {
        violations.push(Violation {
            severity: ViolationSeverity::Error,
            category: ViolationCategory::IntegrityInfo,
            message: format!(
                "[CISA FSCT 3e §2.2.2.5] {}/{pkg_total} component(s) carry no author-provided \
                 cryptographic hash (enrichment-fetched hashes are not author evidence): {}",
                evidence.without_hash.len(),
                truncate_list(&evidence.without_hash, 5)
            ),
            element: None,
            requirement: "CISA FSCT 3e §2.2.2.5: Cryptographic Hash (Minimum Expected)".to_string(),
            rule_id: "SBOM-FSCT-HASH",
            component_id: None,
            counts: Some(ViolationCounts {
                affected: evidence.without_hash.len(),
                total: pkg_total,
            }),
            standard_refs: Cow::Borrowed(&[]),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        });
    }

    // §2.2.2.6 (Minimum) — relationships declared for the Primary Component
    // and its direct dependencies: with other components present, the
    // primary must participate in the edge set (the primary + included-in
    // relationship types). Distinct from SBOM-FSCT-DIRECT-DEPS: a
    // completeness declaration excuses missing dependency *data* but does
    // not declare a relationship structure.
    if evidence.primary_resolvable
        && evidence.total > 1
        && !evidence.primary_in_edge_set
        && !evidence.primary_declared_no_deps
    {
        violations.push(Violation {
            severity: ViolationSeverity::Error,
            category: ViolationCategory::DependencyInfo,
            message: format!(
                "[CISA FSCT 3e §2.2.2.6] SBOM lists {total} components but the Primary \
                 Component appears in no dependency relationship — declare the primary/\
                 included-in relationships connecting it to its direct dependencies"
            ),
            element: None,
            requirement: "CISA FSCT 3e §2.2.2.6: Relationship (Minimum Expected)".to_string(),
            rule_id: "SBOM-FSCT-RELATIONSHIP",
            component_id: None,
            counts: None,
            standard_refs: Cow::Borrowed(&[]),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        });
    }

    // §2.2.2.7 (Minimum) — license information for the Primary Component.
    // NOASSERTION placeholders do not satisfy this check.
    if let Some(primary) = primary {
        if !primary.licenses().is_known() {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::LicenseInfo,
                message: format!(
                    "[CISA FSCT 3e §2.2.2.7] Primary Component '{}' has no license information \
                     (SPDX license identifiers in standard form preferred; NOASSERTION does not \
                     satisfy)",
                    primary.name()
                ),
                element: Some(primary.name().to_string()),
                requirement: "CISA FSCT 3e §2.2.2.7: License (Minimum Expected)".to_string(),
                rule_id: "SBOM-FSCT-LICENSE-PRIMARY",
                component_id: Some(primary.canonical_id().value().to_string()),
                counts: None,
                standard_refs: Cow::Borrowed(&[]),
                remediation: None,
                finding_detail: None,
                severity_override: None,
                deadline: None,
                field: None,
                observed: None,
            });
        }

        // §2.2.2.8 (Minimum) — copyright notice for the Primary Component.
        if !primary.copyright().is_known() {
            violations.push(Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::LicenseInfo,
                message: format!(
                    "[CISA FSCT 3e §2.2.2.8] Primary Component '{}' has no copyright notice \
                     (identifies the legal rights holder; SPDX: PackageCopyrightText; \
                     CycloneDX: component copyright)",
                    primary.name()
                ),
                element: Some(primary.name().to_string()),
                requirement: "CISA FSCT 3e §2.2.2.8: Copyright Notice (Minimum Expected)"
                    .to_string(),
                rule_id: "SBOM-FSCT-COPYRIGHT-PRIMARY",
                component_id: Some(primary.canonical_id().value().to_string()),
                counts: None,
                standard_refs: Cow::Borrowed(&[]),
                remediation: None,
                finding_detail: None,
                severity_override: None,
                deadline: None,
                field: None,
                observed: None,
            });
        }
    }

    // §2.3.1 (Minimum) — undeclared data: baseline attributes must be
    // populated or explicitly declared no-assertion/no-value. Ambiguous
    // placeholders ("TBD", "N/A", …) do neither. Explicit sentinels and
    // format-default absence never fire this rule (see module docs).
    if !evidence.ambiguous_placeholders.is_empty() {
        violations.push(Violation {
            severity: ViolationSeverity::Error,
            category: ViolationCategory::ComponentIdentification,
            message: format!(
                "[CISA FSCT 3e §2.3.1] {}/{pkg_total} component(s) carry ambiguous placeholder \
                 attribute values that neither populate the attribute nor explicitly declare \
                 no-assertion/no-value (use NOASSERTION/NONE to differentiate 'data missing' \
                 from 'not applicable'): {}",
                evidence.ambiguous_placeholders.len(),
                truncate_list(&evidence.ambiguous_placeholders, 5)
            ),
            element: None,
            requirement: "CISA FSCT 3e §2.3.1: Unknown component attributes (Minimum Expected)"
                .to_string(),
            rule_id: "SBOM-FSCT-NOASSERTION",
            component_id: None,
            counts: Some(ViolationCounts {
                affected: evidence.ambiguous_placeholders.len(),
                total: pkg_total,
            }),
            standard_refs: Cow::Borrowed(&[]),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: evidence.first_placeholder.as_deref().and_then(observed),
        });
    }
}

// ════════════════════════════════════════════════════════════════════════
// Tier 2 — Recommended Practice (Warning)
//
// §2.2.1.1 tool identification, §2.2.2 transitive depth, §2.2.2.4
// identifier multiplicity, §2.2.2.5 SHA-2 hashes + primary hash, §2.2.2.6
// relationships for all components, §2.2.2.6.4 completeness assertion,
// §2.2.2.7/§2.2.2.8 coverage, §2.3.3 upstream SBOM data.
// ════════════════════════════════════════════════════════════════════════

#[allow(clippy::too_many_lines)]
fn fsct_recommended_practice(
    ev: &SbomEvidence<'_>,
    evidence: &FsctEvidence,
    violations: &mut Vec<Violation>,
) {
    let pkg_total = evidence.pkg_total;
    let doc = ev.document();

    // §2.2.1.1 (Recommended) — the tool(s) and version(s) that assisted the
    // SBOM's creation. The parsers fold the tool version into the Tool
    // creator's name ("name version"), so a digit in the name is the
    // best-available version signal.
    if !doc.has_tool_creator {
        violations.push(Violation {
            severity: ViolationSeverity::Warning,
            category: ViolationCategory::DocumentMetadata,
            message: "[CISA FSCT 3e §2.2.1.1] SBOM does not identify the tool(s) that assisted \
                      its creation (CycloneDX: metadata.tools; SPDX: Creator: Tool)"
                .to_string(),
            element: None,
            requirement: "CISA FSCT 3e §2.2.1.1: Author Name — creation tool (Recommended \
                          Practice)"
                .to_string(),
            rule_id: "SBOM-FSCT-AUTHOR-TOOL",
            component_id: None,
            counts: None,
            standard_refs: Cow::Borrowed(&[]),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        });
    } else if !doc.tool_name_has_digit {
        violations.push(Violation {
            severity: ViolationSeverity::Warning,
            category: ViolationCategory::DocumentMetadata,
            message: "[CISA FSCT 3e §2.2.1.1] SBOM creation tool(s) are identified without a \
                      discernible version (heuristic: no digit in any tool creator name)"
                .to_string(),
            element: None,
            requirement: "CISA FSCT 3e §2.2.1.1: Author Name — creation tool version \
                          (Recommended Practice)"
                .to_string(),
            rule_id: "SBOM-FSCT-AUTHOR-TOOL",
            component_id: None,
            counts: None,
            standard_refs: Cow::Borrowed(&[]),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        });
    }

    // §2.2.2 (Recommended) — subcomponent levels beyond the direct
    // dependencies. Depth ≥ 2 is the profile-policy proxy for "as many
    // levels as possible"; a completeness declaration or positive
    // no-dependencies assertions on every direct dependency explain their
    // absence.
    if evidence.primary_resolvable
        && evidence.direct_edge_count > 0
        && !evidence.has_depth2_edges
        && !evidence.all_direct_declared_leaf
        && completeness_undeclared(doc.completeness)
    {
        violations.push(Violation {
            severity: ViolationSeverity::Warning,
            category: ViolationCategory::DependencyInfo,
            message: "[CISA FSCT 3e §2.2.2] Only direct dependencies of the Primary Component \
                      are identified — no subcomponent levels (depth ≥ 2) and no completeness \
                      declaration explaining their absence (heuristic threshold; profile policy)"
                .to_string(),
            element: None,
            requirement: "CISA FSCT 3e §2.2.2: Transitive dependencies (Recommended Practice)"
                .to_string(),
            rule_id: "SBOM-FSCT-TRANSITIVE-DEPS",
            component_id: None,
            counts: None,
            standard_refs: Cow::Borrowed(&[]),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        });
    }

    // §2.2.2.4 (Recommended) — as many globally unique identifiers as
    // available; profile-policy threshold of ≥2 distinct identifier kinds.
    if !evidence.fewer_than_two_identifier_kinds.is_empty() {
        violations.push(Violation {
            severity: ViolationSeverity::Warning,
            category: ViolationCategory::ComponentIdentification,
            message: format!(
                "[CISA FSCT 3e §2.2.2.4] {}/{pkg_total} component(s) declare fewer than two \
                 globally unique identifier kinds (PURL/CPE/SWHID/SWID) — list as many as are \
                 available (heuristic threshold; profile policy): {}",
                evidence.fewer_than_two_identifier_kinds.len(),
                truncate_list(&evidence.fewer_than_two_identifier_kinds, 5)
            ),
            element: None,
            requirement: "CISA FSCT 3e §2.2.2.4: Unique Identifier multiplicity (Recommended \
                          Practice)"
                .to_string(),
            rule_id: "SBOM-FSCT-IDENTIFIER-MULTI",
            component_id: None,
            counts: Some(ViolationCounts {
                affected: evidence.fewer_than_two_identifier_kinds.len(),
                total: pkg_total,
            }),
            standard_refs: Cow::Borrowed(&[]),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        });
    }

    // §2.2.2.5 (Recommended) — at least one hash of the Primary Component…
    if let Some(primary) = ev.primary() {
        let authored = primary.authored_hashes();
        if !authored.facts.plausible {
            let mut message = format!(
                "[CISA FSCT 3e §2.2.2.5] Primary Component '{}' has no author-provided \
                 cryptographic hash",
                primary.name()
            );
            let problems = digest_problems(authored.iter());
            if !problems.is_empty() {
                message.push_str(": ");
                message.push_str(&problems.join("; "));
            }
            violations.push(Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::IntegrityInfo,
                message,
                element: Some(primary.name().to_string()),
                requirement: "CISA FSCT 3e §2.2.2.5: Primary Component hash (Recommended \
                              Practice)"
                    .to_string(),
                rule_id: "SBOM-FSCT-HASH-PRIMARY-SHA2",
                component_id: Some(primary.canonical_id().value().to_string()),
                counts: None,
                standard_refs: Cow::Borrowed(&[]),
                remediation: None,
                finding_detail: None,
                severity_override: None,
                deadline: None,
                field: None,
                observed: None,
            });
        }
    }
    // …and the cryptographically secure SHA-2 family (SHA-256 and higher)
    // on hashed components — wherever weaker hashes (MD5/SHA-1) appear, an
    // additional secure hash is required.
    if !evidence.weak_hash_only.is_empty() {
        violations.push(Violation {
            severity: ViolationSeverity::Warning,
            category: ViolationCategory::IntegrityInfo,
            message: format!(
                "[CISA FSCT 3e §2.2.2.5] {}/{pkg_total} component(s) carry author-provided \
                 hashes but none from the SHA-2 family at SHA-256 or stronger — add a \
                 cryptographically secure hash alongside weaker ones: {}",
                evidence.weak_hash_only.len(),
                truncate_list(&evidence.weak_hash_only, 5)
            ),
            element: None,
            requirement: "CISA FSCT 3e §2.2.2.5: SHA-2 family hash (Recommended Practice)"
                .to_string(),
            rule_id: "SBOM-FSCT-HASH-PRIMARY-SHA2",
            component_id: None,
            counts: Some(ViolationCounts {
                affected: evidence.weak_hash_only.len(),
                total: pkg_total,
            }),
            standard_refs: Cow::Borrowed(&[]),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        });
    }

    // §2.2.2.6 (Recommended) — relationships for ALL included components:
    // flag inventory entries that appear in no dependency edge. Gated on a
    // non-empty edge set so a fully unwired SBOM surfaces through the
    // Minimum-tier relationship rules instead of firing three rules at once.
    if ev.has_edges() && !evidence.orphans.is_empty() {
        violations.push(Violation {
            severity: ViolationSeverity::Warning,
            category: ViolationCategory::DependencyInfo,
            message: format!(
                "[CISA FSCT 3e §2.2.2.6] {}/{} component(s) appear in no dependency \
                 relationship (orphans in the inventory): {}",
                evidence.orphans.len(),
                evidence.pkg_total,
                truncate_list(&evidence.orphans, 5)
            ),
            element: None,
            requirement: "CISA FSCT 3e §2.2.2.6: Relationships for all components (Recommended \
                          Practice)"
                .to_string(),
            rule_id: "SBOM-FSCT-RELATIONSHIP-ALL",
            component_id: None,
            counts: Some(ViolationCounts {
                affected: evidence.orphans.len(),
                total: evidence.pkg_total,
            }),
            standard_refs: Cow::Borrowed(&[]),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        });
    }

    // §2.2.2.6.4 / §2.3.3 — relationship-completeness assertion recorded.
    // Warning, not Error: the document labels the attribute supplemental
    // and optional, with Unknown as the open-world default. SPDX 2.x has no
    // equivalent field, so the indication is genuinely absent there (same
    // posture as the BSI §5.2.2 completeness check).
    if completeness_undeclared(doc.completeness) {
        violations.push(Violation {
            severity: ViolationSeverity::Warning,
            category: ViolationCategory::DependencyInfo,
            message: "[CISA FSCT 3e §2.2.2.6.4] No relationship-completeness assertion \
                      (Unknown/None/Partial/Known) is recorded (CycloneDX: \
                      compositions.aggregate)"
                .to_string(),
            element: None,
            requirement: "CISA FSCT 3e §2.2.2.6.4: Relationship completeness (supplemental, \
                          optional)"
                .to_string(),
            rule_id: "SBOM-FSCT-COMPLETENESS",
            component_id: None,
            counts: None,
            standard_refs: Cow::Borrowed(&[]),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        });
    }

    // §2.2.2.7 (Recommended) — license information for as many components
    // as possible; ≥50% coverage is the profile-policy floor.
    let licensed = pkg_total - evidence.without_license.len();
    if pkg_total > 0 && licensed * 2 < pkg_total {
        violations.push(Violation {
            severity: ViolationSeverity::Warning,
            category: ViolationCategory::LicenseInfo,
            message: format!(
                "[CISA FSCT 3e §2.2.2.7] Only {licensed}/{pkg_total} component(s) carry license \
                 information — provide it for as many components as possible (≥50% coverage \
                 floor is profile policy)"
            ),
            element: None,
            requirement: "CISA FSCT 3e §2.2.2.7: License coverage (Recommended Practice)"
                .to_string(),
            rule_id: "SBOM-FSCT-LICENSE-COVERAGE",
            component_id: None,
            counts: Some(ViolationCounts {
                affected: licensed,
                total: pkg_total,
            }),
            standard_refs: Cow::Borrowed(&[]),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        });
    }

    // §2.2.2.8 (Recommended) — copyright notices for as many components as
    // possible; same profile-policy floor.
    let copyrighted = pkg_total - evidence.without_copyright.len();
    if pkg_total > 0 && copyrighted * 2 < pkg_total {
        violations.push(Violation {
            severity: ViolationSeverity::Warning,
            category: ViolationCategory::LicenseInfo,
            message: format!(
                "[CISA FSCT 3e §2.2.2.8] Only {copyrighted}/{pkg_total} component(s) carry a \
                 copyright notice — provide one for as many components as possible (≥50% \
                 coverage floor is profile policy)"
            ),
            element: None,
            requirement: "CISA FSCT 3e §2.2.2.8: Copyright coverage (Recommended Practice)"
                .to_string(),
            rule_id: "SBOM-FSCT-COPYRIGHT-COVERAGE",
            component_id: None,
            counts: Some(ViolationCounts {
                affected: copyrighted,
                total: pkg_total,
            }),
            standard_refs: Cow::Borrowed(&[]),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        });
    }

    // §2.3.3 (Recommended) — upstream supplier SBOM data provided or
    // linked for direct dependencies. Positive evidence: nested transitive
    // data (children edges / a positive no-dependencies assertion) or a
    // BOM-type external reference. Advisory heuristic — contacting the
    // supplier is unobservable in the document, and first/third-party
    // provenance is not modeled.
    if !evidence.direct_without_upstream.is_empty() {
        violations.push(Violation {
            severity: ViolationSeverity::Warning,
            category: ViolationCategory::DependencyInfo,
            message: format!(
                "[CISA FSCT 3e §2.3.3] {} direct dependenc(ies) of the Primary Component carry \
                 neither nested transitive data nor a linked upstream SBOM (BOM-type external \
                 reference): {}",
                evidence.direct_without_upstream.len(),
                truncate_list(&evidence.direct_without_upstream, 5)
            ),
            element: None,
            requirement: "CISA FSCT 3e §2.3.3: Upstream SBOM data (Recommended Practice)"
                .to_string(),
            rule_id: "SBOM-FSCT-UPSTREAM-SBOM",
            component_id: None,
            counts: None,
            standard_refs: Cow::Borrowed(&[]),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        });
    }
}

// ════════════════════════════════════════════════════════════════════════
// Tier 3 — Aspirational Goals (Info)
//
// §2.2.1.3 SBOM Type (wholly optional/aspirational), §2.2.2/§2.2.2.6
// dynamic and remote dependencies, §2.2.2.7 license for ALL components +
// concluded-license attestation, §2.2.2.8 copyright for ALL components,
// §2.4 authenticity/integrity (supplemental element, not a Baseline
// Attribute). Absence surfaces as informational readiness notes, never a
// failure.
// ════════════════════════════════════════════════════════════════════════

#[allow(clippy::too_many_lines)]
fn fsct_aspirational_goals(
    ev: &SbomEvidence<'_>,
    evidence: &FsctEvidence,
    violations: &mut Vec<Violation>,
    not_evaluated: &mut NotEvaluated,
) {
    let pkg_total = evidence.pkg_total;
    let doc = ev.document();
    let cyclonedx = *doc.format == SbomFormat::CycloneDx;
    let spdx2 = doc.spdx2;
    if cyclonedx {
        not_evaluated.push("SBOM-FSCT-DYNAMIC-DEPS", CYCLONEDX_NO_DYNAMIC_DEPS);
        not_evaluated.push("SBOM-FSCT-LICENSE-CONCLUDED", CYCLONEDX_CONCLUDED_NOT_READ);
    } else {
        not_evaluated.push("SBOM-FSCT-SBOM-TYPE", SPDX_SBOM_TYPE_NOT_READ);
    }
    if spdx2 {
        not_evaluated.push("SBOM-FSCT-SIGNATURE", SPDX2_NO_SIGNATURE);
    }

    // §2.2.1.3 — SBOM Type declared. Evidence-gated to CycloneDX: only the
    // CycloneDX parser populates lifecycle_phase (metadata.lifecycles);
    // SPDX 2.x's CreatorComment mapping and SPDX 3.0's sbomType are not
    // parsed, so SPDX input must not false-fail (see module docs).
    if cyclonedx && !doc.lifecycle_phase.is_known() {
        violations.push(Violation {
            severity: ViolationSeverity::Info,
            category: ViolationCategory::DocumentMetadata,
            message: "[CISA FSCT 3e §2.2.1.3] SBOM Type (design/source/build/analyzed/deployed/\
                      runtime) is not declared (CycloneDX 1.5+: metadata.lifecycles) — the \
                      attribute is optional and an aspirational goal"
                .to_string(),
            element: None,
            requirement: "CISA FSCT 3e §2.2.1.3: SBOM Type (Aspirational Goal)".to_string(),
            rule_id: "SBOM-FSCT-SBOM-TYPE",
            component_id: None,
            counts: None,
            standard_refs: Cow::Borrowed(&[]),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        });
    }

    // §2.2.2 / §2.2.2.6 (Aspirational) — dynamic and/or remote dependencies
    // uniquely identified. Evidence-gated to SPDX: dynamic/runtime/provided
    // link relationships are parsed only from SPDX relationships, so a
    // CycloneDX document can never carry the positive signal.
    if !cyclonedx && !evidence.has_dynamic_edge {
        violations.push(Violation {
            severity: ViolationSeverity::Info,
            category: ViolationCategory::DependencyInfo,
            message: "[CISA FSCT 3e §2.2.2/§2.2.2.6] No dynamic, runtime, or provided \
                      dependency relationships are identified (DYNAMIC_LINK / \
                      RUNTIME_DEPENDENCY_OF / PROVIDED_DEPENDENCY_OF) — readiness note for the \
                      aspirational goal of identifying dynamic and remote dependencies"
                .to_string(),
            element: None,
            requirement: "CISA FSCT 3e §2.2.2/§2.2.2.6: Dynamic and remote dependencies \
                          (Aspirational Goal)"
                .to_string(),
            rule_id: "SBOM-FSCT-DYNAMIC-DEPS",
            component_id: None,
            counts: None,
            standard_refs: Cow::Borrowed(&[]),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        });
    }

    // §2.2.2.7 (Aspirational) — license information for ALL listed
    // components…
    if !evidence.without_license.is_empty() {
        violations.push(Violation {
            severity: ViolationSeverity::Info,
            category: ViolationCategory::LicenseInfo,
            message: format!(
                "[CISA FSCT 3e §2.2.2.7] {}/{pkg_total} component(s) have no license \
                 information — the aspirational goal covers ALL listed components: {}",
                evidence.without_license.len(),
                truncate_list(&evidence.without_license, 5)
            ),
            element: None,
            requirement: "CISA FSCT 3e §2.2.2.7: License for all components (Aspirational Goal)"
                .to_string(),
            rule_id: "SBOM-FSCT-LICENSE-ALL",
            component_id: None,
            counts: Some(ViolationCounts {
                affected: evidence.without_license.len(),
                total: pkg_total,
            }),
            standard_refs: Cow::Borrowed(&[]),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        });
    }
    // …including concluded-license attestation. Evidence-gated to SPDX
    // (PackageLicenseConcluded): the CycloneDX 1.6 licenses[].acknowledgement
    // field is not parsed, so CycloneDX input must not false-fail.
    if !cyclonedx && pkg_total > 0 && !evidence.has_concluded_license {
        violations.push(Violation {
            severity: ViolationSeverity::Info,
            category: ViolationCategory::LicenseInfo,
            message: "[CISA FSCT 3e §2.2.2.7] No component carries a concluded-license \
                      attestation (SPDX PackageLicenseConcluded) — aspirational alongside \
                      declared license information"
                .to_string(),
            element: None,
            requirement: "CISA FSCT 3e §2.2.2.7: Concluded license attestation (Aspirational \
                          Goal)"
                .to_string(),
            rule_id: "SBOM-FSCT-LICENSE-CONCLUDED",
            component_id: None,
            counts: None,
            standard_refs: Cow::Borrowed(&[]),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        });
    }

    // §2.2.2.8 (Aspirational) — copyright notice on every listed component.
    if !evidence.without_copyright.is_empty() {
        violations.push(Violation {
            severity: ViolationSeverity::Info,
            category: ViolationCategory::LicenseInfo,
            message: format!(
                "[CISA FSCT 3e §2.2.2.8] {}/{pkg_total} component(s) have no copyright notice — \
                 the aspirational goal covers ALL listed components: {}",
                evidence.without_copyright.len(),
                truncate_list(&evidence.without_copyright, 5)
            ),
            element: None,
            requirement: "CISA FSCT 3e §2.2.2.8: Copyright for all components (Aspirational \
                          Goal)"
                .to_string(),
            rule_id: "SBOM-FSCT-COPYRIGHT-ALL",
            component_id: None,
            counts: Some(ViolationCounts {
                affected: evidence.without_copyright.len(),
                total: pkg_total,
            }),
            standard_refs: Cow::Borrowed(&[]),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        });
    }

    // §2.4 (supplemental element, not a Baseline Attribute) — verifiable
    // digital signature. §2.4 names no format ("authors must be able to
    // digitally sign SBOMs"), so the check accepts the in-document signature
    // of every format that can carry one, as SBOM-CISA2026-SIGNATURE does
    // (`document_signed`): a CycloneDX JSF or XML-DSig signature, or an
    // SPDX 3 verifiedUsing signature. SPDX 2.x has no in-band signature
    // field, so its sidecar/envelope signatures are unobservable and the
    // check skips it. Until v0.4.0 the check read CycloneDX only.
    if !spdx2 && !doc.signed {
        violations.push(Violation {
            severity: ViolationSeverity::Info,
            category: ViolationCategory::IntegrityInfo,
            message: "[CISA FSCT 3e §2.4] SBOM carries no verifiable digital signature \
                      (CycloneDX JSF or XML-DSig signature, or SPDX 3 verifiedUsing \
                      signature) — supplemental authenticity/integrity capability, not a \
                      Baseline Attribute"
                .to_string(),
            element: None,
            requirement: "CISA FSCT 3e §2.4: Authenticity and integrity (supplemental)".to_string(),
            rule_id: "SBOM-FSCT-SIGNATURE",
            component_id: None,
            counts: None,
            standard_refs: Cow::Borrowed(&[]),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        });
    }
}
