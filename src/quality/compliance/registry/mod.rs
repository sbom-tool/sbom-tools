//! Compliance rule registry: the single source of truth for SARIF rule
//! IDs, harmonised-standard cross-references, and remediation text, keyed
//! by the stable internal `Violation::rule_id`.
//!
//! Each rule is declared once, as a match arm of the `declared_rule_meta`
//! of its family's module (`cra`, `generic`, `crypto`, …); the per-format
//! field advice the declarations share is in `advice`. The rule index
//! reads every declaration once, on first use, and keeps the
//! rules sorted by id with what every finding of a rule carries: its
//! remediation for each format and its standard references, rendered once.
//! [`rule_meta`] and the checker's per-finding lookups are binary searches
//! of that index, so a finding borrows its rule's text instead of copying
//! it.

use std::sync::OnceLock;

use super::{ComplianceLevel, StandardKind, StandardRef, ViolationSeverity};
use crate::model::{DocumentMetadata, SbomFormat};

mod advice;
mod ai;
mod bsi;
mod cisa2026;
mod cra;
mod crypto;
mod eucc;
mod fsct;
mod generic;
mod pci_dss;
mod ssdf_eo14028;

use advice::*;

/// Static metadata attached to a compliance rule. The `rule_id` on every
/// [`Violation`] indexes into [`rule_meta`]; the registry — not the
/// human-readable message — is the single source of truth for the
/// externally-visible SARIF rule ID, the harmonised-standard cross-references,
/// and the remediation text. Rewording a message can no longer silently
/// re-bucket a GitHub code-scanning rule or drop a prEN/BSI reference.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
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

    /// Where the field this rule checks lives in an SBOM of `format`: the
    /// [`FieldAdvice::field`] of its advice for that format. `None` when the
    /// rule has no per-format advice, or the format has no field the check
    /// reads.
    #[must_use]
    pub fn field_for(&self, format: RemediationFormat) -> Option<&'static str> {
        self.advice.and_then(|advice| advice.get(format).field)
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
#[non_exhaustive]
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

    /// The position of this format in [`Self::ALL`].
    const fn position(self) -> usize {
        match self {
            Self::CycloneDx => 0,
            Self::Spdx2 => 1,
            Self::Spdx3 => 2,
        }
    }
}

/// Where a rule's fix goes in one SBOM format.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
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
#[non_exhaustive]
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

/// Remediation for a violation whose rule id the registry does not know (one
/// built outside the checkers): the registry has no guidance for it, so the
/// finding itself is all there is to go on.
pub(crate) const REMEDIATION_UNREGISTERED: &str = "This finding's rule is not in the sbom-tools rule registry, so no specific guidance exists: fix the element its requirement and message name.";

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

/// A component the document lists more than once (one finding per document).
const REMEDIATION_DUPLICATE_COMPONENT: &str = "List each component once. Entries that share an identifier (purl, CPE, SWHID or SWID, else the element identifier) and a name and version describe one component: sbom-tools merges them, so the verdict does not depend on their order, and names the fields on which they disagree. Fix the generator so that it writes one entry per component.";

/// Where the CNSA rules cite CNSA 2.0: CNSSP 15, the CNSS policy that
/// requires the suite for US national security systems. No issuance date:
/// none could be confirmed from the policy itself (docs/STANDARDS_VERSIONS.md).
const CNSA2_CNSSP15: &str = "CNSSP 15";

/// Look up the static [`RuleMeta`] for a stable internal rule key.
///
/// The key is the [`Violation::rule_id`] set at each check site. Returns
/// `None` for unregistered keys — the exhaustive test
/// `every_emitted_violation_has_a_registered_rule_id` guarantees no live check
/// site emits an unregistered key.
///
/// A binary search of the rule index (see the module docs), not a pass over
/// the declarations.
#[must_use]
pub fn rule_meta(rule_id: &str) -> Option<RuleMeta> {
    indexed_rule(rule_id).map(|rule| rule.meta)
}

/// A registered rule as the rule index keeps it: its id, its metadata, and
/// what every finding of the rule carries, rendered once from them.
#[derive(Debug)]
pub(crate) struct IndexedRule {
    /// The stable internal rule key.
    pub(crate) id: &'static str,
    /// The rule's declared metadata.
    pub(crate) meta: RuleMeta,
    /// What the rule reports.
    pub(crate) kind: RuleKind,
    /// The rule's standard references, in registry order, each with its
    /// URL (see [`StandardRef::new`]).
    pub(crate) refs: Vec<StandardRef>,
    /// [`RuleMeta::remediation_for`] each format, in
    /// [`RemediationFormat::ALL`] order.
    remediation: [String; 3],
    /// [`RuleMeta::remediation_all_formats`].
    pub(crate) remediation_all_formats: String,
    /// Where the field the rule checks lives in a CycloneDX document's
    /// primary component: the CycloneDX field, with `metadata.component` in
    /// place of `components[]`. `None` when the field is not under
    /// `components[]`.
    primary_field: Option<String>,
}

impl IndexedRule {
    fn new(id: &'static str, meta: RuleMeta) -> Self {
        let primary_field = meta
            .field_for(RemediationFormat::CycloneDx)
            .and_then(|field| field.strip_prefix("components[]"))
            .map(|rest| format!("metadata.component{rest}"));
        Self {
            id,
            kind: if PASS_RULE_IDS.contains(&id) {
                RuleKind::Pass
            } else {
                RuleKind::Finding
            },
            refs: meta
                .refs
                .iter()
                .map(|(kind, clause)| StandardRef::new(*kind, *clause))
                .collect(),
            remediation: RemediationFormat::ALL.map(|format| meta.remediation_for(format)),
            remediation_all_formats: meta.remediation_all_formats(),
            primary_field,
            meta,
        }
    }

    /// [`RuleMeta::remediation_for`] `format`.
    pub(crate) fn remediation(&self, format: RemediationFormat) -> &str {
        &self.remediation[format.position()]
    }

    /// Where the field the rule checks lives in an SBOM of `format`: the
    /// [`RuleMeta::field_for`] that format. A CycloneDX document keeps its
    /// primary component at `metadata.component`, so for a finding
    /// `about_primary` a field under `components[]` is named there.
    pub(crate) fn field(&self, format: RemediationFormat, about_primary: bool) -> Option<&str> {
        match &self.primary_field {
            Some(field) if about_primary && format == RemediationFormat::CycloneDx => Some(field),
            _ => self.meta.field_for(format),
        }
    }
}

/// The rule index: every rule of [`ALL_RULE_IDS`] with its declared
/// metadata, sorted by id, built on first use.
fn rule_index() -> &'static [IndexedRule] {
    static INDEX: OnceLock<Vec<IndexedRule>> = OnceLock::new();
    INDEX.get_or_init(|| {
        let mut rules: Vec<IndexedRule> = ALL_RULE_IDS
            .iter()
            .filter_map(|id| declared_rule_meta(id).map(|meta| IndexedRule::new(id, meta)))
            .collect();
        rules.sort_unstable_by_key(|rule| rule.id);
        rules
    })
}

/// The indexed rule `rule_id` names; `None` for an unregistered id.
pub(crate) fn indexed_rule(rule_id: &str) -> Option<&'static IndexedRule> {
    let rules = rule_index();
    rules
        .binary_search_by(|rule| rule.id.cmp(rule_id))
        .ok()
        .map(|at| &rules[at])
}

/// The declared [`RuleMeta`] of `rule_id`: one match arm per registered
/// rule, in the module of the rule's family. The rule index reads each
/// once; every lookup goes through [`indexed_rule`].
fn declared_rule_meta(rule_id: &str) -> Option<RuleMeta> {
    cra::declared_rule_meta(rule_id)
        .or_else(|| generic::declared_rule_meta(rule_id))
        .or_else(|| eucc::declared_rule_meta(rule_id))
        .or_else(|| ai::declared_rule_meta(rule_id))
        .or_else(|| ssdf_eo14028::declared_rule_meta(rule_id))
        .or_else(|| bsi::declared_rule_meta(rule_id))
        .or_else(|| crypto::declared_rule_meta(rule_id))
        .or_else(|| cisa2026::declared_rule_meta(rule_id))
        .or_else(|| pci_dss::declared_rule_meta(rule_id))
        .or_else(|| fsct::declared_rule_meta(rule_id))
}

/// Every stable internal rule key with a match arm in a family module's
/// `declared_rule_meta`: the rules the rule index holds, in registry order
/// (the order of [`all_rule_ids`] and the rule catalogue). The
/// `all_rule_ids_matches_the_registry` test asserts the list and the match
/// arms stay in lockstep.
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
    "SBOM-CRA-DUPLICATE-COMPONENT",
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
    "SBOM-QUALITY-DUPLICATE-COMPONENT",
    "SBOM-QUALITY-TIMESTAMP",
    "SBOM-QUALITY-VERSION",
    "SBOM-QUALITY-SUPPLIER",
    "SBOM-QUALITY-DEPENDENCY",
    "SBOM-EUCC-PP",
    "SBOM-EUCC-TOE",
    "SBOM-EUCC-ITSEF",
    "SBOM-EUCC-VALIDITY",
    "SBOM-EUCC-CERTREF",
    "SBOM-EUCC-GENERAL",
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
    "SBOM-FDA-MANUFACTURER",
    "SBOM-FDA-TIMESTAMP",
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
    "SBOM-FDA-DUPLICATE-COMPONENT",
    "SBOM-NTIA-AUTHOR",
    "SBOM-NTIA-INVENTORY",
    "SBOM-NTIA-NAME",
    "SBOM-NTIA-IDENTIFIER",
    "SBOM-NTIA-GENERAL",
    "SBOM-NTIA-SPEC-VERSION",
    "SBOM-NTIA-SPEC-VERSION-UNKNOWN",
    "SBOM-NTIA-ELEMENT-ID",
    "SBOM-NTIA-DUPLICATE-COMPONENT",
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
    "SBOM-PQC-HASH-001",
    "SBOM-PQC-CERT-001",
    "SBOM-PQC-CERT-UNKNOWN",
    "SBOM-PQC-PROTO-001",
    "SBOM-PQC-PROTO-002",
    "SBOM-PQC-PROTO-003",
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

/// What a rule reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RuleKind {
    /// A gap or an advisory: a [`Violation`](super::Violation) at a
    /// severity.
    Finding,
    /// A check the SBOM passed: a [`PassedCheck`](super::PassedCheck), never
    /// a violation.
    Pass,
}

/// The pass-only rules ([`RuleKind::Pass`]): each only ever affirms a check
/// the SBOM passed. Every other registered rule is a [`RuleKind::Finding`].
///
/// A pass-only rule keeps the registry's `Info` default severity by
/// convention: the SARIF rule catalogue declares it at `note` as before,
/// while its results (emitted only under `--sarif-include-passes`) carry
/// `kind: "pass"` and level `none`. It shares its SARIF identity with no
/// finding rule.
pub const PASS_RULE_IDS: &[&str] = &["SBOM-PQC-009", "SBOM-PQC-010"];

/// The kind of the registered rule `rule_id`; `None` for an unregistered id.
#[must_use]
pub fn rule_kind(rule_id: &str) -> Option<RuleKind> {
    indexed_rule(rule_id).map(|rule| rule.kind)
}

/// Map an owned rule-id string back to the registry's `&'static str` key.
/// Used when deserializing payloads that carry a serialized `rule_id`, so a
/// round-tripped violation keeps its registry identity instead of collapsing
/// to the generic default.
#[must_use]
pub(crate) fn lookup_static_rule_id(rule_id: &str) -> Option<&'static str> {
    indexed_rule(rule_id).map(|rule| rule.id)
}

/// The registry's spelling of the rule id `value`, ignoring case and
/// surrounding whitespace: how the command line (`--rule`, `--fail-on`,
/// `rules explain`) and the config file (`compliance.rules`) name a rule.
///
/// # Errors
///
/// `value` names no registered rule. The message says how to list the rule
/// ids and names the closest one, if one is a few edits away.
pub fn resolve_rule_id(value: &str) -> Result<&'static str, String> {
    let value = value.trim();
    if let Some(id) = ALL_RULE_IDS
        .iter()
        .find(|id| id.eq_ignore_ascii_case(value))
    {
        return Ok(id);
    }
    Err(match closest_rule_id(value) {
        Some(id) => {
            format!("unknown rule id (did you mean {id}?); `sbom-tools rules` lists every rule id")
        }
        None => "unknown rule id; `sbom-tools rules` lists every rule id".to_string(),
    })
}

/// The registered rule id closest to `value`, when it is a few edits away
/// (with or without the `SBOM-` prefix).
fn closest_rule_id(value: &str) -> Option<&'static str> {
    let upper = value.to_ascii_uppercase();
    let prefixed = if upper.starts_with("SBOM-") {
        upper
    } else {
        format!("SBOM-{upper}")
    };
    ALL_RULE_IDS
        .iter()
        .map(|id| (strsim::levenshtein(&prefixed, id), *id))
        .filter(|(distance, _)| *distance <= 3)
        .min_by_key(|(distance, _)| *distance)
        .map(|(_, id)| id)
}

// ---------------------------------------------------------------------------
// Standard membership: the rules each compliance level reports.
//
// Each slice lists, in display order, every rule the level's checks can
// emit, and nothing else: one per check the standard runs. `rules_for_level`
// maps a level to its slice. The lists are derived from the check sites
// (generic.rs, cra.rs and the per-standard modules) and proven by the rule
// matrices: tests/common/rule_matrix.rs requires each level's matrix to cover
// exactly its list, and runs every matrix fixture at every level, failing on
// a rule outside that level's list. A rule a new check emits must join the
// list of every level whose checks emit it.
//
// A slice is a level's SARIF rule catalogue: a run declares the slices of the
// standards it checked as reportingDescriptors (src/reports/sarif/rules.rs).
// Every id must be a registry key whose `sarif_id` equals the key itself (a
// self-descriptor); the `sarif_rule_slices_are_self_descriptors` test
// enforces this. The SARIF generator renders these through `rule_meta`, so
// name / shortDescription / defaultConfiguration.level can no longer drift
// from the registry.
//
// The `SBOM-<FAMILY>-GENERAL` fallback rules are in no slice: no check emits
// one. The SARIF generator files a finding without a registered rule under
// its family's fallback (`generic_rule_id_for_level` in level.rs) and declares
// that rule when it does.
// ---------------------------------------------------------------------------

/// The rules `level`'s checks can report, in display order: what `sbom-tools
/// rules --standard` lists and what a SARIF run that checks `level` declares
/// in `rules[]`. The family fallback rule (`generic_rule_id_for_level`) is not
/// listed: no check emits it.
#[must_use]
pub const fn rules_for_level(level: ComplianceLevel) -> &'static [&'static str] {
    match level {
        ComplianceLevel::Minimum => MINIMUM_SARIF_RULE_IDS,
        ComplianceLevel::Standard => STANDARD_SARIF_RULE_IDS,
        ComplianceLevel::NtiaMinimum => NTIA_SARIF_RULE_IDS,
        ComplianceLevel::CraPhase1 => CRA_PHASE1_SARIF_RULE_IDS,
        ComplianceLevel::CraPhase2 => CRA_PHASE2_SARIF_RULE_IDS,
        ComplianceLevel::FdaMedicalDevice => FDA_SARIF_RULE_IDS,
        ComplianceLevel::NistSsdf => SSDF_SARIF_RULE_IDS,
        ComplianceLevel::Eo14028 => EO14028_SARIF_RULE_IDS,
        ComplianceLevel::Cnsa2 => CNSA2_SARIF_RULE_IDS,
        ComplianceLevel::NistPqc => PQC_SARIF_RULE_IDS,
        ComplianceLevel::BsiTr03183_2 => BSI_SARIF_RULE_IDS,
        ComplianceLevel::CraOssSteward => CRA_OSS_STEWARD_SARIF_RULE_IDS,
        ComplianceLevel::EuccSubstantial => EUCC_SARIF_RULE_IDS,
        ComplianceLevel::EuAiAct => AIACT_SARIF_RULE_IDS,
        ComplianceLevel::BsiSbomForAi => BSIAI_SARIF_RULE_IDS,
        ComplianceLevel::Cisa2026 => CISA2026_SARIF_RULE_IDS,
        ComplianceLevel::PciDss632 => PCIDSS_SARIF_RULE_IDS,
        ComplianceLevel::Fsct => FSCT_SARIF_RULE_IDS,
        ComplianceLevel::Comprehensive => COMPREHENSIVE_SARIF_RULE_IDS,
    }
}

/// The Minimum quality profile's rules (generic.rs): the document creator, a
/// component inventory, component names and the format checks.
const MINIMUM_SARIF_RULE_IDS: &[&str] = &[
    "SBOM-QUALITY-CREATOR",
    "SBOM-QUALITY-INVENTORY",
    "SBOM-QUALITY-NAME",
    "SBOM-QUALITY-SPEC-VERSION",
    "SBOM-QUALITY-SPEC-VERSION-UNKNOWN",
    "SBOM-QUALITY-ELEMENT-ID",
    "SBOM-QUALITY-DUPLICATE-COMPONENT",
];

/// The Standard quality profile's rules (generic.rs): Minimum's, plus the
/// serial number, component versions, unique identifiers and licenses.
const STANDARD_SARIF_RULE_IDS: &[&str] = &[
    "SBOM-QUALITY-CREATOR",
    "SBOM-QUALITY-SERIAL",
    "SBOM-QUALITY-INVENTORY",
    "SBOM-QUALITY-NAME",
    "SBOM-QUALITY-VERSION",
    "SBOM-QUALITY-IDENTIFIER",
    "SBOM-QUALITY-LICENSE",
    "SBOM-QUALITY-SPEC-VERSION",
    "SBOM-QUALITY-SPEC-VERSION-UNKNOWN",
    "SBOM-QUALITY-ELEMENT-ID",
    "SBOM-QUALITY-DUPLICATE-COMPONENT",
];

/// The Comprehensive quality profile's rules (generic.rs): Standard's, plus
/// the creation timestamp, component suppliers and hashes, and dependency
/// relationships.
const COMPREHENSIVE_SARIF_RULE_IDS: &[&str] = &[
    "SBOM-QUALITY-CREATOR",
    "SBOM-QUALITY-TIMESTAMP",
    "SBOM-QUALITY-SERIAL",
    "SBOM-QUALITY-INVENTORY",
    "SBOM-QUALITY-NAME",
    "SBOM-QUALITY-VERSION",
    "SBOM-QUALITY-IDENTIFIER",
    "SBOM-QUALITY-SUPPLIER",
    "SBOM-QUALITY-LICENSE",
    "SBOM-QUALITY-HASH",
    "SBOM-QUALITY-DEPENDENCY",
    "SBOM-QUALITY-SPEC-VERSION",
    "SBOM-QUALITY-SPEC-VERSION-UNKNOWN",
    "SBOM-QUALITY-ELEMENT-ID",
    "SBOM-QUALITY-DUPLICATE-COMPONENT",
];

/// CRA Phase 1 rules (generic.rs and cra.rs): the document, component,
/// dependency and format checks, the CRA gap checks, Art. 14 readiness, the
/// class-pinned conformity checks and the hardware checks. The Phase 2-only
/// checks (CVD policy, lifecycle evidence, the Annex V DoC reference, the
/// Art. 13(2) risk assessment and the vulnerability severity and remediation
/// checks) are not listed.
const CRA_PHASE1_SARIF_RULE_IDS: &[&str] = &[
    "SBOM-CRA-SBOM-FRESHNESS",
    "SBOM-CRA-MACHINE-READABLE",
    "SBOM-CRA-ART-13-17-CONTACT",
    "SBOM-CRA-VULN-METADATA-PROFILE",
    "SBOM-CRA-ART-13-5",
    "SBOM-CRA-ART-13-5-PROFILE",
    "SBOM-CRA-ART-13-8",
    "SBOM-CRA-ART-13-8-EOL",
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
    "SBOM-CRA-CYCLES",
    "SBOM-CRA-ANNEX-I-PRIMARY",
    "SBOM-CRA-ANNEX-I-CONTROLS",
    "SBOM-CRA-INVENTORY",
    "SBOM-CRA-DOC-INTEGRITY",
    "SBOM-CRA-ART-14-PSIRT",
    "SBOM-CRA-ART-14-EARLY-WARNING",
    "SBOM-CRA-ART-14-NOTIFICATION",
    "SBOM-CRA-ART-14-ENISA",
    "SBOM-CRA-ANNEX-IV",
    "SBOM-CRA-ANNEX-VIII",
    "SBOM-CRA-CREATOR",
    "SBOM-CRA-SERIAL",
    "SBOM-CRA-COMPONENT-NAME",
    "SBOM-CRA-SPEC-VERSION",
    "SBOM-CRA-SPEC-VERSION-UNKNOWN",
    "SBOM-CRA-ELEMENT-ID",
    "SBOM-CRA-DUPLICATE-COMPONENT",
    "SBOM-CRA-PRE-8-RQ-02-PRODUCER",
    "SBOM-CRA-PRE-8-RQ-02-IDENTIFIER",
    "SBOM-CRA-PRE-8-RQ-02-FIRMWARE-VERSION",
    "SBOM-CRA-PRE-8-RQ-02-DEVICE-FIRMWARE",
    "SBOM-CRA-PRE-7-RQ-07-RE",
];

/// CRA Phase 2 rules: Phase 1's, plus the full-application checks — the
/// vulnerability severity and remediation checks (Annex I Part II (4)), the
/// CVD policy (Annex I Part II (5)), lifecycle evidence (Annex II (7)), the
/// EU Declaration of Conformity reference (Annex V) and the risk assessment
/// (Art. 13(2)).
const CRA_PHASE2_SARIF_RULE_IDS: &[&str] = &[
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
    "SBOM-CRA-CYCLES",
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
    "SBOM-CRA-ANNEX-IV",
    "SBOM-CRA-ANNEX-VIII",
    "SBOM-CRA-CREATOR",
    "SBOM-CRA-SERIAL",
    "SBOM-CRA-COMPONENT-NAME",
    "SBOM-CRA-SPEC-VERSION",
    "SBOM-CRA-SPEC-VERSION-UNKNOWN",
    "SBOM-CRA-ELEMENT-ID",
    "SBOM-CRA-DUPLICATE-COMPONENT",
    "SBOM-CRA-PRE-8-RQ-02-PRODUCER",
    "SBOM-CRA-PRE-8-RQ-02-IDENTIFIER",
    "SBOM-CRA-PRE-8-RQ-02-FIRMWARE-VERSION",
    "SBOM-CRA-PRE-8-RQ-02-DEVICE-FIRMWARE",
    "SBOM-CRA-PRE-7-RQ-07-RE",
];

/// CRA Art. 24 open-source steward rules (`check_cra_oss_steward` in cra.rs):
/// the component, dependency and format checks plus the two steward floors.
/// The steward runs no document-metadata, gap, Art. 14 or hardware check.
const CRA_OSS_STEWARD_SARIF_RULE_IDS: &[&str] = &[
    "SBOM-CRA-CVD-POLICY",
    "SBOM-CRA-COMPONENT-VERSION",
    "SBOM-CRA-ANNEX-I-IDENTIFIER",
    "SBOM-CRA-ANNEX-I-INTEGRITY",
    "SBOM-CRA-ANNEX-I-DEPENDENCY",
    "SBOM-CRA-ANNEX-I-DEPENDENCY-ROOTS",
    "SBOM-CRA-CYCLES",
    "SBOM-CRA-INVENTORY",
    "SBOM-CRA-ART-24",
    "SBOM-CRA-ART-24-SUPPLIER",
    "SBOM-CRA-COMPONENT-NAME",
    "SBOM-CRA-SPEC-VERSION",
    "SBOM-CRA-SPEC-VERSION-UNKNOWN",
    "SBOM-CRA-ELEMENT-ID",
    "SBOM-CRA-DUPLICATE-COMPONENT",
];

/// BSI TR-03183-2 rules: every `SBOM-BSI-TR-03183-2-*` rule but the fallback.
const BSI_SARIF_RULE_IDS: &[&str] = &[
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
];

/// EUCC Substantial rules: every `SBOM-EUCC-*` rule but the fallback.
const EUCC_SARIF_RULE_IDS: &[&str] = &[
    "SBOM-EUCC-PP",
    "SBOM-EUCC-TOE",
    "SBOM-EUCC-ITSEF",
    "SBOM-EUCC-VALIDITY",
    "SBOM-EUCC-CERTREF",
];

/// EU AI Act Annex IV readiness rules: every `SBOM-AIACT-*` rule but the
/// fallback.
const AIACT_SARIF_RULE_IDS: &[&str] = &[
    "SBOM-AIACT-ANNEX-IV-1-DESCRIPTION",
    "SBOM-AIACT-ANNEX-IV-1-PURPOSE",
    "SBOM-AIACT-ANNEX-IV-2D-DATASETS",
    "SBOM-AIACT-ANNEX-IV-2D-SENSITIVITY",
    "SBOM-AIACT-ANNEX-IV-2D-PERSONAL-DATA",
    "SBOM-AIACT-ANNEX-IV-2G-METRICS",
    "SBOM-AIACT-ANNEX-IV-2C-ENERGY",
    "SBOM-AIACT-ANNEX-IV-3-LIMITATIONS",
    "SBOM-AIACT-UNTYPED-ML",
];

/// BSI/G7 SBOM-for-AI readiness rules: every `SBOM-BSIAI-*` rule but the
/// fallback.
const BSIAI_SARIF_RULE_IDS: &[&str] = &[
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
    "SBOM-NTIA-DUPLICATE-COMPONENT",
];

/// FDA premarket SARIF rule catalogue. Its NTIA-baseline checks (the
/// guidance incorporates the NTIA minimum elements) report under FDA ids of
/// their own, the timestamp too: it reported as SBOM-NTIA-TIMESTAMP until
/// v0.4.0.
pub const FDA_SARIF_RULE_IDS: &[&str] = &[
    "SBOM-FDA-TIMESTAMP",
    "SBOM-FDA-INVENTORY",
    "SBOM-FDA-CREATOR",
    "SBOM-FDA-NAMESPACE",
    "SBOM-FDA-NAME",
    "SBOM-FDA-MANUFACTURER",
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
    "SBOM-FDA-DUPLICATE-COMPONENT",
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

/// NSA CNSA 2.0 SARIF rule catalogue: every `SBOM-CNSA2-*` self-descriptor
/// in the registry. The `cnsa2_and_pqc_slices_cover_their_rule_families`
/// test keeps this slice in lockstep with the registry, so a CNSA 2.0 run
/// declares every rule of its family.
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
    "SBOM-PQC-HASH-001",
    "SBOM-PQC-CERT-001",
    "SBOM-PQC-CERT-UNKNOWN",
    "SBOM-PQC-PROTO-001",
    "SBOM-PQC-PROTO-002",
    "SBOM-PQC-PROTO-003",
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

    /// The ENISA SBOM advisory is non-binding guidance on SBOM content: only
    /// CRA rules cite it, and always after their CRA and prEN references, so
    /// a rule that cites the regulation keeps linking it as its SARIF
    /// helpUri.
    #[test]
    fn enisa_advisory_follows_the_cra_references() {
        let mut citing = Vec::new();
        for id in all_rule_ids() {
            let refs = rule_meta(id).expect("listed id resolves").refs;
            let Some(first) = refs
                .iter()
                .position(|(kind, _)| *kind == StandardKind::EnisaSbomAdvisory)
            else {
                continue;
            };
            assert!(id.starts_with("SBOM-CRA-"), "{id} is no CRA rule");
            assert!(
                refs[first..]
                    .iter()
                    .all(|(kind, _)| *kind == StandardKind::EnisaSbomAdvisory),
                "{id}: the ENISA advisory must come after the other references"
            );
            citing.push(*id);
        }
        for id in [
            "SBOM-CRA-COMPONENT-VERSION",
            "SBOM-CRA-COMPONENT-SUPPLIER",
            "SBOM-CRA-ANNEX-I-IDENTIFIER",
            "SBOM-CRA-MACHINE-READABLE",
            "SBOM-CRA-DOC-INTEGRITY",
        ] {
            assert!(citing.contains(&id), "{id} cites the ENISA advisory");
        }
    }

    /// CNSA 2.0 is cited through CNSSP 15, the policy that requires it, on
    /// every CNSA rule.
    #[test]
    fn cnsa_rules_cite_cnssp_15() {
        for id in CNSA2_SARIF_RULE_IDS {
            let refs = rule_meta(id).expect("listed id resolves").refs;
            assert_eq!(refs, &[(StandardKind::Cnsa2, CNSA2_CNSSP15)], "{id}");
        }
    }

    /// Pass-only rules are registered, keep the `Info` default the SARIF
    /// catalogue declares as `note`, and share their SARIF identity with no
    /// finding rule, so a SARIF rule is never both a pass and a finding.
    #[test]
    fn pass_rules_are_info_rules_with_a_sarif_identity_of_their_own() {
        for id in PASS_RULE_IDS {
            let meta = rule_meta(id).unwrap_or_else(|| panic!("{id} is registered"));
            assert_eq!(meta.default_severity, ViolationSeverity::Info, "{id}");
            assert_eq!(rule_kind(id), Some(RuleKind::Pass), "{id}");
            for other in ALL_RULE_IDS {
                let other_meta = rule_meta(other).expect("listed ids resolve");
                if other_meta.sarif_id == meta.sarif_id {
                    assert_eq!(
                        rule_kind(other),
                        Some(RuleKind::Pass),
                        "{other} shares the SARIF rule of pass-only {id}"
                    );
                }
            }
        }
        assert_eq!(rule_kind("SBOM-NTIA-AUTHOR"), Some(RuleKind::Finding));
        assert_eq!(rule_kind("SBOM-NO-SUCH-RULE"), None);
    }

    /// `ALL_RULE_IDS` and the `rule_meta` match arms must stay in lockstep:
    /// every listed id resolves, every match arm is listed, no duplicates.
    /// The match arms are recovered from the source text of the family
    /// modules, so a new arm cannot land without being enumerated, and no
    /// rule is declared in two families (where the one match used to flag a
    /// second arm as unreachable).
    #[test]
    fn all_rule_ids_matches_the_registry() {
        let sources = [
            include_str!("ai.rs"),
            include_str!("bsi.rs"),
            include_str!("cisa2026.rs"),
            include_str!("cra.rs"),
            include_str!("crypto.rs"),
            include_str!("eucc.rs"),
            include_str!("fsct.rs"),
            include_str!("generic.rs"),
            include_str!("pci_dss.rs"),
            include_str!("ssdf_eo14028.rs"),
        ];
        let mut match_arms = Vec::new();
        for line in sources.iter().flat_map(|src| src.lines()) {
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
        assert_eq!(match_arms.len(), arm_set.len(), "a rule has two match arms");
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

    /// Every id in a level's rule list must be a self-descriptor: a registry
    /// key whose `sarif_id` is the key itself. The SARIF generator relies on
    /// this to render descriptors without aliasing.
    #[test]
    fn sarif_rule_slices_are_self_descriptors() {
        for level in ComplianceLevel::all() {
            let label = format!("{level:?}");
            let slice = rules_for_level(*level);
            assert!(!slice.is_empty(), "[{label}] lists no rule");
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

    /// The BSI TR-03183-2, EUCC and AI readiness lists enumerate their whole
    /// rule family but its fallback rule, as the tests above do for the
    /// other single-family standards.
    #[test]
    fn single_family_lists_cover_their_rule_families() {
        for (prefix, level) in [
            ("SBOM-BSI-TR-03183-2-", ComplianceLevel::BsiTr03183_2),
            ("SBOM-EUCC-", ComplianceLevel::EuccSubstantial),
            ("SBOM-AIACT-", ComplianceLevel::EuAiAct),
            ("SBOM-BSIAI-", ComplianceLevel::BsiSbomForAi),
            ("SBOM-SSDF-", ComplianceLevel::NistSsdf),
            ("SBOM-EO14028-", ComplianceLevel::Eo14028),
        ] {
            let expected: std::collections::BTreeSet<&str> = all_rule_ids()
                .iter()
                .copied()
                .filter(|id| id.starts_with(prefix) && !is_fallback(id))
                .collect();
            let actual: std::collections::BTreeSet<&str> =
                rules_for_level(level).iter().copied().collect();
            assert_eq!(
                actual, expected,
                "{prefix}* rule list drifted from the registry"
            );
        }
    }

    /// No list names a fallback rule: no check emits one, so a standard's
    /// catalogue lists the checks it runs and nothing else.
    #[test]
    fn no_slice_lists_a_fallback_rule() {
        for level in ComplianceLevel::all() {
            for id in rules_for_level(*level) {
                assert!(!is_fallback(id), "{level:?} lists the fallback rule {id}");
            }
        }
    }

    /// Every rule a check emits belongs to some standard: each registered
    /// rule but the fallback rules is in at least one level's list, so
    /// `sbom-tools rules` and the SARIF catalogue name a standard for it.
    #[test]
    fn every_check_rule_belongs_to_a_standard() {
        let listed: std::collections::BTreeSet<&str> = ComplianceLevel::all()
            .iter()
            .flat_map(|level| rules_for_level(*level).iter().copied())
            .collect();
        let orphans: Vec<&str> = all_rule_ids()
            .iter()
            .copied()
            .filter(|id| !is_fallback(id) && !listed.contains(id))
            .collect();
        assert!(
            orphans.is_empty(),
            "rules in no level's list (add each to rules_for_level's table): {orphans:?}"
        );
    }

    /// Every level reports under its own family's rule ids, the prefix of
    /// its fallback rule: `SBOM-QUALITY-` for the quality profiles,
    /// `SBOM-NTIA-` for NTIA, `SBOM-FDA-` for FDA and so on. Until v0.4.0
    /// the Standard and Comprehensive profiles reported four `SBOM-NTIA-*`
    /// rules and FDA the NTIA timestamp, so their runs listed NTIA rules.
    #[test]
    fn every_level_reports_under_its_own_family() {
        for level in ComplianceLevel::all() {
            let fallback = super::super::generic_rule_id_for_level(*level);
            let prefix = fallback
                .strip_suffix("GENERAL")
                .expect("a fallback rule id ends in GENERAL");
            for id in rules_for_level(*level) {
                assert!(
                    id.starts_with(prefix),
                    "{level:?} lists {id}, a rule outside its family {prefix}*"
                );
            }
        }
    }

    /// Every rule a standard reports cites the clause it implements, so its
    /// findings carry standard references and a help URI. Two groups have
    /// none: the fallback rules, which no check emits, and the quality
    /// profiles' `SBOM-QUALITY-*` rules, which sbom-tools defines itself (their
    /// SARIF help links the tool's documentation).
    #[test]
    fn every_standard_rule_cites_a_reference() {
        let missing: Vec<&str> = all_rule_ids()
            .iter()
            .copied()
            .filter(|id| !is_fallback(id) && !id.starts_with("SBOM-QUALITY-"))
            .filter(|id| rule_meta(id).is_some_and(|meta| meta.refs.is_empty()))
            .collect();
        assert!(
            missing.is_empty(),
            "rules without a standard reference: {missing:?}"
        );
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
