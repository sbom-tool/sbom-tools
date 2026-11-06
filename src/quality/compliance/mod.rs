//! SBOM Compliance checking module.
//!
//! Validates SBOMs against format requirements and industry standards.
//!
//! The public surface ([`ComplianceChecker`], [`ComplianceLevel`],
//! [`ComplianceResult`], [`Violation`], [`PassedCheck`], the rule registry,
//! …) lives here; the per-standard check logic is split across sibling
//! submodules and dispatched through the [`StandardChecker`] trait in
//! [`context`].

use crate::model::{NormalizedSbom, SbomFormat};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

// `pub(crate)` so the AI-readiness scorer (quality/scorer.rs) shares the exact
// ML-component applicability semantics of the AI compliance profiles instead
// of re-deriving them (and drifting, as the type-only filter once did).
pub(crate) mod ai_shared;
mod bsi;
mod bsi_sbom_for_ai;
mod catalog;
mod checker;
mod cisa2026;
mod context;
mod cra;
mod crypto;
mod eo14028;
mod eu_ai_act;
mod eucc;
mod finding;
mod fsct;
mod generic;
mod level;
mod pci_dss;
mod pqc_calendar;
mod registry;
mod result;
mod rule_settings;
mod run_config;
mod selector;
mod shared;
mod ssdf;
mod standard_ref;

pub(crate) use catalog::rule_family_help_uri;
pub use catalog::{
    RuleAdvice, RuleCatalogEntry, RuleCatalogFilter, RuleFormatAdvice, RuleReference, rule_catalog,
    rule_catalog_entry,
};
pub use checker::{ClassCheck, ComplianceChecker};
use context::{ComplianceContext, Findings, NotEvaluated, checker_for};
pub(crate) use finding::compose_finding_key;
pub use finding::{
    DOCUMENT_SUBJECT, FINDING_ID_PREFIX, FindingIdentity, finding_fingerprint, finding_id,
    finding_key, finding_subject, standard_key,
};
pub use level::{ComplianceLevel, CraPhase, generic_rule_id_for_level};
use pqc_calendar::Calendar;
pub use pqc_calendar::{CnsaCategory, Deadline, PqcMode, PqcProfile};
pub use registry::resolve_rule_id;
pub use registry::{
    CISA2026_SARIF_RULE_IDS, CNSA2_SARIF_RULE_IDS, EO14028_SARIF_RULE_IDS, FDA_SARIF_RULE_IDS,
    FSCT_SARIF_RULE_IDS, FieldAdvice, FormatAdvice, NTIA_SARIF_RULE_IDS, PASS_RULE_IDS,
    PCIDSS_SARIF_RULE_IDS, PQC_SARIF_RULE_IDS, RemediationFormat, RuleKind, RuleMeta,
    SSDF_SARIF_RULE_IDS, all_rule_ids, rule_kind, rule_meta, rules_for_level,
};
use registry::{REMEDIATION_UNREGISTERED, indexed_rule, lookup_static_rule_id};
pub use result::{
    Applicability, ComplianceResult, ConformityAssessmentSummary, ConformityEvidence,
    EvaluationStatus, PassedCheck, RuleEvaluation, Violation, ViolationCategory, ViolationCounts,
    ViolationSeverity, compliance_score,
};
pub use rule_settings::{
    RuleSetting, RuleSettings, SettingSource, SeverityOverride, SuppressedRule,
};
pub use run_config::{ComplianceRunConfig, PqcInputsError, parse_as_of};
pub use selector::StandardSelector;
pub use standard_ref::{StandardKind, StandardRef};
// The vendor-hash metric behind SBOM-CRA-PRE-7-RQ-07-RE
// (quality/metrics.rs) classifies vendor components with the same
// sentinel-aware producer test the checks use.
pub(crate) use shared::has_known_producer;
// The same metric counts only plausible digests, as every hash rule does.
pub(crate) use shared::plausible_digest;
// The `cra-docs` dossier names the manufacturer the Art. 13(16) check
// accepts.
#[cfg(feature = "cli")]
pub(crate) use shared::manufacturer_name;
use shared::{
    SPDX2_NO_SIGNATURE, SPEC_VERSION_UNPARSED, ValueState, creator_contacts, creator_identified,
    digest_problems, document_signed, future_timestamp_violation, has_known_license,
    has_known_value, invalid_digest_note, is_contact_reference, is_declared_unknown,
    is_eucc_reference, is_placeholder, is_spdx2, is_valid_email_format, justified_not_affected,
    known_component_name, known_contact, known_value, license_state, manufacturer_identified,
    manufacturer_reference, name_with_digest_problems, observed, observed_digest,
    observed_producer, observed_unparsed_timestamp, truncate_list, unparseable_timestamp,
    unreachable_contact, unreachable_contact_note, unreachable_creator, unreachable_creator_note,
    unreachable_sidecar_note, value_state,
};

#[cfg(test)]
mod tests;
