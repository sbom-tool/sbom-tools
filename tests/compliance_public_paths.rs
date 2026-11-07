//! The public paths of the compliance engine.
//!
//! `quality::compliance` is a private module: the library exposes the
//! engine through the re-exports of `sbom_tools::quality`. This file names
//! every one of them once, by that path, so a refactor that moves an item
//! and drops its re-export fails the build here. Functions are named as
//! function pointers, so their signatures are pinned too.

use sbom_tools::quality::{
    Applicability, CISA2026_SARIF_RULE_IDS, CNSA2_SARIF_RULE_IDS, ClassCheck, CnsaCategory,
    ComplianceChecker, ComplianceLevel, ComplianceResult, ComplianceRunConfig,
    ConformityAssessmentSummary, ConformityEvidence, CraPhase, DOCUMENT_SUBJECT, Deadline,
    EO14028_SARIF_RULE_IDS, EvaluationStatus, FDA_SARIF_RULE_IDS, FINDING_ID_PREFIX,
    FSCT_SARIF_RULE_IDS, FieldAdvice, FindingIdentity, FormatAdvice, NTIA_SARIF_RULE_IDS,
    PASS_RULE_IDS, PCIDSS_SARIF_RULE_IDS, PQC_SARIF_RULE_IDS, PassedCheck, PqcInputsError, PqcMode,
    PqcProfile, RemediationFormat, RuleAdvice, RuleCatalogEntry, RuleCatalogFilter, RuleEvaluation,
    RuleFormatAdvice, RuleKind, RuleMeta, RuleReference, RuleSetting, RuleSettings,
    SSDF_SARIF_RULE_IDS, SettingSource, SeverityOverride, StandardKind, StandardRef,
    StandardSelector, SuppressedRule, Violation, ViolationCategory, ViolationCounts,
    ViolationSeverity, all_rule_ids, compliance_score, finding_fingerprint, finding_id,
    finding_key, finding_subject, generic_rule_id_for_level, parse_as_of, resolve_rule_id,
    rule_catalog, rule_catalog_entry, rule_kind, rule_meta, rules_for_level, standard_key,
};

/// The path of `T`; naming a type here is the check.
fn named<T: ?Sized>() -> &'static str {
    std::any::type_name::<T>()
}

#[test]
fn every_public_compliance_type_resolves() {
    let types = [
        named::<Applicability>(),
        named::<ClassCheck>(),
        named::<CnsaCategory>(),
        named::<ComplianceChecker>(),
        named::<ComplianceLevel>(),
        named::<ComplianceResult>(),
        named::<ComplianceRunConfig>(),
        named::<ConformityAssessmentSummary>(),
        named::<ConformityEvidence>(),
        named::<CraPhase>(),
        named::<Deadline>(),
        named::<EvaluationStatus>(),
        named::<FieldAdvice>(),
        named::<dyn FindingIdentity>(),
        named::<FormatAdvice>(),
        named::<PassedCheck>(),
        named::<PqcInputsError>(),
        named::<PqcMode>(),
        named::<PqcProfile>(),
        named::<RemediationFormat>(),
        named::<RuleAdvice>(),
        named::<RuleCatalogEntry>(),
        named::<RuleCatalogFilter>(),
        named::<RuleEvaluation>(),
        named::<RuleFormatAdvice>(),
        named::<RuleKind>(),
        named::<RuleMeta>(),
        named::<RuleReference>(),
        named::<RuleSetting>(),
        named::<RuleSettings>(),
        named::<SettingSource>(),
        named::<SeverityOverride>(),
        named::<StandardKind>(),
        named::<StandardRef>(),
        named::<StandardSelector>(),
        named::<SuppressedRule>(),
        named::<Violation>(),
        named::<ViolationCategory>(),
        named::<ViolationCounts>(),
        named::<ViolationSeverity>(),
    ];
    assert!(types.iter().all(|path| path.contains("sbom_tools")));
}

#[test]
fn every_public_compliance_constant_resolves() {
    let rule_lists: [&[&str]; 10] = [
        CISA2026_SARIF_RULE_IDS,
        CNSA2_SARIF_RULE_IDS,
        EO14028_SARIF_RULE_IDS,
        FDA_SARIF_RULE_IDS,
        FSCT_SARIF_RULE_IDS,
        NTIA_SARIF_RULE_IDS,
        PASS_RULE_IDS,
        PCIDSS_SARIF_RULE_IDS,
        PQC_SARIF_RULE_IDS,
        SSDF_SARIF_RULE_IDS,
    ];
    assert!(rule_lists.iter().all(|list| !list.is_empty()));
    let texts: [&str; 2] = [DOCUMENT_SUBJECT, FINDING_ID_PREFIX];
    assert!(texts.iter().all(|text| !text.is_empty()));
}

#[test]
fn every_public_compliance_function_resolves() {
    let _: fn() -> &'static [&'static str] = all_rule_ids;
    let _: fn(usize, usize, usize) -> u8 = compliance_score;
    let _: fn(&str) -> String = finding_fingerprint;
    let _: fn(&str) -> String = finding_id;
    let _: fn(ComplianceLevel, &Violation) -> String = finding_key::<Violation>;
    let _: for<'a> fn(&'a Violation) -> std::borrow::Cow<'a, str> = finding_subject::<Violation>;
    let _: fn(ComplianceLevel) -> &'static str = generic_rule_id_for_level;
    let _: fn(&str) -> Result<chrono::DateTime<chrono::Utc>, String> = parse_as_of;
    let _: fn(&str) -> Result<&'static str, String> = resolve_rule_id;
    let _: fn(&RuleCatalogFilter) -> Vec<RuleCatalogEntry> = rule_catalog;
    let _: fn(&str) -> Option<RuleCatalogEntry> = rule_catalog_entry;
    let _: fn(&str) -> Option<RuleKind> = rule_kind;
    let _: fn(&str) -> Option<RuleMeta> = rule_meta;
    let _: fn(ComplianceLevel) -> &'static [&'static str] = rules_for_level;
    let _: fn(ComplianceLevel) -> &'static str = standard_key;
}
