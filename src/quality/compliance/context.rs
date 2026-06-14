//! Dispatch layer: the [`StandardChecker`] trait, the read-only
//! [`ComplianceContext`] passed to each checker, and the per-standard checker
//! structs that turn [`ComplianceLevel`] into a concrete set of violations.
//!
//! Each checker delegates to the (now module-split) check methods on
//! [`ComplianceChecker`]; the bodies are unchanged, so the dispatch is a pure
//! structural reorganisation of the previous `match self.level { … }` in
//! `ComplianceChecker::check`.

use super::{ComplianceChecker, ComplianceLevel, NormalizedSbom, Violation};

/// Read-only context threaded through every [`StandardChecker`].
///
/// Carries the [`ComplianceChecker`] configuration (level, sidecar, product
/// class) alongside the [`NormalizedSbom`] under test. Checkers read both but
/// never mutate either; they return the violations they find.
pub(crate) struct ComplianceContext<'a> {
    /// The configured checker — source of level, sidecar, and product class,
    /// plus the shared severity-calibration helpers.
    pub(crate) checker: &'a ComplianceChecker,
    /// The SBOM being evaluated.
    pub(crate) sbom: &'a NormalizedSbom,
}

impl<'a> ComplianceContext<'a> {
    pub(crate) const fn new(checker: &'a ComplianceChecker, sbom: &'a NormalizedSbom) -> Self {
        Self { checker, sbom }
    }
}

/// One compliance standard's check logic.
///
/// `level()` reports the [`ComplianceLevel`] the checker implements;
/// `check()` runs the standard against the context and returns its
/// violations. The top-level [`ComplianceChecker::check`] selects the checker
/// for the configured level and merges its output.
pub(crate) trait StandardChecker {
    /// The compliance level this checker implements.
    fn level(&self) -> ComplianceLevel;

    /// Run the standard's checks against `ctx`, returning all violations.
    fn check(&self, ctx: &ComplianceContext) -> Vec<Violation>;
}

/// Generic profile path shared by the non-dedicated levels (Minimum,
/// Standard, NTIA, CRA Phase 1/2, FDA, Comprehensive). Runs the document,
/// component, dependency, vulnerability-metadata, and format-specific checks,
/// plus the CRA gap / hardware checks when the level is a CRA profile.
pub(crate) struct GenericChecker {
    level: ComplianceLevel,
}

impl GenericChecker {
    pub(crate) const fn new(level: ComplianceLevel) -> Self {
        Self { level }
    }
}

impl StandardChecker for GenericChecker {
    fn level(&self) -> ComplianceLevel {
        self.level
    }

    fn check(&self, ctx: &ComplianceContext) -> Vec<Violation> {
        let checker = ctx.checker;
        let sbom = ctx.sbom;
        let mut violations = Vec::new();

        // Check document-level requirements
        checker.check_document_metadata(sbom, &mut violations);

        // Check component requirements
        checker.check_components(sbom, &mut violations);

        // Check dependency requirements
        checker.check_dependencies(sbom, &mut violations);

        // Check vulnerability metadata (CRA readiness)
        checker.check_vulnerability_metadata(sbom, &mut violations);

        // Check format-specific requirements
        checker.check_format_specific(sbom, &mut violations);

        // Check CRA-specific gap requirements (Art. 13(3), 13(5), 13(9), Annex I Part III, Annex III)
        if checker.level.is_cra() {
            checker.check_cra_gaps(sbom, &mut violations);
            checker.check_hardware_components(sbom, &mut violations);
        }

        violations
    }
}

/// Generates a thin [`StandardChecker`] struct whose `check()` delegates to a
/// single dedicated method on [`ComplianceChecker`].
macro_rules! dedicated_checker {
    ($name:ident, $level:expr, $method:ident) => {
        pub(crate) struct $name;

        impl StandardChecker for $name {
            fn level(&self) -> ComplianceLevel {
                $level
            }

            fn check(&self, ctx: &ComplianceContext) -> Vec<Violation> {
                let mut violations = Vec::new();
                ctx.checker.$method(ctx.sbom, &mut violations);
                violations
            }
        }
    };
}

dedicated_checker!(NistSsdfChecker, ComplianceLevel::NistSsdf, check_nist_ssdf);
dedicated_checker!(Eo14028Checker, ComplianceLevel::Eo14028, check_eo14028);
dedicated_checker!(Cnsa2Checker, ComplianceLevel::Cnsa2, check_cnsa2);
dedicated_checker!(NistPqcChecker, ComplianceLevel::NistPqc, check_nist_pqc);
dedicated_checker!(
    BsiTr03183Checker,
    ComplianceLevel::BsiTr03183_2,
    check_bsi_tr_03183_2
);
dedicated_checker!(
    CraOssStewardChecker,
    ComplianceLevel::CraOssSteward,
    check_cra_oss_steward
);
dedicated_checker!(
    EuccSubstantialChecker,
    ComplianceLevel::EuccSubstantial,
    check_eucc_substantial
);
dedicated_checker!(EuAiActChecker, ComplianceLevel::EuAiAct, check_eu_ai_act);

/// Resolve the [`StandardChecker`] for a given level. The eight dedicated
/// profiles get their own checker; everything else takes the generic path.
pub(crate) fn checker_for(level: ComplianceLevel) -> Box<dyn StandardChecker> {
    match level {
        ComplianceLevel::NistSsdf => Box::new(NistSsdfChecker),
        ComplianceLevel::Eo14028 => Box::new(Eo14028Checker),
        ComplianceLevel::Cnsa2 => Box::new(Cnsa2Checker),
        ComplianceLevel::NistPqc => Box::new(NistPqcChecker),
        ComplianceLevel::BsiTr03183_2 => Box::new(BsiTr03183Checker),
        ComplianceLevel::CraOssSteward => Box::new(CraOssStewardChecker),
        ComplianceLevel::EuccSubstantial => Box::new(EuccSubstantialChecker),
        ComplianceLevel::EuAiAct => Box::new(EuAiActChecker),
        other => Box::new(GenericChecker::new(other)),
    }
}
