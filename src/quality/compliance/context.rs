//! Dispatch layer: the [`StandardChecker`] trait, the read-only
//! [`ComplianceContext`] passed to each checker, the [`Findings`] each
//! checker returns, and the per-standard checker structs that turn
//! [`ComplianceLevel`] into a concrete set of findings.
//!
//! Each checker delegates to the (now module-split) check methods on
//! [`ComplianceChecker`]; the bodies are unchanged, so the dispatch is a pure
//! structural reorganisation of the previous `match self.level { … }` in
//! `ComplianceChecker::check`.
//!
//! # Checks that do not run
//!
//! A check that skips the SBOM on purpose says so: where it decides not to
//! run, it records the rule and the reason with [`NotEvaluated::push`], and
//! the result lists the entry under `evaluated` (see
//! [`RuleEvaluation`](super::RuleEvaluation) for which skips count). Without
//! the entry a skipped check reads like a passed one. A checker gets the list
//! as [`Findings::not_evaluated`] (the method of a `dedicated_checker!`
//! gets the whole [`Findings`]), or as a `&mut NotEvaluated` argument in a
//! check method the generic path calls:
//!
//! ```ignore
//! if spdx2 {
//!     not_evaluated.push("SBOM-CISA2026-SIGNATURE", SPDX2_NO_SIGNATURE);
//! } else if !has_signature {
//!     violations.push(/* … */);
//! }
//! ```

use super::evidence::SbomEvidence;
use super::{
    Applicability, ComplianceChecker, ComplianceLevel, NormalizedSbom, PassedCheck, RuleEvaluation,
    Violation,
};
use crate::model::AttestationDeclarations;

/// Read-only context threaded through every [`StandardChecker`].
///
/// Carries the [`ComplianceChecker`] configuration (level, sidecar, product
/// class) alongside the [`SbomEvidence`] of the SBOM under test, which the
/// levels of a run share. Checkers read both but never mutate either; they
/// return the violations they find.
pub(crate) struct ComplianceContext<'r, 'a> {
    /// The configured checker — source of level, sidecar, and product class,
    /// plus the shared severity-calibration helpers.
    pub(crate) checker: &'r ComplianceChecker,
    /// The facts of the SBOM being evaluated, at the run's instant.
    pub(crate) ev: &'r SbomEvidence<'a>,
    /// The SBOM being evaluated, for the checkers that do not read the
    /// evidence yet (see [`super::evidence`]).
    pub(crate) sbom: &'a NormalizedSbom,
}

impl<'r, 'a> ComplianceContext<'r, 'a> {
    pub(crate) const fn new(checker: &'r ComplianceChecker, ev: &'r SbomEvidence<'a>) -> Self {
        Self {
            checker,
            ev,
            sbom: ev.raw_sbom(),
        }
    }

    /// CDXA attestation declarations parsed from the document (CycloneDX
    /// 1.6+ `declarations` + `definitions.standards`), if any.
    ///
    /// Structural evidence only: signature objects in the returned model are
    /// PRESENCE records (algorithm, signatory identity) — nothing has been
    /// cryptographically verified, so no consumer may report an evidence
    /// level above `EvidenceLevel::SignaturePresent`.
    pub(crate) fn attestation_declarations(&self) -> Option<&'a AttestationDeclarations> {
        self.sbom.declarations()
    }
}

/// What one standard's checks report: the violations found, the checks the
/// SBOM passed, the checks that did not run, and whether the standard applied
/// to the SBOM at all.
///
/// An affirming check (a pass-only rule, [`RuleKind::Pass`](super::RuleKind))
/// pushes a [`PassedCheck`] to `passed`, never a violation. A check skipped
/// on purpose records itself in `not_evaluated` (see the module docs). A
/// readiness profile that does not apply (the EU AI Act and BSI/G7
/// SBOM-for-AI profiles on an SBOM without AI/ML content) says so through
/// [`Findings::not_applicable`] instead of reporting a placeholder violation.
/// [`ComplianceChecker::check`] copies all four into the
/// [`ComplianceResult`](super::ComplianceResult).
#[derive(Debug, Default)]
pub(crate) struct Findings {
    /// The violations the checks found.
    pub(crate) violations: Vec<Violation>,
    /// The checks the SBOM passed.
    pub(crate) passed: Vec<PassedCheck>,
    /// The checks that did not run on the SBOM.
    pub(crate) not_evaluated: NotEvaluated,
    /// Whether the standard evaluated the SBOM.
    pub(crate) applicability: Applicability,
}

impl Findings {
    /// Mark the standard as not applicable to the SBOM, for `reason`.
    pub(crate) fn not_applicable(&mut self, reason: impl Into<String>) {
        self.applicability = Applicability::NotApplicable(reason.into());
    }
}

/// The checks a standard did not run on the SBOM, in the order its checker
/// recorded them (see the module docs).
#[derive(Debug, Default)]
pub(crate) struct NotEvaluated(Vec<RuleEvaluation>);

impl NotEvaluated {
    /// Record that the check of `rule_id` did not run, for `reason`: one of
    /// the standard's rules, and sbom-tools' own words (no SBOM text). A
    /// rule is listed once; a repeat keeps the first reason.
    pub(crate) fn push(&mut self, rule_id: &'static str, reason: impl Into<String>) {
        debug_assert!(
            super::rule_kind(rule_id).is_some(),
            "{rule_id} is not a registered rule"
        );
        if !self.0.iter().any(|e| e.rule_id == rule_id) {
            self.0.push(RuleEvaluation::not_evaluated(rule_id, reason));
        }
    }

    /// The recorded checks.
    pub(crate) fn into_vec(self) -> Vec<RuleEvaluation> {
        self.0
    }
}

/// One compliance standard's check logic.
///
/// `level()` reports the [`ComplianceLevel`] the checker implements;
/// `check()` runs the standard against the context and returns its
/// [`Findings`]. The top-level [`ComplianceChecker::check`] selects the
/// checker for the configured level and merges its output.
pub(crate) trait StandardChecker {
    /// The compliance level this checker implements.
    fn level(&self) -> ComplianceLevel;

    /// Run the standard's checks against `ctx`, returning what they found.
    fn check(&self, ctx: &ComplianceContext) -> Findings;
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

    /// The checker for `level`, for the standards table.
    pub(crate) fn boxed(level: ComplianceLevel) -> Box<dyn StandardChecker> {
        Box::new(Self::new(level))
    }
}

impl StandardChecker for GenericChecker {
    fn level(&self) -> ComplianceLevel {
        self.level
    }

    fn check(&self, ctx: &ComplianceContext) -> Findings {
        let checker = ctx.checker;
        let mut findings = Findings::default();
        let Findings {
            violations,
            not_evaluated,
            ..
        } = &mut findings;

        // Check document-level requirements
        checker.check_document_metadata(ctx, violations, not_evaluated);

        // Check component requirements
        checker.check_components(ctx, violations);

        // Check dependency requirements
        checker.check_dependencies(ctx, violations);

        // Check vulnerability metadata (CRA readiness)
        checker.check_vulnerability_metadata(ctx, violations);

        // Check format-specific requirements
        checker.check_format_specific(ctx, violations, not_evaluated);

        // Check CRA-specific gap requirements (SBOM freshness, Art. 13(5), 13(9), Annex I Part II, document integrity)
        if checker.level.is_cra() {
            checker.check_cra_gaps(ctx, violations, not_evaluated);
            checker.check_hardware_components(ctx, violations, not_evaluated);
        }

        findings
    }
}

/// Generates a thin [`StandardChecker`] struct whose `check()` delegates to a
/// single dedicated method on [`ComplianceChecker`]. The method takes the
/// [`ComplianceContext`], whose evidence is all a check reads about the SBOM
/// (see [`super::evidence`]), and the whole [`Findings`], so a standard can
/// report passed checks, skip a check on purpose, or decide it does not
/// apply.
macro_rules! dedicated_checker {
    ($name:ident, $level:expr, $method:ident) => {
        pub(crate) struct $name;

        impl $name {
            /// The checker, for the standards table.
            pub(crate) fn boxed(_level: ComplianceLevel) -> Box<dyn StandardChecker> {
                Box::new(Self)
            }
        }

        impl StandardChecker for $name {
            fn level(&self) -> ComplianceLevel {
                $level
            }

            fn check(&self, ctx: &ComplianceContext) -> Findings {
                let mut findings = Findings::default();
                ctx.checker.$method(ctx, &mut findings);
                findings
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
dedicated_checker!(
    BsiSbomForAiChecker,
    ComplianceLevel::BsiSbomForAi,
    check_bsi_sbom_for_ai
);
dedicated_checker!(Cisa2026Checker, ComplianceLevel::Cisa2026, check_cisa2026);
dedicated_checker!(
    PciDss632Checker,
    ComplianceLevel::PciDss632,
    check_pci_dss_6_3_2
);
dedicated_checker!(FsctChecker, ComplianceLevel::Fsct, check_fsct);

/// Resolve the [`StandardChecker`] for a given level: the one its entry in
/// the standards table names. The dedicated profiles have their own
/// checker; the others take the generic path.
pub(crate) fn checker_for(level: ComplianceLevel) -> Box<dyn StandardChecker> {
    (level.descriptor().checker)(level)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        AttestationAssertion, AttestationMapEntry, AttestationRuleFamily, CdxaRef, CdxaResolution,
        DeclaredClaim, DeclaredEvidence, DefinedRequirement, DefinedStandard, EvidenceLevel,
        SignaturePresence,
    };

    fn ts(s: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(s)
            .expect("test timestamp must parse")
            .with_timezone(&chrono::Utc)
    }

    /// An SBOM whose declarations carry one fully-supported SSDF PS.1
    /// requirement (resolved refs, full conformance, fresh signed evidence).
    fn sbom_with_ssdf_declarations() -> NormalizedSbom {
        let declarations = AttestationDeclarations {
            claims: vec![DeclaredClaim {
                bom_ref: Some("claim-1".into()),
                target: Some(CdxaRef {
                    raw: "target-1".into(),
                    resolution: CdxaResolution::Target,
                }),
                evidence: vec![CdxaRef {
                    raw: "ev-1".into(),
                    resolution: CdxaResolution::Evidence,
                }],
                ..DeclaredClaim::default()
            }],
            evidence: vec![DeclaredEvidence {
                bom_ref: Some("ev-1".into()),
                created: Some(ts("2026-01-10T00:00:00Z")),
                expires: Some(ts("2027-01-10T00:00:00Z")),
                signature: Some(SignaturePresence {
                    algorithm: Some("ES256".into()),
                    key_id: None,
                    signer_count: 1,
                }),
                ..DeclaredEvidence::default()
            }],
            attestations: vec![AttestationAssertion {
                map: vec![AttestationMapEntry {
                    requirement: Some(CdxaRef {
                        raw: "req-ps1".into(),
                        resolution: CdxaResolution::Requirement,
                    }),
                    claims: vec![CdxaRef {
                        raw: "claim-1".into(),
                        resolution: CdxaResolution::Claim,
                    }],
                    conformance_score: Some(1.0),
                    ..AttestationMapEntry::default()
                }],
                ..AttestationAssertion::default()
            }],
            standards: vec![DefinedStandard {
                bom_ref: Some("std-ssdf".into()),
                name: Some("NIST Secure Software Development Framework".into()),
                requirements: vec![DefinedRequirement {
                    bom_ref: Some("req-ps1".into()),
                    identifier: Some("PS.1".into()),
                    ..DefinedRequirement::default()
                }],
                ..DefinedStandard::default()
            }],
            ..AttestationDeclarations::default()
        };
        let mut sbom = NormalizedSbom::default();
        sbom.extensions.declarations = Some(declarations);
        sbom
    }

    #[test]
    fn context_exposes_attestation_evidence_per_family() {
        let sbom = sbom_with_ssdf_declarations();
        let checker = ComplianceChecker::new(ComplianceLevel::NistSsdf)
            .with_as_of(ts("2026-06-01T00:00:00Z"));
        let ev = SbomEvidence::new(&sbom, checker.now());
        let ctx = ComplianceContext::new(&checker, &ev);

        assert!(ctx.attestation_declarations().is_some());
        let ssdf: Vec<_> = ctx
            .ev
            .supported_requirements(AttestationRuleFamily::Ssdf)
            .collect();
        assert_eq!(ssdf.len(), 1);
        assert_eq!(ssdf[0].requirement.identifier.as_deref(), Some("PS.1"));
        // Signature PRESENCE only — never SignatureVerified in phase 1.
        assert_eq!(ssdf[0].evidence_level, EvidenceLevel::SignaturePresent);
        let none = |family| ctx.ev.supported_requirements(family).next().is_none();
        assert!(none(AttestationRuleFamily::Cra));
        assert!(none(AttestationRuleFamily::Eo14028));
    }

    #[test]
    fn context_evidence_respects_pinned_clock_and_absence() {
        let sbom = sbom_with_ssdf_declarations();
        // Clock pinned after evidence expiry: fail closed, nothing supports SSDF.
        let expired = ComplianceChecker::new(ComplianceLevel::NistSsdf)
            .with_as_of(ts("2027-06-01T00:00:00Z"));
        let ev = SbomEvidence::new(&sbom, expired.now());
        let ctx = ComplianceContext::new(&expired, &ev);
        let none = |ctx: &ComplianceContext<'_, '_>| {
            ctx.ev
                .supported_requirements(AttestationRuleFamily::Ssdf)
                .next()
                .is_none()
        };
        assert!(none(&ctx));

        // No declarations at all: accessor is None, evidence queries are empty.
        let bare = NormalizedSbom::default();
        let checker = ComplianceChecker::new(ComplianceLevel::NistSsdf)
            .with_as_of(ts("2026-10-12T00:00:00Z"));
        let ev = SbomEvidence::new(&bare, checker.now());
        let ctx = ComplianceContext::new(&checker, &ev);
        assert!(ctx.attestation_declarations().is_none());
        assert!(none(&ctx));
    }
}
