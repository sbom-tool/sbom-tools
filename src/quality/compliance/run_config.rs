//! The inputs of one compliance run, shared by every entry point.
//!
//! `validate`, `quality`, `view` and `diff` (and their TUIs), `cra-docs`, the
//! diff reports and the timeline all build their checkers through a
//! [`ComplianceRunConfig`], so the same SBOM with the same inputs gets the
//! same verdicts on every surface. Which input reaches which level is
//! decided in one place: [`ComplianceRunConfig::checker`].

use super::{
    CnsaCategory, ComplianceChecker, ComplianceLevel, ComplianceResult, PqcMode, PqcProfile,
};
use crate::model::{CraProductClass, CraSidecarMetadata, NormalizedSbom};
use chrono::{DateTime, Utc};

/// The inputs of one compliance run: the evaluation clock (`--as-of`), the
/// CRA sidecar (`--cra-sidecar`, or the one found next to the SBOM), the
/// CRA product class (`--cra-product-class`) and how the crypto standards
/// judge quantum-vulnerable cryptography (`--pqc-mode`, `--pqc-profile`,
/// `--cnsa-category`).
///
/// [`Self::checker`] builds the checker for a level with exactly the inputs
/// that level reads, so no caller decides that itself.
///
/// ```
/// use sbom_tools::model::{CraProductClass, NormalizedSbom};
/// use sbom_tools::quality::{ComplianceLevel, ComplianceRunConfig};
///
/// let as_of = chrono::DateTime::parse_from_rfc3339("2027-01-01T00:00:00Z")
///     .unwrap()
///     .with_timezone(&chrono::Utc);
/// let run = ComplianceRunConfig::new()
///     .with_as_of(as_of)
///     .with_product_class(CraProductClass::ImportantClass1);
/// let sbom = NormalizedSbom::default();
/// let results = run.check_levels(
///     &[ComplianceLevel::CraPhase2, ComplianceLevel::NtiaMinimum],
///     &sbom,
/// );
/// assert_eq!(results.len(), 2);
/// ```
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ComplianceRunConfig {
    as_of: Option<DateTime<Utc>>,
    sidecar: Option<CraSidecarMetadata>,
    product_class: Option<CraProductClass>,
    pqc_mode: PqcMode,
    pqc_profile: PqcProfile,
    cnsa_category: Option<CnsaCategory>,
}

impl ComplianceRunConfig {
    /// A run with no inputs: the wall clock, no sidecar, no product class,
    /// PQC readiness mode.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            as_of: None,
            sidecar: None,
            product_class: None,
            pqc_mode: PqcMode::Readiness,
            pqc_profile: PqcProfile::Nist,
            cnsa_category: None,
        }
    }

    /// Pin the evaluation clock (`--as-of`). Every deadline-sensitive check
    /// (CRA Art. 14 readiness, SBOM age, EUCC certificate expiry) judges this
    /// instant instead of the wall clock, so a run is reproducible.
    #[must_use]
    pub const fn with_as_of(mut self, as_of: DateTime<Utc>) -> Self {
        self.as_of = Some(as_of);
        self
    }

    /// Attach the CRA sidecar: metadata the SBOM does not carry, such as the
    /// manufacturer and its contacts, the Art. 14 reporting channels, the
    /// support period, EUCC certificate evidence, the AI Act high-risk flag
    /// and the product class.
    #[must_use]
    pub fn with_sidecar(mut self, sidecar: CraSidecarMetadata) -> Self {
        self.sidecar = Some(sidecar);
        self
    }

    /// Set the CRA Annex III/IV product class (`--cra-product-class`). The
    /// sidecar's `productClass` wins over it.
    #[must_use]
    pub const fn with_product_class(mut self, class: CraProductClass) -> Self {
        self.product_class = Some(class);
        self
    }

    /// Judge quantum-vulnerable cryptography under CNSA 2.0 and NIST PQC by
    /// `mode` (`--pqc-mode`): readiness, the default, or by each finding's
    /// migration deadline at the run's clock (see
    /// [`ComplianceChecker::with_pqc_mode`]).
    #[must_use]
    pub const fn with_pqc_mode(mut self, mode: PqcMode) -> Self {
        self.pqc_mode = mode;
        self
    }

    /// The deadlines deadline mode applies under NIST PQC (`--pqc-profile`):
    /// NIST IR 8547's, the default, or the federal ones as well.
    #[must_use]
    pub const fn with_pqc_profile(mut self, profile: PqcProfile) -> Self {
        self.pqc_profile = profile;
        self
    }

    /// The CNSA 2.0 equipment category whose timeline deadline mode applies
    /// under CNSA 2.0 (`--cnsa-category`); unset, the strictest.
    #[must_use]
    pub const fn with_cnsa_category(mut self, category: CnsaCategory) -> Self {
        self.cnsa_category = Some(category);
        self
    }

    /// The pinned evaluation clock, or `None` for the wall clock.
    #[must_use]
    pub const fn as_of(&self) -> Option<DateTime<Utc>> {
        self.as_of
    }

    /// The attached CRA sidecar.
    #[must_use]
    pub const fn sidecar(&self) -> Option<&CraSidecarMetadata> {
        self.sidecar.as_ref()
    }

    /// The product class set with [`Self::with_product_class`].
    #[must_use]
    pub const fn product_class(&self) -> Option<CraProductClass> {
        self.product_class
    }

    /// How CNSA 2.0 and NIST PQC judge quantum-vulnerable cryptography.
    #[must_use]
    pub const fn pqc_mode(&self) -> PqcMode {
        self.pqc_mode
    }

    /// The deadlines deadline mode applies under NIST PQC.
    #[must_use]
    pub const fn pqc_profile(&self) -> PqcProfile {
        self.pqc_profile
    }

    /// The CNSA 2.0 equipment category set with
    /// [`Self::with_cnsa_category`].
    #[must_use]
    pub const fn cnsa_category(&self) -> Option<CnsaCategory> {
        self.cnsa_category
    }

    /// The product class the CRA phase checks use: the sidecar's
    /// `productClass`, else [`Self::product_class`]. `None` when neither sets
    /// one; the checks then keep their phase defaults.
    #[must_use]
    pub fn effective_product_class(&self) -> Option<CraProductClass> {
        self.sidecar
            .as_ref()
            .and_then(|s| s.product_class)
            .or(self.product_class)
    }

    /// The configured product class and the sidecar's, when both are set and
    /// differ. The sidecar's wins; callers warn about the conflict.
    #[must_use]
    pub fn product_class_conflict(&self) -> Option<(CraProductClass, CraProductClass)> {
        let sidecar_class = self.sidecar.as_ref().and_then(|s| s.product_class)?;
        self.product_class
            .filter(|class| *class != sidecar_class)
            .map(|class| (class, sidecar_class))
    }

    /// Whether a run hands the CRA sidecar to `level`'s checker. See
    /// [`Self::checker`] for why.
    #[must_use]
    pub const fn sidecar_applies(level: ComplianceLevel) -> bool {
        matches!(
            level,
            ComplianceLevel::CraPhase1
                | ComplianceLevel::CraPhase2
                | ComplianceLevel::CraOssSteward
                | ComplianceLevel::EuccSubstantial
                | ComplianceLevel::EuAiAct
        )
    }

    /// Whether a run hands the CRA product class to `level`'s checker. See
    /// [`Self::checker`] for why.
    #[must_use]
    pub const fn product_class_applies(level: ComplianceLevel) -> bool {
        matches!(
            level,
            ComplianceLevel::CraPhase1 | ComplianceLevel::CraPhase2
        )
    }

    /// Whether a run hands the PQC mode to `level`'s checker. See
    /// [`Self::checker`] for why.
    #[must_use]
    pub const fn pqc_mode_applies(level: ComplianceLevel) -> bool {
        matches!(level, ComplianceLevel::Cnsa2 | ComplianceLevel::NistPqc)
    }

    /// Whether a run hands the PQC profile to `level`'s checker. See
    /// [`Self::checker`] for why.
    #[must_use]
    pub const fn pqc_profile_applies(level: ComplianceLevel) -> bool {
        matches!(level, ComplianceLevel::NistPqc)
    }

    /// Whether a run hands the CNSA 2.0 category to `level`'s checker. See
    /// [`Self::checker`] for why.
    #[must_use]
    pub const fn cnsa_category_applies(level: ComplianceLevel) -> bool {
        matches!(level, ComplianceLevel::Cnsa2)
    }

    /// The checker for `level`, given the inputs of this run that `level`
    /// reads. This is the one place that decides which input reaches which
    /// level:
    ///
    /// | Input | Levels | Why |
    /// |---|---|---|
    /// | `as_of` | every level | A run judges one instant. Deadline-sensitive checks (CRA Art. 14 readiness, SBOM age, certificate expiry, PQC deadlines) read it. |
    /// | CRA sidecar | CRA Phase 1 and 2, OSS steward, EUCC, EU AI Act | It holds CRA metadata (manufacturer, disclosure contacts, Art. 14 channels, support period), EUCC certificate evidence and the AI Act high-risk flag. A sidecar next to the SBOM is used without being asked for, so the other standards, which judge the SBOM document alone, never read it. |
    /// | product class | CRA Phase 1 and 2 | The Annex III/IV class picks the manufacturer's conformity-assessment procedure (Art. 32), which calibrates the CRA phase checks. An open-source steward (Art. 24) follows no such procedure. |
    /// | PQC mode | CNSA 2.0, NIST PQC | Only the crypto standards judge quantum-vulnerable cryptography; deadline mode dates their findings by the migration schedules. |
    /// | PQC profile | NIST PQC | The federal deadlines (EO 14412, OMB M-26-15) bind federal civilian systems on NIST's schedule; national security systems follow CNSA 2.0. |
    /// | CNSA 2.0 category | CNSA 2.0 | The equipment category picks NSA's CNSA 2.0 preference and exclusive-use years. |
    ///
    /// The sidecar's `productClass` and `conformityAssessmentRoute` are the
    /// product class input too, so a level outside the product-class row
    /// gets the sidecar without them.
    #[must_use]
    pub fn checker(&self, level: ComplianceLevel) -> ComplianceChecker {
        let mut checker = ComplianceChecker::new(level);
        if let Some(as_of) = self.as_of {
            checker = checker.with_as_of(as_of);
        }
        if Self::pqc_mode_applies(level) {
            checker = checker.with_pqc_mode(self.pqc_mode);
        }
        if Self::pqc_profile_applies(level) {
            checker = checker.with_pqc_profile(self.pqc_profile);
        }
        if Self::cnsa_category_applies(level)
            && let Some(category) = self.cnsa_category
        {
            checker = checker.with_cnsa_category(category);
        }
        if Self::sidecar_applies(level)
            && let Some(sidecar) = &self.sidecar
        {
            let mut sidecar = sidecar.clone();
            if !Self::product_class_applies(level) {
                sidecar.product_class = None;
                sidecar.conformity_assessment_route = None;
            }
            checker = checker.with_sidecar(sidecar);
        }
        if Self::product_class_applies(level)
            && let Some(class) = self.product_class
        {
            checker = checker.with_product_class(class);
        }
        checker
    }

    /// Check `sbom` against `level` with this run's inputs.
    #[must_use]
    pub fn check(&self, level: ComplianceLevel, sbom: &NormalizedSbom) -> ComplianceResult {
        self.checker(level).check(sbom)
    }

    /// Check `sbom` against each of `levels`, in order.
    #[must_use]
    pub fn check_levels(
        &self,
        levels: &[ComplianceLevel],
        sbom: &NormalizedSbom,
    ) -> Vec<ComplianceResult> {
        levels
            .iter()
            .map(|level| self.check(*level, sbom))
            .collect()
    }

    /// Log a warning when the configured product class and the sidecar's
    /// differ (see [`Self::product_class_conflict`]).
    pub(crate) fn warn_on_product_class_conflict(&self) {
        if let Some((configured, sidecar)) = self.product_class_conflict() {
            tracing::warn!(
                "CRA product class mismatch: --cra-product-class={} but sidecar says {}; using sidecar.",
                configured.label(),
                sidecar.label()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ConformityRoute;

    fn as_of() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-10-12T00:00:00Z")
            .expect("valid instant")
            .with_timezone(&Utc)
    }

    fn sidecar() -> CraSidecarMetadata {
        CraSidecarMetadata {
            support_end_date: Some(as_of() + chrono::Duration::days(3650)),
            is_high_risk_ai: true,
            product_class: Some(CraProductClass::Critical),
            conformity_assessment_route: Some(ConformityRoute::ModuleH),
            ..Default::default()
        }
    }

    fn full_run() -> ComplianceRunConfig {
        ComplianceRunConfig::new()
            .with_as_of(as_of())
            .with_sidecar(sidecar())
            .with_product_class(CraProductClass::ImportantClass1)
            .with_pqc_mode(PqcMode::Deadline)
            .with_pqc_profile(PqcProfile::Federal)
            .with_cnsa_category(CnsaCategory::Niche)
    }

    /// The policy table of `checker`: every level gets the clock; the
    /// sidecar reaches the CRA, EUCC and AI Act profiles; the product class
    /// (from either channel) reaches the CRA phases only; the PQC mode
    /// reaches CNSA 2.0 and NIST PQC, the PQC profile NIST PQC and the CNSA
    /// 2.0 category CNSA 2.0.
    #[test]
    fn checker_hands_each_level_its_inputs() {
        let run = full_run();
        for level in ComplianceLevel::all() {
            let checker = run.checker(*level);
            assert_eq!(checker.now(), as_of(), "{level:?} reads the pinned clock");
            let crypto = matches!(level, ComplianceLevel::Cnsa2 | ComplianceLevel::NistPqc);
            assert_eq!(
                checker.pqc_mode(),
                if crypto {
                    PqcMode::Deadline
                } else {
                    PqcMode::Readiness
                },
                "{level:?}: PQC mode"
            );
            assert_eq!(
                checker.pqc_profile == PqcProfile::Federal,
                *level == ComplianceLevel::NistPqc,
                "{level:?}: PQC profile"
            );
            assert_eq!(
                checker.cnsa_category,
                (*level == ComplianceLevel::Cnsa2).then_some(CnsaCategory::Niche),
                "{level:?}: CNSA 2.0 category"
            );
            let sidecar_expected = matches!(
                level,
                ComplianceLevel::CraPhase1
                    | ComplianceLevel::CraPhase2
                    | ComplianceLevel::CraOssSteward
                    | ComplianceLevel::EuccSubstantial
                    | ComplianceLevel::EuAiAct
            );
            assert_eq!(
                checker.sidecar.is_some(),
                sidecar_expected,
                "{level:?}: sidecar"
            );
            let class_expected = matches!(
                level,
                ComplianceLevel::CraPhase1 | ComplianceLevel::CraPhase2
            );
            assert_eq!(
                checker.has_explicit_product_class(),
                class_expected,
                "{level:?}: product class"
            );
            if class_expected {
                // The sidecar's class wins over the configured one.
                assert_eq!(checker.effective_product_class(), CraProductClass::Critical);
                assert_eq!(checker.effective_route(), ConformityRoute::ModuleH);
            }
        }
    }

    /// A level outside the product-class row keeps every other sidecar
    /// field (the AI Act reads the high-risk flag).
    #[test]
    fn levels_without_a_class_keep_the_rest_of_the_sidecar() {
        let checker = full_run().checker(ComplianceLevel::EuAiAct);
        let sidecar = checker.sidecar.as_ref().expect("AI Act gets the sidecar");
        assert!(sidecar.is_high_risk_ai);
        assert!(sidecar.support_end_date.is_some());
        assert_eq!(sidecar.product_class, None);
        assert_eq!(sidecar.conformity_assessment_route, None);
        assert!(!checker.has_explicit_product_class());
    }

    /// An empty run reads the wall clock (built with `default()`: the test
    /// lint asks every `ComplianceRunConfig::new()` in a test to pin one).
    #[test]
    fn an_empty_run_reads_the_wall_clock_and_nothing_else() {
        let run = ComplianceRunConfig::default();
        assert_eq!(run.as_of(), None);
        assert!(run.sidecar().is_none());
        assert_eq!(run.effective_product_class(), None);
        assert_eq!(run.pqc_mode(), PqcMode::Readiness);
        assert_eq!(run.pqc_profile(), PqcProfile::Nist);
        assert_eq!(run.cnsa_category(), None);
        let checker = run.checker(ComplianceLevel::CraPhase2);
        assert!(checker.as_of.is_none());
        assert!(checker.sidecar.is_none());
        assert!(!checker.has_explicit_product_class());
        assert_eq!(
            run.checker(ComplianceLevel::NistPqc).pqc_mode(),
            PqcMode::Readiness
        );
    }

    #[test]
    fn effective_class_and_conflict() {
        let flag_only = ComplianceRunConfig::new()
            .with_as_of(as_of())
            .with_product_class(CraProductClass::ImportantClass2);
        assert_eq!(
            flag_only.effective_product_class(),
            Some(CraProductClass::ImportantClass2)
        );
        assert_eq!(flag_only.product_class_conflict(), None);

        let run = full_run();
        assert_eq!(
            run.effective_product_class(),
            Some(CraProductClass::Critical)
        );
        assert_eq!(
            run.product_class_conflict(),
            Some((CraProductClass::ImportantClass1, CraProductClass::Critical))
        );

        let agreeing = ComplianceRunConfig::new()
            .with_as_of(as_of())
            .with_sidecar(sidecar())
            .with_product_class(CraProductClass::Critical);
        assert_eq!(agreeing.product_class_conflict(), None);
    }

    #[test]
    fn check_levels_keeps_the_given_order() {
        let levels = [
            ComplianceLevel::Fsct,
            ComplianceLevel::CraPhase1,
            ComplianceLevel::NtiaMinimum,
        ];
        let results = full_run().check_levels(&levels, &NormalizedSbom::default());
        let got: Vec<ComplianceLevel> = results.iter().map(|r| r.level).collect();
        assert_eq!(got, levels);
    }
}
