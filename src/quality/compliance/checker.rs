//! The compliance checker: its builder, the scope helpers the checks
//! share, the CRA product-class calibration, and `check()`, which runs
//! a level's checks and completes their findings from the registry.

use super::result::registry_refs;
use super::standards::Subjects;
use super::*;

/// Calibration check identifiers for `ComplianceChecker::class_severity()`.
///
/// Each variant corresponds to a row in the CRA-P3.2 calibration table —
/// the severity that a given finding should produce *given* the product
/// class (Default → Critical) and conformity-assessment route. `None`
/// from `class_severity()` means "this check is not applicable for the
/// given class" (typically Default doesn't carry EUCC/attestation
/// expectations).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ClassCheck {
    /// Vendor-supplied hash coverage below threshold ([PRE-7-RQ-07-RE]).
    VendorHashCoverage,
    /// EOL component present in SBOM.
    EolComponents,
    /// Dependency cycles detected.
    Cycles,
    /// Annex V Declaration-of-Conformity reference missing.
    DocReference,
    /// EUCC (Common Criteria) reference missing.
    EuccReference,
    /// PSIRT URL / 24h / 72h / ENISA channel missing (Art. 14).
    Psirt,
    /// Conformity-assessment-module certificate reference missing
    /// (only meaningful on Module B+C / H / EUCC routes; SBOM-CRA-ANNEX-VIII).
    ModuleAttestation,
}

/// Compliance checker for SBOMs.
///
/// To check with a run's inputs (clock, CRA sidecar, product class) as the
/// CLI and the TUIs do, build it with [`ComplianceRunConfig::checker`], which
/// gives each level only the inputs it reads.
#[derive(Debug, Clone)]
pub struct ComplianceChecker {
    /// Compliance level to check
    pub(super) level: ComplianceLevel,
    /// Optional CRA sidecar metadata that supplements the SBOM with
    /// manufacturer / disclosure / lifecycle fields the SBOM itself doesn't
    /// carry. When set, document-metadata checks consult the sidecar before
    /// emitting "missing" violations.
    pub(super) sidecar: Option<crate::model::CraSidecarMetadata>,
    /// Optional CRA Annex III/IV product class. Drives severity calibration
    /// for `class_severity()` (vendor-hash, EOL, cycles, DoC, EUCC, PSIRT,
    /// attestation). When `None`, behaves as `CraProductClass::Default`.
    product_class: Option<crate::model::CraProductClass>,
    /// Evaluation clock. `None` means wall clock; pin it (CLI `--as-of`,
    /// tests) so deadline-sensitive checks (Art. 14 readiness, SBOM age,
    /// EUCC certificate expiry) are reproducible across runs.
    pub(super) as_of: Option<chrono::DateTime<chrono::Utc>>,
    /// How CNSA 2.0 and NIST PQC judge quantum-vulnerable cryptography
    /// (CLI `--pqc-mode`); readiness unless set.
    pqc_mode: PqcMode,
    /// Whose deadlines deadline mode applies under NIST PQC (CLI
    /// `--pqc-profile`).
    pub(super) pqc_profile: PqcProfile,
    /// The CNSA 2.0 equipment category deadline mode applies (CLI
    /// `--cnsa-category`); `None` means the strictest.
    pub(super) cnsa_category: Option<CnsaCategory>,
    /// The run's rule settings (CLI `--rule`, the config file's
    /// `compliance.rules`), applied to the findings after the checks.
    pub(super) rule_settings: RuleSettings,
    /// Whether the package rules judge components whose scope is excluded
    /// too (CLI `--include-excluded-scope`); by default they leave them out.
    pub(super) include_excluded_scope: bool,
}

impl ComplianceChecker {
    /// Create a new compliance checker
    #[must_use]
    pub const fn new(level: ComplianceLevel) -> Self {
        Self {
            level,
            sidecar: None,
            product_class: None,
            as_of: None,
            pqc_mode: PqcMode::Readiness,
            pqc_profile: PqcProfile::Nist,
            cnsa_category: None,
            rule_settings: RuleSettings::new(),
            include_excluded_scope: false,
        }
    }

    /// Apply `settings` to the findings after the checks: a finding of a
    /// rule set to a severity takes it, and the findings of a rule that is
    /// off are dropped and counted in [`ComplianceResult::suppressed`]. The
    /// counts, the verdict and the score follow the severities it sets.
    #[must_use]
    pub fn with_rule_settings(mut self, settings: RuleSettings) -> Self {
        self.rule_settings = settings;
        self
    }

    /// Whether the package rules judge components whose scope is excluded
    /// too (`include`), or leave them out, the default (see
    /// [`ComplianceRunConfig::with_include_excluded_scope`]).
    #[must_use]
    pub const fn with_include_excluded_scope(mut self, include: bool) -> Self {
        self.include_excluded_scope = include;
        self
    }

    /// Whether the run leaves `comp` out of the package rules: its scope is
    /// excluded, the run does not judge such components, and it is not the
    /// document's primary component (the product itself is never left out).
    pub(crate) fn leaves_out(&self, sbom: &NormalizedSbom, comp: &crate::model::Component) -> bool {
        !self.include_excluded_scope
            && comp.scope == Some(crate::model::DependencyScope::Excluded)
            && sbom.primary_component_id.as_ref() != Some(&comp.canonical_id)
    }

    /// Whether the package rules judge `comp`: a package-scoped component
    /// (see [`crate::model::ComponentType::is_package_scoped`]) the run does
    /// not leave out for its excluded scope (see [`Self::leaves_out`]).
    pub(crate) fn judges_package(
        &self,
        sbom: &NormalizedSbom,
        comp: &crate::model::Component,
    ) -> bool {
        comp.component_type.is_package_scoped() && !self.leaves_out(sbom, comp)
    }

    /// The components package rules apply to (see [`Self::judges_package`]).
    /// Every per-component package check iterates through this or tests
    /// [`Self::judges_package`], so no standard can forget a carve-out.
    pub(crate) fn package_components<'a>(
        &'a self,
        sbom: &'a NormalizedSbom,
    ) -> impl Iterator<Item = &'a crate::model::Component> + 'a {
        sbom.components
            .values()
            .filter(move |c| self.judges_package(sbom, c))
    }

    /// How many package-scoped components this check leaves out of its
    /// package rules for their excluded scope: none for a standard without
    /// package rules (see [`ComplianceRunConfig::excluded_scope_applies`]).
    fn excluded_component_count(&self, ctx: &ComplianceContext<'_, '_>) -> usize {
        if !ComplianceRunConfig::excluded_scope_applies(self.level) {
            return 0;
        }
        ctx.ev
            .components()
            .filter(|c| c.package_scoped() && ctx.leaves_out(c))
            .count()
    }

    /// Pin the evaluation clock. Deadline-sensitive checks (Art. 14
    /// readiness, SBOM age, EUCC certificate expiry) evaluate against this
    /// instant instead of the wall clock — reproducible CI runs, testable
    /// boundary dates.
    #[must_use]
    pub const fn with_as_of(mut self, as_of: chrono::DateTime<chrono::Utc>) -> Self {
        self.as_of = Some(as_of);
        self
    }

    /// The evaluation instant: the pinned `as_of` clock, or the wall clock.
    pub(crate) fn now(&self) -> chrono::DateTime<chrono::Utc> {
        self.as_of.unwrap_or_else(chrono::Utc::now)
    }

    /// Judge quantum-vulnerable cryptography under CNSA 2.0 and NIST PQC by
    /// `mode` (CLI `--pqc-mode`). [`PqcMode::Readiness`], the default,
    /// reports every quantum-vulnerable algorithm as an Error;
    /// [`PqcMode::Deadline`] judges each by its migration deadline at the
    /// evaluation instant (see [`Self::with_as_of`]) and records the
    /// deadline on the finding ([`Violation::deadline`]).
    #[must_use]
    pub const fn with_pqc_mode(mut self, mode: PqcMode) -> Self {
        self.pqc_mode = mode;
        self
    }

    /// The deadlines [`PqcMode::Deadline`] applies under NIST PQC (CLI
    /// `--pqc-profile`): NIST IR 8547's, the default, or with
    /// [`PqcProfile::Federal`] the federal ones of EO 14412 and OMB
    /// M-26-15 as well. Readiness mode ignores it.
    #[must_use]
    pub const fn with_pqc_profile(mut self, profile: PqcProfile) -> Self {
        self.pqc_profile = profile;
        self
    }

    /// The CNSA 2.0 equipment category whose timeline [`PqcMode::Deadline`]
    /// applies under CNSA 2.0 (CLI `--cnsa-category`). Unset, the strictest
    /// applies. Readiness mode ignores it.
    #[must_use]
    pub const fn with_cnsa_category(mut self, category: CnsaCategory) -> Self {
        self.cnsa_category = Some(category);
        self
    }

    /// How CNSA 2.0 and NIST PQC judge quantum-vulnerable cryptography.
    #[must_use]
    pub const fn pqc_mode(&self) -> PqcMode {
        self.pqc_mode
    }

    /// The calendar the crypto checks judge by: `None` in readiness mode.
    pub(crate) fn pqc_calendar(&self) -> Option<Calendar> {
        (self.pqc_mode == PqcMode::Deadline).then(|| {
            Calendar::new(
                self.pqc_profile,
                self.cnsa_category,
                self.now().date_naive(),
            )
        })
    }

    /// Attach CRA sidecar metadata to supplement SBOM-level fields.
    ///
    /// Sidecar values are only consulted as fallbacks — fields present in the
    /// SBOM always take precedence. The CLI commands attach it through
    /// [`ComplianceRunConfig`] (`--cra-sidecar`, with auto-discovery for
    /// adjacent `<sbom>.cra.{json,yaml}` files), which gives it only to the
    /// levels that read it.
    #[must_use]
    pub fn with_sidecar(mut self, sidecar: crate::model::CraSidecarMetadata) -> Self {
        self.sidecar = Some(sidecar);
        self
    }

    /// Set the CRA Annex III/IV product class explicitly.
    ///
    /// Sidecar `productClass` (when set on the attached sidecar) wins over
    /// this; resolve via [`Self::effective_product_class`].
    #[must_use]
    pub const fn with_product_class(mut self, class: crate::model::CraProductClass) -> Self {
        self.product_class = Some(class);
        self
    }

    /// Resolve the effective product class:
    /// 1. sidecar `productClass` if present,
    /// 2. otherwise `with_product_class` value,
    /// 3. otherwise `CraProductClass::Default`.
    #[must_use]
    pub fn effective_product_class(&self) -> crate::model::CraProductClass {
        self.sidecar
            .as_ref()
            .and_then(|s| s.product_class)
            .or(self.product_class)
            .unwrap_or(crate::model::CraProductClass::Default)
    }

    /// Resolve the effective conformity-assessment route. Falls back to
    /// `CraProductClass::default_route()` when the sidecar doesn't pin one.
    #[must_use]
    pub fn effective_route(&self) -> crate::model::ConformityRoute {
        self.sidecar
            .as_ref()
            .and_then(|s| s.conformity_assessment_route)
            .unwrap_or_else(|| self.effective_product_class().default_route())
    }

    /// CRA-P3.2 calibration table — severity for a given check at the
    /// effective product class. Returns `None` when the check does not
    /// apply for that class (e.g., EUCC reference at `Default`).
    #[must_use]
    pub fn class_severity(&self, check: ClassCheck) -> Option<ViolationSeverity> {
        use crate::model::CraProductClass as C;
        let class = self.effective_product_class();
        match (check, class) {
            // Vendor-hash coverage threshold escalation handled by
            // `vendor_hash_thresholds()`; this row reflects the *severity*
            // emitted when the threshold is breached.
            (ClassCheck::VendorHashCoverage, C::Default | C::ImportantClass1) => {
                Some(ViolationSeverity::Warning)
            }
            (ClassCheck::VendorHashCoverage, C::ImportantClass2 | C::Critical) => {
                Some(ViolationSeverity::Error)
            }

            (ClassCheck::EolComponents, C::Default | C::ImportantClass1) => {
                Some(ViolationSeverity::Warning)
            }
            (ClassCheck::EolComponents, C::ImportantClass2 | C::Critical) => {
                Some(ViolationSeverity::Error)
            }

            (ClassCheck::Cycles, C::Default | C::ImportantClass1) => {
                Some(ViolationSeverity::Warning)
            }
            (ClassCheck::Cycles, C::ImportantClass2 | C::Critical) => {
                Some(ViolationSeverity::Error)
            }

            (ClassCheck::DocReference, C::Default) => Some(ViolationSeverity::Info),
            (ClassCheck::DocReference, C::ImportantClass1) => Some(ViolationSeverity::Warning),
            (ClassCheck::DocReference, C::ImportantClass2 | C::Critical) => {
                Some(ViolationSeverity::Error)
            }

            (ClassCheck::EuccReference, C::Default | C::ImportantClass1) => None,
            (ClassCheck::EuccReference, C::ImportantClass2) => Some(ViolationSeverity::Info),
            (ClassCheck::EuccReference, C::Critical) => Some(ViolationSeverity::Error),

            (ClassCheck::Psirt, C::Default | C::ImportantClass1) => {
                Some(ViolationSeverity::Warning)
            }
            (ClassCheck::Psirt, C::ImportantClass2 | C::Critical) => Some(ViolationSeverity::Error),

            (ClassCheck::ModuleAttestation, C::Default) => None,
            (ClassCheck::ModuleAttestation, C::ImportantClass1) => Some(ViolationSeverity::Warning),
            (ClassCheck::ModuleAttestation, C::ImportantClass2 | C::Critical) => {
                Some(ViolationSeverity::Error)
            }
        }
    }

    /// Vendor-hash coverage threshold (single-stage) below which a violation
    /// fires. The severity is `class_severity(VendorHashCoverage)`. Values:
    /// Default 50%, Important-1 80%, Important-2 80%, Critical 100%.
    #[must_use]
    pub fn vendor_hash_threshold(&self) -> f64 {
        use crate::model::CraProductClass as C;
        match self.effective_product_class() {
            C::Default => 0.50,
            C::ImportantClass1 | C::ImportantClass2 => 0.80,
            C::Critical => 1.00,
        }
    }

    /// Whether a CRA product class has been explicitly configured (either
    /// via `with_product_class()` or the attached sidecar). Used by the
    /// per-check calibration to decide whether to override phase-based
    /// defaults — when no class is set, existing phase-driven behavior is
    /// preserved verbatim for backwards compatibility.
    #[must_use]
    pub fn has_explicit_product_class(&self) -> bool {
        self.product_class.is_some()
            || self
                .sidecar
                .as_ref()
                .and_then(|s| s.product_class)
                .is_some()
    }

    /// Check an SBOM for compliance.
    ///
    /// Selects the [`StandardChecker`] for the configured level (the
    /// dedicated profiles get their own checker; the rest take the generic
    /// path), runs it, then back-fills harmonised-standard references (and,
    /// for violations, the remediation and the field path for the SBOM's
    /// format) from the rule registry, numbers the finding details of
    /// entries the SBOM repeats (so every violation and every passed check
    /// keeps a key of its own, see [`finding_key`]), applies the run's rule
    /// settings (see [`Self::with_rule_settings`]), records whether the
    /// standard applied, which of its checks it did not evaluate and how
    /// many components it left out for their excluded scope, and
    /// attaches the CRA Annex VIII conformity summary when a product class
    /// has been pinned on CRA Phase 1 or Phase 2.
    ///
    /// Every entry point builds its checkers through
    /// [`ComplianceRunConfig::checker`], which decides which of a run's
    /// inputs (clock, sidecar, product class) each level gets.
    #[must_use]
    pub fn check(&self, sbom: &NormalizedSbom) -> ComplianceResult {
        // One check judges one instant: an unpinned checker reads the wall
        // clock once, here, and judges every check at that instant.
        let as_of = self.now();
        let evidence = SbomEvidence::new(sbom, as_of);
        if self.as_of.is_some() {
            self.check_with(&evidence)
        } else {
            self.clone().with_as_of(as_of).check_with(&evidence)
        }
    }

    /// [`Self::check`] on `evidence`, the facts of the SBOM at this
    /// checker's pinned instant. [`ComplianceRunConfig::check_levels`]
    /// shares one evidence value across the levels of a run.
    pub(crate) fn check_with(&self, evidence: &SbomEvidence<'_>) -> ComplianceResult {
        debug_assert_eq!(
            self.as_of,
            Some(evidence.as_of()),
            "a checker judges the instant of the evidence it reads"
        );
        let sbom = evidence.raw_sbom();
        let ctx = ComplianceContext::new(self, evidence);
        let checker = checker_for(self.level);
        debug_assert_eq!(
            checker.level(),
            self.level,
            "dispatched checker must match the configured level"
        );
        let Findings {
            mut violations,
            mut passed,
            not_evaluated,
            applicability,
        } = checker.check(&ctx);
        let evaluated = not_evaluated.into_vec();
        debug_assert!(
            evaluated.iter().all(|e| {
                rules_for_level(self.level).contains(&e.rule_id)
                    && !violations.iter().any(|v| v.rule_id == e.rule_id)
                    && !passed.iter().any(|p| p.rule_id == e.rule_id)
            }),
            "a check not evaluated must be one of the level's rules and report nothing"
        );
        debug_assert!(
            violations
                .iter()
                .all(|v| rule_kind(v.rule_id) != Some(RuleKind::Pass)),
            "a pass-only rule must report a PassedCheck, never a violation"
        );
        debug_assert!(
            passed
                .iter()
                .all(|p| rule_kind(p.rule_id) == Some(RuleKind::Pass)),
            "a passed check must come from a registered pass-only rule"
        );

        // Populate harmonised-standard references, and the remediation and
        // the field path for the input format, from the rule registry: one
        // lookup per finding, and each borrows its rule's text.
        let format = RemediationFormat::of(&sbom.document);
        let primary = sbom.primary_component_id.as_ref().map(|id| id.value());
        for v in &mut violations {
            let rule = indexed_rule(v.rule_id);
            if v.standard_refs.is_empty()
                && let Some(rule) = rule
            {
                v.standard_refs = Cow::Borrowed(&rule.refs);
            }
            if v.remediation.is_none() {
                v.remediation = Some(Cow::Borrowed(
                    rule.map_or(REMEDIATION_UNREGISTERED, |rule| rule.remediation(format)),
                ));
            }
            if v.field.is_none() {
                let about_primary = primary.is_some() && v.component_id.as_deref() == primary;
                v.field = rule
                    .and_then(|rule| rule.field(format, about_primary))
                    .map(Cow::Borrowed);
            }
        }
        for p in &mut passed {
            if p.standard_refs.is_empty() {
                p.standard_refs = Cow::Borrowed(registry_refs(p.rule_id));
            }
        }
        // Every finding keeps a key of its own, also where the SBOM lists
        // one entry twice. Violations and passes never share a rule, so
        // numbering each list keeps their keys apart too.
        finding::number_repeated_details(&mut violations);
        finding::number_repeated_details(&mut passed);

        // The run's rule settings, after the checks and before the counts:
        // the verdict, the counts and the score follow the severities they
        // set, and what `off` drops is counted, never lost silently.
        let suppressed = self.rule_settings.apply(&mut violations);

        let mut result = ComplianceResult::new(self.level, violations)
            .with_passed(passed)
            .with_elements_checked(self.elements_checked(&ctx))
            .with_evaluated(evaluated);
        result.applicability = applicability;
        result.suppressed = suppressed;
        result.excluded_components = self.excluded_component_count(&ctx);
        // Attach the CRA Annex VIII conformity summary when a product class
        // has been pinned and the level is a CRA phase profile. Annex VIII
        // lists the manufacturer's conformity-assessment procedures; an
        // open-source steward (Art. 24, `CraOssSteward`) follows none.
        if self.level.cra_phase().is_some() && self.has_explicit_product_class() {
            result.conformity_summary = Some(self.build_conformity_summary(&ctx));
        }
        result
    }
}

impl Default for ComplianceChecker {
    fn default() -> Self {
        Self::new(ComplianceLevel::Standard)
    }
}

impl ComplianceChecker {
    /// The elements this check judges in the SBOM of `ctx`, the unit its
    /// score is normalised by (see [`ComplianceResult::elements_checked`]):
    /// the document, plus the components in the standard's scope. The
    /// package standards count the components their package rules judge,
    /// so the ones left out for their excluded scope do not count.
    fn elements_checked(&self, ctx: &ComplianceContext<'_, '_>) -> usize {
        let components = match self.level.descriptor().subjects {
            // EUCC checks the sidecar's certification evidence, not components.
            Subjects::CertificationEvidence => 0,
            // All components: the count selects cryptographic assets by type,
            // the subjects of the CNSA 2.0 and PQC checks.
            Subjects::CryptographicAssets => ctx
                .ev
                .components()
                .filter(|c| *c.component_type() == crate::model::ComponentType::Cryptographic)
                .count(),
            // The AI-BOM scope the AI profiles judge, a model with dataset
            // evidence counted once.
            Subjects::AiBom => ctx.ev.ai().component_count,
            Subjects::Packages => ctx.package_count(),
        };
        components.saturating_add(1)
    }
}
