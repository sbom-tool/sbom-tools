//! The result model: a standard's violations, passed checks and checks
//! not evaluated, their counts, the score, and the CRA conformity
//! summary, with the serde forms the reports write and read back.

use super::*;

/// A compliance violation
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Violation {
    /// Severity: error, warning, info. The one the run's rule settings give
    /// the finding's rule, if they set it (see
    /// [`Violation::severity_override`]).
    pub severity: ViolationSeverity,
    /// When the run's rule settings set the finding's rule (`--rule`, the
    /// config file's `compliance.rules`): the severity the check gave the
    /// finding and where the setting comes from. `None` for a rule the run
    /// does not set.
    ///
    /// Serialized as `default_severity` and `severity_source`, both omitted
    /// when `None`; old payloads without them deserialize to `None`.
    pub severity_override: Option<SeverityOverride>,
    /// Category of the violation
    pub category: ViolationCategory,
    /// Human-readable message
    pub message: String,
    /// Component or element that violated (if applicable).
    ///
    /// This is a human-readable *label* (usually the component name, sometimes
    /// a format id) and is not unique across versions or duplicate names — use
    /// [`Violation::component_id`] as the machine-readable join key.
    pub element: Option<String>,
    /// Canonical id of the offending component, when component-scoped.
    ///
    /// Unlike [`Violation::element`], this is a stable join key back to the
    /// SBOM component (the component's `CanonicalId`), so machine consumers
    /// can reliably correlate findings with components. `None` for
    /// document-level and aggregate findings.
    ///
    /// Serialized as `component_id`, omitted when `None`; old payloads
    /// without the field deserialize to `None`.
    pub component_id: Option<String>,
    /// What tells this finding apart from the rule's other findings on the
    /// same subject, for a rule that legitimately reports several: a value
    /// from the SBOM's own data, such as the vulnerability id of a
    /// per-vulnerability finding or the cipher suite of a per-suite one.
    /// Never message text, so rewording a message cannot change it. Where
    /// the SBOM lists one entry twice, `ComplianceChecker::check()` numbers
    /// the repeat (`CVE-2024-3094#2`).
    ///
    /// Part of the finding key (see [`finding_key`]). `None` for rules that
    /// report at most one finding per subject. Serialized as
    /// `finding_detail`, omitted when `None`; old payloads without the field
    /// deserialize to `None`.
    pub finding_detail: Option<String>,
    /// Affected/total component counts for aggregate findings.
    ///
    /// Mirrors the numbers embedded in the human-readable `message`
    /// (e.g. "7/10 components (70%)…") in structured form. `None` for
    /// non-aggregate findings.
    ///
    /// Serialized as `counts`, omitted when `None`; old payloads without the
    /// field deserialize to `None`.
    pub counts: Option<ViolationCounts>,
    /// When the algorithm a crypto finding is about must be replaced: the
    /// milestone [`PqcMode::Deadline`] judged it against and the schedule
    /// that sets it. `None` in readiness mode (the default), for a finding
    /// no schedule dates, and for every finding outside CNSA 2.0 and NIST
    /// PQC.
    ///
    /// Serialized as `deadline` (`YYYY-MM-DD`) and `deadline_source`, both
    /// omitted when `None`; old payloads without them deserialize to `None`.
    pub deadline: Option<Deadline>,
    /// Where the field the rule checks lives in the SBOM's own format: the
    /// registry's field path for the document's format (the
    /// [`FieldAdvice::field`] that `sbom-tools rules explain` shows), such as
    /// `components[].supplier.name` in CycloneDX, `packages[].supplier` in
    /// SPDX 2.x or `suppliedBy` in SPDX 3.0. For a finding about the primary
    /// component of a CycloneDX document, the path starts at
    /// `metadata.component` instead (`metadata.component.supplier.name`).
    ///
    /// Populated by `ComplianceChecker::check()` from [`Violation::rule_id`]
    /// and the input format, as [`Violation::remediation`] is, borrowing the
    /// registry's text. `None` when the rule names no field in that format
    /// (the fix is the same in every format, such as an algorithm choice)
    /// and on violations built outside the checker.
    ///
    /// Serialized as `field`, omitted when `None`; old payloads without it
    /// deserialize to `None`.
    pub field: Option<Cow<'static, str>>,
    /// The value the check read from the SBOM, where there is one: the
    /// placeholder in a supplier field, a digest that does not count, a
    /// timestamp in the future, the algorithm a crypto check rejected. Kept
    /// as read, like [`Violation::message`] and [`Violation::element`], and
    /// cut to 200 characters, ending in `…` when cut: a renderer that shows
    /// it cleans it as it cleans them. `None` when the field is absent or the
    /// check reads no single value.
    ///
    /// Serialized as `observed`, omitted when `None`; old payloads without
    /// it deserialize to `None`.
    pub observed: Option<String>,
    /// Standard/requirement being violated
    pub requirement: String,
    /// Stable internal rule key, set at the check site, indexing into
    /// [`rule_meta`]. This — not the human-readable message — drives the
    /// externally-visible SARIF rule ID, the harmonised-standard references,
    /// and the remediation text. Defaults to `"SBOM-CRA-GENERAL"` for
    /// violations built outside the checker (e.g., from external config).
    ///
    /// Serialized as `rule_id` (alongside a derived `sarif_rule_id`; see the
    /// manual [`Serialize`] impl) so machine consumers get a stable rule key
    /// instead of regexing the message. Deserialization maps a known id back
    /// to its registry `&'static str` key and falls back to the generic
    /// default for unknown ids or old payloads without the field.
    pub rule_id: &'static str,
    /// Structured references to harmonised-standard / regulation clauses.
    ///
    /// Populated by `ComplianceChecker::check()` from [`Violation::rule_id`]
    /// via [`rule_meta`], borrowing the registry's list, which every finding
    /// of the rule shares. Empty when a violation's rule maps to no
    /// references.
    pub standard_refs: Cow<'static, [StandardRef]>,
    /// Remediation guidance phrased for the format of the SBOM the violation
    /// was found in (see [`RuleMeta::remediation_for`]).
    ///
    /// Populated by `ComplianceChecker::check()` from [`Violation::rule_id`]
    /// and the input format, as [`Violation::standard_refs`] is, borrowing
    /// the registry's text, which is rendered once per rule and format.
    /// `None` on violations built outside the checker; read it through
    /// [`Violation::remediation_guidance`], which then falls back to the
    /// registry advice for every format.
    ///
    /// Serialized as `remediation` (always present); old payloads without
    /// the field deserialize to `None`.
    pub remediation: Option<Cow<'static, str>>,
}

/// Affected/total component counts carried by aggregate findings.
///
/// Structured mirror of the coverage numbers that aggregate checks embed in
/// the human-readable message (e.g. "7/10 components (70%)…"), so machine
/// consumers can extract them without regexing the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ViolationCounts {
    /// Numerator as printed in the message — usually the number of offending
    /// components; for coverage-style findings ("only X/Y carry …") it is the
    /// covered count, exactly as the message states it.
    pub affected: usize,
    /// Total number of components considered (the message's denominator).
    pub total: usize,
}

/// The coverage findings: rules whose [`ViolationCounts::affected`] is the
/// covered count ("only X/Y carry …"), so `total - affected` items fail.
/// Every other aggregate finding counts the failing items.
/// [`Violation::failed_checks`] reads this.
const COVERAGE_COUNT_RULE_IDS: &[&str] = &[
    "SBOM-CRA-PRE-7-RQ-07-RE",
    "SBOM-FSCT-COPYRIGHT-COVERAGE",
    "SBOM-FSCT-LICENSE-COVERAGE",
];

/// Serde default for [`Violation::rule_id`] when deserializing payloads that
/// predate the field.
fn default_rule_id() -> &'static str {
    "SBOM-CRA-GENERAL"
}

/// Owned mirror of [`Violation`] used for deserialization: `rule_id` arrives
/// as an owned string (or is absent in old payloads) and is mapped back to
/// its registry `&'static str` key. A derived `Deserialize` directly on
/// [`Violation`] would implicitly borrow the `&'static str` field from the
/// input (`'de: 'static`), which does not hold for streamed payloads.
#[derive(Deserialize)]
struct ViolationPayload {
    severity: ViolationSeverity,
    #[serde(default)]
    default_severity: Option<ViolationSeverity>,
    #[serde(default)]
    severity_source: Option<SettingSource>,
    category: ViolationCategory,
    message: String,
    element: Option<String>,
    #[serde(default)]
    component_id: Option<String>,
    #[serde(default)]
    finding_detail: Option<String>,
    #[serde(default)]
    counts: Option<ViolationCounts>,
    #[serde(default)]
    deadline: Option<chrono::NaiveDate>,
    #[serde(default)]
    deadline_source: Option<String>,
    #[serde(default)]
    field: Option<String>,
    #[serde(default)]
    observed: Option<String>,
    requirement: String,
    #[serde(default)]
    rule_id: Option<String>,
    #[serde(default)]
    standard_refs: Vec<StandardRef>,
    #[serde(default)]
    remediation: Option<String>,
}

impl<'de> Deserialize<'de> for Violation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let payload = ViolationPayload::deserialize(deserializer)?;
        Ok(Self {
            severity: payload.severity,
            // An override is the check's severity and the setting's source
            // together.
            severity_override: payload
                .default_severity
                .zip(payload.severity_source)
                .map(|(default, source)| SeverityOverride::new(default, source)),
            category: payload.category,
            message: payload.message,
            element: payload.element,
            component_id: payload.component_id,
            finding_detail: payload.finding_detail,
            counts: payload.counts,
            // A deadline is its date and its source together.
            deadline: payload
                .deadline
                .zip(payload.deadline_source)
                .map(|(date, source)| Deadline { date, source }),
            field: payload.field.map(Cow::Owned),
            observed: payload.observed,
            requirement: payload.requirement,
            // Unknown ids (from newer/older registries) collapse to the
            // generic default rather than failing deserialization; the
            // serialized `sarif_rule_id` and `help_uri` companion fields are
            // derived, so they are ignored here.
            rule_id: payload
                .rule_id
                .as_deref()
                .and_then(lookup_static_rule_id)
                .unwrap_or_else(default_rule_id),
            standard_refs: Cow::Owned(payload.standard_refs),
            remediation: payload.remediation.map(Cow::Owned),
        })
    }
}

impl Serialize for Violation {
    /// Manual impl so the JSON carries both the stable internal `rule_id` and
    /// the externally-visible `sarif_rule_id` derived from the rule registry
    /// (never stored, so it cannot drift). Field order mirrors declaration
    /// order; `standard_refs` is skipped when empty, and `component_id` /
    /// `finding_detail` / `counts` are skipped when `None`, as their
    /// serde-derive `skip_serializing_if = "Option::is_none"` equivalents
    /// would be. A `deadline` is written as two fields, `deadline` and
    /// `deadline_source`, both skipped when `None`, and so are `field` and
    /// `observed`. A `severity_override` is written as `default_severity`
    /// and `severity_source`, right after `severity`, both skipped when
    /// `None`. `remediation` is always written (see
    /// [`Violation::remediation_guidance`]), followed by the derived
    /// `help_uri` (see [`Violation::help_uri`]), skipped when there is none.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let has_refs = !self.standard_refs.is_empty();
        let has_component_id = self.component_id.is_some();
        let has_finding_detail = self.finding_detail.is_some();
        let has_counts = self.counts.is_some();
        let help_uri = self.help_uri();
        let mut state = serializer.serialize_struct(
            "Violation",
            8 + usize::from(has_refs)
                + 2 * usize::from(self.severity_override.is_some())
                + usize::from(has_component_id)
                + usize::from(has_finding_detail)
                + usize::from(has_counts)
                + 2 * usize::from(self.deadline.is_some())
                + usize::from(self.field.is_some())
                + usize::from(self.observed.is_some())
                + usize::from(help_uri.is_some()),
        )?;
        state.serialize_field("severity", &self.severity)?;
        if let Some(severity_override) = &self.severity_override {
            state.serialize_field("default_severity", &severity_override.default)?;
            state.serialize_field("severity_source", &severity_override.source)?;
        } else {
            state.skip_field("default_severity")?;
            state.skip_field("severity_source")?;
        }
        state.serialize_field("category", &self.category)?;
        state.serialize_field("message", &self.message)?;
        state.serialize_field("element", &self.element)?;
        if has_component_id {
            state.serialize_field("component_id", &self.component_id)?;
        } else {
            state.skip_field("component_id")?;
        }
        if has_finding_detail {
            state.serialize_field("finding_detail", &self.finding_detail)?;
        } else {
            state.skip_field("finding_detail")?;
        }
        if has_counts {
            state.serialize_field("counts", &self.counts)?;
        } else {
            state.skip_field("counts")?;
        }
        if let Some(deadline) = &self.deadline {
            state.serialize_field("deadline", &deadline.date)?;
            state.serialize_field("deadline_source", &deadline.source)?;
        } else {
            state.skip_field("deadline")?;
            state.skip_field("deadline_source")?;
        }
        if let Some(field) = &self.field {
            state.serialize_field("field", field)?;
        } else {
            state.skip_field("field")?;
        }
        if let Some(observed) = &self.observed {
            state.serialize_field("observed", observed)?;
        } else {
            state.skip_field("observed")?;
        }
        state.serialize_field("requirement", &self.requirement)?;
        state.serialize_field("rule_id", self.rule_id)?;
        // Same registry lookup + fallback as the SARIF renderer, so the same
        // violation carries the same external rule id on every surface.
        state.serialize_field("sarif_rule_id", self.sarif_rule_id())?;
        if has_refs {
            state.serialize_field("standard_refs", &self.standard_refs)?;
        } else {
            state.skip_field("standard_refs")?;
        }
        state.serialize_field("remediation", &self.remediation_guidance())?;
        if let Some(uri) = help_uri {
            state.serialize_field("help_uri", uri)?;
        } else {
            state.skip_field("help_uri")?;
        }
        state.end()
    }
}

impl Violation {
    /// Structured standard references for this violation, looked up from the
    /// rule registry by [`Violation::rule_id`].
    ///
    /// References are returned in registry order — typically the most specific
    /// harmonised-standard ID first, then the regulation reference. The
    /// registry, not the human-readable `requirement` string, is the single
    /// source of truth, so rewording a message can never silently drop a
    /// prEN/BSI cross-reference.
    ///
    /// `ComplianceChecker::check()` stores the registry's list in
    /// `Violation::standard_refs` (borrowed, not copied), so most consumers
    /// should read the field directly rather than re-deriving.
    #[must_use]
    pub fn registry_standard_refs(&self) -> Vec<StandardRef> {
        registry_refs(self.rule_id).to_vec()
    }

    /// Remediation guidance for this violation: the [`Violation::remediation`]
    /// that `ComplianceChecker::check()` phrased for the input format, or —
    /// for violations built outside the checker — the registry advice for
    /// every format (see [`RuleMeta::remediation_all_formats`]).
    ///
    /// Every renderer (JSON, text, Markdown, HTML, TUI) reads remediation
    /// through this, so the same violation shows the same text everywhere.
    #[must_use]
    pub fn remediation_guidance(&self) -> Cow<'_, str> {
        match &self.remediation {
            Some(text) => Cow::Borrowed(text),
            None => Cow::Borrowed(
                indexed_rule(self.rule_id).map_or(REMEDIATION_UNREGISTERED, |rule| {
                    &rule.remediation_all_formats
                }),
            ),
        }
    }

    /// Registry remediation for this violation's rule, phrased for `format`.
    /// `ComplianceChecker::check()` stores the same text, borrowed, in
    /// [`Violation::remediation`].
    #[must_use]
    pub fn registry_remediation(&self, format: RemediationFormat) -> String {
        registry_remediation(self.rule_id, format).to_string()
    }

    /// The documentation link of this violation's rule: the URL of the first
    /// standard reference that has one (see
    /// [`StandardKind::canonical_help_uri`]), else the page of the rule's
    /// standard family, as the rule catalogue (`sbom-tools rules`) and the
    /// SARIF rule's `helpUri` give it. Serialized as `help_uri`; `None` only
    /// for a rule of no known family.
    #[must_use]
    pub fn help_uri(&self) -> Option<&str> {
        self.standard_refs
            .iter()
            .find_map(|r| r.help_uri.as_deref())
            .or_else(|| rule_family_help_uri(self.rule_id))
    }

    /// Externally-visible SARIF rule id for this violation, looked up from
    /// the rule registry by [`Violation::rule_id`]. Every check is its own
    /// SARIF rule, so for every registered key — i.e. every violation the
    /// checkers produce — this is the key itself, and JSON and SARIF agree.
    /// Truly unregistered keys (violations built outside the checkers, e.g.
    /// from external config) fall back to the generic CRA rule here; the
    /// SARIF renderer additionally re-buckets those by standard family
    /// ([`generic_rule_id_for_level`]), which is the one residual place the
    /// two outputs can differ.
    #[must_use]
    pub fn sarif_rule_id(&self) -> &'static str {
        registry_sarif_id(self.rule_id)
    }

    /// The checks this finding failed, the unit the score counts (see
    /// [`compliance_score`]): none for an Info finding and one for a finding
    /// about one subject. An aggregate finding (one with
    /// [`Violation::counts`]) failed one check per item it reports as
    /// failing, and at least one: `counts.affected`, or `counts.total -
    /// counts.affected` for a coverage finding, whose `affected` counts the
    /// items that pass.
    #[must_use]
    pub fn failed_checks(&self) -> usize {
        if self.severity == ViolationSeverity::Info {
            return 0;
        }
        let Some(counts) = self.counts else {
            return 1;
        };
        let failing = if COVERAGE_COUNT_RULE_IDS.contains(&self.rule_id) {
            counts.total.saturating_sub(counts.affected)
        } else {
            counts.affected
        };
        failing.max(1)
    }
}

/// The harmonised-standard references the registry lists for `rule_id`, in
/// registry order; empty for an unregistered id.
pub(super) fn registry_refs(rule_id: &str) -> &'static [StandardRef] {
    indexed_rule(rule_id).map_or(&[], |rule| &rule.refs)
}

/// The registry remediation for `rule_id`, phrased for `format`; the
/// unregistered-rule text for an unregistered id.
fn registry_remediation(rule_id: &str, format: RemediationFormat) -> &'static str {
    indexed_rule(rule_id).map_or(REMEDIATION_UNREGISTERED, |rule| rule.remediation(format))
}

/// The externally-visible SARIF rule id of `rule_id`; the generic CRA rule
/// for an unregistered id.
fn registry_sarif_id(rule_id: &str) -> &'static str {
    indexed_rule(rule_id).map_or("SBOM-CRA-GENERAL", |rule| rule.meta.sarif_id)
}

/// A check the SBOM passed: what a pass-only rule ([`RuleKind::Pass`])
/// reports, such as SBOM-PQC-009's "uses a NIST-approved PQC algorithm".
///
/// A pass is no finding to act on, so it is kept apart from the violations:
/// it has no severity, counts toward neither `info_count` nor the score, and
/// is a SARIF result only under `--sarif-include-passes` (then of
/// `kind: "pass"`). It has a finding key built like a violation's (see
/// [`finding_key`]), and the two share one key space: a rule reports either
/// violations or passes, never both.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PassedCheck {
    /// Stable internal rule key, a [`RuleKind::Pass`] rule of the registry.
    pub rule_id: &'static str,
    /// Human-readable statement of what passed.
    pub message: String,
    /// Human-readable label of the element the check is about (usually the
    /// component name). Not unique: [`PassedCheck::component_id`] is the
    /// join key.
    pub element: Option<String>,
    /// Canonical id of the component the check is about; `None` for a
    /// document-level check.
    pub component_id: Option<String>,
    /// What tells this pass apart from the rule's other passes on the same
    /// subject, like [`Violation::finding_detail`]; `None` for a rule that
    /// passes a subject at most once.
    pub finding_detail: Option<String>,
    /// The requirement the check satisfied, as text.
    pub requirement: String,
    /// References to the clauses the rule implements, populated by
    /// `ComplianceChecker::check()` from the registry, borrowing its list
    /// as [`Violation::standard_refs`] does.
    pub standard_refs: Cow<'static, [StandardRef]>,
}

impl PassedCheck {
    /// Structured standard references for this pass, looked up from the rule
    /// registry by [`PassedCheck::rule_id`] (see
    /// [`Violation::registry_standard_refs`]).
    #[must_use]
    pub fn registry_standard_refs(&self) -> Vec<StandardRef> {
        registry_refs(self.rule_id).to_vec()
    }

    /// Externally-visible SARIF rule id for this pass, looked up from the
    /// rule registry like [`Violation::sarif_rule_id`].
    #[must_use]
    pub fn sarif_rule_id(&self) -> &'static str {
        registry_sarif_id(self.rule_id)
    }
}

impl FindingIdentity for PassedCheck {
    fn rule_id(&self) -> &'static str {
        self.rule_id
    }

    fn finding_detail(&self) -> Option<&str> {
        self.finding_detail.as_deref()
    }

    fn component_id(&self) -> Option<&str> {
        self.component_id.as_deref()
    }
}

impl finding::NumberedDetail for PassedCheck {
    fn set_finding_detail(&mut self, detail: String) {
        self.finding_detail = Some(detail);
    }
}

/// Owned mirror of [`PassedCheck`] for deserialization, for the reason
/// [`ViolationPayload`] gives.
#[derive(Deserialize)]
struct PassedCheckPayload {
    message: String,
    #[serde(default)]
    element: Option<String>,
    #[serde(default)]
    component_id: Option<String>,
    #[serde(default)]
    finding_detail: Option<String>,
    #[serde(default)]
    requirement: String,
    #[serde(default)]
    rule_id: Option<String>,
    #[serde(default)]
    standard_refs: Vec<StandardRef>,
}

impl<'de> Deserialize<'de> for PassedCheck {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let payload = PassedCheckPayload::deserialize(deserializer)?;
        Ok(Self {
            // Like a violation's: an unknown id collapses to the generic
            // default rather than failing deserialization, and the derived
            // `sarif_rule_id` is ignored.
            rule_id: payload
                .rule_id
                .as_deref()
                .and_then(lookup_static_rule_id)
                .unwrap_or_else(default_rule_id),
            message: payload.message,
            element: payload.element,
            component_id: payload.component_id,
            finding_detail: payload.finding_detail,
            requirement: payload.requirement,
            standard_refs: Cow::Owned(payload.standard_refs),
        })
    }
}

impl Serialize for PassedCheck {
    /// Manual impl, like [`Violation`]'s, so the JSON carries the derived
    /// `sarif_rule_id` beside the `rule_id`. Fields follow the violation's
    /// order; `component_id` and `finding_detail` are skipped when `None`,
    /// and `standard_refs` when empty.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let has_component_id = self.component_id.is_some();
        let has_finding_detail = self.finding_detail.is_some();
        let has_refs = !self.standard_refs.is_empty();
        let mut state = serializer.serialize_struct(
            "PassedCheck",
            5 + usize::from(has_component_id)
                + usize::from(has_finding_detail)
                + usize::from(has_refs),
        )?;
        state.serialize_field("message", &self.message)?;
        state.serialize_field("element", &self.element)?;
        if has_component_id {
            state.serialize_field("component_id", &self.component_id)?;
        } else {
            state.skip_field("component_id")?;
        }
        if has_finding_detail {
            state.serialize_field("finding_detail", &self.finding_detail)?;
        } else {
            state.skip_field("finding_detail")?;
        }
        state.serialize_field("requirement", &self.requirement)?;
        state.serialize_field("rule_id", self.rule_id)?;
        state.serialize_field("sarif_rule_id", self.sarif_rule_id())?;
        if has_refs {
            state.serialize_field("standard_refs", &self.standard_refs)?;
        } else {
            state.skip_field("standard_refs")?;
        }
        state.end()
    }
}

/// A check a standard did not evaluate on the SBOM, and why.
///
/// A check is listed when it applies to the SBOM but did not run: the
/// document's format or spec version cannot carry the evidence it reads (or
/// sbom-tools does not read it there), the spec version does not parse, the
/// run's inputs leave it out (no CRA product class pinned, PQC readiness
/// mode), the SBOM lists none of the component kinds it is about, or the
/// SBOM is too large to analyze. Without the entry, a check that did not run
/// reads like one that passed: neither reports a violation.
///
/// Not listed: a check that ran and found nothing to report, even over no
/// entries (a vulnerability check of an SBOM without vulnerabilities), and a
/// check of something the document's format does not have at all (an SPDX
/// version string or an SPDX 3.0 profile declaration in a CycloneDX
/// document).
///
/// A checker records one with `NotEvaluated::push` where it skips the check
/// (see `context.rs`); [`ComplianceResult::evaluated`] lists them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct RuleEvaluation {
    /// The rule of the check: one of the rules the standard's checks report
    /// ([`rules_for_level`]).
    pub rule_id: &'static str,
    /// What became of the check.
    pub status: EvaluationStatus,
    /// Why, in sbom-tools' own words (never SBOM text), e.g. "SPDX 2.x has
    /// no field for an in-document signature".
    pub reason: String,
}

impl RuleEvaluation {
    /// The record of a check of `rule_id` that did not run, for `reason`.
    #[must_use]
    pub fn not_evaluated(rule_id: &'static str, reason: impl Into<String>) -> Self {
        Self {
            rule_id,
            status: EvaluationStatus::NotEvaluated,
            reason: reason.into(),
        }
    }
}

/// What became of the check a [`RuleEvaluation`] records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EvaluationStatus {
    /// The check did not run on the SBOM.
    NotEvaluated,
}

/// Owned mirror of [`RuleEvaluation`] for deserialization, for the reason
/// [`ViolationPayload`] gives.
#[derive(Deserialize)]
struct RuleEvaluationPayload {
    rule_id: String,
    status: EvaluationStatus,
    #[serde(default)]
    reason: String,
}

impl<'de> Deserialize<'de> for RuleEvaluation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let payload = RuleEvaluationPayload::deserialize(deserializer)?;
        Ok(Self {
            // Like a violation's: an unknown id collapses to the generic
            // default rather than failing deserialization.
            rule_id: lookup_static_rule_id(&payload.rule_id).unwrap_or_else(default_rule_id),
            status: payload.status,
            reason: payload.reason,
        })
    }
}

/// Severity of a compliance violation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ViolationSeverity {
    /// Must be fixed for compliance
    Error,
    /// Should be fixed, but not strictly required
    Warning,
    /// Informational recommendation
    Info,
}

impl ViolationSeverity {
    /// Canonical display label, matching the strings the reports layer
    /// (markdown/HTML violation tables) emits. Renderers should use this
    /// rather than the `Debug` form so the label can't silently drift.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Error => "Error",
            Self::Warning => "Warning",
            Self::Info => "Info",
        }
    }
}

/// Category of compliance violation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ViolationCategory {
    /// Document metadata issue
    DocumentMetadata,
    /// Component identification issue
    ComponentIdentification,
    /// Dependency information issue
    DependencyInfo,
    /// License information issue
    LicenseInfo,
    /// Supplier information issue
    SupplierInfo,
    /// Hash/integrity issue
    IntegrityInfo,
    /// Security/vulnerability disclosure info
    SecurityInfo,
    /// Format-specific requirement
    FormatSpecific,
    /// Cryptographic algorithm/key/protocol issue
    CryptographyInfo,
}

impl ViolationCategory {
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::DocumentMetadata => "Document Metadata",
            Self::ComponentIdentification => "Component Identification",
            Self::DependencyInfo => "Dependency Information",
            Self::LicenseInfo => "License Information",
            Self::SupplierInfo => "Supplier Information",
            Self::IntegrityInfo => "Integrity Information",
            Self::SecurityInfo => "Security Information",
            Self::FormatSpecific => "Format-Specific",
            Self::CryptographyInfo => "Cryptography",
        }
    }

    /// Short name suitable for compact table display (max 10 chars).
    #[must_use]
    pub const fn short_name(&self) -> &'static str {
        match self {
            Self::DocumentMetadata => "Doc Meta",
            Self::ComponentIdentification => "Comp IDs",
            Self::DependencyInfo => "Deps",
            Self::LicenseInfo => "License",
            Self::SupplierInfo => "Supplier",
            Self::IntegrityInfo => "Integrity",
            Self::SecurityInfo => "Security",
            Self::FormatSpecific => "Format",
            Self::CryptographyInfo => "Crypto",
        }
    }

    /// All category variants in display order.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::SupplierInfo,
            Self::ComponentIdentification,
            Self::DocumentMetadata,
            Self::IntegrityInfo,
            Self::LicenseInfo,
            Self::DependencyInfo,
            Self::SecurityInfo,
            Self::FormatSpecific,
            Self::CryptographyInfo,
        ]
    }
}

/// Whether the checked standard actually evaluated this SBOM.
///
/// Readiness profiles (EU AI Act, BSI/G7 SBOM-for-AI) do not apply to SBOMs
/// outside their scope: their result is `NotApplicable` with the reason, has
/// no violations, and keeps `is_compliant = true` for compatibility, so
/// consumers must render such runs as N/A — never as a pass. Old payloads
/// without the field deserialize as `Applicable`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case", tag = "status", content = "reason")]
#[non_exhaustive]
pub enum Applicability {
    /// The standard evaluated the SBOM; `is_compliant` is meaningful.
    #[default]
    Applicable,
    /// The standard did not apply (the string is the human-readable reason).
    NotApplicable(String),
}

/// Result of compliance checking
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ComplianceResult {
    /// Overall compliance status
    pub is_compliant: bool,
    /// Compliance level checked against
    pub level: ComplianceLevel,
    /// All violations found
    pub violations: Vec<Violation>,
    /// The checks the SBOM passed (see [`PassedCheck`]), in report order.
    /// They are not violations: no severity count includes them.
    ///
    /// Serialized as `passed`, omitted when empty; old payloads without the
    /// field deserialize to an empty list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub passed: Vec<PassedCheck>,
    /// The checks the standard did not evaluate on this SBOM, each with the
    /// reason (see [`RuleEvaluation`]), one per rule, in the order the
    /// checks ran. Every entry is [`EvaluationStatus::NotEvaluated`]. A
    /// standard that did not apply at all lists none: its
    /// [`ComplianceResult::applicability`] says why.
    ///
    /// Serialized as `evaluated`, omitted when empty; old payloads without
    /// the field deserialize to an empty list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evaluated: Vec<RuleEvaluation>,
    /// Error count
    pub error_count: usize,
    /// Warning count
    pub warning_count: usize,
    /// Number of Info-severity violations. Passed checks are not counted:
    /// see [`ComplianceResult::passed`].
    pub info_count: usize,
    /// CRA Annex VIII conformity-assessment summary (CRA-P4.3). Populated
    /// only when the level is CRA Phase 1 or Phase 2 *and* a product class
    /// has been pinned (explicitly or via sidecar). `None` otherwise,
    /// including for the Art. 24 steward profile, which follows no
    /// conformity-assessment procedure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conformity_summary: Option<ConformityAssessmentSummary>,
    /// Whether the standard actually evaluated this SBOM (see
    /// [`Applicability`]). `is_compliant` stays `true` for not-applicable
    /// runs by contract; renderers must show N/A instead of a pass.
    #[serde(default)]
    pub applicability: Applicability,
    /// The elements the standard checked, which the score is normalised by
    /// (see [`compliance_score`]): the document itself, plus each component
    /// in the standard's scope. `cnsa2` and `pqc` check cryptographic
    /// assets, `ai-act` and `bsi-ai` ML models, datasets and components that
    /// look like ML models, `eucc` only the document, and every other
    /// standard the package-scoped components it judges (those it left
    /// out for their excluded scope count in
    /// [`ComplianceResult::excluded_components`] instead).
    ///
    /// Set by `ComplianceChecker::check()`; `1` (the document alone) for a
    /// result built with [`ComplianceResult::new`]. Not serialized: the
    /// `-o json` envelope reports it as `score_basis.checked`.
    #[serde(skip, default = "document_only")]
    pub elements_checked: usize,
    /// The rules whose findings the run's rule settings turned off, by rule
    /// id, with how many findings each dropped. The dropped findings count
    /// toward no severity, the verdict or the score.
    ///
    /// Serialized as `suppressed`, omitted when empty; old payloads without
    /// the field deserialize to an empty list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suppressed: Vec<SuppressedRule>,
    /// How many components the package rules left out because their scope
    /// is excluded (CycloneDX `scope: excluded`, or an SPDX development,
    /// build or test dependency; see `Component::scope`). Zero when the run
    /// judges them too (`--include-excluded-scope`) and for a standard
    /// without package rules (CNSA 2.0, NIST PQC, EUCC and the AI profiles).
    ///
    /// Serialized as `excluded_components`, omitted when zero; old payloads
    /// without the field deserialize to zero.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub excluded_components: usize,
}

/// Serde default for [`ComplianceResult::elements_checked`]: the document.
const fn document_only() -> usize {
    1
}

/// Serde helper: skip a count that is zero.
#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_zero(count: &usize) -> bool {
    *count == 0
}

/// Per-route checklist of evidence the CRA Annex VIII conformity-assessment
/// procedure expects. Surfaced in the JSON, SARIF and OSCAL outputs (the
/// standard's `conformity_summary`, `conformitySummary` and `conformity-*`
/// properties) and the markdown, HTML and TUI reports, so notified bodies
/// and auditors see the route + the missing evidence in one glance.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ConformityAssessmentSummary {
    /// CRA Annex III/IV product class
    pub product_class: crate::model::CraProductClass,
    /// Resolved Annex VIII conformity route
    pub route: crate::model::ConformityRoute,
    /// Per-evidence checklist entries (≥1 element)
    pub evidence: Vec<ConformityEvidence>,
}

/// One row of the conformity-evidence checklist. `satisfied = true` means
/// the SBOM (or sidecar) carries the expected reference; `false` means it
/// is missing and the manufacturer should attach it before submitting.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ConformityEvidence {
    /// Short label (e.g., "EU Declaration of Conformity")
    pub label: String,
    /// Longer description of the evidence
    pub detail: String,
    /// Whether the SBOM/sidecar already provides this evidence
    pub satisfied: bool,
}

impl ComplianceResult {
    /// Create the result of a standard that evaluated the SBOM and found
    /// `violations` (and passed no check; see
    /// [`ComplianceResult::with_passed`]).
    #[must_use]
    pub fn new(level: ComplianceLevel, violations: Vec<Violation>) -> Self {
        let error_count = violations
            .iter()
            .filter(|v| v.severity == ViolationSeverity::Error)
            .count();
        let warning_count = violations
            .iter()
            .filter(|v| v.severity == ViolationSeverity::Warning)
            .count();
        let info_count = violations
            .iter()
            .filter(|v| v.severity == ViolationSeverity::Info)
            .count();

        Self {
            is_compliant: error_count == 0,
            level,
            violations,
            passed: Vec::new(),
            evaluated: Vec::new(),
            conformity_summary: None,
            applicability: Applicability::Applicable,
            error_count,
            warning_count,
            info_count,
            elements_checked: document_only(),
            suppressed: Vec::new(),
            excluded_components: 0,
        }
    }

    /// How many findings the run's rule settings turned off: the sum of
    /// [`ComplianceResult::suppressed`].
    #[must_use]
    pub fn suppressed_count(&self) -> usize {
        self.suppressed.iter().map(|rule| rule.findings).sum()
    }

    /// This result with `passed` as its passed checks. Passes move no count,
    /// no verdict and no score.
    #[must_use]
    pub fn with_passed(mut self, passed: Vec<PassedCheck>) -> Self {
        self.passed = passed;
        self
    }

    /// This result with `elements` as its
    /// [`ComplianceResult::elements_checked`]. A count below one is raised
    /// to one: a standard always checks the document.
    #[must_use]
    pub fn with_elements_checked(mut self, elements: usize) -> Self {
        self.elements_checked = elements.max(1);
        self
    }

    /// This result with `evaluated` as the checks the standard did not
    /// evaluate. They move no count, no verdict and no score.
    #[must_use]
    pub fn with_evaluated(mut self, evaluated: Vec<RuleEvaluation>) -> Self {
        self.evaluated = evaluated;
        self
    }

    /// Create the result of a standard that does not apply to the SBOM, for
    /// `reason`: no violations, and `is_compliant` stays `true` by contract
    /// (see [`Applicability`]).
    #[must_use]
    pub fn not_applicable(level: ComplianceLevel, reason: impl Into<String>) -> Self {
        let mut result = Self::new(level, Vec::new());
        result.applicability = Applicability::NotApplicable(reason.into());
        result
    }

    /// Whether the standard actually evaluated this SBOM.
    #[must_use]
    pub fn is_applicable(&self) -> bool {
        self.applicability == Applicability::Applicable
    }

    /// The checks the result's errors and warnings failed, the sum of their
    /// [`Violation::failed_checks`]. Info findings fail none.
    #[must_use]
    pub fn failed_checks(&self) -> usize {
        self.violations
            .iter()
            .fold(0, |sum, v| sum.saturating_add(v.failed_checks()))
    }

    /// Badge/summary compliance score (0–100): [`compliance_score`] of the
    /// checks the errors and the warnings failed, over the
    /// [`ComplianceResult::elements_checked`]. A compliant result scores
    /// 50–100 and a non-compliant one 0–49; Info findings and passed checks
    /// never move it. The JSON, SARIF, OSCAL, Markdown, HTML and TUI outputs
    /// all render this value. `None` when the standard was not applicable:
    /// an unevaluated SBOM has no score.
    #[must_use]
    pub fn score(&self) -> Option<u8> {
        if !self.is_applicable() {
            return None;
        }
        let (mut errors, mut warnings) = (0usize, 0usize);
        for v in &self.violations {
            match v.severity {
                ViolationSeverity::Error => errors = errors.saturating_add(v.failed_checks()),
                ViolationSeverity::Warning => {
                    warnings = warnings.saturating_add(v.failed_checks());
                }
                ViolationSeverity::Info => {}
            }
        }
        Some(compliance_score(errors, warnings, self.elements_checked))
    }

    /// Get violations filtered by severity
    #[must_use]
    pub fn violations_by_severity(&self, severity: ViolationSeverity) -> Vec<&Violation> {
        self.violations
            .iter()
            .filter(|v| v.severity == severity)
            .collect()
    }

    /// Get violations filtered by category
    #[must_use]
    pub fn violations_by_category(&self, category: ViolationCategory) -> Vec<&Violation> {
        self.violations
            .iter()
            .filter(|v| v.category == category)
            .collect()
    }
}

/// The compliance score (0–100) of a result whose errors failed `errors`
/// checks and whose warnings failed `warnings` (see
/// [`Violation::failed_checks`]), over `checked` elements (see
/// [`ComplianceResult::elements_checked`]):
///
/// ```text
/// score = band + floor(50 × checked / (checked + errors + warnings))
/// band  = 50 without an error, 0 with one
/// ```
///
/// A compliant result therefore scores 50–100 and a non-compliant one 0–49,
/// so every compliant result outscores every non-compliant one. Within the
/// band the score falls with the failed checks per element: none scores
/// 100, one failed check per element halves the band (75, or 25 with an
/// error), and one failed check in an SBOM of 500,000 elements still scores
/// 99 (49 with an error). An extra failed check never raises the score.
/// The arithmetic is exact for any counts.
#[must_use]
pub fn compliance_score(errors: usize, warnings: usize, checked: usize) -> u8 {
    let failed = errors as u128 + warnings as u128;
    let band: u8 = if errors == 0 { 50 } else { 0 };
    if failed == 0 {
        return band + 50;
    }
    let checked = checked as u128;
    // Below 50: `failed` is at least 1.
    let within = u8::try_from(50 * checked / (checked + failed))
        .expect("the share of a 50-point band fits in a u8");
    band + within
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Info findings must not move the score: 5 errors alone and 5 errors +
    /// 20 infos once scored 16 vs 80 because infos inflated the
    /// denominator. Over the document alone, 5 errors now score
    /// floor(50 × 1 / 6) = 8.
    #[test]
    fn score_is_neutral_to_info_findings() {
        let violation = |severity| Violation {
            severity,
            category: ViolationCategory::DocumentMetadata,
            message: "x".to_string(),
            element: None,
            requirement: "x".to_string(),
            rule_id: "SBOM-CRA-GENERAL",
            component_id: None,
            counts: None,
            standard_refs: Cow::Borrowed(&[]),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        };
        let errors_only = ComplianceResult::new(
            ComplianceLevel::NtiaMinimum,
            (0..5)
                .map(|_| violation(ViolationSeverity::Error))
                .collect(),
        );
        let with_infos = ComplianceResult::new(
            ComplianceLevel::NtiaMinimum,
            (0..5)
                .map(|_| violation(ViolationSeverity::Error))
                .chain((0..20).map(|_| violation(ViolationSeverity::Info)))
                .collect(),
        );
        assert_eq!(errors_only.score(), with_infos.score());
        assert_eq!(errors_only.score(), Some(8));
        let clean = ComplianceResult::new(ComplianceLevel::NtiaMinimum, Vec::new());
        assert_eq!(clean.score(), Some(100));
    }

    /// The score's boundaries: no finding, one and many warnings, one and
    /// many errors, and element counts up to `usize::MAX`.
    #[test]
    fn score_boundaries() {
        // No finding: 100 whatever was checked.
        for checked in [0, 1, 4, 500_001, usize::MAX] {
            assert_eq!(compliance_score(0, 0, checked), 100, "{checked}");
        }
        // Over the document and three components.
        assert_eq!(compliance_score(0, 1, 4), 90);
        assert_eq!(compliance_score(0, 3, 4), 78);
        assert_eq!(
            compliance_score(0, 4, 4),
            75,
            "one per element halves the band"
        );
        assert_eq!(compliance_score(0, 1_000, 4), 50);
        assert_eq!(compliance_score(1, 0, 4), 40);
        assert_eq!(compliance_score(1, 2, 4), 28);
        assert_eq!(compliance_score(4, 0, 4), 25);
        assert_eq!(compliance_score(1_000, 0, 4), 0);
        // Many failed checks: the band's floor, never below.
        assert_eq!(compliance_score(0, usize::MAX, 1), 50);
        assert_eq!(compliance_score(usize::MAX, usize::MAX, 1), 0);
        // A large SBOM: one finding barely moves the score.
        assert_eq!(compliance_score(0, 1, 500_001), 99);
        assert_eq!(compliance_score(1, 0, 500_001), 49);
        assert_eq!(compliance_score(0, 1, usize::MAX), 99);
        assert_eq!(compliance_score(1, 0, usize::MAX), 49);
        assert_eq!(compliance_score(0, usize::MAX, usize::MAX), 75);
        // One failed check per element of a large SBOM halves the band.
        assert_eq!(compliance_score(0, 500_001, 500_001), 75);
        assert_eq!(compliance_score(500_001, 0, 500_001), 25);
        // Nothing checked but a failure: the band's floor.
        assert_eq!(compliance_score(0, 1, 0), 50);
        assert_eq!(compliance_score(1, 0, 0), 0);
    }

    /// Over a grid of counts: every compliant result outscores every
    /// non-compliant one, an extra error or warning never raises the score,
    /// turning a warning into an error never does either, and checking more
    /// elements with the same failures never lowers it.
    #[test]
    fn score_orders_verdicts_and_is_monotone() {
        let counts = [0usize, 1, 2, 3, 5, 10, 49, 50, 99, 1_000, 500_000];
        let checked = [0usize, 1, 2, 4, 10, 100, 500_001];
        let mut lowest_compliant = u8::MAX;
        let mut highest_non_compliant = 0;
        for &c in &checked {
            for &e in &counts {
                for &w in &counts {
                    let score = compliance_score(e, w, c);
                    assert!(score <= 100);
                    if e == 0 {
                        assert!(score >= 50, "compliant ({e},{w},{c}) scored {score}");
                        assert_eq!(score == 100, w == 0, "({e},{w},{c})");
                        lowest_compliant = lowest_compliant.min(score);
                    } else {
                        assert!(score <= 49, "non-compliant ({e},{w},{c}) scored {score}");
                        highest_non_compliant = highest_non_compliant.max(score);
                    }
                    assert!(compliance_score(e + 1, w, c) <= score, "({e},{w},{c})");
                    assert!(compliance_score(e, w + 1, c) <= score, "({e},{w},{c})");
                    if w > 0 {
                        assert!(compliance_score(e + 1, w - 1, c) <= score, "({e},{w},{c})");
                    }
                    assert!(compliance_score(e, w, c + 1) >= score, "({e},{w},{c})");
                }
            }
        }
        assert!(lowest_compliant > highest_non_compliant);
    }

    /// What a finding weighs in the score: an Info finding nothing, a
    /// finding about one subject one check, an aggregate finding its failing
    /// items, and a coverage finding the items it does not cover.
    #[test]
    fn failed_checks_count_the_failing_items() {
        let finding = |severity, rule_id, counts| Violation {
            severity,
            category: ViolationCategory::DocumentMetadata,
            message: "x".to_string(),
            element: None,
            requirement: "x".to_string(),
            rule_id,
            component_id: None,
            counts,
            standard_refs: Cow::Borrowed(&[]),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        };
        let of = |affected, total| Some(ViolationCounts { affected, total });
        let w = ViolationSeverity::Warning;
        let e = ViolationSeverity::Error;
        assert_eq!(finding(w, "SBOM-NTIA-AUTHOR", None).failed_checks(), 1);
        assert_eq!(finding(e, "SBOM-NTIA-AUTHOR", None).failed_checks(), 1);
        assert_eq!(
            finding(ViolationSeverity::Info, "SBOM-CRA-ART-13-5", of(7, 10)).failed_checks(),
            0
        );
        assert_eq!(
            finding(e, "SBOM-BSI-TR-03183-2-LICENSE", of(7, 10)).failed_checks(),
            7
        );
        assert_eq!(
            finding(w, "SBOM-BSI-TR-03183-2-LICENSE", of(0, 10)).failed_checks(),
            1,
            "a finding fails at least one check"
        );
        for rule in COVERAGE_COUNT_RULE_IDS {
            assert!(rule_meta(rule).is_some(), "{rule} is registered");
            assert_eq!(finding(w, rule, of(3, 10)).failed_checks(), 7, "{rule}");
            assert_eq!(finding(w, rule, of(0, 10)).failed_checks(), 10, "{rule}");
            assert_eq!(finding(w, rule, of(10, 10)).failed_checks(), 1, "{rule}");
        }

        // The result sums them; Info findings stay out of the sum.
        let result = ComplianceResult::new(
            ComplianceLevel::Fsct,
            vec![
                finding(e, "SBOM-FSCT-AUTHOR", None),
                finding(w, "SBOM-FSCT-LICENSE-COVERAGE", of(1, 4)),
                finding(ViolationSeverity::Info, "SBOM-FSCT-SIGNATURE", None),
            ],
        )
        .with_elements_checked(5);
        assert_eq!(result.failed_checks(), 4);
        // floor(50 × 5 / (5 + 4)) = 27, in the non-compliant band.
        assert_eq!(result.score(), Some(27));
    }

    /// Payloads that predate the applicability field deserialize as
    /// Applicable.
    #[test]
    fn applicability_defaults_on_old_payloads() {
        let r = ComplianceResult::new(ComplianceLevel::NtiaMinimum, Vec::new());
        let mut json: serde_json::Value = serde_json::to_value(&r).unwrap();
        json.as_object_mut().unwrap().remove("applicability");
        let back: ComplianceResult = serde_json::from_value(json).unwrap();
        assert_eq!(back.applicability, Applicability::Applicable);
    }

    fn passed_check() -> PassedCheck {
        PassedCheck {
            rule_id: "SBOM-PQC-009",
            message: "'ML-KEM-1024' uses NIST-approved PQC algorithm (FIPS 203/204/205)"
                .to_string(),
            element: Some("ML-KEM-1024".to_string()),
            component_id: Some("crypto/algorithm/ml-kem-1024".to_string()),
            finding_detail: None,
            requirement: "FIPS 203/204/205: approved".to_string(),
            standard_refs: Cow::Borrowed(registry_refs("SBOM-PQC-009")),
        }
    }

    /// A result serializes `passed` only when it passed a check, and
    /// payloads without the field deserialize to no passes.
    #[test]
    fn passed_is_written_only_when_set_and_round_trips() {
        let none = ComplianceResult::new(ComplianceLevel::NistPqc, Vec::new());
        let json = serde_json::to_value(&none).expect("serializes");
        assert!(json.get("passed").is_none(), "{json}");
        let back: ComplianceResult = serde_json::from_value(json).expect("deserializes");
        assert!(back.passed.is_empty());

        let one = none.with_passed(vec![passed_check()]);
        assert_eq!(one.info_count, 0, "a pass moves no count");
        assert!(one.is_compliant);
        let json = serde_json::to_value(&one).expect("serializes");
        assert_eq!(json["passed"][0]["rule_id"], "SBOM-PQC-009");
        assert_eq!(json["passed"][0]["sarif_rule_id"], "SBOM-PQC-009");
        assert!(json["passed"][0].get("finding_detail").is_none());
        assert!(
            json["passed"][0].get("severity").is_none(),
            "a pass has none"
        );
        let back: ComplianceResult = serde_json::from_value(json).expect("deserializes");
        assert_eq!(back.passed, vec![passed_check()]);
    }

    /// The not-applicable constructor carries the reason and nothing else.
    #[test]
    fn not_applicable_constructor_has_no_findings() {
        let r = ComplianceResult::not_applicable(ComplianceLevel::BsiSbomForAi, "no ML content");
        assert_eq!(
            r.applicability,
            Applicability::NotApplicable("no ML content".to_string())
        );
        assert!(r.violations.is_empty() && r.passed.is_empty());
        assert!(r.is_compliant, "the N/A is_compliant contract is preserved");
        assert_eq!(r.score(), None);
    }

    /// A violation built outside the checker has no input format, so its
    /// remediation lists every format's advice; an unregistered rule id has
    /// no registry guidance at all.
    #[test]
    fn unstamped_remediation_lists_every_format() {
        let unstamped = |rule_id: &'static str| Violation {
            severity: ViolationSeverity::Warning,
            category: ViolationCategory::SupplierInfo,
            message: String::new(),
            element: None,
            requirement: String::new(),
            rule_id,
            component_id: None,
            counts: None,
            standard_refs: Cow::Borrowed(&[]),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        };
        let guidance = unstamped("SBOM-CRA-COMPONENT-SUPPLIER")
            .remediation_guidance()
            .into_owned();
        for format in RemediationFormat::ALL {
            assert!(
                guidance.contains(&format!("{}: ", format.label())),
                "{format:?} advice missing from {guidance:?}"
            );
        }
        assert_eq!(
            unstamped("SBOM-NOT-A-RULE").remediation_guidance(),
            REMEDIATION_UNREGISTERED
        );
    }

    #[test]
    fn test_compliance_result_counts() {
        let violations = vec![
            Violation {
                severity: ViolationSeverity::Error,
                category: ViolationCategory::ComponentIdentification,
                message: "Error 1".to_string(),
                element: None,
                requirement: "Test".to_string(),
                rule_id: "SBOM-CRA-GENERAL",
                component_id: None,
                counts: None,
                standard_refs: Cow::Borrowed(&[]),
                remediation: None,
                finding_detail: None,
                severity_override: None,
                deadline: None,
                field: None,
                observed: None,
            },
            Violation {
                severity: ViolationSeverity::Warning,
                category: ViolationCategory::LicenseInfo,
                message: "Warning 1".to_string(),
                element: None,
                requirement: "Test".to_string(),
                rule_id: "SBOM-CRA-GENERAL",
                component_id: None,
                counts: None,
                standard_refs: Cow::Borrowed(&[]),
                remediation: None,
                finding_detail: None,
                severity_override: None,
                deadline: None,
                field: None,
                observed: None,
            },
            Violation {
                severity: ViolationSeverity::Info,
                category: ViolationCategory::FormatSpecific,
                message: "Info 1".to_string(),
                element: None,
                requirement: "Test".to_string(),
                rule_id: "SBOM-CRA-GENERAL",
                component_id: None,
                counts: None,
                standard_refs: Cow::Borrowed(&[]),
                remediation: None,
                finding_detail: None,
                severity_override: None,
                deadline: None,
                field: None,
                observed: None,
            },
        ];

        let result = ComplianceResult::new(ComplianceLevel::Standard, violations);
        assert!(!result.is_compliant);
        assert_eq!(result.error_count, 1);
        assert_eq!(result.warning_count, 1);
        assert_eq!(result.info_count, 1);
    }

    fn refs_for(rule_id: &'static str) -> Vec<StandardRef> {
        let v = Violation {
            severity: ViolationSeverity::Warning,
            category: ViolationCategory::DocumentMetadata,
            message: String::new(),
            element: None,
            requirement: String::new(),
            rule_id,
            component_id: None,
            counts: None,
            standard_refs: Cow::Borrowed(&[]),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        };
        v.registry_standard_refs()
    }

    #[test]
    fn registry_refs_for_machine_readable_include_annex_and_pren() {
        let refs = refs_for("SBOM-CRA-MACHINE-READABLE");
        assert!(
            refs.iter()
                .any(|r| r.standard == StandardKind::CraAnnex && r.id == "Annex I Part II (1)"),
            "expected CRA Annex I Part II (1); got {refs:?}"
        );
        assert!(
            refs.iter()
                .any(|r| r.standard == StandardKind::Pren40000_1_3 && r.id == "PRE-7-RQ-04"),
            "expected prEN PRE-7-RQ-04; got {refs:?}"
        );
    }

    #[test]
    fn registry_refs_for_annex_i_identifier_include_pren_07() {
        let refs = refs_for("SBOM-CRA-ANNEX-I-IDENTIFIER");
        assert!(
            refs.iter()
                .any(|r| r.standard == StandardKind::Pren40000_1_3 && r.id == "PRE-7-RQ-07"),
            "expected PRE-7-RQ-07; got {refs:?}"
        );
        let pren_count = refs
            .iter()
            .filter(|r| r.standard == StandardKind::Pren40000_1_3 && r.id == "PRE-7-RQ-07")
            .count();
        assert_eq!(pren_count, 1, "PRE-7-RQ-07 should appear exactly once");
    }

    /// #347: the SUPPLY-CHAIN rule is emitted only by the supplier checks,
    /// but its remediation was copied from the DEPENDENCY rule and told the
    /// user to add DEPENDS_ON relationships.
    #[test]
    fn supply_chain_remediation_is_about_suppliers() {
        let v = Violation {
            severity: ViolationSeverity::Error,
            category: ViolationCategory::SupplierInfo,
            message: String::new(),
            element: None,
            requirement: String::new(),
            rule_id: "SBOM-CRA-ANNEX-I-SUPPLY-CHAIN",
            component_id: None,
            counts: None,
            standard_refs: Cow::Borrowed(&[]),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        };
        let guidance = v.remediation_guidance();
        assert!(
            guidance.contains("supplier") && guidance.contains("PackageSupplier"),
            "supplier-rule guidance must name the supplier fields; got: {guidance}"
        );
        assert!(
            !guidance.contains("DEPENDS_ON"),
            "supplier-rule guidance must not be the dependency-relationship text; got: {guidance}"
        );
    }

    #[test]
    fn registry_refs_for_supply_chain_include_annex_and_pren() {
        let refs = refs_for("SBOM-CRA-ANNEX-I-SUPPLY-CHAIN");
        assert!(
            refs.iter()
                .any(|r| r.standard == StandardKind::CraAnnex && r.id == "Annex I Part II"),
            "expected Annex I Part II; got {refs:?}"
        );
        assert!(
            refs.iter()
                .any(|r| r.standard == StandardKind::Pren40000_1_3 && r.id == "PRE-7-RQ-01"),
            "expected PRE-7-RQ-01; got {refs:?}"
        );
        assert!(
            refs.iter()
                .any(|r| r.standard == StandardKind::Pren40000_1_3 && r.id == "PRE-7-RQ-03"),
            "expected PRE-7-RQ-03; got {refs:?}"
        );
    }

    #[test]
    fn registry_refs_for_cvd_policy_include_annex_and_pren_rls() {
        let refs = refs_for("SBOM-CRA-CVD-POLICY");
        assert!(
            refs.iter()
                .any(|r| r.standard == StandardKind::CraAnnex && r.id == "Annex I Part II (5)"),
            "expected CRA Annex I Part II (5); got {refs:?}"
        );
        assert!(
            refs.iter()
                .any(|r| r.standard == StandardKind::Pren40000_1_3 && r.id == "RLS-2-RQ-03-RE"),
            "expected RLS-2-RQ-03-RE; got {refs:?}"
        );
    }

    #[test]
    fn registry_refs_for_ssdf_ps2() {
        let refs = refs_for("SBOM-SSDF-PS2");
        assert!(
            refs.iter()
                .any(|r| r.standard == StandardKind::NistSsdf && r.id == "PS.2"),
            "expected NIST SSDF PS.2; got {refs:?}"
        );
    }
}
