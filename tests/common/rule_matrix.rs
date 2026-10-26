//! Registry-driven per-rule compliance test harness (audit P3).
//!
//! Provides three things to the `tests/rule_matrix_*.rs` integration tests:
//!
//! 1. **A minimal fixture DSL** ([`SbomFixture`] / [`ComponentFixture`]) that
//!    renders a small CycloneDX JSON document and feeds it through the *real*
//!    parser (`parse_sbom_str`), so every matrix case exercises the same
//!    normalization path a production `validate` run does — not a hand-built
//!    `NormalizedSbom` that may drift from what parsers actually produce.
//!
//! 2. **A table-driven matrix runner** ([`run_matrix`]): every SARIF rule id
//!    in a standard's rule universe gets at least one *firing* case (a
//!    minimal SBOM that must surface the rule, with the expected severity)
//!    and one *silent* case (a minimal SBOM that must not surface it), or an
//!    explicit skip-with-reason entry. No silent omissions: the runner fails
//!    if the entry table and the declared universe differ.
//!
//! 3. **A universe sweep**: every violation emitted by every fixture in a
//!    matrix must map (via its registry SARIF identity) into the standard's
//!    declared rule universe — a new check site that emits a new rule id
//!    forces the matrix to be extended instead of silently escaping it.

// Each per-standard matrix binary uses a subset of the DSL (mirrors the
// existing tests/common/ffi_helpers.rs posture).
#![allow(dead_code)]

#[path = "clock.rs"]
pub mod clock;

use sbom_tools::model::NormalizedSbom;
use sbom_tools::parsers::parse_sbom_str;
use sbom_tools::quality::{ComplianceLevel, ComplianceResult, ViolationSeverity, rule_meta};
use std::collections::BTreeSet;

/// Filler SHA-256 digest (64 hex chars) for conforming components.
pub const SHA256_FILLER: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Filler MD5 digest (32 hex chars) for weak-hash cases.
pub const MD5_FILLER: &str = "d41d8cd98f00b204e9800998ecf8427e";

/// One component of a [`SbomFixture`], rendered into the CycloneDX
/// `components[]` array (or `metadata.component` for the primary).
#[derive(Debug, Clone)]
pub struct ComponentFixture {
    /// CycloneDX `bom-ref`. Kept distinct from `name` so the generic
    /// "may be missing bom-ref" Info check stays silent unless a case
    /// deliberately collapses the two.
    pub bom_ref: String,
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
    /// `supplier.name`.
    pub supplier: Option<String>,
    /// `(alg, content)` pairs, e.g. `("SHA-256", SHA256_FILLER)`.
    pub hashes: Vec<(String, String)>,
    /// `(type, url)` external references, e.g. `("vcs", "https://…")`.
    pub external_refs: Vec<(String, String)>,
    /// SPDX license ids rendered as `{"license": {"id": …}}` entries.
    pub licenses: Vec<String>,
    /// `(name, value)` CycloneDX properties.
    pub properties: Vec<(String, String)>,
}

impl ComponentFixture {
    /// A component that satisfies every per-component element the generic /
    /// FDA / SSDF / EO 14028 checkers look for: real name, version, PURL,
    /// supplier, and a strong (SHA-256) hash.
    pub fn conforming(name: &str) -> Self {
        Self {
            bom_ref: format!("ref-{name}"),
            name: name.to_string(),
            version: Some("1.2.3".to_string()),
            purl: Some(format!("pkg:npm/{name}@1.2.3")),
            supplier: Some("Acme Components Ltd".to_string()),
            hashes: vec![("SHA-256".to_string(), SHA256_FILLER.to_string())],
            external_refs: Vec::new(),
            licenses: Vec::new(),
            properties: Vec::new(),
        }
    }

    fn to_json(&self) -> serde_json::Value {
        let mut obj = serde_json::Map::new();
        obj.insert("type".into(), serde_json::json!("library"));
        obj.insert("bom-ref".into(), serde_json::json!(self.bom_ref));
        obj.insert("name".into(), serde_json::json!(self.name));
        if let Some(version) = &self.version {
            obj.insert("version".into(), serde_json::json!(version));
        }
        if let Some(purl) = &self.purl {
            obj.insert("purl".into(), serde_json::json!(purl));
        }
        if let Some(supplier) = &self.supplier {
            obj.insert("supplier".into(), serde_json::json!({ "name": supplier }));
        }
        if !self.hashes.is_empty() {
            let hashes: Vec<_> = self
                .hashes
                .iter()
                .map(|(alg, content)| serde_json::json!({ "alg": alg, "content": content }))
                .collect();
            obj.insert("hashes".into(), serde_json::json!(hashes));
        }
        if !self.external_refs.is_empty() {
            let refs: Vec<_> = self
                .external_refs
                .iter()
                .map(|(ref_type, url)| serde_json::json!({ "type": ref_type, "url": url }))
                .collect();
            obj.insert("externalReferences".into(), serde_json::json!(refs));
        }
        if !self.licenses.is_empty() {
            let licenses: Vec<_> = self
                .licenses
                .iter()
                .map(|id| serde_json::json!({ "license": { "id": id } }))
                .collect();
            obj.insert("licenses".into(), serde_json::json!(licenses));
        }
        if !self.properties.is_empty() {
            let props: Vec<_> = self
                .properties
                .iter()
                .map(|(name, value)| serde_json::json!({ "name": name, "value": value }))
                .collect();
            obj.insert("properties".into(), serde_json::json!(props));
        }
        serde_json::Value::Object(obj)
    }
}

/// A minimal CycloneDX document, rendered to JSON and parsed through the real
/// parser. All fields are public so a test can clone a conforming baseline
/// and break exactly one aspect per case.
#[derive(Debug, Clone)]
pub struct SbomFixture {
    pub spec_version: String,
    /// RFC 3339 `metadata.timestamp`; `None` → the parser stores the
    /// UNIX-epoch "unknown" sentinel (`has_known_timestamp() == false`).
    pub timestamp: Option<String>,
    /// Top-level `serialNumber`.
    pub serial_number: Option<String>,
    /// `metadata.tools` entries `(name, version)` → `CreatorType::Tool`.
    pub tools: Vec<(String, String)>,
    /// `metadata.authors` entries `(name, email)` → `CreatorType::Person`.
    pub authors: Vec<(String, Option<String>)>,
    /// `metadata.manufacturer` `(name, contact email)` →
    /// `CreatorType::Organization`.
    pub manufacturer: Option<(String, Option<String>)>,
    /// `metadata.component` → `document.name` + primary component (joins
    /// `sbom.components` like any other component).
    pub primary: Option<ComponentFixture>,
    pub components: Vec<ComponentFixture>,
    /// `dependencies[]` entries: `(ref, dependsOn refs)`.
    pub dependencies: Vec<(String, Vec<String>)>,
    /// Document `vulnerabilities[]`: `(id, rating severity, affected bom-ref)`.
    pub vulnerabilities: Vec<(String, String, String)>,
}

impl SbomFixture {
    /// Mutable access to a listed component by name (panics when absent, so a
    /// typo in a test case fails loudly instead of silently testing nothing).
    pub fn component_mut(&mut self, name: &str) -> &mut ComponentFixture {
        self.components
            .iter_mut()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("fixture has no component named {name:?}"))
    }

    /// Render the CycloneDX JSON document.
    pub fn to_json_string(&self) -> String {
        let mut doc = serde_json::Map::new();
        doc.insert("bomFormat".into(), serde_json::json!("CycloneDX"));
        doc.insert("specVersion".into(), serde_json::json!(self.spec_version));
        doc.insert("version".into(), serde_json::json!(1));
        if let Some(serial) = &self.serial_number {
            doc.insert("serialNumber".into(), serde_json::json!(serial));
        }

        let mut metadata = serde_json::Map::new();
        if let Some(ts) = &self.timestamp {
            metadata.insert("timestamp".into(), serde_json::json!(ts));
        }
        if !self.tools.is_empty() {
            let tools: Vec<_> = self
                .tools
                .iter()
                .map(|(name, version)| serde_json::json!({ "name": name, "version": version }))
                .collect();
            metadata.insert("tools".into(), serde_json::json!(tools));
        }
        if !self.authors.is_empty() {
            let authors: Vec<_> = self
                .authors
                .iter()
                .map(|(name, email)| {
                    let mut a = serde_json::Map::new();
                    a.insert("name".into(), serde_json::json!(name));
                    if let Some(email) = email {
                        a.insert("email".into(), serde_json::json!(email));
                    }
                    serde_json::Value::Object(a)
                })
                .collect();
            metadata.insert("authors".into(), serde_json::json!(authors));
        }
        if let Some((name, email)) = &self.manufacturer {
            let mut m = serde_json::Map::new();
            m.insert("name".into(), serde_json::json!(name));
            if let Some(email) = email {
                m.insert("contact".into(), serde_json::json!([{ "email": email }]));
            }
            metadata.insert("manufacturer".into(), serde_json::Value::Object(m));
        }
        if let Some(primary) = &self.primary {
            metadata.insert("component".into(), primary.to_json());
        }
        if !metadata.is_empty() {
            doc.insert("metadata".into(), serde_json::Value::Object(metadata));
        }

        let components: Vec<_> = self
            .components
            .iter()
            .map(ComponentFixture::to_json)
            .collect();
        doc.insert("components".into(), serde_json::json!(components));

        if !self.dependencies.is_empty() {
            let deps: Vec<_> = self
                .dependencies
                .iter()
                .map(|(from, depends_on)| {
                    serde_json::json!({ "ref": from, "dependsOn": depends_on })
                })
                .collect();
            doc.insert("dependencies".into(), serde_json::json!(deps));
        }

        if !self.vulnerabilities.is_empty() {
            let vulns: Vec<_> = self
                .vulnerabilities
                .iter()
                .map(|(id, severity, affected_ref)| {
                    serde_json::json!({
                        "id": id,
                        "ratings": [{ "severity": severity }],
                        "affects": [{ "ref": affected_ref }],
                    })
                })
                .collect();
            doc.insert("vulnerabilities".into(), serde_json::json!(vulns));
        }

        serde_json::to_string_pretty(&serde_json::Value::Object(doc))
            .expect("fixture JSON must serialize")
    }

    /// Parse the rendered document through the real CycloneDX parser.
    pub fn parse(&self) -> NormalizedSbom {
        let json = self.to_json_string();
        parse_sbom_str(&json)
            .unwrap_or_else(|e| panic!("fixture must parse as CycloneDX: {e}\n{json}"))
    }
}

/// Run one compliance standard over a fixture (real parser → real checker),
/// at the pinned test clock.
pub fn check(level: ComplianceLevel, fixture: &SbomFixture) -> ComplianceResult {
    clock::checker(level).check(&fixture.parse())
}

/// Render a result's violations for assertion messages.
pub fn render_violations(result: &ComplianceResult) -> String {
    if result.violations.is_empty() {
        return "  (no violations)".to_string();
    }
    result
        .violations
        .iter()
        .map(|v| {
            format!(
                "  [{sev}] {rule} (sarif {sarif}): {msg}",
                sev = v.severity.name(),
                rule = v.rule_id,
                sarif = v.sarif_rule_id(),
                msg = v.message
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Assert a fully-conforming fixture yields a clean, compliant verdict.
pub fn assert_no_violations(level: ComplianceLevel, fixture: &SbomFixture) {
    let result = check(level, fixture);
    assert!(
        result.violations.is_empty() && result.is_compliant,
        "[{level:?}] conforming fixture must pass with zero violations; got \
         is_compliant={compliant}:\n{violations}",
        compliant = result.is_compliant,
        violations = render_violations(&result)
    );
}

/// One firing case: a minimal fixture that must surface the rule at the
/// stated severity.
pub struct FiringCase {
    pub label: &'static str,
    pub severity: ViolationSeverity,
    /// `true` when the push site intentionally emits a severity different
    /// from the registry's documented default (registry doc: "Push sites may
    /// still escalate/relax"). The runner enforces this flag's consistency,
    /// so deviations stay explicit instead of accidental.
    pub departs_from_registry_default: bool,
    pub fixture: SbomFixture,
}

/// Coverage for one SARIF rule id of a standard's universe. The silent
/// fixture is boxed to keep the variants comparable in size
/// (clippy::large_enum_variant).
pub enum RuleCoverage {
    Tested {
        firing: Vec<FiringCase>,
        silent: Box<SbomFixture>,
    },
    /// The rule genuinely cannot fire from document content alone (or has no
    /// emitting check site); the reason is part of the matrix.
    Skipped { reason: &'static str },
}

/// One row of the per-standard matrix.
pub struct RuleEntry {
    pub sarif_id: &'static str,
    pub coverage: RuleCoverage,
}

impl RuleEntry {
    /// Rule with a firing case at the registry's default severity plus a
    /// silent case.
    pub fn tested(
        sarif_id: &'static str,
        severity: ViolationSeverity,
        firing: SbomFixture,
        silent: SbomFixture,
    ) -> Self {
        Self {
            sarif_id,
            coverage: RuleCoverage::Tested {
                firing: vec![FiringCase {
                    label: "firing",
                    severity,
                    departs_from_registry_default: false,
                    fixture: firing,
                }],
                silent: Box::new(silent),
            },
        }
    }

    /// Rule whose main firing case intentionally departs from the registry's
    /// documented default severity (push-site escalation/relaxation).
    pub fn tested_departing(
        sarif_id: &'static str,
        severity: ViolationSeverity,
        firing: SbomFixture,
        silent: SbomFixture,
    ) -> Self {
        Self {
            sarif_id,
            coverage: RuleCoverage::Tested {
                firing: vec![FiringCase {
                    label: "firing",
                    severity,
                    departs_from_registry_default: true,
                    fixture: firing,
                }],
                silent: Box::new(silent),
            },
        }
    }

    /// Additional firing case at the registry's default severity.
    #[must_use]
    pub fn with_firing(
        mut self,
        label: &'static str,
        severity: ViolationSeverity,
        fixture: SbomFixture,
    ) -> Self {
        self.push_firing(FiringCase {
            label,
            severity,
            departs_from_registry_default: false,
            fixture,
        });
        self
    }

    /// Additional firing case at a push-site severity that departs from the
    /// registry default.
    #[must_use]
    pub fn with_departing_firing(
        mut self,
        label: &'static str,
        severity: ViolationSeverity,
        fixture: SbomFixture,
    ) -> Self {
        self.push_firing(FiringCase {
            label,
            severity,
            departs_from_registry_default: true,
            fixture,
        });
        self
    }

    fn push_firing(&mut self, case: FiringCase) {
        match &mut self.coverage {
            RuleCoverage::Tested { firing, .. } => firing.push(case),
            RuleCoverage::Skipped { .. } => {
                panic!("cannot add a firing case to skipped rule {}", self.sarif_id)
            }
        }
    }

    /// Explicit skip-with-reason entry (counted by the exhaustiveness gate).
    pub fn skipped(sarif_id: &'static str, reason: &'static str) -> Self {
        Self {
            sarif_id,
            coverage: RuleCoverage::Skipped { reason },
        }
    }
}

/// Run a per-standard rule matrix:
///
/// 1. exhaustiveness — `entries` must cover `universe` exactly (every rule id
///    tested or explicitly skipped, no duplicates, no strays);
/// 2. per rule — each firing fixture surfaces the rule id at the expected
///    severity (with registry-default consistency enforced), each silent
///    fixture stays silent for that id;
/// 3. sweep — every violation any fixture emits maps into `universe`.
pub fn run_matrix(level: ComplianceLevel, universe: &[&str], entries: &[RuleEntry]) {
    let universe_set: BTreeSet<&str> = universe.iter().copied().collect();
    assert_eq!(
        universe.len(),
        universe_set.len(),
        "[{level:?}] rule universe contains duplicates"
    );

    let mut covered: BTreeSet<&str> = BTreeSet::new();
    for entry in entries {
        assert!(
            covered.insert(entry.sarif_id),
            "[{level:?}] duplicate matrix entry for {}",
            entry.sarif_id
        );
    }
    assert_eq!(
        covered, universe_set,
        "[{level:?}] the matrix must cover the standard's rule universe \
         exactly: every rule id is tested or explicitly skipped with a reason \
         (left = matrix entries, right = universe)"
    );

    for entry in entries {
        let RuleCoverage::Tested { firing, silent } = &entry.coverage else {
            continue; // skip-with-reason rows carry their justification inline
        };
        let id = entry.sarif_id;
        let meta = rule_meta(id)
            .unwrap_or_else(|| panic!("[{level:?}] {id} does not resolve in the rule registry"));

        assert!(!firing.is_empty(), "[{level:?}] {id} has no firing case");
        for case in firing {
            // The flag keeps severity expectations honest against the
            // registry: an expectation that silently matches (or silently
            // departs from) the documented default fails here.
            assert_eq!(
                case.severity == meta.default_severity,
                !case.departs_from_registry_default,
                "[{level:?}] {id} ({label}): expected severity {expected:?} vs registry \
                 default {default:?} — update the departs_from_registry_default flag \
                 (or the expectation) so the deviation is explicit",
                label = case.label,
                expected = case.severity,
                default = meta.default_severity,
            );

            let result = check(level, &case.fixture);
            let hits: Vec<_> = result
                .violations
                .iter()
                .filter(|v| v.sarif_rule_id() == id)
                .collect();
            assert!(
                !hits.is_empty(),
                "[{level:?}] {id} ({label}): the violating fixture must fire this rule; \
                 emitted:\n{violations}",
                label = case.label,
                violations = render_violations(&result)
            );
            assert!(
                hits.iter().any(|v| v.severity == case.severity),
                "[{level:?}] {id} ({label}): rule fired but not at {expected:?}; \
                 emitted:\n{violations}",
                label = case.label,
                expected = case.severity,
                violations = render_violations(&result)
            );
        }

        let result = check(level, silent);
        assert!(
            result.violations.iter().all(|v| v.sarif_rule_id() != id),
            "[{level:?}] {id} (silent): the satisfying fixture must not fire this rule; \
             emitted:\n{violations}",
            violations = render_violations(&result)
        );
    }

    // Universe sweep: no fixture in this matrix may emit a rule outside the
    // declared universe. A new check site for this standard must extend the
    // universe (and therefore the matrix) instead of escaping it.
    for entry in entries {
        let RuleCoverage::Tested { firing, silent } = &entry.coverage else {
            continue;
        };
        let fixtures = firing
            .iter()
            .map(|c| (c.label, &c.fixture))
            .chain(std::iter::once(("silent", silent.as_ref())));
        for (label, fixture) in fixtures {
            let result = check(level, fixture);
            for v in &result.violations {
                assert!(
                    universe_set.contains(v.sarif_rule_id()),
                    "[{level:?}] fixture for {id} ({label}) emitted rule {rule} \
                     (sarif {sarif}) outside the declared rule universe {universe_set:?} — \
                     new check site? extend the universe and the matrix",
                    id = entry.sarif_id,
                    rule = v.rule_id,
                    sarif = v.sarif_rule_id(),
                );
            }
        }
    }
}
