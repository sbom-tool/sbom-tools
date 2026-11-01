//! OSCAL assessment-results export for compliance validation findings.
//!
//! One `results[]` entry is emitted per checked standard
//! ([`ComplianceResult`]), so a multi-standard validation no longer flattens
//! into a single anonymous assessment: each entry carries the standard's
//! identity in its title/description and a per-result `props` block with the
//! machine-readable verdict (the standard's canonical key, compliance,
//! applicability, severity counts, score, and what the run did not evaluate
//! or kept out). A fully compliant standard still gets its result entry,
//! with a satisfied roll-up finding.
//!
//! Each rule a standard checked against the SBOM becomes an observation and
//! the finding that judges it (a `Check`): a violation is a `not-satisfied`
//! finding over a `discovery` observation, a passed check a `satisfied`
//! finding over a `control-objective` observation. Observations name their
//! subjects: the SBOM document, described once as a back-matter resource,
//! and, when the check is about a component, that component, defined in the
//! result's `local-definitions`.
//!
//! The SBOM resource, each result, and each finding and its observation
//! carry the audit fields `-o json` and `-o sarif` carry too
//! (`reports::audit`): the finding its identity, remediation and help link,
//! the observation the rule, the severity, what the check read and the
//! standard references.
//!
//! OSCAL titles, descriptions and remarks are Markdown that viewers render,
//! so every such field that carries SBOM text (violation messages, component
//! and document names, versions) is Markdown-escaped; see `markup_text`.
//! Property values are plain strings and are only normalized.

use std::collections::HashMap;

use super::audit::{self, AssessedSbom, AuditField, AuditValue, OscalPart, instant_text, token};
use super::escape::escape_markdown_inline;
use crate::model::{Component, ComponentType, NormalizedSbom};
use crate::quality::{
    ComplianceLevel, ComplianceResult, PassedCheck, Violation, ViolationSeverity, standard_key,
};
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use uuid::Uuid;

/// The OSCAL release the document conforms to, declared in
/// `metadata.oscal-version`. Tests validate every fixture's output against
/// this release's JSON schema (`tests/fixtures/schemas/oscal/`).
const OSCAL_VERSION: &str = "1.2.3";
const ASSESSMENT_PLAN_URN: &str = "urn:sbom-tools:assessment-plan:validation";
const PROP_NS: &str = "https://sbom.tools/ns/oscal";

/// Generate an OSCAL 1.2.3 assessment-results JSON document.
///
/// Stamps the current time and random UUIDs, so two runs never produce the
/// same bytes, and knows only what the results say about the SBOM: the
/// document subject carries no name or digest, and a component is titled by
/// the label its findings give it. Prefer [`generate_assessment_results_at`],
/// which is reproducible and describes the SBOM and its components.
pub fn generate_assessment_results(results: &[ComplianceResult]) -> Result<String> {
    build_assessment_results(results, None, Utc::now(), &mut RandomUuids::default())
}

/// Generate an OSCAL 1.2.3 assessment-results JSON document about
/// `assessed`, the SBOM the results judge, that is reproducible for a given
/// input.
///
/// `assessed` holds the parsed document the results were computed from, the
/// SHA-256 of its bytes and its file name. They describe the subjects
/// observations name: the SBOM document (a back-matter resource with the
/// digest, format, serial number and file name, and how the document was
/// read) and the components findings are about (local definitions with
/// name, version and canonical id).
///
/// The `collected`, `start` and `last-modified` timestamps are `as_of`, the
/// instant the results were judged at. Every UUID is a UUIDv5. Those that
/// identify the assessment (the document, each result, observation and
/// finding) derive from the SBOM's SHA-256, that instant, the checked
/// standards and their position in the document: the same SBOM evaluated
/// against the same standards at the same instant always yields the same
/// bytes, while a different SBOM, instant or standard set never reuses one.
/// Those that identify a subject derive from the SHA-256 and the subject
/// alone (for a component, its canonical id), so a subject keeps its UUID
/// across instants, standard sets and results, as OSCAL asks of per-subject
/// identifiers.
pub fn generate_assessment_results_at(
    results: &[ComplianceResult],
    assessed: &AssessedSbom<'_>,
    as_of: DateTime<Utc>,
) -> Result<String> {
    let mut uuids = DerivedUuids::new(results, assessed.sha256(), as_of);
    build_assessment_results(results, Some(assessed), as_of, &mut uuids)
}

fn build_assessment_results(
    results: &[ComplianceResult],
    assessed: Option<&AssessedSbom<'_>>,
    timestamp: DateTime<Utc>,
    uuids: &mut impl UuidSource,
) -> Result<String> {
    let collected = instant_text(timestamp);
    let subjects = Subjects::new(assessed, uuids);
    let mut result_entries: Vec<Value> = results
        .iter()
        .map(|result| standard_result(result, &collected, &subjects, uuids))
        .collect();
    // OSCAL requires at least one result entry; keep the historical empty
    // assessment shape when no standard was checked at all.
    if result_entries.is_empty() {
        result_entries.push(json!({
            "uuid": uuids.next(),
            "title": "sbom-tools validation assessment",
            "description": "Validation results derived only from the supplied SBOM.",
            "start": collected,
            "reviewed-controls": reviewed_controls(),
        }));
    }

    Ok(serde_json::to_string_pretty(&json!({
        "assessment-results": {
            "uuid": uuids.next(),
            "metadata": {
                "title": "sbom-tools validation assessment results",
                "last-modified": collected,
                "version": env!("CARGO_PKG_VERSION"),
                "oscal-version": OSCAL_VERSION
            },
            "import-ap": { "href": ASSESSMENT_PLAN_URN },
            "results": result_entries,
            "back-matter": { "resources": [subjects.document_resource()] }
        }
    }))?)
}

// ---------------------------------------------------------------------------
// UUIDs
// ---------------------------------------------------------------------------

/// Where the document's UUIDs come from.
trait UuidSource {
    /// The next UUID that identifies the assessment (the document, a result,
    /// an observation, a finding), drawn in document order.
    fn next(&mut self) -> Uuid;

    /// The UUID of the subject `key` names: equal keys give equal UUIDs.
    fn subject(&mut self, key: &str) -> Uuid;
}

/// Name (in the RFC 4122 URL namespace) of the UUIDv5 namespace that
/// [`generate_assessment_results_at`] derives document UUIDs from.
const UUID_NAMESPACE_NAME: &str =
    "https://github.com/sbom-tool/sbom-tools/oscal/assessment-results";

/// UUIDv5s derived from the input ([`generate_assessment_results_at`]).
struct DerivedUuids {
    namespace: Uuid,
    /// `<digest>|<instant>|<standards>`; an assessment UUID appends its
    /// position in the document.
    assessment_seed: String,
    /// `<digest>`; a subject UUID appends `subject|<key>`.
    subject_seed: String,
    position: u64,
}

impl DerivedUuids {
    fn new(results: &[ComplianceResult], sbom_digest: &str, timestamp: DateTime<Utc>) -> Self {
        let standards: Vec<&str> = results.iter().map(|r| standard_key(r.level)).collect();
        Self {
            namespace: Uuid::new_v5(&Uuid::NAMESPACE_URL, UUID_NAMESPACE_NAME.as_bytes()),
            assessment_seed: format!(
                "{sbom_digest}|{}|{}",
                instant_text(timestamp),
                standards.join(",")
            ),
            subject_seed: sbom_digest.to_string(),
            position: 0,
        }
    }
}

impl UuidSource for DerivedUuids {
    fn next(&mut self) -> Uuid {
        self.position += 1;
        let name = format!("{}|{}", self.assessment_seed, self.position);
        Uuid::new_v5(&self.namespace, name.as_bytes())
    }

    fn subject(&mut self, key: &str) -> Uuid {
        let name = format!("{}|subject|{key}", self.subject_seed);
        Uuid::new_v5(&self.namespace, name.as_bytes())
    }
}

/// Random UUIDv4s ([`generate_assessment_results`]), one per subject.
#[derive(Default)]
struct RandomUuids {
    subjects: HashMap<String, Uuid>,
}

impl UuidSource for RandomUuids {
    fn next(&mut self) -> Uuid {
        Uuid::new_v4()
    }

    fn subject(&mut self, key: &str) -> Uuid {
        *self
            .subjects
            .entry(key.to_string())
            .or_insert_with(Uuid::new_v4)
    }
}

// ---------------------------------------------------------------------------
// Checks: one observation and the finding that judges it
// ---------------------------------------------------------------------------

/// Whether a check met its objective. OSCAL's finding-target `state` is a
/// closed enum (no allow-other) with exactly these two values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Objective {
    Satisfied,
    NotSatisfied,
}

impl Objective {
    const fn from_met(met: bool) -> Self {
        if met {
            Self::Satisfied
        } else {
            Self::NotSatisfied
        }
    }

    const fn state(self) -> &'static str {
        match self {
            Self::Satisfied => "satisfied",
            Self::NotSatisfied => "not-satisfied",
        }
    }

    /// The type of the observation behind a check. An unmet objective is a
    /// `discovery`: OSCAL 1.2.0 deprecated `finding`, the type for
    /// observations made by tools, and named `discovery` its replacement. A
    /// met one is an observation about the status of a `control-objective`.
    const fn observation_type(self) -> &'static str {
        match self {
            Self::Satisfied => "control-objective",
            Self::NotSatisfied => "discovery",
        }
    }
}

/// One rule checked against one subject, emitted as an observation and the
/// finding that judges it. A violation is a check whose objective was not
/// met; a check the SBOM passed takes the same path with
/// [`Objective::Satisfied`].
struct Check<'a> {
    rule_id: &'static str,
    /// What the check found, as plain text that embeds SBOM values
    /// (component names, versions, field contents); see
    /// [`Check::description`].
    message: &'a str,
    objective: Objective,
    /// Canonical id of the component the check is about; `None` for the
    /// document and for aggregate checks.
    component_id: Option<&'a str>,
    /// The SBOM's label for that component (usually its name): its title
    /// when the SBOM itself is not at hand.
    label: Option<&'a str>,
    /// The finding's audit fields (`reports::audit`): the finding carries
    /// its identity, remediation and help link, the observation the rest.
    fields: Vec<AuditField<'a>>,
}

impl<'a> Check<'a> {
    /// The check a violation reported under `level` reports. Any violation,
    /// whatever its severity, is an unmet objective; the severity is the
    /// observation's `severity` property, and a finding whose rule the run
    /// sets (`--rule`) adds the severity its check gave it and the setting's
    /// source as `default-severity` and `severity-source`.
    fn violation(level: ComplianceLevel, violation: &'a Violation) -> Self {
        Self {
            rule_id: violation.rule_id,
            message: &violation.message,
            objective: Objective::NotSatisfied,
            component_id: violation.component_id.as_deref(),
            label: violation.element.as_deref(),
            fields: audit::violation_fields(level, violation),
        }
    }

    /// The check a check passed under `level` reports: a met objective. A
    /// pass has no severity, remediation or help link.
    fn pass(level: ComplianceLevel, pass: &'a PassedCheck) -> Self {
        Self {
            rule_id: pass.rule_id,
            message: &pass.message,
            objective: Objective::Satisfied,
            component_id: pass.component_id.as_deref(),
            label: pass.element.as_deref(),
            fields: audit::pass_fields(level, pass),
        }
    }

    /// The observation's and the finding's `description` (markup): the
    /// message, Markdown-escaped as a whole because SBOM values sit inside it.
    /// Its own wording renders unchanged; only the raw JSON gains backslashes.
    fn description(&self) -> String {
        markup_text(self.message).unwrap_or_default()
    }

    /// What the audit fields of `part` (the finding, or its observation)
    /// give that part.
    fn rendered(&self, part: OscalPart) -> Rendered {
        Rendered::of(self.fields.iter().filter(|field| field.name.part == part))
    }
}

/// The properties, links and remarks that audit fields give one part of
/// the document (see `reports::audit`). Every property is in our
/// namespace; a property or link left with no text is left out.
#[derive(Default)]
struct Rendered {
    props: Vec<Value>,
    links: Vec<Value>,
    remarks: Option<String>,
}

impl Rendered {
    fn of<'f, 'a: 'f>(fields: impl IntoIterator<Item = &'f AuditField<'a>>) -> Self {
        let mut rendered = Self::default();
        for field in fields {
            rendered.add(field);
        }
        rendered
    }

    fn add(&mut self, field: &AuditField<'_>) {
        let name = field.name.oscal;
        match &field.value {
            AuditValue::Text(text) => self.props.extend(prop(name, text)),
            AuditValue::Count(count) => self.props.extend(prop(name, &count.to_string())),
            AuditValue::Flag(flag) => self.props.extend(prop(name, &flag.to_string())),
            AuditValue::Applicability(applicable) => self.props.extend(prop(
                name,
                if *applicable {
                    "applicable"
                } else {
                    "not-applicable"
                },
            )),
            AuditValue::Score(score) => self.props.extend(prop(name, &score.to_string())),
            AuditValue::Severity(value) => self.props.extend(prop(name, severity(*value))),
            AuditValue::Words(words) => self
                .props
                .extend(words.iter().filter_map(|word| prop(name, word))),
            AuditValue::Link(uri) => self.links.extend(link(uri, name, None)),
            AuditValue::Guidance(text) => self.remarks = markup_text(text),
            // A reference is its clause, classed by the standard (as `-o
            // json` names it), and a link to the standard when it has a URL.
            AuditValue::References(refs) => {
                for reference in *refs {
                    let standard = token(&reference.standard);
                    self.props.extend(prop_with(
                        name,
                        &reference.id,
                        PropDetail {
                            class: Some(&standard),
                            ..PropDetail::default()
                        },
                    ));
                    if let Some(uri) = &reference.help_uri {
                        self.links
                            .extend(link(uri, "reference", Some(&reference.citation())));
                    }
                }
            }
            // A check not evaluated is its rule, with the reason as remarks.
            AuditValue::NotEvaluated(checks) => {
                for check in *checks {
                    self.props.extend(prop_with(
                        name,
                        check.rule_id,
                        PropDetail {
                            remarks: Some(&check.reason),
                            ..PropDetail::default()
                        },
                    ));
                }
            }
            // A rule turned off is three properties of one group: the rule,
            // how many findings it dropped and where the setting comes from.
            AuditValue::Suppressed(rules) => {
                for (n, rule) in rules.iter().enumerate() {
                    let group = format!("{name}-{}", n + 1);
                    for (part, value) in [
                        ("rule", rule.rule_id.clone()),
                        ("findings", rule.findings.to_string()),
                        ("source", rule.source.name().to_string()),
                    ] {
                        self.props.extend(prop_with(
                            &format!("{name}-{part}"),
                            &value,
                            PropDetail {
                                group: Some(&group),
                                ..PropDetail::default()
                            },
                        ));
                    }
                }
            }
            // The product class, the route, and each piece of evidence:
            // its label, classed `satisfied` or `not-satisfied` as an
            // objective is, with its detail as remarks.
            AuditValue::Conformity(summary) => {
                self.props.extend(prop(
                    &format!("{name}-product-class"),
                    &token(&summary.product_class),
                ));
                self.props
                    .extend(prop(&format!("{name}-route"), &token(&summary.route)));
                for evidence in &summary.evidence {
                    self.props.extend(prop_with(
                        &format!("{name}-evidence"),
                        &evidence.label,
                        PropDetail {
                            class: Some(Objective::from_met(evidence.satisfied).state()),
                            remarks: Some(&evidence.detail),
                            ..PropDetail::default()
                        },
                    ));
                }
            }
        }
    }
}

fn reviewed_controls() -> Value {
    json!({
        "control-selections": [{
            "description": "Controls represented by the selected sbom-tools validation standards.",
            "include-all": {}
        }]
    })
}

/// Build the `results[]` entry for one checked standard.
fn standard_result(
    result: &ComplianceResult,
    collected: &str,
    subjects: &Subjects<'_>,
    uuids: &mut impl UuidSource,
) -> Value {
    let standard_name = result.level.name();
    // The verdict: the standard's key and name, its compliance and
    // applicability, the counts and score, and the checks it did not
    // evaluate, the findings the run's settings turned off and the
    // components it left out, with the CRA conformity summary.
    let props = Rendered::of(&audit::result_fields(result)).props;

    // The violations, then the passed checks. A standard that did not apply
    // reports neither: the applicability props above carry that verdict
    // (OSCAL's finding-target state is a closed satisfied/not-satisfied enum
    // with no N/A).
    let checks = result
        .violations
        .iter()
        .map(|violation| Check::violation(result.level, violation))
        .chain(
            result
                .passed
                .iter()
                .map(|pass| Check::pass(result.level, pass)),
        );

    let mut observations = Vec::new();
    let mut findings = Vec::new();
    let mut components = LocalComponents::default();
    // Roll-up finding: the standard-level verdict. Not-applicable standards
    // keep `is_compliant = true` by contract but were never evaluated, so
    // they get no roll-up — the props above carry the N/A verdict instead.
    if result.is_applicable() {
        findings.push(rollup_finding(result, standard_name, uuids.next()));
    }
    for check in checks {
        let observation_uuid = uuids.next();
        let observed = subjects.references(&check, &mut components, uuids);
        findings.push(finding(&check, observation_uuid, uuids.next()));
        observations.push(observation(check, observation_uuid, collected, observed));
    }

    let mut entry = json!({
        "uuid": uuids.next(),
        "title": format!("sbom-tools validation assessment — {standard_name}"),
        "description": format!(
            "Validation results for {standard_name}, derived only from the supplied SBOM."
        ),
        "start": collected,
        "reviewed-controls": reviewed_controls(),
    });
    set_array(&mut entry, "props", props);
    if !components.definitions.is_empty() {
        entry["local-definitions"] = json!({ "components": components.definitions });
    }
    set_array(&mut entry, "observations", observations);
    set_array(&mut entry, "findings", findings);
    entry
}

/// Standard-level roll-up finding: `satisfied` when the standard evaluated
/// the SBOM and found no blocking violation, `not-satisfied` otherwise. Its
/// objective is named by the standard's canonical key (`cra-compliance`).
fn rollup_finding(result: &ComplianceResult, standard_name: &str, uuid: Uuid) -> Value {
    // The passed checks are named only when there are some, so a result
    // that passes none keeps its description.
    let passed = match result.passed.len() {
        0 => String::new(),
        n => format!(" {n} check(s) passed."),
    };
    json!({
        "uuid": uuid,
        "title": format!("{standard_name} compliance roll-up"),
        "description": format!(
            "Overall verdict for {standard_name}: {} error(s), {} warning(s), {} informational finding(s).{passed}",
            result.error_count, result.warning_count, result.info_count
        ),
        "target": {
            "type": "objective-id",
            "target-id": format!("{}-compliance", standard_key(result.level)),
            "status": { "state": Objective::from_met(result.is_compliant).state() }
        }
    })
}

/// The observation behind a check: the evidence, with the audit fields of
/// the observation (the rule, the severity, what the check read, the
/// references and their links).
fn observation(check: Check<'_>, uuid: Uuid, collected: &str, subjects: Vec<Value>) -> Value {
    let Rendered { props, links, .. } = check.rendered(OscalPart::Observation);
    let mut observation = json!({
        "uuid": uuid,
        "title": check.rule_id,
        "description": check.description(),
        "methods": ["EXAMINE"],
        "types": [check.objective.observation_type()],
        "subjects": subjects,
        "collected": collected,
    });
    set_array(&mut observation, "props", props);
    set_array(&mut observation, "links", links);
    observation
}

/// The finding that judges a check, with the audit fields of the finding:
/// its identity (`finding-id`, `finding-key`), the link to its rule's
/// documentation and the remediation as remarks.
fn finding(check: &Check<'_>, observation_uuid: Uuid, uuid: Uuid) -> Value {
    let Rendered {
        props,
        links,
        remarks,
    } = check.rendered(OscalPart::Finding);
    let mut finding = json!({
        "uuid": uuid,
        "title": check.rule_id,
        "description": check.description(),
        "target": {
            "type": "objective-id",
            "target-id": check.rule_id.to_ascii_lowercase(),
            "status": { "state": check.objective.state() }
        },
        "related-observations": [{ "observation-uuid": observation_uuid }]
    });
    set_array(&mut finding, "props", props);
    set_array(&mut finding, "links", links);
    if let Some(remarks) = remarks {
        finding["remarks"] = Value::String(remarks);
    }
    finding
}

/// OSCAL's word for a severity: lowercase, as the properties have always
/// carried it.
const fn severity(value: ViolationSeverity) -> &'static str {
    match value {
        ViolationSeverity::Error => "error",
        ViolationSeverity::Warning => "warning",
        ViolationSeverity::Info => "info",
    }
}

// ---------------------------------------------------------------------------
// Subjects: the SBOM document and its components
// ---------------------------------------------------------------------------

/// Subject key of the SBOM document; a component's is `component|<id>`.
const DOCUMENT_SUBJECT_KEY: &str = "document";

/// The subjects observations name: the SBOM document, described once as a
/// back-matter resource, and the components checks are about.
struct Subjects<'a> {
    /// The assessed SBOM, when the writer is given it.
    assessed: Option<&'a AssessedSbom<'a>>,
    /// The SBOM's components by canonical id.
    components: HashMap<&'a str, &'a Component>,
    document_uuid: Uuid,
    document_title: String,
}

impl<'a> Subjects<'a> {
    fn new(assessed: Option<&'a AssessedSbom<'a>>, uuids: &mut impl UuidSource) -> Self {
        let sbom = assessed.map(AssessedSbom::sbom);
        let components = sbom
            .map(|sbom| {
                sbom.components
                    .values()
                    .map(|component| (component.canonical_id.value(), component))
                    .collect()
            })
            .unwrap_or_default();
        Self {
            assessed,
            components,
            document_uuid: uuids.subject(DOCUMENT_SUBJECT_KEY),
            document_title: document_title(sbom),
        }
    }

    /// The back-matter resource describing the SBOM document: an `artifact`
    /// in OSCAL's resource vocabulary, with the audit fields of the SBOM (the
    /// SHA-256 of its bytes, its format and specification version, its file
    /// name, and how its document was read) and its serial number
    /// (CycloneDX) or document namespace (SPDX) as a document id. When that
    /// id is a URI (`urn:uuid:…`, `https://…`), it is also the resource's
    /// `rlink`, with the SHA-256 in `hashes` so the document can be checked
    /// against it.
    fn document_resource(&self) -> Value {
        let mut props: Vec<Value> = oscal_prop("type", "artifact").into_iter().collect();
        let mut document_ids = Vec::new();
        let mut rlinks = Vec::new();
        if let Some(assessed) = self.assessed {
            props.extend(Rendered::of(&audit::subject_fields(assessed)).props);
            let digest = assessed.sha256();
            let document = &assessed.sbom().document;
            if let Some(serial) = document.serial_number.as_deref().and_then(oscal_string) {
                if is_absolute_uri(&serial) {
                    let mut rlink = json!({ "href": serial });
                    // OSCAL checks a SHA-256 value is 64 hex digits.
                    if is_sha256_hex(digest) {
                        rlink["hashes"] = json!([{ "algorithm": "SHA-256", "value": digest }]);
                    }
                    rlinks.push(rlink);
                }
                document_ids.push(json!({ "identifier": serial }));
            }
        }
        let mut resource = json!({
            "uuid": self.document_uuid,
            "title": self.document_title,
            "description": "The SBOM document this assessment examined. Every observation names it as a subject.",
        });
        set_array(&mut resource, "props", props);
        set_array(&mut resource, "document-ids", document_ids);
        set_array(&mut resource, "rlinks", rlinks);
        resource
    }

    /// The subjects of `check`: the SBOM document, then the component the
    /// check is about, defined in `local` on its first reference.
    fn references(
        &self,
        check: &Check<'_>,
        local: &mut LocalComponents,
        uuids: &mut impl UuidSource,
    ) -> Vec<Value> {
        let mut references = vec![json!({
            "subject-uuid": self.document_uuid,
            "type": "resource",
            "title": self.document_title,
        })];
        if let Some(id) = check.component_id {
            let uuid = uuids.subject(&format!("component|{id}"));
            let title = local.title(uuid, || self.component(id, check.label));
            references.push(json!({
                "subject-uuid": uuid,
                "type": "component",
                "title": title,
            }));
        }
        references
    }

    /// The component with canonical id `id`, described from the SBOM when it
    /// is at hand and from the check's `label` otherwise. Its title is markup,
    /// so the name and version in it are escaped; its properties carry them
    /// plain.
    fn component(&self, id: &str, label: Option<&str>) -> ComponentSubject {
        let component = self.components.get(id).copied();
        let version = component.and_then(|c| c.version.as_deref());
        let name = component
            .map(|c| c.name.as_str())
            .or(label)
            .and_then(markup_text)
            .or_else(|| markup_text(id))
            .unwrap_or_else(|| "Unnamed component".to_string());
        let title = match version.and_then(markup_text) {
            Some(version) => format!("{name} {version}"),
            None => name,
        };
        let mut props: Vec<Value> = version
            .and_then(|version| oscal_prop("version", version))
            .into_iter()
            .collect();
        props.extend(prop("component-id", id));
        if let Some(component) = component {
            props.extend(prop(
                "component-type",
                &component.component_type.to_string(),
            ));
        }
        ComponentSubject {
            title,
            oscal_type: component.map_or("software", |c| oscal_component_type(&c.component_type)),
            props,
        }
    }
}

/// The title of the SBOM document's resource, e.g. `acme-app (CycloneDX 1.6
/// SBOM)`. The name and spec version come from the SBOM and are escaped.
fn document_title(sbom: Option<&NormalizedSbom>) -> String {
    let Some(sbom) = sbom else {
        return "Assessed SBOM".to_string();
    };
    let document = &sbom.document;
    let kind = match markup_text(&document.spec_version) {
        Some(spec) => format!("{} {spec} SBOM", document.format),
        None => format!("{} SBOM", document.format),
    };
    match document.name.as_deref().and_then(markup_text) {
        Some(name) => format!("{name} ({kind})"),
        None => kind,
    }
}

/// OSCAL's component `type` for an SBOM component type. The SBOM's own type
/// is kept in the `component-type` property.
const fn oscal_component_type(component_type: &ComponentType) -> &'static str {
    match component_type {
        ComponentType::Service => "service",
        ComponentType::Device => "hardware",
        _ => "software",
    }
}

/// A component as a subject: its local definition and the title its
/// references repeat.
struct ComponentSubject {
    title: String,
    oscal_type: &'static str,
    props: Vec<Value>,
}

impl ComponentSubject {
    fn definition(self, uuid: Uuid) -> Value {
        let mut definition = json!({
            "uuid": uuid,
            "type": self.oscal_type,
            "title": self.title,
            "description": "A component listed in the assessed SBOM.",
            // `status` is required; the SBOM does not say whether the
            // component is operational.
            "status": {
                "state": "other",
                "remarks": "The SBOM does not state the component's operational status."
            },
        });
        set_array(&mut definition, "props", self.props);
        definition
    }
}

/// The components one result's observations name, each defined once, in
/// order of first reference (`local-definitions.components`).
#[derive(Default)]
struct LocalComponents {
    titles: HashMap<Uuid, String>,
    definitions: Vec<Value>,
}

impl LocalComponents {
    /// The title of component `uuid`, defining it from `describe` on first
    /// reference.
    fn title(&mut self, uuid: Uuid, describe: impl FnOnce() -> ComponentSubject) -> String {
        if let Some(title) = self.titles.get(&uuid) {
            return title.clone();
        }
        let subject = describe();
        let title = subject.title.clone();
        self.definitions.push(subject.definition(uuid));
        self.titles.insert(uuid, title.clone());
        title
    }
}

// ---------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------

/// Set `field` to `items` unless there are none: OSCAL arrays hold at least
/// one item.
fn set_array(object: &mut Value, field: &str, items: Vec<Value>) {
    if !items.is_empty() {
        object[field] = Value::Array(items);
    }
}

/// A property in our namespace, or `None` when `value` holds no text.
fn prop(name: &str, value: &str) -> Option<Value> {
    let value = oscal_string(value)?;
    Some(json!({
        "name": name,
        "ns": PROP_NS,
        "value": value
    }))
}

/// A property from OSCAL's own vocabulary (no `ns`), or `None` when `value`
/// holds no text.
fn oscal_prop(name: &str, value: &str) -> Option<Value> {
    let value = oscal_string(value)?;
    Some(json!({ "name": name, "value": value }))
}

/// What a property can say besides its value.
#[derive(Default)]
struct PropDetail<'a> {
    /// A sub-type of the property's name (a token), such as the standard a
    /// reference cites.
    class: Option<&'a str>,
    /// A token that relates properties to each other.
    group: Option<&'a str>,
    /// Commentary, as markup.
    remarks: Option<&'a str>,
}

/// A property in our namespace with `detail`, or `None` when `value` holds
/// no text. A class or group that is no OSCAL token is left out, and so are
/// remarks with no text.
fn prop_with(name: &str, value: &str, detail: PropDetail<'_>) -> Option<Value> {
    let mut prop = prop(name, value)?;
    if let Some(class) = detail.class.filter(|class| is_token(class)) {
        prop["class"] = Value::from(class);
    }
    if let Some(group) = detail.group.filter(|group| is_token(group)) {
        prop["group"] = Value::from(group);
    }
    if let Some(remarks) = detail.remarks.and_then(markup_text) {
        prop["remarks"] = Value::from(remarks);
    }
    Some(prop)
}

/// A link to `href` with the relation `rel` and, when there is one, `text`
/// (escaped, as markup). `None` when `href` is no absolute URI: OSCAL
/// validators check a link's `href` is a URI reference, and a relative one
/// would resolve against the document's own location.
fn link(href: &str, rel: &str, text: Option<&str>) -> Option<Value> {
    if !is_absolute_uri(href) {
        return None;
    }
    let mut link = json!({ "href": href, "rel": rel });
    if let Some(text) = text.and_then(markup_text) {
        link["text"] = Value::from(text);
    }
    Some(link)
}

/// Whether `text` is an OSCAL token (an XML NCName) in ASCII: a letter or
/// `_`, then letters, digits, `.`, `-` and `_`.
fn is_token(text: &str) -> bool {
    let mut chars = text.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// `text` as an OSCAL `string`, or `None` when nothing is left of it.
///
/// OSCAL property values (and the identifiers and versions it types as
/// `string`) must match `^\S(.*\S)?$` read as ECMA-262: no leading or
/// trailing whitespace, and no line terminator anywhere, since `.` stops at
/// each of them. Text taken from the SBOM — component names, labels,
/// versions, identifiers — can hold anything, so line terminators become
/// spaces and surrounding whitespace is trimmed. The result is also a valid
/// `markup-line` (single line, non-empty).
fn oscal_string(text: &str) -> Option<String> {
    let trimmed = text.trim_matches(is_ecma_whitespace);
    (!trimmed.is_empty()).then(|| {
        trimmed
            .chars()
            .map(|c| if is_line_terminator(c) { ' ' } else { c })
            .collect()
    })
}

/// SBOM-derived `text` for an OSCAL markup field (a `markup-line`, or a
/// `markup-multiline` written as one paragraph), or `None` when nothing is
/// left of it.
///
/// OSCAL markup is Markdown that viewers render, so the text goes through
/// [`escape_markdown_inline`] (the S1 rule for human-readable output): it
/// renders as the literal text it is, never as a link, image, HTML tag or
/// emphasis. Line breaks become spaces and surrounding whitespace is trimmed
/// ([`oscal_string`]), so it stays one line and cannot indent into a code
/// block. The inline escaper already covers `#`, `>`, `*`, fences, `|` and
/// `<`; a leading `-`, `+` or ordered-list number (`1.`, `1)`), which opens a
/// list only at the start of a line, is escaped here.
fn markup_text(text: &str) -> Option<String> {
    let mut line = oscal_string(&escape_markdown_inline(text))?;
    if line.starts_with(['-', '+']) {
        line.insert(0, '\\');
    } else if let Some(at) = ordered_list_delimiter(&line) {
        line.insert(at, '\\');
    }
    Some(line)
}

/// The byte offset of the `.` or `)` when `line` opens a CommonMark ordered
/// list item: one to nine digits, the delimiter, then a space, a tab or the
/// end of the line.
fn ordered_list_delimiter(line: &str) -> Option<usize> {
    let digits = line.bytes().take_while(u8::is_ascii_digit).count();
    let rest = &line.as_bytes()[digits..];
    ((1..=9).contains(&digits)
        && matches!(rest.first(), Some(b'.' | b')'))
        && matches!(rest.get(1), None | Some(b' ' | b'\t')))
    .then_some(digits)
}

/// Whether `text` is an absolute URI (RFC 3986): a scheme, a colon, and the
/// rest in URI characters only, such as `urn:uuid:…` or `https://…`.
fn is_absolute_uri(text: &str) -> bool {
    let Some((scheme, rest)) = text.split_once(':') else {
        return false;
    };
    let mut scheme_chars = scheme.chars();
    scheme_chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && scheme_chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        && !rest.is_empty()
        && is_uri_text(text)
}

/// Only RFC 3986 characters (unreserved, reserved, `%XX` escapes), with at
/// most one `#`.
fn is_uri_text(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = |j: usize| bytes.get(j).is_some_and(u8::is_ascii_hexdigit);
            if !(hex(i + 1) && hex(i + 2)) {
                return false;
            }
            i += 3;
        } else if bytes[i].is_ascii_alphanumeric() || b"-._~:/?#[]@!$&'()*+,;=".contains(&bytes[i])
        {
            i += 1;
        } else {
            return false;
        }
    }
    text.matches('#').count() <= 1
}

/// Whether `digest` is a SHA-256 digest in hex.
fn is_sha256_hex(digest: &str) -> bool {
    digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit())
}

/// ECMA-262 `\s` (WhiteSpace and LineTerminator), plus U+0085, which Rust
/// counts as whitespace; trimming it as well is harmless.
fn is_ecma_whitespace(c: char) -> bool {
    c.is_whitespace() || c == '\u{feff}'
}

/// The ECMA-262 LineTerminator code points.
const fn is_line_terminator(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}')
}

#[cfg(test)]
mod tests {
    use super::{AssessedSbom, DerivedUuids, build_assessment_results};
    use crate::model::{Component, DocumentMetadata, NormalizedSbom};
    use crate::quality::{
        ComplianceLevel, ComplianceResult, Violation, ViolationCategory, ViolationSeverity,
    };
    use chrono::{DateTime, TimeZone, Utc};
    use std::borrow::Cow;
    use uuid::Uuid;

    fn violation(message: &str) -> Violation {
        Violation {
            severity: ViolationSeverity::Error,
            category: ViolationCategory::DocumentMetadata,
            message: message.to_string(),
            element: Some("metadata".to_string()),
            requirement: "NTIA minimum elements".to_string(),
            rule_id: "SBOM-NTIA-TIMESTAMP",
            component_id: None,
            counts: None,
            standard_refs: Cow::Borrowed(&[]),
            remediation: None,
            finding_detail: None,
            severity_override: None,
            deadline: None,
            field: None,
            observed: None,
        }
    }

    fn result(violations: Vec<Violation>) -> ComplianceResult {
        ComplianceResult {
            is_compliant: violations.is_empty(),
            level: ComplianceLevel::NtiaMinimum,
            error_count: violations.len(),
            warning_count: 0,
            info_count: 0,
            violations,
            passed: Vec::new(),
            evaluated: Vec::new(),
            conformity_summary: None,
            applicability: crate::quality::Applicability::Applicable,
            elements_checked: 1,
            suppressed: Vec::new(),
            excluded_components: 0,
        }
    }

    fn instant(year: i32, month: u32, day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, 12, 0, 0)
            .single()
            .expect("valid timestamp")
    }

    /// The document for `results` about `sbom` (or, without one, only what
    /// the results say), with UUIDs derived from a fixed digest.
    fn build_for(results: &[ComplianceResult], sbom: Option<&NormalizedSbom>) -> serde_json::Value {
        build_with_digest(results, sbom, "abc123")
    }

    fn build_with_digest(
        results: &[ComplianceResult],
        sbom: Option<&NormalizedSbom>,
        digest: &str,
    ) -> serde_json::Value {
        let timestamp = instant(2026, 7, 1);
        let assessed = sbom.map(|sbom| AssessedSbom::with_sha256(sbom, digest));
        let mut uuids = DerivedUuids::new(results, digest, timestamp);
        let json = build_assessment_results(results, assessed.as_ref(), timestamp, &mut uuids)
            .expect("OSCAL serialization");
        serde_json::from_str(&json).expect("valid JSON")
    }

    /// A SHA-256 digest in hex, as the CLI passes it.
    const SHA256: &str = "be7995c235de8f84244baf2d5cd4a217deb705904ffe2e874647f3e3c0824d96";

    fn build(results: &[ComplianceResult]) -> serde_json::Value {
        build_for(results, None)
    }

    /// An SBOM with one component, `lodash` 4.17.21 (canonical id: its purl).
    fn lodash_sbom() -> NormalizedSbom {
        let document = DocumentMetadata {
            name: Some("acme-app".to_string()),
            spec_version: "1.6".to_string(),
            serial_number: Some("urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79".to_string()),
            ..DocumentMetadata::default()
        };
        let mut sbom = NormalizedSbom::new(document);
        sbom.add_component(
            Component::new("lodash".to_string(), "lodash-ref".to_string())
                .with_version("4.17.21".to_string())
                .with_purl("pkg:npm/lodash@4.17.21".to_string()),
        );
        sbom
    }

    /// A component-scoped violation about the component with canonical id
    /// `component_id`, labelled `label`.
    fn component_violation(rule_id: &'static str, component_id: &str, label: &str) -> Violation {
        let mut v = violation(&format!("Component '{label}' fails {rule_id}"));
        v.rule_id = rule_id;
        v.component_id = Some(component_id.to_string());
        v.element = Some(label.to_string());
        v
    }

    fn subjects(observation: &serde_json::Value) -> &[serde_json::Value] {
        observation["subjects"]
            .as_array()
            .map_or(&[], Vec::as_slice)
    }

    fn prop_value<'a>(entry: &'a serde_json::Value, name: &str) -> Option<&'a str> {
        entry["props"]
            .as_array()?
            .iter()
            .find(|p| p["name"] == name)?["value"]
            .as_str()
    }

    #[test]
    fn compliant_result_still_gets_an_entry_with_satisfied_rollup() {
        let document = build(&[result(Vec::new())]);
        let assessment = &document["assessment-results"]["results"][0];
        assert!(
            assessment["title"]
                .as_str()
                .expect("title")
                .contains("NTIA Minimum Elements"),
            "per-standard entry must carry the standard name in its title"
        );
        assert_eq!(prop_value(assessment, "standard"), Some("ntia"));
        assert_eq!(prop_value(assessment, "is-compliant"), Some("true"));
        assert_eq!(prop_value(assessment, "applicability"), Some("applicable"));
        assert_eq!(prop_value(assessment, "error-count"), Some("0"));
        assert_eq!(prop_value(assessment, "score"), Some("100"));
        assert!(assessment.get("observations").is_none());
        let findings = assessment["findings"].as_array().expect("findings");
        assert_eq!(findings.len(), 1, "clean run keeps only the roll-up");
        assert_eq!(findings[0]["target"]["status"]["state"], "satisfied");
    }

    #[test]
    fn single_finding_links_to_its_observation() {
        let document = build(&[result(vec![violation("missing metadata")])]);
        let assessment = &document["assessment-results"]["results"][0];
        assert_eq!(assessment["observations"].as_array().map(Vec::len), Some(1));
        // Roll-up (not-satisfied) + one violation finding.
        let findings = assessment["findings"].as_array().expect("findings");
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0]["target"]["status"]["state"], "not-satisfied");
        assert_eq!(
            findings[1]["related-observations"][0]["observation-uuid"],
            assessment["observations"][0]["uuid"]
        );
        assert_eq!(prop_value(assessment, "is-compliant"), Some("false"));
    }

    #[test]
    fn multiple_findings_are_emitted_in_input_order() {
        let document = build(&[result(vec![violation("first"), violation("second")])]);
        let assessment = &document["assessment-results"]["results"][0];
        assert_eq!(assessment["observations"].as_array().map(Vec::len), Some(2));
        // findings[0] is the roll-up; violations follow in input order.
        assert_eq!(assessment["findings"][1]["description"], "first");
        assert_eq!(assessment["findings"][2]["description"], "second");
        assert_eq!(
            document["assessment-results"]["metadata"]["last-modified"],
            "2026-07-01T12:00:00Z"
        );
    }

    #[test]
    fn each_standard_gets_its_own_result_entry() {
        let ntia = result(vec![violation("missing metadata")]);
        let mut cra = result(Vec::new());
        cra.level = ComplianceLevel::CraPhase2;
        let document = build(&[ntia, cra]);
        let entries = document["assessment-results"]["results"]
            .as_array()
            .expect("results");
        assert_eq!(entries.len(), 2, "one results[] entry per standard");
        assert_eq!(prop_value(&entries[0], "standard"), Some("ntia"));
        assert_eq!(prop_value(&entries[0], "is-compliant"), Some("false"));
        assert_eq!(prop_value(&entries[1], "standard"), Some("cra"));
        assert_eq!(prop_value(&entries[1], "is-compliant"), Some("true"));
        assert!(
            entries[1]["title"]
                .as_str()
                .expect("title")
                .contains("EU CRA Phase 2"),
        );
    }

    /// The not-applicable reason of the N/A results below.
    const NA_REASON: &str = "[AI-Act] Not applicable: no ML components";

    #[test]
    fn not_applicable_standard_carries_na_verdict_and_no_rollup() {
        let na = ComplianceResult::not_applicable(ComplianceLevel::EuAiAct, NA_REASON);
        assert!(!na.is_applicable());
        let document = build(&[na]);
        let assessment = &document["assessment-results"]["results"][0];
        assert_eq!(
            prop_value(assessment, "applicability"),
            Some("not-applicable")
        );
        assert_eq!(
            prop_value(assessment, "not-applicable-reason"),
            Some(NA_REASON)
        );
        assert!(
            prop_value(assessment, "score").is_none(),
            "an unevaluated standard has no score"
        );
        assert!(
            assessment.get("findings").is_none(),
            "an unevaluated standard gets no roll-up and no finding"
        );
        assert!(
            assessment.get("observations").is_none(),
            "an unevaluated standard gets no observation"
        );
    }

    #[test]
    fn not_applicable_standard_still_renders_its_violations() {
        // Should a checker ever attach a real violation to an N/A result,
        // it keeps the observation + not-satisfied finding behavior; only
        // the roll-up is withheld.
        let mut na =
            ComplianceResult::new(ComplianceLevel::EuAiAct, vec![violation("genuine finding")]);
        na.applicability = crate::quality::Applicability::NotApplicable(NA_REASON.to_string());
        let document = build(&[na]);
        let assessment = &document["assessment-results"]["results"][0];
        assert_eq!(
            prop_value(assessment, "applicability"),
            Some("not-applicable")
        );
        let findings = assessment["findings"].as_array().expect("findings");
        assert_eq!(findings.len(), 1, "no roll-up, the violation kept");
        assert_eq!(findings[0]["description"], "genuine finding");
        assert_eq!(findings[0]["target"]["status"]["state"], "not-satisfied");
        assert_eq!(assessment["observations"].as_array().map(Vec::len), Some(1));
    }

    #[test]
    fn observations_carry_rule_identity() {
        let document = build(&[result(vec![violation("missing timestamp")])]);
        let assessment = &document["assessment-results"]["results"][0];
        let obs = &assessment["observations"][0];
        assert_eq!(prop_value(obs, "rule-id"), Some("SBOM-NTIA-TIMESTAMP"));
        assert_eq!(
            prop_value(obs, "sarif-rule-id"),
            Some("SBOM-NTIA-TIMESTAMP")
        );
    }

    /// A finding carries what identifies and resolves it, its observation
    /// how the check classified it and what it read, as `reports::audit`
    /// places each field.
    #[test]
    fn audit_fields_land_on_the_finding_and_its_observation() {
        let mut v = component_violation("SBOM-NTIA-SUPPLIER", "pkg:npm/lodash@4.17.21", "lodash");
        v.standard_refs = v.registry_standard_refs().into();
        v.field = Some("components[].supplier.name".into());
        v.observed = Some("NOASSERTION".to_string());
        let key = crate::quality::finding_key(ComplianceLevel::NtiaMinimum, &v);
        let document = build(&[result(vec![v])]);
        let entry = &document["assessment-results"]["results"][0];
        let finding = &entry["findings"][1];
        assert_eq!(prop_value(finding, "finding-key"), Some(key.as_str()));
        assert_eq!(
            prop_value(finding, "finding-id"),
            Some(crate::quality::finding_id(&key).as_str())
        );
        assert_eq!(
            finding["links"],
            serde_json::json!([{
                "href": "https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom",
                "rel": "help"
            }])
        );
        assert!(
            finding["remarks"]
                .as_str()
                .is_some_and(|r| r.starts_with("Name the supplier of every component")),
            "the remediation: {finding}"
        );
        assert_eq!(prop_value(finding, "severity"), None, "on the observation");

        let observation = &entry["observations"][0];
        for (name, value) in [
            ("severity", "error"),
            ("requirement", "NTIA minimum elements"),
            ("rule-id", "SBOM-NTIA-SUPPLIER"),
            ("component-id", "pkg:npm/lodash@4.17.21"),
            ("field", "components[].supplier.name"),
            ("observed", "NOASSERTION"),
        ] {
            assert_eq!(prop_value(observation, name), Some(value), "{name}");
        }
        let reference = observation["props"]
            .as_array()
            .expect("props")
            .iter()
            .find(|p| p["name"] == "standard-ref")
            .expect("a reference");
        assert_eq!(reference["class"], "NtiaMinimum");
        assert_eq!(reference["value"], "NTIA Minimum Elements");
        assert_eq!(observation["links"][0]["rel"], "reference");
        assert_eq!(observation["links"][0]["text"], "NTIA Minimum Elements");
        assert!(observation.get("remarks").is_none());
    }

    #[test]
    fn document_declares_oscal_1_2_3_and_discovery_observations() {
        let document = build(&[result(vec![violation("missing timestamp")])]);
        assert_eq!(
            document["assessment-results"]["metadata"]["oscal-version"],
            "1.2.3"
        );
        // OSCAL 1.2.0 deprecated the `finding` observation type in favour
        // of `discovery`.
        assert_eq!(
            document["assessment-results"]["results"][0]["observations"][0]["types"],
            serde_json::json!(["discovery"])
        );
    }

    #[test]
    fn sbom_text_is_normalized_to_an_oscal_string() {
        use super::oscal_string;
        assert_eq!(oscal_string("lodash").as_deref(), Some("lodash"));
        assert_eq!(oscal_string(" lodash\n").as_deref(), Some("lodash"));
        assert_eq!(oscal_string("two\nlines").as_deref(), Some("two lines"));
        assert_eq!(
            oscal_string("a\r\u{2028}\u{2029}b").as_deref(),
            Some("a   b"),
            "every ECMA line terminator becomes a space"
        );
        assert_eq!(oscal_string("tab\tinside").as_deref(), Some("tab\tinside"));
        assert_eq!(oscal_string("\u{feff}bom\u{feff}").as_deref(), Some("bom"));
        for empty in ["", " ", "\n\t", "\u{feff}", "\u{2028}"] {
            assert_eq!(oscal_string(empty), None, "{empty:?}");
        }
    }

    #[test]
    fn a_label_with_no_text_leaves_out_the_property() {
        let mut blank = violation("blank label");
        blank.element = Some(" \n ".to_string());
        let document = build(&[result(vec![blank])]);
        let obs = &document["assessment-results"]["results"][0]["observations"][0];
        assert_eq!(prop_value(obs, "sbom-element"), None);
        assert_eq!(prop_value(obs, "rule-id"), Some("SBOM-NTIA-TIMESTAMP"));
    }

    #[test]
    fn finding_status_state_is_valid_oscal_token_for_every_severity() {
        // OSCAL's finding-target status `state` is a CLOSED enum:
        // only "satisfied" / "not-satisfied" (no allow-other). Every violation
        // is a non-satisfied objective regardless of severity. This guards the
        // Info/Warning branches that the other tests (Error-only) never reach.
        let with_severity = |message: &str, severity: ViolationSeverity| Violation {
            severity,
            category: ViolationCategory::DocumentMetadata,
            message: message.to_string(),
            element: Some("metadata".to_string()),
            requirement: "NTIA minimum elements".to_string(),
            rule_id: "SBOM-NTIA-TIMESTAMP",
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
        let document = build(&[result(vec![
            with_severity("info finding", ViolationSeverity::Info),
            with_severity("warning finding", ViolationSeverity::Warning),
            with_severity("error finding", ViolationSeverity::Error),
        ])]);
        let findings = document["assessment-results"]["results"][0]["findings"]
            .as_array()
            .expect("findings array");
        // Roll-up + three violation findings.
        assert_eq!(findings.len(), 4);
        for finding in findings.iter().skip(1) {
            assert_eq!(finding["target"]["status"]["state"], "not-satisfied");
        }
    }

    #[test]
    fn pinned_instant_makes_the_document_byte_identical() {
        use super::generate_assessment_results_at;
        let as_of = Utc
            .with_ymd_and_hms(2026, 10, 12, 0, 0, 0)
            .single()
            .expect("valid timestamp");
        let sbom = lodash_sbom();
        let results = [result(vec![
            violation("missing timestamp"),
            component_violation("SBOM-NTIA-SUPPLIER", "pkg:npm/lodash@4.17.21", "lodash"),
        ])];
        let assessed = AssessedSbom::with_sha256(&sbom, "abc123");
        let first = generate_assessment_results_at(&results, &assessed, as_of)
            .expect("OSCAL serialization");
        let second = generate_assessment_results_at(&results, &assessed, as_of)
            .expect("OSCAL serialization");
        assert_eq!(
            first, second,
            "same SBOM and instant must give the same bytes"
        );

        let document: serde_json::Value = serde_json::from_str(&first).expect("valid JSON");
        assert_eq!(
            document["assessment-results"]["metadata"]["last-modified"], "2026-10-12T00:00:00Z",
            "the timestamp must come from as_of, not the wall clock"
        );
        let uuid = document["assessment-results"]["uuid"]
            .as_str()
            .expect("document uuid");
        let parsed = Uuid::parse_str(uuid).expect("valid UUID");
        // OSCAL's uuid datatype accepts only RFC 4122 version 4 or 5.
        assert_eq!(parsed.get_version_num(), 5, "document UUID version");

        let other_sbom = generate_assessment_results_at(
            &results,
            &AssessedSbom::with_sha256(&sbom, "def456"),
            as_of,
        )
        .expect("OSCAL serialization");
        let other: serde_json::Value = serde_json::from_str(&other_sbom).expect("valid JSON");
        assert_ne!(
            document["assessment-results"]["uuid"], other["assessment-results"]["uuid"],
            "a different SBOM must not reuse UUIDs"
        );
        let subject_uuids = |document: &serde_json::Value| -> Vec<serde_json::Value> {
            subjects(&document["assessment-results"]["results"][0]["observations"][1])
                .iter()
                .map(|s| s["subject-uuid"].clone())
                .collect()
        };
        assert_ne!(
            subject_uuids(&document),
            subject_uuids(&other),
            "a different SBOM must not reuse subject UUIDs either"
        );
    }

    #[test]
    fn every_observation_names_the_sbom_document_described_in_back_matter() {
        let sbom = lodash_sbom();
        let document = build_for(
            &[result(vec![
                violation("missing timestamp"),
                component_violation("SBOM-NTIA-SUPPLIER", "pkg:npm/lodash@4.17.21", "lodash"),
            ])],
            Some(&sbom),
        );
        let resources = document["assessment-results"]["back-matter"]["resources"]
            .as_array()
            .expect("back-matter resources");
        assert_eq!(resources.len(), 1, "one resource: the SBOM document");
        let resource = &resources[0];
        assert_eq!(resource["title"], "acme-app (CycloneDX 1.6 SBOM)");
        // OSCAL's own resource vocabulary: an artifact an assessor reviews.
        assert!(
            resource["props"]
                .as_array()
                .expect("props")
                .iter()
                .any(|p| p["name"] == "type" && p["value"] == "artifact" && p.get("ns").is_none())
        );
        assert_eq!(prop_value(resource, "sha256"), Some("abc123"));
        assert_eq!(prop_value(resource, "format"), Some("CycloneDX"));
        assert_eq!(prop_value(resource, "spec-version"), Some("1.6"));
        assert_eq!(
            resource["document-ids"][0]["identifier"],
            "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"
        );

        let observations = document["assessment-results"]["results"][0]["observations"]
            .as_array()
            .expect("observations");
        for observation in observations {
            let first = &subjects(observation)[0];
            assert_eq!(first["type"], "resource");
            assert_eq!(first["subject-uuid"], resource["uuid"]);
            assert_eq!(first["title"], resource["title"]);
        }
        assert_eq!(
            subjects(&observations[0]).len(),
            1,
            "a document finding names only the document"
        );
    }

    #[test]
    fn a_component_finding_names_the_component_defined_in_local_definitions() {
        let sbom = lodash_sbom();
        let document = build_for(
            &[result(vec![component_violation(
                "SBOM-NTIA-SUPPLIER",
                "pkg:npm/lodash@4.17.21",
                "a label, not the name",
            )])],
            Some(&sbom),
        );
        let entry = &document["assessment-results"]["results"][0];
        let components = entry["local-definitions"]["components"]
            .as_array()
            .expect("local components");
        assert_eq!(components.len(), 1);
        let component = &components[0];
        assert_eq!(component["type"], "software");
        assert_eq!(
            component["title"], "lodash 4.17.21",
            "the SBOM's name and version, not the finding's label"
        );
        assert_eq!(component["status"]["state"], "other");
        assert_eq!(
            prop_value(component, "component-id"),
            Some("pkg:npm/lodash@4.17.21")
        );
        assert_eq!(prop_value(component, "component-type"), Some("library"));
        let version = component["props"]
            .as_array()
            .expect("props")
            .iter()
            .find(|p| p["name"] == "version")
            .expect("OSCAL version prop");
        assert_eq!(version["value"], "4.17.21");
        assert!(version.get("ns").is_none(), "`version` is OSCAL's own prop");

        let subject = &subjects(&entry["observations"][0])[1];
        assert_eq!(subject["type"], "component");
        assert_eq!(subject["subject-uuid"], component["uuid"]);
        assert_eq!(subject["title"], "lodash 4.17.21");
    }

    #[test]
    fn a_component_is_defined_once_per_result_with_one_uuid_across_results() {
        let sbom = lodash_sbom();
        let id = "pkg:npm/lodash@4.17.21";
        let ntia = result(vec![
            component_violation("SBOM-NTIA-SUPPLIER", id, "lodash"),
            component_violation("SBOM-NTIA-VERSION", id, "lodash"),
        ]);
        let mut cra = result(vec![component_violation("SBOM-CRA-GENERAL", id, "lodash")]);
        cra.level = ComplianceLevel::CraPhase2;
        let document = build_for(&[ntia, cra], Some(&sbom));
        let entries = document["assessment-results"]["results"]
            .as_array()
            .expect("results");
        let definitions = |entry: &serde_json::Value| -> Vec<serde_json::Value> {
            entry["local-definitions"]["components"]
                .as_array()
                .expect("local components")
                .iter()
                .map(|c| c["uuid"].clone())
                .collect()
        };
        assert_eq!(
            definitions(&entries[0]).len(),
            1,
            "defined once, named twice"
        );
        assert_eq!(
            definitions(&entries[0]),
            definitions(&entries[1]),
            "the same component keeps its UUID in every result"
        );
        for observation in entries[0]["observations"].as_array().expect("observations") {
            assert_eq!(
                subjects(observation)[1]["subject-uuid"],
                definitions(&entries[0])[0]
            );
        }
    }

    #[test]
    fn subject_uuids_do_not_depend_on_the_instant_or_the_standards() {
        use super::generate_assessment_results_at;
        let sbom = lodash_sbom();
        let id = "pkg:npm/lodash@4.17.21";
        let ntia = result(vec![component_violation(
            "SBOM-NTIA-SUPPLIER",
            id,
            "lodash",
        )]);
        let mut cra = ntia.clone();
        cra.level = ComplianceLevel::CraPhase2;
        let assessed = AssessedSbom::with_sha256(&sbom, "abc123");
        let render = |results: &[ComplianceResult], as_of| -> serde_json::Value {
            let text = generate_assessment_results_at(results, &assessed, as_of)
                .expect("OSCAL serialization");
            serde_json::from_str(&text).expect("valid JSON")
        };
        let first = render(std::slice::from_ref(&ntia), instant(2026, 10, 12));
        let later = render(&[cra, ntia], instant(2027, 1, 15));
        let subject_uuids = |document: &serde_json::Value| -> Vec<serde_json::Value> {
            subjects(&document["assessment-results"]["results"][0]["observations"][0])
                .iter()
                .map(|s| s["subject-uuid"].clone())
                .collect()
        };
        assert_eq!(
            subject_uuids(&first),
            subject_uuids(&later),
            "the SBOM document and its component keep their UUIDs"
        );
        assert_ne!(
            first["assessment-results"]["uuid"], later["assessment-results"]["uuid"],
            "the assessment does not"
        );
    }

    #[test]
    fn without_the_sbom_a_component_is_titled_by_its_label() {
        let document = build(&[result(vec![component_violation(
            "SBOM-NTIA-SUPPLIER",
            "pkg:npm/lodash@4.17.21",
            "lodash",
        )])]);
        let entry = &document["assessment-results"]["results"][0];
        let component = &entry["local-definitions"]["components"][0];
        assert_eq!(component["title"], "lodash");
        assert_eq!(
            prop_value(component, "component-id"),
            Some("pkg:npm/lodash@4.17.21")
        );
        assert_eq!(
            document["assessment-results"]["back-matter"]["resources"][0]["title"],
            "Assessed SBOM"
        );
    }

    /// A check the SBOM passed takes the violation's path with a met
    /// objective: a satisfied finding over a control-objective observation
    /// that names the same subjects.
    #[test]
    fn a_passed_check_is_a_satisfied_control_objective() {
        use super::{Check, LocalComponents, Objective, Subjects, finding, observation};
        let sbom = lodash_sbom();
        let mut uuids = DerivedUuids::new(&[], "abc123", instant(2026, 7, 1));
        let assessed = AssessedSbom::with_sha256(&sbom, "abc123");
        let subjects_index = Subjects::new(Some(&assessed), &mut uuids);
        let check = Check {
            rule_id: "SBOM-NTIA-SUPPLIER",
            message: "Component 'lodash' names its supplier",
            objective: Objective::Satisfied,
            component_id: Some("pkg:npm/lodash@4.17.21"),
            label: Some("lodash"),
            fields: Vec::new(),
        };
        let mut local = LocalComponents::default();
        let named = subjects_index.references(&check, &mut local, &mut uuids);
        let judged = finding(&check, Uuid::from_u128(1), Uuid::from_u128(2));
        let observed = observation(check, Uuid::from_u128(1), "2026-07-01T12:00:00Z", named);
        assert_eq!(judged["target"]["status"]["state"], "satisfied");
        assert_eq!(observed["types"], serde_json::json!(["control-objective"]));
        assert_eq!(subjects(&observed).len(), 2, "document and component");
        assert_eq!(local.definitions.len(), 1);
        assert!(observed.get("props").is_none(), "no props, no empty array");
    }

    /// A result's passed checks become satisfied findings over
    /// control-objective observations, after its violations; the roll-up
    /// names them and the result counts them.
    #[test]
    fn passed_checks_become_satisfied_findings_after_the_violations() {
        use crate::quality::PassedCheck;
        let pass = PassedCheck {
            rule_id: "SBOM-PQC-009",
            message: "'ML-KEM-1024' uses NIST-approved PQC algorithm (FIPS 203/204/205)"
                .to_string(),
            element: Some("ML-KEM-1024".to_string()),
            component_id: Some("crypto/algorithm/ml-kem-1024".to_string()),
            finding_detail: None,
            requirement: "FIPS 203/204/205: approved".to_string(),
            standard_refs: Cow::Borrowed(&[]),
        };
        let mut checked = result(vec![violation("timestamp missing")]).with_passed(vec![pass]);
        checked.level = ComplianceLevel::NistPqc;
        let document = build(&[checked]);
        let assessment = &document["assessment-results"]["results"][0];
        assert_eq!(prop_value(assessment, "passed-count"), Some("1"));
        assert_eq!(prop_value(assessment, "info-count"), Some("0"));

        let findings = assessment["findings"].as_array().expect("findings");
        assert_eq!(findings.len(), 3, "roll-up, the violation, the pass");
        assert!(
            findings[0]["description"]
                .as_str()
                .is_some_and(|d| d.ends_with("1 check(s) passed.")),
            "{}",
            findings[0]["description"]
        );
        assert_eq!(findings[1]["target"]["status"]["state"], "not-satisfied");
        assert_eq!(findings[2]["target"]["status"]["state"], "satisfied");
        assert_eq!(findings[2]["target"]["target-id"], "sbom-pqc-009");

        let observations = assessment["observations"].as_array().expect("observations");
        assert_eq!(observations.len(), 2);
        assert_eq!(observations[0]["types"], serde_json::json!(["discovery"]));
        let passed = &observations[1];
        assert_eq!(passed["types"], serde_json::json!(["control-objective"]));
        assert_eq!(
            findings[2]["related-observations"][0]["observation-uuid"],
            passed["uuid"]
        );
        assert_eq!(prop_value(passed, "rule-id"), Some("SBOM-PQC-009"));
        assert_eq!(prop_value(passed, "sarif-rule-id"), Some("SBOM-PQC-009"));
        assert_eq!(
            prop_value(passed, "requirement"),
            Some("FIPS 203/204/205: approved")
        );
        assert_eq!(prop_value(passed, "sbom-element"), Some("ML-KEM-1024"));
        assert!(prop_value(passed, "severity").is_none(), "a pass has none");
        assert_eq!(subjects(passed).len(), 2, "document and component");
    }

    #[test]
    fn markup_text_escapes_sbom_text_for_oscal_markup() {
        use super::markup_text;
        let cases = [
            ("lodash", "lodash"),
            ("my_app", "my\\_app"),
            (
                "<img src=x onerror=alert(1)>",
                "\\<img src=x onerror=alert(1)\\>",
            ),
            (
                "<script>alert(1)</script>",
                "\\<script\\>alert(1)\\</script\\>",
            ),
            ("[x](javascript:alert(1))", "\\[x\\](javascript:alert(1))"),
            // A backslash cannot cancel the escape after it.
            ("\\<img src=x>", "\\\\\\<img src=x\\>"),
            // Block markers at the start of the field.
            ("# Forged", "\\# Forged"),
            ("- item", "\\- item"),
            ("+ item", "\\+ item"),
            ("* item", "\\* item"),
            ("> quote", "\\> quote"),
            ("1. item", "1\\. item"),
            ("12) item", "12\\) item"),
            ("7.", "7\\."),
            ("  - indented\n", "\\- indented"),
            // Not list markers: left alone.
            ("1.0.2", "1.0.2"),
            ("2024 release", "2024 release"),
            ("a - b", "a - b"),
            // One line, trimmed; a leading colon cannot start a CI command.
            (" two\nlines ", "two lines"),
            ("::warning::x", "\\::warning::x"),
        ];
        for (text, expected) in cases {
            assert_eq!(markup_text(text).as_deref(), Some(expected), "{text:?}");
        }
        for empty in ["", " \n ", "\u{202E}", "\u{1b}"] {
            assert_eq!(markup_text(empty), None, "{empty:?}");
        }
    }

    #[test]
    fn descriptions_escape_the_message_and_props_stay_plain() {
        let mut hostile = component_violation(
            "SBOM-NTIA-SUPPLIER",
            "pkg:npm/x@1",
            "<img src=x onerror=alert(1)>",
        );
        hostile.message = "Component '<img src=x onerror=alert(1)>' missing supplier".to_string();
        let document = build(&[result(vec![hostile])]);
        let entry = &document["assessment-results"]["results"][0];
        let escaped = "Component '\\<img src=x onerror=alert(1)\\>' missing supplier";
        assert_eq!(entry["observations"][0]["description"], escaped);
        assert_eq!(entry["findings"][1]["description"], escaped);
        assert_eq!(
            prop_value(&entry["observations"][0], "sbom-element"),
            Some("<img src=x onerror=alert(1)>"),
            "a property is a plain string, not markup"
        );
        assert_eq!(
            entry["local-definitions"]["components"][0]["title"],
            "\\<img src=x onerror=alert(1)\\>"
        );
    }

    #[test]
    fn titles_escape_the_sbom_name_and_version() {
        let document_metadata = DocumentMetadata {
            name: Some("- <b>acme</b>".to_string()),
            spec_version: "1.6".to_string(),
            ..DocumentMetadata::default()
        };
        let mut sbom = NormalizedSbom::new(document_metadata);
        sbom.add_component(
            Component::new("# evil_lib".to_string(), "evil-ref".to_string())
                .with_version("*1*".to_string())
                .with_purl("pkg:npm/evil@1".to_string()),
        );
        let document = build_for(
            &[result(vec![component_violation(
                "SBOM-NTIA-SUPPLIER",
                "pkg:npm/evil@1",
                "# evil_lib",
            )])],
            Some(&sbom),
        );
        let ar = &document["assessment-results"];
        let resource = &ar["back-matter"]["resources"][0];
        assert_eq!(
            resource["title"],
            "\\- \\<b\\>acme\\</b\\> (CycloneDX 1.6 SBOM)"
        );
        let component = &ar["results"][0]["local-definitions"]["components"][0];
        assert_eq!(component["title"], "\\# evil\\_lib \\*1\\*");
        let version = component["props"]
            .as_array()
            .expect("props")
            .iter()
            .find(|p| p["name"] == "version")
            .expect("version prop");
        assert_eq!(version["value"], "*1*", "a property is a plain string");
        let named = &subjects(&ar["results"][0]["observations"][0]);
        assert_eq!(named[0]["title"], resource["title"]);
        assert_eq!(named[1]["title"], component["title"]);
    }

    #[test]
    fn a_uri_serial_number_is_the_resources_rlink_with_its_sha256() {
        let sbom = lodash_sbom();
        let document = build_with_digest(&[result(Vec::new())], Some(&sbom), SHA256);
        let resource = &document["assessment-results"]["back-matter"]["resources"][0];
        assert_eq!(
            resource["rlinks"],
            serde_json::json!([{
                "href": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
                "hashes": [{ "algorithm": "SHA-256", "value": SHA256 }]
            }])
        );
        assert_eq!(
            resource["document-ids"][0]["identifier"],
            "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"
        );

        // A digest that is not SHA-256 hex is not claimed as one.
        let unhashed = build_with_digest(&[result(Vec::new())], Some(&sbom), "abc123");
        let rlink = &unhashed["assessment-results"]["back-matter"]["resources"][0]["rlinks"][0];
        assert_eq!(
            rlink["href"],
            "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"
        );
        assert!(rlink.get("hashes").is_none());
    }

    #[test]
    fn a_serial_number_that_is_no_uri_gets_no_rlink() {
        use super::is_absolute_uri;
        for (serial, linked) in [
            ("urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79", true),
            ("https://spdx.org/spdxdocs/acme-1.0", true),
            ("ACME-0001", false),
            ("1urn:x", false),
            ("urn:", false),
            ("https://example.com/a b", false),
            ("https://example.com/a#b#c", false),
        ] {
            assert_eq!(is_absolute_uri(serial), linked, "{serial:?}");
        }
        let mut sbom = lodash_sbom();
        sbom.document.serial_number = Some("ACME-0001".to_string());
        let document = build_with_digest(&[result(Vec::new())], Some(&sbom), SHA256);
        let resource = &document["assessment-results"]["back-matter"]["resources"][0];
        assert!(resource.get("rlinks").is_none());
        assert_eq!(resource["document-ids"][0]["identifier"], "ACME-0001");

        sbom.document.serial_number = None;
        let document = build_with_digest(&[result(Vec::new())], Some(&sbom), SHA256);
        let resource = &document["assessment-results"]["back-matter"]["resources"][0];
        assert!(resource.get("rlinks").is_none());
        assert!(resource.get("document-ids").is_none());
    }
}
