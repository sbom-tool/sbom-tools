//! The evidence layer: what a compliance run knows about the SBOM, derived
//! once and read by every level of the run.
//!
//! Each standard used to derive the facts it judges with predicates of its
//! own (whether a component is judged as a package, whether its version or
//! producer is known, which of its hashes count), and two standards could
//! then disagree about one field. Here a fact is defined once. An
//! [`SbomEvidence`] holds the facts of one SBOM at one evaluation instant:
//! [`ComplianceRunConfig::check_levels`](super::ComplianceRunConfig::check_levels)
//! builds one per run and every level borrows it, and
//! [`ComplianceChecker::check`](super::ComplianceChecker::check) builds its
//! own.
//!
//! The evidence depends on the SBOM and the evaluation instant only. What a
//! level adds (the CRA sidecar, the product class, the PQC inputs, the rule
//! settings, whether the package rules judge components whose scope is
//! excluded) stays on the checker, and the
//! [`ComplianceContext`](super::context::ComplianceContext) combines the
//! two. So the levels of one run can share one evidence value.
//!
//! Nothing is derived up front: [`SbomEvidence::new`] only stores its
//! inputs. A fact that tests a field or two (the package scope, the
//! identifier kinds, the name test) is computed on access, through a
//! [`ComponentView`]. A fact that classifies text or scans a list is a lazy
//! group: computed the first time a check reads it, once per evidence, in
//! inventory order. A run pays only for the facts its levels read.
//!
//! Facts are what a verdict is decided on: states, flags, positions and
//! counts, and the SBOM's own values, borrowed as read. A check writes a
//! finding's message and `observed` value from those values, as it did
//! when it read the SBOM itself.
//!
//! Where a fact has a predicate in [`super::shared`] that checks which do
//! not read the evidence yet still call, the fact calls that predicate, so
//! the two cannot drift. The agreement tests (`tests.rs`) compare every fact
//! with the predicates it replaces on every SBOM fixture.
//!
//! A checker that reads the evidence reaches the SBOM itself only through
//! [`SbomEvidence::raw_sbom`], each use marked `// escape hatch:` with the
//! reason (`tests/evidence_layer_lint.rs` lists the files that read the
//! evidence and enforces it).

// Temporary: the CRA facts are read by their tests until the CRA checks
// read them (the next commit).
#![cfg_attr(not(test), allow(dead_code))]

mod component;
mod document;
mod graph;
mod manufacturer;
mod scope;
mod vulns;

#[cfg(test)]
mod tests;

use std::sync::OnceLock;

use chrono::{DateTime, Utc};

use super::shared::{ValueState, known_component_name, value_state};
use crate::model::{
    CanonicalId, Component, ComponentType, DependencyScope, DuplicateComponent, EolStatus,
    ExternalRefType, NormalizedSbom,
};

pub(crate) use component::{HashFacts, Hashes, IdKinds, Licenses, Producer};
pub(crate) use document::DocumentFacts;
pub(crate) use graph::GraphFacts;
pub(crate) use manufacturer::ManufacturerFacts;
pub(crate) use vulns::VulnFact;

/// What a field says about a required element, with the value when it is a
/// real one. The states are those of [`ValueState`]: a real value, an
/// explicit sentinel such as `NOASSERTION` (the author states the value is
/// unknown), or nothing usable (absent, empty, or a placeholder such as
/// `TBD`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Known<T> {
    /// A real value.
    Value(T),
    /// An explicit sentinel: the author states the value is unknown.
    DeclaredUnknown,
    /// Absent, empty, or a placeholder.
    Missing,
}

impl<T> Known<T> {
    /// The value, when it is a real one.
    pub(crate) fn known(self) -> Option<T> {
        match self {
            Self::Value(value) => Some(value),
            Self::DeclaredUnknown | Self::Missing => None,
        }
    }
}

/// A text field as the SBOM wrote it, and what it says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Text<'a> {
    /// The value as read, untrimmed: a finding's `observed` value and its
    /// message quote this.
    pub(crate) raw: Option<&'a str>,
    /// What the value says; a real value is held trimmed, as
    /// [`super::shared::known_value`] returns it.
    pub(crate) value: Known<&'a str>,
}

impl<'a> Text<'a> {
    /// `raw` classified as [`value_state`] classifies it.
    pub(crate) fn of(raw: Option<&'a str>) -> Self {
        Self::with_state(raw, value_state(raw))
    }

    /// `raw` with the state already classified (a cached column).
    fn with_state(raw: Option<&'a str>, state: ValueState) -> Self {
        let value = match state {
            ValueState::Known => Known::Value(raw.unwrap_or_default().trim()),
            ValueState::DeclaredUnknown => Known::DeclaredUnknown,
            ValueState::Missing => Known::Missing,
        };
        Self { raw, value }
    }

    /// Whether the field holds a real value.
    pub(crate) fn is_known(&self) -> bool {
        self.value.known().is_some()
    }
}

/// A component's position in the inventory (`NormalizedSbom::components`,
/// an `IndexMap`): every per-component fact is kept in that order, so a
/// walk over the evidence visits the components in the order a walk over
/// the SBOM does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ComponentIx(usize);

/// The facts of one SBOM at one evaluation instant, derived once and shared
/// by every level of a run (see the module docs).
pub(crate) struct SbomEvidence<'a> {
    sbom: &'a NormalizedSbom,
    as_of: DateTime<Utc>,
    document: OnceLock<DocumentFacts<'a>>,
    versions: OnceLock<Box<[ValueState]>>,
    producers: OnceLock<Box<[ValueState]>>,
    licenses: OnceLock<Box<[ValueState]>>,
    hashes: OnceLock<Box<[HashFacts]>>,
    /// The number of components the package rules judge, by whether the
    /// run judges components whose scope is excluded (`[false, true]`).
    package_counts: [OnceLock<usize>; 2],
    graph: OnceLock<GraphFacts>,
    cycle_count: OnceLock<usize>,
    lifecycle_property: OnceLock<bool>,
    manufacturer: OnceLock<ManufacturerFacts<'a>>,
    vulnerabilities: OnceLock<Box<[VulnFact<'a>]>>,
    duplicates: OnceLock<Box<[&'a DuplicateComponent]>>,
    vulnerability_assertion: OnceLock<bool>,
    direct_dependencies: OnceLock<Box<[bool]>>,
    firmware_dependencies: OnceLock<Box<[bool]>>,
}

/// One evidence value is read by the levels of a run in parallel.
const _: fn() = || {
    const fn assert_sync<T: Sync>() {}
    assert_sync::<SbomEvidence<'static>>();
};

impl<'a> SbomEvidence<'a> {
    /// The evidence of `sbom` judged at `as_of`. Derives nothing yet: each
    /// fact is derived the first time a check reads it.
    pub(crate) const fn new(sbom: &'a NormalizedSbom, as_of: DateTime<Utc>) -> Self {
        Self {
            sbom,
            as_of,
            document: OnceLock::new(),
            versions: OnceLock::new(),
            producers: OnceLock::new(),
            licenses: OnceLock::new(),
            hashes: OnceLock::new(),
            package_counts: [OnceLock::new(), OnceLock::new()],
            graph: OnceLock::new(),
            cycle_count: OnceLock::new(),
            lifecycle_property: OnceLock::new(),
            manufacturer: OnceLock::new(),
            vulnerabilities: OnceLock::new(),
            duplicates: OnceLock::new(),
            vulnerability_assertion: OnceLock::new(),
            direct_dependencies: OnceLock::new(),
            firmware_dependencies: OnceLock::new(),
        }
    }

    /// The evaluation instant the facts are judged at.
    pub(crate) const fn as_of(&self) -> DateTime<Utc> {
        self.as_of
    }

    /// Escape hatch: the SBOM itself. A check that reads the evidence calls
    /// this only where no fact gives what it needs, with a
    /// `// escape hatch: <why>` comment (see the module docs).
    pub(crate) const fn raw_sbom(&self) -> &'a NormalizedSbom {
        self.sbom
    }

    /// The document-level facts.
    pub(crate) fn document(&self) -> &DocumentFacts<'a> {
        self.document
            .get_or_init(|| DocumentFacts::collect(self.sbom))
    }

    /// How many components the SBOM lists.
    pub(crate) fn component_count(&self) -> usize {
        self.sbom.components.len()
    }

    /// Every component, in inventory order.
    pub(crate) fn components(&self) -> impl ExactSizeIterator<Item = ComponentView<'_, 'a>> + '_ {
        self.sbom
            .components
            .values()
            .enumerate()
            .map(move |(ix, component)| ComponentView {
                ev: self,
                ix: ComponentIx(ix),
                component,
            })
    }

    /// The component at `ix`.
    pub(crate) fn component(&self, ix: ComponentIx) -> ComponentView<'_, 'a> {
        let (_, component) = self
            .sbom
            .components
            .get_index(ix.0)
            .expect("a component index comes from this evidence's inventory");
        ComponentView {
            ev: self,
            ix,
            component,
        }
    }

    /// The document's primary component, when its id names a component.
    pub(crate) fn primary(&self) -> Option<ComponentView<'_, 'a>> {
        self.document().primary.map(|ix| self.component(ix))
    }

    /// The number of components the package rules judge: package-scoped
    /// ones, without those left out for their excluded scope unless
    /// `include_excluded_scope`.
    pub(crate) fn package_count(&self, include_excluded_scope: bool) -> usize {
        *self.package_counts[usize::from(include_excluded_scope)].get_or_init(|| {
            self.components()
                .filter(|c| c.package_scoped() && (include_excluded_scope || !c.excluded_scope()))
                .count()
        })
    }

    /// Whether the document declares any dependency relationship.
    pub(crate) fn has_edges(&self) -> bool {
        !self.sbom.edges.is_empty()
    }

    /// The dependency-graph facts.
    pub(crate) fn graph(&self) -> &GraphFacts {
        self.graph.get_or_init(|| GraphFacts::collect(self.sbom))
    }

    /// The number of cycles in the dependency graph (see
    /// [`crate::quality::cycles::dependency_cycle_count`]).
    pub(crate) fn cycle_count(&self) -> usize {
        *self
            .cycle_count
            .get_or_init(|| crate::quality::cycles::dependency_cycle_count(self.sbom))
    }

    /// Whether any component carries a lifecycle, end-of-life or
    /// end-of-support property with a real value (see
    /// [`component::has_lifecycle_property`]).
    pub(crate) fn has_lifecycle_property(&self) -> bool {
        *self.lifecycle_property.get_or_init(|| {
            self.sbom
                .components
                .values()
                .any(component::has_lifecycle_property)
        })
    }

    /// The facts about the product's manufacturer.
    pub(crate) fn manufacturer(&self) -> &ManufacturerFacts<'a> {
        self.manufacturer
            .get_or_init(|| ManufacturerFacts::collect(self.sbom))
    }

    /// Every vulnerability of every component, in inventory order.
    pub(crate) fn vulnerabilities(&self) -> &[VulnFact<'a>] {
        self.vulnerabilities
            .get_or_init(|| vulns::collect(self.sbom))
    }

    /// The components the document lists more than once, in inventory order
    /// (see `NormalizedSbom::duplicate_components`).
    pub(crate) fn duplicates(&self) -> &[&'a DuplicateComponent] {
        self.duplicates.get_or_init(|| {
            self.sbom
                .components
                .keys()
                .filter_map(|id| self.sbom.duplicate_components.get(id))
                .collect()
        })
    }

    fn versions(&self) -> &[ValueState] {
        self.versions.get_or_init(|| {
            self.sbom
                .components
                .values()
                .map(|c| value_state(c.version.as_deref()))
                .collect()
        })
    }

    fn producers(&self) -> &[ValueState] {
        self.producers.get_or_init(|| {
            self.sbom
                .components
                .values()
                .map(component::producer_state)
                .collect()
        })
    }

    fn licenses(&self) -> &[ValueState] {
        self.licenses.get_or_init(|| {
            self.sbom
                .components
                .values()
                .map(component::license_state)
                .collect()
        })
    }

    fn hashes(&self) -> &[HashFacts] {
        self.hashes.get_or_init(|| {
            self.sbom
                .components
                .values()
                .map(|c| HashFacts::of(&c.hashes))
                .collect()
        })
    }

    /// Whether any component references a vulnerability assertion or an
    /// exploitability statement (a VEX or VDR document, say).
    pub(crate) fn has_vulnerability_assertion(&self) -> bool {
        *self.vulnerability_assertion.get_or_init(|| {
            self.sbom.components.values().any(|c| {
                c.external_refs.iter().any(|r| {
                    matches!(
                        r.ref_type,
                        ExternalRefType::VulnerabilityAssertion
                            | ExternalRefType::ExploitabilityStatement
                    )
                })
            })
        })
    }

    fn direct_dependencies(&self) -> &[bool] {
        self.direct_dependencies.get_or_init(|| {
            let direct = self.sbom.direct_dependency_ids();
            self.sbom
                .components
                .values()
                .map(|c| direct.contains(&c.canonical_id))
                .collect()
        })
    }

    fn firmware_dependencies(&self) -> &[bool] {
        self.firmware_dependencies
            .get_or_init(|| graph::firmware_dependencies(self.sbom))
    }
}

/// One component's facts. The cheap ones are computed on access; the rest
/// are read from the evidence's lazy columns.
#[derive(Clone, Copy)]
pub(crate) struct ComponentView<'e, 'a> {
    ev: &'e SbomEvidence<'a>,
    ix: ComponentIx,
    component: &'a Component,
}

impl<'a> ComponentView<'_, 'a> {
    /// The component's name, as read.
    pub(crate) fn name(&self) -> &'a str {
        &self.component.name
    }

    /// The component's canonical id, the join key of a finding.
    pub(crate) fn canonical_id(&self) -> &'a CanonicalId {
        &self.component.canonical_id
    }

    /// The component's format id: its bom-ref, SPDXID or spdxId.
    pub(crate) fn format_id(&self) -> &'a str {
        &self.component.identifiers.format_id
    }

    /// The component's type.
    pub(crate) fn component_type(&self) -> &'a ComponentType {
        &self.component.component_type
    }

    /// Whether the component is of a package-scoped type (see
    /// [`ComponentType::is_package_scoped`]): not a file, a cryptographic
    /// asset or a service.
    pub(crate) fn package_scoped(&self) -> bool {
        self.component.component_type.is_package_scoped()
    }

    /// Whether the component's scope is excluded and it is not the
    /// document's primary component: a run that does not judge components
    /// whose scope is excluded leaves it out of the package rules (the
    /// product itself is never left out).
    pub(crate) fn excluded_scope(&self) -> bool {
        self.component.scope == Some(DependencyScope::Excluded)
            && self.ev.sbom.primary_component_id.as_ref() != Some(&self.component.canonical_id)
    }

    /// Whether the component's name is real (see
    /// [`super::shared::known_component_name`]).
    pub(crate) fn name_known(&self) -> bool {
        known_component_name(self.component)
    }

    /// The identifier kinds the component declares.
    pub(crate) fn ids(&self) -> IdKinds {
        IdKinds::of(&self.component.identifiers)
    }

    /// The component's version.
    pub(crate) fn version(&self) -> Text<'a> {
        Text::with_state(
            self.component.version.as_deref(),
            self.ev.versions()[self.ix.0],
        )
    }

    /// What the component names as its producer.
    pub(crate) fn producer(&self) -> Producer<'a> {
        Producer::new(self.component, self.ev.producers()[self.ix.0])
    }

    /// The component's licences.
    pub(crate) fn licenses(&self) -> Licenses<'a> {
        Licenses::new(&self.component.licenses, self.ev.licenses()[self.ix.0])
    }

    /// The component's hashes.
    pub(crate) fn hashes(&self) -> Hashes<'a> {
        Hashes::new(&self.component.hashes, self.ev.hashes()[self.ix.0])
    }

    /// Whether the component appears in a dependency relationship.
    pub(crate) fn touched(&self) -> bool {
        self.ev.graph().touched[self.ix.0]
    }

    /// Whether the component positively declares it has no dependencies.
    pub(crate) fn declares_no_dependencies(&self) -> bool {
        self.ev.graph().declares_no_dependencies[self.ix.0]
    }

    /// Whether the component gives a version at all, whatever it says. The
    /// CRA hardware checks ask this, the other version checks what the
    /// version says ([`Self::version`]): a `NOASSERTION` version satisfies
    /// the first and not the second.
    pub(crate) fn version_present(&self) -> bool {
        self.component.version.is_some()
    }

    /// The component's end-of-life status, when enrichment gave one.
    pub(crate) fn eol_status(&self) -> Option<EolStatus> {
        self.component.eol.as_ref().map(|eol| eol.status)
    }

    /// Whether the component lists a licence at all, declared or concluded,
    /// whatever it says (see [`Self::licenses`] for what it says).
    pub(crate) fn license_present(&self) -> bool {
        !self.component.licenses.declared.is_empty() || self.component.licenses.concluded.is_some()
    }

    /// Whether the component is a direct dependency of the product: one
    /// hop from the primary component, or from a root of the graph when
    /// the document names no primary (see
    /// `NormalizedSbom::direct_dependency_ids`).
    pub(crate) fn direct_dependency(&self) -> bool {
        self.ev.direct_dependencies()[self.ix.0]
    }

    /// Whether a dependency relationship leads from the component to a
    /// firmware component.
    pub(crate) fn depends_on_firmware(&self) -> bool {
        self.ev.firmware_dependencies()[self.ix.0]
    }
}
