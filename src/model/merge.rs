//! Merging the entries of a component a document lists more than once.
//!
//! A document can list one component twice: the same purl under two
//! bom-refs, or one bom-ref repeated. Parsers settle each entry's canonical
//! id with [`NormalizedSbom::claim_canonical_id`], which keeps entries of a
//! different known name or version apart, so entries that still share an id
//! are one component ([`Component::is_same_component`]).
//! [`NormalizedSbom::add_component`] merges them with
//! [`Component::merge_duplicate`] and records the duplicate as a
//! [`DuplicateComponent`]. The merged component does not depend on which
//! entry came first:
//!
//! - a list field (hashes, licences, external references, identifiers,
//!   properties, annotations, vulnerabilities) holds every value of every
//!   entry once, sorted; a licence that is not known (`NOASSERTION`, `NONE`,
//!   `TBD`, blank, …) is dropped when another entry names a known one;
//! - a single-valued field that one entry leaves empty, or gives a value
//!   that is not known (a placeholder or sentinel such as `NOASSERTION`,
//!   `NONE` or `TBD`), takes the other entry's known value, without a
//!   conflict;
//! - when the entries give a single-valued field two different known
//!   values, the value that sorts first is kept, and the field is recorded
//!   as a conflict;
//! - the scope is the one of the entry the product needs most at runtime:
//!   `required`, then a scope left unstated (which CycloneDX reads as
//!   `required`), then `optional`, then `excluded`. An entry marked
//!   `excluded` therefore never hides one the product needs, and the
//!   component stays judged by the package rules. Scopes that differ in
//!   effect are recorded as a conflict.
//!
//! Values sort by their JSON form. What counts as known is what every
//! compliance check counts (see `model::known`).
//!
//! [`NormalizedSbom::claim_canonical_id`]: super::NormalizedSbom::claim_canonical_id
//! [`NormalizedSbom::add_component`]: super::NormalizedSbom::add_component

use super::{
    CanonicalId, Component, ComponentExtensions, ComponentIdentifiers, DependencyScope, Hash,
    HashProvenance, LicenseExpression, LicenseInfo, Organization, is_known,
};
use indexmap::IndexMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeSet;

/// A component the document lists more than once. Its entries were merged
/// into one component (see [`Component::merge_duplicate`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DuplicateComponent {
    /// The canonical id the entries share: the merged component's key.
    pub canonical_id: CanonicalId,
    /// How many entries the document lists for the component: two or more.
    pub entries: usize,
    /// The entries' format ids (bom-refs, SPDXIDs), each once, sorted.
    pub format_ids: Vec<String>,
    /// The single-valued fields the entries disagree on, by model field
    /// name (`supplier`, `description`, `licenses.concluded`, …), sorted.
    /// The merged component keeps the value that sorts first. Skipped in
    /// JSON when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conflicts: Vec<String>,
}

impl DuplicateComponent {
    /// The record of a component whose first entry has `format_id`, before
    /// its first repeat is counted.
    pub(super) fn first_entry(canonical_id: CanonicalId, format_id: String) -> Self {
        Self {
            canonical_id,
            entries: 1,
            format_ids: vec![format_id],
            conflicts: Vec::new(),
        }
    }

    /// Count one more entry, with its format id and the fields its merge
    /// found in conflict.
    pub(super) fn count_entry(&mut self, format_id: String, conflicts: BTreeSet<&'static str>) {
        self.entries += 1;
        insert_sorted(&mut self.format_ids, format_id);
        for field in conflicts {
            insert_sorted(&mut self.conflicts, field.to_string());
        }
    }
}

/// Insert `value` into the sorted, duplicate-free `list`.
fn insert_sorted(list: &mut Vec<String>, value: String) {
    if let Err(at) = list.binary_search(&value) {
        list.insert(at, value);
    }
}

/// The serde form of [`NormalizedSbom::duplicate_components`]: a list of
/// records, since a canonical id is no JSON object key. Reading rebuilds the
/// map, keyed by each record's id.
///
/// [`NormalizedSbom::duplicate_components`]: super::NormalizedSbom::duplicate_components
pub(super) mod duplicate_list {
    use super::{CanonicalId, Deserialize, Deserializer, DuplicateComponent, IndexMap, Serializer};

    pub(crate) fn serialize<S: Serializer>(
        map: &IndexMap<CanonicalId, DuplicateComponent>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(map.values())
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<IndexMap<CanonicalId, DuplicateComponent>, D::Error> {
        let records = Vec::<DuplicateComponent>::deserialize(deserializer)?;
        Ok(records
            .into_iter()
            .map(|record| (record.canonical_id.clone(), record))
            .collect())
    }
}

/// The key a value sorts by: its JSON form.
fn sort_key<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

/// Every value of both lists once, sorted by `key`. `combine` folds a value
/// into an earlier one with the same key, for the parts the key leaves out;
/// it must not depend on which of the two comes first.
fn union_sorted_by<T>(
    kept: &mut Vec<T>,
    other: Vec<T>,
    key: impl Fn(&T) -> String,
    mut combine: impl FnMut(&mut T, T),
) {
    let mut keyed: Vec<(String, T)> = std::mem::take(kept)
        .into_iter()
        .chain(other)
        .map(|value| (key(&value), value))
        .collect();
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    let mut merged: Vec<(String, T)> = Vec::with_capacity(keyed.len());
    for (k, value) in keyed {
        match merged.last_mut() {
            Some((last_key, last)) if *last_key == k => combine(last, value),
            _ => merged.push((k, value)),
        }
    }
    *kept = merged.into_iter().map(|(_, value)| value).collect();
}

/// Every value of both lists once, sorted by its JSON form.
fn union_sorted<T: Serialize>(kept: &mut Vec<T>, other: Vec<T>) {
    union_sorted_by(kept, other, sort_key, |_, _| {});
}

/// [`union_sorted`] for an identifier list whose first value can be the one
/// the canonical id derives from (CPEs, SWHIDs): the smaller of the two
/// first values stays first, so the merged identifiers still yield the id.
fn union_identifiers<T: Serialize>(kept: &mut Vec<T>, other: Vec<T>) {
    let front = match (kept.first().map(sort_key), other.first().map(sort_key)) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    };
    union_sorted(kept, other);
    if let Some(front) = front
        && let Some(at) = kept.iter().position(|value| sort_key(value) == front)
    {
        let value = kept.remove(at);
        kept.insert(0, value);
    }
}

/// Keep one value of a single-valued field: an absent value takes the other
/// entry's, and of two different values the one that sorts first is kept.
/// Returns whether the two entries disagree.
fn pick<T: Serialize>(kept: &mut Option<T>, other: Option<T>) -> bool {
    let Some(other) = other else {
        return false;
    };
    match kept {
        None => {
            *kept = Some(other);
            false
        }
        Some(current) => pick_value(current, other),
    }
}

/// [`pick`] for a field that always has a value.
fn pick_value<T: Serialize>(kept: &mut T, other: T) -> bool {
    let (current, incoming) = (sort_key(kept), sort_key(&other));
    if incoming < current {
        *kept = other;
    }
    current != incoming
}

/// Keep one value of a field some of whose values carry no information,
/// which `known` tells apart: a known value beats one that is not known,
/// whichever entry gives it, and the two do not disagree; of two known
/// values the one that sorts first is kept, and they disagree when they
/// differ; of two values that are not known, the one that sorts first is
/// kept without a disagreement. Returns whether the entries disagree.
fn pick_known<T: Serialize>(kept: &mut T, other: T, known: impl Fn(&T) -> bool) -> bool {
    match (known(kept), known(&other)) {
        (true, false) => false,
        (false, true) => {
            *kept = other;
            false
        }
        (true, true) => pick_value(kept, other),
        (false, false) => {
            pick_value(kept, other);
            false
        }
    }
}

/// Whether a text field holds a known value: present, not blank, and no
/// placeholder or sentinel such as `TBD` or `NOASSERTION`.
fn known_text(value: &Option<String>) -> bool {
    value.as_deref().is_some_and(is_known)
}

/// [`pick_known`] for a text field.
fn pick_text(kept: &mut Option<String>, other: Option<String>) -> bool {
    pick_known(kept, other, known_text)
}

/// [`pick_known`] for an organization, known when its name is: two entries
/// naming the same organization add up its URLs and contacts.
fn pick_organization(kept: &mut Option<Organization>, other: Option<Organization>) -> bool {
    match (kept.as_mut(), other) {
        (Some(current), Some(incoming)) if current.name == incoming.name => {
            union_sorted(&mut current.urls, incoming.urls);
            union_sorted(&mut current.contacts, incoming.contacts);
            false
        }
        (_, other) => pick_known(kept, other, |org| {
            org.as_ref().is_some_and(|org| is_known(&org.name))
        }),
    }
}

/// Whether a licence expression is known (not `NOASSERTION`, `NONE`, a
/// placeholder or blank).
fn known_license(license: &LicenseExpression) -> bool {
    is_known(&license.expression)
}

impl Component {
    /// Whether `other`, which shares this component's canonical id, is
    /// another entry of it rather than another component: their names and
    /// versions agree wherever both are known. A name or version that is
    /// absent, blank or not known (`NOASSERTION`, `TBD`, …) agrees with any,
    /// so an entry that leaves it out is merged into the one that gives it.
    #[must_use]
    pub fn is_same_component(&self, other: &Self) -> bool {
        let agree = |a: Option<&str>, b: Option<&str>| match (
            a.filter(|v| is_known(v)),
            b.filter(|v| is_known(v)),
        ) {
            (Some(a), Some(b)) => a == b,
            _ => true,
        };
        agree(Some(&self.name), Some(&other.name))
            && agree(self.version.as_deref(), other.version.as_deref())
    }

    /// Merge `other`, another entry of this component (see
    /// [`Self::is_same_component`]), into it, and return the single-valued
    /// fields the two disagree on, by model field name.
    ///
    /// The result does not depend on which entry is `self` (see the module
    /// docs of `model::merge`): list fields hold every value once, sorted,
    /// and a licence that is not known is dropped when the other entry names
    /// a known one; an absent or unknown value (`NOASSERTION`, `NONE`, `TBD`,
    /// blank, …) takes the other entry's known value, without a conflict; of
    /// two different known values the one that sorts first (by its JSON
    /// form) is kept and the field is returned as a conflict. Two entries
    /// naming the same supplier or manufacturer add up its URLs and
    /// contacts. The format id (bom-ref, SPDXID) that sorts first is kept
    /// without a conflict, since entries of one component often carry two.
    /// The verbatim source JSON and the raw extension data follow the same
    /// rule but are not reported: they differ whenever the entries do. The
    /// content hash is recomputed.
    pub fn merge_duplicate(&mut self, other: Self) -> BTreeSet<&'static str> {
        let mut conflicts = BTreeSet::new();
        let mut record = |field: &'static str, disagree: bool| {
            if disagree {
                conflicts.insert(field);
            }
        };
        let Self {
            canonical_id: _,
            identifiers,
            name,
            version,
            semver: _,
            component_type,
            ecosystem,
            licenses,
            supplier,
            hashes,
            external_refs,
            vulnerabilities,
            vex_status,
            content_hash: _,
            extensions,
            description,
            copyright,
            author,
            manufacturer,
            group,
            is_external,
            version_range,
            staleness,
            eol,
            ml_model,
            dataset,
            crypto_properties,
            scope,
        } = other;

        record("name", pick_known(&mut self.name, name, |n| is_known(n)));
        let version_before = self.version.clone();
        record("version", pick_text(&mut self.version, version));
        if self.version != version_before {
            self.semver = self
                .version
                .as_deref()
                .and_then(|v| semver::Version::parse(v).ok());
        }

        let ComponentIdentifiers {
            purl,
            cpe,
            swhid,
            swid,
            format_id,
            aliases,
        } = identifiers;
        let ids = &mut self.identifiers;
        record("identifiers.purl", pick_text(&mut ids.purl, purl));
        union_identifiers(&mut ids.cpe, cpe);
        union_identifiers(&mut ids.swhid, swhid);
        record("identifiers.swid", pick_text(&mut ids.swid, swid));
        if format_id < ids.format_id {
            ids.format_id = format_id;
        }
        union_sorted(&mut ids.aliases, aliases);

        record(
            "component_type",
            pick_value(&mut self.component_type, component_type),
        );
        record("ecosystem", pick(&mut self.ecosystem, ecosystem));

        let LicenseInfo {
            declared,
            concluded,
            evidence,
        } = licenses;
        // Keyed by the expression alone: the resolved name is display
        // metadata, and of two names the one that sorts first is kept. A
        // licence that is not known adds nothing beside a known one.
        union_sorted_by(
            &mut self.licenses.declared,
            declared,
            |license| license.expression.clone(),
            |kept, other| {
                pick(&mut kept.resolved_name, other.resolved_name);
            },
        );
        if self.licenses.declared.iter().any(known_license) {
            self.licenses.declared.retain(known_license);
        }
        record(
            "licenses.concluded",
            pick_known(&mut self.licenses.concluded, concluded, |l| {
                l.as_ref().is_some_and(known_license)
            }),
        );
        union_sorted(&mut self.licenses.evidence, evidence);

        record("supplier", pick_organization(&mut self.supplier, supplier));
        // A hash both entries carry keeps the authored provenance if either
        // entry has it (provenance is no part of the JSON form).
        union_sorted_by(
            &mut self.hashes,
            hashes,
            sort_key,
            |kept: &mut Hash, other| {
                if other.provenance == HashProvenance::Authored {
                    kept.provenance = HashProvenance::Authored;
                }
            },
        );
        union_sorted(&mut self.external_refs, external_refs);
        union_sorted(&mut self.vulnerabilities, vulnerabilities);
        record("vex_status", pick(&mut self.vex_status, vex_status));

        let ComponentExtensions {
            properties,
            annotations,
            raw,
            source_json,
        } = extensions;
        union_sorted(&mut self.extensions.properties, properties);
        union_sorted(&mut self.extensions.annotations, annotations);
        pick(&mut self.extensions.raw, raw);
        pick(&mut self.extensions.source_json, source_json);

        record("description", pick_text(&mut self.description, description));
        record("copyright", pick_text(&mut self.copyright, copyright));
        record("author", pick_text(&mut self.author, author));
        record(
            "manufacturer",
            pick_organization(&mut self.manufacturer, manufacturer),
        );
        record("group", pick_text(&mut self.group, group));
        record(
            "is_external",
            pick_value(&mut self.is_external, is_external),
        );
        record(
            "version_range",
            pick_text(&mut self.version_range, version_range),
        );
        record("staleness", pick(&mut self.staleness, staleness));
        record("eol", pick(&mut self.eol, eol));
        record("ml_model", pick(&mut self.ml_model, ml_model));
        record("dataset", pick(&mut self.dataset, dataset));
        record(
            "crypto_properties",
            pick(&mut self.crypto_properties, crypto_properties),
        );
        record("scope", pick_scope(&mut self.scope, scope));

        self.calculate_content_hash();
        conflicts
    }
}

/// Keep the scope of the entry the product needs most at runtime (see the
/// module docs): an entry marked `excluded` never hides one that is
/// `required`, or that states no scope, which CycloneDX reads as
/// `required`. Returns whether the two scopes differ in effect, an unstated
/// scope counting as `required`.
fn pick_scope(kept: &mut Option<DependencyScope>, other: Option<DependencyScope>) -> bool {
    const fn need(scope: Option<&DependencyScope>) -> u8 {
        match scope {
            Some(DependencyScope::Required) => 3,
            None => 2,
            Some(DependencyScope::Optional) => 1,
            Some(DependencyScope::Excluded) => 0,
        }
    }
    let effective =
        |scope: Option<&DependencyScope>| scope.cloned().unwrap_or(DependencyScope::Required);
    let disagree = effective(kept.as_ref()) != effective(other.as_ref());
    if need(other.as_ref()) > need(kept.as_ref()) {
        *kept = other;
    }
    disagree
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        ExternalRefType, ExternalReference, HashAlgorithm, LicenseExpression, NormalizedSbom,
        Property,
    };

    fn hash(value: &str) -> Hash {
        Hash::new(HashAlgorithm::Sha256, value.to_string())
    }

    fn reference(url: &str) -> ExternalReference {
        ExternalReference {
            ref_type: ExternalRefType::Vcs,
            url: url.to_string(),
            comment: None,
            hashes: Vec::new(),
        }
    }

    /// An entry of `lodash` 4.17.21 under one purl, with the bom-ref
    /// `format_id`.
    fn entry(format_id: &str) -> Component {
        Component::new("lodash".to_string(), format_id.to_string())
            .with_version("4.17.21".to_string())
            .with_purl("pkg:npm/lodash@4.17.21".to_string())
    }

    /// Three entries of one component that between them carry list values,
    /// fill each other's gaps and disagree on a description.
    fn three_entries() -> Vec<Component> {
        let mut a = entry("ref-a");
        a.hashes = vec![hash("bb"), hash("aa")];
        a.licenses
            .add_declared(LicenseExpression::new("MIT".to_string()));
        a.description = Some("Lodash utilities".to_string());
        a.extensions.properties = vec![Property {
            name: "cdx:npm:package:path".to_string(),
            value: "node_modules/lodash".to_string(),
        }];
        let mut b = entry("ref-b");
        b.hashes = vec![hash("aa")];
        b.licenses
            .add_declared(LicenseExpression::new("MIT".to_string()));
        b.external_refs = vec![reference("https://github.com/lodash/lodash")];
        b.description = Some("A utility library".to_string());
        b.supplier = Some(Organization::new("OpenJS Foundation".to_string()));
        let mut c = entry("ref-a");
        c.copyright = Some("Copyright OpenJS Foundation".to_string());
        c.description = Some("  ".to_string());
        vec![a, b, c]
    }

    /// Every order of `entries`.
    fn permutations(entries: &[Component]) -> Vec<Vec<Component>> {
        if entries.len() <= 1 {
            return vec![entries.to_vec()];
        }
        let mut all = Vec::new();
        for (i, first) in entries.iter().enumerate() {
            let mut rest = entries.to_vec();
            rest.remove(i);
            for mut tail in permutations(&rest) {
                tail.insert(0, first.clone());
                all.push(tail);
            }
        }
        all
    }

    fn sbom_of(entries: Vec<Component>) -> NormalizedSbom {
        let mut sbom = NormalizedSbom::default();
        for c in entries {
            sbom.add_component(c);
        }
        sbom
    }

    /// An entry marked `excluded` never hides one the product needs: the
    /// merged scope is the most needed one in every order, so the component
    /// stays judged, and scopes that differ in effect are a conflict.
    #[test]
    fn an_excluded_entry_never_hides_a_needed_one() {
        use crate::model::DependencyScope::{Excluded, Optional, Required};
        let with_scope = |format_id: &str, scope: Option<DependencyScope>| {
            let mut c = entry(format_id);
            c.scope = scope;
            c
        };
        for (a, b, merged, conflict) in [
            (Some(Excluded), Some(Required), Some(Required), true),
            (Some(Excluded), None, None, true),
            (Some(Excluded), Some(Optional), Some(Optional), true),
            (Some(Optional), Some(Required), Some(Required), true),
            (Some(Optional), None, None, true),
            (None, Some(Required), Some(Required), false),
            (Some(Excluded), Some(Excluded), Some(Excluded), false),
            (None, None, None, false),
        ] {
            for (first, second) in [(a.clone(), b.clone()), (b.clone(), a.clone())] {
                let mut kept = with_scope("ref-a", first.clone());
                let conflicts = kept.merge_duplicate(with_scope("ref-b", second.clone()));
                assert_eq!(kept.scope, merged, "{first:?} + {second:?}");
                assert_eq!(
                    conflicts.contains("scope"),
                    conflict,
                    "{first:?} + {second:?}: {conflicts:?}"
                );
            }
        }
    }

    #[test]
    fn the_merge_does_not_depend_on_entry_order() {
        let orders = permutations(&three_entries());
        assert_eq!(orders.len(), 6);
        let merged: Vec<(String, u64, String)> = orders
            .into_iter()
            .map(|order| {
                let sbom = sbom_of(order);
                assert_eq!(sbom.components.len(), 1);
                let component = sbom.components.values().next().expect("one component");
                let records: Vec<&DuplicateComponent> =
                    sbom.duplicate_components.values().collect();
                (
                    serde_json::to_string(component).expect("serializes"),
                    component.content_hash,
                    serde_json::to_string(&records).expect("serializes"),
                )
            })
            .collect();
        for other in &merged[1..] {
            assert_eq!(other, &merged[0]);
        }
    }

    #[test]
    fn list_fields_hold_every_value_once_and_single_values_fill_gaps() {
        let sbom = sbom_of(three_entries());
        let c = sbom.components.values().next().expect("one component");
        let hashes: Vec<&str> = c.hashes.iter().map(|h| h.value.as_str()).collect();
        assert_eq!(hashes, ["aa", "bb"], "sorted, each once");
        assert_eq!(c.licenses.declared.len(), 1, "MIT once");
        assert_eq!(c.external_refs.len(), 1);
        assert_eq!(c.extensions.properties.len(), 1);
        // A gap takes the other entry's value, without a conflict.
        assert_eq!(
            c.supplier.as_ref().map(|s| s.name.as_str()),
            Some("OpenJS Foundation")
        );
        assert_eq!(c.copyright.as_deref(), Some("Copyright OpenJS Foundation"));
        // Two descriptions: the one that sorts first, and a conflict; the
        // blank one is no value.
        assert_eq!(c.description.as_deref(), Some("A utility library"));
        assert_eq!(
            c.identifiers.format_id, "ref-a",
            "the format id that sorts first"
        );

        let record = &sbom.duplicate_components[&c.canonical_id];
        assert_eq!(record.entries, 3);
        assert_eq!(record.format_ids, ["ref-a", "ref-b"]);
        assert_eq!(record.conflicts, ["description"]);
        assert_eq!(sbom.collision_count, 2, "two entries repeat the first");
    }

    #[test]
    fn an_exact_repeat_is_merged_and_counted() {
        let sbom = sbom_of(vec![entry("ref-a"), entry("ref-a")]);
        assert_eq!(sbom.components.len(), 1);
        assert_eq!(sbom.collision_count, 1, "an exact repeat counts too");
        let record = sbom.duplicate_components.values().next().expect("recorded");
        assert_eq!(record.entries, 2);
        assert_eq!(record.format_ids, ["ref-a"]);
        assert!(record.conflicts.is_empty());
    }

    #[test]
    fn the_same_organization_adds_up_and_another_one_conflicts() {
        let mut a = entry("ref-a");
        let mut acme = Organization::new("Acme".to_string());
        acme.urls = vec!["https://acme.example".to_string()];
        a.supplier = Some(acme.clone());
        let mut b = entry("ref-b");
        acme.urls = vec!["https://acme.example/oss".to_string()];
        b.supplier = Some(acme);
        let sbom = sbom_of(vec![a, b]);
        let c = sbom.components.values().next().expect("one component");
        assert_eq!(c.supplier.as_ref().map(|s| s.urls.len()), Some(2));
        assert!(
            sbom.duplicate_components[&c.canonical_id]
                .conflicts
                .is_empty()
        );

        let mut a = entry("ref-a");
        a.supplier = Some(Organization::new("Zeta".to_string()));
        let mut b = entry("ref-b");
        b.supplier = Some(Organization::new("Acme".to_string()));
        let sbom = sbom_of(vec![a, b]);
        let c = sbom.components.values().next().expect("one component");
        assert_eq!(c.supplier.as_ref().map(|s| s.name.as_str()), Some("Acme"));
        assert_eq!(
            sbom.duplicate_components[&c.canonical_id].conflicts,
            ["supplier"]
        );
    }

    /// A known value beats one that is not known (NOASSERTION, NONE, TBD,
    /// N/A, blank), whichever entry gives which, and that is no conflict.
    /// Every known value here sorts after its placeholder, so keeping the
    /// value that sorts first would keep the placeholder.
    #[test]
    fn a_known_value_beats_a_placeholder_in_either_order() {
        let license = |id: &str| LicenseExpression::new(id.to_string());
        let mut real = entry("ref-a");
        real.supplier = Some(Organization::new("Zeta Components Ltd".to_string()));
        real.manufacturer = Some(Organization::new("Zeta Labs".to_string()));
        real.author = Some("Zoe Writer".to_string());
        real.licenses.add_declared(license("MIT"));
        real.licenses.concluded = Some(license("Zlib"));
        real.identifiers.swid = Some("swid:zeta:lodash".to_string());
        real.description = Some("Zeta's lodash build".to_string());
        let mut placeholder = entry("ref-b");
        placeholder.supplier = Some(Organization::new("NOASSERTION".to_string()));
        placeholder.manufacturer = Some(Organization::new("  ".to_string()));
        placeholder.author = Some("TBD".to_string());
        placeholder.licenses.add_declared(license("NOASSERTION"));
        placeholder.licenses.add_declared(license("NONE"));
        placeholder.licenses.concluded = Some(license("NONE"));
        placeholder.identifiers.swid = Some("NOASSERTION".to_string());
        placeholder.description = Some("N/A".to_string());

        for order in [
            vec![real.clone(), placeholder.clone()],
            vec![placeholder, real],
        ] {
            let sbom = sbom_of(order);
            let c = sbom.components.values().next().expect("one component");
            let name = |org: &Option<Organization>| org.as_ref().map(|o| o.name.clone());
            assert_eq!(name(&c.supplier).as_deref(), Some("Zeta Components Ltd"));
            assert_eq!(name(&c.manufacturer).as_deref(), Some("Zeta Labs"));
            assert_eq!(c.author.as_deref(), Some("Zoe Writer"));
            let declared: Vec<&str> = c
                .licenses
                .declared
                .iter()
                .map(|l| l.expression.as_str())
                .collect();
            assert_eq!(declared, ["MIT"], "NOASSERTION and NONE add nothing to MIT");
            assert_eq!(
                c.licenses.concluded.as_ref().map(|l| l.expression.as_str()),
                Some("Zlib")
            );
            assert_eq!(c.identifiers.swid.as_deref(), Some("swid:zeta:lodash"));
            assert_eq!(c.description.as_deref(), Some("Zeta's lodash build"));
            assert!(
                sbom.duplicate_components[&c.canonical_id]
                    .conflicts
                    .is_empty(),
                "a placeholder against a known value is no conflict"
            );
        }
    }

    /// Placeholders alone stay as they are: a licence list of placeholders
    /// only is kept, and two placeholders are no conflict.
    #[test]
    fn placeholders_alone_are_kept_without_a_conflict() {
        let mut a = entry("ref-a");
        a.licenses
            .add_declared(LicenseExpression::new("NOASSERTION".to_string()));
        a.author = Some("TBD".to_string());
        let mut b = entry("ref-b");
        b.author = Some("N/A".to_string());
        let sbom = sbom_of(vec![a, b]);
        let c = sbom.components.values().next().expect("one component");
        assert_eq!(c.licenses.declared.len(), 1);
        assert!(c.author.is_some());
        assert!(
            sbom.duplicate_components[&c.canonical_id]
                .conflicts
                .is_empty()
        );
    }

    /// An entry that leaves out the name or version (absent, or a
    /// placeholder) is no other component: in either order the parsers'
    /// claim keeps the shared id, and the merged component has the known
    /// name and version. Two known versions stay two components.
    #[test]
    fn an_entry_without_a_known_name_or_version_merges_in_either_order() {
        const PURL: &str = "pkg:npm/lodash@4.17.21";
        let known = entry("ref-a");
        let unversioned =
            Component::new("lodash".to_string(), "ref-b".to_string()).with_purl(PURL.to_string());
        let placeholder_version = Component::new("lodash".to_string(), "ref-c".to_string())
            .with_version("NOASSERTION".to_string())
            .with_purl(PURL.to_string());
        let placeholder_name = Component::new("NOASSERTION".to_string(), "ref-d".to_string())
            .with_version("4.17.21".to_string())
            .with_purl(PURL.to_string());
        let parse = |entries: Vec<Component>| {
            let mut sbom = NormalizedSbom::default();
            for mut c in entries {
                sbom.claim_canonical_id(&mut c);
                sbom.add_component(c);
            }
            sbom
        };
        let entries = vec![known, unversioned, placeholder_version, placeholder_name];
        for order in permutations(&entries) {
            let sbom = parse(order);
            assert_eq!(sbom.components.len(), 1, "one component for four entries");
            let c = sbom.components.values().next().expect("one component");
            assert_eq!(c.name, "lodash");
            assert_eq!(c.version.as_deref(), Some("4.17.21"));
            assert!(c.semver.is_some());
            assert_eq!(sbom.duplicate_components[&c.canonical_id].entries, 4);
        }

        let other_version = Component::new("lodash".to_string(), "ref-e".to_string())
            .with_version("4.17.20".to_string())
            .with_purl("pkg:npm/lodash".to_string());
        let this_version = Component::new("lodash".to_string(), "ref-f".to_string())
            .with_version("4.17.21".to_string())
            .with_purl("pkg:npm/lodash".to_string());
        let sbom = parse(vec![other_version, this_version]);
        assert_eq!(
            sbom.components.len(),
            2,
            "two known versions are two components"
        );
        assert!(sbom.duplicate_components.is_empty());
    }

    #[test]
    fn a_hash_keeps_its_authored_provenance() {
        let mut a = entry("ref-a");
        a.hashes = vec![Hash::enriched(HashAlgorithm::Sha256, "aa".to_string())];
        let mut b = entry("ref-b");
        b.hashes = vec![hash("aa")];
        for order in [vec![a.clone(), b.clone()], vec![b, a]] {
            let sbom = sbom_of(order);
            let c = sbom.components.values().next().expect("one component");
            assert_eq!(c.hashes.len(), 1);
            assert_eq!(c.hashes[0].provenance, HashProvenance::Authored);
        }
    }

    /// The canonical id of a component without a purl comes from its first
    /// CPE; the merged CPE list keeps a first value that yields it.
    #[test]
    fn a_cpe_keyed_component_keeps_its_canonical_id() {
        let key = "cpe:2.3:a:vendor:zlib:1.3:*:*:*:*:*:*:*";
        let mut a = Component::new("zlib".to_string(), "zlib-a".to_string());
        a.add_cpe(key.to_string());
        a.add_cpe("cpe:2.3:a:alt:zlib:1.3:*:*:*:*:*:*:*".to_string());
        let mut b = Component::new("zlib".to_string(), "zlib-b".to_string());
        b.add_cpe(key.to_string());
        let sbom = sbom_of(vec![b, a]);
        let c = sbom.components.values().next().expect("one component");
        assert_eq!(c.identifiers.cpe.len(), 2);
        assert_eq!(c.identifiers.cpe[0], key);
        assert_eq!(c.identifiers.canonical_id(), c.canonical_id);
    }

    /// A component of another version under a taken id is no duplicate:
    /// `add_component` replaces, as it always has (parsers give such a
    /// component an id of its own first, see
    /// `NormalizedSbom::claim_canonical_id`).
    #[test]
    fn another_version_under_a_taken_id_replaces() {
        let v1 = Component::new("lodash".to_string(), "lodash".to_string())
            .with_version("1.0.0".to_string());
        let v2 = Component::new("lodash".to_string(), "lodash".to_string())
            .with_version("2.0.0".to_string());
        let sbom = sbom_of(vec![v1, v2]);
        let c = sbom.components.values().next().expect("one component");
        assert_eq!(c.version.as_deref(), Some("2.0.0"));
        assert!(sbom.duplicate_components.is_empty());
        assert_eq!(sbom.collision_count, 1);
    }

    /// The records serialize as a list and read back into the map.
    #[test]
    fn the_records_round_trip_as_a_list() {
        #[derive(Serialize, Deserialize)]
        struct Records {
            #[serde(with = "duplicate_list")]
            records: IndexMap<CanonicalId, DuplicateComponent>,
        }
        let sbom = sbom_of(three_entries());
        let json = serde_json::to_value(Records {
            records: sbom.duplicate_components.clone(),
        })
        .expect("serializes");
        let list = json["records"].as_array().expect("a list");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["entries"], 3);
        let back: Records = serde_json::from_value(json).expect("deserializes");
        assert_eq!(back.records, sbom.duplicate_components);
    }
}
