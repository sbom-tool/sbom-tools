//! The components re-keyed from a shared canonical id.
//!
//! When two different components share a canonical id,
//! [`NormalizedSbom::claim_canonical_id`] keeps the later one apart under
//! `<id>#<format id>` (then `#2`, `#3`, … while that is taken). A later entry
//! of a re-keyed component, under any format id, must find it again to be
//! merged into it, whatever the order of the entries. [`RekeyIndex`] records
//! the components re-keyed from each shared id, in the order they were
//! added, and finds the first one an entry is the same component as
//! ([`Component::is_same_component`]) without scanning them: a crafted SBOM
//! with tens of thousands of entries under one purl stays linear to parse.
//!
//! Two components are the same when their names and versions agree where
//! both are known; a name or version that is not known agrees with any. A
//! known value never changes (merged entries agree on it), and a value that
//! is not known can become known when an entry that gives it is merged in.
//! The index files each re-keyed component under the name and version it
//! knows now and moves it when a merge teaches it one.
//!
//! [`NormalizedSbom::claim_canonical_id`]: super::NormalizedSbom::claim_canonical_id

use std::collections::{BTreeSet, HashMap};

use super::{CanonicalId, Component, is_known};

/// A component's name and version where known: what
/// [`Component::is_same_component`] compares.
type Known = (Option<String>, Option<String>);

fn known(component: &Component) -> Known {
    (
        Some(component.name.as_str())
            .filter(|name| is_known(name))
            .map(str::to_string),
        component
            .version
            .as_deref()
            .filter(|version| is_known(version))
            .map(str::to_string),
    )
}

/// The components re-keyed from each shared canonical id, kept beside
/// [`NormalizedSbom::components`](super::NormalizedSbom::components) while
/// a document is read. It is derived data: never serialized, and empty in
/// a deserialized SBOM.
#[derive(Debug, Clone, Default)]
pub(crate) struct RekeyIndex {
    /// The re-keyed components, by the id they share.
    groups: HashMap<CanonicalId, Group>,
    /// Each re-keyed component's shared id and position in its group.
    members: HashMap<CanonicalId, (CanonicalId, usize)>,
    /// The next `#<n>` suffix to try after each re-key base
    /// (`<id>#<format id>`), so re-keying many components under one format
    /// id does not walk every suffix taken before.
    next_suffix: HashMap<String, usize>,
}

/// The components re-keyed from one shared id, by position (the order they
/// were added), filed under what each knows of its name and version.
#[derive(Debug, Clone, Default)]
struct Group {
    ids: Vec<CanonicalId>,
    known: Vec<Known>,
    /// By known name and version; either can be unknown (`None`).
    by_known: HashMap<Known, BTreeSet<usize>>,
    /// Those with a known name, by it, whatever their version.
    by_name: HashMap<String, BTreeSet<usize>>,
    /// Those with a known version, by it, whatever their name.
    by_version: HashMap<String, BTreeSet<usize>>,
    /// Those without a known name.
    nameless: BTreeSet<usize>,
    /// Those without a known version.
    versionless: BTreeSet<usize>,
}

impl Group {
    fn file(&mut self, position: usize, known: &Known) {
        self.by_known
            .entry(known.clone())
            .or_default()
            .insert(position);
        match &known.0 {
            Some(name) => {
                self.by_name
                    .entry(name.clone())
                    .or_default()
                    .insert(position);
            }
            None => {
                self.nameless.insert(position);
            }
        }
        match &known.1 {
            Some(version) => {
                self.by_version
                    .entry(version.clone())
                    .or_default()
                    .insert(position);
            }
            None => {
                self.versionless.insert(position);
            }
        }
    }

    fn unfile(&mut self, position: usize, known: &Known) {
        if let Some(set) = self.by_known.get_mut(known) {
            set.remove(&position);
        }
        match &known.0 {
            Some(name) => {
                if let Some(set) = self.by_name.get_mut(name) {
                    set.remove(&position);
                }
            }
            None => {
                self.nameless.remove(&position);
            }
        }
        match &known.1 {
            Some(version) => {
                if let Some(set) = self.by_version.get_mut(version) {
                    set.remove(&position);
                }
            }
            None => {
                self.versionless.remove(&position);
            }
        }
    }

    /// The first member that is the same component as an entry that knows
    /// `query` of its name and version: one whose name and version each
    /// equal the entry's or are not known, where the entry knows them.
    fn first_match(&self, query: &Known) -> Option<usize> {
        let first = |set: Option<&BTreeSet<usize>>| set.and_then(|set| set.first().copied());
        let in_state = |name: Option<&String>, version: Option<&String>| {
            first(self.by_known.get(&(name.cloned(), version.cloned())))
        };
        match query {
            (Some(name), Some(version)) => [
                in_state(Some(name), Some(version)),
                in_state(Some(name), None),
                in_state(None, Some(version)),
                in_state(None, None),
            ]
            .into_iter()
            .flatten()
            .min(),
            (Some(name), None) => [
                first(self.by_name.get(name)),
                self.nameless.first().copied(),
            ]
            .into_iter()
            .flatten()
            .min(),
            (None, Some(version)) => [
                first(self.by_version.get(version)),
                self.versionless.first().copied(),
            ]
            .into_iter()
            .flatten()
            .min(),
            (None, None) => (!self.ids.is_empty()).then_some(0),
        }
    }
}

impl RekeyIndex {
    /// The first component re-keyed from `shared` that `component` could be
    /// another entry of, judged by what each knows of its name and version.
    pub(crate) fn find(&self, shared: &CanonicalId, component: &Component) -> Option<&CanonicalId> {
        let group = self.groups.get(shared)?;
        let position = group.first_match(&known(component))?;
        group.ids.get(position)
    }

    /// The suffix to try first after `base` (`<id>#<format id>`) is taken.
    pub(crate) fn next_suffix(&self, base: &str) -> usize {
        self.next_suffix.get(base).copied().unwrap_or(2)
    }

    /// Record `component`, inserted under `id`, re-keyed from `shared` to
    /// `base` or to `base#<suffix>`.
    pub(crate) fn add(
        &mut self,
        shared: CanonicalId,
        id: CanonicalId,
        base: &str,
        suffix: Option<usize>,
        component: &Component,
    ) {
        if let Some(suffix) = suffix {
            let next = self.next_suffix.entry(base.to_string()).or_insert(2);
            *next = (*next).max(suffix.saturating_add(1));
        }
        let group = self.groups.entry(shared.clone()).or_default();
        let position = group.ids.len();
        let known = known(component);
        group.file(position, &known);
        group.ids.push(id.clone());
        group.known.push(known);
        self.members.insert(id, (shared, position));
    }

    /// Refile the re-keyed component under `id` after an entry was merged
    /// into it, which can teach it its name or version. Nothing for a
    /// component that was not re-keyed.
    pub(crate) fn refresh(&mut self, id: &CanonicalId, component: &Component) {
        let Some((shared, position)) = self.members.get(id) else {
            return;
        };
        let Some(group) = self.groups.get_mut(shared) else {
            return;
        };
        let known = known(component);
        let position = *position;
        if group.known.get(position) == Some(&known) {
            return;
        }
        let old = std::mem::replace(&mut group.known[position], known.clone());
        group.unfile(position, &old);
        group.file(position, &known);
    }
}
