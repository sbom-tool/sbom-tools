//! Per-component facts: identifiers, producer, licences, hashes, and the
//! lifecycle properties.

use super::super::shared::{ValueState, known_value, plausible_digest, value_state};
use crate::model::{Component, ComponentIdentifiers, Hash, HashAlgorithm, LicenseInfo};

/// Which identifier kinds a component declares: a PURL, a CPE, a SWHID, a
/// SWID. Presence only, as the identifier checks read them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct IdKinds {
    pub(crate) purl: bool,
    pub(crate) cpe: bool,
    pub(crate) swhid: bool,
    pub(crate) swid: bool,
}

impl IdKinds {
    pub(super) fn of(identifiers: &ComponentIdentifiers) -> Self {
        Self {
            purl: identifiers.purl.is_some(),
            cpe: !identifiers.cpe.is_empty(),
            swhid: !identifiers.swhid.is_empty(),
            swid: identifiers.swid.is_some(),
        }
    }

    /// Whether any is declared: the CRA-named identifier set
    /// (`ComponentIdentifiers::has_cra_identifier`).
    pub(crate) const fn any(self) -> bool {
        self.purl || self.cpe || self.swhid || self.swid
    }
}

/// What a component names as its producer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Producer<'a> {
    /// The best of what its supplier, manufacturer and author say: a real
    /// value if any of them is one (`has_known_producer`), else an explicit
    /// sentinel if any is one, else missing.
    pub(crate) state: ValueState,
    /// The value a finding quotes when the producer is not known: the first
    /// of the supplier, manufacturer and author names that is present, as
    /// read (`observed_producer`), typically a placeholder such as `TBD`.
    pub(crate) observed: Option<&'a str>,
}

impl<'a> Producer<'a> {
    pub(super) fn new(component: &'a Component, state: ValueState) -> Self {
        let observed = component
            .supplier
            .as_ref()
            .map(|o| o.name.as_str())
            .or_else(|| component.manufacturer.as_ref().map(|o| o.name.as_str()))
            .or(component.author.as_deref());
        Self { state, observed }
    }

    /// Whether the component names a real producer.
    pub(crate) fn is_known(&self) -> bool {
        self.state == ValueState::Known
    }
}

/// The rank of a state when several fields speak for one element: a real
/// value wins over a sentinel, and a sentinel over nothing.
const fn rank(state: ValueState) -> u8 {
    match state {
        ValueState::Known => 0,
        ValueState::DeclaredUnknown => 1,
        ValueState::Missing => 2,
    }
}

/// The producer state of `component` (see [`Producer::state`]).
pub(super) fn producer_state(component: &Component) -> ValueState {
    [
        component.supplier.as_ref().map(|o| o.name.as_str()),
        component.manufacturer.as_ref().map(|o| o.name.as_str()),
        component.author.as_deref(),
    ]
    .into_iter()
    .map(value_state)
    .min_by_key(|state| rank(*state))
    .unwrap_or(ValueState::Missing)
}

/// A component's licences.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Licenses<'a> {
    /// What the best of its declared and concluded licences says (see
    /// `shared::license_state`).
    pub(crate) state: ValueState,
    /// The licences as read, for a finding's message.
    pub(crate) raw: &'a LicenseInfo,
}

impl<'a> Licenses<'a> {
    pub(super) const fn new(raw: &'a LicenseInfo, state: ValueState) -> Self {
        Self { state, raw }
    }

    /// Whether one of the licences is a real expression.
    pub(crate) fn is_known(&self) -> bool {
        self.state == ValueState::Known
    }
}

/// The licence state of `component`, as `shared::license_state` derives it,
/// without collecting the licences into a list first.
pub(super) fn license_state(component: &Component) -> ValueState {
    component
        .licenses
        .declared
        .iter()
        .chain(&component.licenses.concluded)
        .map(|l| value_state(Some(l.expression.as_str())))
        .min_by_key(|state| rank(*state))
        .unwrap_or(ValueState::Missing)
}

/// Which of a component's hashes count. Only plausible digests count (see
/// `shared::plausible_digest`), whoever added them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct HashFacts {
    /// At least one hash is a plausible digest.
    pub(crate) plausible: bool,
    /// At least one plausible digest is of SHA-256 or a stronger algorithm:
    /// SHA-2 and SHA-3 at 256 bits or more, BLAKE2b, BLAKE3 or Streebog.
    pub(crate) plausible_strong: bool,
}

impl HashFacts {
    pub(super) fn of(hashes: &[Hash]) -> Self {
        let mut facts = Self::default();
        for hash in hashes
            .iter()
            .filter(|h| plausible_digest(&h.algorithm, &h.value))
        {
            facts.plausible = true;
            facts.plausible_strong |= is_strong(&hash.algorithm);
        }
        facts
    }
}

/// Whether `algorithm` is SHA-256 or stronger.
const fn is_strong(algorithm: &HashAlgorithm) -> bool {
    matches!(
        algorithm,
        HashAlgorithm::Sha256
            | HashAlgorithm::Sha384
            | HashAlgorithm::Sha512
            | HashAlgorithm::Sha3_256
            | HashAlgorithm::Sha3_384
            | HashAlgorithm::Sha3_512
            | HashAlgorithm::Blake2b256
            | HashAlgorithm::Blake2b384
            | HashAlgorithm::Blake2b512
            | HashAlgorithm::Blake3
            | HashAlgorithm::Streebog256
            | HashAlgorithm::Streebog512
    )
}

/// A component's hashes.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Hashes<'a> {
    /// Which of them count.
    pub(crate) facts: HashFacts,
    /// The hashes as read, for a finding's message.
    pub(crate) raw: &'a [Hash],
}

impl<'a> Hashes<'a> {
    pub(super) const fn new(raw: &'a [Hash], facts: HashFacts) -> Self {
        Self { facts, raw }
    }
}

/// Whether `component` carries a lifecycle, end-of-life or end-of-support
/// property with a real value. The property name is matched by token (`eol`,
/// `lifecycle`) or by the spelled-out terms: a bare substring test let
/// "geolocation" pass through its embedded "eol".
pub(super) fn has_lifecycle_property(component: &Component) -> bool {
    component.extensions.properties.iter().any(|p| {
        let name_lower = p.name.to_lowercase();
        let is_lifecycle_name = name_lower
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|t| t == "eol" || t == "lifecycle")
            || name_lower.contains("end-of-life")
            || name_lower.contains("end-of-support")
            || name_lower.contains("endoflife")
            || name_lower.contains("endofsupport");
        is_lifecycle_name && known_value(Some(p.value.as_str())).is_some()
    })
}
