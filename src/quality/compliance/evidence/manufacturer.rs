//! Facts about the product's manufacturer: who it is, and which components
//! can carry its evidence.

use super::super::shared::{
    manufacturer_identified, manufacturer_scope_components, unreachable_contact_in,
};
use crate::model::{Component, ExternalReference, NormalizedSbom};

/// The facts about the product's manufacturer.
#[derive(Debug)]
pub(crate) struct ManufacturerFacts<'a> {
    /// The components whose external references can carry the
    /// manufacturer's evidence (see `shared::manufacturer_scope_components`),
    /// in that function's order.
    scope: Box<[&'a Component]>,
    /// Whether the SBOM names the product's manufacturer (see
    /// `shared::manufacturer_identified`).
    pub(crate) identified: bool,
    /// The first vulnerability contact the SBOM gives that reaches nobody
    /// (see `shared::unreachable_contact`).
    pub(crate) unreachable_contact: Option<&'a str>,
}

impl<'a> ManufacturerFacts<'a> {
    pub(super) fn collect(sbom: &'a NormalizedSbom) -> Self {
        // The scope is derived once: without a described product it walks
        // the graph for its roots.
        let scope = manufacturer_scope_components(sbom);
        let unreachable_contact = unreachable_contact_in(sbom, &scope);
        Self {
            scope: scope.into_boxed_slice(),
            identified: manufacturer_identified(sbom),
            unreachable_contact,
        }
    }

    /// Whether a component of the manufacturer's scope carries an external
    /// reference that `accepts` (see `shared::manufacturer_reference`).
    pub(crate) fn reference(&self, accepts: impl Fn(&ExternalReference) -> bool) -> bool {
        self.scope
            .iter()
            .any(|c| c.external_refs.iter().any(&accepts))
    }
}
