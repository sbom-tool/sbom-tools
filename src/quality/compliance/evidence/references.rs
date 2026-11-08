//! Facts about the external references of every component, a dependency's
//! included. The references that speak for the product's manufacturer are
//! judged on the product's own components instead (see `manufacturer.rs`).

use super::super::shared::is_contact_reference;
use crate::model::{ExternalRefType, ExternalReference, NormalizedSbom};

/// Whether any component carries an external reference that `accepts`.
fn any_reference(sbom: &NormalizedSbom, accepts: impl Fn(&ExternalReference) -> bool) -> bool {
    sbom.components
        .values()
        .any(|c| c.external_refs.iter().any(&accepts))
}

/// Whether any component references a version-control repository.
pub(super) fn any_vcs(sbom: &NormalizedSbom) -> bool {
    any_reference(sbom, |r| matches!(r.ref_type, ExternalRefType::Vcs))
}

/// Whether any component references build metadata or its build system.
pub(super) fn any_build(sbom: &NormalizedSbom) -> bool {
    any_reference(sbom, |r| {
        matches!(
            r.ref_type,
            ExternalRefType::BuildMeta | ExternalRefType::BuildSystem
        )
    })
}

/// Whether any component carries an advisories or security-contact
/// reference that reaches someone (see `shared::is_contact_reference`), or
/// a vulnerability-assertion reference, whatever its locator.
pub(super) fn any_vulnerability_reference(sbom: &NormalizedSbom) -> bool {
    any_reference(sbom, |r| match r.ref_type {
        ExternalRefType::Advisories | ExternalRefType::SecurityContact => is_contact_reference(r),
        ExternalRefType::VulnerabilityAssertion => true,
        _ => false,
    })
}
