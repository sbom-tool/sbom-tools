//! Vulnerability facts.

use super::super::shared::justified_not_affected;
use super::ComponentIx;
use crate::model::{NormalizedSbom, VulnerabilityRef};

/// One vulnerability of one component.
#[derive(Debug, Clone, Copy)]
pub(crate) struct VulnFact<'a> {
    /// The component it affects.
    pub(crate) component: ComponentIx,
    /// The vulnerability as read: its id, severity, scores and remediation.
    pub(crate) vuln: &'a VulnerabilityRef,
    /// Whether its own VEX statement is a justified `not_affected` (see
    /// `shared::justified_not_affected`).
    pub(crate) justified_not_affected: bool,
}

/// Every vulnerability of every component, in inventory order and, within a
/// component, in document order (as `NormalizedSbom::all_vulnerabilities`).
pub(super) fn collect(sbom: &NormalizedSbom) -> Box<[VulnFact<'_>]> {
    sbom.components
        .values()
        .enumerate()
        .flat_map(|(ix, component)| {
            component.vulnerabilities.iter().map(move |vuln| VulnFact {
                component: ComponentIx(ix),
                vuln,
                justified_not_affected: justified_not_affected(vuln),
            })
        })
        .collect()
}
