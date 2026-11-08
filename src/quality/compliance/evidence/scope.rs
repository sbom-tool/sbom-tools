//! The package rules' view of the evidence: which components a level's
//! package rules judge, from the evidence and the run's excluded-scope
//! choice, which the context's checker holds.

use super::super::Violation;
use super::super::context::ComplianceContext;
use super::super::shared::inventory_absent_finding;
use super::ComponentView;
use crate::model::ComponentType;

impl<'r, 'a> ComplianceContext<'r, 'a> {
    /// Whether the run leaves `c` out of the package rules: its scope is
    /// excluded, the run does not judge such components, and it is not the
    /// document's primary component (the product itself is never left out).
    pub(crate) fn leaves_out(&self, c: &ComponentView<'_, '_>) -> bool {
        !self.checker.include_excluded_scope && c.excluded_scope()
    }

    /// Whether the package rules judge `c`: a package-scoped component the
    /// run does not leave out for its excluded scope (see
    /// [`Self::leaves_out`]).
    pub(crate) fn judges_package(&self, c: &ComponentView<'_, '_>) -> bool {
        c.package_scoped() && !self.leaves_out(c)
    }

    /// The components the package rules apply to (see
    /// [`Self::judges_package`]), in inventory order. Every per-component
    /// package check iterates through this or tests [`Self::judges_package`],
    /// so no standard can forget a carve-out.
    pub(crate) fn package_components(&self) -> impl Iterator<Item = ComponentView<'r, 'a>> + '_ {
        self.ev.components().filter(|c| self.judges_package(c))
    }

    /// How many components the package rules apply to.
    pub(crate) fn package_count(&self) -> usize {
        self.ev.package_count(self.checker.include_excluded_scope)
    }

    /// The inventory-absent finding for `rule_id`, or `None` when the
    /// package rules judge at least one component (see
    /// [`ComplianceChecker::inventory_absent_violation`](super::super::ComplianceChecker::inventory_absent_violation),
    /// which reads the SBOM for the checkers that do not read the evidence
    /// yet).
    pub(crate) fn inventory_absent_violation(
        &self,
        rule_id: &'static str,
        requirement: &str,
    ) -> Option<Violation> {
        // The first judged component settles it: a level that reads no
        // count does not pay for one.
        if self.package_components().next().is_some() {
            return None;
        }
        Some(inventory_absent_finding(
            self.ev.component_count(),
            self.ev.components().filter(|c| c.package_scoped()).count(),
            || {
                self.ev
                    .components()
                    .all(|c| *c.component_type() == ComponentType::Cryptographic)
            },
            rule_id,
            requirement,
        ))
    }

    /// The vendor-supplied components the CRA vendor-hash check counts
    /// ([PRE-7-RQ-07-RE]), in inventory order: of every type, minus those
    /// the run leaves out for their excluded scope, with a known producer
    /// and a PURL, CPE, SWHID or SWID (the vendor cohort of
    /// `HashQualityMetrics`).
    pub(crate) fn vendor_components(&self) -> impl Iterator<Item = ComponentView<'r, 'a>> + '_ {
        self.ev
            .components()
            .filter(|c| !self.leaves_out(c) && c.producer().is_known() && c.ids().any())
    }

    /// How many vendor-supplied components (see [`Self::vendor_components`])
    /// carry a hash that counts.
    pub(crate) fn vendor_hash_coverage(&self) -> VendorHashCoverage {
        let mut coverage = VendorHashCoverage {
            total: 0,
            with_hash: 0,
        };
        for c in self.vendor_components() {
            coverage.total += 1;
            if c.hashes().facts.plausible {
                coverage.with_hash += 1;
            }
        }
        coverage
    }
}

/// The vendor-hash coverage of a run (CRA [PRE-7-RQ-07-RE]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VendorHashCoverage {
    /// How many vendor-supplied components the run counts.
    pub(crate) total: usize,
    /// How many of them carry at least one plausible digest, whoever added
    /// it.
    pub(crate) with_hash: usize,
}

impl VendorHashCoverage {
    /// The share of vendor-supplied components that carry a hash, or `None`
    /// when there is none (as `HashQualityMetrics::vendor_hash_coverage`).
    pub(crate) fn fraction(self) -> Option<f64> {
        if self.total == 0 {
            return None;
        }
        #[allow(clippy::cast_precision_loss)]
        let fraction = self.with_hash as f64 / self.total as f64;
        Some(fraction)
    }
}
