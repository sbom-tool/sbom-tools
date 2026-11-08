//! Attestation facts: the standard requirements the document's CDXA
//! attestations fully support at the evaluation instant, each with the rule
//! family it counts for.

use chrono::{DateTime, Utc};

use crate::model::{AttestationRuleFamily, NormalizedSbom, SupportedRequirement};

/// One requirement the document's attestations fully support.
#[derive(Debug)]
pub(super) struct Supported<'a> {
    /// The rule family the requirement counts for (see
    /// `AttestationRuleFamily::classify`); `None` for a pair no family
    /// knows, which counts for nothing.
    pub(super) family: Option<AttestationRuleFamily>,
    /// The requirement and what supports it.
    pub(super) requirement: SupportedRequirement<'a>,
}

/// The requirements the document's attestations fully support at `as_of`
/// (see `AttestationDeclarations::supported_requirements`), in that
/// function's order, each classified once. Empty when the document carries
/// no declarations.
pub(super) fn collect(sbom: &NormalizedSbom, as_of: DateTime<Utc>) -> Box<[Supported<'_>]> {
    sbom.declarations()
        .map_or_else(Box::default, |declarations| {
            declarations
                .supported_requirements(as_of)
                .into_iter()
                .map(|requirement| Supported {
                    family: AttestationRuleFamily::classify(
                        requirement.standard,
                        requirement.requirement,
                    ),
                    requirement,
                })
                .collect()
        })
}
