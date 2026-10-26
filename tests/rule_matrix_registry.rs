//! Registry exhaustiveness (audit P3, deferred P0 item): every id in
//! `all_rule_ids()` must resolve via `rule_meta`, and its externally-visible
//! SARIF identity must belong to at least one per-standard SARIF slice — or
//! the id must be explicitly documented as slice-less with a reason. No
//! silent omissions: stale exemptions (ids that later join a slice) fail too.

use sbom_tools::quality::{
    CISA2026_SARIF_RULE_IDS, CNSA2_SARIF_RULE_IDS, COMPLIANCE_SARIF_RULE_IDS,
    EO14028_SARIF_RULE_IDS, FDA_SARIF_RULE_IDS, FSCT_SARIF_RULE_IDS, NTIA_SARIF_RULE_IDS,
    PCIDSS_SARIF_RULE_IDS, PQC_SARIF_RULE_IDS, SSDF_SARIF_RULE_IDS, all_rule_ids, rule_meta,
};
use std::collections::{BTreeMap, BTreeSet};

/// Why the quality profiles' checks are slice-less: they alias
/// SBOM-QUALITY-GENERAL, which no per-standard slice lists.
const QUALITY_CHECK: &str = "quality-profile check aliasing SBOM-QUALITY-GENERAL; the quality \
     profiles have no dedicated SARIF slice — their catalogue is backfilled from fired rules";

/// Internal rule ids whose SARIF identity is deliberately in no per-standard
/// SARIF slice, with the reason. These rules still render in SARIF output via
/// the generator's catalogue-completion backfill when they fire; they are
/// just not part of any upfront-declared rule catalogue.
const SLICELESS: &[(&str, &str)] = &[
    (
        "SBOM-QUALITY-GENERAL",
        "generic bucket for the quality profiles (Minimum/Standard/Comprehensive); \
         those profiles have no dedicated SARIF slice — their catalogue is \
         backfilled from fired rules",
    ),
    ("SBOM-QUALITY-CREATOR", QUALITY_CHECK),
    ("SBOM-QUALITY-SERIAL", QUALITY_CHECK),
    ("SBOM-QUALITY-INVENTORY", QUALITY_CHECK),
    ("SBOM-QUALITY-NAME", QUALITY_CHECK),
    ("SBOM-QUALITY-IDENTIFIER", QUALITY_CHECK),
    ("SBOM-QUALITY-LICENSE", QUALITY_CHECK),
    ("SBOM-QUALITY-HASH", QUALITY_CHECK),
    ("SBOM-QUALITY-SPEC-VERSION", QUALITY_CHECK),
    ("SBOM-QUALITY-SPEC-VERSION-UNKNOWN", QUALITY_CHECK),
    ("SBOM-QUALITY-ELEMENT-ID", QUALITY_CHECK),
    (
        "SBOM-CRA-ART-24-SUPPLIER",
        "CRA OSS-steward supplier rule: the shared COMPLIANCE slice predates the \
         Art. 24 steward profile and does not enumerate it; the SARIF generator \
         backfills the descriptor when the rule fires",
    ),
    (
        "SBOM-CRA-CYCLES",
        "CRA dependency-cycles rule: not enumerated in the shared COMPLIANCE \
         slice; backfilled into the SARIF catalogue when it fires",
    ),
    (
        "SBOM-CRA-ANNEX-VIII",
        "CRA Annex VIII conformity-route rule: not enumerated in the shared \
         COMPLIANCE slice; backfilled into the SARIF catalogue when it fires",
    ),
    (
        "SBOM-EUCC-GENERAL",
        "EUCC generic fallback bucket (SARIF re-bucketing target only); no \
         upfront catalogue lists it",
    ),
    (
        "SBOM-AIACT-GENERAL",
        "EU AI Act generic fallback bucket (SARIF re-bucketing target only); no \
         upfront catalogue lists it",
    ),
    (
        "SBOM-BSIAI-GENERAL",
        "BSI/G7 SBOM-for-AI generic fallback bucket (SARIF re-bucketing target \
         only); no upfront catalogue lists it",
    ),
];

fn slice_union() -> BTreeSet<&'static str> {
    [
        NTIA_SARIF_RULE_IDS,
        FDA_SARIF_RULE_IDS,
        SSDF_SARIF_RULE_IDS,
        EO14028_SARIF_RULE_IDS,
        COMPLIANCE_SARIF_RULE_IDS,
        CNSA2_SARIF_RULE_IDS,
        PQC_SARIF_RULE_IDS,
        CISA2026_SARIF_RULE_IDS,
        PCIDSS_SARIF_RULE_IDS,
        FSCT_SARIF_RULE_IDS,
    ]
    .iter()
    .flat_map(|slice| slice.iter().copied())
    .collect()
}

#[test]
fn every_registered_rule_resolves_and_is_sliced_or_documented_sliceless() {
    let union = slice_union();
    let mut exemptions: BTreeMap<&str, &str> = BTreeMap::new();
    for (id, reason) in SLICELESS {
        assert!(
            exemptions.insert(id, reason).is_none(),
            "duplicate SLICELESS entry for {id}"
        );
        assert!(!reason.trim().is_empty(), "{id}: empty exemption reason");
    }

    for id in all_rule_ids() {
        // Deliverable: every id resolves via rule_meta.
        let meta = rule_meta(id)
            .unwrap_or_else(|| panic!("registered rule id {id:?} does not resolve in rule_meta"));

        let sliced = union.contains(meta.sarif_id);
        let exempt = exemptions.contains_key(id);
        assert!(
            sliced || exempt,
            "rule {id} (SARIF identity {sarif}) belongs to no per-standard SARIF \
             slice and is not documented as slice-less — add it to a slice or to \
             SLICELESS with a reason",
            sarif = meta.sarif_id
        );
        assert!(
            !(sliced && exempt),
            "rule {id} is now covered by a SARIF slice (via {sarif}); remove the \
             stale SLICELESS exemption",
            sarif = meta.sarif_id
        );
    }

    // Exemptions must reference real registry ids (no typo'd dead entries).
    for (id, _) in SLICELESS {
        assert!(
            all_rule_ids().contains(id),
            "SLICELESS entry {id:?} is not a registered rule id"
        );
    }
}

/// Every id enumerated by a per-standard SARIF slice must itself be a
/// registered rule (the registry unit tests pin self-descriptor identity;
/// this integration-level check keeps the exported slices resolvable for
/// external consumers of the crate API).
#[test]
fn every_slice_id_resolves_in_the_registry() {
    for id in slice_union() {
        assert!(
            rule_meta(id).is_some(),
            "SARIF slice id {id:?} does not resolve in rule_meta"
        );
    }
}
