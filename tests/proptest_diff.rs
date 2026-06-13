//! Property-based tests for diff engine invariants.
//!
//! Verifies that the semantic diff engine satisfies key properties:
//! reflexivity (diff(a, a) reports no changes), added/removed symmetry
//! between diff directions, and deterministic serialized output across
//! repeated runs — including SBOMs above the 500-component LSH threshold.

use proptest::prelude::*;
use sbom_tools::diff::DiffEngine;
use sbom_tools::model::{Component, DocumentMetadata, NormalizedSbom};
use std::collections::HashSet;

/// Generate an arbitrary component with random fields.
///
/// Mirrors `arb_component` in `proptest_matching.rs`: names are at least
/// 3 characters with no hyphens to avoid known alias-table asymmetries.
fn arb_component() -> impl Strategy<Value = Component> {
    (
        "[a-z][a-z0-9]{2}[a-z0-9]{0,17}", // name (min 3 chars, no hyphens to avoid alias asymmetry)
        prop::option::of("[0-9]{1,2}\\.[0-9]{1,2}\\.[0-9]{1,2}"), // version
        prop::option::of(prop::sample::select(vec![
            "npm", "pypi", "maven", "cargo", "golang",
        ])),
    )
        .prop_map(|(name, version, ecosystem)| {
            let format_id = format!("test:{name}");
            let mut comp = Component::new(name, format_id);
            if let Some(v) = version {
                comp = comp.with_version(v);
            }
            if let Some(eco) = ecosystem {
                comp.ecosystem = Some(sbom_tools::model::Ecosystem::from_purl_type(eco));
            }
            comp
        })
}

/// Build a normalized SBOM from a list of components.
///
/// Per-component content hashes are computed (as parsers do) so the diff
/// engine can detect modifications.
fn build_sbom(components: Vec<Component>) -> NormalizedSbom {
    let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
    for mut comp in components {
        comp.calculate_content_hash();
        sbom.add_component(comp);
    }
    sbom
}

/// Mutation applied per base component when deriving the "new" SBOM.
#[derive(Debug, Clone, Copy)]
enum Mutation {
    /// Component is carried over unchanged
    Keep,
    /// Component is replaced by a same-name variant with a new format ID and
    /// version, forcing it through the fuzzy-matching path
    Bump,
    /// Component is removed
    Drop,
}

fn arb_mutation() -> impl Strategy<Value = Mutation> {
    prop_oneof![
        4 => Just(Mutation::Keep),
        1 => Just(Mutation::Bump),
        1 => Just(Mutation::Drop),
    ]
}

fn apply_mutations(
    base: &[Component],
    mutations: &[Mutation],
    added: Vec<Component>,
) -> Vec<Component> {
    let mut out = Vec::with_capacity(base.len() + added.len());
    for (comp, mutation) in base.iter().zip(mutations) {
        match mutation {
            Mutation::Keep => out.push(comp.clone()),
            Mutation::Bump => {
                let mut bumped = Component::new(comp.name.clone(), format!("v2:{}", comp.name))
                    .with_version("99.0.0".to_string());
                bumped.ecosystem = comp.ecosystem.clone();
                out.push(bumped);
            }
            Mutation::Drop => {}
        }
    }
    out.extend(added);
    out
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn diff_with_self_yields_no_changes(
        components in prop::collection::vec(arb_component(), 0..40),
    ) {
        let sbom = build_sbom(components);
        let engine = DiffEngine::new();
        let result = engine.diff(&sbom, &sbom).expect("diff should succeed");

        prop_assert!(result.components.added.is_empty());
        prop_assert!(result.components.removed.is_empty());
        prop_assert!(result.components.modified.is_empty());
    }

    #[test]
    fn forward_added_equals_reverse_removed(
        a_comps in prop::collection::vec(arb_component(), 0..40),
        b_comps in prop::collection::vec(arb_component(), 0..40),
    ) {
        let a = build_sbom(a_comps);
        let b = build_sbom(b_comps);
        let engine = DiffEngine::new();

        let forward = engine.diff(&a, &b).expect("diff should succeed");
        let reverse = engine.diff(&b, &a).expect("diff should succeed");

        let forward_added: HashSet<String> = forward
            .components
            .added
            .iter()
            .map(|c| c.id.clone())
            .collect();
        let reverse_removed: HashSet<String> = reverse
            .components
            .removed
            .iter()
            .map(|c| c.id.clone())
            .collect();

        prop_assert_eq!(forward_added, reverse_removed);
    }
}

proptest! {
    // Low case count: each case diffs >500-component SBOMs twice
    #![proptest_config(ProptestConfig::with_cases(10))]

    #[test]
    fn large_diff_output_is_deterministic(
        pairs in prop::collection::vec((arb_component(), arb_mutation()), 520..560),
        added in prop::collection::vec(arb_component(), 0..30),
    ) {
        let (base, mutations): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
        let old = build_sbom(base.clone());
        let new = build_sbom(apply_mutations(&base, &mutations, added));

        // Above the 500-component LSH threshold, so MinHash-based candidate
        // generation participates in matching
        prop_assert!(old.component_count() >= 500);

        let run = || {
            let engine = DiffEngine::new();
            let result = engine.diff(&old, &new).expect("diff should succeed");
            serde_json::to_string(&result).expect("diff result should serialize")
        };

        prop_assert_eq!(run(), run());
    }
}
