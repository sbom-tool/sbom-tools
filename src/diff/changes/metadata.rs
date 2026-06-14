//! Document-metadata change computer.
//!
//! Compares the `DocumentMetadata` of two SBOMs and emits one
//! [`MetadataChange`] per differing field. Component / dependency /
//! vulnerability diffing is blind to document-level signals (author churn, tool
//! upgrades, timestamp updates, spec-version bumps, lifecycle transitions,
//! signature changes, primary-component version bumps); this pass restores them.
//!
//! Output is deterministic: scalar fields are emitted in a fixed order, and
//! creator add/remove/change entries are sorted by their stable key.

use crate::diff::MetadataChange;
use crate::model::{Creator, CreatorType, NormalizedSbom, SignatureInfo};
use std::collections::BTreeMap;

/// Compute document-level metadata changes between two SBOMs.
///
/// Returns a deterministic, ordered list of [`MetadataChange`] entries covering
/// the document name, format/spec version, creation timestamp, creators
/// (authors and tools), lifecycle phase, signature, and document- /
/// primary-component version. An empty vec means the metadata is unchanged.
#[must_use]
pub fn compute_metadata_changes(old: &NormalizedSbom, new: &NormalizedSbom) -> Vec<MetadataChange> {
    let old_doc = &old.document;
    let new_doc = &new.document;
    let mut changes = Vec::new();

    // ── Scalar document fields (fixed emission order) ───────────────────────
    push(
        &mut changes,
        "name",
        old_doc.name.clone(),
        new_doc.name.clone(),
    );

    // Format + spec version. The format label and spec version together capture
    // a "CycloneDX 1.5 -> 1.7" upgrade or a cross-format conversion.
    push(
        &mut changes,
        "format",
        Some(old_doc.format.to_string()),
        Some(new_doc.format.to_string()),
    );
    push(
        &mut changes,
        "spec_version",
        non_empty(&old_doc.spec_version),
        non_empty(&new_doc.spec_version),
    );

    // Creation timestamp (RFC 3339 so it round-trips and redacts cleanly).
    push(
        &mut changes,
        "created",
        Some(old_doc.created.to_rfc3339()),
        Some(new_doc.created.to_rfc3339()),
    );

    // Lifecycle phase (e.g. pre-build -> build -> operations).
    push(
        &mut changes,
        "lifecycle_phase",
        old_doc.lifecycle_phase.clone(),
        new_doc.lifecycle_phase.clone(),
    );

    // ── Signature (presence + algorithm) ────────────────────────────────────
    push(
        &mut changes,
        "signature.algorithm",
        signature_label(old_doc.signature.as_ref()),
        signature_label(new_doc.signature.as_ref()),
    );

    // ── Document- and primary-component version ─────────────────────────────
    // The document version proper is the serial number / namespace; the primary
    // component's version is the product version this SBOM describes (e.g. the
    // "1.0.0 -> 2.0.0" release bump that is otherwise only visible as a
    // per-component modification).
    push(
        &mut changes,
        "serial_number",
        old_doc.serial_number.clone(),
        new_doc.serial_number.clone(),
    );
    push(
        &mut changes,
        "primary_component_version",
        old.primary_component().and_then(|c| c.version.clone()),
        new.primary_component().and_then(|c| c.version.clone()),
    );

    // ── Creators: authors and tools (add / remove / change) ─────────────────
    push_creator_changes(&mut changes, &old_doc.creators, &new_doc.creators);

    changes
}

/// Append a [`MetadataChange`] for `field` when `old` and `new` differ.
fn push(changes: &mut Vec<MetadataChange>, field: &str, old: Option<String>, new: Option<String>) {
    if let Some(change) = MetadataChange::from_values(field, old, new) {
        changes.push(change);
    }
}

/// Treat an empty string the same as an absent value, so a blank `spec_version`
/// doesn't masquerade as a present-but-empty field.
fn non_empty(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// Render a signature as `"<algorithm>"` (or `"<algorithm> (unsigned)"` when the
/// algorithm is declared but no value is attached). Absent signature -> `None`,
/// so a newly-signed SBOM reads as an `added` change.
fn signature_label(sig: Option<&SignatureInfo>) -> Option<String> {
    sig.map(|s| {
        if s.has_value {
            s.algorithm.clone()
        } else {
            format!("{} (unsigned)", s.algorithm)
        }
    })
}

/// The prefix used for a creator's metadata field key, keyed by creator type so
/// authors and tools are reported under distinct field names.
const fn creator_field(kind: &CreatorType) -> &'static str {
    match kind {
        CreatorType::Tool => "creator.tool",
        CreatorType::Organization => "creator.organization",
        CreatorType::Person => "creator.author",
    }
}

/// Stable, human-readable label for a creator: `"name <email>"` when an email is
/// present, otherwise just the name. Used both as the change value and (with the
/// field prefix) as the dedup key.
fn creator_label(c: &Creator) -> String {
    match &c.email {
        Some(email) if !email.is_empty() => format!("{} <{email}>", c.name),
        _ => c.name.clone(),
    }
}

/// Emit creator add/remove/change entries.
///
/// Tools and organizations are keyed by `(field, name)` so a version bump on the
/// same tool (e.g. `syft 0.9 -> syft 1.0`, both named `syft`) surfaces as a
/// single `modified` entry rather than an unrelated add + remove. Persons are
/// keyed by their full label since people don't carry versions.
fn push_creator_changes(changes: &mut Vec<MetadataChange>, old: &[Creator], new: &[Creator]) {
    // Keyed maps preserve a deterministic (BTree-sorted) iteration order.
    let old_map = index_creators(old);
    let new_map = index_creators(new);

    // Modified or removed: walk old keys.
    for (key, (field, old_label)) in &old_map {
        match new_map.get(key) {
            Some((_, new_label)) if new_label != old_label => push(
                changes,
                field,
                Some(old_label.clone()),
                Some(new_label.clone()),
            ),
            Some(_) => {} // unchanged
            None => push(changes, field, Some(old_label.clone()), None),
        }
    }

    // Added: keys present only in new.
    for (key, (field, new_label)) in &new_map {
        if !old_map.contains_key(key) {
            push(changes, field, None, Some(new_label.clone()));
        }
    }
}

/// Build a stable key -> `(field, label)` map for a creator list.
///
/// The key is `(field, identity)` where `identity` is the creator's name for
/// versioned creators (tools/organizations) and the full label for persons,
/// so equal-named tools collapse to one entry and re-version as `modified`.
fn index_creators(creators: &[Creator]) -> BTreeMap<(String, String), (&'static str, String)> {
    let mut map = BTreeMap::new();
    for c in creators {
        let field = creator_field(&c.creator_type);
        let label = creator_label(c);
        let identity = match c.creator_type {
            CreatorType::Tool | CreatorType::Organization => c.name.clone(),
            CreatorType::Person => label.clone(),
        };
        map.insert((field.to_string(), identity), (field, label));
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::MetadataChangeKind;
    use crate::model::{DocumentMetadata, SbomFormat};
    use chrono::{TimeZone, Utc};

    fn sbom_with(doc: DocumentMetadata) -> NormalizedSbom {
        NormalizedSbom::new(doc)
    }

    fn find<'a>(changes: &'a [MetadataChange], field: &str) -> &'a MetadataChange {
        changes
            .iter()
            .find(|c| c.field == field)
            .unwrap_or_else(|| panic!("expected a `{field}` change, got {changes:?}"))
    }

    #[test]
    fn identical_metadata_yields_no_changes() {
        let doc = DocumentMetadata::default();
        let old = sbom_with(doc.clone());
        let new = sbom_with(doc);
        assert!(compute_metadata_changes(&old, &new).is_empty());
    }

    #[test]
    fn name_and_spec_version_changes_are_emitted() {
        let mut old_doc = DocumentMetadata::default();
        old_doc.name = Some("old".to_string());
        old_doc.spec_version = "1.5".to_string();
        old_doc.created = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        let mut new_doc = old_doc.clone();
        new_doc.name = Some("new".to_string());
        new_doc.spec_version = "1.7".to_string();

        let changes = compute_metadata_changes(&sbom_with(old_doc), &sbom_with(new_doc));

        let name = find(&changes, "name");
        assert_eq!(name.old_value.as_deref(), Some("old"));
        assert_eq!(name.new_value.as_deref(), Some("new"));
        assert_eq!(name.kind, MetadataChangeKind::Modified);

        let spec = find(&changes, "spec_version");
        assert_eq!(spec.old_value.as_deref(), Some("1.5"));
        assert_eq!(spec.new_value.as_deref(), Some("1.7"));
    }

    #[test]
    fn format_change_is_emitted() {
        let mut old_doc = DocumentMetadata::default();
        old_doc.format = SbomFormat::CycloneDx;
        let mut new_doc = old_doc.clone();
        new_doc.format = SbomFormat::Spdx;

        let changes = compute_metadata_changes(&sbom_with(old_doc), &sbom_with(new_doc));
        let fmt = find(&changes, "format");
        assert_eq!(fmt.old_value.as_deref(), Some("CycloneDX"));
        assert_eq!(fmt.new_value.as_deref(), Some("SPDX"));
    }

    #[test]
    fn tool_version_bump_is_a_single_modified_change() {
        let mut old_doc = DocumentMetadata::default();
        old_doc.creators = vec![Creator {
            creator_type: CreatorType::Tool,
            name: "syft".to_string(),
            email: None,
        }];
        let mut new_doc = old_doc.clone();
        // Same tool name, but represented with an email-style version marker to
        // force a label difference (a real bump would change the label too).
        new_doc.creators = vec![Creator {
            creator_type: CreatorType::Tool,
            name: "syft".to_string(),
            email: Some("v1.0".to_string()),
        }];

        let changes = compute_metadata_changes(&sbom_with(old_doc), &sbom_with(new_doc));
        let tool = find(&changes, "creator.tool");
        assert_eq!(tool.kind, MetadataChangeKind::Modified);
        assert_eq!(tool.old_value.as_deref(), Some("syft"));
        assert_eq!(tool.new_value.as_deref(), Some("syft <v1.0>"));
    }

    #[test]
    fn author_add_and_remove_are_emitted() {
        let mut old_doc = DocumentMetadata::default();
        old_doc.creators = vec![Creator {
            creator_type: CreatorType::Person,
            name: "alice".to_string(),
            email: None,
        }];
        let mut new_doc = DocumentMetadata::default();
        new_doc.creators = vec![Creator {
            creator_type: CreatorType::Person,
            name: "bob".to_string(),
            email: None,
        }];

        let changes = compute_metadata_changes(&sbom_with(old_doc), &sbom_with(new_doc));
        let authors: Vec<&MetadataChange> = changes
            .iter()
            .filter(|c| c.field == "creator.author")
            .collect();
        assert_eq!(authors.len(), 2, "expected one removed + one added author");
        assert!(
            authors.iter().any(|c| c.kind == MetadataChangeKind::Removed
                && c.old_value.as_deref() == Some("alice"))
        );
        assert!(
            authors
                .iter()
                .any(|c| c.kind == MetadataChangeKind::Added
                    && c.new_value.as_deref() == Some("bob"))
        );
    }

    #[test]
    fn newly_signed_sbom_reports_added_signature() {
        let old_doc = DocumentMetadata::default();
        let mut new_doc = DocumentMetadata::default();
        new_doc.signature = Some(SignatureInfo {
            algorithm: "Ed25519".to_string(),
            has_value: true,
        });

        let changes = compute_metadata_changes(&sbom_with(old_doc), &sbom_with(new_doc));
        let sig = find(&changes, "signature.algorithm");
        assert_eq!(sig.kind, MetadataChangeKind::Added);
        assert_eq!(sig.new_value.as_deref(), Some("Ed25519"));
    }
}
