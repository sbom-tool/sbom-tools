//! The `sbom-tools/rules/v1` JSON document emitted by `sbom-tools rules -o
//! json` and `sbom-tools rules explain <RULE_ID> -o json`.
//!
//! One object holding the catalogue entries asked for (see
//! [`rule_catalog`](crate::quality::rule_catalog)), each the serialization of
//! a [`RuleCatalogEntry`]. The schema is published at
//! `schemas/rules/v1.schema.json`; docs/compliance-output.md describes every
//! field.

use super::ReportError;
use crate::quality::RuleCatalogEntry;
use serde::Serialize;

/// The document's `schema` value.
pub const RULE_CATALOG_JSON_SCHEMA: &str = "sbom-tools/rules/v1";

#[derive(Serialize)]
struct Document<'a> {
    schema: &'static str,
    tool: Tool,
    rules: &'a [RuleCatalogEntry],
}

#[derive(Serialize)]
struct Tool {
    name: &'static str,
    version: &'static str,
}

/// Render `rules` as one `sbom-tools/rules/v1` document.
pub fn generate_rule_catalog_json(rules: &[RuleCatalogEntry]) -> Result<String, ReportError> {
    let document = Document {
        schema: RULE_CATALOG_JSON_SCHEMA,
        tool: Tool {
            name: "sbom-tools",
            version: env!("CARGO_PKG_VERSION"),
        },
        rules,
    };
    serde_json::to_string_pretty(&document)
        .map_err(|e| ReportError::SerializationError(e.to_string()))
}
