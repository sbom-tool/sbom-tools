# Architecture

## Overview
sbom-tools follows a linear pipeline that normalizes inputs, performs semantic
diffing and scoring, and renders the result through reports or the TUI.

```
SBOM files
  -> parsers (CycloneDX/SPDX, streaming for large files)
  -> NormalizedSbom (canonical model)
  -> matching (PURL, alias, ecosystem, adaptive fuzzy, LSH index)
  -> diff engine (semantic + graph)
  -> DiffResult / QualityReport
  -> reports (json/sarif/html/markdown/csv/summary/table/side-by-side) or TUI
```

## Core Modules

- **cli** (`src/cli/`): Clap command handlers for diff, view, validate, quality, diff-multi, timeline, matrix, completions, and config-schema.
- **config** (`src/config/`): Typed configuration with YAML/JSON support, presets, validation, and schema generation.
- **parsers** (`src/parsers/`): CycloneDX/SPDX format detection and parsing into NormalizedSbom. Includes a streaming parser for large files (>512MB) with progress callbacks.
- **model** (`src/model/`): Canonical data model — NormalizedSbom, Component, CanonicalId, DocumentMetadata, Vulnerability, DependencyEdge, License.
- **matching** (`src/matching/`): Multi-tier fuzzy matching for component alignment.
  - Exact PURL match, alias lookup, ecosystem-specific normalization, string similarity (Jaro-Winkler, Levenshtein).
  - Adaptive thresholds that adjust based on score distribution.
  - LSH (locality-sensitive hashing) index for fast candidate lookup.
  - Custom rule engine for user-defined matching rules.
- **diff** (`src/diff/`): Semantic diff engine with graph-aware dependency diffing, incremental diff tracking, and cost-model scoring.
- **enrichment** (`src/enrichment/`): OSV and KEV vulnerability database integration plus EOL detection via endoflife.date API (feature-gated behind `enrichment`). Includes file-based caching with TTL and staleness tracking.
- **quality** (`src/quality/`): SBOM quality scoring and compliance checks against NTIA, FDA, CRA, NIST SSDF, and EO 14028 standards.
- **pipeline** (`src/pipeline/`): Orchestrates the parse → enrich → diff → report workflow. Handles stage sequencing and output routing.
- **reports** (`src/reports/`): Report generators for JSON, SARIF, HTML, Markdown, CSV, summary, table, and side-by-side formats. Includes a streaming reporter for large outputs.
- **tui** (`src/tui/`): Interactive ratatui-based UI for exploring diffs and single SBOMs. Supports diff mode, view mode, fleet comparison, and timeline views.

## Data Flow

### Single Diff (`diff` command)

The `diff` command uses the full pipeline:

1. CLI parses arguments and merges config (`src/cli/`, `src/config/`).
2. `pipeline::parse_sbom_with_context()` reads and parses both SBOMs into `ParsedSbom` (preserves raw content for TUI Source tab).
3. Optional enrichment mutates SBOMs in-place with OSV/KEV data (`pipeline::enrich_sbom()`, feature-gated). Currently called from CLI, not pipeline.
4. `pipeline::compute_diff()` builds `DiffEngine` with matching config, rules, and graph options, then diffs.
5. `pipeline::output_report()` selects reporter format, pre-computes CRA compliance, and writes to file or stdout. For TUI output, raw content is preserved; for non-TUI, it is dropped to save memory.

### Multi-SBOM Commands (`diff-multi`, `timeline`, `matrix`)

Multi-SBOM commands bypass the pipeline and use `MultiDiffEngine` directly:

```
cli/multi.rs
  -> parse_sbom() (direct, not pipeline)
  -> FuzzyMatchConfig::from_preset()
  -> MultiDiffEngine::new()
  -> .diff_multi() / .timeline() / .matrix()
  -> JSON or TUI output only
```

Key differences from single-diff:
- No `DiffConfig` — uses scattered function parameters instead
- No enrichment — vulnerability data not available in multi-SBOM views
- No report format variety — JSON or TUI only (no SARIF/CSV/HTML/Markdown)
- No streaming support
- No matching rules

### Enrichment Flow

Enrichment is feature-gated behind the `enrichment` Cargo feature. When enabled,
the CLI layer (`src/cli/diff.rs`) constructs `OsvEnricherConfig` from `DiffConfig.enrichment`
and calls `pipeline::enrich_sbom()` to mutate each SBOM in-place before diffing.

```
DiffConfig.enrichment → OsvEnricherConfig
  → pipeline::enrich_sbom(&mut sbom, &config)
    → OsvEnricher::new() → enricher.enrich(&mut components)
    → Re-insert enriched components into sbom.components
```

The pipeline module exports `enrich_sbom()` but does not orchestrate it — the CLI is
responsible for calling it at the right time.

## TUI Architecture

The TUI has two systems:

- **Legacy system** (`src/tui/views/`): Monolithic `App` struct holds all state. Each tab renders via functions in `views/*.rs` that take `&App` or `&mut App`. Event handling is a large match tree in `input.rs`. All tabs except Quality use this system.

- **Modern system** (`src/tui/view/views/`): `ViewState` trait with per-tab state structs. Events return `EventResult` enums for navigation, overlays, status messages. Only the Quality tab uses this system as a proof-of-concept.

Both systems coexist. The `App` struct has a `quality_view: Option<QualityView>` field that dispatches to the modern system when present. Migration of remaining tabs to the `ViewState` trait is possible but not planned — the legacy system works and is well-tested.

## Invariants and Conventions

- NormalizedSbom is the single source of truth for parsed data.
- Components are keyed by CanonicalId for stability across formats.
- DiffResult summary values are derived from change lists.
- TUI layers should align selection/sort with the same source lists.
- Builders use `with_*` naming and `mut self -> Self` pattern.
- Error handling: thiserror for library code, anyhow for CLI.
- No `&String`, `&Vec<T>`, `Box<dyn Error>`, or production panics.

## Extension Points

- **Matching rules**: Configurable matching behavior via YAML configs and custom rule engine.
- **Enrichment**: OSV/KEV integration for vulnerability data and EOL detection via endoflife.date API (feature-gated).
- **Reports**: Add new generators by implementing ReportGenerator.
- **Compliance**: Add new standards by extending the quality scorer (currently: NTIA, FDA, CRA, NIST SSDF, EO 14028).

## Known Technical Debt

- Multi-SBOM commands bypass the pipeline (no enrichment, limited output formats).
- Enrichment is orchestrated by CLI, not the pipeline module.
- ~112 `unwrap()` calls across 27 files (most in non-production code: cache, parsers, config) and ~30 `expect()` calls (safe-by-construction).
- 12 lock-poisoning patterns (`lock().unwrap()` / `lock().expect()`).
- 38 integration tests across 6 test files in `tests/`.
- TUI dual system (legacy + ViewState trait) — only Quality migrated.
