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
- **enrichment** (`src/enrichment/`): OSV and KEV vulnerability database integration (feature-gated behind `enrichment`). Includes file-based caching with TTL and staleness tracking.
- **quality** (`src/quality/`): SBOM quality scoring and compliance checks against NTIA, FDA, and CRA standards.
- **pipeline** (`src/pipeline/`): Orchestrates the parse → enrich → diff → report workflow. Handles stage sequencing and output routing.
- **reports** (`src/reports/`): Report generators for JSON, SARIF, HTML, Markdown, CSV, summary, table, and side-by-side formats. Includes a streaming reporter for large outputs.
- **tui** (`src/tui/`): Interactive ratatui-based UI for exploring diffs and single SBOMs. Supports diff mode, view mode, fleet comparison, and timeline views.

## Data Flow

1. CLI parses arguments and merges config (`src/cli/`, `src/config/`).
2. Parser detects format and builds NormalizedSbom (`src/parsers/`). For large files, the streaming parser reads incrementally.
3. Optional enrichment adds vulnerability metadata from OSV/KEV (`src/enrichment/`, feature-gated).
4. Pipeline orchestrates matching and diff stages (`src/pipeline/`).
5. DiffEngine matches components and generates DiffResult (`src/matching/`, `src/diff/`).
6. Reports or TUI render the result (`src/reports/`, `src/tui/`).

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
- **Enrichment**: OSV/KEV integration for vulnerability data (feature-gated).
- **Reports**: Add new generators by implementing ReportGenerator.
- **Compliance**: Add new standards by extending the quality scorer.
