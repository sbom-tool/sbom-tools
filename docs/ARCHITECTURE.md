# Architecture

## Overview
sbom-tools follows a linear pipeline that normalizes inputs, performs semantic
diffing and scoring, and renders the result through reports or the TUI.

```
SBOM files
  -> parsers (CycloneDX/SPDX)
  -> NormalizedSbom (canonical model)
  -> matching + diff engine
  -> DiffResult / QualityReport
  -> reports (json/sarif/html/markdown/summary) or TUI
```

## Core Modules
- config: typed configuration, presets, validation, config-file loading.
- parsers: CycloneDX/SPDX detection and parsing into NormalizedSbom.
- model: canonical data model (NormalizedSbom, Component, CanonicalId).
- matching: fuzzy matching, rules, and indexing for component alignment.
- diff: semantic diff engine, graph diffing, and result structures.
- quality: scoring and compliance checks for SBOM quality.
- reports: structured and human-readable report generators.
- tui: interactive diff TUI and view-mode TUI for single SBOMs.

## Data Flow
1. CLI parses arguments and merges config (src/main.rs, src/config/).
2. Parser detects format and builds NormalizedSbom (src/parsers/).
3. Optional enrichment adds vulnerability metadata (feature-gated).
4. DiffEngine performs matching and generates DiffResult (src/diff/).
5. Reports or TUI render the result (src/reports/, src/tui/).

## Invariants and Conventions
- NormalizedSbom is the single source of truth for parsed data.
- Components are keyed by CanonicalId for stability across formats.
- DiffResult summary values are derived from change lists.
- TUI layers should align selection/sort with the same source lists.

## Extension Points
- Matching rules: configurable matching behavior via YAML configs.
- Enrichment: OSV integration for vulnerability data (feature gated).
- Reports: add new generators by implementing ReportGenerator.
