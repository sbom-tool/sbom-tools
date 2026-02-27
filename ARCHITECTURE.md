# Architecture

High-level overview of the sbom-tools codebase (~85K LOC, ~200 Rust files).

## Module Structure

```
src/
  cli/          Command handlers (clap-based)
  config/       YAML/JSON configuration, presets, validation
  model/        Canonical SBOM representation
  parsers/      Format detection + parsing
  matching/     Multi-tier fuzzy component matching
  diff/         Semantic diffing engine
  enrichment/   OSV/KEV vulnerability data, EOL detection, VEX
  quality/      Quality scoring engine + compliance standards
  pipeline/     Orchestration: parse -> enrich -> diff -> report
  reports/      Output format generators
  tui/          Interactive terminal UI (ratatui)
  watch/        Continuous SBOM monitoring
```

## Data Flow

```
Input SBOMs (CycloneDX/SPDX)
    |
    v
  Parsers ──> NormalizedSbom (canonical model)
    |
    v
  Enrichment (OSV, KEV, EOL)  [optional, feature-gated]
    |
    v
  Matching Engine ──> Component pairs
    |
    v
  Diff Engine ──> ChangeSet (added/removed/modified)
    |
    v
  Reports / TUI
```

## Key Design Decisions

### Canonical Model (`model/`)
All SBOM formats are normalized into `NormalizedSbom` with `Component`, `Vulnerability`, and `Dependency` types. This allows format-agnostic diffing and analysis.

### Multi-Tier Matching (`matching/`)
Components are matched across SBOMs using a tiered strategy:
1. Exact PURL match
2. Alias lookup (known package renames)
3. Ecosystem-specific normalization
4. String similarity with adaptive thresholds
5. LSH indexing for large SBOMs

### Quality Scoring (`quality/`)
8-category scoring engine (v2.0) with 6 profiles. N/A-aware weight renormalization handles missing data gracefully. Hard caps enforce minimum standards (e.g., EOL components cap grade at D).

### Compliance (`quality/`)
9 standards: NTIA, CRA Phase 1/2, FDA, NIST SSDF, EO 14028, plus Minimum and Comprehensive. Each standard defines required fields and produces SARIF-compatible findings.

### TUI (`tui/`)
Built on ratatui with crossterm backend. Two parallel systems exist:
- Legacy `App` struct for diff mode (tabs: Summary, Components, Vulnerabilities, Dependencies, Compliance, Source)
- `ViewState` trait for view mode (only Quality tab migrated so far)

### Streaming Parser (`parsers/`)
SBOMs larger than 512MB are parsed with a streaming strategy to avoid memory exhaustion.

### Pipeline (`pipeline/`)
`PipelineError` provides structured errors across stages. `build_enrichment_config()` centralizes feature-gated enrichment setup.

## Error Handling

- `thiserror` for library error types
- `anyhow` for CLI error propagation
- `PipelineError` for pipeline stage errors
- Zero `unwrap()` in production; ~22 `expect()` calls, all safe-by-construction

## Feature Flags

- `enrichment` (default) — enables OSV/KEV vulnerability enrichment and EOL detection
- `vex` — enables OpenVEX integration

## Testing

- 762+ tests (unit + integration)
- Property-based testing via `proptest`
- Fuzz targets for all parser formats (`cargo-fuzz`)
- Golden fixture tests for format compatibility
- Integration tests in `tests/` covering pipeline, CLI, CRA, query, VEX, watch, and graph

## CI/CD

- 10 CI jobs: lint, MSRV, 4 platform tests, 2 cargo-deny, security audit, gate
- CodeQL for static analysis
- OpenSSF Scorecard for security posture
- Trusted Publishing (OIDC) for crates.io releases
- SLSA Build Level 3 provenance for releases
