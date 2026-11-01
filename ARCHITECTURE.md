# Architecture

High-level overview of the sbom-tools codebase (~87K LOC, ~200 Rust files).

## Module Structure

```
src/
  cli/            Command handlers (clap-based, 18 subcommands)
  config/         YAML/JSON configuration, presets, validation, schema generation
  model/          Canonical SBOM representation (NormalizedSbom, Component, CanonicalId)
  parsers/        Format detection + parsing (streaming for >512MB)
  matching/       Multi-tier fuzzy matching (PURL, alias, ecosystem, adaptive, LSH)
  diff/           Semantic diffing engine + graph diff + incremental section-selective diff
  enrichment/     OSV/KEV vulnerability data, EOL detection, VEX (feature-gated)
  quality/        8-category scoring engine v2.0 + 9 compliance standards
  pipeline/       Orchestration: parse -> enrich -> diff -> report + shared enrichment pipeline
  reports/        9 output format generators + streaming reporter
  tui/            Interactive terminal UI (ratatui) — diff, view, multi-diff, timeline, matrix
  verification/   File hash verification + component hash auditing
  license/        License policy engine (allow/deny/review) + propagation analysis
  serialization/  Raw JSON enrichment, tailoring (filter), merging with dedup
  watch/          Continuous SBOM monitoring (file watcher, vulnerability alerts)
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
Built on ratatui with crossterm backend. Unified `App` struct with `ViewState` trait pattern:
- **Diff mode** — 10 tabs: Summary, Components, Dependencies, Licenses, Vulnerabilities, Quality, Compliance, Side-by-Side, Graph Changes, Source
- **View mode** — 8 tabs: Overview, Tree, Vulnerabilities, Licenses, Dependencies, Quality, Compliance, Source
- **Multi-modes** — Full-screen views for diff-multi (1:N), timeline, and matrix (NxN) comparisons
- All tabs implement `ViewState` trait for modular event handling
- `RenderContext` provides read-only rendering decoupled from state mutation
- Features: regex search (Ctrl+R), composable vulnerability filters, version downgrade detection, cached grouped rendering

### Streaming Parser (`parsers/`)
SBOMs larger than 512MB are parsed with a streaming strategy to avoid memory exhaustion.

### Diff Engine (`diff/`)
- Section-selective incremental diffing: only recomputes changed sections (components, dependencies, licenses, vulnerabilities) when cache detects partial changes
- `QualityDelta` tracks per-category quality score changes across SBOM versions
- `VexStatusChange` detects VEX state transitions for persistent vulnerabilities
- `MatchMetrics` records matching quality statistics (exact/fuzzy/rule match counts)
- Cost model with presets (default, security-focused, compliance-focused)

### Pipeline (`pipeline/`)
`PipelineError` provides structured errors across stages. Shared enrichment pipeline (`pipeline/enrich.rs`) composes OSV + EOL + VEX enrichment into a single `enrich_sbom_full()` call used by all commands.

## Error Handling

- `thiserror` for library error types
- `anyhow` for CLI error propagation
- `PipelineError` for pipeline stage errors
- Zero `unwrap()` in production; ~22 `expect()` calls, all safe-by-construction

## Feature Flags

- `enrichment` (default) — enables OSV/KEV vulnerability enrichment, EOL detection, and VEX support

## Go and Swift Bindings MVP

The repository now includes a C-compatible ABI layer in [src/ffi.rs](src/ffi.rs) for the Go and Swift MVP bindings.

- The ABI surface is intentionally narrow: format detection, parse from path/string, diffing, quality scoring (by profile, or with options), compliance validation, the rule catalogue, and ABI version reporting.
- The compliance calls take a JSON options object and build each run through `ComplianceRunConfig` with the parsers the CLI flags use, and return the bytes `validate -o json` and `rules -o json` print (pinned by `tests/ffi_compliance.rs`).
- All complex values cross the ABI as JSON strings rather than field-by-field structs. This keeps the ABI stable for both `cgo` and Swift while allowing the Rust data model to evolve internally.
- The stable header lives at [bindings/swift/Sources/CSbomTools/include/sbom_tools.h](bindings/swift/Sources/CSbomTools/include/sbom_tools.h). Both wrappers consume that same header.
- The Go wrapper lives in [bindings/go](bindings/go) and the Swift package lives in [bindings/swift](bindings/swift).
- Errors are mapped into stable numeric codes plus UTF-8 messages, and every ABI result must be released with `sbom_tools_string_result_free`.
- Both wrappers expose opt-in deduplication helpers for normalized payloads. Components deduplicate by canonical identifier, edges deduplicate by full edge shape, and last occurrence wins in both cases.
- Dedup regression checks are centralized in [scripts/test-bindings-dedup.sh](scripts/test-bindings-dedup.sh) and are invoked by bindings CI to keep Go and Swift helper behavior aligned.

## Testing

- 912+ tests (unit + integration)
- Property-based testing via `proptest` (matching symmetry, score range, self-match)
- Fuzz targets for all parser formats (`cargo-fuzz`)
- Golden fixture tests for format compatibility
- Integration tests in `tests/` covering pipeline, CLI, CRA, query, VEX, watch, and graph

## CI/CD

- 10 CI jobs: lint, MSRV, 4 platform tests, 2 cargo-deny, security audit, gate
- CodeQL for static analysis
- OpenSSF Scorecard for security posture
- Trusted Publishing (OIDC) for crates.io releases
- SLSA Build Level 3 provenance for releases
