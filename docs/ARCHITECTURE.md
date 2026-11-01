# Architecture

## Overview
sbom-tools follows a linear pipeline that normalizes inputs, performs semantic
diffing and scoring, and renders the result through reports or the TUI.

```
SBOM/CBOM/AI-BOM files
  -> parsers (CycloneDX 1.4-1.7, SPDX 2.2/2.3, SPDX 3.0 JSON-LD; streaming for large files)
  -> NormalizedSbom (canonical model, incl. CryptoProperties)
  -> BomProfile detection (SBOM / CBOM / AI-BOM auto-detect)
  -> matching (PURL, cross-ecosystem gate, name identity, alias, fuzzy, LSH index)
  -> diff engine (semantic + graph)
  -> DiffResult / QualityReport (profile-aware: Standard, CBOM, or AI-readiness scoring)
  -> reports (json/ndjson/sarif/oscal-json/html/markdown/csv/summary/table/side-by-side;
     sbomqs-json on `quality`) or TUI
```

## Core Modules

- **cli** (`src/cli/`): Clap command handlers for diff, view, validate, quality, query, diff-multi, timeline, matrix, watch, enrich, tailor, merge, convert, license-check, verify, vex, cache, cra-docs, cra-standards-watch, config, completions, config-schema, and man.
- **config** (`src/config/`): Typed configuration with YAML/JSON support, presets, validation, and schema generation.
- **parsers** (`src/parsers/`): CycloneDX (1.4–1.7, JSON/XML) and SPDX (2.2/2.3 plus SPDX 3.0 JSON-LD via a separate `spdx3.rs` parser) format detection and parsing into NormalizedSbom. Includes a streaming parser for memory-efficient parsing of large files with progress callbacks; inputs are capped at 512 MB (`MAX_SBOM_FILE_SIZE`). The CycloneDX parser resolves every internal ref (`dependencies[].ref`/`dependsOn`, `vulnerabilities[].affects[].ref`, and the CDXA refLinks below) through one `id_map`: bom-refs are registered during the component walk, and component purls are merged in afterwards as **fallback keys**, so a genuine bom-ref always wins a collision while purl-keyed edges and CVE affects still resolve instead of being dropped. The parser also captures the CycloneDX top-level `version` revision counter into `DocumentMetadata.doc_version`.
- **model** (`src/model/`): Canonical data model — NormalizedSbom, Component, CanonicalId, DocumentMetadata (incl. `doc_version`), Vulnerability, DependencyEdge, License, CryptoProperties, BomProfile. Includes CycloneDX 1.6/1.7 crypto types (CryptoAssetType, AlgorithmProperties, CertificateProperties, RelatedCryptoMaterialProperties, ProtocolProperties) and the normalized CDXA attestation model (`attestation.rs`: AttestationDeclarations, EvidenceLevel, AttestationRuleFamily, CdxaResolution — see "Attestation Evidence Ingestion" below).
- **matching** (`src/matching/`): Multi-tier fuzzy matching for component alignment.
  - Tiered scoring, in priority order: exact normalized PURL → 1.0; cross-ecosystem gate (known-different ecosystems match only via the curated equivalence DB in `cross_ecosystem.rs`, penalized and floored per config); name identity, ecosystem-normalized or case-insensitive → 1.0; alias table (opt-in) → 0.95; fuzzy/multi-field string similarity (Jaro-Winkler, Levenshtein), capped at 0.99 when names differ.
  - Adaptive threshold analysis (`adaptive.rs`) that derives a recommended threshold from the score distribution (target match ratio, Otsu, knee detection). It is a reporting facility exposed by `diff --recommend-threshold`, not a step in the scoring path — the matcher always applies the configured threshold.
  - LSH (locality-sensitive hashing) index for fast candidate lookup.
  - Custom rule engine for user-defined matching rules.
- **diff** (`src/diff/`): Semantic diff engine with graph-aware dependency diffing, incremental diff tracking, and cost-model scoring. Component changes carry a resolved `component_type` (crypto assets resolve to `algorithm`/`certificate`/`protocol`/`key-material`, ML components to `machine-learning-model`/`data`); document-level metadata changes — including `doc_version` — are recomputed on every path (full and incremental) rather than cached. `QualityDelta` is profile-aware: when both sides detect as CBOM they are scored under `ScoringProfile::Cbom` and the per-category deltas carry the crypto category names; mixed pairs fall back to the generic categories, and an N/A slot (PQC without algorithms) is omitted.
- **enrichment** (`src/enrichment/`): OSV and KEV vulnerability database integration, EPSS exploit-probability scores, EOL detection via endoflife.date API, package-registry staleness detection, Hugging Face model-registry metadata, and VEX ingestion (feature-gated behind `enrichment`). Includes file-based caching with TTL and staleness tracking, plus an offline mode served purely from cache.
- **quality** (`src/quality/`): 8-category quality scoring engine with profile-aware weights (Standard, Security, CRA, BSI, CBOM, AI-readiness, etc.). CBOM profile scores algorithm strength, PQC readiness, OID coverage, crypto completeness, key/cert lifecycle, and cross-reference resolution with hard caps for broken cryptography; its embedded compliance run is NIST PQC (IR 8547), not the generic package checks. File and `cryptographic-asset` components are not package-scoped (`ComponentType::is_package_scoped`), so package-only elements (version, supplier, license, unique identifier, hash, dependency coverage) are neither required of them by compliance nor counted against them by the quality metrics. `CryptographyMetrics::{quantum_readiness_score, pqc_readiness_score}` return `Option<f32>` and are `None` when a document declares no algorithms at all — never a vacuous 100 — and the CBOM scorer redistributes the PQC weight proportionally across the remaining slots. Compliance checks against 16 selectable standards: NTIA, FDA, CRA Phase 1/2, CRA Art. 24 (OSS steward), BSI TR-03183-2 v2.1.0, NIST SSDF, EO 14028, CNSA 2.0, NIST PQC (IR 8547), EUCC, EU AI Act, BSI/G7 SBOM-for-AI, CISA 2026 Minimum Elements, PCI DSS Req. 6.3.2, and CISA FSCT 3rd ed.
  - Checker modules live one-per-standard-family under `src/quality/compliance/` (`bsi.rs`, `bsi_sbom_for_ai.rs`, `cisa2026.rs`, `cra.rs`, `crypto.rs`, `eo14028.rs`, `eu_ai_act.rs`, `eucc.rs`, `fsct.rs`, `generic.rs`, `pci_dss.rs`, `ssdf.rs`) over shared infrastructure (`registry.rs` rule registry and the per-level rule lists of `rules_for_level()`, `catalog.rs` rule catalogue behind `sbom-tools rules`, `selector.rs` standard/alias parsing, `context.rs` dispatch + attestation exposure, `shared.rs`/`ai_shared.rs` helpers). Every check is its own SARIF rule (the registry key is the SARIF rule id; until v0.4.0 dozens of checks shared bucket rules such as `SBOM-QUALITY-GENERAL` or `SBOM-CRA-ANNEX-I`). Every family also has a `SBOM-<FAMILY>-GENERAL` fallback rule that **no check site emits**: `generic_rule_id_for_level()` (`mod.rs`) files a finding without a registered rule under it, and no per-standard SARIF catalogue lists it. The counts below are *firing* rules and exclude it; the per-rule matrix tests under `tests/rule_matrix_*.rs` cover every rule but the fallbacks.
  - `cisa2026.rs` — CISA/NSA/FBI "2026 Minimum Elements for an SBOM" v2.1 (`SBOM-CISA2026-*`, 17 firing rules — 18 registry ids, the extra being the non-firing `SBOM-CISA2026-GENERAL` fallback). Deliberately stricter than the NTIA profile: an explicit `NOASSERTION`/`NONE`/`UNKNOWN` sentinel *satisfies* the honesty requirement on several elements while silent absence fails — the complement of the NTIA presence gates, where the same sentinels count as missing. Like FSCT, it gates checks by format: Author Signature, Generation Context and Coverage do not run on SPDX 2.x, which has no field for a signature, a lifecycle phase or a completeness declaration.
  - `pci_dss.rs` — PCI DSS v4.0.1 Requirement 6.3.2 software-inventory profile (`SBOM-PCI-*`, 10 firing rules — 9 × `SBOM-PCI-6-3-2-*` plus `SBOM-PCI-11-3-1-1-SEVERITY`; 11 registry ids, the extra being the non-firing `SBOM-PCI-GENERAL` fallback), with companions 6.3.1/11.3.1.1 as proxies where the SBOM embeds vulnerability data. No format gate (PCI DSS prescribes no SBOM schema). A passing verdict is evidence the inventory exists and is usable — not a PCI DSS compliance certification.
  - `fsct.rs` — CISA "Framing Software Component Transparency" 3rd ed. (2024) (`SBOM-FSCT-*`, 28 firing rules — 29 registry ids, the extra being the non-firing `SBOM-FSCT-GENERAL` fallback). The document's maturity tiers map onto severities: Minimum Expected → Error, Recommended Practice → Warning, Aspirational Goal → Info. Several checks are format-gated so absence never false-fails a format whose parsed model cannot carry the evidence.
- **pipeline** (`src/pipeline/`): Orchestrates the parse → enrich → diff → report workflow. Handles stage sequencing and output routing.
- **reports** (`src/reports/`): Report generators for JSON, NDJSON, SARIF, OSCAL 1.2.3 assessment-results (validate), HTML, Markdown, CSV, summary, table, and side-by-side formats. Includes a streaming reporter for large outputs. `sbomqs_compat.rs` is an interoperability view, not a scoring engine: it recomputes interlynk-io/sbomqs **v2.1.2** legacy (v1) engine feature scores straight from the NormalizedSbom (plus the raw document text for file-format detection and the document licenses) and emits them in the exact shape of `sbomqs score --legacy --json`. It never reads `QualityReport` — the 0-100 pipeline and the sbomqs 0-10 model use different taxonomies, weights, and missing-data semantics, so dividing by 10 is not an sbomqs-comparable number. It backs the `quality --output sbomqs-json` format and the 0-10 category table appended to the plain-text quality summary; categories that cannot be computed are emitted as `ignored` with a reason. Per-feature fidelity (exact / approximate / not-computable) is tabulated in `docs/STANDARDS_VERSIONS.md`.
- **tui** (`src/tui/`): Interactive ratatui-based UI for exploring diffs and single SBOMs/CBOMs/AI-BOMs. Supports diff mode, view mode (with SBOM/CBOM/AI-BOM profile-driven tabs), fleet comparison, and timeline views. CBOM mode provides dedicated Algorithms, Certificates, Keys, Protocols, and PQC Compliance tabs with sorting and crypto inventory panels; AI-BOM mode provides Models, Datasets, and AI Readiness tabs plus AI inventory/readiness panels on the Overview.
- **verification** (`src/verification/`): File hash verification (SHA-256/512) and component hash auditing.
- **license** (`src/license/`): License policy engine (allow/deny/review lists) with dependency propagation analysis.
- **serialization** (`src/serialization/`): Raw JSON enrichment, SBOM tailoring (filter), merging with deduplication, and format emit/conversion (backing the `convert` command). The CycloneDX emitter writes `DocumentMetadata.doc_version` back out as the document's top-level `version`, defaulting to `1` only when the source carried none, so a document's revision counter survives a `convert` round-trip.
- **watch** (`src/watch/`): Continuous SBOM monitoring with file watcher, vulnerability alerts, and debounced change detection.

## Data Flow

### Single Diff (`diff` command)

The `diff` command uses the full pipeline:

1. CLI parses arguments and merges config (`src/cli/`, `src/config/`).
2. `pipeline::parse_sbom_with_context()` reads and parses both SBOMs into `ParsedSbom` (preserves raw content for TUI Source tab).
3. Optional enrichment mutates SBOMs in-place with OSV/KEV data (`pipeline::enrich_sbom()`, feature-gated). Currently called from CLI, not pipeline.
4. `pipeline::compute_diff()` builds `DiffEngine` with matching config, rules, and graph options, then diffs.
5. `pipeline::output_report()` selects reporter format, pre-computes CRA compliance, and writes to file or stdout. For TUI output, raw content is preserved; for non-TUI, it is dropped to save memory.

### Multi-SBOM Commands (`diff-multi`, `timeline`, `matrix`)

Multi-SBOM commands reuse the pipeline for parsing and enrichment, then use `MultiDiffEngine` directly:

```
cli/multi.rs
  -> pipeline::parse_sbom_with_context() per path (+ optional enrichment)
  -> FuzzyMatchConfig + optional matching rules (load_multi_rules)
  -> MultiDiffEngine::new()
  -> .diff_multi() / .timeline() / .matrix()
  -> JSON or TUI output only
```

Key differences from single-diff:
- Typed `MultiDiffConfig` (baseline/targets, enrichment, filtering, graph-diff, output sections)
- No report format variety — JSON or TUI only. `-o` is a restricted enum (`auto|tui|json`) declared on the commands themselves, so `--help` lists exactly those and an unsupported value is a clap usage error (exit 3) before any SBOM is read
- No streaming support
- Timeline JSON carries `incremental_pairs` / `cumulative_pairs` alongside `incremental_diffs` / `cumulative_from_first`: index-aligned `{from_index, to_index, from_name, to_name}` records, so a consumer never has to infer which pair an array position refers to

### Query Command (`query`)

The `query` command searches for components across multiple SBOMs:

```
cli/query.rs
  -> parse_multiple_sboms() (reused from multi.rs)
  -> Optional: enrich_sbom() / enrich_eol() (feature-gated)
  -> For each SBOM: NormalizedSbomIndex::build()
  -> QueryFilter::matches() on each component via ComponentSortKey
  -> Deduplicate by (name_lower, version), merge found_in sources
  -> Output: table (default), JSON, or CSV
```

Key design:
- Reuses `parse_multiple_sboms()` and `get_sbom_name()` from `cli/multi.rs`
- Supports optional enrichment (OSV vulns + EOL) before searching
- Version filter tries semver range parsing first (for `<2.17.0`), falls back to exact match
- All filters are AND-combined; pattern filter uses `ComponentSortKey::contains()` for broad matching
- Deduplication groups by `(name_lower, version)` and merges `found_in` sources and vulnerability IDs
- Exit code 1 if no matches (useful for CI gate checks)

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

The TUI has two independent app types:

- **DiffApp** (`src/tui/app.rs`, `src/tui/views/`): Handles diff mode with `App` struct holding all state — 10 tabs (Summary, Components, Dependencies, Licenses, Vulnerabilities, Quality, Compliance, Side-by-Side, Graph, Source; Graph appears only when the diff contains graph changes, and Source takes key `9` in its absence and `0` when it is present). Digit keys are reserved for tab jumps in diff mode — per-tab filters live behind letter keys and modals instead. Multi-diff, timeline, and matrix modes reuse the same `App` but render full-screen dashboards with panel navigation instead of tabs (no tab bar, so no digit dispatch). Uses `ViewState` trait with per-tab state structs for all tabs.

- **ViewApp** (`src/tui/view/app.rs`, `src/tui/view/views/`): Handles single-SBOM/CBOM/AI-BOM view mode. Profile-driven tab system via `ViewTab::tabs_for_profile(BomProfile)` — SBOM mode shows 8 tabs, CBOM mode shows 8 crypto-specific tabs, AI-BOM mode shows 6 tabs (Overview, Models, Datasets, AI Readiness, Compliance, Source). Quality scoring uses `ScoringProfile::Cbom` when CBOM is detected. Runtime toggle via `P` key re-scores with the selected profile.

Both app types share rendering utilities in `src/tui/shared/` (quality charts, component info, theme) and use `RenderContext` for read-only frame preparation.

Color is resolved once at startup by `theme::startup_theme(no_color_flag, prefs_name)`: either the `--no-color` flag *or* a non-empty `NO_COLOR` environment variable forces the monochrome theme regardless of the saved preference, and monochrome is sticky — the `T` theme rotation cannot reintroduce hue for those users. `NO_COLOR=` (empty) counts as unset, matching the check the CLI applies to log and report output, so one invocation cannot be monochrome in one surface and colored in another.

## Invariants and Conventions

- NormalizedSbom is the single source of truth for parsed data.
- Components are keyed by CanonicalId for stability across formats.
- DiffResult summary values are derived from change lists.
- Similarity/deviation scales are fixed and test-pinned: `DiffResult.semantic_score` is **0-100** (single-diff scale), `MatrixResult::similarity_scores` is **0-1** (`semantic_score / 100`), and multi-SBOM `deviation_scores`/`max_deviation` are **0-1** (`1 - similarity`).
- Multi-SBOM aggregation (variable/inconsistent/divergent/evolution entries) is keyed by the **version-stripped logical purl**, so a version bump is one component with a version spread rather than an Added + Removed pair.
- Absence of data is never rendered as absence of risk: an empty vulnerability list, a document with no crypto assets, and an unavailable graph diff each render as an explicit "no data" state, not as a clean/100% result.
- TUI layers should align selection/sort with the same source lists.
- Builders use `with_*` naming and `mut self -> Self` pattern.
- Error handling: thiserror for library code, anyhow for CLI.
- No `&String`, `&Vec<T>`, `Box<dyn Error>`, or production panics.

## Extension Points

- **Matching rules**: Configurable matching behavior via YAML configs and custom rule engine.
- **Enrichment**: OSV/KEV integration for vulnerability data and EOL detection via endoflife.date API (feature-gated).
- **Reports**: Add new generators by implementing ReportGenerator.
- **Compliance**: Add new standards by extending the compliance engine (`src/quality/compliance/`) and its `StandardSelector`/`rule_meta()` registry (currently: NTIA, FDA, CRA Phase 1/2, CRA Art. 24, BSI TR-03183-2, NIST SSDF, EO 14028, CNSA 2.0, NIST PQC, EUCC, EU AI Act, BSI/G7 SBOM-for-AI, CISA 2026 Minimum Elements, PCI DSS 6.3.2, CISA FSCT 3rd ed.). A registry-driven per-rule test matrix (`tests/rule_matrix_*.rs`, shared runner in `tests/common/rule_matrix.rs`) gives every rule in a covered profile a firing fixture and a silent fixture — or an explicit skip-with-reason — and enforces exhaustiveness against that profile's rule list (`rules_for_level()`, which is also its SARIF `rules[]`), so a new rule cannot land untested; every matrix fixture is also run at every other level, which must report only rules of its own list. `tests/rule_matrix_registry.rs` additionally enforces that every id in `all_rule_ids()` resolves via `rule_meta()` and belongs to a level's list or is a fallback rule.
- **CBOM Scoring**: Add new crypto quality categories by extending `CryptographyMetrics` and adding scoring methods. New `ScoringProfile` variants can define custom weight distributions.
- **BOM Profiles**: Add new profile types beyond SBOM/CBOM/AI-BOM by extending `BomProfile` enum and `tabs_for_profile()`.

## Attestation Evidence Ingestion (CDXA, phase 1)

CycloneDX 1.6 introduced Attestations (CDXA): a root-level `declarations` object
(assessors, attestations, claims, evidence, targets, affirmation) plus
`definitions.standards` — machine-readable standard encodings whose requirements
attestations map claims onto. Phase 1 ingests this evidence from documents the
tool already loads; no new I/O surface is involved.

- **Parsing** (`src/parsers/cyclonedx.rs`): the JSON parser deserializes
  `declarations` + `definitions.standards` on `specVersion >= 1.6` only (the
  section is never probed on earlier documents, and its absence is never a
  violation). All CDXA refLinks (`claim.target`, `map[].requirement`,
  `claims[]/evidence[]` lists) are resolved at parse time against
  declarations-local bom-refs, standard/requirement bom-refs,
  `declarations.targets` entries, and the BOM inventory — through the same
  id_map (bom-refs plus purl-fallback keys) used for dependencies and
  vulnerability affects. Unresolvable refs are kept and marked `Dangling`
  (parse never fails) and fail closed at query time. XML declarations are not
  yet normalized.
- **Model** (`src/model/attestation.rs`): normalized `AttestationDeclarations`
  attached at `FormatExtensions::declarations` (accessor:
  `NormalizedSbom::declarations()`). Additive **in the NormalizedSbom's own
  serde output**: the field is `#[serde(default, skip_serializing_if =
  "Option::is_none")]`, so a serialized NormalizedSbom gains a `declarations`
  key only when the source document carried the section, and documents without
  declarations serialize byte-identically to previous releases. This is a
  statement about the model, not about emitted BOMs — the CycloneDX emitter has
  no declarations path, so `convert` **drops** both `declarations` and
  `definitions` (converting
  `tests/fixtures/cyclonedx/declarations-cdxa.cdx.json --to cyclonedx` yields a
  document carrying neither). CDXA is read-only, which is why
  `docs/cyclonedx-tool-center-submission.md` declines the CDXA capability.
  When present, the declarations are folded into the SBOM content hash so
  attestation changes are visible to diff identity.
- **Compliance exposure** (`src/quality/compliance/context.rs`):
  `ComplianceContext::attestation_declarations()` and
  `ComplianceContext::evidence_for(AttestationRuleFamily)` return requirements
  fully supported by resolved evidence, evaluated at the checker's injectable
  clock (`--as-of`): expired (`expires <= as_of`) or future-created evidence
  never counts, partial conformance (`score < 1`) never auto-satisfies, counter
  claims/evidence disqualify, and unknown (standard, requirement) pairs are
  recorded but satisfy nothing. Known families: NIST SSDF practice identifiers,
  EO 14028, EU CRA.
- **Consumers**: the evidence is folded into *existing* rules rather than a new
  standard — `ssdf.rs` (practice identifiers such as PS.1/PO.3/PW.6),
  `eo14028.rs` (4(e) provenance), `cra.rs` (conformity route) and `eucc.rs`
  (EUCC / Common Criteria certification). Evidence only ever strengthens a
  verdict: every pre-existing satisfaction path remains valid as a
  `SelfDeclared`-level fallback, and on documents without `declarations` the
  attestation predicates are uniformly false, so those documents score exactly
  as before. When a rule still fires on a document that *does* carry
  declarations, `cdxa_note()` appends either the specific fail-closed rejection
  reason (expired, dangling, partial, countered, future-dated) or a pointer that
  a machine-readable CDXA attestation is an accepted evidence path; messages on
  declaration-free documents stay byte-identical.
- **Verification scope — structural only**: JSF signature objects are recorded
  as PRESENCE (algorithm, keyId, signer count, signatory identity) and never
  cryptographically verified. Evidence levels are ordered `SelfDeclared <
  Structural < SignaturePresent < SignatureVerified`; phase 1 emits at most
  `SignaturePresent`. `SignatureVerified` is reserved for a future JSF/DSSE
  verification phase.
- **Out of scope (phase 2)**: external in-toto attestation bundles
  (`*.intoto.jsonl`, DSSE envelopes, SLSA provenance/VSA, test-result and vulns
  predicates) — a later phase with its own strict-discovery loader; no CLI
  surface exists for it today.

## Known Technical Debt

- Multi-SBOM fleet commands (diff-multi, timeline, matrix) support enrichment but remain limited to JSON/TUI output — `-o` accepts only `auto|tui|json`, and anything else is rejected as a clap usage error before parsing begins.
- Enrichment is orchestrated by CLI, not the pipeline module.
- TUI has two parallel app types (DiffApp for diff modes, ViewApp for view mode) — intentionally separate but share rendering utilities.
- SPDX 3.0 parser does not extract crypto properties (CycloneDX-only for CBOM).
- CDXA `declarations` are normalized from CycloneDX JSON only; the XML path leaves them unparsed.
- ~2,400 tests (~1,730 unit + ~700 integration, counted by test attribute) across 64 integration test suites.
