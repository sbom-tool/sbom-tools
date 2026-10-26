# Pipeline Diagrams

Conceptual process flows for non-stateful pipelines. These focus on data flow and
decision points rather than UI states.

## Ref Resolution (CycloneDX parser)
Source: `src/parsers/cyclonedx.rs`

Every intra-document reference in a CycloneDX BOM resolves through one
`id_map: HashMap<String, CanonicalId>`, built in a fixed order so that a real
`bom-ref` can never be shadowed by a purl.

```mermaid
flowchart TD
    A[CycloneDX BOM] --> B["Walk metadata.component + components:<br/>register bom-ref as key, collect purl as fallback key"]
    B --> C["Walk services (SaaSBOM 1.4+): register bom-ref as key"]
    C --> D["Merge purl fallbacks with entry().or_insert()<br/>bom-refs win collisions; earliest component wins purl duplicates"]
    D --> E["Resolve dependencies[].ref / dependsOn"]
    D --> F["Resolve vulnerabilities[].affects[].ref"]
    D --> G{"specVersion >= 1.6 AND<br/>declarations or definitions.standards present?"}
    G -->|no| H["extensions.declarations = None<br/>serialized output unchanged"]
    G -->|yes| I["convert_declarations(): resolve CDXA refLinks<br/>claim.target, map[].requirement, claims[]/evidence[]"]
    I --> J{ref resolves?}
    J -->|yes| K[Resolved]
    J -->|no| L["Dangling: kept, never a parse error,<br/>fails closed at query time"]
```

Before this merge step, a `dependsOn` entry or a vulnerability `affects[].ref`
written as a purl — common when components declare no `bom-ref` at all — simply
failed to resolve and the edge or CVE link was dropped silently.

## Diff Pipeline (DiffEngine::diff)
Source: `src/diff/engine.rs`

```mermaid
flowchart TD
    A[NormalizedSbom old/new] --> B{"content_hash equal AND not --include-unchanged?"}
    B -->|yes| C[Return empty DiffResult, semantic_score 100]
    B -->|no| D[Match components]
    D --> E[Compute component changes]
    E --> F[Compute dependency changes]
    F --> G[Compute license changes]
    G --> H[Compute vulnerability changes]
    H --> H1["Compute metadata changes (always, incl. doc_version)"]
    H1 --> H2[Compute match metrics]
    H2 --> H3{graph diff configured?}
    H3 -->|yes| H4[diff_dependency_graph]
    H3 -->|no| I
    H4 --> I[Compute semantic score 0-100]
    I --> J[Calculate summary]
    J --> K[DiffResult]

    D --> D1[Exact match by CanonicalId]
    D1 --> D2[Collect unmatched old/new]
    D2 --> D3{unmatched old > 50?}
    D3 -->|yes| D4[Parallel fuzzy match]
    D3 -->|no| D5[Sequential fuzzy match]
    D4 --> D6[Merge fuzzy matches]
    D5 --> D6
```

The change sections (components/dependencies/licenses/vulnerabilities) are
gated by `ChangedSections` so the incremental path recomputes only what is
dirty; metadata changes, match metrics, the graph diff, the score and the
summary run on **every** path via the same `compute_sections` /
`finalize_result` pair, so the full and incremental paths cannot drift.

## Matching Pipeline (FuzzyMatcher::match_components)
Source: `src/matching/mod.rs` (with submodules: `scoring.rs`, `string_similarity.rs`, `adaptive.rs`, `lsh.rs`)

Tiers are tried in priority order; the first that fires wins. Identity, alias
and cross-ecosystem tiers carry their own acceptance criteria and bypass the
fuzzy threshold — only the fuzzy/multi-field tier is threshold-gated.

```mermaid
flowchart TD
    A[Component A + Component B] --> B{Normalized PURLs equal?}
    B -->|yes| Z1[Tier 1 - ExactPurl, score 1.0]
    B -->|no| C{Both ecosystems known AND different?}
    C -->|yes| C1{Curated equivalence?}
    C1 -->|no / disabled / unverified| Z5[Rejected, score 0.0]
    C1 -->|yes| C2[base = fuzzy score, minus penalty]
    C2 --> C3{penalized > 0 and >= min_score?}
    C3 -->|yes| Z2[Tier 2 - CrossEcosystem, score = penalized]
    C3 -->|no| Z5
    C -->|no| D{Ecosystem-normalized names equal<br/>or case-insensitive names equal?}
    D -->|yes| Z3[Tier 3 - NameIdentity / EcosystemRule, score 1.0]
    D -->|no| E{Alias table match?}
    E -->|yes| Z4[Tier 4 - Alias, score 0.95]
    E -->|no| G[Tier 5 - fuzzy / multi-field score]
    G --> H{score >= threshold?}
    H -->|yes| Z6[Score = computed]
    H -->|no| Z5

    G --> G1[Jaro-Winkler + Levenshtein, weighted]
    G1 --> G2["max with token similarity and 0.85x phonetic similarity"]
    G2 --> G3[Version match boost]
    G3 --> G4[Cap at 0.99 when names differ]
```

Note: adaptive thresholding (`src/matching/adaptive.rs`) is **not** part of this
scoring path. It is an opt-in analysis tool — `diff --recommend-threshold` runs
`AdaptiveThreshold::compute_threshold()` over the two SBOMs and prints a
recommended threshold and score distribution to stderr; the matcher itself uses
the configured threshold.

## Reporting Pipeline (Reporter selection + generation)
Source: `src/reports/mod.rs`

```mermaid
flowchart TD
    A[Report request] --> B{ReportFormat}
    B -->|Auto| C[SummaryReporter - color-aware]
    B -->|Summary| C
    B -->|Table| D[TableReporter - color-aware]
    B -->|Json| E[JsonReporter]
    B -->|Sarif| F[SarifReporter]
    B -->|OscalJson| E
    B -->|Markdown| G[MarkdownReporter]
    B -->|Html| H[HtmlReporter]
    B -->|SideBySide| I[SideBySideReporter - color-aware]
    B -->|Csv| L[CsvReporter]
    B -->|Ndjson| N[NdjsonReportGenerator]
    B -->|Tui| E
    B -->|SbomqsJson| E

    C --> J[generate_diff_report / generate_view_report]
    D --> J
    E --> J
    F --> J
    G --> J
    H --> J
    I --> J
    L --> J
    N --> J
    J --> K[String output]
    K --> M[write to file/stdout]
```

`create_reporter_with_options(format, use_color)` honours `use_color` for every
colored format (Summary, Table, SideBySide) — `--no-color`, `NO_COLOR`, and a
non-TTY destination all reach the reporter through this one flag.

`SbomqsJson` has no diff/view renderer and falls back to `JsonReporter` here; it
is a `quality`-command format, routed before this factory:

```mermaid
flowchart TD
    A[quality command] --> B{format in QUALITY_OUTPUT_FORMATS?}
    B -->|no| C["Reject up front, listing the supported formats<br/>(no silent text fallback)"]
    B -->|yes| D[QualityScorer::score]
    D --> E{ReportFormat}
    E -->|Json| F[format_quality_json]
    E -->|Sarif| G[format_quality_sarif]
    E -->|SbomqsJson| H[sbomqs_compat::render_json]
    E -->|Auto / Summary| I[format_quality_report]
    I --> I1["+ sbomqs_compat::render_summary_table<br/>(skipped for the AI-readiness profile)"]
    F --> Z[write to file/stdout]
    G --> Z
    H --> Z
    I1 --> Z
```

`sbomqs_compat` recomputes sbomqs v2.1.2 feature scores straight from the
NormalizedSbom (plus the raw document text); it never reads `QualityReport`, so
the 0-10 table and the 0-100 score are independent computations, not a rescale.

## Multi-SBOM Pipeline (diff-multi / timeline / matrix)
Source: `src/cli/multi.rs`, `src/diff/multi.rs`

Multi-SBOM commands reuse the pipeline for parsing and optional enrichment, then use `MultiDiffEngine` directly.

```mermaid
flowchart TD
    A[SBOM paths] --> B[pipeline::parse_sbom_with_context per path + optional enrichment]
    B --> C[FuzzyMatchConfig + optional matching rules]
    C --> D[MultiDiffEngine::new]

    D --> E{Command}
    E -->|diff-multi| F[engine.diff_multi baseline vs targets]
    E -->|timeline| G[engine.timeline sequential diffs]
    E -->|matrix| H[engine.matrix NxN comparison]

    F --> I[MultiDiffResult]
    G --> J[TimelineResult]
    H --> K[MatrixResult]

    I --> L{"Output format (auto / tui / json only)"}
    J --> L
    K --> L
    L -->|TUI| M[App::new_multi_diff/timeline/matrix]
    L -->|JSON| N[serde_json::to_string_pretty]
    N --> O[write to file/stdout]
```

Note: Typed `MultiDiffConfig`; enrichment supported; no streaming; output
limited to JSON or TUI. `-o` is a restricted clap enum on these three commands,
so an unsupported value is a usage error (exit 3) before any SBOM is parsed.

Scale conventions across the multi-SBOM results (test-pinned):

| Value | Scale |
| --- | --- |
| `DiffResult.semantic_score` (single diff) | 0-100 |
| `MatrixResult::similarity_scores` | 0-1 (`semantic_score / 100`) |
| `MultiDiffSummary::deviation_scores` / `max_deviation` | 0-1 (`1 - similarity`) |

Aggregated multi-SBOM entries (variable / inconsistent / divergent / evolution)
are keyed by the **version-stripped logical purl** (e.g. `pkg:npm/express`), so
a version bump appears as one component with a version spread rather than as an
Added + Removed pair. `TimelineResult` additionally carries `incremental_pairs`
and `cumulative_pairs` — index-aligned `{from_index, to_index, from_name,
to_name}` records that label each diff in `incremental_diffs` /
`cumulative_from_first`.

## Vulnerability Enrichment Flow (feature-gated)
Source: `src/pipeline/parse.rs`, `src/cli/diff.rs`

```mermaid
flowchart TD
    A[DiffConfig.enrichment] --> B{enrichment enabled?}
    B -->|no| Z[Skip enrichment]
    B -->|yes| C[Build OsvEnricherConfig]
    C --> D[OsvEnricher::new]
    D --> E{offline mode?}
    E -->|yes| G
    E -->|no| E1{API available?}
    E1 -->|no| F[Warn + skip]
    E1 -->|yes| G["enrich_components_in_place():<br/>take components out of sbom.components"]
    G --> H[enricher.enrich on the component slice]
    H --> I[Put components back under the same keys]
    I --> J[Return EnrichmentStats]
```

The offline bypass matters: the availability probe is a live network call, so in
offline mode it would always fail and wrongly skip enrichment that the cache
could have served.

## EOL Enrichment Flow (feature-gated)
Source: `src/enrichment/eol/`, `src/cli/diff.rs`, `src/cli/view.rs`

```mermaid
flowchart TD
    A[--enrich-eol flag] --> B{flag set?}
    B -->|no| Z[Skip EOL enrichment]
    B -->|yes| C[Build EolClientConfig]
    C --> D[pipeline::enrich_eol]
    D --> E[EolEnricher::new with file cache]
    E --> F[For each component: extract name + version]
    F --> G[Query endoflife.date API]
    G --> H{Product found?}
    H -->|no| I[Skip component]
    H -->|yes| J[Match release cycle]
    J --> K[Classify: Supported / SecurityOnly / ApproachingEol / EndOfLife / Unknown]
    K --> L[Set component.eol = EolInfo]
    L --> M[Component enriched with EOL status]
```
