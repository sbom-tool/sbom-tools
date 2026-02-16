# Pipeline Diagrams

Conceptual process flows for non-stateful pipelines. These focus on data flow and
decision points rather than UI states.

## Diff Pipeline (DiffEngine::diff)
Source: `src/diff/engine.rs`

```mermaid
flowchart TD
    A[NormalizedSbom old/new] --> B{content_hash equal?}
    B -->|yes| C[Return empty DiffResult]
    B -->|no| D[Match components]
    D --> E[Compute component changes]
    E --> F[Compute dependency changes]
    F --> G[Compute license changes]
    G --> H[Compute vulnerability changes]
    H --> I[Compute semantic score]
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

## Matching Pipeline (FuzzyMatcher::match_components)
Source: `src/matching/mod.rs` (with submodules: `scoring.rs`, `string_similarity.rs`, `adaptive.rs`, `lsh.rs`)

```mermaid
flowchart TD
    A[Component A + Component B] --> B{Both have PURL?}
    B -->|match| Z1[Score 1.0]
    B -->|no match| C{Alias table match?}
    C -->|yes| Z2[Score 0.95]
    C -->|no| D{Same ecosystem?}
    D -->|yes| E[Normalize via ecosystem rules]
    E --> F{Normalized names equal?}
    F -->|yes| Z3[Score 0.90]
    F -->|no| G[Compute fuzzy score]
    D -->|no| G
    G --> H{score >= threshold?}
    H -->|yes| Z4[Score = computed]
    H -->|no| Z5[Score 0.0]

    G --> G1[Jaro-Winkler + Levenshtein]
    G1 --> G2[Apply weights]
    G2 --> G3[Version match boost]
    G3 --> G4[Adaptive threshold adjustment]
```

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
    B -->|Markdown| G[MarkdownReporter]
    B -->|Html| H[HtmlReporter]
    B -->|SideBySide| I[SideBySideReporter]
    B -->|Csv| L[CsvReporter]
    B -->|Tui| E

    C --> J[generate_diff_report / generate_view_report]
    D --> J
    E --> J
    F --> J
    G --> J
    H --> J
    I --> J
    L --> J
    J --> K[String output]
    K --> M[write to file/stdout]
```

## Multi-SBOM Pipeline (diff-multi / timeline / matrix)
Source: `src/cli/multi.rs`, `src/diff/multi.rs`

Multi-SBOM commands bypass the standard pipeline and use `MultiDiffEngine` directly.

```mermaid
flowchart TD
    A[SBOM paths] --> B[parse_sbom per path]
    B --> C[FuzzyMatchConfig::from_preset]
    C --> D[MultiDiffEngine::new]

    D --> E{Command}
    E -->|diff-multi| F[engine.diff_multi baseline vs targets]
    E -->|timeline| G[engine.timeline sequential diffs]
    E -->|matrix| H[engine.matrix NxN comparison]

    F --> I[MultiDiffResult]
    G --> J[TimelineResult]
    H --> K[MatrixResult]

    I --> L{Output format}
    J --> L
    K --> L
    L -->|TUI| M[App::new_multi_diff/timeline/matrix]
    L -->|JSON| N[serde_json::to_string_pretty]
    N --> O[write to file/stdout]
```

Note: No enrichment, no DiffConfig, no streaming, no report format variety.

## Vulnerability Enrichment Flow (feature-gated)
Source: `src/pipeline/parse.rs`, `src/cli/diff.rs`

```mermaid
flowchart TD
    A[DiffConfig.enrichment] --> B{enrichment enabled?}
    B -->|no| Z[Skip enrichment]
    B -->|yes| C[Build OsvEnricherConfig]
    C --> D[OsvEnricher::new]
    D --> E{API available?}
    E -->|no| F[Warn + skip]
    E -->|yes| G[Clone components to Vec]
    G --> H[enricher.enrich components]
    H --> I[Re-insert into sbom.components]
    I --> J[Return EnrichmentStats]
```

## EOL Enrichment Flow (feature-gated)
Source: `src/enrichment/eol/`, `src/cli/diff.rs`, `src/cli/view.rs`

```mermaid
flowchart TD
    A[--enrich-eol flag] --> B{flag set?}
    B -->|no| Z[Skip EOL enrichment]
    B -->|yes| C[Build EolEnricherConfig]
    C --> D[pipeline::enrich_eol]
    D --> E[EolClient::new with file cache]
    E --> F[For each component: extract name + version]
    F --> G[Query endoflife.date API]
    G --> H{Product found?}
    H -->|no| I[Skip component]
    H -->|yes| J[Match release cycle]
    J --> K[Classify: Supported / SecurityOnly / ApproachingEol / EndOfLife / Unknown]
    K --> L[Set component.eol = EolInfo]
    L --> M[Component enriched with EOL status]
```
