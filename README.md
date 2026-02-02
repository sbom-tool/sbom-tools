# sbom-tools

A semantic SBOM (Software Bill of Materials) diff and analysis tool. Compare, validate, and assess the quality of SBOMs across CycloneDX and SPDX formats.

## Features

- **Semantic Diffing** — Component-level change detection (added, removed, modified), dependency graph diffing, vulnerability tracking, and license change analysis
- **Multi-Format Support** — CycloneDX (1.4–1.6) and SPDX (2.2–2.3) in JSON, XML, tag-value, and RDF/XML with automatic format detection
- **Fuzzy Matching** — Multi-tier matching engine using exact PURL match, alias lookup, ecosystem-specific normalization, and string similarity (Jaro-Winkler, Levenshtein)
- **Vulnerability Enrichment** — Integration with OSV and KEV databases to track new and resolved vulnerabilities (feature-gated)
- **Quality Assessment** — Score SBOMs against compliance standards including NTIA minimum elements, FDA, and CRA (Cyber Resilience Act)
- **Fleet Comparison** — 1:N baseline comparison, timeline analysis across versions, and NxN matrix analysis
- **Multiple Output Formats** — JSON, SARIF, HTML, Markdown, CSV, table, side-by-side, summary, and an interactive TUI
- **Ecosystem-Aware** — Configurable per-ecosystem normalization rules, typosquat detection, and cross-ecosystem package correlation

## Installation

### Prerequisites

- Rust toolchain (1.70+)

### Build from source

```sh
# Release build (includes vulnerability enrichment by default)
cargo build --release

# Without enrichment (lightweight build)
cargo build --release --no-default-features

# With ML-based matching (optional)
cargo build --release --features ml-matching
```

The binary is placed at `target/release/sbom-tools`.

## Usage

### Compare two SBOMs

```sh
sbom-tools diff old-sbom.json new-sbom.json
```

### View a single SBOM

```sh
sbom-tools view sbom.json
```

### Validate against a compliance standard

```sh
sbom-tools validate sbom.json
```

### Assess SBOM quality

```sh
sbom-tools quality sbom.json
```

### Compare one baseline against multiple targets

```sh
sbom-tools diff-multi baseline.json target1.json target2.json target3.json
```

### Analyze SBOM evolution over time

```sh
sbom-tools timeline v1.json v2.json v3.json
```

### All-pairs comparison matrix

```sh
sbom-tools matrix sbom1.json sbom2.json sbom3.json
```

### Generate shell completions

```sh
sbom-tools completions bash > ~/.local/share/bash-completion/completions/sbom-tools
```

### Global flags

| Flag | Description |
|------|-------------|
| `-v, --verbose` | Enable debug output |
| `-q, --quiet` | Suppress non-essential output |
| `--no-color` | Disable colored output |

### Output formats

Select with `--format`:

`auto` (default, detects TTY), `tui`, `json`, `sarif`, `markdown`, `html`, `summary`, `table`, `side-by-side`, `csv`

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | No changes detected (or `--no-fail-on-change`) |
| `1` | Changes detected |
| `2` | New vulnerabilities introduced (`--fail-on-vuln`) |
| `3` | Error |

## Configuration

sbom-tools looks for configuration in the following order:

1. CLI argument: `--ecosystem-rules <path>`
2. Environment variable: `SBOM_TOOLS_ECOSYSTEM_RULES`
3. Project local: `.sbom-tools/ecosystem-rules.yaml`
4. User config: `~/.config/sbom-tools/ecosystem-rules.yaml`

See [`examples/ecosystem-rules.yaml`](examples/ecosystem-rules.yaml) for a full configuration example covering per-ecosystem normalization, aliases, matching presets, and enrichment settings.

### Matching presets

| Preset | Description |
|--------|-------------|
| `strict` | Exact matches only |
| `balanced` | Default — uses normalization and moderate similarity thresholds |
| `permissive` | Aggressive fuzzy matching for noisy SBOMs |

## Project structure

```
src/
  main.rs          CLI entry point
  lib.rs           Library interface
  cli/             Command handlers
  config/          Configuration loading and validation
  parsers/         Format detection and parsing
  model/           Canonical data model (NormalizedSbom, Component, CanonicalId)
  matching/        Fuzzy matching engine
  diff/            Semantic diff engine
  quality/         Quality scoring and compliance checking
  enrichment/      OSV/KEV vulnerability enrichment
  reports/         Report generation (JSON, SARIF, HTML, etc.)
  tui/             Interactive terminal UI
  pipeline/        Data processing pipeline
  utils/           Utilities
tests/             Integration tests and fixtures
benches/           Performance benchmarks
docs/              Architecture documentation
examples/          Example configuration files
```

## Testing

```sh
# Run all tests
cargo test

# Run benchmarks
cargo bench
```

## Documentation

- [Architecture overview](docs/ARCHITECTURE.md)
- [Pipeline diagrams](docs/pipeline-diagrams.md)

## License

[MIT](LICENSE)
