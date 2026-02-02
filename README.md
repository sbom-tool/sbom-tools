<p align="center">
  <img src="assets/logo.png" alt="SBOM Tools logo" width="200">
</p>

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

#### Common diff options

| Flag | Description |
|------|-------------|
| `--fail-on-change` | Exit with code 1 if changes are detected |
| `--fail-on-vuln` | Exit with code 2 if new vulnerabilities are introduced |
| `--ecosystem-rules <path>` | Load custom per-ecosystem normalization rules |
| `--fuzzy-preset <preset>` | Matching preset: `strict`, `balanced` (default), `permissive` |
| `--enrich-vulns` | Query OSV/KEV databases for vulnerability data |
| `--detect-typosquats` | Flag components that look like known-package typosquats |
| `--explain-matches` | Show why each component pair was matched |

#### Example output

```
sbom-tools diff old-sbom.json new-sbom.json --enrich-vulns

SBOM Diff: old-sbom.json → new-sbom.json

Components: 142 → 145 (+5 added, -2 removed, ~3 modified)

 + pkg:npm/express@4.19.2           (added)
 + pkg:npm/zod@3.23.8               (added)
 + pkg:npm/opentelemetry-api@1.9.0  (added)
 + pkg:npm/ws@8.18.0                (added)
 + pkg:npm/pino@9.3.2               (added)
 - pkg:npm/body-parser@1.20.2       (removed)
 - pkg:npm/winston@3.11.0           (removed)
 ~ pkg:npm/lodash@4.17.20 → 4.17.21  (version bump)
 ~ pkg:npm/axios@1.6.0 → 1.7.4       (version bump)
 ~ pkg:npm/semver@7.5.4 → 7.6.3      (version bump)

Vulnerabilities:
 ✗ CVE-2024-29041 (HIGH) — express <4.19.2  [resolved by upgrade]
 ✗ CVE-2024-4068  (HIGH) — braces <3.0.3    [new, in transitive dep]

License changes: none
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
| `0` | No changes detected (or without `--fail-on-change`) |
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

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for a detailed overview of the codebase layout, module responsibilities, and data flow.

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

## Contributing

Contributions are welcome! Please open an issue to discuss your idea before submitting a pull request. Make sure `cargo test` passes and follow the existing code style.

## License

[MIT](LICENSE)
