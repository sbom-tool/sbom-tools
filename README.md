<p align="center">
  <img src="assets/logo.png" alt="sbom-tools logo" width="180">
</p>

<h1 align="center">sbom-tools</h1>

<p align="center">
  Know exactly what changed in your software supply chain — from components to cryptography.
</p>

<p align="center">
  <a href="https://github.com/sbom-tool/sbom-tools/actions/workflows/rust.yml"><img src="https://github.com/sbom-tool/sbom-tools/actions/workflows/rust.yml/badge.svg" alt="build"></a>
  <a href="https://crates.io/crates/sbom-tools"><img src="https://img.shields.io/crates/v/sbom-tools" alt="crates.io"></a>
  <a href="https://docs.rs/sbom-tools"><img src="https://docs.rs/sbom-tools/badge.svg" alt="docs.rs"></a>
  <a href="https://crates.io/crates/sbom-tools"><img src="https://img.shields.io/crates/d/sbom-tools" alt="downloads"></a>
  <a href="https://deps.rs/repo/github/sbom-tool/sbom-tools"><img src="https://deps.rs/repo/github/sbom-tool/sbom-tools/status.svg" alt="dependency status"></a>
  <a href="https://github.com/sbom-tool/sbom-tools"><img src="https://img.shields.io/crates/l/sbom-tools" alt="license"></a>
  <a href="https://github.com/sbom-tool/sbom-tools"><img src="https://img.shields.io/badge/MSRV-1.88-blue" alt="MSRV"></a>
  <a href="https://www.bestpractices.dev/projects/11992"><img src="https://www.bestpractices.dev/projects/11992/badge" alt="OpenSSF Best Practices"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/sbom-tool/sbom-tools"><img src="https://api.scorecard.dev/projects/github.com/sbom-tool/sbom-tools/badge" alt="OpenSSF Scorecard"></a>
</p>

Semantic SBOM/CBOM diff, quality scoring, and analysis tool. Compare, validate, and grade software and cryptographic bills of materials across CycloneDX and SPDX formats.

![sbom-tools diff summary](assets/tui-diff-summary.svg)

## Features

- **Semantic Diffing** — Component-level change detection (added, removed, modified), dependency graph diffing, vulnerability tracking, and license change analysis
- **Multi-Format Support** — CycloneDX (1.4–1.7) and SPDX (2.2–2.3, 3.0) in JSON, JSON-LD, XML, tag-value, and RDF/XML with automatic format detection
- **Streaming Parser** — Memory-efficient parsing for very large SBOMs (>512MB) with progress reporting
- **Fuzzy Matching** — Multi-tier matching engine using exact PURL match, alias lookup, ecosystem-specific normalization, and string similarity with adaptive thresholds and LSH indexing
- **Vulnerability Enrichment** — Integration with OSV and KEV databases to track new and resolved vulnerabilities, with VEX (Vulnerability Exploitability eXchange) overlay support (feature-gated)
- **EOL Detection** — End-of-life status for components via endoflife.date API with TUI visualization and compliance integration (feature-gated)
- **Quality Assessment** — Score SBOMs against compliance standards including NTIA, FDA, CRA (Cyber Resilience Act), NIST SSDF, and EO 14028, with quality delta tracking across versions
- **CBOM Quality Scoring** — Grade cryptographic inventory health across 8 categories: algorithm strength, PQC readiness, OID coverage, crypto completeness, key/certificate lifecycle, and cross-reference resolution, with hard caps for broken cryptography and compromised keys
- **PQC Compliance** — CNSA 2.0 (NSA) and NIST IR 8547 post-quantum cryptography compliance checking with per-algorithm PASS/FAIL assessment
- **Cryptographic Inventory** — Parse CycloneDX 1.6/1.7 `cryptoProperties` (algorithms, certificates, keys, protocols) with auto-detection of CBOM vs SBOM profiles
- **Fleet Comparison** — 1:N baseline comparison, timeline analysis across versions, and NxN matrix analysis, all with enrichment support
- **Incremental Diff** — Section-selective recomputation for partial changes with cached matching results
- **VEX Tracking** — Detect VEX state transitions (NotAffected → Affected) across SBOM versions, with `--fail-on-vex-gap` CI gate
- **Multiple Output Formats** — JSON, SARIF, HTML, Markdown, CSV, table, side-by-side, summary, and an interactive TUI
- **Ecosystem-Aware** — Configurable per-ecosystem normalization rules, typosquat detection, pre-release version handling, and cross-ecosystem package correlation

## Installation

### Homebrew (macOS / Linux)

```sh
brew install sbom-tool/tap/sbom-tools
```

### Pre-built binaries

Download from [GitHub Releases](https://github.com/sbom-tool/sbom-tools/releases/latest):

```sh
# Linux (x86_64)
curl -sSL https://github.com/sbom-tool/sbom-tools/releases/latest/download/sbom-tools-linux-x86_64.tar.gz | tar xz
sudo mv sbom-tools /usr/local/bin/

# macOS (Apple Silicon)
curl -sSL https://github.com/sbom-tool/sbom-tools/releases/latest/download/sbom-tools-macos-aarch64.tar.gz | tar xz
sudo mv sbom-tools /usr/local/bin/

# macOS (Intel)
curl -sSL https://github.com/sbom-tool/sbom-tools/releases/latest/download/sbom-tools-macos-x86_64.tar.gz | tar xz
sudo mv sbom-tools /usr/local/bin/
```

Each pre-built archive is signed with [Sigstore](https://www.sigstore.dev/) and has a [GitHub build attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations). To verify a download:

```sh
# Verify Sigstore signature (requires cosign)
cosign verify-blob \
  --bundle sbom-tools-macos-aarch64.tar.gz.bundle \
  --certificate-identity 'https://github.com/sbom-tool/sbom-tools/.github/workflows/publish-crates.yml@refs/tags/v0.1.19' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  sbom-tools-macos-aarch64.tar.gz

# Verify GitHub attestation (requires gh CLI)
gh attestation verify sbom-tools-macos-aarch64.tar.gz \
  --repo sbom-tool/sbom-tools
```

Replace `v0.1.19` with the version you downloaded. Homebrew users do not need to verify manually — Homebrew validates the source tarball SHA256 automatically.

### From crates.io

```sh
# Fast install (downloads pre-built binary)
cargo binstall sbom-tools

# Or compile from source
cargo install sbom-tools
```

### Build from source

Requires Rust 1.88+.

```sh
# Release build (includes vulnerability enrichment by default)
cargo build --release

# Without enrichment (lightweight build)
cargo build --release --no-default-features
```

The binary is placed at `target/release/sbom-tools`.

### Go and Swift bindings MVP

The repository now includes a shared C ABI plus thin Go and Swift wrappers for the MVP binding surface.

- Shared ABI header: [bindings/swift/Sources/CSbomTools/include/sbom_tools.h](bindings/swift/Sources/CSbomTools/include/sbom_tools.h)
- Go wrapper package: [bindings/go](bindings/go)
- Swift package: [bindings/swift](bindings/swift)

Current ABI scope:

- `detect_format` on raw content
- Parse from file path or raw SBOM string into normalized JSON
- Diff two normalized SBOM JSON payloads
- Score a normalized SBOM JSON payload

Current ABI exclusions:

- CLI subcommands
- TUI and watch mode
- Enrichment providers
- Non-JSON report formats

Build the native Rust library before using either wrapper:

```sh
bash ./scripts/build-bindings-mvp.sh
```

#### Go wrapper

```sh
cd bindings/go
go test ./...
```

Example:

```go
package main

import (
  "fmt"
  "log"

  sbomtools "github.com/sbom-tool/sbom-tools/bindings/go"
)

func main() {
  version, err := sbomtools.Version()
  if err != nil {
    log.Fatal(err)
  }

  parsed, err := sbomtools.ParsePathJSON("../../tests/fixtures/cyclonedx/minimal.cdx.json")
  if err != nil {
    log.Fatal(err)
  }

  fmt.Println(version.ABIVersion)
  fmt.Println(string(parsed))
}
```

#### Swift wrapper

```sh
cd bindings/swift
swift test
```

Example:

```swift
import SbomTools

let version = try SbomTools.version()
let json = try SbomTools.parsePathJSON("../../tests/fixtures/cyclonedx/minimal.cdx.json")

print(version.abiVersion)
print(json)
```

Memory and compatibility rules:

- The Rust ABI owns returned memory and wrappers must call `sbom_tools_string_result_free` exactly once.
- JSON payload shape is the compatibility contract for normalized SBOMs, diff results, and quality reports.
- Error codes are stable across Go and Swift wrappers.

Typed helper APIs are available in both wrappers:

- Go: `ParsePath`, `ParseString`, `Diff`, `Score` over typed payload structs
- Swift: `parsePath`, `parseString`, `diff`, `score` over Codable payload structs

Deduplication helper APIs are available in both wrappers:

- Go payload methods: `DeduplicateInPlace`, `Deduplicated`
- Swift payload methods: `deduplicateInPlace`, `deduplicated`
- Go helper APIs: `DiffDeduplicated`, `ScoreDeduplicated`
- Swift helper APIs: `diffDeduplicated`, `scoreDeduplicated`

Deduplication semantics:

- Components are deduplicated by canonical identifier with last occurrence winning.
- Dependency edges are deduplicated by full edge object equality with last occurrence winning.
- Dedup-aware diff/score helpers are opt-in and return deduplication stats so callers can track normalization impact.

Go dedup-aware helper example:

```go
oldPayload, err := sbomtools.ParsePath("../../tests/fixtures/demo-old.cdx.json")
if err != nil {
  log.Fatal(err)
}

newPayload, err := sbomtools.ParsePath("../../tests/fixtures/demo-new.cdx.json")
if err != nil {
  log.Fatal(err)
}

diff, err := sbomtools.DiffDeduplicated(oldPayload, newPayload)
if err != nil {
  log.Fatal(err)
}

score, err := sbomtools.ScoreDeduplicated(newPayload)
if err != nil {
  log.Fatal(err)
}

fmt.Println(diff.Result.Summary.TotalChanges, diff.NewStats.ComponentsRemoved)
fmt.Println(score.Result.OverallScore, score.Stats.ComponentsRemoved)
```

Swift dedup-aware helper example:

```swift
let oldPayload = try SbomTools.parsePath("../../tests/fixtures/demo-old.cdx.json")
let newPayload = try SbomTools.parsePath("../../tests/fixtures/demo-new.cdx.json")

let diff = try SbomTools.diffDeduplicated(old: oldPayload, new: newPayload)
let score = try SbomTools.scoreDeduplicated(newPayload)

print(diff.result.summary.totalChanges, diff.newStats.componentsRemoved)
print(score.result.overallScore, score.stats.componentsRemoved)
```

ABI contract snapshots are enforced in [tests/ffi_schema_snapshots.rs](tests/ffi_schema_snapshots.rs) using fixtures under [tests/fixtures/abi](tests/fixtures/abi).

Bindings CI checks (dedup-focused):

```sh
# Convenience script (runs both)
./scripts/test-bindings-dedup.sh all

# Go (dedup helper regression checks)
cd bindings/go
go test ./... -run 'TestDeduplicateInPlace_LastWins|TestDeduplicated_DoesNotMutateOriginal|TestDiffAndScoreDeduplicatedHelpers'

# Swift (dedup helper regression checks)
cd ../swift
swift test --filter dedup
```

### Dagger Rust SDK CI/CD

The repository now includes a Dagger Rust SDK runner for bindings CI/CD tasks and static library build/release activities.

- Dagger runner: [dagger/rust-sdk/src/main.rs](dagger/rust-sdk/src/main.rs)
- Commands: `build-staticlib`, `release-staticlib`, `test-abi`, `ci-all`

Run locally:

```sh
cargo run --manifest-path dagger/rust-sdk/Cargo.toml -- ci-all
```

## Usage

```sh
# Compare two SBOMs (launches interactive TUI)
sbom-tools diff old-sbom.json new-sbom.json

# Diff with vulnerability enrichment for CI
sbom-tools diff old.json new.json --enrich-vulns --fail-on-vuln -o sarif

# View SBOM contents interactively
sbom-tools view sbom.json --enrich-vulns

# Search for vulnerable components across your fleet
sbom-tools query "log4j" --version "<2.17.0" fleet/*.json

# Validate against multiple compliance standards
sbom-tools validate sbom.json --standard ntia,cra,eo14028

# Assess quality with CI gate
sbom-tools quality sbom.json --profile security --min-score 70

# Track SBOM evolution over releases
sbom-tools timeline v1.json v2.json v3.json --enrich-vulns

# Enrich an SBOM with vulnerability + EOL data
sbom-tools enrich app.cdx.json --enrich-vulns --enrich-eol -O enriched.json

# Grade cryptographic inventory quality
sbom-tools quality cbom.cdx.json --profile cbom

# View CBOM with crypto-specific tabs
sbom-tools view cbom.cdx.json --bom-type cbom
```

### Diff

```sh
sbom-tools diff old-sbom.json new-sbom.json
```

Compares two SBOMs and reports added, removed, and modified components with version diffs, vulnerability changes, and license deltas.

<details>
<summary>Diff options</summary>

| Flag | Description |
|------|-------------|
| `--fail-on-change` | Exit with code 1 if changes are detected |
| `--fail-on-vuln` | Exit with code 2 if new vulnerabilities are introduced |
| `--fail-on-vex-gap` | Exit with code 4 if introduced vulnerabilities lack VEX statements |
| `--graph-diff` | Enable dependency graph structure diffing |
| `--ecosystem-rules <path>` | Load custom per-ecosystem normalization rules |
| `--fuzzy-preset <preset>` | Matching preset: `strict`, `balanced` (default), `permissive` |
| `--enrich-vulns` | Query OSV/KEV databases for vulnerability data |
| `--enrich-eol` | Detect end-of-life status via endoflife.date API |
| `--vex <path>` | Apply external VEX document(s) (OpenVEX format) |
| `--exclude-vex-resolved` | Exclude vulnerabilities with VEX status `not_affected` or `fixed` |
| `--detect-typosquats` | Flag components that look like known-package typosquats |
| `--explain-matches` | Show why each component pair was matched |
| `--severity <level>` | Filter by minimum severity (`critical`, `high`, `medium`, `low`) |

</details>

<details>
<summary>Example output</summary>

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

</details>

### View

```sh
sbom-tools view sbom.json
```

Launches an interactive TUI with component tree, vulnerability details, license breakdown, and dependency graph.

<details>
<summary>View options</summary>

| Flag | Description |
|------|-------------|
| `--severity <level>` | Filter by minimum vulnerability severity (`critical`, `high`, `medium`, `low`) |
| `--vulnerable-only` | Only show components with known vulnerabilities |
| `--ecosystem <name>` | Filter components by ecosystem (e.g., `npm`, `cargo`, `pypi`) |
| `--enrich-eol` | Detect end-of-life status via endoflife.date API |
| `--validate-ntia` | Validate against NTIA minimum elements |
| `--bom-type <type>` | BOM type override (`sbom`, `cbom`). Auto-detected from content if omitted |

</details>

### Validate

```sh
sbom-tools validate sbom.json --standard ntia
sbom-tools validate sbom.json --standard cra -o sarif -O results.sarif
```

Checks an SBOM against a compliance standard and reports missing fields or failing requirements.

<details>
<summary>Validate options</summary>

| Flag | Description |
|------|-------------|
| `--standard <std>` | Standard to validate: `ntia` (default), `fda`, `cra`, `ssdf`, `eo14028` (comma-separated for multiple) |
| `-o, --output <fmt>` | Output format (default: `json`; supports `sarif` for CI integration) |

</details>

### Quality

```sh
sbom-tools quality sbom.json --profile security --recommendations
```

Scores an SBOM from 0–100 using a weighted profile. Use `--min-score` to fail CI if quality drops below a threshold.

<details>
<summary>Quality options</summary>

| Flag | Description |
|------|-------------|
| `--profile <name>` | Scoring profile: `minimal`, `standard` (default), `security`, `license-compliance`, `cra`, `comprehensive`, `cbom` |
| `--min-score <n>` | Fail if quality score is below threshold (0–100) |
| `--recommendations` | Show detailed improvement recommendations |
| `--metrics` | Show detailed scoring metrics |

</details>

### Query

```sh
sbom-tools query "log4j" sbom1.json sbom2.json sbom3.json
```

Search for components across multiple SBOMs by name, version, ecosystem, license, supplier, or vulnerability ID. Answers the "where is Log4j?" question across your entire SBOM fleet.

<details>
<summary>Query options</summary>

| Flag | Description |
|------|-------------|
| `--name <str>` | Filter by component name (substring) |
| `--version <ver>` | Filter by version — exact match or semver range (e.g., `<2.17.0`) |
| `--ecosystem <eco>` | Filter by ecosystem (e.g., `npm`, `maven`, `pypi`) |
| `--license <str>` | Filter by license (substring) |
| `--purl <str>` | Filter by PURL (substring) |
| `--supplier <str>` | Filter by supplier name (substring) |
| `--affected-by <id>` | Filter by vulnerability ID (e.g., `CVE-2021-44228`) |
| `--enrich-vulns` | Query OSV databases for vulnerability data |
| `--enrich-eol` | Detect end-of-life status via endoflife.date API |
| `--limit <n>` | Maximum number of results |
| `--group-by-sbom` | Group output by SBOM source |

</details>

<details>
<summary>Example output</summary>

```
$ sbom-tools query "log4j" --version "<2.17.0" fleet/*.cdx.json

Query: "log4j" AND version=<2.17.0 across 5 SBOMs (1247 total components)

COMPONENT  VERSION  ECOSYSTEM  LICENSE     VULNS  FOUND IN
log4j      2.14.0   maven      Apache-2.0      1  firmware-v1, device-a
log4j      2.14.1   maven      Apache-2.0      1  gateway

2 components found across 5 SBOMs

$ sbom-tools query --ecosystem pypi *.json --group-by-sbom

Query: ecosystem=pypi across 2 SBOMs (33 total components)

── backend-v3 (4 matches / 18 components) ──
  django 4.2.11 (pypi)
  flask 3.0.2 (pypi)
  celery 5.3.6 (pypi)
  numpy 1.26.4 (pypi)

── backend-v2 (4 matches / 15 components) ──
  django 3.2.23 (pypi)
  flask 2.2.5 (pypi)
  celery 5.3.4 (pypi)
  numpy 1.24.4 (pypi)

8 components found across 2 SBOMs
```

</details>

### Fleet comparison

Compare multiple SBOMs across a project portfolio:

```sh
# Compare a baseline against multiple targets (1:N)
sbom-tools diff-multi baseline.json target1.json target2.json target3.json

# Track evolution over time (provide SBOMs in chronological order)
sbom-tools timeline v1.json v2.json v3.json

# All-pairs comparison matrix (NxN)
sbom-tools matrix sbom1.json sbom2.json sbom3.json
```

### Shell completions

```sh
sbom-tools completions bash > ~/.local/share/bash-completion/completions/sbom-tools
sbom-tools completions zsh > ~/.zfunc/_sbom-tools
sbom-tools completions fish > ~/.config/fish/completions/sbom-tools.fish
```

### Global flags

| Flag | Description |
|------|-------------|
| `-o, --output <fmt>` | Output format (see [Output Formats](#output-formats)) |
| `-v, --verbose` | Enable debug output |
| `-q, --quiet` | Suppress non-essential output |
| `--no-color` | Disable colored output (also respects `NO_COLOR`) |

## Interactive TUI

Both `diff` and `view` commands launch an interactive terminal UI by default when connected to a TTY.

### Diff Mode

Compare two SBOMs with semantic change detection across 9 tabs.

**Summary** — Overall change score with component, vulnerability, and compliance breakdowns at a glance.

![Diff summary](assets/tui-diff-summary.svg)

**Components** — Every added, removed, and modified component with version diffs and ecosystem tags.

![Diff components](assets/tui-diff-components.svg)

<details>
<summary>More diff screenshots</summary>

**Side-by-Side** — Aligned dual-panel comparison with synchronized scrolling.

![Diff side-by-side](assets/tui-diff-sidebyside.svg)

**Source** — Raw SBOM JSON in a synced dual-panel tree view. Press `s` to lock navigation across panels.

![Diff source](assets/tui-diff-source.svg)

**Compliance** — CRA, NTIA, FDA, NIST SSDF, and EO 14028 readiness checks with pass/fail details for each requirement.

![Diff compliance](assets/tui-diff-compliance.svg)

</details>

### View Mode

Explore a single SBOM or CBOM interactively. SBOM mode shows 8 tabs (Overview, Tree, Vulnerabilities, Licenses, Dependencies, Quality, Compliance, Source). CBOM mode auto-detects and shows crypto-specific tabs (Overview, Algorithms, Certificates, Keys, Protocols, Quality, PQC Compliance, Source). Press `P` to toggle between modes.

**Overview** — SBOM metadata, component statistics, and vulnerability summary.

![View overview](assets/tui-view-overview.svg)

**Components** — Expandable component tree grouped by ecosystem.

![View components tree](assets/tui-view-tree.svg)

<details>
<summary>More view screenshots</summary>

**Vulnerabilities** — CVE table with severity, CVSS scores, and affected components.

![View vulnerabilities](assets/tui-view-vulns.svg)

**Quality** — Weighted quality score with category breakdown and improvement recommendations.

![View quality](assets/tui-view-quality.svg)

</details>

### Navigation

| Key | Action |
|-----|--------|
| `1`–`0` / `Tab` | Switch tabs |
| `↑↓` / `jk` | Navigate items |
| `Enter` / `Space` | Expand / collapse |
| `/` | Search |
| `f` | Filter panel |
| `s` | Sync panels (Source) / sort (Algorithms, Vulnerabilities) |
| `w` | Switch focus (Source, Side-by-Side) |
| `P` | Toggle SBOM/CBOM profile |
| `v` | Tree / raw toggle (Source) |
| `e` | Export |
| `T` | Cycle theme |
| `q` | Quit |

## Output Formats

Select with `-o` / `--output`:

| Format | Flag | Use Case |
|--------|------|----------|
| Auto | `auto` | Default — TUI if TTY, summary otherwise |
| TUI | `tui` | Interactive exploration |
| JSON | `json` | Programmatic integration |
| SARIF | `sarif` | CI/CD security dashboards (SARIF 2.1.0) |
| Markdown | `markdown` | Documentation, PR comments |
| HTML | `html` | Stakeholder reports |
| CSV | `csv` | Spreadsheet analysis |
| Summary | `summary` | Terminal quick overview |
| Table | `table` | Aligned, colored terminal output |
| Side-by-side | `side-by-side` | Terminal diff comparison |

## CI/CD Integration

Use sbom-tools in CI pipelines to gate deployments on SBOM changes, new vulnerabilities, or quality regressions.

```sh
# Fail if any components changed
sbom-tools diff old.json new.json --fail-on-change -o summary

# Fail if new vulnerabilities are introduced, output SARIF for dashboards
sbom-tools diff old.json new.json --fail-on-vuln --enrich-vulns -o sarif -O results.sarif

# Fail if introduced vulnerabilities lack VEX statements
sbom-tools diff old.json new.json --fail-on-vex-gap --vex vex.json --enrich-vulns

# Fail if quality score drops below 80
sbom-tools quality sbom.json --profile security --min-score 80 -o json

# Validate CRA compliance
sbom-tools validate sbom.json --standard cra -o sarif -O compliance.sarif

# Check for vulnerable Log4j versions across all SBOMs (exits 1 if found)
sbom-tools query "log4j" --version "<2.17.0" fleet/*.json -o json

# Check license compliance with strict policy
sbom-tools license-check sbom.json --strict --check-propagation
```

<details>
<summary>GitHub Actions — using the action (recommended)</summary>

```yaml
name: SBOM Check

on:
  pull_request:
    paths: ['sbom.json']

jobs:
  sbom-diff:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 2

      - name: Get previous SBOM
        run: git show HEAD~1:sbom.json > /tmp/old-sbom.json

      - name: Diff SBOM
        uses: sbom-tool/sbom-tools-action@v1
        with:
          command: diff
          args: /tmp/old-sbom.json sbom.json
          fail-on-vuln: true
          enrich-vulns: true
          output-format: sarif
          output-file: results.sarif

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif

  sbom-quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Check quality
        uses: sbom-tool/sbom-tools-action@v1
        with:
          command: quality
          args: sbom.json
          profile: security
          min-score: '80'

  sbom-compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Validate CRA compliance
        uses: sbom-tool/sbom-tools-action@v1
        with:
          command: validate
          args: sbom.json
          standard: cra
          output-format: sarif
          output-file: compliance.sarif
```

</details>

<details>
<summary>GitHub Actions — manual binary download</summary>

```yaml
name: SBOM Check

on:
  pull_request:
    paths: ['sbom.json']

jobs:
  sbom-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 2

      - name: Install sbom-tools
        run: |
          curl -fsSL -o sbom-tools.tar.gz \
            https://github.com/sbom-tool/sbom-tools/releases/latest/download/sbom-tools-linux-x86_64.tar.gz
          tar xzf sbom-tools.tar.gz
          sudo mv sbom-tools /usr/local/bin/

      - name: Diff SBOM against main
        run: |
          git show HEAD~1:sbom.json > /tmp/old-sbom.json
          sbom-tools diff /tmp/old-sbom.json sbom.json \
            --fail-on-vuln --enrich-vulns \
            -o sarif -O results.sarif

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

</details>

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success (no changes detected, or run without `--fail-on-change`) |
| `1` | Changes detected (`--fail-on-change`) / no query matches |
| `2` | New vulnerabilities introduced (`--fail-on-vuln`) |
| `3` | Error |
| `4` | VEX coverage gaps found (`--fail-on-vex-gap`) |
| `5` | License policy violations found (`license-check`) |

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

## Project Structure

```
src/
├── cli/          Command handlers (diff, view, validate, quality, query, fleet, vex, watch, ...)
├── config/       YAML/JSON config with presets, validation, schema generation
├── model/        Canonical SBOM representation (NormalizedSbom, Component, CanonicalId)
├── parsers/      Format detection + parsing (streaming for >512MB)
├── matching/     Multi-tier fuzzy matching (PURL, alias, ecosystem, adaptive, LSH)
├── diff/         Semantic diffing engine with graph support + incremental section-selective diff
├── enrichment/   OSV/KEV vulnerability data + EOL detection + VEX (feature-gated)
├── quality/      8-category scoring engine + CBOM crypto scoring profile + 11 compliance standards (NTIA/FDA/CRA/SSDF/EO 14028/CNSA 2.0/NIST PQC)
├── pipeline/     parse → enrich → diff → report orchestration + shared enrichment pipeline
├── reports/      9 output format generators + streaming reporter
├── verification/ File hash verification + component hash auditing
├── license/      License policy engine (allow/deny/review) + propagation analysis
├── serialization/ Raw JSON enrichment, tailoring (filter), merging with dedup
├── watch/        Continuous monitoring (file watcher, vulnerability alerts)
└── tui/          Ratatui-based interactive UI (diff, view, multi-diff, timeline, matrix modes)
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for detailed module responsibilities and data flow.

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
- [Releases and changelog](https://github.com/sbom-tool/sbom-tools/releases)

## Contributing

Contributions are welcome! Please open an issue to discuss your idea before submitting a pull request. Make sure `cargo test` passes and follow the existing code style.

## License

[MIT](LICENSE)
