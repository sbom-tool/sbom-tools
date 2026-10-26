# User journeys

<!-- markdownlint-disable MD013 -->

These journeys use repository fixtures so each command can be reproduced from a
source checkout. Cargo builds the CLI on first use and reuses it afterward:

```sh
cargo build --release
```

## Scientist: inspect and compare an AI-BOM

Use this path when model architecture, training datasets, limitations, or
model-card completeness need to be reviewed.

### 1. Measure AI readiness

```sh
cargo run --release -- quality \
  tests/fixtures/cyclonedx/minimal-mlbom.cdx.json \
  --profile ai-readiness \
  --metrics \
  -o json > /tmp/ai-readiness.json

jq '{
  applicable,
  score: .report.overall_score,
  grade: .report.grade,
  readiness: .report.ai_readiness_metrics
}' /tmp/ai-readiness.json
```

The report is derived from BOM-visible metadata. It does not execute the model
or independently measure accuracy, bias, safety, or performance.

### 2. Create a second model revision and compare it

The following command changes a model version and declared task in a temporary
copy:

```sh
jq '
  (.components[] | select(.name == "bert-base") | .version) = "2.0.0" |
  (.components[] | select(.name == "bert-base")
    | .modelCard.modelParameters.task) = "text-classification"
' tests/fixtures/cyclonedx/minimal-mlbom.cdx.json \
  > /tmp/model-v2.cdx.json

cargo run --release -- diff \
  tests/fixtures/cyclonedx/minimal-mlbom.cdx.json \
  /tmp/model-v2.cdx.json \
  -o json > /tmp/model-diff.json

jq '.reports.components.modified' /tmp/model-diff.json
```

The diff reports only changes represented in the two BOMs. It does not infer
changes from a model registry or training platform.

### 3. Use Python for programmatic inspection

The Python binding requires Python 3.10 or later and a native library built
from the same source tree:

```sh
cargo build -p sbom-tools-ffi --release
cd bindings/python
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
```

On Windows, use `.venv\Scripts\python` instead. Then inspect the canonical model:

```python
from sbomtools import parse_path_json

bom = parse_path_json("../../tests/fixtures/cyclonedx/minimal-mlbom.cdx.json")

for entry in bom["components"]:
    component = entry["component"]
    if component["ml_model"] is not None:
        print(component["name"], component["ml_model"]["task"])
    if component["dataset"] is not None:
        print(component["name"], component["dataset"]["governance_owners"])
```

Use `score_json` and `diff_json` when an application needs the same readiness
and comparison semantics as the CLI. The binding README documents the complete
preview API and native-library lookup order.

## Developer or security engineer: make BOM analysis actionable

Use this path to validate a BOM, compare releases, and create CI-consumable
outputs.

### 1. Validate declared metadata

```sh
cargo run --release -- validate \
  tests/fixtures/cyclonedx/minimal.cdx.json \
  --standard ntia \
  -o json > /tmp/validation.json

jq '.results[0] | {standard, compliant, counts}' /tmp/validation.json
```

Validation checks the supplied BOM. It does not certify the product or create
evidence that is absent from the input. `-o json` is one
`sbom-tools/compliance/v2` envelope whatever the number of standards, and every
violation carries a stable `finding_id`; [compliance-output.md](compliance-output.md)
describes the fields.

`--standard` accepts one profile or a comma-separated list. Recent additions
are `cisa-2026` (CISA 2026 Minimum Elements for an SBOM, v2.1, successor to
the NTIA 2021 elements), `pci-dss` (PCI DSS v4.0.1 Requirement 6.3.2 software
inventory), and `fsct` (CISA Framing Software Component Transparency, 3rd
edition). A list returns one entry of `results` per standard, identified by
`standard`:

```sh
cargo run --release -- validate \
  tests/fixtures/showcase/fleet-v1.cdx.json \
  --standard ntia,cisa-2026 \
  -o json |
  jq -c '.results[] | {standard, error: .counts.error, warning: .counts.warning}'
```

That fixture reports 4 errors under `ntia` and 9 errors with 3 warnings under
`cisa-2026`. The 2026 profile is deliberately stricter on the same document:
a tool-only creator list does not satisfy SBOM Author, because the author is
the entity operating the tool rather than the tool itself.

`fsct` maps the maturity tiers of the 3rd edition onto severities: Minimum
Expected to error, Recommended Practice to warning, Aspirational Goal to
informational, so `--fail-on-warning` promotes the middle tier to a gate. That
flag is also what separates a clean result from a warnings-only one, and only
the second invocation below fails:

```sh
cargo run --release -- validate \
  tests/fixtures/demo-new.cdx.json \
  --standard pci-dss \
  -o json > /dev/null            # exit 0: no errors, one warning

cargo run --release -- validate \
  tests/fixtures/demo-new.cdx.json \
  --standard pci-dss \
  --fail-on-warning \
  -o json > /dev/null            # exit 2: warnings-only result
```

A passing `pci-dss` verdict is evidence that the BOM carries a software
inventory usable for Requirement 6.3.2. It is not a PCI DSS compliance
certification, and no profile here certifies a product or an organization.

When a CycloneDX 1.6 document carries a `declarations` section, existing rules
consume it as evidence: an attestation covering an SSDF practice, a CRA
conformity route, an EUCC certificate reference, or EO 14028 provenance
satisfies the corresponding rule. Removing the section from
`tests/fixtures/cyclonedx/declarations-cdxa-ssdf-delta.cdx.json`, or lowering
that document's `specVersion` to 1.5, moves the `ssdf` result from 2 errors
and 3 warnings to 3 errors and 4 warnings. Every pre-existing satisfaction path remains valid
as a self-declared fallback, so documents without declarations are unaffected.
Ingestion is structural: a signature's presence is recorded, never
cryptographically verified.

### 2. Compare releases

```sh
cargo run --release -- diff \
  tests/fixtures/demo-old.cdx.json \
  tests/fixtures/demo-new.cdx.json \
  -o json > /tmp/release-diff.json

jq '.summary' /tmp/release-diff.json
```

Use `-o sarif` when the result will be uploaded to a code-scanning system.
Use `-o oscal-json` when assessment tooling needs the same validation findings
as an OSCAL 1.2.3 `assessment-results` document:

```sh
cargo run --release -- validate \
  tests/fixtures/cyclonedx/minimal.cdx.json \
  --standard ntia \
  -o oscal-json \
  -O /tmp/validation-results.oscal.json

jq '."assessment-results" | {
  oscal_version: .metadata."oscal-version",
  result_count: (.results | length),
  finding_count: (.results[0].findings | length)
}' /tmp/validation-results.oscal.json
```

Each observation names its subjects: the SBOM document, described in
`back-matter` with its SHA-256, and for a component finding the component,
defined in the result's `local-definitions`. The mapping, and what changed
from the OSCAL 1.1.2 export of earlier releases, is in
[`compliance-output.md`](compliance-output.md#oscal-assessment-results).

The export maps existing findings; it does not generate an assessment plan,
SSP, authorization package, attestation, or evidence absent from the BOM.

### 3. Apply explicit CI gates

```sh
cargo run --release -- quality \
  tests/fixtures/cyclonedx/minimal.cdx.json \
  --profile security \
  --min-score 70 \
  -o json > quality.json

cargo run --release -- validate \
  tests/fixtures/cyclonedx/minimal.cdx.json \
  --standard ntia \
  --fail-on-warning \
  -o sarif > validation.sarif
```

With the repository's deliberately minimal fixture, the quality command exits
with code 1 because its score is below 70, and validation exits with code 1
because the engine-backed NTIA check reports compliance errors (code 2 signals
a warnings-only result under `--fail-on-warning`, as it signals vulnerabilities
introduced under `--fail-on-vuln` in `diff`; command-line usage errors exit 3,
like operational errors). Those non-zero results demonstrate the gates; they
are not command failures. Add `--require-applicable` when a standard that does
not apply to the BOM (an AI readiness profile on a BOM without ML components)
must fail the gate rather than pass as N/A.

Exit codes are part of the CLI contract. A pipeline should gate on the selected
flag and exit code, then retain the JSON or SARIF output for diagnosis. See
`sbom-tools --help` and the relevant subcommand help for the complete exit-code
table.

### 4. Gate on BOM-declared ML metric regressions

Create a candidate AI-BOM whose declared overall accuracy is lower than the
baseline:

```sh
jq '
  walk(
    if type == "object" and .type? == "accuracy"
    then .value = "0.80"
    else .
    end
  )
' tests/fixtures/cyclonedx/aibom-complete.cdx.json \
  > /tmp/candidate-ai-bom.cdx.json

cargo run --release -- diff \
  tests/fixtures/cyclonedx/aibom-complete.cdx.json \
  /tmp/candidate-ai-bom.cdx.json \
  --fail-on-ml-regression \
  -o json \
  -O /tmp/ml-regression.json
```

The command exits with code 7. The retained JSON identifies why:

```sh
jq '.ml_regressions' /tmp/ml-regression.json
```

The gate uses an explicit metric-direction allowlist. It ignores missing,
non-numeric, and unrecognized metrics. It evaluates only values declared in the
two BOMs; it does not run a model or independently verify the measurements.

### 5. Cross-check quality scores against sbomqs

A team that already tracks `interlynk-io/sbomqs` scores can emit the same
schema from the `quality` command and compare side by side:

```sh
cargo run --release -- quality \
  tests/fixtures/showcase/fleet-v3.cdx.json \
  -o sbomqs-json > /tmp/sbomqs-compat.json

jq '{
  engine: .creation_info.scoring_engine_version,
  avg_score: .files[0].avg_score,
  categories: ([.files[0].scores[].category] | unique)
}' /tmp/sbomqs-compat.json
```

The fixture averages 7.22 across the five sbomqs categories
(`NTIA-minimum-elements`, `Quality`, `Semantic`, `Sharing`, `Structural`).
`-o summary` prints the same model as a compact 0-10 category table beneath
the native 0-100 report.

The two scales are not convertible. The compat emitter recomputes every
feature with sbomqs' own formulas instead of rescaling the native score, and
it reproduces sbomqs' quirks, including keeping features that cannot be
computed in the average's denominator as `ignored` entries with a stated
reason rather than dropping them. `docs/STANDARDS_VERSIONS.md` records the
parity target and the quirks.

## Platform engineer: compare a fleet or a release line

Use this path when the question spans more than two BOMs: how far a fleet has
drifted from its baseline, how a release line evolved, or which documents
cluster together.

`diff-multi`, `timeline`, and `matrix` accept only `auto`, `tui`, and `json`
for `-o`. `auto` opens the TUI on a TTY and emits JSON when the output is
piped. Any other value is a usage error, rejected before a single SBOM is
parsed:

```sh
cargo run --release -- timeline \
  tests/fixtures/showcase/fleet-v1.cdx.json \
  tests/fixtures/showcase/fleet-v2.cdx.json \
  -o markdown
# error: invalid value 'markdown' for '--output <OUTPUT>'
#   [possible values: auto, tui, json]
# exit code 3
```

In the TUI, `?` opens the shortcut overlay, `e` opens the export menu, and `q`
exits. `--no-color`, or `NO_COLOR` set to a non-empty value, selects the
monochrome theme and keeps it selected under the `T` theme toggle. The overlay
is context-aware — it lists the active tab's keys and omits global ones that
tab has taken over; [`TUI_SHORTCUTS.md`](TUI_SHORTCUTS.md) is the full
reference across every mode.

### 1. Measure fleet drift from a baseline

```sh
cargo run --release -- diff-multi \
  tests/fixtures/showcase/fleet-v1.cdx.json \
  tests/fixtures/showcase/fleet-v2.cdx.json \
  tests/fixtures/showcase/fleet-v3.cdx.json \
  -o json > /tmp/fleet.json

jq '.summary | {
  max_deviation,
  deviation_scores,
  universal_components,
  variable: [.variable_components[]
    | {id, versions: .version_spread.unique_versions}]
}' /tmp/fleet.json
```

`deviation_scores` and `max_deviation` are fractions between 0 and 1; the
fixture fleet reports 0.211 for `fleet-v2` and 0.306 for `fleet-v3`. Component
entries are keyed by version-stripped purl, so `pkg:npm/express` at three
versions is one variable component rather than an added and a removed pair.

### 2. Follow a release line

```sh
cargo run --release -- timeline \
  tests/fixtures/showcase/fleet-v1.cdx.json \
  tests/fixtures/showcase/fleet-v2.cdx.json \
  tests/fixtures/showcase/fleet-v3.cdx.json \
  -o json > /tmp/timeline.json

jq '{
  incremental_pairs,
  cumulative_pairs,
  express: .evolution_summary.version_history["pkg:npm/express"]
}' /tmp/timeline.json
```

`incremental_pairs` and `cumulative_pairs` label the entries of
`incremental_diffs` and `cumulative_from_first` with `from_index`, `to_index`,
`from_name`, and `to_name`, so a consumer never has to infer the compared pair
from array position. `version_history` reports `pkg:npm/express` moving
`4.18.2` to `4.19.2` to `5.0.1`, classified `Initial`, `MinorUpgrade`, and
`MajorUpgrade`.

### 3. Cluster a set of BOMs

```sh
cargo run --release -- matrix \
  tests/fixtures/showcase/fleet-v*.cdx.json \
  -o json > /tmp/matrix.json

jq '{similarity_scores, clustering}' /tmp/matrix.json
```

At the default 0.8 threshold the three fixtures produce one cluster holding
`fleet-v2` and `fleet-v3`, with `fleet-v1` reported as an outlier.

### Similarity and deviation scales

| Field | Command | Range |
| --- | --- | --- |
| `summary.semantic_score` | `diff` | 0-100 |
| `similarity_scores` | `matrix` | 0-1 |
| `summary.deviation_scores`, `summary.max_deviation` | `diff-multi` | 0-1 |

Matrix similarity is the single-diff `semantic_score` divided by 100, and
deviation is `1 - similarity`. For `fleet-v1` against `fleet-v2` those three
values are 78.899, 0.78899, and 0.21101.

## Choosing an interface

| Need | Recommended interface | Status |
| --- | --- | --- |
| Interactive exploration or CI gates | CLI | Supported |
| Rust application integration | Rust library | Supported |
| Go application integration | Go binding | Supported from source |
| Swift application integration | Swift binding | Supported from source |
| Notebook or Python pipeline | Python `ctypes` binding | Developer preview; native library required |
| TypeScript service or tool | Node.js Koffi binding | Developer preview; private package and native library required |
| Another language | C ABI | Supported foundation for a thin binding |

The bindings expose parse, detect, diff, and score operations. CLI-only
features, enrichment providers, the TUI, and non-JSON reports are not part of
the current C ABI.
