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

jq '.components.modified' /tmp/model-diff.json
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

jq '.summary // .' /tmp/validation.json
```

Validation checks the supplied BOM. It does not certify the product or create
evidence that is absent from the input.

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
as an OSCAL 1.1.2 `assessment-results` document:

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
with code 1 because its score is below 70, and strict validation exits with code
2 because warnings are present. Those non-zero results demonstrate the gates;
they are not command failures.

Exit codes are part of the CLI contract. A pipeline should gate on the selected
flag and exit code, then retain the JSON or SARIF output for diagnosis. See
`sbom-tools --help` and the relevant subcommand help for the complete exit-code
table.

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
