# sbom-tools Python bindings

Pure-Python `ctypes` bindings for the existing
[`sbom-tools`](https://github.com/sbom-tool/sbom-tools) C ABI.

> **Developer preview:** this binding requires a native library built from the
> same source tree. Binary wheels and publishing automation are not available.

Start with the [project overview](../../docs/PROJECT_OVERVIEW.md) and
[user journeys](../../docs/USER_JOURNEYS.md) to understand where Python fits in
the scientist and developer workflows. Those documents are introduced by
[PR #276](https://github.com/sbom-tool/sbom-tools/pull/276) and must land before
these relative links resolve on the upstream default branch.

The package does not change Rust behavior or implement its own SBOM logic.
When troubleshooting, include the output of `version()` in bug reports so the
loaded ABI and Rust crate versions are explicit.

## Requirements

- Python 3.10 or later
- A native `sbom-tools-ffi` library built from this repository

Build the native library from the repository root:

```sh
cargo build -p sbom-tools-ffi --release
```

The loader searches for the platform library in this order:

1. The file named by `SBOM_TOOLS_LIB_PATH`
2. `bindings/python/native/`
3. Repository release, then debug targets (flat or host target-triple directories)
4. The system library path

The platform filenames are:

- macOS: `libsbom_tools_ffi.dylib`
- Linux: `libsbom_tools_ffi.so`
- Windows: `sbom_tools_ffi.dll`

An invalid `SBOM_TOOLS_LIB_PATH` is reported immediately and does not fall
through to another library.

## Install and test

Use an isolated environment:

```sh
cd bindings/python
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
.venv/bin/python -m pytest -q
```

On Windows, replace `.venv/bin/python` with `.venv\Scripts\python`.

Tests that require the native library skip with a clear message when it has not
been built. An explicitly configured but invalid library path is a test failure.

## Usage

```python
import json

from sbomtools import ScoringProfile, parse_path_json, score_json, version

print(version())

normalized = parse_path_json("bom.cdx.json")
report = score_json(json.dumps(normalized), ScoringProfile.STANDARD)
print(report)
```

The diff and score functions accept normalized JSON produced by a parse
function:

```python
old = parse_path_json("old.cdx.json")
new = parse_path_json("new.cdx.json")

from sbomtools import diff_json

result = diff_json(json.dumps(old), json.dumps(new))
```

## Compliance

`validate_json` checks raw SBOM content (any supported format) against
compliance standards and returns the `sbom-tools/compliance/v2` envelope:
what `sbom-tools validate - -o json` writes for the same content and
options. The keyword options are the CLI flags of the same names:

```python
from datetime import date
from pathlib import Path

from sbomtools import validate_json

path = Path("bom.cdx.json")
envelope = validate_json(
    path.read_text(encoding="utf-8"),
    file_name=path,                     # validate <FILE>: named in the subject
    standards=["cra", "ntia"],          # --standard; default ["ntia"]
    as_of=date(2027, 1, 1),             # --as-of; a str, date or datetime
    product_class="important-class-1",  # --cra-product-class
    rules={"SBOM-NTIA-SUPPLIER": "warning"},  # --rule
)

print(envelope["as_of"], envelope["subject"]["sha256"])
for result in envelope["results"]:
    print(result["standard"], result["compliant"], result["counts"])
    for violation in result["violations"]:
        print(" ", violation["finding_id"], violation["rule_id"], violation["message"])
```

The envelope's `as_of` is the instant every standard was judged at (the
`as_of` option, else the wall clock when the call starts, to the second),
and its `subject` gives the SHA-256 of the content passed in and the file
name without its directory, which only `file_name` provides. The other
options are `sidecar` (a dict with the keys of a `.cra.json` file),
`pqc_mode`, `pqc_profile`, `cnsa_category` and `include_excluded_scope`. A
naive `datetime` is taken as UTC. An invalid option raises
`SbomToolsNativeError` with `ErrorCode.VALIDATION`.

`rule_catalog_json()` returns the rule catalogue (`sbom-tools rules -o
json`), every rule or those of the standards given, and
`score_with_options_json(sbom_json, profile="cra", as_of=...)` scores with a
pinned clock and the same run options. Its report names the profile as
`quality --profile` does and reports the compliance check as an entry of the
envelope's `results`. `ComplianceEnvelope`, `ComplianceSubject`,
`ComplianceResult`, `RuleCatalog` and `RuleCatalogEntry` are `TypedDict`
hints for these values.

## Memory and errors

Every native result is decoded before the binding calls
`sbom_tools_string_result_free` exactly once. Native pointers are not exposed
through the public API. ABI failures raise `SbomToolsNativeError` with the
corresponding stable error code.
