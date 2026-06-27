# sbom-tools Python bindings

Pure-Python `ctypes` bindings for the existing
[`sbom-tools`](https://github.com/sbom-tool/sbom-tools) C ABI.

The package does not change Rust behavior or implement its own SBOM logic.

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

## Memory and errors

Every native result is decoded before the binding calls
`sbom_tools_string_result_free` exactly once. Native pointers are not exposed
through the public API. ABI failures raise `SbomToolsNativeError` with the
corresponding stable error code.
