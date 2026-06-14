#!/usr/bin/env bash
# Regenerate the committed C ABI header from src/ffi.rs via cbindgen.
#
# The header is committed (offline Go/Swift consumers build without cbindgen);
# CI runs this script and `git diff --exit-code` to fail on drift.
#
# Requires cbindgen >= 0.29 (earlier versions do not recognise the edition-2024
# `#[unsafe(no_mangle)]` attribute and silently drop every exported function).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

header="bindings/swift/Sources/CSbomTools/include/sbom_tools.h"
config="crates/sbom-tools-ffi/cbindgen.toml"

if ! command -v cbindgen &>/dev/null; then
  echo "error: cbindgen not found (install: cargo install cbindgen --version '^0.29')" >&2
  exit 1
fi

# The exported symbols live in the root `sbom-tools` crate behind the `ffi`
# feature; the sbom-tools-ffi crate is only a thin cdylib/staticlib re-export.
cbindgen --config "$config" --crate sbom-tools --output "$header"

echo "regenerated $header"
