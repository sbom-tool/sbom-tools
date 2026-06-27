#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

header="$repo_root/bindings/swift/Sources/CSbomTools/include/sbom_tools.h"
go_wrapper="$repo_root/bindings/go/sbomtools.go"
swift_wrapper="$repo_root/bindings/swift/Sources/SbomTools/SbomTools.swift"
python_wrapper="$repo_root/bindings/python/sbomtools/types.py"

failures=0

fail() {
  echo "DRIFT: $1" >&2
  failures=$((failures + 1))
}

# SBOM_TOOLS_PROFILE_AI_READINESS -> aiReadiness
to_swift_case() {
  local raw="$1" out="" part lower first=1
  for part in $(echo "$raw" | tr '_' ' '); do
    lower="$(echo "$part" | tr '[:upper:]' '[:lower:]')"
    if [ "$first" -eq 1 ]; then
      out="$lower"
      first=0
    else
      out="${out}$(echo "${lower:0:1}" | tr '[:lower:]' '[:upper:]')${lower:1}"
    fi
  done
  echo "$out"
}

python_enum_block() {
  local enum_name="$1"
  sed -n "/^class ${enum_name}(IntEnum):/,/^class /p" "$python_wrapper" | sed '$d'
}

constants="$(grep -Eo 'SBOM_TOOLS_(PROFILE|ERROR)_[A-Z0-9_]+ = [0-9]+' "$header")"

if [ -z "$constants" ]; then
  echo "No SBOM_TOOLS_PROFILE_*/SBOM_TOOLS_ERROR_* constants found in $header" >&2
  exit 2
fi

echo "[header] found $(echo "$constants" | wc -l | tr -d ' ') constants in ${header#"$repo_root"/}"

# Go mirrors every header constant via cgo (C.<NAME>). cgo pins the value at
# compile time, so a missing reference is the only way the wrapper can drift.
while read -r name _ value; do
  if ! grep -Eq "C\.${name}([^A-Za-z0-9_]|\$)" "$go_wrapper"; then
    fail "Go wrapper missing C.$name (= $value); add a ScoringProfile/ErrorCode constant to ${go_wrapper#"$repo_root"/}"
  fi
done <<<"$constants"

# Swift mirrors profiles in the SbomToolsScoring enum; error codes are consumed
# directly from the vendored header via CSbomTools, so only profiles can drift.
profiles="$(echo "$constants" | grep '^SBOM_TOOLS_PROFILE_')"
scoring_enum="$(sed -n '/enum SbomToolsScoring/,/^}/p' "$swift_wrapper")"

while read -r name _ value; do
  case_name="$(to_swift_case "${name#SBOM_TOOLS_PROFILE_}")"
  if ! echo "$scoring_enum" | grep -Eq "case[[:space:]]+${case_name}[[:space:]]*=[[:space:]]*${value}(\$|[^0-9])"; then
    fail "Swift SbomToolsScoring missing 'case $case_name = $value' (from $name) in ${swift_wrapper#"$repo_root"/}"
  fi
done <<<"$profiles"

header_profile_count="$(echo "$profiles" | wc -l | tr -d ' ')"
swift_case_count="$(echo "$scoring_enum" | grep -Ec 'case[[:space:]]+[a-zA-Z]+[[:space:]]*=' || true)"
if [ "$swift_case_count" != "$header_profile_count" ]; then
  fail "Swift SbomToolsScoring has $swift_case_count cases but the header declares $header_profile_count profiles; remove stale cases"
fi

# Python mirrors both profile and error constants as IntEnum values.
while read -r name _ value; do
  if [[ "$name" == SBOM_TOOLS_PROFILE_* ]]; then
    enum_name="ScoringProfile"
    case_name="${name#SBOM_TOOLS_PROFILE_}"
  else
    enum_name="ErrorCode"
    case_name="${name#SBOM_TOOLS_ERROR_}"
  fi

  enum_block="$(python_enum_block "$enum_name")"
  if ! echo "$enum_block" | grep -Eq "^[[:space:]]+${case_name}[[:space:]]*=[[:space:]]*${value}[[:space:]]*(#.*)?$"; then
    fail "Python $enum_name missing '$case_name = $value' (from $name) in ${python_wrapper#"$repo_root"/}"
  fi
done <<<"$constants"

header_error_count="$(echo "$constants" | grep -c '^SBOM_TOOLS_ERROR_')"
python_profile_count="$(python_enum_block ScoringProfile | grep -Ec '^[[:space:]]+[A-Z0-9_]+[[:space:]]*=' || true)"
python_error_count="$(python_enum_block ErrorCode | grep -Ec '^[[:space:]]+[A-Z0-9_]+[[:space:]]*=' || true)"
if [ "$python_profile_count" != "$header_profile_count" ]; then
  fail "Python ScoringProfile has $python_profile_count cases but the header declares $header_profile_count profiles; remove stale cases"
fi
if [ "$python_error_count" != "$header_error_count" ]; then
  fail "Python ErrorCode has $python_error_count cases but the header declares $header_error_count errors; remove stale cases"
fi

if [ "$failures" -gt 0 ]; then
  echo "" >&2
  echo "Binding constants are out of sync with sbom_tools.h ($failures issue(s))." >&2
  echo "Update the wrappers to match the header, or update the header first if the FFI changed." >&2
  exit 1
fi

echo "[go] OK: all header constants are referenced in ${go_wrapper#"$repo_root"/}"
echo "[swift] OK: SbomToolsScoring matches the $header_profile_count header profiles"
echo "[python] OK: ScoringProfile and ErrorCode match the C ABI header"
