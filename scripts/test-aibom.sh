#!/usr/bin/env bash
# Exercise the AI-BOM test dataset end-to-end through sbom-tools.
#
# For every AI-BOM in the corpus this runs, in order:
#   view     -o json                        -> parses at all? component count
#   quality  --profile ai-readiness -o json -> AI-readiness score, grade, per-check
#   validate --standard bsi-ai      -o json -> BSI/G7 "SBOM for AI" readiness
#   validate --standard ai-act      -o json -> EU AI Act Annex IV readiness
#
# and prints one row per document.
#
# Usage: scripts/test-aibom.sh [options] [FILE...]
#
#   -r, --release        use the release binary (default: debug)
#   -d, --dir DIR        add a dataset directory (repeatable)
#   -m, --min-score N    fail if any document scores below N (default: off)
#   -c, --check-fail     fail if any compliance profile reports non-compliant
#   -v, --verbose        list the failing AI-readiness checks per document
#   -n, --no-build       skip cargo build, use whatever binary is on disk
#   -h, --help           this message
#
# Explicit FILE arguments replace the default dataset.
#
# Exit codes:
#   0  every document parsed and every requested gate passed
#   1  a gate tripped (--min-score / --check-fail)
#   2  a document failed to parse, or sbom-tools hit an operational error
#
# Note that a compliance FAIL is a *result*, not an error: the real-world
# documents in the corpus are expected to miss elements. Only parse failures and
# operational errors (sbom-tools exit >= 2) fail the run by default.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PROFILE_DIR="debug"
CARGO_FLAGS=()
DATASET_DIRS=()
FILES=()
MIN_SCORE=""
CHECK_FAIL=0
VERBOSE=0
BUILD=1

usage() { sed -n '2,32p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        -r|--release)   PROFILE_DIR="release"; CARGO_FLAGS=(--release); shift ;;
        -d|--dir)       DATASET_DIRS+=("$2"); shift 2 ;;
        -m|--min-score) MIN_SCORE="$2"; shift 2 ;;
        -c|--check-fail) CHECK_FAIL=1; shift ;;
        -v|--verbose)   VERBOSE=1; shift ;;
        -n|--no-build)  BUILD=0; shift ;;
        -h|--help)      usage; exit 0 ;;
        -*)             echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
        *)              FILES+=("$1"); shift ;;
    esac
done

# ── JSON extraction: prefer jq, fall back to python3 ──────────────
if command -v jq >/dev/null 2>&1; then
    json_get() { jq -r "$1 // \"-\"" "$2" 2>/dev/null || echo "-"; }
    failed_checks() {
        jq -r '[.report.ai_readiness_metrics.checks[]? | select(.passed | not) | .id] | join(" ")' \
            "$1" 2>/dev/null
    }
elif command -v python3 >/dev/null 2>&1; then
    # Translate the small subset of jq paths used below into python lookups.
    json_get() {
        python3 -c '
import json, sys
path, f = sys.argv[1], sys.argv[2]
try:
    cur = json.load(open(f))
    for key in path.lstrip(".").split("."):
        cur = cur[key]
except Exception:
    cur = None
print("-" if cur is None else cur)
' "$1" "$2"
    }
    failed_checks() {
        python3 -c '
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    checks = d["report"]["ai_readiness_metrics"]["checks"]
    print(" ".join(c["id"] for c in checks if not c["passed"]))
except Exception:
    print("")
' "$1"
    }
else
    echo "error: this script needs either jq or python3 to read JSON output" >&2
    exit 2
fi

# ── Locate the binary ─────────────────────────────────────────────
BIN="${SBOM_TOOLS_BIN:-$REPO_ROOT/target/$PROFILE_DIR/sbom-tools}"
if [[ -n "${SBOM_TOOLS_BIN:-}" ]]; then
    BUILD=0
fi
if [[ "$BUILD" -eq 1 ]]; then
    echo "Building sbom-tools ($PROFILE_DIR)..."
    cargo build --bin sbom-tools "${CARGO_FLAGS[@]}" || exit 2
fi
if [[ ! -x "$BIN" ]]; then
    echo "error: binary not found at $BIN (drop --no-build, or set SBOM_TOOLS_BIN)" >&2
    exit 2
fi

# ── Assemble the dataset ──────────────────────────────────────────
# Default corpus: the third-party AI-BOM dataset plus the hand-written AI/ML
# fixtures already used by the bsi-ai / eu-ai-act / SARIF integration tests.
if [[ ${#FILES[@]} -eq 0 ]]; then
    if [[ ${#DATASET_DIRS[@]} -eq 0 ]]; then
        DATASET_DIRS=(tests/fixtures/aibom)
        while IFS= read -r f; do
            FILES+=("$f")
        done < <(find tests/fixtures/cyclonedx -maxdepth 1 \
                    \( -name '*aibom*' -o -name '*mlbom*' -o -name 'hf-*' \
                       -o -name 'untyped-hf-model*' \) -type f | sort)
    fi
    for dir in "${DATASET_DIRS[@]}"; do
        if [[ ! -d "$dir" ]]; then
            echo "error: dataset directory not found: $dir" >&2
            exit 2
        fi
        while IFS= read -r f; do
            FILES+=("$f")
        done < <(find "$dir" -maxdepth 1 -type f \
                    \( -name '*.json' -o -name '*.xml' \) ! -name 'osv-scanner.toml' | sort)
    done
fi

if [[ ${#FILES[@]} -eq 0 ]]; then
    echo "error: no AI-BOM documents found" >&2
    exit 2
fi

TMPDIR_RUN="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_RUN"' EXIT

run_tool() { # run_tool <outfile> <args...>; echoes the tool's exit code
    local out="$1"; shift
    "$BIN" --no-color -q "$@" >"$out" 2>"$out.err"
    echo $?
}

printf '\nAI-BOM dataset: %d document(s)\n\n' "${#FILES[@]}"
printf '%-38s %5s %4s %7s %6s %-9s %-9s\n' \
    DOCUMENT COMPS ML SCORE GRADE BSI-AI AI-ACT
printf '%s\n' "$(printf '─%.0s' {1..84})"

parse_errors=0
op_errors=0
gate_failures=0
declare -a VERBOSE_NOTES=()

for file in "${FILES[@]}"; do
    label="$(basename "$file")"
    [[ ${#label} -gt 38 ]] && label="${label:0:35}..."
    stem="$TMPDIR_RUN/$(basename "$file" | tr -c 'A-Za-z0-9._-' '_')"

    # ── parse ─────────────────────────────────────────────────────
    rc=$(run_tool "$stem.view.json" view "$file" -o json)
    if [[ "$rc" -ne 0 ]]; then
        printf '%-38s %5s %4s %7s %6s %-9s %-9s\n' "$label" "-" "-" "-" "-" "PARSE-ERR" "-"
        VERBOSE_NOTES+=("$label: view exited $rc — $(head -n 3 "$stem.view.json.err" | tr '\n' ' ')")
        parse_errors=$((parse_errors + 1))
        continue
    fi
    comps=$(json_get '.summary.total_components' "$stem.view.json")

    # ── AI-readiness score ────────────────────────────────────────
    rc=$(run_tool "$stem.quality.json" quality "$file" --profile ai-readiness -o json)
    if [[ "$rc" -ge 2 ]]; then
        score="ERR"; grade="-"; ml="-"
        VERBOSE_NOTES+=("$label: quality exited $rc — $(head -n 3 "$stem.quality.json.err" | tr '\n' ' ')")
        op_errors=$((op_errors + 1))
    else
        score=$(json_get '.report.overall_score' "$stem.quality.json")
        grade=$(json_get '.report.grade' "$stem.quality.json")
        ml=$(json_get '.report.ai_readiness_metrics.ml_component_count' "$stem.quality.json")
        [[ "$score" != "-" && "$score" != "ERR" ]] && score=$(printf '%.1f' "$score")
    fi

    # ── compliance profiles ───────────────────────────────────────
    verdicts=()
    for standard in bsi-ai ai-act; do
        rc=$(run_tool "$stem.$standard.json" validate "$file" --standard "$standard" -o json)
        if [[ "$rc" -ge 2 ]]; then
            verdicts+=("ERR")
            VERBOSE_NOTES+=("$label: validate --standard $standard exited $rc — $(head -n 3 "$stem.$standard.json.err" | tr '\n' ' ')")
            op_errors=$((op_errors + 1))
            continue
        fi
        compliant=$(json_get '.is_compliant' "$stem.$standard.json")
        errs=$(json_get '.error_count' "$stem.$standard.json")
        applicability=$(json_get '.applicability.status' "$stem.$standard.json")
        if [[ "$applicability" == "not_applicable" ]]; then
            verdicts+=("N/A")
        elif [[ "$compliant" == "true" || "$compliant" == "True" ]]; then
            verdicts+=("PASS")
        else
            verdicts+=("FAIL($errs)")
            [[ "$CHECK_FAIL" -eq 1 ]] && gate_failures=$((gate_failures + 1))
        fi
    done

    printf '%-38s %5s %4s %7s %6s %-9s %-9s\n' \
        "$label" "$comps" "$ml" "$score" "$grade" "${verdicts[0]}" "${verdicts[1]}"

    # ── gates and verbose detail ──────────────────────────────────
    if [[ -n "$MIN_SCORE" && "$score" != "-" && "$score" != "ERR" ]]; then
        if awk -v s="$score" -v m="$MIN_SCORE" 'BEGIN { exit !(s < m) }'; then
            VERBOSE_NOTES+=("$label: score $score below --min-score $MIN_SCORE")
            gate_failures=$((gate_failures + 1))
        fi
    fi
    if [[ "$VERBOSE" -eq 1 && -s "$stem.quality.json" ]]; then
        failed=$(failed_checks "$stem.quality.json")
        [[ -n "$failed" ]] && printf '%-38s   failed checks: %s\n' "" "$failed"
    fi
done

echo
echo "${#FILES[@]} document(s), $parse_errors parse error(s), $op_errors operational error(s)"

if [[ ${#VERBOSE_NOTES[@]} -gt 0 ]]; then
    echo
    echo "Notes:"
    printf '  - %s\n' "${VERBOSE_NOTES[@]}"
fi

if [[ "$parse_errors" -gt 0 || "$op_errors" -gt 0 ]]; then
    echo
    echo "FAILED: the corpus must parse cleanly and must not trigger operational errors."
    exit 2
fi
if [[ "$gate_failures" -gt 0 ]]; then
    echo
    echo "FAILED: $gate_failures gate failure(s)."
    exit 1
fi
echo "OK"
