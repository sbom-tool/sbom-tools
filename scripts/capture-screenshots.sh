#!/usr/bin/env bash
#
# Capture TUI screenshots using tmux + freeze.
#
# Prerequisites:
#   brew install tmux charmbracelet/tap/freeze
#   cargo build --release
#
# Usage:
#   ./scripts/capture-screenshots.sh           # capture all
#   ./scripts/capture-screenshots.sh diff      # capture diff mode only
#   ./scripts/capture-screenshots.sh view      # capture view mode only
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ASSETS_DIR="$PROJECT_DIR/assets"
TMP_DIR=$(mktemp -d)

BIN="$PROJECT_DIR/target/release/sbom-tools"
OLD="$PROJECT_DIR/tests/fixtures/demo-old.cdx.json"
NEW="$PROJECT_DIR/tests/fixtures/demo-new.cdx.json"
VULN="$PROJECT_DIR/tests/fixtures/cyclonedx/with-vulnerabilities.cdx.json"

# Terminal dimensions
COLS=160
ROWS=42
SESSION="sbom-screenshot"

# Freeze flags (no config file — -c causes hangs in freeze v0.2.x)
FREEZE_FLAGS="--language ansi --window --font.size 14"

# ── Helpers ──────────────────────────────────────────────────────────────────

cleanup() {
    tmux kill-session -t "$SESSION" 2>/dev/null || true
    pkill -9 -f "freeze" 2>/dev/null || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

ensure_binary() {
    if [[ ! -x "$BIN" ]]; then
        echo "Building release binary..."
        cargo build --release --manifest-path "$PROJECT_DIR/Cargo.toml"
    fi
}

# Start a tmux session, run a command, wait for TUI to render.
start_tui() {
    tmux kill-session -t "$SESSION" 2>/dev/null || true
    sleep 0.3
    tmux new-session -d -s "$SESSION" -x "$COLS" -y "$ROWS"
    tmux send-keys -t "$SESSION" "export TERM=xterm-256color" Enter
    sleep 0.3
    tmux send-keys -t "$SESSION" "$1" Enter
    sleep 3  # wait for TUI render
}

# Send keys and wait.
send_keys() {
    tmux send-keys -t "$SESSION" "$1"
    sleep "${2:-0.5}"
}

# Capture the current tmux pane and render to SVG.
capture() {
    local name="$1"
    local ansi_file="$TMP_DIR/${name}.txt"
    local svg_file="$ASSETS_DIR/${name}.svg"

    # Kill any stale freeze processes first
    pkill -9 -f "freeze" 2>/dev/null || true
    sleep 0.3

    # Capture pane with ANSI escape codes
    tmux capture-pane -t "$SESSION" -p -e > "$ansi_file"

    # Render SVG
    # shellcheck disable=SC2086
    freeze "$ansi_file" -o "$svg_file" $FREEZE_FLAGS

    echo "  [ok] $svg_file ($(wc -c < "$svg_file" | tr -d ' ') bytes)"
}

# ── Diff Mode Captures ──────────────────────────────────────────────────────

capture_diff() {
    echo ""
    echo "=== Diff Mode ==="

    # 1. Summary tab (default landing)
    start_tui "$BIN diff $OLD $NEW"
    capture "tui-diff-summary"

    # 2. Components tab
    send_keys "2" 1
    send_keys "j" 0.3
    send_keys "j" 0.3
    send_keys "j" 0.3
    capture "tui-diff-components"

    # 3. Compliance tab
    send_keys "7" 1
    capture "tui-diff-compliance"

    # 4. Side-by-side tab
    send_keys "8" 1
    send_keys "j" 0.3
    send_keys "j" 0.3
    capture "tui-diff-sidebyside"

    # 5. Source tab (synchronized panels)
    send_keys "9" 1
    sleep 0.5
    send_keys "j" 0.3
    send_keys " " 0.5   # expand (synced to both panels)
    send_keys "j" 0.3
    send_keys " " 0.5   # expand next
    capture "tui-diff-source"

    tmux kill-session -t "$SESSION" 2>/dev/null || true
}

# ── View Mode Captures ──────────────────────────────────────────────────────

capture_view() {
    echo ""
    echo "=== View Mode ==="

    # Pick the best SBOM for screenshots
    local SBOM="$NEW"
    if [[ -f "$VULN" ]]; then
        SBOM="$VULN"
    fi

    # 1. Overview tab
    start_tui "$BIN view $SBOM"
    capture "tui-view-overview"

    # 2. Components tree tab
    send_keys "2" 1
    send_keys " " 0.3  # expand first group
    send_keys "j" 0.3
    send_keys "j" 0.3
    capture "tui-view-tree"

    # 3. Vulnerabilities tab
    send_keys "3" 1
    capture "tui-view-vulns"

    # 4. Quality tab
    send_keys "6" 1
    capture "tui-view-quality"

    tmux kill-session -t "$SESSION" 2>/dev/null || true
}

# ── Main ─────────────────────────────────────────────────────────────────────

main() {
    ensure_binary
    mkdir -p "$ASSETS_DIR"

    local mode="${1:-all}"

    case "$mode" in
        diff)  capture_diff ;;
        view)  capture_view ;;
        all)   capture_diff; capture_view ;;
        *)
            echo "Usage: $0 [all|diff|view]"
            exit 1
            ;;
    esac

    echo ""
    echo "Done! 9 screenshots in $ASSETS_DIR/"
}

main "$@"
