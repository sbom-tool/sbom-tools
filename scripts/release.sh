#!/usr/bin/env bash
# Release script for sbom-tools
# Usage: scripts/release.sh <version>
# Example: scripts/release.sh 0.1.11
set -euo pipefail

VERSION="${1:-}"

# ── Validate arguments ───────────────────────────────────────────
if [[ -z "$VERSION" ]]; then
    echo "Usage: scripts/release.sh <version>"
    echo "Example: scripts/release.sh 0.1.11"
    exit 1
fi

if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: Version '$VERSION' is not valid semver (expected X.Y.Z)"
    exit 1
fi

# ── Verify clean state ──────────────────────────────────────────
if [[ -n "$(git status --porcelain)" ]]; then
    echo "Error: Working tree is not clean. Commit or stash changes first."
    git status --short
    exit 1
fi

BRANCH="$(git branch --show-current)"
if [[ "$BRANCH" != "main" ]]; then
    echo "Error: Must be on 'main' branch (currently on '$BRANCH')"
    exit 1
fi

echo "==> Releasing sbom-tools v$VERSION"

# ── Check current version ────────────────────────────────────────
CURRENT="$(sed -nE 's/^version = "([^"]+)"/\1/p' Cargo.toml | head -n1)"
echo "    Current version: $CURRENT"
echo "    New version:     $VERSION"

if [[ "$CURRENT" == "$VERSION" ]]; then
    echo "Error: Cargo.toml already at version $VERSION"
    exit 1
fi

if git tag -l "v$VERSION" | grep -q "v$VERSION"; then
    echo "Error: Tag v$VERSION already exists"
    exit 1
fi

# ── Run local checks ────────────────────────────────────────────
echo "==> Running cargo deny check..."
if command -v cargo-deny &>/dev/null; then
    cargo deny check advisories bans licenses sources
else
    echo "    Warning: cargo-deny not installed, skipping (install: cargo install cargo-deny)"
fi

echo "==> Running tests..."
cargo test --locked --all-features --quiet

echo "==> Running clippy..."
cargo clippy --all-features -- -D warnings 2>&1 | tail -1

echo "==> Dry-run publish..."
cargo publish --dry-run --locked 2>&1 | tail -3

# ── Bump version ─────────────────────────────────────────────────
echo "==> Bumping Cargo.toml to $VERSION"
sed -i.bak "s/^version = \"$CURRENT\"/version = \"$VERSION\"/" Cargo.toml
rm -f Cargo.toml.bak

# Update Cargo.lock
cargo check --quiet 2>/dev/null

# ── Commit + tag + push ─────────────────────────────────────────
echo "==> Committing and tagging..."
git add Cargo.toml Cargo.lock
git commit -m "Bump version to $VERSION"
git tag -a "v$VERSION" -m "Release v$VERSION"

echo "==> Pushing to origin..."
git push origin main "v$VERSION"

echo ""
echo "Done! v$VERSION pushed. CI will publish to crates.io."
echo "Monitor: gh run list --limit 3"
