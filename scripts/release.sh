#!/usr/bin/env bash
# Release script for sbom-tools
# Usage: scripts/release.sh <version>
# Example: scripts/release.sh 0.1.11
#
# Supports repos with branch protection: creates a PR for the version bump,
# waits for CI, then merges (with --admin if needed), tags, and releases.
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

# ── Verify signing key ─────────────────────────────────────────
if ! git config user.signingkey &>/dev/null; then
    echo "Error: No signing key configured. Set up GPG or SSH signing:"
    echo "  GPG: git config --global user.signingkey <KEY_ID>"
    echo "  SSH: git config --global gpg.format ssh"
    echo "       git config --global user.signingkey ~/.ssh/id_ed25519.pub"
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

# Ensure we're up to date
git fetch origin main --quiet
LOCAL_SHA="$(git rev-parse HEAD)"
REMOTE_SHA="$(git rev-parse origin/main)"
if [[ "$LOCAL_SHA" != "$REMOTE_SHA" ]]; then
    echo "Error: Local main ($LOCAL_SHA) differs from origin/main ($REMOTE_SHA)"
    echo "Run 'git pull origin main' first."
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

# ── Bump version on a release branch ────────────────────────────
RELEASE_BRANCH="release/v$VERSION"
echo "==> Creating release branch '$RELEASE_BRANCH'..."
git checkout -b "$RELEASE_BRANCH"

echo "==> Bumping Cargo.toml to $VERSION"
sed -i.bak "s/^version = \"$CURRENT\"/version = \"$VERSION\"/" Cargo.toml
rm -f Cargo.toml.bak

# Update Cargo.lock
cargo check --quiet 2>/dev/null

git add Cargo.toml Cargo.lock
git commit -m "Bump version to $VERSION"
git push -u origin "$RELEASE_BRANCH"

# ── Create PR and wait for CI ────────────────────────────────────
echo "==> Creating pull request..."
PR_URL="$(gh pr create \
    --title "Release v$VERSION" \
    --body "Bump version to $VERSION for release." \
    --base main \
    --head "$RELEASE_BRANCH")"
PR_NUMBER="$(echo "$PR_URL" | grep -oE '[0-9]+$')"
echo "    PR #$PR_NUMBER: $PR_URL"

echo "==> Waiting for CI checks..."
if ! gh pr checks "$PR_NUMBER" --watch --fail-level all; then
    echo "Error: CI checks failed on PR #$PR_NUMBER"
    echo "Fix the issues, then re-run this script or merge manually."
    git checkout main
    exit 1
fi

# ── Merge PR ─────────────────────────────────────────────────────
echo "==> Merging PR #$PR_NUMBER..."
if ! gh pr merge "$PR_NUMBER" --squash --delete-branch; then
    echo "    Standard merge failed, trying with --admin..."
    gh pr merge "$PR_NUMBER" --squash --delete-branch --admin
fi

# ── Update local main ───────────────────────────────────────────
git checkout main
git pull origin main

# ── Tag and push ─────────────────────────────────────────────────
echo "==> Creating signed tag v$VERSION..."
git tag -s "v$VERSION" -m "Release v$VERSION"
git push origin "v$VERSION"

# ── Create GitHub Release ────────────────────────────────────────
echo "==> Creating GitHub Release..."
gh release create "v$VERSION" \
    --title "v$VERSION" \
    --generate-notes \
    --verify-tag

# ── Cleanup ──────────────────────────────────────────────────────
git branch -d "$RELEASE_BRANCH" 2>/dev/null || true

echo ""
echo "Done! v$VERSION released."
echo "  - GitHub Release: https://github.com/sbom-tool/sbom-tools/releases/tag/v$VERSION"
echo "  - CI will publish to crates.io and attach SLSA provenance."
echo "  - Monitor: gh run list --limit 3"
