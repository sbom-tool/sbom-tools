# sbom-tools v0.1.21

## Highlights

Focused bug-fix release. `view -o json` now emits the full enriched
vulnerability detail (not just counts), `diff` semantic similarity is
correctly bounded to 0–100 (previously could exceed 100% on large diffs),
and CRA compliance sections in Markdown/HTML diff reports collapse to a
compact summary so reports stay readable on SBOMs with hundreds of
components.

## Bug Fixes

- **`view -o json` now emits enriched vulnerability detail.** The JSON view
  previously dropped enriched OSV/KEV data and emitted only a per-component
  count, even when `--enrich-vulns` was set. Each component now serializes
  the full vulnerability list (id, source, severity, CVSS, `fixed_version`,
  CWEs, KEV info, VEX status, description, dates), and the document gains a
  top-level `vulnerabilities[]` array flattened across all components. Each
  component and flattened entry is also tagged with `dependency_kind`
  (`primary` / `direct` / `transitive`). (#179, fixes #178)
- **`diff` semantic similarity bounded to 0–100.** `DiffResult::semantic_score`
  is normalized against an SBOM-size-derived upper bound and clamped to
  `[0, 100]`, fixing reports of values like 916% on heavy-churn diffs.
  Identical SBOMs (matching content hash) now correctly report 100.0.
  (#188, fixes #180)
- **Compact CRA compliance section in human-readable diff reports.** Markdown
  and HTML diff reports previously emitted a full violation table per CRA
  finding, ballooning to 14k+ lines on real SBOMs. The diff path now emits a
  compact "N findings across M groups" summary with a pointer to `-o json` /
  `-o sarif` for full structured detail. Single-SBOM `view` reports and
  JSON/SARIF outputs are unchanged. (#189, fixes #181)

## Infrastructure

- Dependency bumps: `quick-xml` 0.39.3 → 0.40.1, `clap_complete` 4.6.3 → 4.6.5,
  `tokio` 1.52.2 → 1.52.3 (dagger SDK only).
- GitHub Actions bumps: `codeql-action` 4.35.3 → 4.35.5,
  `cargo-deny-action` 2.0.17 → 2.0.18, `crates-io-auth-action` SHA-pin refresh.
- **Total tests: 1214** (787 lib + 427 integration), up from 1196 in v0.1.20.
- **0 clippy warnings** (default + all-features) on Rust 1.88; **0 production `unwrap()`**.

## Acknowledgments

Thanks to **@MChorfa** (Mohamed Chorfa) for contributing the fixes behind
all three user-facing improvements in this release (#179, #188, #189), and
to **@cmyank0** and **@VincentR-OCD** for the bug reports that drove them.

---

Install: `cargo install sbom-tools`
Homebrew: `brew install sbom-tool/tap/sbom-tools`
Crate: https://crates.io/crates/sbom-tools
Full changelog: https://github.com/sbom-tool/sbom-tools/compare/v0.1.20...v0.1.21
