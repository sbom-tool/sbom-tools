# Contributing to sbom-tools

Thank you for your interest in contributing!

## Getting Started

1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes
4. Run the checks: `cargo fmt --check && cargo clippy --all-features -- -D warnings && cargo test --all-features`
5. Open a pull request

## Development Requirements

- Rust 1.88+ (see `rust-toolchain.toml`)
- All PRs must pass CI (lint, test, cargo-deny, CodeQL)
- All PRs require at least one approving review

## Code Style

- Run `cargo fmt` before committing
- Zero clippy warnings (`cargo clippy --all-features -- -D warnings`)
- No `unwrap()` in production code; use `expect()` only when safe-by-construction
- Prefer `&str` over `&String`, `&[T]` over `&Vec<T>`
- Use `thiserror` for library errors, `anyhow` for CLI

## Developer Certificate of Origin (DCO)

By contributing to this project, you certify that your contribution was created in whole or in part by you and you have the right to submit it under the MIT license. This is the [Developer Certificate of Origin](https://developercertificate.org/).

You do not need to sign off each commit, but by submitting a pull request you agree to the DCO.

## Reporting Issues

- **Bugs:** Open a [GitHub Issue](https://github.com/sbom-tool/sbom-tools/issues)
- **Security vulnerabilities:** See [SECURITY.md](SECURITY.md) (do NOT open a public issue)

## Adding a standard

Everything sbom-tools knows about a compliance standard apart from its checks
is one entry of the standards table, `STANDARDS` in
`src/quality/compliance/standards.rs`. The level's names, the `--standard`
spellings, the rule list, the checker, the run inputs and the reports' key
all come from there. To add a standard:

1. Add a `ComplianceLevel` variant (`level.rs`). Its position is its place
   in every list of standards users see.
2. Add its `StandardDescriptor` to `STANDARDS` at the same position. The
   build fails if the entry is out of place, and the `standards` tests fail
   until every level has one.
3. Declare its rules in a family module under `registry/`, list them in a
   slice in `registry/mod.rs` (the entry's `rules`), and register its
   `SBOM-<FAMILY>-GENERAL` fallback rule (the entry's `fallback_rule`).
4. Write its checks in a module of their own and a `dedicated_checker!` in
   `context.rs` (the entry's `checker`); a profile of the generic path uses
   `GenericChecker::boxed`. The checks read the SBOM only through the
   evidence layer (`ctx.ev`, `src/quality/compliance/evidence/`): a fact the
   standard needs and the evidence lacks goes there, with a unit test,
   defined once for every standard (if the standard judges an element
   differently from another one on purpose, add a separately named fact
   rather than change an existing one). Add the module to `READS_EVIDENCE`
   in `tests/evidence_layer_lint.rs`; the lint fails until you do, and
   whenever the module names the SBOM, reads the clock or derives a fact
   the evidence holds.
5. If `--standard` selects it (the entry's `cli`), add a `StandardSelector`
   variant where `--help` should list it, with its arms in `level()` and
   `value_variants()`, and add its spellings to the alias tables in the
   selector tests and `tests/cli_standard_alias_tests.rs` and to the
   `--standard` help in `src/main.rs`. Tests check each against the table.
6. If the TUI offers it as a preset (`in_tui_presets`), add a `PolicyPreset`
   variant in `src/tui/app_states/compliance.rs`.
7. Give it a rule matrix (`tests/rule_matrix_*.rs`) with a firing and a
   silent fixture for each rule, and review the new snapshots of
   `tests/compliance_snapshots.rs`.

## Pull Request Guidelines

- Keep PRs focused on a single change
- Include tests for new functionality
- Tests must not depend on today's date: build compliance checkers with `checker(level)` from `tests/common/clock.rs`, or pin an explicit instant with `.with_as_of(...)` (enforced by `tests/pinned_clock_tests.rs`)
- Update documentation if behavior changes
- PRs are squash-merged by default
