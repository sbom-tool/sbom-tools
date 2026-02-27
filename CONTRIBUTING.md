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

## Pull Request Guidelines

- Keep PRs focused on a single change
- Include tests for new functionality
- Update documentation if behavior changes
- PRs are squash-merged by default
