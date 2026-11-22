# Dagger Rust SDK for SBOM Tools

This Rust SDK client builds the Linux FFI library and runs ABI and Go checks. The
locked SDK version is 0.21.12, which starts the matching Dagger CLI and engine
when no session is supplied.

Supported commands:

- `build-staticlib`: build debug static library artifact
- `release-staticlib`: build release static library artifact
- `test-abi`: run ABI contract tests
- `test-go`: build the release static library once, then run the Go wrapper
  suite and focused dedup tests against that library in the Go 1.22 container
- `ci-all`: run the workspace, FFI, ABI and Go checks (default)

Run from the repository root with Docker and a stable Rust toolchain:

```sh
RUSTUP_TOOLCHAIN=stable ./scripts/run-dagger-ci.sh
RUSTUP_TOOLCHAIN=stable ./scripts/run-dagger-ci.sh test-go
```

The second command is the Linux Go pilot. Compare it with the existing native
Ubuntu Go job on the same commit. Native macOS validation uses the GitHub
Actions runner and its own Rust library build.
