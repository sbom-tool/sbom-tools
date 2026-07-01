# sbom-tools Node.js bindings

Private development package providing synchronous TypeScript bindings over the
`sbom-tools` C ABI with Koffi.

> **Developer preview:** this binding requires a native library built from the
> same source tree. Native npm packages and publishing automation are not
> available.

Start with the [project overview](../../docs/PROJECT_OVERVIEW.md) and
[user journeys](../../docs/USER_JOURNEYS.md) to understand where Node.js fits
in the end-to-end workflow. Those documents are introduced by
[PR #276](https://github.com/sbom-tool/sbom-tools/pull/276) and must land before
these relative links resolve on the upstream default branch.

When troubleshooting, include the output of `version()` in bug reports so the
loaded ABI and Rust crate versions are explicit.

## Build and test

From the repository root:

```sh
cargo build -p sbom-tools-ffi --release
cd bindings/nodejs
npm ci
npm test
```

The native library is resolved in this order:

1. `SBOM_TOOLS_LIB_PATH`
2. `bindings/nodejs/native/`
3. repository `target/release`, then `target/debug`
4. system library lookup

An invalid explicit `SBOM_TOOLS_LIB_PATH` is an error and does not fall through
to other locations.

The package is intentionally private at version `0.0.0-dev`. Publishing
automation is outside the current binding scope.
