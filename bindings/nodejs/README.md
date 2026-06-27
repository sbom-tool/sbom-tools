# sbom-tools Node.js bindings

Private development package providing synchronous TypeScript bindings over the
`sbom-tools` C ABI with Koffi.

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
