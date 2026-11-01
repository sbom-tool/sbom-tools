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

## Compliance

`validateJson` checks raw SBOM content (any supported format) against
compliance standards and returns the `sbom-tools/compliance/v2` envelope,
typed as `ComplianceEnvelope`: what `sbom-tools validate - -o json` writes for
the same content and options. The option keys are the native option names,
the CLI flags in `snake_case`:

```ts
import { readFileSync } from "node:fs";

import { ruleCatalogJson, validateJson } from "@sbom-tools/node";

const envelope = validateJson(readFileSync("bom.cdx.json", "utf8"), {
  file_name: "bom.cdx.json", // validate <FILE>: named in the subject
  standards: ["cra", "ntia"], // --standard; default ["ntia"]
  as_of: new Date(Date.UTC(2027, 0, 1)), // --as-of; a string or a Date
  product_class: "important-class-1", // --cra-product-class
  rules: { "SBOM-NTIA-SUPPLIER": "warning" }, // --rule
});

console.log(envelope.as_of, envelope.subject.sha256);
for (const result of envelope.results) {
  console.log(result.standard, result.compliant, result.counts);
}

const craRules = ruleCatalogJson(["cra"]).rules;
```

The envelope's `as_of` is the instant every standard was judged at (the
`as_of` option, else the wall clock when the call starts, to the second),
and its `subject` gives the SHA-256 of the content passed in and the file
name without its directory, which only `file_name` provides. The other
options are `sidecar` (an object with the keys of a `.cra.json` file),
`pqc_mode`, `pqc_profile`, `cnsa_category` and `include_excluded_scope`. An
invalid option throws `SbomToolsNativeError` with `ErrorCode.Validation`.

`scoreWithOptionsJson(content, { profile, file_name, as_of, ... })` returns
what `sbom-tools quality - -o json` prints for the same content and options
(`quality <FILE>` with `file_name`), typed as `QualityOutput`, with a pinned
clock and the same run options. An AI-readiness profile that does not apply
has `applicable: false`, a `null` score and the grade `N/A`. `scoreJson`
keeps its old behaviour for compatibility.

The package is intentionally private at version `0.0.0-dev`. Publishing
automation is outside the current binding scope.
