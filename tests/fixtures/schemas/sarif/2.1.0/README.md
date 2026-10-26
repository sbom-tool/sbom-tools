# SARIF 2.1.0 JSON schema

The JSON schema of the Static Analysis Results Interchange Format (SARIF)
2.1.0, kept verbatim so `tests/sarif_schema_tests.rs` can validate what every
`-o sarif` writer emits against the version it declares in `version` and
`$schema`.

| File | Upstream | Edition |
|------|----------|---------|
| `sarif-schema-2.1.0.json` | <https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json> | SARIF Version 2.1.0 Plus Errata 01, OASIS Standard incorporating Approved Errata, 28 August 2023 |

The file is unmodified (SHA-256
`c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e`, 112,768
bytes, downloaded 2026-10-26). It is JSON Schema draft-04 and its `id` is the
URL above, which is also the `$schema` the writers declare. It covers what
the JSON schema can express; the prose rules of the standard (for example
that a `partialFingerprints` key is a versioned hierarchical string, or that
a result whose `kind` is not `fail` has the level `none`) are not in it.

The schema is part of the OASIS SARIF standard, Copyright © OASIS Open 2023,
published under the OASIS IPR Policy, which allows the document to be copied
and furnished to others unmodified.

These files are not SBOMs, so this directory is outside the SBOM fixture
directories the compliance snapshot harness walks.
