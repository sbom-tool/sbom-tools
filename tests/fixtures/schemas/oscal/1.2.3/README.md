# OSCAL 1.2.3 assessment-results JSON schema

The JSON schema of the OSCAL assessment-results model, kept verbatim so
`tests/oscal_schema_tests.rs` can validate what `validate -o oscal-json`
emits against the release it declares in `metadata.oscal-version`.

| File | Upstream | Release tag / commit |
|------|----------|----------------------|
| `oscal_assessment-results_schema.json` | <https://github.com/usnistgov/OSCAL/releases/download/v1.2.3/oscal_assessment-results_schema.json> | [`v1.2.3`](https://github.com/usnistgov/OSCAL/releases/tag/v1.2.3) (2026-08-07) / `e061961c7702afeabffdf5e59894d35e748dade1` |

The file is unmodified (SHA-256
`4034e2032332dbf597e59e0646ec16c2c31df992962490371e91f47b219ff42c`, 152,214
bytes, the digest GitHub publishes for the release asset). It is JSON Schema
draft-07. It covers what the JSON schema can express; the Metaschema
constraints OSCAL adds on top (allowed values, `is-unique` and index
constraints) are not in it, so the test file checks the ones that apply to
our output itself.

The OSCAL project is a work of the United States government, in the public
domain in the United States and dedicated worldwide under CC0 1.0. NIST asks
to be acknowledged as the source.

These files are not SBOMs, so this directory is outside the SBOM fixture
directories the compliance snapshot harness walks.
