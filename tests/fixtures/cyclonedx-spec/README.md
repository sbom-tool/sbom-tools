# CycloneDX specification files

Normative files from the CycloneDX specification, kept verbatim so tests can
check the crypto classifier against the spec's own vocabulary.

| File | Upstream | Tag / commit |
|------|----------|--------------|
| `1.7/cryptography-defs.schema.json` | [CycloneDX/specification `schema/cryptography-defs.schema.json`](https://github.com/CycloneDX/specification/blob/1.7/schema/cryptography-defs.schema.json) | `1.7` / `4b3f59453366e27c8073fd24e98bf21ef8892c8e` |

The file is unmodified (SHA-256
`018ea7f78b5208ec647cfd10f669cc9c26aba6aceb79c4da7f9c0ef4c99b60de`). Its
`definitions.algorithmFamiliesEnum` is the list `bom-1.7.schema.json` allows
for `cryptoProperties.algorithmProperties.algorithmFamily`, and
`definitions.ellipticCurvesEnum` the list for `ellipticCurve`.
`tests/crypto_vocabulary_tests.rs` asserts that every family classifies as a
known algorithm. The upstream repository is Apache-2.0.

These files are not SBOMs, so this directory is outside the SBOM fixture
directories the compliance snapshot harness walks.
