# sbom-tools v0.3.0

## Highlights

The **CBOM fidelity release.** v0.2.0 checked whether the tool told the truth; this release asks the same of cryptography inventories, prompted largely by people running real CBOMs through it. A CycloneDX 1.7 IPsec CBOM did not load at all. Crypto fields renamed between CycloneDX 1.6 and 1.7 were read in only one spelling, so an elliptic-curve key declared the 1.6 way, or a certificate linked the 1.7 way, slipped past the CNSA 2.0 and PQC gates. And a sparse IKE CBOM drew 31 findings for missing package versions, suppliers, licenses and hashes on its crypto assets, while the quality score undercounted its real problems — HMAC-SHA1, 3DES and a 1024-bit DH group.

All of those are fixed, and fixtures in both spec versions pin the behaviour.

Alongside the CBOM work: **`convert --to normalized`** exposes the full normalized model on the command line, byte-identical to the C ABI payload; CycloneDX 1.6+ **`manufacturer` and `authors`** now count as producer evidence across nine compliance standards; **Yocto** SPDX 3 documents parse; and a first, unsigned **pipeline receipt** contract lands under `sbom-tools verify`.

> **Please read [Upgrade notes](#upgrade-notes) below** — this release changes several compliance verdicts in both directions, the standard the CBOM quality profile reports, machine-readable output, and the Rust API.

## What's New

### Cryptography (CBOM)

- **CycloneDX 1.7 IKEv2 transforms.** Both the 1.6 bom-ref string and the 1.7 object parse, in JSON and XML. CNSA 2.0 and PQC `PROTO-002` judge each transform by its algorithm reference, IANA name or key-exchange group, including the ML-KEM groups 35–37; a transform that cannot be identified reports `PROTO-UNKNOWN` rather than passing. (#380)
- **Crypto fields are read in both their 1.6 and 1.7 spellings** — the curve, a certificate's signature algorithm and public key, a key material's algorithm, and protocol refs (`cryptoRefArray` / `relatedCryptographicAssets`). A 1.7 certificate that relates several algorithms has every candidate judged, failing closed. (#378)
- **Crypto assets are not packages.** Version, supplier, license, hash and identifier checks no longer apply to `cryptographic-asset` components in any standard or quality metric, and `quality --profile cbom` embeds **NIST PQC** compliance instead of Comprehensive, which ran no crypto checks. (#382)
- **One algorithm classifier** for `quality` and `validate`, so the two agree: `HMAC_SHA1` counts as weak, and IKE groups (`MODPnnnn`, `ECPnnn`, `curve25519`, `curve448`) are classified. The CycloneDX 1.7 protocol types `ike`, `quic`, `wpa`, `sstp`, `eap-aka`, `eap-aka-prime`, `prins` and `5g-aka` are recognised rather than falling through to `Other`. (#382)

### CLI

- **`convert --to normalized`** prints the full normalized model — crypto, ML and dataset detail included — byte-identical to the payload the C ABI and language bindings return, which was previously reachable only by linking the library. (#367)
- **Pipeline receipts.** `verify receipt`, `verify receipt-generate` and `verify receipt-aggregate` validate, generate and aggregate `pipeline-shard-receipt/v1` documents against three versioned JSON Schemas. Receipts are **unsigned and non-promotable** diagnostics; see `docs/pipeline-receipts.md`. (#353)

### Compliance and AI-BOM

- **Component `manufacturer` and `authors` (CycloneDX 1.6+)** are parsed, emitted, and accepted as producer evidence by NTIA, FDA, CRA, CISA 2026, EO 14028, SSDF, both BSI profiles and PCI DSS. (#380)
- **AI-003 accepts nested dataset evidence** — a `contains` child carrying a CycloneDX `data[]` block — alongside `modelParameters.datasets`; a bare nested `type: data` component still does not count. A third-party AI-BOM corpus and `scripts/test-aibom.sh` pin the behaviour. (#361)

### Documentation

- **JSON output contract** in the README: which payloads are contractual, what is test-pinned, and that `view -o json` is a curated projection without crypto, ML or dataset detail. (#364)

## Bug Fixes

- **CycloneDX 1.7 IPsec CBOMs failed to load** — an IKEv2 transform written as a 1.7 object stopped the parser with exit `3`. (#380, #379)
- **The CNSA 2.0 and PQC gates failed open across spec versions.** A 1.6 EC key identified only by `curve` reported an UNKNOWN Warning instead of a quantum-vulnerable Error, and 1.7 certificates linked through `relatedCryptographicAssets` were skipped by `CERT-001`. (#378, #374)
- **CBOMs were graded on package fields** — 31 package-only findings on a sparse IKE CBOM under `quality --profile cbom`, 19 under `validate --standard ntia` — while the quality score undercounted weak crypto and could not classify `modp1024`. (#382, #370)
- **The protocol warning claimed "documents no version"** for protocols that declared one. It now names the fields that are actually missing. (#382, #370)
- **Components that named a `manufacturer` or `authors` failed supplier rules** as though they were anonymous. (#380)
- **Yocto SPDX 3 documents failed to parse** because `suppliedBy` was given as a single string rather than an array. (#349, #348)
- **The TUI Violation Detail overlay clipped its content** at common terminal heights, cutting off remediation text and the close hint, and the CRA supply-chain rule's remediation gave dependency advice instead of naming the supplier fields. (#355, #347)
- **Security.** RUSTSEC-2026-0258 (`h2`), RUSTSEC-2026-0221 (`event-listener`), RUSTSEC-2026-0253 (`lru`, use-after-free), RUSTSEC-2026-0285 (`rustls`) and RUSTSEC-2026-0338 through -0342 (`quinn-proto`) are cleared, with no advisory suppressions. (#352, #369, #388)

## Upgrade notes

These behaviors changed in this release. `CHANGELOG.md` carries the full list with details.

- **Some CBOM gates are stricter.** A 1.6 EC asset identified only by `curve` now fails `ALG-006`, 1.7 certificates and protocols linked through `relatedCryptographicAssets` are now evaluated, and 1.7 IPsec CBOMs that failed to parse are now judged. A passing `validate` run can now exit `1`.
- **Other gates are looser.** Crypto assets no longer get package findings under NTIA, FDA, CRA, Standard, Comprehensive, CISA 2026, PCI DSS or FSCT, and a named `manufacturer` or `authors` now satisfies supplier rules. A failing run can now exit `0`.
- **`quality --profile cbom` reports NIST PQC compliance** instead of Comprehensive, and CBOM scores move in both directions — the #370 fixture goes from 42.1 to 37.2.
- **JSON gains fields, additively:** `cryptography_metrics.protocols_with_algorithm_refs` in quality output; `related_crypto_assets`, component `manufacturer`, and IKEv2 `auth` and `transforms` in the normalized payload.
- **Library API:** `Component` gains `manufacturer` and `Ikev2TransformTypes` gains `auth` and `transforms`; code that builds them with struct literals must add the fields. `ProtocolType` gains eight variants.

## Acknowledgments

Thanks to **@lvlrSajjad** (Sadjad (Mo) Asadi) for the issues behind the curve fix and the normalized-JSON work (#362, #366, #374), to **@paul007ex** for the CBOM evaluation in #370, to **@iwanicki92** for reporting #347 and both reporting and fixing #348 (#349), and to **@MChorfa** (Mohamed Chorfa) for the pipeline-receipt contract (#350, #353) and the CI baseline, benchmark and security-gate repairs (#351, #369).

---

Install: `cargo install sbom-tools`
Homebrew: `brew install sbom-tool/tap/sbom-tools`
Crate: https://crates.io/crates/sbom-tools
Full changelog: https://github.com/sbom-tool/sbom-tools/compare/v0.2.0...v0.3.0
