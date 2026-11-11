# sbom-tools v0.4.0

## Highlights

The **trustworthy-verdict release.** v0.3.0 asked whether cryptography inventories were read faithfully; this release asks whether a compliance verdict can be gated on. Two reviews of the compliance engine after v0.3.0 found checks that failed open and output that tools could not use. A purl of `NOASSERTION` satisfied identifier rules. An SBOM with no packages passed. A security contact on a third-party dependency counted as the manufacturer's. One error scored as high as a compliant result. GitHub code scanning dropped the SARIF entirely. And a crafted component name could run GitHub Actions workflow commands from `validate`'s default output.

All of those are fixed, and every verdict is now pinned by snapshots, a regression corpus, and a rule matrix that runs every check of every standard in CycloneDX JSON, CycloneDX XML, SPDX 2.3 and SPDX 3.

Alongside the fixes: `validate -o json` is one **versioned envelope** with a published schema and a stable id on every finding; JSON, **SARIF** and **OSCAL 1.2.3** carry the same fields, and each violation names the field it checked, the value it read and the fix; **`--rule`** and **`sbom-tools rules`** tune and list the checks; **`--pqc-mode deadline`** judges cryptography against the NIST IR 8547 (final), CNSA 2.0 and US federal migration dates; and **`validate` reaches the C ABI** and the Go, Swift, Python and Node.js bindings, byte for byte.

> **Please read [Upgrade notes](#upgrade-notes) below** — this release changes exit codes, the `-o json` shape, rule ids, compliance verdicts in both directions, scores, SARIF and OSCAL identity, the ABI version, and the Rust API.

## What's New

### Output for tools

- **JSON envelope v2.** `validate -o json` emits one `sbom-tools/compliance/v2` object for any number of standards, described by `schemas/compliance/v2.schema.json` and `docs/compliance-output.md`. Every violation has a `finding_key` and a `finding_id`, unique within a result, and bundled checks are split into 41 rule ids of their own. `--json-schema v1` keeps the old shape until v0.5.0. (#410, #417)
- **Findings explain themselves.** Each violation names the `field` it checked in the SBOM's own format, the value it read (`observed`), and a `remediation` phrased for CycloneDX, SPDX 2.x or SPDX 3.0, with a `help_uri`. Each result lists the checks it did not evaluate and why. Text output adds the rule id and a `fix:` line. (#408, #442)
- **Passed checks are not violations.** Affirming checks, such as an approved post-quantum algorithm, move to `passed[]` and `counts.passed`. (#421)
- **SARIF for code scanning.** Every result points at the SBOM file and the element's line (`--sarif-base`), fingerprints come from the finding identity so alerts survive edits, every check is its own rule, and runs carry a category (`--sarif-category`) and stay within GitHub's 25,000-result limit. `docs/github-code-scanning.md` covers the setup. (#422, #427)
- **The same audit fields in JSON, SARIF and OSCAL** — the SBOM judged (`subject`, with its SHA-256), the instant (`as_of`), and each finding's id, rule, severity, references and fix. OSCAL moves to 1.2.3, with the SBOM and the component as observation subjects. (#420, #445)
- **A score that ranks verdicts.** Compliant results score 50–100 and non-compliant ones 0–49, normalised by the elements the standard checks; `-o json` carries `score_basis`. (#438)
- **A rule catalogue.** `sbom-tools rules [--standard …]` lists each standard's rules, and `sbom-tools rules explain <RULE_ID>` shows one in full, including where the fix goes in each format. SARIF `rules[]` lists exactly the rules of the standards checked. (#435)

### CLI

- **Usage errors exit `3`** in every command, and **`validate --require-applicable`** exits `1` when a selected standard does not apply to the SBOM. (#410)
- **Per-rule settings.** `--rule RULE=off|info|warning|error` and `compliance.rules` in the config file change a rule's severity for a run or turn it off; overridden and suppressed findings stay visible in the output. `validate --fail-on RULE` gates on one rule. (#443)
- **Dev and test components are left out** of package rules — CycloneDX `scope: excluded`, and SPDX dev, build and test dependencies. Each result says how many, and `--include-excluded-scope` judges them anyway. (#443)
- **Every command judges compliance like `validate`.** `view`, `diff`, `quality`, `cra-docs` and `timeline` give each standard the same clock, CRA sidecar and product class, with `--as-of` on each. (#434, #443)

### Cryptography (CBOM)

- **Every CycloneDX 1.7 algorithm family** is classified, along with JCA names, curve aliases, MACs and KDFs, ending false failures on HMAC and HKDF. (#411)
- **PQ/T hybrids are judged by their parts** — P-384 with ML-KEM-1024 passes CNSA 2.0 — and RFC 9370 additional key exchanges are read. (#415)
- **TLS 1.3 named groups and signature schemes** are judged against the IANA registries; a classical-only TLS 1.3 suite fails CNSA 2.0 and PQC. (#419)
- **CycloneDX XML CBOMs** load and read like JSON. (#412)

### Standards

- **PQC migration deadlines.** `--pqc-mode deadline` judges `pqc` and `cnsa2` findings by their migration schedule at `--as-of`, and each finding carries its `deadline` and source: NIST IR 8547 final (deprecated after 2030, disallowed after 2035), NSA's CNSA 2.0 timeline per `--cnsa-category`, and the US federal dates under `--pqc-profile federal`. The default readiness mode is unchanged. (#437)
- **112-bit hashes under PQC.** SHA-224, SHA-512/224 and SHA3-224 assets are reported under the new rule `SBOM-PQC-HASH-001` (IR 8547 §4.1.3). (#444)
- **sbomqs v2.1.2.** `quality -o sbomqs-json` follows sbomqs v2.1.2, and SPDX 3 documents are scored. (#431)
- **CRA and EO 14028.** A missing ENISA platform id is a Warning from 2026-09-11, the day Art. 14 began to apply; a justified VEX `not_affected` statement counts as vulnerability-handling evidence; and the EO 14028 profile reads as practice, not a federal mandate, after OMB M-26-05. (#431)
- **Citations.** Findings cite ENISA's Technical Advisory for SBOMs v1.10, CNSSP 15, EUCC as amended, and the AI Act as amended by Regulation (EU) 2026/1744, whose Annex IV was confirmed unchanged against the Official Journal. No check changed. (#439, #450)

### Library and performance

- **Compliance in the C ABI and every binding.** `sbom_tools_validate_json` returns exactly the `validate -o json` envelope, `sbom_tools_rule_catalog_json` the rule catalogue, and `sbom_tools_score_sbom_with_options_json` exactly what `quality -o json` prints. Go, Swift, Python and Node expose them with types. (#446)
- **`ComplianceRunConfig`** holds one run's inputs and builds each standard's checker, and the result types, `Component` and `NormalizedSbom` are `#[non_exhaustive]`, so later additions stop being breaking. (#423, #434, #455)
- **Large SBOMs are faster.** All 16 standards on 50,000 components: `-o json` 1.63 s → 0.71 s, `-o sarif` 1.89 s → 0.42 s, `-o oscal-json` 16.3 s → 6.9 s, with byte-identical output. The engine was then restructured around one set of facts per run, again with byte-identical output. (#447, #452–#466)

## Bug Fixes

- **Placeholders satisfied rules.** Empty, `NOASSERTION` or scheme-less purls and CPEs passed identifier rules, and `NOASSERTION`, `TBD` and `N/A` passed supplier, author and version rules. (#397, #399)
- **An SBOM with no packages passed.** It now fails every inventory standard with an inventory finding. (#397)
- **Package rules applied to non-packages, and SPDX packages escaped them.** Files, services and crypto assets drew package findings under EO 14028, SSDF, BSI and CRA, while SPDX packages with purpose `SOURCE`, `ARCHIVE` or `FILE` were exempt. (#398)
- **Crypto profiles failed open.** CNSA 2.0 and PQC passed algorithms, certificates and protocols they could not identify. (#400)
- **CycloneDX XML metadata was dropped** — authors, manufacturer, lifecycles, tools, compositions and signature — so XML SBOMs failed rules their JSON twins pass. (#406, #428)
- **Evidence references were ignored,** and their hashes dropped: attestation, certification-report, risk-assessment and VEX references. Expired EUCC certificates still counted. (#416)
- **A dependency's evidence counted as the manufacturer's.** Security contacts, CVD policies, certificates and attestations on third-party components satisfied the product's CRA, EO 14028 and EUCC checks. Only the product's own references count now, and the product's manufacturer or supplier names the manufacturer. (#436)
- **Empty or garbage digests satisfied hash rules.** A hash counts only as hex digits of its algorithm's length. (#436)
- **Checks skipped an SBOM without saying so.** A component listed twice was judged on its last entry, cycles passed above 1,000,000 dependency edges, an unparseable timestamp was reported as missing, and a filtered `view` judged a different SBOM. (#440, #455)
- **Standards disagreed about the same evidence** — licences, contacts, EUCC certificate URLs, justified VEX statements and SPDX 3 signatures now get one answer in every standard, and a serial number no longer counts as document integrity under the CRA. (#441)
- **Smaller fixes:** future timestamps counted as fresh, CISA 2026 asked SPDX 2.x for fields it cannot express, SPDX 3 vulnerabilities were counted twice, and the CRA sidecar's support date was ignored. (#401, #409, #424, #428)
- **`--fail-on-vuln` passed when OSV could not be queried.** With OSV enrichment on, an offline runner, an OSV outage or an endpoint that failed its queries left the gate with no data, and it exited `0`. `diff`, `view`, `diff-multi`, `timeline` and `matrix` now stop with exit `3`, as `--fail-on-kev` does without the KEV catalog. (#469)
- **Security.** A crafted component name or file name could run GitHub Actions workflow commands, send terminal escapes, or inject Markdown and HTML through human-readable output (GHSA-wmcq-2c3v-6pc3, Moderate); SBOM text and file names are now neutralized in every such output. RUSTSEC-2026-0346 through -0349, -0382 and -0383 (`rustls`, `rustls-webpki`, `webpki-root-certs`), RUSTSEC-2026-0386 (`tokio`) and RUSTSEC-2026-0190 (`anyhow`, CI tooling) are cleared. (#395, #413, #418, #420, #449, #403, #404, #426)

## Upgrade notes

These behaviors changed in this release. `CHANGELOG.md` carries the full list with details, and [`docs/MIGRATING-0.4.md`](https://github.com/sbom-tool/sbom-tools/blob/v0.4.0/docs/MIGRATING-0.4.md) says what to do about each.

- **Usage errors exit `3`,** not `2`. `2` still means warnings, or new vulnerabilities.
- **`--enrich-vulns --fail-on-vuln` needs OSV data.** A job that cannot reach OSV now exits `3`, not `0`. Run it with network access, or pre-populate the cache and pass `--offline`.
- **`validate -o json` emits envelope v2.** `--json-schema v1` keeps the old shape until v0.5.0.
- **Rule ids change.** Bundled rules are split and `SBOM-CRA-ART-14` is retired; Standard and Comprehensive report `SBOM-QUALITY-*` instead of `SBOM-NTIA-*`; and the markers `SBOM-AIACT-NA` and `SBOM-BSIAI-NA` are gone — read `applicable`.
- **Verdicts move both ways.** Placeholders, empty inventories, garbage digests, unidentifiable crypto, 112-bit hashes and a dependency's evidence now fail. CycloneDX XML, evidence references, hybrids and the product's own supplier now pass. Run the release on your SBOMs, with the same `--as-of`, before you upgrade a gate.
- **Dev and test components are left out of package rules.** Pass `--include-excluded-scope` to judge them as before.
- **Scores change.** The compliance score has a new formula, so revisit any threshold on the old scale, and sbomqs-compatible scores follow sbomqs v2.1.2.
- **Info counts drop** — passed checks are not Info violations any more — and the `validate` text report gains a rule-id column.
- **SARIF alerts are re-keyed once.** Results carry locations and fingerprints and every check is its own rule. Use `--sarif-category` instead of upload-sarif's `category` input. `standardIds` and `standardHelpUris` are deprecated for `standardRefs`.
- **OSCAL moves to 1.2.3.** `standard-reference` is renamed `requirement`, and assessment UUIDs change once.
- **CRA:** a missing ENISA platform id is a Warning, so `--fail-on-warning` gates on `cra` and `cra-phase1` can fail.
- **TUI verdicts match `validate`.** The `view` and `diff` TUIs no longer give every standard the CRA sidecar or read the wall clock, so `SBOM-FDA-SUPPORT` can appear where it did not.
- **Library API and ABI:** the ABI version is `2`; the result types, `Component` and `NormalizedSbom` are `#[non_exhaustive]` and gain fields; `run_validate`, `run_quality` and `run_cra_docs_with_force` take more arguments; and `quality::COMPLIANCE_SARIF_RULE_IDS` is removed.
- **GitHub Action:** v1.4.0 keeps `@v1` workflows on sbom-tools 0.3.x. Move to `sbom-tools-action@v2` for 0.4.

## Acknowledgments

Thanks to **@Johnbjoseph-cybersec** (John B Joseph) for reading the Official Journal text of the Digital Omnibus on AI and confirming that Annex IV of the AI Act is unchanged (#450), and to **@Trenyx** (Saurabh Bhatt) for privately reporting the `--fail-on-vuln` gate (#469).

---

Install: `cargo install sbom-tools`
Homebrew: `brew install sbom-tool/tap/sbom-tools`
Crate: https://crates.io/crates/sbom-tools
Full changelog: https://github.com/sbom-tool/sbom-tools/compare/v0.3.0...v0.4.0
