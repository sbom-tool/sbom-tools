# sbom-tools v0.4.0-rc.1

**This is a release candidate**, published <DATE>, for sbom-tools v0.4.0, a breaking release. The final release is planned for 2026-12-11. Please try it before then:
- **Run it on your own SBOMs** and compare its verdicts with 0.3.0's. Pass the same `--as-of` to both, so they judge the same instant.
- **Read the [migration guide](https://github.com/sbom-tool/sbom-tools/blob/v0.4.0-rc.1/docs/MIGRATING-0.4.md).** Exit codes, JSON, SARIF and OSCAL output, rule ids, scores and the Rust API change.
- **Report problems** as [GitHub issues](https://github.com/sbom-tool/sbom-tools/issues). Report a security problem as the [security policy](https://github.com/sbom-tool/sbom-tools/security/policy) describes, not in an issue.

Install it with `cargo install sbom-tools --version 0.4.0-rc.1`, or take a binary from this page. Nothing upgrades to it unasked: `cargo install sbom-tools` skips a pre-release, the Homebrew tap carries stable releases only, and a pre-release is never GitHub's Latest release, so `sbom-tools-action@v1` with `version: latest` stays on 0.3.0.

## Highlights

The **trustworthy-verdict release.** A review of the compliance engine after v0.3.0 found 39 problems:
- **False passes:** checks that failed open.
- **False failures.**
- **Injection:** SBOM text could forge CI annotations.
- **Unusable machine output:** SARIF that GitHub code scanning dropped entirely, and JSON whose findings had no stable identity.

A second review, on 2026-10-31, found more of the same kind: a dependency's evidence counted as the manufacturer's, one error scored as high as a compliant result, standards disagreed about the same evidence, and checks skipped an SBOM without saying so.

This release fixes all of them. Every verdict is pinned by snapshots, a regression corpus, and a rule matrix that runs every check of every standard in CycloneDX JSON, CycloneDX XML, SPDX 2.3 and SPDX 3.

What changes for you:
- **Verdicts you can gate on.** Placeholders, empty identifiers, digests that are not digests and assets nothing can identify no longer satisfy a rule, and checks that failed open now fail closed. Only the product's own evidence counts as the manufacturer's. Some false failures are gone too: CycloneDX XML is read like JSON, evidence references count, and test and development dependencies leave the package rules.
- **Output tools can consume:**
  - `-o json` is one versioned envelope with a published schema, and every finding has a stable id;
  - JSON, SARIF and OSCAL carry the same fields: the SBOM judged, the instant, and each finding's rule, severity, references and fix;
  - every violation says how to fix it in the SBOM's own format, which field it checked and what value it read;
  - checks the SBOM passed are listed apart from violations, and checks a standard did not evaluate are listed with the reason;
  - SARIF puts each finding on the SBOM line it is about, with a fingerprint that survives edits;
  - OSCAL output moves to 1.2.3.
- **Runs you can tune:** `--rule RULE=off|info|warning|error` sets a rule's severity for a run, `validate --fail-on RULE` gates on one rule, and `sbom-tools rules` lists what each standard checks.
- **Cryptography completed:** every CycloneDX 1.7 algorithm family, PQ/T hybrids judged by their parts, TLS 1.3 groups and signature schemes, and, under `--pqc-mode deadline`, the migration deadlines of NIST IR 8547 (final), CNSA 2.0 and the US federal deadlines.
- **Compliance from the bindings:** the C ABI and the Go, Swift, Python and Node.js bindings return `validate`'s envelope byte for byte.
- **A security fix:** the security advisory published with v0.4.0 covers workflow-command, terminal-escape and Markdown injection through SBOM text in human-readable output.

> **Please read [Upgrade notes](#upgrade-notes) below, and the [migration guide](https://github.com/sbom-tool/sbom-tools/blob/v0.4.0-rc.1/docs/MIGRATING-0.4.md).** Usage errors exit `3`, `-o json` changes shape, rule ids are split and renamed, verdicts move in both directions, scores use a new formula, SARIF alerts and OSCAL UUIDs are re-keyed, the ABI version is `2`, and the Rust result types are `#[non_exhaustive]`.

## What's New

### Output for tools

- **JSON envelope v2.** `validate -o json` emits one `sbom-tools/compliance/v2` object for any number of standards, described by `schemas/compliance/v2.schema.json` and `docs/compliance-output.md`. `--json-schema v1` keeps the old shape until v0.5.0. (#410)
- **Stable finding identity.**
  - Every violation has a `finding_key` (standard, rule, detail, subject) and a `finding_id`, unique within a result.
  - Bundled checks are split into rules of their own: 41 new rule ids, such as `SBOM-CRA-ART-14-PSIRT` and the `-ELEMENT-ID` checks.

  (#410, #417)
- **Remediation everywhere.** Each violation carries `remediation`, phrased for the input format (CycloneDX, SPDX 2.x or SPDX 3.0), and a `help_uri`. Text output adds a `fix:` line. (#408)
- **Passed checks are not violations.** Affirming checks, such as an approved post-quantum algorithm, move to `passed[]` and `counts.passed`. OSCAL reports them as satisfied, and SARIF only with `--sarif-include-passes`. (#421)
- **SARIF for code scanning.**
  - Every result points at the SBOM file and the element's line, relative to the repository (`--sarif-base`).
  - Fingerprints come from the finding identity, so alerts survive edits.
  - Every check is its own rule, with help text.
  - Runs carry a category (`--sarif-category`) and keep at most 25,000 results, GitHub's limit (`--sarif-max-results`).
  - A new guide, `docs/github-code-scanning.md`, covers the setup.

  (#422, #427)
- **A score that ranks verdicts.** Every compliance score is `(50 when compliant, else 0) + floor(50 × checked / (checked + failed))`: compliant results score 50–100 and non-compliant ones 0–49, normalised by the document and the components the standard checks. `-o json` results carry `score_basis: {checked, failed}`. (#438)
- **Findings explain themselves.** Each violation names the `field` it checked, in the SBOM's own format (`metadata.component.supplier.name`), and the value it read (`observed`). Each result lists the checks it did not evaluate and why (`evaluated`), such as CISA 2026's signature check on SPDX 2.x. Text output prints the rule id on every finding. (#442)
- **The same audit fields in JSON, SARIF and OSCAL.** Every output states the SBOM it judged (`subject`: SHA-256, format, spec version, components, merged duplicates) and the instant (`as_of`); every finding carries the same id, key, rule, severity, references, remediation, field and observed value; and every verdict carries the same counts. One standard key (`cra`) everywhere. Without `--as-of`, `validate` judges every standard at one instant, the wall clock when it starts. (#445)
- **OSCAL 1.2.3** assessment results. Observations name the SBOM and the component as subjects, and the SBOM is described in back-matter with its digest. (#420)
- **A rule catalogue.** `sbom-tools rules [--standard …]` lists each standard's rules with severity, references and a fix summary, and `sbom-tools rules explain <RULE_ID>` shows one rule in full, including where the fix goes in each format. `-o json` emits `sbom-tools/rules/v1` (`schemas/rules/v1.schema.json`). SARIF `rules[]` now lists exactly the rules of the standards checked. (#435)

### CLI

- **Usage errors exit `3`** in every command (they used to exit `2`, like warnings). (#410)
- **`validate --require-applicable`** exits `1` when a selected standard does not apply to the SBOM, such as `ai-act` on an SBOM with no AI components. (#410)
- **Per-rule settings.** `--rule RULE=off|info|warning|error` (repeatable) and `compliance.rules` in the config file change a rule's severity for a run, or turn the rule off. An overridden finding keeps its own severity as `default_severity`, with `severity_source`. `off` drops the rule's findings and counts them under `suppressed`, so nothing disappears silently. Verdicts, scores and exit codes follow the settings. `validate --fail-on RULE` fails on any finding of that rule, whatever its severity. (#443)
- **Dev and test components are left out.** Components with CycloneDX `scope: excluded`, or reached only through SPDX dev, build or test relationships, are left out of package rules; each result says how many (`excluded_components`), and `--include-excluded-scope` judges them anyway. (#443)
- **`timeline --as-of`** and the other run flags pin the timeline's compliance trend; the PQC options have config-file keys. (#443)
- **Every command judges compliance like `validate`.** `view` and `diff` (TUIs, reports, quality delta), `quality`, `cra-docs` and the timeline trend give each standard the inputs `validate` gives it: the clock, the CRA sidecar and the product class. New flags: `--as-of` on `view`, `diff` and `cra-docs`, and `--cra-product-class` on `diff`. A standard selected twice, such as `--standard cra,cra-phase2`, is checked once. (#434)

### Cryptography (CBOM)

- **Every CycloneDX 1.7 algorithm family** is classified, along with JCA names, curve aliases, and MACs and KDFs. This ends false failures on HMAC and HKDF. (#411)
- **PQ/T hybrids are judged by their parts.** P-384 with ML-KEM-1024 passes CNSA 2.0, and RFC 9370 additional key exchanges are read. (#415)
- **TLS 1.3 named groups and signature schemes** are judged against the IANA registries, GREASE excepted. A classical-only TLS 1.3 suite fails CNSA 2.0 and PQC. (#419)
- **CycloneDX XML CBOMs** load and read like JSON: crypto functions, cipher suites, crypto references and `isExternal`. (#412)

### Standards

- **PQC migration deadlines.** `--pqc-mode deadline` judges `pqc` and `cnsa2` findings by their migration schedule at `--as-of`, and each finding carries its `deadline` and `deadline_source`. `pqc` uses NIST IR 8547 final (2026-10-27): quantum-vulnerable schemes are deprecated after 2030 and disallowed after 2035. `--pqc-profile federal` adds the EO 14412 / OMB M-26-15 dates, and TLS 1.3 by 2030-01-02 (EO 14306; new rule `SBOM-PQC-PROTO-003`). `cnsa2` uses NSA's CNSA 2.0 timeline, per `--cnsa-category`. The default readiness mode is unchanged. IR 8547 is cited as final everywhere. (#437)
- **112-bit hashes under PQC.** `pqc` reports SHA-224, SHA-512/224 and SHA3-224 crypto assets under the new rule `SBOM-PQC-HASH-001` (NIST IR 8547 §4.1.3: disallowed after 2030); a SHA-2 asset with no stated size draws a Warning. In deadline mode a signature over a 224-bit digest takes the 2030 deadline. (#444)
- **sbomqs v2.1.2.** `quality -o sbomqs-json` follows sbomqs v2.1.2 and prints the pinned version. A purl or CPE counts as a unique id, sharability follows sbomqs's free-for-any-use licences, and SPDX 3 documents are scored. (#431)
- **EO 14028 as practice.** The profile no longer reads as a federal mandate: OMB M-26-05 rescinded M-22-18 and M-23-16, and the FAR case was withdrawn. (#431)
- **CRA:**
  - A missing ENISA platform id is a Warning from 2026-09-11, the day Art. 14 began to apply. Naming the CSIRT designated as coordinator satisfies it.
  - The product classes cite Implementing Regulation (EU) 2025/2392.
  - A VEX `not_affected` statement with a machine-readable justification counts as vulnerability-handling evidence, following the CRA FAQ v1.4.

  (#431)
- **Citations:** CRA SBOM-content findings also cite ENISA's Technical Advisory for SBOMs (v1.10, October 2026); CNSA 2.0 findings cite CNSSP 15; EUCC is cited as amended by 2024/3144 and 2025/2462, and the AI Act as amended by Regulation (EU) 2026/1744 (the Digital Omnibus on AI). No check changed. (#439)
- **VEX:** the SBOM's own CycloneDX analysis and a `--vex` CycloneDX file map justifications the same way, and a CSAF document newer than 2.0 prints a warning. (#431)

### Library

- **`#[non_exhaustive]`** on the compliance result types and `Component`, so later additions stop being breaking. (#423)
- **Compliance in the C ABI and every binding.** `sbom_tools_validate_json` returns exactly the `validate -o json` envelope for any standard, sidecar, product class, PQC mode, rule settings or `as_of`; `sbom_tools_rule_catalog_json` returns the rule catalogue; and `sbom_tools_score_sbom_with_options_json` returns exactly what `quality -o json` prints. Go, Swift, Python and Node expose them with types. The ABI version is now 2. (#446)
- **`ComplianceRunConfig`** holds one run's inputs (the clock, the CRA sidecar, the product class, the PQC mode, the rule settings and the excluded scope) and builds each standard's checker with exactly the inputs it reads. The CLI, the TUIs, the report writers and the C ABI use it. (#434, #437, #443)

## Bug Fixes

- **Security: injection through SBOM text in human-readable output** (the security advisory published with v0.4.0). A crafted component name could:
  - run GitHub Actions workflow commands from `validate`'s default output, forging annotations or hiding log lines;
  - send terminal escapes and bidi overrides to a terminal or log viewer;
  - inject Markdown or HTML into the reports, the `cra-docs` dossier and OSCAL markup fields.

  SBOM text is now neutralized in every human-readable output. (#395, #413, #418, #420)
- **Security: dependency advisories.** rustls, rustls-webpki and webpki-root-certs (RUSTSEC-2026-0346 to -0349, -0382, -0383, #403), tokio (RUSTSEC-2026-0386, #404), and anyhow in the Dagger CI tooling (RUSTSEC-2026-0190, #426).
- **Placeholder identifiers counted.** Empty, `NOASSERTION` or scheme-less purls and CPEs satisfied identifier rules, and components that shared one collapsed into one. (#397)
- **An SBOM with no packages passed.** It now fails every inventory standard with an inventory finding. (#397)
- **Package rules applied to non-packages, and SPDX packages escaped them.** Files, services and crypto assets drew package findings under EO 14028, SSDF, BSI and CRA. SPDX packages with purpose `SOURCE`, `ARCHIVE` or `FILE` were exempt. (#398)
- **Placeholders satisfied elements.** `NOASSERTION`, `TBD`, `N/A` and the like satisfied supplier, author and version rules. (#399)
- **Crypto profiles failed open.** CNSA 2.0 and PQC passed algorithms, certificates and protocols they could not identify. (#400)
- **Smaller fixes:** the CRA sidecar's support date was ignored, `quality --as-of` did not reach certificate expiry, the format-version checks disagreed, and SARIF links pointed at an old repository. (#401)
- **CycloneDX XML metadata was dropped:** authors, manufacturer, lifecycles, tools, compositions and signature. So XML SBOMs failed rules their JSON twins pass. AI-BOM model cards were dropped too. (#406, #428)
- **Future timestamps counted as fresh,** CISA 2026 warned on the cyclonedx-maven-plugin's default hashes, and it asked SPDX 2.x for fields SPDX 2.x cannot express. (#409)
- **Evidence references were ignored,** and their hashes dropped: CycloneDX attestation, certification-report, risk-assessment and VEX references, and their SPDX 3 counterparts. Expired EUCC certificates still counted. (#416)
- **SPDX 3 vulnerabilities were counted twice** when a relationship and an assessment described the same one. Components re-keyed after an id collision were judged as if they had no identifiers. (#424)
- **Smaller parser and check fixes:** an empty SPDX 3 signature counted as a signature, SPDX 3 metrics were misnamed, and an empty or placeholder document name counted as a name. (#428)
- **The CRA status table for CSAF** in docs/CRA_COMPLIANCE.md swapped `last_affected` and `recommended`. (#431)
- **A dependency's evidence counted as the manufacturer's.** Security contacts, CVD policies, certificates and attestations on third-party components satisfied the product's CRA, EO 14028 and EUCC checks, whenever the dependency graph left them unlinked. Only the product's own references count now. (#436)
- **The manufacturer was read only from SBOM creators.** Art. 13(16) and FDA now accept the product's manufacturer or supplier, and CycloneDX `metadata.supplier`. Placeholders never count. (#436)
- **A support link counted as the disclosure policy, in CycloneDX only.** All three parsers now take the primary's first URL-shaped advisories reference. (#436)
- **Empty or garbage digests satisfied hash rules.** A hash counts only as hex digits of its algorithm's length, and the finding says why one did not count. An empty CycloneDX XML `<hash>` no longer fails the parse. (#436)
- **A component listed twice was judged on its last entry.** Entries of one component are now merged whatever their order: every hash, licence and reference is kept, and a real value beats a placeholder. The generic standards report the duplicates as an Info finding. (#440)
- **Cycles in very large graphs passed.** `SBOM-CRA-CYCLES` was skipped above 1,000,000 dependency edges; it now checks graphs of any size. (#440)
- **An unparseable timestamp was reported as missing.** The finding now quotes the value. (#440)
- **A filtered `view` judged a different SBOM.** With `--severity`, `--ecosystem` or `--vulnerable-only`, the compliance tab, its exports and the quality score now judge the whole SBOM. (#440)
- **Standards disagreed about the same evidence.** One test now answers each question in every standard (#441):
  - a licence must be a known SPDX expression or LicenseRef (`NOASSERTION` and `TBD` failed CRA but passed Standard);
  - a contact must reach someone (placeholders and `example.com`/`.net`/`.org` addresses no longer count, in the SBOM or the sidecar);
  - EUCC certificate URLs are recognised alike by CRA and EUCC;
  - a justified VEX `not_affected` statement counts the same under CRA, FDA and PCI DSS;
  - FSCT reads SPDX 3 signatures as CISA 2026 does.
- **A serial number counted as document integrity.** `SBOM-CRA-DOC-INTEGRITY` now needs a document signature, or a hashed attestation or certification reference on the product. (#441)

## Upgrade notes

These behaviours changed in this release. The [migration guide](https://github.com/sbom-tool/sbom-tools/blob/v0.4.0-rc.1/docs/MIGRATING-0.4.md) has every change, with what to do about it.

- **Exit codes.** Usage errors exit `3`, not `2`. `2` still means warnings, or new vulnerabilities.
- **JSON.** `validate -o json` emits envelope v2. `--json-schema v1` keeps the old shape until v0.5.0.
- **Rule ids.** Bundled rules are split, and `SBOM-CRA-ART-14` is retired. The not-applicable markers SBOM-AIACT-NA and SBOM-BSIAI-NA are gone: read `applicable`.
- **More rule ids.** Standard and Comprehensive report `SBOM-QUALITY-VERSION`, `-TIMESTAMP`, `-SUPPLIER` and `-DEPENDENCY` instead of `SBOM-NTIA-*`; FDA's manufacturer check is `SBOM-FDA-MANUFACTURER` and its timestamp check `SBOM-FDA-TIMESTAMP`. (#441)
- **Verdicts move both ways.** Placeholders, empty inventories, garbage digests, unidentifiable crypto and 112-bit hashes now fail. CycloneDX XML, evidence references, hybrids, the classifier's new names and the product's own supplier now pass where they failed. Run the release on your SBOMs before you upgrade a gate.
- **Excluded scope.** Components a CycloneDX SBOM marks `scope: excluded`, and SPDX development, build and test dependencies, are left out of the package rules of every standard. Pass `--include-excluded-scope` to judge them as before. (#443)
- **Duplicate components** are merged whatever the order of their entries, and the generic standards report them as an Info finding. (#440)
- **Info counts drop.** Passed checks are not Info violations any more.
- **SARIF.** Results carry locations and fingerprints, and every check has its own rule, so the first upload after upgrading re-keys code-scanning alerts. Runs name their category, so upload-sarif's `category` input no longer applies: use `--sarif-category`. `diff -o sarif` reports into the new SBOM only.
- **SARIF `rules[]`** lists only the rules of the standards checked (BSI: 16 instead of a shared 107), so `ruleIndex` values change. Rule ids and fingerprints do not, and alerts are kept. `quality::COMPLIANCE_SARIF_RULE_IDS` is removed: use `rules_for_level`. (#435)
- **OSCAL** moves to 1.2.3. A result's `standard` is the canonical key (`cra`), `standard-reference` is renamed `requirement`, and assessment UUIDs change once. (#445)
- **Deprecated:** the SARIF result properties `standardIds` and `standardHelpUris`; read `standardRefs`. They are removed in v0.5.0. (#445)
- **sbomqs-compatible scores** follow sbomqs v2.1.2. 89 of the 129 test fixtures change score.
- **CRA:** a missing ENISA platform id is a Warning from 2026-09-11, so `--fail-on-warning` gates on `cra` and `cra-phase1` can fail.
- **Scores change.** The compliance score has a new formula (#438): a result with one error now scores below every compliant result, and one finding no longer halves a large SBOM's score. Revisit any threshold on the old scale.
- **Text output** escapes SBOM text, and the `validate` text report names each finding's rule, so a script that splits a finding line on ` | ` sees one more column (#442). Read `-o json` instead.
- **Manufacturer evidence and digests** (#436): a dependency's references no longer pass the product's manufacturer checks; a product supplier now names the manufacturer (fewer Art. 13(16) and FDA warnings); a hash value that is not a digest of its algorithm fails BSI, FDA, CRA, FSCT, CISA 2026, EO 14028, SSDF and BSI SBOM-for-AI hash rules.
- **TUI verdicts match `validate`.** The `view` and `diff` TUIs used to give every standard the CRA sidecar and read the wall clock. FDA no longer reads the sidecar's support date there, so `SBOM-FDA-SUPPORT` can appear where it did not. `oss-steward` takes no product class: no `conformity_summary`, and `SBOM-CRA-CYCLES` stays a Warning. (#434)
- **ABI version `2`.** Code that checks `abi_version == "1"` must accept `"2"`. `sbom_tools_score_sbom_json` is unchanged. (#446)
- **Library.** The result types and `Component` are `#[non_exhaustive]`. `ComplianceResult`, `Violation`, `DocumentMetadata` and `NormalizedSbom` gain fields; `run_validate`, `run_quality` and `run_cra_docs_with_force` take more arguments; and the TUIs take a `ComplianceRunConfig` instead of their CRA sidecar setters.
- **GitHub Action.** A pre-release is never GitHub's Latest release, so `sbom-tools-action@v1` with `version: latest` stays on 0.3.x through the release candidate. For v0.4.0, Action v1.4.0 keeps `@v1` workflows on 0.3.x, and `sbom-tools-action@v2` runs 0.4.

---

Install: `cargo install sbom-tools --version 0.4.0-rc.1`
Crate: https://crates.io/crates/sbom-tools/0.4.0-rc.1
Full changelog: https://github.com/sbom-tool/sbom-tools/compare/v0.3.0...v0.4.0-rc.1
