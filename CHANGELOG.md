# Changelog

Release notes for every version, in the same form as the
[GitHub Releases page](https://github.com/sbom-tool/sbom-tools/releases):
**Highlights**, **What's New**, **Bug Fixes**, and **Upgrade notes**. Each
published version's notes are also kept verbatim in `RELEASE_NOTES_v*.md`.

sbom-tools is pre-1.0 (`0.x`), so breaking changes are permitted in a minor
release — but they are never implied by the version number alone. Every one of
them is listed under **Upgrade notes** for its release.

---

## v0.4.0-rc.1 — <DATE>

Release candidate for v0.4.0, whose final release is planned for 2026-12-11.
Full notes: [`RELEASE_NOTES_v0.4.0-rc.1.md`](RELEASE_NOTES_v0.4.0-rc.1.md)
· [GitHub release](https://github.com/sbom-tool/sbom-tools/releases/tag/v0.4.0-rc.1)
· every breaking change, with what to do: [`docs/MIGRATING-0.4.md`](docs/MIGRATING-0.4.md)

### Highlights

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

> **Please read [Upgrade notes](#upgrade-notes) below, and the [migration guide](docs/MIGRATING-0.4.md).** Usage errors exit `3`, `-o json` changes shape, rule ids are split and renamed, verdicts move in both directions, scores use a new formula, SARIF alerts and OSCAL UUIDs are re-keyed, the ABI version is `2`, and the Rust result types are `#[non_exhaustive]`.

### What's New

#### Output for tools

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

#### CLI

- **Usage errors exit `3`** in every command (they used to exit `2`, like warnings). (#410)
- **`validate --require-applicable`** exits `1` when a selected standard does not apply to the SBOM, such as `ai-act` on an SBOM with no AI components. (#410)
- **Per-rule settings.** `--rule RULE=off|info|warning|error` (repeatable) and `compliance.rules` in the config file change a rule's severity for a run, or turn the rule off. An overridden finding keeps its own severity as `default_severity`, with `severity_source`. `off` drops the rule's findings and counts them under `suppressed`, so nothing disappears silently. Verdicts, scores and exit codes follow the settings. `validate --fail-on RULE` fails on any finding of that rule, whatever its severity. (#443)
- **Dev and test components are left out.** Components with CycloneDX `scope: excluded`, or reached only through SPDX dev, build or test relationships, are left out of package rules; each result says how many (`excluded_components`), and `--include-excluded-scope` judges them anyway. (#443)
- **`timeline --as-of`** and the other run flags pin the timeline's compliance trend; the PQC options have config-file keys. (#443)
- **Every command judges compliance like `validate`.** `view` and `diff` (TUIs, reports, quality delta), `quality`, `cra-docs` and the timeline trend give each standard the inputs `validate` gives it: the clock, the CRA sidecar and the product class. New flags: `--as-of` on `view`, `diff` and `cra-docs`, and `--cra-product-class` on `diff`. A standard selected twice, such as `--standard cra,cra-phase2`, is checked once. (#434)

#### Cryptography (CBOM)

- **Every CycloneDX 1.7 algorithm family** is classified, along with JCA names, curve aliases, and MACs and KDFs. This ends false failures on HMAC and HKDF. (#411)
- **PQ/T hybrids are judged by their parts.** P-384 with ML-KEM-1024 passes CNSA 2.0, and RFC 9370 additional key exchanges are read. (#415)
- **TLS 1.3 named groups and signature schemes** are judged against the IANA registries, GREASE excepted. A classical-only TLS 1.3 suite fails CNSA 2.0 and PQC. (#419)
- **CycloneDX XML CBOMs** load and read like JSON: crypto functions, cipher suites, crypto references and `isExternal`. (#412)

#### Standards

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

#### Library

- **`#[non_exhaustive]`** on the compliance result types and `Component`, so later additions stop being breaking. (#423)
- **Compliance in the C ABI and every binding.** `sbom_tools_validate_json` returns exactly the `validate -o json` envelope for any standard, sidecar, product class, PQC mode, rule settings or `as_of`; `sbom_tools_rule_catalog_json` returns the rule catalogue; and `sbom_tools_score_sbom_with_options_json` returns exactly what `quality -o json` prints. Go, Swift, Python and Node expose them with types. The ABI version is now 2. (#446)
- **`ComplianceRunConfig`** holds one run's inputs (the clock, the CRA sidecar, the product class, the PQC mode, the rule settings and the excluded scope) and builds each standard's checker with exactly the inputs it reads. The CLI, the TUIs, the report writers and the C ABI use it. (#434, #437, #443)

### Bug Fixes

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

### Upgrade notes

These behaviours changed in this release. The [migration guide](docs/MIGRATING-0.4.md) has every change, with what to do about it.

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

## v0.3.0 — 2026-10-12

Full notes, including contributor acknowledgments:
[`RELEASE_NOTES_v0.3.0.md`](RELEASE_NOTES_v0.3.0.md)
· [GitHub release](https://github.com/sbom-tool/sbom-tools/releases/tag/v0.3.0)

### Highlights

The **CBOM fidelity release.** v0.2.0 checked whether the tool told the truth;
this release asks the same question of cryptography inventories, prompted
largely by people running real CBOMs through it. Three gaps stood out. A
CycloneDX 1.7 IPsec CBOM did not load at all — its IKEv2 transform objects
stopped the parser with exit `3`. Crypto fields renamed between CycloneDX 1.6
and 1.7 were read in only one spelling, so an elliptic-curve key declared the
1.6 way, or a certificate linked the 1.7 way, slipped past the CNSA 2.0 and
PQC gates instead of failing them. And CBOMs were graded as if every algorithm
were a package: one sparse IKE document drew 31 findings for missing versions,
suppliers, licenses and hashes on its crypto assets, while the quality score
undercounted its real problems — HMAC-SHA1, 3DES and a 1024-bit DH group.

All three are fixed, and fixtures in both spec versions pin the behaviour.

Also in this release: **`convert --to normalized`** puts the full normalized
model — crypto, ML and dataset detail included — on the command line,
byte-identical to what the C ABI and language bindings return. CycloneDX 1.6+
**`manufacturer` and `authors`** now count as producer evidence across nine
compliance standards. SPDX 3 documents generated by **Yocto** parse. And a
first, unsigned **pipeline receipt** contract lands under `sbom-tools verify`.

> **Please read [Upgrade notes](#upgrade-notes-1) below** — compliance verdicts
> move in both directions for CBOMs and for components that name a
> manufacturer, `quality --profile cbom` reports a different standard, and two
> public Rust structs gain fields.

### What's New

#### Cryptography (CBOM)

- **CycloneDX 1.7 IKEv2 transform objects.** Both shapes parse, in JSON and XML: the 1.6 bom-ref string and the 1.7 object carrying an IANA name, key length and group. `PROTO-002` under `--standard cnsa2` and `--standard pqc` judges each transform by its algorithm reference, then its IANA name, then its key-exchange group; a transform that cannot be identified reports `PROTO-UNKNOWN` rather than passing. IANA Transform Type 4 groups map to algorithm families, including ML-KEM groups 35–37, and the TUI shows the new `auth` transforms. (#380)
- **Crypto fields are read in both their 1.6 and 1.7 spellings** — the curve (`algorithmProperties.curve` / `ellipticCurve`), a certificate's signature algorithm, public key and file extension, a key material's algorithm, and protocol refs (`cryptoRefArray` / `relatedCryptographicAssets`). The 1.7 typed refs are kept losslessly in a new `related_crypto_assets` field. A 1.7 certificate that relates several algorithms without saying which one signs it has every candidate judged, failing closed. (#378)
- **Crypto assets are not packages.** Package-only checks — version, supplier, license, hash, identifier, dependency — no longer apply to `cryptographic-asset` components under NTIA, FDA, Standard, Comprehensive, CISA 2026, PCI DSS and FSCT, or in the quality metrics. EO 14028, SSDF, BSI and the CRA Art. 13(5) licence and Annex I supply-chain rules still count them. Crypto *libraries* typed `library` are still packages. (#382)
- **`quality --profile cbom` embeds NIST PQC compliance** instead of Comprehensive, which ran no crypto checks at all. Its License slot is N/A rather than 0 when a document has no package components. (#382)
- **One algorithm classifier.** Quality scoring now uses the same classifier as `validate`, so the two agree: `HMAC_SHA1` counts as weak, and IKE group names (`MODPnnnn`, `ECPnnn`, `curve25519`, `curve448`) are classified — `modp1024` is DH-1024, quantum-vulnerable, rather than "cannot be classified". The refs slot credits `relatedCryptographicAssets` and IKEv2 transforms. (#382)
- **CycloneDX 1.7 protocol types** `ike`, `sstp`, `wpa`, `quic`, `eap-aka`, `eap-aka-prime`, `prins` and `5g-aka`, which previously fell through to `Other`. (#382)

#### CLI

- **`convert --to normalized`** (alias `normalized-json`) prints the canonical normalized model as JSON — the same bytes the C ABI (`sbom_tools_parse_sbom_*_json`) and the language bindings' `parse` helpers return, pinned by a byte-identity test. Until now that payload, with its crypto, ML and dataset detail, was reachable only by linking the native library. It reads a file or stdin and is lossless, so no fidelity report is printed. (#367, requested in #366)
- **Pipeline receipts.** `verify receipt`, `verify receipt-generate` and `verify receipt-aggregate` validate, generate and aggregate `pipeline-shard-receipt/v1` documents that identify source contents, lock inputs, a build target, declared check results and artifact digests, with three versioned JSON Schemas under `schemas/`. Receipts are **unsigned and non-promotable** diagnostics: supplied check outcomes and versions are recorded, not authenticated. See `docs/pipeline-receipts.md`. (#353, proposed in #350)

#### Compliance and AI-BOM

- **Component `manufacturer` and `authors` (CycloneDX 1.6+)** are parsed, written back by the CycloneDX emitter, and accepted as producer evidence by NTIA, FDA, CRA, CISA 2026, EO 14028, SSDF, BSI TR-03183-2, BSI SBOM-for-AI and PCI DSS. `authors` names fill `author` when the deprecated string is absent. (#380)
- **AI-003 accepts nested dataset evidence.** A model that declares its training data as `contains` children carrying a CycloneDX `data[]` block now satisfies AI-003 and the BSI/G7 SBOM-for-AI model check, alongside `modelCard.modelParameters.datasets`. A bare nested `type: data` component with no `data[]` block is still not dataset evidence — CycloneDX `data` also covers configuration bundles — and `tests/fixtures/aibom/README.md` documents the policy. (#361)
- **Third-party AI-BOM corpus.** Two real-world CycloneDX 1.5 AI-BOMs from Manifest Cyber's `aibom-gen` (Apache-2.0) are kept verbatim with provenance, and `scripts/test-aibom.sh` runs `view`, `quality` and `validate` across the whole AI corpus. (#361)

#### Documentation

- **JSON output contract** in the README: which payloads are contractual, that `view -o json` is a curated projection without crypto/ML/dataset detail, what is test-pinned, and that the shape follows the crate version with breaking changes listed under Upgrade notes. (#364, prompted by #362)

### Bug Fixes

- **CycloneDX 1.7 IPsec CBOMs failed to load.** An IKEv2 transform written as a 1.7 object stopped the parser with `invalid type: map, expected a string` and exit `3`. (#380, #379)
- **CycloneDX 1.6 `curve` and 1.7 `relatedCryptographicAssets` were dropped, and the crypto gates failed open.** A 1.6 EC key whose only identity was its curve reported an UNKNOWN Warning instead of a quantum-vulnerable Error, and 1.7 certificates linked through `relatedCryptographicAssets` were skipped by `CERT-001` and left out of the inventory gate. (#378, #374)
- **CBOMs were graded on package fields.** On a sparse IKE CBOM, `quality --profile cbom` reported 31 package-only findings and `validate --standard ntia` 19; neither now reports any against crypto assets. (#382, #370)
- **The quality score undercounted weak crypto,** counting one weak algorithm where `validate` found two, and could not classify `modp1024`. (#382)
- **The protocol warning claimed "documents no version"** for protocols that declared one. It now states what the protocol declares and names exactly which evaluable fields are missing. (#382, #370)
- **Components that named a `manufacturer` or `authors` failed supplier and producer rules** as though they were anonymous. (#380)
- **SPDX 3 `suppliedBy` given as a single string** — as Yocto emits it — failed to parse with `expected a sequence`. The property has cardinality 0..1 and now accepts both forms. (#349, #348)
- **The TUI Violation Detail overlay clipped its content.** A fixed 60% of terminal height silently cut off remediation text and the close hint; the overlay now sizes to its content and, when even the full height is too small, shows a `… +N more lines` marker. (#355, #347)
- **The CRA supply-chain rule gave dependency advice.** `SBOM-CRA-ANNEX-I-SUPPLY-CHAIN` told users to add `DEPENDS_ON` relationships; its remediation now names the supplier fields. (#355)
- **Security.** Lockfile updates clear RUSTSEC-2026-0258 (`h2` 0.4.19), RUSTSEC-2026-0221 (`event-listener` 5.4.2), RUSTSEC-2026-0253 (`lru` 0.18.3, use-after-free), RUSTSEC-2026-0285 (`rustls` 0.23.45) and RUSTSEC-2026-0338 through -0342 (`quinn-proto` 0.11.19, via `reqwest`), with no advisory suppressions added. (#352, #369, #388)

### Upgrade notes

These behaviors changed in this release:

- **Some CBOM gates are stricter — a passing `validate` run can now exit `1`.** A 1.6 EC asset identified only by `curve` reports `ALG-006` as an Error (it was an `ALG-UNKNOWN` Warning). 1.7 certificates and protocols linked through `relatedCryptographicAssets` are now evaluated by `CERT-001` and `PROTO-002`. 1.7 IPsec CBOMs that previously failed to parse (exit `3`) are now judged.
- **Other gates are looser — a failing run can now exit `0`.** Package-only findings no longer appear on `cryptographic-asset` components under NTIA, FDA, Standard, Comprehensive, CISA 2026, PCI DSS or FSCT, and components that name a `manufacturer` or `authors` now satisfy supplier and producer rules. Both are intended; review any gate that relied on the old findings.
- **`quality --profile cbom` reports NIST PQC compliance,** not Comprehensive. CBOM scores move in both directions — up from the License N/A and the refs credit, down from accurate weak and quantum-vulnerable counts. The #370 fixture goes from 42.1 to 37.2 overall.
- **Normalized and quality JSON gain fields, additively:** `cryptography_metrics.protocols_with_algorithm_refs`; `related_crypto_assets` on certificate, related-material and protocol properties; `manufacturer` on components; `auth` and `transforms` on IKEv2 transform types. Older normalized payloads still deserialize. The eight new protocol types appear as their own values rather than `Other`.
- **Library API (source-breaking):** `Component` gains `manufacturer`, and `Ikev2TransformTypes` gains `auth` and `transforms`. Neither struct is `#[non_exhaustive]`, so code that builds them with struct-literal syntax must add the fields. `CryptographyMetrics` gains `protocols_with_algorithm_refs`, and the `#[non_exhaustive]` `ProtocolType` gains eight variants. New helpers: `ComponentType::is_package_scoped()`, `Component::has_producer()` and `ikev2_key_exchange_group()`.

---

## v0.2.0 — 2026-08-01

### Highlights

The **correctness release.** Where v0.1.22 added an AI-BOM domain, this release
goes back over what was already there and checks whether it told the truth.
Systematic audits of the diff engine, the parser layer, enrichment, quality
scoring, the compliance engine, the CLI surface and the TUI turned up defects
that shared a shape: the tool reporting something other than what it had
computed. A demo SBOM shipped in this repository reported "no vulnerabilities"
while its own Source view displayed a CVSS 9.8 entry. Fleet deviations rendered
as `10000.0%`. A document containing no cryptography scored a perfect 100 for
quantum readiness. A keyboard overlay advertised keys that did nothing.

All of those are fixed, and most are now pinned by tests that fail if the
behaviour regresses.

Alongside the audit work: three new compliance standards bring
`validate --standard` to **16** — **CISA's 2026 Minimum Elements**, **PCI DSS
v4.0.1 Requirement 6.3.2**, and **CISA Framing Software Component Transparency
3rd ed.** — plus **CDXA attestation ingestion**, so a signed machine-readable
declaration can satisfy an SSDF practice or a CRA conformity route that
previously accepted only self-declaration. A new **`quality -o sbomqs-json`**
emits the [sbomqs](https://github.com/interlynk-io/sbomqs) 0–10 score model for
side-by-side comparison.

> **Please read [Upgrade notes](#upgrade-notes-2) below** — this release changes
> machine-readable output, the Rust API, several compliance verdicts, and the
> TUI keymap.

### What's New

#### Compliance

- **CISA 2026 Minimum Elements** — `validate --standard cisa-2026` (aliases `cisa`, `cisa2026`, `minimum-elements-2026`), 17 rules against the final v2.1 document published July 2026, successor to the NTIA 2021 elements. Deliberately stricter than the NTIA profile where the document is: a tool-only creator list does not satisfy SBOM Author, and a silently absent license fails where an explicit no-assertion passes. (#333)
- **PCI DSS 6.3.2** — `validate --standard pci-dss` (aliases `pci`, `pci-dss-6-3-2`, `pci-dss-4`), 10 rules treating the SBOM as the required inventory of bespoke, custom and third-party components. A passing verdict is evidence the inventory exists and is usable, **not** a PCI compliance certification, and thresholds chosen by this tool rather than the standard are labelled as such in the message. (#333)
- **CISA FSCT 3rd ed.** — `validate --standard fsct` (aliases `fsct-3`, `component-transparency`), 27 rules across the document's three maturity tiers, mapped Minimum Expected → Error, Recommended Practice → Warning, Aspirational → Info. Checks are format-gated where the evidence cannot exist rather than failing a document for its format. (#333)
- **CDXA attestation ingestion (phase 1).** CycloneDX 1.6 `declarations` (assessors, attestations, claims, evidence, affirmation, signatories) parse into a normalized model, gated on `specVersion >= 1.6`, with refs resolved through the same id map as the rest of the document. **Structural verification only** — signature *presence* is recorded, never cryptographically verified. Phase 2 (external in-toto/DSSE bundles) is not implemented. (#333)
- **Attestation evidence satisfies existing rules.** A declaration covering an SSDF practice (PS.1/PO.3/PW.6), a CRA conformity route, an EUCC certificate reference or EO 14028 provenance satisfies that rule at structural/signature-present level. Every pre-existing satisfaction path remains valid as a self-declared fallback, so documents without declarations are unaffected. (#334)
- **`--as-of <DATETIME>`** on `validate` and `quality` pins the evaluation clock for deadline-sensitive checks (CRA Art. 14 readiness, SBOM age, EUCC expiry), so CI runs are reproducible instead of drifting with the wall clock. (#320)
- **Registry-driven rule identity** across JSON, SARIF, the quality CLI and OSCAL; structured violation identity (a `component_id` join key with affected/total counts); tri-state applicability so "not applicable" is distinct from "compliant". (#320)
- **Per-rule test matrix** — every rule in the FDA, SSDF, EO 14028, Standard and Comprehensive profiles has a firing and a silent fixture, with exhaustiveness enforced in both directions so a new check site forces a matrix entry. (#333)

#### Interoperability and output

- **`quality -o sbomqs-json`** emits the sbomqs v2.0.11 `score --json` schema (`run_id`, `creation_info`, `files[].scores[]`, `avg_score`), and the plain-text `quality` summary gains a 0–10 category table. Formulas were read from that release's sources rather than its documentation, including the behaviours a reimplementation would otherwise "correct"; categories that cannot be computed are emitted as `ignored` with a stated reason instead of approximated. Quirks are documented in `docs/STANDARDS_VERSIONS.md`. (#333)
- **`validate -o oscal-json`** — OSCAL 1.1.2 assessment-results export, applicability-faithful (N/A findings, multi-standard run summaries). (#280, #320)
- **`timeline` JSON gains `incremental_pairs` and `cumulative_pairs`** — index-aligned `from_index`/`to_index`/`from_name`/`to_name` records, so consumers no longer infer which pair an array position refers to. Additive. (#334)
- **`--fail-on-ml-regression`** on `diff` (exit code `7`) gates on regressions in supported ML performance metrics, and **`--fail-on-noncompliant`** on `quality` gates on the compliance verdict independently of `--min-score`. (#279, #320)
- **`cra-docs --force`** overwrites an existing dossier; a re-run otherwise refuses to clobber hand-completed documents. (#322)

#### Parsers

- **SPDX 3.0.1 canonical JSON-LD** parsing, plus document-level metadata completeness, shared `CreationInfo`, and `software_` aliases. (#311)
- **SPDX 2.x data-loss gaps closed** — `documentDescribes`, file entries, `LicenseRef` resolution, CPE, purpose and emails. (#315)
- **CycloneDX correctness** — spec-valid documents that hard-failed now parse, nested assemblies are inventory, and serialization round-trips. (#314)
- **purl-fallback ref resolution.** `dependencies[].ref`, `dependsOn` and `vulnerabilities[].affects[].ref` expressed as purls resolve to components (explicit bom-refs still win on collision). Such edges and CVEs were previously dropped silently. (#333)
- **Document revision tracking** — the CycloneDX top-level `version` counter is captured, diffed, and round-trips through `convert`, which previously hardcoded `"version": 1`. (#333, #334)

#### TUI

- Four phases land here: data surfacing and a theme backbone (#309), per-tab depth with detail panels and ML/VEX/match transparency (#310), a multi-mode overhaul with shared builders (#312), and unified search behind a single shortcuts surface (#313).
- **A UX audit of every mode** against a 269-frame corpus produced 203 findings; the 30 that survived adversarial verification are fixed, along with the tail. Empty states no longer celebrate, every advertised key exists, `y` copies the row you actually selected, and the Quality, Compliance and AI-Readiness tabs no longer collapse to empty borders at 80×24 — the app's own advertised minimum size. (#333, #334)
- **New surfaces:** component deep dive (Enter on diff Components), a threshold-tuning overlay on `t` (previously unreachable by any key), a `Q` quick-filter picker, AI Inventory and AI Readiness overview panels for the AI-BOM profile, a monochrome theme, VEX gap counts and by-state breakdown, KEV/Fixable/EPSS triage summaries, license-compatibility conflicts, ML performance regressions with direction-aware coloring, match-confidence intervals, and mouse support in the Matrix/Timeline/Multi-Diff modes. (#309, #310, #312, #333)

#### Bindings and documentation

- **Python (ctypes) and Node.js (Koffi) FFI bindings** alongside the existing Go and Swift wrappers. (#274, #275)
- **`docs/TUI_SHORTCUTS.md`** documents every binding across all three TUIs, each traced to its handler with the guard that makes a key mean different things on different tabs. (#334)
- **This changelog**, and a README/`docs/` refresh whose every claim was verified against the built binary and re-checked by independent adversarial review. (#323, #334)

### Bug Fixes

- **Vulnerabilities and dependency edges were silently dropped** whenever a CycloneDX document referenced components by purl — including this repository's own demo fixtures, where the Vulnerabilities tab reported a clean bill while the Source tab displayed a CVSS 9.8 CVE. (#333)
- **Fleet deviation was double-scaled**, rendering as `10000.0%` and saturating every gauge and severity band. It is now a 0–1 fraction, and the three similarity scales are pinned by tests. (#333)
- **A version bump counted as both an addition and a removal** in multi-SBOM analysis, so "Inconsistent" totals exceeded the number of distinct components and Timeline listed every upgrade twice. (#333)
- **Documents with no cryptography scored 100 for quantum readiness.** The score is now absent rather than vacuously perfect, and the CBOM scorer redistributes the weight. (#333)
- **Diff and matching.** Stale-splice and hash-blindness holes in incremental diffing; multi-engine version classification, clustering, naming and timeline semantics; equivalence rules bridging real IDs during matching instead of corrupting the result; `sparse_assignment` optimality restored; wrong-neighbor and cross-ecosystem false merges eliminated behind one tier pipeline; remaining quadratic hot paths removed. (#299)
- **Parsers.** 29 untrusted-input findings, CycloneDX hard-fails, assemblies, services and per-version VEX status gating, SPDX relationship parsing, `@graph` serialization, tag-value text blocks, UTF-8 BOM stripping, streaming metadata, format-detection misrouting, and deterministic content hashing. (#300, #314, #315)
- **Enrichment.** VEX status mapping corrected so external VEX can no longer silently suppress real vulnerabilities; OSV result attribution validated and hydration fan-out bounded; the network trust surface hardened (URL validation, hash provenance, cache integrity). (#303)
- **Compliance.** Vacuous CRA passes closed (steward gates, evidence scoping, class monotonicity, EUCC sidecar); crypto-compliance false passes (vacuous CNSA2/PQC, classical crypto, undocumented CBOM); AI profile applicability gates; CNSA2/PQC classification made input-robust; per-standard element gaps; registry/SARIF severity consistency. (#304, #320)
- **Quality scoring** is monotonic and deterministic (vulnerability baseline, freshness, coverage clamp); license and identifier metrics count per component rather than per entry; required compliance elements gate the score; the crypto score is honest about inventories it cannot verify. (#304)
- **CLI.** A UTF-8 panic in `query`, format gates that did not gate, and filters that claimed more than they did; security gates fail closed and machine output stays parseable; non-TUI reports honour the CRA sidecar and product class like the TUI does; `enrich` is lossless, `merge` stops dropping data, and `tailor` prunes by identity rather than by name; config files reject unknown keys. (#322)
- **`diff` and `view` accepted `-o sbomqs-json`** and silently emitted ordinary JSON under a format the caller never asked for. Both now reject it with a pointer to `quality`. (#334)
- **`--no-color` did not reach the TUI**, which consulted only the `NO_COLOR` environment variable, and the side-by-side reporter ignored both. An empty `NO_COLOR=` now counts as unset everywhere, per the convention. (#333, #334)
- **The shortcuts overlay contradicted itself** — its global rows were gated by mode but not by tab, so one frame could assert both `l Color legend` and `h/l Collapse/expand` on a tab where `l` switches standards. The Graph Changes tab also advertised a `g` binding it never had. (#334)
- **TUI robustness.** Terminal restored on all exits; UTF-8 render panics removed; selection kept on-screen at any terminal size; `Esc` never quits; wrapped-line scrolling; mouse hit-testing derived from the real rendered layout; compliance exports aligned with the canonical result contract. (#309, #310, #312, #313, #324)
- **Reports.** Resolved `LicenseRef` names are surfaced, CycloneDX authors and SPDX creators/files/licensing infos are emitted, and CycloneDX VEX unaffected-version handling is correct. (#321)
- **Security.** `quick-xml` 0.41 (RUSTSEC-2026-0194, RUSTSEC-2026-0195), `quinn-proto` 0.11.15 (RUSTSEC-2026-0185) and `crossbeam-epoch` 0.9.20 (RUSTSEC-2026-0204); untrusted-input DoS vectors bounded in the parsers, and every untrusted response read plus the EPSS gzip decompression are size-bounded. (#300, #303)

### Upgrade notes

These behaviors changed in this release:

- **Deviation is a 0–1 fraction — `diff-multi` only.** `diff-multi -o json` emits `summary.deviation_scores` and `summary.max_deviation` in `0.0…1.0`; they were previously double-scaled. `timeline -o json` has no `summary` object and no deviation field of any kind, so it is unaffected. The three scales are now pinned by tests: single-`diff` `semantic_score` is `0–100`, `matrix` `similarity_scores` is `0–1` (`= semantic_score / 100`), and deviation is `0–1` (`= 1 − similarity`). (#333, #334)
- **Multi-SBOM component identity is the version-stripped logical purl.** `variable_components`, `inconsistent_components` and the timeline evolution/divergence entries key on `pkg:npm/express` rather than `pkg:npm/express@4.18.2`, so a version bump is one component with a version spread instead of an Added + Removed pair. (#333)
- **`diff -o json`: `ComponentChange` gains `component_type`.** Additive, but strict consumers must accept it. Crypto assets resolve to their CycloneDX asset type (`algorithm`, `certificate`, `protocol`), except `related-crypto-material`, which narrows to its declared material type — any of the 17 kinds (`public-key`, `private-key`, `symmetric-key`, `key-pair`, `secret-key`, `signature`, `digest`, `initialization-vector`, `nonce`, `seed`, `salt`, `shared-secret`, `tag`, `password`, `credential`, `token`, `unknown`) or a custom declared string. ML components resolve to `machine-learning-model` and `data`. (#333)
- **`diff -o json`: `metadata_changes` gains `doc_version` entries**, so a pure revision bump is no longer reported as "no changes". Combined with purl ref resolution, change totals move: the `demo-old`/`demo-new` fixture pair goes from 15 to 18. (#333, #334)
- **`diff-multi`, `timeline` and `matrix` accept only `-o auto|tui|json`.** `--help` lists exactly those, and an unsupported value is a clap usage error (exit `2`) at parse time instead of a runtime failure (exit `3`) after every SBOM had been parsed. (#334)
- **Library API:** `CryptographyMetrics::{quantum_readiness_score, pqc_readiness_score}` return `Option<f32>` — `None` when a document declares zero algorithms, instead of a vacuous `100.0`; the CBOM scorer redistributes the PQC weight. `run_tui` and `run_view_tui` take a `no_color` parameter. (#333, #334)
- **Exit-code contract is reachable and fails closed.** Operational errors — I/O, parse failures, an unsupported `-o` for the command, an invalid `--as-of` or `--cra-product-class`, a broken explicit `--cra-sidecar`, an invalid config file — exit `3`; command-line parse errors exit `2`; gate verdicts keep `1`/`2`/`4`/`5`/`6`/`7`. A nonzero exit is only a gate verdict when the expected report was produced. (#322)
- **`validate --standard ntia` and `--standard fda` are engine-backed.** Their divergent fast paths are gone; both are stricter, and SBOMs that passed before can now fail. (#320)
- **Compliance rule identity comes from the registry.** Several SARIF/JSON `rule_id`s were renamed, EUCC checks got their own standard kind and rule ids, and fallback rule identity is family-correct at the source. (#320)
- **CRA phases re-anchored to Reg. (EU) 2024/2847.** Phase 1 is the Art. 14 reporting phase applying from 11 Sep 2026 (was labelled "11 December 2027") and Phase 2 is full application from 11 Dec 2027 (was "11 December 2029"). Article and Annex citations were corrected throughout. (#320)
- **`validate --standard bsi` is rebased on BSI TR-03183-2 v2.1.0** — format gate, SHA-512 hashes, ten required fields, corrected tiers. (#320)
- **The compliance verdict is tri-state** — compliant / non-compliant / not-applicable, the last surfaced as `"compliant": null` — with one honest compliance score shared across the TUI, reports and exports; N/A findings are surfaced rather than counted as passes. (#320)
- **The TUI keymap changed.** Digits always jump tabs in diff mode; Components' quick filters moved to a `Q` picker, Side-by-Side filters to `A`/`r`/`m`/`x`, the KEV filter from `k` to `K`, vulnerability group jump to `}`/`{`, Dependencies fold to `x`/`X`, the cycles toggle to `C`, and the threshold overlay to `t`. `e` is export on every tab. `docs/TUI_SHORTCUTS.md` is the full reference; `?` in the app is context-aware. Recorded demos, scripts and third-party docs referencing the old keys are stale. (#333, #334)

---

## v0.1.22 — 2026-06-15

The **AI BOM release.** Full notes: [`RELEASE_NOTES_v0.1.22.md`](RELEASE_NOTES_v0.1.22.md)
· [GitHub release](https://github.com/sbom-tool/sbom-tools/releases/tag/v0.1.22)

### Highlights

AI systems became a first-class domain across the whole pipeline: CycloneDX
ML-BOM and SPDX 3.0 AI/Dataset parsing, AI-readiness scoring (AI-001…AI-010),
machine-checked **EU AI Act (Annex IV)** and **G7/BSI "SBOM for AI — Minimum
Elements"** standards, semantic model and dataset diffing, model-weight
integrity verification, Hugging Face enrichment, and a dedicated AI-BOM TUI
profile. Alongside it: a `convert` command (CycloneDX ↔ SPDX), KEV/EPSS
enrichment with an offline/air-gapped mode, and broad CLI/TUI alignment.

### Upgrade notes

- Scoring engine 2.0 → 2.1 (cycle detection counts strongly-connected components), `semantic_score` counts per-component license transitions, and `license-check` gating is stricter. (#215, #211, #212)
- Logs moved to stderr so machine-readable output on stdout stays parseable; the EPSS default endpoint moved to the official FIRST host. (#256, #248)
- Library API: `IncrementalDiffEngine::diff` and `MultiDiffEngine::{diff_multi,timeline,matrix}` return `Result`. (#217)

---

Earlier releases: [`RELEASE_NOTES_v0.1.21.md`](RELEASE_NOTES_v0.1.21.md) and the
[GitHub Releases page](https://github.com/sbom-tool/sbom-tools/releases).

[0.3.0]: https://github.com/sbom-tool/sbom-tools/releases/tag/v0.3.0
[0.2.0]: https://github.com/sbom-tool/sbom-tools/releases/tag/v0.2.0
[0.1.22]: https://github.com/sbom-tool/sbom-tools/releases/tag/v0.1.22
