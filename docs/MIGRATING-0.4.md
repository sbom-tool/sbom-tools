# Migrating to sbom-tools 0.4

sbom-tools 0.4.0 is a breaking minor release. Most pipelines need two changes:
- read JSON output from the v2 envelope;
- treat exit code `3` as a configuration error.

Verdicts also move, mostly stricter. Run the release on your own SBOMs before you upgrade a gate. Pass `--as-of` so the comparison is reproducible.

## At a glance

| Change | Who it affects | What to do |
|---|---|---|
| Usage errors exit `3` instead of `2` | CI scripts that read `2` | Treat `3` as a configuration error. `2` still means warnings or new vulnerabilities. |
| `-o json` emits envelope v2 | Anything that parses `validate -o json` | Read results from the envelope, or pass `--json-schema v1` until v0.5.0. |
| Verdicts are stricter in places and looser in others | Everyone who gates CI on `validate` | Read [Verdicts](#verdicts); run the release on your SBOMs. |
| Components whose scope is excluded leave the package rules | SBOMs that list test, build or development dependencies | Pass `--include-excluded-scope` to judge them as before (#443). |
| `view`, `diff` and the other commands judge compliance like `validate` | Users of the TUIs and reports | Expect the verdicts `validate` gives; pass `--as-of` to pin them (#434, #440). |
| Rule ids are split and renamed | Anything that matches on `rule_id` | Map the old ids to the new ones ([table](#renamed-and-split-rule-ids)). |
| Passed checks move to `passed[]` | Dashboards that count Info findings or SARIF notes | Read `passed[]` and `counts.passed`. |
| Compliance scores use a new formula | Thresholds and dashboards on `score` or `overallScore` | Revisit them: a compliant result scores 50–100, a non-compliant one 0–49 ([Compliance scores](#compliance-scores)). |
| SARIF carries locations, fingerprints and one rule per check | GitHub code scanning users | Expect the first upload to re-key alerts; set `--sarif-category` instead of upload-sarif's `category`. |
| SARIF `standardIds` and `standardHelpUris` are deprecated | SARIF consumers that read the references | Read `standardRefs`. The old properties go in v0.5.0 (#445). |
| OSCAL moves to 1.2.3 and names standards by their `--standard` key | OSCAL consumers | Validate against the 1.2.3 schema, read `standard` as `cra` or `ntia`, and expect the assessment UUIDs to change once (#445). |
| sbomqs-compatible scores follow sbomqs v2.1.2 | Users of `quality -o sbomqs-json` | Re-baseline stored comparisons. |
| Text, Markdown, HTML and CSV escape SBOM text, and the text report names each rule | Scripts that scrape human-readable output | Use `-o json`. |
| Normalized and FFI JSON gain variants and fields, and the ABI version is `2` | Bindings and FFI consumers | Handle the new variants, and accept `abi_version` `"2"` (#446). |
| Result types are `#[non_exhaustive]` | Rust library users | Use constructors, and add wildcard arms. |
| Library calls take a run configuration, and some signatures change | Rust library users | Read [Rust library](#rust-library). |

## Command line and CI

### Exit codes

Usage errors exit `3` in every command, as operational errors already did. Usage errors are an unknown flag, standard or value, or a missing argument. They used to exit `2`, so a mistyped flag looked like a warning (#410).

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Compliance errors, a finding of a `--fail-on` rule, a not-applicable standard under `--require-applicable`, changes under `--fail-on-change`, and the other per-command failures in the README |
| `2` | Compliance warnings under `--fail-on-warning`, or new vulnerabilities under `--fail-on-vuln` |
| `3` | Usage or operational error |
| `4`–`7` | VEX gaps, licence policy, KEV and ML regression gates, unchanged |

New: `validate --require-applicable` exits `1` when a selected standard does not apply to the SBOM, for example `--standard ai-act` on an SBOM without AI components (#410).

New: `validate --fail-on RULE` exits `1` on any finding of the rule, whatever its severity, even under `--fail-on-warning` (#443).

More usage errors (exit `3`):
- an unknown rule id or setting in `--rule` or `--fail-on`, or in the config file (#443);
- `--pqc-profile` or `--cnsa-category` without `--pqc-mode deadline` (#437);
- a run flag passed to `diff-multi` or `matrix`, which check no compliance (#443).

### New commands and flags

`sbom-tools rules` lists the compliance rules: every rule, or those of the standards `--standard` names (#435). Each has its id, name, default severity, the standards that use it, its references and a one-line fix. `sbom-tools rules explain <RULE_ID>` shows one rule in full, including where the fix goes in CycloneDX, SPDX 2.x and SPDX 3.0. `-o json` emits the `sbom-tools/rules/v1` document (`schemas/rules/v1.schema.json`). An unknown rule id or standard exits `3`.

Every command that checks compliance takes the same run flags: `validate`, `quality`, `view`, `diff`, `cra-docs` and `timeline`, for its compliance trend.

| Flag | What it does |
|---|---|
| `--as-of` | Pins the instant every standard is judged at. New on `view`, `diff` and `cra-docs` (#434), and on `timeline` (#443). Without it, `validate` judges every standard at one instant, the wall clock when it starts, to the second (#445). |
| `--cra-product-class` | New on `diff` (#434) and `timeline` (#443). The config file's `compliance.cra_product_class` now applies to `diff` too. |
| `--pqc-mode deadline` | Judges `cnsa2` and `pqc` findings by their migration deadlines at `--as-of` ([PQC deadline mode](compliance-output.md#pqc-deadline-mode)). The default, `readiness`, is unchanged (#437). |
| `--pqc-profile federal` | Applies the EO 14412 / OMB M-26-15 deadlines for post-quantum key establishment and signatures. It also reports TLS 1.2 against the TLS 1.3 deadline of 2030-01-02 (EO 14306, OMB M-26-15) under the new `SBOM-PQC-PROTO-003`. Needs `--pqc-mode deadline` (#437). |
| `--cnsa-category <CATEGORY>` | The CNSA 2.0 equipment category, the strictest when unset. Needs `--pqc-mode deadline` (#437). |
| `--rule RULE=SETTING` | Sets a rule's severity for the run (`info`, `warning`, `error`), or turns it off (`off`). Repeatable. The verdict, the counts, the score and the exit code follow ([Rule settings](compliance-output.md#rule-settings), #443). |
| `--include-excluded-scope` | Judges components whose scope is excluded, as 0.3 did ([Components whose scope is excluded](compliance-output.md#components-whose-scope-is-excluded), #443). |
| `--fail-on RULE` | `validate` only: exits `1` on any finding of the rule. Repeatable (#443). |

The config file gives these flags defaults: `compliance.rules`, `compliance.fail_on`, `compliance.include_excluded_scope`, `compliance.pqc_mode`, `compliance.pqc_profile` and `compliance.cnsa_category` (#443). A `--rule` flag wins over the file for its own rule; the file's other settings stay.

Also on the command line:
- **A standard selected twice** (`--standard cra,cra-phase2`, also through `compliance.standards`) is checked once, with a warning on stderr. It used to run twice, and `-o sarif` reported every finding a second time (#434).
- **One help text:** `--cra-sidecar`, `--cra-product-class` and `--as-of` share one definition, so their `--help` text is the same in every command (#434).
- **`diff` warnings:** the product-class mismatch warning names the SBOM it is about (#443).

### Verdicts

Upgrading can change your pass or fail result. The release fixes false passes and false failures found in two reviews after 0.3.0.

**Stricter.** These can make an SBOM that passed in 0.3 fail:
- **Identifiers and inventory:**
  - Empty, `NOASSERTION` or scheme-less purls and CPEs no longer count as identifiers, and components that shared one are kept apart (#397).
  - An SBOM with no package components fails NTIA, FDA, CRA, CISA 2026, EO 14028, SSDF, BSI and PCI DSS with an inventory finding (#397). The `quality` profiles `minimal`, `standard` and `comprehensive` fail it too, with SBOM-QUALITY-INVENTORY, so `quality --fail-on-noncompliant` exits `1`.
  - SPDX packages with purpose `SOURCE`, `ARCHIVE` or `FILE` are checked as packages (#398).
  - Coverage rules count packages only (#398). Where files or crypto assets carried the hashes or suppliers the packages lack, the share of packages missing them rises: SSDF PS.2 can become an Error, and the CRA transitive-supplier finding a Warning.
- **Placeholders:**
  - `NOASSERTION` and placeholders (`TBD`, `N/A` and similar) no longer satisfy supplier, author or version rules. CISA 2026 and FSCT still accept an explicit unknown where their texts allow one (#399).
  - An empty or placeholder document name, such as `""` or `NOASSERTION`, no longer counts as a name for SBOM-FDA-NAME and SBOM-CRA-ART-13-15-PRODUCT (#428).
  - BSI/G7 SBOM-for-AI rejects placeholder model and dataset fields (#416).
  - A licence must be a known SPDX expression or `LicenseRef-*` id in every standard. `NOASSERTION` and placeholders such as `TBD` now fail the CRA Art. 13(5), BSI, FSCT, Standard and Comprehensive licence checks (#399, #441). CISA 2026 still accepts `NOASSERTION` as its explicit unknown, but no placeholder (#441).
  - SBOM-CRA-PRE-7-RQ-07-RE no longer counts a component with a `NOASSERTION` or placeholder supplier as vendor-supplied. Its hash coverage can rise or fall, and below 50% it is an Error under CRA Phase 2 (#416).
  - A contact must reach someone. Placeholders (`NOASSERTION`, `unknown`, `n/a`, `TBD`) and addresses at `example.com`, `example.net` or `example.org` no longer satisfy the CRA security contact, CVD policy, Art. 14 channels and Art. 24 steward floor, EO 14028 disclosure, PCI DSS vulnerability evidence or SSDF PW.6, in the SBOM or the CRA sidecar. Nor do they satisfy the FDA and BSI TR-03183-2 creator-contact checks. Addresses under the reserved `.example` TLD still count (#441).
- **Manufacturer evidence and digests:**
  - The CRA, EO 14028 and EUCC checks that ask for the manufacturer's own evidence read it only from the product: the primary component, and any other product an SPDX document describes. They are the security contact, CVD policy, Art. 24 vulnerability handling, risk assessment, EU DoC, Annex VIII certificate and EUCC reference checks, and the `conformity_summary` rows. A dependency's own references no longer pass them, even when no dependency edge points at it. Only a document that names no product falls back to the roots of its dependency graph (#436).
  - A support link no longer counts as the vulnerability-disclosure URL in CycloneDX. In every format, the URL is the primary component's first `http://`, `https://` or `mailto:` advisories reference (#436).
  - Every hash rule counts only a plausible digest: hex digits, as many as the algorithm's output (SHA-256 64, SHA-512 128, …). An empty, non-hex or wrong-length value no longer satisfies BSI TR-03183-2 (an invalid SHA-512 is an Error), FDA, CRA, FSCT, CISA 2026, EO 14028, SSDF or BSI SBOM-for-AI, and the finding says why (#436).
- **Cryptography:**
  - CNSA 2.0 reports algorithms, certificate signatures and protocols it cannot identify as Errors, and PQC reports unknown algorithms as Warnings. A CBOM with no asset either profile can identify fails both, under SBOM-CNSA2-000 and SBOM-PQC-000 (#400).
  - Names 0.3 could not classify are judged by their own rules (#411): FFDH, JCA names such as `SHA1withRSA`, bare curve names such as `prime256v1`, A5/1 and Dual_EC_DRBG, MQV, the PAKEs, and MACs and KDFs such as HMAC-SHA256. PQC passed them, and now fails a broken or quantum-vulnerable one. CNSA 2.0 warned on them, and now fails one outside its suite under that algorithm's rule, such as SBOM-CNSA2-ALG-002 for HMAC-SHA256.
  - The TLS named groups and signature schemes a cipher suite lists are judged, in TLS 1.2 suites too, so classical-only TLS 1.3 fails CNSA 2.0 and PQC (#419).
  - `pqc` judges hash functions at the 112-bit security level. A CBOM algorithm asset that is SHA-224, SHA-512/224 or SHA3-224 is an Error under the new `SBOM-PQC-HASH-001`, and a SHA-2 asset that states no digest size is a Warning. Keyed uses (HMAC, HKDF, PBKDF2, or an asset declared a MAC, KDF or DRBG) are not judged (#444).
- **CRA and EUCC:**
  - CRA Annex VIII, and the conformity summary's Module B and H rows, need a certification reference. An attestation alone no longer satisfies them (#416).
  - An EUCC certificate past its `euccValidUntil` no longer satisfies the EUCC rules (#416).
  - From 2026-09-11, a missing ENISA platform id (SBOM-CRA-ART-14-ENISA) is a Warning, not an Info. Naming the CSIRT designated as coordinator in `enisaReportingPlatformId` satisfies it (#431).
  - `SBOM-CRA-CYCLES` checks dependency graphs of any size. A graph above 1,000,000 edges was skipped and passed; a cyclic one now gets the Warning, or the Error for important class II and critical products (#440).
- **Dates and versions:**
  - SBOM timestamps later than the evaluation date are a Warning under the CRA and PCI DSS freshness checks (#409).
  - Format versions newer than sbom-tools reads get one explicit Warning (#401).
- **Signatures:** an SPDX 3 signature with an empty value no longer counts as a signature for SBOM-CISA2026-SIGNATURE (#428).

**Looser.** These can make an SBOM that failed in 0.3 pass:
- **CycloneDX XML is read like JSON:** metadata, compositions, signatures and CBOM crypto detail (#406, #412), and AI-BOM model cards (#428). An XML CBOM whose algorithms list `cryptoFunctions` no longer fails to parse with exit `3`: it is judged like its JSON twin (#412).
- **Evidence references count:** CycloneDX attestation, certification-report, risk-assessment, vulnerability-assertion, exploitability-statement and build-system references, and their SPDX 3 counterparts (#416).
- **Package rules apply only to packages:** services, crypto assets and files no longer draw package findings under EO 14028, SSDF, BSI or CRA. The dependency checks of NTIA, FDA, CISA 2026, FSCT and the Comprehensive profile count packages only too. A crypto-only CBOM fails NTIA, FDA, CISA 2026 and Comprehensive on its inventory instead of its dependencies, and FDA and FSCT drop orphan warnings that named only non-packages (#398).
- **Components whose scope is excluded leave the package rules:** a component a CycloneDX SBOM marks `scope: excluded`, and an SPDX development, build or test dependency with what only it brings in. The package rules are the version, supplier, license, hash, identifier and dependency-graph rules of every standard. Each result counts these components in `excluded_components`, and `--include-excluded-scope` judges them as before (#443).
- **The product names its manufacturer:** CRA Art. 13(16) and the FDA manufacturer check accept the product's manufacturer or supplier: CycloneDX `metadata.component.manufacturer` or `.supplier`, CycloneDX `metadata.supplier`, or the SPDX described package's supplier. An organization creator still counts, but only with a real name or email (#436).
- **SPDX 3 `securityAdvisory` references** count as the vulnerability-disclosure URL (#436).
- **A component listed twice is one component:** its entries are merged whatever their order, and a real value (supplier, author, version, licence, identifier, …) always beats an empty one or a placeholder. Until 0.4 the last entry replaced the others, so a verdict could depend on entry order (#440).
- **CISA 2026** accepts a weak hash beside a stronger one (the cyclonedx-maven-plugin default), and no longer asks SPDX 2.x for fields it cannot express (#409).
- **Spec versions compare as numbers:** CycloneDX 1.10 is no longer read as 1.1. It passes EO 14028's format check and draws no CRA machine-readable warning, only the newer-than-supported Warning (#401).
- **Nested training datasets:** SBOM-AIACT-ANNEX-IV-2D-DATASETS accepts a dataset nested under the model with `data[]` evidence, as BSI SBOM-for-AI does (#416).
- **Cryptography:** the classifier names every CycloneDX 1.7 algorithm family, JCA names and common curve aliases (#411). PQ/T hybrids are judged by their parts, not by their weakest part (#415).
- **Justified VEX `not_affected` statements:** one with a machine-readable justification exempts its entry from SBOM-CRA-VULN-METADATA and -REMEDIATION, embedded or via `--vex` (#431). `SBOM-FDA-SECURITY` no longer counts such a vulnerability, and `SBOM-PCI-11-3-1-1-SEVERITY` asks it for no risk ranking (#441).
- **EUCC certificate URLs:** `SBOM-EUCC-CERTREF` also accepts a `commoncriteria` URL, as CRA Annex IV does (#441).
- **OSS stewards:** `oss-steward` takes no product class. Its results carry no `conformity_summary`, and `SBOM-CRA-CYCLES` stays a Warning when the sidecar sets `productClass` to `important-class-2` or `critical` (#434).

**Counts only.** These change counts and lists, not verdicts:
- **Passed checks** are no longer Info violations, so Info counts drop. Verdicts and error and warning counts don't change (#421).
- **SPDX 3 vulnerabilities:** statements that agree about one vulnerability on one component are now one entry, so per-vulnerability counts fall. A vulnerability whose severity only an agreeing CVSS assessment carried no longer draws SBOM-CRA-VULN-METADATA. Contradicting statements still give an entry each (#424).
- **Re-keyed components:** a component re-keyed after a canonical-id collision is judged by its own identifiers. SBOM-CRA-PRE-8-RQ-02-IDENTIFIER no longer fires on such a hardware component with a PURL, and vendor-hash coverage counts such a component (#424).
- **Duplicate components:** the generic standards report one Info finding per document, `SBOM-QUALITY-DUPLICATE-COMPONENT`, `SBOM-NTIA-DUPLICATE-COMPONENT`, `SBOM-CRA-DUPLICATE-COMPONENT` or `SBOM-FDA-DUPLICATE-COMPONENT`. It names the duplicated components and the fields their entries disagree on (#440).
- **Unparseable timestamps:** a creation timestamp that is not an RFC 3339 date-time is reported as unparseable, with its value, instead of missing (#440).
- **Document integrity:** `SBOM-CRA-DOC-INTEGRITY` needs a document signature, or a hashed attestation or certification reference on the product. A serial number alone no longer satisfies it, so more SBOMs get its Info finding (#441).
- **FSCT signatures:** `SBOM-FSCT-SIGNATURE` also reads an SPDX 3 document's `verifiedUsing` signature, so an unsigned SPDX 3 document gets its Info finding (#441).
- **112-bit hashes:** a SHA-224, SHA-512/224 or SHA3-224 asset that declares `nistQuantumSecurityLevel` 0 is reported under `SBOM-PQC-HASH-001` instead of `SBOM-PQC-001` (#444).
- **CRA support period:** a CRA sidecar's `supportEndDate` satisfies SBOM-CRA-ART-13-8, so its Info finding no longer appears beside it (#401).
- **CycloneDX remediation:** `analysis.workaround` is read as remediation, and a declared update or workaround with no text draws the CRA Phase 2 Info finding SBOM-CRA-VULN-METADATA-REMEDIATION (#416).

**Other commands now match `validate`.** These change what `view`, `diff`, `cra-docs` and `timeline` report, not `validate`:
- **The TUIs and reports** (the compliance tab, summary card, policy presets and exports, the quality score, a report's CRA section and the diff's quality delta) give each standard the inputs `validate` gives it: the clock, the CRA sidecar and the product class. They used to give every standard the sidecar and read the wall clock. FDA no longer reads the sidecar's `supportEndDate` there, so `SBOM-FDA-SUPPORT` can appear where it did not (#434).
- **A filtered `view`** judges the whole SBOM. `--severity`, `--ecosystem` and `--vulnerable-only` narrow the component list only: the compliance tab and its exports, the quality score, `--validate-ntia` and a report's CRA section judge every component, as `validate` does (#440).
- **`timeline --as-of`** pins the compliance trend, and the other run flags reach it (#443).

### Compliance scores

Every compliance score uses one formula (#438):

```text
score = (50 without an error, else 0) + floor(50 × checked / (checked + failed))
```

- **Bands:** a compliant result scores 50–100 and a non-compliant one 0–49. In 0.3, one error scored 50 and three warnings 25.
- **Size:** `checked` counts the document and the components in the standard's scope, so one finding no longer halves a large SBOM's score. `failed` counts the errors and warnings, one per failing item.
- **Neutral:** Info findings, passed checks and the findings of a rule that is `off` never lower the score.
- **Where:** `score` in `-o json` and `--summary`, SARIF `overallScore`, the OSCAL `score` property, and the Markdown, HTML and TUI reports. `-o json` results also carry `score_basis: {checked, failed}`, the numbers the score is computed from ([Score](compliance-output.md#score)).
- **Exit codes** follow the verdict, not the score, so they don't change.

### JSON output

`validate -o json` emits the `sbom-tools/compliance/v2` envelope, one object for any number of standards (#410). The schema is `schemas/compliance/v2.schema.json`, and `docs/compliance-output.md` describes every field. The fields added after #410 are additive: the schema id stays `sbom-tools/compliance/v2`.

- **Old layout:** `--json-schema v1` keeps the 0.3 layout until v0.5.0. Passed checks don't appear there. It does carry the new violation fields, and `evaluated`, `suppressed` and `excluded_components` (#437, #442, #443).
- **New in the envelope:** `as_of`, the instant every standard was judged at, and `subject`, the SBOM it judged: the SHA-256 of the bytes read, the format, spec version and file name, the component count, the duplicate entries merged and whether the creation timestamp parses (#445).
- **New on each violation:**
  - `remediation`: guidance phrased for the input format (#408);
  - `help_uri` (#408), which falls back to the page of the rule's standard when no reference has a URL (#445);
  - `finding_id` and `finding_key`: the stable identity of the finding (#410, #417);
  - `finding_detail`, when one rule reports several findings on one subject (#417);
  - `deadline` and `deadline_source`, in deadline mode (#437);
  - `field`, where the checked field lives in the SBOM's format, and `observed`, the value the check read (#442);
  - `default_severity` and `severity_source`, when a rule setting set the severity (#443).
- **New on each result:**
  - `passed[]` and `counts.passed` (#421);
  - `applicable` and `not_applicable_reason` (#410);
  - `score_basis`, when the standard applies (#438);
  - `evaluated`, the checks the standard did not evaluate on the SBOM, each with its reason (#442);
  - `suppressed[]`, the rules turned off and how many findings each dropped, `counts.suppressed`, and `excluded_components` (#443).
- **References:**
  - CRA SBOM-content findings also cite ENISA's Technical Advisory for SBOMs, as `standard_refs` entries of `standard` `EnisaSbomAdvisory` (#439).
  - CNSA 2.0 references have the id `CNSSP 15`, not `CNSA 2.0`, and the EUCC reference names the amending regulations (#439).
  - NIST IR 8547 is cited as final: `IR 8547`, not `IR 8547 ipd` (#437).
  - `SBOM-CRA-ART-24` and the six CRA generic checks (`SBOM-CRA-CREATOR`, `-SERIAL`, `-COMPONENT-NAME`, `-SPEC-VERSION`, `-SPEC-VERSION-UNKNOWN`, `-ELEMENT-ID`) gain `standard_refs` and `help_uri` (#435).
- **`counts.total`** of `SBOM-PCI-11-3-1-1-SEVERITY` counts the entries that still need a risk ranking, not every embedded entry (#441).
- **`--summary`** adds `suppressed` and `excluded_components` when they are not zero (#443).
- **`sarif_rule_id`** now equals `rule_id` (#422).
- **Removed:** the placeholder violations SBOM-AIACT-NA and SBOM-BSIAI-NA. A standard that does not apply says so through `applicable` (#421).

#### Renamed and split rule ids

Bundled rules were split so that each check has its own id (#417), and each standard now reports under its own rule family (#441). `finding_key` and `finding_id` change for findings that moved.

| Old id | New ids |
|---|---|
| `SBOM-CRA-ART-14` (retired) | `SBOM-CRA-ART-14-PSIRT`, `-ART-14-EARLY-WARNING`, `-ART-14-NOTIFICATION`, `-ART-14-ENISA` |
| `SBOM-QUALITY-GENERAL` | `SBOM-QUALITY-` + `CREATOR`, `SERIAL`, `INVENTORY`, `NAME`, `IDENTIFIER`, `LICENSE`, `HASH`, `SPEC-VERSION`, `SPEC-VERSION-UNKNOWN`, `ELEMENT-ID` |
| `SBOM-CRA-GENERAL` | `SBOM-CRA-` + `CREATOR`, `SERIAL`, `COMPONENT-NAME`, `SPEC-VERSION`, `SPEC-VERSION-UNKNOWN`, `ELEMENT-ID` |
| `SBOM-NTIA-GENERAL` | `SBOM-NTIA-` + `SPEC-VERSION`, `SPEC-VERSION-UNKNOWN`, `ELEMENT-ID` |
| `SBOM-FDA-GENERAL` | `SBOM-FDA-` + `COMPONENT-NAME`, `SPEC-VERSION`, `SPEC-VERSION-UNKNOWN`, `ELEMENT-ID` |
| `SBOM-CRA-PRE-8-RQ-02` | `-PRODUCER`, `-IDENTIFIER`, `-FIRMWARE-VERSION`, `-DEVICE-FIRMWARE` |
| `SBOM-CRA-VULN-METADATA` | also `-REMEDIATION`, `-PROFILE` |
| `SBOM-CRA-ANNEX-I-SUPPLY-CHAIN` | also `-TRANSITIVE` |
| `SBOM-CRA-ANNEX-I-DEPENDENCY` | also `-ROOTS` |
| `SBOM-CRA-ART-13-5` | also `-PROFILE` |
| `SBOM-CRA-ART-13-8` | also `-EOL` |
| `SBOM-CRA-LIFECYCLE` | also `-APPROACHING-EOL` |
| `SBOM-SSDF-PS1` | also `-TOOL` |
| `SBOM-FDA-SUPPORT` | also `SBOM-FDA-CONTACT` |
| `SBOM-FSCT-LICENSE-ALL` | also `-LICENSE-CONCLUDED` |
| `SBOM-AIACT-NA`, `SBOM-BSIAI-NA` | removed; see `applicable` |
| `SBOM-NTIA-VERSION` (Standard, Comprehensive) | `SBOM-QUALITY-VERSION` (#441) |
| `SBOM-NTIA-TIMESTAMP` (Comprehensive; FDA) | `SBOM-QUALITY-TIMESTAMP`; `SBOM-FDA-TIMESTAMP` (#441) |
| `SBOM-NTIA-SUPPLIER` (Comprehensive) | `SBOM-QUALITY-SUPPLIER` (#441) |
| `SBOM-NTIA-DEPENDENCY` (Comprehensive) | `SBOM-QUALITY-DEPENDENCY` (#441) |
| `SBOM-FDA-SUPPLIER` | also `SBOM-FDA-MANUFACTURER`, the document-level device manufacturer (#441) |
| `SBOM-PQC-001` | also `SBOM-PQC-HASH-001`, for a 112-bit hash that declares `nistQuantumSecurityLevel` 0 (#444) |

"Also" means the old id stays on the check its text describes, and the new ids take the others. A level in parentheses says where the old id was reported. `SBOM-NTIA-*` ids are unchanged under `--standard ntia`.

**New rule ids** with no old one: the inventory rules `SBOM-NTIA-INVENTORY`, `SBOM-FDA-INVENTORY`, `SBOM-CRA-INVENTORY`, `SBOM-CISA2026-INVENTORY`, `SBOM-EO14028-INVENTORY`, `SBOM-SSDF-INVENTORY` and `SBOM-BSI-TR-03183-2-INVENTORY` (#397); `SBOM-PQC-ALG-UNKNOWN`, PQC's unknown-algorithm Warning (#400); `SBOM-PQC-PROTO-003`, the federal TLS 1.3 deadline (#437); `SBOM-PQC-HASH-001`, hash functions at 112 bits (#444); and `SBOM-QUALITY-DUPLICATE-COMPONENT`, `SBOM-NTIA-DUPLICATE-COMPONENT`, `SBOM-CRA-DUPLICATE-COMPONENT` and `SBOM-FDA-DUPLICATE-COMPONENT` (#440).

**Changed rule texts.** Some short descriptions, requirements, remediation texts and messages changed. Anything that matches on them should match on rule ids instead:
- the EO 14028 rules, now worded as practice: OMB M-26-05 rescinded M-22-18 and M-23-16 (#431);
- the ENISA, ANNEX-IV, ANNEX-VIII, VULN-METADATA and -REMEDIATION rules (#431);
- the SBOM-CRA-ART-13-16 and SBOM-FDA-SUPPLIER remediation, and the field the Art. 13(16) advice names (#436);
- the PQC remediation and references, which cite NIST IR 8547 as final (#437);
- the `SBOM-EUCC-*` short descriptions, which read "EUCC (Reg. (EU) 2024/482, as amended): …", and the `cnsa2`, `eucc` and `ai-act` help texts (#439);
- the `SBOM-CRA-DOC-INTEGRITY` texts, the remediation of the contact, licence, VEX and signature checks, and the messages of the findings that name a contact or licence that does not count (#441);
- the `SBOM-CNSA2-ALG-002` message for a SHA-2 asset of parameter set `512/224` or `512/256`, which now names its digest size (#444).

### SARIF output

SARIF is now code-scanning grade (#422). The first upload after upgrading re-keys alerts. Few alerts existed before: 0.3 results had no location, so GitHub dropped them. [docs/github-code-scanning.md](github-code-scanning.md) walks through the setup.

- **Locations:** every result points at the SBOM file and the line of the element it is about. The path is relative to `--sarif-base`, or to the git root, or to the current directory.
- **Fingerprints:** `partialFingerprints` come from the finding identity, so alerts survive edits that move lines.
- **One rule per check:** 87 checks that reported under shared bucket rules, such as `SBOM-QUALITY-GENERAL`, have rules of their own, and 13 bucket ids are gone. SBOM-CRA-ART-14-ENISA's level is now `warning` (#431).
- **Exact rule lists:** `rules[]` lists exactly the rules of the standards checked, in `--standard` order (#435). `validate --standard bsi -o sarif` declares BSI's 16 rules instead of a shared list of 107 CRA, BSI, EUCC and AI rules. `diff` and `view` declare their own rules and CRA Phase 2's. A fallback rule appears only when a finding needs it. Rule ids and fingerprints do not change, so alerts are kept, but `ruleIndex` values change.
- **Categories:** runs carry `automationDetails.id`, for example `sbom-tools/cra+ntia/`. upload-sarif's `category` input only fills a missing id, so it no longer applies. Pass `--sarif-category` to keep several runs apart.
- **Result cap:** a run keeps at most 25,000 results, GitHub's limit, most severe first. Change it with `--sarif-max-results` (`0` for no cap).
- **`diff -o sarif`:** reports into the new SBOM only. The old SBOM's CRA findings are no longer results, and removed components point at the new SBOM's document line.
- **Passed checks:** not results by default. `--sarif-include-passes` adds them as `kind: "pass"` results at level `none` (#421).
- **The SBOM and the instant:** the run lists the SBOM in `artifacts`, with its `sha-256` hash, and states `asOf` and `subject` as run properties (#445).
- **Verdicts:** a verdict names its standard by the `--standard` key (`standard`) beside the display name (`profile`). It counts the errors, warnings, info findings and passed checks, and carries `notEvaluated` (#442), `suppressed`, `excludedComponents` (#443), `suppressedRules` and `conformitySummary` (#445) where they apply. A run of one standard now says whether it is `compliant`, and each `standards[]` entry puts `compliant` before `applicable`. `quality -o sarif` carries its embedded standard's verdict the same way (#445). `overallScore` uses the new formula (#438).
- **Result properties:** `severity`, `ruleId`, `standardRefs`, `remediation` and `helpUri` (#445); `field` and `observed` (#442); `defaultSeverity` and `severitySource` (#443); and `deadline` and `deadlineSource` in deadline mode (#437). A rule that is `off` reports no result.
- **Deprecated:** the result properties `standardIds` and `standardHelpUris`. They stay in 0.4 and are removed in v0.5.0. Read `standardRefs` instead (#445).
- **A standard selected twice** is checked once, so no alert gets a `#2` twin (#434).
- **TUI exports:** TUI SARIF exports carry no physical locations; use the CLI for code scanning.
- **Links:** SARIF logs link to the current repository (#401), and `$schema` is the OASIS SARIF 2.1.0 id.

### OSCAL output

`validate -o oscal-json` emits OSCAL 1.2.3 (#420).
- **Observations** are typed `discovery`, not the deprecated `finding`. They name their subjects: the SBOM, plus the component for a component finding.
- **Back-matter:** the document's `back-matter` describes the SBOM, with its SHA-256, format, spec version and serial number. Since #445 it also gives the rest of the `-o json` subject: the file name, the component count, the duplicate entries and whether the timestamp parses.
- **Passed checks** are `satisfied` findings, and every result carries `passed-count` (#421).
- **Escaping:** SBOM text in markup fields is escaped, so plain-text readers see backslash escapes such as `\[CISA 2026\]`.
- **Standard key:** a result's `standard` property is the canonical `--standard` value (`cra`, not `CraPhase2`), and the roll-up objective follows it (`cra-compliance`) (#445).
- **Requirement and references:** the observation property `standard-reference` is renamed `requirement`. The standard references are the new `standard-ref` properties, with a `reference` link for each one that has a URL (#445).
- **The fields of `-o json`:** findings carry `finding-id`, `finding-key`, the remediation as `remarks` and a `help` link. Observations carry the finding's other fields, and results the checks not evaluated, the rules turned off and the conformity summary (#445). Rule settings add `default-severity` and `severity-source` to observations, and `suppressed-count` and `excluded-components` to results (#443). The `score` property uses the new formula (#438).
- **UUIDs:** the assessment UUIDs (the document, results, observations and findings) change once in 0.4, because their seed names the standards by their keys. They are stable from then on. The UUIDs of the SBOM and its components do not change (#445).

### sbomqs-compatible scores

`quality -o sbomqs-json` and the sbomqs view follow sbomqs v2.1.2, and they print the pinned version (#431).
- **Score changes:** components with a purl or CPE count as having unique ids, document sharability follows sbomqs's free-for-any-use class, and SPDX 3 documents are scored. 89 of the 129 test fixtures change score.
- **Comparing:** compare against `sbomqs score --legacy --category ntia,semantic,quality,sharing,structural` at v2.1.2.

### VEX

- **CycloneDX justifications:** the SBOM's own CycloneDX analysis and a `--vex` CycloneDX file now map justifications the same way (#431):
  - `code_not_present` is VulnerableCodeNotPresent;
  - `protected_by_compiler` and `protected_at_runtime` are InlineMitigationsAlreadyExist;
  - `protected_at_perimeter` is VulnerableCodeCannotBeControlledByAdversary.

  This shows in `vex status`, diff JSON, the TUI and `convert --to normalized`.
- **CycloneDX `detail`:** a `--vex` CycloneDX file fills the impact statement from `detail` (#431).
- **CSAF:** a CSAF document newer than 2.0 prints a warning, and is read with the 2.0 rules (#431).

### Text, Markdown, HTML and CSV output

Human-readable output escapes SBOM text that could break out of its field. This fixes the injection in the security advisory published with this release (#395, #413, #418, #449):
- **Terminal output:** a line break prints as `\n` and a leading `:` as `\:`. Control and bidi characters are dropped.
- **Markdown and HTML:** text is Markdown-escaped, backslash included. In a Markdown table, `<` and `>` are written `\<` and `\>`, so `<2.0` renders as itself (#449).
- **CSV:** formula-like values are quote-prefixed.
- **File names:** error messages, status lines and the `quality` report header clean the file names they print the same way, since a file name can come from a pull request too (#449).

Text output also gains a `fix:` line under each finding (#408) and an "N checks passed" line (#421). The `validate` text report changes further ([Text report](compliance-output.md#text-report)):
- **Rule column:** the finding line names the rule after the severity: `[ERROR] SBOM-FDA-HASH | Integrity Information | …`. A script that splits the line on ` | ` sees one more column (#442).
- **New lines:** `observed:` shows the value the check read (#442), `deadline:` the deadline in deadline mode (#437), and `severity:` a severity a rule setting set (#443). Under the status, an `Excluded:` line counts the components left out for their scope (#443).
- **New sections:** after the findings, `Not evaluated:` lists the checks the standard did not evaluate, with the reason (#442), and `Suppressed by settings:` lists the rules turned off (#443).

The Markdown, HTML and TUI reports show the new compliance score (#438), and the HTML footer links to the current repository (#401). The side-by-side report pads rows by characters, not bytes, so rows with `→` line up (#395). The TUI violation detail shows `Field:`, `Observed:` and `Deadline:` lines, and the default severity of an overridden finding (#437, #442, #443). Scripts that read these outputs should switch to `-o json`.

### Normalized JSON and the C ABI

For `convert --to normalized` and the FFI:
- CycloneDX services are typed `Service`, and SPDX source, archive and file packages are typed `Other` (#398).
- External-reference types are named variants, such as `"Attestation"`, not `{"Other": "attestation"}`. Reference hashes are kept (#416).
- Every cipher suite carries `tls_groups` and `tls_signature_schemes` (#419).
- **Document:** `document.supplier` holds CycloneDX `metadata.supplier` (#436), `document.created_unparsed` a creation timestamp that does not parse (#440), and `document.profile_conformance` SPDX 3 `profileConformance` (#441). SPDX 3 documents no longer set `distribution_classification`, which is CycloneDX's TLP label (#441).
- **SBOM:** `described_root_ids` lists the other products an SPDX document describes (#436), and `duplicate_components` the components the document lists more than once (#440). Each is omitted when empty.
- **Components:** `scope`, for a component that has one (#443).

The C ABI and the bindings (#446):
- **ABI version `2`:** `sbom_tools_abi_version_json` reports `abi_version: "2"`. The version rises when a release changes the contract incompatibly, as 0.4's renamed payload values do. Additions keep it, and the crate version tells such releases apart. Code that checks `abi_version == "1"` must accept `"2"`.
- **Compliance calls:** `sbom_tools_validate_json` returns the `validate -o json` envelope, `sbom_tools_score_sbom_with_options_json` the `quality -o json` document, and `sbom_tools_rule_catalog_json` the `rules -o json` catalogue, byte for byte. They take the CLI's compliance inputs as JSON options, and read no files ([From the C ABI and the bindings](compliance-output.md#from-the-c-abi-and-the-bindings)).
- **Rule options:** findings whose rule a call's `rules` option sets report `severity_source: "cli"`, as for `--rule`.
- **Unchanged:** `sbom_tools_score_sbom_json` keeps its behaviour, for compatibility, and still reads the wall clock. The other existing functions, enums and error codes are unchanged.
- **Bindings:** the Go, Swift, Python and Node.js bindings expose the three calls with typed results. The Go and Swift `NormalizedSbomPayload` gain `DescribedRootIDs` and `describedRootIDs` (#436).

### GitHub Action

- **Action v1.4.0** pins `version: latest` to sbom-tools 0.3.x, so v1 workflows don't jump to 0.4 unasked. Workflows pinned to an older v1 commit should set `version: 0.3.0` or move to v2.
- **Action v2** supports every standard and profile and the full exit contract. Its default is a pinned 0.4.x.

## Rust library

### `#[non_exhaustive]` types

These types are `#[non_exhaustive]` (#423):
- **Results:** `ComplianceResult`, `Violation`, `ViolationCounts`, `PassedCheck`, `StandardRef`, `ConformityAssessmentSummary`, `ConformityEvidence`;
- **Enums:** `ViolationSeverity`, `ViolationCategory`, `Applicability`, `CraPhase`, `ClassCheck`, `RuleKind`;
- **Registry:** `RuleMeta`, `FieldAdvice`, `FormatAdvice`, `RemediationFormat`;
- **Model:** `Component`.

The types added after #423 are `#[non_exhaustive]` too: `ComplianceRunConfig` (#434); `RuleCatalogEntry`, `RuleReference`, `RuleAdvice`, `RuleFormatAdvice` (#435); `PqcMode`, `PqcProfile`, `CnsaCategory`, `Deadline` (#437); `DuplicateComponent` (#440); `RuleEvaluation`, `EvaluationStatus` (#442); `RuleSetting`, `SettingSource`, `SeverityOverride`, `SuppressedRule` (#443); and `PqcInputsError` (#446).

What changes for your code:
- **Building them:** use the constructors (`ComplianceResult::new`, `with_passed`, `not_applicable`; `StandardRef::new`; `Component::new`; `ComplianceRunConfig::new` and its `with_*` methods), or deserialize them from JSON.
- **Matching on the enums:** add a wildcard arm.

### Compliance API

- **Run configuration:**
  - New `quality::ComplianceRunConfig` holds one run's inputs and builds each standard's checker with the inputs it reads (#434). The CLI, the TUIs, the report writers and the C ABI all build their checkers through it.
  - Builders: `with_as_of`, `with_sidecar`, `with_product_class` (#434); `with_pqc_mode`, `with_pqc_profile`, `with_cnsa_category` (#437); `with_rule_settings`, `with_include_excluded_scope` (#443); and `with_pqc_inputs`, which rejects a profile or category outside deadline mode (#446). Each has a getter.
  - Running: `checker(level)`, `check(level, sbom)`, `check_levels(levels, sbom)`, `effective_product_class()` and `product_class_conflict()` (#434), and `judged_at()`, the one instant a run states (#446).
  - Policy: `sidecar_applies`, `product_class_applies` (#434), `pqc_mode_applies`, `pqc_profile_applies`, `cnsa_category_applies` (#437) and `excluded_scope_applies` (#443) say which levels read which input.
  - `ComplianceChecker` gains `with_pqc_mode`, `with_pqc_profile`, `with_cnsa_category` and `pqc_mode()` (#437), and `with_rule_settings` and `with_include_excluded_scope` (#443). A bare `ComplianceChecker::new(level)` now leaves components whose scope is excluded out of the package rules, as a default run does (#443).
  - `QualityScorer::with_compliance` takes a run configuration. `with_cra_sidecar`, `with_cra_product_class` and `with_as_of` are shorthands for it, and the last two are no longer `const fn` (#434).
  - New `StandardSelector::dedup_by_level`, which keeps the first selection of each level (#434).
  - New `quality::parse_as_of`, the `--as-of` parser, and `quality::PqcInputsError` (#446).
- **PQC deadlines:** new `PqcMode` (`Readiness`, `Deadline`), `PqcProfile` (`Nist`, `Federal`), `CnsaCategory` (six categories, with `label()`, `preferred_by()`, `exclusive_by()` and `ALL`) and `Deadline` (`date`, `source`) (#437).
- **Rule settings:** new `RuleSetting` (`Off`, `Info`, `Warning`, `Error`), `RuleSettings` (`set`, `get`, `iter`, `unmatched`), `SettingSource` (`Config`, `Cli`), `SeverityOverride`, `SuppressedRule` and `resolve_rule_id` (#443).
- **Results:**
  - `ComplianceResult` gains `passed: Vec<PassedCheck>`, with `with_passed()` and `not_applicable(level, reason)`.
  - `ComplianceResult::new` no longer infers not-applicable from marker violations (#421).
  - `ComplianceResult::score()` uses the new formula, also public as `quality::compliance_score(errors, warnings, checked)`. New `elements_checked` (a public field that is not serialized; `1` for a result built with `ComplianceResult::new`), `with_elements_checked()` and `failed_checks()` (#438).
  - `ComplianceResult` gains `evaluated: Vec<RuleEvaluation>` and `with_evaluated()`, with the new `RuleEvaluation` (`not_evaluated(rule_id, reason)`) and `EvaluationStatus::NotEvaluated` (#442).
  - `ComplianceResult` gains `suppressed: Vec<SuppressedRule>`, `excluded_components: usize` and `suppressed_count()` (#443).
  - `conformity_summary` is `None` for `CraOssSteward` at every product class (#434).
- **Violations:**
  - `Violation` gains `remediation` (#408) and `finding_detail` (#417).
  - `Violation::remediation_guidance()` returns `Cow<'_, str>` (#408).
  - `Violation` gains `deadline: Option<Deadline>` (#437), `field` and `observed` (#442), and `severity_override: Option<SeverityOverride>` (#443). Payloads without them deserialize to `None`.
  - New `Violation::failed_checks()` (#438). `Violation::help_uri()` falls back to the page of the rule's standard (#445).
- **Finding identity:**
  - New `finding_id`, `finding_key`, `finding_subject` and `standard_key` (#410, #417).
  - `finding_key` and `finding_subject` take `&impl FindingIdentity`, which `Violation` and `PassedCheck` implement (#421).
  - New `quality::finding_fingerprint` (#422).
- **Registry:**
  - New `RuleKind`, `PASS_RULE_IDS` and `rule_kind()` (#421), and `RemediationFormat`, `FormatAdvice` and `FieldAdvice` (#408).
  - SBOM-AIACT-NA and SBOM-BSIAI-NA leave `all_rule_ids()` and `rule_meta()` (#421).
  - `rule_meta("SBOM-CRA-ART-14-ENISA").default_severity` is Warning (#431).
  - New `rules_for_level(level)`, each level's rule list (#435). `quality::COMPLIANCE_SARIF_RULE_IDS` is removed: use `rules_for_level`, since the CRA profiles, BSI, EUCC and the AI profiles each have a list of their own.
  - New `rule_catalog(&RuleCatalogFilter)` and `rule_catalog_entry(id)`, with `RuleCatalogEntry`, `RuleCatalogFilter`, `RuleReference`, `RuleAdvice` and `RuleFormatAdvice`, and `StandardRef::citation()` (#435).
  - New `RuleMeta::field_for(RemediationFormat)` (#442).
  - `all_rule_ids()`, `rule_meta()` and the `rules_for_level` lists gain the new rule ids (#437, #440, #441, #444). The lists of Standard, Comprehensive and FDA name the renamed ids (#441).
  - New `StandardKind::EnisaSbomAdvisory` (#439).
- **Metrics:** `HashQualityMetrics::vendor_components_with_hash` and `vendor_components_with_strong_hash` count only components whose hash is a plausible digest (#436). New `HashQualityMetrics::from_components` (#443).
- **CLI functions:**
  - `cli::run_validate` gains `require_applicable` and `json_schema` (#410), and `sarif_base`, `sarif_category`, `sarif_include_passes` and `sarif_max_results` (#421, #422). It also gains `pqc: PqcOptions` (#437), and `rules: &RuleOptions` and `fail_on: &[&'static str]` (#443).
  - `cli::run_quality` gains `sarif_base`, `sarif_category` and `sarif_max_results` (#422), `pqc` (#437) and `rules: RuleOptions` (#443). `cli::QualityConfig` gains `pqc` and `rules`.
  - `cli::run_cra_docs_with_force` takes `as_of: Option<&str>` before `force` (#434), and `pqc` and `rules: &RuleOptions` after it (#437, #443).
  - New `cli::compliance_run_config(class, as_of, pqc, rules)`, which parses the run flags and loads the sidecar (#434, #437, #443).
  - New `cli::PqcOptions` (#437) with `with_config_defaults` (#443), `cli::RuleOptions` (`from_flags`), `parse_rule_setting_arg` and `parse_fail_on_arg` (#443).
  - New `cli::run_rules`, `run_rules_explain`, `parse_rule_id` and `RulesOutputFormat` (#435).
  - New `cli::error_report(&anyhow::Error)`: the error report `main` prints, each line cleaned (#449).
- **Reports:**
  - **SARIF:** new `SarifOptions`, `SarifArtifact`, `SarifArtifactLocation`, `SbomLocator`, and `generate_{compliance,multi_compliance,quality,ai_readiness}_sarif_with(.., &SarifOptions)` (#422). Without an artifact, a writer still emits no physical location. `SarifOptions::with_subject(&AssessedSbom, as_of)` adds the SBOM artifact and the `asOf` and `subject` run properties (#445).
  - **Config:** `ReportConfig` gains `sarif: SarifOptions`, and `config::OutputConfig` gains `sarif_base`, `sarif_category` and `sarif_max_results`. Struct literals that don't use `..Default::default()` break (#422).
  - **Subject:** new `reports::AssessedSbom`, the SBOM with the digest of the bytes it was read from and its file name: `new(&sbom, input_bytes)`, `with_file_name(path)`, `sbom()`, `sha256()` and `file_name()` (#445).
  - **JSON:** new `reports::generate_compliance_json_at(&results, &AssessedSbom, as_of)`, which writes `as_of` and `subject`. `generate_compliance_json(&results)` is unchanged and writes neither (#445). New `reports::generate_quality_json`, what `quality -o json` prints (#446).
  - **OSCAL:** `reports::oscal::generate_assessment_results_at(&results, &AssessedSbom, as_of: DateTime<Utc>)` is new in 0.4 (#420). Until #445 it took `(&results, &NormalizedSbom, sbom_digest, Option<DateTime<Utc>>)`: build an `AssessedSbom` from the SBOM and its bytes, and pass `Utc::now()` where you passed `None`.
  - **Rule catalogue:** new `reports::generate_rule_catalog_json` and `reports::RULE_CATALOG_JSON_SCHEMA` (#435).
  - **sbomqs:** `reports::sbomqs_compat::SBOMQS_PARITY_TARGET` is `"v2.1.2"` (#431).
  - **Escaping:** `reports::escape::escape_markdown_table` also escapes `<` and `>` (#449).
- **Types changed for speed (#447):**
  - `Violation::remediation` and `Violation::field` are `Option<Cow<'static, str>>`, not `Option<String>`. Read them with `.as_deref()` as before; build one with `Some(text.into())`.
  - `Violation::standard_refs` and `PassedCheck::standard_refs` are `Cow<'static, [StandardRef]>`, not `Vec<StandardRef>`. Iterate with `.iter()`, build one from a `Vec` with `.into()`, write an empty one as `Cow::Borrowed(&[])`, and change one in place with `.to_mut()`. `registry_standard_refs()` still returns a `Vec`.
  - `ComplianceRunConfig::check_levels` checks the standards in parallel on rayon's global pool (`RAYON_NUM_THREADS` sizes it) and judges each at `judged_at()`. Results come back in the order of the levels, and every output is byte-identical to a one-by-one run.

### Configuration types

These structs are not `#[non_exhaustive]`, so struct literals must set the new fields:
- `config::DiffConfig` gains `compliance: ComplianceRunConfig`, which `DiffConfigBuilder::compliance` sets and the builder defaults (#434).
- `config::ViewConfig` gains `as_of` (#434), `pqc_mode`, `pqc_profile` and `cnsa_category` (#437), and `rule_settings` and `include_excluded_scope` (#443).
- `config::TimelineConfig` gains `compliance` (#443).
- `config::ComplianceConfig` gains `rules`, `fail_on`, `include_excluded_scope`, `pqc_mode`, `pqc_profile` and `cnsa_category`. It implements `Default`, so `..Default::default()` keeps working (#443).

### TUI and diff engine

- New `ViewApp::new_with_compliance` and `App::new_diff_with_compliance`, which take a run configuration (one per side for a diff), and `MultiDiffEngine::with_compliance` (#434).
- Removed `ViewApp::with_cra_sidecar`, `ViewApp::with_cra_product_class` and `App::with_cra_sidecars`: pass a `ComplianceRunConfig` instead (#434).
- New `ViewApp::new_filtered`, `judged_sbom()` and `filtered_out()`, so a filtered view judges the whole SBOM (#440).

### SBOM model

- `DocumentMetadata` gains `supplier: Option<Organization>` (#436), `created_unparsed: Option<String>` (#440) and `profile_conformance: Vec<String>` (#441). It is not `#[non_exhaustive]`: struct literals must add them, or use `..DocumentMetadata::default()`. The SPDX 3 parser no longer sets `distribution_classification` (#441).
- `NormalizedSbom` gains `described_root_ids: Vec<CanonicalId>`, with `add_described_root()` and `described_components()` (#436), and `duplicate_components: IndexMap<CanonicalId, DuplicateComponent>` (#440). Struct literals need both fields.
- Removed `NormalizedSbom::apply_cra_sidecar`, which nothing called (#434).
- `NormalizedSbom::add_component` merges an entry of the same component under a taken id instead of replacing it, and records the merge. Entries are the same component when their names and versions agree where both are known. `claim_canonical_id` re-keys only an entry of another known name or version, and `collision_count` counts every merged entry, exact repeats included (#440).
- New `model::DuplicateComponent` (`canonical_id`, `entries`, `format_ids`, `conflicts`), `Component::is_same_component` and `Component::merge_duplicate` (#440).
- `Component` gains `scope: Option<DependencyScope>`. `merge_duplicate` keeps the most-needed scope of two entries (#443).
- `parsers::ParsedMetadata`, the streaming `ParseEvent::Metadata` payload, gains `described_root_ids` (#436), and `duplicate_components` and `collision_count` (#440). `serialization::NormalizedSbomPayload` gains `duplicate_components` (#440).
- New `CraSidecarMetadata::from_json_value`, which reads a sidecar from JSON with the checks a sidecar file gets (#446).

### C ABI

- New `sbom_tools_validate_json`, `sbom_tools_score_sbom_with_options_json` and `sbom_tools_rule_catalog_json`, in the header and in `sbom_tools::ffi`, which the crate root re-exports under the `ffi` feature (#446).
- `sbom_tools_abi_version_json` reports `abi_version: "2"`. The existing functions, enums and error codes are unchanged (#446).
- **Go:** new `ValidateJSON`, `Validate`, `ScoreWithOptionsJSON`, `ScoreWithOptions`, `RuleCatalogJSON` and `RuleCatalog`, with typed results such as `ComplianceEnvelope`, `QualityOutput` and `RuleCatalogDocument` (#446).
- **Swift:** new `validateJSON(_:options:)`, `validate(_:options:)`, `scoreWithOptionsJSON(_:options:)`, `scoreWithOptions(_:options:)`, `ruleCatalogJSON(standards:)` and `ruleCatalog(standards:)` (#446).
- **Python:** new `validate_json`, `score_with_options_json` and `rule_catalog_json`, with `TypedDict` hints. `version().abi_version` is `"2"` (#446).
- **Node.js:** new `validateJson`, `scoreWithOptionsJson` and `ruleCatalogJson`, with TypeScript types (#446).

### Crypto model

- `AlgorithmClassification` gains `construction` and `primitive_label()` (#411), and `hybrid`, `hybrid()` and `hybrid_parts()` (#415).
- `AlgorithmClass::Hybrid` is a new variant (#415).
- `Ikev2TransformKind::Addke1` to `Addke7` and `additional_key_exchange()` read RFC 9370 additional key exchanges (#415).
- `CipherSuite` gains `tls_groups` and `tls_signature_schemes` and derives `Default` (#419).
- New in `sbom_tools::model`: `TlsRegistryEntry`, `tls_named_group`, `tls_signature_scheme` and `is_tls_grease` (#419).
- `CraProductClass::name()` returns "Annex III, class I" and "Annex III, class II" (#431).
