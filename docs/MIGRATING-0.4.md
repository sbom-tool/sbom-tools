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
| Rule ids are split and renamed | Anything that matches on `rule_id` | Map the old ids to the new ones ([table](#renamed-and-split-rule-ids)). |
| Passed checks move to `passed[]` | Dashboards that count Info findings or SARIF notes | Read `passed[]` and `counts.passed`. |
| SARIF carries locations, fingerprints and one rule per check | GitHub code scanning users | Expect the first upload to re-key alerts; set `--sarif-category` instead of upload-sarif's `category`. |
| OSCAL moves to 1.2.3 | OSCAL consumers | Validate against the 1.2.3 schema. |
| sbomqs-compatible scores follow sbomqs v2.1.2 | Users of `quality -o sbomqs-json` | Re-baseline stored comparisons. |
| Text, Markdown, HTML and CSV escape SBOM text | Scripts that scrape human-readable output | Use `-o json`. |
| Normalized and FFI JSON gain variants and fields | Bindings and FFI consumers | Handle the new variants. |
| Result types are `#[non_exhaustive]` | Rust library users | Use constructors, and add wildcard arms. |

## Command line and CI

### Exit codes

Usage errors exit `3` in every command, as operational errors already did. Usage errors are an unknown flag, standard or value, or a missing argument. They used to exit `2`, so a mistyped flag looked like a warning (#410).

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Compliance errors, a not-applicable standard under `--require-applicable`, changes under `--fail-on-change`, and the other per-command failures in the README |
| `2` | Compliance warnings under `--fail-on-warning`, or new vulnerabilities under `--fail-on-vuln` |
| `3` | Usage or operational error |
| `4`–`7` | VEX gaps, licence policy, KEV and ML regression gates, unchanged |

New: `validate --require-applicable` exits `1` when a selected standard does not apply to the SBOM, for example `--standard ai-act` on an SBOM without AI components (#410).

### Verdicts

Upgrading can change your pass or fail result. The release fixes false passes and false failures found in the post-0.3.0 review.

**Stricter.** These can make an SBOM that passed in 0.3 fail:
- **Identifiers and inventory:**
  - Empty, `NOASSERTION` or scheme-less purls and CPEs no longer count as identifiers, and components that shared one are kept apart (#397).
  - An SBOM with no package components fails NTIA, FDA, CRA, CISA 2026, EO 14028, SSDF, BSI and PCI DSS with an inventory finding (#397).
  - SPDX packages with purpose `SOURCE`, `ARCHIVE` or `FILE` are checked as packages (#398).
- **Placeholders:**
  - `NOASSERTION` and placeholders (`TBD`, `N/A` and similar) no longer satisfy supplier, author or version rules. CISA 2026 and FSCT still accept an explicit unknown where their texts allow one (#399).
  - An empty or placeholder document name, such as `""` or `NOASSERTION`, no longer counts as a name for SBOM-FDA-NAME and SBOM-CRA-ART-13-15-PRODUCT (#428).
  - BSI/G7 SBOM-for-AI rejects placeholder model and dataset fields (#416).
- **Cryptography:**
  - CNSA 2.0 reports algorithms, certificate signatures and protocols it cannot identify as Errors, and PQC reports unknown algorithms as Warnings (#400).
  - TLS 1.3 named groups and signature schemes are judged, so classical-only TLS 1.3 fails CNSA 2.0 and PQC (#419).
- **CRA and EUCC:**
  - CRA Annex VIII, and the conformity summary's Module B and H rows, need a certification reference. An attestation alone no longer satisfies them (#416).
  - An EUCC certificate past its `euccValidUntil` no longer satisfies the EUCC rules (#416).
  - From 2026-09-11, a missing ENISA platform id (SBOM-CRA-ART-14-ENISA) is a Warning, not an Info. Naming the CSIRT designated as coordinator in `enisaReportingPlatformId` satisfies it (#431).
- **Dates and versions:**
  - SBOM timestamps later than the evaluation date are a Warning under the CRA and PCI DSS freshness checks (#409).
  - Format versions newer than sbom-tools reads get one explicit Warning (#401).
- **Signatures:** an SPDX 3 signature with an empty value no longer counts as a signature for SBOM-CISA2026-SIGNATURE (#428).

**Looser.** These can make an SBOM that failed in 0.3 pass:
- **CycloneDX XML is read like JSON:** metadata, compositions, signatures and CBOM crypto detail (#406, #412), and AI-BOM model cards (#428).
- **Evidence references count:** CycloneDX attestation, certification-report, risk-assessment, vulnerability-assertion, exploitability-statement and build-system references, and their SPDX 3 counterparts (#416).
- **Package rules apply only to packages:** services, crypto assets and files no longer draw package findings under EO 14028, SSDF, BSI or CRA (#398).
- **CISA 2026** accepts a weak hash beside a stronger one (the cyclonedx-maven-plugin default), and no longer asks SPDX 2.x for fields it cannot express (#409).
- **Cryptography:** the classifier names every CycloneDX 1.7 algorithm family, JCA names and common curve aliases (#411). PQ/T hybrids are judged by their parts, not by their weakest part (#415).
- **Justified VEX `not_affected` statements:** one with a machine-readable justification exempts its entry from SBOM-CRA-VULN-METADATA and -REMEDIATION, embedded or via `--vex` (#431).

**Counts only.** These change counts and lists, not verdicts:
- **Passed checks** are no longer Info violations, so Info counts drop. Verdicts and error and warning counts don't change (#421).
- **SPDX 3 vulnerabilities:** statements that agree about one vulnerability on one component are now one entry, so per-vulnerability counts fall. A vulnerability whose severity only an agreeing CVSS assessment carried no longer draws SBOM-CRA-VULN-METADATA. Contradicting statements still give an entry each (#424).
- **Re-keyed components:** a component re-keyed after a canonical-id collision is judged by its own identifiers. SBOM-CRA-PRE-8-RQ-02-IDENTIFIER no longer fires on such a hardware component with a PURL, and vendor-hash coverage counts such a component (#424).

### JSON output

`validate -o json` emits the `sbom-tools/compliance/v2` envelope, one object for any number of standards (#410). The schema is `schemas/compliance/v2.schema.json`, and `docs/compliance-output.md` describes every field.

- **Old layout:** `--json-schema v1` keeps the 0.3 layout until v0.5.0. Passed checks don't appear there.
- **New on each violation:**
  - `remediation`: guidance phrased for the input format (#408);
  - `help_uri` (#408);
  - `finding_id` and `finding_key`: the stable identity of the finding (#410, #417);
  - `finding_detail`, when one rule reports several findings on one subject (#417).
- **New on each result:**
  - `passed[]` and `counts.passed` (#421);
  - `applicable` and `not_applicable_reason` (#410).
- **`sarif_rule_id`** now equals `rule_id` (#422).
- **Removed:** the placeholder violations SBOM-AIACT-NA and SBOM-BSIAI-NA. A standard that does not apply says so through `applicable` (#421).

#### Renamed and split rule ids

Bundled rules were split so that each check has its own id (#417). `finding_key` and `finding_id` change for findings that moved.

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

"Also" means the old id stays on the check its text describes, and the new ids take the others.

**Changed rule texts.** Some short descriptions, requirements and remediation texts changed. Anything that matches on them should match on rule ids instead (#431):
- the EO 14028 rules, now worded as practice: OMB M-26-05 rescinded M-22-18 and M-23-16;
- the ENISA, ANNEX-IV, ANNEX-VIII, VULN-METADATA and -REMEDIATION rules.

### SARIF output

SARIF is now code-scanning grade (#422). The first upload after upgrading re-keys alerts. Few alerts existed before: 0.3 results had no location, so GitHub dropped them. [docs/github-code-scanning.md](github-code-scanning.md) walks through the setup.

- **Locations:** every result points at the SBOM file and the line of the element it is about. The path is relative to `--sarif-base`, or to the git root, or to the current directory.
- **Fingerprints:** `partialFingerprints` come from the finding identity, so alerts survive edits that move lines.
- **One rule per check:** 87 checks that reported under shared bucket rules, such as `SBOM-QUALITY-GENERAL`, have rules of their own, and 13 bucket ids are gone. SBOM-CRA-ART-14-ENISA's level is now `warning` (#431).
- **Categories:** runs carry `automationDetails.id`, for example `sbom-tools/cra+ntia/`. upload-sarif's `category` input only fills a missing id, so it no longer applies. Pass `--sarif-category` to keep several runs apart.
- **Result cap:** a run keeps at most 25,000 results, GitHub's limit, most severe first. Change it with `--sarif-max-results` (`0` for no cap).
- **`diff -o sarif`:** reports into the new SBOM only. The old SBOM's CRA findings are no longer results, and removed components point at the new SBOM's document line.
- **Passed checks:** not results by default. `--sarif-include-passes` adds them as `kind: "pass"` results at level `none` (#421).
- **TUI exports:** TUI SARIF exports carry no physical locations; use the CLI for code scanning.
- **Links:** SARIF logs link to the current repository (#401), and `$schema` is the OASIS SARIF 2.1.0 id.

### OSCAL output

`validate -o oscal-json` emits OSCAL 1.2.3 (#420).
- **Observations** are typed `discovery`, not the deprecated `finding`. They name their subjects: the SBOM, plus the component for a component finding.
- **Back-matter:** the document's `back-matter` describes the SBOM, with its SHA-256, format, spec version and serial number.
- **Passed checks** are `satisfied` findings, and every result carries `passed-count` (#421).
- **Escaping:** SBOM text in markup fields is escaped, so plain-text readers see backslash escapes such as `\[CISA 2026\]`.

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

Human-readable output escapes SBOM text that could break out of its field. This fixes the injection in the security advisory published with this release (#395, #413, #418):
- **Terminal output:** a line break prints as `\n` and a leading `:` as `\:`. Control and bidi characters are dropped.
- **Markdown and HTML:** text is Markdown-escaped, backslash included.
- **CSV:** formula-like values are quote-prefixed.

Text output also gains a `fix:` line under each finding (#408) and an "N checks passed" line (#421). Scripts that read these outputs should switch to `-o json`.

### Normalized JSON and the C ABI

For `convert --to normalized` and the FFI:
- CycloneDX services are typed `Service`, and SPDX source, archive and file packages are typed `Other` (#398).
- External-reference types are named variants, such as `"Attestation"`, not `{"Other": "attestation"}`. Reference hashes are kept (#416).
- Every cipher suite carries `tls_groups` and `tls_signature_schemes` (#419).

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

What changes for your code:
- **Building them:** use the constructors (`ComplianceResult::new`, `with_passed`, `not_applicable`; `StandardRef::new`; `Component::new`), or deserialize them from JSON.
- **Matching on the enums:** add a wildcard arm.

### Compliance API

- **Results:**
  - `ComplianceResult` gains `passed: Vec<PassedCheck>`, with `with_passed()` and `not_applicable(level, reason)`.
  - `ComplianceResult::new` no longer infers not-applicable from marker violations (#421).
- **Violations:**
  - `Violation` gains `remediation` (#408) and `finding_detail` (#417).
  - `Violation::remediation_guidance()` returns `Cow<'_, str>` (#408).
- **Finding identity:**
  - New `finding_id`, `finding_key`, `finding_subject` and `standard_key` (#410, #417).
  - `finding_key` and `finding_subject` take `&impl FindingIdentity`, which `Violation` and `PassedCheck` implement (#421).
  - New `quality::finding_fingerprint` (#422).
- **Registry:**
  - New `RuleKind`, `PASS_RULE_IDS` and `rule_kind()` (#421), and `RemediationFormat`, `FormatAdvice` and `FieldAdvice` (#408).
  - SBOM-AIACT-NA and SBOM-BSIAI-NA leave `all_rule_ids()` and `rule_meta()` (#421).
  - `rule_meta("SBOM-CRA-ART-14-ENISA").default_severity` is Warning (#431).
- **CLI functions:**
  - `cli::run_validate` gains `require_applicable` and `json_schema` (#410), and `sarif_base`, `sarif_category`, `sarif_include_passes` and `sarif_max_results` (#421, #422).
  - `cli::run_quality` gains `sarif_base`, `sarif_category` and `sarif_max_results` (#422).
- **Reports:**
  - **SARIF:** new `SarifOptions`, `SarifArtifact`, `SarifArtifactLocation`, `SbomLocator`, and `generate_{compliance,multi_compliance,quality,ai_readiness}_sarif_with(.., &SarifOptions)` (#422). Without an artifact, a writer still emits no physical location.
  - **Config:** `ReportConfig` gains `sarif: SarifOptions`, and `config::OutputConfig` gains `sarif_base`, `sarif_category` and `sarif_max_results`. Struct literals that don't use `..Default::default()` break (#422).
  - **OSCAL:** `reports::oscal::generate_assessment_results_at` is new in 0.4 and takes the `NormalizedSbom` (#420).
  - **sbomqs:** `reports::sbomqs_compat::SBOMQS_PARITY_TARGET` is `"v2.1.2"` (#431).

### Crypto model

- `AlgorithmClassification` gains `construction` and `primitive_label()` (#411), and `hybrid`, `hybrid()` and `hybrid_parts()` (#415).
- `AlgorithmClass::Hybrid` is a new variant (#415).
- `Ikev2TransformKind::Addke1` to `Addke7` and `additional_key_exchange()` read RFC 9370 additional key exchanges (#415).
- `CipherSuite` gains `tls_groups` and `tls_signature_schemes` and derives `Default` (#419).
- New in `sbom_tools::model`: `TlsRegistryEntry`, `tls_named_group`, `tls_signature_scheme` and `is_tls_grease` (#419).
- `CraProductClass::name()` returns "Annex III, class I" and "Annex III, class II" (#431).
