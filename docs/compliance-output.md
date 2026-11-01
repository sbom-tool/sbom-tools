# Compliance JSON output

`sbom-tools validate -o json` prints one JSON object, the
`sbom-tools/compliance/v2` envelope, whatever the number of standards checked.
The schema is published at
[`schemas/compliance/v2.schema.json`](../schemas/compliance/v2.schema.json)
(JSON Schema draft 2020-12), and the test suite validates every `-o json`
output against it.

```sh
sbom-tools validate sbom.json --standard ntia,cra -o json |
  jq -c '.results[] | {standard, applicable, compliant, counts}'
```

`-o oscal-json` prints the same results as an OSCAL assessment-results
document instead; see [OSCAL assessment results](#oscal-assessment-results).
`-o sarif` prints them as a SARIF 2.1.0 log for code scanning; see
[SARIF](#sarif). The three outputs carry the same fields for every finding
and every standard's verdict, under the names each format uses; see
[Fields in every output](#fields-in-every-output). `sbom-tools rules`
describes the rules themselves: which standards use each one, its references
and its remediation; see [Rule catalogue](#rule-catalogue).

## Envelope

```json
{
  "schema": "sbom-tools/compliance/v2",
  "tool": { "name": "sbom-tools", "version": "0.4.0" },
  "as_of": "2026-10-12T00:00:00Z",
  "subject": {
    "sha256": "be7995c235de8f84244baf2d5cd4a217deb705904ffe2e874647f3e3c0824d96",
    "format": "CycloneDX",
    "spec_version": "1.5",
    "file_name": "minimal.cdx.json",
    "components": 3,
    "duplicates": { "components": 0, "entries": 0, "conflicts": [] },
    "timestamp_unparsed": false
  },
  "results": [ { "standard": "ntia", "...": "one entry per standard" } ]
}
```

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | Always `sbom-tools/compliance/v2`. |
| `tool.name` | string | Always `sbom-tools`. |
| `tool.version` | string | The release that produced the document. |
| `as_of` | string | The instant every standard was judged at: `--as-of`, else the wall clock when the run started, to the second. RFC 3339 in UTC. |
| `subject` | object | The SBOM the results judge, and how its document was read, described below. |
| `results` | array | One entry per checked standard, in `--standard` order. Never empty. A standard named twice is checked once (see [Inputs of a run](#inputs-of-a-run)). |

`validate` always writes `as_of` and `subject`. The library's
`generate_compliance_json` leaves both out, since it is not given the SBOM;
`generate_compliance_json_at` adds them.

### Subject

| Field | Type | Meaning |
|---|---|---|
| `sha256` | string | Lowercase hex SHA-256 of the bytes read. |
| `format` | string | `CycloneDX` or `SPDX`. |
| `spec_version` | string | The specification version the document declares: `1.6`, `2.3`, `3.0.1`. |
| `file_name` | string | The SBOM file's name, without its directory, so the output names no local path. Absent for an SBOM read from standard input. |
| `components` | integer | The components the document lists, after the entries of a component listed more than once were merged into one (see [Duplicate components](#duplicate-components)). |
| `duplicates.components` | integer | The components the document lists more than once. |
| `duplicates.entries` | integer | Their entries, before the merge. |
| `duplicates.conflicts` | array | The fields the entries give two different real values, each once, sorted (`description`, `licenses.concluded`). The merged component keeps the value that sorts first. |
| `timestamp_unparsed` | boolean | Whether the creation timestamp is there but is no RFC 3339 date-time (see [Creation timestamps](#creation-timestamps)). |

The subject says how the document was read for every standard. Only the
generic standards report a duplicate component as a finding, and only the
timestamp checks quote an unparseable timestamp, so without it the other
standards' results would not say either.

## Results

| Field | Type | Meaning |
|---|---|---|
| `standard` | string | Canonical `--standard` value: `ntia`, `fda`, `cra`, `cra-phase1`, `ssdf`, `eo14028`, `cnsa2`, `pqc`, `bsi`, `oss-steward`, `eucc`, `ai-act`, `bsi-ai`, `cisa-2026`, `pci-dss`, `fsct`. An alias on the command line (`nist-ssdf`, `cra-2026`, …) still reports the canonical value. |
| `name` | string | Display name, e.g. `NTIA Minimum Elements`. |
| `applicable` | boolean | Whether the standard evaluated the SBOM. The AI readiness profiles (`ai-act`, `bsi-ai`) do not apply to an SBOM without ML components. |
| `not_applicable_reason` | string | Present exactly when `applicable` is `false`. |
| `compliant` | boolean | No error-severity violation. Stays `true` for a standard that did not apply, so read `applicable` first: N/A is not a pass. |
| `score` | integer or null | 0–100: 50–100 when `compliant`, 0–49 when not (see [Score](#score)). `null` exactly when `applicable` is `false`. |
| `score_basis` | object | `checked` and `failed`, the numbers `score` is computed from (see [Score](#score)). Present exactly when `applicable` is `true`. |
| `counts` | object | `error`, `warning` and `info`: the number of violations of each severity. `passed`: the number of passed checks, which no severity count includes. `suppressed`: the findings the run's [rule settings](#rule-settings) turned off, which no other count includes; absent when none. |
| `violations` | array | The findings, described below. |
| `passed` | array | The checks the SBOM passed, described [below](#passed-checks). Always present; empty when the standard passed no check or did not apply. |
| `evaluated` | array | The checks of the standard that did not run on this SBOM, each `{rule_id, status, reason}`, described [below](#checks-not-evaluated). Absent when every check ran. |
| `suppressed` | array | The rules whose findings the [rule settings](#rule-settings) turned off, by rule id: `{rule_id, findings, source}`, where `source` is `config` or `cli`. Absent when no finding was turned off. |
| `excluded_components` | integer | The components the package rules left out because their scope is excluded (see [Components whose scope is excluded](#components-whose-scope-is-excluded)). Absent when none, under `--include-excluded-scope`, and for a standard without package rules. |
| `conformity_summary` | object | CRA Annex VIII checklist (`product_class`, `route`, `evidence[]` of `{label, detail, satisfied}`). Present for `cra` and `cra-phase1` once a product class is pinned by `--cra-product-class` or the sidecar. Never for `oss-steward`: an open-source steward (Art. 24) follows no conformity-assessment procedure. |

A standard that does not apply reports no violation: its verdict is
`applicable: false` with the reason.

## Inputs of a run

These inputs besides the SBOM can change a verdict. Every command that checks
compliance (`validate`, `quality`, `view` and `diff` with their TUIs,
`cra-docs`, and `timeline` for its compliance trend) takes them the same way
and hands each standard only the ones it reads, so the same SBOM with the
same inputs gets the same verdict everywhere. `diff-multi` and `matrix` check
no compliance, so they take none of them.

| Input | Flag | Standards that read it |
|---|---|---|
| Evaluation clock | `--as-of`, else the wall clock | Every standard. |
| CRA sidecar | `--cra-sidecar`, else `<sbom>.cra.{json,yaml}` found next to the SBOM (`diff`: next to each SBOM) | `cra`, `cra-phase1`, `oss-steward`, `eucc`, `ai-act`. A sidecar is used without being asked for, so the other standards, which judge the SBOM alone, never read it. |
| CRA product class | `--cra-product-class`; the sidecar's `productClass` wins | `cra`, `cra-phase1`. The class picks the manufacturer's conformity-assessment procedure, which `oss-steward` does not follow. |
| PQC mode | `--pqc-mode`: `readiness` (the default) or `deadline` | `cnsa2`, `pqc` (and the NIST PQC check of `quality --profile cbom`). See [PQC deadline mode](#pqc-deadline-mode). |
| PQC deadline profile | `--pqc-profile`, with `--pqc-mode deadline`: `nist` (the default) or `federal` | `pqc`. |
| CNSA 2.0 equipment category | `--cnsa-category`, with `--pqc-mode deadline`; the strictest when unset | `cnsa2`. |
| Rule settings | `--rule RULE=SETTING`, over the config file's `compliance.rules` | Every standard whose checks report the rule. See [Rule settings](#rule-settings). |
| Components whose scope is excluded | Left out of the package rules unless `--include-excluded-scope` | Every standard with package rules: all but `cnsa2`, `pqc`, `eucc`, `ai-act` and `bsi-ai`. See [Components whose scope is excluded](#components-whose-scope-is-excluded). |

The config file's `compliance` section holds defaults for these flags:
`cra_product_class`, `pqc_mode`, `pqc_profile`, `cnsa_category`, `rules`
and `include_excluded_scope` (and `cra_sidecar` for the commands that judge
one SBOM). A flag wins over its key. As on the command line, `pqc_profile`
and `cnsa_category` need `pqc_mode: deadline`; a run that `--pqc-mode
readiness` puts in readiness mode ignores them.

A standard named twice is checked once, at its first position, with a
warning on stderr: `--standard cra,cra-phase2` names CRA Phase 2 twice
(`cra-phase2` is an alias of `cra`), and checking it twice would report
every finding twice, in SARIF as a second alert.

## Score

`score` sums a result up on a 0–100 scale. A compliant result (no error)
scores 50–100 and a non-compliant one 0–49, so every compliant result
outscores every non-compliant one:

```text
score = (compliant ? 50 : 0) + floor(50 × checked / (checked + failed))
```

`checked` and `failed` are the result's `score_basis`:

- `checked` counts the elements the standard checked: the document itself,
  plus each component in the standard's scope. `cnsa2` and `pqc` check the
  cryptographic assets, `ai-act` and `bsi-ai` the ML models and datasets (and
  the components that look like ML models), and `eucc` only the document.
  Every other standard checks the package-scoped components: all components
  but files, cryptographic assets and services, less the ones it left out
  for their excluded scope (see
  [Components whose scope is excluded](#components-whose-scope-is-excluded)).
- `failed` counts the checks the errors and warnings failed, at the
  severities the run's [rule settings](#rule-settings) set. A finding about
  one subject, the document or one component, failed one check. An aggregate
  finding (one with `counts`) failed one check per item it reports as
  failing, and at least one: `counts.affected`, or `counts.total -
  counts.affected` for the three coverage findings whose `affected` counts
  the items that pass (`SBOM-CRA-PRE-7-RQ-07-RE`,
  `SBOM-FSCT-LICENSE-COVERAGE` and `SBOM-FSCT-COPYRIGHT-COVERAGE`).

Info findings fail no check, and passed checks are not counted, so neither
moves the score. Under `--pqc-mode deadline` a finding that is still Info
before its deadline lowers the score only once its severity rises (see
[PQC deadline mode](#pqc-deadline-mode)). With no failed check the score is
100. Each failed check
lowers it in proportion to the elements checked: one failed check per
element halves the band (75, or 25 with an error), and the score never
leaves its band. An extra error or warning never raises the score. In a
large SBOM one warning costs one point, and one error drops the score just
below 50.

For an SBOM of three components (`checked` is 4: the document and the three
components):

| Findings | `compliant` | `failed` | `score` |
|---|---|---|---|
| None | `true` | 0 | 50 + 50 = 100 |
| One warning | `true` | 1 | 50 + floor(200 / 5) = 90 |
| Three warnings | `true` | 3 | 50 + floor(200 / 7) = 78 |
| One error | `false` | 1 | floor(200 / 5) = 40 |
| One error, two warnings | `false` | 3 | floor(200 / 7) = 28 |
| One aggregate error with `counts` 2/3 | `false` | 2 | floor(200 / 6) = 33 |

For an SBOM of 500,000 components (`checked` is 500,001):

| Findings | `failed` | `score` |
|---|---|---|
| One warning | 1 | 50 + floor(25,000,050 / 500,002) = 99 |
| One error | 1 | floor(25,000,050 / 500,002) = 49 |
| One error on every component | 500,000 | floor(25,000,050 / 1,000,001) = 24 |

Every output shows this score: `-o json`, `--summary`, the SARIF
`overallScore`, the OSCAL `score` property, the Markdown and HTML reports and
the TUI. `score_basis` is in `-o json` only. The library computes the score
with `sbom_tools::quality::compliance_score` (and
`ComplianceResult::score`).

Releases before v0.4.0 scored `100 / (errors + warnings + 1)`: one error
scored 50, as high as a compliant result, while three warnings scored 25,
and a single finding halved the score of any SBOM, however large.

## Violations

Each violation carries the same fields as in the v1 layout, plus its finding
identity.

| Field | Type | Meaning |
|---|---|---|
| `finding_id` | string | Opaque, stable id of the finding (see [Finding identity](#finding-identity)). |
| `finding_key` | string | `<standard>\|<rule_id>\|<subject>`, or `<standard>\|<rule_id>:<finding_detail>\|<subject>`: the readable form of the id. |
| `severity` | string | `Error`, `Warning` or `Info`: the severity the verdict, the counts, the score and the exit code read. When the run's [rule settings](#rule-settings) set the rule, the one they set. |
| `default_severity` | string | When the rule settings set the finding's rule: the severity the check gave it (the rule's registry default, or the one the check calibrated by product class, CRA phase or PQC deadline). Present exactly when `severity_source` is. |
| `severity_source` | string | Where the setting comes from: `config` (the config file's `compliance.rules`) or `cli` (`--rule`). Present exactly when `default_severity` is. |
| `category` | string | e.g. `DocumentMetadata`, `ComponentIdentification`, `SupplierInfo`. |
| `message` | string | Human-readable explanation. Its wording may change in any release. |
| `element` | string or null | Human-readable label of the offending element (usually a component name). Not unique. |
| `component_id` | string | Canonical id of the offending component. Absent for document-level and aggregate findings. |
| `finding_detail` | string | What tells this finding apart from the rule's other findings on the same subject: a value from the SBOM, such as the vulnerability id or the cipher suite (see [Uniqueness](#finding-identity)). Absent when the rule reports at most one finding per subject. |
| `counts` | object | `affected` and `total` components of an aggregate finding. Absent otherwise. |
| `deadline` | string | `YYYY-MM-DD`. Under `--pqc-mode deadline`, the migration milestone a `cnsa2` or `pqc` finding is judged against: the last day before its severity rises, or, for an error, the last day the algorithm was allowed (see [PQC deadline mode](#pqc-deadline-mode)). Absent in readiness mode and for a finding no schedule dates. |
| `deadline_source` | string | The schedule that sets `deadline`, e.g. `NIST IR 8547 Table 4`. Present exactly when `deadline` is. |
| `field` | string | Where the field the rule checks lives in the SBOM's own format, e.g. `components[].supplier.name`. Absent when the rule names no field in that format. See [Field and observed value](#field-and-observed-value). |
| `observed` | string | The value the check read there, e.g. `NOASSERTION`. Absent when the field is missing or the check reads no single value. See [Field and observed value](#field-and-observed-value). |
| `requirement` | string | The requirement, as text. |
| `rule_id` | string | Stable internal rule key, e.g. `SBOM-NTIA-SUPPLIER`. Every standard reports under its own family's ids (`SBOM-NTIA-*` for `ntia`, `SBOM-FDA-*` for `fda`, and the `SBOM-QUALITY-*` rules of the `quality` profiles). Until v0.4.0 the Standard and Comprehensive quality profiles reported their version, timestamp, supplier and dependency checks as `SBOM-NTIA-*`, FDA its timestamp as `SBOM-NTIA-TIMESTAMP`, and `SBOM-FDA-SUPPLIER` named both the device manufacturer and the component supplier (the manufacturer is `SBOM-FDA-MANUFACTURER` now). |
| `sarif_rule_id` | string | The rule id `-o sarif` reports for this violation. Every check is its own SARIF rule, so this equals `rule_id` (until v0.4.0 several `rule_id`s shared one). |
| `standard_refs` | array | `{standard, id, help_uri?}` references to the clauses the rule implements. Absent when empty. |
| `remediation` | string | How to fix the violation, phrased for the SBOM's format: the rule's guidance and, where the fix goes in a field, that field. |
| `help_uri` | string | The rule's documentation link: the URL of the first reference that has one, else the page of the rule's standard, as `sbom-tools rules` gives it. Until v0.4.0 a rule whose references have no URL (prEN 40000-1-3 alone, or none, as for the quality profiles' rules) had none. |

## PQC deadline mode

`cnsa2` and `pqc` judge quantum-vulnerable cryptography in one of two modes,
set with `--pqc-mode`:

- `readiness` (the default) is today's strict view: every quantum-vulnerable
  algorithm is an error, whatever the date.
- `deadline` judges each finding by its migration schedule at `--as-of` (or
  today) and records the deadline on it. The severity rises as the
  milestones pass.

```sh
sbom-tools validate cbom.json --standard pqc --pqc-mode deadline --as-of 2031-06-01 -o json |
  jq -c '.results[].violations[] | {rule_id, severity, deadline, deadline_source}'
```

Under `pqc`, NIST IR 8547 (final, October 2026) sets the schedule:

| Finding | Until | Then | After |
|---|---|---|---|
| A quantum-vulnerable scheme of Table 2 or 4 (ECDSA, EdDSA, RSA, finite-field and elliptic-curve DH and MQV) at 112 bits of classical security or more, or of unknown strength (`SBOM-PQC-001`, `-CERT-001`, `-PROTO-002`) | Info through 2030 (deprecated after 2030) | Warning through 2035 (disallowed after 2035) | Error from 2036 |
| SHA-1 outside a signature (`SBOM-PQC-005`, `-PROTO-002`; Table 8, note 4) | Warning through 2030 (deprecated now) | Error from 2031 | |
| A symmetric key of 112 to 127 bits (`SBOM-PQC-KEY-001`; §4.1.3) | Info through 2030 | Error from 2031 | |
| A hash function at 112 bits of collision strength: SHA-224, SHA-512/224 or SHA3-224 (`SBOM-PQC-HASH-001`; Table 8, §4.1.3) | Info through 2030 | Error from 2031 | |
| A quantum-vulnerable signature computed over such a digest, such as `SHA224withRSA` or `ecdsa-with-SHA224` (`SBOM-PQC-001`, `-CERT-001`, `-PROTO-002`; Table 8, §4.1.3) | Info through 2030 | Error from 2031 | |
| A SHA-2 hash that states no digest size, which could be SHA-224 (`SBOM-PQC-HASH-001`) | Warning at any date, with the deadline 2030-12-31 | | |

In readiness mode `SBOM-PQC-HASH-001` is an error, as a 112-bit key is.
It reads the hash algorithm assets of a CBOM, by family and parameter
set, OID or name. A SHA-2 asset that states no digest size could be
SHA-224, so it gets a warning in both modes. A keyed use is not judged:
HMAC, HKDF or PBKDF2 built on one of these hashes, or an asset declared a
MAC, KDF or DRBG. The 112 bits of Table 8 are collision strength, which
those uses do not rely on. The hash values that identify a component are
not cryptographic assets, so no PQC rule reads them.

A signature relies on the collision resistance of its digest. So in
deadline mode a quantum-vulnerable signature over one of these digests
takes the digest's deadline, 2030-12-31, which is never later than its
scheme's under either profile, at the more severe of the two severities.
It keeps the rule of its scheme, so it is still one finding. Its message
names the digest, and its `deadline_source` is the digest's schedule,
`NIST IR 8547 §4.1.3 and Table 8`. The digest is read from the name
(`SHA224withRSA`, `ecdsa-with-SHA224`), the family string or the
signature OID (`sha224WithRSAEncryption`). Key establishment keeps its
scheme's schedule, and readiness mode is unchanged: the scheme is an
error already.

`--pqc-profile federal` applies the deadlines of federal high value assets
and high impact systems instead (EO 14412 §4(b), OMB M-26-15): post-quantum
key establishment by 2030-12-31 and post-quantum signatures by 2031-12-31,
each a warning until its deadline and an error after. When the SBOM does
not say whether an algorithm signs or establishes keys (RSA without a
`primitive`), the earlier deadline applies. The profile also reports TLS 1.2
under `SBOM-PQC-PROTO-003`, since agencies support TLS 1.3 by 2030-01-02
(EO 14306, OMB M-26-15): a warning until then, an error after. The default
profile, `nist`, sets no TLS deadline.

Under `cnsa2`, NSA's CNSA 2.0 timeline sets the schedule for what CNSA 1.0
still allows: ECDH or ECDSA over P-384, RSA or DH of 3072 bits or more, and
TLS 1.2 (`SBOM-CNSA2-ALG-006`, `-CERT-001`, `-PROTO-001`, `-PROTO-002`).
Such a finding is info until its equipment category is to support and
prefer CNSA 2.0, a warning until the category is to use CNSA 2.0
exclusively, and an error after. `--cnsa-category` picks the category;
without it the strictest applies, software and firmware signing:

| `--cnsa-category` | Supported and preferred by | Exclusive use by |
|---|---|---|
| `software-signing` (the default timeline) | 2025 | 2030 |
| `web-cloud` (web browsers, servers and cloud services) | 2025 | 2033 |
| `networking` (traditional networking equipment, such as VPNs and routers) | 2026 | 2030 |
| `operating-systems` | 2027 | 2033 |
| `niche` (constrained devices, large PKI systems) | 2030 | 2033 |
| `custom-legacy` (custom applications and legacy equipment) | — (warning until updated or replaced) | 2033 |

A year is read as its last day: "by 2030" and "after 2030" both turn on
2030-12-31. A certificate is judged on the later of the evaluation date and
its `notValidAfter`, since it keeps its signature until it expires.

A finding no schedule dates keeps its readiness severity, carries no
deadline, and says why in its message: an algorithm already disallowed with
no transition (MD5, DES, RSA below 2048 bits, SHA-1 signatures), one IR 8547
does not list (DSA, SM2), one that is not CNSA 1.0 either, ECB mode, and
every finding about evidence the checks cannot read (an unidentified
algorithm, a missing `nistQuantumSecurityLevel`, an empty inventory).
`--pqc-profile` and `--cnsa-category` need `--pqc-mode deadline`; without
it either is a usage error (exit `3`). Like the other
[inputs of a run](#inputs-of-a-run), the three flags are taken by every
command that checks compliance: `quality --profile cbom` applies the mode
and the profile to its embedded NIST PQC check, and the compliance tabs of
`view` and `diff` show the verdicts `validate` reports for them. `cra-docs`
takes them too, though its CRA check reads none.

## Rule settings

A rule setting gives one rule's findings another severity for a run, or
turns the rule off: `--rule RULE=SETTING`, repeatable, where `SETTING` is
`off`, `info`, `warning` or `error`. `sbom-tools rules` lists the rule ids;
an id is read in any case.

```sh
sbom-tools validate sbom.json --standard ntia,cra \
  --rule SBOM-NTIA-SUPPLIER=warning --rule SBOM-CRA-ART-13-15-PRODUCT=off -o json |
  jq -c '.results[] | {standard, compliant, counts, suppressed}'
```

The config file sets them for every run under `compliance.rules`:

```yaml
compliance:
  rules:
    SBOM-NTIA-SUPPLIER: warning
    SBOM-CRA-ART-13-15-PRODUCT: off
```

- **Effective severities.** The settings are applied after the checks, so
  the verdict (`compliant`), the counts, the score and the exit code follow
  the severities they set. A supplier error made a warning no longer makes
  the SBOM non-compliant; a warning made an error does.
- **Nothing hidden.** Each finding of a set rule keeps the severity its
  check gave it in `default_severity`, with `severity_source`. The findings
  of a rule that is `off` leave `violations`, and each result counts them
  per rule under `suppressed` and in `counts.suppressed`, next to the
  checks that did not run, which `evaluated` lists (see
  [Checks not evaluated](#checks-not-evaluated)). The text report adds a
  `severity:` line to each such finding and a `Suppressed by settings:`
  section after `Not evaluated:`; SARIF and OSCAL carry the same data (see
  [Fields in every output](#fields-in-every-output)). An overridden finding
  keeps its `field` and `observed`.
- **Precedence.** A `--rule` flag wins over the config file for its own
  rule; the file's other settings stay. Setting a rule twice on the command
  line keeps the last.
- **Scope.** A setting reaches every standard whose checks report its
  rule. Each standard reports the rules of its own family, so
  `SBOM-CRA-COMPONENT-VERSION`, for one, reaches `cra-phase1`, `cra` and
  `oss-steward`, while `ntia` (`SBOM-NTIA-VERSION`) and the quality
  profiles (`SBOM-QUALITY-VERSION`) have version rules of their own. Every
  command that checks compliance applies the settings, the TUIs included.
- **Errors and warnings.** An unknown rule id or setting is a usage error
  (exit `3`), on the command line and in the config file, and the message
  names the closest rule id. So is a pass-only rule such as `SBOM-PQC-009`,
  whose passed checks have no severity. A setting that no selected standard
  reports, such as `SBOM-CRA-ART-24` in an `ntia` run, changes nothing, and
  the run warns about it on stderr.

`validate --fail-on RULE` (repeatable; config key `compliance.fail_on`)
fails the run with exit `1` when it reports any finding of the rule,
whatever its severity, info included. It reads the effective severities and
the findings that remain: a rule that is `off` reports none, so it can
never trip, and the run warns about that, as about a `--fail-on` rule no
selected standard reports. It ranks with the error gate: a run with a
`--fail-on` finding exits `1` even under `--fail-on-warning`, whose `2` is
for the other warnings.

## Components whose scope is excluded

CycloneDX marks a component the product does not need at runtime, such as
a test or development dependency, with `scope: excluded`. SPDX says it on
the relationships instead: SPDX 2.3 `DEV_DEPENDENCY_OF`,
`BUILD_DEPENDENCY_OF`, `TEST_DEPENDENCY_OF` and the `*_TOOL_OF` types, and
SPDX 3.0 `LifecycleScopedRelationship`s of scope `design`, `development`,
`build` or `test`. An SPDX component counts as excluded when only such
relationships bring it in, directly or through other such components; one
the product also depends on at runtime does not.

The package rules of every standard leave these components out: version,
supplier, license, hash, identifier and dependency-graph membership, and
the inventory and coverage counts built on them. Each result says how many
it left out in `excluded_components`, and the text report in an `Excluded:`
line. `--include-excluded-scope` (config key
`compliance.include_excluded_scope`) judges them like any other component.
The rules that cover every component, such as the component name, and the
crypto, EUCC and AI profiles, which have no package rules, judge them
either way. The primary component is never left out. The compliance score
leaves them out too, but the quality score of `sbom-tools quality` keeps
counting them: it measures the document's data, and every component is in
the document.

## Passed checks

Some rules affirm what the SBOM gets right rather than report a gap: under
`pqc`, `SBOM-PQC-009` (an algorithm NIST approves for post-quantum use) and
`SBOM-PQC-010` (a PQ/T hybrid whose post-quantum part NIST approves). These
pass-only rules report into `passed`, never into `violations`: a pass has no
severity and counts toward neither `counts.info` nor the score. `-o sarif`
reports no pass, so code scanning raises no alert for one;
`--sarif-include-passes` adds each as a SARIF result of `kind: "pass"` at
level `none`, under the rule's `sarif_rule_id`, with the location,
fingerprints and finding identity of a violation's result (see
[SARIF](#sarif)). Each entry carries a violation's identifying and
descriptive fields (not `severity`, `category`, `counts`, `remediation` or
`help_uri`), plus its finding identity:

| Field | Type | Meaning |
|---|---|---|
| `finding_id` | string | As a violation's; see [Finding identity](#finding-identity). |
| `finding_key` | string | As a violation's: `<standard>\|<rule_id>\|<subject>`, with an optional `:<finding_detail>`. |
| `message` | string | What passed, e.g. `'ML-KEM-1024' uses NIST-approved PQC algorithm (FIPS 203/204/205)`. |
| `element` | string or null | Label of the element the check is about (usually a component name). Not unique. |
| `component_id` | string | Canonical id of the component the check is about. Absent for document-level checks. |
| `finding_detail` | string | What tells this pass apart from the rule's other passes on the same subject. Absent when the rule passes a subject at most once. |
| `requirement` | string | The requirement satisfied, as text. |
| `rule_id` | string | Stable internal key of a pass-only rule. |
| `sarif_rule_id` | string | The rule id `--sarif-include-passes` reports this pass under. |
| `standard_refs` | array | `{standard, id, help_uri?}` references to the clauses the rule implements. Absent when empty. |

## Field and observed value

A violation says where the field it checks lives (`field`) and what the
check read there (`observed`), so a finding about a placeholder shows the
placeholder:

```sh
sbom-tools validate sbom.json --standard ntia -o json |
  jq -c '.results[].violations[] | {rule_id, component_id, field, observed}'
```

```json
{"rule_id":"SBOM-NTIA-SUPPLIER","component_id":"pkg:npm/lib@1.0.0","field":"components[].supplier.name","observed":"NOASSERTION"}
```

`field` is the rule's field for the document's format, as
`sbom-tools rules explain` shows it, in the format's JSON shape (also for
CycloneDX XML): `components[].supplier.name` in CycloneDX,
`packages[].supplier` in SPDX 2.x, `suppliedBy` in SPDX 3.0. A finding about
the primary component of a CycloneDX document names the field under
`metadata.component` (`metadata.component.supplier.name`). A rule whose fix
is the same in every format, such as an algorithm choice, names no field.
Of the crypto rules, only `SBOM-PQC-HASH-001` names one, the digest size it
reads: `components[].cryptoProperties.algorithmProperties.parameterSetIdentifier`.

`observed` is set by the checks that read one value:

| Checks | `observed` |
|---|---|
| Supplier, producer, author | The value the component or document names, when it does not count (`NOASSERTION`, `TBD`). |
| Component name, version | The placeholder or empty value read. |
| Hash | The first digest that does not count, as `<algorithm>:<value>` (`SHA-256:abc`). The message says why it does not count. |
| Hash algorithm | The algorithms that fall short (`MD5, SHA-1`). |
| Spec version, format | The version read (`1.3`), or the format and version (`CycloneDX 1.3`). |
| Element identifier | The `bom-ref`, `SPDXID` or `spdxId` read. |
| Timestamp | The creation timestamp as written, when it does not parse; for freshness, the timestamp of an SBOM dated in the future or too old. |
| Contact | The manufacturer email that is no address, or the first contact that reaches nobody (a placeholder, or an address at a documentation domain such as `example.com`). |
| License | The first license that is no SPDX expression (`bsi`). |
| Placeholders (`fsct`) | The first ambiguous placeholder (`TBD`, `N/A`) in a version, supplier, license or copyright. |
| `cnsa2`, `pqc` | The algorithm the check rejected (`RSA-2048`), the protocol and version (`tls 1.0`), the algorithms a protocol offers, or the reference it cannot resolve. |
| `eucc` | The certificate's valid-until date. |

An observed value is SBOM text. Like `message` and `element`, `-o json` and
the SARIF properties carry it as read, cut to 200 characters and ending in
`…` when cut, so treat it as untrusted text: a script that prints it to a CI
log should neutralize it as sbom-tools does. The OSCAL `observed` property
carries it as OSCAL's string type allows: line breaks become spaces and the
ends are trimmed. The text report and the TUI clean it where they show it,
as the text report cleans the rest of the SBOM's text: a line break shows as
`\n`, other control and bidi characters are removed, and a leading `:` gets
a backslash (`\::warning`), so it can neither break a terminal nor start a
CI workflow command.

## Checks not evaluated

A check that does not run on an SBOM reports nothing, so without more it
reads like a check that passed. `evaluated` lists such checks, with the
reason:

```sh
sbom-tools validate sbom.spdx.json --standard cisa-2026 -o json |
  jq '.results[].evaluated'
```

```json
[
  {
    "rule_id": "SBOM-CISA2026-SIGNATURE",
    "status": "not_evaluated",
    "reason": "SPDX 2.x cannot carry a document signature"
  }
]
```

| Field | Type | Meaning |
|---|---|---|
| `rule_id` | string | The rule of the check: one of the rules `sbom-tools rules --standard` lists for the standard. |
| `status` | string | `not_evaluated`. |
| `reason` | string | Why the check did not run, in sbom-tools' own words. |

A check is listed when it applies to the SBOM but did not run. An entry
reports no violation and no passed check, and moves no count, score or
verdict. These checks are skipped today:

| Standard | Rules | Not evaluated when |
|---|---|---|
| `cisa-2026` | `SBOM-CISA2026-SIGNATURE`, `-GENERATION-CONTEXT`, `-COVERAGE` | The SBOM is SPDX 2.x, which has no field for a signature, the lifecycle phase or a completeness declaration. |
| `fsct` | `SBOM-FSCT-SIGNATURE` | The SBOM is SPDX 2.x, which cannot carry a document signature, as for `cisa-2026`. |
| `fsct` | `SBOM-FSCT-SBOM-TYPE` | The SBOM is SPDX: sbom-tools reads the SBOM type from CycloneDX `metadata.lifecycles` only. |
| `fsct` | `SBOM-FSCT-DYNAMIC-DEPS`, `SBOM-FSCT-LICENSE-CONCLUDED` | The SBOM is CycloneDX: its dependency graph cannot mark a dependency dynamic, runtime or provided, and sbom-tools reads concluded licenses from SPDX only. |
| `cra`, `cra-phase1` | `SBOM-CRA-ANNEX-IV`, `SBOM-CRA-ANNEX-VIII` | No product class is pinned (`--cra-product-class`, or `productClass` in the CRA sidecar). |
| `cra`, `cra-phase1` | The four `SBOM-CRA-PRE-8-RQ-02-*` hardware checks | The SBOM lists no device, firmware or device-driver component. |
| `pqc` | `SBOM-PQC-PROTO-003` | The run is not `--pqc-mode deadline --pqc-profile federal`. |
| `ntia`, `fda`, `cra`, `cra-phase1`, `oss-steward` and the quality profiles | `SBOM-<FAMILY>-SPEC-VERSION` | The spec version does not parse, so its range cannot be checked. |
| `cra`, `cra-phase1`; `cisa-2026`; `eo14028`; `bsi` | `SBOM-CRA-MACHINE-READABLE`; `SBOM-CISA2026-FORMAT`; `SBOM-EO14028-FORMAT`; `SBOM-BSI-TR-03183-2-4` | The spec version does not parse. |

Not listed: a check that ran and found nothing to report, even over no
entries (a vulnerability check of an SBOM without vulnerabilities), and a
check of something the document's format does not have at all (an SPDX
version string or an SPDX 3.0 profile declaration in a CycloneDX document).
A standard that does not apply lists nothing: `not_applicable_reason` says
why. `-o sarif` carries the same list in the run properties (see
[SARIF](#sarif)), `-o oscal-json` in each result's `not-evaluated`
properties (see [OSCAL assessment results](#oscal-assessment-results)), and
the text report lists it after the findings (see [Text report](#text-report)).

`evaluated` and `suppressed` sit side by side and say different things. A
rule in `evaluated` did not run on the SBOM, so nobody knows what it would
have found. A rule in `suppressed` ran and found something, and the run's
[rule settings](#rule-settings) turned its findings off. A suppressed rule
is never listed in `evaluated`.

## Finding identity

The finding key names what a finding is about, not how it is worded:

```text
<standard>|<rule_id>|<subject>
<standard>|<rule_id>:<finding_detail>|<subject>
ntia|SBOM-NTIA-SUPPLIER|pkg:npm/lodash@4.17.21
ntia|SBOM-NTIA-AUTHOR|document
cra|SBOM-CRA-VULN-METADATA:CVE-2024-3094|pkg:generic/xz-utils@5.6.0
```

- `<standard>` is the canonical `--standard` value.
- `<rule_id>` is the violation's `rule_id`. Since v0.4.0 it equals the
  `sarif_rule_id`; before, dozens of rules shared a SARIF id (all ten
  `SBOM-BSIAI-MODEL-*` checks reported as `SBOM-BSIAI-MODEL`), which is why
  the key is built from the `rule_id`.
- `<finding_detail>` is the violation's `finding_detail`, present only for a
  rule that reports several findings on one subject (one per vulnerability of
  a component, one per cipher suite of a protocol). `%`, `|` and `:` in it are
  percent-encoded as `%25`, `%7C` and `%3A`. Without a detail the key has no
  `:` after the rule id.
- `<subject>` is the violation's `component_id` when it has one, otherwise
  `document`. A finding about one dependency edge would use
  `edge:<from>-><to>`; no rule reports a single edge today, so that form is
  reserved. A `component_id` that would read as one of those forms (a
  component whose bom-ref is `document`, say), or that starts with
  `component:`, gets `component:` prepended: `component:document`.

Neither the standard nor a rule id contains `|` or `:`, and the encoded detail
contains neither, so the key splits unambiguously: the standard is everything
before the first `|`, the rule id runs to the next `:` or `|`, the detail (if
any) runs from that `:` to the second `|`, and the subject is everything after
the second `|`. The `finding_id` is `sbomtools:v1:` followed by the first 16
hex digits of the SHA-256 of the key's UTF-8 bytes. The library computes
both, and the full 64-digit hash (`sbom_tools::quality::{finding_key,
finding_id, finding_fingerprint}`), so baselines can use the same identity;
`-o sarif` fingerprints its results with the full hash (see [SARIF](#sarif)).

A passed check is keyed the same way, from its own `rule_id`,
`finding_detail` and `component_id`, and shares the violations' key space: a
rule reports either violations or passed checks, never both, so a pass and a
violation never share a key.

**What keeps the id.** Rewording the message, changing the severity, the
element label, the requirement text, the counts or the standard references, the
order of the findings, and upgrading sbom-tools (unless the release notes say a
rule id or the canonical-id derivation changed). The same SBOM gives the same
ids on every run.

**What changes the id.** For a component finding, the id changes exactly when
the component's canonical id does. The canonical id is the component's purl
(lowercased and normalized), else its first CPE, else its first SWHID, else its
SWID tag, else its format id: the CycloneDX `bom-ref` or the SPDX `SPDXID`
(`spdxId` in SPDX 3), or the component name when the document gives neither.
So adding a purl, changing it (a version bump changes the purl), or renaming
the `bom-ref`, `SPDXID` or name the canonical id fell back to gives the
component's findings new ids. Generators that write random UUIDs as `bom-ref`s
therefore produce new ids on every regeneration for components without a purl,
CPE, SWHID or SWID. When two different components share a canonical id, the
later one in the document is re-keyed by appending `#` and its `bom-ref` or
`SPDXID`, so reordering such components can move that suffix. Entries with
the same canonical id, name and version are one component, merged into one
(see [Duplicate components](#duplicate-components)). A finding with a
`finding_detail` also changes id with its detail, which comes from the SBOM's
own data (a vulnerability id, a cipher suite name), never from the message.

**Uniqueness.** No two findings in one result share a key, so no two share an
id. Each distinct check has a rule id of its own (the four CRA Art. 14
reporting channels are `SBOM-CRA-ART-14-PSIRT`, `-EARLY-WARNING`,
`-NOTIFICATION` and `-ENISA`, for example), so a rule without a
`finding_detail` reports at most one finding per subject. A rule that reports
one finding per item on a subject sets `finding_detail` to the item:

| Rule | One finding per | `finding_detail` |
|---|---|---|
| `SBOM-CRA-VULN-METADATA`, `SBOM-CRA-VULN-METADATA-REMEDIATION` | vulnerability of a component | the vulnerability id |
| `SBOM-CNSA2-PROTO-002`, `SBOM-PQC-PROTO-002` | cipher suite of a protocol, the TLS groups and the signature schemes it offers, plus the protocol's IKEv2 transforms and its crypto references | the suite's name, else its IANA identifiers, else its algorithm refs; that detail plus `/tls-groups` or `/tls-signature-schemes`; `ikev2-transforms`; `crypto-refs` |
| `SBOM-CNSA2-CERT-001`, `SBOM-CNSA2-CERT-UNKNOWN`, `SBOM-PQC-CERT-001`, `SBOM-PQC-CERT-UNKNOWN` | signature-algorithm candidate of a certificate | the candidate's bom-ref |
| `SBOM-CRA-ANNEX-I-CONTROLS` | sidecar control claimed without evidence | the control id |
| `SBOM-CRA-ART-13-16-EMAIL` | invalid manufacturer email | the address |

When the SBOM itself lists an entry twice (two `vulnerabilities[]` entries
with one id for the same component, say), both findings are reported, and the
second one's detail is numbered: `CVE-2024-3094`, then `CVE-2024-3094#2`. In
SPDX 3, an `AFFECTS` relationship and an assessment of the same vulnerability
and component are one entry when they agree (a CVSS score, or an `affected`
VEX statement) and two when they contradict each other (`not_affected`,
`fixed`, `under_investigation`).
Passed checks are numbered the same way. The test suite checks the guarantee,
over a result's violations and passed checks together, on every fixture at
every level.

## How the checks read the SBOM

Three cases used to change a verdict, or hide a problem, without a word.

### Duplicate components

A document can list one component more than once: the same purl under two
`bom-ref`s, or one `bom-ref` twice. Entries with the same canonical id are one
component when their names and versions agree; a name or version that is
absent or not a real value (`NOASSERTION`, `NONE`, `UNKNOWN`, a placeholder
such as `TBD` or `N/A`, or blank) agrees with any. sbom-tools merges them, and
the merged component does not depend on the order of the entries:

- A list field (hashes, licences, external references, identifiers,
  properties, annotations, vulnerabilities) keeps every value of every entry
  once, sorted. A licence that is not a real value is dropped when another
  entry names a real one.
- A single-valued field that one entry leaves empty, or fills with a value
  that is not a real one, takes the other entry's real value. A real
  supplier, author, version, licence or identifier always wins over
  `NOASSERTION`, `NONE`, `TBD` or a blank, and that is no conflict.
- When the entries give a single-valued field two different real values, the
  value that sorts first (by its JSON form) is kept, and the field is
  recorded as a conflict.
- The scope is the one of the entry the product needs most at runtime:
  `required`, then no scope (which CycloneDX reads as `required`), then
  `optional`, then `excluded`. An entry marked `excluded` never hides one
  the product needs, so the merged component stays judged by the package
  rules (see
  [Components whose scope is excluded](#components-whose-scope-is-excluded)).
  Scopes that differ in effect are a conflict.

What counts as a real value is what every check counts as one.

Every check then judges the merged component. Until v0.4.0 the last entry
replaced the others, so a verdict could depend on the order of the entries.
The generic checks report one Info finding per document, under the rule of
the standard's family: `SBOM-QUALITY-DUPLICATE-COMPONENT` (`minimum`,
`standard`, `comprehensive`), `SBOM-NTIA-DUPLICATE-COMPONENT`,
`SBOM-CRA-DUPLICATE-COMPONENT` (`cra-phase1`, `cra`, `oss-steward`) and
`SBOM-FDA-DUPLICATE-COMPONENT`. Its `counts` are the duplicated components and
all components, and its message names up to five of them, with their numbers
of entries, and the fields the entries disagree on:

```text
2/9 components are listed more than once (5 entries), and the entries of each were merged into one: pkg:npm/lodash@4.17.21 (3 entries), ref-libbeta (2 entries); the entries disagree on description, and the value that sorts first is kept
```

`convert --to normalized` lists each one under `duplicate_components`, as
`{canonical_id, entries, format_ids, conflicts}`. Every standard's run says
how many there were: `-o json` in `subject.duplicates`, OSCAL in its SBOM
resource (see [Subject](#subject)).

### Dependency cycles

`SBOM-CRA-CYCLES` counts the cycles of the dependency graph in linear time,
for a graph of any size. Until v0.4.0 it skipped every graph above 1,000,000
edges, which then passed. The graph metrics of the quality score
(`dependency_metrics`) still skip graph analysis above that size.

### Creation timestamps

A creation timestamp that is not an RFC 3339 date-time (CycloneDX
`metadata.timestamp`, SPDX `created`) counts as absent, as before, but every
timestamp check now quotes it: "SBOM has an unparseable creation timestamp
'2026-13-45 noon', not an RFC 3339 date-time" instead of "missing". A value
longer than 64 characters is cut. `convert --to normalized` keeps it as
`document.created_unparsed`, and `-o json` and OSCAL say it for every
standard in `subject.timestamp_unparsed` (see [Subject](#subject)).

## Compatibility

The envelope follows the crate version like every other JSON payload, with two
promises:

- **Additive changes keep the schema id.** Later releases add fields without a
  new `schema` value, and the published schema accepts unknown fields. Ignore
  fields you do not know.
- **A breaking change would get a new schema id** (`sbom-tools/compliance/v3`)
  and a new schema file.

`--json-schema v1` prints the pre-0.4 layout until v0.5.0, and warns on stderr
that it is deprecated: a bare result object for one standard, an array of them
for several, each with `is_compliant`, `level` (e.g. `NtiaMinimum`),
`error_count`/`warning_count`/`info_count`, `applicability`, `violations`
(without `finding_id`/`finding_key`), and `conformity_summary`, the
[checks not evaluated](#checks-not-evaluated) (`evaluated`), the rules the
[rule settings](#rule-settings) turned off (`suppressed`) and
`excluded_components` when present.
The v1 layout keeps that shape and predates passed checks, so they do not
appear in it at all: before v0.4.0 they were Info violations
(`SBOM-PQC-009`, `SBOM-PQC-010`), and a v1 consumer now sees fewer Info
violations and a lower `info_count`. The not-applicable markers
`SBOM-AIACT-NA` and `SBOM-BSIAI-NA` are gone from v1 `violations` too:
`applicability` carries that verdict, as it already did. To migrate:

| v1 | v2 |
|---|---|
| object or array | always `results[]` |
| `level` | `standard` (`ntia`) and `name` (`NTIA Minimum Elements`) |
| `is_compliant` | `compliant` |
| `error_count`, `warning_count`, `info_count` | `counts.error`, `counts.warning`, `counts.info` |
| `applicability.status`, `applicability.reason` | `applicable`, `not_applicable_reason` |
| — | `score`, `score_basis` |
| — (Info violations before v0.4.0) | `passed[]`, `counts.passed` |
| — | `as_of`, `subject` |

`--summary` is a separate compact format (the verdict and counts per standard,
with `standard` holding the display name) and keeps its shape. Its `info`
count, like `counts.info`, counts Info violations only, so passed checks are
not in it. It adds `suppressed` and `excluded_components` only when they are
not zero.

## OSCAL assessment results

`sbom-tools validate -o oscal-json` prints an
[OSCAL 1.2.3](https://github.com/usnistgov/OSCAL/releases/tag/v1.2.3)
`assessment-results` document. The test suite validates the output for every
fixture and standard against that release's JSON schema, vendored under
`tests/fixtures/schemas/oscal/1.2.3/`.

```sh
sbom-tools validate sbom.json --standard ntia -o oscal-json --as-of 2026-10-12T00:00:00Z |
  jq '."assessment-results".results[0].observations[0].subjects'
```

| Where | What |
|---|---|
| `metadata.oscal-version` | `1.2.3`. |
| `metadata.last-modified`, `results[].start`, `observations[].collected` | The instant every standard was judged at: `as_of` in `-o json`. |
| `results[]` | One per checked standard, in `--standard` order. Its `props` carry the verdict: `standard` (the canonical `--standard` value, as in `-o json`), `standard-name`, `is-compliant`, `applicability`, `error-count`, `warning-count`, `info-count`, `passed-count`, `not-applicable-reason` when the standard did not apply, `score` (see [Score](#score)), `suppressed-count` and `excluded-components` when they are not zero, one `not-evaluated` per [check not evaluated](#checks-not-evaluated) (the rule, with the reason as `remarks`), three properties per rule the [rule settings](#rule-settings) turned off (`suppressed-rule`, `suppressed-findings` and `suppressed-source`, sharing a `group`), and the CRA conformity summary: `conformity-product-class`, `conformity-route`, and one `conformity-evidence` per checklist row (the label, `class` `satisfied` or `not-satisfied`, the detail as `remarks`). |
| `results[].findings[]` | A roll-up finding for the standard (`satisfied` when compliant), targeting the objective `<standard>-compliance` (`ntia-compliance`), then one `not-satisfied` finding per violation, then one `satisfied` finding per [passed check](#passed-checks), each targeting the objective named by the lowercased rule id. A standard that did not apply gets no roll-up and no finding. Each finding but the roll-up carries `finding-id` and `finding-key`; a violation's also the link to its rule's documentation (`rel: help`) and its remediation as `remarks`. |
| `results[].observations[]` | One per violation, the evidence its finding relates to, typed `discovery`; then one per passed check, typed `control-objective`. Its properties are the finding's other audit fields (see [Fields in every output](#fields-in-every-output)): `severity` (lowercase), `default-severity` and `severity-source` when a rule setting set the rule, `requirement`, `rule-id`, `sarif-rule-id`, `sbom-element` when the SBOM gives a label, `component-id`, `affected` and `total`, `deadline` and `deadline-source`, `field`, `observed`, and one `standard-ref` per standard reference (`class` the standard, as `-o json` names it, `value` the clause), with a link (`rel: reference`) for each reference that has a URL. A passed check has no severity, counts, deadline, field or observed value. |
| `results[].observations[].subjects[]` | The SBOM document (`type: resource`), then, for a finding about a component, the component (`type: component`). |
| `results[].local-definitions.components[]` | The components the result's observations name, titled by name and version, with OSCAL's `version` property, `component-id` (the canonical id: `component_id` in `-o json`) and `component-type` (the SBOM's own type). |
| `back-matter.resources[0]` | The SBOM document: `type` `artifact`, the [subject](#subject) of `-o json` (`sha256` of the SBOM bytes as read, `format`, `spec-version`, `file-name`, `component-count`, `duplicate-components`, `duplicate-entries`, one `duplicate-conflict` per field, `timestamp-unparsed`), and the serial number (CycloneDX) or document namespace (SPDX) in `document-ids`. When that id is a URI (`urn:uuid:…`, `https://…`), it is also the resource's `rlinks[0].href`, with the SHA-256 in `hashes`. |

Properties without an `ns` are OSCAL's own; every other one has the namespace
`https://sbom.tools/ns/oscal`.

Titles, descriptions and remarks are OSCAL markup, Markdown that OSCAL
viewers render. Those that carry SBOM text (component and document titles,
and the violation messages, which embed component names and SBOM values) are
Markdown-escaped (`\_`, `\[`, `\<`, a leading `\-`, …), so a crafted value
renders as literal text and never as a link, image, HTML tag, or a heading or
list item of its own. Render the field as Markdown, or drop the backslash
escapes, to read the plain text. Property values are plain strings and are
not escaped; `sbom-element`, `version` and `component-id` carry the same SBOM
values unescaped.

SBOM text has its line breaks replaced by spaces and its leading and trailing
whitespace trimmed, as OSCAL's string types require, and a property left
with no text is omitted, as is a link whose target is no absolute URI.

Every UUID is a UUIDv5. The document, its results, observations and findings
derive from the SHA-256 of the SBOM, the evaluation instant (`--as-of`, else
the current time), the standards checked (their canonical `--standard`
values) and their position, so a run with `--as-of` prints the same bytes
every time. The SBOM document and its components derive from the SHA-256 of
the SBOM and the subject alone (for a component, its canonical id), so a
subject keeps its UUID across instants, standard sets and results.

### Upgrading from OSCAL 1.1.2

Releases before v0.4.0 emitted OSCAL 1.1.2. Consumers of `-o oscal-json`
should note:

- `metadata.oscal-version` is `1.2.3`. Validate against the 1.2.3 schema.
- Observations are typed `discovery`, not `finding`: OSCAL 1.2.0 deprecated
  `finding` and named `discovery` its replacement. A filter on `types`
  containing `finding` must look for `discovery`.
- Observations gain `subjects`, results gain `local-definitions`, and the
  document gains `back-matter`.
- A check the SBOM passed (an approved post-quantum algorithm under `pqc`)
  used to be an Info violation, and so a `not-satisfied` finding. It is now a
  `satisfied` finding over a `control-objective` observation, and results
  count such checks in the `passed-count` property.
- Titles and descriptions that carry SBOM text are Markdown-escaped, as
  described above. A consumer that read a description as plain text now sees
  backslash escapes (`\[CISA 2026\]`, `TLS\_AES\_256\_GCM\_SHA384`): render it
  as Markdown, or read the plain values from the properties.
- A property that would have no text is omitted instead of carrying an empty
  or whitespace value, and SBOM text in property values is normalized as
  described above. Either used to make the document invalid OSCAL.
- The SBOM document resource has an `rlink` (its serial number or namespace,
  with the SHA-256) when that id is a URI.
- UUIDs and timestamps are reproducible, as described above; earlier
  releases drew random UUIDs and stamped the wall clock.
- A result's `standard` property is the canonical `--standard` value
  (`ntia`, `cra`), as in `-o json` and SARIF, not the level's name
  (`NtiaMinimum`, `CraPhase2`), and the roll-up finding's objective follows
  it: `cra-compliance`, not `craphase2-compliance`.
- The observation property that held the requirement text,
  `standard-reference`, is `requirement`, as in `-o json`. The standard
  references themselves are the new `standard-ref` properties.
- Findings carry `finding-id` and `finding-key`, the identity `-o json` and
  SARIF give them, with the remediation as `remarks` and a link to the
  rule's documentation; observations gain the rest of the
  [fields every output carries](#fields-in-every-output). Results gain the
  checks not evaluated, the rules turned off and the CRA conformity summary,
  and the SBOM resource the rest of the `-o json` subject.

## SARIF

`sbom-tools validate -o sarif` prints a
[SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html)
log with one run for all the standards checked. The test suite validates the
output for every fixture and standard against the OASIS schema, vendored
under `tests/fixtures/schemas/sarif/2.1.0/`. `diff`, `view` and `quality`
write the same shape; their results that are not compliance findings have
finding keys of their own, scoped `diff`, `view`, `quality` or
`ai-readiness` in place of a standard.

| Where | What |
|---|---|
| `runs[0].invocations[0]` | Present only when the run was capped (see below): `executionSuccessful: true` and one `toolExecutionNotifications` warning saying how many results were omitted. |
| `runs[0].automationDetails.id` | The analysis category, ending in `/`: `sbom-tools/` and the canonical `--standard` values, sorted and joined by `+` (`sbom-tools/cra+ntia/`), or the value of `--sarif-category`. GitHub code scanning keeps one set of alerts per category. |
| `runs[0].originalUriBaseIds.SRCROOT` | Declared when the SBOM's URI is relative, which is the default: relative to the repository the SBOM file is in, or to `--sarif-base`. It carries a description only, no absolute URI, so the log names no path on the machine that wrote it. |
| `runs[0].tool.driver.rules[]` | Exactly the rules of the standards checked: the rules each standard's checks can report, one per check and each once, in `--standard` order and in the order of each standard's list. `sbom-tools rules --standard <std>` prints the same list (see [Rule catalogue](#rule-catalogue)). `diff` and `view` check the SBOM against CRA Phase 2, so they list its rules after their own; `quality` lists the rules of its profile's standard, then the `SBOM-QUALITY-REC-*` rules of the recommendations it reports. `id` is the `rule_id`. Each has `shortDescription`, `fullDescription` (with the standard references), `defaultConfiguration.level`, `help.text` and `help.markdown` (the remediation, where the fix goes in each SBOM format, the references) and, where one is known, `helpUri`: the first reference with a URL, else the standard's own page. A `SBOM-<FAMILY>-GENERAL` fallback rule is listed only in a run that has a finding without a registered rule. |
| `runs[0].properties` | The verdict of each standard: for one standard, the run's own properties; for several, `applicable` (whether any standard applied) and `standards[]`, one verdict each. A verdict has `standard` (the canonical `--standard` value, as in `-o json`), `profile` (the display name, `name` in `-o json`), `compliant`, `applicable` (with `notApplicableReason` when it is false), `overallScore` (the [score](#score); absent when the standard did not apply), `suppressed` and `excludedComponents` when not zero (the findings the rule settings turned off, and the components left out for their excluded scope), `notEvaluated` (the [checks not evaluated](#checks-not-evaluated), as `{ruleId, reason}`), `suppressedRules` (the rules turned off, as `{ruleId, findings, source}`) and `conformitySummary` (the CRA Annex VIII checklist, as `{productClass, route, evidence[{label, detail, satisfied}]}`), each absent when empty. `quality -o sarif` carries its embedded standard's verdict the same way, but with the run's own `profile` and quality `overallScore`, and `grade` and `sbom`. |
| `results[].ruleId`, `ruleIndex` | The violation's `rule_id` and the index of its rule in `rules[]`. |
| `results[].kind` | `pass` for a [passed check](#passed-checks), reported only under `--sarif-include-passes`; absent (SARIF's default, `fail`) for a violation. |
| `results[].level` | `error`, `warning` or `note`, from the violation's severity (the one a [rule setting](#rule-settings) sets, if any); `none` for a pass. A pass-only rule's descriptor keeps `defaultConfiguration.level: note`, the lowest level GitHub accepts there. A rule that is `off` reports no result. |
| `results[].message.text` | The violation's message. |
| `results[].locations[0].physicalLocation` | The SBOM file (`artifactLocation.uri`, with `uriBaseId: SRCROOT` when relative) and `region.startLine`: the line of the component's `bom-ref`, `SPDXID`, `spdxId` or `@id`, or, for a finding about the document, the line of the CycloneDX `metadata` or the SPDX creation information. A component whose id the text does not state gets line 1, as does every result for a minified, single-line SBOM. |
| `results[].locations[0].logicalLocations[0]` | For a finding about a component, `name` (its purl, else its `bom-ref`, `SPDXID` or `spdxId`) and `kind: component`. |
| `results[].partialFingerprints` | `sbomToolsFinding/v1`: the full SHA-256 of the `finding_key` (64 hex digits). `primaryLocationLineHash`: its first 16 hex digits and `:1`. |
| `results[].properties` | `findingKey` and `findingId` as in `-o json`; `standardIds` (`<label>:<clause>`, e.g. `CRA:Art. 13(8)`) and `standardHelpUris` (the URLs of the references that have one), the references in the compact form of earlier releases; then the finding's [audit fields](#fields-in-every-output): `severity` (as in `-o json`: `Error`, `Warning`, `Info`), `defaultSeverity` and `severitySource` when a [rule setting](#rule-settings) set the rule, `ruleId` (the `rule_id`), `componentId` for a component finding, `affected` and `total` when the violation counts items, `deadline` and `deadlineSource` when [deadline mode](#pqc-deadline-mode) dates the finding, `field` and `observed` (see [Field and observed value](#field-and-observed-value)), `standardRefs` (the references as `-o json` gives them: `{standard, id, helpUri?}`), `remediation` and `helpUri`. A pass carries `ruleId`, `componentId` and `standardRefs`. |

Both fingerprints depend on the finding identity alone, never on a line
number or the message, so moving, reformatting or reordering the SBOM keeps
every alert. GitHub code scanning matches alerts between uploads by
`primaryLocationLineHash`, and when a SARIF file omits it, GitHub's upload
action computes it from the text at the result's line. Computed that way, any
edit to that text (a version bump on a `bom-ref` line, or any change at all to
a minified SBOM's single line) would close the alert and open a new one.
No two results of one run share a fingerprint; a pass's finding key is built
like a violation's, in the same key space, so no pass shares a violation's.

**Result cap.** GitHub code scanning rejects a SARIF file whose run holds more
than 25,000 results, and shows only the 5,000 most severe. A run keeps at most
`--sarif-max-results` results (25,000 by default, `0` for no cap; config key
`output.sarif_max_results`): beyond it, every error is kept, then warnings,
notes and passes while room is left, the first in report order within a
level, and the kept results stay in report order. The run then carries an
`invocations[0]` notification saying how many results were omitted and to use
`-o json` for the full list, and the same warning goes to stderr.

**`diff`.** A diff reports into the new SBOM only: a code-scanning alert
belongs to a file in the repository, and the old SBOM of a diff is usually an
earlier revision copied outside it.
A removed component (`SBOM-TOOLS-002`) points at the new SBOM's document line,
a resolved vulnerability (`SBOM-TOOLS-006`) at its component's line when the
new SBOM still lists it, else at the document line, and the old SBOM's own CRA
findings are not results. `diff -o json` and the text reports keep both sides.

**TUI exports.** The TUI's SARIF export (`e`, then `s`) does not keep the SBOM
file, so its results have no physical location, only the component's logical
location, and code scanning drops them. Use the CLI to produce SARIF for code
scanning.

Upgrading from v0.3: SARIF results now carry locations and fingerprints, and
every check has its own SARIF rule. The first upload after upgrading re-keys
existing code-scanning alerts. `diff -o sarif` reports into the new SBOM only:
the old SBOM's CRA findings are no longer results, and removed components
point at the new SBOM's document line. A run keeps at most 25,000 results
unless `--sarif-max-results` says otherwise. `rules[]` lists only the rules of
the standards checked: before v0.4.0 the CRA profiles, BSI TR-03183-2, EUCC,
the AI readiness profiles, the quality profiles, `diff` and `view` all
declared one shared list of 107 CRA, BSI, EUCC and AI rules, so
`--standard bsi -o sarif` declared 91 rules BSI never checks. Releases
before v0.4.0 put dozens of checks under shared rules (`SBOM-CRA-ANNEX-I`,
`SBOM-QUALITY-GENERAL`), set no `automationDetails`, and gave results no
location; code scanning drops a result without one. A run's verdict names its
standard by the canonical `--standard` value (`standard`) beside the display
name (`profile`); a run of one standard now says whether it is `compliant`
(it never did) and carries the CRA conformity summary, and each
`standards[]` entry puts `compliant` before `applicable`. Results carry the
finding's severity, rule, references, remediation and help URI as
properties, as `-o json` does.

## Fields in every output

`-o json`, `-o sarif` and `-o oscal-json` carry the same fields for every
finding and every standard's verdict, each under its own format's name. The
fields are declared once in sbom-tools, so a field one output carries, the
others carry too; the test suite checks, for the pinned fixtures of the
snapshot tests, that every finding and every verdict reads the same in all
three.

| `-o json` | SARIF | OSCAL |
|---|---|---|
| `finding_id`, `finding_key` | `properties.findingId`, `findingKey` | finding `finding-id`, `finding-key` |
| `severity` | `properties.severity` (and `level`: `error`, `warning`, `note`) | observation `severity`, in lowercase |
| `default_severity`, `severity_source` | `properties.defaultSeverity`, `severitySource` | observation `default-severity` (lowercase), `severity-source` |
| `requirement` | in `message.text` | observation `requirement` |
| `rule_id` | `properties.ruleId` | observation `rule-id` |
| `sarif_rule_id` | `ruleId` | observation `sarif-rule-id` |
| `element` | in `message.text` | observation `sbom-element` |
| `component_id` | `properties.componentId` | observation `component-id` |
| `counts.affected`, `counts.total` | `properties.affected`, `total` | observation `affected`, `total` |
| `deadline`, `deadline_source` | `properties.deadline`, `deadlineSource` | observation `deadline`, `deadline-source` |
| `field`, `observed` | `properties.field`, `observed` | observation `field`, `observed` |
| `standard_refs[]` `{standard, id, help_uri}` | `properties.standardRefs[]` `{standard, id, helpUri}` | observation `standard-ref` (`class` the standard, `value` the clause), link `rel: reference` |
| `remediation` | `properties.remediation` | finding `remarks` (Markdown) |
| `help_uri` | `properties.helpUri` | finding link `rel: help` |
| `message` | `message.text` | finding and observation `description` (Markdown) |

| `-o json` | SARIF verdict | OSCAL result |
|---|---|---|
| `standard` | `standard` | `standard` |
| `name` | `profile` | `standard-name` |
| `compliant` | `compliant` | `is-compliant` |
| `applicable`, `not_applicable_reason` | `applicable`, `notApplicableReason` | `applicability` (`applicable`, `not-applicable`), `not-applicable-reason` |
| `counts.error`, `warning`, `info`, `passed` | — (the results) | `error-count`, `warning-count`, `info-count`, `passed-count` |
| `score` | `overallScore` | `score` |
| `counts.suppressed` | `suppressed` | `suppressed-count` |
| `excluded_components` | `excludedComponents` | `excluded-components` |
| `evaluated[]` | `notEvaluated[]` | `not-evaluated` (the reason as `remarks`) |
| `suppressed[]` | `suppressedRules[]` | `suppressed-rule`, `suppressed-findings`, `suppressed-source` (the three of one rule share a `group`) |
| `conformity_summary` | `conformitySummary` | `conformity-product-class`, `conformity-route`, `conformity-evidence` |

`category`, `finding_detail` and `score_basis` are in `-o json` only; the
detail is part of the finding key. The JSON `subject` is the OSCAL SBOM
resource (see [OSCAL assessment results](#oscal-assessment-results)); SARIF
names the SBOM file in each result's location instead. A finding built
outside the checks, with no registered rule (a payload of another tool, say),
is the one exception: SARIF files it under the standard's fallback rule and
cites that rule's references in `standardIds`, while its own `rule_id` and
references stay as they are.

## Rule catalogue

`sbom-tools rules` lists the rules each standard checks, and
`sbom-tools rules explain <RULE_ID>` shows one rule in full. Both read the
rule registry only: no SBOM is needed.

```sh
sbom-tools rules                                 # every rule in the registry
sbom-tools rules --standard bsi                  # the rules BSI TR-03183-2 checks
sbom-tools rules --standard cra,oss-steward -o markdown
sbom-tools rules explain SBOM-CRA-ART-24 -o json
```

`--standard` takes the names and aliases `validate --standard` takes,
comma-separated or with the flag repeated. With it, the rules come in the
order a `validate -o sarif` run of those standards lists them in `rules[]`,
followed by each standard's `SBOM-<FAMILY>-GENERAL` fallback rule. Without
it, every registered rule is listed in registry order, including the quality
profiles' `SBOM-QUALITY-*` rules. The rule id of `rules explain` is not case
sensitive. An unknown rule id or standard is a usage error (exit code `3`);
the message names the closest rule id when one is close.

The text output shows, for each rule, its id, name and default severity, what
the check looks for, the standards that use it, its references with their
URLs, and the first sentence of its remediation. `rules explain` adds the
full remediation and where the fix goes in each SBOM format. `-o markdown`
writes one table row per rule (or, for `rules explain`, one section).

`-o json` prints the `sbom-tools/rules/v1` document. Its schema is published
at [`schemas/rules/v1.schema.json`](../schemas/rules/v1.schema.json), and the
test suite validates the output against it. `rules explain -o json` prints
the same document with one rule.

```json
{
  "schema": "sbom-tools/rules/v1",
  "tool": { "name": "sbom-tools", "version": "0.4.0" },
  "rules": [
    {
      "id": "SBOM-CRA-ART-24",
      "name": "CraStewardVulnerabilityHandling",
      "description": "CRA Art. 24: Open-source steward vulnerability-handling process (security contact or disclosure URL)",
      "default_severity": "Error",
      "kind": "finding",
      "fallback": false,
      "standards": ["oss-steward"],
      "references": [
        {
          "standard": "CraArticle",
          "id": "Art. 24",
          "label": "CRA Art. 24",
          "help_uri": "https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng"
        }
      ],
      "help_uri": "https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng",
      "remediation": "Show the open-source steward's vulnerability-handling process (Art. 24): …",
      "remediation_summary": "Show the open-source steward's vulnerability-handling process (Art. 24): …",
      "advice": {
        "cyclonedx": { "text": "add a metadata.component.externalReferences[] entry of type security-contact (or advisories).", "field": "metadata.component.externalReferences[]" },
        "spdx2": { "text": "…", "field": "packages[].externalRefs[]" },
        "spdx3": { "text": "…", "field": "externalRef[]" }
      }
    }
  ]
}
```

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | Always `sbom-tools/rules/v1`. |
| `tool.name`, `tool.version` | string | `sbom-tools` and the release that produced the document. |
| `rules[].id` | string | The rule id: `rule_id` in `-o json`, `ruleId` in SARIF. |
| `rules[].name` | string | PascalCase name, the SARIF `reportingDescriptor.name`. |
| `rules[].description` | string | What the check looks for, the SARIF `shortDescription`. |
| `rules[].default_severity` | string | `Error`, `Warning` or `Info`: the severity the rule reports at. A check may escalate or relax it by product class, CRA phase or context. |
| `rules[].kind` | string | `finding`, or `pass` for a rule that reports [passed checks](#passed-checks) only. |
| `rules[].fallback` | boolean | `true` for a `SBOM-<FAMILY>-GENERAL` fallback rule: no check emits it, and SARIF files a finding without a registered rule under it. |
| `rules[].standards` | array | The canonical `--standard` values of the standards whose reports carry the rule, `minimum`, `standard` and `comprehensive` for the quality profiles (`quality --profile`). For a fallback rule, the standards it is the fallback of. |
| `rules[].references` | array | The clauses the rule implements: `standard` and `id` as in a violation's `standard_refs`, `label` as a reader cites it (`CRA Art. 24`), and `help_uri` when the standard has a canonical URL. Empty only for the quality profiles' own rules, which no external standard defines, and some fallback rules. |
| `rules[].help_uri` | string | The rule's documentation link: the URL of the first reference that has one, else the standard's own page (the SARIF `helpUri`). |
| `rules[].remediation` | string | How to fix a finding, in words that hold for every SBOM format. |
| `rules[].remediation_summary` | string | The first sentence of `remediation`. |
| `rules[].advice` | object | Where the fix goes: `cyclonedx`, `spdx2` and `spdx3`, each with the `text` and, where the format has one, the `field` to set. Absent when the fix is the same in every format. |

The library returns the same entries: `sbom_tools::quality::rule_catalog`
takes a `RuleCatalogFilter` (all rules, or those of some levels or
standards), `rule_catalog_entry` looks up one rule, `rules_for_level` gives a
level's list, and `sbom_tools::reports::generate_rule_catalog_json` writes
the document.

## Text report

Without `-o`, `validate` prints a text report, one block per finding:

```text
[ERROR] SBOM-FDA-HASH | Integrity Information | FDA: Cryptographic hash for integrity | lodash
  Component 'lodash' has no valid cryptographic hash: SHA-256 digest is not hexadecimal
  observed: "SHA-256:abc123def456..." in packages[].checksums[]
  fix: Give every component a cryptographic hash using SHA-256 or stronger …
```

The first line names the severity, the rule (the `rule_id` of `-o json`,
the `ruleId` of `-o sarif`), the category, the requirement and the element.
The message follows, then an `observed:` line when the finding read a value,
a `deadline:` line when [deadline mode](#pqc-deadline-mode) dates it, a
`severity:` line when a [rule setting](#rule-settings) set its rule
(`severity: WARN from --rule (default ERROR)`), and the `fix:` line. Under
the status, an `Excluded:` line counts the
[components left out for their excluded scope](#components-whose-scope-is-excluded).
After the findings, the checks the standard did not evaluate follow, one
line per reason, and then the rules the settings turned off, one line per
rule:

```text
Not evaluated:
  SBOM-CISA2026-SIGNATURE: SPDX 2.x cannot carry a document signature

Suppressed by settings:
  SBOM-NTIA-VERSION: 2 findings turned off by --rule
```

SBOM text in every line is cleaned, the observed value included, as
described under [Field and observed value](#field-and-observed-value). The
text layout may change in any release; scripts should read `-o json`.

## Exit codes

| Code | `validate` | Other commands |
|---|---|---|
| `0` | Compliant: no errors, and no warnings with `--fail-on-warning`. A standard that does not apply also exits `0`, unless `--require-applicable`. | Success |
| `1` | Compliance errors, a finding of a `--fail-on` rule at any severity, or, under `--require-applicable`, a standard that does not apply (with several standards, any one of them). | Gate failed |
| `2` | Compliance warnings, only with `--fail-on-warning`. | Vulnerabilities introduced (`--fail-on-vuln`) |
| `3` | Usage error (unknown flag or standard, invalid flag value, missing argument, `--pqc-profile` or `--cnsa-category` without `--pqc-mode deadline`, an unknown `--rule` or `--fail-on` rule id or setting) or operational error (I/O, parse failure, unsupported output format, invalid `--as-of`, broken sidecar or config file). | Same; for `rules`, also an unknown standard or rule id |

The gate codes read the severities the [rule settings](#rule-settings) set,
and a finding of a rule that is `off` counts toward none of them.

Codes `4`–`7` belong to other gates (VEX gaps, license policy, KEV, ML
regression); the README lists them all. Usage errors exit `3` in every command.
Before v0.4.0 they exited `2`, the code `validate --fail-on-warning` uses, so a
pipeline that tolerated warnings also passed a mistyped standard. `--help`,
`--version` and `help` exit `0` and print to stdout. The gate codes only apply
to runs that produced their report.
