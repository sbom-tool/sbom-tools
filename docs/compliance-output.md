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
[SARIF](#sarif).

## Envelope

```json
{
  "schema": "sbom-tools/compliance/v2",
  "tool": { "name": "sbom-tools", "version": "0.4.0" },
  "results": [ { "standard": "ntia", "...": "one entry per standard" } ]
}
```

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | Always `sbom-tools/compliance/v2`. |
| `tool.name` | string | Always `sbom-tools`. |
| `tool.version` | string | The release that produced the document. |
| `results` | array | One entry per checked standard, in `--standard` order. Never empty. |

## Results

| Field | Type | Meaning |
|---|---|---|
| `standard` | string | Canonical `--standard` value: `ntia`, `fda`, `cra`, `cra-phase1`, `ssdf`, `eo14028`, `cnsa2`, `pqc`, `bsi`, `oss-steward`, `eucc`, `ai-act`, `bsi-ai`, `cisa-2026`, `pci-dss`, `fsct`. An alias on the command line (`nist-ssdf`, `cra-2026`, …) still reports the canonical value. |
| `name` | string | Display name, e.g. `NTIA Minimum Elements`. |
| `applicable` | boolean | Whether the standard evaluated the SBOM. The AI readiness profiles (`ai-act`, `bsi-ai`) do not apply to an SBOM without ML components. |
| `not_applicable_reason` | string | Present exactly when `applicable` is `false`. |
| `compliant` | boolean | No error-severity violation. Stays `true` for a standard that did not apply, so read `applicable` first: N/A is not a pass. |
| `score` | integer or null | 0–100; `null` exactly when `applicable` is `false`. |
| `counts` | object | `error`, `warning` and `info`: the number of violations of each severity. `passed`: the number of passed checks, which no severity count includes. |
| `violations` | array | The findings, described below. |
| `passed` | array | The checks the SBOM passed, described [below](#passed-checks). Always present; empty when the standard passed no check or did not apply. |
| `conformity_summary` | object | CRA Annex VIII checklist (`product_class`, `route`, `evidence[]` of `{label, detail, satisfied}`). Present for the CRA standards once a product class is pinned by `--cra-product-class` or the sidecar. |

A standard that does not apply reports no violation: its verdict is
`applicable: false` with the reason.

## Violations

Each violation carries the same fields as in the v1 layout, plus its finding
identity.

| Field | Type | Meaning |
|---|---|---|
| `finding_id` | string | Opaque, stable id of the finding (see [Finding identity](#finding-identity)). |
| `finding_key` | string | `<standard>\|<rule_id>\|<subject>`, or `<standard>\|<rule_id>:<finding_detail>\|<subject>`: the readable form of the id. |
| `severity` | string | `Error`, `Warning` or `Info`. |
| `category` | string | e.g. `DocumentMetadata`, `ComponentIdentification`, `SupplierInfo`. |
| `message` | string | Human-readable explanation. Its wording may change in any release. |
| `element` | string or null | Human-readable label of the offending element (usually a component name). Not unique. |
| `component_id` | string | Canonical id of the offending component. Absent for document-level and aggregate findings. |
| `finding_detail` | string | What tells this finding apart from the rule's other findings on the same subject: a value from the SBOM, such as the vulnerability id or the cipher suite (see [Uniqueness](#finding-identity)). Absent when the rule reports at most one finding per subject. |
| `counts` | object | `affected` and `total` components of an aggregate finding. Absent otherwise. |
| `requirement` | string | The requirement, as text. |
| `rule_id` | string | Stable internal rule key, e.g. `SBOM-NTIA-SUPPLIER`. |
| `sarif_rule_id` | string | The rule id `-o sarif` reports for this violation. Every check is its own SARIF rule, so this equals `rule_id` (until v0.4.0 several `rule_id`s shared one). |
| `standard_refs` | array | `{standard, id, help_uri?}` references to the clauses the rule implements. Absent when empty. |

## Passed checks

Some rules affirm what the SBOM gets right rather than report a gap: under
`pqc`, `SBOM-PQC-009` (an algorithm NIST approves for post-quantum use) and
`SBOM-PQC-010` (a PQ/T hybrid whose post-quantum part NIST approves). These
pass-only rules report into `passed`, never into `violations`: a pass has no
severity and counts toward neither `counts.info` nor the score. `-o sarif`
reports no pass, so code scanning raises no alert for one;
`--sarif-include-passes` adds each as a SARIF result of `kind: "pass"` at
level `none`, under the rule's `sarif_rule_id`. Each entry carries a
violation's identifying and descriptive fields (not `severity`, `category`,
`counts`, `remediation` or `help_uri`), plus its finding identity:

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
`SPDXID`, so reordering such components can move that suffix. A finding with a
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
second one's detail is numbered: `CVE-2024-3094`, then `CVE-2024-3094#2`.
Passed checks are numbered the same way. The test suite checks the guarantee,
over a result's violations and passed checks together, on every fixture at
every level.

## Compatibility

The envelope follows the crate version like every other JSON payload, with two
promises:

- **Additive changes keep the schema id.** Later releases add fields without a
  new `schema` value, and the published schema accepts unknown fields. Ignore
  fields you do not know. The schema already declares the optional fields
  announced for upcoming releases: `remediation` and `help_uri` (strings) on
  violations.
- **A breaking change would get a new schema id** (`sbom-tools/compliance/v3`)
  and a new schema file.

`--json-schema v1` prints the pre-0.4 layout until v0.5.0, and warns on stderr
that it is deprecated: a bare result object for one standard, an array of them
for several, each with `is_compliant`, `level` (e.g. `NtiaMinimum`),
`error_count`/`warning_count`/`info_count`, `applicability`, `violations`
(without `finding_id`/`finding_key`) and `conformity_summary` when present.
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
| — | `score` |
| — (Info violations before v0.4.0) | `passed[]`, `counts.passed` |

`--summary` is a separate compact format (the verdict and counts per standard,
with `standard` holding the display name) and keeps its shape. Its `info`
count, like `counts.info`, counts Info violations only, so passed checks are
not in it.

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
| `results[]` | One per checked standard, in `--standard` order. Its `props` carry the verdict: `standard`, `standard-name`, `is-compliant`, `applicability`, `error-count`, `warning-count`, `info-count`, `passed-count`, `score`, and `not-applicable-reason` when the standard did not apply. |
| `results[].findings[]` | A roll-up finding for the standard (`satisfied` when compliant), then one `not-satisfied` finding per violation, then one `satisfied` finding per [passed check](#passed-checks), each targeting the objective named by the lowercased rule id. A standard that did not apply gets no roll-up and no finding. |
| `results[].observations[]` | One per violation, the evidence its finding relates to, typed `discovery`, with the properties `severity`, `standard-reference`, `rule-id`, `sarif-rule-id` and, when the SBOM gives a label, `sbom-element`; then one per passed check, typed `control-objective`, with the same properties but `severity`. |
| `results[].observations[].subjects[]` | The SBOM document (`type: resource`), then, for a finding about a component, the component (`type: component`). |
| `results[].local-definitions.components[]` | The components the result's observations name, titled by name and version, with OSCAL's `version` property, `component-id` (the canonical id: `component_id` in `-o json`) and `component-type` (the SBOM's own type). |
| `back-matter.resources[0]` | The SBOM document: `type` `artifact`, `sha256` (of the SBOM bytes as read), `format`, `spec-version`, and the serial number (CycloneDX) or document namespace (SPDX) in `document-ids`. When that id is a URI (`urn:uuid:…`, `https://…`), it is also the resource's `rlinks[0].href`, with the SHA-256 in `hashes`. |

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
with no text is omitted.

Every UUID is a UUIDv5. The document, its results, observations and findings
derive from the SHA-256 of the SBOM, the evaluation instant (`--as-of`, else
the current time), the standards checked and their position, so a run with
`--as-of` prints the same bytes every time. The SBOM document and its
components derive from the SHA-256 of the SBOM and the subject alone (for a
component, its canonical id), so a subject keeps its UUID across instants,
standard sets and results.

### Upgrading from OSCAL 1.1.2

Releases before v0.4.0 emitted OSCAL 1.1.2. Consumers of `-o oscal-json`
should note:

- `metadata.oscal-version` is `1.2.3`. Validate against the 1.2.3 schema.
- Observations are typed `discovery`, not `finding`: OSCAL 1.2.0 deprecated
  `finding` and named `discovery` its replacement. A filter on `types`
  containing `finding` must look for `discovery`.
- Observations gain `subjects`, results gain `local-definitions`, and the
  document gains `back-matter`. These are additions: no existing field moved
  or changed meaning.
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
| `runs[0].automationDetails.id` | The analysis category, ending in `/`: `sbom-tools/` and the canonical `--standard` values, sorted and joined by `+` (`sbom-tools/cra+ntia/`), or the value of `--sarif-category`. GitHub code scanning keeps one set of alerts per category. |
| `runs[0].originalUriBaseIds.SRCROOT` | Declared when the SBOM's URI is relative, which is the default: relative to the repository the SBOM file is in, or to `--sarif-base`. It carries a description only, no absolute URI, so the log names no path on the machine that wrote it. |
| `runs[0].tool.driver.rules[]` | Every rule of every standard checked, one per check and each once, in `--standard` order and registry order within a standard. `id` is the `rule_id`. Each has `shortDescription`, `fullDescription` (with the standard references), `defaultConfiguration.level`, `help.text` and `help.markdown` (the remediation, where the fix goes in each SBOM format, the references) and, where one is known, `helpUri`: the first reference with a URL, else the standard's own page. A `SBOM-<FAMILY>-GENERAL` fallback rule is listed only in a run that has a finding without a registered rule. |
| `runs[0].properties` | The verdict: `applicable` (with `notApplicableReason` when it is false), `overallScore` and `profile` for one standard; `applicable` and `standards[]`, one summary per standard, for several. |
| `results[].ruleId`, `ruleIndex` | The violation's `rule_id` and the index of its rule in `rules[]`. |
| `results[].level` | `error`, `warning` or `note`, from the violation's severity. |
| `results[].message.text` | The violation's message. |
| `results[].locations[0].physicalLocation` | The SBOM file (`artifactLocation.uri`, with `uriBaseId: SRCROOT` when relative) and `region.startLine`: the line of the component's `bom-ref`, `SPDXID`, `spdxId` or `@id`, or, for a finding about the document, the line of the CycloneDX `metadata` or the SPDX creation information. A component whose id the text does not state gets line 1, as does every result for a minified, single-line SBOM. |
| `results[].locations[0].logicalLocations[0]` | For a finding about a component, `name` (its purl, else its `bom-ref`, `SPDXID` or `spdxId`) and `kind: component`. |
| `results[].partialFingerprints` | `sbomToolsFinding/v1`: the full SHA-256 of the `finding_key` (64 hex digits). `primaryLocationLineHash`: its first 16 hex digits and `:1`. |
| `results[].properties` | `findingKey` and `findingId` as in `-o json`, then `standardIds`, `standardHelpUris`, `componentId` for a component finding, and `affected` and `total` when the violation counts items. |

Both fingerprints depend on the finding identity alone, never on a line
number or the message, so moving, reformatting or reordering the SBOM keeps
every alert. GitHub code scanning matches alerts between uploads by
`primaryLocationLineHash`, and when a SARIF file omits it, GitHub's upload
action computes it from the text at the result's line. Computed that way, any
edit to that text (a version bump on a `bom-ref` line, or any change at all to
a minified SBOM's single line) would close the alert and open a new one.
Results inside one run never share a fingerprint for one file. `diff` runs
point into both SBOMs, so a finding on both sides has the same fingerprint
once in each file.

Upgrading from v0.3: SARIF results now carry locations and fingerprints, and
every check has its own SARIF rule. The first upload after upgrading re-keys
existing code-scanning alerts. Releases before v0.4.0 put dozens of checks
under shared rules (`SBOM-CRA-ANNEX-I`, `SBOM-QUALITY-GENERAL`), set no
`automationDetails`, and gave results no location; code scanning drops a
result without one.

## Exit codes

| Code | `validate` | Other commands |
|---|---|---|
| `0` | Compliant: no errors, and no warnings with `--fail-on-warning`. A standard that does not apply also exits `0`, unless `--require-applicable`. | Success |
| `1` | Compliance errors, or, under `--require-applicable`, a standard that does not apply (with several standards, any one of them). | Gate failed |
| `2` | Compliance warnings, only with `--fail-on-warning`. | Vulnerabilities introduced (`--fail-on-vuln`) |
| `3` | Usage error (unknown flag or standard, invalid flag value, missing argument) or operational error (I/O, parse failure, unsupported output format, invalid `--as-of`, broken sidecar or config file). | Same |

Codes `4`–`7` belong to other gates (VEX gaps, license policy, KEV, ML
regression); the README lists them all. Usage errors exit `3` in every command.
Before v0.4.0 they exited `2`, the code `validate --fail-on-warning` uses, so a
pipeline that tolerated warnings also passed a mistyped standard. `--help`,
`--version` and `help` exit `0` and print to stdout. The gate codes only apply
to runs that produced their report.
