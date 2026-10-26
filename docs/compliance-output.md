# Compliance JSON output

`sbom-tools validate -o json` prints one JSON object, the
`sbom-tools/compliance/v2` envelope, whatever the number of standards checked.
The schema is published at
[`schemas/compliance-v2.schema.json`](../schemas/compliance-v2.schema.json)
(JSON Schema draft 2020-12), and the test suite validates every `-o json`
output against it.

```sh
sbom-tools validate sbom.json --standard ntia,cra -o json |
  jq -c '.results[] | {standard, applicable, compliant, counts}'
```

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
| `counts` | object | `error`, `warning` and `info`: the number of violations of each severity. |
| `violations` | array | The findings, described below. |
| `conformity_summary` | object | CRA Annex VIII checklist (`product_class`, `route`, `evidence[]` of `{label, detail, satisfied}`). Present for the CRA standards once a product class is pinned by `--cra-product-class` or the sidecar. |

## Violations

Each violation carries the same fields as in the v1 layout, plus its finding
identity.

| Field | Type | Meaning |
|---|---|---|
| `finding_id` | string | Opaque, stable id of the finding (see [Finding identity](#finding-identity)). |
| `finding_key` | string | `<standard>\|<rule_id>\|<subject>`, the readable form of the id. |
| `severity` | string | `Error`, `Warning` or `Info`. |
| `category` | string | e.g. `DocumentMetadata`, `ComponentIdentification`, `SupplierInfo`. |
| `message` | string | Human-readable explanation. Its wording may change in any release. |
| `element` | string or null | Human-readable label of the offending element (usually a component name). Not unique. |
| `component_id` | string | Canonical id of the offending component. Absent for document-level and aggregate findings. |
| `counts` | object | `affected` and `total` components of an aggregate finding. Absent otherwise. |
| `requirement` | string | The requirement, as text. |
| `rule_id` | string | Stable internal rule key, e.g. `SBOM-NTIA-SUPPLIER`. |
| `sarif_rule_id` | string | The rule id `-o sarif` reports for this violation. Several `rule_id`s can share one. |
| `standard_refs` | array | `{standard, id, help_uri?}` references to the clauses the rule implements. Absent when empty. |

## Finding identity

The finding key names what a finding is about, not how it is worded:

```text
<standard>|<rule_id>|<subject>
ntia|SBOM-NTIA-SUPPLIER|pkg:npm/lodash@4.17.21
ntia|SBOM-NTIA-AUTHOR|document
```

- `<standard>` is the canonical `--standard` value.
- `<rule_id>` is the violation's `rule_id`, not its `sarif_rule_id`: dozens of
  rules share a SARIF id (all ten `SBOM-BSIAI-MODEL-*` checks report as
  `SBOM-BSIAI-MODEL`), so keying on the SARIF id would merge distinct findings
  about one component.
- `<subject>` is the violation's `component_id` when it has one, otherwise
  `document`. A finding about one dependency edge would use
  `edge:<from>-><to>`; no rule reports a single edge today, so that form is
  reserved.

Neither the standard nor a rule id contains `|`, so the subject is everything
after the second `|`. The `finding_id` is `sbomtools:v1:` followed by the first
16 hex digits of the SHA-256 of the key's UTF-8 bytes. The library computes both
(`sbom_tools::quality::{finding_key, finding_id}`), so SARIF fingerprints and
baselines can use the same identity.

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
`SPDXID`, so reordering such components can move that suffix.

**Uniqueness.** The key identifies one rule on one subject. Some rules report
several findings on the same subject, and those share key and id: one
`SBOM-CRA-VULN-METADATA` finding per vulnerability of a component, the four
`SBOM-CRA-ART-14` reporting-channel checks on the document, or the generic
`SBOM-QUALITY-GENERAL` and `SBOM-CRA-GENERAL` buckets.

## Compatibility

The envelope follows the crate version like every other JSON payload, with two
promises:

- **Additive changes keep the schema id.** Later releases add fields without a
  new `schema` value, and the published schema accepts unknown fields. Ignore
  fields you do not know. The schema already declares the optional fields
  announced for upcoming releases: `passed` (array) and `counts.passed`
  (integer) on results, `remediation` and `help_uri` (strings) on violations.
- **A breaking change would get a new schema id** (`sbom-tools/compliance/v3`)
  and a new schema file.

`--json-schema v1` prints the pre-0.4 layout until v0.5.0, and warns on stderr
that it is deprecated: a bare result object for one standard, an array of them
for several, each with `is_compliant`, `level` (e.g. `NtiaMinimum`),
`error_count`/`warning_count`/`info_count`, `applicability`, `violations`
(without `finding_id`/`finding_key`) and `conformity_summary` when present.
To migrate:

| v1 | v2 |
|---|---|
| object or array | always `results[]` |
| `level` | `standard` (`ntia`) and `name` (`NTIA Minimum Elements`) |
| `is_compliant` | `compliant` |
| `error_count`, `warning_count`, `info_count` | `counts.error`, `counts.warning`, `counts.info` |
| `applicability.status`, `applicability.reason` | `applicable`, `not_applicable_reason` |
| — | `score` |

`--summary` is a separate compact format (the verdict and counts per standard,
with `standard` holding the display name) and is not affected.

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
