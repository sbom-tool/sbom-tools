# Standards versions and watch list

The compliance engine pins its checks and citations to specific editions of
the underlying standards. This file records which edition each profile
targets, verified against the primary source on the date shown, plus the
items expected to move. Update this file whenever a checker is rebased onto
a new edition.

Last full verification: **2026-07-12** (primary sources fetched directly).
Rows added after that date carry their own edition dates: the CISA 2026,
PCI DSS 6.3.2 and FSCT profiles and the sbomqs interoperability section
landed 2026-07-30 (commits `b0e533b`, `b283320`); their rule catalogues and
aliases were re-checked against the binary on 2026-07-31.

## Pinned editions

| Profile / reference | Edition implemented | Canonical source | Notes |
|---|---|---|---|
| EU CRA (`cra`, `oss-steward`) | Regulation (EU) 2024/2847 (OJ L, 2024-11-20) | <https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng> | Art. 14 applies from 2026-09-11; full application 2027-12-11 (Art. 71(2)). No 2029 milestone exists. |
| BSI TR-03183-2 (`bsi`) | v2.1.0 (2025-08-20) | <https://bsi.bund.de/dok/TR-03183-en> | CycloneDX ≥ 1.6 / SPDX ≥ 3.0.1; SHA-512 hash of the deployable component; the §7 six-month grace for v2.0.0 ended 2026-02-20. |
| NTIA minimum elements (`ntia`) | July 2021 report | <https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom> | Canonical host is ntia.gov (ntia.doc.gov survives via redirect). Superseded by the CISA 2026 Minimum Elements (below) but retained as the 2021 baseline many regulations still cite. |
| CISA 2026 Minimum Elements (`cisa-2026`) | v2.1 final, 2026-07-29 (TLP:CLEAR; CISA/NSA/FBI + 15 international agencies) | <https://www.cisa.gov/resources-tools/resources/2026-minimum-elements-software-bill-materials-sbom> | "Updates and replaces" the NTIA 2021 elements (the Aug 2025 CISA draft was v2.0 of this document). Aliases `cisa`, `cisa2026`, `minimum-elements-2026`. 17 data fields + document-checkable practices, implemented as 17 `SBOM-CISA2026-*` rules (plus the `SBOM-CISA2026-GENERAL` fallback id); explicit-unknown markers (NOASSERTION) satisfy the 2026 escape hatches; required data fields fail as Error, evidence-limited or heuristic checks only Warn (Author Signature / Generation Context / SBOM Version / Coverage, plus Data Format Version, Tool Version and Hash Algorithm); Author Signature, Generation Context and Coverage are not evaluated on SPDX 2.x, which has no field for them, so a complete SPDX 2.x SBOM can pass `--fail-on-warning`; Hash Algorithm warns only for components with no hash in an accepted algorithm (MD5 and SHA-1 next to SHA-256 do not warn); the format-version floor (CycloneDX 1.4+ / SPDX 2.2+) is tool policy — CISA names no deprecated versions. Frequency, Distribution and Delivery, and Accommodation of Updates are organizational practices with no in-document evidence and carry no rules. Non-binding joint guidance. |
| FDA premarket cybersecurity (`fda`) | Final, 2026-02-03 — "Quality **Management** System Considerations…" | <https://www.fda.gov/media/119933/download> | Supersedes the June 2025 and Sept 2023 finals. SBOM elements (NTIA baseline + level of support + end-of-support date) unchanged. |
| NIST SSDF (`ssdf`) | SP 800-218 v1.1 | <https://doi.org/10.6028/NIST.SP.800-218> | |
| EO 14028 (`eo14028`) | May 2021 + NTIA elements | <https://www.federalregister.gov/d/2021-10460> | |
| CNSA 2.0 (`cnsa2`) | Sept 2022 fact sheet (rev.) | NSA CSA CNSA 2.0 | 2030/2033 milestones not yet severity-scaled (see plan P2). |
| NIST PQC (`pqc`) | **IR 8547 ipd (draft, Nov 2024)** + FIPS 203/204/205 (final, 2024-08-13) + SP 800-208 + SP 800-131A **Rev. 2** | <https://csrc.nist.gov/projects/post-quantum-cryptography> | Cite IR 8547 as draft; SP 800-131A Rev. 3 is draft-only. |
| EUCC (`eucc`) | Implementing Regulation (EU) 2024/482 | <https://eur-lex.europa.eu/eli/reg_impl/2024/482/oj/eng> | Reference-only profile. |
| EU AI Act (`ai-act`) | Regulation (EU) 2024/1689 Annex IV | <https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng> | Readiness profile. |
| BSI/G7 SBOM for AI (`bsi-ai`) | Final joint G7 guidance, 2026-05-12 | <https://www.cisa.gov/resources-tools/resources/software-bill-materials-ai-minimum-elements> | Supersedes the Feb 2026 BSI draft the profile was first built against; element clusters unchanged at the level we check. |
| PCI DSS Req. 6.3.2 (`pci-dss`) | v4.0.1 (2024-06-11); Req. 6.3.2 with companion controls 6.3.1 / 11.3.1.1 | <https://www.pcisecuritystandards.org/document_library/> | Aliases `pci`, `pci-dss-6-3-2`, `pci-dss-4`. 10 rules: 9 × `SBOM-PCI-6-3-2-*` plus `SBOM-PCI-11-3-1-1-SEVERITY` (and the `SBOM-PCI-GENERAL` fallback id). Required in assessments since 2025-03-31 (v4.0 retired 2024-12-31); citations target v4.0.1 only. The standard PDF is license-gated, so the 6.3.2 requirement/testing-procedure text is secondary-sourced (consistent across independent sources). PCI DSS prescribes no SBOM format or field schema — no format gate; the SBOM-as-inventory mapping is guidance-derived, so a passing run evidences that the inventory exists and is usable, **not** PCI DSS compliance (interviews, inventory *use*, and the software-vs-inventory comparison are assessor work). The 365-day staleness advisory is tool policy, not standard text. |
| CISA Framing Software Component Transparency (`fsct`) | Third Edition (document date 2024-09-03, published 2024-10-15) | <https://www.cisa.gov/resources-tools/resources/framing-software-component-transparency-2024> | Aliases `fsct-3`, `component-transparency`. 27 `SBOM-FSCT-*` rules (plus the `SBOM-FSCT-GENERAL` fallback id). Attribute-maturity profile: Minimum Expected → Error, Recommended Practice → Warning, Aspirational Goal → Info (Error means "fails the Minimum Expected tier" — the document is non-regulatory community guidance, distinct from the Minimum Elements line; no 4th edition exists as of 2026-07). The tier structure is asymmetric and preserved as-is; §2.3.2 Redacted Components has no rule (redaction markers are not modeled). Coverage floors (≥50% license/copyright), the ≥2-identifier-kinds threshold, the depth≥2 transitive proxy, and strict global-identifier enforcement (§2.2.2.4 only "prefers" it) are documented profile policy. SBOM Type, signature, concluded-license, and dynamic-dependency checks are evidence-gated by format (see `src/quality/compliance/fsct.rs` module docs). |
| CSAF | v2.0 (OASIS Standard, 2022; ISO/IEC 20153:2025) | <https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html> | |

## Attestation evidence (CycloneDX 1.6 `declarations`)

CycloneDX 1.6 CDXA `declarations` (assessors, attestations, claims, evidence,
targets, affirmation/signatories) plus `definitions.standards` are parsed into
a normalized evidence model (`src/model/attestation.rs`) and consumed by the
existing profiles: an attestation covering an SSDF practice (e.g. PS.1, PO.3),
a CRA conformity route, an EUCC certificate reference or an EO 14028
provenance claim can satisfy that rule
(`src/quality/compliance/{ssdf,cra,eucc,eo14028}.rs`). Two limits are
load-bearing when reading a passing verdict:

- **Structural verification only.** JSF signature objects are recorded as
  *present* — algorithm, named signatories, signer count — and are **never
  cryptographically verified**. The evidence ladder is
  `SelfDeclared < Structural < SignaturePresent < SignatureVerified`, and
  phase 1 can never emit `SignatureVerified` (the variant exists only for
  output-schema stability). "Attested" here means "the document says so, in
  the schema's shape".
- **In-document declarations only.** Ingestion of external in-toto / DSSE
  attestation bundles (SLSA provenance/VSA, test-result, vulns predicates) is
  a later phase with no surface today.

Parsing is gated on `specVersion >= 1.6`; unresolvable CDXA refLinks are kept
as dangling and fail closed (a dangling ref can never help satisfy a
requirement). Every pre-existing satisfaction path remains valid as a
self-declared fallback, so a document without `declarations` scores exactly as
before. Verified 2026-07-31 on the SSDF path: stripping `declarations` from
`tests/fixtures/cyclonedx/declarations-cdxa-ssdf-delta.cdx.json` re-fires
`SBOM-SSDF-PS1` and `SBOM-SSDF-PO3`, while that document's `cra`, `eucc` and
`eo14028` verdicts are identical with and without the section (those three
consume the same evidence accessor, but need a claim that maps onto their own
requirements before a rule changes).

## Watch list (expected to move)

| Item | Status (2026-07-12 unless dated otherwise) | Action when it lands |
|---|---|---|
| CEN/CENELEC prEN 40000-1-3 (CRA vulnerability handling / SBOM) | Enquiry closed 2026-02-09; comment resolution before Formal Vote; publication expected H2 2026, may slip to 2027 | The `PRE-*-RQ-*` ids hardcoded in registry refs must be re-verified against the published EN; revisit `Pren40000_1_3` help-URI (currently None — draft is paywalled). |
| NIST IR 8547 | Initial Public Draft only (comment period closed 2025-01-10) | Change "IR 8547 ipd" citations to final; re-check 2030/2035 timeline wording. |
| CISA 2026 SBOM Minimum Elements | Final v2.1 published 2026-07-29; profile shipped 2026-07-30 as `cisa-2026` (plan P4); the `SBOM-CISA2026-SCAFFOLD` marker is gone from the registry (verified 2026-07-31) | Watch cisa.gov for errata to the 2026-07-29 v2.1; re-verify the 17 rules if an erratum moves a data field. |
| OASIS CSAF 2.1 | Committee Specification Draft 02 (2026-02-25) | Update `Csaf2` references when it reaches OASIS Standard. |
| NIST SP 800-131A Rev. 3 | Draft only (ipd 2024-10-21) | Update PQC registry refs from Rev. 2. |
| BSI TR-03183-2 | v2.1.0 current; no v2.2.0 exists (the `_v2_2_0.pdf` URL on bsi.bund.de serves the archived v1.1 — do not trust the filename) | Rebase `bsi` checker; §7 gives a six-month transition from publication of the next edition. |

## sbomqs interoperability (`quality -o sbomqs-json`)

**Parity target: interlynk-io/sbomqs v2.0.11** (2026-07-10; all formulas below
verified against the fetched v2.0.11 sources). sbomqs is a tool, not a
standard; this view exists so its 0-10 quality scores can be compared with
this tool's output side by side. Implemented in
`src/reports/sbomqs_compat.rs`, surfaced as:

- `sbom-tools quality <sbom> -o sbomqs-json` — a report in the exact
  `sbomqs score --json` schema (`pkg/reporter/json.go` field names/types:
  `run_id`, `timestamp`, `creation_info{name,version,scoring_engine_version,`
  `vendor}`, `files[]{file_name,spec,spec_version,file_format,avg_score,`
  `num_components,creation_time,gen_tool_name,gen_tool_version,`
  `scores[]{category,feature,score,max_score,description,ignored}}`).
  `creation_info` honestly identifies **sbom-tools** — it never impersonates
  the sbomqs binary, so divergent scores cannot be mis-attributed to
  Interlynk.
- A compact "sbomqs-Comparable Scores" table appended to the plain-text
  `quality` summary (per-category 0-10 rollups plus `avg_score` and the
  sbomqs-bracket grade).

Phase 1 emits the sbomqs **legacy (v1) engine's** five default categories
(23 features). The v2 engine (8 weighted categories, `score` default since
sbomqs 2.0) and the per-standard profile scores (`ntia`, `ntia-2025`,
`bsi-v1.1/v2.0/v2.1`, …) are documented here for a later phase; note that
sbomqs v2.0.11's `ntia-2025` profile tracks the superseded CISA **2025
draft** — the successor guidance was finalized on 2026-07-29 as the **2026
Minimum Elements for a SBOM** (CISA/NSA/FBI et al.), so do not describe the
CISA elements as "not yet final".

### Not convertible from the 0-100 score

The 0-100 `quality` score and the sbomqs 0-10 score use different category
taxonomies, different weights, and different missing-data semantics (this
repo renormalizes N/A categories; sbomqs keeps ignored checks in the
`avg_score` denominator), and different grade cut lines (sbomqs `ToGrade`:
A ≥ 9.0, B ≥ 8.0, C ≥ 7.0, D ≥ 5.0, F — source-verified; the sbomqs docs
page saying "A = 8.0-10.0" is stale. This repo: A ≥ 90 … D ≥ 60).
**Dividing the 0-100 score by 10 is not an sbomqs-comparable number and the
emitter never does it** — every feature score is recomputed from the
normalized SBOM with sbomqs' own formulas (the emitter does not read
`QualityReport` at all).

### Aggregation (verbatim sbomqs semantics)

`avg_score = Σ(score of non-ignored entries) / count(ALL entries, ignored
included)` — the verbatim `scores.go AvgScore()` formula, quirk included.
Features this model cannot evaluate are emitted with `ignored: true` and a
reason in `description` — never silently dropped (that would inflate
`avg_score` via the denominator) and never fabricated as 0 or 10.

### Feature mapping (ours → sbomqs, fidelity)

| sbomqs feature (category) | Computed from | Fidelity |
|---|---|---|
| `sbom_spec` (Structural) | `DocumentMetadata.format` (both normalized formats are sbomqs-supported specs) | exact |
| `sbom_spec_version` (Structural) | `DocumentMetadata.spec_version` vs sbomqs' recognized versions (CDX 1.0-1.7; SPDX 2.1-2.3) | exact |
| `sbom_file_format` (Structural) | Serialization detected from the raw document text vs sbomqs' recognized formats (CDX json,xml; SPDX json,yaml,rdf,tag-value) | approximate (detection heuristic); **ignored + reason** when the raw text is unavailable (library callers) |
| `sbom_parsable` (Structural) | Always 10 — this pipeline only scores documents it parsed | exact, with the documented asymmetry that sbomqs can also score an unparsable file 0 |
| `comp_with_name` / `comp_with_version` (NTIA) | `Component.name` / `Component.version`, proportional `10·have/total` | exact |
| `comp_with_uniq_ids` (NTIA) | Non-empty **local id** (`identifiers.format_id`: bom-ref / SPDXID) — `compWithUniqIDCheck` semantics, NOT purl/cpe (that is the BSI variant) | exact |
| `comp_with_supplier` (NTIA) | `Component.supplier.name`; for SPDX also the author field (this model maps the SPDX originator there, mirroring sbomqs' originator fallback) | approximate |
| `sbom_creation_timestamp` (NTIA) | `DocumentMetadata.created` (epoch sentinel = missing/unparseable) | approximate (a document genuinely claiming 1970-01-01 reads as missing) |
| `sbom_authors` (NTIA) | `DocumentMetadata.creators` non-empty (sbomqs counts authors **plus** tools; `creators` carries both) | exact |
| `sbom_dependencies` (NTIA) | Binary: ≥ 1 edge from the **primary component** (verbatim `sbomWithDepedenciesCheck` — not arbitrary edges) | exact |
| `sbom_required_fields` (Semantic) | Blended doc+package formula, quirks preserved: `!docOK → 0.0`; `docOK && all pkgs → 10.0`; else `(10 + 10·have/total)/2` (5.0 for a docOK zero-component SBOM). Doc/pkg sub-checks approximated where the model keeps less than sbomqs reads (CDX `bomFormat`/dependency-refs, SPDX `downloadLocation`/verification code are not modeled) | approximate (fractional formula exact; sub-checks approximate) |
| `comp_with_licenses` / `comp_with_checksums` (Semantic) | `Component.licenses` (NOASSERTION/NONE excluded, as sbomqs does) / `Component.hashes`, proportional | exact |
| `comp_valid_licenses` (Quality) | Mean over ALL components of per-component ratios `(SPDX-listed ids / total license ids)·10`; license-less components contribute 0. v1 counts **only SPDX-list membership** (`l.Spdx()`) — `LicenseRef-*`/custom ids do NOT count | approximate (expression tokenization + `spdx` crate list vs sbomqs' embedded list; `WITH` exception ids dropped) |
| `comp_with_primary_purpose` (Quality) | `ComponentType` display string vs sbomqs' per-spec purpose lists (CDX list lacks e.g. `machine-learning-model`) | approximate (typed model defaults missing purpose to Library → over-counts) |
| `comp_with_deprecated_licenses` / `comp_with_restrictive_licenses` (Quality) | Inverted proportional `10·(total−affected)/total`; 0.0 + "no licenses found" when the SBOM has no licenses. Deprecated = SPDX-list flag; restrictive ≈ copyleft flag (sbomqs uses AboutCode "copyleft/restricted" categories) | approximate |
| `comp_with_any_vuln_lookup_id` / `comp_with_multi_vuln_lookup_id` (Quality) | `identifiers.purl` OR/AND `identifiers.cpe` | exact |
| `sbom_with_creator_and_version` (Quality) | Tool creators with a digit-bearing trailing token as version (the same heuristic sbomqs applies to SPDX tool strings); zero tools replicate sbomqs' `0/0 → NaN → 0.0` coercion | approximate |
| `sbom_with_primary_component` (Quality) | `primary_component_id` present | exact |
| `sbom_sharable` (Sharing) | Quirk-faithful 0.0: sbomqs v2.0.11's vendored SPDX list carries **no** `isFreeAnyUse` flags, so every SPDX-listed document license — including `CC0-1.0` — counts non-free and the check scores 0.0 for essentially every real document. Only AboutCode "Public Domain"-category ids absent from the SPDX list would score 10 there (not replicable without its data — disclosed in the description) | exact for practical inputs; **ignored + reason** when the raw text is unavailable |

Component enumeration parity: SPDX file/snippet components and CycloneDX
service components are excluded from every per-component denominator and
from `num_components`, because sbomqs enumerates SPDX *packages* and CDX
components only. Side effect: an SPDX package whose purpose is
SOURCE/ARCHIVE/FILE is also excluded (the typed model collapses those into
`ComponentType::File`).

Other categories of this repo's 0-100 pipeline map onto sbomqs territory
only loosely (completeness → NTIA + Semantic; identifiers → the Quality
vuln-lookup features; licenses → Semantic/Quality license features;
integrity → `comp_with_checksums`; provenance → `sbom_authors`/timestamp/
creator) — the mapping is feature-level, never score-level.
