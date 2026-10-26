# Standards Support Improvement Plan: CycloneDX 1.7 + SPDX 3.0

> **Status: implemented.** CycloneDX 1.7 and SPDX 3.0 (JSON-LD) support has
> since shipped — the parser today handles CycloneDX 1.4–1.7 (JSON/XML) and
> SPDX 2.2/2.3 (JSON, tag-value, RDF/XML) plus SPDX 3.0 via a separate
> `src/parsers/spdx3.rs`. This document is retained as the historical plan;
> statements below about "current" parser capabilities describe the state
> before implementation. The status section immediately below is the
> authoritative "what is supported today" summary.

## Standards support status

Verified 2026-07-31 against `sbom-tools 0.1.22` (binary, not source reading
alone). Edition pins, citations and caveats for every compliance profile live
in [`STANDARDS_VERSIONS.md`](STANDARDS_VERSIONS.md).

### Formats — shipped

CycloneDX 1.4/1.5/1.6/1.7 (JSON, XML), SPDX 2.2/2.3 (JSON, tag-value,
RDF/XML) and SPDX 3.0 (JSON-LD), per `sbom-tools --version`.

The Part 1 model work also landed: CycloneDX `citations` preserved in the
format extensions plus `DocumentMetadata.citations_count`, the TLP
distribution constraint in `DocumentMetadata.distribution_classification`,
`Component.is_external` / `Component.version_range`,
`HashAlgorithm::Streebog256`/`Streebog512`, and the `Citation` / `Patent` /
`PatentAssertion` / `PatentFamily` external-reference types.

Two deviations from Part 2's model plan are worth knowing:

- SPDX 3.0 `profileConformance` is surfaced through
  `DocumentMetadata.distribution_classification` — there is no dedicated
  `profile_conformance` field.
- There is no `root_elements` list; the first resolvable `rootElement`
  (following at most one collection indirection) becomes
  `primary_component_id`.

### Compliance profiles — 16 shipped (was 13)

`sbom-tools validate --standard` accepts exactly `ntia`, `fda`, `cra`,
`cra-phase1`, `ssdf`, `eo14028`, `cnsa2`, `pqc`, `bsi`, `oss-steward`,
`eucc`, `ai-act`, `bsi-ai`, `cisa-2026`, `pci-dss`, `fsct` (plus the aliases
listed in `--help`). Any other value is a clap usage error — exit code 3,
before any SBOM is parsed.

Three of those shipped on 2026-07-30 (commit `b0e533b`), taking the count
from 13 to 16:

| Profile | Aliases (each verified to resolve) | Rules |
|---|---|---|
| `cisa-2026` | `cisa`, `cisa2026`, `minimum-elements-2026` | 17 `SBOM-CISA2026-*` (+ the `SBOM-CISA2026-GENERAL` fallback id) |
| `pci-dss` | `pci`, `pci-dss-6-3-2`, `pci-dss-4` | 10 — 9 × `SBOM-PCI-6-3-2-*` plus `SBOM-PCI-11-3-1-1-SEVERITY` (+ `SBOM-PCI-GENERAL`) |
| `fsct` | `fsct-3`, `component-transparency` | 27 `SBOM-FSCT-*` (+ `SBOM-FSCT-GENERAL`) |

CISA published the **final** "2026 Minimum Elements for an SBOM" v2.1 on
2026-07-29; `cisa-2026` targets that final text, not the August 2025 draft
(which was v2.0 of the same document). It is deliberately stricter than the
`ntia` profile — a tool-only creator list does not satisfy SBOM Author, while
an explicit `NOASSERTION`-style marker satisfies the elements whose 2026 text
provides an escape hatch. `pci-dss` evidences that a Req. 6.3.2 inventory
exists and is usable; it is not a PCI DSS compliance certification. `fsct`
maps the third edition's maturity tiers onto severities (Minimum Expected →
Error, Recommended Practice → Warning, Aspirational → Info).

CycloneDX 1.6 CDXA `declarations` are consumed as evidence by the existing
SSDF / CRA / EUCC / EO 14028 rules; every pre-existing satisfaction path
remains valid as a self-declared fallback, and documents without
`declarations` are unaffected.

### Not implemented

- **Attestation phase 2** — ingestion of external in-toto / DSSE bundles
  (SLSA provenance/VSA, test-result, vulns predicates) referenced from an
  SBOM. Phase 1 covers in-document CDXA only, and signatures are recorded as
  *present*, never cryptographically verified.
- **METI, OpenChain Telco SBOM, NIST SP 800-161r1** — no profile exists;
  `--standard` rejects those names with exit 3. They were never in scope for
  this document, which covers format support only.

---

## Executive Summary

This plan covers adding CycloneDX 1.7 and SPDX 3.0 support to sbom-tools. These are
fundamentally different in scope: CycloneDX 1.7 is an **incremental, additive update**
from 1.6 (no breaking changes, ~2-3 weeks of work), while SPDX 3.0 is a **ground-up
redesign** requiring a new parser, model adaptations, and careful normalization (~6-8
weeks). The existing architecture's format-agnostic canonical model makes both feasible
without disrupting the diff/matching/quality/enrichment layers.

---

## Part 1: CycloneDX 1.7

### Difficulty: Low-Medium (Incremental)

CycloneDX 1.7 (published October 2025) is backward-compatible with 1.6. All changes are
additive: new fields, new top-level elements, and some structural relaxations. The existing
serde-based parser handles unknown fields gracefully via `Option<T>`, so 1.7 documents
already parse today -- they just lose the new fields.

### Phase 1.1: Parser Updates (cyclonedx.rs)

**Effort: ~3 days**

1. **Add "1.7" to `supported_versions()`**
   - File: `src/parsers/cyclonedx.rs`
   - Trivial: add `"1.7"` to the returned vec

2. **New serde structs for 1.7 fields:**

   ```
   // Top-level citations array
   struct CdxCitation {
       bom_ref: Option<String>,
       pointers: Option<Vec<String>>,      // JSON Pointer (RFC 6901)
       expressions: Option<Vec<String>>,   // JSONPath/XPath
       timestamp: String,                  // Required
       attributed_to: Option<String>,      // bom-ref to entity
       process: Option<String>,            // bom-ref to formulation
       note: Option<String>,
       signature: Option<CdxSignature>,
   }

   // Distribution constraints on metadata
   struct CdxDistributionConstraints {
       tlp: Option<TlpClassification>,     // CLEAR/GREEN/AMBER/AMBER_AND_STRICT/RED
   }

   // License expression details (1.7 relaxation)
   struct CdxExpressionDetail {
       license_identifier: String,
       bom_ref: Option<String>,
       text: Option<CdxAttachment>,
       url: Option<String>,
   }
   ```

3. **Extend existing structs:**
   - `CycloneDxBom`: add `citations: Option<Vec<CdxCitation>>`
   - `CdxMetadata`: add `distribution_constraints: Option<CdxDistributionConstraints>`
   - `CdxComponent`: add `is_external: Option<bool>`, `version_range: Option<String>`,
     `patent_assertions: Option<serde_json::Value>` (preserve but don't deeply parse)
   - `CdxExternalReference`: add `properties: Option<Vec<CdxProperty>>`

4. **License array parsing change:**
   - 1.7 moves the `oneOf` from array-level to item-level, allowing mixed license+expression entries
   - Current `deserialize_licenses` needs to handle both 1.6 (array-level oneOf) and 1.7 (item-level oneOf)
   - Since serde already tries each variant per-item, this may already work; needs testing

5. **New hash algorithms:**
   - Add `Streebog256` and `Streebog512` variants to `HashAlgorithm` enum
   - Already has `Other(String)` fallback, but named variants are better for quality scoring

### Phase 1.2: Model Extensions

**Effort: ~2 days**

1. **DocumentMetadata additions:**
   - Add `distribution_classification: Option<String>` (TLP value)
   - Add `citations_count: usize` (how many citations present -- useful for quality scoring)

2. **Component additions:**
   - Add `is_external: Option<bool>` to `Component` struct
   - Add `version_range: Option<String>` to `Component` struct
   - These are format-agnostic concepts (SPDX 3.0 has similar `supportLevel` on Artifact)

3. **FormatExtensions:**
   - Store full `citations` array in `FormatExtensions::cyclonedx` for lossless round-trip
   - Store patent assertions similarly (domain-specific, not worth canonical modeling yet)

4. **HashAlgorithm enum:**
   - Add `Streebog256`, `Streebog512` variants
   - Update `Display`, `from_str`, quality scoring hash strength classification

5. **ExternalRefType enum:**
   - Add `Citation`, `Patent`, `PatentAssertion`, `PatentFamily` variants

### Phase 1.3: Quality & Compliance Updates

**Effort: ~2 days**

1. **Quality scoring:**
   - Provenance category: award bonus points for documents with `citations` (data provenance)
   - Integrity category: recognize Streebog hash algorithms
   - `check_format_specific()`: update CycloneDX version warning threshold (< 1.5 instead of < 1.4)

2. **Compliance updates:**
   - CRA: `citations` provides Art.13(3) provenance evidence; check and report
   - NIST SSDF: citations support PS.1 provenance traceability

3. **CBOM awareness (light touch):**
   - Don't deeply model the crypto property changes (too specialized)
   - Store in `ComponentExtensions::raw` for preservation
   - Quality: detect `component_type == Cryptographic` and check for crypto properties presence

### Phase 1.4: Testing

**Effort: ~2 days**

1. **Fixture files:**
   - Create `tests/fixtures/cyclonedx/minimal-1.7.cdx.json` with citations, is_external, TLP
   - Create `tests/fixtures/cyclonedx/cbom-1.7.cdx.json` with crypto components
   - Create `tests/fixtures/cyclonedx/mixed-licenses-1.7.cdx.json` testing the license relaxation

2. **Unit tests:**
   - Parse 1.7 document, verify citations extracted
   - Parse 1.7 document, verify is_external flag on components
   - Parse 1.7 document, verify TLP distribution constraint
   - Verify 1.4/1.5/1.6 documents still parse identically (regression)
   - Cross-format diff: 1.7 CycloneDX vs SPDX 2.3

3. **Integration tests:**
   - Diff between 1.6 and 1.7 documents (same components, different format versions)
   - Quality scoring of 1.7 document with citations
   - Compliance checking with CRA standard against 1.7 document

### CycloneDX 1.7 -- Total Effort: ~9 days

---

## Part 2: SPDX 3.0

### Difficulty: High (Ground-Up Redesign)

SPDX 3.0 is not an incremental update from 2.3 -- it is a completely new data model.
The flat document structure is replaced by a graph of typed Elements. Relationships are
first-class objects. Vulnerabilities are native (Security profile). Licensing uses
relationships instead of inline properties. The serialization is JSON-LD.

The good news: our canonical model (`NormalizedSbom`) already abstracts away format
differences, so the diff/matching/quality/enrichment layers need minimal changes. The
challenge is entirely in the parser and normalization layer.

### Phase 2.1: Research & Design (Pre-Implementation)

**Effort: ~3 days**

1. **JSON-LD strategy decision:**
   - Option A: Use a JSON-LD library (`json-ld` crate) for full spec compliance
   - Option B: Treat SPDX 3.0 JSON-LD as "JSON with a `@context` field" and parse with serde
   - **Recommendation: Option B** -- SPDX 3.0 JSON-LD is relatively flat in practice;
     full JSON-LD processing (context resolution, graph expansion) is overkill for parsing.
     The `@context` URL just maps short names to RDF URIs. Real-world SPDX 3.0 files use
     the compact JSON-LD form which is structurally regular JSON.

2. **Profile scope decision:**
   - Must support: **Core** (mandatory) + **Software** (packages/files) + **SimpleLicensing**
   - Should support: **Security** (vulnerabilities/VEX -- aligns with existing enrichment model)
   - Defer: AI, Dataset, Build, Lite, Extension, ExpandedLicensing (can be added incrementally)

3. **Relationship mapping design:**
   - SPDX 3.0 has ~80 relationship types vs our 21 `DependencyType` variants
   - Strategy: map known types to existing enum variants, use `Other(String)` for the rest
   - Key new mappings needed: `affects`, `fixedIn`, `foundBy`, `hasAssessmentFor`,
     `hasConcludedLicense`, `hasDeclaredLicense`

### Phase 2.2: New SPDX 3.0 Parser

**Effort: ~8 days**

File: `src/parsers/spdx3.rs` (new file, separate from existing `spdx.rs`)

**Rationale for separate parser:** The data models are so different that trying to share
code between 2.x and 3.0 parsers would create a maintenance nightmare. Better to have
clean separation with shared normalization logic.

1. **Serde models for SPDX 3.0 JSON-LD:**

   ```
   // Top-level document
   struct Spdx3Document {
       context: serde_json::Value,           // @context (JSON-LD, ignored for parsing)
       spdx_id: String,                      // URI
       type_: String,                        // "SpdxDocument"
       name: Option<String>,
       creation_info: Spdx3CreationInfo,
       data_license: Option<String>,         // Always CC0-1.0
       namespace_map: Option<Vec<Spdx3NamespaceMap>>,
       imports: Option<Vec<Spdx3ExternalMap>>,
       root_element: Option<Vec<String>>,    // URIs of root elements
       element: Option<Vec<Spdx3Element>>,   // All elements in the document
       profile_conformance: Option<Vec<String>>,
   }

   // Polymorphic element (uses serde tag)
   #[serde(tag = "type")]
   enum Spdx3Element {
       Package(Spdx3Package),
       File(Spdx3File),
       Snippet(Spdx3Snippet),
       Relationship(Spdx3Relationship),
       Vulnerability(Spdx3Vulnerability),
       Annotation(Spdx3Annotation),
       Person(Spdx3Agent),
       Organization(Spdx3Agent),
       Tool(Spdx3Agent),
       SoftwareAgent(Spdx3Agent),
       Bom(Spdx3Bom),
       Bundle(Spdx3Bundle),
       // Fallback for unknown element types
       #[serde(other)]
       Unknown,
   }

   struct Spdx3Package {
       spdx_id: String,
       name: Option<String>,
       package_version: Option<String>,
       package_url: Option<String>,           // First-class PURL
       download_location: Option<String>,
       home_page: Option<String>,
       copyright_text: Option<String>,
       description: Option<String>,
       supplied_by: Option<Vec<String>>,       // URIs to Agent elements
       originated_by: Option<Vec<String>>,
       verified_using: Option<Vec<Spdx3IntegrityMethod>>,
       external_identifier: Option<Vec<Spdx3ExternalIdentifier>>,
       external_ref: Option<Vec<Spdx3ExternalRef>>,
       primary_purpose: Option<String>,
       additional_purpose: Option<Vec<String>>,
       content_identifier: Option<String>,
       attribution_text: Option<Vec<String>>,
       support_level: Option<String>,
       valid_until_time: Option<String>,
       built_time: Option<String>,
       release_time: Option<String>,
       creation_info: Option<Spdx3CreationInfo>,
   }

   struct Spdx3Relationship {
       spdx_id: String,
       from: String,                          // URI
       to: Vec<String>,                       // URIs (1..*)
       relationship_type: String,
       start_time: Option<String>,
       end_time: Option<String>,
       completeness: Option<String>,
       creation_info: Option<Spdx3CreationInfo>,
   }

   struct Spdx3Vulnerability {
       spdx_id: String,
       name: Option<String>,
       description: Option<String>,
       published_time: Option<String>,
       modified_time: Option<String>,
       withdrawn_time: Option<String>,
       external_identifier: Option<Vec<Spdx3ExternalIdentifier>>,
       external_ref: Option<Vec<Spdx3ExternalRef>>,
   }
   ```

2. **Element resolution pipeline:**
   - First pass: deserialize all elements into typed structs
   - Build element index: `HashMap<String, &Spdx3Element>` (spdx_id URI -> element)
   - Resolve Agent references: look up `supplied_by`/`originated_by` URIs in the index
   - Resolve Relationship targets: look up `from`/`to` URIs in the index

3. **License extraction via relationships:**
   - Find all Relationship elements where `relationship_type` is `hasDeclaredLicense` or `hasConcludedLicense`
   - The `to` target is a license element (LicenseExpression or CustomLicense)
   - Map to existing `LicenseInfo` model

4. **Vulnerability extraction (Security profile):**
   - Find Vulnerability elements
   - Find VulnAssessmentRelationship elements (CVSS, VEX, EPSS, etc.)
   - Map assessment relationships to `VulnerabilityRef` with scoring data
   - Map VEX relationships to `VexStatus`

### Phase 2.3: Format Detection Updates

**Effort: ~2 days**

1. **Detection for SPDX 3.0 vs 2.x:**
   - SPDX 3.0 JSON-LD has `@context` field and `"type": "SpdxDocument"`
   - SPDX 2.x has `spdxVersion: "SPDX-2.x"` at top level
   - Detection confidence:
     - `@context` containing "spdx.org/rdf/3" → CERTAIN for SPDX 3.0
     - `"type": "SpdxDocument"` → HIGH for SPDX 3.0
     - Presence of `spdxVersion` starting with "SPDX-2" → dispatch to existing 2.x parser
   - File: `src/parsers/detection.rs` -- add SPDX 3.0 detection branch

2. **Parser dispatch:**
   - `ParserKind` enum: add `Spdx3` variant (or detect version in Spdx parser and dispatch)
   - **Recommended:** Keep `ParserKind::Spdx` but have the SPDX detection logic route to
     `Spdx3Parser` vs `SpdxParser` based on detected version

3. **Streaming parser:**
   - `src/parsers/streaming.rs` needs SPDX 3.0 format detection in peek buffer
   - Look for `@context` in first 4KB

### Phase 2.4: Normalization (SPDX 3.0 -> NormalizedSbom)

**Effort: ~5 days**

This is the critical translation layer. SPDX 3.0's graph model must map to our flat
`NormalizedSbom` with `components` HashMap + `edges` Vec.

1. **Element-to-Component mapping:**
   - `Spdx3Package` → `Component` (primary mapping)
   - `Spdx3File` → `Component` with `component_type: File`
   - `Spdx3Snippet` → skip or store in extensions (too granular for SBOM diffing)
   - Agent elements → `Creator`/`Organization` (not components)
   - Vulnerability elements → `VulnerabilityRef` (attached to affected components)

2. **Identifier mapping:**
   - `package_url` (first-class in 3.0) → `identifiers.purl`
   - `external_identifier` with type `cpe23` → `identifiers.cpe`
   - `external_identifier` with type `swid` → `identifiers.swid`
   - `spdx_id` URI → `identifiers.format_id`
   - `CanonicalId` uses existing tiered fallback (PURL > CPE > SWID > synthetic)

3. **Relationship-to-Edge mapping:**
   - Relationship elements with dependency-related types → `DependencyEdge`
   - License relationships → populate `Component.licenses` on the `from` component
   - Vulnerability assessment relationships → populate `Component.vulnerabilities`
   - `rootElement` → `primary_component_id`

4. **CreationInfo handling:**
   - Per-element CreationInfo in 3.0 vs document-level in `DocumentMetadata`
   - Strategy: Use SpdxDocument's CreationInfo for `DocumentMetadata.created`/`creators`
   - Store per-element creation info in `ComponentExtensions.annotations` (preserves provenance)

5. **Profile-aware parsing:**
   - Check `profile_conformance` to know which element types to expect
   - If Security profile present, parse Vulnerability + VulnAssessment elements
   - If only Core + Software, skip vulnerability elements gracefully

6. **Handling `NoneElement` and `NoAssertionElement`:**
   - These are SPDX 3.0 sentinel values meaning "explicitly none" vs "unknown"
   - Map to appropriate `None` vs default values in the canonical model

### Phase 2.5: Model Extensions for SPDX 3.0

**Effort: ~3 days**

1. **DependencyType enum -- new variants:**
   ```
   // SPDX 3.0 relationship types that don't map to existing variants
   Affects,                    // Vulnerability → Package
   FixedIn,                    // Vulnerability → Package@version
   FoundBy,                    // Vulnerability → Agent
   HasAssessmentFor,           // VulnAssessment → Vulnerability
   HasConcludedLicense,        // Package → License
   HasDeclaredLicense,         // Package → License
   AmendedBy,                  // Element → Element (modification)
   ConfiguredBy,               // Package → configuration
   CoordinatedBy,              // Vulnerability → Agent
   ExpandedFromArchive,        // File → Package (extraction)
   FileAdded,                  // already exists
   FileDeleted,                // already exists
   HasPrerequisite,            // already mapped via SPDX 2.3
   InvokedBy,                  // Tool → Agent
   PackagedBy,                 // Package → Agent
   ReportedBy,                 // Vulnerability → Agent
   TestedOn,                   // Tool → Package
   TrainedOn,                  // AI model → Dataset
   UnderInvestigationFor,      // VEX → Vulnerability
   UsesTool,                   // Agent → Tool
   ```
   - Most of these won't affect diff/matching (they're vulnerability/agent relationships)
   - Only dependency-related types flow through the diff engine

2. **SbomFormat considerations:**
   - Keep `SbomFormat::Spdx` for both 2.x and 3.0 (same standard family)
   - Distinguish via `format_version` ("2.3" vs "3.0.1")
   - This preserves cross-version diffing without special-casing the format enum

3. **DocumentMetadata additions:**
   - Add `profile_conformance: Vec<String>` (which SPDX 3.0 profiles the document uses)
   - Add `root_elements: Vec<CanonicalId>` (SPDX 3.0 can have multiple root elements)

4. **FormatExtensions:**
   - Store the full `@context` in `FormatExtensions::spdx` for round-trip capability
   - Store unrecognized element types for lossless preservation

### Phase 2.6: Quality & Compliance for SPDX 3.0

**Effort: ~2 days**

1. **Quality scoring adjustments:**
   - Identifiers: SPDX 3.0 has richer `ExternalIdentifier` with typed identifiers;
     award higher scores for documents with typed CPE/PURL/SWHID identifiers
   - Completeness: check `Relationship.completeness` field
   - VulnDocs: if Security profile present, score native vulnerability data
   - Provenance: per-element CreationInfo provides better provenance; score accordingly

2. **Compliance updates:**
   - `check_format_specific()`: add SPDX 3.0 version detection
   - NTIA: SPDX 3.0 satisfies all NTIA minimum elements natively (supplier as typed Agent)
   - CRA: SPDX 3.0's Security profile provides Art.13(9) vulnerability statements
   - EO 14028: SPDX 3.0 format itself satisfies the "machine-readable" requirement

3. **Report generation:**
   - Format version display: show "SPDX 3.0.1" in reports
   - Profile conformance display in summary reports

### Phase 2.7: Testing

**Effort: ~4 days**

1. **Fixture files:**
   - `tests/fixtures/spdx3/minimal.spdx3.json` -- Core + Software only
   - `tests/fixtures/spdx3/with-vulnerabilities.spdx3.json` -- Core + Software + Security
   - `tests/fixtures/spdx3/with-licenses.spdx3.json` -- License relationships
   - `tests/fixtures/spdx3/multi-root.spdx3.json` -- Multiple root elements
   - Source: Generate from SPDX 3.0 examples at https://github.com/spdx/spdx-3-model
     or create manually following the spec

2. **Unit tests (parser):**
   - Parse minimal SPDX 3.0 document
   - Verify element type dispatch (Package, File, Relationship, Vulnerability)
   - Verify license extraction via relationship traversal
   - Verify vulnerability mapping from Security profile
   - Verify Agent resolution for supplier/originator
   - Verify per-element CreationInfo preservation
   - Verify `@context` detection and version routing

3. **Integration tests:**
   - Cross-format diff: SPDX 3.0 vs CycloneDX 1.7 (the key use case)
   - Cross-version diff: SPDX 2.3 vs SPDX 3.0 (same components, different formats)
   - Quality scoring of SPDX 3.0 document
   - Pipeline: parse → enrich → diff → report with SPDX 3.0 input

4. **Regression tests:**
   - All existing SPDX 2.2/2.3 tests must continue passing
   - All existing CycloneDX 1.4-1.6 tests must continue passing
   - Cross-format diff between SPDX 2.3 and CycloneDX 1.6 unchanged

### SPDX 3.0 -- Total Effort: ~27 days

---

## Part 3: Cross-Cutting Concerns

### 3.1: Cross-Format Diffing (SPDX 3.0 <-> CycloneDX 1.7)

**Effort: ~2 days (mostly testing)**

The canonical model already enables this. Both formats normalize to `NormalizedSbom`,
and the diff engine is format-agnostic. The work here is:

1. **Verify CanonicalId stability across formats:**
   - Same PURL in CycloneDX 1.7 and SPDX 3.0 must produce same CanonicalId
   - SPDX 3.0's `packageUrl` (first-class field) should match CycloneDX's `purl` field
   - Test with real-world PURLs (npm, pypi, maven, cargo)

2. **Verify relationship equivalence:**
   - CycloneDX `dependsOn` ↔ SPDX 3.0 `DEPENDS_ON` relationship type
   - Both should produce identical `DependencyEdge` records

3. **Handle metadata differences:**
   - CycloneDX 1.7 `citations` has no SPDX 3.0 equivalent (format-specific)
   - SPDX 3.0 `profileConformance` has no CycloneDX equivalent (format-specific)
   - These should appear in diff as metadata differences, not false positives

### 3.2: Backward Compatibility Guarantees

1. **Parser coexistence:**
   - Existing `SpdxParser` handles 2.2/2.3 (unchanged)
   - New `Spdx3Parser` handles 3.0+ (separate code path)
   - `CycloneDxParser` handles 1.4-1.7 (extended, not replaced)
   - Format detection routes to correct parser automatically

2. **Model backward compatibility:**
   - All new fields on `Component`, `DocumentMetadata` are `Option<T>` (default None)
   - New enum variants are behind `#[non_exhaustive]` (already in place)
   - Serialized output format unchanged for existing fields

3. **CLI backward compatibility:**
   - No new CLI flags needed (format detection is automatic)
   - Existing `--format` hints should work with new versions
   - Reports should display correct format version strings

### 3.3: Documentation

1. **Update README.md** format support table
2. **Update ARCHITECTURE.md** with SPDX 3.0 parser architecture notes
3. **Update CLI help text** for `--format` flag

---

## Implementation Order (Recommended)

### Sprint 1: CycloneDX 1.7 (Week 1-2)
- Phase 1.1: Parser updates
- Phase 1.2: Model extensions
- Phase 1.3: Quality/compliance updates
- Phase 1.4: Testing
- **Ship as PR #1** -- low risk, high immediate value

### Sprint 2: SPDX 3.0 Foundation (Week 3-5)
- Phase 2.1: Research & design decisions
- Phase 2.2: New parser (spdx3.rs)
- Phase 2.3: Format detection updates
- **Ship as PR #2** -- parser + detection only, no model changes yet

### Sprint 3: SPDX 3.0 Integration (Week 6-8)
- Phase 2.4: Normalization pipeline
- Phase 2.5: Model extensions
- Phase 2.6: Quality/compliance
- Phase 2.7: Testing
- Phase 3.1: Cross-format diffing verification
- **Ship as PR #3** -- full integration with tests

### Sprint 4: Polish (Week 9)
- Phase 3.2: Backward compatibility verification
- Phase 3.3: Documentation
- Cross-version regression testing
- **Ship as PR #4** -- docs + final verification

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| SPDX 3.0 JSON-LD has edge cases that break serde parsing | Medium | High | Test against official SPDX 3.0 examples; fall back to json-ld crate if needed |
| Real-world SPDX 3.0 files are rare (low adoption) | High | Low | Create comprehensive fixtures; monitor community adoption |
| SPDX 3.0 spec is still evolving (3.0.1 published) | Medium | Medium | Pin to 3.0.1; design parser to handle minor version bumps |
| CycloneDX 1.7 license structure change breaks existing parsing | Low | Medium | Custom deserializer already handles variant formats; add tests |
| New DependencyType variants break exhaustive matches downstream | Low | Low | Already using `#[non_exhaustive]` + `Other(String)` fallback |
| Performance regression with SPDX 3.0 element graph resolution | Low | Medium | Single-pass element indexing; benchmark against large documents |

---

## Dependencies & Crate Changes

### No new crate dependencies required for CycloneDX 1.7
- Existing `serde`, `serde_json`, `quick-xml` are sufficient

### Potential new dependencies for SPDX 3.0
- **None required** if using Option B (serde-based JSON-LD parsing)
- Consider `json-ld` crate only if real-world files use advanced JSON-LD features
  (context imports, graph expansion, blank nodes) -- unlikely for SPDX 3.0 in practice

### spdx crate (v0.13)
- Currently used only for SPDX license expression parsing, NOT for document parsing
- Does not need updating for SPDX 3.0 document support (license expressions unchanged)
- May need update if ExpandedLicensing profile support is added later

---

## What NOT to Do

1. **Don't merge SPDX 2.x and 3.0 parsers** -- the data models are too different;
   shared code would be a maintenance burden
2. **Don't add full JSON-LD processing** -- real-world SPDX 3.0 files are compact JSON-LD
   that parses as regular JSON; full graph expansion is unnecessary
3. **Don't deeply model CycloneDX CBOM changes** -- crypto property restructuring is
   highly specialized; store in extensions and parse on demand
4. **Don't deeply model SPDX 3.0 AI/Dataset/Build profiles** -- defer until there's
   user demand; the Core + Software + Security profiles cover 95% of use cases
5. **Don't change the canonical model fundamentally** -- the flat
   `HashMap<CanonicalId, Component>` works well; SPDX 3.0's graph model flattens
   naturally into components + edges during normalization
6. **Don't break the `spdx` crate dependency** -- it's used for license expression
   parsing only, which is unchanged in SPDX 3.0
