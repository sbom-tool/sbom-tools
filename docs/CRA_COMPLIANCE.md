# CRA Compliance — Standards Reverse Map

This document maps every compliance check sbom-tools surfaces under
`--standard cra` (and the related Article 24 / BSI / Annex III/IV
profiles) to the underlying regulation, harmonised standard, and
ENISA / industry guidance. Use it to:

- **Auditors / notified bodies**: locate the regulatory text behind each
  finding by Article number or Annex reference.
- **Engineers**: see which sidecar field (`CraSidecarMetadata`), SBOM
  field, or CycloneDX 1.6 [attestation](#attestation-evidence-cyclonedx-16-declarations)
  clears each violation.
- **GRC / dashboards**: cross-reference SARIF `properties.standardIds`
  and `properties.standardHelpUris` to produce control-mapping reports.

> Generated and maintained alongside the sbom-tools source tree.
> If a check or article moves, send a PR — the reverse map is the
> single source of truth for both human readers and the
> `rule_meta()` registry (surfaced via `Violation::registry_standard_refs()`).

## CRA timeline anchors

| Date          | Event                                                         |
|---------------|---------------------------------------------------------------|
| 2024-12-10    | CRA enters into force (Regulation (EU) 2024/2847)                                  |
| 2026-09-11    | Article 14 reporting obligations apply (`ComplianceLevel::CraPhase1`) — Art. 71(2) |
| 2027-12-11    | Regulation applies in full (`ComplianceLevel::CraPhase2`) — Art. 71(2)             |

## Compliance levels

| `ComplianceLevel`           | sbom-tools `--standard` alias                                                                       | Scope                                                                                                            |
|-----------------------------|-----------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------|
| `CraPhase1`                 | `cra-phase1`, `cra-2026`                                                                            | CRA Phase 1 — Art. 14 reporting obligations (apply from 2026-09-11)                                                          |
| `CraPhase2`                 | `cra` (default CRA meaning), `cra-phase2`                                                           | Full CRA compliance (regulation fully applies from 2027-12-11)                                                                        |
| `CraOssSteward`             | `oss-steward`, `cra-oss-steward`, `cra-oss`, `cra-art24`, `art24`                                   | Article 24 lighter profile for open-source software stewards                                                     |
| `BsiTr03183_2`              | `bsi`, `tr-03183`, `tr03183`, `bsi-tr-03183-2`                                                      | BSI TR-03183-2 (German national CRA-aligned baseline)                                                            |
| `Cnsa2`                     | `cnsa2`, `cnsa-2`, `cnsa_2`, `cnsa2.0`                                                              | NSA CNSA 2.0 (post-quantum mandate for US national-security systems, required by CNSSP 15; `--pqc-mode deadline` applies its 2025–2033 timeline) |
| `NistPqc`                   | `pqc`, `nist-pqc`, `nist_pqc`                                                                       | NIST IR 8547 (final, Oct 2026) + FIPS 203/204/205 (PQC migration; `--pqc-mode deadline` applies its 2030/2035 milestones) |

The `--cra-product-class` flag (or sidecar `productClass`) drives the
[CRA-P3.2 calibration table](#cra-p32-product-class-severity-calibration)
that scales severity for vendor-hash, EOL, cycles, DoC, EUCC, PSIRT,
and module-certificate checks of `CraPhase1` and `CraPhase2`.

Every command that checks compliance (`validate`, `quality`, `view` and
`diff` with their TUIs, `cra-docs`) hands each profile the same inputs:
the CRA sidecar reaches the CRA, OSS-steward, EUCC and EU AI Act profiles,
the product class reaches the two CRA phases only, and the PQC flags
(`--pqc-mode`, `--pqc-profile`, `--cnsa-category`) reach the CNSA 2.0 and
NIST PQC profiles only. The Article 24
steward profile gets the sidecar without its `productClass` and
`conformityAssessmentRoute`: the class picks a manufacturer's
conformity-assessment procedure (Art. 32), which a steward does not
follow. See [Inputs of a run](compliance-output.md#inputs-of-a-run).

## Reverse map

Each row maps a sbom-tools `Violation::requirement` string to its
regulatory anchor, the harmonised-standard requirement ID
(prEN 40000-1-3 where known), the BSI section, and the canonical URL
that ends up in SARIF `properties.standardHelpUris`.

The SBOM-content rules also cite the ENISA Technical Advisory for Software
Bill of Materials (v1.10, 22 October 2026), after their CRA and prEN
references. Its data model (§2.1.1) backs the creator, document
identifier, component name, version, supplier, identifier, hash, licence
and dependency rules; its formats (§2.1.2) the machine-readable format
rule; its signing step (§2.2.1) the document-integrity rule; and its risk
table (§3.2) the freshness, identifier and traceability rules.
[STANDARDS_VERSIONS.md](STANDARDS_VERSIONS.md) lists the rules. The
advisory is guidance: it says it does not "create or modify any legal,
regulatory, or compliance obligations", so these references change no
check.

### CRA Article 13 (essential requirements & SBOM-related obligations)

> Rule citations were re-anchored in 2026-07: the SBOM-facing checks now
> cite the paragraphs and Annex points that actually carry each
> obligation in Reg. (EU) 2024/2847 (e.g., the machine-readable SBOM
> mandate lives in Annex I Part II (1), the vulnerability-reporting
> contact in Art. 13(17), and manufacturer identification in
> Art. 13(16)). The BSI column uses TR-03183-2 v2.1.0 numbering.

| Requirement string                                              | CRA anchor                        | prEN 40000-1-3      | BSI TR-03183-2 § | sidecar field that clears it                              |
|-----------------------------------------------------------------|-----------------------------------|---------------------|------------------|-----------------------------------------------------------|
| `CRA Art. 13(2): Documented risk assessment`                    | Art. 13(2)                        | —                   | —                | `riskAssessmentUrl` (or a `risk-assessment` external reference) |
| `CRA Art. 13(7) / Annex I Part II (1): SBOM freshness`          | Art. 13(7); Annex I Part II (1)   | PRE-7-RQ-04         | §3.1             | regenerate SBOM on each release                           |
| `CRA Annex I Part II (1): Machine-readable SBOM format`         | Annex I Part II (1)               | PRE-7-RQ-04         | §4               | parse-time check (CycloneDX 1.4+ / SPDX 2.3+)             |
| `CRA Art. 13(5): Third-party due diligence (license tracking)`  | Art. 13(5)                        | PRE-7-RQ-05         | §5.2.2           | populate component `license` fields                       |
| `CRA Art. 13(17): Vulnerability disclosure contact`             | Art. 13(17); Annex I Part II (6); Annex II (2) | RLS-2-RQ-01 | §5.2.5 (opt.) | `securityContact` / `vulnerabilityDisclosureUrl` (or a security-contact, advisories or support reference on the product, see [manufacturer evidence](#manufacturer-evidence)) |
| `CRA Annex I Part II (5): Coordinated vulnerability disclosure policy` | Annex I Part II (5); Art. 13(8) | RLS-2-RQ-02      | —                | `coordinatedDisclosurePolicyUrl` (or an advisories reference on the product; a support link does not count) |
| `CRA Art. 13(8): Support period / lifecycle management`         | Art. 13(8)                        | PRE-7-RQ-06         | —                | `supportEndDate` + EOL enrichment                         |
| `CRA Art. 13(8) / 13(19): Support period disclosure`            | Art. 13(8); Art. 13(19); Annex II (7) | PRE-7-RQ-06     | —                | `supportEndDate`                                          |
| `CRA Annex I Part II (1): Documented vulnerability information` | Annex I Part II (1)               | RLS-2-RQ-04         | —                | embedded vulnerabilities (or OSV / KEV / VEX enrichment), or a `vulnerability-assertion` / `exploitability-statement` external reference |
| `CRA Annex II (7): Component lifecycle monitoring/status`       | Art. 13(8); Annex II (7)          | PRE-7-RQ-06         | —                | EOL enrichment + transitive supplier coverage             |
| `CRA Art. 13(15): Product identification`                       | Art. 13(15); Annex II (3)         | PRE-7-RQ-06         | §5.2.2           | SBOM `metadata.component.name` + sidecar `productName`    |
| `CRA Annex I Part II (1): Component version`                    | Annex I Part II (1)               | PRE-7-RQ-06         | §5.2.2           | component `version` fields                                |
| `CRA Annex I Part II (1): Component supplier information`       | Annex I Part II (1)               | PRE-7-RQ-03         | §5.2.2           | component `supplier` fields                               |
| `CRA Annex I Part II (4): Vulnerability metadata completeness`  | Annex I Part II (4)               | —                   | —                | vulnerability severity/CVSS + remediation detail, or a [justified VEX `not_affected` statement](#vex-not_affected-statements) |
| `CRA Art. 13(16): Manufacturer identification`                  | Art. 13(16); Annex II (1)         | —                   | §5.2.1           | `manufacturerName` + `manufacturerEmail` (or, in the SBOM, an organization creator or the product's manufacturer or supplier, see [manufacturer evidence](#manufacturer-evidence)) |

#### VEX `not_affected` statements

The two per-vulnerability Annex I Part II (4) checks, severity or CVSS
(`SBOM-CRA-VULN-METADATA`) and remediation detail
(`SBOM-CRA-VULN-METADATA-REMEDIATION`), skip a vulnerability whose own VEX
statement is `not_affected` and names a justification: CycloneDX
`analysis.justification`, OpenVEX `justification` or SPDX 3.0
`justificationType`. The Commission services' CRA FAQ (version 1.4, 4
September 2026) does not ask for a patch for every vulnerability (FAQ
4.3.1): "When discovering a vulnerability, manufacturers are expected to
determine its relevance for their product, and assess the resulting risk,
in the framework of the manufacturer's risk assessment." Its example is a
Wi-Fi router whose library has a buffer overflow that "cannot be exploited,
as the library functions are never called in the firmware. The
manufacturer may be expected, for example, to document the vulnerability,
but may decide not to fix it with a dedicated update." FAQ 4.2.2 lists what
that case-by-case assessment weighs: "the extent to which the vulnerable
code is invoked or loaded when the product is in use; the level and type of
access required to carry out the exploit; whether compensating controls are
already in place to mitigate exploitation". A VEX justification records
that reason, and Annex I Part II (4) concerns "fixed vulnerabilities". The
FAQ does not mention VEX.

A bare `not_affected` claim does not count, nor does an impact statement or
`detail` text without a justification, a justification on any other state,
or a statement on another vulnerability of the same component (the
component-level VEX status sums up all of a component's statements). Every
CycloneDX justification counts: the SBOM parser and the reader of a
CycloneDX VEX document passed with `--vex` map all nine the same way, each
to the closest of the five model justifications (see the table below). The
CSAF reader ignores `flags` and `threats`, so a CSAF `known_not_affected`
entry does not count yet. Before v0.4.0 every unrated vulnerability warned.
Sources: the FAQ as
the Commission's Markdown conversion
(<https://ec.europa.eu/newsroom/dae/redirection/document/123307>) and PDF
(<https://ec.europa.eu/newsroom/dae/redirection/document/122331>).

| CycloneDX `analysis.justification` (schema 1.6/1.7 definition) | Model justification (CISA, OpenVEX, SPDX 3.0) |
|---|---|
| `code_not_present` ("The code has been removed or tree-shaked.") | `VulnerableCodeNotPresent` |
| `code_not_reachable` ("The vulnerable code is not invoked at runtime.") | `VulnerableCodeNotInExecutePath` |
| `requires_configuration`, `requires_dependency`, `requires_environment` (exploitability requires an option, a dependency or an environment that is not there) | `VulnerableCodeCannotBeControlledByAdversary` |
| `protected_at_perimeter` ("Attacks are blocked at physical, logical, or network perimeter.") | `VulnerableCodeCannotBeControlledByAdversary`: the protection is outside the product |
| `protected_by_compiler` ("Exploitability requires a compiler flag to be set/unset."), `protected_at_runtime` ("Exploits are prevented at runtime."), `protected_by_mitigating_control` ("Preventative measures have been implemented …") | `InlineMitigationsAlreadyExist` |

The `detail` text becomes the statement's impact statement (and its
detail) in either path; it is no justification.

### CRA Article 14 (reporting obligations, applicable from 2026-09-11)

| Requirement string                                          | CRA Article    | prEN 40000-1-3      | sidecar field                         |
|-------------------------------------------------------------|----------------|---------------------|---------------------------------------|
| `CRA Art. 14: PSIRT contact for external vulnerability reports` | Art. 14    | RLS-2-RQ-03         | `psirtUrl`                            |
| `CRA Art. 14(2)(a): 24-hour early-warning channel`          | Art. 14(2)(a) / 14(4)(a) | RLS-2-RQ-03 | `earlyWarningContact`                 |
| `CRA Art. 14(2)(b): 72-hour notification channel`           | Art. 14(2)(b) / 14(4)(b) | RLS-2-RQ-03 | `incidentReportContact`               |
| `CRA Art. 14(7): ENISA single reporting platform`           | Art. 14(7)     | RLS-2-RQ-03-RE      | `enisaReportingPlatformId` (the CSIRT designated as coordinator is enough) |

Pre-deadline findings are emitted as `Info`; post-deadline they become
`Warning` (or `Error` at `ImportantClass2`/`Critical` per the
[product-class calibration](#cra-p32-product-class-severity-calibration)).
The 2026-09-11 deadline is compared against the *evaluation instant* — the
wall clock by default, or `--as-of <RFC 3339>` for reproducible CI runs.

Art. 14(7) follows the same dates — `Info` before 2026-09-11, `Warning` from
then on — but is never escalated to `Error`, at any product class. Art.
14(1) and (3) require every notification "via the single reporting platform
established pursuant to Article 16", and Art. 14(7) through "the electronic
notification end-point of the CSIRT designated as coordinator of the Member
State where the manufacturers have their main establishment"; Art. 14
applies from 11 September 2026 (Art. 71(2)), the day ENISA launched the
platform ("The CRA Single Reporting Platform is launched", ENISA, 11
September 2026, <https://www.enisa.europa.eu/cra-srp/>; portal
<https://portal.cra-srp.enisa.europa.eu/>).

Naming the CSIRT designated as coordinator in `enisaReportingPlatformId`
satisfies the finding. Do not register on the platform early to clear it:
no registration is needed before a notification is due. The CRA names no
manufacturer identifier on the platform, and ENISA's SRP FAQ (updated 15
October 2026,
<https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp/frequently-asked-questions>)
advises manufacturers "to register and initiate the validation process
only when they need to submit a notification" (FAQ 9). It makes them
"responsible for identifying the correct CSIRT designated as coordinator
(CDaC) in accordance with Art. 14(7) of the CRA and selecting it when
submitting a notification through the SRP" (FAQ 18), in general the CSIRT
of the Member State of the main establishment. A registration already made
may be recorded instead. Before v0.4.0 the finding was `Info` on both sides
of the deadline.

### CRA Annexes

| Requirement string                                          | CRA Annex                | prEN 40000-1-3      | What clears it                                          |
|-------------------------------------------------------------|--------------------------|---------------------|---------------------------------------------------------|
| `CRA Annex I Part II / prEN 40000-1-3 [PRE-7-RQ-07-RE]: Vendor hash carry-through` | Annex I Part II | PRE-7-RQ-07-RE | a [valid](#hash-values) hash on vendor-supplied components |
| `CRA Annex I / prEN 40000-1-3 [PRE-7-RQ-07]: Unique component identifier` | Annex I         | PRE-7-RQ-07         | PURL / CPE / SWID / SWHID on each component             |
| `CRA Annex I Part II: Supply chain transparency`            | Annex I Part II          | PRE-7-RQ-01,03      | supplier on direct + transitive deps                    |
| `CRA Annex I Part I (2)(f): Document signature/integrity`   | Annex I Part I (2)(f)    | —                   | serial number / digital signature / attestation hash    |
| `CRA Annex I Part I (2)(f): Component integrity information (hash)` | Annex I Part I (2)(f) | —                | a [valid](#hash-values) cryptographic hash (SHA-256+) per component |
| `CRA Annex IV: EUCC reference (Common Criteria certificate)`| Annex IV                 | —                   | sidecar EUCC evidence fields, a `Certification`/`Attestation` external ref with `eucc`/`common-criteria` URL, or a [CDXA attestation](#attestation-evidence-cyclonedx-16-declarations) naming EUCC / Common Criteria |
| `CRA Annex VII: Technical documentation`                    | Annex VII                | —                   | run `sbom-tools cra-docs <sbom> --output dossier/`     |
| `CRA Annex V: EU Declaration of Conformity reference`       | Annex V                  | —                   | `Attestation`/`Certification` external ref OR `ceMarkingReference` |
| `CRA Annex VIII: <Module> certificate reference`            | Annex VIII (Module B+C/H/EUCC) | —             | `Certification` external ref (the notified-body or certification-body certificate; an `Attestation` ref does not count) |
| `CRA prEN 40000-1-3 [PRE-8-RQ-02]: Hardware component inventory` | Annex I Part II   | PRE-8-RQ-02         | producer + identifier + firmware version on hardware    |

The generic checks that the CRA profiles share with the other standards —
the SBOM creator (`SBOM-CRA-CREATOR`), a document identifier
(`SBOM-CRA-SERIAL`), component names (`SBOM-CRA-COMPONENT-NAME`), a spec
version sbom-tools reads (`SBOM-CRA-SPEC-VERSION`,
`SBOM-CRA-SPEC-VERSION-UNKNOWN`), element identifiers
(`SBOM-CRA-ELEMENT-ID`) and one entry per component
(`SBOM-CRA-DUPLICATE-COMPONENT`, an Info since v0.4.0) — cite Annex I Part II
(1), the clause that asks for an SBOM of the product's components in a
machine-readable format. They cited no clause before v0.4.0, so their
findings carried no reference and no `help_uri`. A component the document
lists more than once is merged into one before any check reads it (see
[Duplicate components](compliance-output.md#duplicate-components)).

External-reference types. The `Attestation`, `Certification`,
`RiskAssessment`, `VulnerabilityAssertion` and `ExploitabilityStatement`
references these checks read come from CycloneDX
`externalReferences[].type` `attestation`, `certification-report`,
`risk-assessment`, `vulnerability-assertion` and `exploitability-statement`,
and from SPDX 3.0 `externalRef[].externalRefType` `secureSoftwareAttestation`,
`certificationReport`, `riskAssessment`, `vulnerabilityDisclosureReport` and
`vulnerabilityExploitabilityAssessment`. SPDX 2.3 has no external-reference
category for any of them (its OTHER category with a
`declaration-of-conformity` type is still read as an Annex V reference).
Before v0.4.0 the parsers did not map these types, so only the sidecar keys
and CDXA attestations could satisfy the checks.

Annex VIII is stricter than Annex V. A route beyond Module A rests on
notified-body or certification-body evidence — the EU-type examination
certificate (Module B+C), the quality-system approval (Module H) or the EUCC
certificate — so `SBOM-CRA-ANNEX-VIII` and the `conformity_summary` Module B
and Module H rows accept only a `Certification` reference
(`certification-report`, SPDX 3.0 `certificationReport`). An `Attestation`
reference may be a self-attestation: it still serves as the Annex V
Declaration of Conformity reference (and the Module C production-conformity
statement), but not as the route's certificate.

### Manufacturer evidence

The checks that ask for the manufacturer's own evidence read it from the
product only: the components the document describes. That is the primary
component (CycloneDX `metadata.component`, SPDX 2 `documentDescribes` or a
`DESCRIBES` relationship, SPDX 3 `rootElement`), plus every other product an
SPDX document describes. A dependency's references never count, even when
the dependency is in no dependency relationship: generators copy a
third-party library's own advisories, support URL or certificate from its
registry metadata, and a sparse `dependencies` section leaves the library
without an incoming edge. Only a document that names no product falls back
to the roots of its dependency graph (or, when the graph is fully cyclic, to
every component).

This scope applies to the security contact (Art. 13(17)), the CVD policy
(Annex I Part II (5)), the risk assessment (Art. 13(2)), the EU Declaration
of Conformity (Annex V), the module certificate (Annex VIII), the EUCC
reference (Annex IV and `SBOM-EUCC-CERTREF`), the Art. 24 steward floors,
the `conformity_summary` rows and `SBOM-EO14028-DISCLOSURE`. Before v0.4.0
every component without an incoming edge counted, and the DoC, risk
assessment, certificate and EUCC checks read every component.

The manufacturer (Art. 13(16), and the FDA device manufacturer) is named by
any of:

- an organization creator of the SBOM with a real name or email address
  (CycloneDX `metadata.manufacturer`, SPDX `Organization:` creator, SPDX 3
  `createdBy` organization);
- the supplier of the product, CycloneDX `metadata.supplier`;
- the manufacturer or supplier of a described component: CycloneDX
  `metadata.component.manufacturer` (where CycloneDX 1.6 moved the
  deprecated `metadata.manufacture`) or `metadata.component.supplier`, the
  SPDX 2 described package's `supplier`, the SPDX 3 root package's
  `suppliedBy`.

Placeholders such as `NOASSERTION`, `TBD` or `unknown` name nobody. The
sidecar `manufacturerName` still lowers the finding to Info. Before v0.4.0
only an organization creator (with any name) or the sidecar counted.

The document's vulnerability-disclosure URL, which the CVD policy, EO 14028
disclosure and PCI DSS checks read, comes from one rule in every format: the
primary component's first advisories reference whose locator is a URL
(`http://`, `https://` or `mailto:`) — CycloneDX `advisories`, SPDX 2
SECURITY `advisory`, SPDX 3 `securityAdvisory`. A support reference never
becomes the disclosure URL: a helpdesk is not a disclosure policy. Before
v0.4.0 the CycloneDX parser also took a support link or any locator, and the
SPDX 3 parser took nothing, so the same content passed in one format and
failed in another.

### Hash values

A hash counts only when its value can be the algorithm's digest: hexadecimal
digits (either case), as many as the algorithm's output has — MD5 32, SHA-1
40, SHA-224 56, SHA-256, SHA3-256, BLAKE2b-256 and Streebog-256 64, SHA-384,
SHA3-384 and BLAKE2b-384 96, SHA-512, SHA3-512, BLAKE2b-512 and Streebog-512
128 — and at least one for BLAKE3 or an unknown algorithm. Every hash rule
of every standard applies this, from the CRA integrity and vendor-hash
checks to the BSI SHA-512 gate, FDA, FSCT, CISA 2026, EO 14028, SSDF and the
BSI SBOM-for-AI hash elements. An empty, non-hex or wrong-length value does
not count, and the finding says why, e.g. "SHA-512 digest is not 128 hex
characters". Before v0.4.0 only CISA 2026 checked the value, and only for
hex digits. An empty CycloneDX XML `<hash>` element now parses as an empty
digest instead of failing the whole document.

### Article 24 — open-source software steward floor

| Requirement string                                          | CRA reference  | Cleared by                                            |
|-------------------------------------------------------------|----------------|-------------------------------------------------------|
| `CRA Art. 24: Vulnerability-handling process (steward floor)` | Art. 24      | `SecurityContact` / `Advisories` / `VulnerabilityAssertion` external ref OR `psirtUrl` / `vulnerabilityDisclosureUrl` |
| `CRA Annex I Part II (5): Coordinated vulnerability disclosure policy` (relaxed to Warning under steward) | Annex I Part II (5) | `Advisories` external ref OR `coordinatedDisclosurePolicyUrl` |

Article 24 *suppresses* manufacturer-only checks (Art. 13(16) email,
Annex V DoC, Annex VIII certificate, Article 14 channels, hardware
[PRE-8-RQ-02], vendor-hash carry-through). The steward profile takes no
product class either: its results carry no `conformity_summary`, and
`SBOM-CRA-CYCLES` stays a Warning whatever the class (before v0.4.0 a
sidecar `productClass` reached it). `sbom-tools rules --standard
oss-steward` lists the 15 rules the steward profile checks. The
vulnerability-handling gate (`SBOM-CRA-ART-24`) cites Art. 24, with the
EUR-Lex URL of the other CRA references; before v0.4.0 it cited nothing, so
its findings had no reference and no `help_uri`.

## CRA-P3.2 product-class severity calibration

When `--cra-product-class` (or sidecar `productClass`) is set, the
severity of certain CRA Phase 1 and Phase 2 checks scales per Annex
III/IV class. Selecting a class also implies a default
conformity-assessment route (Annex VIII), overridable via sidecar
`conformityAssessmentRoute`. The OSS-steward profile ignores both.

The classes are those of the CRA: `important-class-1` is Annex III class I
(19 product categories, from identity management systems and browsers to
operating systems, routers and connected toys), `important-class-2` is
Annex III class II (hypervisors and container runtimes, firewalls and
intrusion detection/prevention systems, tamper-resistant microprocessors
and microcontrollers), and `critical` is Annex IV (hardware devices with
security boxes, smart meter gateways, smartcards and secure elements).
Whether a product falls into a category follows from its core
functionality (Art. 7(1), 8(1)) and from **Commission Implementing
Regulation (EU) 2025/2392** of 28 November 2025 on the technical
description of the categories of important and critical products with
digital elements (OJ L, 2025/2392, 1.12.2025;
<https://eur-lex.europa.eu/eli/reg_impl/2025/2392/oj/eng>), adopted under
Art. 7(4): its Annex I describes the class I and class II categories, its
Annex II the critical ones. sbom-tools does not classify a product; pick
the class from those descriptions.

| Check                          | Default | Important-1 | Important-2 | Critical |
|--------------------------------|---------|-------------|-------------|----------|
| Vendor-hash coverage threshold | 50%     | 80%         | 80%         | 100%     |
| Vendor-hash severity           | Warning | Warning     | Error       | Error    |
| EOL components                 | Warning | Warning     | Error       | Error    |
| Cycles                         | Warning | Warning     | Error       | Error    |
| Annex V DoC reference          | Info    | Warning     | Error       | Error    |
| EUCC reference                 | n/a     | n/a         | Info        | Error    |
| PSIRT documented               | Warning | Warning     | Error       | Error    |
| Module certificate reference   | n/a     | Warning (B+C) | Error (B+C/H) | Error (EUCC) |

The cycle check (`SBOM-CRA-CYCLES`) counts the cycles of a dependency graph
of any size. Until v0.4.0 it skipped every graph above 1,000,000 edges, which
then passed.

Default conformity routes per class:

| Class             | Default route       |
|-------------------|---------------------|
| Default           | Module A (self-assessment) |
| ImportantClass1   | Module A (self-assessment, B+C optional) |
| ImportantClass2   | Module B+C          |
| Critical          | EUCC                |

## Attestation evidence (CycloneDX 1.6 `declarations`)

Added 2026-07: the CRA checks also read machine-readable CDXA evidence.
On a CycloneDX document with `specVersion >= 1.6` carrying a root-level
`declarations` block plus `definitions.standards`, a standard whose
name/description/owner mentions the *Cyber Resilience Act* (or carries the
bare token `cra`) is classified into the CRA rule family, and an
attestation that fully supports one of its requirements can clear a CRA
check on its own. The EUCC-specific rows need the stricter subset: a
CRA-family standard that *also* names EUCC / Common Criteria.

Every sidecar field and external-reference path listed in the reverse map
above remains valid as the self-declared fallback, and a document with no
`declarations` behaves exactly as before — including byte-identical
violation messages.

### What attestation evidence reaches

| Surface                                                          | CDXA can satisfy it | Evidence needed                                     |
|------------------------------------------------------------------|---------------------|-----------------------------------------------------|
| `SBOM-CRA-ANNEX-IV` — EUCC / Common Criteria reference (only fires at Important-2 / Critical) | yes | CRA-family standard that also names EUCC / Common Criteria |
| `SBOM-EUCC-CERTREF` (under `--standard eucc`)                      | yes                 | same as above                                       |
| `conformity_summary` → "EU Declaration of Conformity" row          | yes                 | any CRA-family attestation                          |
| `conformity_summary` → Module B / Module C / Module H rows          | yes                 | any CRA-family attestation (the external-reference fallback: a `Certification` ref for Module B and H, an `Attestation` or `Certification` ref for Module C) |
| `conformity_summary` → EUCC certificate + Target-of-Evaluation rows | yes                 | CRA-family standard that also names EUCC / Common Criteria |
| `SBOM-CRA-ANNEX-V` — Annex V DoC violation                         | no                  | `Attestation`/`Certification` external ref or sidecar `ceMarkingReference` |
| `SBOM-CRA-ANNEX-VIII` — module certificate violation               | no                  | `Certification` external ref (an `Attestation` ref does not count) |
| `SBOM-EUCC-PP` / `-TOE` / `-ITSEF` / `-VALIDITY`                   | no                  | dedicated sidecar EUCC fields                       |
| `SBOM-CRA-ART-14-PSIRT` / `-EARLY-WARNING` / `-NOTIFICATION` / `-ENISA` channels + the `conformity_summary` PSIRT row | no | sidecar fields |

The `conformity_summary` block is the Annex VIII checklist emitted next to
`violations` by `validate --standard cra -o json` (and `cra-phase1`). It
only appears once a product class is pinned — via `--cra-product-class` or
the sidecar `productClass` — since the class picks the conformity route
whose rows are listed, and never on `oss-steward` results. A row strengthened by attestation names the level it was satisfied
at:

```text
Annex V — manufacturer's signed declaration. Provide via Attestation/Certification
external ref or sidecar ceMarkingReference. Satisfied by machine-readable CDXA
attestation (signature-present evidence); external-reference/sidecar presence
remains the self-declared fallback.
```

### When an attestation counts (fail-closed)

All of the following must hold at the evaluation instant (wall clock, or
`--as-of`):

- the attestation map entry declares a full `conformance.score` (`1.0`) —
  any score below 1.0 is partial and never auto-satisfies, and a missing
  score fails closed too;
- the entry carries no counter-claims and cites at least one claim;
- a cited claim resolves, targets a resolvable element, carries no
  counter-evidence, and cites at least one resolvable evidence item that is
  fresh (created at or before the instant, and not past its `expires`).

Unresolvable refLinks are kept as dangling and can never help satisfy a
requirement. When a matching attestation exists but trips one of these
gates, the violation still fires and the message names the reason:

```text
[CRA Annex IV / EUCC] Product class Critical requires (or strongly recommends)
a reference to a Common Criteria / EUCC certificate or Target of Evaluation
— CDXA attestation covering an EUCC / Common Criteria certification found but
rejected: declared conformance is partial (score 0.5); partial conformance
never auto-satisfies
```

### Structural verification only

**No signature is ever cryptographically verified.** JSF signature objects
on the declarations, attestations, claims, evidence, affirmation, and
signatories are parsed for *presence* — algorithm, `keyId`, signer count,
signatory identity — and nothing more. The evidence ladder is
`SelfDeclared < Structural < SignaturePresent < SignatureVerified`; a
satisfied row reports `SignaturePresent` when the declarations block, the
attestation, or a supporting claim/evidence item carries a signature
object, and `Structural` otherwise. `SignatureVerified` exists only for
output-schema stability and is unreachable today.

For a notified body this means an attestation-satisfied row asserts *"the
document says so, in the schema's shape, and nobody in the document
contradicts it"* — not that a signature, a certificate chain, or the
underlying claim was validated. Ingestion of external in-toto / DSSE
attestation bundles (SLSA provenance/VSA and friends) is a later phase with
no surface today; only in-document `declarations` are read.

## BSI TR-03183-2 — quick mapping

`ComplianceLevel::BsiTr03183_2` implements **v2.1.0 (2025-08-20)**: the §4
format gate, the §5.2.1/§5.2.2 required fields, the §5.2.4 additional tier,
§6.1 licence naming, and the §3.1 vulnerability-information prohibition.
SARIF rule prefix: `SBOM-BSI-TR-03183-2-*`. Canonical URL:
[bsi.bund.de/dok/TR-03183-en](https://bsi.bund.de/dok/TR-03183-en).

| BSI section    | Signal (severity)                                                        | Cleared by                                                    |
|----------------|---------------------------------------------------------------------------|---------------------------------------------------------------|
| §4 (+§7)       | CycloneDX ≥ 1.6 or SPDX ≥ 3.0.1 for newly generated/updated SBOMs (Error) | regenerate in an eligible format (v2.0.0 grace ended 2026-02-20) |
| §5.2.1         | Creator of the SBOM with email, or URL if no email (Error / Warning)      | `metadata.authors[].email` / SPDX `creator`                    |
| §5.2.1         | Timestamp of the SBOM data compilation (Error)                            | `metadata.timestamp` / SPDX `created`                          |
| §5.2.2         | Component name (Error) and version (Error)                                | `name` + `version` (filename / RFC 3339 date fallbacks)        |
| §5.2.2         | Distribution licence(s) per component (Error)                             | `licenses[]` with SPDX identifiers                             |
| §5.2.2         | Hash of the deployable component **as SHA-512** (Error when only other algorithms or no [valid](#hash-values) SHA-512 digest; Warning when absent, §3.2.1) | SHA-512 hash (128 hex characters) per component |
| §5.2.2         | Component creator (Warning, presence-level)                               | `supplier` / `author` per component                            |
| §5.2.2         | Dependencies (Error) + completeness clearly indicated (Warning)           | `dependencies` graph + `compositions[].aggregate`              |
| §5.2.4 (add.)  | Other unique identifiers — purl/CPE (Warning)                             | one of `purl` / `cpe` / `swid` / `swhid` per component         |
| §6.1           | Licences named by SPDX identifier/expression (Warning)                    | valid SPDX expressions (text is not a substitute)              |
| §3.1           | No vulnerability information inside the SBOM (Warning)                    | publish advisories separately (e.g. CSAF)                      |

Not modeled (no rule emitted): filename of the component, and the
executable / archive / structured properties (`bsi:component:*`
CycloneDX taxonomy). The TR mandates **no generation-tool field and no
signature** in any tier.

## CSAF v2.0 (ISO/IEC 20153:2025)

CSAF advisories ingest into `VexEnricher` alongside OpenVEX and
CycloneDX VEX. Format auto-detection: `document.csaf_version` starts
with `2.`. CSAF emit support: `sbom-tools vex export --format csaf`
(see the [CLI cheat sheet](#cli-cheat-sheet)).

| CSAF field                                | Internal mapping                              |
|-------------------------------------------|-----------------------------------------------|
| `vulnerabilities[].cve`                   | `Vulnerability.id`                            |
| `vulnerabilities[].ids[].text` (fallback) | `Vulnerability.id` (e.g., GHSA)               |
| `product_status.known_affected`, `first_affected`, `last_affected` | `VexState::Affected`  |
| `product_status.known_not_affected`       | `VexState::NotAffected`, with no justification |
| `product_status.fixed`, `first_fixed`, `recommended` | `VexState::Fixed`                  |
| `product_status.under_investigation`      | `VexState::UnderInvestigation`                |
| `vulnerabilities[].flags`, `threats`, `notes` | not read                                  |
| `product_tree.full_product_names[].product_identification_helper.purl` | `(vuln_id, purl)` lookup key |

Because `flags` are not read, a `known_not_affected` entry carries no
justification, and the CRA vulnerability checks do not take it as evidence
(see [VEX `not_affected` statements](#vex-not_affected-statements)).

## CLI cheat sheet

```bash
# Multi-standard validate with CRA + BSI + NTIA in one pass
sbom-tools validate sbom.json --standard cra,bsi,ntia

# CRA Phase 2 with product-class calibration via sidecar
sbom-tools validate sbom.json --standard cra --cra-sidecar sbom.cra.yaml

# CRA validation with explicit product class
sbom-tools validate sbom.json --standard cra --cra-product-class important-class-2

# Article 24 steward profile
sbom-tools validate sbom.json --standard oss-steward

# The rules each CRA profile checks, and one rule in full
sbom-tools rules --standard cra-phase1,cra,oss-steward
sbom-tools rules explain SBOM-CRA-ART-24

# Pin the evaluation clock (Art. 14 deadline, SBOM age, EUCC / attestation
# expiry) so CI runs are reproducible
sbom-tools validate sbom.json --standard cra --as-of 2027-01-01

# The TUIs take the same inputs and show the same verdicts
sbom-tools view sbom.json --cra-product-class important-class-2 --as-of 2027-01-01
sbom-tools diff old.json new.json --cra-product-class important-class-2 --as-of 2027-01-01

# SARIF output for CI (with helpUri populated)
sbom-tools validate sbom.json --standard cra -o sarif -O compliance.sarif

# Generate CRA conformity dossier (Annex V DoC + Annex VII technical documentation)
sbom-tools cra-docs sbom.json --output dossier/ --cra-sidecar sbom.cra.yaml

# Curated standards-watch catalogue (prEN, BSI, CSAF, EUCC, …)
sbom-tools cra-standards-watch --format json

# Apply CSAF advisories to enrich SBOM with VEX data
sbom-tools vex apply sbom.json --vex advisory.csaf.json

# Emit the SBOM's VEX state as a CSAF v2.0 advisory
sbom-tools vex export sbom.json --format csaf -O advisory.csaf.json
```

## Sidecar example

```yaml
manufacturerName: "Example Corp"
manufacturerEmail: "legal@example.com"
productName: "Example Product"
productVersion: "1.0.0"
ceMarkingReference: "EU-DoC-2026-001"
supportEndDate: "2030-12-31T00:00:00Z"

productClass: "important-class-1"
conformityAssessmentRoute: "module-a"

riskAssessmentUrl: "https://example.com/risk-assessment.pdf"
riskAssessmentMethodology: "ISO/IEC 27005:2022"

securityContact: "security@example.com"
psirtUrl: "https://example.com/psirt"
coordinatedDisclosurePolicyUrl: "https://example.com/security/cvd-policy"
earlyWarningContact: "ew@example.com"
incidentReportContact: "incidents@example.com"
enisaReportingPlatformId: "EU-MFR-12345"

isOssSteward: false
```

Auto-discovered next to the SBOM at any of:
`<stem>.cra.{json,yaml,yml}`, `<stem>-cra.{json,yaml}`, with multi-extension
stems also tried (`app.cdx.json` → `app.cra.json` works).

## Standards bibliography

| Standard / regulation              | URL                                                                                                                                                |
|------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------|
| CRA — Regulation (EU) 2024/2847    | https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng                                                                                                 |
| prEN 40000-1-3 (in development)    | (CEN-CENELEC JTC 13 — paywalled draft; URLs unstable)                                                                                              |
| BSI TR-03183-2 (v2.1.0)            | https://bsi.bund.de/dok/TR-03183-en                                                                                                                |
| ENISA Technical Advisory for SBOM (v1.10, 2026-10-22, non-binding) | https://www.enisa.europa.eu/publications/enisa-technical-advisory-for-software-bill-of-materials                              |
| NIST SP 800-218 SSDF               | https://doi.org/10.6028/NIST.SP.800-218                                                                                                            |
| EO 14028                           | https://www.federalregister.gov/d/2021-10460                                                                                                       |
| FDA premarket cybersecurity (final, 2026-02-03) | https://www.fda.gov/media/119933/download                                                                                          |
| NTIA SBOM minimum elements         | https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom                                                                     |
| CSAF v2.0 (ISO/IEC 20153:2025)     | https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html                                                                                          |
| OpenVEX                            | https://github.com/openvex/spec                                                                                                                    |
| CISA KEV                           | https://www.cisa.gov/known-exploited-vulnerabilities-catalog                                                                                       |
| OSV.dev                            | https://osv.dev                                                                                                                                    |
| EUCC (Implementing Reg. (EU) 2024/482, as amended by 2024/3144 and 2025/2462) | https://eur-lex.europa.eu/eli/reg_impl/2024/482/oj/eng (consolidated text of 2025-12-29: https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:02024R0482-20251229) |
| CycloneDX Attestations (CDXA)      | https://cyclonedx.org/capabilities/attestations/                                                                                                   |

## Where this map lives in the code

- `rule_meta()` in `src/quality/compliance/registry.rs` (via `Violation::registry_standard_refs()`) —
  string → `(StandardKind, id)` mapping. Drives SARIF
  `properties.standardIds`.
- `rules_for_level()` in `src/quality/compliance/registry.rs` — the rules
  each profile's checks can report (Phase 1, Phase 2 and the steward have
  lists of their own). Drives SARIF `rules[]` and `sbom-tools rules
  --standard`; the rule matrices prove each list.
- `rule_catalog()` in `src/quality/compliance/catalog.rs` — the catalogue
  `sbom-tools rules` prints: each rule's standards, references with URLs,
  remediation and per-format field advice.
- `StandardKind::canonical_help_uri()` in `src/quality/compliance/mod.rs` —
  `(StandardKind, id)` → URL. Drives SARIF `helpUri` (a rule links the
  first of its references that has a URL) and `properties.standardHelpUris`.
- `rule_help_uri()` in `src/reports/sarif/rules.rs` — rule-ID prefix → URL,
  the `runs[].tool.driver.rules[].helpUri` of a rule none of whose
  references has a URL, and of the rules outside the registry.
- `ComplianceChecker::class_severity()` in `src/quality/compliance/mod.rs` —
  P3.2 calibration table.
- `ComplianceRunConfig::checker()` in `src/quality/compliance/run_config.rs` —
  which of a run's inputs (`--as-of`, CRA sidecar, product class) each
  profile gets; every command and TUI builds its checkers there.
- `cli::run_cra_docs` in `src/cli/cra_docs.rs` — Annex V DoC + Annex VII tech-doc dossier
  generator.
- `AttestationRuleFamily::classify()` in `src/model/attestation.rs` —
  `definitions.standards` entry → CRA / SSDF / EO 14028 rule family;
  `AttestationDeclarations::supported_requirements()` — the fail-closed
  filter behind "when an attestation counts".
- `ComplianceContext::evidence_for()` in `src/quality/compliance/context.rs` —
  the query the CRA / EUCC checks call.
- `ComplianceChecker::build_conformity_summary()` and
  `check_class_eucc_reference()` in `src/quality/compliance/cra.rs`,
  `standard_references_eucc()` / `cdxa_note()` in
  `src/quality/compliance/ssdf.rs` — the CRA-side attestation integration
  points.
