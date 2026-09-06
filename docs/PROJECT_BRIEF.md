# Project briefing

<!-- markdownlint-disable MD013 -->

This document is a compact orientation for a new contributor, integration
partner, or AI coding assistant.

## Mission

`sbom-tools` is a neutral BOM analysis engine and CLI. It parses CycloneDX and
SPDX documents, normalizes them into one canonical model, and performs semantic
diffing, validation, quality scoring, enrichment, and report generation.

## Mental model

```text
input BOM
  -> format parser
  -> NormalizedSbom
  -> diff / validate / score / enrich
  -> typed result
  -> CLI, TUI, report, or language binding
```

The canonical model is the center of the system. Interfaces must reuse engine
behavior rather than implement independent parsing or analysis rules.

## Stable terminology

| Term | Meaning |
| --- | --- |
| SBOM | Software bill of materials |
| CBOM | Cryptographic bill of materials |
| AI-BOM or ML-BOM | BOM containing model or dataset components and their declared metadata |
| `NormalizedSbom` | Format-independent canonical document, component, and relationship model |
| Canonical ID | Stable component identity used for matching across documents |
| Semantic diff | Component, dependency, vulnerability, license, metadata, model, and dataset changes |
| Enrichment | Optional external metadata added before analysis, such as OSV, KEV, EOL, EPSS, or Hugging Face data |
| CDXA declarations | CycloneDX 1.6 attestation section (assessors, attestations, claims, evidence) ingested structurally as compliance evidence; signature presence is recorded, never verified |
| C ABI | Stable JSON-oriented native interface used by language bindings |

## Implemented capabilities

- CycloneDX and SPDX detection, parsing, and normalization.
- SBOM, CBOM, and AI-BOM component modeling.
- Semantic and graph-aware diffing.
- Multi-SBOM comparison: 1:N (`diff-multi`), chronological (`timeline`), and
  N x N (`matrix`).
- Structural ingestion of CycloneDX 1.6 attestation declarations, consumed as
  evidence by existing compliance rules.
- Quality profiles, 16 standards-validation profiles, and documented CI exit
  gates.
- Optional vulnerability, lifecycle, and model-registry enrichment.
- TUI and JSON, NDJSON, SARIF, OSCAL (validate), sbomqs-comparable JSON
  (quality), HTML, Markdown, CSV, table, summary, and side-by-side output.
- C ABI with Go, Swift, Python, and Node.js bindings.

## Interface contract

- The CLI is the complete operator interface.
- The Rust library is authoritative for domain behavior.
- The C ABI exposes synchronous version, format detection, parse, diff, and
  score operations using JSON payloads.
- Language bindings are thin ownership-safe wrappers over the C ABI.
- JSON result shape and ABI constant parity are compatibility contracts.
- Numeric scales are part of the JSON contract and are test-pinned:
  `DiffResult.semantic_score` is 0-100, `MatrixResult` similarity is 0-1
  (`semantic_score / 100`), and `diff-multi` deviation is 0-1
  (`1 - similarity`).
- The contract is pinned at the top-level keys of each payload and the
  numeric scales; nested shape follows the crate version, and pre-1.0 a
  breaking change may land in a minor release with an entry under **Upgrade
  notes** in `CHANGELOG.md`. There is no separate JSON schema version.
- `view -o json` is a curated projection (summary + per-component identity,
  licenses, supplier, dependency kind, vulnerabilities, EOL). The full
  normalized model, including `crypto_properties`, `ml_model`, and `dataset`,
  is exposed only through the ABI parse functions and the bindings. See
  "JSON output contract" in the README.

## Non-goals and ownership boundary

Do not add organization-specific governance or infrastructure to the upstream
core. The project does not own policy decision engines, admission controllers,
tenant authority models, hardware attestation, PKI, secret management, or an
evidence ledger.

An external evidence or governance system may consume `sbom-tools` outputs. It
must keep its own policy, trust, authority, and persistence semantics outside
this repository.

## Contribution rules

- Keep format-specific details in parsers and normalize before analysis.
- Keep business logic in the Rust engine, not in presentation wrappers.
- Reuse current result types and report conventions.
- Do not claim facts that are not present in a BOM or obtained through an
  explicitly enabled enrichment source.
- Keep language bindings thin and free every native result exactly once.
- Preserve default CLI behavior when adding opt-in CI gates or report formats.

## Current contribution sequence

1. Installation packaging for the Python and Node.js bindings, proposed separately.

Previously sequenced items now implemented: the BOM-visible ML-regression CI
gate (`diff --fail-on-ml-regression`, exit code 7) and OSCAL 1.1.2
assessment-results export for validation findings (`validate -o oscal-json`).

The sequence is a roadmap, not a claim that unmerged or proposed work is
available in a release.

## Source-of-truth map

- [Project overview](PROJECT_OVERVIEW.md): purpose, audiences, data flow, and
  responsibility boundary.
- [User journeys](USER_JOURNEYS.md): verified operator and integration paths.
- [Architecture](ARCHITECTURE.md): modules, invariants, and technical debt.
- [Pipeline diagrams](pipeline-diagrams.md): detailed internal execution flows.
- [README](../README.md): installation, commands, and full feature reference.
