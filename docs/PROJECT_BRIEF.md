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
| C ABI | Stable JSON-oriented native interface used by language bindings |

## Implemented capabilities

- CycloneDX and SPDX detection, parsing, and normalization.
- SBOM, CBOM, and AI-BOM component modeling.
- Semantic and graph-aware diffing.
- Quality profiles, standards validation, and documented CI exit gates.
- Optional vulnerability, lifecycle, and model-registry enrichment.
- TUI and JSON, SARIF, HTML, Markdown, CSV, table, summary, and NDJSON output.
- C ABI with Go and Swift bindings.
- Python and Node.js bindings under upstream review as developer previews.

## Interface contract

- The CLI is the complete operator interface.
- The Rust library is authoritative for domain behavior.
- The C ABI exposes synchronous version, format detection, parse, diff, and
  score operations using JSON payloads.
- Language bindings are thin ownership-safe wrappers over the C ABI.
- JSON result shape and ABI constant parity are compatibility contracts.

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

1. Python binding:
   [PR #274](https://github.com/sbom-tool/sbom-tools/pull/274).
2. Node.js binding:
   [PR #275](https://github.com/sbom-tool/sbom-tools/pull/275).
3. Installation packaging for preview bindings, proposed separately.
4. BOM-visible ML-regression CI gate.
5. OSCAL assessment-results export for existing validation findings.

The sequence is a roadmap, not a claim that unmerged or proposed work is
available in a release.

## Source-of-truth map

- [Project overview](PROJECT_OVERVIEW.md): purpose, audiences, data flow, and
  responsibility boundary.
- [User journeys](USER_JOURNEYS.md): verified operator and integration paths.
- [Architecture](ARCHITECTURE.md): modules, invariants, and technical debt.
- [Pipeline diagrams](pipeline-diagrams.md): detailed internal execution flows.
- [README](../README.md): installation, commands, and full feature reference.
