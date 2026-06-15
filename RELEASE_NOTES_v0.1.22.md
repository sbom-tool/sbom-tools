# sbom-tools v0.1.22

## Highlights

The **AI BOM release.** sbom-tools now treats AI systems as a first-class domain across the whole pipeline: it parses CycloneDX ML-BOMs and SPDX 3.0 AI/Dataset profiles, scores **AI-readiness** (AI-001…AI-010), machine-checks the **EU AI Act (Annex IV)** and the **G7/BSI "SBOM for AI — Minimum Elements"** standards, diffs model and dataset changes semantically, verifies model-weight integrity, enriches Hugging Face components, and renders AI-BOMs as a dedicated profile in the TUI (Models / Datasets / AI-Readiness tabs).

Alongside the AI work this release lands a large wave of correctness and security fixes — including a hostile-SBOM stack-overflow, empty OSV severity data, and broken CycloneDX XML parsing — a new `convert` command (CycloneDX ↔ SPDX), KEV/EPSS vulnerability enrichment with an offline/air-gapped mode, and broad CLI/TUI alignment.

> **Please read [Upgrade notes](#upgrade-notes) below** — this release changes several user-visible behaviors (scoring engine 2.1, stricter license-policy gating, logs moved to stderr, official EPSS endpoint).

## What's New

### AI / ML Bill of Materials

- **AI-readiness scoring profile.** A dedicated `quality --profile ai-readiness` (and TUI AI-BOM profile) grades ten AI-specific checks (AI-001…AI-010): model-card, architecture, training datasets, quantitative analysis, fairness, ethical considerations, use-cases, limitations, energy, and **model-weight hash integrity**. (#205, #239, #246)
- **CycloneDX ML-BOM + SPDX 3.0 AI/Dataset parsing.** Spec-compliant CycloneDX `modelCard` parsing (typed fairness/quantitative-analysis/considerations) and SPDX 3.0 AI + Dataset profile metadata including the `trainedOn` relationship. (#204, #208, #239)
- **Semantic ML model & dataset diffing.** Model and dataset changes are diffed field-by-field — quantization, architecture, training-dataset add/remove, dataset sensitivity — with high diff-costs on provenance-loss and PII-escalation signals, instead of opaque blobs. (#244)
- **Model-weight integrity & Hugging Face enrichment.** New AI-010 weight-hash check, a `verify model-weights --model-dir` subcommand (direct + HF cache layouts), and a Hugging Face enrichment source that maps `siblings[].lfs.sha256` → component hashes, `pipeline_tag` → task, and routes `pkg:huggingface` models into the vulnerability stack. (#246, #253)
- **`SBOM-AIBOM-*` SARIF rule family** for AI-readiness findings, and TUI rendering of ML model / dataset metadata in the component-detail panel. (#207, #206)

### Compliance

- **EU AI Act (Annex IV) readiness** compliance level with `SBOM-AIACT-*` SARIF rules, N/A-gated for non-AI SBOMs and severity-escalated by the CRA high-risk-AI flag. (#245)
- **G7 / BSI "SBOM for AI — Minimum Elements" readiness** — a new `validate --standard bsi-ai` profile that scores an AI-BOM element-by-element across the seven BSI clusters (Metadata, System-Level, Models, Datasets, Infrastructure, Security) with `SBOM-BSIAI-*` rules. (#255)
- **Compliance rule registry.** Every violation now carries a stable `rule_id`; SARIF rule IDs and standard references come from a single registry instead of fragile message-text matching. (#231, #233)

### Cross-format conversion

- **`convert` command.** Re-emit any parsed SBOM to **CycloneDX 1.7** or **SPDX 2.3** with a fidelity report listing synthesized/dropped fields, built on an opt-in source-field preservation slot. (#241, #243, #247)

### Vulnerability enrichment

- **CISA KEV and EPSS enrichment.** New `--kev` / `--epss` flags surface Known-Exploited-Vulnerabilities flags and EPSS exploit-probability on vulnerabilities, with `--fail-on-kev` gating, KEV/EPSS columns in reports, and a watch-mode "entered KEV" alert. (#235, #237)
- **Offline / air-gapped mode + cache management.** A global `--offline` (and `SBOM_TOOLS_OFFLINE`) serves enrichment purely from cache, plus a new `cache status / warm / clear / export / import` subcommand for sneakernet transfer. (#238)
- **Unified enrichment platform.** All sources (OSV, EOL, VEX, KEV, staleness, EPSS, Hugging Face) now share one `EnrichmentSource` trait, an atomic-write cache with schema versioning, and a single retry/User-Agent HTTP client. (#230)

### CLI & TUI

- **Global `--config` file is now honored by every command** (it was previously read only by `config show`), with CLI-flag > file > default precedence. (#227)
- **Stdin input** (`-` as a path) for `diff`/`quality`/`validate`/`query`/ `vex`, enabling `syft … | sbom-tools quality -` pipelines. (#224)
- **Typed exit codes & NDJSON output.** Per-command exit codes, `clap` value-enums (typos fail at parse), and a wired `-o ndjson` format. (#226)
- **Document-metadata diffing.** `diff` now reports author, tool, timestamp, spec-version, signature and serial-number changes. (#254)
- **AI-BOM is first-class in the TUI** — detected as its own profile with AI-readiness scoring and dedicated Models / Datasets / AI-Readiness tabs, plus EPSS/KEV badges, a KEV filter, richer component detail, and a profile-aware help overlay. (#258, #257, #259, #261, #260, #223)

## Bug Fixes

- **Hostile-SBOM stack-overflow fixed.** Cycle detection is now iterative (Tarjan SCC); a deeply-nested dependency chain previously aborted the process (and any FFI host) via stack overflow. (#215)
- **OSV enrichment now carries severity / CVSS / description.** Results from `/v1/querybatch` (id-only) are hydrated via `/v1/vulns/{id}`; previously enriched vulnerabilities had empty severity and were cached empty for 24h. (#219)
- **CycloneDX XML parsing fixed** for spec-conformant documents (components, dependencies, vulnerabilities, license choice, xmlns spec version). (#214)
- **License policy correctness.** `fail_on_conflict` now actually fails, concluded-only licenses are evaluated against the deny list, and deny-patterns match per-operand in SPDX expressions (`deny "GPL-*"` now catches `MIT OR GPL-3.0-only`). (#212)
- **Per-component license changes are populated** in diffs (the field was always empty), and the Licenses TUI tab no longer falsely reports "no changes". (#211, #259)
- **Watch mode no longer fires false "resolved vulnerability" alerts** on file changes (re-parsed SBOMs are now enriched before diffing). (#221)
- **Incremental diff cache** no longer splices sections from an unrelated cached pair, and diff errors propagate instead of becoming "no changes". (#217)
- **Deterministic diffs.** Fixed-seed MinHash and stable solver ordering make diff output reproducible above the LSH threshold (CI `--fail-on-*` gating). (#218)
- **Machine output is parseable again.** Logs are written to **stderr** so `-o json` / `-o sarif` / `-o ndjson` on stdout is valid when piped or redirected (previously two `INFO` lines preceded the JSON, breaking SARIF upload and `jq`). (#256)
- **Multi-SBOM commands honor their flags.** `diff-multi`/`timeline`/ `matrix` now apply `--graph-*`/filter/rules and can reach exit code 4, and reject unsupported `-o` values. (#225)
- **Output hardening.** CSV formula-injection guard, terminal control-char sanitization, and a TUI panic hook that restores the terminal. (#213)
- **Enrichment entry-point consistency.** `enrich`/`watch`/`query` now route through the unified orchestrator so `--kev`/`--epss`/ `--huggingface` take effect everywhere, `query --offline` no longer makes network calls, and the EPSS default endpoint is the official FIRST host with a response-size bound. (#249, #248, #247)
- **FFI binding parity.** The `AiReadiness` profile is exposed in the Go / Swift wrappers with a CI drift check, and the `sbom-tools-ffi` crate's version/`cargo publish` blockers are fixed. (#216, #234)

## Performance

- **Sparse assignment matching.** The dense O(n²) Hungarian path (≈200 MB / effective hang on cross-format diffs) is replaced by a sparse solver over the candidate edge list. (#232)
- **In-place enrichment mutation** removes a 2× component-map copy per pass, and report-stage compliance is computed lazily per reporter. (#236)
- **TUI dependency tab** caches its graph and uses an iterative longest-path, eliminating a per-frame rebuild and an exponential depth calculation. (#223)

## Internal & Quality

- **Compliance engine split** into a `StandardChecker` per-standard module layout behind a registry, and the **enrichment platform** unified behind one trait. (#233, #230)
- **cli / tui feature gates** so the FFI staticlib and fuzz targets no longer link ratatui/clap/rustls (FFI dependency tree 281 → 104 crates). (#228)
- **Test infrastructure.** A ratatui `TestBackend` snapshot harness for the TUI, golden snapshots for all report formats (plus streaming-JSON validity fixes), graph-shaped hot-path benches, and diff/scoring property tests. (#229, #240, #242, #218)

## Infrastructure

- Dependency bumps: `ratatui` 0.30.0 → 0.30.1, `chrono` 0.4.44 → 0.4.45, `regex` 1.12.3 → 1.12.4, `reqwest` 0.13.3 → 0.13.4, `serde_json` 1.0.149 → 1.0.150, `libfuzzer-sys` 0.4.12 → 0.4.13, plus dagger-SDK-only bumps. New runtime dependency: `flate2` (gzip, enrichment feature) for the EPSS bulk feed. (#251, #252, #195, #196, #222, #248)
- GitHub Actions bumps: `codeql-action` → 4.36.1, `cargo-deny-action` → 2.0.20, `actions/checkout` → 6.0.3; SHA-pin hygiene + expanded Dependabot coverage; fuzz CI now installs `cargo-fuzz` with the nightly toolchain. (#193, #194, #199, #200, #202)
- **Total tests: 1560** (1014 lib + 546 integration), up from 1214 in v0.1.21.
- **0 clippy warnings** (default + all-features) on Rust 1.88; **0 production `unwrap()`**.

## Upgrade notes

These behaviors changed in this release:

- **Scoring engine 2.0 → 2.1.** Cycle detection now counts strongly-connected components (actual cycles) rather than DFS back-edges, so quality scores for SBOMs with cyclic dependencies may change. (#215)
- **`semantic_score` now counts per-component license transitions**, so diffs that change a component's license score slightly lower than before. (#211)
- **License-policy gating is stricter.** `license-check` now fails on license conflicts and concluded-only denied licenses that previously passed silently — CI gates may newly fail (correctly). (#212)
- **Logs are on stderr.** Anything parsing tool **stdout** for log lines must now read stderr; machine-readable report output on stdout is clean. (#256)
- **EPSS default endpoint** moved to the official FIRST host `epss.empiricalsecurity.com` (gzip). Override with `--epss-url` / `SBOM_TOOLS_EPSS_URL`. (#248)
- **Library API:** `IncrementalDiffEngine::diff` and `MultiDiffEngine::{diff_multi,timeline,matrix}` now return `Result`. (#217)

## Acknowledgments

The AI-BOM direction in this release was driven by **@MChorfa** (Mohamed Chorfa), who proposed the original ML-BOM and AI-readiness work and filed the issues this release implements: AI-BOM model-card scoring (#184), `SBOM-AIBOM` SARIF rules (#185), SPDX 3.0 AI-profile parsing (#186), and TUI ML/dataset display (#187). Thanks also to **@jkowalleck** (Jan Kowalleck) for the CycloneDX Tool Center invitation (#176) behind the new submission guide (#177), and continued thanks to **@cmyank0** and **@VincentR-OCD** whose issue reports keep sbom-tools' diff and enrichment output honest.

This release also builds on the public security and standards work behind the **G7/BSI "SBOM for AI" minimum elements**, the **EU AI Act**, **CISA KEV**, and **FIRST EPSS**.

---

Install: `cargo install sbom-tools`
Homebrew: `brew install sbom-tool/tap/sbom-tools`
Crate: https://crates.io/crates/sbom-tools
Full changelog: https://github.com/sbom-tool/sbom-tools/compare/v0.1.21...v0.1.22
