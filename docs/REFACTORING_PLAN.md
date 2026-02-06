# sbom-tools Refactoring Plan

> Generated: 2026-02-05
> Codebase: ~50K LOC, 188 files, Rust Edition 2024

## Overall Assessment

Well-architected, production-grade Rust application. Proper error hierarchy, trait-based
extensibility, builder patterns, no `Box<dyn Error>`, zero production panics. The
refactoring opportunities below elevate from "good" to "excellent."

---

## Phase 1: Defensive Attributes (Low effort, immediate quality boost)

### 1.1 Add `#[must_use]`

Currently **0 instances** in the codebase. Add to:

- `DiffEngine::diff()` — ignoring a diff result is always a bug
- `FuzzyMatcher::match_components()` — expensive computation
- `QualityScorer::score()` — expensive computation
- All builder types:
  - `DiffEngine` (the type itself)
  - `AppConfigBuilder`
  - `SbomIndexBuilder`
  - `CompositeMatcherBuilder`
- All `Result`-returning public functions in the library API

### 1.2 Add `#[non_exhaustive]`

Currently **0 instances**. Add to enums likely to grow:

- `Ecosystem` — already has `Unknown(String)` but still exhaustive
- `ComponentType` — new component types will emerge
- `Severity` — security severity levels
- `StalenessLevel` — freshness categories
- `ReportFormat` — output format variants
- `ComplianceStandard` — regulatory standards
- `ParseErrorKind`, `DiffErrorKind`, `ReportErrorKind`, `MatchingErrorKind`, `EnrichmentErrorKind`

### 1.3 Remove 3 Production `.unwrap()` Calls

| File | Line(s) | Fix |
|------|---------|-----|
| `src/tui/shared/quality.rs` | 468, 472 | `.unwrap_or_default()` or pattern match |
| `src/tui/view/views/vulnerabilities.rs` | 258 | `.unwrap_or_default()` or pattern match |

---

## Phase 2: Module Decomposition (Moderate effort, better maintainability)

### 2.1 Split `matching/mod.rs` (1,263 lines, 7 responsibilities)

Extract into focused submodules:

```
src/matching/
├── mod.rs                  # FuzzyMatcher struct, core match_components(), re-exports
├── string_similarity.rs    # NEW: compute_fuzzy_score(), compute_token_similarity()
├── phonetic.rs             # NEW: soundex(), soundex_digit(), compute_phonetic_similarity()
├── multi_field.rs          # NEW: compute_multi_field_score() (92 lines)
├── version_scoring.rs      # NEW: compute_version_divergence_score(), parse_semver_parts()
├── explanation.rs          # NEW: explain_match() (127 lines)
├── aliases.rs              # existing
├── purl.rs                 # existing (move extract_name_from_purl() here)
├── config.rs               # existing
├── ...                     # other existing files
```

### 2.2 Split `reports/html.rs` (789 lines)

- Extract inline CSS (151 lines) to `const HTML_STYLES: &str` in `html_styles.rs`
- Break `generate_diff_report()` (289 lines) into helpers:
  - `write_html_header()`
  - `write_summary_cards()`
  - `write_component_changes_table()`
  - `write_vulnerability_table()`
  - `write_html_footer()`
- Break `generate_view_report()` (293 lines) similarly

### 2.3 Split `reports/summary.rs` (499 lines)

- `SummaryReporter` and `TableReporter` are independent — could be separate files
- Extract shared `ansi_color()` helper to `reports/formatting.rs`

---

## Phase 3: Clone Reduction in Hot Paths (Moderate effort, performance improvement)

### 3.1 HashMap Entry API

Replace clone-then-insert patterns with `entry()` API:

```rust
// BEFORE (aliases.rs:70-87)
map.insert(canonical_lower.clone(), canonical_lower.clone());

// AFTER
use std::collections::hash_map::Entry;
match map.entry(canonical_lower.clone()) {
    Entry::Vacant(e) => { e.insert(value); }
    Entry::Occupied(_) => {}
}
```

### 3.2 Clone-Once Pattern

Fix double/triple clones in single expressions:

```rust
// BEFORE (engine_matching.rs:67)
insert(old_id.clone(), Some(old_id.clone()))

// AFTER
let id = old_id.clone();
insert(id.clone(), Some(id))
```

**Key files:**
- `matching/aliases.rs:70-87` — 4x clone of `canonical_lower`
- `diff/engine_matching.rs:67-72` — double/triple clone of IDs
- `diff/result.rs:148-154` — `c.id.clone()` x3
- `parsers/cyclonedx.rs:231-350` — builder chain clones

### 3.3 Graph Traversal Optimization

BFS/DFS algorithms clone String node IDs repeatedly:

**Files:**
- `tui/app_states/dependencies.rs:287-322`
- `tui/security.rs:239-264`
- `tui/views/dependencies.rs:1681-1704`

**Fix:** Use `&str` references into the SBOM's existing data, or use index-based IDs
instead of String keys for visited sets.

### 3.4 Add `Cow<>` Where Appropriate

Currently **0 instances**. Candidates:
- `CanonicalId` display methods that clone `self.name`
- Report generators: `unwrap_or_else(|| "default".to_string())` → `Cow::Borrowed("default")`
- `"".to_string()` x8 in `reports/summary.rs` → `String::new()`

---

## Phase 4: TUI Unification (High effort, eliminates ~3K duplicate lines)

### 4.1 Problem

Two parallel TUI implementations:
- **Legacy (diff mode):** `src/tui/app.rs` + `src/tui/views/` + `src/tui/events/`
- **New (view mode):** `src/tui/view/app.rs` + `src/tui/view/views/`

Only the Quality tab uses the new `ViewState` pattern. All others are duplicated.

### 4.2 Duplicated File Pairs

| Diff Mode | View Mode | Lines (combined) |
|-----------|-----------|------------------|
| `tui/views/vulnerabilities.rs` | `tui/view/views/vulnerabilities.rs` | 3,122 |
| `tui/views/components.rs` | `tui/view/views/components.rs` | ~2,000 |
| `tui/views/licenses.rs` | `tui/view/views/licenses.rs` | ~2,400 |
| `tui/views/dependencies.rs` | `tui/view/views/dependencies.rs` | ~3,000 |

### 4.3 Strategy: Extract Shared Rendering Functions

Rather than a full architectural migration, extract shared rendering into reusable
widget-level functions:

```rust
// src/tui/shared/component_table.rs
pub fn render_component_table(
    components: &[&Component],
    selected: usize,
    area: Rect,
    buf: &mut Buffer,
    theme: &Theme,
) { ... }
```

Both diff-mode and view-mode call these shared functions, eliminating rendering duplication
while preserving separate state management.

### 4.4 Enforce ListNavigation Trait

The `ListNavigation` trait exists in `src/tui/state.rs` with default implementations,
but 13+ state files manually re-implement `select_next`, `select_prev`, `clamp_selection`.

**Action:** Remove manual implementations, use trait defaults everywhere.

---

## Phase 5: Visibility Tightening (Low effort, better API boundaries)

### 5.1 Add `pub(crate)` to Internal APIs

Currently everything is `pub`. Restrict:

| Module | Items to Restrict |
|--------|-------------------|
| `matching/` | `aliases` internals, `lsh` internals, `index` internals |
| `tui/` | All internal state types, event handlers, view functions |
| `pipeline/` | Stage functions (only called from CLI handlers) |
| `diff/` | `vertex`, `cost` internals |
| `reports/` | Helper functions, internal formatting |

### 5.2 Leave `pub` on

- All re-exported types in `src/lib.rs`
- All trait definitions
- All types used in public function signatures
- All config/model types

---

## Phase 6: Test Coverage (Ongoing, improves reliability)

### 6.1 Current State

- 38% of modules have `#[cfg(test)]` blocks
- Quality is high where tests exist
- Significant gaps in infrastructure layers

### 6.2 Priority Test Additions

| Module | Why | Approach |
|--------|-----|----------|
| `diff/cost.rs` | Pure calculation, easy to test | Unit tests with known cost inputs |
| `enrichment/cache.rs` | I/O logic, regression-prone | Mock filesystem with `tempfile` |
| `enrichment/osv/response.rs` | API response parsing | Golden JSON fixtures |
| `pipeline/` modules | Orchestration correctness | Integration tests with fixture SBOMs |
| `config/validation.rs` | User-facing errors | Boundary value tests |
| `diff/multi.rs` | Multi-diff operations | Unit tests with synthetic data |
| `diff/multi_engine.rs` | Batch processing | Integration tests |

### 6.3 Shared Test Utilities

Each module creates its own `create_test_sbom()` helper. Extract to shared module:

```
tests/
├── common/
│   └── mod.rs          # Shared helpers: create_test_sbom(), create_test_component(), etc.
├── integration_tests.rs
├── proptest_parsers.rs
├── proptest_types.rs
├── golden_fixtures.rs
└── cra_readiness_tests.rs
```

### 6.4 Fix Benchmark Placeholder

`benches/diff_benchmark.rs` is empty. Either implement meaningful benchmarks using
`benches/large_sbom.rs` as a template, or remove the placeholder.

---

## Phase 7: Constants & Consistency (Low effort, polish)

### 7.1 Extract Magic Numbers

| Location | Value | Suggested Constant |
|----------|-------|--------------------|
| `tui/state.rs:54,62` + 34 other locations | `10` | `const PAGE_SIZE: usize = 10;` |
| `tui/app_states/dependencies.rs:109` | `5` | `const DEFAULT_TREE_MAX_DEPTH: usize = 5;` |
| `tui/app_states/dependencies.rs:110` | `50` | `const DEFAULT_TREE_MAX_ROOTS: usize = 50;` |
| `tui/app_impl_items.rs:455` | `10000` | `const SLA_OVERDUE_SORT_OFFSET: i64 = 10000;` |
| Various TUI files | Layout dimensions | Named constants per view |

### 7.2 String Allocation Cleanup

Replace `"".to_string()` with `String::new()` throughout `reports/summary.rs` (8 instances).

---

## Summary Matrix

| Phase | Effort | Impact | Risk | Files Touched |
|-------|--------|--------|------|---------------|
| 1. Defensive Attributes | Low | High | None | ~20 |
| 2. Module Decomposition | Medium | High | Low | ~10 new, ~5 modified |
| 3. Clone Reduction | Medium | Medium-High | Low | ~15 |
| 4. TUI Unification | High | Very High | Medium | ~30 |
| 5. Visibility Tightening | Low | Medium | Low | ~40 |
| 6. Test Coverage | Ongoing | High | None | ~10 new |
| 7. Constants & Consistency | Low | Low | None | ~15 |

---

## Positive Patterns to Preserve

These patterns are already excellent and should be maintained:

- **Error hierarchy:** `thiserror` for library, `anyhow` for CLI — textbook separation
- **No `Box<dyn Error>`** anywhere
- **No `&String` or `&Vec<T>` parameters** — all use `&str` and `&[T]` correctly
- **No `Rc`/`RefCell` misuse** — no interior mutability anti-patterns
- **Builder pattern consistency** — all use `with_*` naming, `mut self` → `Self`
- **Constructor patterns** — clear `new()` / `from_*()` / preset factory methods
- **Default implementations** — 90+ meaningful defaults
- **Zero `todo!()` / `unimplemented!()`** — fully production-ready
- **Zero production `panic!()`** — all in test code only
- **Property-based testing** — proptest for parsers and type invariants
- **Release profile** — LTO + codegen-units=1 already configured
