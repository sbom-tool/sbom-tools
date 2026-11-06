//! Cross-standard compliance invariants.
//!
//! Properties that must hold for every standard at once, so a new standard
//! or a refactored checker cannot quietly break them.

use clap::ValueEnum;
use sbom_tools::parse_sbom_str;
use sbom_tools::quality::{
    ComplianceChecker, ComplianceLevel, ComplianceResult, StandardSelector, ViolationSeverity,
};

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn as_of() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-10-12T00:00:00Z")
        .expect("valid timestamp")
        .with_timezone(&chrono::Utc)
}

fn check(raw: &str, selector: StandardSelector) -> ComplianceResult {
    let sbom = parse_sbom_str(raw).expect("fixture parses");
    ComplianceChecker::new(selector.level())
        .with_as_of(as_of())
        .check(&sbom)
}

fn fixture(rel: &str) -> String {
    std::fs::read_to_string(format!("{FIXTURES_DIR}/{rel}"))
        .unwrap_or_else(|e| panic!("cannot read {rel}: {e}"))
}

/// Standards that judge a software inventory. The crypto profiles judge
/// cryptographic assets with their own inventory gates, the AI profiles are
/// not applicable without ML content, and EUCC checks certification
/// references rather than components.
fn inventory_standards() -> Vec<StandardSelector> {
    StandardSelector::value_variants()
        .iter()
        .copied()
        .filter(|s| {
            !matches!(
                s,
                StandardSelector::Cnsa2
                    | StandardSelector::Pqc
                    | StandardSelector::AiAct
                    | StandardSelector::BsiAi
                    | StandardSelector::Eucc
            )
        })
        .collect()
}

/// Zero package-scoped components never yields a silent pass (review
/// finding V3): an empty document, a file-only document and a crypto-only
/// CBOM used to pass up to seven standards, scoring like perfect SBOMs.
#[test]
fn no_package_inventory_is_never_compliant() {
    let documents = [
        (
            "empty CycloneDX",
            fixture("compliance/regressions/v3-empty-inventory.cdx.json"),
        ),
        (
            "file-only SPDX",
            fixture("compliance/regressions/v3-file-only.spdx.json"),
        ),
        (
            "crypto-only CBOM",
            fixture("cyclonedx/cbom-1.7-sparse-ike.cdx.json"),
        ),
    ];
    let mut passes = Vec::new();
    for (label, raw) in &documents {
        for selector in inventory_standards() {
            let result = check(raw, selector);
            if result.is_compliant {
                passes.push(format!("{selector} passed the {label} document"));
            }
        }
    }
    assert!(
        passes.is_empty(),
        "silent passes:\n  {}",
        passes.join("\n  ")
    );
}

/// The primary component is inventory: a leaf application with no
/// dependencies must not draw an inventory-absent finding.
#[test]
fn a_lone_primary_component_is_an_inventory() {
    let raw = r#"{
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": "2026-10-01T00:00:00Z",
            "component": {
                "type": "application",
                "bom-ref": "app",
                "name": "app",
                "version": "1.0.0",
                "purl": "pkg:generic/app@1.0.0"
            }
        },
        "components": []
    }"#;
    for selector in inventory_standards() {
        let result = check(raw, selector);
        let inventory: Vec<&str> = result
            .violations
            .iter()
            .filter(|v| v.message.contains("SBOM lists no"))
            .map(|v| v.rule_id)
            .collect();
        assert!(
            inventory.is_empty(),
            "{selector}: a lone primary component drew {inventory:?}"
        );
    }
}

/// The compliance engine's code, as the source scans below read it: every
/// `.rs` file under src/quality/compliance/, at any depth, in path order,
/// named by its path below that directory and cut at its first
/// `#[cfg(test)]` (unit tests at the bottom of a file are not checker
/// code). The file of an out-of-line test module (`#[cfg(test)] mod
/// tests;`), and of every module below one, is test code as a whole and
/// left out.
fn compliance_code() -> Vec<(String, String)> {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
            .expect("compliance sources")
            .map(|entry| entry.expect("dir entry").path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    /// The out-of-line modules (`mod name;`) `src` declares, each with
    /// whether `#[cfg(test)]` is among its attributes.
    fn modules(src: &str) -> Vec<(String, bool)> {
        let (mut out, mut cfg_test) = (Vec::new(), false);
        for line in src.lines() {
            let mut rest = line.trim();
            if rest == "#[cfg(test)]" {
                cfg_test = true;
                continue;
            }
            if rest.is_empty() || rest.starts_with("#[") {
                continue;
            }
            for vis in ["pub(crate)", "pub(super)", "pub"] {
                rest = rest.strip_prefix(vis).unwrap_or(rest).trim_start();
            }
            if let Some(name) = rest.strip_prefix("mod ").and_then(|d| d.strip_suffix(';')) {
                out.push((name.trim().to_string(), cfg_test));
            }
            cfg_test = false;
        }
        out
    }
    /// The file the out-of-line module `name` declared in `parent` loads.
    fn module_file(parent: &Path, name: &str) -> Option<PathBuf> {
        let dir = match parent.file_stem()?.to_str()? {
            "mod" => parent.parent()?.to_path_buf(),
            stem => parent.parent()?.join(stem),
        };
        [
            dir.join(format!("{name}.rs")),
            dir.join(name).join("mod.rs"),
        ]
        .into_iter()
        .find(|p| p.is_file())
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/quality/compliance");
    let mut paths = Vec::new();
    walk(&root, &mut paths);
    let sources: Vec<(PathBuf, String)> = paths
        .into_iter()
        .map(|path| {
            let src = std::fs::read_to_string(&path).expect("readable source");
            (path, src)
        })
        .collect();
    let mut tests: BTreeSet<PathBuf> = BTreeSet::new();
    let mut queue: Vec<PathBuf> = Vec::new();
    for (path, src) in &sources {
        for (name, cfg_test) in modules(src) {
            if cfg_test
                && let Some(file) = module_file(path, &name)
                && tests.insert(file.clone())
            {
                queue.push(file);
            }
        }
    }
    while let Some(file) = queue.pop() {
        let Some((_, src)) = sources.iter().find(|(path, _)| *path == file) else {
            continue;
        };
        for (name, _) in modules(src) {
            if let Some(child) = module_file(&file, &name)
                && tests.insert(child.clone())
            {
                queue.push(child);
            }
        }
    }
    sources
        .into_iter()
        .filter(|(path, _)| !tests.contains(path))
        .map(|(path, src)| {
            let name = path
                .strip_prefix(&root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            let code = src.split("#[cfg(test)]").next().unwrap_or_default();
            (name, code.to_string())
        })
        .collect()
}

/// The source scans read the whole engine: the files in subdirectories
/// (the rule registry's family modules) as well as the top level, and no
/// unit-test file.
#[test]
fn source_scans_read_the_whole_engine() {
    let names: Vec<String> = compliance_code()
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    for expected in ["mod.rs", "checker.rs", "registry/mod.rs", "registry/cra.rs"] {
        assert!(
            names.iter().any(|name| name == expected),
            "{expected} is not scanned: {names:?}"
        );
    }
    assert!(
        !names.iter().any(|name| name.starts_with("tests/")),
        "a unit-test file is scanned as checker code: {names:?}"
    );
}

/// Source scan: a checker loop or count over every component must either
/// carve out non-package components (`judges_package`, `is_package_scoped`
/// or `package_components`) or say why its rule covers them all, with an
/// `All components:` comment just above. The carve-out stopped halfway
/// through the standards once (review finding V5); this keeps the next
/// package rule from forgetting it. `judges_package` also leaves out the
/// components whose scope is excluded, which `is_package_scoped` alone
/// does not.
#[test]
fn whole_inventory_walks_are_scoped_or_justified() {
    fn floor(s: &str, mut i: usize) -> usize {
        while !s.is_char_boundary(i) {
            i -= 1;
        }
        i
    }
    let mut offenders = Vec::new();
    for (name, code) in compliance_code() {
        // Drop whitespace so multi-line method chains match one pattern.
        let flat: String = code.chars().filter(|c| !c.is_whitespace()).collect();
        for pattern in [
            "insbom.components.values()",
            "sbom.components.values().filter(",
        ] {
            let mut from = 0;
            while let Some(found) = flat[from..].find(pattern) {
                let at = from + found;
                let before = &flat[floor(&flat, at.saturating_sub(400))..at];
                let after = &flat[at..floor(&flat, (at + 1200).min(flat.len()))];
                let justified = before.contains("Allcomponents:");
                let scoped = after.contains("judges_package")
                    || after.contains("is_package_scoped")
                    || after.contains("package_components");
                if !justified && !scoped {
                    offenders.push(format!("{name}: …{}…", &after[..floor(after, 60)]));
                }
                from = at + pattern.len();
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "unscoped whole-inventory walks (add a package carve-out or an \
         `All components:` comment saying why the rule covers every component):\n  {}",
        offenders.join("\n  ")
    );
}

/// Files, crypto assets and services never draw package findings (review
/// finding V5): the bare ones below carry no version, supplier, identifier,
/// hash or licence, so any package rule that judged them would name them.
#[test]
fn non_package_components_never_draw_package_findings() {
    const SHA512: &str = "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4\
                          8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4";
    let raw = format!(
        r#"{{
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:0b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e",
        "version": 1,
        "metadata": {{
            "timestamp": "2026-10-01T00:00:00Z",
            "authors": [{{ "name": "Example Corp", "email": "sbom@example.com" }}],
            "tools": {{ "components": [{{ "type": "application", "name": "gen", "version": "1.0.0" }}] }},
            "component": {{
                "type": "application", "bom-ref": "ref-app", "name": "app", "version": "1.0.0",
                "purl": "pkg:generic/app@1.0.0", "supplier": {{ "name": "Example Corp" }},
                "hashes": [{{ "alg": "SHA-512", "content": "{SHA512}" }}],
                "licenses": [{{ "license": {{ "id": "MIT" }} }}]
            }}
        }},
        "components": [
            {{
                "type": "library", "bom-ref": "ref-lib", "name": "libgood", "version": "2.0.0",
                "purl": "pkg:npm/libgood@2.0.0", "supplier": {{ "name": "Good Inc" }},
                "hashes": [{{ "alg": "SHA-512", "content": "{SHA512}" }}],
                "licenses": [{{ "license": {{ "id": "MIT" }} }}]
            }},
            {{ "type": "file", "bom-ref": "ref-readme", "name": "README.md" }},
            {{
                "type": "cryptographic-asset", "bom-ref": "ref-aes", "name": "AES-128-GCM",
                "cryptoProperties": {{ "assetType": "algorithm" }}
            }}
        ],
        "services": [{{ "bom-ref": "ref-billing", "name": "billing-api" }}],
        "dependencies": [
            {{ "ref": "ref-app", "dependsOn": ["ref-lib"] }},
            {{ "ref": "ref-lib", "dependsOn": [] }}
        ]
    }}"#
    );
    let bare = [
        "README.md",
        "AES-128-GCM",
        "billing-api",
        "ref-readme",
        "ref-aes",
        "ref-billing",
    ];
    let mut offenders = Vec::new();
    for selector in inventory_standards() {
        let result = check(&raw, selector);
        for v in &result.violations {
            let named = [
                Some(v.message.as_str()),
                v.element.as_deref(),
                v.component_id.as_deref(),
            ]
            .into_iter()
            .flatten()
            .any(|text| bare.iter().any(|b| text.contains(b)));
            if named {
                offenders.push(format!("{selector} {}: {}", v.rule_id, v.message));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "package findings on non-package components:\n  {}",
        offenders.join("\n  ")
    );
}

/// Source scan: compliance checks never use the raw presence test
/// `Component::has_producer`, which lets a NOASSERTION supplier satisfy a
/// rule (review finding V4). They use the sentinel-aware
/// `has_known_producer` — and so does the vendor-hash metric in
/// quality/metrics.rs, which SBOM-CRA-PRE-7-RQ-07-RE reads.
#[test]
fn checkers_never_use_the_raw_producer_test() {
    let metrics = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/quality/metrics.rs"
    ))
    .expect("readable source");
    let mut sources = compliance_code();
    sources.push((
        "src/quality/metrics.rs".to_string(),
        metrics
            .split("#[cfg(test)]")
            .next()
            .unwrap_or_default()
            .to_string(),
    ));
    let mut offenders = Vec::new();
    for (name, code) in sources {
        for (n, line) in code.lines().enumerate() {
            let trimmed = line.trim_start();
            if !trimmed.starts_with("//") && line.contains(".has_producer(") {
                offenders.push(format!("{name}:{}: {}", n + 1, trimmed));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "raw has_producer() in compliance code; use has_known_producer:\n  {}",
        offenders.join("\n  ")
    );
}

/// Every parseable SBOM fixture's text, sorted by path, from the directories
/// the snapshot harness walks.
fn sbom_fixtures() -> Vec<(String, String)> {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.push(path);
            }
        }
    }
    let root = std::path::Path::new(FIXTURES_DIR);
    let mut paths = Vec::new();
    for dir in [
        "aibom",
        "compliance/regressions",
        "cra",
        "cyclonedx",
        "showcase",
        "spdx",
        "spdx3",
    ] {
        walk(&root.join(dir), &mut paths);
    }
    paths.sort();
    paths
        .into_iter()
        .filter_map(|path| {
            let rel = path
                .strip_prefix(root)
                .ok()?
                .to_string_lossy()
                .replace('\\', "/");
            let raw = std::fs::read_to_string(&path).ok()?;
            parse_sbom_str(&raw).ok()?;
            Some((rel, raw))
        })
        .collect()
}

/// The score counts an aggregate finding by its failing items. Most
/// aggregate findings count those in `counts.affected`; a coverage finding
/// ("Only X/Y components carry …") counts the covered ones, so its failing
/// items are the others. A new coverage rule missing from the score's list
/// of coverage rules would be weighed by the items that pass.
#[test]
fn aggregate_findings_weigh_their_failing_items() {
    let mut coverage_rules = std::collections::BTreeSet::new();
    let mut offenders = Vec::new();
    for (rel, raw) in sbom_fixtures() {
        let sbom = parse_sbom_str(&raw).expect("fixture parses");
        for level in ComplianceLevel::all() {
            let result = ComplianceChecker::new(*level)
                .with_as_of(as_of())
                .check(&sbom);
            for v in &result.violations {
                let Some(counts) = v.counts else {
                    continue;
                };
                if v.severity == ViolationSeverity::Info {
                    assert_eq!(v.failed_checks(), 0, "{rel} {}", v.rule_id);
                    continue;
                }
                let coverage = v
                    .message
                    .contains(&format!("Only {}/{}", counts.affected, counts.total));
                let failing = if coverage {
                    coverage_rules.insert(v.rule_id);
                    counts.total - counts.affected
                } else {
                    counts.affected
                };
                if v.failed_checks() != failing.max(1) {
                    offenders.push(format!(
                        "{rel} {level:?} {}: weighs {} for {}/{} ({})",
                        v.rule_id,
                        v.failed_checks(),
                        counts.affected,
                        counts.total,
                        v.message
                    ));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "aggregate findings weighed by the wrong count:\n  {}",
        offenders.join("\n  ")
    );
    // The corpus exercises every coverage rule.
    assert_eq!(
        coverage_rules.into_iter().collect::<Vec<_>>(),
        [
            "SBOM-CRA-PRE-7-RQ-07-RE",
            "SBOM-FSCT-COPYRIGHT-COVERAGE",
            "SBOM-FSCT-LICENSE-COVERAGE",
        ]
    );
}
