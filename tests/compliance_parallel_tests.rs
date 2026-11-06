//! Checking standards in parallel changes no output byte.
//!
//! `ComplianceRunConfig::check_levels` checks the standards on rayon's
//! thread pool, judges them all at one instant and returns the results in
//! the order the standards were selected. These tests check that the results
//! render to the bytes the standards give checked one after another, whatever
//! the number of threads, and that a `validate` of every standard writes the
//! same bytes on every run and on one thread (`RAYON_NUM_THREADS=1`).

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use sbom_tools::model::{CraProductClass, NormalizedSbom};
use sbom_tools::parse_sbom_str;
use sbom_tools::quality::{ComplianceLevel, ComplianceResult, ComplianceRunConfig, PqcMode};
use sbom_tools::reports::oscal::generate_assessment_results_at;
use sbom_tools::reports::{
    AssessedSbom, SarifOptions, generate_compliance_json_at, generate_multi_compliance_sarif_with,
};

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// Every `validate --standard` value.
const ALL_STANDARDS: &str = "ntia,fda,cra,cra-phase1,ssdf,eo14028,cnsa2,pqc,bsi,oss-steward,\
                             eucc,ai-act,bsi-ai,cisa-2026,pci-dss,fsct";

/// Fixtures that between them reach most checks: CRA evidence, CBOM
/// deadlines, AI metadata, excluded scope, SPDX 2.3 and SPDX 3.0.
const FIXTURES: &[&str] = &[
    "cra/cra-compliant.cdx.json",
    "cyclonedx/cbom-pqc-calendar.cdx.json",
    "cyclonedx/aibom-complete.cdx.json",
    "cyclonedx/scope-excluded.cdx.json",
    "spdx/minimal.spdx.json",
    "spdx3/minimal.spdx3.json",
];

fn as_of() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-10-12T00:00:00Z")
        .expect("valid instant")
        .with_timezone(&chrono::Utc)
}

/// A CycloneDX 1.6 document of `count` library components in a dependency
/// chain. Every second component names a supplier and every third a hash,
/// so each standard reports a few hundred findings of several rules.
fn generated_sbom(count: usize) -> String {
    let mut out = String::from(
        r#"{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"timestamp":"2026-01-01T00:00:00Z","component":{"type":"application","name":"app","version":"1.0.0","bom-ref":"app"}},"components":["#,
    );
    for i in 0..count {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            r#"{{"type":"library","bom-ref":"c{i}","name":"comp{i}","version":"1.{i}.0","purl":"pkg:npm/comp{i}@1.{i}.0""#
        );
        if i % 2 == 0 {
            let _ = write!(out, r#","supplier":{{"name":"Supplier {i}"}}"#);
        }
        if i % 3 == 0 {
            out.push_str(r#","hashes":[{"alg":"SHA-256","content":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}]"#);
        }
        out.push('}');
    }
    out.push_str(r#"],"dependencies":[{"ref":"app","dependsOn":["c0"]}"#);
    for i in 1..count {
        let _ = write!(out, r#",{{"ref":"c{}","dependsOn":["c{i}"]}}"#, i - 1);
    }
    out.push_str("]}");
    out
}

/// The SBOMs the tests check: the fixtures and a generated one, each with
/// its text.
fn sboms() -> Vec<(String, String, NormalizedSbom)> {
    let mut sboms: Vec<(String, String)> = FIXTURES
        .iter()
        .map(|rel| {
            let text = std::fs::read_to_string(Path::new(FIXTURES_DIR).join(rel))
                .unwrap_or_else(|e| panic!("{rel}: {e}"));
            ((*rel).to_string(), text)
        })
        .collect();
    sboms.push((
        "generated (120 components)".to_string(),
        generated_sbom(120),
    ));
    sboms
        .into_iter()
        .map(|(label, text)| {
            let sbom = parse_sbom_str(&text).unwrap_or_else(|e| panic!("{label}: {e}"));
            (label, text, sbom)
        })
        .collect()
}

/// The runs each SBOM is checked with: as `validate` checks it, and with a
/// CRA product class and PQC deadline mode.
fn runs() -> Vec<ComplianceRunConfig> {
    vec![
        ComplianceRunConfig::new().with_as_of(as_of()),
        ComplianceRunConfig::new()
            .with_as_of(as_of())
            .with_product_class(CraProductClass::Critical)
            .with_pqc_mode(PqcMode::Deadline),
    ]
}

/// What `results` render to: `-o json`, `-o sarif` with every passed check
/// (uncapped, and capped at 25 results) and `-o oscal-json`.
fn rendered(results: &[ComplianceResult], assessed: &AssessedSbom<'_>) -> Vec<String> {
    let sarif = |max_results: usize| {
        let options = SarifOptions::new()
            .with_passes(true)
            .with_max_results(max_results);
        generate_multi_compliance_sarif_with(results, &options).expect("SARIF renders")
    };
    vec![
        generate_compliance_json_at(results, assessed, as_of()).expect("JSON renders"),
        sarif(0),
        sarif(25),
        generate_assessment_results_at(results, assessed, as_of()).expect("OSCAL renders"),
    ]
}

/// `check_levels` gives every level the result checking it alone gives, in
/// the order of the levels, on rayon's global pool, on one thread and on
/// eight.
#[test]
fn parallel_checks_render_as_checks_one_after_another() {
    let levels = ComplianceLevel::all();
    let pool = |threads: usize| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .expect("thread pool")
    };
    let (one, eight) = (pool(1), pool(8));
    for (label, text, sbom) in sboms() {
        let assessed = AssessedSbom::new(&sbom, text.as_bytes()).with_file_name("sbom.json");
        for run in runs() {
            let one_by_one: Vec<ComplianceResult> = levels
                .iter()
                .map(|level| run.check(*level, &sbom))
                .collect();
            let expected = rendered(&one_by_one, &assessed);
            for (threads, results) in [
                ("the global pool", run.check_levels(levels, &sbom)),
                (
                    "one thread",
                    one.install(|| run.check_levels(levels, &sbom)),
                ),
                (
                    "eight threads",
                    eight.install(|| run.check_levels(levels, &sbom)),
                ),
            ] {
                let got: Vec<ComplianceLevel> = results.iter().map(|r| r.level).collect();
                assert_eq!(got, levels, "{label}: {threads}: the levels' order");
                for (n, (got, want)) in rendered(&results, &assessed)
                    .iter()
                    .zip(&expected)
                    .enumerate()
                {
                    assert!(got == want, "{label}: {threads}: output {n} differs");
                }
            }
        }
    }
}

/// `validate` with every standard writes the same bytes on a second run
/// and on one thread, in each output format.
#[test]
fn a_multi_standard_validate_writes_the_same_bytes_every_run() {
    let dir = tempfile::tempdir().expect("temp dir");
    let generated = dir.path().join("generated.cdx.json");
    std::fs::write(&generated, generated_sbom(120)).expect("generated SBOM written");
    let mut paths: Vec<PathBuf> = FIXTURES
        .iter()
        .map(|rel| Path::new(FIXTURES_DIR).join(rel))
        .collect();
    paths.push(generated);
    for path in &paths {
        for output in [None, Some("json"), Some("sarif"), Some("oscal-json")] {
            let validate = |threads: Option<&str>| -> Vec<u8> {
                let mut cmd = Command::new(env!("CARGO_BIN_EXE_sbom-tools"));
                cmd.args(["--no-color", "validate"])
                    .arg(path)
                    .args(["--standard", ALL_STANDARDS, "--as-of", "2026-10-12"])
                    .env("RUST_LOG", "error");
                if let Some(output) = output {
                    cmd.args(["-o", output]);
                }
                if let Some(threads) = threads {
                    cmd.env("RAYON_NUM_THREADS", threads);
                }
                let run = cmd.output().expect("validate runs");
                assert!(
                    matches!(run.status.code(), Some(0..=2)),
                    "{}: {}",
                    path.display(),
                    String::from_utf8_lossy(&run.stderr)
                );
                run.stdout
            };
            let first = validate(None);
            assert!(!first.is_empty(), "{}: {output:?}", path.display());
            let what = format!("{} -o {}", path.display(), output.unwrap_or("text"));
            assert!(validate(None) == first, "{what}: a second run differs");
            assert!(validate(Some("1")) == first, "{what}: one thread differs");
        }
    }
}
