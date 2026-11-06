#![no_main]
use libfuzzer_sys::fuzz_target;
use sbom_tools::quality::{
    ComplianceLevel, ComplianceResult, ComplianceRunConfig, PqcMode, parse_as_of,
};
use sbom_tools::reports::{
    AssessedSbom, HtmlReporter, MarkdownReporter, NdjsonWriter, ReportConfig, ReportGenerator,
    SarifArtifact, SarifArtifactLocation, SarifOptions, generate_compliance_json,
    generate_compliance_json_at, generate_compliance_sarif_with,
    generate_multi_compliance_sarif_with, oscal,
};

/// The instant every run judges, so a crash reproduces on any day.
const AS_OF: &str = "2026-10-12T00:00:00Z";

/// Fuzz the compliance engine and its writers.
///
/// Parses arbitrary UTF-8 input as an SBOM; when parsing succeeds, checks it
/// against every compliance level, in PQC readiness and deadline mode, with
/// and without the components whose scope is excluded, at a pinned instant.
/// Each run's results go through every writer `validate` and `view` use: the
/// JSON envelope (v2, with and without its subject) and the deprecated v1
/// array, SARIF for one standard and for several (with passes and pointing
/// into the input, and with a small result cap), OSCAL, and the Markdown and
/// HTML view reports that render the CRA verdict. The text and `--summary`
/// renderers of `validate` are private to the CLI and not reached here.
fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(sbom) = sbom_tools::parsers::parse_sbom_str(s) else {
        return;
    };
    let as_of = parse_as_of(AS_OF).expect("valid instant");
    let assessed = AssessedSbom::new(&sbom, data);
    for pqc_mode in [PqcMode::Readiness, PqcMode::Deadline] {
        for include_excluded_scope in [false, true] {
            let run = ComplianceRunConfig::new()
                .with_as_of(as_of)
                .with_pqc_mode(pqc_mode)
                .with_include_excluded_scope(include_excluded_scope);
            let results = run.check_levels(ComplianceLevel::all(), &sbom);
            write_all(&run, &results, &assessed, s);
        }
    }
});

/// Render `results`, the verdicts `run` gave the SBOM `assessed` (read from
/// `content`), with every compliance writer.
fn write_all(
    run: &ComplianceRunConfig,
    results: &[ComplianceResult],
    assessed: &AssessedSbom<'_>,
    content: &str,
) {
    let sbom = assessed.sbom();
    let as_of = run.judged_at();
    let _ = generate_compliance_json(results);
    let _ = generate_compliance_json_at(results, assessed, as_of);
    // `--json-schema v1`: each result's own serialization, without its
    // passed checks. `validate` prints it pretty; the fuzz crate has no
    // serde_json of its own, so the NDJSON writer runs the same `Serialize`
    // impls on one line.
    let v1: Vec<ComplianceResult> = results
        .iter()
        .map(|result| {
            let mut v1 = result.clone();
            v1.passed.clear();
            v1
        })
        .collect();
    let mut buffer = Vec::new();
    let _ = NdjsonWriter::new(&mut buffer).write_item(&v1);

    let artifact = SarifArtifact::new(SarifArtifactLocation::relative("sbom.json"), sbom, content);
    let sarif_options = [
        SarifOptions::new()
            .with_passes(true)
            .with_artifact(artifact)
            .with_subject(assessed, as_of),
        SarifOptions::new().with_max_results(3),
    ];
    for options in &sarif_options {
        for result in results {
            let _ = generate_compliance_sarif_with(result, options);
        }
        let _ = generate_multi_compliance_sarif_with(results, options);
    }
    let _ = oscal::generate_assessment_results_at(results, assessed, as_of);

    // `view -o md` and `view -o html` render the CRA Phase 2 verdict.
    if let Some(cra) = results
        .iter()
        .find(|result| result.level == ComplianceLevel::CraPhase2)
    {
        let config = ReportConfig {
            view_cra_compliance: Some(cra.clone()),
            ..ReportConfig::default()
        };
        let _ = MarkdownReporter::new().generate_view_report(sbom, &config);
        let _ = HtmlReporter::new().generate_view_report(sbom, &config);
    }
}
