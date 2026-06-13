#![no_main]
use libfuzzer_sys::fuzz_target;
use sbom_tools::quality::{QualityScorer, ScoringProfile};

/// Fuzz the quality scoring engine.
///
/// Parses arbitrary UTF-8 input as an SBOM; when parsing succeeds, scores the
/// document with every scoring profile. This exercises all metric computations
/// (including dependency graph analysis) against adversarial component and
/// dependency structures.
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data)
        && let Ok(sbom) = sbom_tools::parsers::parse_sbom_str(s)
    {
        for profile in [
            ScoringProfile::Minimal,
            ScoringProfile::Standard,
            ScoringProfile::Security,
            ScoringProfile::LicenseCompliance,
            ScoringProfile::Cra,
            ScoringProfile::BsiTr03183_2,
            ScoringProfile::Comprehensive,
            ScoringProfile::Cbom,
            ScoringProfile::AiReadiness,
        ] {
            let _ = QualityScorer::new(profile).score(&sbom);
        }
    }
});
