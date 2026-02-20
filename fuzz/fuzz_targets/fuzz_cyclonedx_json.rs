#![no_main]
use libfuzzer_sys::fuzz_target;
use sbom_tools::parsers::{CycloneDxParser, SbomParser};

/// Fuzz the CycloneDX JSON parser directly.
///
/// Prefixes input with a minimal CycloneDX JSON wrapper to increase
/// the likelihood of reaching deep parsing logic rather than failing
/// at format detection.
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let parser = CycloneDxParser::new();

        // Try raw input first
        let _ = parser.parse_str(s);

        // Also try wrapping in CycloneDX JSON envelope
        if s.len() < 10_000 {
            let wrapped = format!(
                r#"{{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{s}]}}"#,
            );
            let _ = parser.parse_str(&wrapped);
        }
    }
});
