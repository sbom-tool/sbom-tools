#![no_main]
use libfuzzer_sys::fuzz_target;
use sbom_tools::parsers::{SpdxParser, SbomParser};

/// Fuzz the SPDX JSON parser directly.
///
/// Wraps input in an SPDX JSON envelope to reach the JSON parsing
/// internals rather than failing at detection.
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let parser = SpdxParser::new();

        // Try raw input
        let _ = parser.parse_str(s);

        // Try wrapping in SPDX JSON envelope
        if s.len() < 10_000 {
            let wrapped = format!(
                r#"{{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"fuzz","documentNamespace":"https://example.com/fuzz","packages":[{s}]}}"#,
            );
            let _ = parser.parse_str(&wrapped);
        }
    }
});
