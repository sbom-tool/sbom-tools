#![no_main]
use libfuzzer_sys::fuzz_target;
use sbom_tools::parsers::{SpdxParser, SbomParser};

/// Fuzz the SPDX tag-value parser.
///
/// Prefixes input with the SPDX tag-value header to exercise the
/// line-by-line tag-value parsing logic.
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let parser = SpdxParser::new();

        // Try raw input
        let _ = parser.parse_str(s);

        // Try wrapping with SPDX tag-value header
        if s.len() < 10_000 {
            let wrapped = format!(
                "SPDXVersion: SPDX-2.3\nDataLicense: CC0-1.0\nSPDXID: SPDXRef-DOCUMENT\nDocumentName: fuzz\nDocumentNamespace: https://example.com/fuzz\n{s}",
            );
            let _ = parser.parse_str(&wrapped);
        }
    }
});
