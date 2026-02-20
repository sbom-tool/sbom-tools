#![no_main]
use libfuzzer_sys::fuzz_target;
use sbom_tools::parsers::{CycloneDxParser, SbomParser};

/// Fuzz the CycloneDX XML parser.
///
/// Wraps input in a CycloneDX XML envelope to exercise the XML
/// deserialization path.
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let parser = CycloneDxParser::new();

        // Try raw input
        let _ = parser.parse_str(s);

        // Try wrapping in CycloneDX XML envelope
        if s.len() < 10_000 {
            let wrapped = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">
  <components>{s}</components>
</bom>"#,
            );
            let _ = parser.parse_str(&wrapped);
        }
    }
});
