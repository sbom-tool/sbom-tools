#![no_main]
use libfuzzer_sys::fuzz_target;

/// Fuzz the main SBOM parsing entry point.
///
/// Feeds arbitrary UTF-8 strings to `parse_sbom_str`, which runs format
/// detection and dispatches to the appropriate parser. This exercises all
/// format detection heuristics and every parser path.
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = sbom_tools::parsers::parse_sbom_str(s);
    }
});
