#![no_main]
use libfuzzer_sys::fuzz_target;

/// Fuzz the format detection logic.
///
/// Exercises the confidence-based format detection without parsing,
/// testing the heuristic matching code paths.
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = sbom_tools::parsers::detect_format(s);
    }
});
