//! SBOM format parsers.
//!
//! This module provides parsers for `CycloneDX` and SPDX SBOM formats,
//! converting them to the normalized intermediate representation.
//!
//! ## Format Detection
//!
//! The module uses a confidence-based detection system to identify SBOM formats:
//! - Each parser reports a confidence score (0.0-1.0) for handling content
//! - The parser with the highest confidence is selected
//! - Detection includes format variant (JSON, XML, tag-value) and version information
//!
//! ## Usage
//!
//! ```no_run
//! use sbom_tools::parsers::{parse_sbom, detect_format};
//! use std::path::Path;
//!
//! // Auto-detect and parse
//! let sbom = parse_sbom(Path::new("sbom.json")).unwrap();
//!
//! // Check format before parsing
//! let content = std::fs::read_to_string("sbom.json").unwrap();
//! if let Some(detection) = detect_format(&content) {
//!     println!("Detected: {} ({})", detection.format_name, detection.confidence);
//! }
//! ```

mod cyclonedx;
pub(crate) mod cyclonedx_analysis;
mod detection;
mod spdx;
mod spdx3;
pub mod streaming;
mod traits;

pub use cyclonedx::CycloneDxParser;
pub use detection::{DetectionResult, FormatDetector, MIN_CONFIDENCE_THRESHOLD, ParserKind};
pub use spdx::SpdxParser;
pub use spdx3::Spdx3Parser;
pub use streaming::{ParseEvent, ParseProgress, ParsedMetadata, StreamingConfig, StreamingParser};
pub use traits::{FormatConfidence, FormatDetection, ParseError, SbomParser};

use crate::model::NormalizedSbom;
use std::path::Path;

/// Result of format detection
///
/// Note: Serialize/Deserialize support was added in v0.1.18 to support FFI and
/// external tooling integration. This is a backwards-compatible expansion of the API.
#[cfg_attr(feature = "ffi", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone)]
pub struct DetectedFormat {
    /// Name of the detected format
    pub format_name: String,
    /// Confidence score (0.0-1.0)
    pub confidence: f32,
    /// Detected variant (e.g., "JSON", "XML", "tag-value")
    pub variant: Option<String>,
    /// Detected version if available
    pub version: Option<String>,
    /// Any warnings about the detection
    pub warnings: Vec<String>,
}

/// Detect SBOM format from content without parsing
///
/// Returns None if no format could be detected with sufficient confidence.
#[must_use]
pub fn detect_format(content: &str) -> Option<DetectedFormat> {
    let detector = FormatDetector::new();
    let result = detector.detect_from_content(content);

    if result.can_parse() {
        Some(DetectedFormat {
            format_name: result
                .parser
                .map(|p| p.name().to_string())
                .unwrap_or_default(),
            confidence: result.confidence.value(),
            variant: result.variant,
            version: result.version,
            warnings: result.warnings,
        })
    } else {
        None
    }
}

/// Maximum SBOM file size (512 MB), enforced to bound memory use when loading a
/// whole document into a string. Inputs larger than this are rejected.
pub(crate) const MAX_SBOM_FILE_SIZE: u64 = 512 * 1024 * 1024;

/// Synthetic component property recording that the source document
/// positively declared the component as having no dependencies (e.g. a
/// CycloneDX `dependencies` entry with an empty `dependsOn`). Compliance
/// checks treat such components as documented, not missing from the graph.
pub const DECLARED_NO_DEPENDENCIES_PROPERTY: &str = "sbom-tools:declared-no-dependencies";

/// Set the document's vulnerability-disclosure URL from the primary
/// component, the one rule every parser applies: the first `advisories`
/// reference (CycloneDX `advisories`, SPDX 2 SECURITY `advisory`/`fix`/`url`,
/// SPDX 3 `securityAdvisory`) whose locator is a URL (`http://`, `https://`
/// or `mailto:`). A bare CPE string or another identifier never becomes the
/// disclosure URL, and neither does a `support` reference: a helpdesk is not
/// a vulnerability-disclosure policy. A URL already set is kept. Call it
/// once the primary component is in the SBOM.
pub(crate) fn lift_disclosure_url(sbom: &mut NormalizedSbom) {
    if sbom.document.vulnerability_disclosure_url.is_some() {
        return;
    }
    let url = sbom.primary_component().and_then(|primary| {
        primary
            .external_refs
            .iter()
            .find(|r| {
                r.ref_type == crate::model::ExternalRefType::Advisories && is_url_shaped(&r.url)
            })
            .map(|r| r.url.clone())
    });
    if url.is_some() {
        sbom.document.vulnerability_disclosure_url = url;
    }
}

/// Whether a reference locator is a URL a reader can follow: `http://`,
/// `https://` or `mailto:` (in any letter case) and something after it.
fn is_url_shaped(locator: &str) -> bool {
    let locator = locator.trim();
    ["http://", "https://", "mailto:"].iter().any(|scheme| {
        locator.len() > scheme.len()
            && locator
                .get(..scheme.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(scheme))
    })
}

/// Strip a leading UTF-8 BOM (U+FEFF), if present.
///
/// `str::trim()` does not remove U+FEFF (it is not `White_Space`), so a
/// BOM-prefixed but otherwise valid SBOM file fails every parser's
/// `content.trim().starts_with('{'/'<')` dispatch and is rejected as
/// unknown format. Every parser's `detect()`/`parse_str()` calls this first.
pub(crate) fn strip_bom(content: &str) -> &str {
    content.strip_prefix('\u{FEFF}').unwrap_or(content)
}

/// Whether `content` contains `key` used as a JSON object key — i.e. a
/// quoted `key` immediately followed by (optional whitespace, then) `:` —
/// rather than merely appearing as, or inside, a string *value* anywhere in
/// the document.
///
/// Format detection scans raw text for markers like `"spdxVersion"` without
/// parsing JSON, so a document whose value happens to equal a marker word
/// (e.g. a component literally named `"spdxVersion"`, or a property value of
/// `"SPDXID"`) previously tripped detection for an unrelated format. This
/// keeps detection allocation-free and streaming-peek-compatible while
/// requiring the marker to be used as a key, not a coincidental value.
pub(crate) fn contains_json_key(content: &str, key: &str) -> bool {
    let quoted = format!("\"{key}\"");
    let mut search_from = 0;
    while let Some(rel) = content[search_from..].find(quoted.as_str()) {
        let after = search_from + rel + quoted.len();
        if content[after..].trim_start().starts_with(':') {
            return true;
        }
        search_from = after;
    }
    false
}

/// Defensive cap on a single vulnerability description (64 KiB).
///
/// A vulnerability's description is attacker-controlled and attached to every
/// component the vulnerability affects; without a cap, one huge description
/// deep-cloned across thousands of `affects`/`to` targets is a memory-
/// amplification DoS. Real CVE descriptions are a paragraph, so 64 KiB is
/// ~100x headroom while bounding the per-target clone to a constant.
pub(crate) const MAX_VULN_DESCRIPTION_BYTES: usize = 64 * 1024;

/// Clone an optional description, truncated to [`MAX_VULN_DESCRIPTION_BYTES`]
/// on a UTF-8 char boundary with a marker appended when truncated.
pub(crate) fn capped_description(desc: &Option<String>) -> Option<String> {
    desc.as_ref().map(|d| {
        if d.len() <= MAX_VULN_DESCRIPTION_BYTES {
            return d.clone();
        }
        let mut end = MAX_VULN_DESCRIPTION_BYTES;
        while end > 0 && !d.is_char_boundary(end) {
            end -= 1;
        }
        let mut truncated = d[..end].to_string();
        truncated.push_str("… [truncated]");
        truncated
    })
}

/// Detect SBOM format from file content and parse accordingly
///
/// Uses confidence-based detection to select the best parser.
/// Returns an error if the file exceeds [`MAX_SBOM_FILE_SIZE`] to prevent OOM.
pub fn parse_sbom(path: &Path) -> Result<NormalizedSbom, ParseError> {
    let metadata = std::fs::metadata(path).map_err(|e| ParseError::IoError(e.to_string()))?;
    if metadata.len() > MAX_SBOM_FILE_SIZE {
        return Err(ParseError::IoError(format!(
            "SBOM file is {} MB, exceeding the {} MB limit. Split the document or filter it (e.g. `sbom-tools tailor`) before processing.",
            metadata.len() / (1024 * 1024),
            MAX_SBOM_FILE_SIZE / (1024 * 1024),
        )));
    }
    let content = std::fs::read_to_string(path).map_err(|e| ParseError::IoError(e.to_string()))?;
    parse_sbom_str(&content)
}

/// Parse SBOM from string content
///
/// Uses confidence-based detection to select the best parser.
pub fn parse_sbom_str(content: &str) -> Result<NormalizedSbom, ParseError> {
    let detector = FormatDetector::new();
    detector.parse_str(content)
}

// Legacy detection functions - kept for backwards compatibility but deprecated

/// Check if content looks like `CycloneDX`
#[deprecated(
    since = "0.2.0",
    note = "Use detect_format() or CycloneDxParser::detect() instead"
)]
#[must_use]
pub fn is_cyclonedx(content: &str) -> bool {
    CycloneDxParser::new().can_parse(content)
}

/// Check if content looks like SPDX
#[deprecated(
    since = "0.2.0",
    note = "Use detect_format() or SpdxParser::detect() instead"
)]
#[must_use]
pub fn is_spdx(content: &str) -> bool {
    SpdxParser::new().can_parse(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capped_description_truncates_on_char_boundary() {
        assert_eq!(capped_description(&None), None);
        assert_eq!(
            capped_description(&Some("short".to_string())).as_deref(),
            Some("short")
        );
        // Multi-byte char straddling the cap must not panic and must produce
        // valid UTF-8.
        let big = "é".repeat(MAX_VULN_DESCRIPTION_BYTES); // 2 bytes each
        let out = capped_description(&Some(big)).unwrap();
        assert!(out.len() <= MAX_VULN_DESCRIPTION_BYTES + 16);
        assert!(out.ends_with("… [truncated]"));
        assert!(std::str::from_utf8(out.as_bytes()).is_ok());
    }

    #[test]
    fn strip_bom_removes_only_a_leading_marker() {
        assert_eq!(strip_bom("\u{FEFF}{\"a\":1}"), "{\"a\":1}");
        assert_eq!(strip_bom("{\"a\":1}"), "{\"a\":1}");
        // A BOM elsewhere in the content (not at the start) is untouched.
        assert_eq!(strip_bom("{\"a\":\"\u{FEFF}\"}"), "{\"a\":\"\u{FEFF}\"}");
    }

    #[test]
    fn contains_json_key_requires_key_position() {
        assert!(contains_json_key(
            r#"{"spdxVersion":"SPDX-2.3"}"#,
            "spdxVersion"
        ));
        assert!(contains_json_key(
            r#"{"spdxVersion"   :   "SPDX-2.3"}"#,
            "spdxVersion"
        ));
        // A value equal to the marker word must NOT count as a key.
        assert!(!contains_json_key(
            r#"{"name":"spdxVersion","other":1}"#,
            "spdxVersion"
        ));
        assert!(!contains_json_key("no markers here", "spdxVersion"));
    }

    /// A BOM-prefixed CycloneDX document must parse successfully end to end,
    /// not just detect correctly — the dispatch check and the actual
    /// serde_json::from_str/quick_xml call must both see BOM-free content.
    #[test]
    fn bom_prefixed_document_parses_end_to_end() {
        let content = "\u{FEFF}{\"bomFormat\": \"CycloneDX\", \"specVersion\": \"1.5\", \
            \"components\": [{\"type\": \"library\", \"name\": \"lib\", \"version\": \"1.0\"}]}";
        let sbom = parse_sbom_str(content).expect("BOM-prefixed document must parse");
        assert_eq!(sbom.component_count(), 1);
    }

    #[test]
    fn test_detect_cyclonedx_json() {
        let content = r#"{"bomFormat": "CycloneDX", "specVersion": "1.5"}"#;
        let detected = detect_format(content).expect("Should detect format");
        assert_eq!(detected.format_name, "CycloneDX");
        assert!(detected.confidence >= 0.75);
        assert_eq!(detected.variant, Some("JSON".to_string()));
        assert_eq!(detected.version, Some("1.5".to_string()));
    }

    #[test]
    fn test_detect_cyclonedx_xml() {
        let content = r#"<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">
  <components/>
</bom>"#;
        let detected = detect_format(content).expect("Should detect format");
        assert_eq!(detected.format_name, "CycloneDX");
        assert!(detected.confidence >= 0.75);
        assert_eq!(detected.variant, Some("XML".to_string()));
    }

    #[test]
    fn test_detect_spdx_json() {
        let content = r#"{"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT"}"#;
        let detected = detect_format(content).expect("Should detect format");
        assert_eq!(detected.format_name, "SPDX");
        assert!(detected.confidence >= 0.75);
        assert_eq!(detected.variant, Some("JSON".to_string()));
        assert_eq!(detected.version, Some("2.3".to_string()));
    }

    #[test]
    fn test_detect_spdx_tag_value() {
        let content = "SPDXVersion: SPDX-2.3\nDataLicense: CC0-1.0\nSPDXID: SPDXRef-DOCUMENT";
        let detected = detect_format(content).expect("Should detect format");
        assert_eq!(detected.format_name, "SPDX");
        assert!(detected.confidence >= 0.75);
        assert_eq!(detected.variant, Some("tag-value".to_string()));
        assert_eq!(detected.version, Some("2.3".to_string()));
    }

    #[test]
    fn test_detect_unknown_format() {
        let content = r#"{"some": "random", "json": "content"}"#;
        let detected = detect_format(content);
        assert!(detected.is_none());
    }

    #[test]
    fn test_detect_spdx3_json_ld() {
        let content = r#"{"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld", "type": "SpdxDocument", "spdxId": "urn:spdx:doc:test", "creationInfo": {"specVersion": "3.0.1"}}"#;
        let detected = detect_format(content).expect("Should detect SPDX 3.0 format");
        assert_eq!(detected.format_name, "SPDX");
        assert!(detected.confidence >= 0.9);
        assert_eq!(detected.variant, Some("JSON-LD".to_string()));
    }

    #[test]
    fn test_confidence_based_selection() {
        // CycloneDX should have higher confidence for this content
        let cdx_content = r#"{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}"#;
        let cdx_parser = CycloneDxParser::new();
        let spdx_parser = SpdxParser::new();

        let cdx_conf = cdx_parser.confidence(cdx_content);
        let spdx_conf = spdx_parser.confidence(cdx_content);

        assert!(cdx_conf.value() > spdx_conf.value());
    }
}
