//! SBOM format parsers.
//!
//! This module provides parsers for CycloneDX and SPDX SBOM formats,
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
mod detection;
mod spdx;
pub mod streaming;
mod traits;

pub use cyclonedx::CycloneDxParser;
pub use detection::{DetectionResult, FormatDetector, ParserKind, MIN_CONFIDENCE_THRESHOLD};
pub use spdx::SpdxParser;
pub use streaming::{ParseEvent, ParseProgress, StreamingConfig, StreamingParser};
pub use traits::{FormatConfidence, FormatDetection, ParseError, SbomParser};

use crate::model::NormalizedSbom;
use std::path::Path;

/// Result of format detection
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

/// Maximum SBOM file size (512 MB). Files larger than this should use the streaming parser.
const MAX_SBOM_FILE_SIZE: u64 = 512 * 1024 * 1024;

/// Detect SBOM format from file content and parse accordingly
///
/// Uses confidence-based detection to select the best parser.
/// Returns an error if the file exceeds [`MAX_SBOM_FILE_SIZE`] to prevent OOM.
/// For very large files, use the streaming parser instead.
pub fn parse_sbom(path: &Path) -> Result<NormalizedSbom, ParseError> {
    let metadata = std::fs::metadata(path).map_err(|e| ParseError::IoError(e.to_string()))?;
    if metadata.len() > MAX_SBOM_FILE_SIZE {
        return Err(ParseError::IoError(format!(
            "SBOM file is {} MB, exceeding the {} MB limit. Use the streaming parser for large files.",
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

/// Check if content looks like CycloneDX
#[deprecated(
    since = "0.2.0",
    note = "Use detect_format() or CycloneDxParser::detect() instead"
)]
pub fn is_cyclonedx(content: &str) -> bool {
    CycloneDxParser::new().can_parse(content)
}

/// Check if content looks like SPDX
#[deprecated(
    since = "0.2.0",
    note = "Use detect_format() or SpdxParser::detect() instead"
)]
pub fn is_spdx(content: &str) -> bool {
    SpdxParser::new().can_parse(content)
}

#[cfg(test)]
mod tests {
    use super::*;

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
