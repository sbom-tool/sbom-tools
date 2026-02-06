//! Centralized format detection for SBOM parsers.
//!
//! This module provides consistent format detection logic used by both
//! the standard parser and streaming parser, ensuring aligned confidence
//! thresholds and detection behavior.

use super::traits::{FormatConfidence, FormatDetection, ParseError, SbomParser};
use super::{CycloneDxParser, SpdxParser};
use crate::model::NormalizedSbom;
use std::io::BufRead;

/// Minimum confidence threshold for accepting a format detection.
/// This is LOW confidence (0.25) - the parser believes it might be able to handle the content.
pub const MIN_CONFIDENCE_THRESHOLD: f32 = 0.25;

/// Parser type identified during detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParserKind {
    CycloneDx,
    Spdx,
}

impl ParserKind {
    /// Get the human-readable name for this parser.
    pub fn name(&self) -> &'static str {
        match self {
            Self::CycloneDx => "CycloneDX",
            Self::Spdx => "SPDX",
        }
    }
}

/// Result of format detection.
#[derive(Debug, Clone)]
pub struct DetectionResult {
    /// The parser that should handle this content, if detected.
    pub parser: Option<ParserKind>,
    /// Confidence level of the detection.
    pub confidence: FormatConfidence,
    /// Detected format variant (e.g., "JSON", "XML", "tag-value").
    pub variant: Option<String>,
    /// Detected version if available.
    pub version: Option<String>,
    /// Any warnings about the detection.
    pub warnings: Vec<String>,
}

impl DetectionResult {
    /// Create a result indicating no format was detected.
    pub fn unknown(reason: &str) -> Self {
        Self {
            parser: None,
            confidence: FormatConfidence::NONE,
            variant: None,
            version: None,
            warnings: vec![reason.to_string()],
        }
    }

    /// Create a result for CycloneDX detection.
    pub fn cyclonedx(detection: FormatDetection) -> Self {
        Self {
            parser: Some(ParserKind::CycloneDx),
            confidence: detection.confidence,
            variant: detection.variant,
            version: detection.version,
            warnings: detection.warnings,
        }
    }

    /// Create a result for SPDX detection.
    pub fn spdx(detection: FormatDetection) -> Self {
        Self {
            parser: Some(ParserKind::Spdx),
            confidence: detection.confidence,
            variant: detection.variant,
            version: detection.version,
            warnings: detection.warnings,
        }
    }

    /// Check if the detection is confident enough to parse.
    pub fn can_parse(&self) -> bool {
        self.parser.is_some() && self.confidence.value() >= MIN_CONFIDENCE_THRESHOLD
    }
}

/// Centralized format detector for SBOM content.
///
/// Provides consistent detection logic for both standard and streaming parsers.
pub struct FormatDetector {
    cyclonedx: CycloneDxParser,
    spdx: SpdxParser,
    min_confidence: f32,
}

impl Default for FormatDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl FormatDetector {
    /// Create a new format detector with default settings.
    pub fn new() -> Self {
        Self {
            cyclonedx: CycloneDxParser::new(),
            spdx: SpdxParser::new(),
            min_confidence: MIN_CONFIDENCE_THRESHOLD,
        }
    }

    /// Create a format detector with a custom confidence threshold.
    pub fn with_threshold(min_confidence: f32) -> Self {
        Self {
            cyclonedx: CycloneDxParser::new(),
            spdx: SpdxParser::new(),
            min_confidence: min_confidence.clamp(0.0, 1.0),
        }
    }

    /// Detect format from full content string.
    ///
    /// This performs full detection using each parser's detect() method.
    pub fn detect_from_content(&self, content: &str) -> DetectionResult {
        let cdx_detection = self.cyclonedx.detect(content);
        let spdx_detection = self.spdx.detect(content);

        self.select_best_parser(cdx_detection, spdx_detection)
    }

    /// Detect format from peeked bytes (for streaming).
    ///
    /// This performs detection using a prefix of the content, suitable for
    /// streaming parsers that can only peek at the beginning of a file.
    pub fn detect_from_peek(&self, peek: &[u8]) -> DetectionResult {
        // Find first non-whitespace byte
        let first_char = peek.iter().find(|&&b| !b.is_ascii_whitespace());

        match first_char {
            Some(b'{' | b'<') => {
                // Convert peek to string for detection
                let preview = String::from_utf8_lossy(peek);

                // Use actual parser detection methods for consistency
                let cdx_detection = self.cyclonedx.detect(&preview);
                let spdx_detection = self.spdx.detect(&preview);

                self.select_best_parser(cdx_detection, spdx_detection)
            }
            Some(c) if c.is_ascii_alphabetic() => {
                // Might be tag-value format (starts with letters like "SPDXVersion:")
                let preview = String::from_utf8_lossy(peek);
                let cdx_detection = self.cyclonedx.detect(&preview);
                let spdx_detection = self.spdx.detect(&preview);

                self.select_best_parser(cdx_detection, spdx_detection)
            }
            Some(_) => DetectionResult::unknown("Unrecognized content format"),
            None => DetectionResult::unknown("Empty content"),
        }
    }

    /// Select the best parser based on detection results.
    ///
    /// Uses consistent threshold checking and returns an error-like result
    /// instead of defaulting to a specific parser when ambiguous.
    fn select_best_parser(
        &self,
        cdx_detection: FormatDetection,
        spdx_detection: FormatDetection,
    ) -> DetectionResult {
        let cdx_conf = cdx_detection.confidence.value();
        let spdx_conf = spdx_detection.confidence.value();

        // Log detection for debugging
        tracing::debug!(
            "Format detection: CycloneDX={:.2}, SPDX={:.2}, threshold={:.2}",
            cdx_conf,
            spdx_conf,
            self.min_confidence
        );

        // Apply consistent threshold and select best parser
        if cdx_conf >= self.min_confidence && cdx_conf > spdx_conf {
            DetectionResult::cyclonedx(cdx_detection)
        } else if spdx_conf >= self.min_confidence {
            DetectionResult::spdx(spdx_detection)
        } else {
            // No default bias - return unknown if neither meets threshold
            let mut result =
                DetectionResult::unknown("Could not detect SBOM format with sufficient confidence");

            // Add helpful context about what was detected
            if cdx_conf > 0.0 {
                result.warnings.push(format!(
                    "CycloneDX detection: {:.0}% confidence (threshold: {:.0}%)",
                    cdx_conf * 100.0,
                    self.min_confidence * 100.0
                ));
            }
            if spdx_conf > 0.0 {
                result.warnings.push(format!(
                    "SPDX detection: {:.0}% confidence (threshold: {:.0}%)",
                    spdx_conf * 100.0,
                    self.min_confidence * 100.0
                ));
            }

            result
        }
    }

    /// Parse content using the detected format.
    ///
    /// This combines detection and parsing in a single operation.
    pub fn parse_str(&self, content: &str) -> Result<NormalizedSbom, ParseError> {
        let detection = self.detect_from_content(content);

        // Log any warnings
        for warning in &detection.warnings {
            tracing::warn!("{}", warning);
        }

        match detection.parser {
            Some(ParserKind::CycloneDx) if detection.can_parse() => {
                self.cyclonedx.parse_str(content)
            }
            Some(ParserKind::Spdx) if detection.can_parse() => self.spdx.parse_str(content),
            _ => Err(ParseError::UnknownFormat(
                "Could not detect SBOM format. Expected CycloneDX or SPDX.".to_string(),
            )),
        }
    }

    /// Parse from a reader using streaming JSON parsing.
    ///
    /// Peeks at the content to detect format, then uses the appropriate
    /// reader-based parser for memory-efficient parsing.
    pub fn parse_reader<R: BufRead>(&self, mut reader: R) -> Result<NormalizedSbom, ParseError> {
        // Peek at the buffer to detect format
        let peek = reader
            .fill_buf()
            .map_err(|e| ParseError::IoError(e.to_string()))?;

        if peek.is_empty() {
            return Err(ParseError::IoError("Empty content".to_string()));
        }

        let detection = self.detect_from_peek(peek);

        // Log any warnings
        for warning in &detection.warnings {
            tracing::warn!("{}", warning);
        }

        match detection.parser {
            Some(ParserKind::CycloneDx) if detection.can_parse() => {
                // Check if it's XML (needs string-based parsing)
                let is_xml = detection.variant.as_deref() == Some("XML");
                if is_xml {
                    let mut content = String::new();
                    reader
                        .read_to_string(&mut content)
                        .map_err(|e| ParseError::IoError(e.to_string()))?;
                    self.cyclonedx.parse_str(&content)
                } else {
                    self.cyclonedx.parse_json_reader(reader)
                }
            }
            Some(ParserKind::Spdx) if detection.can_parse() => {
                // Check variant - tag-value and RDF need string-based parsing
                let needs_string = matches!(
                    detection.variant.as_deref(),
                    Some("tag-value" | "RDF")
                );
                if needs_string {
                    let mut content = String::new();
                    reader
                        .read_to_string(&mut content)
                        .map_err(|e| ParseError::IoError(e.to_string()))?;
                    self.spdx.parse_str(&content)
                } else {
                    self.spdx.parse_json_reader(reader)
                }
            }
            _ => Err(ParseError::UnknownFormat(
                "Could not detect SBOM format. Expected CycloneDX or SPDX.".to_string(),
            )),
        }
    }

    /// Get a reference to the CycloneDX parser.
    pub fn cyclonedx_parser(&self) -> &CycloneDxParser {
        &self.cyclonedx
    }

    /// Get a reference to the SPDX parser.
    pub fn spdx_parser(&self) -> &SpdxParser {
        &self.spdx
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_cyclonedx_json() {
        let detector = FormatDetector::new();
        let content = r#"{"bomFormat": "CycloneDX", "specVersion": "1.5"}"#;
        let result = detector.detect_from_content(content);

        assert_eq!(result.parser, Some(ParserKind::CycloneDx));
        assert!(result.can_parse());
        assert_eq!(result.variant, Some("JSON".to_string()));
    }

    #[test]
    fn test_detect_spdx_json() {
        let detector = FormatDetector::new();
        let content = r#"{"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT"}"#;
        let result = detector.detect_from_content(content);

        assert_eq!(result.parser, Some(ParserKind::Spdx));
        assert!(result.can_parse());
        assert_eq!(result.variant, Some("JSON".to_string()));
    }

    #[test]
    fn test_detect_from_peek_cyclonedx() {
        let detector = FormatDetector::new();
        let peek = br#"{"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}"#;
        let result = detector.detect_from_peek(peek);

        assert_eq!(result.parser, Some(ParserKind::CycloneDx));
        assert!(result.can_parse());
    }

    #[test]
    fn test_detect_unknown_format() {
        let detector = FormatDetector::new();
        let content = r#"{"some": "random", "json": "content"}"#;
        let result = detector.detect_from_content(content);

        assert!(result.parser.is_none());
        assert!(!result.can_parse());
    }

    #[test]
    fn test_no_default_bias() {
        let detector = FormatDetector::new();
        // Ambiguous JSON that doesn't match either format
        let content = r#"{"data": "test"}"#;
        let result = detector.detect_from_content(content);

        // Should NOT default to CycloneDX or any other format
        assert!(result.parser.is_none());
        assert!(!result.can_parse());
    }

    #[test]
    fn test_threshold_enforcement() {
        let detector = FormatDetector::with_threshold(0.5);
        // Content with low confidence might not pass higher threshold
        let content = r#"{"specVersion": "1.5", "components": []}"#;
        let result = detector.detect_from_content(content);

        // If confidence is below 0.5, should not parse
        if result.confidence.value() < 0.5 {
            assert!(!result.can_parse());
        }
    }
}
