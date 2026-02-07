//! Parser trait definitions and error types.
//!
//! This module defines the `SbomParser` trait for format-specific parsers
//! and provides intelligent format detection through confidence scoring.

use crate::model::NormalizedSbom;
use std::path::Path;
use thiserror::Error;

/// Errors that can occur during SBOM parsing
#[derive(Error, Debug)]
pub enum ParseError {
    #[error("IO error: {0}")]
    IoError(String),

    #[error("JSON parse error: {0}")]
    JsonError(String),

    #[error("XML parse error: {0}")]
    XmlError(String),

    #[error("YAML parse error: {0}")]
    YamlError(String),

    #[error("Invalid SBOM structure: {0}")]
    InvalidStructure(String),

    #[error("Unsupported format version: {0}")]
    UnsupportedVersion(String),

    #[error("Unknown SBOM format: {0}")]
    UnknownFormat(String),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Validation error: {0}")]
    ValidationError(String),
}

impl From<std::io::Error> for ParseError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err.to_string())
    }
}

impl From<serde_json::Error> for ParseError {
    fn from(err: serde_json::Error) -> Self {
        Self::JsonError(err.to_string())
    }
}

/// Confidence level for format detection
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct FormatConfidence(f32);

impl FormatConfidence {
    /// No confidence - definitely not this format
    pub const NONE: Self = Self(0.0);
    /// Low confidence - might be this format
    pub const LOW: Self = Self(0.25);
    /// Medium confidence - likely this format
    pub const MEDIUM: Self = Self(0.5);
    /// High confidence - almost certainly this format
    pub const HIGH: Self = Self(0.75);
    /// Certain - definitely this format
    pub const CERTAIN: Self = Self(1.0);

    /// Create a new confidence value
    #[must_use] 
    pub const fn new(value: f32) -> Self {
        Self(value.clamp(0.0, 1.0))
    }

    /// Get the confidence value
    #[must_use] 
    pub const fn value(&self) -> f32 {
        self.0
    }

    /// Check if this confidence indicates the format can be parsed
    #[must_use] 
    pub fn can_parse(&self) -> bool {
        self.0 >= 0.25
    }
}

impl Default for FormatConfidence {
    fn default() -> Self {
        Self::NONE
    }
}

/// Detection result from a parser
#[derive(Debug, Clone)]
pub struct FormatDetection {
    /// Confidence that this parser can handle the content
    pub confidence: FormatConfidence,
    /// Detected format variant (e.g., "JSON", "XML", "tag-value")
    pub variant: Option<String>,
    /// Detected version if applicable
    pub version: Option<String>,
    /// Any issues detected that might affect parsing
    pub warnings: Vec<String>,
}

impl FormatDetection {
    /// Create a detection result indicating no match
    #[must_use] 
    pub const fn no_match() -> Self {
        Self {
            confidence: FormatConfidence::NONE,
            variant: None,
            version: None,
            warnings: Vec::new(),
        }
    }

    /// Create a detection result with confidence
    #[must_use] 
    pub const fn with_confidence(confidence: FormatConfidence) -> Self {
        Self {
            confidence,
            variant: None,
            version: None,
            warnings: Vec::new(),
        }
    }

    /// Set the detected variant
    #[must_use]
    pub fn variant(mut self, variant: &str) -> Self {
        self.variant = Some(variant.to_string());
        self
    }

    /// Set the detected version
    #[must_use]
    pub fn version(mut self, version: &str) -> Self {
        self.version = Some(version.to_string());
        self
    }

    /// Add a warning
    #[must_use]
    pub fn warning(mut self, warning: &str) -> Self {
        self.warnings.push(warning.to_string());
        self
    }
}

/// Trait for SBOM format parsers
///
/// Implementors should provide format detection via `detect()` and parsing via `parse_str()`.
/// The detection method allows intelligent format selection without expensive trial-and-error parsing.
pub trait SbomParser {
    /// Parse SBOM from a file path
    fn parse(&self, path: &Path) -> Result<NormalizedSbom, ParseError> {
        let content = std::fs::read_to_string(path)?;
        self.parse_str(&content)
    }

    /// Parse SBOM from string content
    fn parse_str(&self, content: &str) -> Result<NormalizedSbom, ParseError>;

    /// Get supported format versions
    fn supported_versions(&self) -> Vec<&str>;

    /// Get format name
    fn format_name(&self) -> &str;

    /// Detect if this parser can handle the given content
    ///
    /// This performs lightweight structural validation without full parsing.
    /// Returns a confidence score and any detected metadata about the format.
    fn detect(&self, content: &str) -> FormatDetection;

    /// Quick check if this parser can likely handle the content
    ///
    /// Default implementation delegates to `detect()`, but parsers may override
    /// with a faster heuristic check.
    fn can_parse(&self, content: &str) -> bool {
        self.detect(content).confidence.can_parse()
    }

    /// Get confidence score for parsing this content
    ///
    /// Default implementation delegates to `detect()`.
    fn confidence(&self, content: &str) -> FormatConfidence {
        self.detect(content).confidence
    }
}
