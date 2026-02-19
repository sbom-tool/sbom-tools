//! Unified error types for sbom-tools.
//!
//! This module provides a comprehensive error hierarchy for the library,
//! with rich context for debugging and user-friendly messages.

use std::path::PathBuf;
use thiserror::Error;

/// Main error type for sbom-tools operations.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum SbomDiffError {
    /// Errors during SBOM parsing
    #[error("Failed to parse SBOM: {context}")]
    Parse {
        context: String,
        #[source]
        source: ParseErrorKind,
    },

    /// Errors during diff computation
    #[error("Diff computation failed: {context}")]
    Diff {
        context: String,
        #[source]
        source: DiffErrorKind,
    },

    /// Errors during report generation
    #[error("Report generation failed: {context}")]
    Report {
        context: String,
        #[source]
        source: ReportErrorKind,
    },

    /// Errors during matching operations
    #[error("Matching operation failed: {context}")]
    Matching {
        context: String,
        #[source]
        source: MatchingErrorKind,
    },

    /// Errors during enrichment operations
    #[error("Enrichment failed: {context}")]
    Enrichment {
        context: String,
        #[source]
        source: EnrichmentErrorKind,
    },

    /// IO errors with context
    #[error("IO error at {path:?}: {message}")]
    Io {
        path: Option<PathBuf>,
        message: String,
        #[source]
        source: std::io::Error,
    },

    /// Configuration errors
    #[error("Invalid configuration: {0}")]
    Config(String),

    /// Validation errors
    #[error("Validation failed: {0}")]
    Validation(String),
}

/// Specific parse error kinds
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum ParseErrorKind {
    #[error("Unknown SBOM format - expected CycloneDX or SPDX markers")]
    UnknownFormat,

    #[error("Unsupported format version: {version} (supported: {supported})")]
    UnsupportedVersion { version: String, supported: String },

    #[error("Invalid JSON structure: {0}")]
    InvalidJson(String),

    #[error("Invalid XML structure: {0}")]
    InvalidXml(String),

    #[error("Missing required field: {field} in {context}")]
    MissingField { field: String, context: String },

    #[error("Invalid field value for '{field}': {message}")]
    InvalidValue { field: String, message: String },

    #[error("Malformed PURL: {purl} - {reason}")]
    InvalidPurl { purl: String, reason: String },

    #[error("CycloneDX parsing error: {0}")]
    CycloneDx(String),

    #[error("SPDX parsing error: {0}")]
    Spdx(String),
}

/// Specific diff error kinds
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum DiffErrorKind {
    #[error("Component matching failed: {0}")]
    MatchingFailed(String),

    #[error("Cost model configuration error: {0}")]
    CostModelError(String),

    #[error("Graph construction failed: {0}")]
    GraphError(String),

    #[error("Empty SBOM provided")]
    EmptySbom,
}

/// Specific report error kinds
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum ReportErrorKind {
    #[error("Template rendering failed: {0}")]
    TemplateError(String),

    #[error("JSON serialization failed: {0}")]
    JsonSerializationError(String),

    #[error("SARIF generation failed: {0}")]
    SarifError(String),

    #[error("Output format not supported for this operation: {0}")]
    UnsupportedFormat(String),
}

/// Specific matching error kinds
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum MatchingErrorKind {
    #[error("Alias table not found: {0}")]
    AliasTableNotFound(String),

    #[error("Invalid threshold value: {0} (must be 0.0-1.0)")]
    InvalidThreshold(f64),

    #[error("Ecosystem not supported: {0}")]
    UnsupportedEcosystem(String),
}

/// Specific enrichment error kinds
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum EnrichmentErrorKind {
    #[error("API request failed: {0}")]
    ApiError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Cache error: {0}")]
    CacheError(String),

    #[error("Invalid response format: {0}")]
    InvalidResponse(String),

    #[error("Rate limited: {0}")]
    RateLimited(String),

    #[error("Provider unavailable: {0}")]
    ProviderUnavailable(String),
}

// ============================================================================
// Result type alias
// ============================================================================

/// Convenient Result type for sbom-tools operations
pub type Result<T> = std::result::Result<T, SbomDiffError>;

// ============================================================================
// Error construction helpers
// ============================================================================

impl SbomDiffError {
    /// Create a parse error with context
    pub fn parse(context: impl Into<String>, source: ParseErrorKind) -> Self {
        Self::Parse {
            context: context.into(),
            source,
        }
    }

    /// Create a parse error for unknown format
    pub fn unknown_format(path: impl Into<String>) -> Self {
        Self::parse(format!("at {}", path.into()), ParseErrorKind::UnknownFormat)
    }

    /// Create a parse error for missing field
    pub fn missing_field(field: impl Into<String>, context: impl Into<String>) -> Self {
        Self::parse(
            "missing required field",
            ParseErrorKind::MissingField {
                field: field.into(),
                context: context.into(),
            },
        )
    }

    /// Create an IO error with path context
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        let path = path.into();
        let message = format!("{source}");
        Self::Io {
            path: Some(path),
            message,
            source,
        }
    }

    /// Create a validation error
    pub fn validation(message: impl Into<String>) -> Self {
        Self::Validation(message.into())
    }

    /// Create a config error
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    /// Create a diff error
    pub fn diff(context: impl Into<String>, source: DiffErrorKind) -> Self {
        Self::Diff {
            context: context.into(),
            source,
        }
    }

    /// Create a report error
    pub fn report(context: impl Into<String>, source: ReportErrorKind) -> Self {
        Self::Report {
            context: context.into(),
            source,
        }
    }

    /// Create an enrichment error
    pub fn enrichment(context: impl Into<String>, source: EnrichmentErrorKind) -> Self {
        Self::Enrichment {
            context: context.into(),
            source,
        }
    }
}

// ============================================================================
// Conversions from existing error types
// ============================================================================

impl From<std::io::Error> for SbomDiffError {
    fn from(err: std::io::Error) -> Self {
        Self::Io {
            path: None,
            message: format!("{err}"),
            source: err,
        }
    }
}

impl From<serde_json::Error> for SbomDiffError {
    fn from(err: serde_json::Error) -> Self {
        Self::parse(
            "JSON deserialization",
            ParseErrorKind::InvalidJson(err.to_string()),
        )
    }
}

// ============================================================================
// Error context extension trait
// ============================================================================

/// Extension trait for adding context to errors.
///
/// This trait provides methods to add context information to errors,
/// creating a chain of context that helps trace the source of problems.
///
/// # Example
///
/// ```ignore
/// use sbom_tools::error::ErrorContext;
///
/// fn parse_component(data: &str) -> Result<Component> {
///     let json: Value = serde_json::from_str(data)
///         .context("parsing component JSON")?;
///
///     extract_component(&json)
///         .with_context(|| format!("extracting component from {}", data.chars().take(50).collect::<String>()))?
/// }
///
/// fn load_sbom(path: &Path) -> Result<NormalizedSbom> {
///     let content = std::fs::read_to_string(path)
///         .context("reading SBOM file")?;
///
///     parse_sbom_str(&content)
///         .with_context(|| format!("parsing SBOM from {}", path.display()))?
/// }
/// ```
pub trait ErrorContext<T> {
    /// Add context to an error.
    ///
    /// The context string is prepended to the error's existing context,
    /// creating a chain that shows the path through the code.
    fn context(self, context: impl Into<String>) -> Result<T>;

    /// Add context from a closure (lazy evaluation).
    ///
    /// The closure is only called if the result is an error,
    /// which is more efficient when the context string is expensive to compute.
    fn with_context<F, C>(self, f: F) -> Result<T>
    where
        F: FnOnce() -> C,
        C: Into<String>;
}

impl<T, E: Into<SbomDiffError>> ErrorContext<T> for std::result::Result<T, E> {
    fn context(self, context: impl Into<String>) -> Result<T> {
        let ctx: String = context.into();
        self.map_err(|e| add_context_to_error(e.into(), &ctx))
    }

    fn with_context<F, C>(self, f: F) -> Result<T>
    where
        F: FnOnce() -> C,
        C: Into<String>,
    {
        self.map_err(|e| {
            let ctx: String = f().into();
            add_context_to_error(e.into(), &ctx)
        })
    }
}

/// Add context to an error, chaining with any existing context.
fn add_context_to_error(err: SbomDiffError, new_ctx: &str) -> SbomDiffError {
    match err {
        SbomDiffError::Parse {
            context: existing,
            source,
        } => SbomDiffError::Parse {
            context: chain_context(new_ctx, &existing),
            source,
        },
        SbomDiffError::Diff {
            context: existing,
            source,
        } => SbomDiffError::Diff {
            context: chain_context(new_ctx, &existing),
            source,
        },
        SbomDiffError::Report {
            context: existing,
            source,
        } => SbomDiffError::Report {
            context: chain_context(new_ctx, &existing),
            source,
        },
        SbomDiffError::Matching {
            context: existing,
            source,
        } => SbomDiffError::Matching {
            context: chain_context(new_ctx, &existing),
            source,
        },
        SbomDiffError::Enrichment {
            context: existing,
            source,
        } => SbomDiffError::Enrichment {
            context: chain_context(new_ctx, &existing),
            source,
        },
        SbomDiffError::Io {
            path,
            message,
            source,
        } => SbomDiffError::Io {
            path,
            message: chain_context(new_ctx, &message),
            source,
        },
        SbomDiffError::Config(msg) => SbomDiffError::Config(chain_context(new_ctx, &msg)),
        SbomDiffError::Validation(msg) => SbomDiffError::Validation(chain_context(new_ctx, &msg)),
    }
}

/// Chain two context strings together.
///
/// If the existing context is empty, returns just the new context.
/// Otherwise, returns "`new_context`: `existing_context`".
fn chain_context(new: &str, existing: &str) -> String {
    if existing.is_empty() {
        new.to_string()
    } else {
        format!("{new}: {existing}")
    }
}

/// Extension trait for Option types to convert to errors with context.
pub trait OptionContext<T> {
    /// Convert None to an error with the given context.
    fn context_none(self, context: impl Into<String>) -> Result<T>;

    /// Convert None to an error with context from a closure.
    fn with_context_none<F, C>(self, f: F) -> Result<T>
    where
        F: FnOnce() -> C,
        C: Into<String>;
}

impl<T> OptionContext<T> for Option<T> {
    fn context_none(self, context: impl Into<String>) -> Result<T> {
        self.ok_or_else(|| SbomDiffError::Validation(context.into()))
    }

    fn with_context_none<F, C>(self, f: F) -> Result<T>
    where
        F: FnOnce() -> C,
        C: Into<String>,
    {
        self.ok_or_else(|| SbomDiffError::Validation(f().into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = SbomDiffError::unknown_format("test.json");
        // The error wraps ParseErrorKind::UnknownFormat which says "Unknown SBOM format"
        let display = err.to_string();
        assert!(
            display.contains("parse") || display.contains("SBOM"),
            "Error message should mention parsing or SBOM: {}",
            display
        );

        let err = SbomDiffError::missing_field("version", "component");
        let display = err.to_string();
        assert!(
            display.contains("Missing") || display.contains("field"),
            "Error message should mention missing field: {}",
            display
        );
    }

    #[test]
    fn test_error_chain() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = SbomDiffError::io("/path/to/file.json", io_err);

        assert!(err.to_string().contains("/path/to/file.json"));
    }

    #[test]
    fn test_context_chaining() {
        // Create an initial error
        let initial_err: Result<()> = Err(SbomDiffError::parse(
            "initial context",
            ParseErrorKind::UnknownFormat,
        ));

        // Add context - it should chain, not replace
        let err_with_context = initial_err.context("outer context");

        match err_with_context {
            Err(SbomDiffError::Parse { context, .. }) => {
                assert!(
                    context.contains("outer context"),
                    "Should contain outer context: {}",
                    context
                );
                assert!(
                    context.contains("initial context"),
                    "Should contain initial context: {}",
                    context
                );
            }
            _ => panic!("Expected Parse error"),
        }
    }

    #[test]
    fn test_context_chaining_multiple_levels() {
        fn inner() -> Result<()> {
            Err(SbomDiffError::parse("base", ParseErrorKind::UnknownFormat))
        }

        fn middle() -> Result<()> {
            inner().context("middle layer")
        }

        fn outer() -> Result<()> {
            middle().context("outer layer")
        }

        let result = outer();
        match result {
            Err(SbomDiffError::Parse { context, .. }) => {
                // Context should be chained: "outer layer: middle layer: base"
                assert!(
                    context.contains("outer layer"),
                    "Missing outer: {}",
                    context
                );
                assert!(
                    context.contains("middle layer"),
                    "Missing middle: {}",
                    context
                );
                assert!(context.contains("base"), "Missing base: {}", context);
            }
            _ => panic!("Expected Parse error"),
        }
    }

    #[test]
    fn test_with_context_lazy_evaluation() {
        let mut called = false;

        // This should NOT call the closure
        let ok_result: Result<i32> = Ok(42);
        let _ = ok_result.with_context(|| {
            called = true;
            "should not be called"
        });
        assert!(!called, "Closure should not be called for Ok result");

        // This SHOULD call the closure
        let err_result: Result<i32> = Err(SbomDiffError::validation("error"));
        let _ = err_result.with_context(|| {
            called = true;
            "should be called"
        });
        assert!(called, "Closure should be called for Err result");
    }

    #[test]
    fn test_option_context() {
        let some_value: Option<i32> = Some(42);
        let result = some_value.context_none("missing value");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);

        let none_value: Option<i32> = None;
        let result = none_value.context_none("missing value");
        assert!(result.is_err());
        match result {
            Err(SbomDiffError::Validation(msg)) => {
                assert_eq!(msg, "missing value");
            }
            _ => panic!("Expected Validation error"),
        }
    }

    #[test]
    fn test_chain_context_helper() {
        assert_eq!(chain_context("new", ""), "new");
        assert_eq!(chain_context("new", "existing"), "new: existing");
        assert_eq!(
            chain_context("outer", "middle: inner"),
            "outer: middle: inner"
        );
    }
}
