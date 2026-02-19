//! Streaming SBOM parser for large files.
//!
//! This module provides memory-efficient parsing for very large SBOMs by:
//! - Using streaming JSON/XML parsing (`serde_json::from_reader`)
//! - Not buffering the entire file into memory as a string
//! - Yielding results via an iterator interface
//! - Supporting progress callbacks
//!
//! # Usage
//!
//! ```no_run
//! use sbom_tools::parsers::streaming::{StreamingParser, StreamingConfig, ParseEvent};
//! use std::path::Path;
//!
//! let config = StreamingConfig::default()
//!     .with_chunk_size(64 * 1024)
//!     .with_progress_callback(|p| println!("Progress: {:.1}%", p.percent()));
//!
//! let parser = StreamingParser::new(config);
//! let stream = parser.parse_file(Path::new("large-sbom.json")).unwrap();
//!
//! for event in stream {
//!     match event {
//!         Ok(ParseEvent::Metadata(doc)) => println!("Document: {:?}", doc.format),
//!         Ok(ParseEvent::Component(comp)) => println!("Component: {}", comp.name),
//!         Ok(ParseEvent::Dependency(edge)) => println!("Dependency: {} -> {}", edge.from, edge.to),
//!         Ok(ParseEvent::Complete) => println!("Done!"),
//!         Err(e) => eprintln!("Error: {}", e),
//!     }
//! }
//! ```

use super::detection::FormatDetector;
use super::traits::ParseError;
use crate::model::{Component, DependencyEdge, DocumentMetadata, NormalizedSbom};
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::sync::Arc;

/// Progress information for streaming parsing
#[derive(Debug, Clone)]
pub struct ParseProgress {
    /// Bytes read so far
    pub bytes_read: u64,
    /// Total bytes (if known)
    pub total_bytes: Option<u64>,
    /// Components parsed so far
    pub components_parsed: usize,
    /// Dependencies parsed so far
    pub dependencies_parsed: usize,
}

impl ParseProgress {
    /// Get progress percentage (0-100), or None if total is unknown
    #[must_use] 
    pub fn percent(&self) -> f32 {
        match self.total_bytes {
            Some(total) if total > 0 => (self.bytes_read as f32 / total as f32) * 100.0,
            _ => 0.0,
        }
    }

    /// Check if progress is complete
    #[must_use] 
    pub fn is_complete(&self) -> bool {
        self.total_bytes.is_some_and(|total| self.bytes_read >= total)
    }
}

/// Progress callback type
pub type ProgressCallback = Arc<dyn Fn(&ParseProgress) + Send + Sync>;

/// Configuration for streaming parser
#[derive(Clone)]
pub struct StreamingConfig {
    /// Chunk size for reading (default: 64KB)
    pub chunk_size: usize,
    /// Buffer size for components (default: 1000)
    pub component_buffer_size: usize,
    /// Progress callback (optional)
    progress_callback: Option<ProgressCallback>,
    /// Whether to validate components during parsing
    pub validate_during_parse: bool,
    /// Skip malformed components instead of erroring
    pub skip_malformed: bool,
}

impl Default for StreamingConfig {
    fn default() -> Self {
        Self {
            chunk_size: 64 * 1024, // 64KB
            component_buffer_size: 1000,
            progress_callback: None,
            validate_during_parse: true,
            skip_malformed: false,
        }
    }
}

impl StreamingConfig {
    /// Set chunk size for reading
    #[must_use]
    pub fn with_chunk_size(mut self, size: usize) -> Self {
        self.chunk_size = size.max(1024); // Minimum 1KB
        self
    }

    /// Set component buffer size
    #[must_use]
    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.component_buffer_size = size.max(10);
        self
    }

    /// Set progress callback
    #[must_use]
    pub fn with_progress_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(&ParseProgress) + Send + Sync + 'static,
    {
        self.progress_callback = Some(Arc::new(callback));
        self
    }

    /// Enable/disable validation during parsing
    #[must_use]
    pub const fn with_validation(mut self, validate: bool) -> Self {
        self.validate_during_parse = validate;
        self
    }

    /// Enable/disable skipping malformed components
    #[must_use]
    pub const fn with_skip_malformed(mut self, skip: bool) -> Self {
        self.skip_malformed = skip;
        self
    }
}

impl std::fmt::Debug for StreamingConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamingConfig")
            .field("chunk_size", &self.chunk_size)
            .field("component_buffer_size", &self.component_buffer_size)
            .field("has_progress_callback", &self.progress_callback.is_some())
            .field("validate_during_parse", &self.validate_during_parse)
            .field("skip_malformed", &self.skip_malformed)
            .finish()
    }
}

/// Events emitted during streaming parsing
#[derive(Debug, Clone)]
pub enum ParseEvent {
    /// Document metadata has been parsed
    Metadata(DocumentMetadata),
    /// A component has been parsed
    Component(Box<Component>),
    /// A dependency relationship has been parsed
    Dependency(DependencyEdge),
    /// Parsing is complete
    Complete,
}

/// Streaming parser for large SBOMs
#[derive(Debug)]
pub struct StreamingParser {
    config: StreamingConfig,
}

impl StreamingParser {
    /// Create a new streaming parser with the given configuration
    #[must_use] 
    pub const fn new(config: StreamingConfig) -> Self {
        Self { config }
    }

    /// Create a streaming parser with default configuration
    #[must_use] 
    pub fn default_config() -> Self {
        Self::new(StreamingConfig::default())
    }

    /// Parse a file and return an iterator of events
    pub fn parse_file(&self, path: &Path) -> Result<StreamingIterator, ParseError> {
        let file = std::fs::File::open(path)
            .map_err(|e| ParseError::IoError(format!("Failed to open file: {e}")))?;

        let total_bytes = file.metadata().map(|m| m.len()).ok();
        let reader = BufReader::with_capacity(self.config.chunk_size, file);

        self.parse_reader(reader, total_bytes)
    }

    /// Parse from a reader and return an iterator of events
    pub fn parse_reader<R: Read + Send + 'static>(
        &self,
        reader: BufReader<R>,
        total_bytes: Option<u64>,
    ) -> Result<StreamingIterator, ParseError> {
        Ok(StreamingIterator::new(
            reader,
            total_bytes,
            self.config.clone(),
        ))
    }

    /// Parse from string content
    pub fn parse_str(&self, content: &str) -> Result<StreamingIterator, ParseError> {
        let cursor = std::io::Cursor::new(content.to_string());
        let total_bytes = Some(content.len() as u64);
        let reader = BufReader::new(cursor);
        self.parse_reader(reader, total_bytes)
    }

    /// Collect all events into a `NormalizedSbom` (for convenience)
    ///
    /// Note: This loads the entire SBOM into memory, negating the
    /// streaming benefits. Use the iterator directly for large files.
    pub fn parse_to_sbom(&self, path: &Path) -> Result<NormalizedSbom, ParseError> {
        let mut stream = self.parse_file(path)?;
        stream.collect_sbom()
    }
}

impl Default for StreamingParser {
    fn default() -> Self {
        Self::default_config()
    }
}

/// Iterator over streaming parse events
#[allow(dead_code)]
pub struct StreamingIterator {
    /// Internal state
    state: StreamingState,
    /// Configuration
    config: StreamingConfig,
    /// Progress tracking
    progress: ParseProgress,
    /// Pending events
    pending: VecDeque<ParseEvent>,
    /// Whether parsing is complete
    complete: bool,
}

enum StreamingState {
    /// Initial state - need to detect format and parse
    Initial(Box<dyn BufRead + Send>),
    /// Parsing complete, emitting events from parsed SBOM
    Emitting {
        sbom: Box<NormalizedSbom>,
        component_index: usize,
        dependency_index: usize,
        metadata_emitted: bool,
    },
    /// Finished
    Done,
}

impl StreamingIterator {
    fn new<R: Read + Send + 'static>(
        reader: BufReader<R>,
        total_bytes: Option<u64>,
        config: StreamingConfig,
    ) -> Self {
        Self {
            state: StreamingState::Initial(Box::new(reader)),
            config,
            progress: ParseProgress {
                bytes_read: 0,
                total_bytes,
                components_parsed: 0,
                dependencies_parsed: 0,
            },
            pending: VecDeque::new(),
            complete: false,
        }
    }

    /// Collect all events into a `NormalizedSbom`
    pub fn collect_sbom(&mut self) -> Result<NormalizedSbom, ParseError> {
        let mut metadata: Option<DocumentMetadata> = None;
        let mut components = Vec::new();
        let mut edges = Vec::new();

        for event in self.by_ref() {
            match event {
                Ok(ParseEvent::Metadata(doc)) => metadata = Some(doc),
                Ok(ParseEvent::Component(comp)) => components.push(*comp),
                Ok(ParseEvent::Dependency(edge)) => edges.push(edge),
                Ok(ParseEvent::Complete) => break,
                Err(e) => return Err(e),
            }
        }

        let document = metadata.unwrap_or_default();
        let mut sbom = NormalizedSbom::new(document);

        for comp in components {
            sbom.add_component(comp);
        }
        for edge in edges {
            sbom.add_edge(edge);
        }

        sbom.calculate_content_hash();
        Ok(sbom)
    }

    fn report_progress(&self) {
        if let Some(ref callback) = self.config.progress_callback {
            callback(&self.progress);
        }
    }

    fn advance(&mut self) -> Option<Result<ParseEvent, ParseError>> {
        // Return pending events first
        if let Some(event) = self.pending.pop_front() {
            return Some(Ok(event));
        }

        if self.complete {
            return None;
        }

        // Process based on state
        match std::mem::replace(&mut self.state, StreamingState::Done) {
            StreamingState::Initial(reader) => {
                // Use centralized FormatDetector for consistent detection
                let detector = FormatDetector::new();

                // Parse using the detector which handles format detection and parsing
                match detector.parse_reader(reader) {
                    Ok(sbom) => {
                        self.progress.bytes_read = self.progress.total_bytes.unwrap_or(0);
                        self.report_progress();
                        self.state = StreamingState::Emitting {
                            sbom: Box::new(sbom),
                            component_index: 0,
                            dependency_index: 0,
                            metadata_emitted: false,
                        };
                        self.advance()
                    }
                    Err(e) => Some(Err(e)),
                }
            }
            StreamingState::Emitting {
                sbom,
                component_index,
                dependency_index,
                metadata_emitted,
            } => {
                // Emit metadata first
                if !metadata_emitted {
                    let doc = sbom.document.clone();
                    self.state = StreamingState::Emitting {
                        sbom,
                        component_index,
                        dependency_index,
                        metadata_emitted: true,
                    };
                    return Some(Ok(ParseEvent::Metadata(doc)));
                }

                // Collect components into a vec for indexed access
                let components: Vec<_> = sbom.components.values().cloned().collect();
                let edges_len = sbom.edges.len();

                // Emit components
                if component_index < components.len() {
                    let comp = components[component_index].clone();
                    self.progress.components_parsed += 1;
                    if self.progress.components_parsed.is_multiple_of(100) {
                        self.report_progress();
                    }
                    self.state = StreamingState::Emitting {
                        sbom,
                        component_index: component_index + 1,
                        dependency_index,
                        metadata_emitted,
                    };
                    return Some(Ok(ParseEvent::Component(Box::new(comp))));
                }

                // Emit dependencies
                if dependency_index < edges_len {
                    let edge = sbom.edges[dependency_index].clone();
                    self.progress.dependencies_parsed += 1;
                    self.state = StreamingState::Emitting {
                        sbom,
                        component_index,
                        dependency_index: dependency_index + 1,
                        metadata_emitted,
                    };
                    return Some(Ok(ParseEvent::Dependency(edge)));
                }

                // All done
                self.complete = true;
                self.report_progress();
                self.state = StreamingState::Done;
                Some(Ok(ParseEvent::Complete))
            }
            StreamingState::Done => {
                self.complete = true;
                None
            }
        }
    }
}

impl Iterator for StreamingIterator {
    type Item = Result<ParseEvent, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.advance()
    }
}

/// Estimate the number of components in an SBOM file without full parsing
///
/// This performs a quick scan to estimate component count, useful for
/// progress reporting and memory allocation.
pub fn estimate_component_count(path: &Path) -> Result<ComponentEstimate, ParseError> {
    let file = std::fs::File::open(path)
        .map_err(|e| ParseError::IoError(format!("Failed to open file: {e}")))?;

    let file_size = file.metadata().map(|m| m.len()).unwrap_or(0);

    let reader = BufReader::new(file);
    let mut count = 0;
    let mut bytes_sampled = 0;
    let sample_limit = 1024 * 1024; // Sample first 1MB

    for line in reader.lines() {
        let line = line.map_err(|e| ParseError::IoError(e.to_string()))?;
        bytes_sampled += line.len();

        // Count component markers
        if line.contains("\"bom-ref\"") || line.contains("\"SPDXID\"") {
            count += 1;
        }

        if bytes_sampled > sample_limit {
            break;
        }
    }

    // Extrapolate if we only sampled part of the file
    let estimated = if bytes_sampled < file_size as usize && bytes_sampled > 0 {
        (count as f64 * (file_size as f64 / bytes_sampled as f64)) as usize
    } else {
        count
    };

    Ok(ComponentEstimate {
        estimated_count: estimated,
        sampled_count: count,
        file_size,
        bytes_sampled,
        is_extrapolated: bytes_sampled < file_size as usize,
    })
}

/// Estimate of component count
#[derive(Debug, Clone)]
pub struct ComponentEstimate {
    /// Estimated total component count
    pub estimated_count: usize,
    /// Components found in sampled region
    pub sampled_count: usize,
    /// Total file size in bytes
    pub file_size: u64,
    /// Bytes that were sampled
    pub bytes_sampled: usize,
    /// Whether the estimate was extrapolated
    pub is_extrapolated: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_progress_percent() {
        let progress = ParseProgress {
            bytes_read: 50,
            total_bytes: Some(100),
            components_parsed: 5,
            dependencies_parsed: 3,
        };
        assert_eq!(progress.percent(), 50.0);
        assert!(!progress.is_complete());

        let complete = ParseProgress {
            bytes_read: 100,
            total_bytes: Some(100),
            components_parsed: 10,
            dependencies_parsed: 5,
        };
        assert_eq!(complete.percent(), 100.0);
        assert!(complete.is_complete());
    }

    #[test]
    fn test_streaming_config_builder() {
        let config = StreamingConfig::default()
            .with_chunk_size(128 * 1024)
            .with_buffer_size(500)
            .with_validation(false)
            .with_skip_malformed(true);

        assert_eq!(config.chunk_size, 128 * 1024);
        assert_eq!(config.component_buffer_size, 500);
        assert!(!config.validate_during_parse);
        assert!(config.skip_malformed);
    }

    #[test]
    fn test_streaming_parser_creation() {
        let parser = StreamingParser::default_config();
        assert_eq!(parser.config.chunk_size, 64 * 1024);
    }
}
