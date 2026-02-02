//! Output handling for SBOM reports.
//!
//! Provides utilities for auto-detecting output format and writing reports.

use crate::reports::ReportFormat;
use anyhow::{Context, Result};
use std::io::IsTerminal;
use std::path::PathBuf;

/// Target for output - either stdout or a file
#[derive(Debug, Clone)]
pub enum OutputTarget {
    /// Write to stdout
    Stdout,
    /// Write to a file
    File(PathBuf),
}

impl OutputTarget {
    /// Create output target from optional path
    pub fn from_option(path: Option<PathBuf>) -> Self {
        match path {
            Some(p) => OutputTarget::File(p),
            None => OutputTarget::Stdout,
        }
    }

    /// Check if output is to a terminal
    pub fn is_terminal(&self) -> bool {
        matches!(self, OutputTarget::Stdout) && std::io::stdout().is_terminal()
    }
}

/// Auto-detect the output format based on TTY and output target
///
/// Returns TUI for interactive terminals (stdout to TTY),
/// otherwise returns Summary for non-interactive contexts.
pub fn auto_detect_format(format: ReportFormat, target: &OutputTarget) -> ReportFormat {
    match format {
        ReportFormat::Auto => {
            if target.is_terminal() {
                ReportFormat::Tui
            } else {
                ReportFormat::Summary
            }
        }
        other => other,
    }
}

/// Determine if color should be used based on flags and environment
pub fn should_use_color(no_color_flag: bool) -> bool {
    !no_color_flag && std::env::var("NO_COLOR").is_err()
}

/// Write output to the target (stdout or file)
pub fn write_output(content: &str, target: &OutputTarget, quiet: bool) -> Result<()> {
    match target {
        OutputTarget::Stdout => {
            println!("{}", content);
            Ok(())
        }
        OutputTarget::File(path) => {
            std::fs::write(path, content)
                .with_context(|| format!("Failed to write output to {:?}", path))?;
            if !quiet {
                tracing::info!("Report written to {:?}", path);
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_output_target_from_option_none() {
        let target = OutputTarget::from_option(None);
        assert!(matches!(target, OutputTarget::Stdout));
    }

    #[test]
    fn test_output_target_from_option_some() {
        let path = PathBuf::from("/tmp/test.json");
        let target = OutputTarget::from_option(Some(path.clone()));
        match target {
            OutputTarget::File(p) => assert_eq!(p, path),
            _ => panic!("Expected File variant"),
        }
    }

    #[test]
    fn test_auto_detect_format_non_auto() {
        let target = OutputTarget::Stdout;
        assert_eq!(
            auto_detect_format(ReportFormat::Json, &target),
            ReportFormat::Json
        );
        assert_eq!(
            auto_detect_format(ReportFormat::Sarif, &target),
            ReportFormat::Sarif
        );
    }

    #[test]
    fn test_auto_detect_format_file_target() {
        let target = OutputTarget::File(PathBuf::from("/tmp/test.json"));
        // File targets are never terminals, so Auto -> Summary
        assert_eq!(
            auto_detect_format(ReportFormat::Auto, &target),
            ReportFormat::Summary
        );
    }

    #[test]
    fn test_should_use_color_with_flag() {
        assert!(!should_use_color(true));
    }

    #[test]
    fn test_should_use_color_without_flag() {
        // This depends on NO_COLOR env var
        let expected = std::env::var("NO_COLOR").is_err();
        assert_eq!(should_use_color(false), expected);
    }
}
