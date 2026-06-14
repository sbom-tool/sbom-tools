//! Fidelity reporting for cross-format emission.
//!
//! Records — honestly, like protobom — which fields were synthesized from the
//! canonical model, spliced back from preserved source JSON, or dropped because
//! they have no representation in the target format.

use std::collections::BTreeMap;

/// A human-readable, counted report of what happened during emission.
///
/// Counts are keyed by a short field label so repeated decisions across many
/// components collapse into one line (e.g. "synthesized bom-ref from canonical
/// id (x42)").
#[derive(Debug, Default, Clone)]
pub struct FidelityReport {
    /// Source format of the input document (for the report header).
    source_format: String,
    /// Target format of the emitted document.
    target_format: String,
    /// Fields synthesized from the typed model, keyed by label → count.
    synthesized: BTreeMap<String, usize>,
    /// Fields spliced back verbatim from preserved source JSON.
    preserved: BTreeMap<String, usize>,
    /// Fields dropped (no target representation), keyed by label → count.
    dropped: BTreeMap<String, usize>,
}

impl FidelityReport {
    /// Create a report for a `source` → `target` conversion.
    #[must_use]
    pub fn new(source_format: impl Into<String>, target_format: impl Into<String>) -> Self {
        Self {
            source_format: source_format.into(),
            target_format: target_format.into(),
            synthesized: BTreeMap::new(),
            preserved: BTreeMap::new(),
            dropped: BTreeMap::new(),
        }
    }

    /// Record that `label` was synthesized from the typed model.
    pub fn synthesized(&mut self, label: impl Into<String>) {
        *self.synthesized.entry(label.into()).or_insert(0) += 1;
    }

    /// Record that `label` was spliced back from preserved source JSON.
    pub fn preserved(&mut self, label: impl Into<String>) {
        *self.preserved.entry(label.into()).or_insert(0) += 1;
    }

    /// Record that `label` was dropped (no representation in the target format).
    pub fn dropped(&mut self, label: impl Into<String>) {
        *self.dropped.entry(label.into()).or_insert(0) += 1;
    }

    /// Whether any field was dropped (i.e. the conversion was lossy).
    #[must_use]
    pub fn is_lossy(&self) -> bool {
        !self.dropped.is_empty()
    }

    /// Total number of distinct dropped-field labels.
    #[must_use]
    pub fn dropped_count(&self) -> usize {
        self.dropped.len()
    }

    /// Render the report as a multi-line, stderr-friendly string.
    #[must_use]
    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();

        let _ = writeln!(
            out,
            "Fidelity report: {} → {}",
            self.source_format, self.target_format
        );

        Self::render_section(&mut out, "Synthesized from model", &self.synthesized);
        Self::render_section(&mut out, "Preserved from source", &self.preserved);
        Self::render_section(&mut out, "Dropped (no target mapping)", &self.dropped);

        if self.dropped.is_empty() {
            let _ = writeln!(out, "  No fields dropped.");
        }

        out
    }

    fn render_section(out: &mut String, title: &str, entries: &BTreeMap<String, usize>) {
        use std::fmt::Write as _;
        if entries.is_empty() {
            return;
        }
        let _ = writeln!(out, "  {title}:");
        for (label, count) in entries {
            if *count > 1 {
                let _ = writeln!(out, "    - {label} (x{count})");
            } else {
                let _ = writeln!(out, "    - {label}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lossy_when_dropped() {
        let mut r = FidelityReport::new("SPDX", "CycloneDX");
        assert!(!r.is_lossy());
        r.dropped("spdx annotations");
        assert!(r.is_lossy());
        assert_eq!(r.dropped_count(), 1);
    }

    #[test]
    fn render_collapses_counts() {
        let mut r = FidelityReport::new("SPDX", "CycloneDX");
        r.synthesized("bom-ref from canonical id");
        r.synthesized("bom-ref from canonical id");
        let text = r.render();
        assert!(text.contains("SPDX → CycloneDX"));
        assert!(text.contains("bom-ref from canonical id (x2)"));
        assert!(text.contains("No fields dropped."));
    }
}
