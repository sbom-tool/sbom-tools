//! BOM profile detection and configuration.
//!
//! Determines the type of Bill of Materials (SBOM, CBOM, etc.) and provides
//! profile-specific defaults for quality scoring, compliance standards, and
//! TUI tab selection.

use super::metadata::ComponentType;
use super::sbom::NormalizedSbom;
use serde::{Deserialize, Serialize};

/// BOM profile — determines mode-specific behavior across TUI and CLI.
///
/// Auto-detected from SBOM content or overridden via `--bom-type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[non_exhaustive]
pub enum BomProfile {
    /// Standard Software Bill of Materials
    #[default]
    Sbom,
    /// Cryptographic Bill of Materials (CycloneDX 1.6+ cryptoProperties)
    Cbom,
    /// AI/ML Bill of Materials (CycloneDX 1.5+ ML model + dataset components)
    AiBom,
    // Future: Hbom
}

impl BomProfile {
    /// Auto-detect the BOM profile from SBOM content.
    ///
    /// Classifies as:
    /// - `AiBom` when the SBOM is ML-centric: any `MachineLearningModel`
    ///   component is present, AND the AI-relevant components
    ///   (`MachineLearningModel` + `Data`) either form a majority (>50%) or
    ///   number at least 3.
    /// - `Cbom` when >50% of components are `ComponentType::Cryptographic`
    ///   and there are at least 3 crypto components.
    /// - `Sbom` otherwise.
    ///
    /// Precedence when both crypto and ML are significant: the larger
    /// component count wins (AI-relevant vs. crypto). On a tie, AI-BOM is
    /// preferred because a model-bearing SBOM is the rarer, more specific
    /// classification.
    #[must_use]
    pub fn detect(sbom: &NormalizedSbom) -> Self {
        let total = sbom.components.len();
        if total == 0 {
            return Self::Sbom;
        }

        let crypto_count = sbom
            .components
            .values()
            .filter(|c| c.component_type == ComponentType::Cryptographic)
            .count();

        let ml_count = sbom
            .components
            .values()
            .filter(|c| c.component_type == ComponentType::MachineLearningModel)
            .count();
        // AI-relevant components: models plus their training/eval datasets.
        let ai_count = ml_count
            + sbom
                .components
                .values()
                .filter(|c| c.component_type == ComponentType::Data)
                .count();

        // An AI-BOM must contain at least one model; datasets alone are not enough.
        let is_aibom = ml_count >= 1 && (ai_count * 2 > total || ai_count >= 3);
        let is_cbom = crypto_count >= 3 && crypto_count * 2 > total;

        match (is_aibom, is_cbom) {
            (true, true) => {
                // Both significant: pick by component majority, AI on tie.
                if crypto_count > ai_count {
                    Self::Cbom
                } else {
                    Self::AiBom
                }
            }
            (true, false) => Self::AiBom,
            (false, true) => Self::Cbom,
            (false, false) => Self::Sbom,
        }
    }

    /// Human-readable label for display.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Sbom => "SBOM",
            Self::Cbom => "CBOM",
            Self::AiBom => "AI-BOM",
        }
    }

    /// Parse from a string (CLI `--bom-type` flag).
    #[must_use]
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "sbom" => Some(Self::Sbom),
            "cbom" => Some(Self::Cbom),
            "ai" | "aibom" | "mlbom" => Some(Self::AiBom),
            _ => None,
        }
    }
}

impl std::fmt::Display for BomProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Component;

    #[test]
    fn test_detect_sbom_empty() {
        let sbom = NormalizedSbom::default();
        assert_eq!(BomProfile::detect(&sbom), BomProfile::Sbom);
    }

    #[test]
    fn test_detect_sbom_no_crypto() {
        let mut sbom = NormalizedSbom::default();
        for i in 0..10 {
            let c = Component::new(format!("lib-{i}"), format!("lib-{i}@1.0"));
            sbom.add_component(c);
        }
        assert_eq!(BomProfile::detect(&sbom), BomProfile::Sbom);
    }

    #[test]
    fn test_detect_cbom_majority_crypto() {
        let mut sbom = NormalizedSbom::default();
        // 2 software + 5 crypto = 71% crypto → CBOM
        for i in 0..2 {
            let c = Component::new(format!("app-{i}"), format!("app-{i}@1.0"));
            sbom.add_component(c);
        }
        for i in 0..5 {
            let mut c = Component::new(format!("algo-{i}"), format!("algo-{i}@1.0"));
            c.component_type = ComponentType::Cryptographic;
            sbom.add_component(c);
        }
        assert_eq!(BomProfile::detect(&sbom), BomProfile::Cbom);
    }

    #[test]
    fn test_detect_sbom_minority_crypto() {
        let mut sbom = NormalizedSbom::default();
        // 8 software + 3 crypto = 27% crypto → SBOM (below 50%)
        for i in 0..8 {
            let c = Component::new(format!("lib-{i}"), format!("lib-{i}@1.0"));
            sbom.add_component(c);
        }
        for i in 0..3 {
            let mut c = Component::new(format!("algo-{i}"), format!("algo-{i}@1.0"));
            c.component_type = ComponentType::Cryptographic;
            sbom.add_component(c);
        }
        assert_eq!(BomProfile::detect(&sbom), BomProfile::Sbom);
    }

    #[test]
    fn test_detect_cbom_needs_minimum_3() {
        let mut sbom = NormalizedSbom::default();
        // 2 crypto only but < 3 minimum → SBOM
        for i in 0..2 {
            let mut c = Component::new(format!("algo-{i}"), format!("algo-{i}@1.0"));
            c.component_type = ComponentType::Cryptographic;
            sbom.add_component(c);
        }
        assert_eq!(BomProfile::detect(&sbom), BomProfile::Sbom);
    }

    fn ml_component(name: &str) -> Component {
        let mut c = Component::new(name.to_string(), format!("{name}@1.0"));
        c.component_type = ComponentType::MachineLearningModel;
        c
    }

    fn data_component(name: &str) -> Component {
        let mut c = Component::new(name.to_string(), format!("{name}@1.0"));
        c.component_type = ComponentType::Data;
        c
    }

    #[test]
    fn test_detect_aibom_ml_majority() {
        let mut sbom = NormalizedSbom::default();
        // 1 app + 1 model + 1 dataset = 2/3 AI-relevant (majority) → AI-BOM.
        sbom.add_component(Component::new("app".to_string(), "app@1.0".to_string()));
        sbom.add_component(ml_component("classifier"));
        sbom.add_component(data_component("reviews"));
        assert_eq!(BomProfile::detect(&sbom), BomProfile::AiBom);
    }

    #[test]
    fn test_detect_aibom_min_three_without_majority() {
        let mut sbom = NormalizedSbom::default();
        // 5 libs + 2 models + 1 dataset = 3 AI-relevant (37.5%, not a majority)
        // but >= 3 with at least one model → AI-BOM.
        for i in 0..5 {
            sbom.add_component(Component::new(format!("lib-{i}"), format!("lib-{i}@1.0")));
        }
        sbom.add_component(ml_component("model-a"));
        sbom.add_component(ml_component("model-b"));
        sbom.add_component(data_component("train"));
        assert_eq!(BomProfile::detect(&sbom), BomProfile::AiBom);
    }

    #[test]
    fn test_detect_not_aibom_datasets_only() {
        let mut sbom = NormalizedSbom::default();
        // Datasets with no model must not classify as AI-BOM.
        for i in 0..4 {
            sbom.add_component(data_component(&format!("data-{i}")));
        }
        assert_eq!(BomProfile::detect(&sbom), BomProfile::Sbom);
    }

    #[test]
    fn test_detect_aibom_beats_cbom_on_majority() {
        let mut sbom = NormalizedSbom::default();
        // 4 ML + 3 crypto: both significant, AI count (4) > crypto (3) → AI-BOM.
        for i in 0..4 {
            sbom.add_component(ml_component(&format!("model-{i}")));
        }
        for i in 0..3 {
            let mut c = Component::new(format!("algo-{i}"), format!("algo-{i}@1.0"));
            c.component_type = ComponentType::Cryptographic;
            sbom.add_component(c);
        }
        assert_eq!(BomProfile::detect(&sbom), BomProfile::AiBom);
    }

    #[test]
    fn test_detect_cbom_beats_aibom_when_crypto_dominates() {
        let mut sbom = NormalizedSbom::default();
        // 5 crypto + 1 model + 1 dataset: crypto (5) > AI (2) → CBOM.
        for i in 0..5 {
            let mut c = Component::new(format!("algo-{i}"), format!("algo-{i}@1.0"));
            c.component_type = ComponentType::Cryptographic;
            sbom.add_component(c);
        }
        sbom.add_component(ml_component("model"));
        sbom.add_component(data_component("data"));
        assert_eq!(BomProfile::detect(&sbom), BomProfile::Cbom);
    }

    #[test]
    fn test_from_str_opt() {
        assert_eq!(BomProfile::from_str_opt("sbom"), Some(BomProfile::Sbom));
        assert_eq!(BomProfile::from_str_opt("CBOM"), Some(BomProfile::Cbom));
        assert_eq!(BomProfile::from_str_opt("cbom"), Some(BomProfile::Cbom));
        assert_eq!(BomProfile::from_str_opt("ai"), Some(BomProfile::AiBom));
        assert_eq!(BomProfile::from_str_opt("AiBom"), Some(BomProfile::AiBom));
        assert_eq!(BomProfile::from_str_opt("mlbom"), Some(BomProfile::AiBom));
        assert_eq!(BomProfile::from_str_opt("hbom"), None);
    }

    #[test]
    fn test_label() {
        assert_eq!(BomProfile::Sbom.label(), "SBOM");
        assert_eq!(BomProfile::Cbom.label(), "CBOM");
        assert_eq!(BomProfile::AiBom.label(), "AI-BOM");
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", BomProfile::Sbom), "SBOM");
        assert_eq!(format!("{}", BomProfile::Cbom), "CBOM");
        assert_eq!(format!("{}", BomProfile::AiBom), "AI-BOM");
    }
}
