//! PURL normalization utilities.

use crate::model::Ecosystem;

/// PURL normalizer for consistent comparison.
pub struct PurlNormalizer;

impl PurlNormalizer {
    /// Create a new PURL normalizer
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Normalize a PURL for comparison
    #[must_use]
    pub fn normalize(&self, purl: &str) -> String {
        self.normalize_internal(purl)
    }

    fn normalize_internal(&self, purl: &str) -> String {
        // Detect ecosystem from PURL
        self.detect_ecosystem(purl).map_or_else(
            || purl.to_lowercase(),
            |ecosystem| match ecosystem {
                Ecosystem::PyPi => self.normalize_pypi(purl),
                Ecosystem::Npm => self.normalize_npm(purl),
                Ecosystem::Cargo => self.normalize_cargo(purl),
                Ecosystem::Maven => self.normalize_maven(purl),
                Ecosystem::Golang => self.normalize_golang(purl),
                Ecosystem::Nuget => self.normalize_nuget(purl),
                _ => purl.to_lowercase(),
            },
        )
    }

    /// Detect ecosystem from PURL
    fn detect_ecosystem(&self, purl: &str) -> Option<Ecosystem> {
        let purl_type = purl.strip_prefix("pkg:")?.split('/').next()?;

        Some(Ecosystem::from_purl_type(purl_type))
    }

    /// Normalize `PyPI` PURL
    /// `PyPI` names are case-insensitive and treat `_`, `-`, `.` as equivalent
    fn normalize_pypi(&self, purl: &str) -> String {
        let lower = purl.to_lowercase();
        // Replace underscores and dots with hyphens
        lower.replace(['_', '.'], "-")
    }

    /// Normalize npm PURL
    /// npm names are lowercase, scopes use @ prefix
    fn normalize_npm(&self, purl: &str) -> String {
        let mut normalized = purl.to_lowercase();
        // Decode URL-encoded @ for scopes
        normalized = normalized.replace("%40", "@");
        normalized
    }

    /// Normalize Cargo PURL
    /// Cargo treats hyphens and underscores as equivalent (but prefers underscores)
    fn normalize_cargo(&self, purl: &str) -> String {
        let lower = purl.to_lowercase();
        // Normalize to underscores (Cargo's canonical form)
        lower.replace('-', "_")
    }

    /// Normalize Maven PURL
    /// Maven is case-sensitive for groupId and artifactId
    fn normalize_maven(&self, purl: &str) -> String {
        // Maven PURLs should preserve case
        purl.to_string()
    }

    /// Normalize Go PURL
    /// Go modules are case-sensitive and may have /v2 suffixes
    fn normalize_golang(&self, purl: &str) -> String {
        // Go PURLs should preserve case
        purl.to_string()
    }

    /// Normalize `NuGet` PURL
    /// `NuGet` package IDs are case-insensitive
    fn normalize_nuget(&self, purl: &str) -> String {
        purl.to_lowercase()
    }

    /// Extract package name from PURL
    #[must_use]
    pub fn extract_name(&self, purl: &str) -> Option<String> {
        let without_pkg = purl.strip_prefix("pkg:")?;
        let parts: Vec<&str> = without_pkg.split('/').collect();

        let name_part = if parts.len() >= 2 {
            // Handle namespace/name format
            parts.last()?
        } else {
            return None;
        };

        // Remove version, qualifiers, subpath
        let name = name_part
            .split('@')
            .next()?
            .split('?')
            .next()?
            .split('#')
            .next()?;

        Some(name.to_string())
    }

    /// Extract version from PURL
    #[must_use]
    pub fn extract_version(&self, purl: &str) -> Option<String> {
        let at_pos = purl.find('@')?;
        let version_part = &purl[at_pos + 1..];

        // Remove qualifiers and subpath
        let version = version_part.split('?').next()?.split('#').next()?;

        Some(version.to_string())
    }

    /// Extract ecosystem type from PURL
    #[must_use]
    pub fn extract_type(&self, purl: &str) -> Option<String> {
        let without_pkg = purl.strip_prefix("pkg:")?;
        let purl_type = without_pkg.split('/').next()?;
        Some(purl_type.to_string())
    }

    /// Check if two PURLs refer to the same package (ignoring version)
    #[must_use]
    pub fn same_package(&self, purl_a: &str, purl_b: &str) -> bool {
        let norm_a = self.normalize(purl_a);
        let norm_b = self.normalize(purl_b);

        // Remove version for comparison
        let base_a = norm_a.split('@').next().unwrap_or(&norm_a);
        let base_b = norm_b.split('@').next().unwrap_or(&norm_b);

        base_a == base_b
    }
}

impl Default for PurlNormalizer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pypi_normalization() {
        let normalizer = PurlNormalizer::new();

        let purl1 = "pkg:pypi/Pillow@9.0.0";
        let purl2 = "pkg:pypi/pillow@9.0.0";

        assert_eq!(normalizer.normalize(purl1), normalizer.normalize(purl2));
    }

    #[test]
    fn test_pypi_separator_normalization() {
        let normalizer = PurlNormalizer::new();

        let purl1 = "pkg:pypi/python-dateutil@2.8.2";
        let purl2 = "pkg:pypi/python_dateutil@2.8.2";

        assert_eq!(normalizer.normalize(purl1), normalizer.normalize(purl2));
    }

    #[test]
    fn test_npm_scope_normalization() {
        let normalizer = PurlNormalizer::new();

        let purl1 = "pkg:npm/%40angular/core@15.0.0";
        let purl2 = "pkg:npm/@angular/core@15.0.0";

        assert_eq!(normalizer.normalize(purl1), normalizer.normalize(purl2));
    }

    #[test]
    fn test_extract_name() {
        let normalizer = PurlNormalizer::new();

        assert_eq!(
            normalizer.extract_name("pkg:npm/lodash@4.17.21"),
            Some("lodash".to_string())
        );
        assert_eq!(
            normalizer.extract_name("pkg:maven/org.apache.commons/commons-lang3@3.12.0"),
            Some("commons-lang3".to_string())
        );
    }

    #[test]
    fn test_same_package() {
        let normalizer = PurlNormalizer::new();

        assert!(normalizer.same_package("pkg:npm/lodash@4.17.20", "pkg:npm/lodash@4.17.21"));
        assert!(!normalizer.same_package("pkg:npm/lodash@4.17.21", "pkg:npm/underscore@1.13.0"));
    }
}
