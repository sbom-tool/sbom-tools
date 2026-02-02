//! Version comparison utilities.

use semver::Version;
use std::cmp::Ordering;

/// Compare two version strings
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    // Try semver comparison first
    if let (Ok(ver_a), Ok(ver_b)) = (Version::parse(a), Version::parse(b)) {
        return ver_a.cmp(&ver_b);
    }

    // Fall back to string comparison
    a.cmp(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compare_versions() {
        assert_eq!(compare_versions("1.0.0", "1.0.1"), Ordering::Less);
        assert_eq!(compare_versions("1.0.1", "1.0.0"), Ordering::Greater);
        assert_eq!(compare_versions("1.0.0", "1.0.0"), Ordering::Equal);
    }
}
