//! Curated alias tables for cross-ecosystem package correlation.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Alias table for mapping package names across different conventions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AliasTable {
    /// Mapping from alias to canonical name
    alias_to_canonical: HashMap<String, String>,
    /// Mapping from canonical name to all aliases
    canonical_to_aliases: HashMap<String, HashSet<String>>,
}

impl AliasTable {
    /// Create a new empty alias table
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an alias table with built-in common aliases
    pub fn with_builtins() -> Self {
        let mut table = Self::new();
        table.load_builtins();
        table
    }

    /// Load built-in alias mappings
    fn load_builtins(&mut self) {
        // PyPI aliases (distribution vs import name differences)
        self.add_aliases("pkg:pypi/pillow", &["PIL", "python-pillow", "pillow"]);
        self.add_aliases("pkg:pypi/scikit-learn", &["sklearn", "scikit_learn"]);
        self.add_aliases(
            "pkg:pypi/beautifulsoup4",
            &["bs4", "BeautifulSoup", "beautifulsoup"],
        );
        self.add_aliases("pkg:pypi/pyyaml", &["yaml", "PyYAML"]);
        self.add_aliases(
            "pkg:pypi/opencv-python",
            &["cv2", "opencv-python-headless", "opencv"],
        );
        self.add_aliases("pkg:pypi/python-dateutil", &["dateutil"]);
        self.add_aliases("pkg:pypi/attrs", &["attr"]);
        self.add_aliases("pkg:pypi/importlib-metadata", &["importlib_metadata"]);
        self.add_aliases("pkg:pypi/typing-extensions", &["typing_extensions"]);
        self.add_aliases("pkg:pypi/zipp", &["zipfile"]);

        // npm aliases (package variants)
        self.add_aliases(
            "pkg:npm/lodash",
            &["lodash-es", "lodash.merge", "lodash.get"],
        );
        self.add_aliases("pkg:npm/react", &["react-dom"]);
        self.add_aliases("pkg:npm/webpack", &["webpack-cli"]);

        // Cross-ecosystem common libraries
        self.add_aliases(
            "yaml-parser",
            &["pyyaml", "js-yaml", "serde_yaml", "gopkg.in/yaml"],
        );
        self.add_aliases("json-parser", &["serde_json", "json", "encoding/json"]);
    }

    /// Add aliases for a canonical package
    pub fn add_aliases(&mut self, canonical: &str, aliases: &[&str]) {
        let canonical_lower = canonical.to_lowercase();

        // Add canonical as its own alias
        self.alias_to_canonical
            .insert(canonical_lower.clone(), canonical_lower.clone());

        // Initialize alias set and insert canonical name
        let alias_set = self
            .canonical_to_aliases
            .entry(canonical_lower.clone())
            .or_default();
        alias_set.insert(canonical_lower.clone());

        // Add all aliases
        for alias in aliases {
            let alias_lower = alias.to_lowercase();
            self.alias_to_canonical
                .insert(alias_lower.clone(), canonical_lower.clone());
            if let Some(set) = self.canonical_to_aliases.get_mut(&canonical_lower) {
                set.insert(alias_lower);
            }
        }
    }

    /// Get the canonical name for an alias
    pub fn get_canonical(&self, alias: &str) -> Option<String> {
        self.alias_to_canonical.get(&alias.to_lowercase()).cloned()
    }

    /// Check if a name is an alias of a canonical name
    pub fn is_alias(&self, canonical: &str, name: &str) -> bool {
        let canonical_lower = canonical.to_lowercase();
        let name_lower = name.to_lowercase();

        self.canonical_to_aliases.get(&canonical_lower).is_some_and(|aliases| aliases.contains(&name_lower))
    }

    /// Get all aliases for a canonical name
    pub fn get_aliases(&self, canonical: &str) -> Option<&HashSet<String>> {
        self.canonical_to_aliases.get(&canonical.to_lowercase())
    }

    /// Load aliases from JSON
    pub fn load_json(&mut self, json: &str) -> Result<(), serde_json::Error> {
        let entries: Vec<AliasEntry> = serde_json::from_str(json)?;
        for entry in entries {
            let aliases: Vec<&str> = entry.aliases.iter().map(std::string::String::as_str).collect();
            self.add_aliases(&entry.canonical, &aliases);
        }
        Ok(())
    }

    /// Export aliases to JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        let entries: Vec<AliasEntry> = self
            .canonical_to_aliases
            .iter()
            .map(|(canonical, aliases)| AliasEntry {
                canonical: canonical.clone(),
                aliases: aliases.iter().cloned().collect(),
            })
            .collect();
        serde_json::to_string_pretty(&entries)
    }
}

/// Entry in the alias table JSON format
#[derive(Debug, Serialize, Deserialize)]
struct AliasEntry {
    canonical: String,
    aliases: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alias_lookup() {
        let table = AliasTable::with_builtins();

        // PIL -> pillow
        assert_eq!(
            table.get_canonical("PIL"),
            Some("pkg:pypi/pillow".to_lowercase())
        );

        // sklearn -> scikit-learn
        assert_eq!(
            table.get_canonical("sklearn"),
            Some("pkg:pypi/scikit-learn".to_lowercase())
        );
    }

    #[test]
    fn test_is_alias() {
        let table = AliasTable::with_builtins();

        assert!(table.is_alias("pkg:pypi/pillow", "PIL"));
        assert!(table.is_alias("pkg:pypi/pillow", "pillow"));
        assert!(!table.is_alias("pkg:pypi/pillow", "numpy"));
    }

    #[test]
    fn test_custom_aliases() {
        let mut table = AliasTable::new();
        table.add_aliases("my-package", &["my_package", "mypackage"]);

        assert_eq!(
            table.get_canonical("my_package"),
            Some("my-package".to_string())
        );
        assert!(table.is_alias("my-package", "mypackage"));
    }
}
