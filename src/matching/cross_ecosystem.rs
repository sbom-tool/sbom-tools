//! Cross-ecosystem package mapping database.
//!
//! Many popular packages exist in multiple package ecosystems under different names.
//! This module provides a mapping database to identify equivalent packages across ecosystems.
//!
//! # Examples
//!
//! - `lodash` (npm) ↔ `lodash-py` (`PyPI`) - same library, different ecosystems
//! - `requests` (`PyPI`) ↔ `reqwest` (Cargo) - similar purpose, common confusion
//! - `@types/node` (npm) ↔ `types-node` (npm) - naming variations
//!
//! # Use Cases
//!
//! 1. **Polyglot projects**: Detect when a project uses the same library in multiple languages
//! 2. **Migration detection**: Identify when a package switched ecosystems
//! 3. **Typosquatting**: Detect packages with similar names across ecosystems

use crate::model::Ecosystem;
use std::collections::{HashMap, HashSet};

/// A cross-ecosystem package family.
///
/// Represents a conceptual package that may have different names in different ecosystems.
#[derive(Debug, Clone)]
pub struct PackageFamily {
    /// Canonical name for this package family
    pub canonical_name: String,
    /// Description of the package
    pub description: Option<String>,
    /// Package names in each ecosystem
    pub ecosystem_names: HashMap<Ecosystem, Vec<String>>,
    /// Whether this is a well-known/verified mapping
    pub verified: bool,
    /// Category (e.g., "http-client", "utility", "crypto")
    pub category: Option<String>,
}

impl PackageFamily {
    /// Create a new package family with a canonical name.
    pub fn new(canonical_name: impl Into<String>) -> Self {
        Self {
            canonical_name: canonical_name.into(),
            description: None,
            ecosystem_names: HashMap::new(),
            verified: false,
            category: None,
        }
    }

    /// Add a name mapping for an ecosystem.
    #[must_use]
    pub fn with_name(mut self, ecosystem: Ecosystem, name: impl Into<String>) -> Self {
        self.ecosystem_names
            .entry(ecosystem)
            .or_default()
            .push(name.into());
        self
    }

    /// Add multiple names for an ecosystem.
    #[must_use]
    pub fn with_names(mut self, ecosystem: &Ecosystem, names: &[&str]) -> Self {
        for name in names {
            self.ecosystem_names
                .entry(ecosystem.clone())
                .or_default()
                .push((*name).to_string());
        }
        self
    }

    /// Set the description.
    #[must_use]
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Mark as verified.
    #[must_use]
    pub const fn verified(mut self) -> Self {
        self.verified = true;
        self
    }

    /// Set the category.
    #[must_use]
    pub fn with_category(mut self, category: impl Into<String>) -> Self {
        self.category = Some(category.into());
        self
    }

    /// Check if this family contains a package name in a specific ecosystem.
    #[must_use]
    pub fn contains(&self, ecosystem: &Ecosystem, name: &str) -> bool {
        self.ecosystem_names
            .get(ecosystem)
            .is_some_and(|names| names.iter().any(|n| n.eq_ignore_ascii_case(name)))
    }

    /// Get all names for a specific ecosystem.
    pub fn names_for(&self, ecosystem: &Ecosystem) -> Option<&[String]> {
        self.ecosystem_names
            .get(ecosystem)
            .map(std::vec::Vec::as_slice)
    }

    /// Get all ecosystems this family spans.
    pub fn ecosystems(&self) -> impl Iterator<Item = &Ecosystem> {
        self.ecosystem_names.keys()
    }

    /// Check if two packages (in different ecosystems) are equivalent.
    #[must_use]
    pub fn are_equivalent(
        &self,
        eco_a: &Ecosystem,
        name_a: &str,
        eco_b: &Ecosystem,
        name_b: &str,
    ) -> bool {
        self.contains(eco_a, name_a) && self.contains(eco_b, name_b)
    }
}

/// Cross-ecosystem mapping database.
pub struct CrossEcosystemDb {
    /// All package families
    families: Vec<PackageFamily>,
    /// Index: (ecosystem, `lowercase_name`) -> family indices
    name_index: HashMap<(Ecosystem, String), Vec<usize>>,
}

impl CrossEcosystemDb {
    /// Create a new empty database.
    #[must_use]
    pub fn new() -> Self {
        Self {
            families: Vec::new(),
            name_index: HashMap::new(),
        }
    }

    /// Create a database with built-in well-known mappings.
    #[must_use]
    pub fn with_builtin_mappings() -> Self {
        let mut db = Self::new();
        db.add_builtin_mappings();
        db
    }

    /// Add a package family to the database.
    pub fn add_family(&mut self, family: PackageFamily) {
        let idx = self.families.len();

        // Index all names
        for (ecosystem, names) in &family.ecosystem_names {
            for name in names {
                self.name_index
                    .entry((ecosystem.clone(), name.to_lowercase()))
                    .or_default()
                    .push(idx);
            }
        }

        self.families.push(family);
    }

    /// Look up package families by name and ecosystem.
    #[must_use]
    pub fn lookup(&self, ecosystem: &Ecosystem, name: &str) -> Vec<&PackageFamily> {
        let key = (ecosystem.clone(), name.to_lowercase());
        self.name_index
            .get(&key)
            .map(|indices| indices.iter().map(|&i| &self.families[i]).collect())
            .unwrap_or_default()
    }

    /// Find equivalent packages in other ecosystems.
    #[must_use]
    pub fn find_equivalents(&self, ecosystem: &Ecosystem, name: &str) -> Vec<CrossEcosystemMatch> {
        let families = self.lookup(ecosystem, name);
        let mut matches = Vec::new();

        for family in families {
            for (other_eco, other_names) in &family.ecosystem_names {
                if other_eco != ecosystem {
                    for other_name in other_names {
                        matches.push(CrossEcosystemMatch {
                            source_ecosystem: ecosystem.clone(),
                            source_name: name.to_string(),
                            target_ecosystem: other_eco.clone(),
                            target_name: other_name.clone(),
                            family_name: family.canonical_name.clone(),
                            verified: family.verified,
                        });
                    }
                }
            }
        }

        matches
    }

    /// Check if two packages in different ecosystems are equivalent.
    #[must_use]
    pub fn are_equivalent(
        &self,
        eco_a: &Ecosystem,
        name_a: &str,
        eco_b: &Ecosystem,
        name_b: &str,
    ) -> bool {
        let families_a = self.lookup(eco_a, name_a);
        for family in families_a {
            if family.contains(eco_b, name_b) {
                return true;
            }
        }
        false
    }

    /// Get statistics about the database.
    #[must_use]
    pub fn stats(&self) -> CrossEcosystemDbStats {
        let total_families = self.families.len();
        let verified_families = self.families.iter().filter(|f| f.verified).count();
        let total_mappings = self.name_index.len();

        let mut ecosystems = HashSet::new();
        for family in &self.families {
            for eco in family.ecosystems() {
                ecosystems.insert(eco.clone());
            }
        }

        CrossEcosystemDbStats {
            total_families,
            verified_families,
            total_mappings,
            ecosystems_covered: ecosystems.len(),
        }
    }

    /// Add built-in well-known cross-ecosystem mappings.
    fn add_builtin_mappings(&mut self) {
        // HTTP clients
        self.add_family(
            PackageFamily::new("http-requests")
                .with_description("HTTP request libraries")
                .with_category("http-client")
                .with_name(Ecosystem::PyPi, "requests")
                .with_name(Ecosystem::PyPi, "httpx")
                .with_name(Ecosystem::PyPi, "aiohttp")
                .with_name(Ecosystem::Npm, "axios")
                .with_name(Ecosystem::Npm, "node-fetch")
                .with_name(Ecosystem::Npm, "got")
                .with_name(Ecosystem::Cargo, "reqwest")
                .with_name(Ecosystem::Cargo, "ureq")
                .with_name(Ecosystem::Golang, "net/http")
                .verified(),
        );

        // Utility libraries
        self.add_family(
            PackageFamily::new("lodash-family")
                .with_description("JavaScript utility libraries and ports")
                .with_category("utility")
                .with_names(
                    &Ecosystem::Npm,
                    &["lodash", "lodash-es", "underscore", "ramda"],
                )
                .with_name(Ecosystem::PyPi, "pydash")
                .verified(),
        );

        // JSON handling
        self.add_family(
            PackageFamily::new("json-libs")
                .with_description("JSON parsing and serialization")
                .with_category("serialization")
                .with_name(Ecosystem::Cargo, "serde_json")
                .with_name(Ecosystem::Cargo, "simd-json")
                .with_name(Ecosystem::PyPi, "ujson")
                .with_name(Ecosystem::PyPi, "orjson")
                .with_name(Ecosystem::Golang, "encoding/json")
                .verified(),
        );

        // Date/time handling
        self.add_family(
            PackageFamily::new("datetime-libs")
                .with_description("Date and time manipulation")
                .with_category("datetime")
                .with_names(&Ecosystem::Npm, &["moment", "dayjs", "date-fns", "luxon"])
                .with_names(&Ecosystem::PyPi, &["python-dateutil", "arrow", "pendulum"])
                .with_name(Ecosystem::Cargo, "chrono")
                .with_name(Ecosystem::Cargo, "time")
                .verified(),
        );

        // Async runtimes
        self.add_family(
            PackageFamily::new("async-runtime")
                .with_description("Async runtime/executor libraries")
                .with_category("async")
                .with_names(&Ecosystem::Cargo, &["tokio", "async-std", "smol"])
                .with_names(&Ecosystem::PyPi, &["asyncio", "trio", "curio"])
                .with_name(Ecosystem::Npm, "async")
                .verified(),
        );

        // CLI argument parsing
        self.add_family(
            PackageFamily::new("cli-args")
                .with_description("Command-line argument parsing")
                .with_category("cli")
                .with_names(&Ecosystem::Cargo, &["clap", "structopt", "argh"])
                .with_names(&Ecosystem::PyPi, &["argparse", "click", "typer"])
                .with_names(&Ecosystem::Npm, &["commander", "yargs", "minimist"])
                .with_name(Ecosystem::Golang, "flag")
                .with_name(Ecosystem::Golang, "cobra")
                .verified(),
        );

        // Logging
        self.add_family(
            PackageFamily::new("logging")
                .with_description("Logging frameworks")
                .with_category("logging")
                .with_names(&Ecosystem::Cargo, &["log", "tracing", "env_logger"])
                .with_names(&Ecosystem::PyPi, &["logging", "loguru", "structlog"])
                .with_names(&Ecosystem::Npm, &["winston", "pino", "bunyan"])
                .with_name(Ecosystem::Golang, "log")
                .with_name(Ecosystem::Golang, "zap")
                .verified(),
        );

        // Testing frameworks
        self.add_family(
            PackageFamily::new("testing")
                .with_description("Testing frameworks")
                .with_category("testing")
                .with_names(&Ecosystem::PyPi, &["pytest", "unittest", "nose2"])
                .with_names(&Ecosystem::Npm, &["jest", "mocha", "vitest", "ava"])
                .with_name(Ecosystem::Cargo, "test") // built-in
                .with_name(Ecosystem::Golang, "testing")
                .verified(),
        );

        // Web frameworks
        self.add_family(
            PackageFamily::new("web-framework")
                .with_description("Web application frameworks")
                .with_category("web")
                .with_names(
                    &Ecosystem::PyPi,
                    &["flask", "django", "fastapi", "starlette"],
                )
                .with_names(&Ecosystem::Npm, &["express", "fastify", "koa", "hapi"])
                .with_names(&Ecosystem::Cargo, &["actix-web", "axum", "rocket", "warp"])
                .with_name(Ecosystem::Golang, "net/http")
                .with_name(Ecosystem::Golang, "gin")
                .verified(),
        );

        // ORM / Database
        self.add_family(
            PackageFamily::new("orm-database")
                .with_description("ORM and database access libraries")
                .with_category("database")
                .with_names(&Ecosystem::PyPi, &["sqlalchemy", "peewee", "tortoise-orm"])
                .with_names(&Ecosystem::Npm, &["sequelize", "typeorm", "prisma", "knex"])
                .with_names(&Ecosystem::Cargo, &["diesel", "sqlx", "sea-orm"])
                .with_name(Ecosystem::Golang, "gorm")
                .verified(),
        );

        // Cryptography
        self.add_family(
            PackageFamily::new("crypto")
                .with_description("Cryptography libraries")
                .with_category("crypto")
                .with_names(
                    &Ecosystem::PyPi,
                    &["cryptography", "pycryptodome", "pyopenssl"],
                )
                .with_names(&Ecosystem::Npm, &["crypto-js", "node-forge", "bcrypt"])
                .with_names(&Ecosystem::Cargo, &["ring", "rustcrypto", "openssl"])
                .with_name(Ecosystem::Golang, "crypto")
                .verified(),
        );

        // YAML parsing
        self.add_family(
            PackageFamily::new("yaml-libs")
                .with_description("YAML parsing libraries")
                .with_category("serialization")
                .with_names(&Ecosystem::PyPi, &["pyyaml", "ruamel.yaml"])
                .with_names(&Ecosystem::Npm, &["js-yaml", "yaml"])
                .with_name(Ecosystem::Cargo, "serde_yaml")
                .with_name(Ecosystem::Golang, "gopkg.in/yaml.v3")
                .verified(),
        );

        // Regular expressions
        self.add_family(
            PackageFamily::new("regex")
                .with_description("Regular expression libraries")
                .with_category("text")
                .with_name(Ecosystem::PyPi, "re") // built-in
                .with_name(Ecosystem::PyPi, "regex")
                .with_name(Ecosystem::Cargo, "regex")
                .with_name(Ecosystem::Golang, "regexp")
                .verified(),
        );

        // Markdown
        self.add_family(
            PackageFamily::new("markdown")
                .with_description("Markdown parsing and rendering")
                .with_category("text")
                .with_names(&Ecosystem::PyPi, &["markdown", "mistune", "commonmark"])
                .with_names(&Ecosystem::Npm, &["marked", "markdown-it", "remark"])
                .with_names(&Ecosystem::Cargo, &["pulldown-cmark", "comrak"])
                .verified(),
        );
    }
}

impl Default for CrossEcosystemDb {
    fn default() -> Self {
        Self::with_builtin_mappings()
    }
}

/// A cross-ecosystem match result.
#[derive(Debug, Clone)]
pub struct CrossEcosystemMatch {
    /// Source ecosystem
    pub source_ecosystem: Ecosystem,
    /// Source package name
    pub source_name: String,
    /// Target ecosystem
    pub target_ecosystem: Ecosystem,
    /// Target package name
    pub target_name: String,
    /// Name of the package family
    pub family_name: String,
    /// Whether this is a verified mapping
    pub verified: bool,
}

impl std::fmt::Display for CrossEcosystemMatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{} ↔ {}:{} (family: {}{})",
            self.source_ecosystem,
            self.source_name,
            self.target_ecosystem,
            self.target_name,
            self.family_name,
            if self.verified { ", verified" } else { "" }
        )
    }
}

/// Statistics about the cross-ecosystem database.
#[derive(Debug, Clone)]
pub struct CrossEcosystemDbStats {
    /// Total number of package families
    pub total_families: usize,
    /// Number of verified families
    pub verified_families: usize,
    /// Total number of name mappings
    pub total_mappings: usize,
    /// Number of ecosystems covered
    pub ecosystems_covered: usize,
}

impl std::fmt::Display for CrossEcosystemDbStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Cross-ecosystem DB: {} families ({} verified), {} mappings across {} ecosystems",
            self.total_families,
            self.verified_families,
            self.total_mappings,
            self.ecosystems_covered
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_package_family_creation() {
        let family = PackageFamily::new("test-family")
            .with_name(Ecosystem::Npm, "test-npm")
            .with_name(Ecosystem::PyPi, "test-pypi")
            .with_description("Test family")
            .verified();

        assert!(family.contains(&Ecosystem::Npm, "test-npm"));
        assert!(family.contains(&Ecosystem::PyPi, "test-pypi"));
        assert!(!family.contains(&Ecosystem::Cargo, "test-cargo"));
        assert!(family.verified);
    }

    #[test]
    fn test_package_family_equivalence() {
        let family = PackageFamily::new("http-client")
            .with_name(Ecosystem::PyPi, "requests")
            .with_name(Ecosystem::Cargo, "reqwest");

        assert!(family.are_equivalent(&Ecosystem::PyPi, "requests", &Ecosystem::Cargo, "reqwest"));

        assert!(!family.are_equivalent(&Ecosystem::PyPi, "requests", &Ecosystem::Npm, "axios"));
    }

    #[test]
    fn test_cross_ecosystem_db_builtin() {
        let db = CrossEcosystemDb::with_builtin_mappings();
        let stats = db.stats();

        assert!(stats.total_families > 10, "Should have built-in families");
        assert!(stats.verified_families > 0, "Should have verified families");
    }

    #[test]
    fn test_cross_ecosystem_db_lookup() {
        let db = CrossEcosystemDb::with_builtin_mappings();

        // Look up requests (Python)
        let families = db.lookup(&Ecosystem::PyPi, "requests");
        assert!(!families.is_empty(), "Should find requests in a family");

        // Look up lodash (npm)
        let families = db.lookup(&Ecosystem::Npm, "lodash");
        assert!(!families.is_empty(), "Should find lodash in a family");
    }

    #[test]
    fn test_cross_ecosystem_find_equivalents() {
        let db = CrossEcosystemDb::with_builtin_mappings();

        // Find equivalents for lodash
        let equivalents = db.find_equivalents(&Ecosystem::Npm, "lodash");

        // Should find pydash (Python) as equivalent
        let has_pydash = equivalents
            .iter()
            .any(|m| m.target_ecosystem == Ecosystem::PyPi && m.target_name == "pydash");
        assert!(has_pydash, "Should find pydash as equivalent to lodash");
    }

    #[test]
    fn test_cross_ecosystem_are_equivalent() {
        let db = CrossEcosystemDb::with_builtin_mappings();

        // lodash and pydash should be equivalent
        assert!(db.are_equivalent(&Ecosystem::Npm, "lodash", &Ecosystem::PyPi, "pydash"));

        // requests and reqwest are NOT in same family (different purpose)
        // They're in the same "http-requests" category but different names
        // In our mapping, requests (Python) and reqwest (Rust) are in the same family
        // because they serve the same purpose
        let result = db.are_equivalent(&Ecosystem::PyPi, "requests", &Ecosystem::Cargo, "reqwest");
        assert!(result, "requests and reqwest should be in same family");
    }

    #[test]
    fn test_cross_ecosystem_db_stats() {
        let db = CrossEcosystemDb::with_builtin_mappings();
        let stats = db.stats();

        println!("{}", stats);
        assert!(
            stats.ecosystems_covered >= 4,
            "Should cover major ecosystems"
        );
    }

    #[test]
    fn test_case_insensitive_lookup() {
        let db = CrossEcosystemDb::with_builtin_mappings();

        // Should find regardless of case
        let families_lower = db.lookup(&Ecosystem::Npm, "lodash");
        let families_upper = db.lookup(&Ecosystem::Npm, "LODASH");
        let families_mixed = db.lookup(&Ecosystem::Npm, "LoDaSh");

        assert_eq!(families_lower.len(), families_upper.len());
        assert_eq!(families_lower.len(), families_mixed.len());
    }
}
