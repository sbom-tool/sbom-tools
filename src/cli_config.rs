//! Glue between the global `--config` flag and per-command config construction.
//!
//! [`EffectiveConfig::load`] discovers/loads/validates a YAML config file once,
//! up front. The resulting [`EffectiveConfig`] is then threaded into each
//! subcommand's config builder as the *base* layer. Per-command seeding asks
//! [`resolve`] / [`resolve_bool`] for a value, which resolves precedence as:
//!
//!   explicit CLI flag > config file value > built-in default
//!
//! CLI explicitness is determined at the clap layer ([`ValueSource`]) so that a
//! flag whose value happens to equal the default (e.g. `--output auto`) still
//! overrides the file, while an unset flag falls through to the file value.

use anyhow::{Context, Result};
use clap::ArgMatches;
use clap::parser::ValueSource;
use sbom_tools::config::{
    AppConfig, Validatable, discover_config_file, load_config_file, load_or_default,
};
use std::path::Path;

/// Loaded config plus the discovered source path (for diagnostics).
pub struct EffectiveConfig {
    config: AppConfig,
    loaded_from: Option<std::path::PathBuf>,
}

impl EffectiveConfig {
    /// Discover, load, and validate the config file.
    ///
    /// When `no_config` is true, discovery is skipped entirely and built-in
    /// defaults are returned. Otherwise the explicit `--config` path is
    /// honoured first, falling back to standard discovery locations. Unlike the
    /// lenient loader, a config file that exists but fails to *parse* or
    /// *validate* is rejected with a hard error rather than silently falling
    /// back to defaults — a broken file must never quietly change behaviour.
    pub fn load(explicit_path: Option<&Path>, no_config: bool) -> Result<Self> {
        if no_config {
            return Ok(Self {
                config: AppConfig::default(),
                loaded_from: None,
            });
        }

        // An explicit --config path that doesn't exist is a user error, not a
        // silent fall-through to discovery.
        if let Some(path) = explicit_path
            && !path.exists()
        {
            anyhow::bail!("config file not found: {}", path.display());
        }

        let Some(path) = discover_config_file(explicit_path) else {
            return Ok(Self {
                config: AppConfig::default(),
                loaded_from: None,
            });
        };

        let config = load_config_file(&path)
            .with_context(|| format!("failed to load config file {}", path.display()))?;
        Self::validate(&config, Some(&path))?;
        Ok(Self {
            config,
            loaded_from: Some(path),
        })
    }

    /// Like [`load`](Self::load) but skips validation. Used by meta commands
    /// (config management, completions, man, schema) that must run even when a
    /// discovered config file is invalid. A missing explicit `--config` path is
    /// tolerated here rather than erroring.
    #[must_use]
    pub fn load_lenient(explicit_path: Option<&Path>, no_config: bool) -> Self {
        if no_config {
            return Self {
                config: AppConfig::default(),
                loaded_from: None,
            };
        }
        let (config, loaded_from) = load_or_default(explicit_path);
        Self {
            config,
            loaded_from,
        }
    }

    fn validate(config: &AppConfig, source: Option<&Path>) -> Result<()> {
        let errors = config.validate();
        if errors.is_empty() {
            return Ok(());
        }
        let where_ = source.map_or_else(
            || "configuration".to_string(),
            |p| format!("config file {}", p.display()),
        );
        let detail = errors
            .iter()
            .map(|e| format!("  - {e}"))
            .collect::<Vec<_>>()
            .join("\n");
        anyhow::bail!("invalid {where_}:\n{detail}");
    }

    /// The path the config was loaded from, if any.
    pub fn loaded_from(&self) -> Option<&Path> {
        self.loaded_from.as_deref()
    }

    /// The merged effective config (defaults + file).
    pub fn into_app_config(self) -> AppConfig {
        self.config
    }
}

/// True when `name` was supplied on the command line (not a clap default).
#[must_use]
pub fn arg_was_set(matches: &ArgMatches, name: &str) -> bool {
    matches!(matches.value_source(name), Some(ValueSource::CommandLine))
}

/// [`arg_was_set`] tolerant of an absent subcommand match.
#[must_use]
pub fn arg_was_set_sub(matches: Option<&ArgMatches>, name: &str) -> bool {
    matches.is_some_and(|m| arg_was_set(m, name))
}

/// Resolve precedence for an optional value: explicit CLI > file > `None`.
///
/// `cli_value` is the parsed clap value (possibly a default). `was_set`
/// reflects whether the user actually passed the flag.
#[must_use]
pub fn resolve<T>(cli_value: T, was_set: bool, file_value: Option<T>) -> T {
    if was_set {
        cli_value
    } else {
        file_value.unwrap_or(cli_value)
    }
}

/// Resolve a boolean flag: an explicit `true` from either CLI or file wins.
///
/// Boolean clap flags default to `false` and only ever transition to `true`
/// when present, so OR-ing the CLI flag with the file value yields the correct
/// "either layer enabled it" semantics without needing `value_source`.
#[must_use]
pub const fn resolve_bool(cli_value: bool, file_value: bool) -> bool {
    cli_value || file_value
}
