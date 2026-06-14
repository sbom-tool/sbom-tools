//! CLI handler for the `cache` command.
//!
//! Manages the on-disk enrichment cache so that air-gapped (`--offline`) runs
//! are fully served from local data:
//!
//! - `cache status` — list cached sources, entry counts, ages, total size.
//! - `cache warm <sbom>` — pre-fetch enrichment data for an SBOM's components.
//! - `cache clear` — remove all cached entries.
//! - `cache export <path>` / `cache import <path>` — copy the whole cache tree
//!   for sneakernet transfer between an online and an air-gapped machine.
//!
//! Export/import use a plain recursive directory copy (no archive format, no new
//! dependency): the cache is already a tree of small JSON files, so a directory
//! copy is the simplest portable bundle and keeps the tool dependency-free under
//! cargo-deny. The destination is a self-contained `sbom-tools` cache tree the
//! `--offline` reader consumes directly.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};

use crate::enrichment::source::root_cache_dir;
use crate::pipeline::exit_codes;

/// Cache management action.
#[derive(Debug, Clone, clap::Subcommand)]
pub enum CacheAction {
    /// List cached sources with entry counts, ages, and total size
    Status,
    /// Pre-fetch enrichment data for an SBOM so a later --offline run is served
    Warm {
        /// SBOM file to warm the cache for
        sbom: PathBuf,
        /// Warm every source (OSV, EOL, KEV, staleness), not just OSV
        #[arg(long)]
        all_sources: bool,
    },
    /// Remove all cached enrichment entries
    Clear,
    /// Copy the whole cache tree to a directory for sneakernet transfer
    Export {
        /// Destination directory (created if absent)
        path: PathBuf,
    },
    /// Import a previously exported cache tree into the local cache
    Import {
        /// Source directory produced by `cache export`
        path: PathBuf,
    },
}

/// Run the `cache` command.
pub fn run_cache(action: CacheAction, quiet: bool) -> Result<i32> {
    match action {
        CacheAction::Status => cache_status(quiet),
        CacheAction::Warm { sbom, all_sources } => cache_warm(&sbom, all_sources, quiet),
        CacheAction::Clear => cache_clear(quiet),
        CacheAction::Export { path } => cache_export(&path, quiet),
        CacheAction::Import { path } => cache_import(&path, quiet),
    }
}

/// The enrichment source namespaces that live under the root cache directory.
const SOURCE_NAMESPACES: &[&str] = &["osv", "eol", "kev", "staleness"];

/// Aggregate counts for one source's cache directory.
struct SourceStatus {
    name: String,
    entries: usize,
    total_size: u64,
    oldest: Option<Duration>,
    newest: Option<Duration>,
}

fn source_status(name: &str, dir: &Path) -> SourceStatus {
    let mut entries = 0usize;
    let mut total_size = 0u64;
    let mut oldest: Option<Duration> = None;
    let mut newest: Option<Duration> = None;

    if let Ok(read_dir) = fs::read_dir(dir) {
        for entry in read_dir.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|e| e != "json") {
                continue;
            }
            entries += 1;
            if let Ok(meta) = entry.metadata() {
                total_size += meta.len();
                if let Ok(modified) = meta.modified()
                    && let Ok(age) = modified.elapsed()
                {
                    oldest = Some(oldest.map_or(age, |o| o.max(age)));
                    newest = Some(newest.map_or(age, |n| n.min(age)));
                }
            }
        }
    }

    SourceStatus {
        name: name.to_string(),
        entries,
        total_size,
        oldest,
        newest,
    }
}

fn cache_status(quiet: bool) -> Result<i32> {
    let root = root_cache_dir();
    if !root.exists() {
        if !quiet {
            println!("No cache directory yet ({}).", root.display());
        }
        return Ok(exit_codes::SUCCESS);
    }

    let mut total_entries = 0usize;
    let mut total_size = 0u64;
    let mut rows: Vec<SourceStatus> = Vec::new();
    for ns in SOURCE_NAMESPACES {
        let dir = root.join(ns);
        if dir.exists() {
            let status = source_status(ns, &dir);
            total_entries += status.entries;
            total_size += status.total_size;
            rows.push(status);
        }
    }

    if quiet {
        return Ok(exit_codes::SUCCESS);
    }

    println!("Cache directory: {}", root.display());
    if rows.is_empty() {
        println!("  (no cached enrichment data)");
        return Ok(exit_codes::SUCCESS);
    }

    println!(
        "{:<12} {:>8} {:>12} {:>12} {:>12}",
        "SOURCE", "ENTRIES", "SIZE", "OLDEST", "NEWEST"
    );
    for row in &rows {
        println!(
            "{:<12} {:>8} {:>12} {:>12} {:>12}",
            row.name,
            row.entries,
            human_size(row.total_size),
            row.oldest.map_or_else(|| "-".to_string(), human_age),
            row.newest.map_or_else(|| "-".to_string(), human_age),
        );
    }
    println!(
        "{:<12} {:>8} {:>12}",
        "TOTAL",
        total_entries,
        human_size(total_size)
    );

    Ok(exit_codes::SUCCESS)
}

/// Warm the cache by enriching the SBOM with all (or just OSV) sources, forcing
/// fresh fetches so the on-disk cache is fully populated for a later offline run.
fn cache_warm(sbom_path: &Path, all_sources: bool, quiet: bool) -> Result<i32> {
    use crate::config::EnrichmentConfig;

    // Warming requires the network, so it must not run in offline mode.
    if crate::enrichment::source::is_offline() {
        anyhow::bail!("cannot warm the cache in offline mode: run `cache warm` while online");
    }

    let mut parsed = crate::pipeline::parse_sbom_with_context(sbom_path, quiet)?;

    let mut config = EnrichmentConfig::osv();
    config.enable_eol = all_sources;
    config.enable_kev = all_sources;
    config.enable_staleness = all_sources;
    // Force fresh fetches so every queryable component lands in the cache.
    config.bypass_cache = true;
    config.offline = false;

    let stats = crate::pipeline::enrich_sbom_full(parsed.sbom_mut(), &config, quiet);

    if !quiet {
        for warning in &stats.warnings {
            eprintln!("Warning: {warning}");
        }
        let n = parsed.sbom().component_count();
        println!(
            "Warmed cache for {n} component(s) from {} ({}).",
            sbom_path.display(),
            if all_sources {
                "OSV, EOL, KEV, staleness"
            } else {
                "OSV"
            }
        );
    }

    Ok(exit_codes::SUCCESS)
}

fn cache_clear(quiet: bool) -> Result<i32> {
    let root = root_cache_dir();
    if !root.exists() {
        if !quiet {
            println!("Nothing to clear ({} does not exist).", root.display());
        }
        return Ok(exit_codes::SUCCESS);
    }

    let mut removed = 0usize;
    for ns in SOURCE_NAMESPACES {
        let dir = root.join(ns);
        if let Ok(read_dir) = fs::read_dir(&dir) {
            for entry in read_dir.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "json") && fs::remove_file(&path).is_ok() {
                    removed += 1;
                }
            }
        }
    }

    if !quiet {
        println!("Cleared {removed} cached entr{}.", plural(removed));
    }
    Ok(exit_codes::SUCCESS)
}

fn cache_export(dest: &Path, quiet: bool) -> Result<i32> {
    let root = root_cache_dir();
    if !root.exists() {
        anyhow::bail!("no cache to export ({} does not exist)", root.display());
    }

    fs::create_dir_all(dest)
        .with_context(|| format!("creating export directory {}", dest.display()))?;
    let copied = copy_dir_recursive(&root, dest)?;

    if !quiet {
        println!(
            "Exported {copied} cache file(s) to {} (copy this to the air-gapped host, then `cache import`).",
            dest.display()
        );
    }
    Ok(exit_codes::SUCCESS)
}

fn cache_import(src: &Path, quiet: bool) -> Result<i32> {
    if !src.exists() {
        anyhow::bail!("import source {} does not exist", src.display());
    }

    let root = root_cache_dir();
    fs::create_dir_all(&root)
        .with_context(|| format!("creating cache directory {}", root.display()))?;
    let copied = copy_dir_recursive(src, &root)?;

    if !quiet {
        println!(
            "Imported {copied} cache file(s) into {}. Run with --offline to use them.",
            root.display()
        );
    }
    Ok(exit_codes::SUCCESS)
}

/// Recursively copy every file from `src` into `dest`, mirroring the directory
/// structure. Returns the number of files copied.
fn copy_dir_recursive(src: &Path, dest: &Path) -> Result<usize> {
    let mut copied = 0usize;
    for entry in
        fs::read_dir(src).with_context(|| format!("reading directory {}", src.display()))?
    {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let from = entry.path();
        let to = dest.join(entry.file_name());
        if file_type.is_dir() {
            fs::create_dir_all(&to).with_context(|| format!("creating {}", to.display()))?;
            copied += copy_dir_recursive(&from, &to)?;
        } else if file_type.is_file() {
            if let Some(parent) = to.parent() {
                fs::create_dir_all(parent).ok();
            }
            fs::copy(&from, &to)
                .with_context(|| format!("copying {} -> {}", from.display(), to.display()))?;
            copied += 1;
        }
    }
    Ok(copied)
}

/// Human-readable byte size (e.g. `12.3 KB`).
fn human_size(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    let b = bytes as f64;
    if b >= MB {
        format!("{:.1} MB", b / MB)
    } else if b >= KB {
        format!("{:.1} KB", b / KB)
    } else {
        format!("{bytes} B")
    }
}

/// Human-readable age (e.g. `3d`, `5h`, `12m`, `<1m`).
fn human_age(age: Duration) -> String {
    let secs = age.as_secs();
    if secs >= 86_400 {
        format!("{}d", secs / 86_400)
    } else if secs >= 3_600 {
        format!("{}h", secs / 3_600)
    } else if secs >= 60 {
        format!("{}m", secs / 60)
    } else {
        "<1m".to_string()
    }
}

const fn plural(n: usize) -> &'static str {
    if n == 1 { "y" } else { "ies" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_size_formats() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(2048), "2.0 KB");
        assert_eq!(human_size(3 * 1024 * 1024), "3.0 MB");
    }

    #[test]
    fn human_age_formats() {
        assert_eq!(human_age(Duration::from_secs(30)), "<1m");
        assert_eq!(human_age(Duration::from_secs(120)), "2m");
        assert_eq!(human_age(Duration::from_secs(7200)), "2h");
        assert_eq!(human_age(Duration::from_secs(2 * 86_400)), "2d");
    }

    #[test]
    fn copy_dir_recursive_roundtrip() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        fs::create_dir_all(src.path().join("osv")).unwrap();
        fs::write(src.path().join("osv").join("a.json"), "{}").unwrap();
        fs::write(src.path().join("osv").join("b.json"), "{}").unwrap();

        let copied = copy_dir_recursive(src.path(), dst.path()).unwrap();
        assert_eq!(copied, 2);
        assert!(dst.path().join("osv").join("a.json").exists());
        assert!(dst.path().join("osv").join("b.json").exists());
    }
}
