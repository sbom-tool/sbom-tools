//! Main watch loop orchestrator.
//!
//! Coordinates file monitoring, parsing, diffing, enrichment, and alerting.

use super::alerts::{build_alert_sinks, AlertSink};
use super::config::WatchConfig;
use super::monitor::{FileChange, FileMonitor};
use super::state::{DiffSnapshot, MonitorStatus, WatchState, WatchSummary};
use super::WatchError;
use crate::diff::DiffEngine;
use crate::matching::FuzzyMatchConfig;
use crate::model::NormalizedSbom;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Run the main watch loop.
///
/// Polls directories for SBOM file changes at `config.poll_interval` and
/// optionally re-enriches on `config.enrich_interval`. Returns only when
/// the process is interrupted or `exit_on_change` triggers.
pub fn run_watch_loop(config: &WatchConfig) -> anyhow::Result<()> {
    let mut monitor = FileMonitor::new(config.watch_dirs.clone());
    let mut state = WatchState::new(config.max_snapshots);
    let mut sinks = build_alert_sinks(config)?;
    let engine = DiffEngine::new().with_fuzzy_config(FuzzyMatchConfig::balanced());

    // Graceful shutdown flag
    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop_flag = Arc::clone(&stop);
        ctrlc::set_handler(move || {
            stop_flag.store(true, Ordering::Relaxed);
        })
        .ok(); // Non-fatal if handler cannot be installed
    }

    // --- initial scan ---
    let initial = monitor.poll();
    if initial.is_empty() {
        return Err(WatchError::NoFilesFound.into());
    }

    for change in &initial {
        if let FileChange::Added(path) = change {
            process_initial(path, config, &mut state);
        }
    }

    log_watch_started(&state, &monitor, config);

    // Emit initial status
    emit_status(&state, &mut sinks);

    // Dry-run mode: print discovered files and exit
    if config.dry_run {
        if !config.quiet {
            let healthy = state.count_status(MonitorStatus::Healthy);
            let errors = state.count_status(MonitorStatus::Error);
            eprintln!("Dry run complete: {healthy} SBOM(s) parsed successfully, {errors} error(s)");
            for (path, entry) in &state.sboms {
                let status = match entry.status {
                    MonitorStatus::Healthy => format!("OK ({} components, {} vulns, {} EOL)", entry.component_count, entry.vuln_count, entry.eol_count),
                    MonitorStatus::Error => format!("ERROR: {}", entry.last_error.as_deref().unwrap_or("unknown")),
                    _ => format!("{}", entry.status),
                };
                eprintln!("  {} — {}", path.display(), status);
            }
        }
        return Ok(());
    }

    // If exit_on_change and we already discovered files, we wait for _changes_
    // (initial discovery doesn't count).

    // --- main loop ---
    loop {
        // Graceful shutdown check
        if stop.load(Ordering::Relaxed) {
            if !config.quiet {
                eprintln!("Shutting down gracefully...");
            }
            emit_status(&state, &mut sinks);
            return Ok(());
        }

        std::thread::sleep(config.poll_interval);
        state.poll_count += 1;
        state.last_poll = Some(Instant::now());

        let changes = monitor.poll();

        // Debounce: if changes detected, wait briefly and re-poll to coalesce rapid writes
        let changes = if !changes.is_empty() && !config.debounce.is_zero() {
            std::thread::sleep(config.debounce);
            let mut merged = changes;
            let extra = monitor.poll();
            for change in extra {
                if !merged.contains(&change) {
                    merged.push(change);
                }
            }
            merged
        } else {
            changes
        };

        for change in &changes {
            match change {
                FileChange::Added(p) | FileChange::Modified(p) => {
                    state.total_changes += 1;
                    process_sbom_change(p, config, &mut state, &mut sinks, &engine);
                }
                FileChange::Removed(p) => {
                    state.mark_removed(p);
                    for sink in &mut sinks {
                        if let Err(e) = sink.on_sbom_removed(p) {
                            tracing::warn!("Alert sink error: {e}");
                        }
                    }
                }
            }
        }

        // Periodic re-enrichment
        let should_enrich = state
            .last_enrichment
            .is_none_or(|t| t.elapsed() >= config.enrich_interval);
        if should_enrich && config.enrichment.enabled {
            run_enrichment_cycle(config, &mut state, &mut sinks);
        }

        // Periodic status
        if !changes.is_empty() {
            emit_status(&state, &mut sinks);
        }

        // CI mode: exit after detecting a real change
        if config.exit_on_change && state.total_changes > 0 {
            if !config.quiet {
                eprintln!("Change detected, exiting (--exit-on-change)");
            }
            return Ok(());
        }

        // Check stop flag again after processing
        if stop.load(Ordering::Relaxed) {
            if !config.quiet {
                eprintln!("Shutting down gracefully...");
            }
            emit_status(&state, &mut sinks);
            return Ok(());
        }
    }
}

/// Parse and record the initial state of a discovered SBOM (no diff).
///
/// When enrichment is enabled, also enriches the SBOM with vulnerability/EOL/VEX
/// data so the initial state reflects the full picture.
#[allow(unused_variables)]
fn process_initial(path: &Path, config: &WatchConfig, state: &mut WatchState) {
    let entry = state.get_or_insert(path);
    entry.status = MonitorStatus::Updating;

    match crate::pipeline::parse_sbom_with_context(path, true) {
        Ok(parsed) => {
            let mut sbom = parsed.into_sbom();

            // Enrich on initial scan when enrichment is configured
            #[cfg(feature = "enrichment")]
            if config.enrichment.enabled {
                let osv_config = crate::pipeline::build_enrichment_config(&config.enrichment);
                crate::pipeline::enrich_sbom(&mut sbom, &osv_config, true);

                if config.enrichment.enable_eol {
                    let eol_config = crate::enrichment::EolClientConfig {
                        cache_dir: config
                            .enrichment
                            .cache_dir
                            .clone()
                            .unwrap_or_else(crate::pipeline::dirs::eol_cache_dir),
                        cache_ttl: std::time::Duration::from_secs(
                            config.enrichment.cache_ttl_hours * 3600,
                        ),
                        timeout: std::time::Duration::from_secs(config.enrichment.timeout_secs),
                        ..Default::default()
                    };
                    crate::pipeline::enrich_eol(&mut sbom, &eol_config, true);
                }

                if !config.enrichment.vex_paths.is_empty() {
                    crate::pipeline::enrich_vex(&mut sbom, &config.enrichment.vex_paths, true);
                }

                entry.last_enriched = Some(Instant::now());
            }

            entry.component_count = sbom.component_count();
            entry.vuln_count = count_vulns(&sbom);
            entry.eol_count = count_eol(&sbom);
            entry.current_sbom = Some(sbom);
            entry.last_parsed = Some(Instant::now());
            entry.status = MonitorStatus::Healthy;
            entry.last_error = None;
        }
        Err(e) => {
            tracing::warn!("Failed to parse {}: {e}", path.display());
            entry.status = MonitorStatus::Error;
            entry.last_error = Some(e.to_string());
        }
    }
}

/// Handle a new or modified SBOM file: parse, diff against previous, alert.
fn process_sbom_change(
    path: &Path,
    _config: &WatchConfig,
    state: &mut WatchState,
    sinks: &mut [Box<dyn AlertSink>],
    engine: &DiffEngine,
) {
    let entry = state.get_or_insert(path);
    entry.status = MonitorStatus::Updating;

    let previous_sbom = entry.current_sbom.take();

    match crate::pipeline::parse_sbom_with_context(path, true) {
        Ok(parsed) => {
            let new_sbom = parsed.into_sbom();
            entry.component_count = new_sbom.component_count();
            entry.vuln_count = count_vulns(&new_sbom);
            entry.eol_count = count_eol(&new_sbom);
            entry.last_parsed = Some(Instant::now());
            entry.status = MonitorStatus::Healthy;
            entry.last_error = None;

            // Diff against previous snapshot
            let snapshot = if let Some(ref old) = previous_sbom {
                build_diff_snapshot(old, &new_sbom, engine)
            } else {
                // First time seeing this file (added) — summarize as "all added"
                DiffSnapshot {
                    timestamp: chrono::Utc::now(),
                    components_added: new_sbom.component_count(),
                    components_removed: 0,
                    components_modified: 0,
                    new_vulns: new_sbom
                        .components
                        .values()
                        .flat_map(|c| c.vulnerabilities.iter().map(|v| v.id.clone()))
                        .collect(),
                    resolved_vulns: vec![],
                    new_eol: new_sbom
                        .components
                        .values()
                        .filter(|c| c.eol.is_some())
                        .map(|c| c.name.clone())
                        .collect(),
                }
            };

            // Fire alerts
            if snapshot.has_changes() {
                for sink in sinks.iter_mut() {
                    if let Err(e) = sink.on_change(path, &snapshot) {
                        tracing::warn!("Alert sink error: {e}");
                    }
                }
            }

            // Record snapshot in history
            let path_buf = path.to_path_buf();
            entry.current_sbom = Some(new_sbom);
            // Need to drop the mutable borrow of entry before calling record_snapshot
            state.record_snapshot(&path_buf, snapshot);
        }
        Err(e) => {
            tracing::warn!("Failed to parse {}: {e}", path.display());
            entry.status = MonitorStatus::Error;
            entry.last_error = Some(e.to_string());
            // Restore previous SBOM so we can diff again next time
            entry.current_sbom = previous_sbom;
        }
    }
}

/// Build a [`DiffSnapshot`] by diffing two SBOMs.
fn build_diff_snapshot(old: &NormalizedSbom, new: &NormalizedSbom, engine: &DiffEngine) -> DiffSnapshot {
    match engine.diff(old, new) {
        Ok(result) => {
            let new_vulns: Vec<String> = result
                .vulnerabilities
                .introduced
                .iter()
                .map(|v| v.id.clone())
                .collect();
            let resolved_vulns: Vec<String> = result
                .vulnerabilities
                .resolved
                .iter()
                .map(|v| v.id.clone())
                .collect();

            // Detect newly EOL components (in new but not old)
            let old_eol: std::collections::HashSet<&str> = old
                .components
                .values()
                .filter(|c| c.eol.is_some())
                .map(|c| c.name.as_str())
                .collect();
            let new_eol: Vec<String> = new
                .components
                .values()
                .filter(|c| c.eol.is_some() && !old_eol.contains(c.name.as_str()))
                .map(|c| c.name.clone())
                .collect();

            DiffSnapshot {
                timestamp: chrono::Utc::now(),
                components_added: result.components.added.len(),
                components_removed: result.components.removed.len(),
                components_modified: result.components.modified.len(),
                new_vulns,
                resolved_vulns,
                new_eol,
            }
        }
        Err(e) => {
            tracing::warn!("Diff failed: {e}");
            DiffSnapshot {
                timestamp: chrono::Utc::now(),
                components_added: 0,
                components_removed: 0,
                components_modified: 0,
                new_vulns: vec![],
                resolved_vulns: vec![],
                new_eol: vec![],
            }
        }
    }
}

/// Re-enrich all healthy SBOMs and fire alerts for any newly discovered vulns.
#[allow(unused_variables)]
fn run_enrichment_cycle(
    config: &WatchConfig,
    state: &mut WatchState,
    sinks: &mut [Box<dyn AlertSink>],
) {
    state.last_enrichment = Some(Instant::now());

    #[cfg(feature = "enrichment")]
    {
        let osv_config = crate::pipeline::build_enrichment_config(&config.enrichment);
        let eol_config = if config.enrichment.enable_eol {
            Some(crate::enrichment::EolClientConfig {
                cache_dir: config
                    .enrichment
                    .cache_dir
                    .clone()
                    .unwrap_or_else(crate::pipeline::dirs::eol_cache_dir),
                cache_ttl: std::time::Duration::from_secs(config.enrichment.cache_ttl_hours * 3600),
                bypass_cache: true, // force fresh data during enrichment cycles
                timeout: std::time::Duration::from_secs(config.enrichment.timeout_secs),
                ..Default::default()
            })
        } else {
            None
        };

        let paths: Vec<_> = state
            .sboms
            .iter()
            .filter(|(_, s)| s.status == MonitorStatus::Healthy && s.current_sbom.is_some())
            .map(|(p, _)| p.clone())
            .collect();

        for path in paths {
            let entry = match state.sboms.get_mut(&path) {
                Some(e) => e,
                None => continue,
            };

            let sbom = match entry.current_sbom.as_mut() {
                Some(s) => s,
                None => continue,
            };

            let old_vuln_ids: std::collections::HashSet<String> = sbom
                .components
                .values()
                .flat_map(|c| c.vulnerabilities.iter().map(|v| v.id.clone()))
                .collect();

            // OSV enrichment (with cache bypass for fresh data)
            let mut bypass_config = osv_config.clone();
            bypass_config.bypass_cache = true;
            crate::pipeline::enrich_sbom(sbom, &bypass_config, true);

            // EOL enrichment
            if let Some(ref eol_cfg) = eol_config {
                crate::pipeline::enrich_eol(sbom, eol_cfg, true);
            }

            // VEX enrichment
            if !config.enrichment.vex_paths.is_empty() {
                crate::pipeline::enrich_vex(sbom, &config.enrichment.vex_paths, true);
            }

            entry.last_enriched = Some(Instant::now());
            entry.vuln_count = count_vulns(sbom);
            entry.eol_count = count_eol(sbom);

            // Detect newly discovered vulns
            let new_vuln_ids: Vec<String> = sbom
                .components
                .values()
                .flat_map(|c| c.vulnerabilities.iter().map(|v| v.id.clone()))
                .filter(|id| !old_vuln_ids.contains(id))
                .collect();

            if !new_vuln_ids.is_empty() {
                for sink in sinks.iter_mut() {
                    if let Err(e) = sink.on_new_vulns(&path, &new_vuln_ids) {
                        tracing::warn!("Alert sink error: {e}");
                    }
                }
            }
        }
    }

    if !config.quiet {
        tracing::info!("Enrichment cycle complete");
    }
}

/// Emit a status summary to all sinks.
fn emit_status(state: &WatchState, sinks: &mut [Box<dyn AlertSink>]) {
    let summary = WatchSummary {
        tracked_count: state.sboms.len(),
        healthy_count: state.count_status(MonitorStatus::Healthy),
        error_count: state.count_status(MonitorStatus::Error),
        total_vulns: state.total_vulns(),
        total_changes: state.total_changes,
        uptime_secs: state.started_at.elapsed().as_secs(),
    };
    for sink in sinks.iter_mut() {
        if let Err(e) = sink.on_status(&summary) {
            tracing::warn!("Alert sink error: {e}");
        }
    }
}

fn log_watch_started(state: &WatchState, monitor: &FileMonitor, config: &WatchConfig) {
    if config.quiet {
        return;
    }
    let healthy = state.count_status(MonitorStatus::Healthy);
    let errors = state.count_status(MonitorStatus::Error);
    let total = monitor.tracked_count();
    eprintln!(
        "Watching {} SBOM file(s) across {} dir(s) (poll: {:?}, enrich: {:?})",
        total,
        config.watch_dirs.len(),
        config.poll_interval,
        config.enrich_interval,
    );
    if errors > 0 {
        eprintln!("  {healthy} healthy, {errors} with errors");
    }
}

fn count_vulns(sbom: &NormalizedSbom) -> usize {
    sbom.components
        .values()
        .map(|c| c.vulnerabilities.len())
        .sum()
}

fn count_eol(sbom: &NormalizedSbom) -> usize {
    sbom.components.values().filter(|c| c.eol.is_some()).count()
}
