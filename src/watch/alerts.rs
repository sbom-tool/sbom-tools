//! Alert sinks for the watch subsystem.
//!
//! Provides trait-based extensible alerting: stdout (human-readable),
//! NDJSON (machine-readable), and webhook (HTTP POST, feature-gated).

use super::state::{DiffSnapshot, WatchSummary};
use std::io::Write;
use std::path::Path;

/// Trait for receiving watch events.
pub(crate) trait AlertSink {
    /// Called when an SBOM file changed and a diff was computed.
    fn on_change(&mut self, path: &Path, snapshot: &DiffSnapshot) -> anyhow::Result<()>;

    /// Called when new vulnerabilities are discovered (during enrichment).
    fn on_new_vulns(&mut self, path: &Path, vuln_ids: &[String]) -> anyhow::Result<()>;

    /// Called when a monitored SBOM file is deleted.
    fn on_sbom_removed(&mut self, path: &Path) -> anyhow::Result<()>;

    /// Called periodically with a session summary.
    fn on_status(&mut self, summary: &WatchSummary) -> anyhow::Result<()>;
}

// ============================================================================
// Stdout sink — human-readable colored output to stderr
// ============================================================================

pub(crate) struct StdoutAlertSink {
    quiet: bool,
}

impl StdoutAlertSink {
    pub(crate) fn new(quiet: bool) -> Self {
        Self { quiet }
    }
}

impl AlertSink for StdoutAlertSink {
    fn on_change(&mut self, path: &Path, snapshot: &DiffSnapshot) -> anyhow::Result<()> {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        let ts = chrono::Local::now().format("%H:%M:%S");

        let mut parts = Vec::new();
        if snapshot.components_added > 0 {
            parts.push(format!("+{} added", snapshot.components_added));
        }
        if snapshot.components_removed > 0 {
            parts.push(format!("-{} removed", snapshot.components_removed));
        }
        if snapshot.components_modified > 0 {
            parts.push(format!("~{} modified", snapshot.components_modified));
        }
        if !snapshot.new_vulns.is_empty() {
            parts.push(format!(
                "+{} vulns ({})",
                snapshot.new_vulns.len(),
                snapshot.new_vulns.join(", ")
            ));
        }
        if !snapshot.resolved_vulns.is_empty() {
            parts.push(format!("-{} vulns resolved", snapshot.resolved_vulns.len()));
        }
        if !snapshot.new_eol.is_empty() {
            parts.push(format!("+{} EOL", snapshot.new_eol.len()));
        }

        let detail = if parts.is_empty() {
            "no significant changes".to_string()
        } else {
            parts.join(", ")
        };

        eprintln!("[{ts}] {name}: {detail}");
        Ok(())
    }

    fn on_new_vulns(&mut self, path: &Path, vuln_ids: &[String]) -> anyhow::Result<()> {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        let ts = chrono::Local::now().format("%H:%M:%S");
        eprintln!(
            "[{ts}] {name}: enrichment found {} new vuln(s): {}",
            vuln_ids.len(),
            vuln_ids.join(", ")
        );
        Ok(())
    }

    fn on_sbom_removed(&mut self, path: &Path) -> anyhow::Result<()> {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        let ts = chrono::Local::now().format("%H:%M:%S");
        eprintln!("[{ts}] {name}: file removed");
        Ok(())
    }

    fn on_status(&mut self, summary: &WatchSummary) -> anyhow::Result<()> {
        if self.quiet {
            return Ok(());
        }
        let ts = chrono::Local::now().format("%H:%M:%S");
        eprintln!(
            "[{ts}] Watching {} SBOMs | {} healthy | {} error | {} vulns | uptime {}s",
            summary.tracked_count,
            summary.healthy_count,
            summary.error_count,
            summary.total_vulns,
            summary.uptime_secs,
        );
        Ok(())
    }
}

// ============================================================================
// NDJSON sink — one JSON object per event
// ============================================================================

pub(crate) struct NdjsonAlertSink {
    writer: Box<dyn Write + Send>,
}

impl NdjsonAlertSink {
    pub(crate) fn new(writer: Box<dyn Write + Send>) -> Self {
        Self { writer }
    }

    fn write_event(&mut self, event: &serde_json::Value) -> anyhow::Result<()> {
        serde_json::to_writer(&mut self.writer, event)?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        Ok(())
    }
}

impl AlertSink for NdjsonAlertSink {
    fn on_change(&mut self, path: &Path, snapshot: &DiffSnapshot) -> anyhow::Result<()> {
        let event = serde_json::json!({
            "type": "change",
            "path": path.display().to_string(),
            "timestamp": snapshot.timestamp.to_rfc3339(),
            "added": snapshot.components_added,
            "removed": snapshot.components_removed,
            "modified": snapshot.components_modified,
            "new_vulns": snapshot.new_vulns,
            "resolved_vulns": snapshot.resolved_vulns,
            "new_eol": snapshot.new_eol,
        });
        self.write_event(&event)
    }

    fn on_new_vulns(&mut self, path: &Path, vuln_ids: &[String]) -> anyhow::Result<()> {
        let event = serde_json::json!({
            "type": "new_vulns",
            "path": path.display().to_string(),
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "vuln_ids": vuln_ids,
        });
        self.write_event(&event)
    }

    fn on_sbom_removed(&mut self, path: &Path) -> anyhow::Result<()> {
        let event = serde_json::json!({
            "type": "removed",
            "path": path.display().to_string(),
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        self.write_event(&event)
    }

    fn on_status(&mut self, summary: &WatchSummary) -> anyhow::Result<()> {
        let event = serde_json::json!({
            "type": "status",
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "tracked": summary.tracked_count,
            "healthy": summary.healthy_count,
            "errors": summary.error_count,
            "vulns": summary.total_vulns,
            "total_changes": summary.total_changes,
            "uptime_secs": summary.uptime_secs,
        });
        self.write_event(&event)
    }
}

// ============================================================================
// Webhook sink — HTTP POST (feature-gated)
// ============================================================================

#[cfg(feature = "enrichment")]
pub(crate) struct WebhookAlertSink {
    url: String,
    client: reqwest::blocking::Client,
}

#[cfg(feature = "enrichment")]
impl WebhookAlertSink {
    pub(crate) fn new(url: String) -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::blocking::Client::new());
        Self { url, client }
    }

    fn post_json(&self, payload: &serde_json::Value) -> anyhow::Result<()> {
        let resp = self.client.post(&self.url).json(payload).send();
        match resp {
            Ok(r) if r.status().is_success() => Ok(()),
            Ok(r) => {
                tracing::warn!("Webhook returned status {}", r.status());
                Ok(()) // non-fatal
            }
            Err(e) => {
                tracing::warn!("Webhook delivery failed: {e}");
                Ok(()) // non-fatal
            }
        }
    }
}

#[cfg(feature = "enrichment")]
impl AlertSink for WebhookAlertSink {
    fn on_change(&mut self, path: &Path, snapshot: &DiffSnapshot) -> anyhow::Result<()> {
        let payload = serde_json::json!({
            "type": "change",
            "path": path.display().to_string(),
            "timestamp": snapshot.timestamp.to_rfc3339(),
            "added": snapshot.components_added,
            "removed": snapshot.components_removed,
            "modified": snapshot.components_modified,
            "new_vulns": snapshot.new_vulns,
            "resolved_vulns": snapshot.resolved_vulns,
            "new_eol": snapshot.new_eol,
        });
        self.post_json(&payload)
    }

    fn on_new_vulns(&mut self, path: &Path, vuln_ids: &[String]) -> anyhow::Result<()> {
        let payload = serde_json::json!({
            "type": "new_vulns",
            "path": path.display().to_string(),
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "vuln_ids": vuln_ids,
        });
        self.post_json(&payload)
    }

    fn on_sbom_removed(&mut self, path: &Path) -> anyhow::Result<()> {
        let payload = serde_json::json!({
            "type": "removed",
            "path": path.display().to_string(),
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        self.post_json(&payload)
    }

    fn on_status(&mut self, _summary: &WatchSummary) -> anyhow::Result<()> {
        // Don't spam webhooks with status updates
        Ok(())
    }
}

// ============================================================================
// Sink builder
// ============================================================================

/// Build alert sinks from the watch configuration.
pub(crate) fn build_alert_sinks(
    config: &super::config::WatchConfig,
) -> anyhow::Result<Vec<Box<dyn AlertSink>>> {
    use crate::reports::ReportFormat;

    let mut sinks: Vec<Box<dyn AlertSink>> = Vec::new();

    match config.output.format {
        ReportFormat::Json => {
            let writer: Box<dyn Write + Send> = match &config.output.file {
                Some(path) => {
                    let file = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(path)?;
                    Box::new(file)
                }
                None => Box::new(std::io::stdout()),
            };
            sinks.push(Box::new(NdjsonAlertSink::new(writer)));
        }
        _ => {
            sinks.push(Box::new(StdoutAlertSink::new(config.quiet)));
        }
    }

    #[cfg(feature = "enrichment")]
    if let Some(ref url) = config.webhook_url {
        sinks.push(Box::new(WebhookAlertSink::new(url.clone())));
    }

    Ok(sinks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ndjson_sink_produces_valid_json() {
        let buffer = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let writer = {
            struct ArcWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
            impl Write for ArcWriter {
                fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                    self.0.lock().unwrap().write(buf)
                }
                fn flush(&mut self) -> std::io::Result<()> {
                    Ok(())
                }
            }
            ArcWriter(buffer.clone())
        };

        let mut sink = NdjsonAlertSink::new(Box::new(writer));

        let snapshot = DiffSnapshot {
            timestamp: chrono::Utc::now(),
            components_added: 3,
            components_removed: 1,
            components_modified: 2,
            new_vulns: vec!["CVE-2026-1234".to_string()],
            resolved_vulns: vec![],
            new_eol: vec![],
        };

        sink.on_change(Path::new("/tmp/test.cdx.json"), &snapshot)
            .unwrap();

        let output = buffer.lock().unwrap();
        let line = String::from_utf8_lossy(&output);
        let parsed: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(parsed["type"], "change");
        assert_eq!(parsed["added"], 3);
        assert_eq!(parsed["new_vulns"][0], "CVE-2026-1234");
    }

    #[test]
    fn test_stdout_sink_does_not_panic() {
        let mut sink = StdoutAlertSink::new(true);
        let snapshot = DiffSnapshot {
            timestamp: chrono::Utc::now(),
            components_added: 1,
            components_removed: 0,
            components_modified: 0,
            new_vulns: vec![],
            resolved_vulns: vec![],
            new_eol: vec![],
        };
        // Just verify it doesn't panic
        sink.on_change(Path::new("test.cdx.json"), &snapshot)
            .unwrap();
        sink.on_sbom_removed(Path::new("test.cdx.json")).unwrap();
        sink.on_status(&WatchSummary {
            tracked_count: 1,
            healthy_count: 1,
            error_count: 0,
            total_vulns: 0,
            total_changes: 1,
            uptime_secs: 60,
        })
        .unwrap();
    }
}
