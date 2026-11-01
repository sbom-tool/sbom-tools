//! `cra-standards-watch` command handler.
//!
//! Curated, offline-first list of CRA-related standards bodies and their
//! tracked artefacts (prEN 40000 series, BSI TR-03183, ETSI EN 303 6xx,
//! STAN4CRA hub). The command prints the catalogue with last-known
//! version dates so operators can spot-check freshness without firing
//! HTTP requests; an optional `--check-online` flag follows the URLs
//! and reports HTTP status codes (best-effort, may be rate-limited).
//!
//! Out of scope: scraping working-group draft contents (paywalled), and
//! parsing PDF version histories. The CLI is informational — it does not
//! mutate any project state.

use anyhow::Result;
use serde::Serialize;
use std::time::Duration;

/// One tracked artefact in the CRA standards landscape.
#[derive(Debug, Clone, Serialize)]
pub struct TrackedStandard {
    pub id: &'static str,
    pub title: &'static str,
    pub body: &'static str,
    pub status: &'static str,
    pub last_known_version: &'static str,
    pub last_known_date: &'static str,
    pub url: &'static str,
    pub watch_reason: &'static str,
}

/// Borrow the curated catalogue. Watch-loop integration probes these URLs
/// on a configurable interval and surfaces status drift through
/// [`crate::watch::alerts::AlertSink`].
pub fn cra_catalogue() -> &'static [TrackedStandard] {
    CATALOGUE
}

/// Probe each entry's URL with `timeout` and return the resulting
/// [`OnlineProbe`] list. Without the `enrichment` feature the probes are
/// returned with a static "feature disabled" status string.
pub fn probe_cra_standards(entries: &[TrackedStandard], timeout: Duration) -> Vec<OnlineProbe> {
    probe_urls(entries, timeout)
}

/// Curated catalogue. Update entries here when standards bodies publish a
/// new draft or final version. Dates are last-confirmed by hand; the
/// command does not mutate this list at runtime.
const CATALOGUE: &[TrackedStandard] = &[
    TrackedStandard {
        id: "prEN-40000-1-3",
        title: "prEN 40000-1-3 — SBOM and vulnerability-handling requirements",
        body: "CEN-CENELEC JTC 13",
        status: "Draft (not freely available)",
        last_known_version: "Draft",
        last_known_date: "2025-Q4",
        url: "https://www.cencenelec.eu/areas-of-work/cen-cenelec-topics/cybersecurity-and-data-protection/",
        watch_reason: "Normative requirement IDs (PRE-7-RQ-*, PRE-8-RQ-*, RLS-2-RQ-*) referenced by sbom-tools",
    },
    TrackedStandard {
        id: "prEN-40000-1-2",
        title: "prEN 40000-1-2 — Cybersecurity properties (Annex I Part I)",
        body: "CEN-CENELEC JTC 13",
        status: "Draft (not freely available)",
        last_known_version: "Draft",
        last_known_date: "2025-Q4",
        url: "https://www.cencenelec.eu/areas-of-work/cen-cenelec-topics/cybersecurity-and-data-protection/",
        watch_reason: "Drives Annex I Part I controls-assertion sidecar block (CRA-P5.5)",
    },
    TrackedStandard {
        id: "BSI-TR-03183-2",
        title: "BSI TR-03183-2 — Technical Guideline (national CRA-aligned SBOM)",
        body: "BSI (Germany)",
        status: "Public",
        last_known_version: "2.1.0",
        last_known_date: "2025-08",
        url: "https://bsi.bund.de/dok/TR-03183-en",
        watch_reason: "Free, ENISA-cited; sbom-tools `--standard bsi` runs the v2.1.0 §4/§5.2/§6.1 checks",
    },
    TrackedStandard {
        id: "CSAF-v2.0",
        title: "CSAF v2.0 — Common Security Advisory Framework (ISO/IEC 20153:2025)",
        body: "OASIS / ISO",
        status: "Final",
        last_known_version: "2.0",
        last_known_date: "2022-11",
        url: "https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html",
        watch_reason: "Advisory format named in CRA prEN 40000-1-3 [RLS-2-RQ-03-RE]",
    },
    TrackedStandard {
        id: "ENISA-SBOM-Guidance",
        title: "ENISA Technical Advisory for Software Bill of Materials",
        body: "ENISA",
        status: "Public (non-binding)",
        last_known_version: "v1.10",
        last_known_date: "2026-10-22",
        url: "https://www.enisa.europa.eu/publications/enisa-technical-advisory-for-software-bill-of-materials",
        watch_reason: "ENISA's guidance for CRA-aligned SBOM practice; cited on the CRA SBOM-content rules",
    },
    TrackedStandard {
        id: "EUCC",
        title: "EUCC scheme — Common Criteria (Implementing Reg. (EU) 2024/482)",
        body: "European Commission / ENISA",
        status: "Final",
        last_known_version: "Reg. 2024/482 as amended by 2024/3144 and 2025/2462",
        last_known_date: "2025-12-29",
        url: "https://eur-lex.europa.eu/eli/reg_impl/2024/482/oj/eng",
        watch_reason: "Mandatory for CRA Annex IV (Critical) products",
    },
    TrackedStandard {
        id: "STAN4CRA",
        title: "STAN4CRA — CEN-CENELEC standardisation hub for CRA",
        body: "CEN-CENELEC",
        status: "Hub",
        last_known_version: "Live",
        last_known_date: "n/a",
        url: "https://www.stan4cra.eu/",
        watch_reason: "Aggregates harmonised standards under the CRA mandate",
    },
    TrackedStandard {
        id: "ETSI-EN-303-6xx",
        title: "ETSI EN 303 6xx — vertical product-class cybersecurity",
        body: "ETSI TC CYBER",
        status: "Mixed",
        last_known_version: "Various",
        last_known_date: "ongoing",
        url: "https://docbox.etsi.org/CYBER/EUSR/Open/",
        watch_reason: "Product-class verticals (browsers, AV, OS, password managers) under CRA",
    },
];

/// Output format for `cra-standards-watch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchOutputFormat {
    Table,
    Json,
}

impl WatchOutputFormat {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s.to_lowercase().as_str() {
            "table" | "auto" => Ok(Self::Table),
            "json" => Ok(Self::Json),
            other => anyhow::bail!("Unsupported format '{other}'. Valid: table, json"),
        }
    }
}

/// Run the `cra-standards-watch` command.
pub fn run_cra_standards_watch(
    format: WatchOutputFormat,
    check_online: bool,
    timeout_secs: u64,
) -> Result<()> {
    let entries = CATALOGUE.to_vec();
    let online_status = if check_online {
        Some(probe_urls(&entries, Duration::from_secs(timeout_secs)))
    } else {
        None
    };

    match format {
        WatchOutputFormat::Json => {
            let payload = serde_json::json!({
                "tool": "sbom-tools",
                "version": env!("CARGO_PKG_VERSION"),
                "catalogue": entries,
                "online_status": online_status,
            });
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
        WatchOutputFormat::Table => {
            println!("CRA standards watch — last-known versions");
            println!("{}", "=".repeat(60));
            for s in &entries {
                println!("\n[{}] {}", s.id, s.title);
                println!("  Body:        {}", s.body);
                println!("  Status:      {}", s.status);
                println!(
                    "  Version:     {} ({})",
                    s.last_known_version, s.last_known_date
                );
                println!("  URL:         {}", s.url);
                println!("  Watch:       {}", s.watch_reason);
                if let Some(ref probes) = online_status
                    && let Some(probe) = probes.iter().find(|p| p.id == s.id)
                {
                    println!("  HTTP status: {}", probe.status);
                }
            }
            println!();
            println!(
                "Catalogue is curated and shipped with sbom-tools v{}; \
                 update via PR when standards bodies publish new versions.",
                env!("CARGO_PKG_VERSION")
            );
        }
    }
    Ok(())
}

/// Result of a single URL probe against the CRA standards catalogue.
/// `status` is a verbatim HTTP status string (e.g. "200 OK") or an
/// error description prefixed with `error:`.
#[derive(Debug, Clone, Serialize)]
pub struct OnlineProbe {
    pub id: &'static str,
    pub status: String,
}

/// Fire HEAD requests at each catalogue URL with the supplied timeout.
/// Best-effort — many of these endpoints don't accept HEAD; we report
/// the resulting status string verbatim. No retries, no caching.
fn probe_urls(entries: &[TrackedStandard], timeout: Duration) -> Vec<OnlineProbe> {
    #[cfg(feature = "enrichment")]
    {
        let client = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .user_agent(concat!("sbom-tools/", env!("CARGO_PKG_VERSION")))
            .build();
        let Ok(client) = client else {
            return entries
                .iter()
                .map(|s| OnlineProbe {
                    id: s.id,
                    status: "client-init-failed".to_string(),
                })
                .collect();
        };
        entries
            .iter()
            .map(|s| {
                let status = match client.head(s.url).send() {
                    Ok(resp) => format!("{}", resp.status()),
                    Err(e) => format!("error: {e}"),
                };
                OnlineProbe { id: s.id, status }
            })
            .collect()
    }
    #[cfg(not(feature = "enrichment"))]
    {
        let _ = timeout;
        entries
            .iter()
            .map(|s| OnlineProbe {
                id: s.id,
                status: "online-checks require the 'enrichment' feature".to_string(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogue_has_no_empty_fields() {
        for s in CATALOGUE {
            assert!(!s.id.is_empty(), "catalogue id must not be empty");
            assert!(!s.title.is_empty(), "catalogue title must not be empty");
            assert!(
                s.url.starts_with("https://"),
                "catalogue URL must be https: {}",
                s.url
            );
        }
    }

    #[test]
    fn catalogue_ids_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for s in CATALOGUE {
            assert!(seen.insert(s.id), "duplicate catalogue id: {}", s.id);
        }
    }

    #[test]
    fn catalogue_covers_core_artefacts() {
        let ids: std::collections::HashSet<&str> = CATALOGUE.iter().map(|s| s.id).collect();
        for required in [
            "prEN-40000-1-3",
            "BSI-TR-03183-2",
            "CSAF-v2.0",
            "EUCC",
            "STAN4CRA",
        ] {
            assert!(ids.contains(required), "catalogue must include {required}");
        }
    }

    #[test]
    fn output_format_parser_is_strict() {
        assert!(matches!(
            WatchOutputFormat::parse("table").unwrap(),
            WatchOutputFormat::Table
        ));
        assert!(matches!(
            WatchOutputFormat::parse("json").unwrap(),
            WatchOutputFormat::Json
        ));
        assert!(WatchOutputFormat::parse("xml").is_err());
    }
}
