//! sbom-tools: Semantic SBOM diff and analysis tool
//!
//! A format-agnostic SBOM comparison tool for `CycloneDX` and SPDX formats.

#![allow(
    clippy::too_many_lines,
    clippy::struct_excessive_bools,
    clippy::needless_pass_by_value
)]

use anyhow::{Context, Result};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{Shell, generate};
use sbom_tools::{
    cli,
    config::{
        BehaviorConfig, DiffConfig, DiffPaths, EcosystemRulesConfig, EnrichmentConfig,
        FilterConfig, FuzzyPreset, GraphAwareDiffConfig, MatchingConfig, MatchingRulesPathConfig,
        MatrixConfig, MultiDiffConfig, OutputConfig, QueryConfig, TimelineConfig, ViewConfig,
        WatchConfig,
    },
    pipeline::dirs,
    reports::{ReportFormat, ReportType},
    watch::parse_duration,
};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Build long version string with format support info
const fn build_long_version() -> &'static str {
    concat!(
        env!("CARGO_PKG_VERSION"),
        "\n\nSupported SBOM Formats:",
        "\n  CycloneDX: 1.4, 1.5, 1.6, 1.7 (JSON, XML)",
        "\n  SPDX:      2.2, 2.3 (JSON, tag-value, RDF/XML), 3.0 (JSON-LD)",
        "\n\nOutput Formats:",
        "\n  tui, json, ndjson, sarif, markdown, html, summary, table, side-by-side",
        "\n\nFeatures:",
        "\n  Semantic diff, fuzzy matching, vulnerability tracking, license analysis"
    )
}

#[derive(Parser)]
#[command(name = "sbom-tools")]
#[command(author = "Binarly.io")]
#[command(version, long_version = build_long_version())]
#[command(about = "Semantic SBOM diff and analysis tool", long_about = None)]
#[command(after_help = "EXIT CODES:
    0  No changes detected (or --no-fail-on-change)
    1  Changes detected / no query matches
    2  Vulnerabilities introduced
    3  Error occurred
    4  VEX gaps found (--fail-on-vex-gap)
    5  License policy violations found

EXAMPLES:
  Comparing SBOMs:
    sbom-tools diff old.cdx.json new.cdx.json                     # Interactive TUI
    sbom-tools diff old.cdx.json new.cdx.json -o summary           # Terminal summary
    sbom-tools diff old.cdx.json new.cdx.json -o json > diff.json  # JSON export
    sbom-tools diff old.cdx.json new.cdx.json -o sarif             # CI/CD SARIF

  Enrichment (add vulnerability + EOL data before diffing):
    sbom-tools diff old.json new.json --enrich-vulns --enrich-eol
    sbom-tools view app.cdx.json --enrich-vulns --fail-on-vuln

  CI/CD pipeline gates:
    sbom-tools diff old.json new.json --fail-on-vuln --fail-on-change
    sbom-tools diff old.json new.json --fail-on-vex-gap --vex vex.json
    sbom-tools quality app.cdx.json --min-score 70

  Fleet / multi-SBOM analysis (interactive TUI or -o json):
    sbom-tools diff-multi baseline.json device-*.json -o json
    sbom-tools timeline v1.json v2.json v3.json --enrich-vulns
    sbom-tools matrix *.cdx.json --cluster-threshold 0.9

  Search and query:
    sbom-tools query \"log4j\" --version \"<2.17.0\" fleet/*.json
    sbom-tools query --affected-by CVE-2021-44228 *.json

  Quality and compliance:
    sbom-tools quality app.cdx.json --profile security --metrics
    sbom-tools validate app.cdx.json --standard ntia,cra,eo14028
    sbom-tools license-check app.cdx.json --strict

  VEX operations:
    sbom-tools vex status --sbom app.json --vex vex.json
    sbom-tools vex apply --sbom app.json --vex vex.json -O enriched.json

  SBOM operations (enrich, filter, merge):
    sbom-tools enrich app.cdx.json --enrich-vulns --enrich-eol -O enriched.json
    sbom-tools tailor app.cdx.json --exclude-ecosystems npm,pypi
    sbom-tools merge primary.json secondary.json -O combined.json

  Monitoring:
    sbom-tools watch --dir ./sboms --enrich-vulns --exit-on-change
    sbom-tools verify hash app.cdx.json --algorithm sha256

For more details on any command: sbom-tools <command> --help")]
struct Cli {
    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Suppress non-essential output
    #[arg(short, long, global = true)]
    quiet: bool,

    /// Disable colored output (also respects `NO_COLOR` env)
    #[arg(long, global = true)]
    no_color: bool,

    /// Export filename template for TUI exports
    ///
    /// Placeholders: {date}, {time}, {format}, {command}
    #[arg(long, global = true)]
    export_template: Option<String>,

    /// Path to configuration file
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

// ============================================================================
// Command argument structs (extracted for readability)
// ============================================================================

/// Shared enrichment arguments for commands that support vulnerability/EOL data enrichment.
#[derive(Args, Debug)]
struct SharedEnrichmentArgs {
    /// Enable OSV vulnerability enrichment
    #[arg(long)]
    enrich_vulns: bool,

    /// Enable end-of-life detection via endoflife.date
    #[arg(long)]
    enrich_eol: bool,

    /// Apply external VEX document(s) (OpenVEX format). Can be specified multiple times
    #[arg(long = "vex", value_name = "PATH")]
    vex: Vec<PathBuf>,

    /// Cache directory for enrichment data
    #[arg(long, alias = "cache-dir")]
    vuln_cache_dir: Option<PathBuf>,

    /// Cache TTL in hours
    #[arg(long, alias = "cache-ttl", default_value = "24")]
    vuln_cache_ttl: u64,

    /// Bypass cache and fetch fresh data
    #[arg(long, alias = "refresh")]
    refresh_vulns: bool,

    /// API timeout in seconds
    #[arg(long, default_value = "30")]
    api_timeout: u64,

    /// Custom matching rules YAML file
    #[arg(long)]
    matching_rules: Option<PathBuf>,
}

impl SharedEnrichmentArgs {
    fn to_enrichment_config(&self) -> EnrichmentConfig {
        EnrichmentConfig {
            enabled: self.enrich_vulns,
            cache_dir: self
                .vuln_cache_dir
                .clone()
                .or_else(|| Some(dirs::osv_cache_dir())),
            cache_ttl_hours: self.vuln_cache_ttl,
            bypass_cache: self.refresh_vulns,
            timeout_secs: self.api_timeout,
            enable_eol: self.enrich_eol,
            vex_paths: self.vex.clone(),
            ..Default::default()
        }
    }
}

/// Arguments for the `diff` subcommand
#[derive(Parser)]
#[command(after_help = "EXIT CODES:
    0  No changes detected (or --no-fail-on-change)
    1  Changes detected (--fail-on-change)
    2  Vulnerabilities introduced (--fail-on-vuln)
    3  Error occurred
    4  VEX gaps found (--fail-on-vex-gap)

EXAMPLES:
    sbom-tools diff old.cdx.json new.cdx.json                    # Interactive TUI
    sbom-tools diff old.json new.json -o summary --fail-on-vuln   # CI gate
    sbom-tools diff old.json new.json --enrich-vulns -o sarif     # Enriched SARIF
    sbom-tools diff old.json new.json --graph-diff --graph-max-depth 3
    sbom-tools diff old.json new.json --vex vex.json --fail-on-vex-gap")]
struct DiffArgs {
    /// Path to the old/baseline SBOM
    old: PathBuf,

    /// Path to the new SBOM
    new: PathBuf,

    /// Output format (auto detects TTY: tui if interactive, summary otherwise)
    #[arg(short, long, default_value = "auto")]
    output: ReportFormat,

    /// Output file path (stdout if not specified)
    #[arg(short = 'O', long)]
    output_file: Option<PathBuf>,

    /// Report types to include
    #[arg(long, default_value = "all")]
    reports: ReportType,

    /// Fuzzy matching preset
    #[arg(long, value_enum, default_value_t = FuzzyPreset::Balanced)]
    fuzzy_preset: FuzzyPreset,

    /// Include unchanged components in output
    #[arg(long)]
    include_unchanged: bool,

    /// Exit with code 2 if new vulnerabilities are introduced
    #[arg(long)]
    fail_on_vuln: bool,

    /// Exit with code 1 if any changes detected (default for non-zero changes)
    #[arg(long)]
    fail_on_change: bool,

    /// Only show items with changes (hide unchanged)
    #[arg(long)]
    only_changes: bool,

    /// Filter by minimum severity (critical, high, medium, low)
    #[arg(long)]
    severity: Option<String>,

    #[command(flatten)]
    enrichment: SharedEnrichmentArgs,

    /// Enable graph-aware diffing (detect reparenting, depth changes)
    #[arg(long)]
    graph_diff: bool,

    /// Maximum depth for graph analysis (0 = unlimited, requires --graph-diff)
    #[arg(long, default_value = "0")]
    graph_max_depth: u32,

    /// Minimum impact level to include in graph diff output (low, medium, high, critical)
    #[arg(long, default_value = "low")]
    graph_impact_threshold: String,

    /// Comma-separated list of relationship types to include in graph diff
    /// (e.g., "DependsOn,DevDependsOn"). Empty = all types.
    #[arg(long)]
    graph_relations: Option<String>,

    /// Dry-run matching rules (show what would match without applying)
    #[arg(long)]
    dry_run_rules: bool,

    /// Path to ecosystem rules configuration file (YAML/JSON)
    #[arg(long, env = "SBOM_TOOLS_ECOSYSTEM_RULES")]
    ecosystem_rules: Option<PathBuf>,

    /// Disable ecosystem-specific name normalization
    #[arg(long)]
    no_ecosystem_rules: bool,

    /// Exclude vulnerabilities with VEX status `not_affected` or fixed
    #[arg(long, alias = "exclude-vex-not-affected")]
    exclude_vex_resolved: bool,

    /// Exit with error if introduced vulnerabilities lack VEX statements (CI gate)
    #[arg(long)]
    fail_on_vex_gap: bool,

    /// Enable typosquat detection warnings
    #[arg(long)]
    detect_typosquats: bool,

    /// Show detailed match explanations for each matched component
    #[arg(long)]
    explain_matches: bool,

    /// Recommend optimal matching threshold based on the SBOMs
    #[arg(long)]
    recommend_threshold: bool,

    /// Force streaming mode for large SBOM handling (reduces memory usage)
    #[arg(long)]
    streaming: bool,

    /// Streaming threshold in MB. Files larger than this use streaming mode.
    #[arg(long, default_value = "10")]
    streaming_threshold: u64,
}

/// Arguments for the `view` subcommand
#[derive(Parser)]
#[command(after_help = "EXAMPLES:
    sbom-tools view app.cdx.json                                  # Interactive TUI
    sbom-tools view app.cdx.json --enrich-vulns --fail-on-vuln    # CI vuln check
    sbom-tools view app.cdx.json -o json > components.json        # Export
    sbom-tools view app.cdx.json --vulnerable-only --severity high")]
struct ViewArgs {
    /// Path to the SBOM file
    sbom: PathBuf,

    /// Output format (auto detects TTY: tui if interactive, summary otherwise)
    #[arg(short, long, default_value = "auto")]
    output: ReportFormat,

    /// Output file path (stdout if not specified)
    #[arg(short = 'O', long)]
    output_file: Option<PathBuf>,

    /// Validate against NTIA minimum elements
    #[arg(long)]
    validate_ntia: bool,

    /// Filter by minimum vulnerability severity (critical, high, medium, low)
    #[arg(long)]
    severity: Option<String>,

    /// Only show components with vulnerabilities
    #[arg(long)]
    vulnerable_only: bool,

    /// Filter by ecosystem (e.g., npm, cargo, pypi, maven)
    #[arg(long)]
    ecosystem: Option<String>,

    /// Exit with code 2 if any vulnerabilities are present in the SBOM
    #[arg(long)]
    fail_on_vuln: bool,

    /// BOM type override (sbom, cbom). Auto-detected from content if omitted
    #[arg(long, value_name = "TYPE")]
    bom_type: Option<String>,

    /// Path to a CRA sidecar metadata file (JSON or YAML).
    /// If omitted, auto-discovers `<sbom>.cra.json|yaml` next to the SBOM.
    #[arg(long, value_name = "PATH")]
    cra_sidecar: Option<PathBuf>,

    /// CRA Annex III/IV product class (drives severity calibration).
    /// One of: default, important-class-1, important-class-2, critical.
    /// Sidecar `productClass` wins over this flag.
    #[arg(long, value_name = "CLASS")]
    cra_product_class: Option<String>,

    #[command(flatten)]
    enrichment: SharedEnrichmentArgs,
}

/// Arguments for the `validate` subcommand
#[derive(Parser)]
#[command(after_help = "EXIT CODES:
    0  Compliant (no errors; no warnings with --fail-on-warning)
    1  Compliance errors found (non-compliant)
    2  Compliance warnings found (only with --fail-on-warning)
    3  Error occurred

EXAMPLES:
    sbom-tools validate app.cdx.json                              # NTIA minimum
    sbom-tools validate app.cdx.json --standard cra,eo14028       # Multi-standard
    sbom-tools validate app.cdx.json --standard ntia -o sarif     # SARIF for CI
    sbom-tools validate app.cdx.json --fail-on-warning            # Strict CI gate")]
struct ValidateArgs {
    /// Path to the SBOM file
    sbom: PathBuf,

    /// Compliance standard(s) to validate against (comma-separated: ntia, fda, cra, ssdf, eo14028)
    #[arg(long, default_value = "ntia")]
    standard: String,

    /// Output format (auto detects TTY: tui if interactive, summary otherwise)
    #[arg(short, long, default_value = "auto")]
    output: ReportFormat,

    /// Output file path (stdout if not specified)
    #[arg(short = 'O', long)]
    output_file: Option<PathBuf>,

    /// Exit with non-zero code when warnings are found (not just errors)
    #[arg(long)]
    fail_on_warning: bool,

    /// Output only a compact JSON summary (overrides --output)
    #[arg(long)]
    summary: bool,

    /// Path to a CRA sidecar metadata file (JSON or YAML) supplying
    /// security_contact, manufacturer, support_end_date, ce_marking_reference,
    /// and similar CRA fields the SBOM itself doesn't carry.
    /// If omitted, sbom-tools auto-discovers `<sbom>.cra.json|yaml` next to the SBOM.
    #[arg(long, value_name = "PATH")]
    cra_sidecar: Option<PathBuf>,

    /// CRA Annex III/IV product class (drives severity calibration).
    /// One of: default, important-class-1, important-class-2, critical.
    /// Sidecar `productClass` wins over this flag.
    #[arg(long, value_name = "CLASS")]
    cra_product_class: Option<String>,
}

/// Arguments for the `diff-multi` subcommand
#[derive(Parser)]
#[command(after_help = "EXAMPLES:
    sbom-tools diff-multi baseline.json target1.json target2.json
    sbom-tools diff-multi baseline.json devices/*.json -o json
    sbom-tools diff-multi base.json t1.json t2.json --enrich-vulns --fail-on-vuln")]
struct DiffMultiArgs {
    /// Path to the baseline SBOM
    baseline: PathBuf,

    /// Paths to target SBOMs to compare against baseline
    #[arg(required = true)]
    targets: Vec<PathBuf>,

    /// Output format: tui (interactive, default on a TTY) or json (default when piped)
    #[arg(short, long, default_value = "auto")]
    output: ReportFormat,

    /// Output file path (stdout if not specified)
    #[arg(short = 'O', long)]
    output_file: Option<PathBuf>,

    /// Fuzzy matching preset
    #[arg(long, value_enum, default_value_t = FuzzyPreset::Balanced)]
    fuzzy_preset: FuzzyPreset,

    /// Include unchanged components in output
    #[arg(long)]
    include_unchanged: bool,

    /// Enable graph-aware diffing for multi-comparisons
    #[arg(long)]
    graph_diff: bool,

    /// Maximum depth for graph analysis (0 = unlimited, requires --graph-diff)
    #[arg(long, default_value = "0")]
    graph_max_depth: u32,

    /// Minimum impact level for graph diff output (low, medium, high, critical)
    #[arg(long, default_value = "low")]
    graph_impact_threshold: String,

    /// Relationship types to include in graph diff (comma-separated, e.g., "DependsOn,DevDependsOn")
    #[arg(long)]
    graph_relations: Option<String>,

    /// Filter by minimum severity (critical, high, medium, low)
    #[arg(long)]
    severity: Option<String>,

    /// Exit with code 2 if new vulnerabilities are introduced
    #[arg(long)]
    fail_on_vuln: bool,

    /// Exit with code 1 if any changes detected
    #[arg(long)]
    fail_on_change: bool,

    /// Exclude vulnerabilities with VEX status `not_affected` or fixed
    #[arg(long)]
    exclude_vex_resolved: bool,

    /// Exit with error if introduced vulnerabilities lack VEX statements
    #[arg(long)]
    fail_on_vex_gap: bool,

    #[command(flatten)]
    enrichment: SharedEnrichmentArgs,
}

/// Arguments for the `timeline` subcommand
#[derive(Parser)]
#[command(after_help = "EXAMPLES:
    sbom-tools timeline v1.0.json v1.1.json v1.2.json             # Version evolution
    sbom-tools timeline releases/*.json --enrich-vulns -o json     # Vuln trend report
    sbom-tools timeline *.json --fail-on-vuln --fail-on-change     # CI gate")]
struct TimelineArgs {
    /// Paths to SBOMs in chronological order (oldest first)
    #[arg(required = true)]
    sboms: Vec<PathBuf>,

    /// Output format: tui (interactive, default on a TTY) or json (default when piped)
    #[arg(short, long, default_value = "auto")]
    output: ReportFormat,

    /// Output file path (stdout if not specified)
    #[arg(short = 'O', long)]
    output_file: Option<PathBuf>,

    /// Fuzzy matching preset
    #[arg(long, value_enum, default_value_t = FuzzyPreset::Balanced)]
    fuzzy_preset: FuzzyPreset,

    /// Enable graph-aware diffing for timeline analysis
    #[arg(long)]
    graph_diff: bool,

    /// Maximum depth for graph analysis (0 = unlimited, requires --graph-diff)
    #[arg(long, default_value = "0")]
    graph_max_depth: u32,

    /// Minimum impact level for graph diff output (low, medium, high, critical)
    #[arg(long, default_value = "low")]
    graph_impact_threshold: String,

    /// Relationship types to include in graph diff (comma-separated, e.g., "DependsOn,DevDependsOn")
    #[arg(long)]
    graph_relations: Option<String>,

    /// Filter by minimum severity (critical, high, medium, low)
    #[arg(long)]
    severity: Option<String>,

    /// Exit with code 2 if new vulnerabilities are introduced
    #[arg(long)]
    fail_on_vuln: bool,

    /// Exit with code 1 if any changes detected
    #[arg(long)]
    fail_on_change: bool,

    /// Exclude vulnerabilities with VEX status `not_affected` or fixed
    #[arg(long)]
    exclude_vex_resolved: bool,

    /// Exit with error if introduced vulnerabilities lack VEX statements
    #[arg(long)]
    fail_on_vex_gap: bool,

    #[command(flatten)]
    enrichment: SharedEnrichmentArgs,
}

/// Arguments for the `matrix` subcommand
#[derive(Parser)]
#[command(after_help = "EXAMPLES:
    sbom-tools matrix v1.json v2.json v3.json                     # NxN comparison
    sbom-tools matrix *.cdx.json --cluster-threshold 0.9 -o json  # Clustering
    sbom-tools matrix *.json --enrich-vulns --fail-on-vuln         # CI with enrichment")]
struct MatrixArgs {
    /// Paths to SBOMs to compare
    #[arg(required = true)]
    sboms: Vec<PathBuf>,

    /// Output format: tui (interactive, default on a TTY) or json (default when piped)
    #[arg(short, long, default_value = "auto")]
    output: ReportFormat,

    /// Output file path (stdout if not specified)
    #[arg(short = 'O', long)]
    output_file: Option<PathBuf>,

    /// Fuzzy matching preset
    #[arg(long, value_enum, default_value_t = FuzzyPreset::Balanced)]
    fuzzy_preset: FuzzyPreset,

    /// Similarity threshold for clustering (0.0-1.0)
    #[arg(long, default_value = "0.8")]
    cluster_threshold: f64,

    /// Enable graph-aware diffing for matrix comparison
    #[arg(long)]
    graph_diff: bool,

    /// Maximum depth for graph analysis (0 = unlimited, requires --graph-diff)
    #[arg(long, default_value = "0")]
    graph_max_depth: u32,

    /// Minimum impact level for graph diff output (low, medium, high, critical)
    #[arg(long, default_value = "low")]
    graph_impact_threshold: String,

    /// Relationship types to include in graph diff (comma-separated, e.g., "DependsOn,DevDependsOn")
    #[arg(long)]
    graph_relations: Option<String>,

    /// Filter by minimum severity (critical, high, medium, low)
    #[arg(long)]
    severity: Option<String>,

    /// Exit with code 2 if new vulnerabilities are introduced
    #[arg(long)]
    fail_on_vuln: bool,

    /// Exit with code 1 if any changes detected
    #[arg(long)]
    fail_on_change: bool,

    /// Exclude vulnerabilities with VEX status `not_affected` or fixed
    #[arg(long)]
    exclude_vex_resolved: bool,

    /// Exit with error if introduced vulnerabilities lack VEX statements
    #[arg(long)]
    fail_on_vex_gap: bool,

    #[command(flatten)]
    enrichment: SharedEnrichmentArgs,
}

/// Arguments for the `quality` subcommand
#[derive(Parser)]
#[command(after_help = "EXIT CODES:
    0  Score meets the --min-score threshold (or no threshold set)
    1  Overall score below --min-score
    3  Error occurred

EXAMPLES:
    sbom-tools quality app.cdx.json                                # Score overview
    sbom-tools quality app.cdx.json --profile security --metrics   # Detailed metrics
    sbom-tools quality app.cdx.json --min-score 70 -o json         # CI gate with export
    sbom-tools quality app.cdx.json --recommendations              # Improvement suggestions")]
struct QualityArgs {
    /// Path to the SBOM file
    sbom: PathBuf,

    /// Scoring profile (minimal, standard, security, license-compliance, comprehensive)
    #[arg(long, default_value = "standard")]
    profile: String,

    /// Output format (auto detects TTY: tui if interactive, summary otherwise)
    #[arg(short, long, default_value = "auto")]
    output: ReportFormat,

    /// Output file path (stdout if not specified)
    #[arg(short = 'O', long)]
    output_file: Option<PathBuf>,

    /// Show detailed recommendations
    #[arg(long)]
    recommendations: bool,

    /// Show detailed metrics
    #[arg(long)]
    metrics: bool,

    /// Fail if quality score is below threshold (0-100)
    #[arg(long)]
    min_score: Option<f32>,

    /// Path to a CRA sidecar metadata file (JSON or YAML).
    /// Consulted by the embedded CRA compliance check when running
    /// `--profile cra`. Auto-discovered next to the SBOM if omitted.
    #[arg(long, value_name = "PATH")]
    cra_sidecar: Option<PathBuf>,

    /// CRA Annex III/IV product class (drives severity calibration).
    /// One of: default, important-class-1, important-class-2, critical.
    /// Sidecar `productClass` wins over this flag.
    #[arg(long, value_name = "CLASS")]
    cra_product_class: Option<String>,
}

/// Arguments for the `query` subcommand
#[derive(Parser)]
#[command(after_help = "EXIT CODES:
    0  At least one component matched the filter
    1  No components matched the filter
    3  Error occurred

EXAMPLES:
    sbom-tools query log4j fleet/*.json                            # Search by name
    sbom-tools query --affected-by CVE-2021-44228 *.json           # Search by CVE
    sbom-tools query --ecosystem npm --license GPL fleet/*.json     # Multi-filter
    sbom-tools query --version \"<2.0.0\" --enrich-vulns *.json      # With enrichment")]
struct QueryArgs {
    /// Positional arguments: [PATTERN] SBOM_FILES...
    /// First argument is treated as search pattern if it doesn't look like a file path.
    /// All remaining arguments are SBOM file paths.
    #[arg(required = true)]
    args: Vec<String>,

    /// Filter by component name (substring)
    #[arg(long)]
    name: Option<String>,

    /// Filter by PURL (substring)
    #[arg(long)]
    purl: Option<String>,

    /// Filter by version (exact or semver range, e.g., "<2.17.0")
    #[arg(long)]
    version: Option<String>,

    /// Filter by license (substring)
    #[arg(long)]
    license: Option<String>,

    /// Filter by ecosystem (e.g., npm, maven, cargo)
    #[arg(long)]
    ecosystem: Option<String>,

    /// Filter by supplier name (substring)
    #[arg(long)]
    supplier: Option<String>,

    /// Filter by vulnerability ID (e.g., CVE-2021-44228)
    #[arg(long)]
    affected_by: Option<String>,

    /// Filter by crypto asset type (algorithm, certificate, key, protocol)
    #[arg(long)]
    crypto_type: Option<String>,

    /// Filter by algorithm family (substring, e.g., "AES", "RSA", "ML-KEM")
    #[arg(long)]
    algorithm_family: Option<String>,

    /// Show only quantum-safe cryptographic assets
    #[arg(long, conflicts_with = "quantum_vulnerable")]
    quantum_safe: bool,

    /// Show only quantum-vulnerable cryptographic assets
    #[arg(long, conflicts_with = "quantum_safe")]
    quantum_vulnerable: bool,

    /// Output format (table, json, csv)
    #[arg(short, long, default_value = "auto")]
    output: ReportFormat,

    /// Output file path (stdout if not specified)
    #[arg(short = 'O', long)]
    output_file: Option<PathBuf>,

    #[command(flatten)]
    enrichment: SharedEnrichmentArgs,

    /// Maximum number of results to return
    #[arg(long)]
    limit: Option<usize>,

    /// Group results by SBOM source
    #[arg(long)]
    group_by_sbom: bool,
}

/// Arguments for the `watch` subcommand
#[derive(Parser)]
#[command(after_help = "EXAMPLES:
    sbom-tools watch --dir ./sboms                                 # Monitor directory
    sbom-tools watch --dir ./sboms --enrich-vulns --exit-on-change # CI mode
    sbom-tools watch --dir ./sboms -i 30s --enrich-vulns -o json   # Streaming JSON")]
struct WatchArgs {
    /// Directories to watch for SBOM file changes
    #[arg(long = "dir", short = 'd', required = true)]
    dirs: Vec<PathBuf>,

    /// Polling interval for file changes (e.g., 30s, 5m, 1h)
    #[arg(long, short = 'i', default_value = "5m")]
    interval: String,

    /// Enrichment refresh interval (e.g., 1h, 6h, 1d)
    #[arg(long, default_value = "6h")]
    enrich_interval: String,

    /// Output format (summary for human, json for NDJSON streaming)
    #[arg(short, long, default_value = "auto")]
    output: ReportFormat,

    /// Output file path (stdout if not specified)
    #[arg(short = 'O', long)]
    output_file: Option<PathBuf>,

    /// Optional webhook URL for alerts (requires enrichment feature)
    #[arg(long)]
    webhook: Option<String>,

    #[command(flatten)]
    enrichment: SharedEnrichmentArgs,

    /// Debounce duration — wait after detecting a change before processing,
    /// to coalesce rapid writes (e.g., 2s, 500ms). Use 0s to disable.
    #[arg(long, default_value = "2s")]
    debounce: String,

    /// Exit after the first change is detected (CI mode)
    #[arg(long)]
    exit_on_change: bool,

    /// Maximum number of diff snapshots to retain per SBOM
    #[arg(long, default_value = "10")]
    max_snapshots: usize,

    /// Scan once and print discovered SBOMs, then exit (useful for testing watch configuration)
    #[arg(long)]
    dry_run: bool,

    /// Periodically probe the curated CRA-standards catalogue and surface
    /// drift through the configured watch sinks (stdout / NDJSON / webhook).
    /// Requires the `enrichment` feature for live HTTP probes.
    #[arg(long)]
    cra_standards: bool,

    /// Interval between CRA-standards probe cycles (e.g., 6h, 24h, 7d)
    #[arg(long, default_value = "24h")]
    cra_standards_interval: String,

    /// Per-request timeout for CRA-standards HTTP probes (e.g., 5s, 10s)
    #[arg(long, default_value = "10s")]
    cra_standards_timeout: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Compare two SBOMs
    Diff(DiffArgs),

    /// View a single SBOM
    View(ViewArgs),

    /// Validate an SBOM against a compliance standard
    Validate(ValidateArgs),

    /// Compare a baseline SBOM against multiple targets (1:N comparison)
    DiffMulti(DiffMultiArgs),

    /// Analyze SBOM evolution over time (timeline comparison)
    Timeline(TimelineArgs),

    /// Compare all SBOMs against each other (`NxN` matrix comparison)
    Matrix(MatrixArgs),

    /// Assess SBOM quality and completeness
    Quality(QualityArgs),

    /// Search for components across multiple SBOMs
    Query(QueryArgs),

    /// Standalone VEX (Vulnerability Exploitability eXchange) operations
    Vex {
        #[command(subcommand)]
        action: VexAction,
    },

    /// Continuously monitor SBOMs for file changes and new vulnerabilities
    Watch(WatchArgs),

    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: Shell,
    },

    /// Generate JSON Schema for the config file format
    ConfigSchema {
        /// Write schema to file instead of stdout
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Show, discover, or initialize configuration
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Verify SBOM integrity
    Verify {
        #[command(subcommand)]
        action: VerifyAction,
    },

    /// Check license policy compliance
    LicenseCheck(LicenseCheckArgs),

    /// Enrich an SBOM with vulnerability and EOL data
    #[cfg(feature = "enrichment")]
    Enrich(EnrichArgs),

    /// Tailor (filter) an SBOM by removing unwanted components
    Tailor(TailorArgs),

    /// Merge two SBOMs into one
    Merge(MergeArgs),

    /// Generate CRA technical-documentation dossier (Annex V templates)
    CraDocs(CraDocsArgs),

    /// Show curated CRA standards-watch catalogue (prEN, BSI, CSAF, EUCC, …)
    CraStandardsWatch(CraStandardsWatchArgs),

    /// Generate a man page and print it to stdout
    Man,
}

/// Sub-subcommands for the `config` command
#[derive(Subcommand)]
enum ConfigAction {
    /// Print current effective configuration (merged from defaults + file)
    Show,
    /// Print config file search paths and discovered config file
    Path,
    /// Generate an example .sbom-tools.yaml in the current directory
    Init,
}

/// Sub-subcommands for the `vex` command
#[derive(Subcommand)]
enum VexAction {
    /// Apply external VEX documents to an SBOM and output enriched vulnerability data
    Apply(VexArgs),
    /// Show VEX coverage summary (how many vulns have VEX statements)
    Status(VexArgs),
    /// Filter vulnerabilities by VEX state (for CI pipelines)
    Filter(VexArgs),
    /// Export the SBOM's VEX state as a CSAF v2.0 advisory document
    Export(VexExportArgs),
}

/// Arguments for `vex export`. Output format defaults to CSAF v2.0.
#[derive(Parser)]
struct VexExportArgs {
    /// Path to the SBOM file
    sbom: PathBuf,

    /// Apply external VEX document(s) before exporting (OpenVEX / CycloneDX VEX / CSAF).
    #[arg(long = "vex", value_name = "PATH")]
    vex: Vec<PathBuf>,

    /// Output advisory format. Currently: csaf (CSAF v2.0).
    #[arg(short, long, value_enum, default_value = "csaf")]
    format: VexExportFormatArg,

    /// Output file path (stdout if not specified)
    #[arg(short = 'O', long)]
    output_file: Option<PathBuf>,
}

/// Shared arguments for all VEX subcommands
#[derive(Parser)]
struct VexArgs {
    /// Path to the SBOM file
    sbom: PathBuf,

    /// Apply external VEX document(s) (OpenVEX or CycloneDX VEX). Can be specified multiple times.
    #[arg(long = "vex", value_name = "PATH")]
    vex: Vec<PathBuf>,

    /// Output format (json, summary, table)
    #[arg(short, long, default_value = "auto")]
    output: ReportFormat,

    /// Output file path (stdout if not specified)
    #[arg(short = 'O', long)]
    output_file: Option<PathBuf>,

    /// Only show actionable vulnerabilities (exclude NotAffected/Fixed).
    /// For `filter`: exit code 1 if actionable vulns remain.
    /// For `status`: exit code 1 if actionable vulns exist.
    #[arg(long)]
    actionable_only: bool,

    /// Filter by VEX state (not_affected, affected, fixed, under_investigation, none)
    #[arg(long, value_parser = validate_vex_state)]
    state: Option<String>,

    /// Enable OSV vulnerability enrichment before VEX overlay
    #[arg(long)]
    enrich_vulns: bool,

    /// Enable end-of-life detection
    #[arg(long)]
    enrich_eol: bool,

    /// Cache directory for enrichment data
    #[arg(long)]
    vuln_cache_dir: Option<PathBuf>,

    /// Cache TTL in hours
    #[arg(long, default_value = "24")]
    vuln_cache_ttl: u64,

    /// Bypass cache and fetch fresh data
    #[arg(long)]
    refresh_vulns: bool,

    /// API timeout in seconds
    #[arg(long, default_value = "30")]
    api_timeout: u64,
}

/// Sub-subcommands for the `verify` command
#[derive(Subcommand)]
enum VerifyAction {
    /// Verify file integrity against a hash value
    Hash {
        /// SBOM file to verify
        file: PathBuf,
        /// Expected hash (sha256:<hex>, sha512:<hex>, or bare hex)
        #[arg(long)]
        expected: Option<String>,
        /// Read expected hash from a file (e.g., sbom.json.sha256)
        #[arg(long, conflicts_with = "expected")]
        hash_file: Option<PathBuf>,
    },
    /// Audit component hashes within an SBOM
    AuditHashes {
        /// SBOM file to audit
        file: PathBuf,
        /// Output format (table or json)
        #[arg(
            short = 'f',
            long = "output",
            alias = "format",
            value_enum,
            default_value = "table"
        )]
        format: TableJsonFormat,
    },
}

/// Arguments for the `license-check` subcommand
#[derive(Parser)]
#[command(after_help = "EXAMPLES:
    sbom-tools license-check app.cdx.json                         # Default policy
    sbom-tools license-check app.cdx.json --strict                 # Permissive-only
    sbom-tools license-check app.cdx.json --policy policy.json     # Custom policy
    sbom-tools license-check app.cdx.json --check-propagation      # Dep tree analysis")]
struct LicenseCheckArgs {
    /// SBOM file to check
    file: PathBuf,

    /// Path to license policy config file (JSON)
    #[arg(long)]
    policy: Option<PathBuf>,

    /// Check license propagation through dependency tree
    #[arg(long)]
    check_propagation: bool,

    /// Use strict permissive-only policy (default is permissive)
    #[arg(long)]
    strict: bool,

    /// Output format (table or json)
    #[arg(
        short = 'f',
        long = "output",
        alias = "format",
        value_enum,
        default_value = "table"
    )]
    output_format: TableJsonFormat,
}

/// Arguments for the `enrich` subcommand
#[cfg(feature = "enrichment")]
#[derive(Parser)]
#[command(after_help = "EXAMPLES:
    sbom-tools enrich app.cdx.json --enrich-vulns                  # Add OSV vulns
    sbom-tools enrich app.cdx.json --enrich-vulns --enrich-eol     # Vulns + EOL
    sbom-tools enrich app.cdx.json --enrich-vulns -O enriched.json # Save to file
    sbom-tools enrich app.cdx.json --vex vex.json --enrich-vulns   # With VEX overlay")]
struct EnrichArgs {
    /// SBOM file to enrich
    file: PathBuf,

    /// Output file (stdout if not specified)
    #[arg(short = 'O', long)]
    output_file: Option<PathBuf>,

    #[command(flatten)]
    enrichment: SharedEnrichmentArgs,
}

/// Arguments for the `tailor` subcommand
#[derive(Parser)]
#[command(after_help = "EXAMPLES:
    sbom-tools tailor app.cdx.json --exclude-ecosystems npm        # Remove npm deps
    sbom-tools tailor app.cdx.json --include-name \"my-org/*\"       # Keep only org pkgs
    sbom-tools tailor app.cdx.json --strip-vulns -O clean.json     # Remove vuln data
    sbom-tools tailor app.cdx.json --include-types library,framework")]
struct TailorArgs {
    /// SBOM file to tailor
    file: PathBuf,

    /// Output file (stdout if not specified)
    #[arg(short = 'O', long)]
    output_file: Option<PathBuf>,

    /// Include only components matching this name pattern
    #[arg(long)]
    include_name: Option<String>,

    /// Include only these component types (comma-separated)
    #[arg(long)]
    include_types: Option<String>,

    /// Exclude these ecosystems (comma-separated)
    #[arg(long)]
    exclude_ecosystems: Option<String>,

    /// Strip vulnerability data from output
    #[arg(long)]
    strip_vulns: bool,

    /// Strip extension/property data
    #[arg(long)]
    strip_extensions: bool,
}

/// Arguments for the `merge` subcommand
#[derive(Parser)]
#[command(after_help = "EXAMPLES:
    sbom-tools merge primary.json secondary.json                   # Merge to stdout
    sbom-tools merge primary.json secondary.json -O combined.json  # Merge to file
    sbom-tools merge primary.json secondary.json --dedup purl      # Deduplicate by PURL")]
struct MergeArgs {
    /// Primary SBOM (provides document metadata)
    primary: PathBuf,

    /// Secondary SBOM to merge into primary
    secondary: PathBuf,

    /// Output file (stdout if not specified)
    #[arg(short = 'O', long)]
    output_file: Option<PathBuf>,

    /// Deduplication strategy
    #[arg(long, value_enum, default_value = "name")]
    dedup: sbom_tools::serialization::DeduplicationStrategy,
}

/// Arguments for the `cra-standards-watch` subcommand. Curated, offline-first
/// catalogue of CRA-related standards bodies and their tracked artefacts.
#[derive(Parser)]
#[command(after_help = "EXAMPLES:
    sbom-tools cra-standards-watch                   # Print the curated catalogue
    sbom-tools cra-standards-watch --format json     # Machine-readable output
    sbom-tools cra-standards-watch --check-online    # HEAD-probe each URL")]
struct CraStandardsWatchArgs {
    /// Output format: table (default) or json
    #[arg(short, long, value_enum, default_value = "table")]
    format: TableJsonFormat,

    /// Issue HEAD requests against each tracked URL and report HTTP status
    #[arg(long)]
    check_online: bool,

    /// Online-probe timeout in seconds
    #[arg(long, default_value = "10")]
    timeout: u64,
}

/// Arguments for the `cra-docs` subcommand — generates a CRA technical
/// documentation dossier (Annex V templates) prefilled from the SBOM and
/// optional CRA sidecar metadata.
#[derive(Parser)]
#[command(after_help = "EXAMPLES:
    sbom-tools cra-docs app.cdx.json --output dossier/                # Markdown dossier
    sbom-tools cra-docs app.cdx.json --output dossier/ --cra-sidecar app.cra.yaml
    sbom-tools cra-docs app.cdx.json --output dossier/ --cra-product-class important-class-1")]
struct CraDocsArgs {
    /// Path to the SBOM file
    sbom: PathBuf,

    /// Output directory (will be created if it doesn't exist)
    #[arg(short, long, default_value = "cra-dossier")]
    output: PathBuf,

    /// Path to a CRA sidecar metadata file (JSON or YAML).
    /// If omitted, auto-discovers `<sbom>.cra.json|yaml` next to the SBOM.
    #[arg(long, value_name = "PATH")]
    cra_sidecar: Option<PathBuf>,

    /// CRA Annex III/IV product class.
    /// One of: default, important-class-1, important-class-2, critical.
    /// Sidecar `productClass` wins.
    #[arg(long, value_name = "CLASS")]
    cra_product_class: Option<String>,
}

/// Dedicated table/json output format for commands that only emit those two
/// shapes (`license-check`, `verify audit-hashes`, `cra-standards-watch`).
///
/// Kept separate from the 10-variant [`ReportFormat`] so that unknown values
/// fail at parse time with a did-you-mean hint instead of silently degrading.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
enum TableJsonFormat {
    /// Human-readable table (default)
    #[default]
    Table,
    /// Machine-readable JSON
    Json,
}

impl TableJsonFormat {
    fn as_str(self) -> &'static str {
        match self {
            Self::Table => "table",
            Self::Json => "json",
        }
    }
}

/// Advisory export format for `vex export`. Currently only CSAF v2.0.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
enum VexExportFormatArg {
    /// CSAF v2.0 advisory document (default)
    #[default]
    Csaf,
}

/// Validate VEX state filter values at the CLI boundary.
fn validate_vex_state(s: &str) -> std::result::Result<String, String> {
    match s.to_lowercase().as_str() {
        "not_affected"
        | "notaffected"
        | "affected"
        | "fixed"
        | "under_investigation"
        | "underinvestigation"
        | "in_triage"
        | "none"
        | "missing" => Ok(s.to_string()),
        _ => Err(format!(
            "unknown VEX state: '{s}'. Valid values: \
             not_affected, affected, fixed, under_investigation, none"
        )),
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| log_level.to_string()),
        ))
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .init();

    // Dispatch to command handlers
    match cli.command {
        Commands::Diff(args) => {
            let enrichment = args.enrichment.to_enrichment_config();

            let config = DiffConfig {
                paths: DiffPaths {
                    old: args.old,
                    new: args.new,
                },
                output: OutputConfig {
                    format: args.output,
                    file: args.output_file,
                    report_types: args.reports,
                    no_color: cli.no_color,
                    streaming: sbom_tools::config::StreamingConfig {
                        threshold_bytes: args.streaming_threshold * 1024 * 1024,
                        force: args.streaming,
                        disabled: false,
                        stream_stdin: true,
                    },
                    export_template: cli.export_template.clone(),
                },
                matching: MatchingConfig {
                    fuzzy_preset: args.fuzzy_preset,
                    threshold: None,
                    include_unchanged: args.include_unchanged,
                },
                filtering: FilterConfig {
                    only_changes: args.only_changes,
                    min_severity: args.severity,
                    exclude_vex_resolved: args.exclude_vex_resolved,
                    fail_on_vex_gap: args.fail_on_vex_gap,
                },
                behavior: BehaviorConfig {
                    fail_on_vuln: args.fail_on_vuln,
                    fail_on_change: args.fail_on_change,
                    quiet: cli.quiet,
                    explain_matches: args.explain_matches,
                    recommend_threshold: args.recommend_threshold,
                },
                graph_diff: if args.graph_diff {
                    let mut gdc = GraphAwareDiffConfig::enabled();
                    gdc.max_depth = args.graph_max_depth;
                    if args.graph_impact_threshold != "low" {
                        gdc.impact_threshold = Some(args.graph_impact_threshold.clone());
                    }
                    if let Some(ref rels) = args.graph_relations {
                        gdc.relation_filter =
                            rels.split(',').map(|s| s.trim().to_string()).collect();
                    }
                    gdc
                } else {
                    GraphAwareDiffConfig::default()
                },
                rules: MatchingRulesPathConfig {
                    rules_file: args.enrichment.matching_rules,
                    dry_run: args.dry_run_rules,
                },
                ecosystem_rules: EcosystemRulesConfig {
                    config_file: args.ecosystem_rules,
                    disabled: args.no_ecosystem_rules,
                    detect_typosquats: args.detect_typosquats,
                },
                enrichment,
            };

            let exit_code = cli::run_diff(config)?;
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
            Ok(())
        }

        Commands::View(args) => {
            let enrichment = args.enrichment.to_enrichment_config();

            let config = ViewConfig {
                sbom_path: args.sbom,
                output: OutputConfig {
                    format: args.output,
                    file: args.output_file,
                    report_types: ReportType::All,
                    no_color: cli.no_color,
                    streaming: sbom_tools::config::StreamingConfig::default(),
                    export_template: cli.export_template.clone(),
                },
                validate_ntia: args.validate_ntia,
                min_severity: args.severity,
                vulnerable_only: args.vulnerable_only,
                ecosystem_filter: args.ecosystem,
                fail_on_vuln: args.fail_on_vuln,
                bom_profile: args
                    .bom_type
                    .as_deref()
                    .and_then(sbom_tools::BomProfile::from_str_opt),
                enrichment,
                cra_sidecar_path: args.cra_sidecar.clone(),
                cra_product_class: args.cra_product_class.clone(),
            };
            let exit_code = cli::run_view(config)?;
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
            Ok(())
        }

        Commands::Validate(args) => {
            let exit_code = cli::run_validate(
                args.sbom,
                args.standard,
                args.output,
                args.output_file,
                args.fail_on_warning,
                args.summary,
                args.cra_sidecar,
                args.cra_product_class,
            )?;
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
            Ok(())
        }

        Commands::DiffMulti(args) => {
            let enrichment = args.enrichment.to_enrichment_config();
            let config = MultiDiffConfig {
                baseline: args.baseline,
                targets: args.targets,
                output: OutputConfig {
                    format: args.output,
                    file: args.output_file,
                    no_color: cli.no_color,
                    export_template: cli.export_template.clone(),
                    ..Default::default()
                },
                matching: MatchingConfig {
                    fuzzy_preset: args.fuzzy_preset,
                    include_unchanged: args.include_unchanged,
                    ..Default::default()
                },
                filtering: FilterConfig {
                    min_severity: args.severity,
                    exclude_vex_resolved: args.exclude_vex_resolved,
                    fail_on_vex_gap: args.fail_on_vex_gap,
                    ..Default::default()
                },
                behavior: BehaviorConfig {
                    fail_on_vuln: args.fail_on_vuln,
                    fail_on_change: args.fail_on_change,
                    quiet: cli.quiet,
                    ..Default::default()
                },
                graph_diff: if args.graph_diff {
                    let mut gdc = GraphAwareDiffConfig::enabled();
                    gdc.max_depth = args.graph_max_depth;
                    if args.graph_impact_threshold != "low" {
                        gdc.impact_threshold = Some(args.graph_impact_threshold.clone());
                    }
                    if let Some(ref rels) = args.graph_relations {
                        gdc.relation_filter =
                            rels.split(',').map(|s| s.trim().to_string()).collect();
                    }
                    gdc
                } else {
                    GraphAwareDiffConfig::default()
                },
                rules: MatchingRulesPathConfig {
                    rules_file: args.enrichment.matching_rules,
                    ..Default::default()
                },
                ecosystem_rules: Default::default(),
                enrichment,
            };
            let exit_code = cli::run_diff_multi(config)?;
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
            Ok(())
        }

        Commands::Timeline(args) => {
            let enrichment = args.enrichment.to_enrichment_config();
            let config = TimelineConfig {
                sbom_paths: args.sboms,
                output: OutputConfig {
                    format: args.output,
                    file: args.output_file,
                    no_color: cli.no_color,
                    export_template: cli.export_template.clone(),
                    ..Default::default()
                },
                matching: MatchingConfig {
                    fuzzy_preset: args.fuzzy_preset,
                    ..Default::default()
                },
                filtering: FilterConfig {
                    min_severity: args.severity,
                    exclude_vex_resolved: args.exclude_vex_resolved,
                    fail_on_vex_gap: args.fail_on_vex_gap,
                    ..Default::default()
                },
                behavior: BehaviorConfig {
                    fail_on_vuln: args.fail_on_vuln,
                    fail_on_change: args.fail_on_change,
                    quiet: cli.quiet,
                    ..Default::default()
                },
                graph_diff: if args.graph_diff {
                    let mut gdc = GraphAwareDiffConfig::enabled();
                    gdc.max_depth = args.graph_max_depth;
                    if args.graph_impact_threshold != "low" {
                        gdc.impact_threshold = Some(args.graph_impact_threshold.clone());
                    }
                    if let Some(ref rels) = args.graph_relations {
                        gdc.relation_filter =
                            rels.split(',').map(|s| s.trim().to_string()).collect();
                    }
                    gdc
                } else {
                    GraphAwareDiffConfig::default()
                },
                rules: MatchingRulesPathConfig {
                    rules_file: args.enrichment.matching_rules,
                    ..Default::default()
                },
                ecosystem_rules: Default::default(),
                enrichment,
            };
            let exit_code = cli::run_timeline(config)?;
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
            Ok(())
        }

        Commands::Matrix(args) => {
            let enrichment = args.enrichment.to_enrichment_config();
            let config = MatrixConfig {
                sbom_paths: args.sboms,
                output: OutputConfig {
                    format: args.output,
                    file: args.output_file,
                    no_color: cli.no_color,
                    export_template: cli.export_template.clone(),
                    ..Default::default()
                },
                matching: MatchingConfig {
                    fuzzy_preset: args.fuzzy_preset,
                    ..Default::default()
                },
                cluster_threshold: args.cluster_threshold,
                filtering: FilterConfig {
                    min_severity: args.severity,
                    exclude_vex_resolved: args.exclude_vex_resolved,
                    fail_on_vex_gap: args.fail_on_vex_gap,
                    ..Default::default()
                },
                behavior: BehaviorConfig {
                    fail_on_vuln: args.fail_on_vuln,
                    fail_on_change: args.fail_on_change,
                    quiet: cli.quiet,
                    ..Default::default()
                },
                graph_diff: if args.graph_diff {
                    let mut gdc = GraphAwareDiffConfig::enabled();
                    gdc.max_depth = args.graph_max_depth;
                    if args.graph_impact_threshold != "low" {
                        gdc.impact_threshold = Some(args.graph_impact_threshold.clone());
                    }
                    if let Some(ref rels) = args.graph_relations {
                        gdc.relation_filter =
                            rels.split(',').map(|s| s.trim().to_string()).collect();
                    }
                    gdc
                } else {
                    GraphAwareDiffConfig::default()
                },
                rules: MatchingRulesPathConfig {
                    rules_file: args.enrichment.matching_rules,
                    ..Default::default()
                },
                ecosystem_rules: Default::default(),
                enrichment,
            };
            let exit_code = cli::run_matrix(config)?;
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
            Ok(())
        }

        Commands::Quality(args) => {
            let exit_code = cli::run_quality(
                args.sbom,
                args.profile,
                args.output,
                args.output_file,
                args.recommendations,
                args.metrics,
                args.min_score,
                cli.no_color,
                args.cra_sidecar,
                args.cra_product_class,
            )?;
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
            Ok(())
        }

        Commands::Query(args) => {
            // Split positional args: first arg is pattern if it doesn't look like a file,
            // otherwise all args are file paths
            let (pattern, sbom_paths) = split_query_args(&args.args);

            if sbom_paths.is_empty() {
                anyhow::bail!("No SBOM files specified. Usage: sbom-tools query [PATTERN] FILE...");
            }

            let enrichment = args.enrichment.to_enrichment_config();

            let quantum_safe_filter = if args.quantum_safe {
                Some(true)
            } else if args.quantum_vulnerable {
                Some(false)
            } else {
                None
            };

            let filter = cli::QueryFilter {
                pattern,
                name: args.name,
                purl: args.purl,
                version: args.version,
                license: args.license,
                ecosystem: args.ecosystem,
                supplier: args.supplier,
                affected_by: args.affected_by,
                crypto_type: args.crypto_type,
                algorithm_family: args.algorithm_family,
                quantum_safe: quantum_safe_filter,
            };

            let config = QueryConfig {
                sbom_paths,
                output: OutputConfig {
                    format: args.output,
                    file: args.output_file,
                    report_types: ReportType::All,
                    no_color: cli.no_color,
                    streaming: sbom_tools::config::StreamingConfig::default(),
                    export_template: None,
                },
                enrichment,
                limit: args.limit,
                group_by_sbom: args.group_by_sbom,
            };

            let exit_code = cli::run_query(config, filter)?;
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
            Ok(())
        }

        Commands::Vex { action } => {
            let (args, cli_action) = match action {
                VexAction::Apply(args) => (args, cli::VexAction::Apply),
                VexAction::Status(args) => (args, cli::VexAction::Status),
                VexAction::Filter(args) => (args, cli::VexAction::Filter),
                VexAction::Export(export_args) => {
                    let fmt = match export_args.format {
                        VexExportFormatArg::Csaf => cli::VexExportFormat::Csaf,
                    };
                    let synth_args = VexArgs {
                        sbom: export_args.sbom,
                        vex: export_args.vex,
                        output: ReportFormat::Json,
                        output_file: export_args.output_file,
                        actionable_only: false,
                        state: None,
                        enrich_vulns: false,
                        enrich_eol: false,
                        vuln_cache_ttl: 24,
                        vuln_cache_dir: None,
                        refresh_vulns: false,
                        api_timeout: 10,
                    };
                    (synth_args, cli::VexAction::Export(fmt))
                }
            };

            let enrichment = EnrichmentConfig {
                enabled: args.enrich_vulns,
                provider: "osv".to_string(),
                cache_ttl_hours: args.vuln_cache_ttl,
                max_concurrent: 10,
                cache_dir: args.vuln_cache_dir.or_else(|| Some(dirs::osv_cache_dir())),
                bypass_cache: args.refresh_vulns,
                timeout_secs: args.api_timeout,
                enable_eol: args.enrich_eol,
                vex_paths: Vec::new(), // VEX paths handled separately
                ..Default::default()
            };

            let config = sbom_tools::config::VexConfig {
                sbom_path: args.sbom,
                vex_paths: args.vex,
                output_format: args.output,
                output_file: args.output_file,
                quiet: cli.quiet,
                actionable_only: args.actionable_only,
                filter_state: args.state,
                enrichment,
            };

            let exit_code = cli::run_vex(config, cli_action)?;
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
            Ok(())
        }

        Commands::Watch(args) => {
            let enrichment = args.enrichment.to_enrichment_config();

            let config = WatchConfig {
                watch_dirs: args.dirs,
                poll_interval: parse_duration(&args.interval)?,
                enrich_interval: parse_duration(&args.enrich_interval)?,
                debounce: parse_duration(&args.debounce)?,
                output: OutputConfig {
                    format: args.output,
                    file: args.output_file,
                    report_types: ReportType::All,
                    no_color: cli.no_color,
                    streaming: sbom_tools::config::StreamingConfig::default(),
                    export_template: None,
                },
                enrichment,
                webhook_url: args.webhook,
                exit_on_change: args.exit_on_change,
                max_snapshots: args.max_snapshots,
                quiet: cli.quiet,
                dry_run: args.dry_run,
                cra_standards_enabled: args.cra_standards,
                cra_standards_interval: parse_duration(&args.cra_standards_interval)?,
                cra_standards_timeout: parse_duration(&args.cra_standards_timeout)?,
            };

            cli::run_watch(config)
        }

        Commands::Completions { shell } => {
            generate(shell, &mut Cli::command(), "sbom-tools", &mut io::stdout());
            Ok(())
        }

        Commands::ConfigSchema { output } => {
            let schema = sbom_tools::config::generate_json_schema();
            match output {
                Some(path) => {
                    std::fs::write(&path, &schema)?;
                    eprintln!("Schema written to {}", path.display());
                }
                None => {
                    println!("{schema}");
                }
            }
            Ok(())
        }

        Commands::Config { action } => match action {
            ConfigAction::Show => {
                let (config, loaded_from) =
                    sbom_tools::config::load_or_default(cli.config.as_deref());
                if let Some(path) = &loaded_from {
                    eprintln!("# Loaded from: {}", path.display());
                } else {
                    eprintln!("# No config file found; showing defaults");
                }
                let yaml =
                    serde_yaml_ng::to_string(&config).context("failed to serialize config")?;
                print!("{yaml}");
                Ok(())
            }
            ConfigAction::Path => {
                let search_paths: [Option<String>; 3] = [
                    std::env::current_dir()
                        .ok()
                        .map(|p| p.display().to_string()),
                    ::dirs::config_dir().map(|p| p.join("sbom-tools").display().to_string()),
                    ::dirs::home_dir().map(|p| p.display().to_string()),
                ];
                eprintln!("Config file search paths (in order):");
                for path in search_paths.into_iter().flatten() {
                    eprintln!("  {path}");
                }
                eprintln!();
                eprintln!("Recognized file names:");
                for name in &[
                    ".sbom-tools.yaml",
                    ".sbom-tools.yml",
                    "sbom-tools.yaml",
                    "sbom-tools.yml",
                    ".sbom-toolsrc",
                ] {
                    eprintln!("  {name}");
                }
                eprintln!();
                match sbom_tools::config::discover_config_file(cli.config.as_deref()) {
                    Some(path) => eprintln!("Active config file: {}", path.display()),
                    None => eprintln!("No config file found."),
                }
                Ok(())
            }
            ConfigAction::Init => {
                let target = std::env::current_dir()
                    .context("cannot determine current directory")?
                    .join(".sbom-tools.yaml");
                if target.exists() {
                    anyhow::bail!(
                        "{} already exists. Remove it first to re-initialize.",
                        target.display()
                    );
                }
                let content = sbom_tools::config::generate_full_example_config();
                std::fs::write(&target, content)
                    .with_context(|| format!("failed to write {}", target.display()))?;
                eprintln!("Created {}", target.display());
                Ok(())
            }
        },

        Commands::Verify { action } => {
            let cli_action = match action {
                VerifyAction::Hash {
                    file,
                    expected,
                    hash_file,
                } => cli::VerifyAction::Hash {
                    file,
                    expected,
                    hash_file,
                },
                VerifyAction::AuditHashes { file, format } => cli::VerifyAction::AuditHashes {
                    file,
                    format: format.as_str().to_string(),
                },
            };

            let exit_code = cli::run_verify(cli_action, cli.quiet)?;
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
            Ok(())
        }

        Commands::LicenseCheck(args) => {
            let exit_code = cli::run_license_check(
                &args.file,
                args.policy.as_ref(),
                args.check_propagation,
                args.strict,
                args.output_format.as_str(),
                cli.quiet,
            )?;
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
            Ok(())
        }

        #[cfg(feature = "enrichment")]
        Commands::Enrich(args) => {
            let enrichment = args.enrichment.to_enrichment_config();

            let exit_code =
                cli::run_enrich(&args.file, args.output_file.as_ref(), enrichment, cli.quiet)?;
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
            Ok(())
        }

        Commands::Tailor(args) => {
            let config = sbom_tools::serialization::TailorConfig {
                include_name_pattern: args.include_name,
                include_types: args
                    .include_types
                    .map(|s| s.split(',').map(|t| t.trim().to_string()).collect())
                    .unwrap_or_default(),
                exclude_ecosystems: args
                    .exclude_ecosystems
                    .map(|s| s.split(',').map(|e| e.trim().to_string()).collect())
                    .unwrap_or_default(),
                strip_vulns: args.strip_vulns,
                strip_extensions: args.strip_extensions,
                ..Default::default()
            };

            let exit_code =
                cli::run_tailor(&args.file, args.output_file.as_ref(), config, cli.quiet)?;
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
            Ok(())
        }

        Commands::Merge(args) => {
            let config = sbom_tools::serialization::MergeConfig {
                dedup_strategy: args.dedup,
            };

            let exit_code = cli::run_merge(
                &args.primary,
                &args.secondary,
                args.output_file.as_ref(),
                config,
                cli.quiet,
            )?;
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
            Ok(())
        }

        Commands::CraDocs(args) => cli::run_cra_docs(
            args.sbom,
            args.output,
            args.cra_sidecar,
            args.cra_product_class,
        ),

        Commands::CraStandardsWatch(args) => cli::run_cra_standards_watch(
            cli::WatchOutputFormat::parse(args.format.as_str())?,
            args.check_online,
            args.timeout,
        ),

        Commands::Man => {
            let cmd = Cli::command();
            let man = clap_mangen::Man::new(cmd);
            let mut buf = Vec::new();
            man.render(&mut buf).context("failed to render man page")?;
            io::stdout().write_all(&buf)?;
            Ok(())
        }
    }
}

/// Split positional args into (optional pattern, file paths).
///
/// The first argument is treated as a search pattern unless it clearly looks
/// like a file path: contains a path separator, has a known SBOM file extension,
/// or is an existing file on disk.
fn split_query_args(args: &[String]) -> (Option<String>, Vec<PathBuf>) {
    if args.is_empty() {
        return (None, Vec::new());
    }

    let first = &args[0];
    let looks_like_file = first.contains(std::path::MAIN_SEPARATOR)
        || first.contains('/')
        || has_sbom_extension(first)
        || Path::new(first).is_file();

    if looks_like_file {
        // All args are file paths
        (None, args.iter().map(PathBuf::from).collect())
    } else {
        // First arg is pattern, rest are file paths
        let pattern = Some(first.clone());
        let paths = args[1..].iter().map(PathBuf::from).collect();
        (pattern, paths)
    }
}

/// Check if a string has a known SBOM file extension.
fn has_sbom_extension(s: &str) -> bool {
    let lower = s.to_lowercase();
    lower.ends_with(".json")
        || lower.ends_with(".xml")
        || lower.ends_with(".spdx")
        || lower.ends_with(".cdx")
        || lower.ends_with(".yaml")
        || lower.ends_with(".yml")
        || lower.ends_with(".rdf")
}
