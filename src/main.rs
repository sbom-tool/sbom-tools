//! sbom-tools: Semantic SBOM diff and analysis tool
//!
//! A format-agnostic SBOM comparison tool for `CycloneDX` and SPDX formats.

#![allow(
    clippy::too_many_lines,
    clippy::struct_excessive_bools,
    clippy::needless_pass_by_value
)]

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{Shell, generate};
use sbom_tools::{
    cli,
    config::{
        BehaviorConfig, DiffConfig, DiffPaths, EcosystemRulesConfig, EnrichmentConfig,
        FilterConfig, GraphAwareDiffConfig, MatchingConfig, MatchingRulesPathConfig, OutputConfig,
        QueryConfig, ViewConfig, WatchConfig,
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
        "\n  CycloneDX: 1.4, 1.5, 1.6 (JSON, XML)",
        "\n  SPDX:      2.2, 2.3 (JSON, tag-value, RDF/XML)",
        "\n\nOutput Formats:",
        "\n  tui, json, sarif, markdown, html, summary, table, side-by-side",
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

EXAMPLES:
    # Quick diff with auto-detected output
    sbom-tools diff old.cdx.json new.cdx.json

    # CI/CD pipeline check
    sbom-tools diff old.cdx.json new.cdx.json -o summary --fail-on-vuln

    # Export JSON for processing
    sbom-tools diff old.cdx.json new.cdx.json -o json > diff.json

    # Compare baseline against fleet
    sbom-tools diff-multi baseline.cdx.json device-*.cdx.json -o table

    # Search for vulnerable components across SBOMs
    sbom-tools query \"log4j\" --version \"<2.17.0\" fleet/*.json")]
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

/// Arguments for the `diff` subcommand
#[derive(Parser)]
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

    /// Fuzzy matching preset (strict, balanced, permissive)
    #[arg(long, default_value = "balanced")]
    fuzzy_preset: String,

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

    /// Enable OSV vulnerability enrichment
    #[arg(long)]
    enrich_vulns: bool,

    /// Enable end-of-life detection via endoflife.date
    #[arg(long)]
    enrich_eol: bool,

    /// Apply external VEX document(s) (OpenVEX format). Can be specified multiple times.
    #[arg(long = "vex", value_name = "PATH")]
    vex: Vec<PathBuf>,

    /// Cache directory for vulnerability data
    #[arg(long)]
    vuln_cache_dir: Option<PathBuf>,

    /// Cache TTL in hours (default: 24)
    #[arg(long, default_value = "24")]
    vuln_cache_ttl: u64,

    /// Bypass cache and fetch fresh vulnerability data
    #[arg(long)]
    refresh_vulns: bool,

    /// API timeout in seconds (default: 30)
    #[arg(long, default_value = "30")]
    api_timeout: u64,

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

    /// Custom matching rules YAML file
    #[arg(long)]
    matching_rules: Option<PathBuf>,

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

    /// Streaming threshold in MB (default: 10). Files larger than this use streaming mode.
    #[arg(long, default_value = "10")]
    streaming_threshold: u64,
}

/// Arguments for the `view` subcommand
#[derive(Parser)]
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

    /// Exit with code 2 if vulnerabilities are present (for CI pipelines)
    #[arg(long)]
    fail_on_vuln: bool,

    /// Enable OSV vulnerability enrichment
    #[arg(long)]
    enrich_vulns: bool,

    /// Enable end-of-life detection via endoflife.date
    #[arg(long)]
    enrich_eol: bool,

    /// Apply external VEX document(s) (OpenVEX format). Can be specified multiple times.
    #[arg(long = "vex", value_name = "PATH")]
    vex: Vec<PathBuf>,

    /// Cache directory for enrichment data
    #[arg(long)]
    vuln_cache_dir: Option<PathBuf>,

    /// Cache TTL in hours (default: 24)
    #[arg(long, default_value = "24")]
    vuln_cache_ttl: u64,

    /// Bypass cache and fetch fresh data
    #[arg(long)]
    refresh_vulns: bool,

    /// API timeout in seconds (default: 30)
    #[arg(long, default_value = "30")]
    api_timeout: u64,
}

/// Arguments for the `validate` subcommand
#[derive(Parser)]
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
}

/// Arguments for the `diff-multi` subcommand
#[derive(Parser)]
struct DiffMultiArgs {
    /// Path to the baseline SBOM
    baseline: PathBuf,

    /// Paths to target SBOMs to compare against baseline
    #[arg(required = true)]
    targets: Vec<PathBuf>,

    /// Output format (auto detects TTY: tui if interactive, summary otherwise)
    #[arg(short, long, default_value = "auto")]
    output: ReportFormat,

    /// Output file path (stdout if not specified)
    #[arg(short = 'O', long)]
    output_file: Option<PathBuf>,

    /// Fuzzy matching preset (strict, balanced, permissive)
    #[arg(long, default_value = "balanced")]
    fuzzy_preset: String,

    /// Include unchanged components in output
    #[arg(long)]
    include_unchanged: bool,

    /// Enable graph-aware diffing for multi-comparisons
    #[arg(long)]
    graph_diff: bool,
}

/// Arguments for the `timeline` subcommand
#[derive(Parser)]
struct TimelineArgs {
    /// Paths to SBOMs in chronological order (oldest first)
    #[arg(required = true)]
    sboms: Vec<PathBuf>,

    /// Output format (auto detects TTY: tui if interactive, summary otherwise)
    #[arg(short, long, default_value = "auto")]
    output: ReportFormat,

    /// Output file path (stdout if not specified)
    #[arg(short = 'O', long)]
    output_file: Option<PathBuf>,

    /// Fuzzy matching preset (strict, balanced, permissive)
    #[arg(long, default_value = "balanced")]
    fuzzy_preset: String,

    /// Enable graph-aware diffing for timeline analysis
    #[arg(long)]
    graph_diff: bool,
}

/// Arguments for the `matrix` subcommand
#[derive(Parser)]
struct MatrixArgs {
    /// Paths to SBOMs to compare
    #[arg(required = true)]
    sboms: Vec<PathBuf>,

    /// Output format (auto detects TTY: tui if interactive, summary otherwise)
    #[arg(short, long, default_value = "auto")]
    output: ReportFormat,

    /// Output file path (stdout if not specified)
    #[arg(short = 'O', long)]
    output_file: Option<PathBuf>,

    /// Fuzzy matching preset (strict, balanced, permissive)
    #[arg(long, default_value = "balanced")]
    fuzzy_preset: String,

    /// Similarity threshold for clustering (0.0-1.0)
    #[arg(long, default_value = "0.8")]
    cluster_threshold: f64,

    /// Enable graph-aware diffing for matrix comparison
    #[arg(long)]
    graph_diff: bool,
}

/// Arguments for the `quality` subcommand
#[derive(Parser)]
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
}

/// Arguments for the `query` subcommand
#[derive(Parser)]
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

    /// Output format (table, json, csv)
    #[arg(short, long, default_value = "auto")]
    output: ReportFormat,

    /// Output file path (stdout if not specified)
    #[arg(short = 'O', long)]
    output_file: Option<PathBuf>,

    /// Enable OSV vulnerability enrichment
    #[arg(long)]
    enrich_vulns: bool,

    /// Enable end-of-life detection via endoflife.date
    #[arg(long)]
    enrich_eol: bool,

    /// Apply external VEX document(s) (OpenVEX format). Can be specified multiple times.
    #[arg(long = "vex", value_name = "PATH")]
    vex: Vec<PathBuf>,

    /// Cache directory for enrichment data
    #[arg(long)]
    vuln_cache_dir: Option<PathBuf>,

    /// Cache TTL in hours (default: 24)
    #[arg(long, default_value = "24")]
    vuln_cache_ttl: u64,

    /// Bypass cache and fetch fresh data
    #[arg(long)]
    refresh_vulns: bool,

    /// API timeout in seconds (default: 30)
    #[arg(long, default_value = "30")]
    api_timeout: u64,

    /// Maximum number of results to return
    #[arg(long)]
    limit: Option<usize>,

    /// Group results by SBOM source
    #[arg(long)]
    group_by_sbom: bool,
}

/// Arguments for the `watch` subcommand
#[derive(Parser)]
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

    /// Enable OSV vulnerability enrichment
    #[arg(long)]
    enrich_vulns: bool,

    /// Enable end-of-life detection via endoflife.date
    #[arg(long)]
    enrich_eol: bool,

    /// Apply external VEX document(s) (OpenVEX format). Can be specified multiple times.
    #[arg(long = "vex", value_name = "PATH")]
    vex: Vec<PathBuf>,

    /// Cache directory for enrichment data
    #[arg(long)]
    vuln_cache_dir: Option<PathBuf>,

    /// Cache TTL in hours (default: 24)
    #[arg(long, default_value = "24")]
    vuln_cache_ttl: u64,

    /// Bypass cache and fetch fresh data
    #[arg(long)]
    refresh_vulns: bool,

    /// API timeout in seconds (default: 30)
    #[arg(long, default_value = "30")]
    api_timeout: u64,

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
            let enrichment = EnrichmentConfig {
                enabled: args.enrich_vulns,
                provider: "osv".to_string(),
                cache_ttl_hours: args.vuln_cache_ttl,
                max_concurrent: 10,
                cache_dir: args.vuln_cache_dir.or_else(|| Some(dirs::osv_cache_dir())),
                bypass_cache: args.refresh_vulns,
                timeout_secs: args.api_timeout,
                enable_eol: args.enrich_eol,
                vex_paths: args.vex,
            };

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
                    rules_file: args.matching_rules,
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
            let enrichment = EnrichmentConfig {
                enabled: args.enrich_vulns,
                provider: "osv".to_string(),
                cache_ttl_hours: args.vuln_cache_ttl,
                max_concurrent: 10,
                cache_dir: args.vuln_cache_dir.or_else(|| Some(dirs::osv_cache_dir())),
                bypass_cache: args.refresh_vulns,
                timeout_secs: args.api_timeout,
                enable_eol: args.enrich_eol,
                vex_paths: args.vex,
            };

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
                enrichment,
            };
            let exit_code = cli::run_view(config)?;
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
            Ok(())
        }

        Commands::Validate(args) => cli::run_validate(
            args.sbom,
            args.standard,
            args.output,
            args.output_file,
            args.fail_on_warning,
            args.summary,
        ),

        Commands::DiffMulti(args) => cli::run_diff_multi(
            args.baseline,
            args.targets,
            args.output,
            args.output_file,
            args.fuzzy_preset,
            args.include_unchanged,
            args.graph_diff,
        ),

        Commands::Timeline(args) => cli::run_timeline(
            args.sboms,
            args.output,
            args.output_file,
            args.fuzzy_preset,
            args.graph_diff,
        ),

        Commands::Matrix(args) => cli::run_matrix(
            args.sboms,
            args.output,
            args.output_file,
            args.fuzzy_preset,
            args.cluster_threshold,
            args.graph_diff,
        ),

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

            let enrichment = EnrichmentConfig {
                enabled: args.enrich_vulns,
                provider: "osv".to_string(),
                cache_ttl_hours: args.vuln_cache_ttl,
                max_concurrent: 10,
                cache_dir: args.vuln_cache_dir.or_else(|| Some(dirs::osv_cache_dir())),
                bypass_cache: args.refresh_vulns,
                timeout_secs: args.api_timeout,
                enable_eol: args.enrich_eol,
                vex_paths: args.vex,
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

            cli::run_query(config, filter)
        }

        Commands::Watch(args) => {
            let enrichment = EnrichmentConfig {
                enabled: args.enrich_vulns,
                provider: "osv".to_string(),
                cache_ttl_hours: args.vuln_cache_ttl,
                max_concurrent: 10,
                cache_dir: args.vuln_cache_dir.or_else(|| Some(dirs::osv_cache_dir())),
                bypass_cache: args.refresh_vulns,
                timeout_secs: args.api_timeout,
                enable_eol: args.enrich_eol,
                vex_paths: args.vex,
            };

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
