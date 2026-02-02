//! sbom-tools: Semantic SBOM diff and analysis tool
//!
//! A format-agnostic SBOM comparison tool for CycloneDX and SPDX formats.

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use sbom_tools::{
    cli,
    config::{
        BehaviorConfig, DiffConfig, DiffPaths, EcosystemRulesConfig, EnrichmentConfig,
        FilterConfig, GraphAwareDiffConfig, MatchingConfig, MatchingRulesPathConfig, OutputConfig,
        ViewConfig,
    },
    pipeline::dirs,
    reports::{ReportFormat, ReportType},
};
use std::io;
use std::path::PathBuf;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Build long version string with format support info
fn build_long_version() -> &'static str {
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
    1  Changes detected
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
    sbom-tools diff-multi baseline.cdx.json device-*.cdx.json -o table")]
struct Cli {
    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Suppress non-essential output
    #[arg(short, long, global = true)]
    quiet: bool,

    /// Disable colored output (also respects NO_COLOR env)
    #[arg(long, global = true)]
    no_color: bool,

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

    /// Cache directory for vulnerability data
    #[arg(long)]
    vuln_cache_dir: Option<PathBuf>,

    /// Cache TTL in hours (default: 24)
    #[arg(long, default_value = "24")]
    vuln_cache_ttl: u64,

    /// Bypass cache and fetch fresh vulnerability data
    #[arg(long)]
    refresh_vulns: bool,

    /// OSV API timeout in seconds (default: 30)
    #[arg(long, default_value = "30")]
    osv_timeout: u64,

    /// Enable graph-aware diffing (detect reparenting, depth changes)
    #[arg(long)]
    graph_diff: bool,

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

    /// Exclude vulnerabilities with VEX status not_affected or fixed
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
}

/// Arguments for the `validate` subcommand
#[derive(Parser)]
struct ValidateArgs {
    /// Path to the SBOM file
    sbom: PathBuf,

    /// Compliance standard to validate against (ntia, fda, cra)
    #[arg(long, default_value = "ntia", value_parser = ["ntia", "fda", "cra"])]
    standard: String,

    /// Output format
    #[arg(short, long, default_value = "json")]
    output: ReportFormat,

    /// Output file path (stdout if not specified)
    #[arg(short = 'O', long)]
    output_file: Option<PathBuf>,
}

/// Arguments for the `diff-multi` subcommand
#[derive(Parser)]
struct DiffMultiArgs {
    /// Path to the baseline SBOM
    baseline: PathBuf,

    /// Paths to target SBOMs to compare against baseline
    #[arg(required = true)]
    targets: Vec<PathBuf>,

    /// Output format
    #[arg(short, long, default_value = "tui")]
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
}

/// Arguments for the `timeline` subcommand
#[derive(Parser)]
struct TimelineArgs {
    /// Paths to SBOMs in chronological order (oldest first)
    #[arg(required = true)]
    sboms: Vec<PathBuf>,

    /// Output format
    #[arg(short, long, default_value = "tui")]
    output: ReportFormat,

    /// Output file path (stdout if not specified)
    #[arg(short = 'O', long)]
    output_file: Option<PathBuf>,

    /// Fuzzy matching preset (strict, balanced, permissive)
    #[arg(long, default_value = "balanced")]
    fuzzy_preset: String,
}

/// Arguments for the `matrix` subcommand
#[derive(Parser)]
struct MatrixArgs {
    /// Paths to SBOMs to compare
    #[arg(required = true)]
    sboms: Vec<PathBuf>,

    /// Output format
    #[arg(short, long, default_value = "tui")]
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
}

/// Arguments for the `quality` subcommand
#[derive(Parser)]
struct QualityArgs {
    /// Path to the SBOM file
    sbom: PathBuf,

    /// Scoring profile (minimal, standard, security, license-compliance, comprehensive)
    #[arg(long, default_value = "standard")]
    profile: String,

    /// Output format
    #[arg(short, long, default_value = "summary")]
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

    /// Compare all SBOMs against each other (NxN matrix comparison)
    Matrix(MatrixArgs),

    /// Assess SBOM quality and completeness
    Quality(QualityArgs),

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
                timeout_secs: args.osv_timeout,
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
                    GraphAwareDiffConfig::enabled()
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
            let config = ViewConfig {
                sbom_path: args.sbom,
                output: OutputConfig {
                    format: args.output,
                    file: args.output_file,
                    report_types: ReportType::All,
                    no_color: cli.no_color,
                    streaming: sbom_tools::config::StreamingConfig::default(),
                },
                validate_ntia: args.validate_ntia,
                min_severity: args.severity,
                vulnerable_only: args.vulnerable_only,
                ecosystem_filter: args.ecosystem,
            };
            cli::run_view(config)
        }

        Commands::Validate(args) => {
            cli::run_validate(args.sbom, args.standard, args.output, args.output_file)
        }

        Commands::DiffMulti(args) => cli::run_diff_multi(
            args.baseline,
            args.targets,
            args.output,
            args.output_file,
            args.fuzzy_preset,
            args.include_unchanged,
        ),

        Commands::Timeline(args) => {
            cli::run_timeline(args.sboms, args.output, args.output_file, args.fuzzy_preset)
        }

        Commands::Matrix(args) => cli::run_matrix(
            args.sboms,
            args.output,
            args.output_file,
            args.fuzzy_preset,
            args.cluster_threshold,
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
    }
}
