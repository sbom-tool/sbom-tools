//! sbom-tools: Semantic SBOM diff and analysis tool
//!
//! A format-agnostic SBOM comparison tool for `CycloneDX` and SPDX formats.

#![allow(
    clippy::too_many_lines,
    clippy::struct_excessive_bools,
    clippy::needless_pass_by_value
)]

mod cli_config;

use anyhow::{Context, Result};
use clap::{ArgMatches, Args, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use clap_complete::{Shell, generate};
use cli_config::{EffectiveConfig, arg_was_set_sub, resolve, resolve_bool};
use sbom_tools::{
    cli,
    config::{
        AppConfig, BehaviorConfig, DiffConfig, DiffPaths, EcosystemRulesConfig, EnrichmentConfig,
        FilterConfig, FuzzyPreset, GraphAwareDiffConfig, MatchingConfig, MatchingRulesPathConfig,
        MatrixConfig, MultiDiffConfig, OutputConfig, QueryConfig, TimelineConfig, ViewConfig,
        WatchConfig,
    },
    pipeline::dirs,
    quality::{ScoringProfile, StandardSelector},
    reports::{ReportFormat, ReportType},
    watch::parse_duration,
};
use std::io::{self, IsTerminal as _, Write as _};
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
    0  Success / gate passed
    1  Gate failed: --fail-on-change, --min-score, --fail-on-noncompliant,
       query with no matches, vex status/filter --actionable-only,
       verify audit-hashes gate
    2  Command-line usage error; also vulnerabilities introduced
       (diff/view --fail-on-vuln)
    3  Operational error (I/O, parse, config, invalid values)
    4  VEX gaps found (--fail-on-vex-gap)
    5  License policy violations found (license-check)
    6  Actively exploited (KEV) vulnerability introduced (--fail-on-kev)
    7  ML performance metric regressed (diff --fail-on-ml-regression)

EXAMPLES:
  Comparing SBOMs:
    sbom-tools diff old.cdx.json new.cdx.json                     # Interactive TUI
    sbom-tools diff old.cdx.json new.cdx.json -o summary           # Terminal summary
    sbom-tools diff old.cdx.json new.cdx.json -o json > diff.json  # JSON export
    sbom-tools diff old.cdx.json new.cdx.json -o sarif             # CI/CD SARIF

  Enrichment (add vulnerability + EOL + KEV data before diffing):
    sbom-tools diff old.json new.json --enrich-vulns --enrich-eol
    sbom-tools diff old.json new.json --enrich-vulns --kev
    sbom-tools view app.cdx.json --enrich-vulns --fail-on-vuln

  CI/CD pipeline gates:
    sbom-tools diff old.json new.json --fail-on-vuln --fail-on-change
    sbom-tools diff old.json new.json --enrich-vulns --kev --fail-on-kev
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
    sbom-tools vex status app.json --vex vex.json
    sbom-tools vex apply app.json --vex vex.json -O enriched.json

  SBOM operations (enrich, filter, merge):
    sbom-tools enrich app.cdx.json --enrich-vulns --enrich-eol -O enriched.json
    sbom-tools tailor app.cdx.json --exclude-ecosystems npm,pypi
    sbom-tools merge primary.json secondary.json -O combined.json

  Monitoring:
    sbom-tools watch --dir ./sboms --enrich-vulns --exit-on-change
    sbom-tools verify hash app.cdx.json --hash-file app.cdx.json.sha256

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

    /// Skip config-file discovery entirely (ignore any `.sbom-tools.yaml`)
    #[arg(long, global = true, conflicts_with = "config")]
    no_config: bool,

    /// Offline mode: never make network calls; enrichment is served purely from
    /// cache (including TTL-expired entries, with a staleness warning). For
    /// air-gapped environments. Also settable via `SBOM_TOOLS_OFFLINE`
    /// (accepted values, case-insensitive: 1/0, true/false, yes/no, on/off).
    #[arg(
        long,
        global = true,
        env = "SBOM_TOOLS_OFFLINE",
        value_parser = parse_env_bool
    )]
    offline: bool,

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

    /// Flag vulnerabilities in CISA's Known Exploited Vulnerabilities catalog
    #[arg(long = "kev", alias = "enrich-kev")]
    enrich_kev: bool,

    /// Annotate vulnerabilities with FIRST EPSS exploit-probability scores
    #[arg(long = "epss", alias = "enrich-epss")]
    enrich_epss: bool,

    /// Detect stale/abandoned/deprecated dependencies via package registries
    #[arg(long = "enrich-staleness", alias = "staleness")]
    enrich_staleness: bool,

    /// Enrich ML-model components from the HuggingFace Hub (weight hashes from
    /// `siblings[].lfs.sha256`, task from `pipeline_tag`, license, staleness)
    #[arg(long = "huggingface", alias = "enrich-huggingface", alias = "hf")]
    enrich_huggingface: bool,

    /// CISA KEV catalog URL override (test seam; defaults to the public feed)
    #[arg(long = "kev-url", env = "SBOM_TOOLS_KEV_URL", hide = true)]
    kev_url: Option<String>,

    /// FIRST EPSS scores URL override (test seam; defaults to the public feed)
    #[arg(long = "epss-url", env = "SBOM_TOOLS_EPSS_URL", hide = true)]
    epss_url: Option<String>,

    /// HuggingFace Hub API base URL override (test seam; defaults to the public Hub)
    #[arg(
        long = "huggingface-url",
        env = "SBOM_TOOLS_HUGGINGFACE_URL",
        hide = true
    )]
    huggingface_url: Option<String>,

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
            enable_kev: self.enrich_kev,
            enable_epss: self.enrich_epss,
            enable_staleness: self.enrich_staleness,
            enable_huggingface: self.enrich_huggingface,
            kev_url: self.kev_url.clone(),
            epss_url: self.epss_url.clone(),
            huggingface_url: self.huggingface_url.clone(),
            vex_paths: self.vex.clone(),
            ..Default::default()
        }
    }
}

/// Build the effective `EnrichmentConfig`, layering CLI enrichment flags over
/// the `enrichment:` section of the loaded config file.
///
/// The CLI value always wins when any enrichment flag was passed; otherwise the
/// file's enrichment block (if present) supplies the base. When neither layer
/// requested enrichment, the CLI-derived config (disabled) is returned so cache
/// directory / timeout defaults stay intact.
fn seed_enrichment(
    args: &SharedEnrichmentArgs,
    sub: Option<&ArgMatches>,
    app: &AppConfig,
    offline: bool,
) -> EnrichmentConfig {
    let cli = args.to_enrichment_config();
    let cli_touched = cli.enabled
        || cli.enable_eol
        || cli.enable_kev
        || cli.enable_epss
        || cli.enable_staleness
        || cli.enable_huggingface
        || arg_was_set_sub(sub, "vuln_cache_dir")
        || arg_was_set_sub(sub, "vuln_cache_ttl")
        || arg_was_set_sub(sub, "api_timeout")
        || arg_was_set_sub(sub, "refresh_vulns")
        || !cli.vex_paths.is_empty();

    let mut config = match (&app.enrichment, cli_touched) {
        (Some(file), false) => file.clone(),
        _ => cli,
    };
    // The global --offline flag (or config) wins; either layer enabling it is
    // honored so an air-gapped config file can't be silently overridden.
    config.offline = offline || config.offline;
    config
}

/// Build the effective `EnrichmentConfig` for `vex apply|status|filter`,
/// layering the CLI enrichment flags over the config file's `enrichment:`
/// block — the same precedence [`seed_enrichment`] applies for diff/view/
/// query. (`vex` has its own flat argument struct instead of
/// [`SharedEnrichmentArgs`], so it needs a dedicated seeder.)
///
/// `vex export` never routes through here: it exposes no enrichment flags and
/// always runs with enrichment disabled.
fn seed_vex_enrichment(
    args: &VexArgs,
    sub: Option<&ArgMatches>,
    app: &AppConfig,
    offline: bool,
) -> EnrichmentConfig {
    let cli = EnrichmentConfig {
        enabled: args.enrich_vulns,
        provider: "osv".to_string(),
        cache_ttl_hours: args.vuln_cache_ttl,
        max_concurrent: 10,
        cache_dir: args
            .vuln_cache_dir
            .clone()
            .or_else(|| Some(dirs::osv_cache_dir())),
        bypass_cache: args.refresh_vulns,
        timeout_secs: args.api_timeout,
        enable_eol: args.enrich_eol,
        vex_paths: Vec::new(),
        ..Default::default()
    };
    let cli_touched = cli.enabled
        || cli.enable_eol
        || arg_was_set_sub(sub, "vuln_cache_dir")
        || arg_was_set_sub(sub, "vuln_cache_ttl")
        || arg_was_set_sub(sub, "api_timeout")
        || arg_was_set_sub(sub, "refresh_vulns");
    let mut config = match (&app.enrichment, cli_touched) {
        (Some(file), false) => {
            let mut file = file.clone();
            // VEX documents are threaded separately via `VexConfig::vex_paths`
            // (the CLI `--vex` flags); keeping the file's paths here would
            // apply the overlay twice.
            file.vex_paths = Vec::new();
            file
        }
        _ => cli,
    };
    config.offline = offline || config.offline;
    config
}

/// Arguments for the `diff` subcommand
#[derive(Parser)]
#[command(after_help = "EXIT CODES:
    0  Success (changes alone exit 0 without --fail-on-change)
    1  Changes detected (--fail-on-change)
    2  Vulnerabilities introduced (--fail-on-vuln); also CLI usage errors
    3  Operational error (I/O, parse, config, invalid values)
    4  VEX gaps found (--fail-on-vex-gap)
    6  Actively exploited (KEV) vulnerability introduced (--fail-on-kev)
    7  ML performance metric regressed (--fail-on-ml-regression)

EXAMPLES:
    sbom-tools diff old.cdx.json new.cdx.json                    # Interactive TUI
    sbom-tools diff old.json new.json -o summary --fail-on-vuln   # CI gate
    sbom-tools diff old.json new.json --enrich-vulns -o sarif     # Enriched SARIF
    sbom-tools diff old.json new.json --graph-diff --graph-max-depth 3
    sbom-tools diff old.json new.json --enrich-vulns --kev --fail-on-kev
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

    /// Exit with code 6 if any introduced vulnerability is in CISA's KEV catalog
    /// (implies --kev enrichment)
    #[arg(long)]
    fail_on_kev: bool,

    /// Exit with code 1 if any changes detected (without this flag, changes
    /// still exit 0)
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
    #[arg(long, default_value = "low", value_parser = ["low", "medium", "high", "critical"])]
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

    /// Exit with code 4 if introduced vulnerabilities lack VEX statements (CI gate)
    #[arg(long)]
    fail_on_vex_gap: bool,

    /// Exit with code 7 if a supported ML performance metric regresses.
    ///
    /// Higher is better: accuracy, f1, precision, recall, auc, roc_auc, bleu,
    /// rouge. Lower is better: loss, error, perplexity, latency.
    #[arg(long)]
    fail_on_ml_regression: bool,

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

    /// BOM type override (sbom, cbom, aibom). Auto-detected from content if omitted
    #[arg(long, value_name = "TYPE", value_parser = parse_bom_type)]
    bom_type: Option<sbom_tools::BomProfile>,

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
    2  Compliance warnings found (only with --fail-on-warning); also
       command-line parse errors
    3  Operational error (unsupported output format, invalid --as-of /
       --cra-product-class / --cra-sidecar, broken config file, I/O)

    The gate codes (0/1/warning-2) only apply to runs that completed a
    validation — a nonzero exit is only a compliance verdict when the
    expected report was produced.

EXAMPLES:
    sbom-tools validate app.cdx.json                              # NTIA minimum
    sbom-tools validate app.cdx.json --standard cra,eo14028       # Multi-standard
    sbom-tools validate app.cdx.json --standard ntia -o sarif     # SARIF for CI
    sbom-tools validate app.cdx.json --standard ntia -o oscal-json # OSCAL assessment results
    sbom-tools validate app.cdx.json --fail-on-warning            # Strict CI gate")]
struct ValidateArgs {
    /// Path to the SBOM file
    sbom: PathBuf,

    /// Compliance standard(s) to validate against (comma-separated)
    ///
    /// `cra` means CRA Phase 2 (full application, Dec 2027); use
    /// `cra-phase1` (alias `cra-2026`) for the Art. 14 reporting phase.
    /// Aliases: cra-phase2, nist-ssdf/nist_ssdf, eo-14028/eo_14028,
    /// cnsa-2/cnsa_2/cnsa2.0, nist-pqc/nist_pqc,
    /// tr-03183/tr03183/bsi-tr-03183-2,
    /// cra-oss-steward/cra-oss/cra-art24/art24,
    /// eucc-substantial/common-criteria, ai_act/aiact/eu-ai-act,
    /// bsi_ai/bsiai/sbom-for-ai/ai-bom,
    /// cisa/cisa2026/minimum-elements-2026,
    /// pci/pci-dss-6-3-2/pci-dss-4, fsct-3/component-transparency.
    #[arg(
        long,
        value_parser = StandardSelectorParser,
        value_delimiter = ',',
        default_value = "ntia"
    )]
    standard: Vec<StandardSelector>,

    /// Output format (summary, json, sarif, oscal-json; auto = summary)
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

    /// Pin the evaluation clock (RFC 3339, e.g. 2027-01-01T00:00:00Z or
    /// 2027-01-01). Deadline-sensitive checks (CRA Art. 14 readiness, SBOM
    /// age, EUCC certificate expiry) evaluate against this instant instead
    /// of the wall clock — reproducible CI runs.
    #[arg(long, value_name = "DATETIME")]
    as_of: Option<String>,
}

/// Output formats the multi-SBOM commands actually render.
///
/// `diff-multi`, `timeline` and `matrix` have no summary/markdown/SARIF
/// renderers — offering the full [`ReportFormat`] list in `--help` advertised
/// formats that failed at runtime. Restricting the parser here makes `--help`
/// honest and turns a bad value into a clap usage error (exit 2) listing the
/// real choices, instead of an operational error (exit 3) after the SBOMs are
/// parsed. `cli::multi` still gates at runtime, which also covers a format
/// arriving from the config file.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum MultiOutputFormat {
    /// TUI on a TTY, JSON when piped
    Auto,
    /// Interactive TUI display
    Tui,
    /// Structured JSON output
    Json,
}

impl From<MultiOutputFormat> for ReportFormat {
    fn from(value: MultiOutputFormat) -> Self {
        match value {
            MultiOutputFormat::Auto => Self::Auto,
            MultiOutputFormat::Tui => Self::Tui,
            MultiOutputFormat::Json => Self::Json,
        }
    }
}

/// Arguments for the `diff-multi` subcommand
#[derive(Parser)]
#[command(after_help = "EXIT CODES:
    Gates: 1 changes (--fail-on-change), 2 vulnerabilities (--fail-on-vuln),
    4 VEX gaps (--fail-on-vex-gap). Operational errors exit 3.

EXAMPLES:
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
    #[arg(short, long, value_enum, default_value_t = MultiOutputFormat::Auto)]
    output: MultiOutputFormat,

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
    #[arg(long, default_value = "low", value_parser = ["low", "medium", "high", "critical"])]
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

    /// Exit with code 4 if introduced vulnerabilities lack VEX statements
    #[arg(long)]
    fail_on_vex_gap: bool,

    #[command(flatten)]
    enrichment: SharedEnrichmentArgs,
}

/// Arguments for the `timeline` subcommand
#[derive(Parser)]
#[command(after_help = "EXIT CODES:
    Gates: 1 changes (--fail-on-change), 2 vulnerabilities (--fail-on-vuln),
    4 VEX gaps (--fail-on-vex-gap). Operational errors exit 3.

EXAMPLES:
    sbom-tools timeline v1.0.json v1.1.json v1.2.json             # Version evolution
    sbom-tools timeline releases/*.json --enrich-vulns -o json     # Vuln trend report
    sbom-tools timeline *.json --fail-on-vuln --fail-on-change     # CI gate")]
struct TimelineArgs {
    /// Paths to SBOMs in chronological order (oldest first)
    #[arg(required = true)]
    sboms: Vec<PathBuf>,

    /// Output format: tui (interactive, default on a TTY) or json (default when piped)
    #[arg(short, long, value_enum, default_value_t = MultiOutputFormat::Auto)]
    output: MultiOutputFormat,

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
    #[arg(long, default_value = "low", value_parser = ["low", "medium", "high", "critical"])]
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

    /// Exit with code 4 if introduced vulnerabilities lack VEX statements
    #[arg(long)]
    fail_on_vex_gap: bool,

    #[command(flatten)]
    enrichment: SharedEnrichmentArgs,
}

/// Arguments for the `matrix` subcommand
#[derive(Parser)]
#[command(after_help = "EXIT CODES:
    Gates: 1 changes (--fail-on-change), 2 vulnerabilities (--fail-on-vuln),
    4 VEX gaps (--fail-on-vex-gap). Operational errors exit 3.

EXAMPLES:
    sbom-tools matrix v1.json v2.json v3.json                     # NxN comparison
    sbom-tools matrix *.cdx.json --cluster-threshold 0.9 -o json  # Clustering
    sbom-tools matrix *.json --enrich-vulns --fail-on-vuln         # CI with enrichment")]
struct MatrixArgs {
    /// Paths to SBOMs to compare
    #[arg(required = true)]
    sboms: Vec<PathBuf>,

    /// Output format: tui (interactive, default on a TTY) or json (default when piped)
    #[arg(short, long, value_enum, default_value_t = MultiOutputFormat::Auto)]
    output: MultiOutputFormat,

    /// Output file path (stdout if not specified)
    #[arg(short = 'O', long)]
    output_file: Option<PathBuf>,

    /// Fuzzy matching preset
    #[arg(long, value_enum, default_value_t = FuzzyPreset::Balanced)]
    fuzzy_preset: FuzzyPreset,

    /// Similarity threshold for clustering (finite, 0.0-1.0)
    #[arg(long, default_value = "0.8", value_parser = parse_cluster_threshold)]
    cluster_threshold: f64,

    /// Enable graph-aware diffing for matrix comparison
    #[arg(long)]
    graph_diff: bool,

    /// Maximum depth for graph analysis (0 = unlimited, requires --graph-diff)
    #[arg(long, default_value = "0")]
    graph_max_depth: u32,

    /// Minimum impact level for graph diff output (low, medium, high, critical)
    #[arg(long, default_value = "low", value_parser = ["low", "medium", "high", "critical"])]
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

    /// Exit with code 4 if introduced vulnerabilities lack VEX statements
    #[arg(long)]
    fail_on_vex_gap: bool,

    #[command(flatten)]
    enrichment: SharedEnrichmentArgs,
}

/// Arguments for the `quality` subcommand
#[derive(Parser)]
#[command(after_help = "EXIT CODES:
    0  Score meets --min-score (or no threshold) and, with --fail-on-noncompliant, the SBOM is compliant
    1  Overall score below --min-score, OR (with --fail-on-noncompliant) the SBOM is non-compliant
    2  Command-line parse errors
    3  Operational error (unsupported output format, invalid --as-of /
       --cra-product-class / --cra-sidecar, broken config file, I/O)

    The gate codes (0/1) only apply to runs that completed an assessment —
    a nonzero exit is only a quality/compliance verdict when the expected
    report was produced. N/A runs (e.g. --profile ai-readiness on an SBOM
    without ML components) never trip either gate.

EXAMPLES:
    sbom-tools quality app.cdx.json                                # Score overview
    sbom-tools quality app.cdx.json --profile security --metrics   # Detailed metrics
    sbom-tools quality app.cdx.json --min-score 70 -o json         # CI gate with export
    sbom-tools quality app.cdx.json --profile cra --fail-on-noncompliant  # gate on compliance
    sbom-tools quality app.cdx.json --recommendations              # Improvement suggestions")]
struct QualityArgs {
    /// Path to the SBOM file
    sbom: PathBuf,

    /// Scoring profile
    ///
    /// Aliases: license (license-compliance), cyber-resilience (cra),
    /// tr-03183/tr03183/bsi-tr-03183-2 (bsi), full (comprehensive),
    /// cryptographic (cbom), ai_readiness (ai-readiness).
    #[arg(long, value_enum, ignore_case = true, default_value = "standard")]
    profile: ScoringProfile,

    /// Output format (summary, json, sarif, sbomqs-json; auto = summary).
    /// sbomqs-json emits interlynk-io/sbomqs `score --json`-shaped 0-10
    /// scores for side-by-side comparison with sbomqs output.
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

    /// Exit non-zero when the SBOM is non-compliant with the report's
    /// compliance standard (the score gate `--min-score` ignores compliance).
    #[arg(long)]
    fail_on_noncompliant: bool,

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

    /// Pin the evaluation clock (RFC 3339, e.g. 2027-01-01T00:00:00Z or
    /// 2027-01-01). Deadline-sensitive compliance checks embedded in the
    /// quality report (CRA Art. 14 readiness, SBOM age, EUCC certificate
    /// expiry) evaluate against this instant instead of the wall clock —
    /// reproducible CI runs, mirroring `validate --as-of`.
    #[arg(long, value_name = "DATETIME")]
    as_of: Option<String>,

    #[command(flatten)]
    enrichment: SharedEnrichmentArgs,
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

    /// Output format (auto, table, json, csv, summary); unsupported formats error
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

    /// Output format: auto, summary (human), or json (NDJSON streaming);
    /// other formats error
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

    /// Manage the enrichment cache (status, warm, clear, export, import)
    #[cfg(feature = "enrichment")]
    Cache {
        #[command(subcommand)]
        action: cli::CacheAction,
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

    /// Convert an SBOM to another format (e.g. SPDX → CycloneDX)
    Convert(ConvertArgs),

    /// Generate CRA technical-documentation dossier (Annex V templates)
    CraDocs(CraDocsArgs),

    /// Show curated CRA standards-watch catalogue (prEN, BSI, CSAF, EUCC, …)
    CraStandardsWatch(CraStandardsWatchArgs),

    /// Generate a man page and print it to stdout
    Man,
}

impl Commands {
    /// Whether this command seeds a per-command config from the loaded
    /// `AppConfig`. Meta commands (config management, shell completions, man
    /// page, schema generation) don't, so a broken or missing config file must
    /// never block them — they get a lenient (unvalidated) load instead. Cache
    /// management is likewise config-independent (it only touches the on-disk
    /// cache) and must stay usable for recovery even with a broken config.
    const fn consumes_config(&self) -> bool {
        // Cache management is config-independent (it only touches the on-disk
        // cache) and must stay usable for recovery even with a broken config.
        #[cfg(feature = "enrichment")]
        if matches!(self, Self::Cache { .. }) {
            return false;
        }
        !matches!(
            self,
            Self::Config { .. } | Self::Completions { .. } | Self::ConfigSchema { .. } | Self::Man
        )
    }
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
    /// Load + validate the config and print the effective merged settings
    Check,
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
    /// Verify ML-model weight files against the hashes recorded in an SBOM
    ModelWeights {
        /// SBOM file describing the model(s)
        file: PathBuf,
        /// Directory holding the weight files (supports the HuggingFace cache
        /// snapshot layout where blobs are named by their SHA-256)
        #[arg(long = "model-dir")]
        model_dir: PathBuf,
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
    /// Validate a versioned pipeline shard receipt
    Receipt { file: PathBuf },
    /// Aggregate receipts from a JSON file or directory using a strict policy JSON file.
    ReceiptAggregate {
        receipts: PathBuf,
        #[arg(long)]
        policy: PathBuf,
    },
    /// Generate an unsigned receipt from a strict, digest-free JSON descriptor.
    ReceiptGenerate {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Generate an unsigned aggregate policy from strict manifest and context JSON.
    ReceiptPolicyGenerate {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        context: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Generate a target-scoped receipt from a checked-in job manifest and CI outcomes.
    ReceiptJob {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        context: PathBuf,
        #[arg(long)]
        outcome: Vec<String>,
        #[arg(long)]
        runner_os: Option<String>,
        #[arg(long)]
        runner_arch: Option<String>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Write a strict hosted receipt context from CI-provided values.
    ReceiptContext {
        #[arg(long)]
        repository: String,
        #[arg(long)]
        commit_sha: String,
        #[arg(long)]
        event_name: String,
        #[arg(long)]
        ref_name: String,
        #[arg(long)]
        default_branch: String,
        #[arg(long)]
        head_repository: Option<String>,
        #[arg(long)]
        output: PathBuf,
    },
}

/// Arguments for the `license-check` subcommand
#[derive(Parser)]
#[command(after_help = "EXIT CODES:
    0    License policy passed
    3    Operational error (unreadable SBOM, parse failure, invalid policy file)
    5    License policy violations (denied licenses; review-needed under --strict;
         propagation conflicts under --check-propagation)

EXAMPLES:
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

/// Arguments for the `convert` subcommand
#[derive(Parser)]
#[command(after_help = "EXAMPLES:
    sbom-tools convert app.spdx.json --to cyclonedx                # SPDX → CycloneDX (stdout)
    sbom-tools convert app.cdx.json  --to spdx                     # CycloneDX → SPDX 2.3
    sbom-tools convert app.spdx.json --to cyclonedx -O out.cdx.json
    sbom-tools convert app.cdx.json --to cyclonedx --preserve      # Keep format-specific blocks

NOTE: Supported targets are --to cyclonedx (1.7 JSON) and --to spdx (2.3 JSON).
A fidelity report (synthesized/dropped fields) is written to stderr.")]
struct ConvertArgs {
    /// SBOM file to convert
    file: PathBuf,

    /// Target format: cyclonedx (1.7 JSON) or spdx (2.3 JSON)
    #[arg(long = "to")]
    to: String,

    /// Output file (stdout if not specified)
    // -O like every sibling; -o here previously meant the output FILE while
    // meaning output FORMAT everywhere else, so `-o json` silently wrote a
    // file literally named "json".
    #[arg(short = 'O', long)]
    output_file: Option<PathBuf>,

    /// Capture verbatim source JSON before conversion so format-specific blocks
    /// (cryptoProperties, evidence) are spliced back where present
    #[arg(long)]
    preserve: bool,
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

    /// Overwrite existing dossier files (by default a re-run refuses to
    /// clobber hand-completed documents)
    #[arg(long)]
    force: bool,
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

/// Clap value parser for `--standard`.
///
/// Trims surrounding whitespace before matching so quoted comma lists like
/// `--standard "ntia, cra"` parse (the pre-typed hand parser applied
/// `str::trim`, and the config-file path still does via `FromStr`), then
/// delegates to [`StandardSelector`]'s alias-aware, case-insensitive
/// `FromStr`. `possible_values` forwards the ValueEnum table so `--help`
/// enumeration, shell completions, and clap's invalid-value error (with the
/// valid-value list) are identical to the plain `value_enum` parser.
#[derive(Clone)]
struct StandardSelectorParser;

impl clap::builder::TypedValueParser for StandardSelectorParser {
    type Value = StandardSelector;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> std::result::Result<Self::Value, clap::Error> {
        use clap::error::{ContextKind, ContextValue, ErrorKind};
        let raw = value
            .to_str()
            .ok_or_else(|| clap::Error::new(ErrorKind::InvalidUtf8).with_cmd(cmd))?;
        raw.trim().parse::<StandardSelector>().map_err(|_| {
            let mut err = clap::Error::new(ErrorKind::InvalidValue).with_cmd(cmd);
            if let Some(arg) = arg {
                err.insert(
                    ContextKind::InvalidArg,
                    ContextValue::String(arg.to_string()),
                );
            }
            err.insert(ContextKind::InvalidValue, ContextValue::String(raw.into()));
            err.insert(
                ContextKind::ValidValue,
                ContextValue::Strings(
                    StandardSelector::value_variants()
                        .iter()
                        .map(|v| v.canonical_name().to_string())
                        .collect(),
                ),
            );
            err
        })
    }

    fn possible_values(
        &self,
    ) -> Option<Box<dyn Iterator<Item = clap::builder::PossibleValue> + '_>> {
        Some(Box::new(
            StandardSelector::value_variants()
                .iter()
                .filter_map(clap::ValueEnum::to_possible_value),
        ))
    }
}

/// The config-file `output.format` only participates in a command's format
/// resolution when that command actually supports it.
///
/// A global default aimed at `diff`/`view` (e.g. `format: tui` or `html`)
/// must not hard-fail a bare `validate`/`quality` invocation the user never
/// asked to render in that format — it silently degrades to the command
/// default instead (with a debug note). An **explicit** `-o` flag is
/// unaffected: it wins resolution here and is still hard-gated in the
/// command handler.
fn supported_config_format(
    command: &str,
    cli_format_was_set: bool,
    config_format: ReportFormat,
    supported: &[ReportFormat],
) -> Option<ReportFormat> {
    if cli_format_was_set {
        // Explicit -o wins; the config value is never consulted.
        return None;
    }
    if supported.contains(&config_format) {
        return Some(config_format);
    }
    tracing::debug!(
        "config output.format '{config_format}' is not supported by `sbom-tools {command}`; \
         falling back to the command default"
    );
    None
}

/// Parse a boolean environment/flag value leniently.
///
/// `SBOM_TOOLS_OFFLINE=1` (the natural spelling) used to hard-fail every
/// invocation because clap's default bool parser only accepts `true`/`false`.
/// Accepts 1/0, true/false, yes/no, on/off — case-insensitively. An empty
/// value (`SBOM_TOOLS_OFFLINE=`) counts as unset/false.
fn parse_env_bool(s: &str) -> std::result::Result<bool, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "y" | "on" => Ok(true),
        "" | "0" | "false" | "no" | "n" | "off" => Ok(false),
        other => Err(format!(
            "invalid boolean value '{other}' \
             (accepted, case-insensitive: 1/0, true/false, yes/no, on/off)"
        )),
    }
}

/// Parse and validate `--cluster-threshold`: a finite similarity in 0.0..=1.0.
///
/// NaN, infinities, and out-of-range values used to be accepted silently and
/// produced nonsensical clustering.
fn parse_cluster_threshold(s: &str) -> std::result::Result<f64, String> {
    let value: f64 = s
        .parse()
        .map_err(|e| format!("invalid number '{s}': {e}"))?;
    if !value.is_finite() || !(0.0..=1.0).contains(&value) {
        return Err(format!(
            "cluster threshold must be a finite value between 0.0 and 1.0, got '{s}'"
        ));
    }
    Ok(value)
}

/// Parse and validate `--bom-type` at the CLI boundary.
///
/// An unrecognized value used to be silently dropped (falling back to content
/// auto-detection); it is now a hard error listing the valid spellings.
fn parse_bom_type(s: &str) -> std::result::Result<sbom_tools::BomProfile, String> {
    sbom_tools::BomProfile::from_str_opt(s).ok_or_else(|| {
        format!("invalid BOM type '{s}' (valid values: sbom, cbom, aibom; aliases: ai, mlbom)")
    })
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

/// Restore the default `SIGPIPE` disposition.
///
/// Rust's runtime ignores `SIGPIPE`, so writes to a closed pipe surface as
/// `EPIPE` errors — which `println!`/`generate` turn into a panic (exit 101)
/// for pipelines like `sbom-tools completions bash | head`. Restoring
/// `SIG_DFL` makes the process terminate quietly (conventional exit 141),
/// matching standard CLI behaviour.
#[cfg(unix)]
fn reset_sigpipe() {
    unsafe extern "C" {
        fn signal(signum: std::ffi::c_int, handler: usize) -> usize;
    }
    /// `SIGPIPE` is 13 on every supported Unix (Linux, macOS, BSDs).
    const SIGPIPE: std::ffi::c_int = 13;
    /// `SIG_DFL` is 0 on every supported Unix.
    const SIG_DFL: usize = 0;
    // SAFETY: setting SIGPIPE back to its default disposition cannot violate
    // memory safety; this runs at the top of main() before any other threads
    // are spawned.
    unsafe {
        signal(SIGPIPE, SIG_DFL);
    }
}

fn main() {
    #[cfg(unix)]
    reset_sigpipe();

    // Central operational-error exit: every anyhow error (I/O, parse, config,
    // unsupported output format, invalid flag values) leaves with code 3, so
    // it can never collide with gate codes (1 = verdict gates, 2 = clap usage
    // errors and diff/view --fail-on-vuln, 4 = --fail-on-vex-gap, 5 =
    // license-check denial, 6 = --fail-on-kev, 7 = diff ML regression).
    if let Err(err) = run() {
        // Mirror the format the default `fn main() -> Result` termination
        // prints: message plus the "Caused by:" chain.
        eprintln!("Error: {err:?}");
        std::process::exit(3);
    }
}

fn run() -> Result<()> {
    let matches = Cli::command().get_matches();
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());

    // Initialize logging. ANSI escapes only when stderr is a live terminal
    // and neither --no-color nor the NO_COLOR convention (set to a non-empty
    // value) asked for monochrome — piped/redirected stderr stays clean.
    let ansi = std::io::stderr().is_terminal()
        && !cli.no_color
        && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty());
    let log_level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| log_level.to_string()),
        ))
        // Logs go to stderr so machine-readable report output on stdout
        // (`-o json`/`sarif`/`ndjson`) stays parseable when piped or redirected.
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_ansi(ansi)
                .with_writer(std::io::stderr),
        )
        .init();

    // Load the file-based config once, up front, so every command can use it
    // as the base layer that explicit CLI flags override. Consuming commands
    // get a strict (validated) load so a broken file fails loudly; meta
    // commands (config management, completions, man, schema) get a lenient load
    // so they are never blocked by an unrelated invalid config.
    let effective = if cli.command.consumes_config() {
        EffectiveConfig::load(cli.config.as_deref(), cli.no_config)?
    } else {
        EffectiveConfig::load_lenient(cli.config.as_deref(), cli.no_config)
    };
    let app = effective.into_app_config();

    // Resolve offline mode once: the global --offline flag (or
    // SBOM_TOOLS_OFFLINE), OR the config file's enrichment.offline. Setting the
    // process-wide switch here makes every code path — including the cache
    // subcommand and watch loop — refuse network calls and serve stale cache.
    let offline = cli.offline || app.enrichment.as_ref().is_some_and(|e| e.offline);
    #[cfg(feature = "enrichment")]
    sbom_tools::enrichment::source::set_offline(offline);

    // Per-subcommand argument matches, used to detect which CLI flags were set
    // explicitly (vs. left at their clap default).
    let sub_matches = matches.subcommand().map(|(_, m)| m);

    // Dispatch to command handlers
    match cli.command {
        Commands::Diff(args) => {
            let sm = sub_matches;
            let fail_on_kev = resolve_bool(args.fail_on_kev, app.behavior.fail_on_kev);
            let mut enrichment = seed_enrichment(&args.enrichment, sm, &app, offline);
            // --fail-on-kev is meaningless without KEV data, so it implies --kev.
            if fail_on_kev {
                enrichment.enable_kev = true;
            }

            let config = DiffConfig {
                paths: DiffPaths {
                    old: args.old,
                    new: args.new,
                },
                output: OutputConfig {
                    format: resolve(
                        args.output,
                        arg_was_set_sub(sm, "output"),
                        Some(app.output.format),
                    ),
                    file: args.output_file,
                    report_types: args.reports,
                    no_color: resolve_bool(cli.no_color, app.output.no_color),
                    streaming: sbom_tools::config::StreamingConfig {
                        threshold_bytes: args.streaming_threshold * 1024 * 1024,
                        force: args.streaming,
                        disabled: false,
                        stream_stdin: true,
                    },
                    export_template: cli.export_template.clone(),
                },
                matching: MatchingConfig {
                    fuzzy_preset: resolve(
                        args.fuzzy_preset.clone(),
                        arg_was_set_sub(sm, "fuzzy_preset"),
                        Some(app.matching.fuzzy_preset.clone()),
                    ),
                    threshold: app.matching.threshold,
                    include_unchanged: resolve_bool(
                        args.include_unchanged,
                        app.matching.include_unchanged,
                    ),
                },
                filtering: FilterConfig {
                    only_changes: resolve_bool(args.only_changes, app.filtering.only_changes),
                    min_severity: args.severity.or_else(|| app.filtering.min_severity.clone()),
                    exclude_vex_resolved: resolve_bool(
                        args.exclude_vex_resolved,
                        app.filtering.exclude_vex_resolved,
                    ),
                    fail_on_vex_gap: resolve_bool(
                        args.fail_on_vex_gap,
                        app.filtering.fail_on_vex_gap,
                    ),
                    fail_on_ml_regression: resolve_bool(
                        args.fail_on_ml_regression,
                        app.filtering.fail_on_ml_regression,
                    ),
                },
                behavior: BehaviorConfig {
                    fail_on_vuln: resolve_bool(args.fail_on_vuln, app.behavior.fail_on_vuln),
                    fail_on_kev,
                    fail_on_change: resolve_bool(args.fail_on_change, app.behavior.fail_on_change),
                    quiet: resolve_bool(cli.quiet, app.behavior.quiet),
                    explain_matches: resolve_bool(
                        args.explain_matches,
                        app.behavior.explain_matches,
                    ),
                    recommend_threshold: resolve_bool(
                        args.recommend_threshold,
                        app.behavior.recommend_threshold,
                    ),
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
                    app.graph_diff.clone()
                },
                rules: MatchingRulesPathConfig {
                    rules_file: args
                        .enrichment
                        .matching_rules
                        .or_else(|| app.rules.rules_file.clone()),
                    dry_run: resolve_bool(args.dry_run_rules, app.rules.dry_run),
                },
                ecosystem_rules: EcosystemRulesConfig {
                    config_file: args
                        .ecosystem_rules
                        .or_else(|| app.ecosystem_rules.config_file.clone()),
                    disabled: resolve_bool(args.no_ecosystem_rules, app.ecosystem_rules.disabled),
                    detect_typosquats: resolve_bool(
                        args.detect_typosquats,
                        app.ecosystem_rules.detect_typosquats,
                    ),
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
            let sm = sub_matches;
            let enrichment = seed_enrichment(&args.enrichment, sm, &app, offline);

            let config = ViewConfig {
                sbom_path: args.sbom,
                output: OutputConfig {
                    format: resolve(
                        args.output,
                        arg_was_set_sub(sm, "output"),
                        Some(app.output.format),
                    ),
                    file: args.output_file,
                    report_types: ReportType::All,
                    no_color: resolve_bool(cli.no_color, app.output.no_color),
                    streaming: sbom_tools::config::StreamingConfig::default(),
                    export_template: cli.export_template.clone(),
                },
                validate_ntia: args.validate_ntia,
                min_severity: args.severity.or_else(|| app.filtering.min_severity.clone()),
                vulnerable_only: args.vulnerable_only,
                ecosystem_filter: args.ecosystem,
                fail_on_vuln: resolve_bool(args.fail_on_vuln, app.behavior.fail_on_vuln),
                bom_profile: args.bom_type,
                enrichment,
                cra_sidecar_path: args
                    .cra_sidecar
                    .clone()
                    .or_else(|| app.compliance.cra_sidecar.clone()),
                cra_product_class: args
                    .cra_product_class
                    .clone()
                    .or_else(|| app.compliance.cra_product_class.clone()),
            };
            let exit_code = cli::run_view(config)?;
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
            Ok(())
        }

        Commands::Validate(args) => {
            let sm = sub_matches;
            // Standards: explicit --standard > config `compliance.standards`
            // > built-in default (ntia). Config values go through the same
            // alias-aware parser as the CLI flag.
            let standards: Vec<StandardSelector> =
                if arg_was_set_sub(sm, "standard") || app.compliance.standards.is_empty() {
                    args.standard
                } else {
                    app.compliance
                        .standards
                        .iter()
                        .map(|s| {
                            s.parse().map_err(|e| {
                                anyhow::anyhow!("invalid `compliance.standards` in config: {e}")
                            })
                        })
                        .collect::<Result<_>>()?
                };
            let output_was_set = arg_was_set_sub(sm, "output");
            let output = resolve(
                args.output,
                output_was_set,
                supported_config_format(
                    "validate",
                    output_was_set,
                    app.output.format,
                    cli::VALIDATE_OUTPUT_FORMATS,
                ),
            );
            let exit_code = cli::run_validate(
                args.sbom,
                standards,
                output,
                args.output_file,
                resolve_bool(args.fail_on_warning, app.compliance.fail_on_warning),
                args.summary,
                args.cra_sidecar
                    .or_else(|| app.compliance.cra_sidecar.clone()),
                args.cra_product_class
                    .or_else(|| app.compliance.cra_product_class.clone()),
                args.as_of.as_deref(),
            )?;
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
            Ok(())
        }

        Commands::DiffMulti(args) => {
            let sm = sub_matches;
            let enrichment = seed_enrichment(&args.enrichment, sm, &app, offline);
            let config = MultiDiffConfig {
                baseline: args.baseline,
                targets: args.targets,
                output: OutputConfig {
                    format: resolve(
                        args.output.into(),
                        arg_was_set_sub(sm, "output"),
                        Some(app.output.format),
                    ),
                    file: args.output_file,
                    no_color: resolve_bool(cli.no_color, app.output.no_color),
                    export_template: cli.export_template.clone(),
                    ..Default::default()
                },
                matching: MatchingConfig {
                    fuzzy_preset: resolve(
                        args.fuzzy_preset.clone(),
                        arg_was_set_sub(sm, "fuzzy_preset"),
                        Some(app.matching.fuzzy_preset.clone()),
                    ),
                    include_unchanged: resolve_bool(
                        args.include_unchanged,
                        app.matching.include_unchanged,
                    ),
                    threshold: app.matching.threshold,
                },
                filtering: FilterConfig {
                    min_severity: args.severity.or_else(|| app.filtering.min_severity.clone()),
                    exclude_vex_resolved: resolve_bool(
                        args.exclude_vex_resolved,
                        app.filtering.exclude_vex_resolved,
                    ),
                    fail_on_vex_gap: resolve_bool(
                        args.fail_on_vex_gap,
                        app.filtering.fail_on_vex_gap,
                    ),
                    ..Default::default()
                },
                behavior: BehaviorConfig {
                    fail_on_vuln: resolve_bool(args.fail_on_vuln, app.behavior.fail_on_vuln),
                    fail_on_change: resolve_bool(args.fail_on_change, app.behavior.fail_on_change),
                    quiet: resolve_bool(cli.quiet, app.behavior.quiet),
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
                    app.graph_diff.clone()
                },
                rules: MatchingRulesPathConfig {
                    rules_file: args
                        .enrichment
                        .matching_rules
                        .or_else(|| app.rules.rules_file.clone()),
                    ..Default::default()
                },
                ecosystem_rules: app.ecosystem_rules.clone(),
                enrichment,
            };
            let exit_code = cli::run_diff_multi(config)?;
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
            Ok(())
        }

        Commands::Timeline(args) => {
            let sm = sub_matches;
            let enrichment = seed_enrichment(&args.enrichment, sm, &app, offline);
            let config = TimelineConfig {
                sbom_paths: args.sboms,
                output: OutputConfig {
                    format: resolve(
                        args.output.into(),
                        arg_was_set_sub(sm, "output"),
                        Some(app.output.format),
                    ),
                    file: args.output_file,
                    no_color: resolve_bool(cli.no_color, app.output.no_color),
                    export_template: cli.export_template.clone(),
                    ..Default::default()
                },
                matching: MatchingConfig {
                    fuzzy_preset: resolve(
                        args.fuzzy_preset.clone(),
                        arg_was_set_sub(sm, "fuzzy_preset"),
                        Some(app.matching.fuzzy_preset.clone()),
                    ),
                    threshold: app.matching.threshold,
                    ..Default::default()
                },
                filtering: FilterConfig {
                    min_severity: args.severity.or_else(|| app.filtering.min_severity.clone()),
                    exclude_vex_resolved: resolve_bool(
                        args.exclude_vex_resolved,
                        app.filtering.exclude_vex_resolved,
                    ),
                    fail_on_vex_gap: resolve_bool(
                        args.fail_on_vex_gap,
                        app.filtering.fail_on_vex_gap,
                    ),
                    ..Default::default()
                },
                behavior: BehaviorConfig {
                    fail_on_vuln: resolve_bool(args.fail_on_vuln, app.behavior.fail_on_vuln),
                    fail_on_change: resolve_bool(args.fail_on_change, app.behavior.fail_on_change),
                    quiet: resolve_bool(cli.quiet, app.behavior.quiet),
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
                    app.graph_diff.clone()
                },
                rules: MatchingRulesPathConfig {
                    rules_file: args
                        .enrichment
                        .matching_rules
                        .or_else(|| app.rules.rules_file.clone()),
                    ..Default::default()
                },
                ecosystem_rules: app.ecosystem_rules.clone(),
                enrichment,
            };
            let exit_code = cli::run_timeline(config)?;
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
            Ok(())
        }

        Commands::Matrix(args) => {
            let sm = sub_matches;
            let enrichment = seed_enrichment(&args.enrichment, sm, &app, offline);
            let config = MatrixConfig {
                sbom_paths: args.sboms,
                output: OutputConfig {
                    format: resolve(
                        args.output.into(),
                        arg_was_set_sub(sm, "output"),
                        Some(app.output.format),
                    ),
                    file: args.output_file,
                    no_color: resolve_bool(cli.no_color, app.output.no_color),
                    export_template: cli.export_template.clone(),
                    ..Default::default()
                },
                matching: MatchingConfig {
                    fuzzy_preset: resolve(
                        args.fuzzy_preset.clone(),
                        arg_was_set_sub(sm, "fuzzy_preset"),
                        Some(app.matching.fuzzy_preset.clone()),
                    ),
                    threshold: app.matching.threshold,
                    ..Default::default()
                },
                cluster_threshold: args.cluster_threshold,
                filtering: FilterConfig {
                    min_severity: args.severity.or_else(|| app.filtering.min_severity.clone()),
                    exclude_vex_resolved: resolve_bool(
                        args.exclude_vex_resolved,
                        app.filtering.exclude_vex_resolved,
                    ),
                    fail_on_vex_gap: resolve_bool(
                        args.fail_on_vex_gap,
                        app.filtering.fail_on_vex_gap,
                    ),
                    ..Default::default()
                },
                behavior: BehaviorConfig {
                    fail_on_vuln: resolve_bool(args.fail_on_vuln, app.behavior.fail_on_vuln),
                    fail_on_change: resolve_bool(args.fail_on_change, app.behavior.fail_on_change),
                    quiet: resolve_bool(cli.quiet, app.behavior.quiet),
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
                    app.graph_diff.clone()
                },
                rules: MatchingRulesPathConfig {
                    rules_file: args
                        .enrichment
                        .matching_rules
                        .or_else(|| app.rules.rules_file.clone()),
                    ..Default::default()
                },
                ecosystem_rules: app.ecosystem_rules.clone(),
                enrichment,
            };
            let exit_code = cli::run_matrix(config)?;
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
            Ok(())
        }

        Commands::Quality(args) => {
            let sm = sub_matches;
            let output_was_set = arg_was_set_sub(sm, "output");
            let output = resolve(
                args.output,
                output_was_set,
                supported_config_format(
                    "quality",
                    output_was_set,
                    app.output.format,
                    cli::QUALITY_OUTPUT_FORMATS,
                ),
            );
            // Profile: explicit --profile > config `compliance.profile` >
            // built-in default (standard). Config values go through the same
            // alias-aware parser as the CLI flag.
            let profile = if arg_was_set_sub(sm, "profile") {
                args.profile
            } else if let Some(ref p) = app.compliance.profile {
                p.parse()
                    .map_err(|e| anyhow::anyhow!("invalid `compliance.profile` in config: {e}"))?
            } else {
                args.profile
            };
            let enrichment = seed_enrichment(&args.enrichment, sm, &app, offline);
            let exit_code = cli::run_quality(
                args.sbom,
                profile,
                output,
                args.output_file,
                args.recommendations,
                args.metrics,
                args.min_score.or(app.compliance.min_score),
                resolve_bool(
                    args.fail_on_noncompliant,
                    app.compliance.fail_on_noncompliant,
                ),
                resolve_bool(cli.no_color, app.output.no_color),
                args.cra_sidecar
                    .or_else(|| app.compliance.cra_sidecar.clone()),
                args.cra_product_class
                    .or_else(|| app.compliance.cra_product_class.clone()),
                args.as_of,
                enrichment,
            )?;
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
            Ok(())
        }

        Commands::Query(args) => {
            let sm = sub_matches;
            // Split positional args: first arg is pattern if it doesn't look like a file,
            // otherwise all args are file paths
            let (pattern, sbom_paths) = split_query_args(&args.args);

            if sbom_paths.is_empty() {
                anyhow::bail!("No SBOM files specified. Usage: sbom-tools query [PATTERN] FILE...");
            }

            // Route through the shared seeder so the config file's `enrichment:`
            // block applies (ValueSource precedence) and the global --offline
            // flag is carried into the config. seed_enrichment already folds
            // `offline` in, so no double-setting is needed below.
            let enrichment = seed_enrichment(&args.enrichment, sm, &app, offline);

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
                    format: resolve(
                        args.output,
                        arg_was_set_sub(sm, "output"),
                        Some(app.output.format),
                    ),
                    file: args.output_file,
                    report_types: ReportType::All,
                    no_color: resolve_bool(cli.no_color, app.output.no_color),
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
            // Argument matches of the nested vex sub-subcommand
            // (apply/status/filter/export), for CLI-explicitness detection.
            let vex_sub = sub_matches.and_then(|m| m.subcommand()).map(|(_, m)| m);
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

            // `vex export` exposes no enrichment flags (it exports existing
            // state), so it always runs with enrichment disabled. The other
            // vex actions honor the config file's `enrichment:` block exactly
            // like diff/view/query, with explicit CLI flags winning.
            let enrichment = if matches!(cli_action, cli::VexAction::Export(_)) {
                EnrichmentConfig {
                    enabled: false,
                    provider: "osv".to_string(),
                    cache_ttl_hours: args.vuln_cache_ttl,
                    max_concurrent: 10,
                    cache_dir: args
                        .vuln_cache_dir
                        .clone()
                        .or_else(|| Some(dirs::osv_cache_dir())),
                    bypass_cache: args.refresh_vulns,
                    timeout_secs: args.api_timeout,
                    enable_eol: false,
                    vex_paths: Vec::new(), // VEX paths handled separately
                    offline,
                    ..Default::default()
                }
            } else {
                seed_vex_enrichment(&args, vex_sub, &app, offline)
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
            let sm = sub_matches;
            let enrichment = seed_enrichment(&args.enrichment, sm, &app, offline);

            let config = WatchConfig {
                watch_dirs: args.dirs,
                poll_interval: parse_duration(&args.interval)?,
                enrich_interval: parse_duration(&args.enrich_interval)?,
                debounce: parse_duration(&args.debounce)?,
                output: OutputConfig {
                    format: resolve(
                        args.output,
                        arg_was_set_sub(sm, "output"),
                        Some(app.output.format),
                    ),
                    file: args.output_file,
                    report_types: ReportType::All,
                    no_color: resolve_bool(cli.no_color, app.output.no_color),
                    streaming: sbom_tools::config::StreamingConfig::default(),
                    export_template: None,
                },
                enrichment,
                webhook_url: args.webhook,
                exit_on_change: args.exit_on_change,
                max_snapshots: args.max_snapshots,
                quiet: resolve_bool(cli.quiet, app.behavior.quiet),
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
                // Strict like every consuming command: an explicit --config
                // that is missing or unparseable is an error, never a silent
                // fallback to a different discovered file or defaults.
                let (config, loaded_from) = if cli.no_config {
                    (AppConfig::default(), None)
                } else {
                    sbom_tools::config::load_strict(cli.config.as_deref())
                        .context("failed to load config")?
                };
                if let Some(path) = &loaded_from {
                    eprintln!("# Loaded from: {}", path.display());
                } else if cli.no_config {
                    eprintln!("# Config discovery disabled (--no-config); showing defaults");
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
                    Some(path) => {
                        if cli.config.is_some() && !path.exists() {
                            anyhow::bail!("config file not found: {}", path.display());
                        }
                        eprintln!("Active config file: {}", path.display());
                    }
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
            ConfigAction::Check => {
                // Strict load: surfaces a hard error (with field-level detail)
                // when the discovered config fails validation.
                let checked = EffectiveConfig::load(cli.config.as_deref(), cli.no_config)?;
                match checked.loaded_from() {
                    Some(path) => eprintln!("# Valid. Loaded from: {}", path.display()),
                    None if cli.no_config => eprintln!(
                        "# Valid. Config discovery disabled (--no-config); showing defaults"
                    ),
                    None => eprintln!("# Valid. No config file found; showing defaults"),
                }
                let config = checked.into_app_config();
                let yaml =
                    serde_yaml_ng::to_string(&config).context("failed to serialize config")?;
                print!("{yaml}");
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
                VerifyAction::ModelWeights {
                    file,
                    model_dir,
                    format,
                } => cli::VerifyAction::ModelWeights {
                    file,
                    model_dir,
                    format: format.as_str().to_string(),
                },
                VerifyAction::Receipt { file } => cli::VerifyAction::Receipt { file },
                VerifyAction::ReceiptAggregate { receipts, policy } => {
                    cli::VerifyAction::ReceiptAggregate { receipts, policy }
                }
                VerifyAction::ReceiptGenerate { input, output } => {
                    cli::VerifyAction::ReceiptGenerate { input, output }
                }
                VerifyAction::ReceiptPolicyGenerate {
                    manifest,
                    context,
                    output,
                } => cli::VerifyAction::ReceiptPolicyGenerate {
                    manifest,
                    context,
                    output,
                },
                VerifyAction::ReceiptJob {
                    manifest,
                    context,
                    outcome,
                    runner_os,
                    runner_arch,
                    output,
                } => cli::VerifyAction::ReceiptJob {
                    manifest,
                    context,
                    outcome,
                    runner_os,
                    runner_arch,
                    output,
                },
                VerifyAction::ReceiptContext {
                    repository,
                    commit_sha,
                    event_name,
                    ref_name,
                    default_branch,
                    head_repository,
                    output,
                } => cli::VerifyAction::ReceiptContext {
                    repository,
                    commit_sha,
                    event_name,
                    ref_name,
                    default_branch,
                    head_repository,
                    output,
                },
            };

            let exit_code = cli::run_verify(cli_action, cli.quiet)?;
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
            Ok(())
        }

        #[cfg(feature = "enrichment")]
        Commands::Cache { action } => {
            let exit_code = cli::run_cache(action, cli.quiet)?;
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
            // Same layering as diff/view/query: the config file's `enrichment:`
            // block is the base and explicit CLI flags win.
            let enrichment = seed_enrichment(&args.enrichment, sub_matches, &app, offline);

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

        Commands::Convert(args) => {
            let exit_code = cli::run_convert(
                &args.file,
                &args.to,
                args.output_file.as_ref(),
                args.preserve,
                cli.quiet,
            )?;
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
            Ok(())
        }

        // Same config fallback as validate/quality/view: the `compliance:`
        // section supplies the sidecar path and product class when the CLI
        // flags are absent, so the dossier agrees with the validate verdict
        // produced under the same config.
        Commands::CraDocs(args) => cli::run_cra_docs_with_force(
            args.sbom,
            args.output,
            args.cra_sidecar
                .or_else(|| app.compliance.cra_sidecar.clone()),
            args.cra_product_class
                .or_else(|| app.compliance.cra_product_class.clone()),
            args.force,
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
    let looks_like_file = first == sbom_tools::pipeline::STDIN_PATH
        || first.contains(std::path::MAIN_SEPARATOR)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parse_env_bool_accepts_common_spellings_case_insensitively() {
        for truthy in ["1", "true", "TRUE", "Yes", "y", "ON"] {
            assert_eq!(parse_env_bool(truthy), Ok(true), "{truthy}");
        }
        for falsy in ["0", "false", "False", "NO", "n", "off", "", " "] {
            assert_eq!(parse_env_bool(falsy), Ok(false), "{falsy:?}");
        }
    }

    #[test]
    fn parse_env_bool_rejects_garbage_with_accepted_values_listed() {
        let err = parse_env_bool("banana").unwrap_err();
        assert!(err.contains("banana"), "{err}");
        assert!(err.contains("1/0") && err.contains("true/false"), "{err}");
    }

    #[test]
    fn parse_cluster_threshold_accepts_finite_unit_interval() {
        assert_eq!(parse_cluster_threshold("0"), Ok(0.0));
        assert_eq!(parse_cluster_threshold("0.8"), Ok(0.8));
        assert_eq!(parse_cluster_threshold("1.0"), Ok(1.0));
    }

    #[test]
    fn parse_cluster_threshold_rejects_nan_infinite_and_out_of_range() {
        for bad in ["NaN", "nan", "-0.5", "1.5", "inf", "-inf", "1e300", "x"] {
            assert!(parse_cluster_threshold(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn parse_bom_type_is_strict_and_lists_valid_values() {
        assert_eq!(parse_bom_type("sbom"), Ok(sbom_tools::BomProfile::Sbom));
        assert_eq!(parse_bom_type("CBOM"), Ok(sbom_tools::BomProfile::Cbom));
        assert_eq!(parse_bom_type("aibom"), Ok(sbom_tools::BomProfile::AiBom));
        let err = parse_bom_type("banana").unwrap_err();
        assert!(err.contains("banana"), "{err}");
        for valid in ["sbom", "cbom", "aibom"] {
            assert!(err.contains(valid), "must list '{valid}': {err}");
        }
    }

    /// The phantom `--no-fail-on-change` flag must not be advertised anywhere
    /// (it never existed), and the root exit-code table must document the
    /// central operational-error code 3.
    #[test]
    fn help_text_matches_reality() {
        let mut cmd = Cli::command();
        cmd.build();
        let root = cmd.render_long_help().to_string();
        assert!(
            !root.contains("--no-fail-on-change"),
            "phantom flag in root help"
        );
        assert!(
            root.contains("Operational error"),
            "root help must document exit 3"
        );
        let diff = cmd
            .find_subcommand_mut("diff")
            .expect("diff subcommand")
            .render_long_help()
            .to_string();
        assert!(
            !diff.contains("--no-fail-on-change"),
            "phantom flag in diff help"
        );
        assert!(
            diff.contains("--fail-on-ml-regression"),
            "diff help must document exit 7 gate"
        );
    }
}
