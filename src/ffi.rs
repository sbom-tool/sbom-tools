//! C-compatible ABI for the Go, Swift, Python and Node.js wrappers.
//!
//! Every function takes NUL-terminated UTF-8 strings and returns a
//! [`SbomToolsStringResult`] holding JSON. The compliance calls
//! ([`sbom_tools_validate_json`], [`sbom_tools_rule_catalog_json`],
//! [`sbom_tools_score_sbom_with_options_json`]) take their options as a JSON
//! object and build each run through [`ComplianceRunConfig`], with the
//! parsers the CLI flags use, so a call judges an SBOM exactly as the
//! command line does.

#![deny(unsafe_op_in_unsafe_fn)]

use crate::diff::DiffEngine;
use crate::model::{CraProductClass, CraSidecarError, CraSidecarMetadata, NormalizedSbom};
use crate::parsers::{ParseError, detect_format, parse_sbom, parse_sbom_str};
use crate::quality::{
    CnsaCategory, ComplianceLevel, ComplianceRunConfig, PqcMode, PqcProfile, QualityReport,
    QualityScorer, RuleCatalogFilter, RuleSetting, RuleSettings, ScoringProfile, SettingSource,
    StandardSelector, parse_as_of, resolve_rule_id, rule_catalog,
};
use crate::reports::{
    AssessedSbom, compliance_result_json, generate_compliance_json_at, generate_rule_catalog_json,
};
use crate::serialization::NormalizedSbomPayload;
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::ffi::{CStr, CString, c_char};
use std::path::Path;

/// The version of the ABI contract, as [`sbom_tools_abi_version_json`]
/// reports it: one number.
///
/// A release raises it when it changes the contract in a way a wrapper
/// written for the previous one could misread: a function removed, or its
/// signature or meaning changed; an error code or enum value renumbered or
/// removed; a JSON payload field removed, renamed or retyped, or a value
/// renamed. Additions keep it: new functions, enum values, options, payload
/// fields and variants, which wrappers must accept. The crate version tells
/// releases with the same ABI version apart.
///
/// `2` (sbom-tools 0.4.0): the normalized payload renamed values (typed
/// services, named external-reference types; see docs/MIGRATING-0.4.md),
/// and the ABI gained [`sbom_tools_validate_json`],
/// [`sbom_tools_rule_catalog_json`] and
/// [`sbom_tools_score_sbom_with_options_json`].
const ABI_VERSION: &str = "2";

/// The sbom-tools crate version.
const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Stable error codes for the C ABI.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbomToolsErrorCode {
    /// Successful operation.
    Ok = 0,
    /// Parsing of raw SBOM input failed.
    Parse = 1,
    /// Semantic diffing failed.
    Diff = 2,
    /// Validation of normalized JSON input failed.
    Validation = 3,
    /// IO failed while reading from disk.
    Io = 4,
    /// Requested functionality is unsupported.
    Unsupported = 5,
    /// Unexpected internal failure.
    Internal = 6,
}

/// Stable scoring profile identifiers for the C ABI.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbomToolsScoringProfile {
    Minimal = 0,
    Standard = 1,
    Security = 2,
    LicenseCompliance = 3,
    Cra = 4,
    Comprehensive = 5,
    AiReadiness = 6,
}

impl SbomToolsScoringProfile {
    const fn into_rust(self) -> ScoringProfile {
        match self {
            Self::Minimal => ScoringProfile::Minimal,
            Self::Standard => ScoringProfile::Standard,
            Self::Security => ScoringProfile::Security,
            Self::LicenseCompliance => ScoringProfile::LicenseCompliance,
            Self::Cra => ScoringProfile::Cra,
            Self::Comprehensive => ScoringProfile::Comprehensive,
            Self::AiReadiness => ScoringProfile::AiReadiness,
        }
    }
}

/// Generic string payload result for the C ABI.
#[repr(C)]
#[derive(Debug)]
pub struct SbomToolsStringResult {
    /// JSON payload on success.
    pub data: *mut c_char,
    /// Stable ABI error code.
    pub error_code: SbomToolsErrorCode,
    /// UTF-8 error message on failure.
    pub error_message: *mut c_char,
}

impl SbomToolsStringResult {
    fn success(payload: String) -> Self {
        Self {
            data: into_c_string(payload),
            error_code: SbomToolsErrorCode::Ok,
            error_message: std::ptr::null_mut(),
        }
    }

    fn error(code: SbomToolsErrorCode, message: impl Into<String>) -> Self {
        Self {
            data: std::ptr::null_mut(),
            error_code: code,
            error_message: into_c_string(message.into()),
        }
    }
}

struct FfiError {
    code: SbomToolsErrorCode,
    message: String,
}

#[derive(Serialize)]
struct AbiVersionPayload<'a> {
    abi_version: &'a str,
    crate_version: &'a str,
}

fn into_c_string(value: String) -> *mut c_char {
    let sanitized = value.replace('\0', " ");
    match CString::new(sanitized) {
        Ok(c_string) => c_string.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

fn read_input(value: *const c_char, field: &str) -> Result<String, FfiError> {
    if value.is_null() {
        return Err(FfiError {
            code: SbomToolsErrorCode::Validation,
            message: format!("{field} pointer must not be null"),
        });
    }

    // SAFETY: The caller guarantees a valid NUL-terminated string pointer.
    let c_string = unsafe { CStr::from_ptr(value) };
    c_string
        .to_str()
        .map(str::to_owned)
        .map_err(|err| FfiError {
            code: SbomToolsErrorCode::Validation,
            message: format!("{field} must be valid UTF-8: {err}"),
        })
}

fn parse_normalized_sbom(json: &str, field: &str) -> Result<NormalizedSbom, FfiError> {
    serde_json::from_str::<NormalizedSbomPayload>(json)
        .map(NormalizedSbomPayload::into_sbom)
        .map_err(|err| FfiError {
            code: SbomToolsErrorCode::Validation,
            message: format!("invalid normalized SBOM JSON in {field}: {err}"),
        })
}

fn map_parse_error(err: ParseError) -> FfiError {
    let (code, message) = match err {
        ParseError::IoError(_) => (
            SbomToolsErrorCode::Io,
            "failed to read file (permission denied, file not found, or I/O error)".to_string(),
        ),
        ParseError::UnsupportedVersion(v) => (
            SbomToolsErrorCode::Unsupported,
            format!("unsupported SBOM version: {v}"),
        ),
        ParseError::UnknownFormat(_) => (
            SbomToolsErrorCode::Unsupported,
            "unknown SBOM format (expected CycloneDX or SPDX)".to_string(),
        ),
        ParseError::ValidationError(msg) => (
            SbomToolsErrorCode::Validation,
            format!("SBOM validation failed: {msg}"),
        ),
        ParseError::MissingField(field) => (
            SbomToolsErrorCode::Validation,
            format!("required field missing: {field}"),
        ),
        ParseError::JsonError(msg) => (
            SbomToolsErrorCode::Parse,
            format!("JSON parsing failed: {msg}"),
        ),
        ParseError::XmlError(msg) => (
            SbomToolsErrorCode::Parse,
            format!("XML parsing failed: {msg}"),
        ),
        ParseError::YamlError(msg) => (
            SbomToolsErrorCode::Parse,
            format!("YAML parsing failed: {msg}"),
        ),
        ParseError::InvalidStructure(msg) => (
            SbomToolsErrorCode::Parse,
            format!("invalid SBOM structure: {msg}"),
        ),
    };

    FfiError { code, message }
}

fn run_json<T, F>(operation: F) -> SbomToolsStringResult
where
    T: Serialize,
    F: FnOnce() -> Result<T, FfiError>,
{
    match operation() {
        Ok(value) => match serde_json::to_string_pretty(&value) {
            Ok(payload) => SbomToolsStringResult::success(payload),
            Err(err) => SbomToolsStringResult::error(
                SbomToolsErrorCode::Internal,
                format!("failed to serialize ABI response: {err}"),
            ),
        },
        Err(err) => SbomToolsStringResult::error(err.code, err.message),
    }
}

/// Wrap an FFI function body with panic catching.
///
/// Any panic inside the closure will be caught and converted to an FFI error.
/// This prevents undefined behavior from panics crossing the FFI boundary.
///
/// # SAFETY & CORRECTNESS
/// Panics must never unwind across the FFI boundary into C code (UB).
/// This wrapper converts `catch_unwind` panic payload into an error result.
fn catch_ffi_panic<F>(f: F) -> SbomToolsStringResult
where
    F: FnOnce() -> SbomToolsStringResult + std::panic::UnwindSafe,
{
    match std::panic::catch_unwind(f) {
        Ok(result) => result,
        Err(_) => SbomToolsStringResult::error(
            SbomToolsErrorCode::Internal,
            "internal panic caught at FFI boundary",
        ),
    }
}

/// Return a payload the library's own writer already rendered as JSON (the
/// compliance envelope, the rule catalogue) unchanged, so the bytes are the
/// ones the CLI prints.
fn run_text<F>(operation: F) -> SbomToolsStringResult
where
    F: FnOnce() -> Result<String, FfiError>,
{
    match operation() {
        Ok(payload) => SbomToolsStringResult::success(payload),
        Err(err) => SbomToolsStringResult::error(err.code, err.message),
    }
}

/// An invalid argument: a [`SbomToolsErrorCode::Validation`] error.
fn invalid(message: impl Into<String>) -> FfiError {
    FfiError {
        code: SbomToolsErrorCode::Validation,
        message: message.into(),
    }
}

/// A payload that failed to render: a [`SbomToolsErrorCode::Internal`]
/// error.
fn render_error(what: &str, err: impl std::fmt::Display) -> FfiError {
    FfiError {
        code: SbomToolsErrorCode::Internal,
        message: format!("failed to render {what}: {err}"),
    }
}

/// The options of a compliance run, as the CLI's shared compliance flags
/// give them: `as_of` (`--as-of`), `sidecar` (`--cra-sidecar`, inline),
/// `product_class` (`--cra-product-class`), `pqc_mode`, `pqc_profile`,
/// `cnsa_category` (`--pqc-mode`, `--pqc-profile`, `--cnsa-category`),
/// `rules` (`--rule`) and `include_excluded_scope`
/// (`--include-excluded-scope`).
const RUN_OPTIONS: &[&str] = &[
    "as_of",
    "sidecar",
    "product_class",
    "pqc_mode",
    "pqc_profile",
    "cnsa_category",
    "rules",
    "include_excluded_scope",
];

/// The `standards` option: `validate --standard`, and `rules --standard`
/// for the rule catalogue.
const STANDARDS_OPTION: &[&str] = &["standards"];

/// The `file_name` option of validate: the name of the file the SBOM was
/// read from, which `validate <FILE>` states in the envelope's `subject`.
const FILE_NAME_OPTION: &[&str] = &["file_name"];

/// The `profile` option: `quality --profile`.
const PROFILE_OPTION: &[&str] = &["profile"];

/// A call's options: the JSON object passed as its options argument,
/// checked against the keys the call reads. A key whose value is `null`
/// counts as not given.
struct Options {
    /// The argument's name, for messages.
    argument: &'static str,
    entries: Map<String, Value>,
}

impl Options {
    /// Parse `json` (the argument `argument`) as an object whose keys are
    /// all among `keys`.
    fn parse(json: &str, argument: &'static str, keys: &[&[&str]]) -> Result<Self, FfiError> {
        let value: Value = serde_json::from_str(json)
            .map_err(|e| invalid(format!("{argument} is not valid JSON: {e}")))?;
        let Value::Object(entries) = value else {
            return Err(invalid(format!(
                "{argument} must be a JSON object (`{{}}` for the defaults)"
            )));
        };
        let valid: Vec<&str> = keys.iter().flat_map(|k| k.iter().copied()).collect();
        if let Some(unknown) = entries.keys().find(|key| !valid.contains(&key.as_str())) {
            return Err(invalid(format!(
                "unknown option `{unknown}` in {argument}; valid options: {}",
                valid.join(", ")
            )));
        }
        Ok(Self { argument, entries })
    }

    /// The value of `key`; `None` when it is absent or `null`.
    fn get(&self, key: &str) -> Option<&Value> {
        self.entries.get(key).filter(|value| !value.is_null())
    }

    fn wrong_type(&self, key: &str, expected: &str) -> FfiError {
        invalid(format!(
            "option `{key}` in {} must be {expected}",
            self.argument
        ))
    }

    fn string(&self, key: &str) -> Result<Option<&str>, FfiError> {
        match self.get(key) {
            None => Ok(None),
            Some(Value::String(value)) => Ok(Some(value)),
            Some(_) => Err(self.wrong_type(key, "a string")),
        }
    }

    fn bool(&self, key: &str) -> Result<Option<bool>, FfiError> {
        match self.get(key) {
            None => Ok(None),
            Some(Value::Bool(value)) => Ok(Some(*value)),
            Some(_) => Err(self.wrong_type(key, "true or false")),
        }
    }

    fn strings(&self, key: &str) -> Result<Option<Vec<&str>>, FfiError> {
        match self.get(key) {
            None => Ok(None),
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| {
                    item.as_str()
                        .ok_or_else(|| self.wrong_type(key, "an array of strings"))
                })
                .collect::<Result<Vec<_>, _>>()
                .map(Some),
            Some(_) => Err(self.wrong_type(key, "an array of strings")),
        }
    }

    fn object(&self, key: &str) -> Result<Option<&Map<String, Value>>, FfiError> {
        match self.get(key) {
            None => Ok(None),
            Some(Value::Object(value)) => Ok(Some(value)),
            Some(_) => Err(self.wrong_type(key, "a JSON object")),
        }
    }

    /// The standards option `standards` names: the CLI's `--standard` names
    /// and aliases, in any case.
    fn standards(&self) -> Result<Option<Vec<StandardSelector>>, FfiError> {
        self.strings("standards")?
            .map(|names| {
                names
                    .into_iter()
                    .map(|name| {
                        name.parse::<StandardSelector>()
                            .map_err(|e| invalid(format!("invalid standards: {e}")))
                    })
                    .collect()
            })
            .transpose()
    }

    /// Option `key` parsed as the CLI flag of the same name parses its
    /// value, in any case (as the config file reads it).
    fn value_enum<T: clap::ValueEnum>(&self, key: &str) -> Result<Option<T>, FfiError> {
        self.string(key)?
            .map(|value| {
                T::from_str(value, true).map_err(|_| {
                    let valid: Vec<String> = T::value_variants()
                        .iter()
                        .filter_map(|v| v.to_possible_value().map(|pv| pv.get_name().to_string()))
                        .collect();
                    invalid(format!(
                        "invalid {key} {value:?}; valid values: {}",
                        valid.join(", ")
                    ))
                })
            })
            .transpose()
    }

    /// The compliance run the run options describe (see [`RUN_OPTIONS`]),
    /// built through [`ComplianceRunConfig`] as the CLI builds it from its
    /// flags: the same parsers, the same checks.
    fn run_config(&self) -> Result<ComplianceRunConfig, FfiError> {
        let mode = self.value_enum::<PqcMode>("pqc_mode")?.unwrap_or_default();
        let profile = self.value_enum::<PqcProfile>("pqc_profile")?;
        let category = self.value_enum::<CnsaCategory>("cnsa_category")?;
        let mut run = ComplianceRunConfig::new()
            .with_pqc_inputs(mode, profile, category)
            .map_err(|_| {
                invalid("`pqc_profile` and `cnsa_category` apply only with `pqc_mode` \"deadline\"")
            })?
            .with_rule_settings(self.rule_settings()?)
            .with_include_excluded_scope(self.bool("include_excluded_scope")?.unwrap_or(false));
        if let Some(raw) = self.string("as_of")? {
            let as_of =
                parse_as_of(raw).map_err(|e| invalid(format!("invalid as_of {raw:?}: {e}")))?;
            run = run.with_as_of(as_of);
        }
        if let Some(raw) = self.string("product_class")? {
            let class = CraProductClass::parse_cli_strict(raw)
                .map_err(|e| invalid(format!("invalid product_class: {e}")))?;
            run = run.with_product_class(class);
        }
        if let Some(sidecar) = self.get("sidecar") {
            if !sidecar.is_object() {
                return Err(self.wrong_type("sidecar", "a JSON object (a CRA sidecar's keys)"));
            }
            let sidecar = CraSidecarMetadata::from_json_value(sidecar.clone()).map_err(|e| {
                let detail = match e {
                    CraSidecarError::ParseError(detail) => detail,
                    other => other.to_string(),
                };
                invalid(format!("invalid sidecar: {detail}"))
            })?;
            run = run.with_sidecar(sidecar);
        }
        Ok(run)
    }

    /// The rule settings option `rules` gives: rule id (any case) →
    /// `off`, `info`, `warning` or `error`, checked against the registry as
    /// `--rule` is. The settings count as the run's own, as `--rule` does:
    /// their findings say `severity_source: "cli"`.
    fn rule_settings(&self) -> Result<RuleSettings, FfiError> {
        let mut settings = RuleSettings::new();
        let Some(rules) = self.object("rules")? else {
            return Ok(settings);
        };
        let mut named: BTreeMap<&'static str, &str> = BTreeMap::new();
        for (rule_id, value) in rules {
            let invalid_rule = |e: String| invalid(format!("invalid rules.{rule_id}: {e}"));
            let setting = value
                .as_str()
                .ok_or_else(|| {
                    invalid_rule("the setting must be a string: off, info, warning or error".into())
                })?
                .parse::<RuleSetting>()
                .map_err(invalid_rule)?;
            let id = resolve_rule_id(rule_id).map_err(invalid_rule)?;
            if let Some(earlier) = named.insert(id, rule_id) {
                return Err(invalid(format!(
                    "rules names {id} twice (`{earlier}` and `{rule_id}`)"
                )));
            }
            settings
                .set(id, setting, SettingSource::Cli)
                .map_err(invalid_rule)?;
        }
        Ok(settings)
    }
}

/// `validate`'s default standard when `--standard` is not given.
const DEFAULT_STANDARD: StandardSelector = StandardSelector::Ntia;

/// The `sbom-tools/compliance/v2` envelope of `content`, the SBOM document
/// as passed in, checked with `options` (see [`sbom_tools_validate_json`]).
fn validate(content: &str, options: &str) -> Result<String, FfiError> {
    let options = Options::parse(
        options,
        "options_json",
        &[STANDARDS_OPTION, FILE_NAME_OPTION, RUN_OPTIONS],
    )?;
    let selectors = options
        .standards()?
        .unwrap_or_else(|| vec![DEFAULT_STANDARD]);
    let file_name = options.string("file_name")?;
    let run = options.run_config()?;
    // One instant for the whole run, as `validate` judges at: `as_of`, else
    // the wall clock now, to the second. The envelope states it.
    let judged_at = run.judged_at();
    let run = run.with_as_of(judged_at);
    if selectors.is_empty() {
        return Err(invalid(format!(
            "no compliance standard selected; name one in `standards` (valid values: {})",
            StandardSelector::valid_values()
        )));
    }
    // A repeat (`cra` and `cra-phase2` name one level) is checked once, as
    // `validate` does.
    let (kept, _repeats) = StandardSelector::dedup_by_level(&selectors);
    let levels: Vec<ComplianceLevel> = kept.into_iter().map(StandardSelector::level).collect();
    let sbom = parse_sbom_str(content).map_err(map_parse_error)?;
    let results = run.check_levels(&levels, &sbom);
    // The subject's digest is over the exact bytes passed in; it names a
    // file only when the options give one.
    let mut assessed = AssessedSbom::new(&sbom, content.as_bytes());
    if let Some(name) = file_name {
        assessed = assessed.with_file_name(name);
    }
    generate_compliance_json_at(&results, &assessed, judged_at)
        .map_err(|e| render_error("the compliance envelope", e))
}

/// The `sbom-tools/rules/v1` catalogue `filter` selects (see
/// [`sbom_tools_rule_catalog_json`]).
fn rule_catalog_document(filter: &str) -> Result<String, FfiError> {
    let filter = Options::parse(filter, "filter_json", &[STANDARDS_OPTION])?;
    let selectors = filter.standards()?.unwrap_or_default();
    let entries = rule_catalog(&RuleCatalogFilter::for_standards(selectors));
    generate_rule_catalog_json(&entries).map_err(|e| render_error("the rule catalogue", e))
}

/// The quality report of the normalized `sbom_json` scored with `options`
/// (see [`sbom_tools_score_sbom_with_options_json`]).
fn score_with_options(sbom_json: &str, options: &str) -> Result<String, FfiError> {
    let options = Options::parse(options, "options_json", &[PROFILE_OPTION, RUN_OPTIONS])?;
    let profile = options
        .string("profile")?
        .map(|name| {
            name.parse::<ScoringProfile>()
                .map_err(|e| invalid(format!("invalid profile: {e}")))
        })
        .transpose()?
        .unwrap_or(ScoringProfile::Standard);
    let run = options.run_config()?;
    let sbom = parse_normalized_sbom(sbom_json, "sbom_json")?;
    let report = QualityScorer::new(profile)
        .with_compliance(run)
        .score(&sbom);
    score_report_json(&report)
}

/// `report` as the score-with-options call returns it: the report's own
/// fields, with the profile named as `quality --profile` names it and the
/// compliance check rendered as an entry of the `validate -o json`
/// envelope's `results[]` (standard key, finding identities).
fn score_report_json(report: &QualityReport) -> Result<String, FfiError> {
    let fail = |e: &dyn std::fmt::Display| render_error("the quality report", e);
    let Value::Object(mut fields) = serde_json::to_value(report).map_err(|e| fail(&e))? else {
        return Err(fail(&"a quality report must serialize to a JSON object"));
    };
    fields.insert(
        "profile".to_string(),
        Value::String(report.profile.canonical_name().to_string()),
    );
    fields.insert(
        "compliance".to_string(),
        compliance_result_json(&report.compliance).map_err(|e| fail(&e))?,
    );
    serde_json::to_string_pretty(&Value::Object(fields)).map_err(|e| fail(&e))
}

/// Return the ABI and crate versions as JSON.
#[unsafe(no_mangle)]
pub extern "C" fn sbom_tools_abi_version_json() -> SbomToolsStringResult {
    catch_ffi_panic(|| {
        run_json(|| {
            Ok(AbiVersionPayload {
                abi_version: ABI_VERSION,
                crate_version: CRATE_VERSION,
            })
        })
    })
}

/// Detect the SBOM format from raw content and return JSON.
#[unsafe(no_mangle)]
pub extern "C" fn sbom_tools_detect_format_json(content: *const c_char) -> SbomToolsStringResult {
    catch_ffi_panic(|| {
        run_json(|| {
            let content = read_input(content, "content")?;
            Ok(detect_format(&content))
        })
    })
}

/// Parse an SBOM file from disk and return normalized JSON.
#[unsafe(no_mangle)]
pub extern "C" fn sbom_tools_parse_sbom_path_json(path: *const c_char) -> SbomToolsStringResult {
    catch_ffi_panic(|| {
        run_json(|| {
            let path = read_input(path, "path")?;
            parse_sbom(Path::new(&path))
                .map(NormalizedSbomPayload::from_sbom)
                .map_err(map_parse_error)
        })
    })
}

/// Parse raw SBOM content and return normalized JSON.
#[unsafe(no_mangle)]
pub extern "C" fn sbom_tools_parse_sbom_str_json(content: *const c_char) -> SbomToolsStringResult {
    catch_ffi_panic(|| {
        run_json(|| {
            let content = read_input(content, "content")?;
            parse_sbom_str(&content)
                .map(NormalizedSbomPayload::from_sbom)
                .map_err(map_parse_error)
        })
    })
}

/// Diff two normalized SBOM JSON documents and return a diff result as JSON.
#[unsafe(no_mangle)]
pub extern "C" fn sbom_tools_diff_sboms_json(
    old_sbom_json: *const c_char,
    new_sbom_json: *const c_char,
) -> SbomToolsStringResult {
    catch_ffi_panic(|| {
        run_json(|| {
            let old_json = read_input(old_sbom_json, "old_sbom_json")?;
            let new_json = read_input(new_sbom_json, "new_sbom_json")?;
            let old = parse_normalized_sbom(&old_json, "old_sbom_json")?;
            let new = parse_normalized_sbom(&new_json, "new_sbom_json")?;

            DiffEngine::new().diff(&old, &new).map_err(|err| FfiError {
                code: SbomToolsErrorCode::Diff,
                message: err.to_string(),
            })
        })
    })
}

/// Score a normalized SBOM JSON document and return a quality report as JSON.
///
/// The report is the scorer's own serialization, judged at the wall clock
/// with no compliance inputs. [`sbom_tools_score_sbom_with_options_json`]
/// pins the clock, takes the run's inputs and names levels as the rest of
/// the ABI does.
#[unsafe(no_mangle)]
pub extern "C" fn sbom_tools_score_sbom_json(
    sbom_json: *const c_char,
    profile: SbomToolsScoringProfile,
) -> SbomToolsStringResult {
    catch_ffi_panic(|| {
        run_json(|| {
            let sbom_json = read_input(sbom_json, "sbom_json")?;
            let sbom = parse_normalized_sbom(&sbom_json, "sbom_json")?;
            Ok(QualityScorer::new(profile.into_rust()).score(&sbom))
        })
    })
}

/// Validate a raw SBOM document against compliance standards and return
/// the `sbom-tools/compliance/v2` envelope: byte for byte what
/// `sbom-tools validate - -o json` writes for the same document and inputs
/// (`validate <FILE>` for a `file_name`).
///
/// `sbom` is the document as read (any format the parse functions accept).
/// The envelope's `subject` gives the SHA-256 of exactly these bytes. Its
/// `as_of` is the instant every standard was judged at: `as_of`, else the
/// wall clock when the call starts, to the second.
/// `options_json` is a JSON object (`{}` for the defaults) with:
/// - `standards`: array of `--standard` names or aliases (default
///   `["ntia"]`); a level named twice is checked once
/// - `file_name`: the name of the file the document was read from, which
///   the `subject` states without its directory; without it, the subject
///   names no file, as for standard input
/// - `as_of`: the evaluation instant (`--as-of`)
/// - `sidecar`: a CRA sidecar object, with the keys of a `.cra.json` file
///   (`--cra-sidecar`). No sidecar is discovered next to a file, as
///   `validate <FILE>` does: pass it here
/// - `product_class`: `--cra-product-class`
/// - `pqc_mode`, `pqc_profile`, `cnsa_category`: `--pqc-mode`,
///   `--pqc-profile`, `--cnsa-category`
/// - `rules`: rule id → `off`, `info`, `warning` or `error` (`--rule`)
/// - `include_excluded_scope`: `--include-excluded-scope`
///
/// An unknown key, a value of the wrong type and every value the CLI would
/// reject are [`SbomToolsErrorCode::Validation`] errors; an SBOM that does
/// not parse fails as [`sbom_tools_parse_sbom_str_json`] does.
#[unsafe(no_mangle)]
pub extern "C" fn sbom_tools_validate_json(
    sbom: *const c_char,
    options_json: *const c_char,
) -> SbomToolsStringResult {
    catch_ffi_panic(|| {
        run_text(|| {
            let sbom = read_input(sbom, "sbom")?;
            let options_json = read_input(options_json, "options_json")?;
            validate(&sbom, &options_json)
        })
    })
}

/// Return the compliance rule catalogue as the `sbom-tools/rules/v1`
/// document: byte for byte what `sbom-tools rules -o json` prints, without
/// its final newline.
///
/// `filter_json` is a JSON object: `{}` for every rule, or
/// `{"standards": [...]}` (`--standard` names) for the rules of those
/// standards.
#[unsafe(no_mangle)]
pub extern "C" fn sbom_tools_rule_catalog_json(
    filter_json: *const c_char,
) -> SbomToolsStringResult {
    catch_ffi_panic(|| {
        run_text(|| {
            let filter_json = read_input(filter_json, "filter_json")?;
            rule_catalog_document(&filter_json)
        })
    })
}

/// Score a normalized SBOM JSON document with options and return a quality
/// report as JSON.
///
/// `options_json` is a JSON object (`{}` for the defaults) with `profile`
/// (a `quality --profile` name, default `standard`) and the run options of
/// [`sbom_tools_validate_json`] (all but `standards`), which reach the
/// profile's compliance check and date the time-sensitive metrics.
///
/// The report carries the fields [`sbom_tools_score_sbom_json`] returns,
/// with `profile` as `quality --profile` names it and `compliance` as an
/// entry of the validate envelope's `results[]`.
#[unsafe(no_mangle)]
pub extern "C" fn sbom_tools_score_sbom_with_options_json(
    sbom_json: *const c_char,
    options_json: *const c_char,
) -> SbomToolsStringResult {
    catch_ffi_panic(|| {
        run_text(|| {
            let sbom_json = read_input(sbom_json, "sbom_json")?;
            let options_json = read_input(options_json, "options_json")?;
            score_with_options(&sbom_json, &options_json)
        })
    })
}

/// Free memory allocated by the ABI result.
///
/// # Safety
/// - The caller must call this exactly once per result.
/// - The result must not be used after this call.
/// - Calling free twice on the same result is **undefined behavior**: the struct
///   is passed by value (C calling convention), so the caller's copy retains
///   the original (now-dangling) pointers. The internal pointer zeroing only
///   affects the local copy inside this function.
///
/// # C Usage
/// ```c
/// SbomToolsStringResult result = sbom_tools_parse_sbom_str_json(content);
/// // use result.data and result.error_message
/// sbom_tools_string_result_free(result);
/// // Do NOT call sbom_tools_string_result_free(result) again — undefined behavior.
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn sbom_tools_string_result_free(mut result: SbomToolsStringResult) {
    if !result.data.is_null() {
        // SAFETY: The pointer was allocated by CString::into_raw in this module.
        // Caller must guarantee this is the first and only free of this pointer.
        unsafe {
            drop(CString::from_raw(result.data));
        }
        result.data = std::ptr::null_mut(); // Zero to defend against caller copies
    }

    if !result.error_message.is_null() {
        // SAFETY: The pointer was allocated by CString::into_raw in this module.
        // Caller must guarantee this is the first and only free of this pointer.
        unsafe {
            drop(CString::from_raw(result.error_message));
        }
        #[allow(unused_assignments)]
        {
            result.error_message = std::ptr::null_mut(); // Zero to defend against caller copies
        }
    }
}
