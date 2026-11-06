export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

export enum ErrorCode {
  Ok = 0,
  Parse = 1,
  Diff = 2,
  Validation = 3,
  Io = 4,
  Unsupported = 5,
  Internal = 6,
}

export enum ScoringProfile {
  Minimal = 0,
  Standard = 1,
  Security = 2,
  LicenseCompliance = 3,
  Cra = 4,
  Comprehensive = 5,
  AiReadiness = 6,
}

export interface AbiVersion {
  readonly abi_version: string;
  readonly crate_version: string;
}

export interface DetectedFormat {
  readonly format_name: string;
  readonly confidence: number;
  readonly variant: string | null;
  readonly version: string | null;
  readonly warnings: readonly string[];
}

/**
 * The inputs of a compliance run, as the CLI's shared compliance flags give
 * them. The keys are the native option names; a key left out keeps its
 * default.
 */
export interface RunOptions {
  /**
   * The evaluation instant (`--as-of`): an RFC 3339 datetime, an offset-less
   * datetime taken as UTC, or a date (midnight UTC). A `Date` is sent as its
   * UTC instant.
   */
  readonly as_of?: string | Date;
  /** A CRA sidecar object, with the keys of a `.cra.json` file. */
  readonly sidecar?: { readonly [key: string]: JsonValue };
  /** The CRA product class (`--cra-product-class`). */
  readonly product_class?: string;
  /** `readiness` or `deadline` (`--pqc-mode`). */
  readonly pqc_mode?: string;
  /** `--pqc-profile`; deadline mode only. */
  readonly pqc_profile?: string;
  /** `--cnsa-category`; deadline mode only. */
  readonly cnsa_category?: string;
  /** Rule id to `off`, `info`, `warning` or `error` (`--rule`). */
  readonly rules?: { readonly [ruleId: string]: string };
  /** Judge components whose scope is excluded too (`--include-excluded-scope`). */
  readonly include_excluded_scope?: boolean;
}

export interface ValidateOptions extends RunOptions {
  /** `--standard` names or aliases; left out, `["ntia"]`. */
  readonly standards?: readonly string[];
  /**
   * The file the content was read from, which the envelope's subject names
   * without its directory, as `validate <FILE>` does; left out, no file is
   * named, as for standard input.
   */
  readonly file_name?: string;
}

export interface ScoreOptions extends RunOptions {
  /** A `quality --profile` name; left out, `standard`. */
  readonly profile?: string;
  /**
   * The file the content was read from, which the output's `sbom` names
   * without its directory, as `quality <FILE>` does; left out, `sbom` is
   * `-`, as for standard input.
   */
  readonly file_name?: string;
}

export type Severity = "Error" | "Warning" | "Info";

export interface ToolInfo {
  readonly name: string;
  readonly version: string;
}

export interface StandardRef {
  readonly standard: string;
  readonly id: string;
  readonly help_uri?: string;
}

/** One finding of a standard. */
export interface ComplianceViolation {
  readonly finding_id: string;
  readonly finding_key: string;
  readonly severity: Severity;
  readonly default_severity?: Severity;
  readonly severity_source?: "config" | "cli";
  readonly category: string;
  readonly message: string;
  readonly element: string | null;
  readonly component_id?: string;
  readonly finding_detail?: string;
  readonly counts?: { readonly affected: number; readonly total: number };
  readonly deadline?: string;
  readonly deadline_source?: string;
  readonly field?: string;
  readonly observed?: string;
  readonly requirement: string;
  readonly rule_id: string;
  readonly sarif_rule_id: string;
  readonly standard_refs?: readonly StandardRef[];
  readonly remediation?: string;
  readonly help_uri?: string;
}

/** A check the SBOM passed; it is not a violation. */
export interface PassedCheck {
  readonly finding_id: string;
  readonly finding_key: string;
  readonly message: string;
  readonly element: string | null;
  readonly component_id?: string;
  readonly finding_detail?: string;
  readonly requirement: string;
  readonly rule_id: string;
  readonly sarif_rule_id: string;
  readonly standard_refs?: readonly StandardRef[];
}

/** One standard's verdict. */
export interface ComplianceResult {
  readonly standard: string;
  readonly name: string;
  readonly applicable: boolean;
  readonly not_applicable_reason?: string;
  readonly compliant: boolean;
  readonly score: number | null;
  readonly score_basis?: { readonly checked: number; readonly failed: number };
  readonly counts: {
    readonly error: number;
    readonly warning: number;
    readonly info: number;
    readonly passed: number;
    readonly suppressed?: number;
  };
  readonly violations: readonly ComplianceViolation[];
  readonly passed: readonly PassedCheck[];
  readonly evaluated?: readonly {
    readonly rule_id: string;
    readonly status: string;
    readonly reason: string;
  }[];
  readonly suppressed?: readonly {
    readonly rule_id: string;
    readonly findings: number;
    readonly source: "config" | "cli";
  }[];
  readonly excluded_components?: number;
  readonly conformity_summary?: { readonly [key: string]: JsonValue };
}

/** The SBOM a compliance envelope judges, and how its document was read. */
export interface ComplianceSubject {
  /** Lowercase hex SHA-256 of the content passed in. */
  readonly sha256: string;
  readonly format: string;
  readonly spec_version: string;
  /** The `file_name` option without its directory. */
  readonly file_name?: string;
  readonly components: number;
  readonly duplicates: {
    readonly components: number;
    readonly entries: number;
    readonly conflicts: readonly string[];
  };
  readonly timestamp_unparsed: boolean;
}

/**
 * The `sbom-tools/compliance/v2` envelope `validateJson` returns, as
 * `sbom-tools validate -o json` writes it.
 */
export interface ComplianceEnvelope {
  readonly schema: "sbom-tools/compliance/v2";
  readonly tool: ToolInfo;
  /** The instant every standard was judged at (RFC 3339, UTC). */
  readonly as_of: string;
  readonly subject: ComplianceSubject;
  readonly results: readonly ComplianceResult[];
}

export interface RuleReference {
  readonly standard: string;
  readonly id: string;
  readonly label: string;
  readonly help_uri?: string;
}

export interface RuleFormatAdvice {
  readonly text: string;
  readonly field?: string;
}

/** Everything the registry records about one rule. */
export interface RuleCatalogEntry {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly default_severity: Severity;
  readonly kind: "finding" | "pass";
  readonly fallback: boolean;
  readonly standards: readonly string[];
  readonly references: readonly RuleReference[];
  readonly help_uri?: string;
  readonly remediation: string;
  readonly remediation_summary: string;
  readonly advice?: {
    readonly cyclonedx: RuleFormatAdvice;
    readonly spdx2: RuleFormatAdvice;
    readonly spdx3: RuleFormatAdvice;
  };
}

/** The `sbom-tools/rules/v1` document `ruleCatalogJson` returns. */
export interface RuleCatalog {
  readonly schema: "sbom-tools/rules/v1";
  readonly tool: ToolInfo;
  readonly rules: readonly RuleCatalogEntry[];
}

/**
 * The quality report inside a `QualityOutput`: the scorer's own fields
 * (category scores, metrics, the profile's compliance result). For a profile
 * that did not apply (ai-readiness on an SBOM without ML components),
 * `overall_score` is `null` and `grade` is `N/A`.
 */
export interface QualityOutputReport {
  readonly scoring_engine_version: string;
  readonly overall_score: number | null;
  readonly grade: string;
  readonly profile: string;
  readonly compliance: { readonly [key: string]: JsonValue };
  readonly recommendations: readonly JsonValue[];
  readonly [field: string]: unknown;
}

/**
 * The document `scoreWithOptionsJson` returns, as
 * `sbom-tools quality -o json` prints it: the tool and its version, the
 * SBOM's file name (`-` without `file_name`), the profile as `--profile`
 * names it, whether the profile applied, and the report.
 */
export interface QualityOutput {
  readonly tool: string;
  readonly version: string;
  readonly sbom: string;
  readonly profile: string;
  readonly applicable: boolean;
  readonly report: QualityOutputReport;
}
