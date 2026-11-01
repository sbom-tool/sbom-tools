#ifndef SBOM_TOOLS_H
#define SBOM_TOOLS_H

/**
 * @file sbom_tools.h
 * @brief C ABI for sbom-tools — SBOM parsing, diffing, quality scoring and
 * compliance validation.
 *
 * All functions return a SbomToolsStringResult containing either:
 *   - On success: data (non-NULL JSON), error_code == OK, error_message == NULL
 *   - On error:   data == NULL, error_code != OK, error_message (non-NULL)
 *
 * Every result MUST be freed exactly once via sbom_tools_string_result_free().
 * After freeing, the result must not be reused. Calling free twice on the same
 * result is undefined behavior.
 *
 * Every pointer argument must be a non-NULL, NUL-terminated UTF-8 string; a
 * NULL pointer is a SBOM_TOOLS_ERROR_VALIDATION error. Options arguments are
 * JSON objects: pass "{}" for the defaults.
 *
 * ABI version: 2 (sbom_tools_abi_version_json reports it). A release raises
 * it when it changes the contract in a way a wrapper written for the
 * previous one could misread: a function removed or its signature or
 * meaning changed, an error code or enum value renumbered or removed, or a
 * JSON payload field removed, renamed or retyped, or a value renamed.
 * Additions keep it: new functions, enum values, options, payload fields and
 * variants, which wrappers must accept. Version 2 (sbom-tools 0.4.0) follows
 * the 0.4.0 normalized payload changes and adds sbom_tools_validate_json,
 * sbom_tools_rule_catalog_json and sbom_tools_score_sbom_with_options_json.
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Error codes returned by all ABI functions. */
typedef enum SbomToolsErrorCode {
    SBOM_TOOLS_ERROR_OK = 0,            /**< Success — data contains JSON payload */
    SBOM_TOOLS_ERROR_PARSE = 1,         /**< SBOM parsing failed */
    SBOM_TOOLS_ERROR_DIFF = 2,          /**< Diff computation failed */
    SBOM_TOOLS_ERROR_VALIDATION = 3,    /**< Input validation failed (null ptr, bad UTF-8) */
    SBOM_TOOLS_ERROR_IO = 4,            /**< File I/O error */
    SBOM_TOOLS_ERROR_UNSUPPORTED = 5,   /**< Unsupported SBOM format or version */
    SBOM_TOOLS_ERROR_INTERNAL = 6       /**< Internal error (panic caught, serialization failure) */
} SbomToolsErrorCode;

/** Scoring profile presets for quality assessment. */
typedef enum SbomToolsScoringProfile {
    SBOM_TOOLS_PROFILE_MINIMAL = 0,
    SBOM_TOOLS_PROFILE_STANDARD = 1,
    SBOM_TOOLS_PROFILE_SECURITY = 2,
    SBOM_TOOLS_PROFILE_LICENSE_COMPLIANCE = 3,
    SBOM_TOOLS_PROFILE_CRA = 4,
    SBOM_TOOLS_PROFILE_COMPREHENSIVE = 5,
    SBOM_TOOLS_PROFILE_AI_READINESS = 6
} SbomToolsScoringProfile;

/**
 * Result type for all ABI functions.
 *
 * Ownership: the caller receives ownership and MUST call
 * sbom_tools_string_result_free() exactly once. Do not free individual
 * fields — the free function handles both data and error_message.
 */
typedef struct SbomToolsStringResult {
    char *data;                  /**< JSON payload on success, NULL on error */
    SbomToolsErrorCode error_code;
    char *error_message;         /**< Error description on failure, NULL on success */
} SbomToolsStringResult;

/** Return ABI and crate version as JSON. */
SbomToolsStringResult sbom_tools_abi_version_json(void);

/** Detect SBOM format from content string. Returns JSON with format details. */
SbomToolsStringResult sbom_tools_detect_format_json(const char *content);

/** Parse an SBOM file at the given path. Returns normalized SBOM as JSON. */
SbomToolsStringResult sbom_tools_parse_sbom_path_json(const char *path);

/** Parse an SBOM from a JSON/XML/tag-value string. Returns normalized SBOM as JSON. */
SbomToolsStringResult sbom_tools_parse_sbom_str_json(const char *content);

/** Compute a semantic diff between two normalized SBOMs (as JSON strings). */
SbomToolsStringResult sbom_tools_diff_sboms_json(
    const char *old_sbom_json,
    const char *new_sbom_json
);

/**
 * Score an SBOM's quality using the given profile. Returns quality report as
 * JSON, judged at the wall clock with no compliance inputs (see
 * sbom_tools_score_sbom_with_options_json).
 */
SbomToolsStringResult sbom_tools_score_sbom_json(
    const char *sbom_json,
    SbomToolsScoringProfile profile
);

/**
 * Validate a raw SBOM document (any format the parse functions read) against
 * compliance standards. Returns the "sbom-tools/compliance/v2" envelope, byte
 * for byte what `sbom-tools validate - -o json` writes for the same document
 * and inputs (`validate <FILE>` when "file_name" names the file). Its
 * "subject" holds the SHA-256 of exactly the bytes passed in, and its "as_of"
 * the instant every standard was judged at: "as_of", else the wall clock
 * when the call starts, to the second.
 *
 * options_json keys (all optional; an unknown key is an error):
 *   "standards"              array of --standard names or aliases (default ["ntia"])
 *   "file_name"              the file the document was read from; the subject
 *                            names it without its directory (default: no name)
 *   "as_of"                  evaluation instant, e.g. "2027-01-01" (--as-of)
 *   "sidecar"                CRA sidecar object, the keys of a .cra.json file
 *                            (no sidecar is discovered next to any file)
 *   "product_class"          --cra-product-class value
 *   "pqc_mode"               "readiness" or "deadline" (--pqc-mode)
 *   "pqc_profile"            --pqc-profile value (deadline mode only)
 *   "cnsa_category"          --cnsa-category value (deadline mode only)
 *   "rules"                  object: rule id -> "off", "info", "warning", "error"
 *   "include_excluded_scope" boolean (--include-excluded-scope)
 * Invalid options are SBOM_TOOLS_ERROR_VALIDATION errors.
 */
SbomToolsStringResult sbom_tools_validate_json(
    const char *sbom,
    const char *options_json
);

/**
 * Return the compliance rule catalogue as the "sbom-tools/rules/v1" document,
 * byte for byte what `sbom-tools rules -o json` prints (without its final
 * newline). filter_json: "{}" for every rule, or {"standards": [...]} for the
 * rules of those standards.
 */
SbomToolsStringResult sbom_tools_rule_catalog_json(const char *filter_json);

/**
 * Score a normalized SBOM (as JSON) with options: "profile" (a
 * `quality --profile` name, default "standard") and the run options of
 * sbom_tools_validate_json except "standards". Returns the quality report as
 * JSON, with "profile" named as `quality --profile` names it and
 * "compliance" as an entry of the validate envelope's "results".
 */
SbomToolsStringResult sbom_tools_score_sbom_with_options_json(
    const char *sbom_json,
    const char *options_json
);

/**
 * Free a result returned by any ABI function.
 *
 * Must be called exactly once per result. After this call, the result must
 * not be reused. Calling free twice on the same result is undefined behavior
 * (the struct is passed by value, so the caller's copy retains dangling pointers).
 */
void sbom_tools_string_result_free(SbomToolsStringResult result);

#ifdef __cplusplus
}
#endif

#endif