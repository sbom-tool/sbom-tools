#ifndef SBOM_TOOLS_H
#define SBOM_TOOLS_H

/**
 * @file sbom_tools.h
 * @brief C ABI for sbom-tools — SBOM parsing, diffing, and quality scoring.
 *
 * All functions return a SbomToolsStringResult containing either:
 *   - On success: data (non-NULL JSON), error_code == OK, error_message == NULL
 *   - On error:   data == NULL, error_code != OK, error_message (non-NULL)
 *
 * Every result MUST be freed exactly once via sbom_tools_string_result_free().
 * After freeing, the result must not be reused. Calling free twice on the same
 * result is undefined behavior.
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

/** Score an SBOM's quality using the given profile. Returns quality report as JSON. */
SbomToolsStringResult sbom_tools_score_sbom_json(
    const char *sbom_json,
    SbomToolsScoringProfile profile
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