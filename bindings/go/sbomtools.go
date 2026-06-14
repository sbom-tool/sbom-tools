package sbomtools

/*
#cgo CFLAGS: -I../swift/Sources/CSbomTools/include
#cgo darwin,arm64 LDFLAGS: -L../../target/aarch64-apple-darwin/release -L../../target/aarch64-apple-darwin/debug -L../../target/release -L../../target/debug -lsbom_tools_ffi
#cgo darwin,amd64 LDFLAGS: -L../../target/x86_64-apple-darwin/release -L../../target/x86_64-apple-darwin/debug -L../../target/release -L../../target/debug -lsbom_tools_ffi
#cgo linux,amd64 LDFLAGS: -L../../target/x86_64-unknown-linux-gnu/release -L../../target/x86_64-unknown-linux-gnu/debug -L../../target/release -L../../target/debug -Wl,-Bstatic -lsbom_tools_ffi -Wl,-Bdynamic -lm -ldl -lpthread
#cgo linux,arm64 LDFLAGS: -L../../target/aarch64-unknown-linux-gnu/release -L../../target/aarch64-unknown-linux-gnu/debug -L../../target/release -L../../target/debug -Wl,-Bstatic -lsbom_tools_ffi -Wl,-Bdynamic -lm -ldl -lpthread
#cgo !darwin,!linux LDFLAGS: -L../../target/release -L../../target/debug -lsbom_tools_ffi
#include <stdlib.h>
#include "sbom_tools.h"
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"unsafe"
)

type ErrorCode uint32

const (
	ErrorCodeOK          ErrorCode = ErrorCode(C.SBOM_TOOLS_ERROR_OK)
	ErrorCodeParse       ErrorCode = ErrorCode(C.SBOM_TOOLS_ERROR_PARSE)
	ErrorCodeDiff        ErrorCode = ErrorCode(C.SBOM_TOOLS_ERROR_DIFF)
	ErrorCodeValidation  ErrorCode = ErrorCode(C.SBOM_TOOLS_ERROR_VALIDATION)
	ErrorCodeIO          ErrorCode = ErrorCode(C.SBOM_TOOLS_ERROR_IO)
	ErrorCodeUnsupported ErrorCode = ErrorCode(C.SBOM_TOOLS_ERROR_UNSUPPORTED)
	ErrorCodeInternal    ErrorCode = ErrorCode(C.SBOM_TOOLS_ERROR_INTERNAL)
)

type ScoringProfile uint32

const (
	MinimalProfile           ScoringProfile = ScoringProfile(C.SBOM_TOOLS_PROFILE_MINIMAL)
	StandardProfile          ScoringProfile = ScoringProfile(C.SBOM_TOOLS_PROFILE_STANDARD)
	SecurityProfile          ScoringProfile = ScoringProfile(C.SBOM_TOOLS_PROFILE_SECURITY)
	LicenseComplianceProfile ScoringProfile = ScoringProfile(C.SBOM_TOOLS_PROFILE_LICENSE_COMPLIANCE)
	CRAProfile               ScoringProfile = ScoringProfile(C.SBOM_TOOLS_PROFILE_CRA)
	ComprehensiveProfile     ScoringProfile = ScoringProfile(C.SBOM_TOOLS_PROFILE_COMPREHENSIVE)
	AIReadinessProfile       ScoringProfile = ScoringProfile(C.SBOM_TOOLS_PROFILE_AI_READINESS)
)

type Error struct {
	Code    ErrorCode
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("sbom-tools ABI error (%d): %s", e.Code, e.Message)
}

type AbiVersion struct {
	ABIVersion   string `json:"abi_version"`
	CrateVersion string `json:"crate_version"`
}

type DetectedFormat struct {
	FormatName string   `json:"format_name"`
	Confidence float32  `json:"confidence"`
	Variant    *string  `json:"variant"`
	Version    *string  `json:"version"`
	Warnings   []string `json:"warnings"`
}

type NormalizedSbomComponentEntry struct {
	CanonicalID map[string]any `json:"canonical_id"`
	Component   map[string]any `json:"component"`
}

type NormalizedSbomPayload struct {
	Document           map[string]any                 `json:"document"`
	Components         []NormalizedSbomComponentEntry `json:"components"`
	Edges              []map[string]any               `json:"edges"`
	Extensions         map[string]any                 `json:"extensions"`
	ContentHash        uint64                         `json:"content_hash"`
	PrimaryComponentID map[string]any                 `json:"primary_component_id"`
	CollisionCount     uint64                         `json:"collision_count"`
}

type DedupStats struct {
	ComponentsRemoved uint64
	EdgesRemoved      uint64
}

func (p *NormalizedSbomPayload) Clone() *NormalizedSbomPayload {
	if p == nil {
		return nil
	}

	payload, err := json.Marshal(p)
	if err != nil {
		return nil
	}

	var cloned NormalizedSbomPayload
	if err := json.Unmarshal(payload, &cloned); err != nil {
		return nil
	}

	return &cloned
}

func (p *NormalizedSbomPayload) DeduplicateInPlace() (componentsRemoved uint64, edgesRemoved uint64) {
	if p == nil {
		return 0, 0
	}

	p.Components, componentsRemoved = dedupeComponentsLastWins(p.Components)
	p.Edges, edgesRemoved = dedupeMapsLastWins(p.Edges)

	return componentsRemoved, edgesRemoved
}

func (p *NormalizedSbomPayload) Deduplicated() (*NormalizedSbomPayload, uint64, uint64) {
	if p == nil {
		return nil, 0, 0
	}

	cloned := p.Clone()
	if cloned == nil {
		return nil, 0, 0
	}

	componentsRemoved, edgesRemoved := cloned.DeduplicateInPlace()
	return cloned, componentsRemoved, edgesRemoved
}

func stableJSONKey(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("marshal_error:%T", value)
	}
	return string(encoded)
}

func componentDedupKey(entry NormalizedSbomComponentEntry) string {
	return stableJSONKey(entry.CanonicalID)
}

func dedupeComponentsLastWins(entries []NormalizedSbomComponentEntry) ([]NormalizedSbomComponentEntry, uint64) {
	if len(entries) < 2 {
		return entries, 0
	}

	seen := make(map[string]struct{}, len(entries))
	keptReversed := make([]NormalizedSbomComponentEntry, 0, len(entries))

	for i := len(entries) - 1; i >= 0; i-- {
		key := componentDedupKey(entries[i])
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		keptReversed = append(keptReversed, entries[i])
	}

	for i, j := 0, len(keptReversed)-1; i < j; i, j = i+1, j-1 {
		keptReversed[i], keptReversed[j] = keptReversed[j], keptReversed[i]
	}

	removed := uint64(len(entries) - len(keptReversed))
	return keptReversed, removed
}

func dedupeMapsLastWins(entries []map[string]any) ([]map[string]any, uint64) {
	if len(entries) < 2 {
		return entries, 0
	}

	seen := make(map[string]struct{}, len(entries))
	keptReversed := make([]map[string]any, 0, len(entries))

	for i := len(entries) - 1; i >= 0; i-- {
		key := stableJSONKey(entries[i])
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		keptReversed = append(keptReversed, entries[i])
	}

	for i, j := 0, len(keptReversed)-1; i < j; i, j = i+1, j-1 {
		keptReversed[i], keptReversed[j] = keptReversed[j], keptReversed[i]
	}

	removed := uint64(len(entries) - len(keptReversed))
	return keptReversed, removed
}

type DiffSummary struct {
	TotalChanges              uint64 `json:"total_changes"`
	ComponentsAdded           uint64 `json:"components_added"`
	ComponentsRemoved         uint64 `json:"components_removed"`
	ComponentsModified        uint64 `json:"components_modified"`
	DependenciesAdded         uint64 `json:"dependencies_added"`
	DependenciesRemoved       uint64 `json:"dependencies_removed"`
	VulnerabilitiesIntroduced uint64 `json:"vulnerabilities_introduced"`
	VulnerabilitiesResolved   uint64 `json:"vulnerabilities_resolved"`
	VulnerabilitiesPersistent uint64 `json:"vulnerabilities_persistent"`
	LicensesAdded             uint64 `json:"licenses_added"`
	LicensesRemoved           uint64 `json:"licenses_removed"`
	GraphChangesCount         uint64 `json:"graph_changes_count"`
}

type DiffResultPayload struct {
	Summary       DiffSummary `json:"summary"`
	SemanticScore float64     `json:"semantic_score"`
	RulesApplied  uint64      `json:"rules_applied"`
}

type QualityReportPayload struct {
	OverallScore    float64          `json:"overall_score"`
	Grade           string           `json:"grade"`
	Profile         string           `json:"profile"`
	Compliance      map[string]any   `json:"compliance"`
	Recommendations []map[string]any `json:"recommendations"`
}

func Version() (*AbiVersion, error) {
	payload, err := consumeResult(C.sbom_tools_abi_version_json())
	if err != nil {
		return nil, err
	}

	var version AbiVersion
	if err := json.Unmarshal(payload, &version); err != nil {
		return nil, err
	}
	return &version, nil
}

func DetectFormat(content string) (*DetectedFormat, error) {
	input, cleanup := makeCString(content)
	defer cleanup()

	payload, err := consumeResult(C.sbom_tools_detect_format_json(input))
	if err != nil {
		return nil, err
	}
	if string(payload) == "null" {
		return nil, nil
	}

	var detected DetectedFormat
	if err := json.Unmarshal(payload, &detected); err != nil {
		return nil, err
	}
	return &detected, nil
}

func ParsePathJSON(path string) ([]byte, error) {
	input, cleanup := makeCString(path)
	defer cleanup()
	return consumeResult(C.sbom_tools_parse_sbom_path_json(input))
}

func ParsePath(path string) (*NormalizedSbomPayload, error) {
	payload, err := ParsePathJSON(path)
	if err != nil {
		return nil, err
	}
	return Decode[NormalizedSbomPayload](payload)
}

func ParseStringJSON(content string) ([]byte, error) {
	input, cleanup := makeCString(content)
	defer cleanup()
	return consumeResult(C.sbom_tools_parse_sbom_str_json(input))
}

func ParseString(content string) (*NormalizedSbomPayload, error) {
	payload, err := ParseStringJSON(content)
	if err != nil {
		return nil, err
	}
	return Decode[NormalizedSbomPayload](payload)
}

func DiffJSON(oldJSON, newJSON []byte) ([]byte, error) {
	oldInput, oldCleanup := makeCString(string(oldJSON))
	defer oldCleanup()
	newInput, newCleanup := makeCString(string(newJSON))
	defer newCleanup()

	return consumeResult(C.sbom_tools_diff_sboms_json(oldInput, newInput))
}

func Diff(oldPayload, newPayload *NormalizedSbomPayload) (*DiffResultPayload, error) {
	if oldPayload == nil || newPayload == nil {
		return nil, fmt.Errorf("oldPayload and newPayload must not be nil")
	}

	oldJSON, err := json.Marshal(oldPayload)
	if err != nil {
		return nil, err
	}
	newJSON, err := json.Marshal(newPayload)
	if err != nil {
		return nil, err
	}

	payload, err := DiffJSON(oldJSON, newJSON)
	if err != nil {
		return nil, err
	}
	return Decode[DiffResultPayload](payload)
}

func DiffDeduplicated(oldPayload, newPayload *NormalizedSbomPayload) (*DiffResultPayload, DedupStats, DedupStats, error) {
	if oldPayload == nil || newPayload == nil {
		return nil, DedupStats{}, DedupStats{}, fmt.Errorf("oldPayload and newPayload must not be nil")
	}

	oldCopy, oldComponentsRemoved, oldEdgesRemoved := oldPayload.Deduplicated()
	if oldCopy == nil {
		return nil, DedupStats{}, DedupStats{}, fmt.Errorf("failed to clone oldPayload for deduplication")
	}

	newCopy, newComponentsRemoved, newEdgesRemoved := newPayload.Deduplicated()
	if newCopy == nil {
		return nil, DedupStats{}, DedupStats{}, fmt.Errorf("failed to clone newPayload for deduplication")
	}

	diff, err := Diff(oldCopy, newCopy)
	if err != nil {
		return nil, DedupStats{}, DedupStats{}, err
	}

	oldStats := DedupStats{ComponentsRemoved: oldComponentsRemoved, EdgesRemoved: oldEdgesRemoved}
	newStats := DedupStats{ComponentsRemoved: newComponentsRemoved, EdgesRemoved: newEdgesRemoved}
	return diff, oldStats, newStats, nil
}

func ScoreJSON(sbomJSON []byte, profile ScoringProfile) ([]byte, error) {
	input, cleanup := makeCString(string(sbomJSON))
	defer cleanup()

	return consumeResult(C.sbom_tools_score_sbom_json(
		input,
		C.SbomToolsScoringProfile(profile),
	))
}

func Score(sbomPayload *NormalizedSbomPayload, profile ScoringProfile) (*QualityReportPayload, error) {
	if sbomPayload == nil {
		return nil, fmt.Errorf("sbomPayload must not be nil")
	}

	sbomJSON, err := json.Marshal(sbomPayload)
	if err != nil {
		return nil, err
	}

	payload, err := ScoreJSON(sbomJSON, profile)
	if err != nil {
		return nil, err
	}
	return Decode[QualityReportPayload](payload)
}

func ScoreDeduplicated(sbomPayload *NormalizedSbomPayload, profile ScoringProfile) (*QualityReportPayload, DedupStats, error) {
	if sbomPayload == nil {
		return nil, DedupStats{}, fmt.Errorf("sbomPayload must not be nil")
	}

	sbomCopy, componentsRemoved, edgesRemoved := sbomPayload.Deduplicated()
	if sbomCopy == nil {
		return nil, DedupStats{}, fmt.Errorf("failed to clone sbomPayload for deduplication")
	}

	report, err := Score(sbomCopy, profile)
	if err != nil {
		return nil, DedupStats{}, err
	}

	stats := DedupStats{ComponentsRemoved: componentsRemoved, EdgesRemoved: edgesRemoved}
	return report, stats, nil
}

func Decode[T any](payload []byte) (*T, error) {
	var value T
	if err := json.Unmarshal(payload, &value); err != nil {
		return nil, err
	}
	return &value, nil
}

func consumeResult(result C.SbomToolsStringResult) ([]byte, error) {
	// SAFETY: Free the result after we extract data. Passed by value per C ABI.
	// Pointer zeroing in free() defends against accidental double-free on copies.
	defer C.sbom_tools_string_result_free(result)

	if result.error_code != C.SBOM_TOOLS_ERROR_OK {
		var message string
		if result.error_message != nil {
			message = C.GoString(result.error_message)
		}
		// Provide context if error_message is NULL (Rust into_c_string() may have failed on line 164)
		if message == "" {
			message = fmt.Sprintf("unknown ABI error (code %d) - error message allocation failed in Rust", result.error_code)
		}
		return nil, &Error{Code: ErrorCode(result.error_code), Message: message}
	}

	// OK response: data should be valid pointer. If NULL, return empty bytes as safeguard.
	if result.data == nil {
		return []byte{}, nil
	}

	return []byte(C.GoString(result.data)), nil
}

func makeCString(value string) (*C.char, func()) {
	input := C.CString(value)
	cleanup := func() {
		C.free(unsafe.Pointer(input))
	}
	return input, cleanup
}
