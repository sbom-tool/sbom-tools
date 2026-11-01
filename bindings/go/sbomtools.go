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
	DescribedRootIDs   []map[string]any               `json:"described_root_ids,omitempty"`
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

// RunOptions are the inputs of a compliance run, as the CLI's shared
// compliance flags give them. Zero values are left out, so the defaults
// apply.
type RunOptions struct {
	// AsOf pins the evaluation clock (--as-of): an RFC 3339 datetime, an
	// offset-less datetime taken as UTC, or a date (midnight UTC).
	AsOf string `json:"as_of,omitempty"`

	// Sidecar is a CRA sidecar object, with the keys of a .cra.json file
	// (--cra-sidecar), e.g. the bytes of that file.
	Sidecar json.RawMessage `json:"sidecar,omitempty"`

	// ProductClass is the CRA product class (--cra-product-class).
	ProductClass string `json:"product_class,omitempty"`

	// PqcMode is "readiness" or "deadline" (--pqc-mode).
	PqcMode string `json:"pqc_mode,omitempty"`

	// PqcProfile applies only with PqcMode "deadline" (--pqc-profile).
	PqcProfile string `json:"pqc_profile,omitempty"`

	// CnsaCategory applies only with PqcMode "deadline" (--cnsa-category).
	CnsaCategory string `json:"cnsa_category,omitempty"`

	// Rules maps a rule id to "off", "info", "warning" or "error" (--rule).
	Rules map[string]string `json:"rules,omitempty"`

	// IncludeExcludedScope judges components whose scope is excluded too
	// (--include-excluded-scope).
	IncludeExcludedScope bool `json:"include_excluded_scope,omitempty"`
}

// ValidateOptions are the inputs of Validate: the standards, the name of
// the SBOM's file, and the run options.
type ValidateOptions struct {
	// Standards are --standard names or aliases; empty means ntia.
	Standards []string `json:"standards,omitempty"`

	// FileName is the file the content was read from, which the envelope's
	// subject names without its directory, as `validate <FILE>` does; empty
	// names no file, as for standard input.
	FileName string `json:"file_name,omitempty"`

	RunOptions
}

// ScoreOptions are the inputs of ScoreWithOptions: the profile and the run
// options.
type ScoreOptions struct {
	// Profile is a `quality --profile` name; empty means standard.
	Profile string `json:"profile,omitempty"`

	RunOptions
}

// ToolInfo names the tool that wrote a compliance envelope or a rule
// catalogue.
type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ComplianceEnvelope is the sbom-tools/compliance/v2 document Validate
// returns, as `sbom-tools validate -o json` writes it. AsOf is the instant
// every standard was judged at (RFC 3339, UTC), and Subject the SBOM the
// results judge.
type ComplianceEnvelope struct {
	Schema  string             `json:"schema"`
	Tool    ToolInfo           `json:"tool"`
	AsOf    string             `json:"as_of"`
	Subject ComplianceSubject  `json:"subject"`
	Results []ComplianceResult `json:"results"`
}

// ComplianceSubject is the SBOM a compliance envelope judges, and how its
// document was read. SHA256 is the lowercase hex SHA-256 of the content
// passed in, and FileName is ValidateOptions.FileName without its directory.
type ComplianceSubject struct {
	SHA256            string           `json:"sha256"`
	Format            string           `json:"format"`
	SpecVersion       string           `json:"spec_version"`
	FileName          string           `json:"file_name,omitempty"`
	Components        int              `json:"components"`
	Duplicates        DuplicateSummary `json:"duplicates"`
	TimestampUnparsed bool             `json:"timestamp_unparsed"`
}

// DuplicateSummary counts the components a document lists more than once,
// whose entries were merged into one each.
type DuplicateSummary struct {
	Components int      `json:"components"`
	Entries    int      `json:"entries"`
	Conflicts  []string `json:"conflicts"`
}

// ComplianceResult is one standard's verdict.
type ComplianceResult struct {
	Standard            string           `json:"standard"`
	Name                string           `json:"name"`
	Applicable          bool             `json:"applicable"`
	NotApplicableReason string           `json:"not_applicable_reason,omitempty"`
	Compliant           bool             `json:"compliant"`
	Score               *int             `json:"score"`
	ScoreBasis          *ScoreBasis      `json:"score_basis,omitempty"`
	Counts              ComplianceCounts `json:"counts"`
	Violations          []Violation      `json:"violations"`
	Passed              []PassedCheck    `json:"passed"`
	Evaluated           []RuleEvaluation `json:"evaluated,omitempty"`
	Suppressed          []SuppressedRule `json:"suppressed,omitempty"`
	ExcludedComponents  int              `json:"excluded_components,omitempty"`
	ConformitySummary   map[string]any   `json:"conformity_summary,omitempty"`
}

// ScoreBasis is what a result's score is computed from.
type ScoreBasis struct {
	Checked int `json:"checked"`
	Failed  int `json:"failed"`
}

// ComplianceCounts counts a result's findings by severity, its passed checks
// and the findings the rule settings turned off.
type ComplianceCounts struct {
	Error      int `json:"error"`
	Warning    int `json:"warning"`
	Info       int `json:"info"`
	Passed     int `json:"passed"`
	Suppressed int `json:"suppressed,omitempty"`
}

// Violation is one finding of a standard.
type Violation struct {
	FindingID       string           `json:"finding_id"`
	FindingKey      string           `json:"finding_key"`
	Severity        string           `json:"severity"`
	DefaultSeverity string           `json:"default_severity,omitempty"`
	SeveritySource  string           `json:"severity_source,omitempty"`
	Category        string           `json:"category"`
	Message         string           `json:"message"`
	Element         *string          `json:"element"`
	ComponentID     string           `json:"component_id,omitempty"`
	FindingDetail   string           `json:"finding_detail,omitempty"`
	Counts          *ViolationCounts `json:"counts,omitempty"`
	Deadline        string           `json:"deadline,omitempty"`
	DeadlineSource  string           `json:"deadline_source,omitempty"`
	Field           string           `json:"field,omitempty"`
	Observed        string           `json:"observed,omitempty"`
	Requirement     string           `json:"requirement"`
	RuleID          string           `json:"rule_id"`
	SarifRuleID     string           `json:"sarif_rule_id"`
	StandardRefs    []StandardRef    `json:"standard_refs,omitempty"`
	Remediation     string           `json:"remediation,omitempty"`
	HelpURI         string           `json:"help_uri,omitempty"`
}

// PassedCheck is a check the SBOM passed; it is not a violation.
type PassedCheck struct {
	FindingID     string        `json:"finding_id"`
	FindingKey    string        `json:"finding_key"`
	Message       string        `json:"message"`
	Element       *string       `json:"element"`
	ComponentID   string        `json:"component_id,omitempty"`
	FindingDetail string        `json:"finding_detail,omitempty"`
	Requirement   string        `json:"requirement"`
	RuleID        string        `json:"rule_id"`
	SarifRuleID   string        `json:"sarif_rule_id"`
	StandardRefs  []StandardRef `json:"standard_refs,omitempty"`
}

// ViolationCounts says how many of a set an aggregate finding is about.
type ViolationCounts struct {
	Affected int `json:"affected"`
	Total    int `json:"total"`
}

// StandardRef is a clause a finding cites.
type StandardRef struct {
	Standard string `json:"standard"`
	ID       string `json:"id"`
	HelpURI  string `json:"help_uri,omitempty"`
}

// RuleEvaluation is a check the standard did not evaluate, with the reason.
type RuleEvaluation struct {
	RuleID string `json:"rule_id"`
	Status string `json:"status"`
	Reason string `json:"reason"`
}

// SuppressedRule is a rule the run's settings turned off.
type SuppressedRule struct {
	RuleID   string `json:"rule_id"`
	Findings int    `json:"findings"`
	Source   string `json:"source"`
}

// RuleCatalogDocument is the sbom-tools/rules/v1 document RuleCatalog
// returns, as `sbom-tools rules -o json` prints it.
type RuleCatalogDocument struct {
	Schema string             `json:"schema"`
	Tool   ToolInfo           `json:"tool"`
	Rules  []RuleCatalogEntry `json:"rules"`
}

// RuleCatalogEntry is everything the registry records about one rule.
type RuleCatalogEntry struct {
	ID                 string          `json:"id"`
	Name               string          `json:"name"`
	Description        string          `json:"description"`
	DefaultSeverity    string          `json:"default_severity"`
	Kind               string          `json:"kind"`
	Fallback           bool            `json:"fallback"`
	Standards          []string        `json:"standards"`
	References         []RuleReference `json:"references"`
	HelpURI            string          `json:"help_uri,omitempty"`
	Remediation        string          `json:"remediation"`
	RemediationSummary string          `json:"remediation_summary"`
	Advice             *RuleAdvice     `json:"advice,omitempty"`
}

// RuleReference is a clause a rule implements.
type RuleReference struct {
	Standard string `json:"standard"`
	ID       string `json:"id"`
	Label    string `json:"label"`
	HelpURI  string `json:"help_uri,omitempty"`
}

// RuleAdvice says where a rule's fix goes in each SBOM format.
type RuleAdvice struct {
	CycloneDX RuleFormatAdvice `json:"cyclonedx"`
	SPDX2     RuleFormatAdvice `json:"spdx2"`
	SPDX3     RuleFormatAdvice `json:"spdx3"`
}

// RuleFormatAdvice is a rule's fix in one SBOM format.
type RuleFormatAdvice struct {
	Text  string `json:"text"`
	Field string `json:"field,omitempty"`
}

// ScoreReport is the quality report ScoreWithOptions returns: the profile
// named as `quality --profile` names it, and the compliance check as an
// entry of the compliance envelope's results.
type ScoreReport struct {
	ScoringEngineVersion string           `json:"scoring_engine_version"`
	OverallScore         float64          `json:"overall_score"`
	Grade                string           `json:"grade"`
	Profile              string           `json:"profile"`
	CompletenessScore    float64          `json:"completeness_score"`
	IdentifierScore      float64          `json:"identifier_score"`
	LicenseScore         float64          `json:"license_score"`
	VulnerabilityScore   *float64         `json:"vulnerability_score"`
	DependencyScore      float64          `json:"dependency_score"`
	IntegrityScore       float64          `json:"integrity_score"`
	ProvenanceScore      float64          `json:"provenance_score"`
	LifecycleScore       *float64         `json:"lifecycle_score"`
	CryptographyScore    *float64         `json:"cryptography_score"`
	Compliance           ComplianceResult `json:"compliance"`
	Recommendations      []map[string]any `json:"recommendations"`
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

// ValidateJSON validates raw SBOM content against compliance standards and
// returns the sbom-tools/compliance/v2 envelope: byte for byte what
// `sbom-tools validate - -o json` writes for the same content and options
// (`validate <FILE>` when options.FileName names the file). The subject's
// SHA-256 is over exactly the content passed in, and the envelope's AsOf is
// options.AsOf, else the wall clock when the call starts, to the second.
func ValidateJSON(content string, options ValidateOptions) ([]byte, error) {
	optionsJSON, err := json.Marshal(options)
	if err != nil {
		return nil, err
	}

	input, cleanup := makeCString(content)
	defer cleanup()
	optionsInput, optionsCleanup := makeCString(string(optionsJSON))
	defer optionsCleanup()

	return consumeResult(C.sbom_tools_validate_json(input, optionsInput))
}

// Validate validates raw SBOM content against compliance standards and
// returns the decoded compliance envelope.
func Validate(content string, options ValidateOptions) (*ComplianceEnvelope, error) {
	payload, err := ValidateJSON(content, options)
	if err != nil {
		return nil, err
	}
	return Decode[ComplianceEnvelope](payload)
}

// RuleCatalogJSON returns the sbom-tools/rules/v1 rule catalogue: every
// rule, or the rules of the given --standard names.
func RuleCatalogJSON(standards ...string) ([]byte, error) {
	filter := struct {
		Standards []string `json:"standards,omitempty"`
	}{Standards: standards}
	filterJSON, err := json.Marshal(filter)
	if err != nil {
		return nil, err
	}

	input, cleanup := makeCString(string(filterJSON))
	defer cleanup()

	return consumeResult(C.sbom_tools_rule_catalog_json(input))
}

// RuleCatalog returns the decoded rule catalogue: every rule, or the rules
// of the given --standard names.
func RuleCatalog(standards ...string) (*RuleCatalogDocument, error) {
	payload, err := RuleCatalogJSON(standards...)
	if err != nil {
		return nil, err
	}
	return Decode[RuleCatalogDocument](payload)
}

// ScoreWithOptionsJSON scores normalized SBOM JSON with a profile and the
// run options, judged at options.AsOf.
func ScoreWithOptionsJSON(sbomJSON []byte, options ScoreOptions) ([]byte, error) {
	optionsJSON, err := json.Marshal(options)
	if err != nil {
		return nil, err
	}

	input, cleanup := makeCString(string(sbomJSON))
	defer cleanup()
	optionsInput, optionsCleanup := makeCString(string(optionsJSON))
	defer optionsCleanup()

	return consumeResult(C.sbom_tools_score_sbom_with_options_json(input, optionsInput))
}

// ScoreWithOptions scores a normalized SBOM with a profile and the run
// options and returns the decoded report.
func ScoreWithOptions(sbomPayload *NormalizedSbomPayload, options ScoreOptions) (*ScoreReport, error) {
	if sbomPayload == nil {
		return nil, fmt.Errorf("sbomPayload must not be nil")
	}

	sbomJSON, err := json.Marshal(sbomPayload)
	if err != nil {
		return nil, err
	}

	payload, err := ScoreWithOptionsJSON(sbomJSON, options)
	if err != nil {
		return nil, err
	}
	return Decode[ScoreReport](payload)
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
