package sbomtools

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixturePath(name string) string {
	return filepath.Join("..", "..", "tests", "fixtures", name)
}

func TestVersionAndDetectFormat(t *testing.T) {
	version, err := Version()
	if err != nil {
		t.Fatalf("Version() failed: %v", err)
	}
	if version.ABIVersion == "" || version.CrateVersion == "" {
		t.Fatalf("expected ABI and crate versions, got %+v", version)
	}

	content, err := os.ReadFile(fixturePath(filepath.Join("cyclonedx", "minimal.cdx.json")))
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}
	detected, err := DetectFormat(string(content))
	if err != nil {
		t.Fatalf("DetectFormat() failed: %v", err)
	}
	if detected == nil || detected.FormatName != "CycloneDX" {
		t.Fatalf("unexpected detection result: %+v", detected)
	}
}

func TestParseDiffAndScoreJSON(t *testing.T) {
	oldJSON, err := ParsePathJSON(fixturePath("demo-old.cdx.json"))
	if err != nil {
		t.Fatalf("ParsePathJSON(old) failed: %v", err)
	}
	newJSON, err := ParsePathJSON(fixturePath("demo-new.cdx.json"))
	if err != nil {
		t.Fatalf("ParsePathJSON(new) failed: %v", err)
	}

	diffJSON, err := DiffJSON(oldJSON, newJSON)
	if err != nil {
		t.Fatalf("DiffJSON() failed: %v", err)
	}
	var diff map[string]any
	if err := json.Unmarshal(diffJSON, &diff); err != nil {
		t.Fatalf("failed to decode diff JSON: %v", err)
	}

	summary := diff["summary"].(map[string]any)
	if summary["total_changes"].(float64) <= 0 {
		t.Fatalf("expected total_changes > 0, got %#v", summary)
	}

	scoreJSON, err := ScoreJSON(newJSON, StandardProfile)
	if err != nil {
		t.Fatalf("ScoreJSON() failed: %v", err)
	}
	var score map[string]any
	if err := json.Unmarshal(scoreJSON, &score); err != nil {
		t.Fatalf("failed to decode score JSON: %v", err)
	}
	if score["overall_score"].(float64) <= 0 {
		t.Fatalf("expected overall_score > 0, got %#v", score)
	}
}

func TestDiffRejectsInvalidNormalizedJSON(t *testing.T) {
	_, err := DiffJSON([]byte("{not-json}"), []byte("{not-json}"))
	if err == nil {
		t.Fatal("expected DiffJSON to fail for invalid normalized JSON")
	}
	abiErr, ok := err.(*Error)
	if !ok {
		t.Fatalf("expected ABI error, got %T", err)
	}
	if abiErr.Code != ErrorCodeValidation {
		t.Fatalf("expected validation error, got %+v", abiErr)
	}
}

func TestTypedHelpers(t *testing.T) {
	oldPayload, err := ParsePath(fixturePath("demo-old.cdx.json"))
	if err != nil {
		t.Fatalf("ParsePath(old) failed: %v", err)
	}
	newPayload, err := ParsePath(fixturePath("demo-new.cdx.json"))
	if err != nil {
		t.Fatalf("ParsePath(new) failed: %v", err)
	}

	diffPayload, err := Diff(oldPayload, newPayload)
	if err != nil {
		t.Fatalf("Diff() failed: %v", err)
	}
	if diffPayload.Summary.TotalChanges == 0 {
		t.Fatalf("expected non-zero total changes, got %+v", diffPayload.Summary)
	}

	quality, err := Score(newPayload, StandardProfile)
	if err != nil {
		t.Fatalf("Score() failed: %v", err)
	}
	if quality.OverallScore <= 0 {
		t.Fatalf("expected positive score, got %+v", quality)
	}
}

func TestDeduplicateInPlace_LastWins(t *testing.T) {
	payload := &NormalizedSbomPayload{
		Components: []NormalizedSbomComponentEntry{
			{
				CanonicalID: map[string]any{"purl": "pkg:npm/example@1.0.0"},
				Component:   map[string]any{"name": "example", "version": "1.0.0"},
			},
			{
				CanonicalID: map[string]any{"purl": "pkg:npm/unique@1.0.0"},
				Component:   map[string]any{"name": "unique", "version": "1.0.0"},
			},
			{
				CanonicalID: map[string]any{"purl": "pkg:npm/example@1.0.0"},
				Component:   map[string]any{"name": "example", "version": "2.0.0", "note": "last"},
			},
		},
		Edges: []map[string]any{
			{"from": "pkg:npm/example@1.0.0", "to": "pkg:npm/dep@1.0.0"},
			{"from": "pkg:npm/example@1.0.0", "to": "pkg:npm/dep@1.0.0"},
			{"from": "pkg:npm/unique@1.0.0", "to": "pkg:npm/dep@2.0.0"},
		},
	}

	componentsRemoved, edgesRemoved := payload.DeduplicateInPlace()

	if componentsRemoved != 1 {
		t.Fatalf("expected 1 component removed, got %d", componentsRemoved)
	}
	if edgesRemoved != 1 {
		t.Fatalf("expected 1 edge removed, got %d", edgesRemoved)
	}
	if len(payload.Components) != 2 {
		t.Fatalf("expected 2 components after dedupe, got %d", len(payload.Components))
	}
	if len(payload.Edges) != 2 {
		t.Fatalf("expected 2 edges after dedupe, got %d", len(payload.Edges))
	}

	lastDuplicateFound := false
	for _, entry := range payload.Components {
		if entry.CanonicalID["purl"] == "pkg:npm/example@1.0.0" {
			lastDuplicateFound = true
			if entry.Component["version"] != "2.0.0" {
				t.Fatalf("expected last duplicate component version 2.0.0, got %#v", entry.Component["version"])
			}
		}
	}
	if !lastDuplicateFound {
		t.Fatal("expected deduped component for duplicate canonical_id")
	}

	duplicateEdgeKey := stableJSONKey(map[string]any{"from": "pkg:npm/example@1.0.0", "to": "pkg:npm/dep@1.0.0"})
	duplicateEdgeCount := 0
	for _, edge := range payload.Edges {
		if stableJSONKey(edge) == duplicateEdgeKey {
			duplicateEdgeCount++
		}
	}
	if duplicateEdgeCount != 1 {
		t.Fatalf("expected exactly one retained duplicate edge, got %d", duplicateEdgeCount)
	}
}

func TestDeduplicated_DoesNotMutateOriginal(t *testing.T) {
	payload := &NormalizedSbomPayload{
		Components: []NormalizedSbomComponentEntry{
			{
				CanonicalID: map[string]any{"purl": "pkg:npm/example@1.0.0"},
				Component:   map[string]any{"name": "example", "version": "1.0.0"},
			},
			{
				CanonicalID: map[string]any{"purl": "pkg:npm/example@1.0.0"},
				Component:   map[string]any{"name": "example", "version": "2.0.0"},
			},
		},
		Edges: []map[string]any{
			{"from": "pkg:npm/example@1.0.0", "to": "pkg:npm/dep@1.0.0"},
			{"from": "pkg:npm/example@1.0.0", "to": "pkg:npm/dep@1.0.0"},
		},
	}

	originalComponentCount := len(payload.Components)
	originalEdgeCount := len(payload.Edges)

	deduped, componentsRemoved, edgesRemoved := payload.Deduplicated()
	if deduped == nil {
		t.Fatal("expected non-nil deduplicated payload")
	}
	if deduped == payload {
		t.Fatal("expected deduplicated payload to be a clone, got same pointer")
	}
	if componentsRemoved != 1 {
		t.Fatalf("expected 1 component removed, got %d", componentsRemoved)
	}
	if edgesRemoved != 1 {
		t.Fatalf("expected 1 edge removed, got %d", edgesRemoved)
	}
	if len(deduped.Components) != 1 {
		t.Fatalf("expected deduplicated components length 1, got %d", len(deduped.Components))
	}
	if len(deduped.Edges) != 1 {
		t.Fatalf("expected deduplicated edges length 1, got %d", len(deduped.Edges))
	}

	if len(payload.Components) != originalComponentCount {
		t.Fatalf("expected original component count to remain %d, got %d", originalComponentCount, len(payload.Components))
	}
	if len(payload.Edges) != originalEdgeCount {
		t.Fatalf("expected original edge count to remain %d, got %d", originalEdgeCount, len(payload.Edges))
	}
}

func TestDeduplicateNilPayload(t *testing.T) {
	var payload *NormalizedSbomPayload = nil

	componentsRemoved, edgesRemoved := payload.DeduplicateInPlace()
	if componentsRemoved != 0 || edgesRemoved != 0 {
		t.Fatalf("expected zero removals for nil payload, got components=%d edges=%d", componentsRemoved, edgesRemoved)
	}

	deduped, dedupedComponentsRemoved, dedupedEdgesRemoved := payload.Deduplicated()
	if deduped != nil {
		t.Fatalf("expected nil deduplicated payload for nil receiver, got %#v", deduped)
	}
	if dedupedComponentsRemoved != 0 || dedupedEdgesRemoved != 0 {
		t.Fatalf(
			"expected zero removals from Deduplicated() for nil payload, got components=%d edges=%d",
			dedupedComponentsRemoved,
			dedupedEdgesRemoved,
		)
	}
}

func TestDiffAndScoreDeduplicatedHelpers(t *testing.T) {
	payload, err := ParsePath(fixturePath("demo-old.cdx.json"))
	if err != nil {
		t.Fatalf("ParsePath() failed: %v", err)
	}
	if payload == nil || len(payload.Components) == 0 {
		t.Fatal("expected parsed payload with at least one component")
	}

	payload.Components = append(payload.Components, payload.Components[0])

	if len(payload.Edges) > 0 {
		payload.Edges = append(payload.Edges, payload.Edges[0])
	} else {
		edge := map[string]any{
			"from":         payload.Components[0].CanonicalID,
			"to":           payload.Components[0].CanonicalID,
			"relationship": "DependsOn",
			"scope":        nil,
		}
		payload.Edges = append(payload.Edges, edge, edge)
	}

	diff, oldStats, newStats, err := DiffDeduplicated(payload, payload)
	if err != nil {
		t.Fatalf("DiffDeduplicated() failed: %v", err)
	}
	if diff == nil {
		t.Fatal("expected non-nil diff")
	}
	if oldStats.ComponentsRemoved < 1 || oldStats.EdgesRemoved < 1 {
		t.Fatalf("unexpected old dedup stats: %+v", oldStats)
	}
	if newStats.ComponentsRemoved < 1 || newStats.EdgesRemoved < 1 {
		t.Fatalf("unexpected new dedup stats: %+v", newStats)
	}

	quality, scoreStats, err := ScoreDeduplicated(payload, StandardProfile)
	if err != nil {
		t.Fatalf("ScoreDeduplicated() failed: %v", err)
	}
	if quality == nil {
		t.Fatal("expected non-nil quality report")
	}
	if scoreStats.ComponentsRemoved < 1 || scoreStats.EdgesRemoved < 1 {
		t.Fatalf("unexpected score dedup stats: %+v", scoreStats)
	}
}

func readFixture(t *testing.T, name string) string {
	t.Helper()
	content, err := os.ReadFile(fixturePath(name))
	if err != nil {
		t.Fatalf("failed to read fixture %s: %v", name, err)
	}
	return string(content)
}

func TestValidateReturnsTheComplianceEnvelope(t *testing.T) {
	content := readFixture(t, "demo-new.cdx.json")
	options := ValidateOptions{
		Standards:  []string{"cra", "NTIA", "cra-phase2"},
		RunOptions: RunOptions{AsOf: "2027-01-01", ProductClass: "important-class-1"},
	}

	envelope, err := Validate(content, options)
	if err != nil {
		t.Fatalf("Validate() failed: %v", err)
	}
	if envelope.Schema != "sbom-tools/compliance/v2" || envelope.Tool.Name != "sbom-tools" {
		t.Fatalf("unexpected envelope header: %+v", envelope)
	}
	if envelope.AsOf != "2027-01-01T00:00:00Z" {
		t.Fatalf("expected the pinned instant, got %q", envelope.AsOf)
	}
	digest := sha256.Sum256([]byte(content))
	if envelope.Subject.SHA256 != hex.EncodeToString(digest[:]) || envelope.Subject.FileName != "" {
		t.Fatalf("unexpected subject: %+v", envelope.Subject)
	}
	if envelope.Subject.Format != "CycloneDX" || envelope.Subject.Components == 0 {
		t.Fatalf("unexpected subject: %+v", envelope.Subject)
	}
	// cra-phase2 names the level cra already selected, so it is checked once.
	if len(envelope.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(envelope.Results))
	}
	if envelope.Results[0].Standard != "cra" || envelope.Results[1].Standard != "ntia" {
		t.Fatalf("unexpected standards: %s, %s", envelope.Results[0].Standard, envelope.Results[1].Standard)
	}
	cra := envelope.Results[0]
	if cra.Compliant || cra.Counts.Error == 0 || len(cra.Violations) == 0 {
		t.Fatalf("expected CRA errors on the demo SBOM, got %+v", cra.Counts)
	}
	for _, violation := range cra.Violations {
		if !strings.HasPrefix(violation.FindingID, "sbomtools:v1:") || violation.RuleID == "" {
			t.Fatalf("finding without identity: %+v", violation)
		}
	}

	raw, err := ValidateJSON(content, options)
	if err != nil {
		t.Fatalf("ValidateJSON() failed: %v", err)
	}
	decoded, err := Decode[ComplianceEnvelope](raw)
	if err != nil {
		t.Fatalf("failed to decode ValidateJSON(): %v", err)
	}
	if len(decoded.Results) != len(envelope.Results) {
		t.Fatal("ValidateJSON() and Validate() disagree")
	}

	options.FileName = filepath.Join("some", "dir", "demo-new.cdx.json")
	named, err := Validate(content, options)
	if err != nil {
		t.Fatalf("Validate() with FileName failed: %v", err)
	}
	if named.Subject.FileName != "demo-new.cdx.json" {
		t.Fatalf("expected the file name without its directory, got %q", named.Subject.FileName)
	}
}

func TestValidateAppliesSidecarAndRuleSettings(t *testing.T) {
	content := readFixture(t, filepath.Join("cra", "cra-compliant.cdx.json"))
	sidecar := readFixture(t, filepath.Join("cra", "cra-compliant.cra.json"))

	envelope, err := Validate(content, ValidateOptions{
		Standards: []string{"cra"},
		RunOptions: RunOptions{
			AsOf:    "2027-12-11",
			Sidecar: json.RawMessage(sidecar),
			Rules:   map[string]string{"SBOM-CRA-SBOM-FRESHNESS": "error"},
		},
	})
	if err != nil {
		t.Fatalf("Validate() failed: %v", err)
	}
	found := false
	for _, violation := range envelope.Results[0].Violations {
		if violation.RuleID == "SBOM-CRA-SBOM-FRESHNESS" {
			found = true
			if violation.Severity != "Error" || violation.SeveritySource != "cli" || violation.DefaultSeverity == "" {
				t.Fatalf("rule setting not applied: %+v", violation)
			}
		}
	}
	if !found {
		t.Fatal("expected a SBOM-CRA-SBOM-FRESHNESS finding")
	}
}

func TestValidateRejectsInvalidOptions(t *testing.T) {
	content := readFixture(t, filepath.Join("cyclonedx", "minimal.cdx.json"))
	cases := []ValidateOptions{
		{Standards: []string{"ntai"}},
		{RunOptions: RunOptions{AsOf: "01/01/2027"}},
		{RunOptions: RunOptions{PqcProfile: "federal"}},
		{RunOptions: RunOptions{Rules: map[string]string{"SBOM-NTIA-SUPLIER": "off"}}},
		{RunOptions: RunOptions{Sidecar: json.RawMessage(`{"security_contact": "x"}`)}},
	}
	for _, options := range cases {
		_, err := Validate(content, options)
		abiErr, ok := err.(*Error)
		if !ok || abiErr.Code != ErrorCodeValidation {
			t.Fatalf("expected a validation error for %+v, got %v", options, err)
		}
	}
}

func TestRuleCatalog(t *testing.T) {
	catalog, err := RuleCatalog()
	if err != nil {
		t.Fatalf("RuleCatalog() failed: %v", err)
	}
	if catalog.Schema != "sbom-tools/rules/v1" || len(catalog.Rules) < 100 {
		t.Fatalf("unexpected catalogue: %s with %d rules", catalog.Schema, len(catalog.Rules))
	}

	ntia, err := RuleCatalog("ntia")
	if err != nil {
		t.Fatalf("RuleCatalog(ntia) failed: %v", err)
	}
	if len(ntia.Rules) == 0 || len(ntia.Rules) >= len(catalog.Rules) {
		t.Fatalf("expected a subset, got %d of %d rules", len(ntia.Rules), len(catalog.Rules))
	}
	for _, rule := range ntia.Rules {
		listed := false
		for _, standard := range rule.Standards {
			listed = listed || standard == "ntia"
		}
		if !listed {
			t.Fatalf("rule %s is not an ntia rule: %v", rule.ID, rule.Standards)
		}
	}

	if _, err := RuleCatalog("crab"); err == nil {
		t.Fatal("expected an unknown standard to fail")
	}
}

func TestScoreWithOptions(t *testing.T) {
	content := readFixture(t, "demo-new.cdx.json")
	options := ScoreOptions{Profile: "cra", RunOptions: RunOptions{AsOf: "2027-01-01"}}

	output, err := ScoreWithOptions(content, options)
	if err != nil {
		t.Fatalf("ScoreWithOptions() failed: %v", err)
	}
	if output.Tool != "sbom-tools" || output.Profile != "cra" || output.Sbom != "-" || !output.Applicable {
		t.Fatalf("unexpected quality document: %+v", output)
	}
	if output.Report.OverallScore == nil || *output.Report.OverallScore <= 0 || output.Report.Grade == "" {
		t.Fatalf("unexpected report: %+v", output.Report)
	}
	if len(output.Report.Compliance) == 0 {
		t.Fatal("expected the profile's compliance result in the report")
	}

	raw, err := ScoreWithOptionsJSON(content, options)
	if err != nil {
		t.Fatalf("ScoreWithOptionsJSON() failed: %v", err)
	}
	again, err := ScoreWithOptionsJSON(content, options)
	if err != nil {
		t.Fatalf("ScoreWithOptionsJSON() failed: %v", err)
	}
	if string(raw) != string(again) {
		t.Fatal("a pinned clock must give the same document")
	}

	options.FileName = filepath.Join("some", "dir", "demo-new.cdx.json")
	named, err := ScoreWithOptions(content, options)
	if err != nil {
		t.Fatalf("ScoreWithOptions() with FileName failed: %v", err)
	}
	if named.Sbom != "demo-new.cdx.json" {
		t.Fatalf("expected the file name without its directory, got %q", named.Sbom)
	}

	_, err = ScoreWithOptions(content, ScoreOptions{Profile: "strict"})
	if abiErr, ok := err.(*Error); !ok || abiErr.Code != ErrorCodeValidation {
		t.Fatalf("expected a validation error for an unknown profile, got %v", err)
	}
}

func TestScoreWithOptionsReportsAProfileThatDoesNotApply(t *testing.T) {
	content := readFixture(t, filepath.Join("cyclonedx", "minimal.cdx.json"))
	output, err := ScoreWithOptions(content, ScoreOptions{
		Profile:    "ai-readiness",
		RunOptions: RunOptions{AsOf: "2027-01-01"},
	})
	if err != nil {
		t.Fatalf("ScoreWithOptions() failed: %v", err)
	}
	if output.Applicable || output.Report.OverallScore != nil || output.Report.Grade != "N/A" {
		t.Fatalf("expected a not-applicable report without a score, got %+v", output)
	}
}
