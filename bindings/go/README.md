# SBOM Tools Go Bindings

Go bindings for [sbom-tools](https://github.com/sbom-tool/sbom-tools), a library
for parsing, validating, scoring, and diffing bills of materials in multiple
formats.

Start with the [project overview](../../docs/PROJECT_OVERVIEW.md) and
[user journeys](../../docs/USER_JOURNEYS.md) to understand where the binding
fits in the end-to-end workflow.

## Features

- **Multi-format support**: SPDX (2.x, 3.0), CycloneDX, and more
- **Normalization**: All formats converted to a unified internal representation
- **Validation & Scoring**: Multiple scoring profiles (Minimal, Standard, Security, License Compliance, CRA, Comprehensive)
- **Diffing**: Compare two SBOMs and identify changes with semantic analysis
- **Deduplication**: Remove duplicate components and edges while preserving structure
- **Type-safe Go API**: Fully typed Go wrapper around the C FFI

## Installation

### Prerequisites

- Go 1.21+
- `libsbom_tools.a` compiled from the Rust crate (`crates/sbom-tools-ffi`)

### Building the Library

From the repository root:

```bash
# Build release static library (preferred for production)
cargo build -p sbom-tools-ffi --release

# Or debug build (larger, slower, better for troubleshooting)
cargo build -p sbom-tools-ffi
```

The library will be available at:

- Release: `target/*/release/libsbom_tools.a`
- Debug: `target/*/debug/libsbom_tools.a`

The Go bindings use CGo to link against this library automatically (see `cgo` directives in `sbomtools.go`).

### Adding to Your Go Project

```bash
go get github.com/sbom-tool/sbom-tools
```

Then import:

```go
import "github.com/sbom-tool/sbom-tools/bindings/go"
```

## Quick Start

### 1. Parse an SBOM File

```go
package main

import (
 "fmt"
 "log"

 sbomtools "github.com/sbom-tool/sbom-tools/bindings/go"
)

func main() {
 // Parse from file path
 sbom, err := sbomtools.ParsePath("path/to/sbom.json")
 if err != nil {
  log.Fatalf("Parse failed: %v", err)
 }

 // Access the parsed SBOM
 fmt.Printf("Format: %v\n", sbom.Document["format"])
 fmt.Printf("Component count: %d\n", len(sbom.Components))
}
```

### 2. Detect SBOM Format

```go
// Detect format from raw content
content := `{
  "bomFormat": "CycloneDX",
  "version": 1,
  "components": []
}`

format, err := sbomtools.DetectFormat(content)
if err != nil {
 log.Fatalf("Detection failed: %v", err)
}

if format != nil {
 fmt.Printf("Detected: %s (confidence: %.2f)\n",
  format.FormatName, format.Confidence)
}
```

### 3. Score an SBOM

```go
// Score with Standard profile
report, err := sbomtools.Score(sbom, sbomtools.StandardProfile)
if err != nil {
 log.Fatalf("Scoring failed: %v", err)
}

fmt.Printf("Overall Score: %.2f\n", report.OverallScore)
fmt.Printf("Grade: %s\n", report.Grade)
```

### 4. Compare Two SBOMs

```go
// Parse two versions
oldSbom, err := sbomtools.ParsePath("sbom-v1.json")
if err != nil {
 log.Fatal(err)
}

newSbom, err := sbomtools.ParsePath("sbom-v2.json")
if err != nil {
 log.Fatal(err)
}

// Compute diff
diff, err := sbomtools.Diff(oldSbom, newSbom)
if err != nil {
 log.Fatalf("Diff failed: %v", err)
}

fmt.Printf("Components added: %d\n", diff.Summary.ComponentsAdded)
fmt.Printf("Components removed: %d\n", diff.Summary.ComponentsRemoved)
fmt.Printf("Semantic score: %.2f\n", diff.SemanticScore)
```

## Error Handling

All operations return a standard Go `error`. For detailed error information, use type assertion:

```go
sbom, err := sbomtools.ParsePath("invalid.json")
if err != nil {
 // Type assert to sbomtools.Error for code-specific handling
 if sbomErr, ok := err.(*sbomtools.Error); ok {
  fmt.Printf("Error code: %d\n", sbomErr.Code)
  fmt.Printf("Message: %s\n", sbomErr.Message)

  switch sbomErr.Code {
  case sbomtools.ErrorCodeParse:
   // Handle parse errors (malformed input)
  case sbomtools.ErrorCodeValidation:
   // Handle validation errors (invalid structure)
  case sbomtools.ErrorCodeIO:
   // Handle I/O errors (file not found, permissions)
  case sbomtools.ErrorCodeUnsupported:
   // Handle unsupported formats
  case sbomtools.ErrorCodeInternal:
   // Handle internal library errors
  }
 }
}
```

### Error Codes

| Code | Constant               | Meaning                                         |
| ---- | ---------------------- | ----------------------------------------------- |
| 0    | `ErrorCodeOK`          | Success (no error)                              |
| 1    | `ErrorCodeParse`       | Parse error — input is malformed                |
| 3    | `ErrorCodeValidation`  | Validation error — structure is invalid         |
| 4    | `ErrorCodeIO`          | I/O error — file not found or permission denied |
| 5    | `ErrorCodeUnsupported` | Unsupported format or operation                 |
| 6    | `ErrorCodeInternal`    | Internal library error                          |

## API Reference

### Version Information

#### `func Version() (*AbiVersion, error)`

Returns ABI and crate version information.

```go
version, err := sbomtools.Version()
if err != nil {
 log.Fatal(err)
}
fmt.Printf("ABI Version: %s\n", version.ABIVersion)
fmt.Printf("Crate Version: %s\n", version.CrateVersion)
```

**Returns:**

- `ABIVersion`: Semantic version of the ABI contract (stable at "1")
- `CrateVersion`: Version of the sbom-tools crate

---

### Format Detection

#### `func DetectFormat(content string) (*DetectedFormat, error)`

Auto-detects the SBOM format from raw content.

```go
format, err := sbomtools.DetectFormat(content)
if err != nil {
 log.Fatal(err)
}

if format == nil {
 fmt.Println("Unknown format")
 return
}

fmt.Printf("Format: %s\n", format.FormatName)
fmt.Printf("Confidence: %.2f\n", format.Confidence)
if format.Version != nil {
 fmt.Printf("Version: %s\n", *format.Version)
}
```

**Returns:**

- `FormatName`: Name of detected format ("Spdx", "CycloneDx", etc.)
- `Confidence`: Confidence score (0.0–1.0)
- `Variant`: Format variant if detected (e.g., "JSON-LD" for SPDX 3.0)
- `Version`: Format version if detected
- `Warnings`: List of warnings during detection

**Returns `nil` if format cannot be detected.**

---

### Parsing

#### `func ParsePath(path string) (*NormalizedSbomPayload, error)`

Parses an SBOM from a file path.

```go
sbom, err := sbomtools.ParsePath("/path/to/sbom.json")
if err != nil {
 log.Fatal(err)
}

// Work with the normalized payload
components := len(sbom.Components)
fmt.Printf("Parsed %d components\n", components)
```

**Supports all formats:** SPDX 2.x (JSON, RDF/XML, Tag-Value), SPDX 3.0 (JSON-LD), CycloneDX (JSON, XML).

---

#### `func ParsePathJSON(path string) ([]byte, error)`

Parses an SBOM from file and returns raw JSON bytes (no unmarshaling).

```go
jsonBytes, err := sbomtools.ParsePathJSON("sbom.cdx.json")
if err != nil {
 log.Fatal(err)
}

// Process raw JSON without unmarshaling overhead
fmt.Println(string(jsonBytes))
```

**Use when:**

- You need to work with raw JSON
- Unmarshaling overhead is a concern
- You want to delegate unmarshaling to your own JSON parser

---

#### `func ParseString(content string) (*NormalizedSbomPayload, error)`

Parses an SBOM from a string.

```go
content := `{
  "bomFormat": "CycloneDX",
  "version": 1,
  "components": []
}`

sbom, err := sbomtools.ParseString(content)
if err != nil {
 log.Fatal(err)
}
```

---

#### `func ParseStringJSON(content string) ([]byte, error)`

Parses an SBOM from a string and returns raw JSON bytes.

```go
jsonBytes, err := sbomtools.ParseStringJSON(content)
if err != nil {
 log.Fatal(err)
}
```

---

### Scoring

#### `func Score(sbomPayload *NormalizedSbomPayload, profile ScoringProfile) (*QualityReportPayload, error)`

Scores an SBOM using the specified profile.

```go
// Score with Standard profile
report, err := sbomtools.Score(sbom, sbomtools.StandardProfile)
if err != nil {
 log.Fatal(err)
}

fmt.Printf("Score: %.2f\n", report.OverallScore)
fmt.Printf("Grade: %s\n", report.Grade)
fmt.Printf("Profile: %s\n", report.Profile)

// Print recommendations
for _, rec := range report.Recommendations {
 fmt.Printf("→ %v\n", rec)
}
```

**Scoring Profiles:**

| Profile                    | Use Case                 | Focus                                |
| -------------------------- | ------------------------ | ------------------------------------ |
| `MinimalProfile`           | Basic validation         | Presence of core fields              |
| `StandardProfile`          | General-purpose          | Completeness and accuracy            |
| `SecurityProfile`          | Vulnerability tracking   | Vulnerability info, severity scoring |
| `LicenseComplianceProfile` | Legal compliance         | License declarations and clarity     |
| `CRAProfile`               | Critical Risk Assessment | Coverage and dependency depth        |
| `ComprehensiveProfile`     | Detailed audit           | All aspects — most demanding         |

**Returns:**

- `OverallScore`: Score from 0.0–100.0
- `Grade`: Letter grade (A–F)
- `Profile`: Profile name
- `Compliance`: Map of compliance rule results
- `Recommendations`: List of actionable improvement suggestions

---

#### `func ScoreJSON(sbomJSON []byte, profile ScoringProfile) ([]byte, error)`

Scores an SBOM from raw JSON bytes.

```go
scoreJSON, err := sbomtools.ScoreJSON(jsonBytes, sbomtools.ComprehensiveProfile)
if err != nil {
 log.Fatal(err)
}

// Parse manually or use Decode helper
report := &sbomtools.QualityReportPayload{}
json.Unmarshal(scoreJSON, report)
```

---

#### `func ScoreDeduplicated(sbomPayload *NormalizedSbomPayload, profile ScoringProfile) (*QualityReportPayload, DedupStats, error)`

Scores an SBOM after removing duplicates. Useful for more accurate scoring when duplicate components exist.

```go
report, dedupStats, err := sbomtools.ScoreDeduplicated(sbom, sbomtools.StandardProfile)
if err != nil {
 log.Fatal(err)
}

fmt.Printf("Score: %.2f\n", report.OverallScore)
fmt.Printf("Duplicates removed: %d components, %d edges\n",
 dedupStats.ComponentsRemoved, dedupStats.EdgesRemoved)
```

---

### Diffing

#### `func Diff(oldPayload, newPayload *NormalizedSbomPayload) (*DiffResultPayload, error)`

Compares two SBOMs and computes a detailed diff.

```go
oldSbom, _ := sbomtools.ParsePath("sbom-v1.json")
newSbom, _ := sbomtools.ParsePath("sbom-v2.json")

diff, err := sbomtools.Diff(oldSbom, newSbom)
if err != nil {
 log.Fatal(err)
}

// Inspect changes
fmt.Printf("Total changes: %d\n", diff.Summary.TotalChanges)
fmt.Printf("Components: +%d -%d ~%d\n",
 diff.Summary.ComponentsAdded,
 diff.Summary.ComponentsRemoved,
 diff.Summary.ComponentsModified)
fmt.Printf("Semantic score: %.3f\n", diff.SemanticScore)
```

**Summary Fields:**

| Field                       | Meaning                             |
| --------------------------- | ----------------------------------- |
| `TotalChanges`              | Sum of all changes                  |
| `ComponentsAdded`           | New components in new SBOM          |
| `ComponentsRemoved`         | Components missing from new SBOM    |
| `ComponentsModified`        | Components with changed attributes  |
| `DependenciesAdded`         | New edges in dependency graph       |
| `DependenciesRemoved`       | Removed edges                       |
| `VulnerabilitiesIntroduced` | New vulnerabilities                 |
| `VulnerabilitiesResolved`   | Vulnerabilities no longer present   |
| `VulnerabilitiesPersistent` | Vulnerabilities still present       |
| `LicensesAdded`             | New licenses declared               |
| `LicensesRemoved`           | Licenses no longer used             |
| `GraphChangesCount`         | Changes to dependency relationships |

**Also returns:**

- `SemanticScore`: Similarity measure (0.0–1.0; higher = more similar)
- `RulesApplied`: Count of diff rules applied

---

#### `func DiffJSON(oldJSON, newJSON []byte) ([]byte, error)`

Computes diff from raw JSON bytes without unmarshaling overhead.

```go
oldJSON, _ := sbomtools.ParsePathJSON("v1.json")
newJSON, _ := sbomtools.ParsePathJSON("v2.json")

diffJSON, err := sbomtools.DiffJSON(oldJSON, newJSON)
if err != nil {
 log.Fatal(err)
}
```

---

#### `func DiffDeduplicated(oldPayload, newPayload *NormalizedSbomPayload) (*DiffResultPayload, DedupStats, DedupStats, error)`

Compares two SBOMs after removing duplicates from each. Returns diff and dedup stats for both.

```go
diff, oldStats, newStats, err := sbomtools.DiffDeduplicated(oldSbom, newSbom)
if err != nil {
 log.Fatal(err)
}

fmt.Printf("Old SBOM: %d dup components, %d dup edges\n",
 oldStats.ComponentsRemoved, oldStats.EdgesRemoved)
fmt.Printf("New SBOM: %d dup components, %d dup edges\n",
 newStats.ComponentsRemoved, newStats.EdgesRemoved)
fmt.Printf("Diff (after dedup): %d total changes\n", diff.Summary.TotalChanges)
```

**Use when:**

- Comparing SBOMs from different tools (which may have duplicate entries)
- Getting a "clean" diff without noise from duplicates
- Improving accuracy of change detection

---

### Deduplication

#### `func (p *NormalizedSbomPayload) Deduplicated() (*NormalizedSbomPayload, uint64, uint64)`

Returns a deduplicated copy without modifying the original.

```go
dedup, compsRemoved, edgesRemoved := sbom.Deduplicated()
if dedup == nil {
 log.Fatal("Deduplication failed")
}

fmt.Printf("Removed: %d components, %d edges\n", compsRemoved, edgesRemoved)
```

**Returns:**

- Deduplicated copy (nil on error)
- Component count removed
- Edge count removed

---

#### `func (p *NormalizedSbomPayload) DeduplicateInPlace() (uint64, uint64)`

Removes duplicates from the SBOM in-place (modifies the receiver).

```go
compsRemoved, edgesRemoved := sbom.DeduplicateInPlace()
fmt.Printf("Removed: %d components, %d edges\n", compsRemoved, edgesRemoved)

// sbom is now deduplicated
```

**Use carefully** — this mutates the receiver. Prefer `Deduplicated()` when possible.

---

#### `func (p *NormalizedSbomPayload) Clone() *NormalizedSbomPayload`

Creates a deep copy of the SBOM.

```go
copy := sbom.Clone()
if copy == nil {
 log.Fatal("Clone failed")
}
```

---

### Type Definitions

#### `type NormalizedSbomPayload`

The canonical internal representation of any SBOM.

```go
type NormalizedSbomPayload struct {
 Document           map[string]any                 // Document metadata
 Components         []NormalizedSbomComponentEntry // All components
 Edges              []map[string]any               // Dependency graph edges
 Extensions         map[string]any                 // Format-specific extensions
 ContentHash        uint64                         // Hash of normalized content
 PrimaryComponentID map[string]any                 // Root/primary component ID
 CollisionCount     uint64                         // Count of ID collisions detected
}
```

Fields are fully typed Go maps — iterate or query as needed.

---

#### `type DetectedFormat`

Result from format detection.

```go
type DetectedFormat struct {
 FormatName string   // "Spdx", "CycloneDx", etc.
 Confidence float32  // 0.0–1.0
 Variant    *string  // Optional variant ("JSON-LD", etc.)
 Version    *string  // Optional version
 Warnings   []string // Any warnings during detection
}
```

---

#### `type QualityReportPayload`

Result from scoring operation.

```go
type QualityReportPayload struct {
 OverallScore    float64          // 0.0–100.0
 Grade           string           // "A", "B", "C", "D", "F"
 Profile         string           // Profile name
 Compliance      map[string]any   // Rule-by-rule results
 Recommendations []map[string]any // Improvement suggestions
}
```

---

#### `type DiffResultPayload`

Result from diff operation.

```go
type DiffResultPayload struct {
 Summary       DiffSummary // Change statistics
 SemanticScore float64     // Similarity (0.0–1.0)
 RulesApplied  uint64      // Rules evaluated
}
```

---

## Common Patterns

### Parse, Deduplicate, and Score

```go
// 1. Parse
sbom, err := sbomtools.ParsePath("sbom.json")
if err != nil {
 log.Fatal(err)
}

// 2. Deduplicate
dedup, _, _ := sbom.Deduplicated()

// 3. Score
report, err := sbomtools.Score(dedup, sbomtools.ComprehensiveProfile)
if err != nil {
 log.Fatal(err)
}

fmt.Printf("Score: %.2f (%s)\n", report.OverallScore, report.Grade)
```

### Track Changes Across Releases

```go
type Release struct {
 Version string
 Sbom    *sbomtools.NormalizedSbomPayload
}

releases := []*Release{ /* ... */ }

for i := 0; i < len(releases)-1; i++ {
 old := releases[i]
 new := releases[i+1]

 diff, err := sbomtools.Diff(old.Sbom, new.Sbom)
 if err != nil {
  log.Fatal(err)
 }

 fmt.Printf("%s → %s: %d changes\n",
  old.Version, new.Version, diff.Summary.TotalChanges)
}
```

### Validate and Report

```go
func validateSBOM(filePath string) error {
 sbom, err := sbomtools.ParsePath(filePath)
 if err != nil {
  return fmt.Errorf("parse: %w", err)
 }

 report, err := sbomtools.Score(sbom, sbomtools.StandardProfile)
 if err != nil {
  return fmt.Errorf("score: %w", err)
 }

 if report.OverallScore < 70.0 {
  fmt.Printf("⚠ Low quality score: %.2f\n", report.OverallScore)
  for _, rec := range report.Recommendations {
   fmt.Printf("  → %v\n", rec)
  }
 }

 return nil
}
```

### Batch Processing

```go
import (
 "os"
 "path/filepath"
)

func processSBOMs(dir string) error {
 entries, err := os.ReadDir(dir)
 if err != nil {
  return err
 }

 for _, entry := range entries {
  if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
   path := filepath.Join(dir, entry.Name())

   sbom, err := sbomtools.ParsePath(path)
   if err != nil {
    fmt.Printf("FAIL %s: %v\n", entry.Name(), err)
    continue
   }

   report, _ := sbomtools.Score(sbom, sbomtools.StandardProfile)
   fmt.Printf("OK %s: %.2f\n", entry.Name(), report.OverallScore)
  }
 }

 return nil
}
```

## Testing

The bindings include comprehensive tests in `sbomtools_test.go`. Run them:

```bash
go test ./...
```

Tests cover:

- Parsing all supported formats
- Error conditions (missing files, invalid input)
- Scoring with all profiles
- Diff operations (same SBOM, different SBOMs)
- Deduplication

## Performance Considerations

1. **Parsing is the bottleneck** — format detection and normalization are CPU-intensive
2. **Reuse parsed payloads** — parsing is expensive; cache results when comparing multiple SBOMs
3. **Use JSON variants** (`ParsePathJSON`, `ParseStringJSON`, `DiffJSON`) when you need raw output without unmarshaling overhead
4. **Deduplication is optional** — only deduplicate if you suspect duplicates; it adds overhead

## Building from Source

To rebuild the Go bindings after changes to the Rust FFI:

```bash
# Ensure the Rust library is built
cargo build -p sbom-tools-ffi --release

# Run Go tests (will link against libsbom_tools.a)
cd bindings/go
go test ./...

# Build a binary that uses the bindings
go build -o my-sbom-tool ./cmd/my-tool
```

## License

See the [main repository](https://github.com/sbom-tool/sbom-tools) for license information.

## Support

- **Issues**: Report bugs in the [main repository](https://github.com/sbom-tool/sbom-tools/issues)
- **Discussions**: Ask questions in [Discussions](https://github.com/sbom-tool/sbom-tools/discussions)
- **Documentation**: See [docs/](../../docs) for architecture and design guides
