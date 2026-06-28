# SBOM Tools Swift Bindings

Swift bindings for [sbom-tools](https://github.com/sbom-tool/sbom-tools), a
library for parsing, validating, scoring, and diffing bills of materials in
multiple formats.

Start with the [project overview](../../docs/PROJECT_OVERVIEW.md) and
[user journeys](../../docs/USER_JOURNEYS.md) to understand where the binding
fits in the end-to-end workflow.

## Features

- **Multi-format support**: SPDX (2.x, 3.0), CycloneDX, and more
- **Normalization**: All formats converted to a unified internal representation
- **Validation & Scoring**: Multiple scoring profiles (Minimal, Standard, Security, License Compliance, CRA, Comprehensive)
- **Diffing**: Compare two SBOMs and identify changes with semantic analysis
- **Deduplication**: Remove duplicate components and edges while preserving structure
- **Type-safe Swift API**: Fully typed Swift wrapper around the C FFI using async/await patterns
- **Codable support**: All types conform to `Codable` for easy serialization

## Installation

### Swift Package Manager (SPM)

Add to your `Package.swift`:

```swift
.package(
    url: "https://github.com/sbom-tool/sbom-tools.git",
    .branch("main")
)
```

Then add to your target dependencies:

```swift
.target(
    name: "YourApp",
    dependencies: [
        .product(name: "SbomTools", package: "sbom-tools")
    ]
)
```

### Prerequisites

- Swift 5.9+ (macOS 13+, iOS 16+, or equivalent)
- Rust toolchain (for building the underlying `libsbom_tools.a`)

### Building the Library

The native library is built automatically by SPM during first use. If you need to rebuild:

```bash
# From the repository root
cargo build -p sbom-tools-ffi --release

# Swift Package will link against target/*/release/libsbom_tools.a
```

## Quick Start

### 1. Parse an SBOM File

```swift
import SbomTools

do {
    let sbom = try SbomTools.parsePath("/path/to/sbom.json")

    if let format = sbom.document["format"] {
        print("Format: \(format)")
    }
    print("Components: \(sbom.components.count)")
} catch {
    print("Error: \(error)")
}
```

### 2. Detect SBOM Format

```swift
let content = """
{
  "bomFormat": "CycloneDX",
  "version": 1,
  "components": []
}
"""

do {
    if let format = try SbomTools.detectFormat(content) {
        print("Detected: \(format.formatName)")
        print("Confidence: \(format.confidence)")
    } else {
        print("Unknown format")
    }
} catch {
    print("Error: \(error)")
}
```

### 3. Score an SBOM

```swift
do {
    let sbom = try SbomTools.parsePath("sbom.json")
    let report = try SbomTools.score(sbom, profile: .standard)

    print("Score: \(report.overallScore)")
    print("Grade: \(report.grade)")
} catch {
    print("Error: \(error)")
}
```

### 4. Compare Two SBOMs

```swift
do {
    let oldSbom = try SbomTools.parsePath("sbom-v1.json")
    let newSbom = try SbomTools.parsePath("sbom-v2.json")

    let diff = try SbomTools.diff(old: oldSbom, new: newSbom)

    print("Total changes: \(diff.summary.totalChanges)")
    print("Semantic score: \(diff.semanticScore)")
} catch {
    print("Error: \(error)")
}
```

## Error Handling

All operations throw `SbomToolsError` on failure. The error includes a code and message:

```swift
do {
    let sbom = try SbomTools.parsePath("invalid.json")
} catch let error as SbomToolsError {
    print("Code: \(error.code)")
    print("Message: \(error.message)")
} catch {
    print("Unexpected error: \(error)")
}
```

### Error Codes

| Code | Meaning                                         |
| ---- | ----------------------------------------------- |
| 0    | Success (no error)                              |
| 1    | Parse error — input is malformed                |
| 3    | Validation error — structure is invalid         |
| 4    | I/O error — file not found or permission denied |
| 5    | Unsupported format or operation                 |
| 6    | Internal library error                          |

## API Reference

### Version Information

#### `static func version() throws -> AbiVersion`

Returns ABI and crate version information.

```swift
let version = try SbomTools.version()
print("ABI: \(version.abiVersion)")
print("Crate: \(version.crateVersion)")
```

**Returns:**

- `abiVersion`: Semantic version of the ABI contract (stable at "1")
- `crateVersion`: Version of the sbom-tools crate

---

### Format Detection

#### `static func detectFormat(_ content: String) throws -> DetectedFormat?`

Auto-detects the SBOM format from raw content.

```swift
let format = try SbomTools.detectFormat(content)

if let f = format {
    print("Format: \(f.formatName)")
    print("Confidence: \(f.confidence)")
    if let variant = f.variant {
        print("Variant: \(variant)")
    }
} else {
    print("Unknown format")
}
```

**Returns:**

- `nil` if format cannot be detected
- `DetectedFormat` with:
  - `formatName`: Name of detected format
  - `confidence`: Confidence score (0.0–1.0)
  - `variant`: Optional variant (e.g., "JSON-LD")
  - `version`: Optional version
  - `warnings`: List of warnings

---

### Parsing

#### `static func parsePath(_ path: String) throws -> NormalizedSbomPayload`

Parses an SBOM from a file path.

```swift
let sbom = try SbomTools.parsePath("/path/to/sbom.json")

let componentCount = sbom.components.count
let edges = sbom.edges.count
```

**Supports all formats:** SPDX 2.x (JSON, RDF/XML, Tag-Value), SPDX 3.0 (JSON-LD), CycloneDX (JSON, XML).

---

#### `static func parsePathJSON(_ path: String) throws -> String`

Parses an SBOM from file and returns raw JSON string (no decoding).

```swift
let jsonString = try SbomTools.parsePathJSON("sbom.json")

// Process raw JSON without decoding overhead
print(jsonString)
```

**Use when:**

- You need raw JSON output
- Decoding overhead is a concern
- You want to delegate decoding to your own JSON parser

---

#### `static func parseString(_ content: String) throws -> NormalizedSbomPayload`

Parses an SBOM from a string.

```swift
let content = try String(contentsOfFile: "sbom.json", encoding: .utf8)
let sbom = try SbomTools.parseString(content)
```

---

#### `static func parseStringJSON(_ content: String) throws -> String`

Parses an SBOM from a string and returns raw JSON.

```swift
let json = try SbomTools.parseStringJSON(content)
```

---

### Scoring

#### `static func score(_ sbom: NormalizedSbomPayload, profile: SbomToolsScoring = .standard) throws -> QualityReportPayload`

Scores an SBOM using the specified profile.

```swift
let sbom = try SbomTools.parsePath("sbom.json")

// Score with different profiles
let standard = try SbomTools.score(sbom, profile: .standard)
let security = try SbomTools.score(sbom, profile: .security)
let comprehensive = try SbomTools.score(sbom, profile: .comprehensive)

print("Standard: \(standard.overallScore) (\(standard.grade))")
print("Security: \(security.overallScore) (\(security.grade))")
print("Comprehensive: \(comprehensive.overallScore) (\(comprehensive.grade))")
```

**Scoring Profiles:**

| Profile              | Use Case                 | Focus                                |
| -------------------- | ------------------------ | ------------------------------------ |
| `.minimal`           | Basic validation         | Presence of core fields              |
| `.standard`          | General-purpose          | Completeness and accuracy            |
| `.security`          | Vulnerability tracking   | Vulnerability info, severity scoring |
| `.licenseCompliance` | Legal compliance         | License declarations                 |
| `.cra`               | Critical Risk Assessment | Coverage and dependency depth        |
| `.comprehensive`     | Detailed audit           | All aspects — most demanding         |

**Returns:**

- `overallScore`: Score from 0.0–100.0
- `grade`: Letter grade (A–F)
- `profile`: Profile name

---

#### `static func scoreJSON(_ sbomJSON: String, profile: SbomToolsScoring = .standard) throws -> String`

Scores an SBOM from raw JSON string.

```swift
let json = try SbomTools.parsePathJSON("sbom.json")
let scoreJSON = try SbomTools.scoreJSON(json, profile: .comprehensive)

// Parse manually or use decode helper
let report = try SbomTools.decode(QualityReportPayload.self, from: scoreJSON)
```

---

#### `static func scoreDeduplicated(_ sbom: NormalizedSbomPayload, profile: SbomToolsScoring = .standard) throws -> (result: QualityReportPayload, stats: DeduplicationStats)`

Scores an SBOM after removing duplicates.

```swift
let sbom = try SbomTools.parsePath("sbom.json")
let (report, stats) = try SbomTools.scoreDeduplicated(sbom, profile: .standard)

print("Score: \(report.overallScore)")
print("Duplicates removed: \(stats.componentsRemoved) components, \(stats.edgesRemoved) edges")
```

---

### Diffing

#### `static func diff(old: NormalizedSbomPayload, new: NormalizedSbomPayload) throws -> DiffResultPayload`

Compares two SBOMs and computes a detailed diff.

```swift
let oldSbom = try SbomTools.parsePath("sbom-v1.json")
let newSbom = try SbomTools.parsePath("sbom-v2.json")

let diff = try SbomTools.diff(old: oldSbom, new: newSbom)

print("Total changes: \(diff.summary.totalChanges)")
print("Semantic score: \(diff.semanticScore)")
```

**Summary fields:**

| Field          | Meaning            |
| -------------- | ------------------ |
| `totalChanges` | Sum of all changes |

**Also returns:**

- `semanticScore`: Similarity measure (0.0–1.0; higher = more similar)
- `rulesApplied`: Count of diff rules applied

---

#### `static func diffJSON(old: String, new: String) throws -> String`

Computes diff from raw JSON strings.

```swift
let oldJSON = try SbomTools.parsePathJSON("v1.json")
let newJSON = try SbomTools.parsePathJSON("v2.json")

let diffJSON = try SbomTools.diffJSON(old: oldJSON, new: newJSON)
```

**Use when:**

- Working with raw JSON without decoding overhead
- Delegating parsing to custom JSON processor

---

#### `static func diffDeduplicated(old: NormalizedSbomPayload, new: NormalizedSbomPayload) throws -> (result: DiffResultPayload, oldStats: DeduplicationStats, newStats: DeduplicationStats)`

Compares two SBOMs after deduplication.

```swift
let (diff, oldStats, newStats) = try SbomTools.diffDeduplicated(old: oldSbom, new: newSbom)

print("Old duplicates: \(oldStats.componentsRemoved) components")
print("New duplicates: \(newStats.componentsRemoved) components")
print("Changes: \(diff.summary.totalChanges)")
```

**Use when:**

- Comparing SBOMs from different tools (which may have duplicates)
- Getting a "clean" diff without noise from duplicates
- Improving accuracy of change detection

---

### Deduplication

#### `mutating func deduplicateInPlace() -> (componentsRemoved: Int, edgesRemoved: Int)`

Removes duplicates from the SBOM in-place.

```swift
var sbom = try SbomTools.parsePath("sbom.json")
let (compsRemoved, edgesRemoved) = sbom.deduplicateInPlace()

print("Removed: \(compsRemoved) components, \(edgesRemoved) edges")
```

**Modifies the receiver** — use `deduplicated()` to preserve the original.

---

#### `func deduplicated() -> (payload: NormalizedSbomPayload, componentsRemoved: Int, edgesRemoved: Int)`

Returns a deduplicated copy without modifying the original.

```swift
let sbom = try SbomTools.parsePath("sbom.json")
let (dedup, compsRemoved, edgesRemoved) = sbom.deduplicated()

print("Original: \(sbom.components.count) components")
print("Deduplicated: \(dedup.components.count) components")
```

---

### Encoding/Decoding Helpers

#### `static func decode<T: Decodable>(_ type: T.Type, from json: String) throws -> T`

Decodes a custom type from JSON string.

```swift
let json = try SbomTools.parsePathJSON("sbom.json")
let sbom = try SbomTools.decode(NormalizedSbomPayload.self, from: json)
```

---

#### `static func encode<T: Encodable>(_ value: T) throws -> String`

Encodes a type to JSON string.

```swift
let sbom = try SbomTools.parsePath("sbom.json")
let json = try SbomTools.encode(sbom)

// Write to file or send over network
try json.write(toFile: "output.json", atomically: true, encoding: .utf8)
```

---

## Type Definitions

### `struct NormalizedSbomPayload`

The canonical internal representation of any SBOM. Conforms to `Codable`.

```swift
struct NormalizedSbomPayload: Codable, Equatable {
    let document: [String: JSONValue]              // Document metadata
    var components: [NormalizedSbomComponentEntry] // All components (mutable for dedup)
    var edges: [[String: JSONValue]]               // Dependency graph edges (mutable for dedup)
    let extensions: [String: JSONValue]            // Format-specific extensions
    let contentHash: UInt64                        // Hash of normalized content
    let primaryComponentID: [String: JSONValue]    // Root/primary component
    let collisionCount: Int                        // ID collision count
}
```

---

### `struct DetectedFormat`

Result from format detection. Conforms to `Codable`.

```swift
struct DetectedFormat: Codable, Equatable {
    let formatName: String   // "Spdx", "CycloneDx", etc.
    let confidence: Float    // 0.0–1.0
    let variant: String?     // Optional variant
    let version: String?     // Optional version
    let warnings: [String]   // Any warnings
}
```

---

### `struct QualityReportPayload`

Result from scoring. Conforms to `Codable`.

```swift
struct QualityReportPayload: Codable, Equatable {
    let overallScore: Double // 0.0–100.0
    let grade: String        // "A", "B", "C", "D", "F"
    let profile: String      // Profile name
}
```

---

### `struct DiffResultPayload`

Result from diff operation. Conforms to `Codable`.

```swift
struct DiffResultPayload: Codable, Equatable {
    let summary: DiffSummary  // Change statistics
    let semanticScore: Double // Similarity (0.0–1.0)
    let rulesApplied: Int     // Rules evaluated
}
```

---

### `struct DeduplicationStats`

Statistics from deduplication.

```swift
struct DeduplicationStats: Equatable {
    let componentsRemoved: Int
    let edgesRemoved: Int
}
```

---

### `enum JSONValue`

Type-safe representation of arbitrary JSON values. Conforms to `Codable`.

```swift
enum JSONValue: Codable, Equatable {
    case string(String)
    case unsignedInteger(UInt64)
    case integer(Int64)
    case number(Double)
    case bool(Bool)
    case object([String: JSONValue])
    case array([JSONValue])
    case null
}
```

**Access properties:**

```swift
if case .object(let dict) = value {
    if let format = dict["format"] {
        print(format)
    }
}
```

---

## Common Patterns

### Parse, Deduplicate, and Score

```swift
do {
    var sbom = try SbomTools.parsePath("sbom.json")

    // Deduplicate in-place
    let (compsRemoved, edgesRemoved) = sbom.deduplicateInPlace()

    // Score
    let report = try SbomTools.score(sbom, profile: .comprehensive)

    print("Removed duplicates: \(compsRemoved)")
    print("Score: \(report.overallScore) (\(report.grade))")
} catch {
    print("Error: \(error)")
}
```

### Track Changes Across Releases

```swift
struct Release {
    let version: String
    let sbom: NormalizedSbomPayload
}

func trackChanges(releases: [Release]) throws {
    for i in 0..<releases.count - 1 {
        let old = releases[i]
        let new = releases[i + 1]

        let diff = try SbomTools.diff(old: old.sbom, new: new.sbom)

        print("\(old.version) → \(new.version): \(diff.summary.totalChanges) changes")
    }
}
```

### Validate and Report

```swift
func validateAndReport(filePath: String) throws {
    let sbom = try SbomTools.parsePath(filePath)

    let report = try SbomTools.score(sbom, profile: .standard)

    print("Components: \(sbom.components.count)")
    print("Score: \(report.overallScore)")
    print("Grade: \(report.grade)")

    if report.overallScore < 70 {
        print("⚠ Low quality score")
    }
}
```

### Batch Processing

```swift
import Foundation

func processSBOMs(inDirectory dir: String) throws {
    let fileManager = FileManager.default
    let files = try fileManager.contentsOfDirectory(atPath: dir)

    for file in files where file.hasSuffix(".json") {
        let path = (dir as NSString).appendingPathComponent(file)

        do {
            let sbom = try SbomTools.parsePath(path)
            let report = try SbomTools.score(sbom, profile: .standard)

            print("✓ \(file): \(report.overallScore)")
        } catch {
            print("✗ \(file): \(error)")
        }
    }
}
```

### Export Results

```swift
func exportScores(from directory: String, to outputFile: String) throws {
    var results: [[String: String]] = []

    let fileManager = FileManager.default
    let files = try fileManager.contentsOfDirectory(atPath: directory)

    for file in files where file.hasSuffix(".json") {
        let path = (directory as NSString).appendingPathComponent(file)

        if let sbom = try? SbomTools.parsePath(path),
           let report = try? SbomTools.score(sbom, profile: .standard) {
            results.append([
                "file": file,
                "score": String(format: "%.2f", report.overallScore),
                "grade": report.grade
            ])
        }
    }

    let json = try JSONSerialization.data(withJSONObject: results, options: .prettyPrinted)
    try json.write(toFile: outputFile)
}
```

## Testing

The bindings include comprehensive tests in `Tests/SbomToolsTests/`. Run them:

```bash
swift test
```

Tests cover:

- Parsing all supported formats
- Format detection
- Scoring with all profiles
- Diff operations
- Deduplication

## Performance Considerations

1. **Parsing is the bottleneck** — format detection and normalization are CPU-intensive
2. **Reuse parsed payloads** — cache results when comparing multiple SBOMs
3. **Use JSON variants** (`parsePathJSON`, `parseStringJSON`, `diffJSON`) when you need raw output
4. **Deduplication is optional** — only deduplicate when you suspect duplicates
5. **Avoid encoding/decoding cycles** — work with `NormalizedSbomPayload` directly when possible

## Building from Source

After changes to the Rust FFI:

```bash
# Rebuild the static library
cargo build -p sbom-tools-ffi --release

# Run Swift tests (will link against new library)
swift test

# Build release app
swift build -c release
```

## Troubleshooting

### Linking Errors

If you see "linker error: library not found for -lsbom_tools", ensure the Rust library was built:

```bash
cargo build -p sbom-tools-ffi --release
```

### Module Not Found

If `import SbomTools` fails, check your `Package.swift` includes the product:

```swift
.product(name: "SbomTools", package: "sbom-tools")
```

### CI/CD Issues

When running in CI, ensure the Rust toolchain is installed and the library is built before running Swift tests.

## License

See the [main repository](https://github.com/sbom-tool/sbom-tools) for license information.

## Support

- **Issues**: Report bugs in the [main repository](https://github.com/sbom-tool/sbom-tools/issues)
- **Discussions**: Ask questions in [Discussions](https://github.com/sbom-tool/sbom-tools/discussions)
- **Documentation**: See [docs/](../../docs) for architecture and design guides
