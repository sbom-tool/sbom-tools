import CSbomTools
import Foundation

public enum JSONValue: Codable, Equatable {
    case string(String)
    case unsignedInteger(UInt64)
    case integer(Int64)
    case number(Double)
    case bool(Bool)
    case object([String: JSONValue])
    case array([JSONValue])
    case null

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let bool = try? container.decode(Bool.self) {
            self = .bool(bool)
        } else if let unsignedInteger = try? container.decode(UInt64.self) {
            self = .unsignedInteger(unsignedInteger)
        } else if let integer = try? container.decode(Int64.self) {
            self = .integer(integer)
        } else if let number = try? container.decode(Double.self) {
            self = .number(number)
        } else if let string = try? container.decode(String.self) {
            self = .string(string)
        } else if let object = try? container.decode([String: JSONValue].self) {
            self = .object(object)
        } else if let array = try? container.decode([JSONValue].self) {
            self = .array(array)
        } else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Unsupported JSON value"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .string(let value):
            try container.encode(value)
        case .unsignedInteger(let value):
            try container.encode(value)
        case .integer(let value):
            try container.encode(value)
        case .number(let value):
            try container.encode(value)
        case .bool(let value):
            try container.encode(value)
        case .object(let value):
            try container.encode(value)
        case .array(let value):
            try container.encode(value)
        case .null:
            try container.encodeNil()
        }
    }
}

public enum SbomToolsScoring: UInt32 {
    case minimal = 0
    case standard = 1
    case security = 2
    case licenseCompliance = 3
    case cra = 4
    case comprehensive = 5
    case aiReadiness = 6
}

public struct SbomToolsError: Error, CustomStringConvertible {
    public let code: UInt32
    public let message: String

    public var description: String {
        "sbom-tools ABI error (\(code)): \(message)"
    }
}

public struct AbiVersion: Codable, Equatable {
    public let abiVersion: String
    public let crateVersion: String

    enum CodingKeys: String, CodingKey {
        case abiVersion = "abi_version"
        case crateVersion = "crate_version"
    }
}

public struct DetectedFormat: Codable, Equatable {
    public let formatName: String
    public let confidence: Float
    public let variant: String?
    public let version: String?
    public let warnings: [String]

    enum CodingKeys: String, CodingKey {
        case formatName = "format_name"
        case confidence
        case variant
        case version
        case warnings
    }
}

public struct NormalizedSbomComponentEntry: Codable, Equatable {
    public let canonicalID: [String: JSONValue]
    public let component: [String: JSONValue]

    enum CodingKeys: String, CodingKey {
        case canonicalID = "canonical_id"
        case component
    }
}

public struct NormalizedSbomPayload: Codable, Equatable {
    public let document: [String: JSONValue]
    public var components: [NormalizedSbomComponentEntry]
    public var edges: [[String: JSONValue]]
    public let extensions: [String: JSONValue]
    public let contentHash: UInt64
    public let primaryComponentID: [String: JSONValue]
    /// The other components the document describes, besides the primary;
    /// absent from the payload when there are none.
    public var describedRootIDs: [[String: JSONValue]]? = nil
    public let collisionCount: Int

    enum CodingKeys: String, CodingKey {
        case document
        case components
        case edges
        case extensions
        case contentHash = "content_hash"
        case primaryComponentID = "primary_component_id"
        case describedRootIDs = "described_root_ids"
        case collisionCount = "collision_count"
    }

    public mutating func deduplicateInPlace() -> (componentsRemoved: Int, edgesRemoved: Int) {
        let componentResult = Self.dedupeComponentsLastWins(components)
        let edgeResult = Self.dedupeEdgesLastWins(edges)
        components = componentResult.values
        edges = edgeResult.values
        return (componentResult.removed, edgeResult.removed)
    }

    public func deduplicated() -> (payload: NormalizedSbomPayload, componentsRemoved: Int, edgesRemoved: Int) {
        var copy = self
        let removed = copy.deduplicateInPlace()
        return (copy, removed.componentsRemoved, removed.edgesRemoved)
    }

    private static func dedupeComponentsLastWins(_ input: [NormalizedSbomComponentEntry]) -> (values: [NormalizedSbomComponentEntry], removed: Int) {
        if input.count < 2 {
            return (input, 0)
        }

        var seen = Set<String>()
        var keptReversed: [NormalizedSbomComponentEntry] = []
        keptReversed.reserveCapacity(input.count)

        for entry in input.reversed() {
            let key = stableJSONKey(entry.canonicalID)
            if seen.contains(key) {
                continue
            }
            seen.insert(key)
            keptReversed.append(entry)
        }

        let kept = keptReversed.reversed()
        let output = Array(kept)
        return (output, input.count - output.count)
    }

    private static func dedupeEdgesLastWins(_ input: [[String: JSONValue]]) -> (values: [[String: JSONValue]], removed: Int) {
        if input.count < 2 {
            return (input, 0)
        }

        var seen = Set<String>()
        var keptReversed: [[String: JSONValue]] = []
        keptReversed.reserveCapacity(input.count)

        for edge in input.reversed() {
            let key = stableJSONKey(edge)
            if seen.contains(key) {
                continue
            }
            seen.insert(key)
            keptReversed.append(edge)
        }

        let kept = keptReversed.reversed()
        let output = Array(kept)
        return (output, input.count - output.count)
    }

    private static func stableJSONKey<T: Encodable>(_ value: T) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        if let encoded = try? encoder.encode(value),
           let text = String(data: encoded, encoding: .utf8) {
            return text
        }
        return String(describing: value)
    }
}

public struct DiffSummary: Codable, Equatable {
    public let totalChanges: Int

    enum CodingKeys: String, CodingKey {
        case totalChanges = "total_changes"
    }
}

public struct DiffResultPayload: Codable, Equatable {
    public let summary: DiffSummary
    public let semanticScore: Double
    public let rulesApplied: Int

    enum CodingKeys: String, CodingKey {
        case summary
        case semanticScore = "semantic_score"
        case rulesApplied = "rules_applied"
    }
}

public struct QualityReportPayload: Codable, Equatable {
    public let overallScore: Double
    public let grade: String
    public let profile: String

    enum CodingKeys: String, CodingKey {
        case overallScore = "overall_score"
        case grade
        case profile
    }
}

/// The inputs of `SbomTools.validate`: the standards, and the run options
/// the CLI's shared compliance flags give. `nil` leaves an input out, so its
/// default applies.
public struct ValidateOptions: Encodable, Equatable {
    /// `--standard` names or aliases; `nil` means `["ntia"]`.
    public var standards: [String]?
    /// The file the content was read from, which the envelope's subject
    /// names without its directory, as `validate <FILE>` does; `nil` names
    /// no file, as for standard input.
    public var fileName: String?
    /// The evaluation instant (`--as-of`): an RFC 3339 datetime, an
    /// offset-less datetime taken as UTC, or a date (midnight UTC).
    public var asOf: String?
    /// A CRA sidecar object, with the keys of a `.cra.json` file.
    public var sidecar: JSONValue?
    /// The CRA product class (`--cra-product-class`).
    public var productClass: String?
    /// `readiness` or `deadline` (`--pqc-mode`).
    public var pqcMode: String?
    /// `--pqc-profile`; deadline mode only.
    public var pqcProfile: String?
    /// `--cnsa-category`; deadline mode only.
    public var cnsaCategory: String?
    /// Rule id to `off`, `info`, `warning` or `error` (`--rule`).
    public var rules: [String: String]?
    /// Judge components whose scope is excluded too
    /// (`--include-excluded-scope`).
    public var includeExcludedScope: Bool?

    public init(
        standards: [String]? = nil,
        fileName: String? = nil,
        asOf: String? = nil,
        sidecar: JSONValue? = nil,
        productClass: String? = nil,
        pqcMode: String? = nil,
        pqcProfile: String? = nil,
        cnsaCategory: String? = nil,
        rules: [String: String]? = nil,
        includeExcludedScope: Bool? = nil
    ) {
        self.standards = standards
        self.fileName = fileName
        self.asOf = asOf
        self.sidecar = sidecar
        self.productClass = productClass
        self.pqcMode = pqcMode
        self.pqcProfile = pqcProfile
        self.cnsaCategory = cnsaCategory
        self.rules = rules
        self.includeExcludedScope = includeExcludedScope
    }

    enum CodingKeys: String, CodingKey {
        case standards
        case fileName = "file_name"
        case asOf = "as_of"
        case sidecar
        case productClass = "product_class"
        case pqcMode = "pqc_mode"
        case pqcProfile = "pqc_profile"
        case cnsaCategory = "cnsa_category"
        case rules
        case includeExcludedScope = "include_excluded_scope"
    }
}

/// The inputs of `SbomTools.score(_:options:)`: a `quality --profile` name
/// and the run options of `ValidateOptions` (all but the standards).
public struct ScoreOptions: Encodable, Equatable {
    /// A `quality --profile` name; `nil` means `standard`.
    public var profile: String?
    public var asOf: String?
    public var sidecar: JSONValue?
    public var productClass: String?
    public var pqcMode: String?
    public var pqcProfile: String?
    public var cnsaCategory: String?
    public var rules: [String: String]?
    public var includeExcludedScope: Bool?

    public init(
        profile: String? = nil,
        asOf: String? = nil,
        sidecar: JSONValue? = nil,
        productClass: String? = nil,
        pqcMode: String? = nil,
        pqcProfile: String? = nil,
        cnsaCategory: String? = nil,
        rules: [String: String]? = nil,
        includeExcludedScope: Bool? = nil
    ) {
        self.profile = profile
        self.asOf = asOf
        self.sidecar = sidecar
        self.productClass = productClass
        self.pqcMode = pqcMode
        self.pqcProfile = pqcProfile
        self.cnsaCategory = cnsaCategory
        self.rules = rules
        self.includeExcludedScope = includeExcludedScope
    }

    enum CodingKeys: String, CodingKey {
        case profile
        case asOf = "as_of"
        case sidecar
        case productClass = "product_class"
        case pqcMode = "pqc_mode"
        case pqcProfile = "pqc_profile"
        case cnsaCategory = "cnsa_category"
        case rules
        case includeExcludedScope = "include_excluded_scope"
    }
}

/// The tool that wrote a compliance envelope or a rule catalogue.
public struct ToolInfo: Codable, Equatable {
    public let name: String
    public let version: String
}

/// The `sbom-tools/compliance/v2` envelope `SbomTools.validate` returns, as
/// `sbom-tools validate -o json` writes it.
public struct ComplianceEnvelope: Codable, Equatable {
    public let schema: String
    public let tool: ToolInfo
    /// The instant every standard was judged at (RFC 3339, UTC).
    public let asOf: String
    /// The SBOM the results judge.
    public let subject: ComplianceSubject
    public let results: [ComplianceResultPayload]

    enum CodingKeys: String, CodingKey {
        case schema
        case tool
        case asOf = "as_of"
        case subject
        case results
    }
}

/// The SBOM a compliance envelope judges, and how its document was read.
public struct ComplianceSubject: Codable, Equatable {
    /// Lowercase hex SHA-256 of the content passed in.
    public let sha256: String
    public let format: String
    public let specVersion: String
    /// `ValidateOptions.fileName` without its directory.
    public let fileName: String?
    public let components: Int
    public let duplicates: DuplicateSummary
    public let timestampUnparsed: Bool

    enum CodingKeys: String, CodingKey {
        case sha256
        case format
        case specVersion = "spec_version"
        case fileName = "file_name"
        case components
        case duplicates
        case timestampUnparsed = "timestamp_unparsed"
    }
}

/// The components a document lists more than once, whose entries were
/// merged into one each.
public struct DuplicateSummary: Codable, Equatable {
    public let components: Int
    public let entries: Int
    public let conflicts: [String]
}

/// One standard's verdict.
public struct ComplianceResultPayload: Codable, Equatable {
    public let standard: String
    public let name: String
    public let applicable: Bool
    public let notApplicableReason: String?
    public let compliant: Bool
    public let score: Int?
    public let scoreBasis: ScoreBasis?
    public let counts: ComplianceCounts
    public let violations: [ComplianceViolation]
    public let passed: [PassedCheckPayload]
    public let evaluated: [RuleEvaluationPayload]?
    public let suppressed: [SuppressedRulePayload]?
    public let excludedComponents: Int?
    public let conformitySummary: [String: JSONValue]?

    enum CodingKeys: String, CodingKey {
        case standard
        case name
        case applicable
        case notApplicableReason = "not_applicable_reason"
        case compliant
        case score
        case scoreBasis = "score_basis"
        case counts
        case violations
        case passed
        case evaluated
        case suppressed
        case excludedComponents = "excluded_components"
        case conformitySummary = "conformity_summary"
    }
}

/// What a result's score is computed from.
public struct ScoreBasis: Codable, Equatable {
    public let checked: Int
    public let failed: Int
}

/// A result's findings by severity, its passed checks and the findings the
/// rule settings turned off.
public struct ComplianceCounts: Codable, Equatable {
    public let error: Int
    public let warning: Int
    public let info: Int
    public let passed: Int
    public let suppressed: Int?
}

/// One finding of a standard.
public struct ComplianceViolation: Codable, Equatable {
    public let findingID: String
    public let findingKey: String
    public let severity: String
    public let defaultSeverity: String?
    public let severitySource: String?
    public let category: String
    public let message: String
    public let element: String?
    public let componentID: String?
    public let findingDetail: String?
    public let deadline: String?
    public let deadlineSource: String?
    public let field: String?
    public let observed: String?
    public let requirement: String
    public let ruleID: String
    public let sarifRuleID: String
    public let standardRefs: [StandardRefPayload]?
    public let remediation: String?
    public let helpURI: String?

    enum CodingKeys: String, CodingKey {
        case findingID = "finding_id"
        case findingKey = "finding_key"
        case severity
        case defaultSeverity = "default_severity"
        case severitySource = "severity_source"
        case category
        case message
        case element
        case componentID = "component_id"
        case findingDetail = "finding_detail"
        case deadline
        case deadlineSource = "deadline_source"
        case field
        case observed
        case requirement
        case ruleID = "rule_id"
        case sarifRuleID = "sarif_rule_id"
        case standardRefs = "standard_refs"
        case remediation
        case helpURI = "help_uri"
    }
}

/// A check the SBOM passed; it is not a violation.
public struct PassedCheckPayload: Codable, Equatable {
    public let findingID: String
    public let findingKey: String
    public let message: String
    public let element: String?
    public let componentID: String?
    public let requirement: String
    public let ruleID: String
    public let standardRefs: [StandardRefPayload]?

    enum CodingKeys: String, CodingKey {
        case findingID = "finding_id"
        case findingKey = "finding_key"
        case message
        case element
        case componentID = "component_id"
        case requirement
        case ruleID = "rule_id"
        case standardRefs = "standard_refs"
    }
}

/// A clause a finding cites.
public struct StandardRefPayload: Codable, Equatable {
    public let standard: String
    public let id: String
    public let helpURI: String?

    enum CodingKeys: String, CodingKey {
        case standard
        case id
        case helpURI = "help_uri"
    }
}

/// A check the standard did not evaluate, with the reason.
public struct RuleEvaluationPayload: Codable, Equatable {
    public let ruleID: String
    public let status: String
    public let reason: String

    enum CodingKeys: String, CodingKey {
        case ruleID = "rule_id"
        case status
        case reason
    }
}

/// A rule the run's settings turned off.
public struct SuppressedRulePayload: Codable, Equatable {
    public let ruleID: String
    public let findings: Int
    public let source: String

    enum CodingKeys: String, CodingKey {
        case ruleID = "rule_id"
        case findings
        case source
    }
}

/// The `sbom-tools/rules/v1` document `SbomTools.ruleCatalog` returns, as
/// `sbom-tools rules -o json` prints it.
public struct RuleCatalog: Codable, Equatable {
    public let schema: String
    public let tool: ToolInfo
    public let rules: [RuleCatalogEntry]
}

/// Everything the registry records about one rule.
public struct RuleCatalogEntry: Codable, Equatable {
    public let id: String
    public let name: String
    public let description: String
    public let defaultSeverity: String
    public let kind: String
    public let fallback: Bool
    public let standards: [String]
    public let references: [RuleReference]
    public let helpURI: String?
    public let remediation: String
    public let remediationSummary: String
    public let advice: RuleAdvice?

    enum CodingKeys: String, CodingKey {
        case id
        case name
        case description
        case defaultSeverity = "default_severity"
        case kind
        case fallback
        case standards
        case references
        case helpURI = "help_uri"
        case remediation
        case remediationSummary = "remediation_summary"
        case advice
    }
}

/// A clause a rule implements.
public struct RuleReference: Codable, Equatable {
    public let standard: String
    public let id: String
    public let label: String
    public let helpURI: String?

    enum CodingKeys: String, CodingKey {
        case standard
        case id
        case label
        case helpURI = "help_uri"
    }
}

/// Where a rule's fix goes in each SBOM format.
public struct RuleAdvice: Codable, Equatable {
    public let cyclonedx: RuleFormatAdvice
    public let spdx2: RuleFormatAdvice
    public let spdx3: RuleFormatAdvice
}

/// A rule's fix in one SBOM format.
public struct RuleFormatAdvice: Codable, Equatable {
    public let text: String
    public let field: String?
}

/// The quality report `SbomTools.score(_:options:)` returns: the profile
/// named as `quality --profile` names it, and the compliance check as an
/// entry of the compliance envelope's results.
public struct ScoreReport: Codable, Equatable {
    public let scoringEngineVersion: String
    public let overallScore: Double
    public let grade: String
    public let profile: String
    public let compliance: ComplianceResultPayload

    enum CodingKeys: String, CodingKey {
        case scoringEngineVersion = "scoring_engine_version"
        case overallScore = "overall_score"
        case grade
        case profile
        case compliance
    }
}

private struct RuleCatalogFilter: Encodable {
    let standards: [String]
}

public struct DeduplicationStats: Equatable {
    public let componentsRemoved: Int
    public let edgesRemoved: Int

    public init(componentsRemoved: Int, edgesRemoved: Int) {
        self.componentsRemoved = componentsRemoved
        self.edgesRemoved = edgesRemoved
    }
}

public enum SbomTools {
    public static func version() throws -> AbiVersion {
        let json = try consume(sbom_tools_abi_version_json())
        return try decode(AbiVersion.self, from: json)
    }

    public static func detectFormat(_ content: String) throws -> DetectedFormat? {
        let json = try content.withCString { pointer in
            try consume(sbom_tools_detect_format_json(pointer))
        }

        if json == "null" {
            return nil
        }

        return try decode(DetectedFormat.self, from: json)
    }

    public static func parsePathJSON(_ path: String) throws -> String {
        try path.withCString { pointer in
            try consume(sbom_tools_parse_sbom_path_json(pointer))
        }
    }

    public static func parsePath(_ path: String) throws -> NormalizedSbomPayload {
        try decode(NormalizedSbomPayload.self, from: parsePathJSON(path))
    }

    public static func parseStringJSON(_ content: String) throws -> String {
        try content.withCString { pointer in
            try consume(sbom_tools_parse_sbom_str_json(pointer))
        }
    }

    public static func parseString(_ content: String) throws -> NormalizedSbomPayload {
        try decode(NormalizedSbomPayload.self, from: parseStringJSON(content))
    }

    public static func diffJSON(old: String, new: String) throws -> String {
        try old.withCString { oldPointer in
            try new.withCString { newPointer in
                try consume(sbom_tools_diff_sboms_json(oldPointer, newPointer))
            }
        }
    }

    public static func diff(old: NormalizedSbomPayload, new: NormalizedSbomPayload) throws -> DiffResultPayload {
        let oldJSON = try encode(old)
        let newJSON = try encode(new)
        return try decode(DiffResultPayload.self, from: diffJSON(old: oldJSON, new: newJSON))
    }

    public static func diffDeduplicated(
        old: NormalizedSbomPayload,
        new: NormalizedSbomPayload
    ) throws -> (result: DiffResultPayload, oldStats: DeduplicationStats, newStats: DeduplicationStats) {
        let oldResult = old.deduplicated()
        let newResult = new.deduplicated()

        let diffResult = try diff(old: oldResult.payload, new: newResult.payload)
        let oldStats = DeduplicationStats(
            componentsRemoved: oldResult.componentsRemoved,
            edgesRemoved: oldResult.edgesRemoved
        )
        let newStats = DeduplicationStats(
            componentsRemoved: newResult.componentsRemoved,
            edgesRemoved: newResult.edgesRemoved
        )
        return (diffResult, oldStats, newStats)
    }

    public static func scoreJSON(_ sbomJSON: String, profile: SbomToolsScoring = .standard) throws -> String {
        try sbomJSON.withCString { pointer in
            try consume(sbom_tools_score_sbom_json(pointer, SbomToolsScoringProfile(profile.rawValue)))
        }
    }

    public static func score(_ sbom: NormalizedSbomPayload, profile: SbomToolsScoring = .standard) throws -> QualityReportPayload {
        let sbomJSON = try encode(sbom)
        return try decode(QualityReportPayload.self, from: scoreJSON(sbomJSON, profile: profile))
    }

    public static func scoreDeduplicated(
        _ sbom: NormalizedSbomPayload,
        profile: SbomToolsScoring = .standard
    ) throws -> (result: QualityReportPayload, stats: DeduplicationStats) {
        let dedupResult = sbom.deduplicated()
        let quality = try score(dedupResult.payload, profile: profile)
        let stats = DeduplicationStats(
            componentsRemoved: dedupResult.componentsRemoved,
            edgesRemoved: dedupResult.edgesRemoved
        )
        return (quality, stats)
    }

    /// Validate raw SBOM content against compliance standards and return the
    /// `sbom-tools/compliance/v2` envelope: byte for byte what
    /// `sbom-tools validate - -o json` writes for the same content and options
    /// (`validate <FILE>` when `options.fileName` names the file). The
    /// subject's SHA-256 is over exactly the content passed in, and `asOf` is
    /// `options.asOf`, else the wall clock when the call starts, to the second.
    public static func validateJSON(_ content: String, options: ValidateOptions = ValidateOptions()) throws -> String {
        let optionsJSON = try encode(options)
        return try content.withCString { contentPointer in
            try optionsJSON.withCString { optionsPointer in
                try consume(sbom_tools_validate_json(contentPointer, optionsPointer))
            }
        }
    }

    /// Validate raw SBOM content against compliance standards and return the
    /// decoded envelope.
    public static func validate(_ content: String, options: ValidateOptions = ValidateOptions()) throws -> ComplianceEnvelope {
        try decode(ComplianceEnvelope.self, from: validateJSON(content, options: options))
    }

    /// The `sbom-tools/rules/v1` rule catalogue: every rule, or the rules of
    /// the given `--standard` names.
    public static func ruleCatalogJSON(standards: [String] = []) throws -> String {
        let filterJSON = try encode(RuleCatalogFilter(standards: standards))
        return try filterJSON.withCString { pointer in
            try consume(sbom_tools_rule_catalog_json(pointer))
        }
    }

    /// The decoded rule catalogue: every rule, or the rules of the given
    /// `--standard` names.
    public static func ruleCatalog(standards: [String] = []) throws -> RuleCatalog {
        try decode(RuleCatalog.self, from: ruleCatalogJSON(standards: standards))
    }

    /// Score normalized SBOM JSON with a profile and the run options, judged
    /// at `options.asOf`.
    public static func scoreJSON(_ sbomJSON: String, options: ScoreOptions) throws -> String {
        let optionsJSON = try encode(options)
        return try sbomJSON.withCString { sbomPointer in
            try optionsJSON.withCString { optionsPointer in
                try consume(sbom_tools_score_sbom_with_options_json(sbomPointer, optionsPointer))
            }
        }
    }

    /// Score a normalized SBOM with a profile and the run options, and
    /// return the decoded report.
    public static func score(_ sbom: NormalizedSbomPayload, options: ScoreOptions) throws -> ScoreReport {
        let sbomJSON = try encode(sbom)
        return try decode(ScoreReport.self, from: scoreJSON(sbomJSON, options: options))
    }

    public static func decode<T: Decodable>(_ type: T.Type, from json: String) throws -> T {
        try JSONDecoder().decode(T.self, from: Data(json.utf8))
    }

    public static func encode<T: Encodable>(_ value: T) throws -> String {
        let data = try JSONEncoder().encode(value)
        guard let json = String(data: data, encoding: .utf8) else {
            throw SbomToolsError(code: UInt32(SBOM_TOOLS_ERROR_INTERNAL.rawValue), message: "failed to encode JSON payload")
        }
        return json
    }

    private static func consume(_ result: SbomToolsStringResult) throws -> String {
        defer { sbom_tools_string_result_free(result) }

        if result.error_code != SBOM_TOOLS_ERROR_OK {
            let message = result.error_message.map { String(cString: $0) } ?? "unknown error"
            throw SbomToolsError(code: UInt32(result.error_code.rawValue), message: message)
        }

        guard let data = result.data else {
            throw SbomToolsError(code: UInt32(SBOM_TOOLS_ERROR_INTERNAL.rawValue), message: "missing ABI payload")
        }

        return String(cString: data)
    }
}