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
    public let collisionCount: Int

    enum CodingKeys: String, CodingKey {
        case document
        case components
        case edges
        case extensions
        case contentHash = "content_hash"
        case primaryComponentID = "primary_component_id"
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