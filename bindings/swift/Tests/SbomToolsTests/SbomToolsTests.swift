import Foundation
import Testing
@testable import SbomTools

private func fixtureURL(_ name: String) -> URL {
    let fileURL = URL(fileURLWithPath: #filePath)
    let repoRoot = fileURL
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
    return repoRoot.appending(path: "tests/fixtures/\(name)")
}

@Test func versionAndFormatDetectionWork() throws {
    let version = try SbomTools.version()
    #expect(!version.abiVersion.isEmpty)
    #expect(!version.crateVersion.isEmpty)

    let content = try String(contentsOf: fixtureURL("cyclonedx/minimal.cdx.json"), encoding: .utf8)
    let detected = try SbomTools.detectFormat(content)
    #expect(detected?.formatName == "CycloneDX")
}

@Test func parseDiffAndScoreWork() throws {
    let oldJSON = try SbomTools.parsePathJSON(fixtureURL("demo-old.cdx.json").path())
    let newJSON = try SbomTools.parsePathJSON(fixtureURL("demo-new.cdx.json").path())

    let diffJSON = try SbomTools.diffJSON(old: oldJSON, new: newJSON)
    let diffObject = try JSONSerialization.jsonObject(with: Data(diffJSON.utf8)) as? [String: Any]
    let summary = diffObject?["summary"] as? [String: Any]
    let totalChanges = summary?["total_changes"] as? Double
    #expect((totalChanges ?? 0) > 0)

    let scoreJSON = try SbomTools.scoreJSON(newJSON)
    let scoreObject = try JSONSerialization.jsonObject(with: Data(scoreJSON.utf8)) as? [String: Any]
    let overallScore = scoreObject?["overall_score"] as? Double
    #expect((overallScore ?? 0) > 0)
}

@Test func typedHelpersWork() throws {
    let oldPayload = try SbomTools.parsePath(fixtureURL("demo-old.cdx.json").path())
    let newPayload = try SbomTools.parsePath(fixtureURL("demo-new.cdx.json").path())

    let diff = try SbomTools.diff(old: oldPayload, new: newPayload)
    #expect(diff.summary.totalChanges > 0)

    let quality = try SbomTools.score(newPayload)
    #expect(quality.overallScore > 0)
}

@Test func invalidDiffInputFails() throws {
    do {
        _ = try SbomTools.diffJSON(old: "{not-json}", new: "{not-json}")
        Issue.record("Expected invalid normalized JSON to fail")
    } catch let error as SbomToolsError {
        #expect(error.code == 3)
        #expect(error.message.contains("invalid normalized SBOM JSON"))
    }
}

@Test func validateReturnsTheComplianceEnvelope() throws {
    let content = try String(contentsOf: fixtureURL("demo-new.cdx.json"), encoding: .utf8)
    let options = ValidateOptions(
        standards: ["cra", "NTIA", "cra-phase2"],
        asOf: "2027-01-01",
        productClass: "important-class-1"
    )

    let envelope = try SbomTools.validate(content, options: options)
    #expect(envelope.schema == "sbom-tools/compliance/v2")
    #expect(envelope.tool.name == "sbom-tools")
    #expect(envelope.asOf == "2027-01-01T00:00:00Z")
    #expect(envelope.subject.sha256.count == 64)
    #expect(envelope.subject.sha256.allSatisfy { $0.isHexDigit })
    #expect(envelope.subject.format == "CycloneDX")
    #expect(envelope.subject.fileName == nil)
    // cra-phase2 names the level cra already selected, so it is checked once.
    #expect(envelope.results.map(\.standard) == ["cra", "ntia"])
    let cra = envelope.results[0]
    #expect(!cra.compliant)
    #expect(cra.counts.error > 0)
    #expect(!cra.violations.isEmpty)
    #expect(cra.violations.allSatisfy { $0.findingID.hasPrefix("sbomtools:v1:") && !$0.ruleID.isEmpty })

    let json = try SbomTools.validateJSON(content, options: options)
    #expect(try SbomTools.decode(ComplianceEnvelope.self, from: json) == envelope)

    var named = options
    named.fileName = "some/dir/demo-new.cdx.json"
    #expect(try SbomTools.validate(content, options: named).subject.fileName == "demo-new.cdx.json")
}

@Test func validateAppliesSidecarAndRuleSettings() throws {
    let content = try String(contentsOf: fixtureURL("cra/cra-compliant.cdx.json"), encoding: .utf8)
    let sidecarData = try Data(contentsOf: fixtureURL("cra/cra-compliant.cra.json"))
    let sidecar = try JSONDecoder().decode(JSONValue.self, from: sidecarData)

    let envelope = try SbomTools.validate(
        content,
        options: ValidateOptions(
            standards: ["cra"],
            asOf: "2027-12-11",
            sidecar: sidecar,
            rules: ["SBOM-CRA-SBOM-FRESHNESS": "error"]
        )
    )
    let freshness = envelope.results[0].violations.first { $0.ruleID == "SBOM-CRA-SBOM-FRESHNESS" }
    #expect(freshness?.severity == "Error")
    #expect(freshness?.severitySource == "cli")
    #expect(freshness?.defaultSeverity != nil)
}

@Test func validateRejectsInvalidOptions() throws {
    let content = try String(contentsOf: fixtureURL("cyclonedx/minimal.cdx.json"), encoding: .utf8)
    let invalid = [
        ValidateOptions(standards: ["ntai"]),
        ValidateOptions(asOf: "01/01/2027"),
        ValidateOptions(pqcProfile: "federal"),
        ValidateOptions(rules: ["SBOM-NTIA-SUPLIER": "off"]),
        ValidateOptions(sidecar: .object(["security_contact": .string("x")])),
    ]
    for options in invalid {
        do {
            _ = try SbomTools.validate(content, options: options)
            Issue.record("Expected \(options) to fail")
        } catch let error as SbomToolsError {
            #expect(error.code == 3)
        }
    }
}

@Test func ruleCatalogListsTheRegistry() throws {
    let catalog = try SbomTools.ruleCatalog()
    #expect(catalog.schema == "sbom-tools/rules/v1")
    #expect(catalog.rules.count >= 100)

    let ntia = try SbomTools.ruleCatalog(standards: ["ntia"])
    #expect(!ntia.rules.isEmpty)
    #expect(ntia.rules.count < catalog.rules.count)
    #expect(ntia.rules.allSatisfy { $0.standards.contains("ntia") })

    do {
        _ = try SbomTools.ruleCatalog(standards: ["crab"])
        Issue.record("Expected an unknown standard to fail")
    } catch let error as SbomToolsError {
        #expect(error.code == 3)
    }
}

@Test func scoreWithOptionsReturnsTheQualityDocument() throws {
    let content = try String(contentsOf: fixtureURL("demo-new.cdx.json"), encoding: .utf8)
    let options = ScoreOptions(profile: "cra", asOf: "2027-01-01")

    let output = try SbomTools.scoreWithOptions(content, options: options)
    #expect(output.tool == "sbom-tools")
    #expect(output.profile == "cra")
    #expect(output.sbom == "-")
    #expect(output.applicable)
    #expect((output.report.overallScore ?? 0) > 0)
    #expect(!output.report.compliance.isEmpty)
    // A pinned clock gives the same bytes.
    #expect(
        try SbomTools.scoreWithOptionsJSON(content, options: options)
            == SbomTools.scoreWithOptionsJSON(content, options: options)
    )

    var named = options
    named.fileName = "some/dir/demo-new.cdx.json"
    #expect(try SbomTools.scoreWithOptions(content, options: named).sbom == "demo-new.cdx.json")

    do {
        _ = try SbomTools.scoreWithOptions(content, options: ScoreOptions(profile: "strict"))
        Issue.record("Expected an unknown profile to fail")
    } catch let error as SbomToolsError {
        #expect(error.code == 3)
    }
}

@Test func scoreWithOptionsReportsAProfileThatDoesNotApply() throws {
    let content = try String(contentsOf: fixtureURL("cyclonedx/minimal.cdx.json"), encoding: .utf8)
    let output = try SbomTools.scoreWithOptions(
        content,
        options: ScoreOptions(profile: "ai-readiness", asOf: "2027-01-01")
    )
    #expect(!output.applicable)
    #expect(output.report.overallScore == nil)
    #expect(output.report.grade == "N/A")
}

@Test func deduplicateInPlaceLastWins() throws {
    var payload = makeDedupFixturePayload()
    let originalComponentCount = payload.components.count
    let originalEdgeCount = payload.edges.count

    let removed = payload.deduplicateInPlace()

    #expect(removed.componentsRemoved == 1)
    #expect(removed.edgesRemoved == 1)
    #expect(payload.components.count == originalComponentCount - removed.componentsRemoved)
    #expect(payload.edges.count == originalEdgeCount - removed.edgesRemoved)
}

@Test func deduplicatedDoesNotMutateOriginal() throws {
    let payload = makeDedupFixturePayload()

    let originalComponentCount = payload.components.count
    let originalEdgeCount = payload.edges.count

    let result = payload.deduplicated()

    #expect(payload.components.count == originalComponentCount)
    #expect(payload.edges.count == originalEdgeCount)
    #expect(result.componentsRemoved == 1)
    #expect(result.edgesRemoved == 1)
    #expect(result.payload.components.count == originalComponentCount - 1)
    #expect(result.payload.edges.count == originalEdgeCount - 1)
}

@Test func dedupAwareDiffAndScoreHelpersWork() throws {
    var payload = try SbomTools.parsePath(fixtureURL("demo-old.cdx.json").path())
    #expect(!payload.components.isEmpty)

    payload.components.append(payload.components[0])

    if !payload.edges.isEmpty {
        payload.edges.append(payload.edges[0])
    } else {
        let edge: [String: JSONValue] = [
            "from": .object(payload.components[0].canonicalID),
            "to": .object(payload.components[0].canonicalID),
            "relationship": .string("DependsOn"),
            "scope": .null,
        ]
        payload.edges.append(edge)
        payload.edges.append(edge)
    }

    let diffResult = try SbomTools.diffDeduplicated(old: payload, new: payload)
    #expect(diffResult.result.summary.totalChanges == 0)
    #expect(diffResult.oldStats.componentsRemoved >= 1)
    #expect(diffResult.oldStats.edgesRemoved >= 1)
    #expect(diffResult.newStats.componentsRemoved >= 1)
    #expect(diffResult.newStats.edgesRemoved >= 1)

    let scoreResult = try SbomTools.scoreDeduplicated(payload)
    #expect(scoreResult.result.overallScore >= 0)
    #expect(scoreResult.stats.componentsRemoved >= 1)
    #expect(scoreResult.stats.edgesRemoved >= 1)
}

private func makeDedupFixturePayload() -> NormalizedSbomPayload {
    let duplicateCanonicalID: [String: JSONValue] = [
        "value": .string("pkg:npm/left-pad@1.3.0"),
        "source": .string("Purl"),
        "stable": .bool(true),
    ]
    let uniqueCanonicalID: [String: JSONValue] = [
        "value": .string("pkg:npm/unique-lib@2.0.0"),
        "source": .string("Purl"),
        "stable": .bool(true),
    ]

    let componentA = NormalizedSbomComponentEntry(
        canonicalID: duplicateCanonicalID,
        component: [
            "canonical_id": .object(duplicateCanonicalID),
            "name": .string("left-pad"),
        ]
    )
    let componentB = NormalizedSbomComponentEntry(
        canonicalID: duplicateCanonicalID,
        component: [
            "canonical_id": .object(duplicateCanonicalID),
            "name": .string("left-pad-new"),
        ]
    )
    let componentC = NormalizedSbomComponentEntry(
        canonicalID: uniqueCanonicalID,
        component: [
            "canonical_id": .object(uniqueCanonicalID),
            "name": .string("unique-lib"),
        ]
    )

    let duplicateEdge: [String: JSONValue] = [
        "from": .object(duplicateCanonicalID),
        "to": .object(uniqueCanonicalID),
        "relationship": .string("DependsOn"),
        "scope": .null,
    ]
    let uniqueEdge: [String: JSONValue] = [
        "from": .object(uniqueCanonicalID),
        "to": .object(duplicateCanonicalID),
        "relationship": .string("DependsOn"),
        "scope": .null,
    ]

    return NormalizedSbomPayload(
        document: [
            "format": .string("CycloneDx"),
            "format_version": .string("1.6"),
            "spec_version": .string("1.6"),
            "serial_number": .null,
            "created": .string("2026-01-01T00:00:00Z"),
            "creators": .array([]),
            "name": .null,
            "security_contact": .null,
            "vulnerability_disclosure_url": .null,
            "support_end_date": .null,
            "lifecycle_phase": .null,
            "completeness_declaration": .string("Unknown"),
            "signature": .null,
            "distribution_classification": .null,
            "citations_count": .unsignedInteger(0),
            "version": .string("1.6"),
        ],
        components: [componentA, componentB, componentC],
        edges: [duplicateEdge, duplicateEdge, uniqueEdge],
        extensions: [:],
        contentHash: 0,
        primaryComponentID: duplicateCanonicalID,
        collisionCount: 0
    )
}