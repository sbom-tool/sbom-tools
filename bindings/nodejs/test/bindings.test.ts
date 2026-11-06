import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";

import {
  ErrorCode,
  ScoringProfile,
  SbomToolsNativeError,
  detectFormat,
  diffJson,
  parsePathJson,
  parseStringJson,
  ruleCatalogJson,
  scoreJson,
  scoreWithOptionsJson,
  validateJson,
  version,
  type ValidateOptions,
} from "../src/index.js";

const fixturePath = resolve("fixtures/minimal.cdx.json");
const fixture = readFileSync(fixturePath, "utf8");

test("ABI constants mirror the C header", () => {
  assert.deepEqual(
    [
      ErrorCode.Ok,
      ErrorCode.Parse,
      ErrorCode.Diff,
      ErrorCode.Validation,
      ErrorCode.Io,
      ErrorCode.Unsupported,
      ErrorCode.Internal,
    ],
    [0, 1, 2, 3, 4, 5, 6],
  );
  assert.deepEqual(
    [
      ScoringProfile.Minimal,
      ScoringProfile.Standard,
      ScoringProfile.Security,
      ScoringProfile.LicenseCompliance,
      ScoringProfile.Cra,
      ScoringProfile.Comprehensive,
      ScoringProfile.AiReadiness,
    ],
    [0, 1, 2, 3, 4, 5, 6],
  );
});

test("version returns live ABI metadata", () => {
  const result = version();
  assert.match(result.abi_version, /^\d+$/);
  assert.match(result.crate_version, /^\d+\.\d+\.\d+/);
});

test("detectFormat preserves format details", () => {
  const result = detectFormat(fixture);
  assert.ok(result !== null);
  assert.equal(result.format_name, "CycloneDX");
  assert.equal(typeof result.confidence, "number");
  assert.ok(Array.isArray(result.warnings));
});

test("parsePathJson and parseStringJson normalize an SBOM", () => {
  const fromPath = parsePathJson(fixturePath);
  const fromString = parseStringJson(fixture);
  assert.equal(typeof fromPath, "object");
  assert.match(JSON.stringify(fromPath), /"name":"example"/);
  assert.match(JSON.stringify(fromString), /"name":"example"/);
});

test("diffJson reports no component changes for identical input", () => {
  const normalized = JSON.stringify(parseStringJson(fixture));
  const result = diffJson(normalized, normalized);
  assert.equal(typeof result, "object");
  assert.match(JSON.stringify(result), /"total_changes":0/);
});

test("scoreJson returns a quality report", () => {
  const normalized = JSON.stringify(parseStringJson(fixture));
  const result = scoreJson(normalized, ScoringProfile.Standard);
  assert.equal(typeof result, "object");
});

test("invalid native input is reported as SbomToolsNativeError", () => {
  assert.throws(() => parseStringJson("{"), SbomToolsNativeError);
});

test("NUL bytes are rejected before crossing the C boundary", () => {
  assert.throws(() => parseStringJson("bad\0input"), TypeError);
});

test("invalid scoring profiles are rejected before the FFI call", () => {
  assert.throws(
    () => scoreJson("{}", 99 as ScoringProfile),
    RangeError,
  );
});

function isValidationError(error: unknown): boolean {
  return (
    error instanceof SbomToolsNativeError &&
    error.code === ErrorCode.Validation
  );
}

test("validateJson returns the compliance envelope", () => {
  const envelope = validateJson(fixture, {
    standards: ["cra", "NTIA", "cra-phase2"],
    as_of: "2027-01-01",
  });
  assert.equal(envelope.schema, "sbom-tools/compliance/v2");
  assert.equal(envelope.tool.name, "sbom-tools");
  assert.equal(envelope.as_of, "2027-01-01T00:00:00Z");
  assert.equal(
    envelope.subject.sha256,
    createHash("sha256").update(fixture, "utf8").digest("hex"),
  );
  assert.equal(envelope.subject.format, "CycloneDX");
  assert.equal(envelope.subject.file_name, undefined);
  // cra-phase2 names the level cra already selected, so it is checked once.
  assert.deepEqual(
    envelope.results.map((result) => result.standard),
    ["cra", "ntia"],
  );
  const ntia = envelope.results[1];
  assert.ok(ntia !== undefined);
  assert.equal(ntia.compliant, false);
  assert.ok(ntia.violations.length > 0);
  for (const violation of ntia.violations) {
    assert.match(violation.finding_id, /^sbomtools:v1:/);
  }

  const named = validateJson(fixture, {
    file_name: fixturePath,
    as_of: "2027-01-01",
  });
  assert.equal(named.subject.file_name, "minimal.cdx.json");
});

test("validateJson takes a Date and applies rule settings", () => {
  const rules = { "SBOM-NTIA-SUPPLIER": "warning" };
  const fromText = validateJson(fixture, {
    as_of: "2027-01-01T00:00:00Z",
    rules,
  });
  const fromDate = validateJson(fixture, {
    as_of: new Date(Date.UTC(2027, 0, 1)),
    rules,
  });
  assert.deepEqual(fromDate, fromText);
  const supplier = fromText.results[0]?.violations.find(
    (violation) => violation.rule_id === "SBOM-NTIA-SUPPLIER",
  );
  assert.equal(supplier?.severity, "Warning");
  assert.equal(supplier?.default_severity, "Error");
  assert.equal(supplier?.severity_source, "cli");
});

test("validateJson reports invalid options as validation errors", () => {
  const invalid: readonly ValidateOptions[] = [
    { standards: ["ntai"] },
    { as_of: "01/01/2027" },
    { pqc_profile: "federal" },
    { rules: { "SBOM-NTIA-SUPLIER": "off" } },
    { sidecar: { security_contact: "x" } },
  ];
  for (const options of invalid) {
    assert.throws(() => validateJson(fixture, options), isValidationError);
  }
  assert.throws(
    () => validateJson(fixture, { standards: "ntia" as unknown as string[] }),
    TypeError,
  );
});

test("ruleCatalogJson lists the registry", () => {
  const every = ruleCatalogJson();
  assert.equal(every.schema, "sbom-tools/rules/v1");
  assert.ok(every.rules.length >= 100);

  const ntia = ruleCatalogJson(["ntia"]);
  assert.ok(ntia.rules.length > 0 && ntia.rules.length < every.rules.length);
  assert.ok(ntia.rules.every((rule) => rule.standards.includes("ntia")));

  assert.throws(() => ruleCatalogJson(["crab"]), isValidationError);
});

test("scoreWithOptionsJson returns the quality document", () => {
  const options = { profile: "cra", as_of: "2027-01-01" };
  const output = scoreWithOptionsJson(fixture, options);
  assert.equal(output.tool, "sbom-tools");
  assert.equal(output.profile, "cra");
  assert.equal(output.sbom, "-");
  assert.equal(output.applicable, true);
  assert.equal(typeof output.report.overall_score, "number");
  assert.equal(typeof output.report.compliance, "object");
  // A pinned clock gives the same document.
  assert.deepEqual(scoreWithOptionsJson(fixture, options), output);

  const named = scoreWithOptionsJson(fixture, {
    ...options,
    file_name: fixturePath,
  });
  assert.equal(named.sbom, "minimal.cdx.json");
  assert.throws(
    () => scoreWithOptionsJson(fixture, { profile: "strict" }),
    isValidationError,
  );
});

test("scoreWithOptionsJson reports a profile that does not apply", () => {
  const output = scoreWithOptionsJson(fixture, {
    profile: "ai-readiness",
    as_of: "2027-01-01",
  });
  assert.equal(output.applicable, false);
  assert.equal(output.report.overall_score, null);
  assert.equal(output.report.grade, "N/A");
});
