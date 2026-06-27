import assert from "node:assert/strict";
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
  scoreJson,
  version,
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
