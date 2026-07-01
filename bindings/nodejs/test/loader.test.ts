import assert from "node:assert/strict";
import { resolve } from "node:path";
import test from "node:test";

import {
  libraryName,
  loadLibrary,
  localCandidates,
  resetLibraryForTests,
} from "../src/loader.js";
import { NativeLibraryNotFoundError } from "../src/errors.js";

test("platform library names match the Rust cdylib outputs", () => {
  assert.equal(libraryName("darwin"), "libsbom_tools_ffi.dylib");
  assert.equal(libraryName("linux"), "libsbom_tools_ffi.so");
  assert.equal(libraryName("win32"), "sbom_tools_ffi.dll");
});

test("local candidates follow documented precedence", () => {
  const candidates = localCandidates(libraryName());
  assert.match(candidates[0] ?? "", /bindings[/\\]nodejs[/\\]native/);
  assert.match(candidates[1] ?? "", /target[/\\]release/);
  assert.ok(candidates.some((candidate) => /target[/\\]debug/.test(candidate)));
});

test("an invalid explicit library path fails without fallback", () => {
  const previous = process.env.SBOM_TOOLS_LIB_PATH;
  process.env.SBOM_TOOLS_LIB_PATH = resolve("does-not-exist");
  resetLibraryForTests();
  try {
    assert.throws(() => loadLibrary(), NativeLibraryNotFoundError);
  } finally {
    if (previous === undefined) {
      delete process.env.SBOM_TOOLS_LIB_PATH;
    } else {
      process.env.SBOM_TOOLS_LIB_PATH = previous;
    }
    resetLibraryForTests();
  }
});
