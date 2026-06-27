import koffi from "koffi";

import { SbomToolsNativeError } from "./errors.js";
import { loadLibrary } from "./loader.js";
import {
  ErrorCode,
  ScoringProfile,
  type AbiVersion,
  type DetectedFormat,
  type JsonValue,
} from "./types.js";

type NativePointer = unknown | null;

interface NativeResult {
  readonly data: NativePointer;
  readonly error_code: number;
  readonly error_message: NativePointer;
}

interface NativeFunctions {
  readonly version: () => NativeResult;
  readonly detectFormat: (content: string) => NativeResult;
  readonly parsePath: (path: string) => NativeResult;
  readonly parseString: (content: string) => NativeResult;
  readonly diff: (oldSbom: string, newSbom: string) => NativeResult;
  readonly score: (sbom: string, profile: number) => NativeResult;
  readonly free: (result: NativeResult) => void;
  readonly stringLength: (pointer: NativePointer) => number | bigint;
}

let functions: NativeFunctions | undefined;

function native(): NativeFunctions {
  if (functions !== undefined) {
    return functions;
  }

  const library = loadLibrary();
  const ownedByte = koffi.opaque("SbomToolsOwnedByte");
  const ownedString = koffi.pointer("SbomToolsOwnedString", ownedByte);
  const stringResult = koffi.struct("SbomToolsStringResult", {
    data: ownedString,
    error_code: "uint32_t",
    error_message: ownedString,
  });
  const cRuntimeName =
    process.platform === "darwin"
      ? "/usr/lib/libSystem.B.dylib"
      : process.platform === "win32"
        ? "ucrtbase.dll"
        : "libc.so.6";
  const cRuntime = koffi.load(cRuntimeName);

  functions = {
    version: library.func("sbom_tools_abi_version_json", stringResult, []),
    detectFormat: library.func("sbom_tools_detect_format_json", stringResult, [
      "const char *",
    ]),
    parsePath: library.func("sbom_tools_parse_sbom_path_json", stringResult, [
      "const char *",
    ]),
    parseString: library.func("sbom_tools_parse_sbom_str_json", stringResult, [
      "const char *",
    ]),
    diff: library.func("sbom_tools_diff_sboms_json", stringResult, [
      "const char *",
      "const char *",
    ]),
    score: library.func("sbom_tools_score_sbom_json", stringResult, [
      "const char *",
      "uint32_t",
    ]),
    free: library.func("sbom_tools_string_result_free", "void", [stringResult]),
    stringLength: cRuntime.func("strlen", "size_t", [ownedString]),
  };
  return functions;
}

function decodePointer(
  api: NativeFunctions,
  pointer: NativePointer,
): string | null {
  if (pointer === null) {
    return null;
  }
  const rawLength = api.stringLength(pointer);
  const length = Number(rawLength);
  if (!Number.isSafeInteger(length) || length < 0) {
    throw new SbomToolsNativeError(
      `native library returned an invalid string length: ${String(rawLength)}`,
      ErrorCode.Internal,
    );
  }
  const bytes = koffi.decode(pointer, "uint8_t", length) as Uint8Array;
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

function consume(api: NativeFunctions, result: NativeResult): JsonValue {
  try {
    if (!Number.isInteger(result.error_code) || !(result.error_code in ErrorCode)) {
      throw new SbomToolsNativeError(
        `native library returned unknown error code ${result.error_code}`,
      );
    }
    const code = result.error_code as ErrorCode;
    if (code !== ErrorCode.Ok) {
      throw new SbomToolsNativeError(
        decodePointer(api, result.error_message) ??
          "native library returned no error message",
        code,
      );
    }

    const payload = decodePointer(api, result.data);
    if (payload === null) {
      throw new SbomToolsNativeError(
        "native library returned no JSON payload",
        ErrorCode.Internal,
      );
    }
    try {
      return JSON.parse(payload) as JsonValue;
    } catch (error: unknown) {
      throw new SbomToolsNativeError(
        `native library returned invalid JSON: ${String(error)}`,
        ErrorCode.Internal,
      );
    }
  } finally {
    api.free(result);
  }
}

function checkedInput(value: string, field: string): string {
  if (value.includes("\0")) {
    throw new TypeError(`${field} must not contain NUL bytes`);
  }
  return value;
}

function objectPayload(
  value: JsonValue,
  operation: string,
): { [key: string]: JsonValue } {
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    throw new SbomToolsNativeError(
      `${operation} returned a non-object payload`,
      ErrorCode.Internal,
    );
  }
  return value;
}

function requiredString(value: JsonValue | undefined, field: string): string {
  if (typeof value !== "string") {
    throw new SbomToolsNativeError(
      `native library returned invalid ${field}`,
      ErrorCode.Internal,
    );
  }
  return value;
}

export function version(): AbiVersion {
  const api = native();
  const payload = objectPayload(consume(api, api.version()), "version");
  return {
    abi_version: requiredString(payload.abi_version, "abi_version"),
    crate_version: requiredString(payload.crate_version, "crate_version"),
  };
}

export function detectFormat(content: string): DetectedFormat | null {
  const checkedContent = checkedInput(content, "content");
  const api = native();
  const value = consume(api, api.detectFormat(checkedContent));
  if (value === null) {
    return null;
  }
  const payload = objectPayload(value, "detectFormat");
  if (
    typeof payload.confidence !== "number" ||
    !Array.isArray(payload.warnings) ||
    !payload.warnings.every((warning) => typeof warning === "string") ||
    (payload.variant !== null && typeof payload.variant !== "string") ||
    (payload.version !== null && typeof payload.version !== "string")
  ) {
    throw new SbomToolsNativeError(
      "native library returned an invalid detected-format payload",
      ErrorCode.Internal,
    );
  }
  return {
    format_name: requiredString(payload.format_name, "format_name"),
    confidence: payload.confidence,
    variant: payload.variant,
    version: payload.version,
    warnings: payload.warnings,
  };
}

export function parsePathJson(path: string): JsonValue {
  const checkedPath = checkedInput(path, "path");
  const api = native();
  return consume(api, api.parsePath(checkedPath));
}

export function parseStringJson(content: string): JsonValue {
  const checkedContent = checkedInput(content, "content");
  const api = native();
  return consume(api, api.parseString(checkedContent));
}

export function diffJson(oldSbomJson: string, newSbomJson: string): JsonValue {
  const checkedOldSbom = checkedInput(oldSbomJson, "oldSbomJson");
  const checkedNewSbom = checkedInput(newSbomJson, "newSbomJson");
  const api = native();
  return consume(api, api.diff(checkedOldSbom, checkedNewSbom));
}

export function scoreJson(
  sbomJson: string,
  profile: ScoringProfile = ScoringProfile.Standard,
): JsonValue {
  if (
    !Number.isInteger(profile) ||
    profile < ScoringProfile.Minimal ||
    profile > ScoringProfile.AiReadiness
  ) {
    throw new RangeError(`invalid scoring profile: ${profile}`);
  }
  const checkedSbom = checkedInput(sbomJson, "sbomJson");
  const api = native();
  return consume(api, api.score(checkedSbom, profile));
}
