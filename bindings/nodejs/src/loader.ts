import { existsSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import koffi from "koffi";

import {
  NativeLibraryLoadError,
  NativeLibraryNotFoundError,
} from "./errors.js";

const libraryPathEnvironment = "SBOM_TOOLS_LIB_PATH";

export function libraryName(platform: NodeJS.Platform = process.platform): string {
  switch (platform) {
    case "darwin":
      return "libsbom_tools_ffi.dylib";
    case "linux":
      return "libsbom_tools_ffi.so";
    case "win32":
      return "sbom_tools_ffi.dll";
    default:
      throw new NativeLibraryNotFoundError(`unsupported platform: ${platform}`);
  }
}

function packageRoot(): string {
  return resolve(dirname(fileURLToPath(import.meta.url)), "../..");
}

function rustTargetTriple(): string | undefined {
  const triples: Partial<Record<NodeJS.Platform, Partial<Record<string, string>>>> = {
    darwin: {
      arm64: "aarch64-apple-darwin",
      x64: "x86_64-apple-darwin",
    },
    linux: {
      arm64: "aarch64-unknown-linux-gnu",
      x64: "x86_64-unknown-linux-gnu",
    },
    win32: {
      arm64: "aarch64-pc-windows-msvc",
      x64: "x86_64-pc-windows-msvc",
    },
  };
  return triples[process.platform]?.[process.arch];
}

export function localCandidates(name: string): readonly string[] {
  const root = packageRoot();
  const repositoryRoot = resolve(root, "../..");
  const targetRoot = resolve(repositoryRoot, "target");
  const candidates = [
    resolve(root, "native", name),
    resolve(targetRoot, "release", name),
  ];
  const targetTriple = rustTargetTriple();
  if (targetTriple !== undefined) {
    candidates.push(resolve(targetRoot, targetTriple, "release", name));
  }
  candidates.push(resolve(targetRoot, "debug", name));
  if (targetTriple !== undefined) {
    candidates.push(resolve(targetRoot, targetTriple, "debug", name));
  }
  return candidates;
}

function loadExact(path: string): koffi.IKoffiLib {
  if (!existsSync(path) || !statSync(path).isFile()) {
    throw new NativeLibraryNotFoundError(
      `${libraryPathEnvironment} does not name a library file: ${path}`,
    );
  }
  try {
    return koffi.load(path);
  } catch (error: unknown) {
    throw new NativeLibraryLoadError(
      `failed to load ${libraryPathEnvironment}=${path}: ${String(error)}`,
    );
  }
}

let loadedLibrary: koffi.IKoffiLib | undefined;

export function loadLibrary(): koffi.IKoffiLib {
  if (loadedLibrary !== undefined) {
    return loadedLibrary;
  }

  const configured = process.env[libraryPathEnvironment];
  if (configured) {
    loadedLibrary = loadExact(resolve(configured));
    return loadedLibrary;
  }

  const name = libraryName();
  const attempted: string[] = [];
  const loadErrors: string[] = [];

  for (const candidate of localCandidates(name)) {
    attempted.push(candidate);
    if (!existsSync(candidate) || !statSync(candidate).isFile()) {
      continue;
    }
    try {
      loadedLibrary = koffi.load(candidate);
      return loadedLibrary;
    } catch (error: unknown) {
      loadErrors.push(`${candidate}: ${String(error)}`);
    }
  }

  attempted.push(name);
  try {
    loadedLibrary = koffi.load(name);
    return loadedLibrary;
  } catch (error: unknown) {
    if (loadErrors.length > 0) {
      throw new NativeLibraryLoadError(
        `found no loadable native library; searched ${attempted.join(", ")}; ` +
          `loader errors: ${loadErrors.join("; ")}`,
      );
    }
    throw new NativeLibraryNotFoundError(
      `native library not found; searched ${attempted.join(", ")}; ` +
        `system loader: ${String(error)}`,
    );
  }
}

export function resetLibraryForTests(): void {
  loadedLibrary = undefined;
}
