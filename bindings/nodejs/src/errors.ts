import { ErrorCode } from "./types.js";

export class NativeLibraryNotFoundError extends Error {
  override readonly name = "NativeLibraryNotFoundError";
}

export class NativeLibraryLoadError extends Error {
  override readonly name = "NativeLibraryLoadError";
}

export class SbomToolsNativeError extends Error {
  override readonly name = "SbomToolsNativeError";

  constructor(
    message: string,
    readonly code?: ErrorCode,
  ) {
    super(message);
  }
}
