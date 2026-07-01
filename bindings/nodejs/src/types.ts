export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

export enum ErrorCode {
  Ok = 0,
  Parse = 1,
  Diff = 2,
  Validation = 3,
  Io = 4,
  Unsupported = 5,
  Internal = 6,
}

export enum ScoringProfile {
  Minimal = 0,
  Standard = 1,
  Security = 2,
  LicenseCompliance = 3,
  Cra = 4,
  Comprehensive = 5,
  AiReadiness = 6,
}

export interface AbiVersion {
  readonly abi_version: string;
  readonly crate_version: string;
}

export interface DetectedFormat {
  readonly format_name: string;
  readonly confidence: number;
  readonly variant: string | null;
  readonly version: string | null;
  readonly warnings: readonly string[];
}
