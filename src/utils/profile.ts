import type { IntegritySignature } from "./integrity.js";
import { SnapshotIntegrityError, createSnapshotIntegrity, verifySnapshotIntegrity } from "./snapshotIntegrity.js";
import { isVaultLocalStorageRecordKey } from "./vaultStorageKeys.js";

export const PROFILE_SCHEMA_VERSION = 2;
const LEGACY_PROFILE_SCHEMA_VERSION = 1;
const PREFIX = "nullid:";

export type ProfileSnapshot = {
  schemaVersion: number;
  exportedAt: string;
  kind?: "profile";
  entries: Record<string, unknown>;
  integrity?: {
    entryCount: number;
    payloadHash: string;
  };
  signature?: IntegritySignature;
};

export interface ProfileExportOptions {
  signingPassphrase?: string;
  keyHint?: string;
}

export interface ProfileImportOptions {
  verificationPassphrase?: string;
}

export interface ProfileImportResult {
  applied: number;
  signed: boolean;
  verified: boolean;
  legacy: boolean;
}

export interface ProfileDescriptor {
  schemaVersion: number;
  kind: string;
  entryCount: number;
  signed: boolean;
  keyHint?: string;
  legacy: boolean;
}

export type ProfileVerificationState = "unsigned" | "integrity-checked" | "verified" | "verification-required" | "mismatch" | "invalid";

export interface ProfileVerificationResult extends ProfileDescriptor {
  verificationState: ProfileVerificationState;
  verificationLabel: string;
  trustBasis: string[];
  verifiedChecks: string[];
  unverifiedChecks: string[];
  warnings: string[];
  exportedAt?: string;
  sampleKeys: string[];
  failure?: string;
}

export async function collectProfile(options?: ProfileExportOptions): Promise<ProfileSnapshot> {
  const entries: Record<string, unknown> = {};
  for (let i = 0; i < localStorage.length; i += 1) {
    const key = localStorage.key(i);
    if (!key || !key.startsWith(PREFIX)) continue;
    if (isVaultLocalStorageRecordKey(key)) continue;
    const value = localStorage.getItem(key);
    try {
      entries[key] = value ? JSON.parse(value) : null;
    } catch {
      entries[key] = value;
    }
  }

  const exportedAt = new Date().toISOString();
  const payload = {
    schemaVersion: PROFILE_SCHEMA_VERSION,
    exportedAt,
    entries,
  };
  const { integrity, signature } = await createSnapshotIntegrity(payload, "entryCount", Object.keys(entries).length, options);
  const snapshot: ProfileSnapshot = {
    schemaVersion: PROFILE_SCHEMA_VERSION,
    kind: "profile",
    exportedAt,
    entries,
    integrity,
  };
  if (signature) {
    snapshot.signature = signature;
  }
  return {
    ...snapshot,
  };
}

export async function downloadProfile(filename = "nullid-profile.json", options?: ProfileExportOptions) {
  const snapshot = await collectProfile(options);
  const blob = new Blob([JSON.stringify(snapshot, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
  return {
    signed: Boolean(snapshot.signature),
    entryCount: Object.keys(snapshot.entries).length,
  };
}

export function describeProfilePayload(input: unknown): ProfileDescriptor {
  if (!isPlainObject(input)) {
    return { schemaVersion: 0, kind: "unknown", entryCount: 0, signed: false, legacy: false };
  }
  const entries = isPlainObject(input.entries) ? input.entries : {};
  const signature = isPlainObject(input.signature) ? input.signature : undefined;
  const schemaVersion = typeof input.schemaVersion === "number" ? input.schemaVersion : 0;
  return {
    schemaVersion,
    kind: typeof input.kind === "string" ? input.kind : "profile",
    entryCount: Object.keys(entries).length,
    signed: Boolean(signature),
    keyHint: typeof signature?.keyHint === "string" ? signature.keyHint : undefined,
    legacy: schemaVersion === LEGACY_PROFILE_SCHEMA_VERSION,
  };
}

export async function importProfileFile(file: File, options?: ProfileImportOptions): Promise<ProfileImportResult> {
  const text = await file.text();
  const parsed = JSON.parse(text) as Partial<ProfileSnapshot>;

  if (parsed.schemaVersion === LEGACY_PROFILE_SCHEMA_VERSION) {
    const entries = parseLegacyEntries(parsed);
    const applied = applyEntries(entries);
    return { applied, signed: false, verified: false, legacy: true };
  }

  if (parsed.schemaVersion !== PROFILE_SCHEMA_VERSION) {
    throw new Error(`Unsupported profile schema: ${String(parsed.schemaVersion ?? "unknown")}`);
  }

  if (parsed.kind && parsed.kind !== "profile") {
    throw new Error("Invalid profile payload kind");
  }
  if (!isPlainObject(parsed.entries)) {
    throw new Error("Invalid profile payload");
  }
  if (!isPlainObject(parsed.integrity)) {
    throw new Error("Profile integrity metadata missing");
  }
  const entries = parsed.entries as Record<string, unknown>;

  if (!Object.values(entries).every((value) => isSupportedValue(value))) {
    throw new Error("Profile payload contains unsupported value types");
  }

  const { signed, verified } = await verifySnapshotIntegrity({
    subject: "Profile",
    countKey: "entryCount",
    actualCount: Object.keys(entries).length,
    payload: {
      schemaVersion: PROFILE_SCHEMA_VERSION,
      exportedAt: parsed.exportedAt,
      entries,
    },
    integrity: parsed.integrity,
    signature: parsed.signature,
    verificationPassphrase: options?.verificationPassphrase,
    missingIntegrityMessage: "Profile integrity metadata missing",
    invalidIntegrityMessage: "Invalid profile integrity metadata",
    countMismatchMessage: "Profile integrity mismatch (entry count)",
    hashMismatchMessage: "Profile integrity mismatch (hash)",
    invalidSignatureMessage: "Invalid profile signature metadata",
    verificationRequiredMessage: "Profile is signed; verification passphrase required",
    verificationFailedMessage: "Profile signature verification failed",
  });

  const applied = applyEntries(entries);
  return { applied, signed, verified, legacy: false };
}

export async function verifyProfilePayload(input: unknown, options?: ProfileImportOptions): Promise<ProfileVerificationResult> {
  const descriptor = describeProfilePayload(input);
  if (!isPlainObject(input)) {
    return invalidProfileResult(descriptor, "Invalid profile payload");
  }

  const exportedAt = typeof input.exportedAt === "string" ? input.exportedAt : undefined;
  if (input.schemaVersion === LEGACY_PROFILE_SCHEMA_VERSION) {
    const entries = parseLegacyEntries(input as Partial<ProfileSnapshot>);
    return {
      ...descriptor,
      verificationState: "unsigned",
      verificationLabel: "Unsigned",
      trustBasis: ["Legacy profile payload with no integrity metadata."],
      verifiedChecks: [`Parsed ${Object.keys(entries).length} profile entr${Object.keys(entries).length === 1 ? "y" : "ies"}.`],
      unverifiedChecks: ["Legacy profile payloads do not carry payload hashing or HMAC verification metadata."],
      warnings: [],
      exportedAt,
      sampleKeys: sampleEntryKeys(entries),
    };
  }

  if (input.schemaVersion !== PROFILE_SCHEMA_VERSION) {
    return invalidProfileResult(descriptor, `Unsupported profile schema: ${String(input.schemaVersion ?? "unknown")}`, exportedAt);
  }
  if (input.kind && input.kind !== "profile") {
    return invalidProfileResult(descriptor, "Invalid profile payload kind", exportedAt);
  }
  if (!isPlainObject(input.entries)) {
    return invalidProfileResult(descriptor, "Invalid profile payload", exportedAt);
  }

  const entries = input.entries as Record<string, unknown>;
  if (!Object.values(entries).every((value) => isSupportedValue(value))) {
    return invalidProfileResult(descriptor, "Profile payload contains unsupported value types", exportedAt, sampleEntryKeys(entries));
  }

  try {
    const verification = await verifySnapshotIntegrity({
      subject: "Profile",
      countKey: "entryCount",
      actualCount: Object.keys(entries).length,
      payload: {
        schemaVersion: PROFILE_SCHEMA_VERSION,
        exportedAt: input.exportedAt,
        entries,
      },
      integrity: input.integrity,
      signature: input.signature,
      verificationPassphrase: options?.verificationPassphrase,
      missingIntegrityMessage: "Profile integrity metadata missing",
      invalidIntegrityMessage: "Invalid profile integrity metadata",
      countMismatchMessage: "Profile integrity mismatch (entry count)",
      hashMismatchMessage: "Profile integrity mismatch (hash)",
      invalidSignatureMessage: "Invalid profile signature metadata",
      verificationRequiredMessage: "Profile is signed; verification passphrase required",
      verificationFailedMessage: "Profile signature verification failed",
    });
    const signed = verification.signed;
    return {
      ...descriptor,
      verificationState: signed ? "verified" : "integrity-checked",
      verificationLabel: signed ? "HMAC verified" : "Integrity checked",
      trustBasis: signed
        ? ["Shared-secret HMAC verification succeeded.", "Payload hash and entry count matched the embedded metadata."]
        : ["Payload hash and entry count matched the embedded integrity metadata.", "No sender identity is asserted."],
      verifiedChecks: [
        `Profile entry count matched (${Object.keys(entries).length}).`,
        "Payload hash matched the embedded integrity metadata.",
      ],
      unverifiedChecks: signed ? ["Shared-secret verification proves tamper detection for holders of the same secret, not public-key identity."] : [],
      warnings: [],
      exportedAt,
      sampleKeys: sampleEntryKeys(entries),
    };
  } catch (error) {
    return profileErrorResult(descriptor, error, sampleEntryKeys(entries), exportedAt);
  }
}

function parseLegacyEntries(parsed: Partial<ProfileSnapshot>) {
  if (!isPlainObject(parsed.entries)) {
    throw new Error("Invalid legacy profile payload");
  }
  const entries = parsed.entries as Record<string, unknown>;
  if (!Object.values(entries).every((value) => isSupportedValue(value))) {
    throw new Error("Legacy profile contains unsupported value types");
  }
  return entries;
}

function applyEntries(entries: Record<string, unknown>) {
  let applied = 0;
  Object.entries(entries).forEach(([key, value]) => {
    if (!key.startsWith(PREFIX)) return;
    if (isVaultLocalStorageRecordKey(key)) return;
    localStorage.setItem(key, JSON.stringify(value));
    applied += 1;
  });
  return applied;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isSupportedValue(value: unknown): value is string | number | boolean | null | Record<string, unknown> | unknown[] {
  if (value === null) return true;
  const t = typeof value;
  if (t === "string" || t === "number" || t === "boolean") return true;
  if (Array.isArray(value)) return value.every(isSupportedValue);
  if (t === "object") return Object.values(value as Record<string, unknown>).every(isSupportedValue);
  return false;
}

function sampleEntryKeys(entries: Record<string, unknown>) {
  return Object.keys(entries).sort().slice(0, 6);
}

function invalidProfileResult(
  descriptor: ProfileDescriptor,
  failure: string,
  exportedAt?: string,
  sampleKeys: string[] = [],
): ProfileVerificationResult {
  return {
    ...descriptor,
    verificationState: "invalid",
    verificationLabel: "Invalid",
    trustBasis: ["NullID could not validate the structure of this profile payload."],
    verifiedChecks: [],
    unverifiedChecks: ["No integrity or authenticity guarantees could be established."],
    warnings: [failure],
    exportedAt,
    sampleKeys,
    failure,
  };
}

function profileErrorResult(
  descriptor: ProfileDescriptor,
  error: unknown,
  sampleKeys: string[],
  exportedAt?: string,
): ProfileVerificationResult {
  const failure = error instanceof Error ? error.message : "Profile verification failed";
  if (error instanceof SnapshotIntegrityError) {
    if (error.code === "verification-required") {
      return {
        ...descriptor,
        verificationState: "verification-required",
        verificationLabel: "Verification required",
        trustBasis: ["Shared-secret HMAC metadata is present."],
        verifiedChecks: [],
        unverifiedChecks: ["A verification passphrase is required before authenticity can be checked."],
        warnings: descriptor.keyHint ? [`Expected key hint: ${descriptor.keyHint}`] : [],
        exportedAt,
        sampleKeys,
        failure,
      };
    }
    if (error.code === "verification-failed" || error.code === "integrity-count-mismatch" || error.code === "integrity-hash-mismatch") {
      return {
        ...descriptor,
        verificationState: "mismatch",
        verificationLabel: "Mismatch",
        trustBasis: ["Profile integrity metadata was present, but verification did not succeed."],
        verifiedChecks: [],
        unverifiedChecks: ["The payload may be tampered, incomplete, or paired with the wrong shared secret."],
        warnings: [failure],
        exportedAt,
        sampleKeys,
        failure,
      };
    }
  }
  return invalidProfileResult(descriptor, failure, exportedAt, sampleKeys);
}
