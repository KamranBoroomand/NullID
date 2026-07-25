import type { IntegritySignature } from "./integrity.js";
import { SnapshotIntegrityError, createSnapshotIntegrity, verifySnapshotIntegrity } from "./snapshotIntegrity.js";
import {
  classifyProfileExportEntry,
  validateProfileEntryValue,
  type ProfileImportEntryDecision,
  type ProfileImportEntryIssue,
} from "./persistedSettings.js";
import { INPUT_LIMITS, readFileTextWithLimit } from "./inputLimits.js";

export const PROFILE_SCHEMA_VERSION = 2;
const LEGACY_PROFILE_SCHEMA_VERSION = 1;
const MAX_PROFILE_VALUE_DEPTH = 128;
const MAX_PROFILE_VALUE_NODES = 20_000;

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
  importedKeys: string[];
  skippedKeys: ProfileImportEntryIssue[];
  invalidKeys: ProfileImportEntryIssue[];
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

type ProfileVerificationState = "unsigned" | "integrity-checked" | "verified" | "verification-required" | "mismatch" | "invalid";

interface ProfileImportPlan {
  writes: Array<{ sourceKey: string; targetKey: string; serializedValue: string }>;
  aliasRemovals: string[];
  skippedKeys: ProfileImportEntryIssue[];
  invalidKeys: ProfileImportEntryIssue[];
}

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
    if (!key) continue;
    const decision = classifyProfileExportEntry(key, localStorage.getItem(key));
    if (decision.status === "export") {
      entries[key] = decision.value;
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
  const text = await readFileTextWithLimit(file, { label: "Profile snapshot", maxBytes: INPUT_LIMITS.jsonImportBytes });
  const parsed = JSON.parse(text) as Partial<ProfileSnapshot>;

  if (parsed.schemaVersion === LEGACY_PROFILE_SCHEMA_VERSION) {
    const entries = parseLegacyEntries(parsed);
    return { ...applyEntries(entries), signed: false, verified: false, legacy: true };
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

  return { ...applyEntries(entries), signed, verified, legacy: false };
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
  const plan = buildImportPlan(entries);
  if (plan.invalidKeys.length > 0) {
    return invalidProfileResult(
      descriptor,
      `Profile contains invalid recognized profile entries: ${formatImportIssues(plan.invalidKeys)}`,
      exportedAt,
      sampleEntryKeys(entries),
    );
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
  return parsed.entries as Record<string, unknown>;
}

function applyEntries(entries: Record<string, unknown>) {
  const plan = buildImportPlan(entries);
  if (plan.invalidKeys.length > 0) {
    throw new Error(`Profile import validation failed: ${formatImportIssues(plan.invalidKeys)}`);
  }
  const importedKeys = applyImportPlan(plan);

  return {
    applied: importedKeys.length,
    importedKeys,
    skippedKeys: plan.skippedKeys,
    invalidKeys: [],
  };
}

function buildImportPlan(entries: Record<string, unknown>): ProfileImportPlan {
  const skippedKeys: ProfileImportEntryIssue[] = [];
  const invalidKeys: ProfileImportEntryIssue[] = [];
  const writes: ProfileImportPlan["writes"] = [];
  const aliasRemovals = new Set<string>();
  const byTarget = new Map<string, ProfileImportEntryDecision>();

  for (const [key, value] of Object.entries(entries).sort(([left], [right]) => left.localeCompare(right))) {
    const decision = validateProfileEntryValue(key, value);
    if (decision.status === "skip") {
      skippedKeys.push({ key, reason: decision.reason ?? "profile key skipped" });
      continue;
    }
    if (decision.status === "invalid" || !decision.targetKey || decision.serializedValue == null) {
      invalidKeys.push({ key, reason: decision.reason ?? "profile value failed validation" });
      continue;
    }
    const previous = byTarget.get(decision.targetKey);
    if (previous) {
      invalidKeys.push({ key, reason: `profile entry conflicts with ${previous.key} for target ${decision.targetKey}` });
      continue;
    }
    byTarget.set(decision.targetKey, decision);
    writes.push({ sourceKey: key, targetKey: decision.targetKey, serializedValue: decision.serializedValue });
    if (key !== decision.targetKey) aliasRemovals.add(key);
  }

  return {
    writes: writes.sort((left, right) => left.targetKey.localeCompare(right.targetKey) || left.sourceKey.localeCompare(right.sourceKey)),
    aliasRemovals: Array.from(aliasRemovals).sort(),
    skippedKeys,
    invalidKeys,
  };
}

function applyImportPlan(plan: ProfileImportPlan): string[] {
  const touchedKeys = Array.from(new Set([...plan.writes.map((write) => write.targetKey), ...plan.aliasRemovals])).sort();
  const snapshot = new Map(touchedKeys.map((key) => [key, localStorage.getItem(key)] as const));
  const importedKeys: string[] = [];

  try {
    for (const write of plan.writes) {
      localStorage.setItem(write.targetKey, write.serializedValue);
      importedKeys.push(write.targetKey);
    }
    for (const key of plan.aliasRemovals) {
      try {
        localStorage.removeItem(key);
      } catch (error) {
        throw new Error(`profile alias removal failed for ${key}: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
    for (const write of plan.writes) {
      if (localStorage.getItem(write.targetKey) !== write.serializedValue) {
        throw new Error(`profile postcondition failed for ${write.targetKey}`);
      }
    }
    for (const key of plan.aliasRemovals) {
      if (localStorage.getItem(key) !== null) {
        throw new Error(`profile alias removal postcondition failed for ${key}`);
      }
    }
    return importedKeys;
  } catch (error) {
    const rollbackErrors: string[] = [];
    for (const [key, value] of snapshot) {
      try {
        if (value === null) localStorage.removeItem(key);
        else localStorage.setItem(key, value);
      } catch (rollbackError) {
        rollbackErrors.push(`${key}: ${rollbackError instanceof Error ? rollbackError.message : String(rollbackError)}`);
      }
    }
    const reason = error instanceof Error ? error.message : String(error || "profile import failed");
    if (rollbackErrors.length > 0) {
      throw new Error(`Profile import failed and rollback failed: ${reason}; ${rollbackErrors.join("; ")}`);
    }
    throw new Error(`Profile import failed; rolled back: ${reason}`);
  }
}

function formatImportIssues(issues: ProfileImportEntryIssue[]) {
  return issues.map((issue) => `${issue.key} (${issue.reason})`).join("; ");
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isSupportedValue(value: unknown): value is string | number | boolean | null | Record<string, unknown> | unknown[] {
  const pending: Array<{ value: unknown; depth: number }> = [{ value, depth: 0 }];
  let nodes = 0;
  while (pending.length > 0) {
    const current = pending.pop()!;
    nodes += 1;
    if (nodes > MAX_PROFILE_VALUE_NODES || current.depth > MAX_PROFILE_VALUE_DEPTH) return false;
    if (current.value === null) continue;
    const t = typeof current.value;
    if (t === "string" || t === "number" || t === "boolean") continue;
    if (Array.isArray(current.value)) {
      for (const item of current.value) {
        pending.push({ value: item, depth: current.depth + 1 });
      }
      continue;
    }
    if (t === "object") {
      for (const item of Object.values(current.value as Record<string, unknown>)) {
        pending.push({ value: item, depth: current.depth + 1 });
      }
      continue;
    }
    return false;
  }
  return true;
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
