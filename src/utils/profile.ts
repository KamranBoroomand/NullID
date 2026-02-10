import { sha256Base64Url, signHash, verifyHashSignature, type IntegritySignature } from "./integrity.js";

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

export async function collectProfile(options?: ProfileExportOptions): Promise<ProfileSnapshot> {
  const entries: Record<string, unknown> = {};
  for (let i = 0; i < localStorage.length; i += 1) {
    const key = localStorage.key(i);
    if (!key || !key.startsWith(PREFIX)) continue;
    const value = localStorage.getItem(key);
    try {
      entries[key] = value ? JSON.parse(value) : null;
    } catch {
      entries[key] = value;
    }
  }

  const exportedAt = new Date().toISOString();
  const payloadHash = await sha256Base64Url({
    schemaVersion: PROFILE_SCHEMA_VERSION,
    exportedAt,
    entries,
  });
  const snapshot: ProfileSnapshot = {
    schemaVersion: PROFILE_SCHEMA_VERSION,
    kind: "profile",
    exportedAt,
    entries,
    integrity: {
      entryCount: Object.keys(entries).length,
      payloadHash,
    },
  };
  if (options?.signingPassphrase) {
    snapshot.signature = {
      algorithm: "HMAC-SHA-256",
      value: await signHash(payloadHash, options.signingPassphrase),
      keyHint: options.keyHint?.trim().slice(0, 64) || undefined,
    };
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
  const entryCount = parsed.integrity.entryCount;
  const payloadHash = parsed.integrity.payloadHash;
  if (!Number.isInteger(entryCount) || entryCount < 0 || typeof payloadHash !== "string" || payloadHash.length < 16) {
    throw new Error("Invalid profile integrity metadata");
  }
  const entries = parsed.entries as Record<string, unknown>;
  if (Object.keys(entries).length !== entryCount) {
    throw new Error("Profile integrity mismatch (entry count)");
  }

  if (!Object.values(entries).every((value) => isSupportedValue(value))) {
    throw new Error("Profile payload contains unsupported value types");
  }

  const computedHash = await sha256Base64Url({
    schemaVersion: PROFILE_SCHEMA_VERSION,
    exportedAt: parsed.exportedAt,
    entries,
  });
  if (computedHash !== payloadHash) {
    throw new Error("Profile integrity mismatch (hash)");
  }

  let signed = false;
  let verified = false;
  if (parsed.signature) {
    if (!isPlainObject(parsed.signature) || parsed.signature.algorithm !== "HMAC-SHA-256" || typeof parsed.signature.value !== "string") {
      throw new Error("Invalid profile signature metadata");
    }
    signed = true;
    const verifySecret = options?.verificationPassphrase;
    if (!verifySecret) {
      throw new Error("Profile is signed; verification passphrase required");
    }
    verified = await verifyHashSignature(payloadHash, parsed.signature.value, verifySecret);
    if (!verified) {
      throw new Error("Profile signature verification failed");
    }
  }

  const applied = applyEntries(entries);
  return { applied, signed, verified, legacy: false };
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
