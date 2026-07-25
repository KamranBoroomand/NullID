import {
  canonicalMachineIdentifier,
  canonicalSemanticIdentity,
  normalizeMachineIdentifier,
  normalizeSemanticDisplayText,
} from "./semanticIdentity.js";

export type KeyHintProfile = {
  id: string;
  name: string;
  keyHint: string;
  version: number;
  createdAt: string;
  updatedAt: string;
};

export const SHARED_KEY_HINT_PROFILE_KEY = "nullid:signing:key-hints";
export const LEGACY_KEY_HINT_PROFILE_KEYS = ["nullid:sanitize:key-hints"] as const;

const KEY_HINT_PROFILE_KEYS = ["id", "name", "keyHint", "version", "createdAt", "updatedAt"] as const;
const MAX_KEY_HINT_PROFILES = 20;
const MAX_KEY_HINT_ID_LENGTH = 128;
const MAX_KEY_HINT_NAME_LENGTH = 160;
const MAX_KEY_HINT_LENGTH = 64;
const MAX_KEY_HINT_VERSION = 10_000;

export type KeyHintProfileCollectionResult =
  | { ok: true; value: KeyHintProfile[] }
  | { ok: false; reason: string };

export function sanitizeKeyHint(value?: string) {
  const normalized = (value ?? "").trim();
  return normalized ? normalized.normalize("NFKC").slice(0, MAX_KEY_HINT_LENGTH) : "";
}

function rotateKeyHint(current: string, nextVersion: number) {
  const base = current.replace(/-v\d+$/i, "");
  return `${base || "hint"}-v${nextVersion}`;
}

export function upsertKeyHintProfile(profiles: KeyHintProfile[], nameRaw: string, hintRaw: string, nowIso = new Date().toISOString()) {
  const normalizedProfiles = normalizeKeyHintProfileCollection(profiles);
  if (!normalizedProfiles.ok) {
    return { ok: false as const, message: normalizedProfiles.reason };
  }
  const currentProfiles = normalizedProfiles.value;
  const name = normalizeSemanticDisplayText(nameRaw);
  const keyHint = sanitizeKeyHint(hintRaw);
  if (!name || !keyHint) {
    return { ok: false as const, message: "profile name + key hint required" };
  }

  const nameIdentity = canonicalSemanticIdentity(name);
  const existing = currentProfiles.find((profile) => canonicalSemanticIdentity(profile.name) === nameIdentity);
  if (existing) {
    const updated: KeyHintProfile = {
      ...existing,
      name,
      keyHint,
      updatedAt: nowIso,
    };
    return {
      ok: true as const,
      selectedId: updated.id,
      profiles: currentProfiles.map((profile) =>
        canonicalMachineIdentifier(profile.id, MAX_KEY_HINT_ID_LENGTH) === canonicalMachineIdentifier(existing.id, MAX_KEY_HINT_ID_LENGTH) ? updated : profile,
      ),
    };
  }

  const created: KeyHintProfile = {
    id: crypto.randomUUID(),
    name,
    keyHint,
    version: 1,
    createdAt: nowIso,
    updatedAt: nowIso,
  };

  return {
    ok: true as const,
    selectedId: created.id,
    profiles: [created, ...currentProfiles].slice(0, MAX_KEY_HINT_PROFILES),
  };
}

export function rotateProfileHint(profiles: KeyHintProfile[], id: string, nowIso = new Date().toISOString()) {
  const normalizedProfiles = normalizeKeyHintProfileCollection(profiles);
  if (!normalizedProfiles.ok) {
    return { ok: false as const, message: normalizedProfiles.reason };
  }
  const idIdentity = canonicalMachineIdentifier(id, MAX_KEY_HINT_ID_LENGTH);
  if (!idIdentity) {
    return { ok: false as const, message: "invalid key hint profile id" };
  }
  const currentProfiles = normalizedProfiles.value;
  const profile = currentProfiles.find((entry) => canonicalMachineIdentifier(entry.id, MAX_KEY_HINT_ID_LENGTH) === idIdentity);
  if (!profile) {
    return { ok: false as const, message: "key hint profile missing" };
  }

  const nextVersion = profile.version + 1;
  const nextHint = rotateKeyHint(profile.keyHint, nextVersion);
  return {
    ok: true as const,
    hint: nextHint,
    profiles: currentProfiles.map((entry) =>
      canonicalMachineIdentifier(entry.id, MAX_KEY_HINT_ID_LENGTH) === idIdentity
        ? {
            ...entry,
            version: nextVersion,
            keyHint: nextHint,
            updatedAt: nowIso,
          }
        : entry,
    ),
  };
}

export function removeProfileHint(profiles: KeyHintProfile[], id: string) {
  const normalizedProfiles = normalizeKeyHintProfileCollection(profiles);
  if (!normalizedProfiles.ok) {
    return profiles;
  }
  const idIdentity = canonicalMachineIdentifier(id, MAX_KEY_HINT_ID_LENGTH);
  if (!idIdentity) return normalizedProfiles.value;
  return normalizedProfiles.value.filter((profile) => canonicalMachineIdentifier(profile.id, MAX_KEY_HINT_ID_LENGTH) !== idIdentity);
}

export function findKeyHintProfileById(profiles: KeyHintProfile[], id: string) {
  const idIdentity = canonicalMachineIdentifier(id, MAX_KEY_HINT_ID_LENGTH);
  if (!idIdentity) return null;
  return profiles.find((profile) => canonicalMachineIdentifier(profile.id, MAX_KEY_HINT_ID_LENGTH) === idIdentity) ?? null;
}

export function normalizeKeyHintProfileCollection(value: unknown): KeyHintProfileCollectionResult {
  if (!Array.isArray(value) || value.length > MAX_KEY_HINT_PROFILES) {
    return { ok: false, reason: "expected bounded key hint profile array" };
  }
  const profiles: KeyHintProfile[] = [];
  const seenIds = new Set<string>();
  const seenNames = new Set<string>();
  for (const entry of value) {
    const normalized = normalizeProfile(entry);
    if (!normalized) return { ok: false, reason: "invalid key hint profile" };
    const idIdentity = canonicalMachineIdentifier(normalized.id, MAX_KEY_HINT_ID_LENGTH);
    const nameIdentity = canonicalSemanticIdentity(normalized.name);
    if (!idIdentity) return { ok: false, reason: "invalid key hint profile id" };
    if (seenIds.has(idIdentity)) return { ok: false, reason: "duplicate key hint profile id" };
    if (seenNames.has(nameIdentity)) return { ok: false, reason: "duplicate key hint profile name" };
    seenIds.add(idIdentity);
    seenNames.add(nameIdentity);
    profiles.push(normalized);
  }
  return { ok: true, value: profiles };
}

export function readLegacyProfiles(storageKey: string, storage: Storage | undefined = typeof localStorage === "undefined" ? undefined : localStorage): KeyHintProfile[] {
  if (!storage) return [];
  try {
    const raw = storage.getItem(storageKey);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    const normalized = normalizeKeyHintProfileCollection(parsed);
    return normalized.ok ? normalized.value : [];
  } catch {
    return [];
  }
}

function normalizeProfile(value: unknown): KeyHintProfile | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  if (!hasExactKeys(record, KEY_HINT_PROFILE_KEYS)) return null;
  if (typeof record.id !== "string" || typeof record.name !== "string" || typeof record.keyHint !== "string") return null;
  const id = normalizeMachineIdentifier(record.id, MAX_KEY_HINT_ID_LENGTH);
  const name = normalizeBoundedText(record.name, 1, MAX_KEY_HINT_NAME_LENGTH);
  const keyHint = sanitizeKeyHint(record.keyHint);
  if (!id || !name || !keyHint) return null;
  const version = record.version;
  if (typeof version !== "number" || !Number.isInteger(version) || version < 1 || version > MAX_KEY_HINT_VERSION) return null;
  const createdAt = normalizeCanonicalIsoTimestamp(record.createdAt);
  const updatedAt = normalizeCanonicalIsoTimestamp(record.updatedAt);
  if (!createdAt || !updatedAt || Date.parse(createdAt) > Date.parse(updatedAt)) return null;
  return {
    id,
    name,
    keyHint,
    version,
    createdAt,
    updatedAt,
  };
}

function normalizeBoundedText(value: string, min: number, max: number) {
  const normalized = normalizeSemanticDisplayText(value);
  return normalized.length >= min && normalized.length <= max ? normalized : null;
}

function normalizeCanonicalIsoTimestamp(value: unknown): string | null {
  if (typeof value !== "string" || value.length < 1 || value.length > 128) return null;
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) return null;
  const canonical = new Date(timestamp).toISOString();
  return canonical === value ? canonical : null;
}

function hasExactKeys(record: Record<string, unknown>, keys: readonly string[]) {
  const actual = Object.keys(record).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}
