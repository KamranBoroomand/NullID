export type KeyHintProfile = {
  id: string;
  name: string;
  keyHint: string;
  version: number;
  createdAt: string;
  updatedAt: string;
};

export const SHARED_KEY_HINT_PROFILE_KEY = "nullid:signing:key-hints";

export function sanitizeKeyHint(value?: string) {
  const normalized = (value ?? "").trim();
  return normalized ? normalized.slice(0, 64) : "";
}

export function rotateKeyHint(current: string, nextVersion: number) {
  const base = current.replace(/-v\d+$/i, "");
  return `${base || "hint"}-v${nextVersion}`;
}

export function upsertKeyHintProfile(profiles: KeyHintProfile[], nameRaw: string, hintRaw: string, nowIso = new Date().toISOString()) {
  const name = nameRaw.trim();
  const keyHint = sanitizeKeyHint(hintRaw);
  if (!name || !keyHint) {
    return { ok: false as const, message: "profile name + key hint required" };
  }

  const existing = profiles.find((profile) => profile.name.toLowerCase() === name.toLowerCase());
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
      profiles: profiles.map((profile) => (profile.id === existing.id ? updated : profile)),
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
    profiles: [created, ...profiles].slice(0, 20),
  };
}

export function rotateProfileHint(profiles: KeyHintProfile[], id: string, nowIso = new Date().toISOString()) {
  const profile = profiles.find((entry) => entry.id === id);
  if (!profile) {
    return { ok: false as const, message: "key hint profile missing" };
  }

  const nextVersion = profile.version + 1;
  const nextHint = rotateKeyHint(profile.keyHint, nextVersion);
  return {
    ok: true as const,
    hint: nextHint,
    profiles: profiles.map((entry) =>
      entry.id === id
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
  return profiles.filter((profile) => profile.id !== id);
}

export function readLegacyProfiles(storageKey: string): KeyHintProfile[] {
  if (typeof localStorage === "undefined") return [];
  try {
    const raw = localStorage.getItem(storageKey);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed
      .map((entry) => normalizeProfile(entry))
      .filter((entry): entry is KeyHintProfile => Boolean(entry));
  } catch {
    return [];
  }
}

function normalizeProfile(value: unknown): KeyHintProfile | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  if (typeof record.id !== "string" || typeof record.name !== "string" || typeof record.keyHint !== "string") {
    return null;
  }
  const keyHint = sanitizeKeyHint(record.keyHint);
  if (!keyHint) return null;
  return {
    id: record.id,
    name: record.name.trim() || "hint",
    keyHint,
    version: typeof record.version === "number" && Number.isInteger(record.version) && record.version > 0 ? record.version : 1,
    createdAt: typeof record.createdAt === "string" ? record.createdAt : new Date().toISOString(),
    updatedAt: typeof record.updatedAt === "string" ? record.updatedAt : new Date().toISOString(),
  };
}
