import { sha256Base64Url, signHash, verifyHashSignature, type IntegritySignature } from "./integrity.js";
import { normalizePolicyConfig, type PolicyPack } from "./sanitizeEngine.js";

export const POLICY_PACK_SCHEMA_VERSION = 2;
const LEGACY_POLICY_PACK_SCHEMA_VERSION = 1;

interface SerializablePolicyPack {
  name: string;
  createdAt: string;
  config: unknown;
}

export interface PolicyPackSnapshot {
  schemaVersion: number;
  kind: "sanitize-policy-pack";
  exportedAt: string;
  packs: SerializablePolicyPack[];
  integrity: {
    packCount: number;
    payloadHash: string;
  };
  signature?: IntegritySignature;
}

export interface PolicyPackExportOptions {
  signingPassphrase?: string;
  keyHint?: string;
}

export interface PolicyPackImportOptions {
  verificationPassphrase?: string;
  requireVerified?: boolean;
}

export interface PolicyPackImportResult {
  packs: PolicyPack[];
  signed: boolean;
  verified: boolean;
  legacy: boolean;
  keyHint?: string;
}

export interface PolicyPackDescriptor {
  schemaVersion: number;
  kind: string;
  packCount: number;
  signed: boolean;
  keyHint?: string;
}

export async function createPolicyPackSnapshot(packs: PolicyPack[], options?: PolicyPackExportOptions): Promise<PolicyPackSnapshot> {
  const normalizedPacks = packs
    .map((pack) => ({
      name: pack.name,
      createdAt: pack.createdAt,
      config: pack.config,
    }))
    .sort((a, b) => a.name.localeCompare(b.name) || a.createdAt.localeCompare(b.createdAt));

  const exportedAt = new Date().toISOString();
  const payloadHash = await sha256Base64Url({
    schemaVersion: POLICY_PACK_SCHEMA_VERSION,
    kind: "sanitize-policy-pack",
    exportedAt,
    packs: normalizedPacks,
  });

  const snapshot: PolicyPackSnapshot = {
    schemaVersion: POLICY_PACK_SCHEMA_VERSION,
    kind: "sanitize-policy-pack",
    exportedAt,
    packs: normalizedPacks,
    integrity: {
      packCount: normalizedPacks.length,
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

  return snapshot;
}

export function describePolicyPackPayload(input: unknown): PolicyPackDescriptor {
  if (!isRecord(input)) {
    return { schemaVersion: 0, kind: "unknown", packCount: 0, signed: false };
  }
  const packCount = Array.isArray(input.packs) ? input.packs.length : input.pack ? 1 : 0;
  const signature = input.signature;
  const keyHint = isRecord(signature) && typeof signature.keyHint === "string" ? signature.keyHint : undefined;
  return {
    schemaVersion: typeof input.schemaVersion === "number" ? input.schemaVersion : 0,
    kind: typeof input.kind === "string" ? input.kind : "unknown",
    packCount,
    signed: Boolean(signature),
    keyHint,
  };
}

export async function importPolicyPackPayload(input: unknown, options?: PolicyPackImportOptions): Promise<PolicyPackImportResult> {
  if (!isRecord(input) || input.kind !== "sanitize-policy-pack") {
    throw new Error("Invalid policy payload kind");
  }

  const schemaVersion = Number(input.schemaVersion);
  if (schemaVersion === LEGACY_POLICY_PACK_SCHEMA_VERSION) {
    return {
      packs: parseLegacyPacks(input),
      signed: false,
      verified: false,
      legacy: true,
    };
  }

  if (schemaVersion !== POLICY_PACK_SCHEMA_VERSION) {
    throw new Error(`Unsupported policy schema: ${String(input.schemaVersion ?? "unknown")}`);
  }

  const packs = parseRawPacks(input);
  if (!isRecord(input.integrity)) {
    throw new Error("Policy integrity metadata missing");
  }
  const integrity = input.integrity;
  const packCount = typeof integrity.packCount === "number" ? integrity.packCount : Number.NaN;
  const payloadHash = integrity.payloadHash;
  if (!Number.isInteger(packCount) || packCount < 0 || typeof payloadHash !== "string" || payloadHash.length < 16) {
    throw new Error("Invalid policy integrity metadata");
  }
  if (packCount !== packs.length) {
    throw new Error("Policy integrity mismatch (count)");
  }

  const computedHash = await sha256Base64Url({
    schemaVersion: POLICY_PACK_SCHEMA_VERSION,
    kind: "sanitize-policy-pack",
    exportedAt: input.exportedAt,
    packs: packs.map((entry) => ({ name: entry.name, createdAt: entry.createdAt, config: entry.config })),
  });
  if (computedHash !== payloadHash) {
    throw new Error("Policy integrity mismatch (hash)");
  }

  let signed = false;
  let verified = false;
  let keyHint: string | undefined;

  if (input.signature) {
    if (!isRecord(input.signature) || input.signature.algorithm !== "HMAC-SHA-256" || typeof input.signature.value !== "string") {
      throw new Error("Invalid policy signature metadata");
    }
    signed = true;
    keyHint = typeof input.signature.keyHint === "string" ? input.signature.keyHint : undefined;
    const secret = options?.verificationPassphrase;
    if (!secret) {
      throw new Error("Policy pack is signed; verification passphrase required");
    }
    verified = await verifyHashSignature(payloadHash, input.signature.value, secret);
    if (!verified) {
      throw new Error("Policy signature verification failed");
    }
  }

  if (options?.requireVerified && signed && !verified) {
    throw new Error("Policy verification required");
  }

  return {
    packs: packs.map((entry) => ({
      id: crypto.randomUUID(),
      name: entry.name,
      createdAt: entry.createdAt,
      config: entry.config,
    })),
    signed,
    verified,
    legacy: false,
    keyHint,
  };
}

export function mergePolicyPacks(existing: PolicyPack[], incoming: PolicyPack[]): PolicyPack[] {
  const byName = new Map(existing.map((pack) => [pack.name.toLowerCase(), pack]));
  incoming.forEach((pack) => {
    byName.set(pack.name.toLowerCase(), pack);
  });
  return Array.from(byName.values())
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt) || a.name.localeCompare(b.name))
    .slice(0, 30);
}

function parseLegacyPacks(input: Record<string, unknown>): PolicyPack[] {
  const source = Array.isArray(input.packs) ? input.packs : input.pack ? [input.pack] : [];
  return source
    .map((entry) => normalizePack(entry))
    .filter((entry): entry is PolicyPack => Boolean(entry));
}

function parseRawPacks(input: Record<string, unknown>): Array<{ name: string; createdAt: string; config: NonNullable<PolicyPack["config"]> }> {
  const source = Array.isArray(input.packs) ? input.packs : [];
  return source
    .map((entry) => normalizePack(entry))
    .filter((entry): entry is PolicyPack => Boolean(entry))
    .map((entry) => ({
      name: entry.name,
      createdAt: entry.createdAt,
      config: entry.config,
    }));
}

function normalizePack(entry: unknown): PolicyPack | null {
  if (!isRecord(entry)) return null;
  const name = typeof entry.name === "string" ? entry.name.trim() : "";
  if (!name) return null;
  const config = normalizePolicyConfig(entry.config);
  if (!config) return null;
  return {
    id: crypto.randomUUID(),
    name,
    createdAt: typeof entry.createdAt === "string" ? entry.createdAt : new Date().toISOString(),
    config,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
