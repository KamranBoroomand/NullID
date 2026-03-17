import type { IntegritySignature } from "./integrity.js";
import { createSnapshotIntegrity, verifySnapshotIntegrity } from "./snapshotIntegrity.js";
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
  const payload = {
    schemaVersion: POLICY_PACK_SCHEMA_VERSION,
    kind: "sanitize-policy-pack",
    exportedAt,
    packs: normalizedPacks,
  };
  const { integrity, signature } = await createSnapshotIntegrity(payload, "packCount", normalizedPacks.length, options);

  const snapshot: PolicyPackSnapshot = {
    schemaVersion: POLICY_PACK_SCHEMA_VERSION,
    kind: "sanitize-policy-pack",
    exportedAt,
    packs: normalizedPacks,
    integrity,
  };

  if (signature) {
    snapshot.signature = signature;
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
  const { signed, verified, keyHint } = await verifySnapshotIntegrity({
    subject: "Policy pack",
    countKey: "packCount",
    actualCount: packs.length,
    payload: {
      schemaVersion: POLICY_PACK_SCHEMA_VERSION,
      kind: "sanitize-policy-pack",
      exportedAt: input.exportedAt,
      packs: packs.map((entry) => ({ name: entry.name, createdAt: entry.createdAt, config: entry.config })),
    },
    integrity: input.integrity,
    signature: input.signature,
    verificationPassphrase: options?.verificationPassphrase,
    missingIntegrityMessage: "Policy integrity metadata missing",
    invalidIntegrityMessage: "Invalid policy integrity metadata",
    countMismatchMessage: "Policy integrity mismatch (count)",
    hashMismatchMessage: "Policy integrity mismatch (hash)",
    invalidSignatureMessage: "Invalid policy signature metadata",
    verificationRequiredMessage: "Policy pack is signed; verification passphrase required",
    verificationFailedMessage: "Policy signature verification failed",
  });

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
