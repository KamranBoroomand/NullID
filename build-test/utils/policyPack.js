import { createSnapshotIntegrity, verifySnapshotIntegrity } from "./snapshotIntegrity.js";
import { normalizePolicyConfig } from "./sanitizeEngine.js";
export const POLICY_PACK_SCHEMA_VERSION = 2;
const LEGACY_POLICY_PACK_SCHEMA_VERSION = 1;
export async function createPolicyPackSnapshot(packs, options) {
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
    const snapshot = {
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
export function describePolicyPackPayload(input) {
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
export async function importPolicyPackPayload(input, options) {
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
export function mergePolicyPacks(existing, incoming) {
    const byName = new Map(existing.map((pack) => [pack.name.toLowerCase(), pack]));
    incoming.forEach((pack) => {
        byName.set(pack.name.toLowerCase(), pack);
    });
    return Array.from(byName.values())
        .sort((a, b) => b.createdAt.localeCompare(a.createdAt) || a.name.localeCompare(b.name))
        .slice(0, 30);
}
function parseLegacyPacks(input) {
    const source = Array.isArray(input.packs) ? input.packs : input.pack ? [input.pack] : [];
    return source
        .map((entry) => normalizePack(entry))
        .filter((entry) => Boolean(entry));
}
function parseRawPacks(input) {
    const source = Array.isArray(input.packs) ? input.packs : [];
    return source
        .map((entry) => normalizePack(entry))
        .filter((entry) => Boolean(entry))
        .map((entry) => ({
        name: entry.name,
        createdAt: entry.createdAt,
        config: entry.config,
    }));
}
function normalizePack(entry) {
    if (!isRecord(entry))
        return null;
    const name = typeof entry.name === "string" ? entry.name.trim() : "";
    if (!name)
        return null;
    const config = normalizePolicyConfig(entry.config);
    if (!config)
        return null;
    return {
        id: crypto.randomUUID(),
        name,
        createdAt: typeof entry.createdAt === "string" ? entry.createdAt : new Date().toISOString(),
        config,
    };
}
function isRecord(value) {
    return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
