import { sha256Base64Url, signHash, verifyHashSignature } from "./integrity.js";
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
    const payloadHash = await sha256Base64Url({
        schemaVersion: POLICY_PACK_SCHEMA_VERSION,
        kind: "sanitize-policy-pack",
        exportedAt,
        packs: normalizedPacks,
    });
    const snapshot = {
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
    let keyHint;
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
