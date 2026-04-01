import { SnapshotIntegrityError, createSnapshotIntegrity, verifySnapshotIntegrity } from "./snapshotIntegrity.js";
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
export async function verifyPolicyPackPayload(input, options) {
    const descriptor = describePolicyPackPayload(input);
    if (!isRecord(input) || input.kind !== "sanitize-policy-pack") {
        return invalidPolicyPackResult(descriptor, "Invalid policy payload kind");
    }
    const schemaVersion = Number(input.schemaVersion);
    if (schemaVersion === LEGACY_POLICY_PACK_SCHEMA_VERSION) {
        const packs = parseLegacyPacks(input);
        return {
            ...descriptor,
            verificationState: "unsigned",
            verificationLabel: "Unsigned",
            trustBasis: ["Legacy policy pack with no integrity metadata."],
            verifiedChecks: [`Parsed ${packs.length} policy pack(s) from the legacy payload.`],
            unverifiedChecks: ["Legacy policy packs do not include payload hashing or HMAC verification metadata."],
            warnings: [],
            exportedAt: typeof input.exportedAt === "string" ? input.exportedAt : undefined,
            packNames: packs.map((pack) => pack.name),
        };
    }
    if (schemaVersion !== POLICY_PACK_SCHEMA_VERSION) {
        return invalidPolicyPackResult(descriptor, `Unsupported policy schema: ${String(input.schemaVersion ?? "unknown")}`);
    }
    const packs = parseRawPacks(input);
    try {
        const verification = await verifySnapshotIntegrity({
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
        const signed = verification.signed;
        return {
            ...descriptor,
            verificationState: signed ? "verified" : "integrity-checked",
            verificationLabel: signed ? "HMAC verified" : "Integrity checked",
            trustBasis: signed
                ? ["Shared-secret HMAC verification succeeded.", "Payload hash and pack count matched the signed metadata."]
                : ["Payload hash and pack count matched the embedded integrity metadata.", "No sender identity is asserted."],
            verifiedChecks: [
                `Policy pack count matched (${packs.length}).`,
                "Payload hash matched the embedded integrity metadata.",
            ],
            unverifiedChecks: signed ? ["Shared-secret verification proves tamper detection for holders of the same secret, not public-key identity."] : [],
            warnings: [],
            exportedAt: typeof input.exportedAt === "string" ? input.exportedAt : undefined,
            packNames: packs.map((pack) => pack.name),
        };
    }
    catch (error) {
        return policyPackErrorResult(descriptor, error, packs.map((pack) => pack.name), typeof input.exportedAt === "string" ? input.exportedAt : undefined);
    }
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
function invalidPolicyPackResult(descriptor, failure) {
    return {
        ...descriptor,
        verificationState: "invalid",
        verificationLabel: "Invalid",
        trustBasis: ["NullID could not validate the structure of this policy pack payload."],
        verifiedChecks: [],
        unverifiedChecks: ["No integrity or authenticity guarantees could be established."],
        warnings: [failure],
        packNames: [],
        failure,
    };
}
function policyPackErrorResult(descriptor, error, packNames, exportedAt) {
    const failure = error instanceof Error ? error.message : "Policy verification failed";
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
                packNames,
                failure,
            };
        }
        if (error.code === "verification-failed" || error.code === "integrity-count-mismatch" || error.code === "integrity-hash-mismatch") {
            return {
                ...descriptor,
                verificationState: "mismatch",
                verificationLabel: "Mismatch",
                trustBasis: ["Policy pack integrity metadata was present, but verification did not succeed."],
                verifiedChecks: [],
                unverifiedChecks: ["The payload may be tampered, incomplete, or paired with the wrong shared secret."],
                warnings: [failure],
                exportedAt,
                packNames,
                failure,
            };
        }
    }
    return {
        ...descriptor,
        verificationState: "invalid",
        verificationLabel: "Invalid",
        trustBasis: ["NullID could not validate the structure of this policy pack payload."],
        verifiedChecks: [],
        unverifiedChecks: ["No integrity or authenticity guarantees could be established."],
        warnings: [failure],
        exportedAt,
        packNames,
        failure,
    };
}
