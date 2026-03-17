import { createSnapshotIntegrity, verifySnapshotIntegrity } from "./snapshotIntegrity.js";
import { isVaultLocalStorageRecordKey } from "./vaultStorageKeys.js";
export const PROFILE_SCHEMA_VERSION = 2;
const LEGACY_PROFILE_SCHEMA_VERSION = 1;
const PREFIX = "nullid:";
export async function collectProfile(options) {
    const entries = {};
    for (let i = 0; i < localStorage.length; i += 1) {
        const key = localStorage.key(i);
        if (!key || !key.startsWith(PREFIX))
            continue;
        if (isVaultLocalStorageRecordKey(key))
            continue;
        const value = localStorage.getItem(key);
        try {
            entries[key] = value ? JSON.parse(value) : null;
        }
        catch {
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
    const snapshot = {
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
export async function downloadProfile(filename = "nullid-profile.json", options) {
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
export function describeProfilePayload(input) {
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
export async function importProfileFile(file, options) {
    const text = await file.text();
    const parsed = JSON.parse(text);
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
    const entries = parsed.entries;
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
function parseLegacyEntries(parsed) {
    if (!isPlainObject(parsed.entries)) {
        throw new Error("Invalid legacy profile payload");
    }
    const entries = parsed.entries;
    if (!Object.values(entries).every((value) => isSupportedValue(value))) {
        throw new Error("Legacy profile contains unsupported value types");
    }
    return entries;
}
function applyEntries(entries) {
    let applied = 0;
    Object.entries(entries).forEach(([key, value]) => {
        if (!key.startsWith(PREFIX))
            return;
        if (isVaultLocalStorageRecordKey(key))
            return;
        localStorage.setItem(key, JSON.stringify(value));
        applied += 1;
    });
    return applied;
}
function isPlainObject(value) {
    return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
function isSupportedValue(value) {
    if (value === null)
        return true;
    const t = typeof value;
    if (t === "string" || t === "number" || t === "boolean")
        return true;
    if (Array.isArray(value))
        return value.every(isSupportedValue);
    if (t === "object")
        return Object.values(value).every(isSupportedValue);
    return false;
}
