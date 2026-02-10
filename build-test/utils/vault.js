import { getVaultBackend, getAllValues, getValue, putValue, clearStore } from "./storage.js";
import { fromBase64Url, toBase64Url, utf8ToBytes, bytesToUtf8, randomBytes } from "./encoding.js";
import { decryptText, encryptText } from "./cryptoEnvelope.js";
import { sha256Base64Url, signHash, verifyHashSignature } from "./integrity.js";
const AAD = utf8ToBytes("nullid:vault:v1");
const VAULT_EXPORT_SCHEMA_VERSION = 2;
export async function ensureVaultMeta() {
    const backend = await getVaultBackend();
    const existing = await getValue(backend, "meta", "meta");
    if (existing) {
        const normalized = {
            salt: existing.salt,
            iterations: existing.iterations,
            version: existing.version ?? 1,
            lockedAt: existing.lockedAt ?? Date.now(),
        };
        if (!existing.version) {
            await putValue(backend, "meta", "meta", normalized);
        }
        return normalized;
    }
    const salt = toBase64Url(randomBytes(16));
    const meta = { salt, iterations: 200_000, version: 1, lockedAt: Date.now() };
    await putValue(backend, "meta", "meta", meta);
    return meta;
}
export async function unlockVault(passphrase) {
    const meta = await ensureVaultMeta();
    const key = await deriveVaultKey(passphrase, meta);
    const backend = await getVaultBackend();
    const canary = await getValue(backend, "canary", "canary");
    if (canary) {
        await verifyCanary(key, canary.ciphertext, canary.iv);
    }
    else {
        await storeCanary(key);
    }
    return key;
}
async function deriveVaultKey(passphrase, meta) {
    const salt = fromBase64Url(meta.salt);
    const keyMaterial = await crypto.subtle.importKey("raw", utf8ToBytes(passphrase).buffer, "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "PBKDF2", salt: salt.buffer, iterations: meta.iterations, hash: "SHA-256" }, keyMaterial, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function storeCanary(key) {
    const iv = randomBytes(12);
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv.buffer, additionalData: AAD.buffer }, key, utf8ToBytes("vault-canary").buffer));
    const backend = await getVaultBackend();
    await putValue(backend, "canary", "canary", { ciphertext: toBase64Url(ciphertext), iv: toBase64Url(iv) });
}
async function verifyCanary(key, payload, ivText) {
    const ciphertext = fromBase64Url(payload);
    const iv = fromBase64Url(ivText);
    await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv.buffer, additionalData: AAD.buffer }, key, ciphertext.buffer);
}
export async function loadNotes() {
    const backend = await getVaultBackend();
    const all = await getAllValues(backend, "notes");
    return all.sort((a, b) => b.updatedAt - a.updatedAt);
}
export async function saveNote(key, id, title, body, metadata) {
    const backend = await getVaultBackend();
    const iv = randomBytes(12);
    const now = Date.now();
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv.buffer, additionalData: AAD.buffer }, key, utf8ToBytes(JSON.stringify({ title, body, tags: metadata.tags, createdAt: metadata.createdAt, updatedAt: now })).buffer));
    const note = {
        id,
        ciphertext: toBase64Url(ciphertext),
        iv: toBase64Url(iv),
        updatedAt: now,
    };
    await putValue(backend, "notes", id, note);
}
export async function deleteNote(id) {
    const backend = await getVaultBackend();
    if (backend.kind === "idb") {
        const db = backend.db;
        return new Promise((resolve, reject) => {
            const tx = db.transaction("notes", "readwrite");
            tx.objectStore("notes").delete(id);
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        });
    }
    localStorage.removeItem(`nullid:vault:notes:${id}`);
}
export async function decryptNote(key, note) {
    const iv = fromBase64Url(note.iv);
    const ciphertext = fromBase64Url(note.ciphertext);
    const bytes = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv.buffer, additionalData: AAD.buffer }, key, ciphertext.buffer));
    const parsed = JSON.parse(bytesToUtf8(bytes));
    return parsed;
}
export async function exportVault(options) {
    const snapshot = await readVaultSnapshot(options);
    return new Blob([snapshot], { type: "application/json" });
}
async function readVaultSnapshot(options) {
    const snapshot = await buildVaultSnapshot(options);
    return JSON.stringify(snapshot, null, 2);
}
async function buildVaultSnapshot(options) {
    const vault = await readVaultSnapshotData();
    const exportedAt = new Date().toISOString();
    const payloadHash = await sha256Base64Url({
        schemaVersion: VAULT_EXPORT_SCHEMA_VERSION,
        exportedAt,
        vault,
    });
    const snapshot = {
        schemaVersion: VAULT_EXPORT_SCHEMA_VERSION,
        kind: "vault",
        exportedAt,
        vault,
        integrity: {
            noteCount: vault.notes.length,
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
async function readVaultSnapshotData() {
    const backend = await getVaultBackend();
    const notes = (await getAllValues(backend, "notes")).sort((a, b) => a.id.localeCompare(b.id));
    const meta = (await getValue(backend, "meta", "meta")) ?? null;
    const canary = (await getValue(backend, "canary", "canary")) ?? null;
    return { meta, notes, canary };
}
export async function importVault(file, options) {
    const text = await file.text();
    const parsed = JSON.parse(text);
    const resolved = await resolveImportedSnapshot(parsed, options);
    await applySnapshot(resolved.snapshot);
    return resolved.result;
}
export async function exportVaultEncrypted(passphrase, options) {
    const snapshot = await readVaultSnapshot(options);
    const envelope = await encryptText(passphrase, snapshot);
    return new Blob([envelope], { type: "text/plain" });
}
export async function importVaultEncrypted(file, passphrase, options) {
    const payload = await file.text();
    const snapshotJson = await decryptText(passphrase, payload);
    const snapshot = JSON.parse(snapshotJson);
    const resolved = await resolveImportedSnapshot(snapshot, options);
    await applySnapshot(resolved.snapshot);
    return resolved.result;
}
async function resolveImportedSnapshot(payload, options) {
    if (!isRecord(payload)) {
        throw new Error("Invalid vault snapshot payload");
    }
    if (payload.schemaVersion === VAULT_EXPORT_SCHEMA_VERSION) {
        const resolved = await validateSignedVaultSnapshot(payload, options);
        return {
            snapshot: resolved.snapshot,
            result: {
                noteCount: resolved.snapshot.notes.length,
                signed: resolved.signed,
                verified: resolved.verified,
                legacy: false,
            },
        };
    }
    const legacy = normalizeLegacySnapshot(payload);
    return {
        snapshot: legacy,
        result: {
            noteCount: legacy.notes.length,
            signed: false,
            verified: false,
            legacy: true,
        },
    };
}
async function validateSignedVaultSnapshot(payload, options) {
    if (payload.kind && payload.kind !== "vault") {
        throw new Error("Invalid vault snapshot kind");
    }
    if (typeof payload.exportedAt !== "string") {
        throw new Error("Invalid vault exportedAt metadata");
    }
    if (!isRecord(payload.vault) || !isRecord(payload.integrity)) {
        throw new Error("Vault integrity metadata missing");
    }
    const snapshot = normalizeSnapshotData(payload.vault);
    const noteCount = payload.integrity.noteCount;
    const payloadHash = payload.integrity.payloadHash;
    if (typeof noteCount !== "number" || !Number.isInteger(noteCount) || noteCount < 0 || typeof payloadHash !== "string" || payloadHash.length < 16) {
        throw new Error("Invalid vault integrity metadata");
    }
    if (snapshot.notes.length !== noteCount) {
        throw new Error("Vault integrity mismatch (note count)");
    }
    const computedHash = await sha256Base64Url({
        schemaVersion: VAULT_EXPORT_SCHEMA_VERSION,
        exportedAt: payload.exportedAt,
        vault: snapshot,
    });
    if (computedHash !== payloadHash) {
        throw new Error("Vault integrity mismatch (hash)");
    }
    let signed = false;
    let verified = false;
    if (payload.signature !== undefined) {
        if (!isRecord(payload.signature) || payload.signature.algorithm !== "HMAC-SHA-256" || typeof payload.signature.value !== "string") {
            throw new Error("Invalid vault signature metadata");
        }
        signed = true;
        const verifySecret = options?.verificationPassphrase;
        if (!verifySecret) {
            throw new Error("Vault snapshot is signed; verification passphrase required");
        }
        verified = await verifyHashSignature(payloadHash, payload.signature.value, verifySecret);
        if (!verified) {
            throw new Error("Vault signature verification failed");
        }
    }
    return { snapshot, signed, verified };
}
function normalizeLegacySnapshot(payload) {
    return normalizeSnapshotData(payload);
}
function normalizeSnapshotData(payload) {
    const notesRaw = Array.isArray(payload.notes) ? payload.notes : [];
    const notes = notesRaw.map((note, index) => normalizeNote(note, index));
    notes.sort((a, b) => a.id.localeCompare(b.id));
    const meta = payload.meta == null ? null : normalizeMeta(payload.meta);
    const canary = payload.canary == null ? null : normalizeCanary(payload.canary);
    return { meta, notes, canary };
}
function normalizeMeta(value) {
    if (!isRecord(value)) {
        throw new Error("Invalid vault meta payload");
    }
    const salt = value.salt;
    const iterations = value.iterations;
    const version = value.version;
    const lockedAt = value.lockedAt;
    if (typeof salt !== "string" || salt.length < 8) {
        throw new Error("Invalid vault meta salt");
    }
    if (typeof iterations !== "number" || !Number.isInteger(iterations) || iterations < 10_000) {
        throw new Error("Invalid vault meta iterations");
    }
    if (version !== undefined && version !== null && (typeof version !== "number" || !Number.isInteger(version) || version < 1)) {
        throw new Error("Invalid vault meta version");
    }
    if (lockedAt !== undefined && lockedAt !== null && (typeof lockedAt !== "number" || !Number.isFinite(lockedAt) || lockedAt <= 0)) {
        throw new Error("Invalid vault meta lockedAt");
    }
    return {
        salt,
        iterations,
        version: typeof version === "number" ? version : undefined,
        lockedAt: typeof lockedAt === "number" ? lockedAt : undefined,
    };
}
function normalizeCanary(value) {
    if (!isRecord(value) || typeof value.ciphertext !== "string" || typeof value.iv !== "string") {
        throw new Error("Invalid vault canary payload");
    }
    return {
        ciphertext: value.ciphertext,
        iv: value.iv,
    };
}
function normalizeNote(value, index) {
    if (!isRecord(value)) {
        throw new Error(`Invalid vault note at index ${index}`);
    }
    const id = value.id;
    const ciphertext = value.ciphertext;
    const iv = value.iv;
    const updatedAt = value.updatedAt;
    if (typeof id !== "string" || !id.trim()) {
        throw new Error(`Invalid vault note id at index ${index}`);
    }
    if (typeof ciphertext !== "string" || ciphertext.length < 8) {
        throw new Error(`Invalid vault note ciphertext at index ${index}`);
    }
    if (typeof iv !== "string" || iv.length < 8) {
        throw new Error(`Invalid vault note iv at index ${index}`);
    }
    if (typeof updatedAt !== "number" || !Number.isFinite(updatedAt) || updatedAt <= 0) {
        throw new Error(`Invalid vault note timestamp at index ${index}`);
    }
    return {
        id,
        ciphertext,
        iv,
        updatedAt: Number(updatedAt),
    };
}
function isRecord(value) {
    return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
async function applySnapshot(snapshot) {
    const backend = await getVaultBackend();
    await clearStore(backend, "meta");
    await clearStore(backend, "notes");
    await clearStore(backend, "canary");
    if (snapshot.meta) {
        await putValue(backend, "meta", "meta", { ...snapshot.meta, lockedAt: Date.now() });
    }
    if (snapshot.canary) {
        await putValue(backend, "canary", "canary", snapshot.canary);
    }
    if (snapshot.notes?.length) {
        await Promise.all(snapshot.notes.map((note) => putValue(backend, "notes", note.id, note)));
    }
}
