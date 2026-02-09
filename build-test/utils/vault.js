import { getVaultBackend, getAllValues, getValue, putValue, clearStore } from "./storage.js";
import { fromBase64Url, toBase64Url, utf8ToBytes, bytesToUtf8, randomBytes } from "./encoding.js";
import { decryptText, encryptText } from "./cryptoEnvelope.js";
const AAD = utf8ToBytes("nullid:vault:v1");
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
export async function exportVault() {
    const snapshot = await readVaultSnapshot();
    return new Blob([snapshot], { type: "application/json" });
}
async function readVaultSnapshot() {
    const backend = await getVaultBackend();
    const notes = await getAllValues(backend, "notes");
    const meta = await getValue(backend, "meta", "meta");
    const canary = await getValue(backend, "canary", "canary");
    const snapshot = { meta, notes, canary };
    return JSON.stringify(snapshot, null, 2);
}
export async function importVault(file) {
    const text = await file.text();
    const snapshot = JSON.parse(text);
    await applySnapshot(snapshot);
}
export async function exportVaultEncrypted(passphrase) {
    const snapshot = await readVaultSnapshot();
    const envelope = await encryptText(passphrase, snapshot);
    return new Blob([envelope], { type: "text/plain" });
}
export async function importVaultEncrypted(file, passphrase) {
    const payload = await file.text();
    const snapshotJson = await decryptText(passphrase, payload);
    const snapshot = JSON.parse(snapshotJson);
    await applySnapshot(snapshot);
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
