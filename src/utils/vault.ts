import { getVaultBackend, getAllValues, getValue, putValue, clearStore } from "./storage.js";
import { fromBase64Url, toBase64Url, utf8ToBytes, bytesToUtf8, randomBytes } from "./encoding.js";
import { decryptText, encryptText } from "./cryptoEnvelope.js";

const AAD = utf8ToBytes("nullid:vault:v1");

export interface VaultMeta {
  salt: string;
  iterations: number;
  version?: number;
  lockedAt?: number;
}

export type VaultNote = {
  id: string;
  ciphertext: string;
  iv: string;
  updatedAt: number;
};

export async function ensureVaultMeta(): Promise<VaultMeta> {
  const backend = await getVaultBackend();
  const existing = await getValue<VaultMeta & { lockedAt: number }>(backend, "meta", "meta");
  if (existing) {
    const normalized: VaultMeta = {
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
  const meta: VaultMeta = { salt, iterations: 200_000, version: 1, lockedAt: Date.now() };
  await putValue(backend, "meta", "meta", meta);
  return meta;
}

export async function unlockVault(passphrase: string): Promise<CryptoKey> {
  const meta = await ensureVaultMeta();
  const key = await deriveVaultKey(passphrase, meta);
  const backend = await getVaultBackend();
  const canary = await getValue<{ ciphertext: string; iv: string }>(backend, "canary", "canary");
  if (canary) {
    await verifyCanary(key, canary.ciphertext, canary.iv);
  } else {
    await storeCanary(key);
  }
  return key;
}

async function deriveVaultKey(passphrase: string, meta: VaultMeta) {
  const salt = fromBase64Url(meta.salt);
  const keyMaterial = await crypto.subtle.importKey("raw", utf8ToBytes(passphrase).buffer as ArrayBuffer, "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt.buffer as ArrayBuffer, iterations: meta.iterations, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function storeCanary(key: CryptoKey) {
  const iv = randomBytes(12);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv.buffer as ArrayBuffer, additionalData: AAD.buffer as ArrayBuffer },
      key,
      utf8ToBytes("vault-canary").buffer as ArrayBuffer,
    ),
  );
  const backend = await getVaultBackend();
  await putValue(backend, "canary", "canary", { ciphertext: toBase64Url(ciphertext), iv: toBase64Url(iv) });
}

async function verifyCanary(key: CryptoKey, payload: string, ivText: string) {
  const ciphertext = fromBase64Url(payload);
  const iv = fromBase64Url(ivText);
  await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv.buffer as ArrayBuffer, additionalData: AAD.buffer as ArrayBuffer },
    key,
    ciphertext.buffer as ArrayBuffer,
  );
}

export async function loadNotes(): Promise<VaultNote[]> {
  const backend = await getVaultBackend();
  const all = await getAllValues<VaultNote>(backend, "notes");
  return all.sort((a, b) => b.updatedAt - a.updatedAt);
}

export async function saveNote(
  key: CryptoKey,
  id: string,
  title: string,
  body: string,
  metadata: { createdAt: number; tags: string[] },
) {
  const backend = await getVaultBackend();
  const iv = randomBytes(12);
  const now = Date.now();
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv.buffer as ArrayBuffer, additionalData: AAD.buffer as ArrayBuffer },
      key,
      utf8ToBytes(JSON.stringify({ title, body, tags: metadata.tags, createdAt: metadata.createdAt, updatedAt: now })).buffer as ArrayBuffer,
    ),
  );
  const note: VaultNote = {
    id,
    ciphertext: toBase64Url(ciphertext),
    iv: toBase64Url(iv),
    updatedAt: now,
  };
  await putValue(backend, "notes", id, note);
}

export async function deleteNote(id: string) {
  const backend = await getVaultBackend();
  if (backend.kind === "idb") {
    const db = backend.db;
    return new Promise<void>((resolve, reject) => {
      const tx = db.transaction("notes", "readwrite");
      tx.objectStore("notes").delete(id);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }
  localStorage.removeItem(`nullid:vault:notes:${id}`);
}

export async function decryptNote(
  key: CryptoKey,
  note: VaultNote,
): Promise<{ title: string; body: string; tags?: string[]; createdAt?: number; updatedAt?: number }> {
  const iv = fromBase64Url(note.iv);
  const ciphertext = fromBase64Url(note.ciphertext);
  const bytes = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv.buffer as ArrayBuffer, additionalData: AAD.buffer as ArrayBuffer },
      key,
      ciphertext.buffer as ArrayBuffer,
    ),
  );
  const parsed = JSON.parse(bytesToUtf8(bytes)) as { title: string; body: string; tags?: string[]; createdAt?: number; updatedAt?: number };
  return parsed;
}

export async function exportVault(): Promise<Blob> {
  const snapshot = await readVaultSnapshot();
  return new Blob([snapshot], { type: "application/json" });
}

async function readVaultSnapshot(): Promise<string> {
  const backend = await getVaultBackend();
  const notes = await getAllValues<VaultNote>(backend, "notes");
  const meta = await getValue(backend, "meta", "meta");
  const canary = await getValue(backend, "canary", "canary");
  const snapshot = { meta, notes, canary };
  return JSON.stringify(snapshot, null, 2);
}

export async function importVault(file: File) {
  const text = await file.text();
  const snapshot = JSON.parse(text) as { meta: VaultMeta; notes: VaultNote[]; canary: { ciphertext: string; iv: string } };
  await applySnapshot(snapshot);
}

export async function exportVaultEncrypted(passphrase: string): Promise<Blob> {
  const snapshot = await readVaultSnapshot();
  const envelope = await encryptText(passphrase, snapshot);
  return new Blob([envelope], { type: "text/plain" });
}

export async function importVaultEncrypted(file: File, passphrase: string) {
  const payload = await file.text();
  const snapshotJson = await decryptText(passphrase, payload);
  const snapshot = JSON.parse(snapshotJson) as { meta: VaultMeta; notes: VaultNote[]; canary: { ciphertext: string; iv: string } };
  await applySnapshot(snapshot);
}

async function applySnapshot(snapshot: { meta: VaultMeta; notes: VaultNote[]; canary: { ciphertext: string; iv: string } }) {
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
