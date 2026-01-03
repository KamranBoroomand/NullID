const DB_NAME = "nullid-vault";
const DB_VERSION = 2;
const LS_PREFIX = "nullid:vault:";
const FALLBACK_BACKEND: VaultBackend = { kind: "ls" };

// In some environments (notably iOS Safari private mode), IndexedDB can be
// unavailable or throw on open. Provide a deterministic localStorage fallback
// so Secure Notes continues to function. The selected backend is cached to avoid
// thrashing between IDB and localStorage after a failure/quota rejection.

export type VaultBackend =
  | { kind: "idb"; db: IDBDatabase }
  | { kind: "ls" };

let cachedBackend: VaultBackend | null = null;
let backendInit: Promise<VaultBackend> | null = null;
let fallbackReason: string | null = null;

function lsKey(store: string, key: IDBValidKey) {
  return `${LS_PREFIX}${store}:${String(key)}`;
}

function recordFallback(reason: string) {
  fallbackReason = reason;
  cachedBackend = FALLBACK_BACKEND;
}

function assertIndexedDbAvailable() {
  if (typeof indexedDB === "undefined") {
    throw new Error("IndexedDB unavailable");
  }
}

async function openVaultDb(): Promise<IDBDatabase> {
  assertIndexedDbAvailable();
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains("meta")) db.createObjectStore("meta");
      if (!db.objectStoreNames.contains("notes")) db.createObjectStore("notes");
      if (!db.objectStoreNames.contains("canary")) db.createObjectStore("canary");
      if (!db.objectStoreNames.contains("selftest")) db.createObjectStore("selftest");
    };
    request.onerror = () => reject(request.error ?? new Error("IndexedDB open failed"));
    request.onsuccess = () => resolve(request.result);
  });
}

export async function getVaultBackend(): Promise<VaultBackend> {
  if (cachedBackend) return cachedBackend;
  if (backendInit) return backendInit;
  backendInit = (async () => {
    try {
      const db = await openVaultDb();
      cachedBackend = { kind: "idb", db };
      fallbackReason = null;
      return cachedBackend;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      recordFallback(message || "IndexedDB unavailable");
      console.warn("Vault: falling back to localStorage backend", error);
      cachedBackend = FALLBACK_BACKEND;
      return cachedBackend;
    } finally {
      backendInit = null;
    }
  })();
  return backendInit;
}

export async function wipeVault() {
  const backend = await getVaultBackend();
  await Promise.all([clearStore(backend, "notes"), clearStore(backend, "meta"), clearStore(backend, "canary"), clearStore(backend, "selftest")]);
}

export function getVaultBackendInfo() {
  return { kind: cachedBackend?.kind ?? "unknown", fallbackReason };
}

export async function clearStore(backend: VaultBackend, name: string) {
  if (backend.kind === "idb") {
    const db = backend.db;
    try {
      return await new Promise<void>((resolve, reject) => {
        const tx = db.transaction(name, "readwrite");
        tx.objectStore(name).clear();
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      });
    } catch (error) {
      console.warn("Vault: IDB clear failed, falling back to localStorage", error);
      recordFallback(error instanceof Error ? error.message : "IDB clear failed");
    }
  }

  // localStorage backend
  const prefix = `${LS_PREFIX}${name}:`;
  const keysToRemove: string[] = [];
  for (let i = 0; i < localStorage.length; i += 1) {
    const key = localStorage.key(i);
    if (key && key.startsWith(prefix)) keysToRemove.push(key);
  }
  keysToRemove.forEach((key) => localStorage.removeItem(key));
}

export async function putValue<T>(backend: VaultBackend, store: string, key: IDBValidKey, value: T) {
  if (backend.kind === "idb") {
    const db = backend.db;
    try {
      return await new Promise<void>((resolve, reject) => {
        const tx = db.transaction(store, "readwrite");
        tx.objectStore(store).put(value as any, key);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      });
    } catch (error) {
      console.warn("Vault: IDB put failed, falling back to localStorage", error);
      recordFallback(error instanceof Error ? error.message : "IDB put failed");
    }
  }
  try {
    localStorage.setItem(lsKey(store, key), JSON.stringify(value));
  } catch (error) {
    recordFallback(error instanceof Error ? error.message : "localStorage blocked");
    throw error;
  }
}

export async function getValue<T>(backend: VaultBackend, store: string, key: IDBValidKey): Promise<T | undefined> {
  if (backend.kind === "idb") {
    const db = backend.db;
    try {
      return await new Promise((resolve, reject) => {
        const tx = db.transaction(store, "readonly");
        const req = tx.objectStore(store).get(key);
        req.onsuccess = () => resolve(req.result as T | undefined);
        req.onerror = () => reject(req.error);
      });
    } catch (error) {
      console.warn("Vault: IDB get failed, falling back to localStorage", error);
      recordFallback(error instanceof Error ? error.message : "IDB get failed");
    }
  }
  const raw = localStorage.getItem(lsKey(store, key));
  if (!raw) return undefined;
  return JSON.parse(raw) as T;
}

export async function getAllValues<T>(backend: VaultBackend, store: string): Promise<T[]> {
  if (backend.kind === "idb") {
    const db = backend.db;
    try {
      return await new Promise((resolve, reject) => {
        const tx = db.transaction(store, "readonly");
        const req = tx.objectStore(store).getAll();
        req.onsuccess = () => resolve(req.result as T[]);
        req.onerror = () => reject(req.error);
      });
    } catch (error) {
      console.warn("Vault: IDB getAll failed, falling back to localStorage", error);
      recordFallback(error instanceof Error ? error.message : "IDB getAll failed");
    }
  }

  const prefix = `${LS_PREFIX}${store}:`;
  const out: T[] = [];
  for (let i = 0; i < localStorage.length; i += 1) {
    const k = localStorage.key(i);
    if (!k || !k.startsWith(prefix)) continue;
    const raw = localStorage.getItem(k);
    if (!raw) continue;
    out.push(JSON.parse(raw) as T);
  }
  return out;
}
