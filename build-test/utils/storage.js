const DB_NAME = "nullid-vault";
const DB_VERSION = 2;
const LS_PREFIX = "nullid:vault:";
const FALLBACK_BACKEND = { kind: "ls" };
let cachedBackend = null;
let backendInit = null;
let fallbackReason = null;
function lsKey(store, key) {
    return `${LS_PREFIX}${store}:${String(key)}`;
}
function recordFallback(reason) {
    fallbackReason = reason;
    cachedBackend = FALLBACK_BACKEND;
}
function assertIndexedDbAvailable() {
    if (typeof indexedDB === "undefined") {
        throw new Error("IndexedDB unavailable");
    }
}
async function openVaultDb() {
    assertIndexedDbAvailable();
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, DB_VERSION);
        request.onupgradeneeded = () => {
            const db = request.result;
            if (!db.objectStoreNames.contains("meta"))
                db.createObjectStore("meta");
            if (!db.objectStoreNames.contains("notes"))
                db.createObjectStore("notes");
            if (!db.objectStoreNames.contains("canary"))
                db.createObjectStore("canary");
            if (!db.objectStoreNames.contains("selftest"))
                db.createObjectStore("selftest");
        };
        request.onerror = () => reject(request.error ?? new Error("IndexedDB open failed"));
        request.onsuccess = () => resolve(request.result);
    });
}
export async function getVaultBackend() {
    if (cachedBackend)
        return cachedBackend;
    if (backendInit)
        return backendInit;
    backendInit = (async () => {
        try {
            const db = await openVaultDb();
            cachedBackend = { kind: "idb", db };
            fallbackReason = null;
            return cachedBackend;
        }
        catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            recordFallback(message || "IndexedDB unavailable");
            console.warn("Vault: falling back to localStorage backend", error);
            cachedBackend = FALLBACK_BACKEND;
            return cachedBackend;
        }
        finally {
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
export async function clearStore(backend, name) {
    if (backend.kind === "idb") {
        const db = backend.db;
        try {
            return await new Promise((resolve, reject) => {
                const tx = db.transaction(name, "readwrite");
                tx.objectStore(name).clear();
                tx.oncomplete = () => resolve();
                tx.onerror = () => reject(tx.error);
            });
        }
        catch (error) {
            console.warn("Vault: IDB clear failed, falling back to localStorage", error);
            recordFallback(error instanceof Error ? error.message : "IDB clear failed");
        }
    }
    // localStorage backend
    const prefix = `${LS_PREFIX}${name}:`;
    const keysToRemove = [];
    for (let i = 0; i < localStorage.length; i += 1) {
        const key = localStorage.key(i);
        if (key && key.startsWith(prefix))
            keysToRemove.push(key);
    }
    keysToRemove.forEach((key) => localStorage.removeItem(key));
}
export async function putValue(backend, store, key, value) {
    if (backend.kind === "idb") {
        const db = backend.db;
        try {
            return await new Promise((resolve, reject) => {
                const tx = db.transaction(store, "readwrite");
                tx.objectStore(store).put(value, key);
                tx.oncomplete = () => resolve();
                tx.onerror = () => reject(tx.error);
            });
        }
        catch (error) {
            console.warn("Vault: IDB put failed, falling back to localStorage", error);
            recordFallback(error instanceof Error ? error.message : "IDB put failed");
        }
    }
    try {
        localStorage.setItem(lsKey(store, key), JSON.stringify(value));
    }
    catch (error) {
        recordFallback(error instanceof Error ? error.message : "localStorage blocked");
        throw error;
    }
}
export async function getValue(backend, store, key) {
    if (backend.kind === "idb") {
        const db = backend.db;
        try {
            return await new Promise((resolve, reject) => {
                const tx = db.transaction(store, "readonly");
                const req = tx.objectStore(store).get(key);
                req.onsuccess = () => resolve(req.result);
                req.onerror = () => reject(req.error);
            });
        }
        catch (error) {
            console.warn("Vault: IDB get failed, falling back to localStorage", error);
            recordFallback(error instanceof Error ? error.message : "IDB get failed");
        }
    }
    const raw = localStorage.getItem(lsKey(store, key));
    if (!raw)
        return undefined;
    return JSON.parse(raw);
}
export async function getAllValues(backend, store) {
    if (backend.kind === "idb") {
        const db = backend.db;
        try {
            return await new Promise((resolve, reject) => {
                const tx = db.transaction(store, "readonly");
                const req = tx.objectStore(store).getAll();
                req.onsuccess = () => resolve(req.result);
                req.onerror = () => reject(req.error);
            });
        }
        catch (error) {
            console.warn("Vault: IDB getAll failed, falling back to localStorage", error);
            recordFallback(error instanceof Error ? error.message : "IDB getAll failed");
        }
    }
    const prefix = `${LS_PREFIX}${store}:`;
    const out = [];
    for (let i = 0; i < localStorage.length; i += 1) {
        const k = localStorage.key(i);
        if (!k || !k.startsWith(prefix))
            continue;
        const raw = localStorage.getItem(k);
        if (!raw)
            continue;
        out.push(JSON.parse(raw));
    }
    return out;
}
