import { isVaultLocalStorageRecordKey } from "./vaultStorageKeys.js";

const DB_NAME = "nullid-vault";
const DB_VERSION = 2;
const FALLBACK_BACKEND: VaultBackend = { kind: "ls" };
const VAULT_DATA_STORES = ["meta", "notes", "canary"] as const;
const VAULT_WIPE_STORES = ["notes", "meta", "canary", "selftest"] as const;
const FALLBACK_ACTIVE_GENERATION_KEY = "nullid:vault:data:active-generation";
const FALLBACK_GENERATION_PREFIX = "nullid:vault:data:gen:";
const FALLBACK_GENERATION_STATE_STORE = "state";
const FALLBACK_GENERATION_STATE_KEY = "state";
const FALLBACK_DATA_PREFIX = "nullid:vault:data:";
const OBSOLETE_FALLBACK_DATA_PREFIX = "nullid:vault:";
const MAX_FALLBACK_VAULT_STRING = 4096;
const MAX_FALLBACK_VAULT_NOTES = 10_000;
const MIN_FALLBACK_VAULT_ITERATIONS = 100_000;
const MAX_FALLBACK_VAULT_ITERATIONS = 5_000_000;

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
let vaultStorageLogger: Pick<Console, "warn"> = console;

class VaultStorageError extends Error {
  constructor(
    readonly code: "unavailable" | "blocked" | "transient" | "version" | "corruption",
    message: string,
  ) {
    super(message);
    this.name = "VaultStorageError";
  }
}

export interface VaultStoreReplacement {
  meta: StructuredCloneValue | null;
  canary: StructuredCloneValue | null;
  notes: Array<{ id: string; value: StructuredCloneValue }>;
}

export function setVaultStorageLogger(logger: Pick<Console, "warn"> | null) {
  vaultStorageLogger = logger ?? console;
}

export function resetVaultStorageForTests() {
  cachedBackend = null;
  backendInit = null;
  fallbackReason = null;
}

function recordFallback(reason: string) {
  fallbackReason = reason;
  cachedBackend = FALLBACK_BACKEND;
}

function assertIndexedDbAvailable() {
  if (typeof indexedDB === "undefined" || typeof indexedDB.open !== "function") {
    throw new VaultStorageError("unavailable", "IndexedDB unavailable");
  }
}

async function openVaultDb(): Promise<IDBDatabase> {
  assertIndexedDbAvailable();
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    let settled = false;
    let blockedTimer: ReturnType<typeof setTimeout> | null = null;
    const finish = (error?: unknown, db?: IDBDatabase) => {
      if (settled) {
        if (db) db.close();
        return;
      }
      settled = true;
      if (blockedTimer) clearTimeout(blockedTimer);
      if (error) {
        reject(normalizeIndexedDbOpenError(error));
      } else if (db) {
        resolve(db);
      } else {
        reject(new Error("IndexedDB open failed"));
      }
    };
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains("meta")) db.createObjectStore("meta");
      if (!db.objectStoreNames.contains("notes")) db.createObjectStore("notes");
      if (!db.objectStoreNames.contains("canary")) db.createObjectStore("canary");
      if (!db.objectStoreNames.contains("selftest")) db.createObjectStore("selftest");
    };
    request.onblocked = () => {
      blockedTimer = setTimeout(
        () => finish(new VaultStorageError("blocked", "IndexedDB open blocked by another NullID tab or stale database connection.")),
        50,
      );
    };
    request.onerror = () => finish(request.error ?? new VaultStorageError("transient", "IndexedDB open failed"));
    request.onsuccess = () => {
      const db = request.result;
      db.onversionchange = () => {
        invalidateCachedBackend(db);
        db.close();
      };
      (db as IDBDatabase & { onclose?: (() => void) | null }).onclose = () => invalidateCachedBackend(db);
      finish(undefined, db);
    };
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
      if (isIndexedDbUnavailable(error)) {
        const message = error instanceof Error ? error.message : String(error);
        recordFallback(message || "IndexedDB unavailable");
        vaultStorageLogger.warn("Vault: falling back to localStorage backend", error);
        cachedBackend = FALLBACK_BACKEND;
        return cachedBackend;
      }
      cachedBackend = null;
      fallbackReason = error instanceof Error ? error.message : String(error);
      throw error instanceof Error ? error : new Error(String(error || "IndexedDB initialization failed"));
    } finally {
      backendInit = null;
    }
  })();
  return backendInit;
}

export async function wipeVault() {
  const backend = await getVaultBackend();
  if (backend.kind === "ls") {
    replaceFallbackVaultStores({ meta: null, canary: null, notes: [] });
    cleanupAllFallbackVaultData();
    await assertStoresEmpty(backend, [...VAULT_WIPE_STORES]);
    return;
  }
  await clearStoresAtomically(backend, [...VAULT_WIPE_STORES]);
  await assertStoresEmpty(backend, [...VAULT_WIPE_STORES]);
}

export function getVaultBackendInfo() {
  return { kind: cachedBackend?.kind ?? "unknown", fallbackReason };
}

export async function clearStore(backend: VaultBackend, name: string) {
  if (backend.kind === "idb") {
    const db = backend.db;
    return new Promise<void>((resolve, reject) => {
      let tx: IDBTransaction;
      try {
        tx = db.transaction(name, "readwrite");
        tx.objectStore(name).clear();
      } catch (error) {
        reject(error);
        return;
      }
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error ?? new Error("IDB clear failed"));
      tx.onabort = () => reject(tx.error ?? new Error("IDB clear aborted"));
    });
  }

  // localStorage backend
  replaceFallbackVaultStores(buildFallbackReplacementWithClearedStore(name));
}

export async function replaceVaultStores(backend: VaultBackend, replacement: VaultStoreReplacement) {
  if (backend.kind === "idb") {
    const db = backend.db;
    return new Promise<void>((resolve, reject) => {
      let tx: IDBTransaction | null = null;
      const fail = (error: unknown) => reject(error instanceof Error ? error : new Error(String(error || "IDB vault replacement failed")));
      try {
        tx = db.transaction([...VAULT_DATA_STORES], "readwrite");
        const meta = tx.objectStore("meta");
        const notes = tx.objectStore("notes");
        const canary = tx.objectStore("canary");
        meta.clear();
        notes.clear();
        canary.clear();
        if (replacement.meta) meta.put(replacement.meta, "meta");
        if (replacement.canary) canary.put(replacement.canary, "canary");
        replacement.notes.forEach((note) => notes.put(note.value, note.id));
      } catch (error) {
        try {
          tx?.abort();
        } catch {
          // Transaction may already be inactive.
        }
        fail(error);
        return;
      }
      tx.oncomplete = () => resolve();
      tx.onerror = () => fail(tx?.error ?? new Error("IDB vault replacement failed"));
      tx.onabort = () => fail(tx?.error ?? new Error("IDB vault replacement aborted"));
    });
  }

  replaceFallbackVaultStores(replacement);
}

export async function putValue<T>(backend: VaultBackend, store: string, key: IDBValidKey, value: T) {
  if (backend.kind === "idb") {
    const db = backend.db;
    return new Promise<void>((resolve, reject) => {
      let tx: IDBTransaction;
      try {
        tx = db.transaction(store, "readwrite");
        tx.objectStore(store).put(value as StructuredCloneValue, key);
      } catch (error) {
        reject(error);
        return;
      }
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error ?? new Error("IDB put failed"));
      tx.onabort = () => reject(tx.error ?? new Error("IDB put aborted"));
    });
  }
  try {
    replaceFallbackVaultStores(buildFallbackReplacementWithValue(store, key, value as StructuredCloneValue));
  } catch (error) {
    recordFallback(error instanceof Error ? error.message : "localStorage blocked");
    throw error;
  }
}

export async function removeValue(backend: VaultBackend, store: string, key: IDBValidKey) {
  if (backend.kind === "idb") {
    const db = backend.db;
    return new Promise<void>((resolve, reject) => {
      let tx: IDBTransaction;
      try {
        tx = db.transaction(store, "readwrite");
        tx.objectStore(store).delete(key);
      } catch (error) {
        reject(error);
        return;
      }
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error ?? new Error("IDB delete failed"));
      tx.onabort = () => reject(tx.error ?? new Error("IDB delete aborted"));
    });
  }

  replaceFallbackVaultStores(buildFallbackReplacementWithoutValue(store, key));
}

export async function getValue<T>(backend: VaultBackend, store: string, key: IDBValidKey): Promise<T | undefined> {
  if (backend.kind === "idb") {
    const db = backend.db;
    return new Promise((resolve, reject) => {
      let tx: IDBTransaction;
      try {
        tx = db.transaction(store, "readonly");
        const req = tx.objectStore(store).get(key);
        req.onsuccess = () => {
          try {
            const value = req.result as T | undefined;
            if (value !== undefined) assertRecordMatchesStorageKey(store, String(key), value);
            resolve(value);
          } catch (error) {
            reject(error);
          }
        };
        req.onerror = () => reject(req.error ?? new Error("IDB get failed"));
      } catch (error) {
        reject(error);
        return;
      }
      tx.onabort = () => reject(tx.error ?? new Error("IDB get aborted"));
    });
  }
  const activeGeneration = getActiveFallbackGeneration();
  if (activeGeneration) {
    const storageKey = fallbackGenerationStorageKey(activeGeneration, store, key);
    const raw = localStorage.getItem(storageKey);
    if (!raw) return undefined;
    const value = parseFallbackRecord<T>(storageKey, raw);
    if (value !== undefined) assertRecordMatchesStorageKey(store, String(key), value);
    return value;
  }
  return undefined;
}

export async function getAllValues<T>(backend: VaultBackend, store: string): Promise<T[]> {
  if (backend.kind === "idb") {
    const db = backend.db;
    return new Promise<T[]>((resolve, reject) => {
      let tx: IDBTransaction;
      const values: T[] = [];
      let settled = false;
      const fail = (error: unknown) => {
        if (settled) return;
        settled = true;
        try {
          tx.abort();
        } catch {
          // Transaction may already have completed.
        }
        reject(error instanceof Error ? error : new Error(String(error || "IDB getAll failed")));
      };
      try {
        tx = db.transaction(store, "readonly");
        const req = tx.objectStore(store).openCursor();
        req.onsuccess = () => {
          try {
            const cursor = req.result;
            if (!cursor) {
              if (!settled) {
                settled = true;
                resolve(values);
              }
              return;
            }
            const recordKey = String(cursor.key);
            const value = cursor.value as T;
            assertRecordMatchesStorageKey(store, recordKey, value);
            values.push(value);
            cursor.continue();
          } catch (error) {
            fail(error);
          }
        };
        req.onerror = () => fail(req.error ?? new Error("IDB getAll failed"));
      } catch (error) {
        reject(error);
        return;
      }
      tx.oncomplete = () => {
        // The cursor success handler resolves when it reaches null so record-key
        // validation cannot be bypassed by an early transaction completion signal.
      };
      tx.onerror = () => fail(tx.error ?? new Error("IDB getAll failed"));
      tx.onabort = () => fail(tx.error ?? new Error("IDB getAll aborted"));
    });
  }

  const activeGeneration = getActiveFallbackGeneration();
  if (activeGeneration) {
    const prefix = fallbackGenerationStorePrefix(activeGeneration, store);
    return localStorageKeysWithPrefix(prefix).reduce<T[]>((values, key) => {
      const raw = localStorage.getItem(key);
      if (!raw) return values;
      const value = parseFallbackRecord<T>(key, raw);
      if (value !== undefined) {
        assertRecordMatchesStorageKey(store, key.slice(prefix.length), value);
        values.push(value);
      }
      return values;
    }, []);
  }
  return [];
}

type StructuredCloneValue =
  | null
  | string
  | number
  | boolean
  | Date
  | ArrayBuffer
  | Uint8Array
  | StructuredCloneValue[]
  | { [key: string]: StructuredCloneValue };

type FallbackGenerationState = {
  schemaVersion: number;
  kind: "nullid-vault-fallback-generation";
  state: "active" | "wiped";
  noteCount?: number;
  createdAt?: number;
};

type FallbackGenerationValidation =
  | { ok: true; generation: string; state: FallbackGenerationState }
  | { ok: false; generation: string; reason: string };

function readFallbackRecord<T>(key: string, raw: string): { ok: true; value: T } | { ok: false } {
  try {
    return { ok: true, value: JSON.parse(raw) as T };
  } catch (error) {
    vaultStorageLogger.warn(`Vault: skipping corrupt fallback record ${key}`, error);
    return { ok: false };
  }
}

function parseFallbackRecord<T>(key: string, raw: string): T | undefined {
  const parsed = readFallbackRecord<T>(key, raw);
  return parsed.ok ? parsed.value : undefined;
}

function assertRecordMatchesStorageKey(store: string, recordKey: string, value: unknown) {
  if (store !== "notes") return;
  if (!isPlainFallbackObject(value) || value.id !== recordKey) {
    throw new VaultStorageError("corruption", `Vault note id does not match storage key: ${recordKey}`);
  }
}

function invalidateCachedBackend(db: IDBDatabase) {
  if (cachedBackend?.kind === "idb" && cachedBackend.db === db) {
    cachedBackend = null;
  }
}

function normalizeIndexedDbOpenError(error: unknown): Error {
  if (error instanceof VaultStorageError) return error;
  if (error instanceof Error) {
    if (error.name === "VersionError") {
      return new VaultStorageError("version", error.message || "IndexedDB version error");
    }
    if (error.name === "AbortError") {
      return new VaultStorageError("transient", error.message || "IndexedDB open aborted");
    }
    if (error.name === "UnknownError" || error.name === "InvalidStateError") {
      return new VaultStorageError("corruption", error.message || "IndexedDB open failed");
    }
    return new VaultStorageError("transient", error.message || "IndexedDB open failed");
  }
  return new VaultStorageError("transient", String(error || "IndexedDB open failed"));
}

function isIndexedDbUnavailable(error: unknown) {
  return error instanceof VaultStorageError && error.code === "unavailable";
}

function clearStoresAtomically(backend: VaultBackend, stores: string[]) {
  if (backend.kind === "idb") {
    const db = backend.db;
    return new Promise<void>((resolve, reject) => {
      let tx: IDBTransaction | null = null;
      const fail = (error: unknown) => reject(error instanceof Error ? error : new Error(String(error || "IDB clear failed")));
      try {
        tx = db.transaction(stores, "readwrite");
        stores.forEach((store) => tx?.objectStore(store).clear());
      } catch (error) {
        try {
          tx?.abort();
        } catch {
          // Transaction may already be inactive.
        }
        fail(error);
        return;
      }
      tx.oncomplete = () => resolve();
      tx.onerror = () => fail(tx?.error ?? new Error("IDB clear failed"));
      tx.onabort = () => fail(tx?.error ?? new Error("IDB clear aborted"));
    });
  }

  const keysToRemove = collectFallbackKeys(stores);
  keysToRemove.forEach((key) => localStorage.removeItem(key));
  if (VAULT_DATA_STORES.every((store) => stores.includes(store))) {
    localStorage.removeItem(FALLBACK_ACTIVE_GENERATION_KEY);
  }
  return Promise.resolve();
}

async function assertStoresEmpty(backend: VaultBackend, stores: string[]) {
  for (const store of stores) {
    const values = await getAllValues<unknown>(backend, store);
    if (values.length > 0) {
      throw new Error(`Vault wipe failed to clear ${store}`);
    }
  }
}

function replaceFallbackVaultStores(replacement: VaultStoreReplacement) {
  const previousGeneration = recoverFallbackGenerations();
  const nextGeneration = createFallbackGenerationId();
  const stagedRecords = buildFallbackReplacementRecords(replacement, nextGeneration);

  let committed = false;
  try {
    stagedRecords.forEach(([key, value]) => localStorage.setItem(key, value));
    stagedRecords.forEach(([key, value]) => {
      if (localStorage.getItem(key) !== value) {
        throw new Error("localStorage vault staging verification failed");
      }
    });

    localStorage.setItem(FALLBACK_ACTIVE_GENERATION_KEY, nextGeneration);
    if (localStorage.getItem(FALLBACK_ACTIVE_GENERATION_KEY) !== nextGeneration) {
      throw new Error("localStorage vault active generation commit verification failed");
    }
    verifyActiveFallbackGeneration(stagedRecords);
    committed = true;
  } catch (error) {
    if (!committed) {
      restoreFallbackGenerationPointer(previousGeneration);
      cleanupFallbackGeneration(nextGeneration);
    }
    throw error;
  }

  cleanupFallbackGeneration(previousGeneration);
  cleanupFallbackStoreKeys([...VAULT_DATA_STORES]);
}

function buildFallbackReplacementWithValue(store: string, key: IDBValidKey, value: StructuredCloneValue): VaultStoreReplacement {
  const replacement = readCurrentFallbackReplacement();
  if (store === "meta" && String(key) === "meta") {
    replacement.meta = value;
  } else if (store === "canary" && String(key) === "canary") {
    replacement.canary = value;
  } else if (store === "notes") {
    const noteId = String(key);
    replacement.notes = replacement.notes.filter((note) => note.id !== noteId);
    replacement.notes.push({ id: noteId, value });
  }
  return replacement;
}

function buildFallbackReplacementWithoutValue(store: string, key: IDBValidKey): VaultStoreReplacement {
  const replacement = readCurrentFallbackReplacement();
  if (store === "meta" && String(key) === "meta") {
    replacement.meta = null;
  } else if (store === "canary" && String(key) === "canary") {
    replacement.canary = null;
  } else if (store === "notes") {
    const noteId = String(key);
    replacement.notes = replacement.notes.filter((note) => note.id !== noteId);
  }
  return replacement;
}

function buildFallbackReplacementWithClearedStore(store: string): VaultStoreReplacement {
  const replacement = readCurrentFallbackReplacement();
  if (store === "meta") {
    replacement.meta = null;
  } else if (store === "canary") {
    replacement.canary = null;
  } else if (store === "notes") {
    replacement.notes = [];
  }
  return replacement;
}

function readCurrentFallbackReplacement(): VaultStoreReplacement {
  const generation = getActiveFallbackGeneration();
  if (!generation) {
    return { meta: null, canary: null, notes: [] };
  }
  const meta = readFallbackJsonRecord(fallbackGenerationStorageKey(generation, "meta", "meta"));
  const canary = readFallbackJsonRecord(fallbackGenerationStorageKey(generation, "canary", "canary"));
  const notePrefix = fallbackGenerationStorePrefix(generation, "notes");
  const notes = localStorageKeysWithPrefix(notePrefix).map((recordKey) => {
    const record = readFallbackJsonRecord(recordKey);
    if (!record.ok) {
      throw new VaultStorageError("corruption", `Vault fallback active generation contains an invalid note record: ${recordKey}`);
    }
    return {
      id: recordKey.slice(notePrefix.length),
      value: record.value as StructuredCloneValue,
    };
  });
  return {
    meta: meta.ok ? meta.value as StructuredCloneValue : null,
    canary: canary.ok ? canary.value as StructuredCloneValue : null,
    notes,
  };
}

function buildFallbackReplacementRecords(replacement: VaultStoreReplacement, generation: string): Array<[string, string]> {
  const generationState = replacement.meta || replacement.canary || replacement.notes.length > 0 ? "active" : "wiped";
  const records: Array<[string, string]> = [
    [
      fallbackGenerationStorageKey(generation, FALLBACK_GENERATION_STATE_STORE, FALLBACK_GENERATION_STATE_KEY),
      JSON.stringify({
        schemaVersion: 2,
        kind: "nullid-vault-fallback-generation",
        state: generationState,
        noteCount: replacement.notes.length,
        createdAt: Date.now(),
      }),
    ],
  ];
  if (replacement.meta) {
    records.push([fallbackGenerationStorageKey(generation, "meta", "meta"), JSON.stringify(replacement.meta)]);
  }
  if (replacement.canary) {
    records.push([fallbackGenerationStorageKey(generation, "canary", "canary"), JSON.stringify(replacement.canary)]);
  }
  replacement.notes.forEach((note) => {
    records.push([fallbackGenerationStorageKey(generation, "notes", note.id), JSON.stringify(note.value)]);
  });
  return records;
}

function collectFallbackKeys(stores: string[]): string[] {
  const prefixes = stores.flatMap((store) => [
    `${FALLBACK_DATA_PREFIX}${store}:`,
    `${OBSOLETE_FALLBACK_DATA_PREFIX}${store}:`,
  ]);
  const keys: string[] = [];
  for (let i = 0; i < localStorage.length; i += 1) {
    const key = localStorage.key(i);
    if (
      key
      && (
        prefixes.some((prefix) => key.startsWith(prefix))
        || stores.some((store) => isFallbackGenerationStoreKey(key, store))
      )
    ) {
      keys.push(key);
    }
  }
  return keys;
}

function localStorageKeysWithPrefix(prefix: string): string[] {
  const keys: string[] = [];
  for (let i = 0; i < localStorage.length; i += 1) {
    const key = localStorage.key(i);
    if (key?.startsWith(prefix)) {
      keys.push(key);
    }
  }
  return keys;
}

function getActiveFallbackGeneration(): string | null {
  const value = localStorage.getItem(FALLBACK_ACTIVE_GENERATION_KEY);
  if (value === null) {
    return recoverMissingFallbackGenerationPointer();
  }
  if (!isSafeFallbackGenerationId(value)) {
    return recoverMalformedFallbackGenerationPointer(value);
  }
  const validation = validateFallbackGeneration(value);
  if (!validation.ok) {
    throw new VaultStorageError("corruption", `Vault fallback active generation ${value} failed integrity validation: ${validation.reason}`);
  }
  return value;
}

function createFallbackGenerationId(): string {
  const random = typeof crypto !== "undefined" && typeof crypto.randomUUID === "function"
    ? crypto.randomUUID().replace(/-/g, "")
    : `${Date.now().toString(36)}${Math.random().toString(36).slice(2)}`;
  return `g${random}`;
}

function isSafeFallbackGenerationId(value: unknown): value is string {
  return typeof value === "string" && /^g[a-zA-Z0-9]+$/u.test(value);
}

function fallbackGenerationStorePrefix(generation: string, store: string): string {
  return `${FALLBACK_GENERATION_PREFIX}${generation}:${store}:`;
}

function fallbackGenerationStorageKey(generation: string, store: string, key: IDBValidKey): string {
  return `${fallbackGenerationStorePrefix(generation, store)}${String(key)}`;
}

function isFallbackGenerationStoreKey(key: string, store: string): boolean {
  return key.startsWith(FALLBACK_GENERATION_PREFIX) && key.includes(`:${store}:`);
}

function verifyActiveFallbackGeneration(expectedRecords: Array<[string, string]>) {
  expectedRecords.forEach(([key, value]) => {
    if (localStorage.getItem(key) !== value) {
      throw new Error("localStorage vault active generation verification failed");
    }
  });
}

function recoverFallbackGenerations(): string | null {
  const activeGeneration = getActiveFallbackGeneration();
  collectFallbackGenerationIds()
    .filter((generation) => generation !== activeGeneration)
    .forEach((generation) => cleanupFallbackGeneration(generation));
  return activeGeneration;
}

function restoreFallbackGenerationPointer(previousGeneration: string | null) {
  try {
    if (previousGeneration) {
      localStorage.setItem(FALLBACK_ACTIVE_GENERATION_KEY, previousGeneration);
    } else {
      localStorage.removeItem(FALLBACK_ACTIVE_GENERATION_KEY);
    }
  } catch {
    // If pointer restoration is blocked, the original failure remains authoritative.
  }
}

function collectFallbackGenerationIds(): string[] {
  const generations = new Set<string>();
  for (let i = 0; i < localStorage.length; i += 1) {
    const key = localStorage.key(i);
    if (!key?.startsWith(FALLBACK_GENERATION_PREFIX)) continue;
    const rest = key.slice(FALLBACK_GENERATION_PREFIX.length);
    const delimiterIndex = rest.indexOf(":");
    if (delimiterIndex <= 0) continue;
    const generation = rest.slice(0, delimiterIndex);
    if (isSafeFallbackGenerationId(generation)) generations.add(generation);
  }
  return Array.from(generations);
}

function recoverMissingFallbackGenerationPointer(): string | null {
  const generations = collectFallbackGenerationIds();
  if (generations.length === 0) {
    return null;
  }
  throw new VaultStorageError("corruption", "Vault fallback active generation pointer is missing");
}

function recoverMalformedFallbackGenerationPointer(value: string): string {
  throw new VaultStorageError("corruption", `Vault fallback active generation pointer is malformed: ${value}`);
}

function validateFallbackGeneration(generation: string): FallbackGenerationValidation {
  const generationPrefix = `${FALLBACK_GENERATION_PREFIX}${generation}:`;
  const keys = localStorageKeysWithPrefix(generationPrefix);
  if (!isSafeFallbackGenerationId(generation)) return { ok: false, generation, reason: "invalid generation id" };
  if (keys.length === 0) return { ok: false, generation, reason: "missing generation records" };

  const stateResult = readFallbackGenerationState(generation);
  if (!stateResult.ok) return { ok: false, generation, reason: stateResult.reason };
  const state = stateResult.state;

  const metaKey = fallbackGenerationStorageKey(generation, "meta", "meta");
  const canaryKey = fallbackGenerationStorageKey(generation, "canary", "canary");
  const noteKeys = localStorageKeysWithPrefix(fallbackGenerationStorePrefix(generation, "notes"));

  if (state.state === "wiped") {
    if (localStorage.getItem(metaKey) !== null || localStorage.getItem(canaryKey) !== null || noteKeys.length > 0) {
      return { ok: false, generation, reason: "wiped generation contains vault records" };
    }
    return { ok: true, generation, state };
  }

  if (noteKeys.length > MAX_FALLBACK_VAULT_NOTES) return { ok: false, generation, reason: "generation note count exceeds limit" };
  if (typeof state.noteCount === "number" && state.noteCount !== noteKeys.length) {
    return { ok: false, generation, reason: "generation note count does not match note records" };
  }

  const meta = readFallbackJsonRecord(metaKey);
  if (!meta.ok || !isValidFallbackVaultMeta(meta.value)) return { ok: false, generation, reason: "invalid vault metadata" };
  const canary = readFallbackJsonRecord(canaryKey);
  if (canary.ok && !isValidFallbackVaultCanary(canary.value)) return { ok: false, generation, reason: "invalid vault canary" };
  if (noteKeys.length > 0 && !canary.ok) return { ok: false, generation, reason: "invalid vault canary" };

  for (const key of noteKeys) {
    const note = readFallbackJsonRecord(key);
    if (!note.ok || !isValidFallbackVaultNote(note.value)) {
      return { ok: false, generation, reason: `invalid vault note record: ${key}` };
    }
    const recordId = key.slice(fallbackGenerationStorePrefix(generation, "notes").length);
    if ((note.value as { id: string }).id !== recordId) {
      return { ok: false, generation, reason: `vault note id does not match storage key: ${recordId}` };
    }
  }

  return { ok: true, generation, state };
}

function readFallbackGenerationState(generation: string): { ok: true; state: FallbackGenerationState } | { ok: false; reason: string } {
  const key = fallbackGenerationStorageKey(generation, FALLBACK_GENERATION_STATE_STORE, FALLBACK_GENERATION_STATE_KEY);
  const parsed = readFallbackJsonRecord(key);
  if (!parsed.ok) return { ok: false, reason: "invalid generation state" };
  const value = parsed.value;
  if (!isPlainFallbackObject(value)) return { ok: false, reason: "invalid generation state" };
  if (value.schemaVersion !== 2) return { ok: false, reason: "unsupported generation state schema" };
  if (value.kind !== "nullid-vault-fallback-generation") return { ok: false, reason: "invalid generation state kind" };
  if (value.state !== "active" && value.state !== "wiped") return { ok: false, reason: "invalid generation state value" };
  if (value.noteCount !== undefined && !isBoundedInteger(value.noteCount, 0, MAX_FALLBACK_VAULT_NOTES)) {
    return { ok: false, reason: "invalid generation note count" };
  }
  if (value.createdAt !== undefined && !isBoundedTimestamp(value.createdAt)) {
    return { ok: false, reason: "invalid generation timestamp" };
  }
  return {
    ok: true,
    state: {
      schemaVersion: value.schemaVersion,
      kind: "nullid-vault-fallback-generation",
      state: value.state,
      noteCount: typeof value.noteCount === "number" ? value.noteCount : undefined,
      createdAt: typeof value.createdAt === "number" ? value.createdAt : undefined,
    },
  };
}

function readFallbackJsonRecord(key: string): { ok: true; value: unknown } | { ok: false } {
  const raw = localStorage.getItem(key);
  if (!raw) return { ok: false };
  try {
    return { ok: true, value: JSON.parse(raw) as unknown };
  } catch {
    return { ok: false };
  }
}

function isValidFallbackVaultMeta(value: unknown): boolean {
  if (!isPlainFallbackObject(value)) return false;
  if (typeof value.salt !== "string" || !isBoundedString(value.salt, 1, MAX_FALLBACK_VAULT_STRING)) return false;
  if (!isBoundedInteger(value.iterations, MIN_FALLBACK_VAULT_ITERATIONS, MAX_FALLBACK_VAULT_ITERATIONS)) return false;
  if (value.version !== undefined && !isBoundedInteger(value.version, 1, 100)) return false;
  if (value.lockedAt !== undefined && !isBoundedTimestamp(value.lockedAt)) return false;
  return true;
}

function isValidFallbackVaultCanary(value: unknown): boolean {
  if (!isPlainFallbackObject(value)) return false;
  return isBoundedString(value.ciphertext, 1, MAX_FALLBACK_VAULT_STRING) && isBoundedString(value.iv, 1, MAX_FALLBACK_VAULT_STRING);
}

function isValidFallbackVaultNote(value: unknown): value is { id: string } {
  if (!isPlainFallbackObject(value)) return false;
  if (!isBoundedString(value.id, 1, 256) || value.id.includes("\0")) return false;
  if (!isBoundedString(value.ciphertext, 1, MAX_FALLBACK_VAULT_STRING)) return false;
  if (!isBoundedString(value.iv, 1, MAX_FALLBACK_VAULT_STRING)) return false;
  if (value.version !== 3) return false;
  if (!isBoundedTimestamp(value.createdAt)) return false;
  if (!isBoundedTimestamp(value.updatedAt)) return false;
  return true;
}

function isPlainFallbackObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isBoundedString(value: unknown, min: number, max: number): value is string {
  return typeof value === "string" && value.length >= min && value.length <= max;
}

function isBoundedInteger(value: unknown, min: number, max: number): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= min && value <= max;
}

function isBoundedTimestamp(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 8_640_000_000_000_000;
}

function cleanupFallbackGeneration(generation: string | null) {
  if (!generation) return;
  localStorageKeysWithPrefix(`${FALLBACK_GENERATION_PREFIX}${generation}:`).forEach((key) => {
    try {
      localStorage.removeItem(key);
    } catch {
      vaultStorageLogger.warn(`Vault: could not clean stale fallback generation ${generation}`);
    }
  });
}

function cleanupFallbackStoreKeys(stores: string[]) {
  collectFallbackKeys(stores)
    .filter((key) => !key.startsWith(FALLBACK_GENERATION_PREFIX) && key !== FALLBACK_ACTIVE_GENERATION_KEY)
    .forEach((key) => {
      try {
        localStorage.removeItem(key);
      } catch {
        vaultStorageLogger.warn(`Vault: could not clean legacy fallback record ${key}`);
      }
    });
}

function cleanupAllFallbackVaultData() {
  const keys: string[] = [];
  for (let i = 0; i < localStorage.length; i += 1) {
    const key = localStorage.key(i);
    if (key && isVaultLocalStorageRecordKey(key)) {
      keys.push(key);
    }
  }
  keys.forEach((key) => localStorage.removeItem(key));
}
