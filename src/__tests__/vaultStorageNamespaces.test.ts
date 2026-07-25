import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readPersistentStateValue, writePersistentStateValue } from "../hooks/usePersistentState.js";
import { collectProfile } from "../utils/profile.js";
import {
  clearStore,
  getAllValues,
  getValue,
  getVaultBackend,
  getVaultBackendInfo,
  putValue,
  replaceVaultStores,
  resetVaultStorageForTests,
  setVaultStorageLogger,
  wipeVault,
  type VaultBackend,
  type VaultStoreReplacement,
} from "../utils/storage.js";
import {
  VAULT_PREFERENCE_STATE_KEYS,
  isVaultLocalStorageRecordKey,
  vaultFallbackStorageKey,
} from "../utils/vaultStorageKeys.js";

class MemoryStorage implements Storage {
  private map = new Map<string, string>();
  failOnRemoveKey: string | null = null;
  failOnSetKey: string | null = null;

  get length() {
    return this.map.size;
  }

  clear() {
    this.map.clear();
  }

  getItem(key: string) {
    return this.map.has(key) ? this.map.get(key)! : null;
  }

  key(index: number) {
    return Array.from(this.map.keys())[index] ?? null;
  }

  removeItem(key: string) {
    if (this.failOnRemoveKey === key) {
      this.failOnRemoveKey = null;
      throw new Error(`injected removeItem failure for ${key}`);
    }
    this.map.delete(key);
  }

  setItem(key: string, value: string) {
    if (this.failOnSetKey === key) {
      this.failOnSetKey = null;
      throw new Error(`injected setItem failure for ${key}`);
    }
    this.map.set(key, value);
  }

  snapshot() {
    return Array.from(this.map.entries()).sort(([left], [right]) => left.localeCompare(right));
  }
}

const FALLBACK_ACTIVE_GENERATION_KEY = "nullid:vault:data:active-generation";
const FALLBACK_GENERATION_PREFIX = "nullid:vault:data:gen:";

describe("vault storage namespaces", () => {
  const fallbackBackend: VaultBackend = { kind: "ls" };

  const setup = () => {
    const storage = new MemoryStorage();
    Object.defineProperty(globalThis, "localStorage", { value: storage, configurable: true, writable: true });
    Object.defineProperty(globalThis, "indexedDB", { value: undefined, configurable: true, writable: true });
    resetVaultStorageForTests();
    setVaultStorageLogger({ warn() {} });
    return storage;
  };

  it("migrates vault preferences into the pref namespace", () => {
    const storage = setup();
    storage.setItem("nullid:vault:unlock-rate-limit", JSON.stringify(false));

    const value = readPersistentStateValue(storage, VAULT_PREFERENCE_STATE_KEYS.unlockRateLimitEnabled, true);
    assert.equal(value, false);
    assert.equal(storage.getItem(VAULT_PREFERENCE_STATE_KEYS.unlockRateLimitEnabled.key), JSON.stringify(false));
    assert.equal(storage.getItem("nullid:vault:unlock-rate-limit"), null);

    writePersistentStateValue(storage, VAULT_PREFERENCE_STATE_KEYS.unlockRateLimitEnabled, true);
    assert.equal(storage.getItem(VAULT_PREFERENCE_STATE_KEYS.unlockRateLimitEnabled.key), JSON.stringify(true));
  });

  it("ignores obsolete fallback blobs instead of migrating them into the data namespace", async () => {
    const storage = setup();
    const legacyNoteKey = legacyVaultFallbackStorageKey("notes", "note-1");
    storage.setItem(legacyNoteKey, JSON.stringify(createNoteRecord("note-1")));
    storage.setItem(legacyVaultFallbackStorageKey("meta", "meta"), JSON.stringify({ salt: "salt", iterations: 200_000 }));

    const notes = await getAllValues<{ id: string }>(fallbackBackend, "notes");
    const meta = await getValue<{ salt: string }>(fallbackBackend, "meta", "meta");

    assert.deepEqual(notes, []);
    assert.equal(meta, undefined);
    assert.equal(storage.getItem(vaultFallbackStorageKey("notes", "note-1")), null);
    assert.notEqual(storage.getItem(legacyNoteKey), null);
  });

  it("ignores old fallback-key-only vault records instead of surfacing or migrating them", async () => {
    const storage = setup();
    const oldNoteKey = "nullid:vault:notes:legacy-note";
    const oldMetaKey = "nullid:vault:meta:meta";
    storage.setItem(oldNoteKey, JSON.stringify(createNoteRecord("legacy-note", "OLD")));
    storage.setItem(oldMetaKey, JSON.stringify(createMetaRecord("old-meta")));

    assert.deepEqual(await getAllValues<{ id: string }>(fallbackBackend, "notes"), []);
    assert.equal(await getValue(fallbackBackend, "meta", "meta"), undefined);
    assert.equal(storage.getItem(oldNoteKey) !== null, true);
    assert.equal(storage.getItem(oldMetaKey) !== null, true);
    assert.equal(storage.getItem(vaultFallbackStorageKey("notes", "legacy-note")), null);
  });

  it("does not let old fallback records override the active generation or get cleaned up on read", async () => {
    const storage = setup();
    await replaceVaultStores(fallbackBackend, createReplacement());
    const oldNoteKey = "nullid:vault:notes:new-note";
    storage.setItem(oldNoteKey, JSON.stringify(createNoteRecord("new-note", "OLD")));
    const before = storage.snapshot();

    assert.deepEqual(await getAllValues(fallbackBackend, "notes"), [createNoteRecord("new-note", "NEW")]);
    assert.deepEqual(await getValue(fallbackBackend, "notes", "new-note"), createNoteRecord("new-note", "NEW"));
    assert.deepEqual(storage.snapshot(), before);
  });

  it("fails closed when the current active-generation pointer is missing instead of recovering abandoned generations", async () => {
    const storage = setup();
    await replaceVaultStores(fallbackBackend, createReplacement());
    const before = storage.snapshot();
    storage.removeItem(FALLBACK_ACTIVE_GENERATION_KEY);

    await expectRejects(() => getAllValues<{ id: string }>(fallbackBackend, "notes"), /active generation|pointer|integrity|corrupt/i);
    assert.equal(storage.getItem(FALLBACK_ACTIVE_GENERATION_KEY), null);
    assert.deepEqual(
      storage.snapshot().filter(([key]) => key !== FALLBACK_ACTIVE_GENERATION_KEY),
      before.filter(([key]) => key !== FALLBACK_ACTIVE_GENERATION_KEY),
    );
  });

  it("removes current and obsolete NullID vault data on wipe without interpreting old layouts", async () => {
    const storage = setup();
    await replaceVaultStores(fallbackBackend, createReplacement());
    storage.setItem("nullid:vault:notes:old-note", JSON.stringify(createNoteRecord("old-note", "OLD")));
    storage.setItem("nullid:vault:data:notes:old-note", JSON.stringify(createNoteRecord("old-note", "OLD")));
    storage.setItem("nullid:vault:selftest:selftest", JSON.stringify({ ok: true }));
    storage.setItem(VAULT_PREFERENCE_STATE_KEYS.unlockRateLimitEnabled.key, JSON.stringify(true));

    await wipeVault();

    assert.equal(storage.snapshot().some(([key]) => isVaultLocalStorageRecordKey(key)), false);
    assert.equal(storage.getItem(VAULT_PREFERENCE_STATE_KEYS.unlockRateLimitEnabled.key), JSON.stringify(true));
  });

  it("does not migrate obsolete fallback notes when current namespace writes are blocked", async () => {
    const storage = setup();
    const legacyNoteKey = legacyVaultFallbackStorageKey("notes", "note-1");
    const primaryNoteKey = vaultFallbackStorageKey("notes", "note-1");
    const note = createNoteRecord("note-1");
    storage.setItem(legacyNoteKey, JSON.stringify(note));
    storage.failOnSetKey = primaryNoteKey;

    const notes = await getAllValues<{ id: string }>(fallbackBackend, "notes");

    assert.deepEqual(notes, []);
    assert.equal(storage.getItem(primaryNoteKey), null);
    assert.notEqual(storage.getItem(legacyNoteKey), null);
  });

  it("ignores plain fallback records even when both old namespaces are present", async () => {
    const storage = setup();
    const primaryKey = vaultFallbackStorageKey("meta", "meta");
    const legacyKey = legacyVaultFallbackStorageKey("meta", "meta");
    storage.setItem(primaryKey, "{not-json");
    storage.setItem(legacyKey, JSON.stringify(createMetaRecord("legacy-meta")));

    const meta = await getValue(fallbackBackend, "meta", "meta");

    assert.equal(meta, undefined);
    assert.equal(storage.getItem(primaryKey), "{not-json");
    assert.notEqual(storage.getItem(legacyKey), null);
  });

  it("ignores conflicting obsolete fallback values without deleting evidence", async () => {
    const storage = setup();
    const primaryKey = vaultFallbackStorageKey("meta", "meta");
    const legacyKey = legacyVaultFallbackStorageKey("meta", "meta");
    const primaryMeta = createMetaRecord("primary-meta");
    const legacyMeta = createMetaRecord("legacy-meta");
    storage.setItem(primaryKey, JSON.stringify(primaryMeta));
    storage.setItem(legacyKey, JSON.stringify(legacyMeta));

    assert.equal(await getValue(fallbackBackend, "meta", "meta"), undefined);

    assert.equal(storage.getItem(primaryKey), JSON.stringify(primaryMeta));
    assert.equal(storage.getItem(legacyKey), JSON.stringify(legacyMeta));
  });

  it("keeps profile snapshots scoped to preferences and excludes fallback vault data in both namespaces", async () => {
    const storage = setup();
    storage.setItem("nullid:theme", JSON.stringify("dark"));
    storage.setItem(VAULT_PREFERENCE_STATE_KEYS.unlockRateLimitEnabled.key, JSON.stringify(true));
    storage.setItem(vaultFallbackStorageKey("notes", "note-1"), JSON.stringify({ ciphertext: "secret", iv: "iv" }));
    storage.setItem(legacyVaultFallbackStorageKey("canary", "canary"), JSON.stringify({ ciphertext: "secret", iv: "iv" }));

    const snapshot = await collectProfile();

    assert.equal(snapshot.entries["nullid:theme"], "dark");
    assert.equal(snapshot.entries[VAULT_PREFERENCE_STATE_KEYS.unlockRateLimitEnabled.key], true);
    assert.equal(vaultFallbackStorageKey("notes", "note-1") in snapshot.entries, false);
    assert.equal(legacyVaultFallbackStorageKey("canary", "canary") in snapshot.entries, false);
  });

  it("distinguishes fallback data keys from vault preference keys", () => {
    assert.equal(isVaultLocalStorageRecordKey(VAULT_PREFERENCE_STATE_KEYS.unlockRateLimitEnabled.key), false);
    assert.equal(isVaultLocalStorageRecordKey(FALLBACK_ACTIVE_GENERATION_KEY), true);
    assert.equal(isVaultLocalStorageRecordKey(fallbackGenerationStorageKeyForTest("gtest", "state", "state")), true);
    assert.equal(isVaultLocalStorageRecordKey(vaultFallbackStorageKey("notes", "note-1")), true);
    assert.equal(isVaultLocalStorageRecordKey(legacyVaultFallbackStorageKey("notes", "note-1")), true);
  });

  it("ignores corrupt plain fallback records without treating old layouts as active data", async () => {
    const storage = setup();
    storage.setItem(vaultFallbackStorageKey("notes", "bad"), "{not-json");
    storage.setItem(vaultFallbackStorageKey("notes", "good"), JSON.stringify(createNoteRecord("good")));
    storage.setItem(vaultFallbackStorageKey("meta", "meta"), "{not-json");

    const notes = await getAllValues<{ id: string }>(fallbackBackend, "notes");
    const meta = await getValue<{ salt: string }>(fallbackBackend, "meta", "meta");

    assert.deepEqual(notes, []);
    assert.equal(meta, undefined);
  });

  it("preserves the old fallback generation byte-for-byte when wipe pointer commit fails", async () => {
    const storage = setup();
    await replaceVaultStores(fallbackBackend, createReplacement());
    const before = storage.snapshot();
    storage.failOnSetKey = FALLBACK_ACTIVE_GENERATION_KEY;

    await expectRejects(() => wipeVault(), /injected setItem failure/i);

    assert.deepEqual(storage.snapshot(), before);
  });

  it("still removes all fallback vault data when stale-generation cleanup has a transient failure", async () => {
    const storage = setup();
    await replaceVaultStores(fallbackBackend, createReplacement());
    const oldMetaKey = storage.snapshot().find(([key]) => key.includes(":meta:"))?.[0];
    assert.ok(oldMetaKey, "seeded fallback generation contains a meta record");
    storage.failOnRemoveKey = oldMetaKey;

    await wipeVault();

    assert.equal(storage.getItem(oldMetaKey), null);
    assert.equal(storage.snapshot().some(([key]) => isVaultLocalStorageRecordKey(key)), false);
  });

  it("fails closed when the active fallback generation pointer is malformed", async () => {
    const storage = setup();
    storage.setItem(FALLBACK_ACTIVE_GENERATION_KEY, JSON.stringify("not-a-generation-id"));
    storage.setItem(legacyVaultFallbackStorageKey("notes", "legacy-note"), JSON.stringify(createNoteRecord("legacy-note", "OLD")));

    await expectRejects(() => getAllValues<{ id: string }>(fallbackBackend, "notes"), /generation pointer|storage integrity/i);

    assert.equal(storage.getItem(legacyVaultFallbackStorageKey("notes", "legacy-note")) !== null, true);
  });

  it("fails closed when the active fallback generation points to missing or incomplete data", async () => {
    const cases = [
      { label: "missing generation", records: [] },
      { label: "incomplete generation", records: [[fallbackGenerationStorageKeyForTest("gbroken", "notes", "note-1"), JSON.stringify({ id: "note-1" })]] },
    ] as const;

    for (const testCase of cases) {
      const storage = setup();
      storage.setItem(FALLBACK_ACTIVE_GENERATION_KEY, "gbroken");
      testCase.records.forEach(([key, value]) => storage.setItem(key, value));

      await expectRejects(() => getAllValues<{ id: string }>(fallbackBackend, "notes"), /generation|storage integrity/i);
      assert.equal(storage.getItem(FALLBACK_ACTIVE_GENERATION_KEY), "gbroken", testCase.label);
    }
  });

  it("rejects exactly one complete abandoned fallback generation instead of recovering it", async () => {
    const storage = setup();
    seedGeneration(storage, "grecover", { noteIds: ["note-1"] });

    await expectRejects(() => getAllValues<{ id: string }>(fallbackBackend, "notes"), /active generation pointer is missing|generation/i);

    assert.equal(storage.getItem(FALLBACK_ACTIVE_GENERATION_KEY), null);
  });

  it("rejects ambiguous complete abandoned fallback generations", async () => {
    const storage = setup();
    for (const generation of ["ga", "gb"]) {
      seedGeneration(storage, generation, { noteIds: [] });
    }

    await expectRejects(() => getAllValues<{ id: string }>(fallbackBackend, "notes"), /ambiguous|generation|storage integrity/i);
    assert.equal(storage.getItem(FALLBACK_ACTIVE_GENERATION_KEY), null);
  });

  it("fails closed instead of rolling back to stale legacy vault data after pointer loss", async () => {
    const storage = setup();
    const staleLegacyKey = legacyVaultFallbackStorageKey("notes", "old-note");
    storage.setItem(staleLegacyKey, JSON.stringify(createNoteRecord("old-note", "OLD")));
    storage.failOnRemoveKey = staleLegacyKey;

    await replaceVaultStores(fallbackBackend, createReplacement());
    assert.deepEqual(await getAllValues(fallbackBackend, "notes"), [createNoteRecord("new-note", "NEW")]);
    assert.equal(storage.getItem(staleLegacyKey) !== null, true, "cleanup failure leaves stale legacy evidence");

    storage.removeItem(FALLBACK_ACTIVE_GENERATION_KEY);

    await expectRejects(() => getAllValues(fallbackBackend, "notes"), /legacy|conflict|integrity|generation/i);
    assert.equal(storage.getItem(staleLegacyKey) !== null, true, "stale evidence is preserved for recovery UI");
    assert.equal(storage.snapshot().some(([key]) => key.startsWith(FALLBACK_GENERATION_PREFIX)), true, "generation evidence remains");
  });

  it("does not auto-select or delete a generation with corrupt metadata", async () => {
    const storage = setup();
    seedGeneration(storage, "gcorrupt", { noteIds: ["note-1"] });
    const corruptMetaKey = fallbackGenerationStorageKeyForTest("gcorrupt", "meta", "meta");
    storage.setItem(corruptMetaKey, "{not-json");

    await expectRejects(() => getAllValues(fallbackBackend, "notes"), /corrupt|integrity|generation/i);

    assert.equal(storage.getItem(corruptMetaKey), "{not-json");
    assert.equal(storage.getItem(FALLBACK_ACTIVE_GENERATION_KEY), null);
  });

  it("rejects abandoned generation recovery even after obsolete data is removed", async () => {
    const storage = setup();
    seedGeneration(storage, "grecover", { noteIds: ["note-1"] });
    storage.setItem(legacyVaultFallbackStorageKey("notes", "legacy-note"), JSON.stringify(createNoteRecord("legacy-note", "OLD")));

    await expectRejects(() => getAllValues(fallbackBackend, "notes"), /legacy|conflict|integrity|generation/i);

    storage.removeItem(legacyVaultFallbackStorageKey("notes", "legacy-note"));
    await expectRejects(() => getAllValues(fallbackBackend, "notes"), /active generation pointer is missing|generation/i);
    assert.equal(storage.getItem(FALLBACK_ACTIVE_GENERATION_KEY), null);
  });

  it("rejects recovery when a valid abandoned generation coexists with a corrupt generation", async () => {
    const storage = setup();
    seedGeneration(storage, "gvalid", { noteIds: ["note-1"] });
    storage.setItem(
      fallbackGenerationStorageKeyForTest("gbad", "state", "state"),
      JSON.stringify({ schemaVersion: 1, kind: "nullid-vault-fallback-generation", state: "active" }),
    );
    storage.setItem(fallbackGenerationStorageKeyForTest("gbad", "meta", "meta"), "{not-json");

    await expectRejects(() => getAllValues(fallbackBackend, "notes"), /corrupt|integrity|generation/i);

    assert.equal(storage.getItem(FALLBACK_ACTIVE_GENERATION_KEY), null);
    assert.equal(storage.getItem(fallbackGenerationStorageKeyForTest("gbad", "meta", "meta")), "{not-json");
  });

  it("rejects note records whose storage key does not match the note id", async () => {
    const storage = setup();
    seedGeneration(storage, "gmismatch", { noteIds: ["stored-note"] });
    storage.setItem(fallbackGenerationStorageKeyForTest("gmismatch", "notes", "stored-note"), JSON.stringify(createNoteRecord("other-note")));
    storage.setItem(FALLBACK_ACTIVE_GENERATION_KEY, "gmismatch");

    await expectRejects(() => getAllValues(fallbackBackend, "notes"), /note id|integrity|generation/i);

    assert.equal(storage.getItem(fallbackGenerationStorageKeyForTest("gmismatch", "notes", "stored-note")) !== null, true);
  });

  it("ignores plain fallback note records whose storage key does not match the note id", async () => {
    const storage = setup();
    const physicalKey = vaultFallbackStorageKey("notes", "stored-note");
    storage.setItem(physicalKey, JSON.stringify(createNoteRecord("other-note")));

    assert.deepEqual(await getAllValues(fallbackBackend, "notes"), []);

    assert.equal(storage.getItem(physicalKey) !== null, true);
  });

  it("rejects IndexedDB note records whose physical key does not match the note id", async () => {
    setup();
    const fake = createFakeVaultDb();
    fake.stores.notes.set("stored-note", createNoteRecord("other-note"));

    await expectRejects(() => getAllValues({ kind: "idb", db: fake.db }, "notes"), /note id|storage key|integrity/i);

    assert.deepEqual(snapshotStore(fake.stores.notes), [["stored-note", createNoteRecord("other-note")]]);
  });

  it("does not silently switch to localStorage after a transient IndexedDB write failure", async () => {
    const storage = setup();
    const failingBackend = createFailingIdbBackend("transient write failure");

    await expectRejects(() => putValue(failingBackend, "notes", "note-1", { id: "note-1" }), /transient write failure/);

    assert.equal(storage.getItem(vaultFallbackStorageKey("notes", "note-1")), null);
  });

  it("does not claim an IndexedDB clear succeeded by clearing only localStorage", async () => {
    const storage = setup();
    storage.setItem(vaultFallbackStorageKey("notes", "note-1"), JSON.stringify({ id: "note-1" }));
    const failingBackend = createFailingIdbBackend("clear failed");

    await expectRejects(() => clearStore(failingBackend, "notes"), /clear failed/);

    assert.equal(storage.getItem(vaultFallbackStorageKey("notes", "note-1")) !== null, true);
  });

  it("falls back to localStorage only when IndexedDB is unavailable", async () => {
    setup();

    const backend = await getVaultBackend();

    assert.equal(backend.kind, "ls");
    assert.equal(getVaultBackendInfo().kind, "ls");
    assert.match(getVaultBackendInfo().fallbackReason ?? "", /unavailable/i);
  });

  it("fails closed instead of switching storage when IndexedDB open is blocked", async () => {
    const storage = setup();
    installFakeIndexedDb(() => {
      const request = createOpenRequest();
      queueMicrotask(() => request.onblocked?.call(request, {} as IDBVersionChangeEvent));
      return request;
    });

    await expectRejects(() => getVaultBackend(), /blocked/i);

    assert.equal(getVaultBackendInfo().kind, "unknown");
    assert.match(getVaultBackendInfo().fallbackReason ?? "", /blocked/i);
    assert.equal(storage.getItem(vaultFallbackStorageKey("notes", "note-1")), null);
  });

  it("clears failed IndexedDB initialization so a later open can retry", async () => {
    setup();
    let attempts = 0;
    installFakeIndexedDb(() => {
      attempts += 1;
      const request = createOpenRequest();
      if (attempts === 1) {
        queueMicrotask(() => {
          request.error = new DOMException("temporary abort", "AbortError");
          request.onerror?.call(request, {} as Event);
        });
      } else {
        const fake = createFakeVaultDb();
        queueMicrotask(() => {
          request.result = fake.db;
          request.onsuccess?.call(request, {} as Event);
        });
      }
      return request;
    });

    await expectRejects(() => getVaultBackend(), /temporary abort/i);
    const backend = await getVaultBackend();

    assert.equal(backend.kind, "idb");
    assert.equal(attempts, 2);
  });

  it("invalidates a version-changed IndexedDB backend and reopens on the next access", async () => {
    setup();
    const opened: FakeVaultDb[] = [];
    installFakeIndexedDb(() => {
      const request = createOpenRequest();
      const fake = createFakeVaultDb();
      opened.push(fake);
      queueMicrotask(() => {
        request.result = fake.db;
        request.onsuccess?.call(request, {} as Event);
      });
      return request;
    });

    const first = await getVaultBackend();
    assert.equal(first.kind, "idb");
    first.db.onversionchange?.call(first.db, {} as IDBVersionChangeEvent);
    const second = await getVaultBackend();

    assert.equal(second.kind, "idb");
    assert.notEqual(second.db, first.db);
    assert.equal(opened.length, 2);
    assert.equal(opened[0].closed, true);
  });

  it("keeps old IndexedDB vault stores intact when replacement transactions fail", async () => {
    const cases: Array<[string, FakeVaultDbFailure]> = [
      ["clear", { failClearStore: "notes" }],
      ["metadata write", { failPutStore: "meta" }],
      ["note write", { failPutStore: "notes" }],
      ["canary write", { failPutStore: "canary" }],
      ["transaction abort", { abortAfterOperations: true }],
    ];

    for (const [label, failure] of cases) {
      setup();
      const fake = createFakeVaultDb(createSeedStores(), failure);
      const backend: VaultBackend = { kind: "idb", db: fake.db };

      await expectRejects(() => replaceVaultStores(backend, createReplacement()), /failed|abort|injected/i);

      assert.deepEqual(snapshotFakeStores(fake), snapshotFakeStores(createFakeVaultDb(createSeedStores())), label);
    }
  });

  it("empties every IndexedDB vault store only after a successful wipe", async () => {
    setup();
    const fake = createFakeVaultDb(createSeedStores());
    installFakeIndexedDb(() => {
      const request = createOpenRequest();
      queueMicrotask(() => {
        request.result = fake.db;
        request.onsuccess?.call(request, {} as Event);
      });
      return request;
    });

    await wipeVault();

    assert.deepEqual(snapshotFakeStores(fake), { canary: [], meta: [], notes: [], selftest: [] });
  });
});

function createFailingIdbBackend(message: string): VaultBackend {
  return {
    kind: "idb",
    db: {
      transaction() {
        throw new Error(message);
      },
    } as unknown as IDBDatabase,
  };
}

async function expectRejects(fn: () => Promise<unknown>, pattern: RegExp) {
  let rejected = false;
  let message = "";
  try {
    await fn();
  } catch (error) {
    rejected = true;
    message = error instanceof Error ? error.message : String(error);
  }
  assert.equal(rejected, true);
  assert.equal(pattern.test(message), true);
}

type StoreName = "meta" | "notes" | "canary" | "selftest";
type FakeStores = Record<StoreName, Map<string, unknown>>;

interface FakeVaultDbFailure {
  failClearStore?: StoreName;
  failPutStore?: StoreName;
  abortAfterOperations?: boolean;
}

interface FakeVaultDb {
  db: IDBDatabase;
  stores: FakeStores;
  closed: boolean;
}

type OpenFactory = () => IDBOpenDBRequest;

function installFakeIndexedDb(open: OpenFactory) {
  Object.defineProperty(globalThis, "indexedDB", {
    configurable: true,
    writable: true,
    value: { open },
  });
}

function createOpenRequest(): IDBOpenDBRequest & { result: IDBDatabase; error: DOMException | null } {
  return {
    result: undefined as unknown as IDBDatabase,
    error: null,
    onblocked: null,
    onerror: null,
    onsuccess: null,
    onupgradeneeded: null,
  } as IDBOpenDBRequest & { result: IDBDatabase; error: DOMException | null };
}

function createSeedStores(): FakeStores {
  return {
    meta: new Map([["meta", createMetaRecord("old-salt")]]),
    notes: new Map([["old-note", createNoteRecord("old-note", "OLD")]]),
    canary: new Map([["canary", createCanaryRecord("old-canary")]]),
    selftest: new Map([["selftest", { ok: true }]]),
  };
}

function createReplacement(): VaultStoreReplacement {
  return {
    meta: createMetaRecord("new-salt"),
    canary: createCanaryRecord("new-canary"),
    notes: [{ id: "new-note", value: createNoteRecord("new-note", "NEW") }],
  };
}

function fallbackGenerationStorageKeyForTest(generation: string, store: string, key: string) {
  return `${FALLBACK_GENERATION_PREFIX}${generation}:${store}:${key}`;
}

function legacyVaultFallbackStorageKey(store: string, key: string) {
  return `nullid:vault:${store}:${key}`;
}

function seedGeneration(storage: MemoryStorage, generation: string, options: { noteIds: string[] }) {
  storage.setItem(
    fallbackGenerationStorageKeyForTest(generation, "state", "state"),
    JSON.stringify({
      schemaVersion: 2,
      kind: "nullid-vault-fallback-generation",
      state: options.noteIds.length > 0 ? "active" : "active",
      noteCount: options.noteIds.length,
      createdAt: 1_700_000_000_000,
    }),
  );
  storage.setItem(fallbackGenerationStorageKeyForTest(generation, "meta", "meta"), JSON.stringify(createMetaRecord(generation)));
  storage.setItem(fallbackGenerationStorageKeyForTest(generation, "canary", "canary"), JSON.stringify(createCanaryRecord(generation)));
  options.noteIds.forEach((id) => {
    storage.setItem(fallbackGenerationStorageKeyForTest(generation, "notes", id), JSON.stringify(createNoteRecord(id)));
  });
}

function createMetaRecord(salt = "test-salt") {
  return { salt, iterations: 200_000, version: 1, lockedAt: 1_700_000_000_000 };
}

function createCanaryRecord(label = "test-canary") {
  return { ciphertext: `${label}-ciphertext`, iv: `${label}-iv` };
}

function createNoteRecord(id: string, label = id) {
  return {
    id,
    ciphertext: `${label}-ciphertext`,
    iv: `${label}-iv`,
    createdAt: 1_700_000_000_000,
    updatedAt: 1_700_000_100_000,
    version: 3,
  };
}

function createFakeVaultDb(seed: FakeStores = createEmptyStores(), failure: FakeVaultDbFailure = {}): FakeVaultDb {
  const stores = cloneStores(seed);
  const fake: FakeVaultDb = {
    stores,
    closed: false,
    db: {
      objectStoreNames: {
        contains(name: string) {
          return name in stores;
        },
      } as DOMStringList,
      createObjectStore(name: string) {
        stores[name as StoreName] = new Map();
        return {} as IDBObjectStore;
      },
      close() {
        fake.closed = true;
      },
      transaction(storeNames: string | string[], _mode?: IDBTransactionMode) {
        const selected = (Array.isArray(storeNames) ? storeNames : [storeNames]) as StoreName[];
        const staged = cloneStores(stores);
        let aborted = false;
        const tx = {
          error: null as DOMException | Error | null,
          onabort: null as ((this: IDBTransaction, ev: Event) => unknown) | null,
          oncomplete: null as ((this: IDBTransaction, ev: Event) => unknown) | null,
          onerror: null as ((this: IDBTransaction, ev: Event) => unknown) | null,
          abort() {
            aborted = true;
            tx.error ??= new DOMException("injected abort", "AbortError");
          },
          objectStore(name: string) {
            const storeName = name as StoreName;
            if (!selected.includes(storeName)) {
              throw new Error(`store ${storeName} not in transaction`);
            }
            return createFakeObjectStore(storeName, staged, failure, tx as IDBTransaction);
          },
        };

        queueMicrotask(() => {
          if (aborted) return;
          if (failure.abortAfterOperations) {
            tx.error = new DOMException("injected transaction abort", "AbortError");
            tx.onabort?.call(tx as IDBTransaction, {} as Event);
            return;
          }
          selected.forEach((name) => {
            stores[name] = cloneStore(staged[name]);
          });
          tx.oncomplete?.call(tx as IDBTransaction, {} as Event);
        });

        return tx as IDBTransaction;
      },
    } as IDBDatabase,
  };
  return fake;
}

function createFakeObjectStore(
  storeName: StoreName,
  staged: FakeStores,
  failure: FakeVaultDbFailure,
  tx: IDBTransaction,
): IDBObjectStore {
  return {
    clear() {
      if (failure.failClearStore === storeName) {
        throw new Error(`injected clear failed for ${storeName}`);
      }
      staged[storeName].clear();
      return {} as IDBRequest<undefined>;
    },
    put(value: unknown, key?: IDBValidKey) {
      if (failure.failPutStore === storeName) {
        throw new Error(`injected put failed for ${storeName}`);
      }
      staged[storeName].set(String(key), structuredCloneForTest(value));
      return {} as IDBRequest<IDBValidKey>;
    },
    getAll() {
      const request = {
        result: [] as unknown[],
        error: null,
        onsuccess: null as ((this: IDBRequest<unknown[]>, ev: Event) => unknown) | null,
        onerror: null as ((this: IDBRequest<unknown[]>, ev: Event) => unknown) | null,
      } as IDBRequest<unknown[]> & { result: unknown[]; error: DOMException | null };
      queueMicrotask(() => {
        if (tx.error) {
          request.error = tx.error;
          request.onerror?.call(request, {} as Event);
          return;
        }
        request.result = Array.from(staged[storeName].values()).map(structuredCloneForTest);
        request.onsuccess?.call(request, {} as Event);
      });
      return request;
    },
    openCursor() {
      const entries = Array.from(staged[storeName].entries());
      const request = {
        result: null as IDBCursorWithValue | null,
        error: null,
        onsuccess: null as ((this: IDBRequest<IDBCursorWithValue | null>, ev: Event) => unknown) | null,
        onerror: null as ((this: IDBRequest<IDBCursorWithValue | null>, ev: Event) => unknown) | null,
      } as IDBRequest<IDBCursorWithValue | null> & { result: IDBCursorWithValue | null; error: DOMException | null };
      let index = 0;
      const advance = () => {
        if (tx.error) {
          request.error = tx.error;
          request.onerror?.call(request, {} as Event);
          return;
        }
        const entry = entries[index];
        if (!entry) {
          request.result = null;
          request.onsuccess?.call(request, {} as Event);
          return;
        }
        const [key, value] = entry;
        request.result = {
          key,
          primaryKey: key,
          value: structuredCloneForTest(value),
          continue() {
            index += 1;
            queueMicrotask(advance);
          },
        } as IDBCursorWithValue;
        request.onsuccess?.call(request, {} as Event);
      };
      queueMicrotask(advance);
      return request;
    },
  } as IDBObjectStore;
}

function createEmptyStores(): FakeStores {
  return {
    meta: new Map(),
    notes: new Map(),
    canary: new Map(),
    selftest: new Map(),
  };
}

function cloneStores(stores: FakeStores): FakeStores {
  return {
    meta: cloneStore(stores.meta),
    notes: cloneStore(stores.notes),
    canary: cloneStore(stores.canary),
    selftest: cloneStore(stores.selftest),
  };
}

function cloneStore(store: Map<string, unknown>) {
  return new Map(Array.from(store, ([key, value]) => [key, structuredCloneForTest(value)]));
}

function snapshotFakeStores(fake: FakeVaultDb) {
  return {
    canary: snapshotStore(fake.stores.canary),
    meta: snapshotStore(fake.stores.meta),
    notes: snapshotStore(fake.stores.notes),
    selftest: snapshotStore(fake.stores.selftest),
  };
}

function snapshotStore(store: Map<string, unknown>) {
  const entries: Array<[string, unknown]> = Array.from(store, ([key, value]) => [key, value]);
  return entries.sort(([left], [right]) => left.localeCompare(right));
}

function structuredCloneForTest<T>(value: T): T {
  return value === undefined ? value : JSON.parse(JSON.stringify(value)) as T;
}
