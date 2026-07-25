import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { decryptNote, exportVault, importVault, loadNotes, saveNote, unlockVault, verifyVaultPayload, type VaultNote } from "../utils/vault.js";
import { toBase64Url, utf8ToBytes } from "../utils/encoding.js";
import { setVaultStorageLogger } from "../utils/storage.js";
import { createSnapshotIntegrity } from "../utils/snapshotIntegrity.js";

class MemoryStorage implements Storage {
  private map = new Map<string, string>();
  failOnSetKey: string | null = null;
  failOnSetPrefix: string | null = null;
  failOnSetIncludes: string | null = null;
  persistentFailOnSetPrefix: string | null = null;
  failOnRemoveCall: number | null = null;
  corruptOnSetKey: string | null = null;
  corruptOnSetIncludes: string | null = null;
  private removeCalls = 0;

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
    this.removeCalls += 1;
    if (this.failOnRemoveCall === this.removeCalls) {
      this.failOnRemoveCall = null;
      throw new Error(`injected removeItem failure for ${key}`);
    }
    this.map.delete(key);
  }

  setItem(key: string, value: string) {
    if (this.failOnSetKey === key) {
      this.failOnSetKey = null;
      throw new Error(`injected setItem failure for ${key}`);
    }
    if (this.failOnSetPrefix && key.startsWith(this.failOnSetPrefix)) {
      this.failOnSetPrefix = null;
      throw new Error(`injected setItem failure for ${key}`);
    }
    if (this.failOnSetIncludes && key.includes(this.failOnSetIncludes)) {
      this.failOnSetIncludes = null;
      throw new Error(`injected setItem failure for ${key}`);
    }
    if (this.persistentFailOnSetPrefix && key.startsWith(this.persistentFailOnSetPrefix)) {
      throw new Error(`injected setItem failure for ${key}`);
    }
    this.map.set(
      key,
      this.corruptOnSetKey === key || (this.corruptOnSetIncludes !== null && key.includes(this.corruptOnSetIncludes))
        ? `${value}-corrupt`
        : value,
    );
  }

  snapshot() {
    return Array.from(this.map.entries()).sort(([left], [right]) => left.localeCompare(right));
  }

  resetRemoveCalls() {
    this.removeCalls = 0;
  }
}

describe("vault snapshot integrity", () => {
  const fixtureSalt = toBase64Url(utf8ToBytes("signed-salt-1234"));
  const fixtureIv = toBase64Url(utf8ToBytes("0123456789ab"));
  const fixtureCiphertext = toBase64Url(utf8ToBytes("0123456789abcdef"));

  const setup = () => {
    const storage = new MemoryStorage();
    Object.defineProperty(globalThis, "localStorage", { value: storage, configurable: true, writable: true });
    Object.defineProperty(globalThis, "indexedDB", { value: undefined, configurable: true, writable: true });
    setVaultStorageLogger({ warn() {} });
    return storage;
  };

  it("exports signed metadata and verifies during import", async () => {
    setup();
    const key = await unlockVault("vault-sign-secret-source");
    await saveNote(key, "note-1", "Signed", "metadata", { createdAt: 1_700_000_000_000, tags: [] });

    const signedBlob = await exportVault({ signingPassphrase: "vault-sign-secret", keyHint: "vault-local-key" });
    const signedText = await signedBlob.text();
    const signedFile = new File([signedText], "signed-vault.json", { type: "application/json" });
    const verified = await importVault(signedFile, { verificationPassphrase: "vault-sign-secret" });
    assert.equal(verified.signed, true);
    assert.equal(verified.verified, true);
    assert.equal(verified.legacy, false);
    assert.equal(verified.noteCount, 1);
  });

  it("rejects tampered signed vault payload", async () => {
    setup();
    const key = await unlockVault("tampered-vault-source");
    await saveNote(key, "note-1", "Signed", "metadata", { createdAt: 1_700_000_000_000, tags: [] });

    const signedBlob = await exportVault({ signingPassphrase: "vault-sign-secret" });
    const tampered = JSON.parse(await signedBlob.text()) as {
      vault: { notes: Array<{ id: string; ciphertext: string; iv: string; createdAt: number; updatedAt: number; version: 3 }> };
    };
    tampered.vault.notes.push({ id: "note-2", ciphertext: fixtureCiphertext, iv: fixtureIv, createdAt: Date.now(), updatedAt: Date.now(), version: 3 });
    const tamperedFile = new File([JSON.stringify(tampered)], "tampered-vault.json", { type: "application/json" });
    await expectRejects(() => importVault(tamperedFile, { verificationPassphrase: "vault-sign-secret" }), /integrity mismatch/i);
  });

  it("requires verification secret for signed vault metadata", async () => {
    setup();
    const key = await unlockVault("verification-required-source");
    await saveNote(key, "note-1", "Signed", "metadata", { createdAt: 1_700_000_000_000, tags: [] });
    const signedBlob = await exportVault({ signingPassphrase: "vault-sign-secret" });
    const signedFile = new File([await signedBlob.text()], "signed-vault.json", { type: "application/json" });
    await expectRejects(() => importVault(signedFile), /verification passphrase required/i);
  });

  it("round-trips a fresh empty vault snapshot", async () => {
    const storage = setup();

    const exported = JSON.parse(await (await exportVault()).text()) as {
      vault: { meta: unknown; notes: unknown[]; canary: unknown };
    };

    assert.deepEqual(exported.vault, { meta: null, notes: [], canary: null });
    const verification = await verifyVaultPayload(exported);
    assert.equal(verification.verificationState, "integrity-checked");

    storage.clear();
    const result = await importVault(new File([JSON.stringify(exported)], "empty-vault.json", { type: "application/json" }));
    assert.equal(result.noteCount, 0);
    assert.deepEqual(await loadNotes(), []);

    const reexported = JSON.parse(await (await exportVault()).text()) as typeof exported;
    assert.deepEqual(reexported.vault, exported.vault);
  });

  it("authenticates saved note identity and timestamp metadata before decrypting", async () => {
    setup();
    const key = await unlockVault("timestamp-binding-secret");
    const createdAt = Date.now() - 10_000;

    await saveNote(key, "note-a", "Alpha", "bound body", { createdAt, tags: ["case"] });
    const [note] = await loadNotes();
    assert.equal(note.id, "note-a");
    assert.equal(note.version, 3);

    const decrypted = await decryptNote(key, note);
    assert.equal(decrypted.title, "Alpha");
    assert.equal(decrypted.createdAt, createdAt);
    assert.equal(decrypted.updatedAt, note.updatedAt);

    await assert.rejects(
      () => decryptNote(key, { ...note, updatedAt: note.updatedAt + 1 }),
      /decrypt|authenticat|timestamp|operation/i,
    );
    await assert.rejects(
      () => decryptNote(key, { ...note, id: "note-b" }),
      /decrypt|authenticat|note id|operation/i,
    );
    assert.equal((note as VaultNote & { createdAt?: number }).createdAt, createdAt);
    await assert.rejects(
      () => decryptNote(key, { ...note, createdAt: createdAt + 1 } as VaultNote),
      /decrypt|authenticat|createdAt|operation/i,
    );
  });

  it("rejects unsupported vault note versions without partially replacing the active vault", async () => {
    const cases: Array<{ label: string; mutate: (note: Record<string, unknown>) => void; pattern: RegExp }> = [
      { label: "missing version", mutate: (note) => { delete note.version; }, pattern: /unsupported|version|canonical/i },
      { label: "explicit v1", mutate: (note) => { note.version = 1; }, pattern: /unsupported|version|v1|canonical/i },
      { label: "explicit v2", mutate: (note) => { note.version = 2; }, pattern: /unsupported|version|v2|canonical/i },
      { label: "unknown version", mutate: (note) => { note.version = 99; }, pattern: /unsupported|version|canonical/i },
      { label: "downgrade string", mutate: (note) => { note.version = "3"; }, pattern: /unsupported|version|canonical/i },
    ];

    for (const testCase of cases) {
      setup();
      const key = await unlockVault(`version-secret-${testCase.label}`);
      await saveNote(key, "existing-note", "Existing", "must remain", { createdAt: 1_700_000_000_000, tags: [] });
      const before = JSON.stringify(await loadNotes());
      const exported = await exportCurrentVaultObject();
      const replacementNote = { ...(exported.vault.notes[0] as Record<string, unknown>), id: "replacement-note" };
      testCase.mutate(replacementNote);
      exported.vault.notes = [replacementNote as never];
      await refreshVaultIntegrity(exported);

      await expectRejects(
        () => importVault(new File([JSON.stringify(exported)], `${testCase.label}.json`, { type: "application/json" })),
        testCase.pattern,
        testCase.label,
      );
      assert.equal(JSON.stringify(await loadNotes()), before, testCase.label);
    }
  });

  it("rejects mixed v2/v3 vault snapshots transactionally", async () => {
    setup();
    const key = await unlockVault("mixed-version-source");
    await saveNote(key, "note-a", "A", "body a", { createdAt: 1_700_000_000_000, tags: [] });
    await saveNote(key, "note-b", "B", "body b", { createdAt: 1_700_000_001_000, tags: [] });
    const exported = await exportCurrentVaultObject();
    const [first, second] = exported.vault.notes as Array<Record<string, unknown>>;
    first.version = 2;
    second.version = 3;
    await refreshVaultIntegrity(exported);

    setup();
    const existingKey = await unlockVault("mixed-version-destination");
    await saveNote(existingKey, "existing-note", "Existing", "must remain", { createdAt: 1_700_000_002_000, tags: [] });
    const before = JSON.stringify(await loadNotes());

    await expectRejects(
      () => importVault(new File([JSON.stringify(exported)], "mixed-vault.json", { type: "application/json" })),
      /unsupported|version|v2|canonical/i,
    );

    assert.equal(JSON.stringify(await loadNotes()), before);
  });

  it("rejects legacy unversioned snapshots and only round-trips canonical schema exports", async () => {
    const storage = setup();
    const key = await unlockVault("canonical-export-secret");
    await saveNote(key, "canonical-note", "Canonical", "current schema only", {
      createdAt: 1_700_000_000_000,
      tags: ["release"],
    });
    const exported = await exportCurrentVaultObject();
    assert.equal(exported.schemaVersion, 2);
    assert.equal(exported.kind, "vault");
    assert.equal(exported.vault.notes.every((note: { version?: number }) => note.version === 3), true);

    storage.clear();
    const imported = await importVault(new File([JSON.stringify(exported)], "canonical-vault.json", { type: "application/json" }));
    assert.equal(imported.legacy, false);
    assert.equal(imported.noteCount, 1);
    assert.equal((await loadNotes())[0].id, "canonical-note");

    await expectRejects(
      () => importVault(new File([JSON.stringify(buildLegacySnapshot(["legacy-note"]))], "legacy-vault.json", { type: "application/json" })),
      /unsupported|schema|legacy|canonical/i,
    );
  });

  it("rejects legacy vault metadata and records as unsupported formats", async () => {
    setup();
    const invalidMeta = new File(
      [
        JSON.stringify({
          meta: { salt: fixtureSalt, iterations: 50_000_000, version: 1 },
          notes: [],
        }),
      ],
      "invalid-meta.json",
      { type: "application/json" },
    );
    await expectRejects(() => importVault(invalidMeta), /unsupported vault snapshot schema version|missing/i);

    const invalidNoteIv = new File(
      [
        JSON.stringify({
          meta: { salt: fixtureSalt, iterations: 200_000, version: 1 },
          notes: [{ id: "note-1", ciphertext: fixtureCiphertext, iv: "not-base64!!!", updatedAt: Date.now() }],
        }),
      ],
      "invalid-note.json",
      { type: "application/json" },
    );
    await expectRejects(() => importVault(invalidNoteIv), /unsupported vault snapshot schema version|missing/i);
  });

  it("rejects invalid vault imports before mutating existing fallback data", async () => {
    const missingCanarySnapshot = await buildCanonicalImportSnapshot(["new-note"]);
    (missingCanarySnapshot.vault as { canary: unknown }).canary = null;
    await refreshVaultIntegrity(missingCanarySnapshot);

    const countMismatchSnapshot = await buildCanonicalImportSnapshot(["new-note"]);
    countMismatchSnapshot.integrity.noteCount = 2;

    const unicodeCollisionSnapshot = await buildCanonicalImportSnapshot(["\u00c9", "e\u0301"]);

    const invalidCases: Array<{ label: string; payload: unknown; pattern: RegExp }> = [
      { label: "empty object", payload: {}, pattern: /unsupported vault snapshot schema version|missing/i },
      { label: "unrelated object", payload: { hello: "world" }, pattern: /unsupported vault snapshot schema version|missing/i },
      { label: "array", payload: [], pattern: /invalid vault snapshot/i },
      { label: "null", payload: null, pattern: /invalid vault snapshot/i },
      { label: "unknown schema version", payload: { schemaVersion: 999, kind: "vault", meta: {}, notes: [] }, pattern: /unsupported|schema/i },
      {
        label: "v2 wrong kind",
        payload: { schemaVersion: 2, kind: "profile", exportedAt: new Date().toISOString(), vault: buildLegacySnapshot(["new-note"]), integrity: { noteCount: 1, payloadHash: "00" } },
        pattern: /kind/i,
      },
      {
        label: "legacy missing required fields",
        payload: { meta: { salt: fixtureSalt, iterations: 200_000, version: 1 }, notes: [] },
        pattern: /unsupported vault snapshot schema version|missing/i,
      },
      {
        label: "note without canary invariants",
        payload: missingCanarySnapshot,
        pattern: /canary/i,
      },
      {
        label: "declared count mismatch",
        payload: countMismatchSnapshot,
        pattern: /note count|integrity/i,
      },
      {
        label: "combined note id collision",
        payload: unicodeCollisionSnapshot,
        pattern: /duplicate vault note id/i,
      },
    ];

    for (const testCase of invalidCases) {
      const storage = setup();
      const key = await unlockVault(`old-${testCase.label}`);
      await saveNote(key, "old-note", "Old", "must remain", { createdAt: 1_700_000_000_000, tags: [] });
      const before = storage.snapshot();
      const fileBody = typeof testCase.payload === "string" ? testCase.payload : JSON.stringify(testCase.payload);

      await expectRejects(
        () => importVault(new File([fileBody], `${testCase.label}.json`, { type: "application/json" })),
        testCase.pattern,
        testCase.label,
      );

      assert.deepEqual(storage.snapshot(), before, testCase.label);
    }
  });

  it("preserves the existing fallback vault when import replacement fails at each commit stage", async () => {
    const cases: Array<{ label: string; configure: (storage: MemoryStorage) => RegExp }> = [
      {
        label: "first staged write",
        configure: (storage) => {
          storage.failOnSetPrefix = "nullid:vault:data:gen:";
          return /injected setItem failure/i;
        },
      },
      {
        label: "during staged note write",
        configure: (storage) => {
          storage.failOnSetIncludes = "notes:new-note";
          return /injected setItem failure/i;
        },
      },
      {
        label: "during active-pointer update",
        configure: (storage) => {
          storage.failOnSetKey = "nullid:vault:data:active-generation";
          return /injected setItem failure/i;
        },
      },
      {
        label: "during staged verification",
        configure: (storage) => {
          storage.corruptOnSetIncludes = "notes:new-note";
          return /staging verification failed/i;
        },
      },
      {
        label: "persistent final write failure",
        configure: (storage) => {
          storage.persistentFailOnSetPrefix = "nullid:vault:data:gen:";
          return /injected setItem failure/i;
        },
      },
    ];

    for (const testCase of cases) {
      const storage = setup();
      const key = await unlockVault(`replacement-${testCase.label}`);
      await saveNote(key, "old-note", "Old", "must remain", { createdAt: 1_700_000_000_000, tags: [] });
      const before = storage.snapshot();
      const pattern = testCase.configure(storage);

      await expectRejects(
        async () => {
          const snapshot = await buildCanonicalImportSnapshot(["new-note"]);
          await importVault(new File([JSON.stringify(snapshot)], `${testCase.label}-new.json`, { type: "application/json" }));
        },
        pattern,
        testCase.label,
      );

      assert.deepEqual(storage.snapshot(), before, testCase.label);
    }
  });

  it("rejects duplicate imported note ids before mutating the existing vault", async () => {
    const storage = setup();
    const key = await unlockVault("duplicate-existing");
    await saveNote(key, "old-note", "Old", "must remain", { createdAt: 1_700_000_000_000, tags: [] });
    const before = storage.snapshot();

    const duplicateSnapshot = await buildCanonicalImportSnapshot(["duplicate-note", "duplicate-note"]);
    await expectRejects(
      () => importVault(new File([JSON.stringify(duplicateSnapshot)], "duplicate-vault.json", { type: "application/json" })),
      /duplicate vault note id/i,
    );

    assert.deepEqual(storage.snapshot(), before);
  });

  it("binds encrypted note ciphertext to the stored note id", async () => {
    setup();
    const key = await unlockVault("note-identity-secret");
    await saveNote(key, "note-a", "Alpha", "first body", { createdAt: 1_700_000_000_000, tags: ["a"] });
    await saveNote(key, "note-b", "Beta", "second body", { createdAt: 1_700_000_001_000, tags: ["b"] });

    const notes = await loadNotes();
    const noteA = notes.find((note) => note.id === "note-a");
    const noteB = notes.find((note) => note.id === "note-b");
    assert.ok(noteA);
    assert.ok(noteB);

    await expectRejects(
      () => decryptNote(key, { ...noteA, ciphertext: noteB.ciphertext, iv: noteB.iv, updatedAt: noteB.updatedAt }),
      /decrypt|auth|identity|aad|operation-specific/i,
    );
  });

  function buildLegacySnapshot(noteIds: string[]) {
    return {
      meta: { salt: fixtureSalt, iterations: 200_000, version: 1 },
      canary: { ciphertext: fixtureCiphertext, iv: fixtureIv },
      notes: noteIds.map((id, index) => ({ id, ciphertext: fixtureCiphertext, iv: fixtureIv, updatedAt: Date.now() + index })),
    };
  }

  async function buildCanonicalImportSnapshot(noteIds: string[]) {
    const snapshot = {
      schemaVersion: 2,
      kind: "vault",
      exportedAt: new Date().toISOString(),
      vault: {
        meta: { salt: fixtureSalt, iterations: 200_000, version: 1 },
        canary: { ciphertext: fixtureCiphertext, iv: fixtureIv },
        notes: noteIds.map((id, index) => ({
          id,
          ciphertext: fixtureCiphertext,
          iv: fixtureIv,
          createdAt: 1_700_000_000_000 + index,
          updatedAt: 1_700_000_100_000 + index,
          version: 3,
        })),
      },
      integrity: {
        noteCount: noteIds.length,
        payloadHash: "",
      },
    };
    await refreshVaultIntegrity(snapshot);
    return snapshot;
  }

  async function exportCurrentVaultObject() {
    return JSON.parse(await (await exportVault()).text()) as {
      schemaVersion: number;
      kind: "vault";
      exportedAt: string;
      vault: {
        meta: unknown;
        notes: Array<Record<string, unknown>>;
        canary: unknown;
      };
      integrity: { noteCount: number; payloadHash: string };
    };
  }

  async function refreshVaultIntegrity(snapshot: {
    schemaVersion: number;
    exportedAt: string;
    vault: unknown & { notes: unknown[] };
    integrity: unknown;
  }) {
    const { integrity } = await createSnapshotIntegrity(
      {
        schemaVersion: 2,
        exportedAt: snapshot.exportedAt,
        vault: snapshot.vault,
      },
      "noteCount",
      snapshot.vault.notes.length,
    );
    snapshot.integrity = integrity;
  }

  it("rejects malformed decrypted vault note payloads", async () => {
    setup();
    const key = await unlockVault("note-validation-secret");
    const cases: Array<{ payload: unknown; pattern: RegExp }> = [
      { payload: "{not-json", pattern: /json/i },
      { payload: { title: 1, body: "body", tags: [], createdAt: Date.now(), updatedAt: Date.now() }, pattern: /title/i },
      { payload: { title: "x".repeat(241), body: "body", tags: [], createdAt: Date.now(), updatedAt: Date.now() }, pattern: /title/i },
      { payload: { title: "title", body: "x".repeat(5 * 1024 * 1024 + 1), tags: [], createdAt: Date.now(), updatedAt: Date.now() }, pattern: /body/i },
      { payload: { title: "title", body: "body", tags: [1], createdAt: Date.now(), updatedAt: Date.now() }, pattern: /tags/i },
      { payload: { title: "title", body: "body", tags: [], createdAt: -1, updatedAt: Date.now() }, pattern: /createdAt/i },
      { payload: { title: "title", body: "body", tags: [], createdAt: Date.now(), updatedAt: Number.NaN }, pattern: /updatedAt/i },
    ];

    for (const [index, testCase] of cases.entries()) {
      const note = await encryptVaultNotePayload(key, `bad-${index}`, testCase.payload);
      await expectRejects(() => decryptNote(key, note), testCase.pattern);
    }
  });

  async function encryptVaultNotePayload(key: CryptoKey, id: string, payload: unknown): Promise<VaultNote> {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plaintext = typeof payload === "string" ? payload : JSON.stringify(payload);
    const createdAt = Date.now();
    const updatedAt = createdAt + 1;
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: exactArrayBuffer(iv),
          additionalData: exactArrayBuffer(utf8ToBytes(`nullid:vault:note:v3:${id}:${updatedAt}`)),
        },
        key,
        exactArrayBuffer(utf8ToBytes(plaintext)),
      ),
    );
    return {
      id,
      ciphertext: toBase64Url(ciphertext),
      iv: toBase64Url(iv),
      createdAt,
      updatedAt,
      version: 3,
    };
  }
});

async function expectRejects(fn: () => Promise<unknown>, pattern: RegExp, label?: string) {
  let rejected = false;
  let message = "";
  try {
    await fn();
  } catch (error) {
    rejected = true;
    message = error instanceof Error ? error.message : String(error);
  }
  if (label) {
    assert.equal(rejected, true, label);
    assert.equal(pattern.test(message), true, `${label}: ${message}`);
    return;
  }
  assert.equal(rejected, true);
  assert.equal(pattern.test(message), true);
}

function exactArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}
