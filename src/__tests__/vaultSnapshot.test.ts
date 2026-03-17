import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { exportVault, importVault } from "../utils/vault.js";
import { toBase64Url, utf8ToBytes } from "../utils/encoding.js";

class MemoryStorage implements Storage {
  private map = new Map<string, string>();

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
    this.map.delete(key);
  }

  setItem(key: string, value: string) {
    this.map.set(key, value);
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
  };

  it("exports signed metadata and verifies during import", async () => {
    setup();
    const legacySnapshot = {
      meta: { salt: fixtureSalt, iterations: 200_000, version: 1 },
      canary: { ciphertext: fixtureCiphertext, iv: fixtureIv },
      notes: [{ id: "note-1", ciphertext: fixtureCiphertext, iv: fixtureIv, updatedAt: Date.now() }],
    };
    const legacyFile = new File([JSON.stringify(legacySnapshot)], "legacy-vault.json", { type: "application/json" });
    const legacyResult = await importVault(legacyFile);
    assert.equal(legacyResult.legacy, true);
    assert.equal(legacyResult.noteCount, 1);

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
    const legacySnapshot = {
      meta: { salt: fixtureSalt, iterations: 200_000, version: 1 },
      canary: { ciphertext: fixtureCiphertext, iv: fixtureIv },
      notes: [{ id: "note-1", ciphertext: fixtureCiphertext, iv: fixtureIv, updatedAt: Date.now() }],
    };
    const legacyFile = new File([JSON.stringify(legacySnapshot)], "legacy-vault.json", { type: "application/json" });
    await importVault(legacyFile);

    const signedBlob = await exportVault({ signingPassphrase: "vault-sign-secret" });
    const tampered = JSON.parse(await signedBlob.text()) as {
      vault: { notes: Array<{ id: string; ciphertext: string; iv: string; updatedAt: number }> };
    };
    tampered.vault.notes.push({ id: "note-2", ciphertext: fixtureCiphertext, iv: fixtureIv, updatedAt: Date.now() });
    const tamperedFile = new File([JSON.stringify(tampered)], "tampered-vault.json", { type: "application/json" });
    await expectRejects(() => importVault(tamperedFile, { verificationPassphrase: "vault-sign-secret" }), /integrity mismatch/i);
  });

  it("requires verification secret for signed vault metadata", async () => {
    setup();
    const legacySnapshot = {
      meta: { salt: fixtureSalt, iterations: 200_000, version: 1 },
      canary: { ciphertext: fixtureCiphertext, iv: fixtureIv },
      notes: [{ id: "note-1", ciphertext: fixtureCiphertext, iv: fixtureIv, updatedAt: Date.now() }],
    };
    const legacyFile = new File([JSON.stringify(legacySnapshot)], "legacy-vault.json", { type: "application/json" });
    await importVault(legacyFile);
    const signedBlob = await exportVault({ signingPassphrase: "vault-sign-secret" });
    const signedFile = new File([await signedBlob.text()], "signed-vault.json", { type: "application/json" });
    await expectRejects(() => importVault(signedFile), /verification passphrase required/i);
  });

  it("rejects malformed legacy vault metadata and records", async () => {
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
    await expectRejects(() => importVault(invalidMeta), /Invalid vault meta iterations/i);

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
    await expectRejects(() => importVault(invalidNoteIv), /Invalid vault note iv at index 0/i);
  });
});

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
