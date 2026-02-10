import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { exportVault, importVault } from "../utils/vault.js";
class MemoryStorage {
    map = new Map();
    get length() {
        return this.map.size;
    }
    clear() {
        this.map.clear();
    }
    getItem(key) {
        return this.map.has(key) ? this.map.get(key) : null;
    }
    key(index) {
        return Array.from(this.map.keys())[index] ?? null;
    }
    removeItem(key) {
        this.map.delete(key);
    }
    setItem(key, value) {
        this.map.set(key, value);
    }
}
describe("vault snapshot integrity", () => {
    const setup = () => {
        const storage = new MemoryStorage();
        Object.defineProperty(globalThis, "localStorage", { value: storage, configurable: true, writable: true });
        Object.defineProperty(globalThis, "indexedDB", { value: undefined, configurable: true, writable: true });
    };
    it("exports signed metadata and verifies during import", async () => {
        setup();
        const legacySnapshot = {
            meta: { salt: "c2lnbmVkLXNhbHQxMjM0", iterations: 200_000, version: 1 },
            canary: { ciphertext: "canary-ciphertext", iv: "canary-iv-value" },
            notes: [{ id: "note-1", ciphertext: "ciphertext-note-value", iv: "note-iv-value", updatedAt: Date.now() }],
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
            meta: { salt: "dGFtcGVyLXNhbHQxMjM0", iterations: 200_000, version: 1 },
            canary: { ciphertext: "canary-ciphertext", iv: "canary-iv-value" },
            notes: [{ id: "note-1", ciphertext: "ciphertext-note-value", iv: "note-iv-value", updatedAt: Date.now() }],
        };
        const legacyFile = new File([JSON.stringify(legacySnapshot)], "legacy-vault.json", { type: "application/json" });
        await importVault(legacyFile);
        const signedBlob = await exportVault({ signingPassphrase: "vault-sign-secret" });
        const tampered = JSON.parse(await signedBlob.text());
        tampered.vault.notes.push({ id: "note-2", ciphertext: "other-ciphertext", iv: "other-iv-value", updatedAt: Date.now() });
        const tamperedFile = new File([JSON.stringify(tampered)], "tampered-vault.json", { type: "application/json" });
        await expectRejects(() => importVault(tamperedFile, { verificationPassphrase: "vault-sign-secret" }), /integrity mismatch/i);
    });
    it("requires verification secret for signed vault metadata", async () => {
        setup();
        const legacySnapshot = {
            meta: { salt: "c2lnbmVkLXNhbHQxMjM0", iterations: 200_000, version: 1 },
            canary: { ciphertext: "canary-ciphertext", iv: "canary-iv-value" },
            notes: [{ id: "note-1", ciphertext: "ciphertext-note-value", iv: "note-iv-value", updatedAt: Date.now() }],
        };
        const legacyFile = new File([JSON.stringify(legacySnapshot)], "legacy-vault.json", { type: "application/json" });
        await importVault(legacyFile);
        const signedBlob = await exportVault({ signingPassphrase: "vault-sign-secret" });
        const signedFile = new File([await signedBlob.text()], "signed-vault.json", { type: "application/json" });
        await expectRejects(() => importVault(signedFile), /verification passphrase required/i);
    });
});
async function expectRejects(fn, pattern) {
    let rejected = false;
    let message = "";
    try {
        await fn();
    }
    catch (error) {
        rejected = true;
        message = error instanceof Error ? error.message : String(error);
    }
    assert.equal(rejected, true);
    assert.equal(pattern.test(message), true);
}
