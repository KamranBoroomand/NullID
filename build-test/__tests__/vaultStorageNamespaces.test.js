import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readPersistentStateValue, writePersistentStateValue } from "../hooks/usePersistentState.js";
import { collectProfile } from "../utils/profile.js";
import { getAllValues, getValue } from "../utils/storage.js";
import { VAULT_PREFERENCE_STATE_KEYS, isVaultLocalStorageRecordKey, legacyVaultFallbackStorageKey, vaultFallbackStorageKey, } from "../utils/vaultStorageKeys.js";
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
describe("vault storage namespaces", () => {
    const fallbackBackend = { kind: "ls" };
    const setup = () => {
        const storage = new MemoryStorage();
        Object.defineProperty(globalThis, "localStorage", { value: storage, configurable: true, writable: true });
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
    it("migrates legacy fallback blobs into the data namespace while preserving reads", async () => {
        const storage = setup();
        const legacyNoteKey = legacyVaultFallbackStorageKey("notes", "note-1");
        storage.setItem(legacyNoteKey, JSON.stringify({ id: "note-1", ciphertext: "secret", iv: "iv", updatedAt: 1 }));
        storage.setItem(legacyVaultFallbackStorageKey("meta", "meta"), JSON.stringify({ salt: "salt", iterations: 200_000 }));
        const notes = await getAllValues(fallbackBackend, "notes");
        const meta = await getValue(fallbackBackend, "meta", "meta");
        assert.equal(notes.length, 1);
        assert.equal(notes[0].id, "note-1");
        assert.equal(meta?.salt, "salt");
        assert.equal(storage.getItem(vaultFallbackStorageKey("notes", "note-1")) !== null, true);
        assert.equal(storage.getItem(vaultFallbackStorageKey("meta", "meta")) !== null, true);
        assert.equal(storage.getItem(legacyNoteKey), null);
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
        assert.equal(isVaultLocalStorageRecordKey(vaultFallbackStorageKey("notes", "note-1")), true);
        assert.equal(isVaultLocalStorageRecordKey(legacyVaultFallbackStorageKey("notes", "note-1")), true);
    });
});
