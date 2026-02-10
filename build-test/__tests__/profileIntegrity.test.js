import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { PROFILE_SCHEMA_VERSION, collectProfile, importProfileFile } from "../utils/profile.js";
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
describe("profile integrity", () => {
    const setup = () => {
        const storage = new MemoryStorage();
        Object.defineProperty(globalThis, "localStorage", { value: storage, configurable: true, writable: true });
        storage.setItem("nullid:theme", JSON.stringify("dark"));
        storage.setItem("nullid:pw-settings", JSON.stringify({ length: 22, symbols: true }));
        storage.setItem("non-nullid:key", JSON.stringify("ignored"));
        return storage;
    };
    it("exports signed profile metadata and verifies on import", async () => {
        const storage = setup();
        const snapshot = await collectProfile({ signingPassphrase: "profile-sign-secret", keyHint: "local-key" });
        assert.equal(snapshot.schemaVersion, PROFILE_SCHEMA_VERSION);
        assert.equal(Boolean(snapshot.integrity?.payloadHash), true);
        assert.equal(Boolean(snapshot.signature?.value), true);
        storage.clear();
        const file = new File([JSON.stringify(snapshot)], "profile.json", { type: "application/json" });
        const result = await importProfileFile(file, { verificationPassphrase: "profile-sign-secret" });
        assert.equal(result.applied, 2);
        assert.equal(result.signed, true);
        assert.equal(result.verified, true);
        assert.equal(result.legacy, false);
        assert.equal(storage.getItem("nullid:theme"), JSON.stringify("dark"));
    });
    it("rejects tampered profile payloads", async () => {
        setup();
        const snapshot = await collectProfile({ signingPassphrase: "profile-sign-secret" });
        const tampered = JSON.parse(JSON.stringify(snapshot));
        tampered.entries["nullid:theme"] = "light";
        const file = new File([JSON.stringify(tampered)], "tampered.json", { type: "application/json" });
        await expectRejects(() => importProfileFile(file, { verificationPassphrase: "profile-sign-secret" }), /integrity mismatch/i);
    });
    it("requires verification passphrase when signed metadata exists", async () => {
        setup();
        const snapshot = await collectProfile({ signingPassphrase: "profile-sign-secret" });
        const file = new File([JSON.stringify(snapshot)], "signed.json", { type: "application/json" });
        await expectRejects(() => importProfileFile(file), /verification passphrase required/i);
    });
    it("imports legacy schema payloads", async () => {
        setup();
        const legacy = {
            schemaVersion: 1,
            exportedAt: new Date().toISOString(),
            entries: {
                "nullid:last-module": "guide",
            },
        };
        const file = new File([JSON.stringify(legacy)], "legacy.json", { type: "application/json" });
        const result = await importProfileFile(file);
        assert.equal(result.legacy, true);
        assert.equal(result.applied, 1);
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
