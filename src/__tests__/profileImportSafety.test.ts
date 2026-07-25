import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { PROFILE_SCHEMA_VERSION, importProfileFile } from "../utils/profile.js";
import { sha256Base64Url } from "../utils/integrity.js";

class MemoryStorage implements Storage {
  private map = new Map<string, string>();
  failOnSetKeys: string[] = [];
  failOnRemoveKeys: string[] = [];

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
    if (this.failOnRemoveKeys[0] === key) {
      this.failOnRemoveKeys.shift();
      throw new Error(`injected removeItem failure for ${key}`);
    }
    this.map.delete(key);
  }

  setItem(key: string, value: string) {
    if (this.failOnSetKeys[0] === key) {
      this.failOnSetKeys.shift();
      throw new DOMException(`injected setItem failure for ${key}`, "QuotaExceededError");
    }
    this.map.set(key, value);
  }

  snapshot() {
    return Array.from(this.map.entries()).sort(([left], [right]) => left.localeCompare(right));
  }
}

describe("profile import safety", () => {
  const setup = () => {
    const storage = new MemoryStorage();
    Object.defineProperty(globalThis, "localStorage", { value: storage, configurable: true, writable: true });
    return storage;
  };

  it("imports only allow-listed valid profile settings and reports rejected entries", async () => {
    const storage = setup();
    const file = await profileFile({
      "nullid:theme": "dark",
      "nullid:locale": "ru",
      "nullid:layout-mode": "desktop",
      "nullid:onboarding-complete": true,
      "nullid:unknown-setting": true,
      "nullid:vault:data:notes:note-1": { ciphertext: "secret", iv: "iv" },
      "non-nullid:key": "ignored",
    });

    const result = await importProfileFile(file);

    assert.equal(result.applied, 4);
    assert.deepEqual(result.importedKeys.sort(), [
      "nullid:layout-mode",
      "nullid:locale",
      "nullid:onboarding-complete",
      "nullid:theme",
    ]);
    assert.deepEqual(result.skippedKeys.map((entry) => entry.key).sort(), [
      "non-nullid:key",
      "nullid:unknown-setting",
      "nullid:vault:data:notes:note-1",
    ]);
    assert.deepEqual(result.invalidKeys, []);
    assert.equal(storage.getItem("nullid:theme"), JSON.stringify("dark"));
    assert.equal(storage.getItem("nullid:locale"), "ru");
    assert.equal(storage.getItem("nullid:layout-mode"), JSON.stringify("desktop"));
    assert.equal(storage.getItem("nullid:unknown-setting"), null);
    assert.equal(storage.getItem("nullid:vault:data:notes:note-1"), null);
  });

  it("rejects invalid recognized entries before mutating storage", async () => {
    const storage = setup();
    storage.setItem("nullid:theme", JSON.stringify("dark"));
    const before = storage.snapshot();
    const file = await profileFile({
      "nullid:clipboard:prefs": { enableAutoClearClipboard: true, clipboardClearSeconds: 30 },
      "nullid:theme": "system",
      "nullid:locale": "bad",
      "nullid:language": 42,
      "nullid:layout-mode": "wide",
      "nullid:onboarding-complete": {},
      "nullid:profile:key-hint-selected": "x".repeat(5000),
    });

    await assert.rejects(() => importProfileFile(file), /profile import validation failed|profile value failed validation/i);

    assert.deepEqual(storage.snapshot(), before);
  });

  it("skips private vault import keys including fallback records and MFA credentials", async () => {
    const storage = setup();
    const file = await profileFile({
      "nullid:vault:data:notes:note-1": { ciphertext: "secret" },
      "nullid:vault:notes:legacy-note": { ciphertext: "secret" },
      "nullid:vault:pref:mfa-credential": { id: "credential-id" },
      "nullid:vault:pref:unlock-rate-limit": false,
    });

    const result = await importProfileFile(file);

    assert.equal(result.applied, 1);
    assert.deepEqual(result.importedKeys, ["nullid:vault:pref:unlock-rate-limit"]);
    assert.deepEqual(result.skippedKeys.map((entry) => entry.key).sort(), [
      "nullid:vault:data:notes:note-1",
      "nullid:vault:notes:legacy-note",
      "nullid:vault:pref:mfa-credential",
    ]);
    assert.equal(storage.getItem("nullid:vault:pref:unlock-rate-limit"), JSON.stringify(false));
    assert.equal(storage.getItem("nullid:vault:pref:mfa-credential"), null);
  });

  it("throws for unreadable malformed profile JSON", async () => {
    setup();
    const file = new File(["{not json"], "bad-profile.json", { type: "application/json" });

    await assert.rejects(() => importProfileFile(file));
  });

  it("rejects malformed complex profile settings such as empty password settings and null sanitizer rules", async () => {
    const storage = setup();
    const file = await profileFile({
      "nullid:pw-settings": {},
      "nullid:sanitize:custom": [null],
    });

    await assert.rejects(() => importProfileFile(file), /profile import validation failed|profile value failed validation/i);

    assert.equal(storage.length, 0);
  });

  it("rolls back all writes when an intermediate profile import write fails", async () => {
    const storage = setup();
    storage.setItem("nullid:theme", JSON.stringify("dark"));
    const before = storage.snapshot();
    storage.failOnSetKeys = ["nullid:layout-mode"];
    const file = await profileFile({
      "nullid:clipboard:prefs": { enableAutoClearClipboard: true, clipboardClearSeconds: 30 },
      "nullid:layout-mode": "desktop",
      "nullid:theme": "light",
    });

    await assert.rejects(() => importProfileFile(file), /profile import failed|storage write failed|rollback/i);

    assert.deepEqual(storage.snapshot(), before);
  });

  it("rolls back target writes when legacy alias cleanup fails", async () => {
    const storage = setup();
    storage.setItem("nullid:locale", "en");
    storage.setItem("nullid:language", JSON.stringify("ru"));
    const before = storage.snapshot();
    storage.failOnRemoveKeys = ["nullid:language"];
    const file = await profileFile({
      "nullid:language": "fa",
    });

    await assert.rejects(() => importProfileFile(file), /profile import failed|alias|rollback|removeItem/i);

    assert.deepEqual(storage.snapshot(), before);
  });

  it("reports rollback failure without claiming profile import success", async () => {
    const storage = setup();
    storage.setItem("nullid:clipboard:prefs", JSON.stringify({ enableAutoClearClipboard: false, clipboardClearSeconds: 45 }));
    const before = storage.snapshot();
    storage.failOnSetKeys = ["nullid:layout-mode", "nullid:clipboard:prefs"];
    const file = await profileFile({
      "nullid:clipboard:prefs": { enableAutoClearClipboard: true, clipboardClearSeconds: 30 },
      "nullid:layout-mode": "desktop",
    });

    await assert.rejects(() => importProfileFile(file), /rollback failed/i);

    assert.notDeepEqual(storage.snapshot(), before);
  });
});

async function profileFile(entries: Record<string, unknown>) {
  const exportedAt = new Date("2026-01-01T00:00:00.000Z").toISOString();
  const payload = {
    schemaVersion: PROFILE_SCHEMA_VERSION,
    exportedAt,
    entries,
  };
  const payloadHash = await sha256Base64Url(payload);
  return new File(
    [
      JSON.stringify({
        ...payload,
        kind: "profile",
        integrity: { entryCount: Object.keys(entries).length, payloadHash },
      }),
    ],
    "profile.json",
    { type: "application/json" },
  );
}
