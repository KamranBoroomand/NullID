import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { PROFILE_SCHEMA_VERSION, collectProfile, importProfileFile, verifyProfilePayload } from "../utils/profile.js";
import { sha256Base64Url } from "../utils/integrity.js";

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

describe("profile integrity", () => {
  const setup = () => {
    const storage = new MemoryStorage();
    Object.defineProperty(globalThis, "localStorage", { value: storage, configurable: true, writable: true });
    storage.setItem("nullid:theme", JSON.stringify("dark"));
    storage.setItem("nullid:pw-settings", JSON.stringify(validPasswordSettings()));
    storage.setItem("nullid:vault:pref:unlock-rate-limit", JSON.stringify(true));
    storage.setItem("nullid:vault:notes:note-1", JSON.stringify({ ciphertext: "secret", iv: "0123456789ab" }));
    storage.setItem("nullid:vault:meta:meta", JSON.stringify({ salt: "vault-salt", iterations: 200_000 }));
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
    assert.equal(result.applied, 3);
    assert.equal(result.signed, true);
    assert.equal(result.verified, true);
    assert.equal(result.legacy, false);
    assert.equal(storage.getItem("nullid:theme"), JSON.stringify("dark"));
  });

  it("excludes localStorage fallback vault records from profile snapshots", async () => {
    setup();
    const snapshot = await collectProfile();
    assert.equal("nullid:vault:notes:note-1" in snapshot.entries, false);
    assert.equal("nullid:vault:meta:meta" in snapshot.entries, false);
    assert.equal(snapshot.entries["nullid:vault:pref:unlock-rate-limit"], true);
  });

  it("exports only explicit non-sensitive profile settings", async () => {
    const storage = setup();
    storage.setItem("nullid:locale", "ru");
    storage.setItem("nullid:clipboard:prefs", JSON.stringify({ enableAutoClearClipboard: true, clipboardClearSeconds: 30 }));
    storage.setItem("nullid:language", JSON.stringify("fa"));

    const sensitiveEntries = [
      ["nullid:enc:plaintext", "PROFILE_SENTINEL_PASSPHRASE_LAB"],
      ["nullid:incident:draft", "PROFILE_SENTINEL_INCIDENT_NOTE"],
      ["nullid:share:input", "PROFILE_SENTINEL_SAFE_SHARE_INPUT"],
      ["nullid:redact:draft", "PROFILE_SENTINEL_REDACTION_DRAFT"],
      ["nullid:feedback-log", "PROFILE_SENTINEL_FEEDBACK_LOG"],
      ["nullid:hash:batch-input", "PROFILE_SENTINEL_HASH_BATCH"],
      ["nullid:workspace:draft", "PROFILE_SENTINEL_WORKSPACE_DRAFT"],
      ["nullid:file:history", "PROFILE_SENTINEL_FILE_HISTORY"],
      ["nullid:vault:data:active-generation", "gprofileleak"],
      ["nullid:vault:data:gen:gprofileleak:meta:meta", "PROFILE_SENTINEL_VAULT_META"],
      ["nullid:vault:data:gen:gprofileleak:canary:canary", "PROFILE_SENTINEL_VAULT_CANARY"],
      ["nullid:vault:data:gen:gprofileleak:notes:note-1", "PROFILE_SENTINEL_VAULT_NOTE"],
      ["nullid:vault:pref:mfa-credential", "PROFILE_SENTINEL_MFA_CREDENTIAL"],
      ["nullid:future:unknown-key", "PROFILE_SENTINEL_UNKNOWN_FUTURE"],
    ] as const;

    sensitiveEntries.forEach(([key, sentinel]) => {
      storage.setItem(key, JSON.stringify({ sentinel }));
    });

    const snapshot = await collectProfile();
    const serialized = JSON.stringify(snapshot);

    assert.equal(snapshot.entries["nullid:theme"], "dark");
    assert.equal(snapshot.entries["nullid:locale"], "ru");
    assert.deepEqual(snapshot.entries["nullid:clipboard:prefs"], { enableAutoClearClipboard: true, clipboardClearSeconds: 30 });
    assert.equal("nullid:language" in snapshot.entries, false);

    for (const [key, sentinel] of sensitiveEntries) {
      assert.equal(key in snapshot.entries, false, key);
      assert.equal(serialized.includes(key), false, key);
      assert.equal(serialized.includes(sentinel), false, sentinel);
    }
  });

  it("describes profile export as supported non-sensitive preferences in UI copy", () => {
    const appSource = fs.readFileSync("src/App.tsx", "utf8");
    const translationsSource = fs.readFileSync("src/i18n.tsx", "utf8");
    const accurateCopy = "Export supported non-sensitive preferences and configuration as JSON.";

    assert.match(appSource, new RegExp(escapeRegExp(accurateCopy)));
    assert.match(translationsSource, new RegExp(escapeRegExp(accurateCopy)));
    assert.doesNotMatch(appSource, /Export local nullid:\* settings as JSON/);
    assert.doesNotMatch(translationsSource, /Export local nullid:\* settings as JSON/);
  });

  it("does not export malformed recognized profile settings from current storage", async () => {
    const storage = setup();
    storage.setItem("nullid:pw-settings", JSON.stringify({}));
    storage.setItem("nullid:sanitize:custom", JSON.stringify([null]));
    storage.setItem("nullid:clipboard:prefs", JSON.stringify({ enableAutoClearClipboard: true, clipboardClearSeconds: 30, extra: true }));

    const snapshot = await collectProfile();

    assert.equal("nullid:pw-settings" in snapshot.entries, false);
    assert.equal("nullid:sanitize:custom" in snapshot.entries, false);
    assert.equal("nullid:clipboard:prefs" in snapshot.entries, false);
    assert.equal(snapshot.entries["nullid:theme"], "dark");
  });

  it("does not verify a profile with invalid recognized entries as usable", async () => {
    setup();
    const exportedAt = new Date("2026-01-01T00:00:00.000Z").toISOString();
    const entries = {
      "nullid:theme": "dark",
      "nullid:pw-settings": {},
    };
    const payload = {
      schemaVersion: PROFILE_SCHEMA_VERSION,
      exportedAt,
      kind: "profile" as const,
      entries,
      integrity: {
        entryCount: Object.keys(entries).length,
        payloadHash: await sha256ForTest({ schemaVersion: PROFILE_SCHEMA_VERSION, exportedAt, entries }),
      },
    };

    const verification = await verifyProfilePayload(payload);

    assert.equal(verification.verificationState, "invalid");
    assert.match(verification.failure ?? "", /profile value failed validation|invalid recognized profile entries/i);
  });

  it("rejects deeply nested imported profile JSON without recursive stack overflow", async () => {
    setup();
    let nested: unknown = "leaf";
    for (let depth = 0; depth < 20_000; depth += 1) {
      nested = { next: nested };
    }

    const verification = await verifyProfilePayload({
      schemaVersion: PROFILE_SCHEMA_VERSION,
      exportedAt: new Date("2026-01-01T00:00:00.000Z").toISOString(),
      kind: "profile" as const,
      entries: {
        "nullid:theme": nested,
      },
      integrity: {
        entryCount: 1,
        payloadHash: "0".repeat(64),
      },
    });

    assert.equal(verification.verificationState, "invalid");
    assert.match(verification.failure ?? "", /depth|unsupported value|profile payload/i);
  });

  it("rejects tampered profile payloads", async () => {
    setup();
    const snapshot = await collectProfile({ signingPassphrase: "profile-sign-secret" });
    const tampered = JSON.parse(JSON.stringify(snapshot)) as typeof snapshot;
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

  it("ignores fallback vault records when importing older profile payloads", async () => {
    const storage = setup();
    storage.clear();
    const exportedAt = new Date().toISOString();
    const entries = {
      "nullid:theme": "light",
      "nullid:vault:notes:note-1": { ciphertext: "secret", iv: "0123456789ab" },
    };
    const payloadHash = await sha256ForTest({
      schemaVersion: PROFILE_SCHEMA_VERSION,
      exportedAt,
      entries,
    });
    const file = new File(
      [
        JSON.stringify({
          schemaVersion: PROFILE_SCHEMA_VERSION,
          exportedAt,
          kind: "profile" as const,
          entries,
          integrity: { entryCount: 2, payloadHash },
        }),
      ],
      "profile.json",
      { type: "application/json" },
    );
    const result = await importProfileFile(file);
    assert.equal(result.applied, 1);
    assert.equal(storage.getItem("nullid:theme"), JSON.stringify("light"));
    assert.equal(storage.getItem("nullid:vault:notes:note-1"), null);
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

async function sha256ForTest(payload: unknown) {
  return sha256Base64Url(payload);
}

function validPasswordSettings() {
  return {
    length: 22,
    upper: true,
    lower: true,
    digits: true,
    symbols: true,
    avoidAmbiguity: true,
    enforceMix: true,
    blockSequential: true,
    blockRepeats: true,
    minUniqueChars: 12,
  };
}

function escapeRegExp(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
