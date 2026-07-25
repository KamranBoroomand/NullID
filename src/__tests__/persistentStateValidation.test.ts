import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readPersistentStateValue, writePersistentStateValue } from "../hooks/usePersistentState.js";
import {
  classifyProfileExportEntry,
  DEFAULT_LAYOUT_MODE,
  DEFAULT_LOCALE,
  DEFAULT_THEME_MODE,
  getPersistentStateSchemaMatrix,
  getProfileSchemaMatrix,
  isLayoutMode,
  isThemeMode,
  readPersistedLocale,
  validateProfileEntryValue,
} from "../utils/persistedSettings.js";
import {
  findKeyHintProfileById,
  readLegacyProfiles,
  removeProfileHint,
  SHARED_KEY_HINT_PROFILE_KEY,
  type KeyHintProfile,
} from "../utils/keyHintProfiles.js";
import { getRuleKeys } from "../utils/sanitizeEngine.js";
import { VAULT_PREFERENCE_STATE_KEYS } from "../utils/vaultStorageKeys.js";

class MemoryStorage implements Storage {
  private map = new Map<string, string>();
  failOnSetKey: string | null = null;
  failOnRemoveKey: string | null = null;
  setCounts = new Map<string, number>();
  removeCounts = new Map<string, number>();

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
    if (this.failOnRemoveKey === key) throw new Error(`blocked remove ${key}`);
    this.removeCounts.set(key, (this.removeCounts.get(key) ?? 0) + 1);
    this.map.delete(key);
  }

  setItem(key: string, value: string) {
    if (this.failOnSetKey === key) throw new Error(`blocked set ${key}`);
    this.setCounts.set(key, (this.setCounts.get(key) ?? 0) + 1);
    this.map.set(key, value);
  }
}

describe("persistent state validation", () => {
  it("falls back and clears malformed JSON", () => {
    const storage = new MemoryStorage();
    storage.setItem("nullid:theme", "{not json");

    const value = readPersistentStateValue(storage, { key: "nullid:theme", validator: isThemeMode }, DEFAULT_THEME_MODE);

    assert.equal(value, "dark");
    assert.equal(storage.getItem("nullid:theme"), null);
  });

  it("rejects invalid theme values including unsupported system mode", () => {
    const storage = new MemoryStorage();
    storage.setItem("nullid:theme", JSON.stringify("system"));

    const value = readPersistentStateValue(storage, { key: "nullid:theme", validator: isThemeMode }, DEFAULT_THEME_MODE);

    assert.equal(value, "dark");
    assert.equal(storage.getItem("nullid:theme"), null);
  });

  it("rejects invalid persisted layout modes", () => {
    const storage = new MemoryStorage();
    storage.setItem("nullid:layout-mode", JSON.stringify("sideways"));

    const value = readPersistentStateValue(storage, { key: "nullid:layout-mode", validator: isLayoutMode }, DEFAULT_LAYOUT_MODE);

    assert.equal(value, "auto");
    assert.equal(storage.getItem("nullid:layout-mode"), null);
  });

  it("rejects non-boolean values for boolean state", () => {
    const storage = new MemoryStorage();
    storage.setItem("nullid:onboarding-complete", JSON.stringify({}));

    const value = readPersistentStateValue(storage, "nullid:onboarding-complete", false);

    assert.equal(value, false);
    assert.equal(storage.getItem("nullid:onboarding-complete"), null);
  });

  it("falls back to the default locale for invalid persisted language values", () => {
    const storage = new MemoryStorage();
    storage.setItem("nullid:locale", JSON.stringify("bad"));
    storage.setItem("nullid:language", JSON.stringify("also-bad"));

    const locale = readPersistedLocale(storage);

    assert.equal(locale, DEFAULT_LOCALE);
    assert.equal(storage.getItem("nullid:locale"), null);
    assert.equal(storage.getItem("nullid:language"), null);
  });

  it("migrates a valid legacy language key to the current locale key", () => {
    const storage = new MemoryStorage();
    storage.setItem("nullid:language", JSON.stringify("fa"));

    const locale = readPersistedLocale(storage);

    assert.equal(locale, "fa");
    assert.equal(storage.getItem("nullid:locale"), "fa");
    assert.equal(storage.getItem("nullid:language"), null);
  });

  it("uses exact profile schemas when loading complex persisted settings", () => {
    const storage = new MemoryStorage();
    const passwordDefaults = {
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
    storage.setItem("nullid:pw-settings", JSON.stringify({}));

    const value = readPersistentStateValue(storage, "nullid:pw-settings", passwordDefaults);

    assert.deepEqual(value, passwordDefaults);
    assert.equal(storage.getItem("nullid:pw-settings"), null);
  });

  it("treats the self-test interval consistently as bounded seconds", () => {
    for (const intervalSeconds of [30, 180, 3600]) {
      const storage = new MemoryStorage();
      storage.setItem("nullid:selftest:interval", JSON.stringify(intervalSeconds));

      assert.equal(readPersistentStateValue(storage, "nullid:selftest:interval", 180), intervalSeconds);
      assert.equal(validateProfileEntryValue("nullid:selftest:interval", intervalSeconds).status, "import");
      assert.equal(classifyProfileExportEntry("nullid:selftest:interval", JSON.stringify(intervalSeconds)).status, "export");
      assert.equal(storage.getItem("nullid:selftest:interval"), JSON.stringify(intervalSeconds));
    }

    const storage = new MemoryStorage();
    storage.setItem("nullid:selftest:interval", JSON.stringify(5000));

    assert.equal(readPersistentStateValue(storage, "nullid:selftest:interval", 180), 180);
    assert.equal(storage.getItem("nullid:selftest:interval"), null);
    assert.equal(validateProfileEntryValue("nullid:selftest:interval", 5000).status, "invalid");
  });

  it("validates private MFA persisted state exactly while keeping it out of profile import/export", () => {
    const mfaStorageKey = VAULT_PREFERENCE_STATE_KEYS.mfaCredential.key;
    const validCredential = { id: "AQIDBA", label: "Touch ID", createdAt: 1_735_689_600_000 };
    const invalidCredentials = [
      42,
      {},
      { id: 123, createdAt: validCredential.createdAt },
      { id: "not base64url!", createdAt: validCredential.createdAt },
      { id: validCredential.id, createdAt: "2026-01-01T00:00:00.000Z" },
      { id: validCredential.id, label: "x".repeat(49), createdAt: validCredential.createdAt },
      { id: validCredential.id, label: "Touch ID", createdAt: validCredential.createdAt, extra: true },
    ];

    for (const credential of invalidCredentials) {
      const storage = new MemoryStorage();
      storage.setItem(mfaStorageKey, JSON.stringify(credential));

      assert.equal(readPersistentStateValue(storage, mfaStorageKey, null), null);
      assert.equal(storage.getItem(mfaStorageKey), null);
    }

    const storage = new MemoryStorage();
    storage.setItem(mfaStorageKey, JSON.stringify(validCredential));

    assert.deepEqual(readPersistentStateValue(storage, mfaStorageKey, null), validCredential);
    assert.equal(classifyProfileExportEntry(mfaStorageKey, JSON.stringify(validCredential)).status, "skip");
    assert.equal(validateProfileEntryValue(mfaStorageKey, validCredential).status, "skip");
  });

  it("rejects malformed sanitizer custom rules during local persisted-state loading", () => {
    const storage = new MemoryStorage();
    storage.setItem("nullid:sanitize:custom", JSON.stringify([null]));

    const value = readPersistentStateValue(storage, "nullid:sanitize:custom", []);

    assert.deepEqual(value, []);
    assert.equal(storage.getItem("nullid:sanitize:custom"), null);
  });

  it("rejects ambiguous duplicate IDs and non-canonical timestamps in persisted profile collections", () => {
    const createdAt = "2026-01-01T00:00:00.000Z";
    const updatedAt = "2026-01-02T00:00:00.000Z";
    const keyHint = {
      id: "profile-1",
      name: "Team",
      keyHint: "team-v1",
      version: 1,
      createdAt,
      updatedAt,
    };
    const customRule = {
      id: "rule-1",
      pattern: "secret",
      replacement: "[redacted]",
      flags: "gi",
      scope: "both",
    };
    const policyPack = {
      id: "pack-1",
      name: "Incident",
      createdAt,
      config: {
        rulesState: Object.fromEntries(getRuleKeys().map((key) => [key, true])),
        jsonAware: true,
        customRules: [customRule],
      },
    };

    const invalidCollections: Array<[string, unknown]> = [
      ["nullid:signing:key-hints", [keyHint, { ...keyHint, name: "Other" }]],
      ["nullid:signing:key-hints", [keyHint, { ...keyHint, id: "profile-2", name: " team " }]],
      ["nullid:signing:key-hints", [{ ...keyHint, createdAt: "not-a-date" }]],
      ["nullid:signing:key-hints", [{ ...keyHint, createdAt: updatedAt, updatedAt: createdAt }]],
      ["nullid:sanitize:custom", [customRule, { ...customRule, pattern: "token" }]],
      ["nullid:sanitize:policy-packs", [policyPack, { ...policyPack, name: "Other" }]],
      ["nullid:sanitize:policy-packs", [policyPack, { ...policyPack, id: "pack-2", name: " incident " }]],
      ["nullid:sanitize:policy-packs", [{ ...policyPack, createdAt: "not-a-date" }]],
    ];

    for (const [key, value] of invalidCollections) {
      assert.equal(validateProfileEntryValue(key, value).status, "invalid", key);
      const storage = new MemoryStorage();
      storage.setItem(key, JSON.stringify(value));
      assert.deepEqual(readPersistentStateValue(storage, key, []), []);
      assert.equal(storage.getItem(key), null);
    }
  });

  it("rejects legacy key-hint collections that bypass current exact validation", () => {
    const legacyKey = "nullid:sanitize:key-hints";
    const invalidLegacyProfiles = [
      validKeyHintProfile({ id: "dup", name: "Team", createdAt: "not-a-date" }),
      validKeyHintProfile({ id: "dup", name: "Other", updatedAt: "also-not-a-date" }),
    ];
    const storage = new MemoryStorage();
    storage.setItem(legacyKey, JSON.stringify(invalidLegacyProfiles));

    const migrated = readPersistentStateValue(storage, { key: SHARED_KEY_HINT_PROFILE_KEY, legacyKeys: [legacyKey] }, [] as KeyHintProfile[]);

    assert.deepEqual(readLegacyProfiles(legacyKey, storage), []);
    assert.deepEqual(migrated, []);
    assert.equal(storage.getItem(SHARED_KEY_HINT_PROFILE_KEY), null);
    assert.notEqual(storage.getItem(legacyKey), null);
  });

  it("migrates valid legacy key-hints once, verifies the write, and preserves evidence on blocked migration steps", () => {
    const legacyKey = "nullid:sanitize:key-hints";
    const legacyProfiles = [validKeyHintProfile({ id: "Profile-1", name: " Team " })];

    const storage = new MemoryStorage();
    storage.setItem(legacyKey, JSON.stringify(legacyProfiles));

    const config = { key: SHARED_KEY_HINT_PROFILE_KEY, legacyKeys: [legacyKey] };
    const first = readPersistentStateValue(storage, config, [] as KeyHintProfile[]);
    const second = readPersistentStateValue(storage, config, [] as KeyHintProfile[]);
    const third = readPersistentStateValue(storage, config, [] as KeyHintProfile[]);

    assert.deepEqual(first, second);
    assert.deepEqual(second, third);
    assert.equal(first[0]?.id, "Profile-1");
    assert.equal(first[0]?.name, "Team");
    assert.equal(storage.getItem(legacyKey), null);
    assert.equal(storage.setCounts.get(SHARED_KEY_HINT_PROFILE_KEY), 1);
    assert.equal(storage.removeCounts.get(legacyKey), 1);

    const blockedWrite = new MemoryStorage();
    blockedWrite.setItem(legacyKey, JSON.stringify(legacyProfiles));
    blockedWrite.failOnSetKey = SHARED_KEY_HINT_PROFILE_KEY;
    assert.deepEqual(readPersistentStateValue(blockedWrite, config, [] as KeyHintProfile[]), first);
    assert.equal(blockedWrite.getItem(SHARED_KEY_HINT_PROFILE_KEY), null);
    assert.notEqual(blockedWrite.getItem(legacyKey), null);

    const blockedRemoval = new MemoryStorage();
    blockedRemoval.setItem(legacyKey, JSON.stringify(legacyProfiles));
    blockedRemoval.failOnRemoveKey = legacyKey;
    assert.deepEqual(readPersistentStateValue(blockedRemoval, config, [] as KeyHintProfile[]), first);
    assert.deepEqual(readPersistentStateValue(blockedRemoval, config, [] as KeyHintProfile[]), first);
    assert.notEqual(blockedRemoval.getItem(SHARED_KEY_HINT_PROFILE_KEY), null);
    assert.notEqual(blockedRemoval.getItem(legacyKey), null);
    assert.equal(blockedRemoval.setCounts.get(SHARED_KEY_HINT_PROFILE_KEY), 1);
  });

  it("validates direct persisted key-hint writes instead of trusting setter output", () => {
    const storage = new MemoryStorage();
    const invalidProfiles = [
      validKeyHintProfile({ id: "dup", name: "One" }),
      validKeyHintProfile({ id: "dup", name: "Two" }),
    ];

    assert.throws(
      () => writePersistentStateValue(storage, SHARED_KEY_HINT_PROFILE_KEY, invalidProfiles),
      /validation|duplicate|key hint/i,
    );
    assert.equal(storage.getItem(SHARED_KEY_HINT_PROFILE_KEY), null);
  });

  it("rejects case and Unicode canonical identity collisions across semantic collections", () => {
    const createdAt = "2026-01-01T00:00:00.000Z";
    const keyHint = validKeyHintProfile({ id: "Profile-1", name: "É", createdAt, updatedAt: createdAt });
    const customRule = {
      id: "Rule-1",
      pattern: "secret",
      replacement: "[redacted]",
      flags: "gi",
      scope: "both",
    };
    const policyPack = {
      id: "Pack-1",
      name: "É",
      createdAt,
      config: {
        rulesState: Object.fromEntries(getRuleKeys().map((key) => [key, true])),
        jsonAware: true,
        customRules: [customRule],
      },
    };

    const invalidCollections: Array<[string, unknown]> = [
      [SHARED_KEY_HINT_PROFILE_KEY, [keyHint, { ...keyHint, id: "profile-1", name: "Other" }]],
      [SHARED_KEY_HINT_PROFILE_KEY, [keyHint, { ...keyHint, id: "Profile-2", name: "e\u0301" }]],
      [SHARED_KEY_HINT_PROFILE_KEY, [keyHint, { ...keyHint, id: "e\u0301", name: "Other" }, { ...keyHint, id: "É", name: "Third" }]],
      ["nullid:sanitize:custom", [customRule, { ...customRule, id: "rule-1", pattern: "token" }]],
      ["nullid:sanitize:custom", [customRule, { ...customRule, id: "Ru\u0301le-2", pattern: "token" }, { ...customRule, id: "Rúle-2", pattern: "other" }]],
      ["nullid:sanitize:policy-packs", [policyPack, { ...policyPack, id: "pack-1", name: "Other" }]],
      ["nullid:sanitize:policy-packs", [policyPack, { ...policyPack, id: "Pack-2", name: "e\u0301" }]],
    ];

    for (const [key, value] of invalidCollections) {
      assert.equal(validateProfileEntryValue(key, value).status, "invalid", key);
      const storage = new MemoryStorage();
      storage.setItem(key, JSON.stringify(value));
      assert.deepEqual(readPersistentStateValue(storage, key, []), []);
      assert.equal(storage.getItem(key), null);
    }
  });

  it("restricts machine identifiers to ASCII while treating Unicode names as display text", () => {
    const createdAt = "2026-01-01T00:00:00.000Z";
    const unicodeDisplayProfiles = [
      validKeyHintProfile({ id: "profile-alpha", name: "Straße", createdAt, updatedAt: createdAt }),
      validKeyHintProfile({ id: "profile-beta", name: "STRASSE", createdAt, updatedAt: createdAt }),
      validKeyHintProfile({ id: "profile-gamma", name: "ΟΣ", createdAt, updatedAt: createdAt }),
      validKeyHintProfile({ id: "profile-delta", name: "οσ", createdAt, updatedAt: createdAt }),
    ];

    assert.equal(validateProfileEntryValue(SHARED_KEY_HINT_PROFILE_KEY, unicodeDisplayProfiles).status, "import");
    assert.equal(findKeyHintProfileById(unicodeDisplayProfiles, "PROFILE-ALPHA")?.name, "Straße");
    assert.deepEqual(removeProfileHint(unicodeDisplayProfiles, "PROFILE-ALPHA").map((profile) => profile.id), [
      "profile-beta",
      "profile-gamma",
      "profile-delta",
    ]);

    const customRule = {
      id: "rule-alpha",
      pattern: "secret",
      replacement: "[redacted]",
      flags: "gi",
      scope: "both",
    };
    const policyPack = {
      id: "pack-alpha",
      name: "Σ",
      createdAt,
      config: {
        rulesState: Object.fromEntries(getRuleKeys().map((key) => [key, true])),
        jsonAware: true,
        customRules: [customRule],
      },
    };
    const invalidMachineIds: Array<[string, unknown]> = [
      [SHARED_KEY_HINT_PROFILE_KEY, [{ ...unicodeDisplayProfiles[0], id: "Straße" }]],
      [SHARED_KEY_HINT_PROFILE_KEY, [{ ...unicodeDisplayProfiles[0], id: "Σ" }]],
      ["nullid:sanitize:custom", [{ ...customRule, id: "rule-ς" }]],
      ["nullid:sanitize:policy-packs", [{ ...policyPack, id: "πακέτο" }]],
    ];

    for (const [key, value] of invalidMachineIds) {
      assert.equal(validateProfileEntryValue(key, value).status, "invalid", key);
    }
  });

  it("documents exact profile schemas for every sensitive profile key class", () => {
    const matrix = getProfileSchemaMatrix();
    const byKey = new Map(matrix.map((entry) => [entry.key, entry]));
    const persistedByKey = new Map(getPersistentStateSchemaMatrix().map((entry) => [entry.key, entry]));

    assert.equal(matrix.length, byKey.size);
    assert.equal(byKey.get("nullid:locale")?.encoding, "raw");
    assert.equal(persistedByKey.get("nullid:vault:pref:mfa-credential")?.profilePolicy, "private-local-only");
    assert.match(persistedByKey.get("nullid:selftest:interval")?.description ?? "", /seconds/i);
    for (const key of [
      "nullid:pw-settings",
      "nullid:pp-settings",
      "nullid:sanitize:rules",
      "nullid:sanitize:custom",
      "nullid:sanitize:policy-packs",
      "nullid:batch:rule-sets",
      "nullid:analyze:rule-sets",
      "nullid:financial:rule-sets",
      "nullid:redact:rule-sets",
      "nullid:redact:detectors",
      "nullid:clipboard:prefs",
      "nullid:vault:pref:unlock-throttle",
      "nullid:signing:key-hints",
    ]) {
      assert.ok(byKey.get(key)?.description, key);
    }
  });
});

function validKeyHintProfile(overrides: Partial<KeyHintProfile> = {}): KeyHintProfile {
  return {
    id: "profile-1",
    name: "Team",
    keyHint: "team-v1",
    version: 1,
    createdAt: "2026-01-01T00:00:00.000Z",
    updatedAt: "2026-01-02T00:00:00.000Z",
    ...overrides,
  };
}
