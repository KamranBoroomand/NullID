import type { PersistentStateConfig } from "../hooks/usePersistentState.js";

const VAULT_STORAGE_ROOT = "nullid:vault:";
const VAULT_PREFS_SEGMENT = "pref:";
const VAULT_DATA_SEGMENT = "data:";

const VAULT_PREFERENCE_PREFIX = `${VAULT_STORAGE_ROOT}${VAULT_PREFS_SEGMENT}`;
const VAULT_DATA_PREFIX = `${VAULT_STORAGE_ROOT}${VAULT_DATA_SEGMENT}`;
const LEGACY_VAULT_PREFIX = VAULT_STORAGE_ROOT;
const VAULT_FALLBACK_STORES = ["notes", "meta", "canary", "selftest"] as const;

export const VAULT_PREFERENCE_STATE_KEYS = {
  selectedKeyHintProfileId: createVaultPreferenceStateConfig("key-hint-selected"),
  unlockRateLimitEnabled: createVaultPreferenceStateConfig("unlock-rate-limit"),
  unlockHumanCheckEnabled: createVaultPreferenceStateConfig("unlock-human-check"),
  unlockThrottle: createVaultPreferenceStateConfig("unlock-throttle"),
  sessionCookieEnabled: createVaultPreferenceStateConfig("session-cookie-enabled"),
  mfaCredential: createVaultPreferenceStateConfig("mfa-credential"),
} as const;

function createVaultPreferenceStateConfig(name: string): PersistentStateConfig {
  return {
    key: vaultPreferenceKey(name),
    legacyKeys: [legacyVaultPreferenceKey(name)],
  };
}

function vaultPreferenceKey(name: string): string {
  return `${VAULT_PREFERENCE_PREFIX}${name}`;
}

function legacyVaultPreferenceKey(name: string): string {
  return `${LEGACY_VAULT_PREFIX}${name}`;
}

export function vaultFallbackStorageKey(store: string, key: IDBValidKey): string {
  return `${VAULT_DATA_PREFIX}${store}:${String(key)}`;
}

function vaultFallbackStoragePrefix(store: string): string {
  return `${VAULT_DATA_PREFIX}${store}:`;
}

function legacyVaultFallbackStoragePrefix(store: string): string {
  return `${LEGACY_VAULT_PREFIX}${store}:`;
}

export function isVaultLocalStorageRecordKey(key: string): boolean {
  if (key.startsWith(VAULT_DATA_PREFIX)) return true;
  return VAULT_FALLBACK_STORES.some(
    (store) => key.startsWith(vaultFallbackStoragePrefix(store)) || key.startsWith(legacyVaultFallbackStoragePrefix(store)),
  );
}
