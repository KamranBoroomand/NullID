import type { PersistentStateConfig } from "../hooks/usePersistentState.js";

const VAULT_STORAGE_ROOT = "nullid:vault:";
const VAULT_PREFS_SEGMENT = "pref:";
const VAULT_DATA_SEGMENT = "data:";

export const VAULT_PREFERENCE_PREFIX = `${VAULT_STORAGE_ROOT}${VAULT_PREFS_SEGMENT}`;
export const VAULT_DATA_PREFIX = `${VAULT_STORAGE_ROOT}${VAULT_DATA_SEGMENT}`;
export const LEGACY_VAULT_PREFIX = VAULT_STORAGE_ROOT;
export const VAULT_FALLBACK_STORES = ["notes", "meta", "canary", "selftest"] as const;

export const VAULT_PREFERENCE_STATE_KEYS = {
  selectedKeyHintProfileId: createVaultPreferenceStateConfig("key-hint-selected"),
  unlockRateLimitEnabled: createVaultPreferenceStateConfig("unlock-rate-limit"),
  unlockHumanCheckEnabled: createVaultPreferenceStateConfig("unlock-human-check"),
  unlockThrottle: createVaultPreferenceStateConfig("unlock-throttle"),
  sessionCookieEnabled: createVaultPreferenceStateConfig("session-cookie-enabled"),
  mfaCredential: createVaultPreferenceStateConfig("mfa-credential"),
} as const;

export function createVaultPreferenceStateConfig(name: string): PersistentStateConfig {
  return {
    key: vaultPreferenceKey(name),
    legacyKeys: [legacyVaultPreferenceKey(name)],
  };
}

export function vaultPreferenceKey(name: string): string {
  return `${VAULT_PREFERENCE_PREFIX}${name}`;
}

export function legacyVaultPreferenceKey(name: string): string {
  return `${LEGACY_VAULT_PREFIX}${name}`;
}

export function vaultFallbackStorageKey(store: string, key: IDBValidKey): string {
  return `${VAULT_DATA_PREFIX}${store}:${String(key)}`;
}

export function vaultFallbackStoragePrefix(store: string): string {
  return `${VAULT_DATA_PREFIX}${store}:`;
}

export function legacyVaultFallbackStorageKey(store: string, key: IDBValidKey): string {
  return `${LEGACY_VAULT_PREFIX}${store}:${String(key)}`;
}

export function legacyVaultFallbackStoragePrefix(store: string): string {
  return `${LEGACY_VAULT_PREFIX}${store}:`;
}

export function getVaultFallbackKeyCandidates(store: string, key: IDBValidKey): string[] {
  const primary = vaultFallbackStorageKey(store, key);
  if (!isVaultFallbackStore(store)) return [primary];
  return [primary, legacyVaultFallbackStorageKey(store, key)];
}

export function getVaultFallbackStorePrefixes(store: string): string[] {
  const primary = vaultFallbackStoragePrefix(store);
  if (!isVaultFallbackStore(store)) return [primary];
  return [primary, legacyVaultFallbackStoragePrefix(store)];
}

export function isVaultLocalStorageRecordKey(key: string): boolean {
  return VAULT_FALLBACK_STORES.some(
    (store) => key.startsWith(vaultFallbackStoragePrefix(store)) || key.startsWith(legacyVaultFallbackStoragePrefix(store)),
  );
}

function isVaultFallbackStore(store: string): boolean {
  return (VAULT_FALLBACK_STORES as readonly string[]).includes(store);
}
