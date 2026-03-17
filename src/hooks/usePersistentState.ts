import { useEffect, useState } from "react";

export interface PersistentStateConfig {
  key: string;
  legacyKeys?: string[];
}

export function usePersistentState<T>(keyOrConfig: string | PersistentStateConfig, initial: T) {
  const config = normalizePersistentStateConfig(keyOrConfig);
  const legacyKeySignature = config.legacyKeys.join("\0");
  const [value, setValue] = useState<T>(() => {
    try {
      return readPersistentStateValue(localStorage, config, initial);
    } catch {
      return initial;
    }
  });

  useEffect(() => {
    try {
      writePersistentStateValue(localStorage, config, value);
    } catch (error) {
      console.warn("persistent state write blocked", error);
    }
  }, [config.key, legacyKeySignature, value]);

  return [value, setValue] as const;
}

export function readPersistentStateValue<T>(storage: Storage, keyOrConfig: string | PersistentStateConfig, initial: T): T {
  const config = normalizePersistentStateConfig(keyOrConfig);
  const keys = [config.key, ...config.legacyKeys];
  for (const key of keys) {
    const stored = storage.getItem(key);
    if (stored == null) continue;
    try {
      const value = JSON.parse(stored) as T;
      if (key !== config.key) {
        try {
          storage.setItem(config.key, JSON.stringify(value));
          storage.removeItem(key);
        } catch {
          // Preserve legacy keys if migration writes are blocked.
        }
      }
      return value;
    } catch {
      if (key === config.key) return initial;
    }
  }
  return initial;
}

export function writePersistentStateValue<T>(storage: Storage, keyOrConfig: string | PersistentStateConfig, value: T) {
  const config = normalizePersistentStateConfig(keyOrConfig);
  storage.setItem(config.key, JSON.stringify(value));
  config.legacyKeys.forEach((legacyKey) => storage.removeItem(legacyKey));
}

function normalizePersistentStateConfig(keyOrConfig: string | PersistentStateConfig): { key: string; legacyKeys: string[] } {
  if (typeof keyOrConfig === "string") {
    return { key: keyOrConfig, legacyKeys: [] };
  }
  return {
    key: keyOrConfig.key,
    legacyKeys: Array.from(new Set((keyOrConfig.legacyKeys ?? []).filter((key) => key && key !== keyOrConfig.key))),
  };
}
