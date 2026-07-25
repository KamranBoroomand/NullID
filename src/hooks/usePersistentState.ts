import { useEffect, useMemo, useState } from "react";
import { normalizePersistentStateValue, type PersistentStateValidator } from "../utils/persistedSettings.js";

export interface PersistentStateConfig {
  key: string;
  legacyKeys?: string[];
  validator?: PersistentStateValidator<unknown>;
}

interface NormalizedPersistentStateConfig {
  key: string;
  legacyKeys: string[];
  validator?: PersistentStateValidator<unknown>;
}

export function usePersistentState<T>(keyOrConfig: string | PersistentStateConfig, initial: T) {
  const config = useMemo(() => normalizePersistentStateConfig(keyOrConfig), [keyOrConfig]);
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
  }, [config, legacyKeySignature, value]);

  return [value, setValue] as const;
}

export function readPersistentStateValue<T>(storage: Storage, keyOrConfig: string | PersistentStateConfig, initial: T): T {
  const config = normalizePersistentStateConfig(keyOrConfig);
  const keys = [config.key, ...config.legacyKeys];
  for (const key of keys) {
    const stored = storage.getItem(key);
    if (stored == null) continue;
    try {
      const value = JSON.parse(stored) as unknown;
      const normalized = normalizePersistentStateValue(config.key, value, initial, config.validator as PersistentStateValidator<T> | undefined);
      if (!normalized.ok) {
        reportInvalidPersistentState(key);
        if (key === config.key) {
          try {
            storage.removeItem(key);
          } catch {
            // Best-effort cleanup only.
          }
        }
        continue;
      }
      if (key !== config.key) {
        migrateLegacyPersistentStateValue(storage, config.key, key, normalized.value);
      }
      return normalized.value;
    } catch {
      reportInvalidPersistentState(key);
      if (key === config.key) {
        try {
          storage.removeItem(key);
        } catch {
          // Best-effort cleanup only.
        }
      }
    }
  }
  return initial;
}

export function writePersistentStateValue<T>(storage: Storage, keyOrConfig: string | PersistentStateConfig, value: T) {
  const config = normalizePersistentStateConfig(keyOrConfig);
  const normalized = normalizePersistentStateValue(config.key, value, value, config.validator as PersistentStateValidator<T> | undefined);
  if (!normalized.ok) {
    throw new Error(`persistent state validation failed for ${config.key}`);
  }
  storage.setItem(config.key, JSON.stringify(normalized.value));
  config.legacyKeys.forEach((legacyKey) => storage.removeItem(legacyKey));
}

function migrateLegacyPersistentStateValue(storage: Storage, currentKey: string, legacyKey: string, value: unknown) {
  const serialized = JSON.stringify(value);
  try {
    storage.setItem(currentKey, serialized);
    if (storage.getItem(currentKey) !== serialized) {
      throw new Error("persistent state migration verification failed");
    }
  } catch (error) {
    reportPersistentMigrationIssue(`persistent state migration write blocked for ${legacyKey}`, error);
    return;
  }

  try {
    storage.removeItem(legacyKey);
  } catch (error) {
    reportPersistentMigrationIssue(`persistent state legacy cleanup blocked for ${legacyKey}`, error);
  }
}

function normalizePersistentStateConfig(keyOrConfig: string | PersistentStateConfig): NormalizedPersistentStateConfig {
  if (typeof keyOrConfig === "string") {
    return { key: keyOrConfig, legacyKeys: [] };
  }
  return {
    key: keyOrConfig.key,
    legacyKeys: Array.from(new Set((keyOrConfig.legacyKeys ?? []).filter((key) => key && key !== keyOrConfig.key))),
    validator: keyOrConfig.validator,
  };
}

function reportInvalidPersistentState(key: string) {
  if (typeof console !== "undefined" && typeof console.warn === "function") {
    console.warn("invalid persistent state removed", { key });
  }
}

function reportPersistentMigrationIssue(message: string, error: unknown) {
  if (typeof console !== "undefined" && typeof console.warn === "function") {
    console.warn(message, error);
  }
}
