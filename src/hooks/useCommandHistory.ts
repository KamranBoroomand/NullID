import { useCallback, useEffect, useMemo, useRef, useState } from "react";

const HISTORY_LIMIT = 50;

function normalizeEntries(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const entries: string[] = [];
  value.forEach((entry) => {
    if (typeof entry !== "string") return;
    const trimmed = entry.trim();
    if (!trimmed) return;
    const previous = entries.indexOf(trimmed);
    if (previous >= 0) entries.splice(previous, 1);
    entries.push(trimmed);
  });
  return entries.slice(-HISTORY_LIMIT);
}

function readEntries(storageKey: string): string[] {
  try {
    const stored = localStorage.getItem(storageKey);
    return stored ? normalizeEntries(JSON.parse(stored)) : [];
  } catch {
    return [];
  }
}

export function useCommandHistory(key: string) {
  const storageKey = `nullid-history:${key}`;
  const [entries, setEntries] = useState<string[]>(() => readEntries(storageKey));
  const cursor = useRef<number>(entries.length);

  useEffect(() => {
    const stored = readEntries(storageKey);
    setEntries(stored);
    cursor.current = stored.length;
  }, [storageKey]);

  useEffect(() => {
    const safeEntries = entries.slice(-HISTORY_LIMIT);
    cursor.current = entries.length;
    try {
      localStorage.setItem(storageKey, JSON.stringify(safeEntries));
    } catch {
      // History is a convenience cache; command execution must not depend on storage.
    }
  }, [entries, storageKey]);

  const push = useCallback((value: string) => {
    const trimmed = value.trim();
    if (!trimmed) return;
    setEntries((prev) => normalizeEntries([...prev.filter((entry) => entry !== trimmed), trimmed]));
  }, []);

  const navigate = useCallback((delta: 1 | -1): string => {
    const next = Math.min(Math.max(0, cursor.current + delta), entries.length);
    cursor.current = next;
    return entries[next] ?? "";
  }, [entries]);

  const resetCursor = useCallback(() => {
    cursor.current = entries.length;
  }, [entries.length]);

  return useMemo(() => ({ entries, push, navigate, resetCursor }), [entries, navigate, push, resetCursor]);
}
