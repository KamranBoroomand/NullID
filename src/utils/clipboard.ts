import { useEffect } from "react";
import { usePersistentState } from "../hooks/usePersistentState.js";
import { isClipboardPrefs } from "./persistedSettings.js";

export type ClipboardPrefs = {
  enableAutoClearClipboard: boolean;
  clipboardClearSeconds: number;
};

export const defaultClipboardPrefs: ClipboardPrefs = {
  enableAutoClearClipboard: true,
  clipboardClearSeconds: 30,
};

export type ClipboardReporter = (message: string, tone?: "neutral" | "accent" | "danger") => void;

export interface ClipboardResult {
  ok: boolean;
  error?: string;
}

type ClipboardClearReason = "changed" | "read-unavailable" | "read-failed" | "write-failed";

export interface ClipboardClearResult {
  cleared: boolean;
  reason?: ClipboardClearReason;
}

export interface ClipboardTextAccess {
  readText?: () => Promise<string>;
  writeText: (value: string) => Promise<void>;
}

export async function writeClipboard(
  value: string,
  prefs: ClipboardPrefs,
  reporter?: ClipboardReporter,
  successLabel = "copied",
): Promise<ClipboardResult> {
  try {
    await navigator.clipboard.writeText(value);
    reporter?.(successLabel, "accent");
    if (prefs.enableAutoClearClipboard && prefs.clipboardClearSeconds > 0) {
      const clipboard = navigator.clipboard;
      window.setTimeout(() => {
        void clearClipboardIfUnchanged(value, clipboard);
      }, prefs.clipboardClearSeconds * 1000);
    }
    return { ok: true };
  } catch {
    const message = "clipboard unavailable";
    reporter?.(message, "danger");
    return { ok: false, error: message };
  }
}

export async function clearClipboardIfUnchanged(originalValue: string, clipboard: ClipboardTextAccess = navigator.clipboard): Promise<ClipboardClearResult> {
  if (typeof clipboard.readText !== "function") {
    return { cleared: false, reason: "read-unavailable" };
  }

  let currentValue: string;
  try {
    currentValue = await clipboard.readText();
  } catch {
    return { cleared: false, reason: "read-failed" };
  }

  if (currentValue !== originalValue) {
    return { cleared: false, reason: "changed" };
  }

  try {
    await clipboard.writeText("");
    return { cleared: true };
  } catch {
    return { cleared: false, reason: "write-failed" };
  }
}

export function useClipboardPrefs() {
  const [prefs, setPrefs] = usePersistentState<ClipboardPrefs>(
    { key: "nullid:clipboard:prefs", validator: isClipboardPrefs },
    defaultClipboardPrefs,
  );

  useEffect(() => {
    const handleStorage = (event: StorageEvent) => {
      if (event.key === "nullid:clipboard:prefs" && event.newValue) {
        try {
          const parsed = JSON.parse(event.newValue) as unknown;
          if (isClipboardPrefs(parsed)) {
            setPrefs(parsed);
          }
        } catch {
          // ignore malformed updates
        }
      }
    };
    const handleCustom = (event: Event) => {
      const custom = event as CustomEvent<ClipboardPrefs>;
      if (isClipboardPrefs(custom.detail)) {
        setPrefs(custom.detail);
      }
    };
    window.addEventListener("storage", handleStorage);
    window.addEventListener("nullid:clipboard-sync", handleCustom);
    return () => {
      window.removeEventListener("storage", handleStorage);
      window.removeEventListener("nullid:clipboard-sync", handleCustom);
    };
  }, [setPrefs]);

  const setSharedPrefs = (update: ClipboardPrefs | ((prev: ClipboardPrefs) => ClipboardPrefs)) => {
    setPrefs((prev) => {
      const next = typeof update === "function" ? (update as (prev: ClipboardPrefs) => ClipboardPrefs)(prev) : update;
      window.dispatchEvent(new CustomEvent("nullid:clipboard-sync", { detail: next }));
      return next;
    });
  };

  return [prefs, setSharedPrefs] as const;
}
