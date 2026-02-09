import { useEffect } from "react";
import { usePersistentState } from "../hooks/usePersistentState";
export const defaultClipboardPrefs = {
    enableAutoClearClipboard: true,
    clipboardClearSeconds: 30,
};
export async function writeClipboard(value, prefs, reporter, successLabel = "copied") {
    try {
        await navigator.clipboard.writeText(value);
        reporter?.(successLabel, "accent");
        if (prefs.enableAutoClearClipboard && prefs.clipboardClearSeconds > 0) {
            window.setTimeout(() => {
                void navigator.clipboard.writeText("").catch(() => { });
            }, prefs.clipboardClearSeconds * 1000);
        }
        return { ok: true };
    }
    catch (error) {
        console.error(error);
        const message = "clipboard unavailable";
        reporter?.(message, "danger");
        return { ok: false, error: message };
    }
}
export function useClipboardPrefs() {
    const [prefs, setPrefs] = usePersistentState("nullid:clipboard:prefs", defaultClipboardPrefs);
    useEffect(() => {
        const handleStorage = (event) => {
            if (event.key === "nullid:clipboard:prefs" && event.newValue) {
                try {
                    setPrefs(JSON.parse(event.newValue));
                }
                catch {
                    // ignore malformed updates
                }
            }
        };
        const handleCustom = (event) => {
            const custom = event;
            if (custom.detail) {
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
    const setSharedPrefs = (update) => {
        setPrefs((prev) => {
            const next = typeof update === "function" ? update(prev) : update;
            window.dispatchEvent(new CustomEvent("nullid:clipboard-sync", { detail: next }));
            return next;
        });
    };
    return [prefs, setSharedPrefs];
}
