import { useEffect, useRef, useState } from "react";
export function useCommandHistory(key) {
    const storageKey = `nullid-history:${key}`;
    const [entries, setEntries] = useState(() => {
        try {
            const stored = localStorage.getItem(storageKey);
            return stored ? JSON.parse(stored) : [];
        }
        catch {
            return [];
        }
    });
    const cursor = useRef(entries.length);
    useEffect(() => {
        cursor.current = entries.length;
        localStorage.setItem(storageKey, JSON.stringify(entries.slice(-50)));
    }, [entries, storageKey]);
    const push = (value) => {
        if (!value.trim())
            return;
        setEntries((prev) => [...prev.filter((entry) => entry !== value), value]);
    };
    const navigate = (delta) => {
        const next = Math.min(Math.max(0, cursor.current + delta), entries.length);
        cursor.current = next;
        return entries[next] ?? "";
    };
    const resetCursor = () => {
        cursor.current = entries.length;
    };
    return { entries, push, navigate, resetCursor };
}
