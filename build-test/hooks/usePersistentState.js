import { useEffect, useState } from "react";
export function usePersistentState(key, initial) {
    const [value, setValue] = useState(() => {
        try {
            const stored = localStorage.getItem(key);
            return stored ? JSON.parse(stored) : initial;
        }
        catch {
            return initial;
        }
    });
    useEffect(() => {
        try {
            localStorage.setItem(key, JSON.stringify(value));
        }
        catch (error) {
            console.warn("persistent state write blocked", error);
        }
    }, [key, value]);
    return [value, setValue];
}
