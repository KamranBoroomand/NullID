import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { createContext, useCallback, useContext, useMemo, useState } from "react";
import "./ToastHost.css";
const ToastContext = createContext(null);
export function ToastProvider({ children }) {
    const [toasts, setToasts] = useState([]);
    const push = useCallback((message, tone = "neutral") => {
        const id = crypto.randomUUID();
        setToasts((prev) => [...prev.slice(-3), { id, message, tone }]);
        setTimeout(() => {
            setToasts((prev) => prev.filter((toast) => toast.id !== id));
        }, 2800);
    }, []);
    const clear = useCallback(() => setToasts([]), []);
    const value = useMemo(() => ({ push, clear }), [clear, push]);
    return (_jsxs(ToastContext.Provider, { value: value, children: [children, _jsx("div", { className: "toast-host", role: "status", "aria-live": "polite", children: toasts.map((toast) => (_jsx("div", { className: `toast toast-${toast.tone}`, children: toast.message }, toast.id))) })] }));
}
export function useToast() {
    const ctx = useContext(ToastContext);
    if (!ctx) {
        throw new Error("useToast must be used within ToastProvider");
    }
    return ctx;
}
