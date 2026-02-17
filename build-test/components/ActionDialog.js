import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useEffect } from "react";
import { useI18n } from "../i18n";
import "./ActionDialog.css";
export function ActionDialog({ open, title, description, confirmLabel, cancelLabel, confirmDisabled, danger = false, onConfirm, onCancel, children, }) {
    const { t } = useI18n();
    useEffect(() => {
        if (!open)
            return;
        const onKey = (event) => {
            if (event.key === "Escape") {
                event.preventDefault();
                onCancel();
            }
        };
        window.addEventListener("keydown", onKey);
        return () => window.removeEventListener("keydown", onKey);
    }, [onCancel, open]);
    if (!open)
        return null;
    return (_jsx("div", { className: "action-dialog-overlay", role: "dialog", "aria-modal": "true", "aria-label": title, onMouseDown: (event) => {
            if (event.target === event.currentTarget) {
                onCancel();
            }
        }, children: _jsxs("div", { className: "action-dialog-panel", children: [_jsx("div", { className: "action-dialog-header", children: _jsx("h2", { children: title }) }), description ? _jsx("p", { className: "action-dialog-description", children: description }) : null, children ? _jsx("div", { className: "action-dialog-body", children: children }) : null, _jsxs("div", { className: "action-dialog-actions", children: [_jsx("button", { type: "button", className: "button", onClick: onCancel, children: cancelLabel ?? t("app.cancel") }), _jsx("button", { type: "button", className: `button ${danger ? "action-dialog-danger" : ""}`, onClick: onConfirm, disabled: confirmDisabled, children: confirmLabel ?? t("app.confirm") })] })] }) }));
}
