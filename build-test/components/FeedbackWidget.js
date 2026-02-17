import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useMemo, useState } from "react";
import { usePersistentState } from "../hooks/usePersistentState";
import { useToast } from "./ToastHost";
import { useI18n } from "../i18n";
import "./FeedbackWidget.css";
const storageKey = "nullid:feedback-log";
export function FeedbackWidget({ activeModule }) {
    const { push } = useToast();
    const { t } = useI18n();
    const [open, setOpen] = useState(false);
    const [category, setCategory] = usePersistentState("nullid:feedback-category", "idea");
    const [priority, setPriority] = usePersistentState("nullid:feedback-priority", "medium");
    const [message, setMessage] = usePersistentState("nullid:feedback-draft", "");
    const [entryCount, setEntryCount] = useState(() => loadFeedbackEntries().length);
    const canSave = useMemo(() => message.trim().length >= 8, [message]);
    const handleSave = () => {
        const trimmed = message.trim();
        if (trimmed.length < 8) {
            push("feedback too short (min 8 chars)", "danger");
            return;
        }
        const nextEntry = {
            id: `fb-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
            createdAt: new Date().toISOString(),
            module: activeModule,
            category,
            priority,
            message: trimmed,
        };
        const entries = [nextEntry, ...loadFeedbackEntries()].slice(0, 100);
        localStorage.setItem(storageKey, JSON.stringify(entries));
        setEntryCount(entries.length);
        setMessage("");
        push("feedback stored locally", "accent");
    };
    const handleExport = () => {
        const entries = loadFeedbackEntries();
        if (entries.length === 0) {
            push("no saved feedback to export", "neutral");
            return;
        }
        const payload = {
            schemaVersion: 1,
            exportedAt: new Date().toISOString(),
            entries,
        };
        const blob = new Blob([`${JSON.stringify(payload, null, 2)}\n`], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement("a");
        anchor.href = url;
        anchor.download = `nullid-feedback-${Date.now()}.json`;
        anchor.click();
        URL.revokeObjectURL(url);
        push("feedback export ready", "accent");
    };
    return (_jsx("div", { className: "feedback-widget", children: open ? (_jsxs("div", { className: "feedback-panel", "aria-label": t("feedback.panel"), children: [_jsxs("div", { className: "feedback-header", children: [_jsx("span", { className: "section-title", children: t("feedback.title") }), _jsx("button", { type: "button", className: "button", onClick: () => setOpen(false), "aria-label": t("feedback.close"), children: t("feedback.close") })] }), _jsx("div", { className: "microcopy", children: t("feedback.stored", { count: entryCount }) }), _jsxs("div", { className: "controls-row", children: [_jsxs("select", { className: "select", value: category, onChange: (event) => setCategory(event.target.value), "aria-label": t("feedback.category"), children: [_jsx("option", { value: "idea", children: t("feedback.idea") }), _jsx("option", { value: "bug", children: t("feedback.bug") }), _jsx("option", { value: "ux", children: t("feedback.ux") }), _jsx("option", { value: "performance", children: t("feedback.performance") })] }), _jsxs("select", { className: "select", value: priority, onChange: (event) => setPriority(event.target.value), "aria-label": t("feedback.priority"), children: [_jsx("option", { value: "low", children: t("feedback.low") }), _jsx("option", { value: "medium", children: t("feedback.medium") }), _jsx("option", { value: "high", children: t("feedback.high") })] })] }), _jsx("textarea", { className: "textarea", value: message, onChange: (event) => setMessage(event.target.value), placeholder: t("feedback.context", { module: activeModule }), "aria-label": t("feedback.message") }), _jsxs("div", { className: "controls-row", children: [_jsx("button", { className: "button", type: "button", onClick: handleSave, disabled: !canSave, children: t("feedback.save") }), _jsx("button", { className: "button", type: "button", onClick: handleExport, disabled: entryCount === 0, children: t("feedback.export") }), _jsx("button", { className: "button", type: "button", onClick: () => setMessage(""), children: t("feedback.clear") })] })] })) : (_jsx("button", { type: "button", className: "button feedback-launcher", onClick: () => setOpen(true), "aria-label": t("feedback.open"), children: t("feedback.launcher") })) }));
}
function loadFeedbackEntries() {
    try {
        const raw = localStorage.getItem(storageKey);
        if (!raw)
            return [];
        const parsed = JSON.parse(raw);
        if (!Array.isArray(parsed))
            return [];
        return parsed.filter((entry) => entry && typeof entry.message === "string");
    }
    catch {
        return [];
    }
}
