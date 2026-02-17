import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useEffect, useMemo, useRef, useState } from "react";
import "./CommandPalette.css";
import { useCommandHistory } from "../hooks/useCommandHistory";
import { useI18n } from "../i18n";
export function CommandPalette({ open, commands, completions = [], historyKey = "palette", onClose, onSelect }) {
    const { t } = useI18n();
    const inputRef = useRef(null);
    const [query, setQuery] = useState("");
    const [activeIndex, setActiveIndex] = useState(0);
    const history = useCommandHistory(historyKey);
    useEffect(() => {
        if (!open)
            return;
        setQuery("");
        requestAnimationFrame(() => inputRef.current?.focus());
        history.resetCursor();
    }, [open]);
    useEffect(() => {
        const handler = (event) => {
            if (event.key === "Escape" && open) {
                event.preventDefault();
                onClose();
            }
        };
        window.addEventListener("keydown", handler);
        return () => window.removeEventListener("keydown", handler);
    }, [open, onClose]);
    const filtered = useMemo(() => {
        const terms = query.trim().toLowerCase();
        if (!terms)
            return commands;
        return commands.filter((command) => command.label.toLowerCase().includes(terms) ||
            command.id.toLowerCase().includes(terms) ||
            command.description?.toLowerCase().includes(terms));
    }, [commands, query]);
    const grouped = useMemo(() => {
        const map = new Map();
        filtered.forEach((command) => {
            const list = map.get(command.group) ?? [];
            list.push(command);
            map.set(command.group, list);
        });
        return Array.from(map.entries());
    }, [filtered]);
    const flat = useMemo(() => grouped.flatMap(([, items]) => items), [grouped]);
    useEffect(() => {
        if (activeIndex >= flat.length) {
            setActiveIndex(Math.max(flat.length - 1, 0));
        }
    }, [activeIndex, flat.length]);
    useEffect(() => {
        if (!open)
            return;
        const firstEnabled = flat.findIndex((command) => !command.disabled);
        setActiveIndex(firstEnabled >= 0 ? firstEnabled : 0);
    }, [flat, open]);
    const moveActive = (delta) => {
        if (!flat.length)
            return;
        let next = activeIndex;
        for (let i = 0; i < flat.length; i += 1) {
            next = (next + delta + flat.length) % flat.length;
            if (!flat[next].disabled)
                break;
        }
        setActiveIndex(next);
    };
    const handleKeyDown = (event) => {
        if (event.key === "Tab") {
            const terms = query.trim().toLowerCase();
            if (terms.startsWith(":")) {
                const match = completions.find((entry) => entry.toLowerCase().startsWith(terms.slice(1)));
                if (match) {
                    event.preventDefault();
                    const completed = `:${match}`;
                    setQuery(completed);
                    history.push(completed);
                }
            }
            return;
        }
        if (event.key === "ArrowUp" || event.key === "ArrowDown") {
            if (document.activeElement === inputRef.current) {
                event.preventDefault();
                const next = history.navigate(event.key === "ArrowUp" ? -1 : 1);
                setQuery(next);
                return;
            }
        }
        if (!flat.length)
            return;
        if (event.key === "ArrowDown") {
            event.preventDefault();
            moveActive(1);
        }
        else if (event.key === "ArrowUp") {
            event.preventDefault();
            moveActive(-1);
        }
        else if (event.key === "Enter") {
            event.preventDefault();
            const command = flat[activeIndex];
            if (!command?.disabled) {
                history.push(command.id);
                onSelect?.(command);
            }
        }
    };
    if (!open)
        return null;
    return (_jsxs("div", { className: "command-overlay", role: "dialog", "aria-modal": "true", "aria-label": t("app.commandPalette"), children: [_jsxs("div", { className: "command-surface", children: [_jsxs("div", { className: "command-field", children: [_jsx("span", { "aria-hidden": "true", children: "/" }), _jsx("input", { ref: inputRef, value: query, onChange: (event) => setQuery(event.target.value), placeholder: t("app.commandInputPlaceholder"), onKeyDown: handleKeyDown, "aria-label": t("app.searchCommands") })] }), _jsxs("div", { className: "command-results", role: "listbox", "aria-label": t("app.commandsList"), children: [grouped.length === 0 && _jsx("div", { className: "command-empty", children: t("app.noCommands") }), grouped.map(([group, items]) => (_jsxs("div", { className: "command-group", children: [_jsx("div", { className: "command-group-title", children: group }), _jsx("ul", { children: items.map((command) => {
                                            const flatIndex = flat.indexOf(command);
                                            const active = flatIndex === activeIndex;
                                            const isDisabled = Boolean(command.disabled);
                                            return (_jsx("li", { children: _jsxs("button", { type: "button", className: `command-item ${active ? "active" : ""}`, onClick: () => {
                                                        if (isDisabled)
                                                            return;
                                                        onSelect?.(command);
                                                    }, role: "option", "aria-selected": active, disabled: isDisabled, children: [_jsxs("div", { className: "command-label", children: [_jsx("span", { className: "command-id", children: command.id }), _jsx("span", { className: "command-text", children: command.label })] }), _jsxs("div", { className: "command-meta", children: [command.description && _jsx("span", { className: "command-desc", children: command.description }), command.shortcut && _jsx("kbd", { className: "command-key", children: command.shortcut })] })] }) }, command.id));
                                        }) })] }, group)))] })] }), _jsx("button", { type: "button", className: "command-dismiss", "aria-label": t("app.closeCommandPalette"), onClick: onClose })] }));
}
