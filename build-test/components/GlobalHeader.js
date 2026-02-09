import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useRef, useState } from "react";
import { Chip } from "./Chip";
import { Popover } from "./Overlay/Popover";
import "./GlobalHeader.css";
export function GlobalHeader({ brand, pageTitle, pageToken, status, theme, compact = false, onToggleTheme, onOpenCommands, onWipe, }) {
    const chipTone = status?.tone === "danger" ? "danger" : status?.tone === "accent" ? "accent" : "muted";
    const [menuOpen, setMenuOpen] = useState(false);
    const actionButtonRef = useRef(null);
    return (_jsxs("header", { className: `global-header ${compact ? "is-compact" : ""}`, children: [_jsx("div", { className: "header-cluster", children: _jsx("div", { className: "brand-mark", children: _jsx("span", { className: "brand-name", children: brand }) }) }), _jsxs("div", { className: "header-center", children: [_jsxs("div", { className: "page-meta", children: [_jsx("span", { className: "page-title", children: pageTitle }), _jsx("span", { className: "page-token", children: pageToken })] }), status?.message && _jsx(Chip, { label: status.message, tone: chipTone, ariaLabel: "Status" })] }), _jsxs("div", { className: "header-actions", children: [_jsxs("div", { className: "indicator-row", "aria-label": "Connection indicators", children: [_jsx(Chip, { label: "local", tone: "muted" }), _jsx(Chip, { label: "offline", tone: "muted" }), _jsx(Chip, { label: "no-net", tone: "muted" })] }), compact ? (_jsxs("div", { className: "compact-actions", children: [_jsx("button", { type: "button", className: "ghost-button", ref: actionButtonRef, onClick: () => setMenuOpen((open) => !open), "aria-expanded": menuOpen, "aria-haspopup": "menu", "aria-label": "Open quick actions", children: "Actions" }), _jsxs(Popover, { anchorRef: actionButtonRef, align: "end", className: "compact-menu", open: menuOpen, onClose: () => setMenuOpen(false), role: "menu", children: [_jsxs("button", { type: "button", className: "ghost-button", onClick: () => {
                                            setMenuOpen(false);
                                            onToggleTheme();
                                        }, "aria-label": "Toggle theme", role: "menuitem", children: ["Theme: ", theme === "dark" ? "Dark" : "Light"] }), _jsx("button", { type: "button", className: "ghost-button", onClick: () => {
                                            setMenuOpen(false);
                                            onWipe();
                                        }, "aria-label": "Wipe local data", role: "menuitem", children: "Wipe data" }), _jsx("button", { type: "button", className: "command-button", onClick: () => {
                                            setMenuOpen(false);
                                            onOpenCommands();
                                        }, "aria-label": "Open command palette", "aria-keyshortcuts": "/,Control+K,Meta+K", role: "menuitem", children: "/ Commands" })] })] })) : (_jsxs("div", { className: "action-row", children: [_jsxs("button", { type: "button", className: "ghost-button", onClick: onToggleTheme, "aria-label": "Toggle theme", "aria-live": "polite", children: ["Theme: ", theme === "dark" ? "Dark" : "Light"] }), _jsx("button", { type: "button", className: "ghost-button", onClick: onWipe, "aria-label": "Wipe local data", children: "Wipe data" }), _jsx("button", { type: "button", className: "command-button", onClick: onOpenCommands, "aria-label": "Open command palette", "aria-keyshortcuts": "/,Control+K,Meta+K", children: "/ Commands" })] }))] })] }));
}
