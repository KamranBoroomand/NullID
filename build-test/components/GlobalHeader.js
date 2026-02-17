import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useRef, useState } from "react";
import { Chip } from "./Chip";
import { Popover } from "./Overlay/Popover";
import { useI18n } from "../i18n";
import "./GlobalHeader.css";
export function GlobalHeader({ brand, pageTitle, pageToken, status, theme, locale, compact = false, onToggleTheme, onLocaleChange, onOpenCommands, onWipe, }) {
    const { t, tr, availableLocales, localeMeta } = useI18n();
    const chipTone = status?.tone === "danger" ? "danger" : status?.tone === "accent" ? "accent" : "muted";
    const [menuOpen, setMenuOpen] = useState(false);
    const actionButtonRef = useRef(null);
    return (_jsxs("header", { className: `global-header ${compact ? "is-compact" : ""}`, children: [_jsx("div", { className: "header-cluster", children: _jsx("div", { className: "brand-mark", children: _jsx("span", { className: "brand-name", children: brand }) }) }), _jsxs("div", { className: "header-center", children: [_jsxs("div", { className: "page-meta", children: [_jsx("span", { className: "page-title", children: pageTitle }), _jsx("span", { className: "page-token", children: pageToken })] }), status?.message && _jsx(Chip, { label: tr(status.message), tone: chipTone, ariaLabel: t("app.status") })] }), _jsxs("div", { className: "header-actions", children: [_jsxs("div", { className: "indicator-row", "aria-label": t("app.connectionIndicators"), children: [_jsx(Chip, { label: t("app.local"), tone: "muted" }), _jsx(Chip, { label: t("app.offline"), tone: "muted" }), _jsx(Chip, { label: t("app.noNet"), tone: "muted" })] }), compact ? (_jsxs("div", { className: "compact-actions", children: [_jsx("button", { type: "button", className: "ghost-button", ref: actionButtonRef, onClick: () => setMenuOpen((open) => !open), "aria-expanded": menuOpen, "aria-haspopup": "menu", "aria-label": t("app.openQuickActions"), children: t("app.actions") }), _jsxs(Popover, { anchorRef: actionButtonRef, align: "end", className: "compact-menu", open: menuOpen, onClose: () => setMenuOpen(false), role: "menu", children: [_jsxs("button", { type: "button", className: "ghost-button", onClick: () => {
                                            setMenuOpen(false);
                                            onToggleTheme();
                                        }, "aria-label": t("app.command.toggleTheme"), role: "menuitem", children: [t("app.themeLabel"), ": ", theme === "dark" ? t("app.theme.dark") : t("app.theme.light")] }), _jsxs("label", { className: "header-locale-label", children: [t("app.language"), _jsx("select", { className: "header-locale-select", value: locale, onChange: (event) => {
                                                    onLocaleChange(event.target.value);
                                                    setMenuOpen(false);
                                                }, "aria-label": t("app.language"), children: availableLocales.map((entry) => (_jsx("option", { value: entry, children: localeMeta[entry].label }, entry))) })] }), _jsx("button", { type: "button", className: "ghost-button", onClick: () => {
                                            setMenuOpen(false);
                                            onWipe();
                                        }, "aria-label": t("app.command.wipe"), role: "menuitem", children: t("app.wipeData") }), _jsx("button", { type: "button", className: "command-button", onClick: () => {
                                            setMenuOpen(false);
                                            onOpenCommands();
                                        }, "aria-label": t("app.commandPalette"), "aria-keyshortcuts": "/,Control+K,Meta+K", role: "menuitem", children: t("app.commands") })] })] })) : (_jsxs("div", { className: "action-row", children: [_jsxs("button", { type: "button", className: "ghost-button", onClick: onToggleTheme, "aria-label": t("app.command.toggleTheme"), "aria-live": "polite", children: [t("app.themeLabel"), ": ", theme === "dark" ? t("app.theme.dark") : t("app.theme.light")] }), _jsxs("label", { className: "header-locale-label", children: [t("app.language"), _jsx("select", { className: "header-locale-select", value: locale, onChange: (event) => onLocaleChange(event.target.value), "aria-label": t("app.language"), children: availableLocales.map((entry) => (_jsx("option", { value: entry, children: localeMeta[entry].label }, entry))) })] }), _jsx("button", { type: "button", className: "ghost-button", onClick: onWipe, "aria-label": t("app.command.wipe"), children: t("app.wipeData") }), _jsx("button", { type: "button", className: "command-button", onClick: onOpenCommands, "aria-label": t("app.commandPalette"), "aria-keyshortcuts": "/,Control+K,Meta+K", children: t("app.commands") })] }))] })] }));
}
