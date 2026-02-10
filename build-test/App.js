import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { CommandPalette } from "./components/CommandPalette";
import { Frame } from "./components/Frame";
import { GlobalHeader } from "./components/GlobalHeader";
import { ModuleList } from "./components/ModuleList";
import { EncView } from "./views/EncView";
import { HashView } from "./views/HashView";
import { MetaView } from "./views/MetaView";
import { PwView } from "./views/PwView";
import { GuideView } from "./views/GuideView";
import { RedactView } from "./views/RedactView";
import { SanitizeView } from "./views/SanitizeView";
import { VaultView } from "./views/VaultView";
import { SelfTestView } from "./views/SelfTestView";
import "./App.css";
import { ToastProvider, useToast } from "./components/ToastHost";
import { usePersistentState } from "./hooks/usePersistentState";
import { wipeVault } from "./utils/storage";
import { applyTheme } from "./theme";
import { downloadProfile, importProfileFile } from "./utils/profile";
import { ErrorBoundary } from "./components/ErrorBoundary";
const modules = [
    { key: "hash", title: "Hash & Verify", subtitle: "digests" },
    { key: "redact", title: "Text Redaction", subtitle: "pii scrubbing" },
    { key: "sanitize", title: "Log Sanitizer", subtitle: "diff preview" },
    { key: "meta", title: "Metadata Inspector", subtitle: "exif" },
    { key: "enc", title: "Encrypt / Decrypt", subtitle: "envelopes" },
    { key: "pw", title: "Password & Passphrase", subtitle: "generator" },
    { key: "vault", title: "Secure Notes", subtitle: "sealed" },
    { key: "selftest", title: "Self-test", subtitle: "diagnostics" },
    { key: "guide", title: "Guide", subtitle: "how-to" },
];
function WorkspaceView({ active, onRegisterHashActions, onStatus, onOpenGuide }) {
    switch (active) {
        case "hash":
            return _jsx(HashView, { onRegisterActions: onRegisterHashActions, onStatus: onStatus, onOpenGuide: onOpenGuide });
        case "redact":
            return _jsx(RedactView, { onOpenGuide: onOpenGuide });
        case "sanitize":
            return _jsx(SanitizeView, { onOpenGuide: onOpenGuide });
        case "meta":
            return _jsx(MetaView, { onOpenGuide: onOpenGuide });
        case "enc":
            return _jsx(EncView, { onOpenGuide: onOpenGuide });
        case "pw":
            return _jsx(PwView, { onOpenGuide: onOpenGuide });
        case "vault":
            return _jsx(VaultView, { onOpenGuide: onOpenGuide });
        case "selftest":
            return _jsx(SelfTestView, { onOpenGuide: onOpenGuide });
        case "guide":
            return _jsx(GuideView, {});
        default:
            return null;
    }
}
function AppShell() {
    const { push } = useToast();
    const [activeModule, setActiveModule] = usePersistentState("nullid:last-module", "hash");
    const [status, setStatus] = useState({ message: "ready", tone: "neutral" });
    const [theme, setTheme] = usePersistentState("nullid:theme", "light");
    const [paletteOpen, setPaletteOpen] = useState(false);
    const [hashActions, setHashActions] = useState(null);
    const [viewport, setViewport] = useState({ width: window.innerWidth, height: window.innerHeight });
    const importProfileInputRef = useRef(null);
    const moduleLookup = useMemo(() => Object.fromEntries(modules.map((module) => [module.key, module])), []);
    const resolvedActiveModule = useMemo(() => (modules.some((module) => module.key === activeModule) ? activeModule : "guide"), [activeModule]);
    useEffect(() => {
        if (resolvedActiveModule !== activeModule) {
            setActiveModule("guide");
        }
    }, [activeModule, resolvedActiveModule, setActiveModule]);
    const handleStatus = useCallback((message, tone = "neutral") => {
        setStatus({ message, tone });
    }, []);
    useEffect(() => {
        applyTheme(theme);
    }, [theme]);
    useEffect(() => {
        const handleError = (event) => {
            console.error("window error", event.error || event.message);
            push(`runtime error: ${event.message}`, "danger");
        };
        const handleRejection = (event) => {
            console.error("unhandled rejection", event.reason);
            push("unhandled promise rejection", "danger");
        };
        window.addEventListener("error", handleError);
        window.addEventListener("unhandledrejection", handleRejection);
        return () => {
            window.removeEventListener("error", handleError);
            window.removeEventListener("unhandledrejection", handleRejection);
        };
    }, [push]);
    const toggleTheme = useCallback(() => {
        setTheme((prev) => {
            const next = prev === "light" ? "dark" : "light";
            setStatus({ message: `theme :: ${next}`, tone: "accent" });
            push(`theme :: ${next}`, "accent");
            return next;
        });
    }, [push, setTheme]);
    const handleSelectModule = useCallback((key) => {
        setActiveModule(key);
        setStatus({ message: `:${key} ready`, tone: "neutral" });
        push(`module :: ${key}`, "accent");
        setPaletteOpen(false);
    }, [push, setActiveModule]);
    const navigationCommands = useMemo(() => modules.map((module) => ({
        id: `:${module.key}`,
        label: module.title,
        description: module.subtitle,
        group: "Tools",
        action: () => handleSelectModule(module.key),
    })), [handleSelectModule]);
    const contextualCommands = useMemo(() => {
        const base = [
            {
                id: "toggle-theme",
                label: "Toggle theme",
                description: "Switch between light and dark",
                group: "System",
                shortcut: "T",
                action: toggleTheme,
            },
            {
                id: "wipe",
                label: "Wipe local data",
                description: "Clear preferences and stored content",
                group: "System",
                action: async () => {
                    localStorage.clear();
                    await wipeVault();
                    setActiveModule("hash");
                    push("local data wiped", "danger");
                    setStatus({ message: "data wiped", tone: "danger" });
                },
            },
            {
                id: "export-profile",
                label: "Export profile",
                description: "Download preferences as JSON",
                group: "System",
                action: async () => {
                    const shouldSign = confirm("Sign profile metadata with a passphrase?");
                    let signingPassphrase;
                    let keyHint;
                    if (shouldSign) {
                        const pass = prompt("Signing passphrase:");
                        if (!pass) {
                            push("profile export cancelled", "neutral");
                            setStatus({ message: "profile export cancelled", tone: "neutral" });
                            return;
                        }
                        signingPassphrase = pass;
                        const hint = prompt("Optional key hint (for future verification):");
                        keyHint = hint?.trim() || undefined;
                    }
                    const result = await downloadProfile(`nullid-profile-${Date.now()}.json`, {
                        signingPassphrase,
                        keyHint,
                    });
                    push(`profile exported (${result.entryCount}${result.signed ? ", signed" : ""})`, "accent");
                    setStatus({ message: "profile exported", tone: "accent" });
                },
            },
            {
                id: "import-profile",
                label: "Import profile",
                description: "Load preferences from JSON",
                group: "System",
                action: () => {
                    importProfileInputRef.current?.click();
                },
            },
        ];
        if (activeModule === "hash") {
            base.unshift({
                id: "compare",
                label: "Compare digest",
                description: "Validate against provided hash",
                group: "Hash actions",
                shortcut: "Enter",
                action: hashActions?.compare ?? (() => { }),
                disabled: !hashActions,
            }, {
                id: "clear-inputs",
                label: "Clear inputs",
                description: "Reset text, file, and verify fields",
                group: "Hash actions",
                action: hashActions?.clearInputs ?? (() => { }),
                disabled: !hashActions,
            }, {
                id: "copy-digest",
                label: "Copy digest",
                description: "Copy computed hash to clipboard",
                group: "Hash actions",
                shortcut: "C",
                action: hashActions?.copyDigest ?? (() => { }),
                disabled: !hashActions,
            });
        }
        return base;
    }, [activeModule, hashActions, toggleTheme]);
    const commandList = useMemo(() => [...navigationCommands, ...contextualCommands], [contextualCommands, navigationCommands]);
    const openPalette = useCallback(() => setPaletteOpen(true), []);
    const closePalette = useCallback(() => setPaletteOpen(false), []);
    useEffect(() => {
        if (activeModule !== "hash") {
            setHashActions(null);
        }
    }, [activeModule]);
    useEffect(() => {
        const handleResize = () => setViewport({ width: window.innerWidth, height: window.innerHeight });
        window.addEventListener("resize", handleResize);
        return () => window.removeEventListener("resize", handleResize);
    }, []);
    useEffect(() => {
        const handleKey = (event) => {
            const target = event.target;
            const tagName = target?.tagName?.toLowerCase();
            const isInput = target?.isContentEditable ||
                tagName === "input" ||
                tagName === "textarea" ||
                tagName === "select";
            if (event.key === "/" && !event.metaKey && !event.ctrlKey) {
                if (isInput)
                    return;
                event.preventDefault();
                openPalette();
            }
            if ((event.key === "k" || event.key === "K") && (event.metaKey || event.ctrlKey)) {
                event.preventDefault();
                openPalette();
            }
            if (event.key === "Escape" && paletteOpen) {
                closePalette();
            }
        };
        window.addEventListener("keydown", handleKey);
        return () => window.removeEventListener("keydown", handleKey);
    }, [closePalette, openPalette, paletteOpen]);
    const handleCommandSelect = useCallback(async (command) => {
        try {
            await command.action();
            setStatus({ message: `command :: ${command.id}`, tone: "accent" });
            push(`command :: ${command.id}`, "accent");
        }
        catch (error) {
            console.error(error);
            setStatus({ message: `error :: ${command.id}`, tone: "danger" });
            push(`error :: ${command.id}`, "danger");
        }
        finally {
            closePalette();
        }
    }, [closePalette, push]);
    const isStacked = viewport.width < 1100;
    const isCompact = viewport.height < 820;
    const goToGuide = useCallback((key) => {
        setActiveModule("guide");
        setStatus({ message: "guide", tone: "accent" });
        if (key) {
            window.location.hash = `#${key}`;
        }
    }, [setActiveModule]);
    return (_jsxs("div", { className: `app-surface ${isCompact ? "is-compact" : ""}`, children: [_jsx("input", { ref: importProfileInputRef, type: "file", accept: "application/json", style: { position: "absolute", opacity: 0, width: 1, height: 1, pointerEvents: "none" }, tabIndex: -1, onChange: async (event) => {
                    const file = event.target.files?.[0];
                    if (!file)
                        return;
                    try {
                        const verifyPassphrase = prompt("Verification passphrase for signed profiles (optional):")?.trim() || undefined;
                        const result = await importProfileFile(file, { verificationPassphrase: verifyPassphrase });
                        const suffix = result.legacy ? "legacy" : result.signed ? result.verified ? "signed+verified" : "signed" : "unsigned";
                        push(`profile imported (${result.applied}, ${suffix})`, "accent");
                        setStatus({ message: "profile imported", tone: "accent" });
                        window.location.reload();
                    }
                    catch (error) {
                        console.error(error);
                        const message = error instanceof Error ? error.message : "import failed";
                        push(`import failed: ${message}`, "danger");
                        setStatus({ message: "import failed", tone: "danger" });
                    }
                    event.target.value = "";
                } }), _jsx(Frame, { stacked: isStacked, compact: isCompact, modulePane: _jsx(ModuleList, { modules: modules, active: resolvedActiveModule, onSelect: handleSelectModule }), header: _jsx(GlobalHeader, { brand: "NullID", pageTitle: moduleLookup[resolvedActiveModule].title, pageToken: `:${resolvedActiveModule}`, status: status, theme: theme, compact: isCompact, onToggleTheme: toggleTheme, onOpenCommands: openPalette, onWipe: () => {
                        localStorage.clear();
                        void wipeVault();
                        push("local data wiped", "danger");
                    } }), workspace: _jsx("div", { className: "workspace", children: _jsx(WorkspaceView, { active: resolvedActiveModule, onRegisterHashActions: setHashActions, onStatus: handleStatus, onOpenGuide: goToGuide }) }) }), _jsx(CommandPalette, { open: paletteOpen, commands: commandList, completions: modules.map((module) => module.key), historyKey: "command-bar", onClose: closePalette, onSelect: handleCommandSelect })] }));
}
export default function App() {
    return (_jsx(ToastProvider, { children: _jsx(ErrorBoundary, { children: _jsx(AppShell, {}) }) }));
}
