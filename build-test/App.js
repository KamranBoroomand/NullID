import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import { Suspense, lazy, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { CommandPalette } from "./components/CommandPalette";
import { Frame } from "./components/Frame";
import { GlobalHeader } from "./components/GlobalHeader";
import { ModuleList } from "./components/ModuleList";
import "./App.css";
import { ToastProvider, useToast } from "./components/ToastHost";
import { usePersistentState } from "./hooks/usePersistentState";
import { wipeVault } from "./utils/storage";
import { applyTheme } from "./theme";
import { describeProfilePayload, downloadProfile, importProfileFile } from "./utils/profile";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { FeedbackWidget } from "./components/FeedbackWidget";
import { OnboardingTour } from "./components/OnboardingTour";
import { ActionDialog } from "./components/ActionDialog";
import { I18nProvider, useI18n } from "./i18n";
import { SHARED_KEY_HINT_PROFILE_KEY, readLegacyProfiles, sanitizeKeyHint, upsertKeyHintProfile, } from "./utils/keyHintProfiles";
const HashView = lazy(() => import("./views/HashView").then((module) => ({ default: module.HashView })));
const RedactView = lazy(() => import("./views/RedactView").then((module) => ({ default: module.RedactView })));
const SanitizeView = lazy(() => import("./views/SanitizeView").then((module) => ({ default: module.SanitizeView })));
const MetaView = lazy(() => import("./views/MetaView").then((module) => ({ default: module.MetaView })));
const EncView = lazy(() => import("./views/EncView").then((module) => ({ default: module.EncView })));
const PwView = lazy(() => import("./views/PwView").then((module) => ({ default: module.PwView })));
const VaultView = lazy(() => import("./views/VaultView").then((module) => ({ default: module.VaultView })));
const SelfTestView = lazy(() => import("./views/SelfTestView").then((module) => ({ default: module.SelfTestView })));
const GuideView = lazy(() => import("./views/GuideView").then((module) => ({ default: module.GuideView })));
function WorkspaceView({ active, onRegisterHashActions, onStatus, onOpenGuide }) {
    const { tr } = useI18n();
    return (_jsxs(Suspense, { fallback: _jsx("div", { className: "workspace-loading", children: tr("loading module...") }), children: [active === "hash" ? _jsx(HashView, { onRegisterActions: onRegisterHashActions, onStatus: onStatus, onOpenGuide: onOpenGuide }) : null, active === "redact" ? _jsx(RedactView, { onOpenGuide: onOpenGuide }) : null, active === "sanitize" ? _jsx(SanitizeView, { onOpenGuide: onOpenGuide }) : null, active === "meta" ? _jsx(MetaView, { onOpenGuide: onOpenGuide }) : null, active === "enc" ? _jsx(EncView, { onOpenGuide: onOpenGuide }) : null, active === "pw" ? _jsx(PwView, { onOpenGuide: onOpenGuide }) : null, active === "vault" ? _jsx(VaultView, { onOpenGuide: onOpenGuide }) : null, active === "selftest" ? _jsx(SelfTestView, { onOpenGuide: onOpenGuide }) : null, active === "guide" ? _jsx(GuideView, {}) : null] }));
}
function AppShell() {
    const { push } = useToast();
    const { locale, setLocale, t, tr } = useI18n();
    const buildId = import.meta.env.VITE_BUILD_ID?.trim();
    const buildMarker = buildId ? `Version: ${buildId.slice(0, 7)}` : import.meta.env.PROD ? "Version: Release" : "Version: Local";
    const [activeModule, setActiveModule] = usePersistentState("nullid:last-module", "hash");
    const [status, setStatus] = useState({ message: "ready", tone: "neutral" });
    const [theme, setTheme] = usePersistentState("nullid:theme", "light");
    const [paletteOpen, setPaletteOpen] = useState(false);
    const [onboardingComplete, setOnboardingComplete] = usePersistentState("nullid:onboarding-complete", false);
    const [tourStepIndex, setTourStepIndex] = usePersistentState("nullid:onboarding-step", 0);
    const [tourOpen, setTourOpen] = useState(!onboardingComplete);
    const [hashActions, setHashActions] = useState(null);
    const [viewport, setViewport] = useState({ width: window.innerWidth, height: window.innerHeight });
    const [keyHintProfiles, setKeyHintProfiles] = usePersistentState(SHARED_KEY_HINT_PROFILE_KEY, []);
    const [selectedKeyHintProfileId, setSelectedKeyHintProfileId] = usePersistentState("nullid:profile:key-hint-selected", "");
    const [keyHintProfileName, setKeyHintProfileName] = useState("");
    const [profileExportOpen, setProfileExportOpen] = useState(false);
    const [profileExportSign, setProfileExportSign] = useState(false);
    const [profileExportPassphrase, setProfileExportPassphrase] = useState("");
    const [profileExportKeyHint, setProfileExportKeyHint] = useState("");
    const [profileExportError, setProfileExportError] = useState(null);
    const [profileImportOpen, setProfileImportOpen] = useState(false);
    const [pendingProfileImportFile, setPendingProfileImportFile] = useState(null);
    const [profileImportDescriptor, setProfileImportDescriptor] = useState(null);
    const [profileImportPassphrase, setProfileImportPassphrase] = useState("");
    const [profileImportError, setProfileImportError] = useState(null);
    const importProfileInputRef = useRef(null);
    const modules = useMemo(() => [
        { key: "hash", title: t("module.hash.title"), subtitle: t("module.hash.subtitle") },
        { key: "redact", title: t("module.redact.title"), subtitle: t("module.redact.subtitle") },
        { key: "sanitize", title: t("module.sanitize.title"), subtitle: t("module.sanitize.subtitle") },
        { key: "meta", title: t("module.meta.title"), subtitle: t("module.meta.subtitle") },
        { key: "enc", title: t("module.enc.title"), subtitle: t("module.enc.subtitle") },
        { key: "pw", title: t("module.pw.title"), subtitle: t("module.pw.subtitle") },
        { key: "vault", title: t("module.vault.title"), subtitle: t("module.vault.subtitle") },
        { key: "selftest", title: t("module.selftest.title"), subtitle: t("module.selftest.subtitle") },
        { key: "guide", title: t("module.guide.title"), subtitle: t("module.guide.subtitle") },
    ], [t]);
    const moduleLookup = useMemo(() => Object.fromEntries(modules.map((module) => [module.key, module])), [modules]);
    const selectedKeyHintProfile = useMemo(() => keyHintProfiles.find((profile) => profile.id === selectedKeyHintProfileId) ?? null, [keyHintProfiles, selectedKeyHintProfileId]);
    const resolvedActiveModule = useMemo(() => (modules.some((module) => module.key === activeModule) ? activeModule : "guide"), [activeModule, modules]);
    useEffect(() => {
        if (resolvedActiveModule !== activeModule) {
            setActiveModule("guide");
        }
    }, [activeModule, resolvedActiveModule, setActiveModule]);
    useEffect(() => {
        if (!onboardingComplete) {
            setTourOpen(true);
        }
    }, [onboardingComplete]);
    useEffect(() => {
        if (keyHintProfiles.length > 0)
            return;
        const legacy = readLegacyProfiles("nullid:sanitize:key-hints");
        if (legacy.length > 0) {
            setKeyHintProfiles(legacy);
        }
    }, [keyHintProfiles.length, setKeyHintProfiles]);
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
    const startOnboarding = useCallback(() => {
        setOnboardingComplete(false);
        setTourStepIndex(0);
        setTourOpen(true);
        setStatus({ message: "onboarding", tone: "accent" });
    }, [setOnboardingComplete, setTourStepIndex]);
    const openProfileExportDialog = useCallback(() => {
        setProfileExportOpen(true);
        setProfileExportError(null);
        setProfileExportSign(false);
        setProfileExportPassphrase("");
        setProfileExportKeyHint(selectedKeyHintProfile?.keyHint ?? "");
    }, [selectedKeyHintProfile]);
    const closeProfileExportDialog = useCallback(() => {
        setProfileExportOpen(false);
        setProfileExportError(null);
        setProfileExportPassphrase("");
    }, []);
    const confirmProfileExport = useCallback(async () => {
        try {
            if (profileExportSign && !profileExportPassphrase.trim()) {
                setProfileExportError("signing passphrase required");
                return;
            }
            const keyHint = profileExportSign ? sanitizeKeyHint(profileExportKeyHint) || undefined : undefined;
            const signingPassphrase = profileExportSign ? profileExportPassphrase : undefined;
            const result = await downloadProfile(`nullid-profile-${Date.now()}.json`, { signingPassphrase, keyHint });
            push(`profile exported (${result.entryCount}${result.signed ? ", signed" : ""})`, "accent");
            setStatus({ message: "profile exported", tone: "accent" });
            closeProfileExportDialog();
        }
        catch (error) {
            console.error(error);
            setProfileExportError(error instanceof Error ? error.message : "profile export failed");
        }
    }, [closeProfileExportDialog, profileExportKeyHint, profileExportPassphrase, profileExportSign, push]);
    const saveProfileHint = useCallback(() => {
        const result = upsertKeyHintProfile(keyHintProfiles, keyHintProfileName, profileExportKeyHint);
        if (!result.ok) {
            setProfileExportError(result.message);
            return;
        }
        setKeyHintProfiles(result.profiles);
        setSelectedKeyHintProfileId(result.selectedId);
        setKeyHintProfileName("");
        setProfileExportKeyHint(result.profiles.find((entry) => entry.id === result.selectedId)?.keyHint ?? profileExportKeyHint);
        setProfileExportError(null);
        push("key hint profile saved", "accent");
    }, [keyHintProfileName, keyHintProfiles, profileExportKeyHint, push, setKeyHintProfiles, setSelectedKeyHintProfileId]);
    const beginProfileImportFlow = useCallback(async (file) => {
        if (!file)
            return;
        try {
            const text = await file.text();
            const parsed = JSON.parse(text);
            const descriptor = describeProfilePayload(parsed);
            setPendingProfileImportFile(file);
            setProfileImportDescriptor(descriptor);
            setProfileImportPassphrase("");
            setProfileImportError(null);
            setProfileImportOpen(true);
        }
        catch (error) {
            console.error(error);
            const message = error instanceof Error ? error.message : "import failed";
            push(`import failed: ${message}`, "danger");
            setStatus({ message: "import failed", tone: "danger" });
        }
    }, [push]);
    const closeProfileImportDialog = useCallback(() => {
        setProfileImportOpen(false);
        setPendingProfileImportFile(null);
        setProfileImportDescriptor(null);
        setProfileImportPassphrase("");
        setProfileImportError(null);
    }, []);
    const confirmProfileImport = useCallback(async () => {
        if (!pendingProfileImportFile || !profileImportDescriptor)
            return;
        if (profileImportDescriptor.signed && !profileImportPassphrase.trim()) {
            setProfileImportError("verification passphrase required for signed profiles");
            return;
        }
        try {
            const result = await importProfileFile(pendingProfileImportFile, {
                verificationPassphrase: profileImportDescriptor.signed ? profileImportPassphrase.trim() : undefined,
            });
            const suffix = result.legacy ? "legacy" : result.signed ? (result.verified ? "signed+verified" : "signed") : "unsigned";
            push(`profile imported (${result.applied}, ${suffix})`, "accent");
            setStatus({ message: "profile imported", tone: "accent" });
            closeProfileImportDialog();
            window.location.reload();
        }
        catch (error) {
            console.error(error);
            const message = error instanceof Error ? error.message : "import failed";
            setProfileImportError(message);
        }
    }, [closeProfileImportDialog, pendingProfileImportFile, profileImportDescriptor, profileImportPassphrase, push]);
    const navigationCommands = useMemo(() => modules.map((module) => ({
        id: `:${module.key}`,
        label: module.title,
        description: module.subtitle,
        group: t("app.command.toolsGroup"),
        action: () => handleSelectModule(module.key),
    })), [handleSelectModule, modules, t]);
    const contextualCommands = useMemo(() => {
        const base = [
            {
                id: "toggle-theme",
                label: t("app.command.toggleTheme"),
                description: t("app.command.switchTheme"),
                group: t("app.command.systemGroup"),
                shortcut: "T",
                action: toggleTheme,
            },
            {
                id: "wipe",
                label: t("app.command.wipe"),
                description: t("app.command.clearPrefs"),
                group: t("app.command.systemGroup"),
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
                label: t("app.command.exportProfile"),
                description: t("app.command.exportProfileDesc"),
                group: t("app.command.systemGroup"),
                action: openProfileExportDialog,
            },
            {
                id: "import-profile",
                label: t("app.command.importProfile"),
                description: t("app.command.importProfileDesc"),
                group: t("app.command.systemGroup"),
                action: () => {
                    importProfileInputRef.current?.click();
                },
            },
            {
                id: "onboarding",
                label: t("app.command.runOnboarding"),
                description: t("app.command.runOnboardingDesc"),
                group: t("app.command.systemGroup"),
                action: startOnboarding,
            },
            {
                id: "language-en",
                label: t("app.command.language.en"),
                description: t("app.command.languageDesc"),
                group: t("app.command.systemGroup"),
                action: () => {
                    setLocale("en");
                    push(`language changed: ${t("locale.en")}`, "accent");
                },
            },
            {
                id: "language-fa",
                label: t("app.command.language.fa"),
                description: t("app.command.languageDesc"),
                group: t("app.command.systemGroup"),
                action: () => {
                    setLocale("fa");
                    push(`language changed: ${t("locale.fa")}`, "accent");
                },
            },
            {
                id: "language-ru",
                label: t("app.command.language.ru"),
                description: t("app.command.languageDesc"),
                group: t("app.command.systemGroup"),
                action: () => {
                    setLocale("ru");
                    push(`language changed: ${t("locale.ru")}`, "accent");
                },
            },
        ];
        if (activeModule === "hash") {
            base.unshift({
                id: "compare",
                label: t("app.command.compareDigest"),
                description: t("app.command.compareDigestDesc"),
                group: t("app.command.hashGroup"),
                shortcut: "Enter",
                action: hashActions?.compare ?? (() => { }),
                disabled: !hashActions,
            }, {
                id: "clear-inputs",
                label: t("app.command.clearInputs"),
                description: t("app.command.clearInputsDesc"),
                group: t("app.command.hashGroup"),
                action: hashActions?.clearInputs ?? (() => { }),
                disabled: !hashActions,
            }, {
                id: "copy-digest",
                label: t("app.command.copyDigest"),
                description: t("app.command.copyDigestDesc"),
                group: t("app.command.hashGroup"),
                shortcut: "C",
                action: hashActions?.copyDigest ?? (() => { }),
                disabled: !hashActions,
            });
        }
        return base;
    }, [activeModule, hashActions, openProfileExportDialog, push, setLocale, startOnboarding, t, toggleTheme]);
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
    const isCompact = viewport.width < 960 || viewport.height < 820;
    const goToGuide = useCallback((key) => {
        setActiveModule("guide");
        setStatus({ message: "guide", tone: "accent" });
        if (key) {
            window.location.hash = `#${key}`;
        }
    }, [setActiveModule]);
    const finishOnboarding = useCallback(() => {
        setOnboardingComplete(true);
        setTourStepIndex(0);
        setTourOpen(false);
        push("onboarding complete", "accent");
        setStatus({ message: "onboarding complete", tone: "accent" });
    }, [push, setOnboardingComplete, setTourStepIndex]);
    const skipOnboarding = useCallback(() => {
        setOnboardingComplete(true);
        setTourStepIndex(0);
        setTourOpen(false);
        setStatus({ message: "onboarding skipped", tone: "neutral" });
    }, [setOnboardingComplete, setTourStepIndex]);
    const onboardingSteps = useMemo(() => [
        {
            id: "guide",
            title: t("app.onboarding.1.title"),
            body: t("app.onboarding.1.body"),
            actionLabel: t("app.onboarding.1.action"),
            onAction: () => goToGuide(),
        },
        {
            id: "password",
            title: t("app.onboarding.2.title"),
            body: t("app.onboarding.2.body"),
            actionLabel: t("app.onboarding.2.action"),
            onAction: () => handleSelectModule("pw"),
        },
        {
            id: "sanitize",
            title: t("app.onboarding.3.title"),
            body: t("app.onboarding.3.body"),
            actionLabel: t("app.onboarding.3.action"),
            onAction: () => handleSelectModule("sanitize"),
        },
        {
            id: "commands",
            title: t("app.onboarding.4.title"),
            body: t("app.onboarding.4.body"),
            actionLabel: t("app.onboarding.4.action"),
            onAction: openPalette,
        },
        {
            id: "feedback",
            title: t("app.onboarding.5.title"),
            body: t("app.onboarding.5.body"),
        },
    ], [goToGuide, handleSelectModule, openPalette, t]);
    return (_jsxs("div", { className: `app-surface ${isCompact ? "is-compact" : ""}`, children: [_jsx("input", { ref: importProfileInputRef, type: "file", accept: "application/json", style: { position: "absolute", opacity: 0, width: 1, height: 1, pointerEvents: "none" }, tabIndex: -1, onChange: async (event) => {
                    const file = event.target.files?.[0];
                    await beginProfileImportFlow(file);
                    event.target.value = "";
                } }), _jsx(Frame, { stacked: isStacked, compact: isCompact, buildMarker: buildMarker, modulePane: _jsx(ModuleList, { modules: modules, active: resolvedActiveModule, onSelect: handleSelectModule }), header: _jsx(GlobalHeader, { brand: "NullID", pageTitle: moduleLookup[resolvedActiveModule].title, pageToken: `:${resolvedActiveModule}`, status: status, theme: theme, locale: locale, compact: isCompact, onToggleTheme: toggleTheme, onLocaleChange: setLocale, onOpenCommands: openPalette, onWipe: () => {
                        localStorage.clear();
                        void wipeVault();
                        push("local data wiped", "danger");
                    } }), workspace: _jsx("div", { className: "workspace", children: _jsx(WorkspaceView, { active: resolvedActiveModule, onRegisterHashActions: setHashActions, onStatus: handleStatus, onOpenGuide: goToGuide }) }) }), _jsx(CommandPalette, { open: paletteOpen, commands: commandList, completions: modules.map((module) => module.key), historyKey: "command-bar", onClose: closePalette, onSelect: handleCommandSelect }), _jsxs(ActionDialog, { open: profileExportOpen, title: tr("Export profile snapshot"), description: tr("Export local nullid:* settings as JSON. Signed exports require a verification passphrase on import."), confirmLabel: tr("export profile"), onCancel: closeProfileExportDialog, onConfirm: () => void confirmProfileExport(), confirmDisabled: profileExportSign && !profileExportPassphrase.trim(), children: [_jsxs("label", { className: "action-dialog-field", children: [_jsx("span", { children: tr("Sign metadata") }), _jsx("input", { type: "checkbox", checked: profileExportSign, onChange: (event) => setProfileExportSign(event.target.checked), "aria-label": tr("Sign profile metadata") })] }), profileExportSign ? (_jsxs(_Fragment, { children: [_jsxs("label", { className: "action-dialog-field", children: [_jsx("span", { children: tr("Signing passphrase") }), _jsx("input", { className: "action-dialog-input", type: "password", value: profileExportPassphrase, onChange: (event) => {
                                            setProfileExportPassphrase(event.target.value);
                                            if (profileExportError)
                                                setProfileExportError(null);
                                        }, "aria-label": tr("Profile signing passphrase"), placeholder: tr("required when signing") })] }), _jsxs("div", { className: "action-dialog-row", children: [_jsxs("label", { className: "action-dialog-field", children: [_jsx("span", { children: tr("Saved key hint") }), _jsxs("select", { className: "action-dialog-select", value: selectedKeyHintProfileId, onChange: (event) => {
                                                    const nextId = event.target.value;
                                                    setSelectedKeyHintProfileId(nextId);
                                                    const profile = keyHintProfiles.find((entry) => entry.id === nextId);
                                                    setProfileExportKeyHint(profile?.keyHint ?? "");
                                                }, "aria-label": tr("Saved key hint profile"), children: [_jsx("option", { value: "", children: tr("custom key hint") }), keyHintProfiles.map((profile) => (_jsxs("option", { value: profile.id, children: [profile.name, " \u00B7 ", profile.keyHint] }, profile.id)))] })] }), _jsxs("label", { className: "action-dialog-field", children: [_jsx("span", { children: tr("Key hint label") }), _jsx("input", { className: "action-dialog-input", value: profileExportKeyHint, onChange: (event) => setProfileExportKeyHint(event.target.value), "aria-label": tr("Profile key hint"), placeholder: tr("optional recipient-visible hint") })] })] }), _jsxs("div", { className: "action-dialog-row", children: [_jsxs("label", { className: "action-dialog-field", children: [_jsx("span", { children: tr("Save key hint profile as") }), _jsx("input", { className: "action-dialog-input", value: keyHintProfileName, onChange: (event) => setKeyHintProfileName(event.target.value), "aria-label": tr("Key hint profile name"), placeholder: "team-signing-key" })] }), _jsx("button", { type: "button", className: "button", onClick: saveProfileHint, disabled: !profileExportKeyHint.trim(), children: tr("save hint") })] }), _jsxs("p", { className: "action-dialog-note", children: [tr("Key hints are local labels only. Passphrases are not persisted."), selectedKeyHintProfile ? ` Active: ${selectedKeyHintProfile.name} (v${selectedKeyHintProfile.version})` : ""] })] })) : (_jsx("p", { className: "action-dialog-note", children: tr("Unsigned profile exports can still be imported, but signature verification is unavailable.") })), profileExportError ? _jsx("p", { className: "action-dialog-error", children: profileExportError }) : null] }), _jsxs(ActionDialog, { open: profileImportOpen, title: tr("Import profile snapshot"), description: profileImportDescriptor
                    ? `${profileImportDescriptor.entryCount} entries · ${profileImportDescriptor.legacy ? "legacy" : `schema ${profileImportDescriptor.schemaVersion}`}`
                    : tr("Select import settings"), confirmLabel: tr("import profile"), onCancel: closeProfileImportDialog, onConfirm: () => void confirmProfileImport(), children: [profileImportDescriptor?.signed ? (_jsxs(_Fragment, { children: [_jsxs("p", { className: "action-dialog-note", children: [tr("Signed profile detected"), profileImportDescriptor.keyHint ? ` (${tr("hint")}: ${profileImportDescriptor.keyHint})` : "", ". ", tr("Verification is required before import.")] }), _jsxs("label", { className: "action-dialog-field", children: [_jsx("span", { children: tr("Verification passphrase") }), _jsx("input", { className: "action-dialog-input", type: "password", value: profileImportPassphrase, onChange: (event) => {
                                            setProfileImportPassphrase(event.target.value);
                                            if (profileImportError)
                                                setProfileImportError(null);
                                        }, "aria-label": tr("Profile verification passphrase"), placeholder: tr("required for signed profile") })] })] })) : (_jsx("p", { className: "action-dialog-note", children: tr("Unsigned profile snapshot. Continue only if you trust the source.") })), profileImportError ? _jsx("p", { className: "action-dialog-error", children: profileImportError }) : null] }), _jsx(FeedbackWidget, { activeModule: resolvedActiveModule }), _jsx(OnboardingTour, { open: tourOpen, stepIndex: tourStepIndex, steps: onboardingSteps, onStepIndexChange: setTourStepIndex, onSkip: skipOnboarding, onFinish: finishOnboarding })] }));
}
export default function App() {
    return (_jsx(I18nProvider, { children: _jsx(ToastProvider, { children: _jsx(ErrorBoundary, { children: _jsx(AppShell, {}) }) }) }));
}
