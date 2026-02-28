import { Suspense, lazy, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { CommandPalette, CommandItem } from "./components/CommandPalette";
import { Frame } from "./components/Frame";
import { GlobalHeader } from "./components/GlobalHeader";
import { ModuleDefinition, ModuleKey, ModuleList } from "./components/ModuleList";
import "./App.css";
import { ToastProvider, useToast } from "./components/ToastHost";
import { usePersistentState } from "./hooks/usePersistentState";
import { wipeVault } from "./utils/storage";
import { applyTheme } from "./theme";
import type { ThemeMode } from "./theme/tokens";
import { describeProfilePayload, downloadProfile, importProfileFile, type ProfileDescriptor } from "./utils/profile";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { FeedbackWidget } from "./components/FeedbackWidget";
import { OnboardingStep, OnboardingTour } from "./components/OnboardingTour";
import type { HashViewActions } from "./views/HashView";
import { ActionDialog } from "./components/ActionDialog";
import { I18nProvider, useI18n } from "./i18n";
import {
  SHARED_KEY_HINT_PROFILE_KEY,
  readLegacyProfiles,
  sanitizeKeyHint,
  upsertKeyHintProfile,
  type KeyHintProfile,
} from "./utils/keyHintProfiles";

const HashView = lazy(() => import("./views/HashView").then((module) => ({ default: module.HashView })));
const RedactView = lazy(() => import("./views/RedactView").then((module) => ({ default: module.RedactView })));
const SanitizeView = lazy(() => import("./views/SanitizeView").then((module) => ({ default: module.SanitizeView })));
const MetaView = lazy(() => import("./views/MetaView").then((module) => ({ default: module.MetaView })));
const EncView = lazy(() => import("./views/EncView").then((module) => ({ default: module.EncView })));
const PwView = lazy(() => import("./views/PwView").then((module) => ({ default: module.PwView })));
const VaultView = lazy(() => import("./views/VaultView").then((module) => ({ default: module.VaultView })));
const SelfTestView = lazy(() => import("./views/SelfTestView").then((module) => ({ default: module.SelfTestView })));
const GuideView = lazy(() => import("./views/GuideView").then((module) => ({ default: module.GuideView })));

type StatusTone = "neutral" | "accent" | "danger";
type TrustState = "unsigned" | "verified" | "mismatch";

interface WorkspaceViewProps {
  active: ModuleKey;
  onRegisterHashActions?: (actions: HashViewActions | null) => void;
  onStatus?: (message: string, tone?: StatusTone) => void;
  onOpenGuide?: (key?: ModuleKey) => void;
}

function WorkspaceView({ active, onRegisterHashActions, onStatus, onOpenGuide }: WorkspaceViewProps) {
  const { tr } = useI18n();
  return (
    <Suspense fallback={<div className="workspace-loading">{tr("loading module...")}</div>}>
      {active === "hash" ? <HashView onRegisterActions={onRegisterHashActions} onStatus={onStatus} onOpenGuide={onOpenGuide} /> : null}
      {active === "redact" ? <RedactView onOpenGuide={onOpenGuide} /> : null}
      {active === "sanitize" ? <SanitizeView onOpenGuide={onOpenGuide} /> : null}
      {active === "meta" ? <MetaView onOpenGuide={onOpenGuide} /> : null}
      {active === "enc" ? <EncView onOpenGuide={onOpenGuide} /> : null}
      {active === "pw" ? <PwView onOpenGuide={onOpenGuide} /> : null}
      {active === "vault" ? <VaultView onOpenGuide={onOpenGuide} /> : null}
      {active === "selftest" ? <SelfTestView onOpenGuide={onOpenGuide} /> : null}
      {active === "guide" ? <GuideView /> : null}
    </Suspense>
  );
}

function AppShell() {
  const { push } = useToast();
  const { locale, setLocale, t, tr } = useI18n();
  const buildId = import.meta.env.VITE_BUILD_ID?.trim();
  const buildMarker = buildId ? `Version: ${buildId.slice(0, 7)}` : import.meta.env.PROD ? "Version: Release" : "Version: Local";
  const [activeModule, setActiveModule] = usePersistentState<ModuleKey>("nullid:last-module", "hash");
  const [status, setStatus] = useState({ message: "ready", tone: "neutral" as StatusTone });
  const [theme, setTheme] = usePersistentState<ThemeMode>("nullid:theme", "light");
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [onboardingComplete, setOnboardingComplete] = usePersistentState<boolean>("nullid:onboarding-complete", false);
  const [tourStepIndex, setTourStepIndex] = usePersistentState<number>("nullid:onboarding-step", 0);
  const [tourOpen, setTourOpen] = useState(!onboardingComplete);
  const [hashActions, setHashActions] = useState<HashViewActions | null>(null);
  const [viewport, setViewport] = useState({ width: window.innerWidth, height: window.innerHeight });
  const [keyHintProfiles, setKeyHintProfiles] = usePersistentState<KeyHintProfile[]>(SHARED_KEY_HINT_PROFILE_KEY, []);
  const [selectedKeyHintProfileId, setSelectedKeyHintProfileId] = usePersistentState<string>("nullid:profile:key-hint-selected", "");
  const [keyHintProfileName, setKeyHintProfileName] = useState("");
  const [profileExportOpen, setProfileExportOpen] = useState(false);
  const [profileExportSign, setProfileExportSign] = useState(false);
  const [profileExportPassphrase, setProfileExportPassphrase] = useState("");
  const [profileExportKeyHint, setProfileExportKeyHint] = useState("");
  const [profileExportError, setProfileExportError] = useState<string | null>(null);
  const [profileImportOpen, setProfileImportOpen] = useState(false);
  const [pendingProfileImportFile, setPendingProfileImportFile] = useState<File | null>(null);
  const [profileImportDescriptor, setProfileImportDescriptor] = useState<ProfileDescriptor | null>(null);
  const [profileImportPassphrase, setProfileImportPassphrase] = useState("");
  const [profileImportError, setProfileImportError] = useState<string | null>(null);
  const [wipeDialogOpen, setWipeDialogOpen] = useState(false);
  const [wipeConfirmText, setWipeConfirmText] = useState("");
  const [wipeIncludeVault, setWipeIncludeVault] = useState(true);
  const [wipeBusy, setWipeBusy] = useState(false);
  const [wipeError, setWipeError] = useState<string | null>(null);
  const importProfileInputRef = useRef<HTMLInputElement>(null);
  const modules = useMemo<ModuleDefinition[]>(
    () => [
      { key: "hash", title: t("module.hash.title"), subtitle: t("module.hash.subtitle") },
      { key: "redact", title: t("module.redact.title"), subtitle: t("module.redact.subtitle") },
      { key: "sanitize", title: t("module.sanitize.title"), subtitle: t("module.sanitize.subtitle") },
      { key: "meta", title: t("module.meta.title"), subtitle: t("module.meta.subtitle") },
      { key: "enc", title: t("module.enc.title"), subtitle: t("module.enc.subtitle") },
      { key: "pw", title: t("module.pw.title"), subtitle: t("module.pw.subtitle") },
      { key: "vault", title: t("module.vault.title"), subtitle: t("module.vault.subtitle") },
      { key: "selftest", title: t("module.selftest.title"), subtitle: t("module.selftest.subtitle") },
      { key: "guide", title: t("module.guide.title"), subtitle: t("module.guide.subtitle") },
    ],
    [t],
  );
  const moduleLookup = useMemo(
    () => Object.fromEntries(modules.map((module) => [module.key, module])) as Record<ModuleKey, ModuleDefinition>,
    [modules],
  );
  const selectedKeyHintProfile = useMemo(
    () => keyHintProfiles.find((profile) => profile.id === selectedKeyHintProfileId) ?? null,
    [keyHintProfiles, selectedKeyHintProfileId],
  );
  const profileExportTrustState: TrustState = !profileExportSign
    ? "unsigned"
    : profileExportPassphrase.trim()
      ? "verified"
      : "mismatch";
  const profileImportTrustState = useMemo<TrustState>(() => {
    if (!profileImportDescriptor?.signed) return "unsigned";
    if (!profileImportPassphrase.trim()) return "mismatch";
    if (profileImportError && /verification|signature|mismatch|integrity/i.test(profileImportError)) return "mismatch";
    return "verified";
  }, [profileImportDescriptor?.signed, profileImportError, profileImportPassphrase]);

  const resolvedActiveModule = useMemo<ModuleKey>(
    () => (modules.some((module) => module.key === activeModule) ? activeModule : "guide"),
    [activeModule, modules],
  );

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
    if (keyHintProfiles.length > 0) return;
    const legacy = readLegacyProfiles("nullid:sanitize:key-hints");
    if (legacy.length > 0) {
      setKeyHintProfiles(legacy);
    }
  }, [keyHintProfiles.length, setKeyHintProfiles]);

  const handleStatus = useCallback((message: string, tone: StatusTone = "neutral") => {
    setStatus({ message, tone });
  }, []);

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  useEffect(() => {
    const handleError = (event: ErrorEvent) => {
      console.error("window error", event.error || event.message);
      push(`runtime error: ${event.message}`, "danger");
    };
    const handleRejection = (event: PromiseRejectionEvent) => {
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

  const handleSelectModule = useCallback(
    (key: ModuleKey) => {
      setActiveModule(key);
      setStatus({ message: `:${key} ready`, tone: "neutral" });
      push(`module :: ${key}`, "accent");
      setPaletteOpen(false);
    },
    [push, setActiveModule],
  );

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
    } catch (error) {
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

  const beginProfileImportFlow = useCallback(async (file?: File | null) => {
    if (!file) return;
    try {
      const text = await file.text();
      const parsed = JSON.parse(text) as unknown;
      const descriptor = describeProfilePayload(parsed);
      setPendingProfileImportFile(file);
      setProfileImportDescriptor(descriptor);
      setProfileImportPassphrase("");
      setProfileImportError(null);
      setProfileImportOpen(true);
    } catch (error) {
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
    if (!pendingProfileImportFile || !profileImportDescriptor) return;
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
    } catch (error) {
      console.error(error);
      const message = error instanceof Error ? error.message : "import failed";
      setProfileImportError(message);
    }
  }, [closeProfileImportDialog, pendingProfileImportFile, profileImportDescriptor, profileImportPassphrase, push]);

  const openWipeDialog = useCallback(() => {
    setWipeDialogOpen(true);
    setWipeConfirmText("");
    setWipeIncludeVault(true);
    setWipeError(null);
  }, []);

  const closeWipeDialog = useCallback(() => {
    if (wipeBusy) return;
    setWipeDialogOpen(false);
    setWipeConfirmText("");
    setWipeError(null);
  }, [wipeBusy]);

  const confirmWipe = useCallback(async () => {
    if (wipeConfirmText.trim().toUpperCase() !== "WIPE") {
      setWipeError("type WIPE to confirm");
      return;
    }
    setWipeBusy(true);
    try {
      clearManagedLocalState({ includeVault: wipeIncludeVault });
      if (wipeIncludeVault) {
        await wipeVault();
      }
      setActiveModule("hash");
      push(wipeIncludeVault ? "local data wiped (including vault)" : "local settings wiped", "danger");
      setStatus({ message: "data wiped", tone: "danger" });
      setWipeDialogOpen(false);
      setWipeConfirmText("");
      setWipeError(null);
    } catch (error) {
      console.error(error);
      const message = error instanceof Error ? error.message : "wipe failed";
      setWipeError(message);
      push(message, "danger");
    } finally {
      setWipeBusy(false);
    }
  }, [push, setActiveModule, wipeConfirmText, wipeIncludeVault]);

  const navigationCommands: CommandItem[] = useMemo(
    () =>
      modules.map((module) => ({
        id: `:${module.key}`,
        label: module.title,
        description: module.subtitle,
        group: t("app.command.toolsGroup"),
        action: () => handleSelectModule(module.key),
      })),
    [handleSelectModule, modules, t],
  );

  const contextualCommands: CommandItem[] = useMemo(() => {
    const base: CommandItem[] = [
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
        action: openWipeDialog,
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
      base.unshift(
        {
          id: "compare",
          label: t("app.command.compareDigest"),
          description: t("app.command.compareDigestDesc"),
          group: t("app.command.hashGroup"),
          shortcut: "Enter",
          action: hashActions?.compare ?? (() => {}),
          disabled: !hashActions,
        },
        {
          id: "clear-inputs",
          label: t("app.command.clearInputs"),
          description: t("app.command.clearInputsDesc"),
          group: t("app.command.hashGroup"),
          action: hashActions?.clearInputs ?? (() => {}),
          disabled: !hashActions,
        },
        {
          id: "copy-digest",
          label: t("app.command.copyDigest"),
          description: t("app.command.copyDigestDesc"),
          group: t("app.command.hashGroup"),
          shortcut: "C",
          action: hashActions?.copyDigest ?? (() => {}),
          disabled: !hashActions,
        },
      );
    }

    return base;
  }, [activeModule, hashActions, openProfileExportDialog, openWipeDialog, push, setLocale, startOnboarding, t, toggleTheme]);

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
    const handleKey = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      const tagName = target?.tagName?.toLowerCase();
      const isInput =
        target?.isContentEditable ||
        tagName === "input" ||
        tagName === "textarea" ||
        tagName === "select";

      if (event.key === "/" && !event.metaKey && !event.ctrlKey) {
        if (isInput) return;
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

  const handleCommandSelect = useCallback(
    async (command: CommandItem) => {
      try {
        await command.action();
        setStatus({ message: `command :: ${command.id}`, tone: "accent" });
        push(`command :: ${command.id}`, "accent");
      } catch (error) {
        console.error(error);
        setStatus({ message: `error :: ${command.id}`, tone: "danger" });
        push(`error :: ${command.id}`, "danger");
      } finally {
        closePalette();
      }
    },
    [closePalette, push],
  );

  const isStacked = viewport.width < 1100;
  const isCompact = viewport.width < 960 || viewport.height < 820;

  const goToGuide = useCallback(
    (key?: ModuleKey) => {
      setActiveModule("guide");
      setStatus({ message: "guide", tone: "accent" });
      if (key) {
        window.location.hash = `#${key}`;
      }
    },
    [setActiveModule],
  );

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

  const onboardingSteps = useMemo<OnboardingStep[]>(
    () => [
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
    ],
    [goToGuide, handleSelectModule, openPalette, t],
  );

  return (
    <div className={`app-surface ${isCompact ? "is-compact" : ""}`}>
      <input
        ref={importProfileInputRef}
        type="file"
        accept="application/json"
        style={{ position: "absolute", opacity: 0, width: 1, height: 1, pointerEvents: "none" }}
        tabIndex={-1}
        onChange={async (event) => {
          const file = event.target.files?.[0];
          await beginProfileImportFlow(file);
          event.target.value = "";
        }}
      />
      <Frame
        stacked={isStacked}
        compact={isCompact}
        buildMarker={buildMarker}
        modulePane={<ModuleList modules={modules} active={resolvedActiveModule} onSelect={handleSelectModule} />}
        header={
          <GlobalHeader
            brand="NullID"
            pageTitle={moduleLookup[resolvedActiveModule].title}
            pageToken={`:${resolvedActiveModule}`}
            status={status}
            theme={theme}
            locale={locale}
            compact={isCompact}
            onToggleTheme={toggleTheme}
            onLocaleChange={setLocale}
            onOpenCommands={openPalette}
            onWipe={openWipeDialog}
          />
        }
        workspace={
          <div className="workspace">
            <WorkspaceView
              active={resolvedActiveModule}
              onRegisterHashActions={setHashActions}
              onStatus={handleStatus}
              onOpenGuide={goToGuide}
            />
          </div>
        }
      />
      <CommandPalette
        open={paletteOpen}
        commands={commandList}
        completions={modules.map((module) => module.key)}
        historyKey="command-bar"
        onClose={closePalette}
        onSelect={handleCommandSelect}
      />
      <ActionDialog
        open={wipeDialogOpen}
        title={tr("Wipe local data")}
        description={tr("This only clears NullID-managed local state on this origin. Type WIPE to continue.")}
        confirmLabel={wipeBusy ? tr("wiping…") : tr("wipe now")}
        confirmDisabled={wipeBusy || wipeConfirmText.trim().toUpperCase() !== "WIPE"}
        danger
        onCancel={closeWipeDialog}
        onConfirm={() => void confirmWipe()}
      >
        <p className="action-dialog-note">
          {tr("Recommended: export your profile first. Vault backups can be exported from :vault before wiping.")}
        </p>
        <div className="action-dialog-row">
          <button
            type="button"
            className="button"
            onClick={() => {
              setWipeDialogOpen(false);
              openProfileExportDialog();
            }}
          >
            {tr("export profile first")}
          </button>
          <button
            type="button"
            className="button"
            onClick={() => {
              setWipeDialogOpen(false);
              handleSelectModule("vault");
            }}
          >
            {tr("open :vault backup")}
          </button>
        </div>
        <label className="action-dialog-field">
          <span>{tr("Also wipe vault data")}</span>
          <input
            type="checkbox"
            checked={wipeIncludeVault}
            onChange={(event) => setWipeIncludeVault(event.target.checked)}
            aria-label={tr("Also wipe vault data")}
            disabled={wipeBusy}
          />
        </label>
        <label className="action-dialog-field">
          <span>{tr("Type WIPE to confirm")}</span>
          <input
            className="action-dialog-input"
            value={wipeConfirmText}
            onChange={(event) => {
              setWipeConfirmText(event.target.value);
              if (wipeError) setWipeError(null);
            }}
            aria-label={tr("Type WIPE to confirm")}
            placeholder="WIPE"
            autoComplete="off"
            disabled={wipeBusy}
          />
        </label>
        {wipeError ? <p className="action-dialog-error">{wipeError}</p> : null}
      </ActionDialog>
      <ActionDialog
        open={profileExportOpen}
        title={tr("Export profile snapshot")}
        description={tr("Export local nullid:* settings as JSON. Signed exports require a verification passphrase on import.")}
        confirmLabel={tr("export profile")}
        onCancel={closeProfileExportDialog}
        onConfirm={() => void confirmProfileExport()}
        confirmDisabled={profileExportSign && !profileExportPassphrase.trim()}
      >
        <label className="action-dialog-field">
          <span>{tr("Sign metadata")}</span>
          <input
            type="checkbox"
            checked={profileExportSign}
            onChange={(event) => setProfileExportSign(event.target.checked)}
            aria-label={tr("Sign profile metadata")}
          />
        </label>
        {profileExportSign ? (
          <>
            <div className="status-line">
              <span>trust state</span>
              <span className={trustTagClass(profileExportTrustState)}>{profileExportTrustState}</span>
              {profileExportKeyHint.trim() ? <span className="microcopy">hint: {profileExportKeyHint.trim()}</span> : null}
            </div>
            <label className="action-dialog-field">
              <span>{tr("Signing passphrase")}</span>
              <input
                className="action-dialog-input"
                type="password"
                value={profileExportPassphrase}
                onChange={(event) => {
                  setProfileExportPassphrase(event.target.value);
                  if (profileExportError) setProfileExportError(null);
                }}
                aria-label={tr("Profile signing passphrase")}
                placeholder={tr("required when signing")}
              />
            </label>
            <div className="action-dialog-row">
              <label className="action-dialog-field">
                <span>{tr("Saved key hint")}</span>
                <select
                  className="action-dialog-select"
                  value={selectedKeyHintProfileId}
                  onChange={(event) => {
                    const nextId = event.target.value;
                    setSelectedKeyHintProfileId(nextId);
                    const profile = keyHintProfiles.find((entry) => entry.id === nextId);
                    setProfileExportKeyHint(profile?.keyHint ?? "");
                  }}
                  aria-label={tr("Saved key hint profile")}
                >
                  <option value="">{tr("custom key hint")}</option>
                  {keyHintProfiles.map((profile) => (
                    <option key={profile.id} value={profile.id}>
                      {profile.name} · {profile.keyHint}
                    </option>
                  ))}
                </select>
              </label>
              <label className="action-dialog-field">
                <span>{tr("Key hint label")}</span>
                <input
                  className="action-dialog-input"
                  value={profileExportKeyHint}
                  onChange={(event) => setProfileExportKeyHint(event.target.value)}
                  aria-label={tr("Profile key hint")}
                  placeholder={tr("optional recipient-visible hint")}
                />
              </label>
            </div>
            <div className="action-dialog-row">
              <label className="action-dialog-field">
                <span>{tr("Save key hint profile as")}</span>
                <input
                  className="action-dialog-input"
                  value={keyHintProfileName}
                  onChange={(event) => setKeyHintProfileName(event.target.value)}
                  aria-label={tr("Key hint profile name")}
                  placeholder="team-signing-key"
                />
              </label>
              <button type="button" className="button" onClick={saveProfileHint} disabled={!profileExportKeyHint.trim()}>
                {tr("save hint")}
              </button>
            </div>
            <p className="action-dialog-note">
              {tr("Key hints are local labels only. Passphrases are not persisted.")}
              {selectedKeyHintProfile ? ` Active: ${selectedKeyHintProfile.name} (v${selectedKeyHintProfile.version})` : ""}
            </p>
          </>
        ) : (
          <p className="action-dialog-note">{tr("Unsigned profile exports can still be imported, but signature verification is unavailable.")}</p>
        )}
        {profileExportError ? <p className="action-dialog-error">{profileExportError}</p> : null}
      </ActionDialog>
      <ActionDialog
        open={profileImportOpen}
        title={tr("Import profile snapshot")}
        description={
          profileImportDescriptor
            ? `${profileImportDescriptor.entryCount} entries · ${profileImportDescriptor.legacy ? "legacy" : `schema ${profileImportDescriptor.schemaVersion}`}`
            : tr("Select import settings")
        }
        confirmLabel={tr("import profile")}
        onCancel={closeProfileImportDialog}
        onConfirm={() => void confirmProfileImport()}
      >
        {profileImportDescriptor?.signed ? (
          <>
            <div className="status-line">
              <span>trust state</span>
              <span className={trustTagClass(profileImportTrustState)}>{profileImportTrustState}</span>
              {profileImportDescriptor.keyHint ? <span className="microcopy">{tr("hint")}: {profileImportDescriptor.keyHint}</span> : null}
            </div>
            <p className="action-dialog-note">
              {tr("Signed profile detected")}{profileImportDescriptor.keyHint ? ` (${tr("hint")}: ${profileImportDescriptor.keyHint})` : ""}. {tr("Verification is required before import.")}
            </p>
            <label className="action-dialog-field">
              <span>{tr("Verification passphrase")}</span>
              <input
                className="action-dialog-input"
                type="password"
                value={profileImportPassphrase}
                onChange={(event) => {
                  setProfileImportPassphrase(event.target.value);
                  if (profileImportError) setProfileImportError(null);
                }}
                aria-label={tr("Profile verification passphrase")}
                placeholder={tr("required for signed profile")}
              />
            </label>
          </>
        ) : (
          <>
            <div className="status-line">
              <span>trust state</span>
              <span className={trustTagClass(profileImportTrustState)}>{profileImportTrustState}</span>
            </div>
            <p className="action-dialog-note">{tr("Unsigned profile snapshot. Continue only if you trust the source.")}</p>
          </>
        )}
        {profileImportError ? <p className="action-dialog-error">{profileImportError}</p> : null}
      </ActionDialog>
      <FeedbackWidget activeModule={resolvedActiveModule} />
      <OnboardingTour
        open={tourOpen}
        stepIndex={tourStepIndex}
        steps={onboardingSteps}
        onStepIndexChange={setTourStepIndex}
        onSkip={skipOnboarding}
        onFinish={finishOnboarding}
      />
    </div>
  );
}

export default function App() {
  return (
    <I18nProvider>
      <ToastProvider>
        <ErrorBoundary>
          <AppShell />
        </ErrorBoundary>
      </ToastProvider>
    </I18nProvider>
  );
}

function trustTagClass(state: TrustState): string {
  if (state === "verified") return "tag tag-accent";
  if (state === "mismatch") return "tag tag-danger";
  return "tag";
}

function clearManagedLocalState(options: { includeVault: boolean }) {
  const prefixes = ["nullid:", "nullid-history:"];
  const keysToRemove: string[] = [];

  for (let index = 0; index < localStorage.length; index += 1) {
    const key = localStorage.key(index);
    if (!key) continue;
    if (!prefixes.some((prefix) => key.startsWith(prefix))) continue;
    if (!options.includeVault && key.startsWith("nullid:vault:")) continue;
    keysToRemove.push(key);
  }

  keysToRemove.forEach((key) => localStorage.removeItem(key));
}
