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
const modules: ModuleDefinition[] = [
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

interface WorkspaceViewProps {
  active: ModuleKey;
  onRegisterHashActions?: (actions: HashViewActions | null) => void;
  onStatus?: (message: string, tone?: StatusTone) => void;
  onOpenGuide?: (key?: ModuleKey) => void;
}

function WorkspaceView({ active, onRegisterHashActions, onStatus, onOpenGuide }: WorkspaceViewProps) {
  return (
    <Suspense fallback={<div className="workspace-loading">loading module...</div>}>
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
  const importProfileInputRef = useRef<HTMLInputElement>(null);
  const moduleLookup = useMemo(
    () => Object.fromEntries(modules.map((module) => [module.key, module])) as Record<ModuleKey, ModuleDefinition>,
    [],
  );
  const selectedKeyHintProfile = useMemo(
    () => keyHintProfiles.find((profile) => profile.id === selectedKeyHintProfileId) ?? null,
    [keyHintProfiles, selectedKeyHintProfileId],
  );

  const resolvedActiveModule = useMemo<ModuleKey>(
    () => (modules.some((module) => module.key === activeModule) ? activeModule : "guide"),
    [activeModule],
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

  const navigationCommands: CommandItem[] = useMemo(
    () =>
      modules.map((module) => ({
        id: `:${module.key}`,
        label: module.title,
        description: module.subtitle,
        group: "Tools",
        action: () => handleSelectModule(module.key),
      })),
    [handleSelectModule],
  );

  const contextualCommands: CommandItem[] = useMemo(() => {
    const base: CommandItem[] = [
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
        action: openProfileExportDialog,
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
      {
        id: "onboarding",
        label: "Run onboarding",
        description: "Replay quick setup tour",
        group: "System",
        action: startOnboarding,
      },
    ];

    if (activeModule === "hash") {
      base.unshift(
        {
          id: "compare",
          label: "Compare digest",
          description: "Validate against provided hash",
          group: "Hash actions",
          shortcut: "Enter",
          action: hashActions?.compare ?? (() => {}),
          disabled: !hashActions,
        },
        {
          id: "clear-inputs",
          label: "Clear inputs",
          description: "Reset text, file, and verify fields",
          group: "Hash actions",
          action: hashActions?.clearInputs ?? (() => {}),
          disabled: !hashActions,
        },
        {
          id: "copy-digest",
          label: "Copy digest",
          description: "Copy computed hash to clipboard",
          group: "Hash actions",
          shortcut: "C",
          action: hashActions?.copyDigest ?? (() => {}),
          disabled: !hashActions,
        },
      );
    }

    return base;
  }, [activeModule, hashActions, openProfileExportDialog, startOnboarding, toggleTheme]);

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
  const isCompact = viewport.height < 820;

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
        title: "Start with the Guide",
        body: "Every tool has limits and safe defaults. The guide gives the shortest path to avoid common mistakes.",
        actionLabel: "open guide",
        onAction: () => goToGuide(),
      },
      {
        id: "password",
        title: "Use the Strength Lab",
        body: "The Password & Passphrase module now includes a larger dictionary, hardening toggles, and secret auditing.",
        actionLabel: "open :pw",
        onAction: () => handleSelectModule("pw"),
      },
      {
        id: "sanitize",
        title: "Sanitize before sharing",
        body: "Use the Log Sanitizer for policy packs, diff preview, and bundle exports when sharing logs externally.",
        actionLabel: "open :sanitize",
        onAction: () => handleSelectModule("sanitize"),
      },
      {
        id: "commands",
        title: "Drive the app from commands",
        body: "Press / or Cmd/Ctrl+K for fast navigation, profile export/import, and system actions.",
        actionLabel: "open commands",
        onAction: openPalette,
      },
      {
        id: "feedback",
        title: "Track feedback locally",
        body: "Use the feedback button at the bottom-right to save issues and ideas locally, then export as JSON.",
      },
    ],
    [goToGuide, handleSelectModule, openPalette],
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
        modulePane={<ModuleList modules={modules} active={resolvedActiveModule} onSelect={handleSelectModule} />}
        header={
          <GlobalHeader
            brand="NullID"
            pageTitle={moduleLookup[resolvedActiveModule].title}
            pageToken={`:${resolvedActiveModule}`}
            status={status}
            theme={theme}
            compact={isCompact}
            onToggleTheme={toggleTheme}
            onOpenCommands={openPalette}
            onWipe={() => {
              localStorage.clear();
              void wipeVault();
              push("local data wiped", "danger");
            }}
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
        open={profileExportOpen}
        title="Export profile snapshot"
        description="Export local nullid:* settings as JSON. Signed exports require a verification passphrase on import."
        confirmLabel="export profile"
        onCancel={closeProfileExportDialog}
        onConfirm={() => void confirmProfileExport()}
        confirmDisabled={profileExportSign && !profileExportPassphrase.trim()}
      >
        <label className="action-dialog-field">
          <span>Sign metadata</span>
          <input
            type="checkbox"
            checked={profileExportSign}
            onChange={(event) => setProfileExportSign(event.target.checked)}
            aria-label="Sign profile metadata"
          />
        </label>
        {profileExportSign ? (
          <>
            <label className="action-dialog-field">
              <span>Signing passphrase</span>
              <input
                className="action-dialog-input"
                type="password"
                value={profileExportPassphrase}
                onChange={(event) => {
                  setProfileExportPassphrase(event.target.value);
                  if (profileExportError) setProfileExportError(null);
                }}
                aria-label="Profile signing passphrase"
                placeholder="required when signing"
              />
            </label>
            <div className="action-dialog-row">
              <label className="action-dialog-field">
                <span>Saved key hint</span>
                <select
                  className="action-dialog-select"
                  value={selectedKeyHintProfileId}
                  onChange={(event) => {
                    const nextId = event.target.value;
                    setSelectedKeyHintProfileId(nextId);
                    const profile = keyHintProfiles.find((entry) => entry.id === nextId);
                    setProfileExportKeyHint(profile?.keyHint ?? "");
                  }}
                  aria-label="Saved key hint profile"
                >
                  <option value="">custom key hint</option>
                  {keyHintProfiles.map((profile) => (
                    <option key={profile.id} value={profile.id}>
                      {profile.name} · {profile.keyHint}
                    </option>
                  ))}
                </select>
              </label>
              <label className="action-dialog-field">
                <span>Key hint label</span>
                <input
                  className="action-dialog-input"
                  value={profileExportKeyHint}
                  onChange={(event) => setProfileExportKeyHint(event.target.value)}
                  aria-label="Profile key hint"
                  placeholder="optional recipient-visible hint"
                />
              </label>
            </div>
            <div className="action-dialog-row">
              <label className="action-dialog-field">
                <span>Save key hint profile as</span>
                <input
                  className="action-dialog-input"
                  value={keyHintProfileName}
                  onChange={(event) => setKeyHintProfileName(event.target.value)}
                  aria-label="Key hint profile name"
                  placeholder="team-signing-key"
                />
              </label>
              <button type="button" className="button" onClick={saveProfileHint} disabled={!profileExportKeyHint.trim()}>
                save hint
              </button>
            </div>
            <p className="action-dialog-note">
              Key hints are local labels only. Passphrases are not persisted.
              {selectedKeyHintProfile ? ` Active: ${selectedKeyHintProfile.name} (v${selectedKeyHintProfile.version})` : ""}
            </p>
          </>
        ) : (
          <p className="action-dialog-note">Unsigned profile exports can still be imported, but signature verification is unavailable.</p>
        )}
        {profileExportError ? <p className="action-dialog-error">{profileExportError}</p> : null}
      </ActionDialog>
      <ActionDialog
        open={profileImportOpen}
        title="Import profile snapshot"
        description={
          profileImportDescriptor
            ? `${profileImportDescriptor.entryCount} entries · ${profileImportDescriptor.legacy ? "legacy" : `schema ${profileImportDescriptor.schemaVersion}`}`
            : "Select import settings"
        }
        confirmLabel="import profile"
        onCancel={closeProfileImportDialog}
        onConfirm={() => void confirmProfileImport()}
      >
        {profileImportDescriptor?.signed ? (
          <>
            <p className="action-dialog-note">
              Signed profile detected{profileImportDescriptor.keyHint ? ` (hint: ${profileImportDescriptor.keyHint})` : ""}. Verification is required before import.
            </p>
            <label className="action-dialog-field">
              <span>Verification passphrase</span>
              <input
                className="action-dialog-input"
                type="password"
                value={profileImportPassphrase}
                onChange={(event) => {
                  setProfileImportPassphrase(event.target.value);
                  if (profileImportError) setProfileImportError(null);
                }}
                aria-label="Profile verification passphrase"
                placeholder="required for signed profile"
              />
            </label>
          </>
        ) : (
          <p className="action-dialog-note">Unsigned profile snapshot. Continue only if you trust the source.</p>
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
    <ToastProvider>
      <ErrorBoundary>
        <AppShell />
      </ErrorBoundary>
    </ToastProvider>
  );
}
