import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { CommandPalette, CommandItem } from "./components/CommandPalette";
import { Frame } from "./components/Frame";
import { GlobalHeader } from "./components/GlobalHeader";
import { ModuleDefinition, ModuleKey, ModuleList } from "./components/ModuleList";
import { EncView } from "./views/EncView";
import { HashView, HashViewActions } from "./views/HashView";
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
import type { ThemeMode } from "./theme/tokens";
import { downloadProfile, importProfileFile } from "./utils/profile";
import { ErrorBoundary } from "./components/ErrorBoundary";

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
  switch (active) {
    case "hash":
      return <HashView onRegisterActions={onRegisterHashActions} onStatus={onStatus} onOpenGuide={onOpenGuide} />;
    case "redact":
      return <RedactView onOpenGuide={onOpenGuide} />;
    case "sanitize":
      return <SanitizeView onOpenGuide={onOpenGuide} />;
    case "meta":
      return <MetaView onOpenGuide={onOpenGuide} />;
    case "enc":
      return <EncView onOpenGuide={onOpenGuide} />;
    case "pw":
      return <PwView onOpenGuide={onOpenGuide} />;
    case "vault":
      return <VaultView onOpenGuide={onOpenGuide} />;
    case "selftest":
      return <SelfTestView onOpenGuide={onOpenGuide} />;
    case "guide":
      return <GuideView />;
    default:
      return null;
  }
}

function AppShell() {
  const { push } = useToast();
  const [activeModule, setActiveModule] = usePersistentState<ModuleKey>("nullid:last-module", "hash");
  const [status, setStatus] = useState({ message: "ready", tone: "neutral" as StatusTone });
  const [theme, setTheme] = usePersistentState<ThemeMode>("nullid:theme", "light");
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [hashActions, setHashActions] = useState<HashViewActions | null>(null);
  const [viewport, setViewport] = useState({ width: window.innerWidth, height: window.innerHeight });
  const importProfileInputRef = useRef<HTMLInputElement>(null);
  const moduleLookup = useMemo(
    () => Object.fromEntries(modules.map((module) => [module.key, module])) as Record<ModuleKey, ModuleDefinition>,
    [],
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
        action: () => {
          downloadProfile(`nullid-profile-${Date.now()}.json`);
          push("profile exported", "accent");
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
          if (!file) return;
          try {
            const { applied } = await importProfileFile(file);
            push(`profile imported (${applied})`, "accent");
            setStatus({ message: "profile imported", tone: "accent" });
            window.location.reload();
          } catch (error) {
            console.error(error);
            push("import failed", "danger");
            setStatus({ message: "import failed", tone: "danger" });
          }
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
              onStatus={(message, tone = "neutral") => setStatus({ message, tone })}
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
