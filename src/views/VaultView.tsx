import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import "./styles.css";
import { Chip } from "../components/Chip";
import { ActionDialog } from "../components/ActionDialog";
import { useToast } from "../components/ToastHost";
import {
  describeVaultPayload,
  decryptNote,
  deleteNote,
  exportVault,
  exportVaultEncrypted,
  importVault,
  importVaultEncrypted,
  loadNotes,
  saveNote,
  type VaultSnapshotDescriptor,
  unlockVault,
} from "../utils/vault";
import { getVaultBackendInfo, wipeVault } from "../utils/storage";
import type { ModuleKey } from "../components/ModuleList";
import { analyzeSecret, gradeLabel, type SecretGrade } from "../utils/passwordToolkit";
import { usePersistentState } from "../hooks/usePersistentState";
import {
  SHARED_KEY_HINT_PROFILE_KEY,
  readLegacyProfiles,
  sanitizeKeyHint,
  type KeyHintProfile,
} from "../utils/keyHintProfiles";

type DecryptedNote = { id: string; title: string; body: string; tags: string[]; createdAt: number; updatedAt: number };

interface VaultViewProps {
  onOpenGuide?: (key?: ModuleKey) => void;
}

export function VaultView({ onOpenGuide }: VaultViewProps) {
  const { push } = useToast();
  const [passphrase, setPassphrase] = useState("");
  const [unlocked, setUnlocked] = useState(false);
  const [key, setKey] = useState<CryptoKey | null>(null);
  const [notes, setNotes] = useState<DecryptedNote[]>([]);
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [filter, setFilter] = useState("");
  const [tags, setTags] = useState("");
  const [activeId, setActiveId] = useState<string | null>(null);
  const [autoLockSeconds, setAutoLockSeconds] = useState(300);
  const [lockTimer, setLockTimer] = useState<number | null>(null);
  const [lockDeadlineMs, setLockDeadlineMs] = useState<number | null>(null);
  const [lockRemaining, setLockRemaining] = useState<number>(0);
  const [backendInfo, setBackendInfo] = useState(() => getVaultBackendInfo());
  const [template, setTemplate] = useState<"blank" | "incident" | "credentials" | "checklist">("blank");
  const [keyHintProfiles, setKeyHintProfiles] = usePersistentState<KeyHintProfile[]>(SHARED_KEY_HINT_PROFILE_KEY, []);
  const [selectedKeyHintProfileId, setSelectedKeyHintProfileId] = usePersistentState<string>("nullid:vault:key-hint-selected", "");
  const [vaultExportDialogOpen, setVaultExportDialogOpen] = useState(false);
  const [vaultExportMode, setVaultExportMode] = useState<"plain" | "encrypted">("plain");
  const [vaultExportPassphrase, setVaultExportPassphrase] = useState("");
  const [vaultExportSign, setVaultExportSign] = useState(false);
  const [vaultSigningPassphrase, setVaultSigningPassphrase] = useState("");
  const [vaultExportKeyHint, setVaultExportKeyHint] = useState("");
  const [vaultExportError, setVaultExportError] = useState<string | null>(null);
  const [vaultImportDialogOpen, setVaultImportDialogOpen] = useState(false);
  const [vaultImportMode, setVaultImportMode] = useState<"plain" | "encrypted">("plain");
  const [vaultImportFile, setVaultImportFile] = useState<File | null>(null);
  const [vaultImportDescriptor, setVaultImportDescriptor] = useState<VaultSnapshotDescriptor | null>(null);
  const [vaultImportExportPassphrase, setVaultImportExportPassphrase] = useState("");
  const [vaultImportVerifyPassphrase, setVaultImportVerifyPassphrase] = useState("");
  const [vaultImportError, setVaultImportError] = useState<string | null>(null);
  const [reportDialogOpen, setReportDialogOpen] = useState(false);
  const [reportIncludeBodies, setReportIncludeBodies] = useState(false);
  const [wipeDialogOpen, setWipeDialogOpen] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const encryptedImportRef = useRef<HTMLInputElement>(null);
  const formatTs = useCallback((value: number) => new Date(value).toLocaleString(), []);
  const passphraseAssessment = useMemo(() => analyzeSecret(passphrase), [passphrase]);
  const selectedKeyHintProfile = useMemo(
    () => keyHintProfiles.find((profile) => profile.id === selectedKeyHintProfileId) ?? null,
    [keyHintProfiles, selectedKeyHintProfileId],
  );

  const filteredNotes = useMemo(
    () =>
      notes.filter((note) => {
        const query = filter.toLowerCase();
        return (
          note.title.toLowerCase().includes(query) ||
          note.body.toLowerCase().includes(query) ||
          note.tags.some((tag) => tag.toLowerCase().includes(query))
        );
      }),
    [filter, notes],
  );
  const vaultStats = useMemo(() => {
    const uniqueTags = new Set(notes.flatMap((note) => note.tags));
    const totalChars = notes.reduce((sum, note) => sum + note.body.length + note.title.length, 0);
    return {
      totalNotes: notes.length,
      filteredNotes: filteredNotes.length,
      totalChars,
      avgChars: notes.length ? Math.round(totalChars / notes.length) : 0,
      uniqueTags: uniqueTags.size,
      latestUpdate: notes.length ? Math.max(...notes.map((note) => note.updatedAt)) : null,
    };
  }, [filteredNotes.length, notes]);

  useEffect(() => {
    if (keyHintProfiles.length > 0) return;
    const legacy = readLegacyProfiles("nullid:sanitize:key-hints");
    if (legacy.length > 0) {
      setKeyHintProfiles(legacy);
    }
  }, [keyHintProfiles.length, setKeyHintProfiles]);

  const resetLockTimer = useCallback(() => {
    if (lockTimer) {
      window.clearTimeout(lockTimer);
    }
    const deadline = Date.now() + autoLockSeconds * 1000;
    setLockDeadlineMs(deadline);
    const timer = window.setTimeout(() => {
      setUnlocked(false);
      setKey(null);
      setNotes([]);
      setLockDeadlineMs(null);
      setLockRemaining(0);
      push("vault locked (timeout)", "neutral");
    }, autoLockSeconds * 1000);
    setLockTimer(timer);
  }, [autoLockSeconds, lockTimer, push]);

  useEffect(() => {
    if (unlocked) {
      resetLockTimer();
    }
  }, [autoLockSeconds, resetLockTimer, unlocked]);

  useEffect(() => {
    setBackendInfo(getVaultBackendInfo());
  }, [unlocked, notes.length]);

  useEffect(() => {
    if (backendInfo.fallbackReason) {
      push(`storage fallback: ${backendInfo.fallbackReason}`, "danger");
    }
  }, [backendInfo.fallbackReason, push]);

  useEffect(() => () => {
    if (lockTimer) window.clearTimeout(lockTimer);
  }, [lockTimer]);

  useEffect(() => {
    if (!lockDeadlineMs || !unlocked) {
      setLockRemaining(0);
      return;
    }
    const tick = () => {
      const seconds = Math.max(0, Math.ceil((lockDeadlineMs - Date.now()) / 1000));
      setLockRemaining(seconds);
    };
    tick();
    const timer = window.setInterval(tick, 1000);
    return () => window.clearInterval(timer);
  }, [lockDeadlineMs, unlocked]);

  useEffect(() => {
    if (!unlocked) return;
    const handleActivity = () => resetLockTimer();
    const events: (keyof WindowEventMap)[] = ["mousemove", "keydown", "pointerdown", "scroll"];
    events.forEach((eventName) => window.addEventListener(eventName, handleActivity, { passive: true }));
    return () => events.forEach((eventName) => window.removeEventListener(eventName, handleActivity));
  }, [resetLockTimer, unlocked]);

  const handleUnlock = useCallback(async () => {
    if (!passphrase) return;
    try {
      const derived = await unlockVault(passphrase);
      setKey(derived);
      setUnlocked(true);
      push("vault unlocked", "accent");
      setBackendInfo(getVaultBackendInfo());
      const stored = await loadNotes();
      const decrypted = await Promise.all(
        stored.map(async (note) => {
          const data = await decryptNote(derived, note);
          return {
            id: note.id,
            updatedAt: note.updatedAt,
            title: data.title,
            body: data.body,
            tags: data.tags ?? [],
            createdAt: data.createdAt ?? note.updatedAt,
          };
        }),
      );
      setNotes(decrypted.sort((a, b) => b.updatedAt - a.updatedAt));
      resetLockTimer();
    } catch (error) {
      console.error(error);
      push("unlock failed: passphrase or data invalid", "danger");
      setUnlocked(false);
      setKey(null);
      setNotes([]);
      setBackendInfo(getVaultBackendInfo());
    }
  }, [passphrase, push, resetLockTimer]);

  const handleSave = useCallback(async () => {
    if (!key || !title.trim() || !body.trim()) return;
    const id = activeId ?? crypto.randomUUID();
    const existing = notes.find((note) => note.id === id);
    const createdAt = existing?.createdAt ?? Date.now();
    const tagsList = tags
      .split(",")
      .map((tag) => tag.trim())
      .filter(Boolean);
    try {
      await saveNote(key, id, title.trim(), body.trim(), { createdAt, tags: tagsList });
      const updated = { id, title: title.trim(), body: body.trim(), tags: tagsList, createdAt, updatedAt: Date.now() };
      setNotes((prev) => {
        const other = prev.filter((note) => note.id !== id);
        return [updated, ...other].sort((a, b) => b.updatedAt - a.updatedAt);
      });
      setTitle("");
      setBody("");
      setTags("");
      setActiveId(null);
      push("note saved", "accent");
      resetLockTimer();
    } catch (error) {
      console.error(error);
      push("save failed (storage blocked?)", "danger");
      setBackendInfo(getVaultBackendInfo());
    }
  }, [activeId, body, key, notes, push, resetLockTimer, tags, title]);

  const handleEdit = useCallback(
    (note: DecryptedNote) => {
      setTitle(note.title);
      setBody(note.body);
      setTags(note.tags.join(", "));
      setActiveId(note.id);
      resetLockTimer();
    },
    [resetLockTimer],
  );

  const handleDelete = useCallback(
    async (id: string) => {
      if (!key) return;
      await deleteNote(id);
      setNotes((prev) => prev.filter((note) => note.id !== id));
      push("note deleted", "neutral");
      resetLockTimer();
    },
    [key, push, resetLockTimer],
  );

  const handleLock = useCallback(() => {
    if (lockTimer) {
      window.clearTimeout(lockTimer);
      setLockTimer(null);
    }
    setUnlocked(false);
    setKey(null);
    setLockDeadlineMs(null);
    setLockRemaining(0);
    setNotes([]);
    setTitle("");
    setBody("");
    setTags("");
    setActiveId(null);
    setPassphrase("");
    push("vault locked", "neutral");
  }, [lockTimer, push]);

  const applyTemplate = useCallback(
    (next: "blank" | "incident" | "credentials" | "checklist") => {
      setTemplate(next);
      if (next === "blank") {
        setTitle("");
        setBody("");
        setTags("");
        return;
      }
      if (next === "incident") {
        setTitle(`Incident ${new Date().toISOString().slice(0, 10)}`);
        setBody("Summary:\nImpact:\nIndicators:\nActions taken:\nNext steps:");
        setTags("incident,triage");
      } else if (next === "credentials") {
        setTitle("Credential inventory");
        setBody("System:\nAccount:\nRotation date:\nRecovery path:\nNotes:");
        setTags("credentials,rotation");
      } else {
        setTitle("Security checklist");
        setBody("- [ ] Validate artifact hash\n- [ ] Sanitize logs\n- [ ] Export signed snapshot\n- [ ] Confirm recipient");
        setTags("checklist,ops");
      }
      if (unlocked) resetLockTimer();
    },
    [resetLockTimer, unlocked],
  );

  const handleWipe = useCallback(async () => {
    await wipeVault();
    handleLock();
    push("vault wiped", "danger");
  }, [handleLock, push]);

  const openVaultExportDialog = useCallback(
    (mode: "plain" | "encrypted") => {
      setVaultExportMode(mode);
      setVaultExportPassphrase("");
      setVaultExportSign(false);
      setVaultSigningPassphrase("");
      setVaultExportKeyHint(selectedKeyHintProfile?.keyHint ?? "");
      setVaultExportError(null);
      setVaultExportDialogOpen(true);
    },
    [selectedKeyHintProfile],
  );

  const closeVaultExportDialog = useCallback(() => {
    setVaultExportDialogOpen(false);
    setVaultExportError(null);
    setVaultExportPassphrase("");
    setVaultSigningPassphrase("");
  }, []);

  const confirmVaultExport = useCallback(async () => {
    if (vaultExportMode === "encrypted" && !vaultExportPassphrase.trim()) {
      setVaultExportError("export passphrase required for encrypted export");
      return;
    }
    if (vaultExportSign && !vaultSigningPassphrase.trim()) {
      setVaultExportError("signing passphrase required when metadata signing is enabled");
      return;
    }
    try {
      const options = {
        signingPassphrase: vaultExportSign ? vaultSigningPassphrase : undefined,
        keyHint: vaultExportSign ? sanitizeKeyHint(vaultExportKeyHint) || undefined : undefined,
      };
      const blob =
        vaultExportMode === "encrypted"
          ? await exportVaultEncrypted(vaultExportPassphrase.trim(), options)
          : await exportVault(options);
      const filename = vaultExportMode === "encrypted" ? "nullid-vault.enc" : "nullid-vault.json";
      downloadBlob(blob, filename);
      push(
        vaultExportMode === "encrypted"
          ? `encrypted export ready${vaultExportSign ? " (signed metadata)" : ""}`
          : `vault export ready${vaultExportSign ? " (signed)" : ""}`,
        "accent",
      );
      closeVaultExportDialog();
    } catch (error) {
      console.error(error);
      setVaultExportError(error instanceof Error ? error.message : "vault export failed");
    }
  }, [
    closeVaultExportDialog,
    push,
    vaultExportKeyHint,
    vaultExportMode,
    vaultExportPassphrase,
    vaultExportSign,
    vaultSigningPassphrase,
  ]);

  const handleImport = useCallback(() => {
    fileInputRef.current?.click();
  }, []);

  const beginVaultImport = useCallback(
    async (file?: File | null, mode: "plain" | "encrypted" = "plain") => {
      if (!file) return;
      try {
        setVaultImportFile(file);
        setVaultImportMode(mode);
        setVaultImportError(null);
        setVaultImportVerifyPassphrase("");
        setVaultImportExportPassphrase("");
        if (mode === "plain") {
          const parsed = JSON.parse(await file.text()) as unknown;
          setVaultImportDescriptor(describeVaultPayload(parsed));
        } else {
          setVaultImportDescriptor(null);
        }
        setVaultImportDialogOpen(true);
      } catch (error) {
        console.error(error);
        const message = error instanceof Error ? error.message : "vault import failed";
        push(`vault import failed: ${message}`, "danger");
      }
    },
    [push],
  );

  const closeVaultImportDialog = useCallback(() => {
    setVaultImportDialogOpen(false);
    setVaultImportFile(null);
    setVaultImportDescriptor(null);
    setVaultImportError(null);
    setVaultImportVerifyPassphrase("");
    setVaultImportExportPassphrase("");
  }, []);

  const confirmVaultImport = useCallback(async () => {
    if (!vaultImportFile) return;
    if (vaultImportMode === "plain" && vaultImportDescriptor?.signed && !vaultImportVerifyPassphrase.trim()) {
      setVaultImportError("verification passphrase required for signed snapshots");
      return;
    }
    if (vaultImportMode === "encrypted" && !vaultImportExportPassphrase.trim()) {
      setVaultImportError("export passphrase required for encrypted vault imports");
      return;
    }
    try {
      const result =
        vaultImportMode === "encrypted"
          ? await importVaultEncrypted(vaultImportFile, vaultImportExportPassphrase.trim(), {
              verificationPassphrase: vaultImportVerifyPassphrase.trim() || undefined,
            })
          : await importVault(vaultImportFile, {
              verificationPassphrase: vaultImportVerifyPassphrase.trim() || undefined,
            });
      setUnlocked(false);
      setKey(null);
      setNotes([]);
      setTitle("");
      setBody("");
      setTags("");
      setActiveId(null);
      const suffix = result.legacy ? "legacy" : result.signed ? (result.verified ? "signed+verified" : "signed") : "unsigned";
      push(
        `${vaultImportMode === "encrypted" ? "encrypted vault imported" : "vault imported"} (${result.noteCount} notes, ${suffix}); please unlock`,
        vaultImportMode === "encrypted" ? "accent" : "neutral",
      );
      closeVaultImportDialog();
    } catch (error) {
      console.error(error);
      const message = error instanceof Error ? error.message : "vault import failed";
      setVaultImportError(message);
    }
  }, [
    closeVaultImportDialog,
    push,
    vaultImportDescriptor?.signed,
    vaultImportExportPassphrase,
    vaultImportFile,
    vaultImportMode,
    vaultImportVerifyPassphrase,
  ]);

  const exportFilteredReport = useCallback(
    (includeBodies: boolean) => {
      if (!unlocked) {
        push("unlock to export report", "danger");
        return;
      }
      const payload = {
        schemaVersion: 1,
        kind: "nullid-vault-report",
        createdAt: new Date().toISOString(),
        filters: { query: filter || null },
        stats: vaultStats,
        notes: filteredNotes.map((note) => ({
          id: note.id,
          title: note.title,
          body: includeBodies ? note.body : undefined,
          bodyChars: note.body.length,
          tags: note.tags,
          createdAt: note.createdAt,
          updatedAt: note.updatedAt,
        })),
      };
      const blob = new Blob([`${JSON.stringify(payload, null, 2)}\n`], { type: "application/json" });
      downloadBlob(blob, `nullid-vault-report-${Date.now()}.json`);
      push("vault report exported", "accent");
      resetLockTimer();
    },
    [filter, filteredNotes, push, resetLockTimer, unlocked, vaultStats],
  );

  useEffect(() => {
    const onVisibility = () => {
      if (document.visibilityState === "hidden" && unlocked) {
        handleLock();
      }
    };
    document.addEventListener("visibilitychange", onVisibility);
    const onPanic = (event: KeyboardEvent) => {
      if (unlocked && event.key.toLowerCase() === "l" && event.ctrlKey && event.shiftKey) {
        event.preventDefault();
        handleLock();
        push("panic lock", "danger");
      }
    };
    window.addEventListener("keydown", onPanic);
    return () => {
      document.removeEventListener("visibilitychange", onVisibility);
      window.removeEventListener("keydown", onPanic);
    };
  }, [handleLock, push, unlocked]);

  return (
    <div className="workspace-scroll">
      <div className="guide-link">
        <button type="button" className="guide-link-button" onClick={() => onOpenGuide?.("vault")}>
          ? guide
        </button>
      </div>
      <div className="grid-two">
        <div className="panel" aria-label="Vault controls">
          <div className="panel-heading">
            <span>Secure Notes</span>
            <span className="panel-subtext">AES-GCM + PBKDF2</span>
          </div>
          <div className="controls-row">
            <input
              className="input"
              type="password"
              placeholder="passphrase"
              value={passphrase}
              onChange={(event) => setPassphrase(event.target.value)}
              aria-label="Vault key"
            />
            <button className="button" type="button" onClick={handleUnlock} disabled={unlocked || !passphrase}>
              unlock
            </button>
            <button className="button" type="button" onClick={handleLock} disabled={!unlocked}>
              lock
            </button>
          </div>
          <div className="status-line">
            <span>passphrase strength</span>
            <span className={gradeTagClass(passphraseAssessment.grade)}>{gradeLabel(passphraseAssessment.grade)}</span>
            <span className="microcopy">effective ≈ {passphraseAssessment.effectiveEntropyBits} bits</span>
          </div>
          <div className="controls-row">
            <button className="button" type="button" onClick={() => openVaultExportDialog("plain")} disabled={!unlocked || notes.length === 0}>
              export (json)
            </button>
            <button className="button" type="button" onClick={() => openVaultExportDialog("encrypted")} disabled={!unlocked || notes.length === 0}>
              export encrypted
            </button>
            <button className="button" type="button" onClick={handleImport}>
              import
            </button>
            <button
              className="button"
              type="button"
              onClick={() => encryptedImportRef.current?.click()}
            >
              import encrypted
            </button>
            <input
              ref={fileInputRef}
              type="file"
              accept="application/json"
              tabIndex={-1}
              style={{ position: "absolute", opacity: 0, width: 1, height: 1, pointerEvents: "none" }}
              onChange={async (event) => {
                const file = event.target.files?.[0];
                await beginVaultImport(file, "plain");
                event.target.value = "";
              }}
            />
            <input
              ref={encryptedImportRef}
              type="file"
              accept="text/plain"
              tabIndex={-1}
              style={{ position: "absolute", opacity: 0, width: 1, height: 1, pointerEvents: "none" }}
              onChange={async (event) => {
                const file = event.target.files?.[0];
                await beginVaultImport(file, "encrypted");
                event.target.value = "";
              }}
            />
            <button
              className="button"
              type="button"
              onClick={() => setWipeDialogOpen(true)}
              style={{ borderColor: "var(--danger)", color: "var(--danger)" }}
            >
              wipe
            </button>
          </div>
          <div className="status-line">
            <span>state</span>
            <Chip label={unlocked ? "unsealed" : "locked"} tone={unlocked ? "accent" : "muted"} />
            <span className="microcopy">notes: {notes.length}</span>
            <Chip label={`storage: ${backendInfo.kind}`} tone={backendInfo.fallbackReason ? "danger" : "muted"} />
            {backendInfo.fallbackReason && <span className="microcopy">fallback: {backendInfo.fallbackReason}</span>}
          </div>
          <div className="status-line">
            <span>auto-lock</span>
            <span className="tag">{unlocked ? `${lockRemaining}s` : "locked"}</span>
            <span className="microcopy">{unlocked ? "timer resets on activity" : "unlock to start timer"}</span>
          </div>
          <div className="controls-row">
            <label className="section-title" htmlFor="vault-search">
              Search
            </label>
            <input
              id="vault-search"
              className="input"
              placeholder="Filter title, body, or tags"
              value={filter}
              onChange={(event) => setFilter(event.target.value)}
              disabled={!unlocked}
            />
          </div>
          <div className="controls-row">
            <label className="section-title" htmlFor="auto-lock">
              Auto lock (seconds)
            </label>
            <input
              id="auto-lock"
              className="input"
              type="number"
              min={30}
              max={1800}
              value={autoLockSeconds}
              onChange={(event) => setAutoLockSeconds(Math.min(1800, Math.max(30, Number(event.target.value))))}
              disabled={!unlocked}
            />
          </div>
        </div>
        <div className="panel" aria-label="Create note form">
          <div className="panel-heading">
            <span>{activeId ? "Edit note" : "Create note"}</span>
            <span className="panel-subtext">encrypted body</span>
          </div>
          <label className="section-title" htmlFor="note-title">
            Title
          </label>
          <input
            id="note-title"
            className="input"
            placeholder="Incident draft"
            aria-label="Note title"
            disabled={!unlocked}
            value={title}
            onChange={(event) => setTitle(event.target.value)}
          />
          <label className="section-title" htmlFor="note-body">
            Body
          </label>
          <textarea
            id="note-body"
            className="textarea"
            placeholder="Encrypted note body..."
            aria-label="Note body"
            disabled={!unlocked}
            value={body}
            onChange={(event) => setBody(event.target.value)}
          />
          <label className="section-title" htmlFor="note-tags">
            Tags (comma separated)
          </label>
          <input
            id="note-tags"
            className="input"
            placeholder="incident, access, case-142"
            aria-label="Note tags"
            disabled={!unlocked}
            value={tags}
            onChange={(event) => setTags(event.target.value)}
          />
          <div className="controls-row">
            <span className="section-title">Templates</span>
            <div className="pill-buttons" role="group" aria-label="Vault note templates">
              <button type="button" className={template === "blank" ? "active" : ""} onClick={() => applyTemplate("blank")}>
                blank
              </button>
              <button type="button" className={template === "incident" ? "active" : ""} onClick={() => applyTemplate("incident")}>
                incident
              </button>
              <button type="button" className={template === "credentials" ? "active" : ""} onClick={() => applyTemplate("credentials")}>
                credentials
              </button>
              <button type="button" className={template === "checklist" ? "active" : ""} onClick={() => applyTemplate("checklist")}>
                checklist
              </button>
            </div>
          </div>
          <div className="controls-row">
            <button className="button" type="button" disabled={!unlocked} onClick={handleSave}>
              {activeId ? "update" : "store"}
            </button>
            <button
              className="button"
              type="button"
              disabled={!unlocked}
              onClick={() => {
                setTitle("");
                setBody("");
                setTags("");
                setActiveId(null);
              }}
            >
              clear
            </button>
          </div>
        </div>
      </div>
      <div className="panel" aria-label="Notes list">
        <div className="panel-heading">
          <span>Notes</span>
          <span className="panel-subtext">decrypted in-memory only</span>
        </div>
        <div className="note-box">
          <div className="status-line">
            <span>analytics</span>
            <span className="tag tag-accent">notes {vaultStats.totalNotes}</span>
            <span className="tag">avg chars {vaultStats.avgChars}</span>
            <span className="tag">tags {vaultStats.uniqueTags}</span>
          </div>
          <div className="controls-row">
            <button
              className="button"
              type="button"
              onClick={() => {
                setReportIncludeBodies(false);
                setReportDialogOpen(true);
              }}
              disabled={!unlocked || filteredNotes.length === 0}
            >
              export notes report
            </button>
            <span className="microcopy">
              {vaultStats.latestUpdate ? `latest update: ${formatTs(vaultStats.latestUpdate)}` : "no notes yet"}
            </span>
          </div>
          {unlocked ? (
            filteredNotes.length === 0 ? (
              <div className="microcopy">no matching notes</div>
            ) : (
              <ul className="note-list">
                {filteredNotes.map((note) => (
                  <li key={note.id}>
                    <div className="note-title">{note.title}</div>
                    <div className="note-body">{note.body}</div>
                    {note.tags.length > 0 && (
                      <div className="controls-row">
                        {note.tags.map((tag) => (
                          <Chip key={tag} label={tag} tone="muted" />
                        ))}
                      </div>
                    )}
                    <div className="microcopy">
                      created {formatTs(note.createdAt)} · updated {formatTs(note.updatedAt)}
                    </div>
                    <div className="controls-row">
                      <button className="button" type="button" onClick={() => handleEdit(note)}>
                        edit
                      </button>
                      <button
                        className="button"
                        type="button"
                        onClick={() => handleDelete(note.id)}
                        style={{ borderColor: "var(--danger)", color: "var(--danger)" }}
                      >
                        delete
                      </button>
                    </div>
                  </li>
                ))}
              </ul>
            )
          ) : (
            <div className="microcopy">locked. unlock to view.</div>
          )}
        </div>
      </div>
      <ActionDialog
        open={vaultExportDialogOpen}
        title={vaultExportMode === "encrypted" ? "Export encrypted vault snapshot" : "Export vault snapshot"}
        description="Signed exports add integrity metadata that can be verified during import."
        confirmLabel={vaultExportMode === "encrypted" ? "export encrypted" : "export snapshot"}
        onCancel={closeVaultExportDialog}
        onConfirm={() => void confirmVaultExport()}
        confirmDisabled={
          (vaultExportMode === "encrypted" && !vaultExportPassphrase.trim()) || (vaultExportSign && !vaultSigningPassphrase.trim())
        }
      >
        {vaultExportMode === "encrypted" ? (
          <label className="action-dialog-field">
            <span>Export passphrase</span>
            <input
              className="action-dialog-input"
              type="password"
              value={vaultExportPassphrase}
              onChange={(event) => {
                setVaultExportPassphrase(event.target.value);
                if (vaultExportError) setVaultExportError(null);
              }}
              aria-label="Vault export passphrase"
              placeholder="required for encrypted export"
            />
          </label>
        ) : null}
        <label className="action-dialog-field">
          <span>Sign metadata</span>
          <input
            type="checkbox"
            checked={vaultExportSign}
            onChange={(event) => setVaultExportSign(event.target.checked)}
            aria-label="Sign vault export metadata"
          />
        </label>
        {vaultExportSign ? (
          <>
            <label className="action-dialog-field">
              <span>Signing passphrase</span>
              <input
                className="action-dialog-input"
                type="password"
                value={vaultSigningPassphrase}
                onChange={(event) => {
                  setVaultSigningPassphrase(event.target.value);
                  if (vaultExportError) setVaultExportError(null);
                }}
                aria-label="Vault signing passphrase"
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
                    setVaultExportKeyHint(profile?.keyHint ?? "");
                  }}
                  aria-label="Saved vault key hint profile"
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
                  value={vaultExportKeyHint}
                  onChange={(event) => setVaultExportKeyHint(event.target.value)}
                  aria-label="Vault key hint"
                  placeholder="optional verification hint"
                />
              </label>
            </div>
            <p className="action-dialog-note">
              Key hints are local labels only; passphrases are never persisted.
              {selectedKeyHintProfile ? ` Active: ${selectedKeyHintProfile.name} (v${selectedKeyHintProfile.version})` : ""}
            </p>
          </>
        ) : (
          <p className="action-dialog-note">Unsigned exports skip signature verification during import.</p>
        )}
        {vaultExportError ? <p className="action-dialog-error">{vaultExportError}</p> : null}
      </ActionDialog>
      <ActionDialog
        open={vaultImportDialogOpen}
        title={vaultImportMode === "encrypted" ? "Import encrypted vault snapshot" : "Import vault snapshot"}
        description={
          vaultImportMode === "encrypted"
            ? "Provide export passphrase and optional verification passphrase."
            : `${vaultImportDescriptor?.noteCount ?? 0} notes · schema ${vaultImportDescriptor?.schemaVersion ?? "unknown"}`
        }
        confirmLabel={vaultImportMode === "encrypted" ? "import encrypted" : "import snapshot"}
        onCancel={closeVaultImportDialog}
        onConfirm={() => void confirmVaultImport()}
      >
        {vaultImportMode === "encrypted" ? (
          <>
            <label className="action-dialog-field">
              <span>Export passphrase</span>
              <input
                className="action-dialog-input"
                type="password"
                value={vaultImportExportPassphrase}
                onChange={(event) => {
                  setVaultImportExportPassphrase(event.target.value);
                  if (vaultImportError) setVaultImportError(null);
                }}
                aria-label="Encrypted vault import passphrase"
                placeholder="required"
              />
            </label>
            <label className="action-dialog-field">
              <span>Verification passphrase</span>
              <input
                className="action-dialog-input"
                type="password"
                value={vaultImportVerifyPassphrase}
                onChange={(event) => {
                  setVaultImportVerifyPassphrase(event.target.value);
                  if (vaultImportError) setVaultImportError(null);
                }}
                aria-label="Encrypted vault verification passphrase"
                placeholder="required when snapshot metadata is signed"
              />
            </label>
          </>
        ) : vaultImportDescriptor?.signed ? (
          <>
            <p className="action-dialog-note">
              Signed snapshot detected{vaultImportDescriptor.keyHint ? ` (hint: ${vaultImportDescriptor.keyHint})` : ""}. Verification is required before import.
            </p>
            <label className="action-dialog-field">
              <span>Verification passphrase</span>
              <input
                className="action-dialog-input"
                type="password"
                value={vaultImportVerifyPassphrase}
                onChange={(event) => {
                  setVaultImportVerifyPassphrase(event.target.value);
                  if (vaultImportError) setVaultImportError(null);
                }}
                aria-label="Vault verification passphrase"
                placeholder="required for signed snapshots"
              />
            </label>
          </>
        ) : (
          <p className="action-dialog-note">Unsigned snapshot. Continue only if you trust this file.</p>
        )}
        {vaultImportError ? <p className="action-dialog-error">{vaultImportError}</p> : null}
      </ActionDialog>
      <ActionDialog
        open={reportDialogOpen}
        title="Export notes report"
        description="Choose whether note body content should be included in the report."
        confirmLabel="export report"
        onCancel={() => setReportDialogOpen(false)}
        onConfirm={() => {
          exportFilteredReport(reportIncludeBodies);
          setReportDialogOpen(false);
        }}
      >
        <label className="action-dialog-field">
          <span>Include note bodies in report</span>
          <input
            type="checkbox"
            checked={reportIncludeBodies}
            onChange={(event) => setReportIncludeBodies(event.target.checked)}
            aria-label="Include note bodies"
          />
        </label>
      </ActionDialog>
      <ActionDialog
        open={wipeDialogOpen}
        title="Wipe vault data"
        description="This removes all vault metadata, canary records, and encrypted notes from local storage."
        confirmLabel="wipe vault"
        danger
        onCancel={() => setWipeDialogOpen(false)}
        onConfirm={() => {
          void handleWipe();
          setWipeDialogOpen(false);
        }}
      />
    </div>
  );
}

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.rel = "noopener";
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1500);
}

function gradeTagClass(grade: SecretGrade): string {
  if (grade === "critical" || grade === "weak") return "tag tag-danger";
  if (grade === "fair") return "tag";
  return "tag tag-accent";
}
