import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import "./styles.css";
import { Chip } from "../components/Chip";
import { useToast } from "../components/ToastHost";
import {
  decryptNote,
  deleteNote,
  exportVault,
  exportVaultEncrypted,
  importVault,
  importVaultEncrypted,
  loadNotes,
  saveNote,
  unlockVault,
} from "../utils/vault";
import { getVaultBackendInfo, wipeVault } from "../utils/storage";
import type { ModuleKey } from "../components/ModuleList";

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
  const [backendInfo, setBackendInfo] = useState(() => getVaultBackendInfo());
  const fileInputRef = useRef<HTMLInputElement>(null);
  const encryptedImportRef = useRef<HTMLInputElement>(null);
  const formatTs = useCallback((value: number) => new Date(value).toLocaleString(), []);

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

  const resetLockTimer = useCallback(() => {
    if (lockTimer) {
      window.clearTimeout(lockTimer);
    }
    const timer = window.setTimeout(() => {
      setUnlocked(false);
      setKey(null);
      setNotes([]);
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
    setNotes([]);
    setTitle("");
    setBody("");
    setTags("");
    setActiveId(null);
    setPassphrase("");
    push("vault locked", "neutral");
  }, [lockTimer, push]);

  const handleWipe = useCallback(async () => {
    await wipeVault();
    handleLock();
    push("vault wiped", "danger");
  }, [handleLock, push]);

  const handleExport = useCallback(async () => {
    const blob = await exportVault();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "nullid-vault.json";
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1500);
  }, []);

  const handleExportEncrypted = useCallback(async () => {
    const pass = prompt("Set export passphrase:");
    if (!pass) {
      push("export cancelled", "neutral");
      return;
    }
    const blob = await exportVaultEncrypted(pass);
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "nullid-vault.enc";
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1500);
    push("encrypted export ready", "accent");
  }, [push]);

  const handleImport = useCallback(async () => {
    fileInputRef.current?.click();
  }, []);

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
          <div className="controls-row">
            <button className="button" type="button" onClick={handleExport} disabled={!unlocked || notes.length === 0}>
              export (json)
            </button>
            <button className="button" type="button" onClick={handleExportEncrypted} disabled={!unlocked || notes.length === 0}>
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
                if (!file) return;
                await importVault(file);
                setUnlocked(false);
                setKey(null);
                setNotes([]);
                setTitle("");
                setBody("");
                setTags("");
                setActiveId(null);
                push("vault imported; please unlock", "neutral");
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
                if (!file) return;
                const pass = prompt("Enter export passphrase:");
                if (!pass) {
                  push("import cancelled", "neutral");
                  return;
                }
                try {
                  await importVaultEncrypted(file, pass);
                  setUnlocked(false);
                  setKey(null);
                  setNotes([]);
                  setTitle("");
                  setBody("");
                  setTags("");
                  setActiveId(null);
                  push("encrypted vault imported; please unlock", "accent");
                } catch (error) {
                  console.error(error);
                  push("encrypted import failed", "danger");
                }
              }}
            />
            <button
              className="button"
              type="button"
              onClick={() => {
                if (confirm("Wipe all vault data?")) handleWipe();
              }}
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
    </div>
  );
}
