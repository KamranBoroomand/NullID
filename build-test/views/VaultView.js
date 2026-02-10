import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import "./styles.css";
import { Chip } from "../components/Chip";
import { useToast } from "../components/ToastHost";
import { decryptNote, deleteNote, exportVault, exportVaultEncrypted, importVault, importVaultEncrypted, loadNotes, saveNote, unlockVault, } from "../utils/vault";
import { getVaultBackendInfo, wipeVault } from "../utils/storage";
export function VaultView({ onOpenGuide }) {
    const { push } = useToast();
    const [passphrase, setPassphrase] = useState("");
    const [unlocked, setUnlocked] = useState(false);
    const [key, setKey] = useState(null);
    const [notes, setNotes] = useState([]);
    const [title, setTitle] = useState("");
    const [body, setBody] = useState("");
    const [filter, setFilter] = useState("");
    const [tags, setTags] = useState("");
    const [activeId, setActiveId] = useState(null);
    const [autoLockSeconds, setAutoLockSeconds] = useState(300);
    const [lockTimer, setLockTimer] = useState(null);
    const [backendInfo, setBackendInfo] = useState(() => getVaultBackendInfo());
    const fileInputRef = useRef(null);
    const encryptedImportRef = useRef(null);
    const formatTs = useCallback((value) => new Date(value).toLocaleString(), []);
    const filteredNotes = useMemo(() => notes.filter((note) => {
        const query = filter.toLowerCase();
        return (note.title.toLowerCase().includes(query) ||
            note.body.toLowerCase().includes(query) ||
            note.tags.some((tag) => tag.toLowerCase().includes(query)));
    }), [filter, notes]);
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
        if (lockTimer)
            window.clearTimeout(lockTimer);
    }, [lockTimer]);
    useEffect(() => {
        if (!unlocked)
            return;
        const handleActivity = () => resetLockTimer();
        const events = ["mousemove", "keydown", "pointerdown", "scroll"];
        events.forEach((eventName) => window.addEventListener(eventName, handleActivity, { passive: true }));
        return () => events.forEach((eventName) => window.removeEventListener(eventName, handleActivity));
    }, [resetLockTimer, unlocked]);
    const handleUnlock = useCallback(async () => {
        if (!passphrase)
            return;
        try {
            const derived = await unlockVault(passphrase);
            setKey(derived);
            setUnlocked(true);
            push("vault unlocked", "accent");
            setBackendInfo(getVaultBackendInfo());
            const stored = await loadNotes();
            const decrypted = await Promise.all(stored.map(async (note) => {
                const data = await decryptNote(derived, note);
                return {
                    id: note.id,
                    updatedAt: note.updatedAt,
                    title: data.title,
                    body: data.body,
                    tags: data.tags ?? [],
                    createdAt: data.createdAt ?? note.updatedAt,
                };
            }));
            setNotes(decrypted.sort((a, b) => b.updatedAt - a.updatedAt));
            resetLockTimer();
        }
        catch (error) {
            console.error(error);
            push("unlock failed: passphrase or data invalid", "danger");
            setUnlocked(false);
            setKey(null);
            setNotes([]);
            setBackendInfo(getVaultBackendInfo());
        }
    }, [passphrase, push, resetLockTimer]);
    const handleSave = useCallback(async () => {
        if (!key || !title.trim() || !body.trim())
            return;
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
        }
        catch (error) {
            console.error(error);
            push("save failed (storage blocked?)", "danger");
            setBackendInfo(getVaultBackendInfo());
        }
    }, [activeId, body, key, notes, push, resetLockTimer, tags, title]);
    const handleEdit = useCallback((note) => {
        setTitle(note.title);
        setBody(note.body);
        setTags(note.tags.join(", "));
        setActiveId(note.id);
        resetLockTimer();
    }, [resetLockTimer]);
    const handleDelete = useCallback(async (id) => {
        if (!key)
            return;
        await deleteNote(id);
        setNotes((prev) => prev.filter((note) => note.id !== id));
        push("note deleted", "neutral");
        resetLockTimer();
    }, [key, push, resetLockTimer]);
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
        const shouldSign = confirm("Sign vault export metadata with a passphrase?");
        let signingPassphrase;
        let keyHint;
        if (shouldSign) {
            const signaturePass = prompt("Signing passphrase:");
            if (!signaturePass) {
                push("export cancelled", "neutral");
                return;
            }
            signingPassphrase = signaturePass;
            keyHint = prompt("Optional key hint (for verification):")?.trim() || undefined;
        }
        const blob = await exportVault({ signingPassphrase, keyHint });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = "nullid-vault.json";
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.setTimeout(() => URL.revokeObjectURL(url), 1500);
        push(`vault export ready${signingPassphrase ? " (signed)" : ""}`, "accent");
    }, [push]);
    const handleExportEncrypted = useCallback(async () => {
        const pass = prompt("Set export passphrase:");
        if (!pass) {
            push("export cancelled", "neutral");
            return;
        }
        const shouldSign = confirm("Sign vault metadata before encryption?");
        let signingPassphrase;
        let keyHint;
        if (shouldSign) {
            const signaturePass = prompt("Signing passphrase:");
            if (!signaturePass) {
                push("export cancelled", "neutral");
                return;
            }
            signingPassphrase = signaturePass;
            keyHint = prompt("Optional key hint (for verification):")?.trim() || undefined;
        }
        const blob = await exportVaultEncrypted(pass, { signingPassphrase, keyHint });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = "nullid-vault.enc";
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.setTimeout(() => URL.revokeObjectURL(url), 1500);
        push(`encrypted export ready${signingPassphrase ? " (signed metadata)" : ""}`, "accent");
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
        const onPanic = (event) => {
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
    return (_jsxs("div", { className: "workspace-scroll", children: [_jsx("div", { className: "guide-link", children: _jsx("button", { type: "button", className: "guide-link-button", onClick: () => onOpenGuide?.("vault"), children: "? guide" }) }), _jsxs("div", { className: "grid-two", children: [_jsxs("div", { className: "panel", "aria-label": "Vault controls", children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: "Secure Notes" }), _jsx("span", { className: "panel-subtext", children: "AES-GCM + PBKDF2" })] }), _jsxs("div", { className: "controls-row", children: [_jsx("input", { className: "input", type: "password", placeholder: "passphrase", value: passphrase, onChange: (event) => setPassphrase(event.target.value), "aria-label": "Vault key" }), _jsx("button", { className: "button", type: "button", onClick: handleUnlock, disabled: unlocked || !passphrase, children: "unlock" }), _jsx("button", { className: "button", type: "button", onClick: handleLock, disabled: !unlocked, children: "lock" })] }), _jsxs("div", { className: "controls-row", children: [_jsx("button", { className: "button", type: "button", onClick: handleExport, disabled: !unlocked || notes.length === 0, children: "export (json)" }), _jsx("button", { className: "button", type: "button", onClick: handleExportEncrypted, disabled: !unlocked || notes.length === 0, children: "export encrypted" }), _jsx("button", { className: "button", type: "button", onClick: handleImport, children: "import" }), _jsx("button", { className: "button", type: "button", onClick: () => encryptedImportRef.current?.click(), children: "import encrypted" }), _jsx("input", { ref: fileInputRef, type: "file", accept: "application/json", tabIndex: -1, style: { position: "absolute", opacity: 0, width: 1, height: 1, pointerEvents: "none" }, onChange: async (event) => {
                                            const file = event.target.files?.[0];
                                            if (!file)
                                                return;
                                            try {
                                                const verifyPassphrase = prompt("Verification passphrase for signed snapshots (optional):")?.trim() || undefined;
                                                const result = await importVault(file, { verificationPassphrase: verifyPassphrase });
                                                setUnlocked(false);
                                                setKey(null);
                                                setNotes([]);
                                                setTitle("");
                                                setBody("");
                                                setTags("");
                                                setActiveId(null);
                                                const suffix = result.legacy ? "legacy" : result.signed ? result.verified ? "signed+verified" : "signed" : "unsigned";
                                                push(`vault imported (${result.noteCount} notes, ${suffix}); please unlock`, "neutral");
                                            }
                                            catch (error) {
                                                console.error(error);
                                                const message = error instanceof Error ? error.message : "vault import failed";
                                                push(`vault import failed: ${message}`, "danger");
                                            }
                                        } }), _jsx("input", { ref: encryptedImportRef, type: "file", accept: "text/plain", tabIndex: -1, style: { position: "absolute", opacity: 0, width: 1, height: 1, pointerEvents: "none" }, onChange: async (event) => {
                                            const file = event.target.files?.[0];
                                            if (!file)
                                                return;
                                            const pass = prompt("Enter export passphrase:");
                                            if (!pass) {
                                                push("import cancelled", "neutral");
                                                return;
                                            }
                                            try {
                                                const verifyPassphrase = prompt("Verification passphrase for signed snapshots (optional):")?.trim() || undefined;
                                                const result = await importVaultEncrypted(file, pass, { verificationPassphrase: verifyPassphrase });
                                                setUnlocked(false);
                                                setKey(null);
                                                setNotes([]);
                                                setTitle("");
                                                setBody("");
                                                setTags("");
                                                setActiveId(null);
                                                const suffix = result.legacy ? "legacy" : result.signed ? result.verified ? "signed+verified" : "signed" : "unsigned";
                                                push(`encrypted vault imported (${result.noteCount} notes, ${suffix}); please unlock`, "accent");
                                            }
                                            catch (error) {
                                                console.error(error);
                                                const message = error instanceof Error ? error.message : "encrypted import failed";
                                                push(`encrypted import failed: ${message}`, "danger");
                                            }
                                        } }), _jsx("button", { className: "button", type: "button", onClick: () => {
                                            if (confirm("Wipe all vault data?"))
                                                handleWipe();
                                        }, style: { borderColor: "var(--danger)", color: "var(--danger)" }, children: "wipe" })] }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: "state" }), _jsx(Chip, { label: unlocked ? "unsealed" : "locked", tone: unlocked ? "accent" : "muted" }), _jsxs("span", { className: "microcopy", children: ["notes: ", notes.length] }), _jsx(Chip, { label: `storage: ${backendInfo.kind}`, tone: backendInfo.fallbackReason ? "danger" : "muted" }), backendInfo.fallbackReason && _jsxs("span", { className: "microcopy", children: ["fallback: ", backendInfo.fallbackReason] })] }), _jsxs("div", { className: "controls-row", children: [_jsx("label", { className: "section-title", htmlFor: "vault-search", children: "Search" }), _jsx("input", { id: "vault-search", className: "input", placeholder: "Filter title, body, or tags", value: filter, onChange: (event) => setFilter(event.target.value), disabled: !unlocked })] }), _jsxs("div", { className: "controls-row", children: [_jsx("label", { className: "section-title", htmlFor: "auto-lock", children: "Auto lock (seconds)" }), _jsx("input", { id: "auto-lock", className: "input", type: "number", min: 30, max: 1800, value: autoLockSeconds, onChange: (event) => setAutoLockSeconds(Math.min(1800, Math.max(30, Number(event.target.value)))), disabled: !unlocked })] })] }), _jsxs("div", { className: "panel", "aria-label": "Create note form", children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: activeId ? "Edit note" : "Create note" }), _jsx("span", { className: "panel-subtext", children: "encrypted body" })] }), _jsx("label", { className: "section-title", htmlFor: "note-title", children: "Title" }), _jsx("input", { id: "note-title", className: "input", placeholder: "Incident draft", "aria-label": "Note title", disabled: !unlocked, value: title, onChange: (event) => setTitle(event.target.value) }), _jsx("label", { className: "section-title", htmlFor: "note-body", children: "Body" }), _jsx("textarea", { id: "note-body", className: "textarea", placeholder: "Encrypted note body...", "aria-label": "Note body", disabled: !unlocked, value: body, onChange: (event) => setBody(event.target.value) }), _jsx("label", { className: "section-title", htmlFor: "note-tags", children: "Tags (comma separated)" }), _jsx("input", { id: "note-tags", className: "input", placeholder: "incident, access, case-142", "aria-label": "Note tags", disabled: !unlocked, value: tags, onChange: (event) => setTags(event.target.value) }), _jsxs("div", { className: "controls-row", children: [_jsx("button", { className: "button", type: "button", disabled: !unlocked, onClick: handleSave, children: activeId ? "update" : "store" }), _jsx("button", { className: "button", type: "button", disabled: !unlocked, onClick: () => {
                                            setTitle("");
                                            setBody("");
                                            setTags("");
                                            setActiveId(null);
                                        }, children: "clear" })] })] })] }), _jsxs("div", { className: "panel", "aria-label": "Notes list", children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: "Notes" }), _jsx("span", { className: "panel-subtext", children: "decrypted in-memory only" })] }), _jsx("div", { className: "note-box", children: unlocked ? (filteredNotes.length === 0 ? (_jsx("div", { className: "microcopy", children: "no matching notes" })) : (_jsx("ul", { className: "note-list", children: filteredNotes.map((note) => (_jsxs("li", { children: [_jsx("div", { className: "note-title", children: note.title }), _jsx("div", { className: "note-body", children: note.body }), note.tags.length > 0 && (_jsx("div", { className: "controls-row", children: note.tags.map((tag) => (_jsx(Chip, { label: tag, tone: "muted" }, tag))) })), _jsxs("div", { className: "microcopy", children: ["created ", formatTs(note.createdAt), " \u00B7 updated ", formatTs(note.updatedAt)] }), _jsxs("div", { className: "controls-row", children: [_jsx("button", { className: "button", type: "button", onClick: () => handleEdit(note), children: "edit" }), _jsx("button", { className: "button", type: "button", onClick: () => handleDelete(note.id), style: { borderColor: "var(--danger)", color: "var(--danger)" }, children: "delete" })] })] }, note.id))) }))) : (_jsx("div", { className: "microcopy", children: "locked. unlock to view." })) })] })] }));
}
