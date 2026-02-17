import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import "./styles.css";
import { Chip } from "../components/Chip";
import { ActionDialog } from "../components/ActionDialog";
import { useToast } from "../components/ToastHost";
import { describeVaultPayload, decryptNote, deleteNote, exportVault, exportVaultEncrypted, importVault, importVaultEncrypted, loadNotes, saveNote, unlockVault, } from "../utils/vault";
import { getVaultBackendInfo, wipeVault } from "../utils/storage";
import { analyzeSecret, gradeLabel } from "../utils/passwordToolkit";
import { usePersistentState } from "../hooks/usePersistentState";
import { SHARED_KEY_HINT_PROFILE_KEY, readLegacyProfiles, sanitizeKeyHint, } from "../utils/keyHintProfiles";
import { useI18n } from "../i18n";
export function VaultView({ onOpenGuide }) {
    const { push } = useToast();
    const { t, tr, formatDateTime, formatNumber } = useI18n();
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
    const [lockDeadlineMs, setLockDeadlineMs] = useState(null);
    const [lockRemaining, setLockRemaining] = useState(0);
    const [backendInfo, setBackendInfo] = useState(() => getVaultBackendInfo());
    const [template, setTemplate] = useState("blank");
    const [keyHintProfiles, setKeyHintProfiles] = usePersistentState(SHARED_KEY_HINT_PROFILE_KEY, []);
    const [selectedKeyHintProfileId, setSelectedKeyHintProfileId] = usePersistentState("nullid:vault:key-hint-selected", "");
    const [vaultExportDialogOpen, setVaultExportDialogOpen] = useState(false);
    const [vaultExportMode, setVaultExportMode] = useState("plain");
    const [vaultExportPassphrase, setVaultExportPassphrase] = useState("");
    const [vaultExportSign, setVaultExportSign] = useState(false);
    const [vaultSigningPassphrase, setVaultSigningPassphrase] = useState("");
    const [vaultExportKeyHint, setVaultExportKeyHint] = useState("");
    const [vaultExportError, setVaultExportError] = useState(null);
    const [vaultImportDialogOpen, setVaultImportDialogOpen] = useState(false);
    const [vaultImportMode, setVaultImportMode] = useState("plain");
    const [vaultImportFile, setVaultImportFile] = useState(null);
    const [vaultImportDescriptor, setVaultImportDescriptor] = useState(null);
    const [vaultImportExportPassphrase, setVaultImportExportPassphrase] = useState("");
    const [vaultImportVerifyPassphrase, setVaultImportVerifyPassphrase] = useState("");
    const [vaultImportError, setVaultImportError] = useState(null);
    const [reportDialogOpen, setReportDialogOpen] = useState(false);
    const [reportIncludeBodies, setReportIncludeBodies] = useState(false);
    const [wipeDialogOpen, setWipeDialogOpen] = useState(false);
    const fileInputRef = useRef(null);
    const encryptedImportRef = useRef(null);
    const formatTs = useCallback((value) => formatDateTime(value), [formatDateTime]);
    const passphraseAssessment = useMemo(() => analyzeSecret(passphrase), [passphrase]);
    const selectedKeyHintProfile = useMemo(() => keyHintProfiles.find((profile) => profile.id === selectedKeyHintProfileId) ?? null, [keyHintProfiles, selectedKeyHintProfileId]);
    const filteredNotes = useMemo(() => notes.filter((note) => {
        const query = filter.toLowerCase();
        return (note.title.toLowerCase().includes(query) ||
            note.body.toLowerCase().includes(query) ||
            note.tags.some((tag) => tag.toLowerCase().includes(query)));
    }), [filter, notes]);
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
        if (keyHintProfiles.length > 0)
            return;
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
        if (lockTimer)
            window.clearTimeout(lockTimer);
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
    const applyTemplate = useCallback((next) => {
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
        }
        else if (next === "credentials") {
            setTitle("Credential inventory");
            setBody("System:\nAccount:\nRotation date:\nRecovery path:\nNotes:");
            setTags("credentials,rotation");
        }
        else {
            setTitle("Security checklist");
            setBody("- [ ] Validate artifact hash\n- [ ] Sanitize logs\n- [ ] Export signed snapshot\n- [ ] Confirm recipient");
            setTags("checklist,ops");
        }
        if (unlocked)
            resetLockTimer();
    }, [resetLockTimer, unlocked]);
    const handleWipe = useCallback(async () => {
        await wipeVault();
        handleLock();
        push("vault wiped", "danger");
    }, [handleLock, push]);
    const openVaultExportDialog = useCallback((mode) => {
        setVaultExportMode(mode);
        setVaultExportPassphrase("");
        setVaultExportSign(false);
        setVaultSigningPassphrase("");
        setVaultExportKeyHint(selectedKeyHintProfile?.keyHint ?? "");
        setVaultExportError(null);
        setVaultExportDialogOpen(true);
    }, [selectedKeyHintProfile]);
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
            const blob = vaultExportMode === "encrypted"
                ? await exportVaultEncrypted(vaultExportPassphrase.trim(), options)
                : await exportVault(options);
            const filename = vaultExportMode === "encrypted" ? "nullid-vault.enc" : "nullid-vault.json";
            downloadBlob(blob, filename);
            push(vaultExportMode === "encrypted"
                ? `encrypted export ready${vaultExportSign ? " (signed metadata)" : ""}`
                : `vault export ready${vaultExportSign ? " (signed)" : ""}`, "accent");
            closeVaultExportDialog();
        }
        catch (error) {
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
    const beginVaultImport = useCallback(async (file, mode = "plain") => {
        if (!file)
            return;
        try {
            setVaultImportFile(file);
            setVaultImportMode(mode);
            setVaultImportError(null);
            setVaultImportVerifyPassphrase("");
            setVaultImportExportPassphrase("");
            if (mode === "plain") {
                const parsed = JSON.parse(await file.text());
                setVaultImportDescriptor(describeVaultPayload(parsed));
            }
            else {
                setVaultImportDescriptor(null);
            }
            setVaultImportDialogOpen(true);
        }
        catch (error) {
            console.error(error);
            const message = error instanceof Error ? error.message : "vault import failed";
            push(`vault import failed: ${message}`, "danger");
        }
    }, [push]);
    const closeVaultImportDialog = useCallback(() => {
        setVaultImportDialogOpen(false);
        setVaultImportFile(null);
        setVaultImportDescriptor(null);
        setVaultImportError(null);
        setVaultImportVerifyPassphrase("");
        setVaultImportExportPassphrase("");
    }, []);
    const confirmVaultImport = useCallback(async () => {
        if (!vaultImportFile)
            return;
        if (vaultImportMode === "plain" && vaultImportDescriptor?.signed && !vaultImportVerifyPassphrase.trim()) {
            setVaultImportError("verification passphrase required for signed snapshots");
            return;
        }
        if (vaultImportMode === "encrypted" && !vaultImportExportPassphrase.trim()) {
            setVaultImportError("export passphrase required for encrypted vault imports");
            return;
        }
        try {
            const result = vaultImportMode === "encrypted"
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
            push(`${vaultImportMode === "encrypted" ? "encrypted vault imported" : "vault imported"} (${result.noteCount} notes, ${suffix}); please unlock`, vaultImportMode === "encrypted" ? "accent" : "neutral");
            closeVaultImportDialog();
        }
        catch (error) {
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
    const exportFilteredReport = useCallback((includeBodies) => {
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
    }, [filter, filteredNotes, push, resetLockTimer, unlocked, vaultStats]);
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
    return (_jsxs("div", { className: "workspace-scroll", children: [_jsx("div", { className: "guide-link", children: _jsx("button", { type: "button", className: "guide-link-button", onClick: () => onOpenGuide?.("vault"), children: t("guide.link") }) }), _jsxs("div", { className: "grid-two", children: [_jsxs("div", { className: "panel", "aria-label": tr("Vault controls"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("Secure Notes") }), _jsx("span", { className: "panel-subtext", children: "AES-GCM + PBKDF2" })] }), _jsxs("div", { className: "controls-row", children: [_jsx("input", { className: "input", type: "password", placeholder: tr("passphrase"), value: passphrase, onChange: (event) => setPassphrase(event.target.value), "aria-label": tr("Vault key") }), _jsx("button", { className: "button", type: "button", onClick: handleUnlock, disabled: unlocked || !passphrase, children: tr("unlock") }), _jsx("button", { className: "button", type: "button", onClick: handleLock, disabled: !unlocked, children: tr("lock") })] }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: tr("passphrase strength") }), _jsx("span", { className: gradeTagClass(passphraseAssessment.grade), children: gradeLabel(passphraseAssessment.grade) }), _jsxs("span", { className: "microcopy", children: [tr("effective"), " \u2248 ", formatNumber(passphraseAssessment.effectiveEntropyBits), " ", tr("bits")] })] }), _jsxs("div", { className: "controls-row", children: [_jsx("button", { className: "button", type: "button", onClick: () => openVaultExportDialog("plain"), disabled: !unlocked || notes.length === 0, children: tr("export (json)") }), _jsx("button", { className: "button", type: "button", onClick: () => openVaultExportDialog("encrypted"), disabled: !unlocked || notes.length === 0, children: tr("export encrypted") }), _jsx("button", { className: "button", type: "button", onClick: handleImport, children: tr("import") }), _jsx("button", { className: "button", type: "button", onClick: () => encryptedImportRef.current?.click(), children: tr("import encrypted") }), _jsx("input", { ref: fileInputRef, type: "file", accept: "application/json", tabIndex: -1, style: { position: "absolute", opacity: 0, width: 1, height: 1, pointerEvents: "none" }, onChange: async (event) => {
                                            const file = event.target.files?.[0];
                                            await beginVaultImport(file, "plain");
                                            event.target.value = "";
                                        } }), _jsx("input", { ref: encryptedImportRef, type: "file", accept: "text/plain", tabIndex: -1, style: { position: "absolute", opacity: 0, width: 1, height: 1, pointerEvents: "none" }, onChange: async (event) => {
                                            const file = event.target.files?.[0];
                                            await beginVaultImport(file, "encrypted");
                                            event.target.value = "";
                                        } }), _jsx("button", { className: "button", type: "button", onClick: () => setWipeDialogOpen(true), style: { borderColor: "var(--danger)", color: "var(--danger)" }, children: tr("wipe") })] }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: tr("state") }), _jsx(Chip, { label: unlocked ? tr("unsealed") : tr("locked"), tone: unlocked ? "accent" : "muted" }), _jsxs("span", { className: "microcopy", children: [tr("notes"), ": ", formatNumber(notes.length)] }), _jsx(Chip, { label: `storage: ${backendInfo.kind}`, tone: backendInfo.fallbackReason ? "danger" : "muted" }), backendInfo.fallbackReason && _jsxs("span", { className: "microcopy", children: ["fallback: ", backendInfo.fallbackReason] })] }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: tr("auto-lock") }), _jsx("span", { className: "tag", children: unlocked ? `${formatNumber(lockRemaining)}s` : tr("locked") }), _jsx("span", { className: "microcopy", children: unlocked ? tr("timer resets on activity") : tr("unlock to start timer") })] }), _jsxs("div", { className: "controls-row", children: [_jsx("label", { className: "section-title", htmlFor: "vault-search", children: tr("Search") }), _jsx("input", { id: "vault-search", className: "input", placeholder: tr("Filter title, body, or tags"), value: filter, onChange: (event) => setFilter(event.target.value), disabled: !unlocked })] }), _jsxs("div", { className: "controls-row", children: [_jsx("label", { className: "section-title", htmlFor: "auto-lock", children: tr("Auto lock (seconds)") }), _jsx("input", { id: "auto-lock", className: "input", type: "number", min: 30, max: 1800, value: autoLockSeconds, onChange: (event) => setAutoLockSeconds(Math.min(1800, Math.max(30, Number(event.target.value)))), disabled: !unlocked })] })] }), _jsxs("div", { className: "panel", "aria-label": tr("Create note form"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: activeId ? tr("Edit note") : tr("Create note") }), _jsx("span", { className: "panel-subtext", children: tr("encrypted body") })] }), _jsx("label", { className: "section-title", htmlFor: "note-title", children: tr("Title") }), _jsx("input", { id: "note-title", className: "input", placeholder: tr("Incident draft"), "aria-label": tr("Note title"), disabled: !unlocked, value: title, onChange: (event) => setTitle(event.target.value) }), _jsx("label", { className: "section-title", htmlFor: "note-body", children: tr("Body") }), _jsx("textarea", { id: "note-body", className: "textarea", placeholder: tr("Encrypted note body..."), "aria-label": tr("Note body"), disabled: !unlocked, value: body, onChange: (event) => setBody(event.target.value) }), _jsx("label", { className: "section-title", htmlFor: "note-tags", children: tr("Tags (comma separated)") }), _jsx("input", { id: "note-tags", className: "input", placeholder: tr("incident, access, case-142"), "aria-label": tr("Note tags"), disabled: !unlocked, value: tags, onChange: (event) => setTags(event.target.value) }), _jsxs("div", { className: "controls-row", children: [_jsx("span", { className: "section-title", children: tr("Templates") }), _jsxs("div", { className: "pill-buttons", role: "group", "aria-label": tr("Vault note templates"), children: [_jsx("button", { type: "button", className: template === "blank" ? "active" : "", onClick: () => applyTemplate("blank"), children: tr("blank") }), _jsx("button", { type: "button", className: template === "incident" ? "active" : "", onClick: () => applyTemplate("incident"), children: tr("incident") }), _jsx("button", { type: "button", className: template === "credentials" ? "active" : "", onClick: () => applyTemplate("credentials"), children: tr("credentials") }), _jsx("button", { type: "button", className: template === "checklist" ? "active" : "", onClick: () => applyTemplate("checklist"), children: tr("checklist") })] })] }), _jsxs("div", { className: "controls-row", children: [_jsx("button", { className: "button", type: "button", disabled: !unlocked, onClick: handleSave, children: activeId ? tr("update") : tr("store") }), _jsx("button", { className: "button", type: "button", disabled: !unlocked, onClick: () => {
                                            setTitle("");
                                            setBody("");
                                            setTags("");
                                            setActiveId(null);
                                        }, children: tr("clear") })] })] })] }), _jsxs("div", { className: "panel", "aria-label": tr("Notes list"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("Notes") }), _jsx("span", { className: "panel-subtext", children: tr("decrypted in-memory only") })] }), _jsxs("div", { className: "note-box", children: [_jsxs("div", { className: "status-line", children: [_jsx("span", { children: tr("analytics") }), _jsxs("span", { className: "tag tag-accent", children: [tr("notes"), " ", formatNumber(vaultStats.totalNotes)] }), _jsxs("span", { className: "tag", children: [tr("avg chars"), " ", formatNumber(vaultStats.avgChars)] }), _jsxs("span", { className: "tag", children: [tr("tags"), " ", formatNumber(vaultStats.uniqueTags)] })] }), _jsxs("div", { className: "controls-row", children: [_jsx("button", { className: "button", type: "button", onClick: () => {
                                            setReportIncludeBodies(false);
                                            setReportDialogOpen(true);
                                        }, disabled: !unlocked || filteredNotes.length === 0, children: tr("export notes report") }), _jsx("span", { className: "microcopy", children: vaultStats.latestUpdate ? `latest update: ${formatTs(vaultStats.latestUpdate)}` : "no notes yet" })] }), unlocked ? (filteredNotes.length === 0 ? (_jsx("div", { className: "microcopy", children: tr("no matching notes") })) : (_jsx("ul", { className: "note-list", children: filteredNotes.map((note) => (_jsxs("li", { children: [_jsx("div", { className: "note-title", children: note.title }), _jsx("div", { className: "note-body", children: note.body }), note.tags.length > 0 && (_jsx("div", { className: "controls-row", children: note.tags.map((tag) => (_jsx(Chip, { label: tag, tone: "muted" }, tag))) })), _jsxs("div", { className: "microcopy", children: ["created ", formatTs(note.createdAt), " \u00B7 updated ", formatTs(note.updatedAt)] }), _jsxs("div", { className: "controls-row", children: [_jsx("button", { className: "button", type: "button", onClick: () => handleEdit(note), children: tr("edit") }), _jsx("button", { className: "button", type: "button", onClick: () => handleDelete(note.id), style: { borderColor: "var(--danger)", color: "var(--danger)" }, children: tr("delete") })] })] }, note.id))) }))) : (_jsx("div", { className: "microcopy", children: tr("locked. unlock to view.") }))] })] }), _jsxs(ActionDialog, { open: vaultExportDialogOpen, title: vaultExportMode === "encrypted" ? "Export encrypted vault snapshot" : "Export vault snapshot", description: "Signed exports add integrity metadata that can be verified during import.", confirmLabel: vaultExportMode === "encrypted" ? "export encrypted" : "export snapshot", onCancel: closeVaultExportDialog, onConfirm: () => void confirmVaultExport(), confirmDisabled: (vaultExportMode === "encrypted" && !vaultExportPassphrase.trim()) || (vaultExportSign && !vaultSigningPassphrase.trim()), children: [vaultExportMode === "encrypted" ? (_jsxs("label", { className: "action-dialog-field", children: [_jsx("span", { children: "Export passphrase" }), _jsx("input", { className: "action-dialog-input", type: "password", value: vaultExportPassphrase, onChange: (event) => {
                                    setVaultExportPassphrase(event.target.value);
                                    if (vaultExportError)
                                        setVaultExportError(null);
                                }, "aria-label": "Vault export passphrase", placeholder: "required for encrypted export" })] })) : null, _jsxs("label", { className: "action-dialog-field", children: [_jsx("span", { children: "Sign metadata" }), _jsx("input", { type: "checkbox", checked: vaultExportSign, onChange: (event) => setVaultExportSign(event.target.checked), "aria-label": "Sign vault export metadata" })] }), vaultExportSign ? (_jsxs(_Fragment, { children: [_jsxs("label", { className: "action-dialog-field", children: [_jsx("span", { children: "Signing passphrase" }), _jsx("input", { className: "action-dialog-input", type: "password", value: vaultSigningPassphrase, onChange: (event) => {
                                            setVaultSigningPassphrase(event.target.value);
                                            if (vaultExportError)
                                                setVaultExportError(null);
                                        }, "aria-label": "Vault signing passphrase", placeholder: "required when signing" })] }), _jsxs("div", { className: "action-dialog-row", children: [_jsxs("label", { className: "action-dialog-field", children: [_jsx("span", { children: "Saved key hint" }), _jsxs("select", { className: "action-dialog-select", value: selectedKeyHintProfileId, onChange: (event) => {
                                                    const nextId = event.target.value;
                                                    setSelectedKeyHintProfileId(nextId);
                                                    const profile = keyHintProfiles.find((entry) => entry.id === nextId);
                                                    setVaultExportKeyHint(profile?.keyHint ?? "");
                                                }, "aria-label": "Saved vault key hint profile", children: [_jsx("option", { value: "", children: "custom key hint" }), keyHintProfiles.map((profile) => (_jsxs("option", { value: profile.id, children: [profile.name, " \u00B7 ", profile.keyHint] }, profile.id)))] })] }), _jsxs("label", { className: "action-dialog-field", children: [_jsx("span", { children: "Key hint label" }), _jsx("input", { className: "action-dialog-input", value: vaultExportKeyHint, onChange: (event) => setVaultExportKeyHint(event.target.value), "aria-label": "Vault key hint", placeholder: "optional verification hint" })] })] }), _jsxs("p", { className: "action-dialog-note", children: ["Key hints are local labels only; passphrases are never persisted.", selectedKeyHintProfile ? ` Active: ${selectedKeyHintProfile.name} (v${selectedKeyHintProfile.version})` : ""] })] })) : (_jsx("p", { className: "action-dialog-note", children: "Unsigned exports skip signature verification during import." })), vaultExportError ? _jsx("p", { className: "action-dialog-error", children: vaultExportError }) : null] }), _jsxs(ActionDialog, { open: vaultImportDialogOpen, title: vaultImportMode === "encrypted" ? "Import encrypted vault snapshot" : "Import vault snapshot", description: vaultImportMode === "encrypted"
                    ? "Provide export passphrase and optional verification passphrase."
                    : `${vaultImportDescriptor?.noteCount ?? 0} notes · schema ${vaultImportDescriptor?.schemaVersion ?? "unknown"}`, confirmLabel: vaultImportMode === "encrypted" ? "import encrypted" : "import snapshot", onCancel: closeVaultImportDialog, onConfirm: () => void confirmVaultImport(), children: [vaultImportMode === "encrypted" ? (_jsxs(_Fragment, { children: [_jsxs("label", { className: "action-dialog-field", children: [_jsx("span", { children: "Export passphrase" }), _jsx("input", { className: "action-dialog-input", type: "password", value: vaultImportExportPassphrase, onChange: (event) => {
                                            setVaultImportExportPassphrase(event.target.value);
                                            if (vaultImportError)
                                                setVaultImportError(null);
                                        }, "aria-label": "Encrypted vault import passphrase", placeholder: "required" })] }), _jsxs("label", { className: "action-dialog-field", children: [_jsx("span", { children: "Verification passphrase" }), _jsx("input", { className: "action-dialog-input", type: "password", value: vaultImportVerifyPassphrase, onChange: (event) => {
                                            setVaultImportVerifyPassphrase(event.target.value);
                                            if (vaultImportError)
                                                setVaultImportError(null);
                                        }, "aria-label": "Encrypted vault verification passphrase", placeholder: "required when snapshot metadata is signed" })] })] })) : vaultImportDescriptor?.signed ? (_jsxs(_Fragment, { children: [_jsxs("p", { className: "action-dialog-note", children: ["Signed snapshot detected", vaultImportDescriptor.keyHint ? ` (hint: ${vaultImportDescriptor.keyHint})` : "", ". Verification is required before import."] }), _jsxs("label", { className: "action-dialog-field", children: [_jsx("span", { children: "Verification passphrase" }), _jsx("input", { className: "action-dialog-input", type: "password", value: vaultImportVerifyPassphrase, onChange: (event) => {
                                            setVaultImportVerifyPassphrase(event.target.value);
                                            if (vaultImportError)
                                                setVaultImportError(null);
                                        }, "aria-label": "Vault verification passphrase", placeholder: "required for signed snapshots" })] })] })) : (_jsx("p", { className: "action-dialog-note", children: "Unsigned snapshot. Continue only if you trust this file." })), vaultImportError ? _jsx("p", { className: "action-dialog-error", children: vaultImportError }) : null] }), _jsx(ActionDialog, { open: reportDialogOpen, title: "Export notes report", description: "Choose whether note body content should be included in the report.", confirmLabel: "export report", onCancel: () => setReportDialogOpen(false), onConfirm: () => {
                    exportFilteredReport(reportIncludeBodies);
                    setReportDialogOpen(false);
                }, children: _jsxs("label", { className: "action-dialog-field", children: [_jsx("span", { children: "Include note bodies in report" }), _jsx("input", { type: "checkbox", checked: reportIncludeBodies, onChange: (event) => setReportIncludeBodies(event.target.checked), "aria-label": "Include note bodies" })] }) }), _jsx(ActionDialog, { open: wipeDialogOpen, title: "Wipe vault data", description: "This removes all vault metadata, canary records, and encrypted notes from local storage.", confirmLabel: "wipe vault", danger: true, onCancel: () => setWipeDialogOpen(false), onConfirm: () => {
                    void handleWipe();
                    setWipeDialogOpen(false);
                } })] }));
}
function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    link.rel = "noopener";
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1500);
}
function gradeTagClass(grade) {
    if (grade === "critical" || grade === "weak")
        return "tag tag-danger";
    if (grade === "fair")
        return "tag";
    return "tag tag-accent";
}
