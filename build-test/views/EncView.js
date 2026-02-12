import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import "./styles.css";
import { bytesToUtf8 } from "../utils/encoding";
import { KDF_PROFILES, decryptBlob, decryptText, encryptBytes, encryptText, inspectEnvelope } from "../utils/cryptoEnvelope";
import { Chip } from "../components/Chip";
import { useToast } from "../components/ToastHost";
import { analyzeSecret, gradeLabel } from "../utils/passwordToolkit";
export function EncView({ onOpenGuide }) {
    const { push } = useToast();
    const [plain, setPlain] = useState("");
    const [encPass, setEncPass] = useState("");
    const [cipherText, setCipherText] = useState("");
    const [decPass, setDecPass] = useState("");
    const [decrypted, setDecrypted] = useState("");
    const [kdfProfile, setKdfProfile] = useState("compat");
    const [kdfMode, setKdfMode] = useState("profile");
    const [customIterations, setCustomIterations] = useState(600_000);
    const [customHash, setCustomHash] = useState("SHA-512");
    const [encFile, setEncFile] = useState(null);
    const [encFileBlob, setEncFileBlob] = useState(null);
    const [decFileBlob, setDecFileBlob] = useState(null);
    const [decFileName, setDecFileName] = useState(null);
    const [decMime, setDecMime] = useState("application/octet-stream");
    const [autoClear, setAutoClear] = useState(true);
    const [clearAfter, setClearAfter] = useState(30);
    const [error, setError] = useState(null);
    const [isEncrypting, setIsEncrypting] = useState(false);
    const [isDecrypting, setIsDecrypting] = useState(false);
    const [payloadMeta, setPayloadMeta] = useState(null);
    const [envelopeMeta, setEnvelopeMeta] = useState(null);
    const [envelopeMetaError, setEnvelopeMetaError] = useState(null);
    const encryptFileInput = useRef(null);
    const decryptFileInput = useRef(null);
    const clearTimerRef = useRef(null);
    const MAX_FILE_BYTES = 25 * 1024 * 1024; // 25MB (envelope expands ~33%)
    const kdfConfig = useMemo(() => kdfMode === "custom"
        ? {
            iterations: clamp(customIterations, 100_000, 2_000_000),
            hash: customHash,
        }
        : KDF_PROFILES[kdfProfile], [customHash, customIterations, kdfMode, kdfProfile]);
    const encPassAssessment = useMemo(() => analyzeSecret(encPass), [encPass]);
    const decPassAssessment = useMemo(() => analyzeSecret(decPass), [decPass]);
    const scheduleClear = useCallback(() => {
        if (!autoClear)
            return;
        if (clearTimerRef.current)
            window.clearTimeout(clearTimerRef.current);
        clearTimerRef.current = window.setTimeout(() => {
            setPlain("");
            setDecrypted("");
        }, clearAfter * 1000);
    }, [autoClear, clearAfter]);
    useEffect(() => {
        return () => {
            if (clearTimerRef.current)
                window.clearTimeout(clearTimerRef.current);
        };
    }, []);
    const handleEncryptText = useCallback(async () => {
        if (!plain || !encPass)
            return;
        setIsEncrypting(true);
        try {
            const blob = await encryptText(encPass, plain, {
                kdfProfile,
                kdf: kdfMode === "custom" ? kdfConfig : undefined,
            });
            setCipherText(blob.trim());
            setEncFileBlob(blob.trim());
            push("sealed", "accent");
            setError(null);
            setPayloadMeta({ bytes: plain.length, mime: "text/plain" });
            scheduleClear();
        }
        catch (err) {
            console.error(err);
            setError("encrypt failed");
            push("encrypt failed", "danger");
        }
        finally {
            setIsEncrypting(false);
        }
    }, [encPass, kdfConfig, kdfMode, kdfProfile, plain, push, scheduleClear]);
    const handleEncryptFile = useCallback(async () => {
        if (!encPass || !encFile)
            return;
        setIsEncrypting(true);
        if (encFile.size > MAX_FILE_BYTES) {
            setError(`file too large (${Math.ceil(encFile.size / (1024 * 1024))}MB). max 25MB.`);
            push("file too large", "danger");
            setIsEncrypting(false);
            return;
        }
        try {
            const bytes = new Uint8Array(await encFile.arrayBuffer());
            const { blob } = await encryptBytes(encPass, bytes, {
                mime: encFile.type,
                name: encFile.name,
                kdfProfile,
                kdf: kdfMode === "custom" ? kdfConfig : undefined,
            });
            setEncFileBlob(blob);
            setCipherText(blob.trim());
            push("file sealed", "accent");
            setPayloadMeta({ name: encFile.name, mime: encFile.type, bytes: encFile.size });
            scheduleClear();
        }
        catch (err) {
            console.error(err);
            setError("file encrypt failed");
            push("file encrypt failed", "danger");
        }
        finally {
            setIsEncrypting(false);
        }
    }, [encFile, encPass, kdfConfig, kdfMode, kdfProfile, push, scheduleClear]);
    const handleDecryptText = useCallback(async () => {
        if (!cipherText || !decPass)
            return;
        setIsDecrypting(true);
        try {
            const pt = await decryptText(decPass, cipherText);
            setDecrypted(pt);
            setPayloadMeta({ mime: "text/plain", bytes: pt.length });
            push("decrypted", "accent");
            setError(null);
            scheduleClear();
        }
        catch (err) {
            console.error(err);
            setDecrypted("");
            setDecFileBlob(null);
            setPayloadMeta(null);
            setError("decrypt failed: bad passphrase or envelope");
            push("decrypt failed", "danger");
        }
        finally {
            setIsDecrypting(false);
        }
    }, [cipherText, decPass, push, scheduleClear]);
    const handleDecryptFile = useCallback(async () => {
        if (!decPass || !cipherText)
            return;
        setIsDecrypting(true);
        try {
            const { plaintext, header } = await decryptBlob(decPass, cipherText);
            setDecFileBlob(plaintext);
            setDecFileName(header.name ?? "decrypted.bin");
            setDecMime(header.mime ?? "application/octet-stream");
            try {
                setDecrypted(bytesToUtf8(plaintext));
            }
            catch {
                setDecrypted("[binary payload]");
            }
            setPayloadMeta({ name: header.name, mime: header.mime, bytes: plaintext.byteLength });
            setError(null);
            push("file ready", "accent");
            scheduleClear();
        }
        catch (err) {
            console.error(err);
            setPayloadMeta(null);
            setError("decrypt failed: bad passphrase or envelope");
            push("decrypt failed", "danger");
        }
        finally {
            setIsDecrypting(false);
        }
    }, [cipherText, decPass, push, scheduleClear]);
    const safeDownload = (blob, filename) => {
        const link = document.createElement("a");
        link.href = URL.createObjectURL(blob);
        link.download = filename;
        link.rel = "noopener";
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.setTimeout(() => URL.revokeObjectURL(link.href), 1500);
    };
    const downloadEncryptedFile = () => {
        if (!encFileBlob) {
            push("no envelope to download", "danger");
            return;
        }
        safeDownload(new Blob([encFileBlob], { type: "text/plain;charset=utf-8" }), `${encFile?.name ?? "payload"}.nullid`);
    };
    const downloadDecryptedFile = () => {
        if (!decFileBlob) {
            push("nothing to download", "danger");
            return;
        }
        const copy = new Uint8Array(decFileBlob);
        safeDownload(new Blob([copy.buffer], { type: decMime }), decFileName ?? "decrypted.bin");
    };
    useEffect(() => {
        if (!decPass || !cipherText) {
            setDecFileBlob(null);
            setDecFileName(null);
        }
    }, [cipherText, decPass]);
    useEffect(() => {
        const trimmed = cipherText.trim();
        if (!trimmed) {
            setEnvelopeMeta(null);
            setEnvelopeMetaError(null);
            return;
        }
        try {
            const inspected = inspectEnvelope(trimmed);
            setEnvelopeMeta({
                iterations: inspected.header.kdf.iterations,
                hash: inspected.header.kdf.hash,
                cipherBytes: inspected.ciphertextBytes,
                mime: inspected.header.mime,
                name: inspected.header.name,
            });
            setEnvelopeMetaError(null);
        }
        catch (error) {
            setEnvelopeMeta(null);
            setEnvelopeMetaError(error instanceof Error ? error.message : "invalid envelope");
        }
    }, [cipherText]);
    return (_jsxs("div", { className: "workspace-scroll", children: [_jsx("div", { className: "guide-link", children: _jsx("button", { type: "button", className: "guide-link-button", onClick: () => onOpenGuide?.("enc"), children: "? guide" }) }), _jsxs("div", { className: "grid-two", children: [_jsxs("div", { className: "panel", "aria-label": "Encrypt panel", children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: "Encrypt" }), _jsx("span", { className: "panel-subtext", children: "PBKDF2 + AES-GCM" })] }), _jsx("label", { className: "section-title", htmlFor: "encrypt-plain", children: "Plaintext" }), _jsx("textarea", { id: "encrypt-plain", className: "textarea", placeholder: "Enter text to encrypt", "aria-label": "Plaintext", value: plain, onChange: (event) => setPlain(event.target.value) }), _jsx("label", { className: "section-title", htmlFor: "encrypt-pass", children: "Passphrase" }), _jsx("input", { id: "encrypt-pass", className: "input", type: "password", placeholder: "\u2022\u2022\u2022\u2022\u2022\u2022", "aria-label": "Encrypt passphrase", value: encPass, onChange: (event) => setEncPass(event.target.value) }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: "passphrase strength" }), _jsx("span", { className: gradeTagClass(encPassAssessment.grade), children: gradeLabel(encPassAssessment.grade) }), _jsxs("span", { className: "microcopy", children: ["effective \u2248 ", encPassAssessment.effectiveEntropyBits, " bits"] })] }), _jsxs("div", { className: "controls-row", children: [_jsx("span", { className: "section-title", children: "KDF profile" }), _jsx("div", { className: "pill-buttons", role: "group", "aria-label": "KDF profile", children: ["compat", "strong", "paranoid"].map((profile) => (_jsx("button", { type: "button", className: kdfProfile === profile ? "active" : "", onClick: () => setKdfProfile(profile), children: profile }, profile))) })] }), _jsxs("div", { className: "controls-row", children: [_jsx("span", { className: "section-title", children: "KDF mode" }), _jsxs("div", { className: "pill-buttons", role: "group", "aria-label": "KDF mode", children: [_jsx("button", { type: "button", className: kdfMode === "profile" ? "active" : "", onClick: () => setKdfMode("profile"), children: "profile" }), _jsx("button", { type: "button", className: kdfMode === "custom" ? "active" : "", onClick: () => setKdfMode("custom"), children: "custom" })] }), kdfMode === "custom" && (_jsxs(_Fragment, { children: [_jsxs("select", { className: "select", value: customHash, onChange: (event) => setCustomHash(event.target.value), "aria-label": "Custom KDF hash", children: [_jsx("option", { value: "SHA-256", children: "SHA-256" }), _jsx("option", { value: "SHA-512", children: "SHA-512" })] }), _jsx("input", { className: "input", type: "number", min: 100000, max: 2000000, step: 50000, value: customIterations, onChange: (event) => setCustomIterations(clamp(Number(event.target.value) || 0, 100_000, 2_000_000)), "aria-label": "Custom KDF iterations" })] }))] }), _jsxs("div", { className: "microcopy", children: ["PBKDF2 ", kdfConfig.hash.toLowerCase(), " \u00B7 ", kdfConfig.iterations.toLocaleString(), " iterations"] }), _jsxs("div", { className: "controls-row", children: [_jsx("button", { className: "button", type: "button", onClick: handleEncryptText, disabled: !plain || !encPass || isEncrypting, children: "seal text" }), _jsx("button", { className: "button", type: "button", onClick: () => encryptFileInput.current?.click(), disabled: !encPass || isEncrypting, children: "select file" }), _jsx("input", { ref: encryptFileInput, type: "file", style: { position: "absolute", opacity: 0, width: 1, height: 1, pointerEvents: "none" }, onChange: (event) => setEncFile(event.target.files?.[0] ?? null), "aria-label": "Pick file to encrypt", tabIndex: -1 }), _jsx("button", { className: "button", type: "button", onClick: handleEncryptFile, disabled: !encPass || !encFile || isEncrypting, children: "seal file" })] }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: "file" }), _jsx(Chip, { label: encFile?.name ?? "none", tone: "muted" }), isEncrypting && _jsx(Chip, { label: "working\u2026", tone: "accent" })] })] }), _jsxs("div", { className: "panel", "aria-label": "Decrypt panel", children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: "Decrypt" }), _jsx("span", { className: "panel-subtext", children: "verify envelope" })] }), _jsx("label", { className: "section-title", htmlFor: "decrypt-blob", children: "Ciphertext" }), _jsx("textarea", { id: "decrypt-blob", className: "textarea", placeholder: "Paste envelope", "aria-label": "Ciphertext", value: cipherText, onChange: (event) => setCipherText(event.target.value) }), _jsxs("div", { className: "controls-row", children: [_jsx("button", { className: "button", type: "button", onClick: () => decryptFileInput.current?.click(), children: "load file" }), _jsx("input", { ref: decryptFileInput, type: "file", accept: ".nullid,text/plain", style: { position: "absolute", opacity: 0, width: 1, height: 1, pointerEvents: "none" }, onChange: async (event) => {
                                            const file = event.target.files?.[0];
                                            if (!file)
                                                return;
                                            const text = await file.text();
                                            setCipherText(text.trim());
                                        }, tabIndex: -1 }), _jsx("button", { className: "button", type: "button", onClick: handleDecryptText, disabled: !cipherText || !decPass || isDecrypting, children: "decrypt text" }), _jsx("button", { className: "button", type: "button", onClick: handleDecryptFile, disabled: !cipherText || !decPass || isDecrypting, children: "decrypt file" })] }), _jsx("label", { className: "section-title", htmlFor: "decrypt-pass", children: "Passphrase" }), _jsx("input", { id: "decrypt-pass", className: "input", type: "password", placeholder: "\u2022\u2022\u2022\u2022\u2022\u2022", "aria-label": "Decrypt passphrase", value: decPass, onChange: (event) => setDecPass(event.target.value) }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: "passphrase strength" }), _jsx("span", { className: gradeTagClass(decPassAssessment.grade), children: gradeLabel(decPassAssessment.grade) }), _jsxs("span", { className: "microcopy", children: ["effective \u2248 ", decPassAssessment.effectiveEntropyBits, " bits"] })] }), _jsxs("div", { className: "controls-row", children: [_jsx(Chip, { label: payloadMeta?.name ?? "text/plain", tone: "muted" }), payloadMeta?.bytes !== undefined && _jsx(Chip, { label: `${Math.ceil((payloadMeta.bytes ?? 0) / 1024)} KB`, tone: "muted" }), isDecrypting && _jsx(Chip, { label: "decrypting\u2026", tone: "accent" })] })] })] }), _jsxs("div", { className: "panel", "aria-label": "Envelope preview", children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: "Envelope" }), _jsx("span", { className: "panel-subtext", children: "NULLID:ENC:1" })] }), _jsxs("div", { className: "note-box", children: [_jsxs("div", { className: "microcopy", children: ["prefix NULLID:ENC:1, AES-GCM, PBKDF2 profile: ", kdfProfile, " (", kdfConfig.hash.toLowerCase(), " / ", kdfConfig.iterations.toLocaleString(), "), AAD bound"] }), _jsx("div", { className: "microcopy", children: envelopeMeta
                                    ? `header: ${envelopeMeta.hash.toLowerCase()} / ${envelopeMeta.iterations.toLocaleString()} · ${Math.ceil(envelopeMeta.cipherBytes / 1024)} KB ciphertext${envelopeMeta.name ? ` · ${envelopeMeta.name}` : ""}`
                                    : envelopeMetaError
                                        ? `header parse: ${envelopeMetaError}`
                                        : "header parse pending" }), _jsx("pre", { className: "output", children: cipherText || "Generate an envelope to view" })] }), _jsxs("div", { className: "controls-row", children: [_jsx("label", { className: "section-title", htmlFor: "auto-clear", children: "Hygiene" }), _jsxs("div", { className: "pill-buttons", role: "group", "aria-label": "Auto clear options", children: [_jsx("button", { id: "auto-clear", type: "button", className: autoClear ? "active" : "", onClick: () => setAutoClear((prev) => !prev), children: "auto clear" }), _jsx("input", { className: "input", type: "number", min: 5, max: 300, value: clearAfter, onChange: (event) => setClearAfter(Math.min(300, Math.max(5, Number(event.target.value)))), "aria-label": "Auto clear seconds" }), _jsx("button", { className: "button", type: "button", onClick: downloadEncryptedFile, disabled: !encFileBlob, children: "download envelope" }), _jsx("button", { className: "button", type: "button", onClick: downloadDecryptedFile, disabled: !decFileBlob, children: "download decrypted" })] })] }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: "decrypt" }), _jsx("span", { className: `tag ${error ? "tag-danger" : "tag-accent"}`, children: error || decrypted || "pending" })] })] }), _jsxs("div", { className: "panel", "aria-label": "Decryption output", children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: "Output" }), _jsx("span", { className: "panel-subtext", children: decFileBlob ? "file ready" : "text" })] }), _jsxs("div", { className: "note-box", children: [_jsx("div", { className: "microcopy", children: "Decrypted preview" }), _jsx("pre", { className: "output", "aria-live": "polite", children: decrypted || "[pending]" }), decFileBlob && (_jsxs("div", { className: "microcopy", children: ["file: ", decFileName ?? "decrypted.bin", " \u00B7 type: ", decMime, " \u00B7 size: ", decFileBlob.byteLength, " bytes"] }))] })] })] }));
}
function gradeTagClass(grade) {
    if (grade === "critical" || grade === "weak")
        return "tag tag-danger";
    if (grade === "fair")
        return "tag";
    return "tag tag-accent";
}
function clamp(value, min, max) {
    return Math.min(max, Math.max(min, value));
}
