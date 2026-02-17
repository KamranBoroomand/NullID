import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Chip } from "../components/Chip";
import { useToast } from "../components/ToastHost";
import { useI18n } from "../i18n";
import "./styles.css";
import { expectedHashLengths, hashFile, hashText, normalizeHashInput } from "../utils/hash";
import { useClipboardPrefs, writeClipboard } from "../utils/clipboard";
import { usePersistentState } from "../hooks/usePersistentState";
export function HashView({ onRegisterActions, onStatus, onOpenGuide }) {
    const { push } = useToast();
    const { t, tr, formatNumber } = useI18n();
    const [clipboardPrefs] = useClipboardPrefs();
    const [algorithm, setAlgorithm] = useState("SHA-256");
    const [displayFormat, setDisplayFormat] = useState("hex");
    const [textValue, setTextValue] = useState("");
    const [verifyValue, setVerifyValue] = useState("");
    const [debouncedVerifyValue, setDebouncedVerifyValue] = useState("");
    const [result, setResult] = useState(null);
    const [source, setSource] = useState(null);
    const [fileName, setFileName] = useState("none");
    const [comparison, setComparison] = useState("idle");
    const [progress, setProgress] = useState(0);
    const [fileComparison, setFileComparison] = useState("idle");
    const [fileCompareName, setFileCompareName] = useState("none");
    const [batchInput, setBatchInput] = usePersistentState("nullid:hash:batch-input", "");
    const [batchAlgorithm, setBatchAlgorithm] = usePersistentState("nullid:hash:batch-algo", "SHA-256");
    const [batchRows, setBatchRows] = useState([]);
    const [isBatching, setIsBatching] = useState(false);
    const [isHashing, setIsHashing] = useState(false);
    const [lastDurationMs, setLastDurationMs] = useState(null);
    const [lastInputBytes, setLastInputBytes] = useState(null);
    const abortRef = useRef(null);
    const textDebounceRef = useRef(null);
    const verifyDebounceRef = useRef(null);
    const jobRef = useRef(0);
    const textTokenRef = useRef(0);
    const verifyTokenRef = useRef(0);
    const [isComposing, setIsComposing] = useState(false);
    const fileInputRef = useRef(null);
    const fileCompareRef = useRef(null);
    const algorithmRef = useRef(algorithm);
    const lastAlgorithmRef = useRef(algorithm);
    const resultRef = useRef(result);
    const debouncedVerifyRef = useRef(debouncedVerifyValue);
    const onStatusRef = useRef(onStatus);
    const handleProgress = useCallback((percent) => {
        setProgress(percent);
    }, []);
    const MAX_FILE_BYTES = 50 * 1024 * 1024; // 50MB (prevents browser OOM)
    const MAX_TEXT_CHARS = 1_000_000; // ~1MB text safety guard
    const TEXT_DEBOUNCE_MS = 300;
    const digestDisplay = useMemo(() => {
        if (!result)
            return "";
        if (displayFormat === "hex")
            return result.hex;
        if (displayFormat === "base64")
            return result.base64;
        if (displayFormat === "sha256sum" && algorithm === "SHA-256") {
            const name = source?.kind === "file" ? source.file.name : "stdin";
            return `${result.hex}  ${name}`;
        }
        return result.hex;
    }, [algorithm, displayFormat, result, source]);
    const isBusy = progress > 0 && progress < 100;
    const computeHash = useCallback(async (input) => {
        setComparison("idle");
        setFileComparison("idle");
        setProgress(0);
        setIsHashing(true);
        abortRef.current?.abort();
        const controller = new AbortController();
        abortRef.current = controller;
        const jobId = (jobRef.current += 1);
        const startedAt = performance.now();
        let succeeded = false;
        try {
            const nextResult = input.kind === "file"
                ? await hashFile(input.file, algorithm, { onProgress: handleProgress, signal: controller.signal })
                : await hashText(input.value, algorithm, { signal: controller.signal, onProgress: handleProgress });
            if (jobId === jobRef.current) {
                setResult(nextResult);
                setSource(input);
                setFileName(input.kind === "file" ? input.file.name : "inline");
                const bytes = input.kind === "file" ? input.file.size : new TextEncoder().encode(input.value).byteLength;
                setLastDurationMs(Math.round(performance.now() - startedAt));
                setLastInputBytes(bytes);
                succeeded = true;
                onStatus?.("digest ready", "accent");
            }
        }
        catch (error) {
            if (error.name === "AbortError")
                return;
            console.error(error);
            if (jobId === jobRef.current) {
                setProgress(0);
                setComparison("idle");
                setFileComparison("idle");
            }
            const message = error instanceof Error ? error.message : "hash failed";
            onStatus?.(message, "danger");
        }
        finally {
            if (jobId === jobRef.current && succeeded) {
                setProgress(100);
            }
            if (jobId === jobRef.current) {
                setIsHashing(false);
            }
        }
    }, [algorithm, handleProgress, onStatus]);
    const report = useCallback((message, tone = "neutral") => {
        onStatus?.(message, tone);
        push(message, tone === "danger" ? "danger" : tone === "accent" ? "accent" : "neutral");
    }, [onStatus, push]);
    const handleFile = useCallback(async (file) => {
        if (!file)
            return;
        if (file.size > MAX_FILE_BYTES) {
            report(`file too large (${Math.ceil(file.size / (1024 * 1024))}MB). max 50MB.`, "danger");
            return;
        }
        await computeHash({ kind: "file", file });
    }, [MAX_FILE_BYTES, computeHash, report]);
    const handleTextChange = useCallback((value) => {
        if (value.length > MAX_TEXT_CHARS) {
            report("text too large for inline hashing", "danger");
            return;
        }
        setTextValue(value);
    }, [MAX_TEXT_CHARS, report]);
    const copyDigest = useCallback(async () => {
        if (!digestDisplay) {
            report("no digest", "danger");
            return;
        }
        await writeClipboard(digestDisplay, clipboardPrefs, report, "copied");
    }, [clipboardPrefs, digestDisplay, report]);
    const copyShaLine = useCallback(async () => {
        if (!result) {
            onStatus?.("no digest", "danger");
            return;
        }
        const name = source?.kind === "file" ? source.file.name : "stdin";
        const line = `${result.hex}  ${name}`;
        await writeClipboard(line, clipboardPrefs, report, "sha256sum line copied");
    }, [clipboardPrefs, report, result, source]);
    const runBatchHash = useCallback(async () => {
        const lines = batchInput
            .split(/\r?\n/)
            .map((line) => line.trim())
            .filter(Boolean)
            .slice(0, 120);
        if (lines.length === 0) {
            report("add lines for batch hashing", "danger");
            return;
        }
        setIsBatching(true);
        try {
            const rows = [];
            for (let i = 0; i < lines.length; i += 1) {
                const digest = await hashText(lines[i], batchAlgorithm);
                rows.push({ line: lines[i], hex: digest.hex, base64: digest.base64, index: i + 1 });
            }
            setBatchRows(rows);
            report(`batch hashed ${rows.length} lines`, "accent");
        }
        catch (error) {
            console.error(error);
            report("batch hash failed", "danger");
        }
        finally {
            setIsBatching(false);
        }
    }, [batchAlgorithm, batchInput, report]);
    const exportDigestManifest = useCallback(() => {
        if (!result) {
            report("no digest to export", "danger");
            return;
        }
        const payload = {
            schemaVersion: 1,
            kind: "nullid-hash-manifest",
            createdAt: new Date().toISOString(),
            algorithm,
            source: source?.kind ?? "none",
            sourceName: source?.kind === "file" ? source.file.name : "inline",
            sourceBytes: source?.kind === "file" ? source.file.size : source?.kind === "text" ? new TextEncoder().encode(source.value).byteLength : 0,
            digest: result,
            verifyValue: verifyValue.trim() || null,
            comparison,
            fileComparison,
            fileCompareName,
            durationMs: lastDurationMs,
        };
        const blob = new Blob([`${JSON.stringify(payload, null, 2)}\n`], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = `nullid-hash-manifest-${Date.now()}.json`;
        link.click();
        URL.revokeObjectURL(url);
        report("hash manifest exported", "accent");
    }, [algorithm, comparison, fileCompareName, fileComparison, lastDurationMs, report, result, source, verifyValue]);
    const exportBatchManifest = useCallback(() => {
        if (batchRows.length === 0) {
            report("no batch rows", "danger");
            return;
        }
        const payload = {
            schemaVersion: 1,
            kind: "nullid-hash-batch",
            createdAt: new Date().toISOString(),
            algorithm: batchAlgorithm,
            rows: batchRows.map((row) => ({ index: row.index, line: row.line, hex: row.hex, base64: row.base64 })),
        };
        const blob = new Blob([`${JSON.stringify(payload, null, 2)}\n`], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = `nullid-hash-batch-${Date.now()}.json`;
        link.click();
        URL.revokeObjectURL(url);
        report("batch manifest exported", "accent");
    }, [batchAlgorithm, batchRows, report]);
    const clearInputs = useCallback(() => {
        abortRef.current?.abort();
        setTextValue("");
        setVerifyValue("");
        setResult(null);
        setSource(null);
        setFileName("none");
        setProgress(0);
        setComparison("idle");
        setFileComparison("idle");
        setFileCompareName("none");
        if (fileInputRef.current)
            fileInputRef.current.value = "";
        if (fileCompareRef.current)
            fileCompareRef.current.value = "";
        onStatus?.("cleared", "neutral");
    }, [onStatus]);
    const compare = useCallback((value) => {
        const currentResult = resultRef.current;
        const currentVerify = value ?? debouncedVerifyRef.current;
        const expected = expectedHashLengths[algorithmRef.current];
        const status = onStatusRef.current;
        if (!currentResult) {
            setComparison("invalid");
            status?.("digest missing", "danger");
            return;
        }
        const normalized = normalizeHashInput(currentVerify);
        if (!normalized || (expected && normalized.length !== expected)) {
            setComparison("invalid");
            status?.("invalid hash", "danger");
            return;
        }
        const match = normalized === normalizeHashInput(currentResult.hex);
        setComparison(match ? "match" : "mismatch");
        status?.(match ? "hash match" : "hash mismatch", match ? "accent" : "danger");
    }, []);
    const handleVerifyChange = useCallback((value) => {
        setVerifyValue(value);
        setComparison("idle");
    }, []);
    useEffect(() => {
        if (lastAlgorithmRef.current === algorithm)
            return;
        lastAlgorithmRef.current = algorithm;
        if (source?.kind === "file")
            void computeHash(source);
    }, [algorithm, computeHash, source]);
    useEffect(() => {
        if (source?.kind === "file")
            return;
        if (isComposing)
            return;
        if (!textValue) {
            setResult(null);
            setSource(null);
            setFileName("none");
            setProgress(0);
            setIsHashing(false);
            return;
        }
        if (textDebounceRef.current)
            window.clearTimeout(textDebounceRef.current);
        const token = (textTokenRef.current += 1);
        textDebounceRef.current = window.setTimeout(() => {
            void (async () => {
                try {
                    await computeHash({ kind: "text", value: textValue });
                }
                catch (error) {
                    console.error(error);
                }
                finally {
                    if (textTokenRef.current === token) {
                        textDebounceRef.current = null;
                    }
                }
            })();
        }, TEXT_DEBOUNCE_MS);
    }, [TEXT_DEBOUNCE_MS, computeHash, isComposing, source, textValue]);
    useEffect(() => {
        algorithmRef.current = algorithm;
    }, [algorithm]);
    useEffect(() => {
        resultRef.current = result;
    }, [result]);
    useEffect(() => {
        if (verifyDebounceRef.current)
            window.clearTimeout(verifyDebounceRef.current);
        const token = (verifyTokenRef.current += 1);
        verifyDebounceRef.current = window.setTimeout(() => {
            if (verifyTokenRef.current === token) {
                setDebouncedVerifyValue(verifyValue);
                verifyDebounceRef.current = null;
            }
        }, 300);
    }, [verifyValue]);
    useEffect(() => {
        debouncedVerifyRef.current = debouncedVerifyValue;
        if (!debouncedVerifyValue) {
            setComparison("idle");
            return;
        }
        compare();
    }, [compare, debouncedVerifyValue]);
    useEffect(() => {
        onStatusRef.current = onStatus;
    }, [onStatus]);
    useEffect(() => {
        onRegisterActions?.({ copyDigest, clearInputs, compare });
        return () => onRegisterActions?.(null);
    }, [clearInputs, compare, copyDigest, onRegisterActions]);
    useEffect(() => {
        return () => {
            if (textDebounceRef.current)
                window.clearTimeout(textDebounceRef.current);
            if (verifyDebounceRef.current)
                window.clearTimeout(verifyDebounceRef.current);
            abortRef.current?.abort();
        };
    }, []);
    const comparisonTone = comparison === "match" ? "accent" : comparison === "invalid" || comparison === "mismatch" ? "danger" : "muted";
    const throughput = useMemo(() => {
        if (!lastDurationMs || !lastInputBytes || lastDurationMs <= 0)
            return null;
        const kibPerSec = (lastInputBytes / 1024) / (lastDurationMs / 1000);
        return `${kibPerSec.toFixed(1)} KiB/s`;
    }, [lastDurationMs, lastInputBytes]);
    return (_jsxs("div", { className: "workspace-scroll", children: [_jsx("div", { className: "guide-link", children: _jsx("button", { type: "button", className: "guide-link-button", onClick: () => onOpenGuide?.("hash"), children: t("guide.link") }) }), _jsxs("div", { className: "grid-two", children: [_jsxs("div", { className: "panel", "aria-label": tr("Hash inputs"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("Hash input") }), _jsx("span", { className: "panel-subtext", children: tr("text or file") })] }), _jsx("label", { className: "section-title", htmlFor: "hash-text", children: tr("Text") }), _jsx("textarea", { id: "hash-text", className: "textarea", placeholder: tr("Type or paste text to hash"), value: textValue, onCompositionStart: () => setIsComposing(true), onCompositionEnd: (event) => {
                                    setIsComposing(false);
                                    handleTextChange(event.currentTarget.value);
                                }, onChange: (event) => handleTextChange(event.target.value), "aria-label": tr("Text to hash") }), _jsxs("div", { className: "dropzone", role: "button", tabIndex: 0, "aria-label": tr("Drop file to hash"), onClick: () => fileInputRef.current?.click(), onKeyDown: (event) => {
                                    if (event.key === "Enter" || event.key === " ") {
                                        event.preventDefault();
                                        fileInputRef.current?.click();
                                    }
                                }, onDragOver: (event) => event.preventDefault(), onDrop: (event) => {
                                    event.preventDefault();
                                    void handleFile(event.dataTransfer.files?.[0] ?? null);
                                }, children: [_jsx("input", { ref: fileInputRef, type: "file", "aria-label": tr("Pick file"), onChange: (event) => void handleFile(event.target.files?.[0] ?? null), style: { position: "absolute", opacity: 0, width: 1, height: 1, pointerEvents: "none" }, tabIndex: -1 }), _jsx("div", { className: "section-title", children: tr("Drop or select file") }), _jsx("div", { className: "microcopy", children: tr("progressive chunk hashing") }), isBusy && _jsxs("div", { className: "microcopy", children: [tr("progress"), " ", progress, "%"] }), isHashing && _jsx("div", { className: "microcopy", children: tr("Hashing...") })] }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: tr("source") }), _jsx(Chip, { label: fileName, tone: "muted" }), isBusy && _jsx(Chip, { label: tr("hashing…"), tone: "accent" })] })] }), _jsxs("div", { className: "panel", "aria-label": tr("Hash output"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("Digest") }), _jsx("span", { className: "panel-subtext", children: algorithm.toLowerCase() })] }), _jsxs("div", { className: "controls-row", children: [_jsx("input", { className: "input", value: digestDisplay, readOnly: true, "aria-label": tr("Computed hash") }), _jsx("button", { className: "button", type: "button", onClick: copyDigest, disabled: !result, children: tr("copy") }), _jsx("button", { className: "button", type: "button", onClick: copyShaLine, disabled: !result || algorithm !== "SHA-256", children: tr("sha256sum line") }), _jsx("button", { className: "button", type: "button", onClick: exportDigestManifest, disabled: !result, children: tr("export manifest") })] }), _jsxs("div", { className: "controls-row", children: [_jsxs("div", { children: [_jsx("label", { className: "section-title", htmlFor: "hash-algo", children: tr("Algorithm") }), _jsxs("select", { id: "hash-algo", className: "select", value: algorithm, onChange: (event) => setAlgorithm(event.target.value), "aria-label": tr("Select hash algorithm"), children: [_jsx("option", { value: "SHA-256", children: "SHA-256" }), _jsx("option", { value: "SHA-512", children: "SHA-512" }), _jsx("option", { value: "SHA-1", children: tr("SHA-1 (legacy/insecure)") })] })] }), _jsxs("div", { children: [_jsx("div", { className: "section-title", "aria-hidden": "true", children: tr("Output") }), _jsx("div", { className: "pill-buttons", role: "group", "aria-label": tr("Output format"), children: ["hex", "base64", "sha256sum"].map((format) => (_jsx("button", { type: "button", className: displayFormat === format ? "active" : "", onClick: () => setDisplayFormat(format), disabled: format === "sha256sum" && algorithm !== "SHA-256", children: format }, format))) })] })] }), _jsx("div", { className: "microcopy", children: tr("Digest tools are for integrity checks. For password storage, use Password Storage Hashing (Argon2id/PBKDF2) in :pw.") }), _jsx("label", { className: "section-title", htmlFor: "hash-verify", children: tr("Verify digest") }), _jsxs("div", { className: "controls-row", children: [_jsx("input", { id: "hash-verify", className: "input", placeholder: tr("Paste hash to verify"), value: verifyValue, onChange: (event) => handleVerifyChange(event.target.value), "aria-label": tr("Hash to verify"), onKeyDown: (event) => {
                                            if (event.key === "Enter") {
                                                event.preventDefault();
                                                compare(verifyValue);
                                            }
                                        } }), _jsx("button", { className: "button", type: "button", onClick: () => compare(verifyValue), disabled: !verifyValue, children: tr("compare") })] }), _jsxs("div", { className: "controls-row", children: [_jsx("label", { className: "section-title", htmlFor: "hash-compare-file", children: tr("Compare against file") }), _jsx("button", { className: "button", type: "button", onClick: () => fileCompareRef.current?.click(), disabled: !result, children: tr("select file") }), _jsx("input", { ref: fileCompareRef, id: "hash-compare-file", type: "file", "aria-label": tr("Pick file to compare hash"), tabIndex: -1, style: { position: "absolute", opacity: 0, width: 1, height: 1, pointerEvents: "none" }, onChange: async (event) => {
                                            try {
                                                const file = event.target.files?.[0];
                                                if (!file)
                                                    return;
                                                if (!result) {
                                                    setFileComparison("idle");
                                                    onStatus?.("hash source first", "danger");
                                                    return;
                                                }
                                                setFileComparison("pending");
                                                setFileCompareName(file.name);
                                                const compareDigest = await hashFile(file, algorithm, { onProgress: handleProgress });
                                                const match = compareDigest.hex === result.hex;
                                                setFileComparison(match ? "match" : "mismatch");
                                                onStatus?.(match ? "files match" : "files differ", match ? "accent" : "danger");
                                            }
                                            catch (error) {
                                                console.error(error);
                                                setFileComparison("idle");
                                                onStatus?.("file compare failed", "danger");
                                            }
                                        } })] }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: tr("Result") }), _jsx(Chip, { label: comparison === "match"
                                            ? tr("MATCH")
                                            : comparison === "mismatch"
                                                ? tr("MISMATCH")
                                                : comparison === "invalid"
                                                    ? tr("INVALID")
                                                    : tr("PENDING"), tone: comparisonTone }), _jsx("span", { className: "microcopy", children: result ? tr("digest ready") : tr("awaiting input") })] }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: tr("Perf") }), _jsx("span", { className: "tag", children: lastDurationMs ? `${formatNumber(lastDurationMs)}ms` : tr("pending") }), _jsx("span", { className: "microcopy", children: throughput ? `${throughput} · ${formatNumber(Math.ceil((lastInputBytes ?? 0) / 1024))} KiB` : tr("hash telemetry after first run") })] }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: tr("File compare") }), _jsx(Chip, { label: fileComparison === "match"
                                            ? tr("FILES MATCH")
                                            : fileComparison === "mismatch"
                                                ? tr("FILES DIFFER")
                                                : fileComparison === "pending"
                                                    ? tr("CHECKING")
                                                    : tr("IDLE"), tone: fileComparison === "match" ? "accent" : fileComparison === "mismatch" ? "danger" : "muted" }), _jsxs("span", { className: "microcopy", children: [tr("against:"), " ", fileCompareName] })] })] })] }), _jsxs("div", { className: "panel", "aria-label": tr("Batch hash lab"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("Batch Hash Lab") }), _jsx("span", { className: "panel-subtext", children: tr("line-by-line integrity") })] }), _jsxs("div", { className: "controls-row", children: [_jsxs("select", { className: "select", value: batchAlgorithm, onChange: (event) => setBatchAlgorithm(event.target.value), "aria-label": tr("Batch hash algorithm"), children: [_jsx("option", { value: "SHA-256", children: "SHA-256" }), _jsx("option", { value: "SHA-512", children: "SHA-512" }), _jsx("option", { value: "SHA-1", children: tr("SHA-1 (legacy/insecure)") })] }), _jsx("button", { className: "button", type: "button", onClick: () => void runBatchHash(), disabled: isBatching, children: isBatching ? tr("hashing...") : tr("hash lines") }), _jsx("button", { className: "button", type: "button", onClick: exportBatchManifest, disabled: batchRows.length === 0, children: tr("export batch") })] }), _jsx("textarea", { className: "textarea", value: batchInput, onChange: (event) => setBatchInput(event.target.value), placeholder: tr("Paste one value per line (up to 120 lines)"), "aria-label": tr("Batch hash input") }), _jsxs("table", { className: "table", children: [_jsx("thead", { children: _jsxs("tr", { children: [_jsx("th", { children: "#" }), _jsx("th", { children: tr("input") }), _jsx("th", { children: tr("digest (hex)") })] }) }), _jsx("tbody", { children: batchRows.length === 0 ? (_jsx("tr", { children: _jsx("td", { colSpan: 3, className: "muted", children: tr("run batch hashing to populate") }) })) : (batchRows.slice(0, 10).map((row) => (_jsxs("tr", { children: [_jsx("td", { children: row.index }), _jsx("td", { className: "microcopy", children: row.line }), _jsx("td", { className: "microcopy", children: row.hex })] }, `${row.index}-${row.hex}`)))) })] })] })] }));
}
