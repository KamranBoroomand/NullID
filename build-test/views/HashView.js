import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Chip } from "../components/Chip";
import { useToast } from "../components/ToastHost";
import "./styles.css";
import { expectedHashLengths, hashFile, hashText, normalizeHashInput } from "../utils/hash";
import { useClipboardPrefs, writeClipboard } from "../utils/clipboard";
export function HashView({ onRegisterActions, onStatus, onOpenGuide }) {
    const { push } = useToast();
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
    const [isHashing, setIsHashing] = useState(false);
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
        let succeeded = false;
        try {
            const nextResult = input.kind === "file"
                ? await hashFile(input.file, algorithm, { onProgress: handleProgress, signal: controller.signal })
                : await hashText(input.value, algorithm, { signal: controller.signal, onProgress: handleProgress });
            if (jobId === jobRef.current) {
                setResult(nextResult);
                setSource(input);
                setFileName(input.kind === "file" ? input.file.name : "inline");
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
    return (_jsxs("div", { className: "workspace-scroll", children: [_jsx("div", { className: "guide-link", children: _jsx("button", { type: "button", className: "guide-link-button", onClick: () => onOpenGuide?.("hash"), children: "? guide" }) }), _jsxs("div", { className: "grid-two", children: [_jsxs("div", { className: "panel", "aria-label": "Hash inputs", children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: "Hash input" }), _jsx("span", { className: "panel-subtext", children: "text or file" })] }), _jsx("label", { className: "section-title", htmlFor: "hash-text", children: "Text" }), _jsx("textarea", { id: "hash-text", className: "textarea", placeholder: "Type or paste text to hash", value: textValue, onCompositionStart: () => setIsComposing(true), onCompositionEnd: (event) => {
                                    setIsComposing(false);
                                    handleTextChange(event.currentTarget.value);
                                }, onChange: (event) => handleTextChange(event.target.value), "aria-label": "Text to hash" }), _jsxs("div", { className: "dropzone", role: "button", tabIndex: 0, "aria-label": "Drop file to hash", onClick: () => fileInputRef.current?.click(), onKeyDown: (event) => {
                                    if (event.key === "Enter" || event.key === " ") {
                                        event.preventDefault();
                                        fileInputRef.current?.click();
                                    }
                                }, onDragOver: (event) => event.preventDefault(), onDrop: (event) => {
                                    event.preventDefault();
                                    void handleFile(event.dataTransfer.files?.[0] ?? null);
                                }, children: [_jsx("input", { ref: fileInputRef, type: "file", "aria-label": "Pick file", onChange: (event) => void handleFile(event.target.files?.[0] ?? null), style: { position: "absolute", opacity: 0, width: 1, height: 1, pointerEvents: "none" }, tabIndex: -1 }), _jsx("div", { className: "section-title", children: "Drop or select file" }), _jsx("div", { className: "microcopy", children: "progressive chunk hashing" }), isBusy && _jsxs("div", { className: "microcopy", children: ["progress ", progress, "%"] }), isHashing && _jsx("div", { className: "microcopy", children: "Hashing..." })] }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: "source" }), _jsx(Chip, { label: fileName, tone: "muted" }), isBusy && _jsx(Chip, { label: "hashing\u2026", tone: "accent" })] })] }), _jsxs("div", { className: "panel", "aria-label": "Hash output", children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: "Digest" }), _jsx("span", { className: "panel-subtext", children: algorithm.toLowerCase() })] }), _jsxs("div", { className: "controls-row", children: [_jsx("input", { className: "input", value: digestDisplay, readOnly: true, "aria-label": "Computed hash" }), _jsx("button", { className: "button", type: "button", onClick: copyDigest, disabled: !result, children: "copy" }), _jsx("button", { className: "button", type: "button", onClick: copyShaLine, disabled: !result || algorithm !== "SHA-256", children: "sha256sum line" })] }), _jsxs("div", { className: "controls-row", children: [_jsxs("div", { children: [_jsx("label", { className: "section-title", htmlFor: "hash-algo", children: "Algorithm" }), _jsxs("select", { id: "hash-algo", className: "select", value: algorithm, onChange: (event) => setAlgorithm(event.target.value), "aria-label": "Select hash algorithm", children: [_jsx("option", { value: "SHA-256", children: "SHA-256" }), _jsx("option", { value: "SHA-512", children: "SHA-512" }), _jsx("option", { value: "SHA-1", children: "SHA-1 (legacy/insecure)" })] })] }), _jsxs("div", { children: [_jsx("div", { className: "section-title", "aria-hidden": "true", children: "Output" }), _jsx("div", { className: "pill-buttons", role: "group", "aria-label": "Output format", children: ["hex", "base64", "sha256sum"].map((format) => (_jsx("button", { type: "button", className: displayFormat === format ? "active" : "", onClick: () => setDisplayFormat(format), disabled: format === "sha256sum" && algorithm !== "SHA-256", children: format }, format))) })] })] }), _jsx("label", { className: "section-title", htmlFor: "hash-verify", children: "Verify digest" }), _jsxs("div", { className: "controls-row", children: [_jsx("input", { id: "hash-verify", className: "input", placeholder: "Paste hash to verify", value: verifyValue, onChange: (event) => handleVerifyChange(event.target.value), "aria-label": "Hash to verify", onKeyDown: (event) => {
                                            if (event.key === "Enter") {
                                                event.preventDefault();
                                                compare(verifyValue);
                                            }
                                        } }), _jsx("button", { className: "button", type: "button", onClick: () => compare(verifyValue), disabled: !verifyValue, children: "compare" })] }), _jsxs("div", { className: "controls-row", children: [_jsx("label", { className: "section-title", htmlFor: "hash-compare-file", children: "Compare against file" }), _jsx("button", { className: "button", type: "button", onClick: () => fileCompareRef.current?.click(), disabled: !result, children: "select file" }), _jsx("input", { ref: fileCompareRef, id: "hash-compare-file", type: "file", "aria-label": "Pick file to compare hash", tabIndex: -1, style: { position: "absolute", opacity: 0, width: 1, height: 1, pointerEvents: "none" }, onChange: async (event) => {
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
                                        } })] }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: "Result" }), _jsx(Chip, { label: comparison === "match"
                                            ? "MATCH"
                                            : comparison === "mismatch"
                                                ? "MISMATCH"
                                                : comparison === "invalid"
                                                    ? "INVALID"
                                                    : "PENDING", tone: comparisonTone }), _jsx("span", { className: "microcopy", children: result ? "digest ready" : "awaiting input" })] }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: "File compare" }), _jsx(Chip, { label: fileComparison === "match"
                                            ? "FILES MATCH"
                                            : fileComparison === "mismatch"
                                                ? "FILES DIFFER"
                                                : fileComparison === "pending"
                                                    ? "CHECKING"
                                                    : "IDLE", tone: fileComparison === "match" ? "accent" : fileComparison === "mismatch" ? "danger" : "muted" }), _jsxs("span", { className: "microcopy", children: ["against: ", fileCompareName] })] })] })] })] }));
}
