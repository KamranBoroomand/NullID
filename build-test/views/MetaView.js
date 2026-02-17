import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import "./styles.css";
import { Chip } from "../components/Chip";
import { chooseExportMime, probeCanvasEncodeSupport, probeImageFormatDiagnostics, } from "../utils/imageFormats";
import { detectImageFormat, readMetadataFields } from "../utils/metadataInspector";
import { analyzeMetadataFromBuffer, sanitizePdfMetadata, } from "../utils/metadataAdvanced";
import { useI18n } from "../i18n";
export function MetaView({ onOpenGuide }) {
    const { t, tr } = useI18n();
    const fileInputRef = useRef(null);
    const advancedInputRef = useRef(null);
    const [sourceFile, setSourceFile] = useState(null);
    const [fileName, setFileName] = useState("none");
    const [beforeFields, setBeforeFields] = useState([]);
    const [afterFields, setAfterFields] = useState([]);
    const [removedFields, setRemovedFields] = useState([]);
    const [message, setMessage] = useState("drop an image to inspect metadata");
    const [cleanBlob, setCleanBlob] = useState(null);
    const [unsupportedReason, setUnsupportedReason] = useState(null);
    const [resizePercent, setResizePercent] = useState(100);
    const [outputChoice, setOutputChoice] = useState("auto");
    const [quality, setQuality] = useState(92);
    const [beforePreview, setBeforePreview] = useState(null);
    const [afterPreview, setAfterPreview] = useState(null);
    const [beforeSha256, setBeforeSha256] = useState("");
    const [afterSha256, setAfterSha256] = useState("");
    const [sizeDeltaBytes, setSizeDeltaBytes] = useState(0);
    const [formatRows, setFormatRows] = useState([]);
    const [outputSupport, setOutputSupport] = useState(null);
    const [advancedFile, setAdvancedFile] = useState(null);
    const [advancedFileName, setAdvancedFileName] = useState("none");
    const [advancedMode, setAdvancedMode] = useState("auto");
    const [advancedAnalysis, setAdvancedAnalysis] = useState(null);
    const [advancedMessage, setAdvancedMessage] = useState("drop any file for advanced metadata analysis");
    const [advancedActions, setAdvancedActions] = useState([]);
    const [advancedCleanBlob, setAdvancedCleanBlob] = useState(null);
    const [advancedBeforeSha256, setAdvancedBeforeSha256] = useState("");
    const [advancedAfterSha256, setAdvancedAfterSha256] = useState("");
    const refreshCleanResult = useCallback(async (file) => {
        try {
            const supportedOutput = outputSupport ?? (await probeCanvasEncodeSupport());
            if (!outputSupport)
                setOutputSupport(supportedOutput);
            const cleaned = await renderCleanImage(file, resizePercent / 100, supportedOutput, outputChoice, quality / 100);
            const afterMeta = await readMetadataFields(cleaned.cleanedBlob);
            setCleanBlob(cleaned.cleanedBlob);
            setAfterPreview((prev) => {
                if (prev)
                    URL.revokeObjectURL(prev);
                return URL.createObjectURL(cleaned.cleanedBlob);
            });
            setAfterFields([{ key: "type", value: cleaned.cleanedBlob.type }, { key: "exportMime", value: cleaned.outputMime }, ...afterMeta]);
            setRemovedFields(cleaned.removed);
            const [beforeDigest, afterDigest] = await Promise.all([sha256Hex(file), sha256Hex(cleaned.cleanedBlob)]);
            setBeforeSha256(beforeDigest);
            setAfterSha256(afterDigest);
            setSizeDeltaBytes(cleaned.cleanedBlob.size - file.size);
        }
        catch (error) {
            console.error(error);
            const detail = error instanceof Error ? error.message : "Failed to parse image metadata.";
            setMessage(detail);
            setUnsupportedReason("Browser could not decode this image format.");
        }
    }, [outputChoice, outputSupport, quality, resizePercent]);
    const handleFile = useCallback(async (file) => {
        if (!file)
            return;
        setUnsupportedReason(null);
        setSourceFile(null);
        setFileName(file.name);
        setBeforeFields([]);
        setAfterFields([]);
        setRemovedFields([]);
        setBeforeSha256("");
        setAfterSha256("");
        setCleanBlob(null);
        setBeforePreview((prev) => {
            if (prev)
                URL.revokeObjectURL(prev);
            return URL.createObjectURL(file);
        });
        setAfterPreview((prev) => {
            if (prev)
                URL.revokeObjectURL(prev);
            return null;
        });
        setMessage("reading…");
        if (!file.type.startsWith("image/")) {
            setMessage("Only images supported for EXIF.");
            setUnsupportedReason("Unsupported file type for metadata cleaning.");
            return;
        }
        const format = detectImageFormat(file.type, new Uint8Array(await file.slice(0, 64).arrayBuffer()), file.name);
        if (format === "heic") {
            setMessage("HEIC/HEIF parsing is usually blocked in browser decode pipelines.");
            setUnsupportedReason("Convert HEIC/HEIF to JPEG/PNG/AVIF before cleaning.");
            return;
        }
        try {
            setSourceFile(file);
            const dims = await readImageDimensions(file);
            const baseFields = await readMetadataFields(file);
            setBeforeFields([
                { key: "file", value: file.name },
                { key: "size", value: `${(file.size / 1024).toFixed(1)} KB` },
                { key: "type", value: file.type || "unknown" },
                { key: "format", value: format.toUpperCase() },
                { key: "dimensions", value: `${dims.width} x ${dims.height}` },
                ...baseFields,
            ]);
            setMessage(baseFields.length ? "metadata parsed" : "no metadata fields found");
        }
        catch (error) {
            console.error(error);
            const detail = error instanceof Error ? error.message : "Failed to parse image metadata.";
            setMessage(detail);
            setUnsupportedReason("Browser could not decode this image format.");
        }
    }, []);
    const handleAdvancedFile = useCallback(async (file) => {
        if (!file)
            return;
        setAdvancedFile(file);
        setAdvancedFileName(file.name);
        setAdvancedAnalysis(null);
        setAdvancedMessage("analyzing metadata…");
        setAdvancedActions([]);
        setAdvancedCleanBlob(null);
        setAdvancedBeforeSha256("");
        setAdvancedAfterSha256("");
        try {
            const shouldReadFull = file.size <= 24_000_000 || file.type.startsWith("image/") || file.type.includes("pdf");
            const analysisBytes = shouldReadFull ? new Uint8Array(await file.arrayBuffer()) : await readHeadTailBytes(file, 1_000_000);
            const analysis = analyzeMetadataFromBuffer(file.type || "", analysisBytes, file.name);
            setAdvancedAnalysis(analysis);
            setAdvancedBeforeSha256(await sha256Hex(file));
            setAdvancedMessage(shouldReadFull
                ? `analysis ready (${analysis.risk} risk)`
                : `analysis ready (${analysis.risk} risk, large-file sampled scan)`);
        }
        catch (error) {
            console.error(error);
            const detail = error instanceof Error ? error.message : "advanced metadata analysis failed";
            setAdvancedMessage(detail);
        }
    }, []);
    const refreshAdvancedSanitize = useCallback(async (file, analysis) => {
        const resolvedMode = resolveAdvancedMode(advancedMode, analysis.recommendedSanitizer);
        setAdvancedActions([]);
        setAdvancedCleanBlob(null);
        setAdvancedAfterSha256("");
        if (resolvedMode === "browser-image") {
            if (analysis.kind !== "image" || analysis.format === "heic") {
                setAdvancedMessage("image re-encode unavailable for this format");
                return;
            }
            try {
                const supportedOutput = outputSupport ?? (await probeCanvasEncodeSupport());
                if (!outputSupport)
                    setOutputSupport(supportedOutput);
                const cleaned = await renderCleanImage(file, 1, supportedOutput, "auto", 0.92);
                setAdvancedCleanBlob(cleaned.cleanedBlob);
                setAdvancedActions(cleaned.removed.length > 0 ? cleaned.removed : ["image re-encode completed (metadata minimized)"]);
                setAdvancedAfterSha256(await sha256Hex(cleaned.cleanedBlob));
                setAdvancedMessage("advanced sanitize ready");
                return;
            }
            catch (error) {
                console.error(error);
                const detail = error instanceof Error ? error.message : "image sanitize failed";
                setAdvancedMessage(detail);
                return;
            }
        }
        if (resolvedMode === "browser-pdf") {
            try {
                const result = await sanitizePdfMetadata(file);
                setAdvancedCleanBlob(result.cleanedBlob);
                setAdvancedActions(result.actions.length > 0 ? result.actions : ["no visible PDF metadata fields found"]);
                setAdvancedAfterSha256(await sha256Hex(result.cleanedBlob));
                setAdvancedMessage(result.changed ? "advanced sanitize ready" : "no visible metadata rewrites were required");
                return;
            }
            catch (error) {
                console.error(error);
                const detail = error instanceof Error ? error.message : "pdf sanitize failed";
                setAdvancedMessage(detail);
                return;
            }
        }
        if (resolvedMode === "mat2") {
            setAdvancedMessage("external sanitization recommended (mat2/ffmpeg)");
            setAdvancedActions(["in-browser sanitizer not available for this format"]);
            return;
        }
        setAdvancedMessage("analysis-only mode enabled");
        setAdvancedActions(["no sanitizer selected"]);
    }, [advancedMode, outputSupport]);
    const saveClean = async () => {
        if (!cleanBlob)
            return;
        const safeName = fileName.replace(/\.[^.]+$/, "") || "clean";
        const url = URL.createObjectURL(cleanBlob);
        const link = document.createElement("a");
        link.href = url;
        link.download = `${safeName}-clean.${extensionFromMime(cleanBlob.type)}`;
        link.click();
        URL.revokeObjectURL(url);
    };
    const saveAdvancedClean = useCallback(() => {
        if (!advancedCleanBlob)
            return;
        const safeName = advancedFileName.replace(/\.[^.]+$/, "") || "advanced-clean";
        const ext = advancedCleanBlob.type === "application/pdf"
            ? "pdf"
            : advancedCleanBlob.type
                ? extensionFromMime(advancedCleanBlob.type)
                : extensionFromFileName(advancedFileName);
        downloadBlob(advancedCleanBlob, `${safeName}-clean.${ext}`);
    }, [advancedCleanBlob, advancedFileName]);
    const exportAdvancedReport = useCallback(() => {
        if (!advancedFile || !advancedAnalysis)
            return;
        const payload = {
            file: advancedFile.name,
            bytes: advancedFile.size,
            sha256Before: advancedBeforeSha256 || null,
            sha256After: advancedAfterSha256 || null,
            mode: resolveAdvancedMode(advancedMode, advancedAnalysis.recommendedSanitizer),
            analysis: advancedAnalysis,
            actions: advancedActions,
            generatedAt: new Date().toISOString(),
        };
        downloadBlob(new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" }), "nullid-metadata-analysis.json");
    }, [advancedActions, advancedAfterSha256, advancedAnalysis, advancedBeforeSha256, advancedFile, advancedMode]);
    const copyExternalCommand = useCallback(async () => {
        if (!advancedAnalysis?.commandHint)
            return;
        try {
            await navigator.clipboard.writeText(advancedAnalysis.commandHint);
            setAdvancedMessage("command copied");
        }
        catch (error) {
            console.error(error);
            setAdvancedMessage("clipboard unavailable");
        }
    }, [advancedAnalysis]);
    const removedList = useMemo(() => removedFields.join(", "), [removedFields]);
    const compressionDeltaLabel = useMemo(() => {
        if (!sourceFile || !cleanBlob)
            return "n/a";
        const ratio = ((cleanBlob.size / Math.max(1, sourceFile.size)) * 100).toFixed(1);
        const sign = sizeDeltaBytes === 0 ? "" : sizeDeltaBytes > 0 ? "+" : "";
        return `${sign}${Math.round(sizeDeltaBytes / 1024)} KB (${ratio}% of original)`;
    }, [cleanBlob, sizeDeltaBytes, sourceFile]);
    const advancedActionList = useMemo(() => advancedActions.join(", "), [advancedActions]);
    const advancedResolvedMode = useMemo(() => (advancedAnalysis ? resolveAdvancedMode(advancedMode, advancedAnalysis.recommendedSanitizer) : "manual"), [advancedAnalysis, advancedMode]);
    useEffect(() => {
        let cancelled = false;
        void (async () => {
            try {
                const diagnostics = await probeImageFormatDiagnostics();
                if (cancelled)
                    return;
                setFormatRows(diagnostics.rows);
                setOutputSupport(diagnostics.outputSupport);
            }
            catch (error) {
                console.error("format diagnostics failed", error);
            }
        })();
        return () => {
            cancelled = true;
        };
    }, []);
    useEffect(() => {
        return () => {
            if (beforePreview)
                URL.revokeObjectURL(beforePreview);
            if (afterPreview)
                URL.revokeObjectURL(afterPreview);
        };
    }, [afterPreview, beforePreview]);
    useEffect(() => {
        if (!sourceFile || unsupportedReason)
            return;
        void refreshCleanResult(sourceFile);
    }, [outputChoice, quality, refreshCleanResult, resizePercent, sourceFile, unsupportedReason]);
    useEffect(() => {
        if (!advancedFile || !advancedAnalysis)
            return;
        void refreshAdvancedSanitize(advancedFile, advancedAnalysis);
    }, [advancedAnalysis, advancedFile, refreshAdvancedSanitize]);
    return (_jsxs("div", { className: "workspace-scroll", children: [_jsx("div", { className: "guide-link", children: _jsx("button", { type: "button", className: "guide-link-button", onClick: () => onOpenGuide?.("meta"), children: t("guide.link") }) }), _jsxs("div", { className: "grid-two", children: [_jsxs("div", { className: "panel", "aria-label": tr("Metadata input"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("Metadata Inspector") }), _jsx("span", { className: "panel-subtext", children: tr("drop image") })] }), _jsxs("div", { className: "dropzone", role: "button", tabIndex: 0, "aria-label": tr("Drop file for inspection"), onClick: () => fileInputRef.current?.click(), onKeyDown: (event) => {
                                    if (event.key === "Enter" || event.key === " ") {
                                        event.preventDefault();
                                        fileInputRef.current?.click();
                                    }
                                }, onDragOver: (event) => event.preventDefault(), onDrop: (event) => {
                                    event.preventDefault();
                                    void handleFile(event.dataTransfer.files?.[0] ?? null);
                                }, children: [_jsx("input", { ref: fileInputRef, type: "file", accept: "image/*", onChange: (event) => void handleFile(event.target.files?.[0] ?? null), style: { position: "absolute", opacity: 0, width: 1, height: 1, pointerEvents: "none" }, tabIndex: -1 }), _jsx("div", { className: "section-title", children: tr("drag image") }), _jsx("div", { className: "microcopy", children: "jpeg / png / webp / avif / gif / bmp / tiff" })] }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: tr("file") }), _jsx(Chip, { label: fileName, tone: "muted" }), _jsx(Chip, { label: message, tone: "accent" })] })] }), _jsxs("div", { className: "panel", "aria-label": tr("Clean export"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("Clean export") }), _jsx("span", { className: "panel-subtext", children: tr("strip EXIF") })] }), _jsx("p", { className: "microcopy", children: "Images are re-encoded via canvas to drop metadata. Compatibility diagnostics below show decode and export readiness by format." }), _jsxs("div", { className: "controls-row", children: [_jsx("label", { className: "section-title", htmlFor: "resize-percent", children: tr("Strip + resize") }), _jsxs("select", { id: "resize-percent", className: "select", value: resizePercent, onChange: (event) => setResizePercent(Number(event.target.value)), "aria-label": "Resize percent", children: [_jsx("option", { value: 100, children: "100%" }), _jsx("option", { value: 75, children: "75%" }), _jsx("option", { value: 50, children: "50%" })] }), _jsx("label", { className: "section-title", htmlFor: "meta-output-format", children: tr("Output format") }), _jsxs("select", { id: "meta-output-format", className: "select", value: outputChoice, onChange: (event) => setOutputChoice(event.target.value), "aria-label": "Output format", children: [_jsx("option", { value: "auto", children: "auto" }), _jsx("option", { value: "image/png", children: "png" }), _jsx("option", { value: "image/jpeg", children: "jpeg" }), _jsx("option", { value: "image/webp", children: "webp" }), _jsx("option", { value: "image/avif", children: "avif" })] }), _jsx("label", { className: "section-title", htmlFor: "meta-quality", children: tr("Quality") }), _jsx("input", { id: "meta-quality", className: "input", type: "number", min: 50, max: 100, value: quality, onChange: (event) => setQuality(Math.min(100, Math.max(50, Number(event.target.value)))), "aria-label": tr("Output quality percent") })] }), _jsxs("div", { className: "controls-row", children: [_jsx("button", { className: "button", type: "button", onClick: () => void saveClean(), disabled: !cleanBlob || Boolean(unsupportedReason), "aria-label": tr("Download cleaned image"), children: tr("download clean") }), unsupportedReason ? _jsx(Chip, { label: tr("unsupported"), tone: "danger" }) : _jsx(Chip, { label: tr("ready"), tone: "accent" })] }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: tr("removed") }), _jsx("span", { className: "microcopy", children: removedList || tr("none") })] }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: tr("size delta") }), _jsx("span", { className: "tag", children: compressionDeltaLabel }), _jsx("span", { className: "microcopy", children: cleanBlob ? `${tr("clean")} ${Math.ceil(cleanBlob.size / 1024)} KB` : tr("pending") })] }), _jsx("div", { className: "section-title", children: tr("Compatibility diagnostics") }), _jsxs("table", { className: "table", children: [_jsx("thead", { children: _jsxs("tr", { children: [_jsx("th", { children: tr("format") }), _jsx("th", { children: tr("decode") }), _jsx("th", { children: tr("encode") }), _jsx("th", { children: tr("clean export") })] }) }), _jsx("tbody", { children: formatRows.length === 0 ? (_jsx("tr", { children: _jsx("td", { colSpan: 4, className: "muted", children: tr("probing browser support...") }) })) : (formatRows.map((row) => (_jsxs("tr", { children: [_jsxs("td", { children: [row.label, row.note ? _jsx("div", { className: "microcopy", children: row.note }) : null] }), _jsx("td", { children: row.decode }), _jsx("td", { children: row.encode }), _jsx("td", { children: row.cleanExport })] }, row.key)))) })] })] })] }), _jsxs("div", { className: "panel", "aria-label": tr("Advanced metadata analysis"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("Advanced metadata analysis") }), _jsx("span", { className: "panel-subtext", children: tr("documents + images + videos") })] }), _jsxs("div", { className: "dropzone", role: "button", tabIndex: 0, "aria-label": tr("Drop file for advanced metadata analysis"), onClick: () => advancedInputRef.current?.click(), onKeyDown: (event) => {
                            if (event.key === "Enter" || event.key === " ") {
                                event.preventDefault();
                                advancedInputRef.current?.click();
                            }
                        }, onDragOver: (event) => event.preventDefault(), onDrop: (event) => {
                            event.preventDefault();
                            void handleAdvancedFile(event.dataTransfer.files?.[0] ?? null);
                        }, children: [_jsx("input", { ref: advancedInputRef, type: "file", accept: "image/*,video/*,application/pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.zip,.mkv,.avi,.mov,.mp4,.webm", onChange: (event) => void handleAdvancedFile(event.target.files?.[0] ?? null), style: { position: "absolute", opacity: 0, width: 1, height: 1, pointerEvents: "none" }, tabIndex: -1 }), _jsx("div", { className: "section-title", children: tr("drag any file") }), _jsx("div", { className: "microcopy", children: "image / pdf / office / video / archive" })] }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: tr("file") }), _jsx(Chip, { label: advancedFileName, tone: "muted" }), _jsx(Chip, { label: advancedMessage, tone: "accent" })] }), _jsxs("div", { className: "controls-row", children: [_jsx("label", { className: "section-title", htmlFor: "advanced-meta-mode", children: tr("Sanitize mode") }), _jsxs("select", { id: "advanced-meta-mode", className: "select", value: advancedMode, onChange: (event) => setAdvancedMode(event.target.value), "aria-label": tr("Advanced sanitize mode"), children: [_jsx("option", { value: "auto", children: "auto" }), _jsx("option", { value: "browser-image", children: "browser image clean" }), _jsx("option", { value: "browser-pdf", children: "browser pdf clean" }), _jsx("option", { value: "mat2", children: "mat2 / external clean" }), _jsx("option", { value: "manual", children: "analysis only" })] }), _jsx("button", { className: "button", type: "button", onClick: saveAdvancedClean, disabled: !advancedCleanBlob, children: tr("download advanced clean") }), _jsx("button", { className: "button", type: "button", onClick: exportAdvancedReport, disabled: !advancedAnalysis, children: tr("download analysis report") }), _jsx("button", { className: "button", type: "button", onClick: () => void copyExternalCommand(), disabled: !advancedAnalysis?.commandHint, children: tr("copy command") })] }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: tr("risk") }), _jsx(Chip, { label: advancedAnalysis?.risk ?? tr("pending"), tone: toneForRisk(advancedAnalysis?.risk) }), _jsx("span", { className: "microcopy", children: advancedAnalysis ? `${advancedAnalysis.kind} :: ${advancedAnalysis.format}` : tr("pending") })] }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: tr("sanitizer") }), _jsx(Chip, { label: advancedAnalysis ? formatSanitizerLabel(advancedResolvedMode) : tr("pending"), tone: advancedAnalysis && advancedResolvedMode !== "manual" ? "accent" : "muted" }), _jsx("span", { className: "microcopy", children: advancedActionList || tr("none") })] }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: tr("before sha256") }), _jsx("span", { className: "microcopy", children: advancedBeforeSha256 || tr("pending") })] }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: tr("after sha256") }), _jsx("span", { className: "microcopy", children: advancedAfterSha256 || tr("pending") })] }), advancedAnalysis?.commandHint ? (_jsxs("div", { className: "note-box", children: [_jsx("div", { className: "section-title", children: tr("External command hint") }), _jsx("div", { className: "microcopy", children: advancedAnalysis.commandHint })] })) : null, advancedAnalysis?.guidance?.length ? (_jsxs("div", { className: "note-box", children: [_jsx("div", { className: "section-title", children: tr("Guidance") }), _jsx("ul", { className: "note-list", children: advancedAnalysis.guidance.map((item) => (_jsx("li", { children: item }, item))) })] })) : null, _jsx("div", { className: "section-title", children: tr("Sensitive metadata signals") }), _jsxs("table", { className: "table", children: [_jsx("thead", { children: _jsxs("tr", { children: [_jsx("th", { children: tr("type") }), _jsx("th", { children: tr("severity") }), _jsx("th", { children: tr("detail") })] }) }), _jsx("tbody", { children: !advancedAnalysis || advancedAnalysis.signals.length === 0 ? (_jsx("tr", { children: _jsx("td", { colSpan: 3, className: "muted", children: tr("no signals") }) })) : (advancedAnalysis.signals.map((signal) => (_jsxs("tr", { children: [_jsx("td", { children: signal.label }), _jsx("td", { children: signal.severity }), _jsx("td", { children: signal.detail })] }, signal.id)))) })] }), _jsx("div", { className: "section-title", children: tr("Detected fields") }), _jsx("table", { className: "table", children: _jsx("tbody", { children: !advancedAnalysis || advancedAnalysis.fields.length === 0 ? (_jsx("tr", { children: _jsx("td", { className: "muted", colSpan: 2, children: tr("no fields") }) })) : (advancedAnalysis.fields.map((field, index) => (_jsxs("tr", { children: [_jsx("td", { children: field.key }), _jsx("td", { children: field.value })] }, `${field.key}-${index}`)))) }) })] }), _jsxs("div", { className: "panel", "aria-label": tr("Metadata table"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("Fields") }), _jsx("span", { className: "panel-subtext", children: tr("before / after") })] }), _jsxs("div", { className: "note-box", children: [_jsx("div", { className: "section-title", children: tr("Forensic fingerprint") }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: tr("before sha256") }), _jsx("span", { className: "microcopy", children: beforeSha256 || tr("pending") })] }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: tr("after sha256") }), _jsx("span", { className: "microcopy", children: afterSha256 || tr("pending") })] }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: tr("match") }), _jsx(Chip, { label: beforeSha256 && afterSha256 ? (beforeSha256 === afterSha256 ? tr("unchanged") : tr("changed")) : tr("pending"), tone: beforeSha256 && afterSha256 ? (beforeSha256 === afterSha256 ? "muted" : "accent") : "muted" })] })] }), _jsxs("div", { className: "grid-two", children: [_jsxs("div", { children: [_jsx("div", { className: "section-title", children: tr("Previews") }), _jsxs("div", { className: "grid-two", children: [_jsxs("div", { className: "note-box", children: [_jsx("div", { className: "microcopy", children: tr("Before") }), beforePreview ? (_jsx("img", { src: beforePreview, alt: "Before preview", className: "image-preview" })) : (_jsx("div", { className: "microcopy", children: tr("no file") }))] }), _jsxs("div", { className: "note-box", children: [_jsx("div", { className: "microcopy", children: tr("After (cleaned)") }), afterPreview ? (_jsx("img", { src: afterPreview, alt: "After preview", className: "image-preview" })) : (_jsx("div", { className: "microcopy", children: tr("not generated") }))] })] })] }), _jsxs("div", { children: [_jsx("div", { className: "section-title", children: tr("Before cleaning") }), _jsx("table", { className: "table", children: _jsx("tbody", { children: beforeFields.length === 0 ? (_jsx("tr", { children: _jsx("td", { className: "muted", colSpan: 2, children: tr("no fields") }) })) : (beforeFields.map((field) => (_jsxs("tr", { children: [_jsx("td", { children: field.key }), _jsx("td", { children: field.value })] }, field.key)))) }) })] }), _jsxs("div", { children: [_jsx("div", { className: "section-title", children: tr("After cleaning") }), _jsx("table", { className: "table", children: _jsx("tbody", { children: afterFields.length === 0 ? (_jsx("tr", { children: _jsx("td", { className: "muted", colSpan: 2, children: tr("stripped (expected minimal metadata after re-encode)") }) })) : (afterFields.map((field) => (_jsxs("tr", { children: [_jsx("td", { children: field.key }), _jsx("td", { children: field.value })] }, field.key)))) }) })] })] })] })] }));
}
function resolveAdvancedMode(mode, recommended) {
    return mode === "auto" ? recommended : mode;
}
function toneForRisk(value) {
    if (value === "high")
        return "danger";
    if (value === "medium")
        return "accent";
    return "muted";
}
function formatSanitizerLabel(value) {
    if (value === "browser-image")
        return "browser image clean";
    if (value === "browser-pdf")
        return "browser pdf clean";
    if (value === "mat2")
        return "mat2 / external clean";
    return "analysis only";
}
function extensionFromFileName(name) {
    const dot = name.lastIndexOf(".");
    if (dot < 0 || dot === name.length - 1)
        return "bin";
    return name.slice(dot + 1).toLowerCase();
}
function downloadBlob(blob, fileName) {
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = fileName;
    link.click();
    URL.revokeObjectURL(url);
}
async function readHeadTailBytes(file, sliceSize) {
    if (file.size <= sliceSize * 2) {
        return new Uint8Array(await file.arrayBuffer());
    }
    const head = new Uint8Array(await file.slice(0, sliceSize).arrayBuffer());
    const tail = new Uint8Array(await file.slice(Math.max(0, file.size - sliceSize)).arrayBuffer());
    const out = new Uint8Array(head.length + tail.length);
    out.set(head, 0);
    out.set(tail, head.length);
    return out;
}
async function renderCleanImage(file, scale, outputSupport, outputChoice, quality = 0.92) {
    const url = URL.createObjectURL(file);
    try {
        const img = await loadImage(url);
        const canvas = document.createElement("canvas");
        const clampScale = Math.max(0.1, Math.min(1, scale));
        canvas.width = Math.max(1, Math.round(img.naturalWidth * clampScale));
        canvas.height = Math.max(1, Math.round(img.naturalHeight * clampScale));
        const ctx = canvas.getContext("2d");
        if (!ctx)
            throw new Error("Canvas unavailable");
        ctx.drawImage(img, 0, 0);
        const preferredMime = outputChoice === "auto" ? chooseExportMime(file.type, outputSupport) : outputChoice;
        const candidates = Array.from(new Set([preferredMime, "image/png", "image/jpeg", "image/webp", "image/avif"])).filter((mime) => outputSupport[mime]);
        let cleanedBlob = null;
        let outputMime = preferredMime;
        for (const mime of candidates) {
            cleanedBlob = await new Promise((resolve) => {
                const codecQuality = mime === "image/png" ? undefined : Math.max(0.5, Math.min(1, quality));
                canvas.toBlob((blob) => resolve(blob), mime, codecQuality);
            });
            if (cleanedBlob && cleanedBlob.type === mime) {
                outputMime = mime;
                break;
            }
        }
        if (!cleanedBlob) {
            throw new Error("No supported export image codec available");
        }
        const before = await readMetadataFields(file);
        return {
            cleanedBlob,
            removed: before.map((entry) => entry.key),
            outputMime,
        };
    }
    finally {
        URL.revokeObjectURL(url);
    }
}
function loadImage(url) {
    return new Promise((resolve, reject) => {
        const img = new Image();
        img.onload = () => resolve(img);
        img.onerror = () => reject(new Error("Image load failed"));
        img.src = url;
    });
}
async function readImageDimensions(file) {
    const url = URL.createObjectURL(file);
    try {
        const img = await loadImage(url);
        return { width: img.naturalWidth, height: img.naturalHeight };
    }
    finally {
        URL.revokeObjectURL(url);
    }
}
function extensionFromMime(mime) {
    if (mime.includes("png"))
        return "png";
    if (mime.includes("webp"))
        return "webp";
    if (mime.includes("avif"))
        return "avif";
    if (mime.includes("gif"))
        return "gif";
    if (mime.includes("bmp"))
        return "bmp";
    if (mime.includes("tiff"))
        return "tiff";
    return "jpg";
}
async function sha256Hex(blob) {
    const bytes = new Uint8Array(await blob.arrayBuffer());
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
    return Array.from(digest)
        .map((value) => value.toString(16).padStart(2, "0"))
        .join("");
}
