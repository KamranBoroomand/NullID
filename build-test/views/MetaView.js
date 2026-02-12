import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import "./styles.css";
import { Chip } from "../components/Chip";
import { chooseExportMime, probeCanvasEncodeSupport, probeImageFormatDiagnostics, } from "../utils/imageFormats";
import { detectImageFormat, readMetadataFields } from "../utils/metadataInspector";
export function MetaView({ onOpenGuide }) {
    const fileInputRef = useRef(null);
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
    const removedList = useMemo(() => removedFields.join(", "), [removedFields]);
    const compressionDeltaLabel = useMemo(() => {
        if (!sourceFile || !cleanBlob)
            return "n/a";
        const ratio = ((cleanBlob.size / Math.max(1, sourceFile.size)) * 100).toFixed(1);
        const sign = sizeDeltaBytes === 0 ? "" : sizeDeltaBytes > 0 ? "+" : "";
        return `${sign}${Math.round(sizeDeltaBytes / 1024)} KB (${ratio}% of original)`;
    }, [cleanBlob, sizeDeltaBytes, sourceFile]);
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
    return (_jsxs("div", { className: "workspace-scroll", children: [_jsx("div", { className: "guide-link", children: _jsx("button", { type: "button", className: "guide-link-button", onClick: () => onOpenGuide?.("meta"), children: "? guide" }) }), _jsxs("div", { className: "grid-two", children: [_jsxs("div", { className: "panel", "aria-label": "Metadata input", children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: "Metadata Inspector" }), _jsx("span", { className: "panel-subtext", children: "drop image" })] }), _jsxs("div", { className: "dropzone", role: "button", tabIndex: 0, "aria-label": "Drop file for inspection", onClick: () => fileInputRef.current?.click(), onKeyDown: (event) => {
                                    if (event.key === "Enter" || event.key === " ") {
                                        event.preventDefault();
                                        fileInputRef.current?.click();
                                    }
                                }, onDragOver: (event) => event.preventDefault(), onDrop: (event) => {
                                    event.preventDefault();
                                    void handleFile(event.dataTransfer.files?.[0] ?? null);
                                }, children: [_jsx("input", { ref: fileInputRef, type: "file", accept: "image/*", onChange: (event) => void handleFile(event.target.files?.[0] ?? null), style: { position: "absolute", opacity: 0, width: 1, height: 1, pointerEvents: "none" }, tabIndex: -1 }), _jsx("div", { className: "section-title", children: "drag image" }), _jsx("div", { className: "microcopy", children: "jpeg / png / webp / avif / gif / bmp / tiff" })] }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: "file" }), _jsx(Chip, { label: fileName, tone: "muted" }), _jsx(Chip, { label: message, tone: "accent" })] })] }), _jsxs("div", { className: "panel", "aria-label": "Clean export", children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: "Clean export" }), _jsx("span", { className: "panel-subtext", children: "strip EXIF" })] }), _jsx("p", { className: "microcopy", children: "Images are re-encoded via canvas to drop metadata. Compatibility diagnostics below show decode and export readiness by format." }), _jsxs("div", { className: "controls-row", children: [_jsx("label", { className: "section-title", htmlFor: "resize-percent", children: "Strip + resize" }), _jsxs("select", { id: "resize-percent", className: "select", value: resizePercent, onChange: (event) => setResizePercent(Number(event.target.value)), "aria-label": "Resize percent", children: [_jsx("option", { value: 100, children: "100%" }), _jsx("option", { value: 75, children: "75%" }), _jsx("option", { value: 50, children: "50%" })] }), _jsx("label", { className: "section-title", htmlFor: "meta-output-format", children: "Output format" }), _jsxs("select", { id: "meta-output-format", className: "select", value: outputChoice, onChange: (event) => setOutputChoice(event.target.value), "aria-label": "Output format", children: [_jsx("option", { value: "auto", children: "auto" }), _jsx("option", { value: "image/png", children: "png" }), _jsx("option", { value: "image/jpeg", children: "jpeg" }), _jsx("option", { value: "image/webp", children: "webp" }), _jsx("option", { value: "image/avif", children: "avif" })] }), _jsx("label", { className: "section-title", htmlFor: "meta-quality", children: "Quality" }), _jsx("input", { id: "meta-quality", className: "input", type: "number", min: 50, max: 100, value: quality, onChange: (event) => setQuality(Math.min(100, Math.max(50, Number(event.target.value)))), "aria-label": "Output quality percent" })] }), _jsxs("div", { className: "controls-row", children: [_jsx("button", { className: "button", type: "button", onClick: () => void saveClean(), disabled: !cleanBlob || Boolean(unsupportedReason), "aria-label": "Download cleaned image", children: "download clean" }), unsupportedReason ? _jsx(Chip, { label: "unsupported", tone: "danger" }) : _jsx(Chip, { label: "ready", tone: "accent" })] }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: "removed" }), _jsx("span", { className: "microcopy", children: removedList || "none" })] }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: "size delta" }), _jsx("span", { className: "tag", children: compressionDeltaLabel }), _jsx("span", { className: "microcopy", children: cleanBlob ? `clean ${Math.ceil(cleanBlob.size / 1024)} KB` : "pending" })] }), _jsx("div", { className: "section-title", children: "Compatibility diagnostics" }), _jsxs("table", { className: "table", children: [_jsx("thead", { children: _jsxs("tr", { children: [_jsx("th", { children: "format" }), _jsx("th", { children: "decode" }), _jsx("th", { children: "encode" }), _jsx("th", { children: "clean export" })] }) }), _jsx("tbody", { children: formatRows.length === 0 ? (_jsx("tr", { children: _jsx("td", { colSpan: 4, className: "muted", children: "probing browser support..." }) })) : (formatRows.map((row) => (_jsxs("tr", { children: [_jsxs("td", { children: [row.label, row.note ? _jsx("div", { className: "microcopy", children: row.note }) : null] }), _jsx("td", { children: row.decode }), _jsx("td", { children: row.encode }), _jsx("td", { children: row.cleanExport })] }, row.key)))) })] })] })] }), _jsxs("div", { className: "panel", "aria-label": "Metadata table", children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: "Fields" }), _jsx("span", { className: "panel-subtext", children: "before / after" })] }), _jsxs("div", { className: "note-box", children: [_jsx("div", { className: "section-title", children: "Forensic fingerprint" }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: "before sha256" }), _jsx("span", { className: "microcopy", children: beforeSha256 || "pending" })] }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: "after sha256" }), _jsx("span", { className: "microcopy", children: afterSha256 || "pending" })] }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: "match" }), _jsx(Chip, { label: beforeSha256 && afterSha256 ? (beforeSha256 === afterSha256 ? "unchanged" : "changed") : "pending", tone: beforeSha256 && afterSha256 ? (beforeSha256 === afterSha256 ? "muted" : "accent") : "muted" })] })] }), _jsxs("div", { className: "grid-two", children: [_jsxs("div", { children: [_jsx("div", { className: "section-title", children: "Previews" }), _jsxs("div", { className: "grid-two", children: [_jsxs("div", { className: "note-box", children: [_jsx("div", { className: "microcopy", children: "Before" }), beforePreview ? (_jsx("img", { src: beforePreview, alt: "Before preview", className: "image-preview" })) : (_jsx("div", { className: "microcopy", children: "no file" }))] }), _jsxs("div", { className: "note-box", children: [_jsx("div", { className: "microcopy", children: "After (cleaned)" }), afterPreview ? (_jsx("img", { src: afterPreview, alt: "After preview", className: "image-preview" })) : (_jsx("div", { className: "microcopy", children: "not generated" }))] })] })] }), _jsxs("div", { children: [_jsx("div", { className: "section-title", children: "Before cleaning" }), _jsx("table", { className: "table", children: _jsx("tbody", { children: beforeFields.length === 0 ? (_jsx("tr", { children: _jsx("td", { className: "muted", colSpan: 2, children: "no fields" }) })) : (beforeFields.map((field) => (_jsxs("tr", { children: [_jsx("td", { children: field.key }), _jsx("td", { children: field.value })] }, field.key)))) }) })] }), _jsxs("div", { children: [_jsx("div", { className: "section-title", children: "After cleaning" }), _jsx("table", { className: "table", children: _jsx("tbody", { children: afterFields.length === 0 ? (_jsx("tr", { children: _jsx("td", { className: "muted", colSpan: 2, children: "stripped (expected minimal metadata after re-encode)" }) })) : (afterFields.map((field) => (_jsxs("tr", { children: [_jsx("td", { children: field.key }), _jsx("td", { children: field.value })] }, field.key)))) }) })] })] })] })] }));
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
