import { detectImageFormat, inspectMetadataFromBuffer, } from "./metadataInspector.js";
const MAX_SCAN_WINDOW = 1_000_000;
const MAX_METADATA_FIELDS = 80;
const latin1Decoder = new TextDecoder("latin1");
const videoFormats = new Set(["mp4", "mov", "webm", "mkv", "avi"]);
export function detectMetadataFormat(mime, bytes, fileName = "") {
    const image = detectImageFormat(mime, bytes, fileName);
    if (image !== "unknown")
        return image;
    const name = fileName.toLowerCase();
    if (name.endsWith(".pdf"))
        return "pdf";
    if (name.endsWith(".docx"))
        return "docx";
    if (name.endsWith(".xlsx"))
        return "xlsx";
    if (name.endsWith(".pptx"))
        return "pptx";
    if (name.endsWith(".mp4") || name.endsWith(".m4v"))
        return "mp4";
    if (name.endsWith(".mov") || name.endsWith(".qt"))
        return "mov";
    if (name.endsWith(".webm"))
        return "webm";
    if (name.endsWith(".mkv"))
        return "mkv";
    if (name.endsWith(".avi"))
        return "avi";
    if (bytes.length >= 5 && getAscii(bytes, 0, 5) === "%PDF-")
        return "pdf";
    const brand = parseFtypBrand(bytes);
    if (brand) {
        if (brand.startsWith("avif") || brand.startsWith("avis"))
            return "avif";
        if (brand.startsWith("heic") || brand.startsWith("heif") || brand.startsWith("heix") || brand.startsWith("hevc"))
            return "heic";
        if (brand === "qt  ")
            return "mov";
        return "mp4";
    }
    if (bytes.length >= 12 && getAscii(bytes, 0, 4) === "RIFF" && getAscii(bytes, 8, 4) === "AVI ")
        return "avi";
    if (bytes.length >= 4 && bytes[0] === 0x1a && bytes[1] === 0x45 && bytes[2] === 0xdf && bytes[3] === 0xa3) {
        if (name.endsWith(".webm"))
            return "webm";
        return "mkv";
    }
    if (isZip(bytes)) {
        const scanText = buildScanText(bytes);
        if (scanText.includes("word/"))
            return "docx";
        if (scanText.includes("xl/"))
            return "xlsx";
        if (scanText.includes("ppt/"))
            return "pptx";
        return "zip";
    }
    return "unknown";
}
export function analyzeMetadataFromBuffer(mime, bytes, fileName = "") {
    const format = detectMetadataFormat(mime, bytes, fileName);
    const kind = classifyFormat(format);
    const fields = collectMetadataFields(format, mime, bytes);
    const signals = collectSignals(format, fields, bytes);
    const risk = resolveRisk(signals);
    const recommendedSanitizer = chooseSanitizer(format, kind);
    return {
        format,
        kind,
        risk,
        fields,
        signals,
        recommendedSanitizer,
        commandHint: buildCommandHint(format, fileName),
        guidance: buildGuidance(recommendedSanitizer, kind),
    };
}
export async function analyzeMetadataFile(file) {
    const bytes = new Uint8Array(await file.arrayBuffer());
    return analyzeMetadataFromBuffer(file.type || "", bytes, file.name);
}
export function sanitizePdfMetadataBuffer(bytes) {
    if (bytes.length < 5 || getAscii(bytes, 0, 5) !== "%PDF-") {
        return { cleanedBytes: bytes.slice(), actions: [], changed: false };
    }
    const input = decodeLatin1(bytes);
    let output = input;
    const actions = [];
    const rewrite = (regex, transform, label) => {
        const result = replaceSameLength(output, regex, transform);
        output = result.output;
        if (result.count > 0)
            actions.push(`${label}:${result.count}`);
    };
    rewrite(/(\/(?:Author|Creator|Producer|Title|Subject|Keywords)\s*)(\((?:\\.|[^()])*\)|<[^>]*>)/g, (_match, prefix, value) => `${prefix}${maskPdfValue(value, "redacted")}`, "info-fields");
    rewrite(/(\/(?:CreationDate|ModDate)\s*)(\((?:\\.|[^()])*\)|<[^>]*>)/g, (_match, prefix, value) => `${prefix}${maskPdfValue(value, "D:19700101000000Z")}`, "date-fields");
    rewrite(/(<x:xmpmeta[\s\S]*?<\/x:xmpmeta>)/gi, (match) => " ".repeat(match.length), "xmp-blocks");
    rewrite(/(<\?xpacket[\s\S]*?\?>)/gi, (match) => " ".repeat(match.length), "xpacket-blocks");
    rewrite(/(\/Metadata\s+)(\d+\s+\d+\s+R)/g, (_match, prefix, ref) => `${prefix}${fitToLength("0 0 R", ref.length)}`, "metadata-refs");
    const changed = output !== input;
    return {
        cleanedBytes: encodeLatin1(output),
        actions,
        changed,
    };
}
export async function sanitizePdfMetadata(file) {
    const bytes = new Uint8Array(await file.arrayBuffer());
    const result = sanitizePdfMetadataBuffer(bytes);
    const blobBytes = Uint8Array.from(result.cleanedBytes);
    return {
        cleanedBlob: new Blob([blobBytes], { type: "application/pdf" }),
        actions: result.actions,
        changed: result.changed,
    };
}
function classifyFormat(format) {
    if (videoFormats.has(format))
        return "video";
    if (["jpeg", "png", "webp", "avif", "gif", "bmp", "tiff", "heic"].includes(format))
        return "image";
    if (["pdf", "docx", "xlsx", "pptx"].includes(format))
        return "document";
    if (format === "zip")
        return "archive";
    return "unknown";
}
function collectMetadataFields(format, mime, bytes) {
    const collected = new Map();
    const addField = (key, value) => {
        const cleanKey = key.trim();
        const cleanValue = sanitizeText(value);
        if (!cleanKey || !cleanValue || collected.has(cleanKey))
            return;
        collected.set(cleanKey, cleanValue);
    };
    if (classifyFormat(format) === "image") {
        const base = inspectMetadataFromBuffer(mime, bytes);
        Object.entries(base).forEach(([key, value]) => addField(key, value));
    }
    const scanText = buildScanText(bytes);
    if (format === "pdf") {
        capturePdfField(scanText, /\/Author\s*(\((?:\\.|[^()])*\)|<[^>]*>)/i, "author", addField);
        capturePdfField(scanText, /\/Creator\s*(\((?:\\.|[^()])*\)|<[^>]*>)/i, "creator", addField);
        capturePdfField(scanText, /\/Producer\s*(\((?:\\.|[^()])*\)|<[^>]*>)/i, "producer", addField);
        capturePdfField(scanText, /\/(?:CreationDate|ModDate)\s*(\((?:\\.|[^()])*\)|<[^>]*>)/i, "timestamp", addField);
        if (/<x:xmpmeta[\s\S]*?<\/x:xmpmeta>/i.test(scanText))
            addField("xmp", "present");
        if (/\/Metadata\s+\d+\s+\d+\s+R/i.test(scanText))
            addField("metadataRef", "present");
    }
    if (format === "docx" || format === "xlsx" || format === "pptx" || format === "zip") {
        if (scanText.includes("docProps/core.xml"))
            addField("docProps.core", "present");
        if (scanText.includes("docProps/app.xml"))
            addField("docProps.app", "present");
        if (scanText.includes("docProps/custom.xml"))
            addField("docProps.custom", "present");
        captureXmlField(scanText, "dc:creator", "creator", addField);
        captureXmlField(scanText, "cp:lastModifiedBy", "lastModifiedBy", addField);
        captureXmlField(scanText, "dcterms:created", "created", addField);
        captureXmlField(scanText, "dcterms:modified", "modified", addField);
    }
    if (videoFormats.has(format)) {
        const brand = parseFtypBrand(bytes);
        if (brand)
            addField("containerBrand", brand.trim() || brand);
        if (/com\.apple\.quicktime\.location\.ISO6709/i.test(scanText))
            addField("quicktimeLocation", "present");
        if (/(?:^|\W)(?:©nam|©ART|©cmt|©day|©too|©wrt)(?:$|\W)/i.test(scanText))
            addField("itunesMetadataAtoms", "present");
    }
    return Array.from(collected.entries())
        .slice(0, MAX_METADATA_FIELDS)
        .map(([key, value]) => ({ key, value }));
}
function capturePdfField(scanText, pattern, key, addField) {
    const match = scanText.match(pattern);
    if (!match?.[1])
        return;
    addField(key, normalizePdfValue(match[1]));
}
function captureXmlField(scanText, tag, key, addField) {
    const escapedTag = tag.replace(/[-/\\^$*+?.()|[\]{}]/g, "\\$&");
    const regex = new RegExp(`<${escapedTag}[^>]*>([^<]{1,180})<\\/${escapedTag}>`, "i");
    const match = scanText.match(regex);
    if (!match?.[1])
        return;
    addField(key, match[1]);
}
function collectSignals(format, fields, bytes) {
    const dedupe = new Map();
    const addSignal = (signal) => {
        if (!dedupe.has(signal.id))
            dedupe.set(signal.id, signal);
    };
    const addByField = (pattern, signal) => {
        if (fields.some((field) => pattern.test(field.key) || pattern.test(field.value))) {
            addSignal(signal);
        }
    };
    addByField(/gps|latitude|longitude/i, {
        id: "geo",
        label: "Geolocation",
        severity: "high",
        detail: "Location markers found (GPS/coordinates).",
    });
    addByField(/author|creator|artist|cameraownername|bodyserialnumber|lensserialnumber|copyright/i, {
        id: "author",
        label: "Author identity",
        severity: "high",
        detail: "Author, owner, or serial identity markers found.",
    });
    addByField(/created|modified|captured|datetime|timestamp|date/i, {
        id: "time",
        label: "Timestamps",
        severity: "medium",
        detail: "Creation or modification time markers found.",
    });
    addByField(/software|producer|xmp|metadataref|docprops|quicktimelocation|itunesmetadataatoms|makernote/i, {
        id: "tooling",
        label: "Tooling fingerprints",
        severity: "medium",
        detail: "Editing tool, embedded profile, or container metadata markers found.",
    });
    const scanText = buildScanText(bytes);
    const textSignals = [
        {
            id: "geo-scan",
            label: "Geolocation",
            severity: "high",
            detail: "Text scan found coordinate/location fields.",
            pattern: /(?:GPSLatitude|GPSLongitude|latitude|longitude|com\.apple\.quicktime\.location\.ISO6709|location=|geo:)/i,
        },
        {
            id: "identity-scan",
            label: "Author identity",
            severity: "high",
            detail: "Text scan found author/owner metadata fields.",
            pattern: /(?:\/Author\b|dc:creator|cp:lastModifiedBy|cameraOwnerName|bodySerialNumber|artist|copyright)/i,
        },
        {
            id: "time-scan",
            label: "Timestamps",
            severity: "medium",
            detail: "Text scan found create/modify timestamps.",
            pattern: /(?:CreationDate|ModDate|DateTimeOriginal|dcterms:created|dcterms:modified|timestamp)/i,
        },
        {
            id: "xmp-scan",
            label: "XMP / embedded metadata",
            severity: "medium",
            detail: "XMP or EXIF containers appear present.",
            pattern: /(?:Exif\u0000\u0000|<x:xmpmeta|<\?xpacket|\/Metadata\s+\d+\s+\d+\s+R|docProps\/core\.xml)/i,
        },
    ];
    textSignals.forEach((signal) => {
        if (signal.pattern.test(scanText)) {
            addSignal({
                id: signal.id,
                label: signal.label,
                severity: signal.severity,
                detail: signal.detail,
            });
        }
    });
    if (fields.length > 0) {
        addSignal({
            id: "metadata-present",
            label: "Metadata fields present",
            severity: "low",
            detail: "Detected metadata fields that may include private context.",
        });
    }
    if (format === "unknown") {
        addSignal({
            id: "unknown-format",
            label: "Unknown format",
            severity: "medium",
            detail: "Format detection was inconclusive; use external scrubbers for safer handling.",
        });
    }
    return Array.from(dedupe.values());
}
function resolveRisk(signals) {
    let score = 0;
    let hasHigh = false;
    signals.forEach((signal) => {
        if (signal.severity === "high") {
            score += 3;
            hasHigh = true;
            return;
        }
        if (signal.severity === "medium") {
            score += 2;
            return;
        }
        score += 1;
    });
    if (hasHigh || score >= 6)
        return "high";
    if (score >= 2)
        return "medium";
    return "low";
}
function chooseSanitizer(format, kind) {
    if (format === "pdf")
        return "browser-pdf";
    if (kind === "image" && format !== "heic")
        return "browser-image";
    if (kind === "document" || kind === "archive" || kind === "video" || format === "heic")
        return "mat2";
    return "manual";
}
function buildGuidance(sanitizer, kind) {
    if (sanitizer === "browser-image") {
        return [
            "Use clean export to re-encode and strip EXIF/XMP metadata.",
            "Review before/after SHA-256 to verify file changes.",
        ];
    }
    if (sanitizer === "browser-pdf") {
        return [
            "Use browser PDF scrub to redact Author/Creator/Date/XMP metadata blocks.",
            "Validate critical PDFs after cleaning because this is a best-effort rewrite.",
        ];
    }
    if (sanitizer === "mat2") {
        return [
            "For broader document/media types, run mat2 locally for robust metadata stripping.",
            kind === "video"
                ? "For videos, ffmpeg metadata reset is often required in addition to mat2 workflows."
                : "Re-run analysis after external cleaning before sharing.",
        ];
    }
    return [
        "No safe in-browser sanitizer is available for this file format.",
        "Use external offline tooling and re-analyze before sharing.",
    ];
}
function buildCommandHint(format, fileName) {
    const safeFile = shellQuote(fileName || "input-file");
    const output = shellQuote(suggestCleanName(fileName || "input-file", format));
    if (videoFormats.has(format)) {
        return `ffmpeg -i ${safeFile} -map_metadata -1 -c copy ${output}`;
    }
    if (format === "unknown")
        return null;
    return `mat2 ${safeFile}`;
}
function suggestCleanName(fileName, format) {
    const dot = fileName.lastIndexOf(".");
    if (dot <= 0)
        return `${fileName}-clean`;
    const stem = fileName.slice(0, dot);
    const ext = fileName.slice(dot + 1);
    if (!ext)
        return `${stem}-clean`;
    if (format === "unknown")
        return `${stem}-clean.${ext}`;
    return `${stem}-clean.${ext}`;
}
function shellQuote(value) {
    const escaped = value.replace(/["\\$`]/g, "\\$&");
    return `"${escaped}"`;
}
function isZip(bytes) {
    return bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04;
}
function parseFtypBrand(bytes) {
    if (bytes.length < 12 || getAscii(bytes, 4, 4) !== "ftyp")
        return null;
    return getAscii(bytes, 8, 4).toLowerCase();
}
function buildScanText(bytes) {
    if (bytes.length <= MAX_SCAN_WINDOW * 2)
        return decodeLatin1(bytes);
    const head = decodeLatin1(bytes.subarray(0, MAX_SCAN_WINDOW));
    const tail = decodeLatin1(bytes.subarray(bytes.length - MAX_SCAN_WINDOW));
    return `${head}\n[scan-truncated]\n${tail}`;
}
function decodeLatin1(bytes) {
    return latin1Decoder.decode(bytes);
}
function encodeLatin1(value) {
    const out = new Uint8Array(value.length);
    for (let i = 0; i < value.length; i += 1) {
        out[i] = value.charCodeAt(i) & 0xff;
    }
    return out;
}
function replaceSameLength(input, regex, transform) {
    let count = 0;
    const output = input.replace(regex, (...args) => {
        count += 1;
        const match = args[0];
        const next = String(transform(...args));
        return fitToLength(next, match.length);
    });
    return { output, count };
}
function fitToLength(value, length, fillChar = " ") {
    if (value.length === length)
        return value;
    if (value.length > length)
        return value.slice(0, length);
    return value + fillChar.repeat(length - value.length);
}
function maskPdfValue(value, token) {
    if (value.startsWith("(") && value.endsWith(")") && value.length >= 2) {
        const inner = fitToLength(token, value.length - 2);
        return `(${inner})`;
    }
    if (value.startsWith("<") && value.endsWith(">") && value.length >= 2) {
        const hexToken = token.replace(/[^0-9a-f]/gi, "").toLowerCase() || "00";
        const inner = fitToLength(hexToken.repeat(Math.ceil((value.length - 2) / Math.max(1, hexToken.length))), value.length - 2, "0");
        return `<${inner}>`;
    }
    return fitToLength(token, value.length);
}
function normalizePdfValue(value) {
    if (value.startsWith("(") && value.endsWith(")")) {
        return sanitizeText(value.slice(1, -1).replace(/\\([()\\])/g, "$1"));
    }
    if (value.startsWith("<") && value.endsWith(">")) {
        const hex = value.slice(1, -1).replace(/[^0-9a-f]/gi, "");
        const bytes = new Uint8Array(Math.floor(hex.length / 2));
        for (let i = 0; i < bytes.length; i += 1) {
            bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
        }
        return sanitizeText(decodeLatin1(bytes));
    }
    return sanitizeText(value);
}
function sanitizeText(value) {
    return value
        .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, "")
        .replace(/\s+/g, " ")
        .trim();
}
function getAscii(bytes, offset, length) {
    if (offset < 0 || length <= 0 || offset >= bytes.length)
        return "";
    const end = Math.min(bytes.length, offset + length);
    return String.fromCharCode(...bytes.subarray(offset, end));
}
