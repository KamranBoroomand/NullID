import {
  detectImageFormat,
  inspectMetadataFromBuffer,
  type ImageFormat,
  type MetadataField,
} from "./metadataInspector.js";

export type MetadataRiskLevel = "low" | "medium" | "high";
export type MetadataTargetKind = "image" | "document" | "video" | "archive" | "unknown";
export type MetadataSanitizer = "browser-image" | "browser-pdf" | "mat2" | "manual";
export type MetadataDetectedFormat =
  | ImageFormat
  | "pdf"
  | "docx"
  | "xlsx"
  | "pptx"
  | "zip"
  | "mp4"
  | "mov"
  | "webm"
  | "mkv"
  | "avi"
  | "unknown";

export interface MetadataSignal {
  id: string;
  label: string;
  severity: MetadataRiskLevel;
  detail: string;
}

export interface MetadataReviewSection {
  id: "metadata-found" | "removable-locally" | "remaining-traces" | "unsupported-cleanup" | "review-recommendations";
  label: string;
  items: string[];
}

export interface MetadataAnalysisResult {
  format: MetadataDetectedFormat;
  kind: MetadataTargetKind;
  risk: MetadataRiskLevel;
  fields: MetadataField[];
  signals: MetadataSignal[];
  recommendedSanitizer: MetadataSanitizer;
  commandHint: string | null;
  guidance: string[];
  remainingTraces: string[];
  removable: string[];
  cannotGuarantee: string[];
  unsupportedCleanup: string[];
  reviewRecommendations: string[];
  metadataFound: string[];
  reviewSections: MetadataReviewSection[];
}

export interface PdfSanitizeBufferResult {
  cleanedBytes: Uint8Array;
  actions: string[];
  changed: boolean;
}

export interface PdfSanitizeResult {
  cleanedBlob: Blob;
  actions: string[];
  changed: boolean;
}

const MAX_SCAN_WINDOW = 1_000_000;
const MAX_METADATA_FIELDS = 80;
const latin1Decoder = new TextDecoder("latin1");

const videoFormats = new Set<MetadataDetectedFormat>(["mp4", "mov", "webm", "mkv", "avi"]);

export function detectMetadataFormat(mime: string, bytes: Uint8Array, fileName = ""): MetadataDetectedFormat {
  const image = detectImageFormat(mime, bytes, fileName);
  if (image !== "unknown") return image;

  const name = fileName.toLowerCase();
  if (name.endsWith(".pdf")) return "pdf";
  if (name.endsWith(".docx")) return "docx";
  if (name.endsWith(".xlsx")) return "xlsx";
  if (name.endsWith(".pptx")) return "pptx";
  if (name.endsWith(".mp4") || name.endsWith(".m4v")) return "mp4";
  if (name.endsWith(".mov") || name.endsWith(".qt")) return "mov";
  if (name.endsWith(".webm")) return "webm";
  if (name.endsWith(".mkv")) return "mkv";
  if (name.endsWith(".avi")) return "avi";

  if (bytes.length >= 5 && getAscii(bytes, 0, 5) === "%PDF-") return "pdf";

  const brand = parseFtypBrand(bytes);
  if (brand) {
    if (brand.startsWith("avif") || brand.startsWith("avis")) return "avif";
    if (brand.startsWith("heic") || brand.startsWith("heif") || brand.startsWith("heix") || brand.startsWith("hevc")) return "heic";
    if (brand === "qt  ") return "mov";
    return "mp4";
  }

  if (bytes.length >= 12 && getAscii(bytes, 0, 4) === "RIFF" && getAscii(bytes, 8, 4) === "AVI ") return "avi";
  if (bytes.length >= 4 && bytes[0] === 0x1a && bytes[1] === 0x45 && bytes[2] === 0xdf && bytes[3] === 0xa3) {
    if (name.endsWith(".webm")) return "webm";
    return "mkv";
  }

  if (isZip(bytes)) {
    const scanText = buildScanText(bytes);
    if (scanText.includes("word/")) return "docx";
    if (scanText.includes("xl/")) return "xlsx";
    if (scanText.includes("ppt/")) return "pptx";
    return "zip";
  }

  return "unknown";
}

export function analyzeMetadataFromBuffer(mime: string, bytes: Uint8Array, fileName = ""): MetadataAnalysisResult {
  const format = detectMetadataFormat(mime, bytes, fileName);
  const kind = classifyFormat(format);
  const fields = collectMetadataFields(format, mime, bytes);
  const signals = collectSignals(format, fields, bytes);
  const risk = resolveRisk(signals);
  const recommendedSanitizer = chooseSanitizer(format, kind);
  const metadataFound = buildMetadataFoundList(fields, signals, format);
  const removable = buildRemovableList(format, fields);
  const remainingTraces = buildRemainingTracesList(format, kind);
  const unsupportedCleanup = buildUnsupportedCleanupList(format, kind, recommendedSanitizer);
  const reviewRecommendations = buildReviewRecommendations(recommendedSanitizer, kind, signals, format);
  const cannotGuarantee = buildCannotGuaranteeList(format, kind);

  return {
    format,
    kind,
    risk,
    fields,
    signals,
    recommendedSanitizer,
    commandHint: buildCommandHint(format, fileName),
    guidance: buildGuidance(recommendedSanitizer, kind),
    remainingTraces,
    removable,
    cannotGuarantee,
    unsupportedCleanup,
    reviewRecommendations,
    metadataFound,
    reviewSections: buildReviewSections({
      metadataFound,
      removable,
      remainingTraces,
      unsupportedCleanup,
      reviewRecommendations,
    }),
  };
}

export async function analyzeMetadataFile(file: File): Promise<MetadataAnalysisResult> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  return analyzeMetadataFromBuffer(file.type || "", bytes, file.name);
}

export function sanitizePdfMetadataBuffer(bytes: Uint8Array): PdfSanitizeBufferResult {
  if (bytes.length < 5 || getAscii(bytes, 0, 5) !== "%PDF-") {
    return { cleanedBytes: bytes.slice(), actions: [], changed: false };
  }

  const input = decodeLatin1(bytes);
  let output = input;
  const actions: string[] = [];

  const rewrite = (regex: RegExp, transform: (...args: string[]) => string, label: string) => {
    const result = replaceSameLength(output, regex, transform);
    output = result.output;
    if (result.count > 0) actions.push(`${label}:${result.count}`);
  };

  rewrite(
    /(\/(?:Author|Creator|Producer|Title|Subject|Keywords)\s*)(\((?:\\.|[^()])*\)|<[^>]*>)/g,
    (_match, prefix, value) => `${prefix}${maskPdfValue(value, "redacted")}`,
    "info-fields",
  );
  rewrite(
    /(\/(?:CreationDate|ModDate)\s*)(\((?:\\.|[^()])*\)|<[^>]*>)/g,
    (_match, prefix, value) => `${prefix}${maskPdfValue(value, "D:19700101000000Z")}`,
    "date-fields",
  );
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

export async function sanitizePdfMetadata(file: File | Blob): Promise<PdfSanitizeResult> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  const result = sanitizePdfMetadataBuffer(bytes);
  const blobBytes = Uint8Array.from(result.cleanedBytes);
  return {
    cleanedBlob: new Blob([blobBytes], { type: "application/pdf" }),
    actions: result.actions,
    changed: result.changed,
  };
}

function classifyFormat(format: MetadataDetectedFormat): MetadataTargetKind {
  if (videoFormats.has(format)) return "video";
  if (["jpeg", "png", "webp", "avif", "gif", "bmp", "tiff", "heic"].includes(format)) return "image";
  if (["pdf", "docx", "xlsx", "pptx"].includes(format)) return "document";
  if (format === "zip") return "archive";
  return "unknown";
}

function collectMetadataFields(format: MetadataDetectedFormat, mime: string, bytes: Uint8Array): MetadataField[] {
  const collected = new Map<string, string>();
  const addField = (key: string, value: string) => {
    const cleanKey = key.trim();
    const cleanValue = sanitizeText(value);
    if (!cleanKey || !cleanValue || collected.has(cleanKey)) return;
    collected.set(cleanKey, cleanValue);
  };

  if (classifyFormat(format) === "image") {
    const base = inspectMetadataFromBuffer(mime, bytes);
    Object.entries(base).forEach(([key, value]) => addField(key, value));
  }

  const scanText = buildScanText(bytes);

  if (format === "pdf") {
    capturePdfField(scanText, /\/Title\s*(\((?:\\.|[^()])*\)|<[^>]*>)/i, "title", addField);
    capturePdfField(scanText, /\/Subject\s*(\((?:\\.|[^()])*\)|<[^>]*>)/i, "subject", addField);
    capturePdfField(scanText, /\/Keywords\s*(\((?:\\.|[^()])*\)|<[^>]*>)/i, "keywords", addField);
    capturePdfField(scanText, /\/Author\s*(\((?:\\.|[^()])*\)|<[^>]*>)/i, "author", addField);
    capturePdfField(scanText, /\/Creator\s*(\((?:\\.|[^()])*\)|<[^>]*>)/i, "creator", addField);
    capturePdfField(scanText, /\/Producer\s*(\((?:\\.|[^()])*\)|<[^>]*>)/i, "producer", addField);
    capturePdfField(scanText, /\/(?:CreationDate|ModDate)\s*(\((?:\\.|[^()])*\)|<[^>]*>)/i, "timestamp", addField);
    if (/<x:xmpmeta[\s\S]*?<\/x:xmpmeta>/i.test(scanText)) addField("xmp", "present");
    if (/\/Metadata\s+\d+\s+\d+\s+R/i.test(scanText)) addField("metadataRef", "present");
    if (/\/EmbeddedFiles\b/i.test(scanText)) addField("embeddedFiles", "present");
  }

  if (format === "docx" || format === "xlsx" || format === "pptx" || format === "zip") {
    if (scanText.includes("docProps/core.xml")) addField("docProps.core", "present");
    if (scanText.includes("docProps/app.xml")) addField("docProps.app", "present");
    if (scanText.includes("docProps/custom.xml")) addField("docProps.custom", "present");
    captureXmlField(scanText, "dc:creator", "creator", addField);
    captureXmlField(scanText, "dc:title", "title", addField);
    captureXmlField(scanText, "dc:subject", "subject", addField);
    captureXmlField(scanText, "cp:lastModifiedBy", "lastModifiedBy", addField);
    captureXmlField(scanText, "dcterms:created", "created", addField);
    captureXmlField(scanText, "dcterms:modified", "modified", addField);
    captureXmlField(scanText, "Application", "application", addField);
    captureXmlField(scanText, "Company", "company", addField);
    captureXmlField(scanText, "Manager", "manager", addField);
    captureXmlField(scanText, "Template", "template", addField);
    captureXmlField(scanText, "HyperlinkBase", "hyperlinkBase", addField);
    captureXmlField(scanText, "cp:revision", "revision", addField);
  }

  if (videoFormats.has(format)) {
    const brand = parseFtypBrand(bytes);
    if (brand) addField("containerBrand", brand.trim() || brand);
    if (/com\.apple\.quicktime\.location\.ISO6709/i.test(scanText)) addField("quicktimeLocation", "present");
    if (/(?:^|\W)(?:©nam|©ART|©cmt|©day|©too|©wrt)(?:$|\W)/i.test(scanText)) addField("itunesMetadataAtoms", "present");
  }

  return Array.from(collected.entries())
    .slice(0, MAX_METADATA_FIELDS)
    .map(([key, value]) => ({ key, value }));
}

function capturePdfField(scanText: string, pattern: RegExp, key: string, addField: (key: string, value: string) => void) {
  const match = scanText.match(pattern);
  if (!match?.[1]) return;
  addField(key, normalizePdfValue(match[1]));
}

function captureXmlField(scanText: string, tag: string, key: string, addField: (key: string, value: string) => void) {
  const escapedTag = tag.replace(/[-/\\^$*+?.()|[\]{}]/g, "\\$&");
  const regex = new RegExp(`<${escapedTag}[^>]*>([^<]{1,180})<\\/${escapedTag}>`, "i");
  const match = scanText.match(regex);
  if (!match?.[1]) return;
  addField(key, match[1]);
}

function collectSignals(format: MetadataDetectedFormat, fields: MetadataField[], bytes: Uint8Array): MetadataSignal[] {
  const dedupe = new Map<string, MetadataSignal>();
  const addSignal = (signal: MetadataSignal) => {
    if (!dedupe.has(signal.id)) dedupe.set(signal.id, signal);
  };

  const addByField = (pattern: RegExp, signal: MetadataSignal) => {
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
  const textSignals: Array<{ id: string; label: string; severity: MetadataRiskLevel; detail: string; pattern: RegExp }> = [
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

function resolveRisk(signals: MetadataSignal[]): MetadataRiskLevel {
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

  if (hasHigh || score >= 6) return "high";
  if (score >= 2) return "medium";
  return "low";
}

function chooseSanitizer(format: MetadataDetectedFormat, kind: MetadataTargetKind): MetadataSanitizer {
  if (format === "pdf") return "browser-pdf";
  if (kind === "image" && format !== "heic") return "browser-image";
  if (kind === "document" || kind === "archive" || kind === "video" || format === "heic") return "mat2";
  return "manual";
}

function buildGuidance(sanitizer: MetadataSanitizer, kind: MetadataTargetKind): string[] {
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

function buildMetadataFoundList(
  fields: MetadataField[],
  signals: MetadataSignal[],
  format: MetadataDetectedFormat,
) {
  return dedupeList([
    `Detected format: ${format}`,
    ...(signals.length > 0
      ? signals.map((signal) => `${signal.label}: ${signal.detail}`)
      : ["No high-signal metadata markers were surfaced in this local scan."]),
    ...(fields.length > 0
      ? fields.slice(0, 10).map((field) => `${field.key}: ${field.value}`)
      : ["No structured metadata fields were parsed from the scanned bytes."]),
  ]);
}

function buildRemovableList(format: MetadataDetectedFormat, fields: MetadataField[]): string[] {
  if (format === "pdf") {
    return dedupeList([
      fields.some((field) => ["author", "creator", "producer", "title", "subject", "keywords", "timestamp"].includes(field.key))
        ? "PDF info-dictionary fields such as author, title, producer, and timestamps."
        : "",
      fields.some((field) => field.key === "xmp") ? "Embedded XMP metadata packets." : "",
      fields.some((field) => field.key === "metadataRef") ? "Direct PDF metadata references that point at metadata objects." : "",
    ]);
  }

  if (["docx", "xlsx", "pptx"].includes(format)) {
    return dedupeList([
      "OOXML document properties in docProps/core.xml, app.xml, and custom.xml.",
      fields.some((field) => ["creator", "lastModifiedBy", "company", "manager", "template"].includes(field.key))
        ? "Author, editor, company, manager, and template strings when external cleanup rewrites package metadata."
        : "",
    ]);
  }

  if (format === "zip") {
    return dedupeList([
      "Archive-internal metadata files only if you unpack, inspect, and re-pack them intentionally.",
      "NullID can hash and verify ZIP contents locally, but it does not silently rewrite arbitrary archive members here.",
    ]);
  }

  if (videoFormats.has(format)) {
    return [
      "Container metadata atoms and common creation/location tags through external offline tools such as ffmpeg.",
    ];
  }

  if (classifyFormat(format) === "image") {
    return [
      "EXIF, XMP, and similar container metadata when the file is re-encoded locally.",
    ];
  }

  return [
    "Only metadata markers that the chosen offline sanitizer explicitly rewrites.",
  ];
}

function buildRemainingTracesList(format: MetadataDetectedFormat, kind: MetadataTargetKind): string[] {
  if (format === "pdf") {
    return [
      "Visible page text, annotations, attachments, and incremental-update history may still carry private context.",
      "Embedded files or hidden objects can survive unless you review the document structure manually.",
    ];
  }

  if (["docx", "xlsx", "pptx"].includes(format)) {
    return [
      "Comments, tracked changes, speaker notes, hidden sheets/slides, and embedded previews may still remain.",
      "Relationship targets, embedded objects, and document body content can preserve context beyond document properties.",
    ];
  }

  if (kind === "archive") {
    return [
      "Archive member names, folder layout, and each embedded file remain intact unless you repack intentionally.",
      "Archive comments, per-entry timestamps, and unsupported compressed members may still carry context.",
    ];
  }

  if (kind === "image") {
    return [
      "Visible pixels, burned-in labels, faces, watermarks, and any identifying scene content remain after metadata cleanup.",
      "Sidecar files or alternate image derivatives outside the current file are not covered by this analysis.",
    ];
  }

  if (kind === "video") {
    return [
      "Frame content, subtitle tracks, waveform-visible audio, and burned-in overlays remain outside metadata-only cleanup.",
      "Sidecar captions, thumbnails, and container-specific atoms may still exist in related files.",
    ];
  }

  return [
    "NullID can only explain what this local scan could see in the current file bytes.",
  ];
}

function buildCannotGuaranteeList(format: MetadataDetectedFormat, kind: MetadataTargetKind): string[] {
  if (format === "pdf") {
    return [
      "Hidden content, attachments, or incremental-update history are not guaranteed removed by this best-effort browser rewrite.",
      "Visible page content still needs manual review; metadata cleanup does not prove the document is safe to share.",
    ];
  }

  if (["docx", "xlsx", "pptx"].includes(format)) {
    return [
      "Comments, tracked changes, embedded objects, and document body text are not removed by metadata-only handling.",
      "NullID does not guarantee every OOXML relationship or embedded preview is clean without a full external scrub.",
    ];
  }

  if (kind === "archive") {
    return [
      "Archive member names, folder structure, and payload contents stay intact unless you rewrite them explicitly.",
      "A matching manifest proves byte consistency for listed entries, not that the archive is complete or harmless.",
    ];
  }

  if (kind === "image") {
    return [
      "Pixels, visible watermarks, and information rendered into the image are unaffected by metadata cleanup.",
      "Codec conversion can change bytes, but it does not prove all identifying context is gone.",
    ];
  }

  if (kind === "video") {
    return [
      "Frame content, burned-in overlays, and subtitle tracks are outside metadata-only cleanup guarantees.",
      "Different containers can carry extra atoms or sidecar files that still need manual review.",
    ];
  }

  return [
    "NullID only reports signals it can see locally; absence of findings is not proof that no metadata or context remains.",
  ];
}

function buildUnsupportedCleanupList(
  format: MetadataDetectedFormat,
  kind: MetadataTargetKind,
  sanitizer: MetadataSanitizer,
) {
  if (sanitizer === "manual") {
    return [
      "This file type currently has no safe in-browser cleanup path in NullID.",
      "Use an external offline tool, then re-run local analysis before sharing.",
    ];
  }

  if (sanitizer === "mat2") {
    return [
      "This surface can inspect the file locally, but cleanup depends on external offline tooling.",
      kind === "archive"
        ? "Archive member payloads are not silently rewritten here; unpack and repack intentionally if you need cleanup."
        : "NullID does not silently rewrite embedded document/media structures for this format in-browser.",
    ];
  }

  if (format === "pdf") {
    return [
      "Browser PDF cleanup is best-effort and does not rebuild the full document structure.",
    ];
  }

  return [];
}

function buildReviewRecommendations(
  sanitizer: MetadataSanitizer,
  kind: MetadataTargetKind,
  signals: MetadataSignal[],
  format: MetadataDetectedFormat,
) {
  const recommendations = [
    ...buildGuidance(sanitizer, kind),
    ...buildCannotGuaranteeList(format, kind),
  ];

  if (signals.some((signal) => signal.id === "geo" || signal.id === "geo-scan")) {
    recommendations.push("Check whether visible content or companion files also expose location information.");
  }
  if (signals.some((signal) => signal.id === "author" || signal.id === "identity-scan")) {
    recommendations.push("Review author, owner, and serial strings before export because they often survive outside obvious metadata panels.");
  }
  if (kind === "archive") {
    recommendations.push("Review archive member names and folder layout separately from hash comparison results.");
  }

  return dedupeList(recommendations);
}

function buildReviewSections(input: {
  metadataFound: string[];
  removable: string[];
  remainingTraces: string[];
  unsupportedCleanup: string[];
  reviewRecommendations: string[];
}): MetadataReviewSection[] {
  const sections: MetadataReviewSection[] = [
    { id: "metadata-found", label: "Metadata found", items: input.metadataFound },
    { id: "removable-locally", label: "Removable locally", items: input.removable },
    { id: "remaining-traces", label: "Remaining traces", items: input.remainingTraces },
    { id: "unsupported-cleanup", label: "Unsupported cleanup", items: input.unsupportedCleanup },
    { id: "review-recommendations", label: "Review recommendations", items: input.reviewRecommendations },
  ];
  return sections.filter((section) => section.items.length > 0);
}

function dedupeList(items: string[]) {
  return Array.from(new Set(items.filter(Boolean)));
}

function buildCommandHint(format: MetadataDetectedFormat, fileName: string): string | null {
  const safeFile = shellQuote(fileName || "input-file");
  const output = shellQuote(suggestCleanName(fileName || "input-file", format));

  if (videoFormats.has(format)) {
    return `ffmpeg -i ${safeFile} -map_metadata -1 -c copy ${output}`;
  }

  if (format === "unknown") return null;
  return `mat2 ${safeFile}`;
}

function suggestCleanName(fileName: string, format: MetadataDetectedFormat): string {
  const dot = fileName.lastIndexOf(".");
  if (dot <= 0) return `${fileName}-clean`;
  const stem = fileName.slice(0, dot);
  const ext = fileName.slice(dot + 1);
  if (!ext) return `${stem}-clean`;
  if (format === "unknown") return `${stem}-clean.${ext}`;
  return `${stem}-clean.${ext}`;
}

function shellQuote(value: string): string {
  const escaped = value.replace(/["\\$`]/g, "\\$&");
  return `"${escaped}"`;
}

function isZip(bytes: Uint8Array): boolean {
  return bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04;
}

function parseFtypBrand(bytes: Uint8Array): string | null {
  if (bytes.length < 12 || getAscii(bytes, 4, 4) !== "ftyp") return null;
  return getAscii(bytes, 8, 4).toLowerCase();
}

function buildScanText(bytes: Uint8Array): string {
  if (bytes.length <= MAX_SCAN_WINDOW * 2) return decodeLatin1(bytes);
  const head = decodeLatin1(bytes.subarray(0, MAX_SCAN_WINDOW));
  const tail = decodeLatin1(bytes.subarray(bytes.length - MAX_SCAN_WINDOW));
  return `${head}\n[scan-truncated]\n${tail}`;
}

function decodeLatin1(bytes: Uint8Array): string {
  return latin1Decoder.decode(bytes);
}

function encodeLatin1(value: string): Uint8Array {
  const out = new Uint8Array(value.length);
  for (let i = 0; i < value.length; i += 1) {
    out[i] = value.charCodeAt(i) & 0xff;
  }
  return out;
}

function replaceSameLength(
  input: string,
  regex: RegExp,
  transform: (...args: string[]) => string,
): { output: string; count: number } {
  let count = 0;
  const output = input.replace(regex, (...args) => {
    count += 1;
    const match = args[0] as string;
    const next = String(transform(...(args as string[])));
    return fitToLength(next, match.length);
  });
  return { output, count };
}

function fitToLength(value: string, length: number, fillChar = " "): string {
  if (value.length === length) return value;
  if (value.length > length) return value.slice(0, length);
  return value + fillChar.repeat(length - value.length);
}

function maskPdfValue(value: string, token: string): string {
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

function normalizePdfValue(value: string): string {
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

function sanitizeText(value: string): string {
  return value
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

function getAscii(bytes: Uint8Array, offset: number, length: number): string {
  if (offset < 0 || length <= 0 || offset >= bytes.length) return "";
  const end = Math.min(bytes.length, offset + length);
  return String.fromCharCode(...bytes.subarray(offset, end));
}
