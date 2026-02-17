import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import "./styles.css";
import { Chip } from "../components/Chip";
import {
  chooseExportMime,
  probeCanvasEncodeSupport,
  probeImageFormatDiagnostics,
  type ImageFormatDiagnostic,
  type OutputMime,
} from "../utils/imageFormats";
import { detectImageFormat, readMetadataFields } from "../utils/metadataInspector";
import type { ModuleKey } from "../components/ModuleList";
import { useI18n } from "../i18n";

type MetaField = { key: string; value: string };
type OutputChoice = OutputMime | "auto";

interface CleanResult {
  cleanedBlob: Blob;
  removed: string[];
  outputMime: string;
}

interface MetaViewProps {
  onOpenGuide?: (key?: ModuleKey) => void;
}

export function MetaView({ onOpenGuide }: MetaViewProps) {
  const { t, tr } = useI18n();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [sourceFile, setSourceFile] = useState<File | null>(null);
  const [fileName, setFileName] = useState("none");
  const [beforeFields, setBeforeFields] = useState<MetaField[]>([]);
  const [afterFields, setAfterFields] = useState<MetaField[]>([]);
  const [removedFields, setRemovedFields] = useState<string[]>([]);
  const [message, setMessage] = useState("drop an image to inspect metadata");
  const [cleanBlob, setCleanBlob] = useState<Blob | null>(null);
  const [unsupportedReason, setUnsupportedReason] = useState<string | null>(null);
  const [resizePercent, setResizePercent] = useState(100);
  const [outputChoice, setOutputChoice] = useState<OutputChoice>("auto");
  const [quality, setQuality] = useState(92);
  const [beforePreview, setBeforePreview] = useState<string | null>(null);
  const [afterPreview, setAfterPreview] = useState<string | null>(null);
  const [beforeSha256, setBeforeSha256] = useState<string>("");
  const [afterSha256, setAfterSha256] = useState<string>("");
  const [sizeDeltaBytes, setSizeDeltaBytes] = useState<number>(0);
  const [formatRows, setFormatRows] = useState<ImageFormatDiagnostic[]>([]);
  const [outputSupport, setOutputSupport] = useState<Record<OutputMime, boolean> | null>(null);

  const refreshCleanResult = useCallback(
    async (file: File) => {
      try {
        const supportedOutput = outputSupport ?? (await probeCanvasEncodeSupport());
        if (!outputSupport) setOutputSupport(supportedOutput);
        const cleaned = await renderCleanImage(file, resizePercent / 100, supportedOutput, outputChoice, quality / 100);
        const afterMeta = await readMetadataFields(cleaned.cleanedBlob);
        setCleanBlob(cleaned.cleanedBlob);
        setAfterPreview((prev) => {
          if (prev) URL.revokeObjectURL(prev);
          return URL.createObjectURL(cleaned.cleanedBlob);
        });
        setAfterFields([{ key: "type", value: cleaned.cleanedBlob.type }, { key: "exportMime", value: cleaned.outputMime }, ...afterMeta]);
        setRemovedFields(cleaned.removed);
        const [beforeDigest, afterDigest] = await Promise.all([sha256Hex(file), sha256Hex(cleaned.cleanedBlob)]);
        setBeforeSha256(beforeDigest);
        setAfterSha256(afterDigest);
        setSizeDeltaBytes(cleaned.cleanedBlob.size - file.size);
      } catch (error) {
        console.error(error);
        const detail = error instanceof Error ? error.message : "Failed to parse image metadata.";
        setMessage(detail);
        setUnsupportedReason("Browser could not decode this image format.");
      }
    },
    [outputChoice, outputSupport, quality, resizePercent],
  );

  const handleFile = useCallback(
    async (file?: File | null) => {
      if (!file) return;
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
        if (prev) URL.revokeObjectURL(prev);
        return URL.createObjectURL(file);
      });
      setAfterPreview((prev) => {
        if (prev) URL.revokeObjectURL(prev);
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
      } catch (error) {
        console.error(error);
        const detail = error instanceof Error ? error.message : "Failed to parse image metadata.";
        setMessage(detail);
        setUnsupportedReason("Browser could not decode this image format.");
      }
    },
    [],
  );

  const saveClean = async () => {
    if (!cleanBlob) return;
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
    if (!sourceFile || !cleanBlob) return "n/a";
    const ratio = ((cleanBlob.size / Math.max(1, sourceFile.size)) * 100).toFixed(1);
    const sign = sizeDeltaBytes === 0 ? "" : sizeDeltaBytes > 0 ? "+" : "";
    return `${sign}${Math.round(sizeDeltaBytes / 1024)} KB (${ratio}% of original)`;
  }, [cleanBlob, sizeDeltaBytes, sourceFile]);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const diagnostics = await probeImageFormatDiagnostics();
        if (cancelled) return;
        setFormatRows(diagnostics.rows);
        setOutputSupport(diagnostics.outputSupport);
      } catch (error) {
        console.error("format diagnostics failed", error);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    return () => {
      if (beforePreview) URL.revokeObjectURL(beforePreview);
      if (afterPreview) URL.revokeObjectURL(afterPreview);
    };
  }, [afterPreview, beforePreview]);

  useEffect(() => {
    if (!sourceFile || unsupportedReason) return;
    void refreshCleanResult(sourceFile);
  }, [outputChoice, quality, refreshCleanResult, resizePercent, sourceFile, unsupportedReason]);

  return (
    <div className="workspace-scroll">
      <div className="guide-link">
        <button type="button" className="guide-link-button" onClick={() => onOpenGuide?.("meta")}>
          {t("guide.link")}
        </button>
      </div>
      <div className="grid-two">
        <div className="panel" aria-label={tr("Metadata input")}>
          <div className="panel-heading">
            <span>{tr("Metadata Inspector")}</span>
            <span className="panel-subtext">{tr("drop image")}</span>
          </div>
          <div
            className="dropzone"
            role="button"
            tabIndex={0}
            aria-label={tr("Drop file for inspection")}
            onClick={() => fileInputRef.current?.click()}
            onKeyDown={(event) => {
              if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                fileInputRef.current?.click();
              }
            }}
            onDragOver={(event) => event.preventDefault()}
            onDrop={(event) => {
              event.preventDefault();
              void handleFile(event.dataTransfer.files?.[0] ?? null);
            }}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept="image/*"
              onChange={(event) => void handleFile(event.target.files?.[0] ?? null)}
              style={{ position: "absolute", opacity: 0, width: 1, height: 1, pointerEvents: "none" }}
              tabIndex={-1}
            />
            <div className="section-title">{tr("drag image")}</div>
            <div className="microcopy">jpeg / png / webp / avif / gif / bmp / tiff</div>
          </div>
          <div className="status-line">
            <span>{tr("file")}</span>
            <Chip label={fileName} tone="muted" />
            <Chip label={message} tone="accent" />
          </div>
        </div>
        <div className="panel" aria-label={tr("Clean export")}>
          <div className="panel-heading">
            <span>{tr("Clean export")}</span>
            <span className="panel-subtext">{tr("strip EXIF")}</span>
          </div>
          <p className="microcopy">
            Images are re-encoded via canvas to drop metadata. Compatibility diagnostics below show decode and export readiness by format.
          </p>
          <div className="controls-row">
            <label className="section-title" htmlFor="resize-percent">
              {tr("Strip + resize")}
            </label>
            <select
              id="resize-percent"
              className="select"
              value={resizePercent}
              onChange={(event) => setResizePercent(Number(event.target.value))}
              aria-label="Resize percent"
            >
              <option value={100}>100%</option>
              <option value={75}>75%</option>
              <option value={50}>50%</option>
            </select>
            <label className="section-title" htmlFor="meta-output-format">
              {tr("Output format")}
            </label>
            <select
              id="meta-output-format"
              className="select"
              value={outputChoice}
              onChange={(event) => setOutputChoice(event.target.value as OutputChoice)}
              aria-label="Output format"
            >
              <option value="auto">auto</option>
              <option value="image/png">png</option>
              <option value="image/jpeg">jpeg</option>
              <option value="image/webp">webp</option>
              <option value="image/avif">avif</option>
            </select>
            <label className="section-title" htmlFor="meta-quality">
              {tr("Quality")}
            </label>
            <input
              id="meta-quality"
              className="input"
              type="number"
              min={50}
              max={100}
              value={quality}
              onChange={(event) => setQuality(Math.min(100, Math.max(50, Number(event.target.value))))}
              aria-label={tr("Output quality percent")}
            />
          </div>
          <div className="controls-row">
            <button
              className="button"
              type="button"
              onClick={() => void saveClean()}
              disabled={!cleanBlob || Boolean(unsupportedReason)}
              aria-label={tr("Download cleaned image")}
            >
              {tr("download clean")}
            </button>
            {unsupportedReason ? <Chip label={tr("unsupported")} tone="danger" /> : <Chip label={tr("ready")} tone="accent" />}
          </div>
          <div className="status-line">
            <span>{tr("removed")}</span>
            <span className="microcopy">{removedList || tr("none")}</span>
          </div>
          <div className="status-line">
            <span>{tr("size delta")}</span>
            <span className="tag">{compressionDeltaLabel}</span>
            <span className="microcopy">{cleanBlob ? `${tr("clean")} ${Math.ceil(cleanBlob.size / 1024)} KB` : tr("pending")}</span>
          </div>
          <div className="section-title">{tr("Compatibility diagnostics")}</div>
          <table className="table">
            <thead>
              <tr>
                <th>{tr("format")}</th>
                <th>{tr("decode")}</th>
                <th>{tr("encode")}</th>
                <th>{tr("clean export")}</th>
              </tr>
            </thead>
            <tbody>
              {formatRows.length === 0 ? (
                <tr>
                  <td colSpan={4} className="muted">
                    {tr("probing browser support...")}
                  </td>
                </tr>
              ) : (
                formatRows.map((row) => (
                  <tr key={row.key}>
                    <td>
                      {row.label}
                      {row.note ? <div className="microcopy">{row.note}</div> : null}
                    </td>
                    <td>{row.decode}</td>
                    <td>{row.encode}</td>
                    <td>{row.cleanExport}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
      <div className="panel" aria-label={tr("Metadata table")}>
        <div className="panel-heading">
          <span>{tr("Fields")}</span>
          <span className="panel-subtext">{tr("before / after")}</span>
        </div>
        <div className="note-box">
          <div className="section-title">{tr("Forensic fingerprint")}</div>
          <div className="status-line">
            <span>{tr("before sha256")}</span>
            <span className="microcopy">{beforeSha256 || tr("pending")}</span>
          </div>
          <div className="status-line">
            <span>{tr("after sha256")}</span>
            <span className="microcopy">{afterSha256 || tr("pending")}</span>
          </div>
          <div className="status-line">
            <span>{tr("match")}</span>
            <Chip
              label={beforeSha256 && afterSha256 ? (beforeSha256 === afterSha256 ? tr("unchanged") : tr("changed")) : tr("pending")}
              tone={beforeSha256 && afterSha256 ? (beforeSha256 === afterSha256 ? "muted" : "accent") : "muted"}
            />
          </div>
        </div>
        <div className="grid-two">
          <div>
            <div className="section-title">{tr("Previews")}</div>
            <div className="grid-two">
              <div className="note-box">
                <div className="microcopy">{tr("Before")}</div>
                {beforePreview ? (
                  <img src={beforePreview} alt="Before preview" className="image-preview" />
                ) : (
                  <div className="microcopy">{tr("no file")}</div>
                )}
              </div>
              <div className="note-box">
                <div className="microcopy">{tr("After (cleaned)")}</div>
                {afterPreview ? (
                  <img src={afterPreview} alt="After preview" className="image-preview" />
                ) : (
                  <div className="microcopy">{tr("not generated")}</div>
                )}
              </div>
            </div>
          </div>
          <div>
            <div className="section-title">{tr("Before cleaning")}</div>
            <table className="table">
              <tbody>
                {beforeFields.length === 0 ? (
                  <tr>
                    <td className="muted" colSpan={2}>
                      {tr("no fields")}
                    </td>
                  </tr>
                ) : (
                  beforeFields.map((field) => (
                    <tr key={field.key}>
                      <td>{field.key}</td>
                      <td>{field.value}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
          <div>
            <div className="section-title">{tr("After cleaning")}</div>
            <table className="table">
              <tbody>
                {afterFields.length === 0 ? (
                  <tr>
                    <td className="muted" colSpan={2}>
                      {tr("stripped (expected minimal metadata after re-encode)")}
                    </td>
                  </tr>
                ) : (
                  afterFields.map((field) => (
                    <tr key={field.key}>
                      <td>{field.key}</td>
                      <td>{field.value}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}

async function renderCleanImage(
  file: File,
  scale: number,
  outputSupport: Record<OutputMime, boolean>,
  outputChoice: OutputChoice,
  quality = 0.92,
): Promise<CleanResult> {
  const url = URL.createObjectURL(file);
  try {
    const img = await loadImage(url);
    const canvas = document.createElement("canvas");
    const clampScale = Math.max(0.1, Math.min(1, scale));
    canvas.width = Math.max(1, Math.round(img.naturalWidth * clampScale));
    canvas.height = Math.max(1, Math.round(img.naturalHeight * clampScale));
    const ctx = canvas.getContext("2d");
    if (!ctx) throw new Error("Canvas unavailable");
    ctx.drawImage(img, 0, 0);
    const preferredMime = outputChoice === "auto" ? chooseExportMime(file.type, outputSupport) : outputChoice;
    const candidates = Array.from(
      new Set<OutputMime>([preferredMime as OutputMime, "image/png", "image/jpeg", "image/webp", "image/avif"]),
    ).filter((mime) => outputSupport[mime]);
    let cleanedBlob: Blob | null = null;
    let outputMime = preferredMime;
    for (const mime of candidates) {
      cleanedBlob = await new Promise<Blob | null>((resolve) => {
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
  } finally {
    URL.revokeObjectURL(url);
  }
}

function loadImage(url: string): Promise<HTMLImageElement> {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => resolve(img);
    img.onerror = () => reject(new Error("Image load failed"));
    img.src = url;
  });
}

async function readImageDimensions(file: File) {
  const url = URL.createObjectURL(file);
  try {
    const img = await loadImage(url);
    return { width: img.naturalWidth, height: img.naturalHeight };
  } finally {
    URL.revokeObjectURL(url);
  }
}

function extensionFromMime(mime: string) {
  if (mime.includes("png")) return "png";
  if (mime.includes("webp")) return "webp";
  if (mime.includes("avif")) return "avif";
  if (mime.includes("gif")) return "gif";
  if (mime.includes("bmp")) return "bmp";
  if (mime.includes("tiff")) return "tiff";
  return "jpg";
}

async function sha256Hex(blob: Blob): Promise<string> {
  const bytes = new Uint8Array(await blob.arrayBuffer());
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Array.from(digest)
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("");
}
