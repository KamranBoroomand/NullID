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

type MetaField = { key: string; value: string };

interface CleanResult {
  cleanedBlob: Blob;
  removed: string[];
  outputMime: string;
}

interface MetaViewProps {
  onOpenGuide?: (key?: ModuleKey) => void;
}

export function MetaView({ onOpenGuide }: MetaViewProps) {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [fileName, setFileName] = useState("none");
  const [beforeFields, setBeforeFields] = useState<MetaField[]>([]);
  const [afterFields, setAfterFields] = useState<MetaField[]>([]);
  const [removedFields, setRemovedFields] = useState<string[]>([]);
  const [message, setMessage] = useState("drop an image to inspect metadata");
  const [cleanBlob, setCleanBlob] = useState<Blob | null>(null);
  const [unsupportedReason, setUnsupportedReason] = useState<string | null>(null);
  const [resizePercent, setResizePercent] = useState(100);
  const [beforePreview, setBeforePreview] = useState<string | null>(null);
  const [afterPreview, setAfterPreview] = useState<string | null>(null);
  const [formatRows, setFormatRows] = useState<ImageFormatDiagnostic[]>([]);
  const [outputSupport, setOutputSupport] = useState<Record<OutputMime, boolean> | null>(null);

  const handleFile = useCallback(
    async (file?: File | null) => {
      if (!file) return;
      setUnsupportedReason(null);
      setFileName(file.name);
      setBeforeFields([]);
      setAfterFields([]);
      setRemovedFields([]);
      setCleanBlob(null);
      if (beforePreview) URL.revokeObjectURL(beforePreview);
      if (afterPreview) URL.revokeObjectURL(afterPreview);
      setBeforePreview(URL.createObjectURL(file));
      setAfterPreview(null);
      setMessage("reading…");

      if (!file.type.startsWith("image/")) {
        setMessage("Only images supported for EXIF.");
        setUnsupportedReason("Unsupported file type for metadata cleaning.");
        return;
      }
      const format = detectImageFormat(file.type, new Uint8Array(await file.slice(0, 64).arrayBuffer()));
      if (format === "heic") {
        setMessage("HEIC/HEIF parsing is usually blocked in browser decode pipelines.");
        setUnsupportedReason("Convert HEIC/HEIF to JPEG/PNG/AVIF before cleaning.");
        return;
      }

      try {
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

        const supportedOutput = outputSupport ?? (await probeCanvasEncodeSupport());
        if (!outputSupport) setOutputSupport(supportedOutput);
        const cleaned = await renderCleanImage(file, resizePercent / 100, supportedOutput);
        const afterMeta = await readMetadataFields(cleaned.cleanedBlob);
        setCleanBlob(cleaned.cleanedBlob);
        if (afterPreview) URL.revokeObjectURL(afterPreview);
        setAfterPreview(URL.createObjectURL(cleaned.cleanedBlob));
        setAfterFields([{ key: "type", value: cleaned.cleanedBlob.type }, { key: "exportMime", value: cleaned.outputMime }, ...afterMeta]);
        setRemovedFields(cleaned.removed);
      } catch (error) {
        console.error(error);
        const detail = error instanceof Error ? error.message : "Failed to parse image metadata.";
        setMessage(detail);
        setUnsupportedReason("Browser could not decode this image format.");
      }
    },
    [afterPreview, beforePreview, outputSupport, resizePercent],
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

  return (
    <div className="workspace-scroll">
      <div className="guide-link">
        <button type="button" className="guide-link-button" onClick={() => onOpenGuide?.("meta")}>
          ? guide
        </button>
      </div>
      <div className="grid-two">
        <div className="panel" aria-label="Metadata input">
          <div className="panel-heading">
            <span>Metadata Inspector</span>
            <span className="panel-subtext">drop image</span>
          </div>
          <div
            className="dropzone"
            role="button"
            tabIndex={0}
            aria-label="Drop file for inspection"
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
            <div className="section-title">drag image</div>
            <div className="microcopy">jpeg / png / webp / avif / gif / bmp / tiff</div>
          </div>
          <div className="status-line">
            <span>file</span>
            <Chip label={fileName} tone="muted" />
            <Chip label={message} tone="accent" />
          </div>
        </div>
        <div className="panel" aria-label="Clean export">
          <div className="panel-heading">
            <span>Clean export</span>
            <span className="panel-subtext">strip EXIF</span>
          </div>
          <p className="microcopy">
            Images are re-encoded via canvas to drop metadata. Compatibility diagnostics below show decode and export readiness by format.
          </p>
          <div className="controls-row">
            <label className="section-title" htmlFor="resize-percent">
              Strip + resize
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
          </div>
          <div className="controls-row">
            <button
              className="button"
              type="button"
              onClick={() => void saveClean()}
              disabled={!cleanBlob || Boolean(unsupportedReason)}
              aria-label="Download cleaned image"
            >
              download clean
            </button>
            {unsupportedReason ? <Chip label="unsupported" tone="danger" /> : <Chip label="ready" tone="accent" />}
          </div>
          <div className="status-line">
            <span>removed</span>
            <span className="microcopy">{removedList || "none"}</span>
          </div>
          <div className="section-title">Compatibility diagnostics</div>
          <table className="table">
            <thead>
              <tr>
                <th>format</th>
                <th>decode</th>
                <th>encode</th>
                <th>clean export</th>
              </tr>
            </thead>
            <tbody>
              {formatRows.length === 0 ? (
                <tr>
                  <td colSpan={4} className="muted">
                    probing browser support...
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
      <div className="panel" aria-label="Metadata table">
        <div className="panel-heading">
          <span>Fields</span>
          <span className="panel-subtext">before / after</span>
        </div>
        <div className="grid-two">
          <div>
            <div className="section-title">Previews</div>
            <div className="grid-two">
              <div className="note-box">
                <div className="microcopy">Before</div>
                {beforePreview ? (
                  <img src={beforePreview} alt="Before preview" className="image-preview" />
                ) : (
                  <div className="microcopy">no file</div>
                )}
              </div>
              <div className="note-box">
                <div className="microcopy">After (cleaned)</div>
                {afterPreview ? (
                  <img src={afterPreview} alt="After preview" className="image-preview" />
                ) : (
                  <div className="microcopy">not generated</div>
                )}
              </div>
            </div>
          </div>
          <div>
            <div className="section-title">Before cleaning</div>
            <table className="table">
              <tbody>
                {beforeFields.length === 0 ? (
                  <tr>
                    <td className="muted" colSpan={2}>
                      no fields
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
            <div className="section-title">After cleaning</div>
            <table className="table">
              <tbody>
                {afterFields.length === 0 ? (
                  <tr>
                    <td className="muted" colSpan={2}>
                      stripped (expected minimal metadata after re-encode)
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
    const preferredMime = chooseExportMime(file.type, outputSupport);
    const candidates = Array.from(
      new Set<OutputMime>([preferredMime as OutputMime, "image/png", "image/jpeg", "image/webp", "image/avif"]),
    ).filter((mime) => outputSupport[mime]);
    let cleanedBlob: Blob | null = null;
    let outputMime = preferredMime;
    for (const mime of candidates) {
      cleanedBlob = await new Promise<Blob | null>((resolve) => {
        canvas.toBlob((blob) => resolve(blob), mime, 0.92);
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
