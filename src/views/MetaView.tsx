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
        const baseFields = await readMetadata(file);
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
        const afterMeta = await readMetadata(cleaned.cleanedBlob);
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

type ParsedEntry = { tag: number; value: string | number | number[] };
type ImageFormat = "jpeg" | "png" | "webp" | "avif" | "gif" | "bmp" | "tiff" | "heic" | "unknown";

async function readMetadata(file: File | Blob): Promise<MetaField[]> {
  const buffer = new Uint8Array(await file.arrayBuffer());
  const mime = file instanceof File ? file.type : (file as Blob).type;
  const format = detectImageFormat(mime, buffer);
  const fields: MetaField[] = [];
  const metadata = (() => {
    if (format === "jpeg") return parseExif(buffer);
    if (format === "tiff") return parseTiff(buffer);
    if (format === "png") return parsePngMetadata(buffer);
    if (format === "webp") return parseWebpMetadata(buffer);
    if (format === "gif") return parseGifMetadata(buffer);
    return {};
  })();
  Object.entries(metadata).forEach(([key, value]) => fields.push({ key, value }));
  return fields.slice(0, 60);
}

function detectImageFormat(mime: string, bytes: Uint8Array): ImageFormat {
  const normalized = (mime || "").toLowerCase();
  if (normalized.includes("jpeg") || normalized.includes("jpg")) return "jpeg";
  if (normalized.includes("png")) return "png";
  if (normalized.includes("webp")) return "webp";
  if (normalized.includes("avif")) return "avif";
  if (normalized.includes("gif")) return "gif";
  if (normalized.includes("bmp")) return "bmp";
  if (normalized.includes("tiff")) return "tiff";
  if (normalized.includes("heic") || normalized.includes("heif")) return "heic";
  if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return "jpeg";
  if (isPngSignature(bytes)) return "png";
  if (bytes.length >= 12 && getAscii(bytes, 0, 4) === "RIFF" && getAscii(bytes, 8, 4) === "WEBP") return "webp";
  if (bytes.length >= 6 && /^GIF8/.test(getAscii(bytes, 0, 6))) return "gif";
  if (bytes.length >= 2 && getAscii(bytes, 0, 2) === "BM") return "bmp";
  if (bytes.length >= 4 && (getAscii(bytes, 0, 4) === "II*\u0000" || getAscii(bytes, 0, 4) === "MM\u0000*")) return "tiff";
  return "unknown";
}

function parseExif(bytes: Uint8Array): Record<string, string> {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.byteLength < 4 || view.getUint16(0) !== 0xffd8) return {};
  let offset = 2;
  const result: Record<string, string> = {};
  let gpsOffset: number | null = null;
  while (offset < view.byteLength) {
    if (offset + 4 > view.byteLength) break;
    if (view.getUint8(offset) !== 0xff) break;
    const marker = view.getUint8(offset + 1);
    const length = view.getUint16(offset + 2);
    if (length < 2) break;
    if (marker === 0xe1) {
      const header = getAscii(bytes, offset + 4, 6);
      if (header === "Exif\u0000\u0000") {
        const tiffStart = offset + 10;
        Object.assign(result, parseTiff(view, tiffStart));
        const little = getAscii(bytes, tiffStart, 2) === "II";
        if (tiffStart + 8 <= view.byteLength) {
          const ifdOffset = view.getUint32(tiffStart + 4, little);
          const tags = readIfd(view, tiffStart + ifdOffset, little, tiffStart);
          tags.forEach(({ tag, value }) => {
            if (tag === 0x8825 && typeof value === "number") {
              gpsOffset = tiffStart + value;
            }
          });
        }
        if (gpsOffset) {
          const gpsTags = readIfd(view, gpsOffset, little, tiffStart);
          const gps = buildGps(gpsTags);
          if (gps) result.gps = gps;
        }
      }
    }
    if (marker === 0xda) break;
    offset += 2 + length;
  }
  return result;
}

function parseTiff(bytesOrView: Uint8Array | DataView, offset = 0): Record<string, string> {
  const view =
    bytesOrView instanceof DataView
      ? bytesOrView
      : new DataView(bytesOrView.buffer, bytesOrView.byteOffset, bytesOrView.byteLength);
  if (offset + 8 > view.byteLength) return {};
  const endian = getAsciiFromView(view, offset, 2);
  if (endian !== "II" && endian !== "MM") return {};
  const little = endian === "II";
  const magic = view.getUint16(offset + 2, little);
  if (magic !== 42) return {};
  const ifdOffset = view.getUint32(offset + 4, little);
  const result: Record<string, string> = {};
  const tags = readIfd(view, offset + ifdOffset, little, offset);
  tags.forEach(({ tag, value }) => {
    const label = tagNames[tag];
    if (label) result[label] = String(value);
  });
  return result;
}

function parsePngMetadata(bytes: Uint8Array): Record<string, string> {
  if (!isPngSignature(bytes)) return {};
  const result: Record<string, string> = {};
  const textKeys: string[] = [];
  let offset = 8;
  while (offset + 8 <= bytes.length) {
    const length = readUint32BE(bytes, offset);
    const type = getAscii(bytes, offset + 4, 4);
    const dataStart = offset + 8;
    const dataEnd = dataStart + length;
    if (dataEnd + 4 > bytes.length) break;
    if (type === "tEXt" || type === "iTXt" || type === "zTXt") {
      const nul = bytes.indexOf(0, dataStart);
      if (nul > dataStart && nul < dataEnd) {
        textKeys.push(getAscii(bytes, dataStart, Math.min(48, nul - dataStart)));
      }
    } else if (type === "eXIf") {
      result.exifChunk = `${length} bytes`;
      const exif = parseTiff(bytes.slice(dataStart, dataEnd));
      Object.entries(exif).forEach(([key, value]) => {
        if (!result[key]) result[key] = value;
      });
    } else if (type === "iCCP") {
      result.iccProfile = "present";
    } else if (type === "pHYs" && length >= 9) {
      const x = readUint32BE(bytes, dataStart);
      const y = readUint32BE(bytes, dataStart + 4);
      result.pixelDensity = `${x}x${y}`;
    } else if (type === "tIME" && length >= 7) {
      const year = (bytes[dataStart] << 8) + bytes[dataStart + 1];
      const month = bytes[dataStart + 2];
      const day = bytes[dataStart + 3];
      result.timestamp = `${year}-${String(month).padStart(2, "0")}-${String(day).padStart(2, "0")}`;
    }
    offset = dataEnd + 4;
    if (type === "IEND") break;
  }
  if (textKeys.length) {
    result.textKeys = textKeys.slice(0, 8).join(", ");
  }
  return result;
}

function isPngSignature(bytes: Uint8Array) {
  return (
    bytes.length >= 8 &&
    bytes[0] === 0x89 &&
    bytes[1] === 0x50 &&
    bytes[2] === 0x4e &&
    bytes[3] === 0x47 &&
    bytes[4] === 0x0d &&
    bytes[5] === 0x0a &&
    bytes[6] === 0x1a &&
    bytes[7] === 0x0a
  );
}

function parseWebpMetadata(bytes: Uint8Array): Record<string, string> {
  if (bytes.length < 12 || getAscii(bytes, 0, 4) !== "RIFF" || getAscii(bytes, 8, 4) !== "WEBP") return {};
  const result: Record<string, string> = {};
  const chunkNames: string[] = [];
  let offset = 12;
  while (offset + 8 <= bytes.length) {
    const type = getAscii(bytes, offset, 4);
    const size = readUint32LE(bytes, offset + 4);
    const dataStart = offset + 8;
    const dataEnd = dataStart + size;
    if (dataEnd > bytes.length) break;
    chunkNames.push(type.trim() || type);
    if (type === "EXIF") {
      result.exifChunk = `${size} bytes`;
      let exifPayload = bytes.slice(dataStart, dataEnd);
      if (exifPayload.length >= 6 && getAscii(exifPayload, 0, 6) === "Exif\u0000\u0000") {
        exifPayload = exifPayload.slice(6);
      }
      const exif = parseTiff(exifPayload);
      Object.entries(exif).forEach(([key, value]) => {
        if (!result[key]) result[key] = value;
      });
    }
    if (type === "XMP ") result.xmp = "present";
    if (type === "ICCP") result.iccProfile = "present";
    if (type === "ANIM") result.animated = "yes";
    offset = dataEnd + (size % 2);
  }
  if (chunkNames.length) {
    result.webpChunks = chunkNames.slice(0, 10).join(", ");
  }
  return result;
}

function parseGifMetadata(bytes: Uint8Array): Record<string, string> {
  if (bytes.length < 6 || !/^GIF8/.test(getAscii(bytes, 0, 6))) return {};
  let comments = 0;
  let applications = 0;
  for (let i = 0; i < bytes.length - 1; i += 1) {
    if (bytes[i] === 0x21 && bytes[i + 1] === 0xfe) comments += 1;
    if (bytes[i] === 0x21 && bytes[i + 1] === 0xff) applications += 1;
  }
  const result: Record<string, string> = {
    commentBlocks: String(comments),
  };
  if (applications > 0) {
    result.applicationBlocks = String(applications);
  }
  return result;
}

function readIfd(view: DataView, offset: number, little: boolean, start: number): ParsedEntry[] {
  if (offset < 0 || offset + 2 > view.byteLength) return [];
  const count = view.getUint16(offset, little);
  const entries: ParsedEntry[] = [];
  for (let i = 0; i < count; i += 1) {
    const entryOffset = offset + 2 + i * 12;
    if (entryOffset + 12 > view.byteLength) break;
    const tag = view.getUint16(entryOffset, little);
    const type = view.getUint16(entryOffset + 2, little);
    const itemCount = view.getUint32(entryOffset + 4, little);
    const valueOffset = view.getUint32(entryOffset + 8, little);
    const size = typeSize[type] ?? 1;
    const totalSize = size * itemCount;
    const valuePos = totalSize <= 4 ? entryOffset + 8 : start + valueOffset;
    if (valuePos < 0 || valuePos + Math.max(1, totalSize) > view.byteLength) continue;
    let value: string | number | number[] = "";
    if (type === 2) {
      value = getAsciiFromView(view, valuePos, itemCount).replace(/\u0000+$/, "");
    } else if (type === 3) {
      value = view.getUint16(valuePos, little);
    } else if (type === 4) {
      value = view.getUint32(valuePos, little);
    } else if (type === 5) {
      const values: number[] = [];
      for (let item = 0; item < itemCount; item += 1) {
        const base = valuePos + item * 8;
        if (base + 8 > view.byteLength) break;
        const num = view.getUint32(base, little);
        const den = view.getUint32(base + 4, little) || 1;
        values.push(Math.round((num / den) * 1000) / 1000);
      }
      value = itemCount === 1 ? values[0] ?? 0 : values;
    }
    entries.push({ tag, value });
  }
  return entries;
}

function getAscii(bytes: Uint8Array, offset: number, length: number) {
  const slice = bytes.slice(offset, offset + length);
  return new TextDecoder().decode(slice);
}

function getAsciiFromView(view: DataView, offset: number, length: number) {
  return getAscii(new Uint8Array(view.buffer, view.byteOffset, view.byteLength), offset, length);
}

function readUint32BE(bytes: Uint8Array, offset: number) {
  return (((bytes[offset] << 24) >>> 0) + (bytes[offset + 1] << 16) + (bytes[offset + 2] << 8) + bytes[offset + 3]) >>> 0;
}

function readUint32LE(bytes: Uint8Array, offset: number) {
  return (bytes[offset] + (bytes[offset + 1] << 8) + (bytes[offset + 2] << 16) + ((bytes[offset + 3] << 24) >>> 0)) >>> 0;
}

const tagNames: Record<number, string> = {
  0x010f: "make",
  0x0110: "model",
  0x0112: "orientation",
  0x0132: "datetime",
  0x9003: "captured",
  0x829a: "exposureTime",
  0x829d: "fNumber",
  0x8827: "iso",
  0x920a: "focalLength",
  0x8825: "gpsInfo",
};

const typeSize: Record<number, number> = {
  1: 1, // BYTE
  2: 1, // ASCII
  3: 2, // SHORT
  4: 4, // LONG
  5: 8, // RATIONAL
};

function buildGps(entries: { tag: number; value: string | number | number[] }[]) {
  const map: Record<number, string | number | number[]> = {};
  entries.forEach((entry) => {
    map[entry.tag] = entry.value;
  });
  const latRef = typeof map[0x0001] === "string" ? (map[0x0001] as string) : undefined;
  const lat = map[0x0002];
  const lonRef = typeof map[0x0003] === "string" ? (map[0x0003] as string) : undefined;
  const lon = map[0x0004];
  const latVal = Array.isArray(lat) ? dmsToDecimal(lat, latRef === "S") : typeof lat === "number" ? lat : null;
  const lonVal = Array.isArray(lon) ? dmsToDecimal(lon, lonRef === "W") : typeof lon === "number" ? lon : null;
  if (latVal != null && lonVal != null) {
    return `${latVal.toFixed(6)}, ${lonVal.toFixed(6)}`;
  }
  return null;
}

function dmsToDecimal(values: number[], negative: boolean | undefined) {
  const [deg = 0, min = 0, sec = 0] = values;
  const decimal = deg + min / 60 + sec / 3600;
  return negative ? -decimal : decimal;
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
    const before = await readMetadata(file);
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
