export type OutputMime = "image/png" | "image/jpeg" | "image/webp" | "image/avif";

export type SupportState = "yes" | "no" | "unknown" | "n/a";

export interface ImageFormatDiagnostic {
  key: string;
  label: string;
  mime: string;
  decode: SupportState;
  encode: SupportState;
  cleanExport: SupportState;
  note?: string;
}

export interface ImageFormatDiagnostics {
  outputSupport: Record<OutputMime, boolean>;
  rows: ImageFormatDiagnostic[];
}

const outputMimes: OutputMime[] = ["image/png", "image/jpeg", "image/webp", "image/avif"];

const formatRows: { key: string; label: string; mime: string; note?: string }[] = [
  { key: "jpeg", label: "JPEG", mime: "image/jpeg" },
  { key: "png", label: "PNG", mime: "image/png" },
  { key: "webp", label: "WebP", mime: "image/webp" },
  { key: "avif", label: "AVIF", mime: "image/avif" },
  { key: "gif", label: "GIF", mime: "image/gif", note: "animated GIFs are flattened to one frame on clean export" },
  { key: "bmp", label: "BMP", mime: "image/bmp" },
  { key: "tiff", label: "TIFF", mime: "image/tiff" },
  { key: "heic", label: "HEIC/HEIF", mime: "image/heic", note: "often unsupported in browser decode pipelines" },
];

export async function probeCanvasEncodeSupport(): Promise<Record<OutputMime, boolean>> {
  const checks = await Promise.all(outputMimes.map(async (mime) => [mime, await canEncodeMime(mime)] as const));
  return Object.fromEntries(checks) as Record<OutputMime, boolean>;
}

export async function probeImageFormatDiagnostics(): Promise<ImageFormatDiagnostics> {
  const outputSupport = await probeCanvasEncodeSupport();
  const fallbackClean = outputSupport["image/png"] || outputSupport["image/jpeg"];
  const rows = await Promise.all(
    formatRows.map(async (format) => {
      const decodeProbe = await probeDecodeSupport(format.mime);
      const decode = normalizeDecodeState(format.mime, decodeProbe);
      const encode = format.mime in outputSupport ? (outputSupport[format.mime as OutputMime] ? "yes" : "no") : "n/a";
      const cleanExport: SupportState = decode === "no" ? "no" : fallbackClean ? "yes" : "no";
      return {
        ...format,
        decode,
        encode: encode as SupportState,
        cleanExport,
      };
    }),
  );
  return { outputSupport, rows };
}

export function chooseExportMime(inputMime: string, outputSupport: Record<OutputMime, boolean>) {
  const normalized = (inputMime || "").toLowerCase();
  if (normalized === "image/png" && outputSupport["image/png"]) return "image/png";
  if (normalized === "image/webp" && outputSupport["image/webp"]) return "image/webp";
  if (normalized === "image/avif" && outputSupport["image/avif"]) return "image/avif";
  if (normalized === "image/jpeg" && outputSupport["image/jpeg"]) return "image/jpeg";
  if (outputSupport["image/png"]) return "image/png";
  if (outputSupport["image/jpeg"]) return "image/jpeg";
  if (outputSupport["image/webp"]) return "image/webp";
  if (outputSupport["image/avif"]) return "image/avif";
  return "image/png";
}

function normalizeDecodeState(mime: string, raw: boolean | null): SupportState {
  if (raw === true) return "yes";
  if (raw === false) return "no";
  if (mime === "image/png" || mime === "image/jpeg" || mime === "image/gif" || mime === "image/bmp") return "yes";
  if (mime === "image/heic") return "no";
  return "unknown";
}

async function probeDecodeSupport(mime: string): Promise<boolean | null> {
  const decoder = (globalThis as unknown as { ImageDecoder?: { isTypeSupported?: (type: string) => Promise<boolean> } }).ImageDecoder;
  if (!decoder?.isTypeSupported) {
    return null;
  }
  try {
    return await decoder.isTypeSupported(mime);
  } catch {
    return null;
  }
}

async function canEncodeMime(mime: OutputMime): Promise<boolean> {
  const canvas = document.createElement("canvas");
  canvas.width = 2;
  canvas.height = 2;
  const ctx = canvas.getContext("2d");
  if (!ctx) return false;
  ctx.fillStyle = "#202020";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  const blob = await new Promise<Blob | null>((resolve) => {
    canvas.toBlob((value) => resolve(value), mime, 0.9);
  });
  return Boolean(blob && blob.type === mime);
}
