import { type OutputMime, chooseExportMime } from "./imageFormats.js";
import { readMetadataFields } from "./metadataInspector.js";

export interface BrowserImageCleanResult {
  cleanedBlob: Blob;
  removed: string[];
  outputMime: string;
}

export type OutputChoice = OutputMime | "auto";
const MAX_IMAGE_PIXELS = 32_000_000;
const MAX_IMAGE_SIDE = 16_384;
const IMAGE_HEADER_SCAN_BYTES = 256 * 1024;
const JPEG_MAX_SEGMENTS = 128;

export async function sanitizeBrowserImage(
  file: File,
  options: {
    scale?: number;
    outputSupport: Record<OutputMime, boolean>;
    outputChoice?: OutputChoice;
    quality?: number;
  },
): Promise<BrowserImageCleanResult> {
  const clampScale = Math.max(0.1, Math.min(1, options.scale ?? 1));
  await assertEncodedImageCanvasBudget(file, clampScale);
  const url = URL.createObjectURL(file);
  try {
    const img = await loadImage(url);
    const dimensions = assertImageCanvasBudget(img.naturalWidth, img.naturalHeight, clampScale);
    const canvas = document.createElement("canvas");
    canvas.width = dimensions.width;
    canvas.height = dimensions.height;
    const ctx = canvas.getContext("2d");
    if (!ctx) throw new Error("Canvas unavailable");
    ctx.drawImage(img, 0, 0);

    const preferredMime = options.outputChoice === "auto" || !options.outputChoice
      ? chooseExportMime(file.type, options.outputSupport)
      : options.outputChoice;
    const quality = Math.max(0.5, Math.min(1, options.quality ?? 0.92));
    const candidates = Array.from(new Set<OutputMime>([preferredMime as OutputMime, "image/png", "image/jpeg", "image/webp"]))
      .filter((mime) => options.outputSupport[mime]);

    let cleanedBlob: Blob | null = null;
    let outputMime = preferredMime;
    for (const mime of candidates) {
      cleanedBlob = await new Promise<Blob | null>((resolve) => {
        const codecQuality = mime === "image/png" ? undefined : quality;
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

export function assertImageCanvasBudget(width: number, height: number, scale = 1) {
  if (!Number.isFinite(width) || !Number.isFinite(height) || width <= 0 || height <= 0) {
    throw new Error("Invalid decoded image dimensions");
  }
  if (width > MAX_IMAGE_SIDE || height > MAX_IMAGE_SIDE || width * height > MAX_IMAGE_PIXELS) {
    throw new Error("Decoded image dimensions exceed NullID canvas safety limits");
  }
  const scaledWidth = Math.max(1, Math.round(width * scale));
  const scaledHeight = Math.max(1, Math.round(height * scale));
  if (scaledWidth > MAX_IMAGE_SIDE || scaledHeight > MAX_IMAGE_SIDE || scaledWidth * scaledHeight > MAX_IMAGE_PIXELS) {
    throw new Error("Decoded image dimensions exceed NullID canvas safety limits after scaling");
  }
  return { width: scaledWidth, height: scaledHeight };
}

export async function assertEncodedImageCanvasBudget(file: Blob, scale = 1) {
  const head = new Uint8Array(await file.slice(0, IMAGE_HEADER_SCAN_BYTES).arrayBuffer());
  const dimensions = parseEncodedImageDimensions(head, file.type);
  if (!dimensions) {
    throw new Error("Unsupported or unresolved encoded image dimensions; browser decode blocked by NullID canvas safety limits");
  }
  return assertImageCanvasBudget(dimensions.width, dimensions.height, scale);
}

export async function readBrowserImageDimensions(file: Blob, scale = 1) {
  await assertEncodedImageCanvasBudget(file, scale);
  const url = URL.createObjectURL(file);
  try {
    const img = await loadImage(url);
    return assertImageCanvasBudget(img.naturalWidth, img.naturalHeight, scale);
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

function parseEncodedImageDimensions(bytes: Uint8Array, mimeType = ""): { width: number; height: number } | null {
  if (bytes.byteLength >= 24 && hasSignature(bytes, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) {
    return {
      width: readUint32BE(bytes, 16),
      height: readUint32BE(bytes, 20),
    };
  }
  if (bytes.byteLength >= 10 && asciiAt(bytes, 0, "GIF87a") || bytes.byteLength >= 10 && asciiAt(bytes, 0, "GIF89a")) {
    return {
      width: readUint16LE(bytes, 6),
      height: readUint16LE(bytes, 8),
    };
  }
  if (bytes.byteLength >= 20 && asciiAt(bytes, 0, "RIFF") && asciiAt(bytes, 8, "WEBP")) {
    if (asciiAt(bytes, 12, "VP8X") && bytes.byteLength >= 30) {
      return {
        width: readUint24LE(bytes, 24) + 1,
        height: readUint24LE(bytes, 27) + 1,
      };
    }
    if (asciiAt(bytes, 12, "VP8 ") && bytes.byteLength >= 30 && bytes[23] === 0x9d && bytes[24] === 0x01 && bytes[25] === 0x2a) {
      return {
        width: readUint16LE(bytes, 26) & 0x3fff,
        height: readUint16LE(bytes, 28) & 0x3fff,
      };
    }
    if (asciiAt(bytes, 12, "VP8L") && bytes.byteLength >= 25 && readUint32LE(bytes, 16) >= 5 && bytes[20] === 0x2f) {
      const packed = bytes[21] | (bytes[22] << 8) | (bytes[23] << 16) | (bytes[24] << 24);
      return {
        width: (packed & 0x3fff) + 1,
        height: ((packed >>> 14) & 0x3fff) + 1,
      };
    }
  }
  if (bytes.byteLength >= 26 && asciiAt(bytes, 0, "BM")) {
    return {
      width: Math.abs(readInt32LE(bytes, 18)),
      height: Math.abs(readInt32LE(bytes, 22)),
    };
  }
  if (bytes.byteLength >= 2 && bytes[0] === 0xff && bytes[1] === 0xd8) {
    return parseJpegDimensions(bytes);
  }
  if (mimeType.startsWith("image/")) {
    return null;
  }
  return null;
}

function parseJpegDimensions(bytes: Uint8Array): { width: number; height: number } | null {
  if (bytes.byteLength < 4 || bytes[0] !== 0xff || bytes[1] !== 0xd8) return null;
  let offset = 2;
  let segments = 0;
  while (offset + 9 < bytes.byteLength) {
    if (bytes[offset] !== 0xff) {
      offset += 1;
      continue;
    }
    while (bytes[offset] === 0xff) offset += 1;
    const marker = bytes[offset];
    offset += 1;
    if (marker === 0xd9 || marker === 0xda) return null;
    if (marker >= 0xd0 && marker <= 0xd7) continue;
    segments += 1;
    if (segments > JPEG_MAX_SEGMENTS) return null;
    if (offset + 2 > bytes.byteLength) return null;
    const length = readUint16BE(bytes, offset);
    if (length < 2 || offset + length > bytes.byteLength) return null;
    if (isJpegStartOfFrame(marker) && length >= 7) {
      return {
        height: readUint16BE(bytes, offset + 3),
        width: readUint16BE(bytes, offset + 5),
      };
    }
    offset += length;
  }
  return null;
}

function isJpegStartOfFrame(marker: number) {
  return (
    marker >= 0xc0
    && marker <= 0xcf
    && marker !== 0xc4
    && marker !== 0xc8
    && marker !== 0xcc
  );
}

function hasSignature(bytes: Uint8Array, signature: number[]) {
  return signature.every((byte, index) => bytes[index] === byte);
}

function asciiAt(bytes: Uint8Array, offset: number, value: string) {
  if (offset + value.length > bytes.byteLength) return false;
  for (let index = 0; index < value.length; index += 1) {
    if (bytes[offset + index] !== value.charCodeAt(index)) return false;
  }
  return true;
}

function readUint16BE(bytes: Uint8Array, offset: number) {
  return (bytes[offset] << 8) | bytes[offset + 1];
}

function readUint16LE(bytes: Uint8Array, offset: number) {
  return bytes[offset] | (bytes[offset + 1] << 8);
}

function readUint24LE(bytes: Uint8Array, offset: number) {
  return bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16);
}

function readUint32BE(bytes: Uint8Array, offset: number) {
  return ((bytes[offset] * 0x1000000) + ((bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3])) >>> 0;
}

function readUint32LE(bytes: Uint8Array, offset: number) {
  return (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0;
}

function readInt32LE(bytes: Uint8Array, offset: number) {
  const value = bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24);
  return value | 0;
}
