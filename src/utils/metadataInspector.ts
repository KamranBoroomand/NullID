export type MetadataField = { key: string; value: string };
export type ImageFormat = "jpeg" | "png" | "webp" | "avif" | "gif" | "bmp" | "tiff" | "heic" | "unknown";

type ParsedEntry = { tag: number; value: string | number | number[] };

const MAX_FIELDS = 60;
const MAX_TIFF_IFD_ENTRIES = 1024;
const MAX_TIFF_IFD_VALUES = 64;
const MAX_TIFF_VALUE_BYTES = 1024 * 1024;
const MAX_TIFF_SECTIONS = 24;
const MAX_PNG_CHUNKS = 512;
const MAX_WEBP_CHUNKS = 256;
const MAX_ASCII_BYTES = 256;
const MAX_BINARY_PREVIEW_BYTES = 12;
const asciiDecoder = new TextDecoder();

const POINTER_TAGS = new Set([0x8769, 0x8825, 0xa005, 0x014a]);
const FALLBACK_VENDOR_TAGS = new Set([0x927c, 0xa430, 0xa431, 0xa434, 0xa435]);

export async function readMetadataFields(file: File | Blob): Promise<MetadataField[]> {
  const buffer = new Uint8Array(await file.arrayBuffer());
  const mime = file.type || "";
  const metadata = inspectMetadataFromBuffer(mime, buffer);
  return Object.entries(metadata)
    .slice(0, MAX_FIELDS)
    .map(([key, value]) => ({ key, value }));
}

export function inspectMetadataFromBuffer(mime: string, bytes: Uint8Array): Record<string, string> {
  const format = detectImageFormat(mime, bytes);
  if (format === "jpeg") return parseExif(bytes);
  if (format === "tiff") return parseTiff(bytes);
  if (format === "png") return parsePngMetadata(bytes);
  if (format === "webp") return parseWebpMetadata(bytes);
  if (format === "gif") return parseGifMetadata(bytes);
  return {};
}

export function detectImageFormat(mime: string, bytes: Uint8Array, fileName = ""): ImageFormat {
  const normalized = (mime || "").toLowerCase();
  const normalizedName = fileName.toLowerCase();
  if (normalized.includes("jpeg") || normalized.includes("jpg")) return "jpeg";
  if (normalized.includes("png")) return "png";
  if (normalized.includes("webp")) return "webp";
  if (normalized.includes("avif")) return "avif";
  if (normalized.includes("gif")) return "gif";
  if (normalized.includes("bmp")) return "bmp";
  if (normalized.includes("tiff")) return "tiff";
  if (normalized.includes("heic") || normalized.includes("heif")) return "heic";
  if (/\.(jpe?g)$/i.test(normalizedName)) return "jpeg";
  if (normalizedName.endsWith(".png")) return "png";
  if (normalizedName.endsWith(".webp")) return "webp";
  if (normalizedName.endsWith(".avif")) return "avif";
  if (normalizedName.endsWith(".gif")) return "gif";
  if (normalizedName.endsWith(".bmp")) return "bmp";
  if (normalizedName.endsWith(".tif") || normalizedName.endsWith(".tiff")) return "tiff";
  if (normalizedName.endsWith(".heic") || normalizedName.endsWith(".heif")) return "heic";
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

  const result: Record<string, string> = {};
  let offset = 2;

  while (offset + 1 < view.byteLength) {
    if (view.getUint8(offset) !== 0xff) {
      offset += 1;
      continue;
    }

    const marker = view.getUint8(offset + 1);
    if (marker === 0xd9 || marker === 0xda) break;

    if (marker === 0x00 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
      offset += 2;
      continue;
    }

    if (offset + 4 > view.byteLength) break;
    const length = view.getUint16(offset + 2);
    if (length < 2) break;

    const segmentEnd = safeAdd(offset, 2 + length);
    if (segmentEnd == null || segmentEnd <= offset || segmentEnd > view.byteLength) break;

    if (marker === 0xe1 && length >= 8) {
      const header = getAscii(bytes, offset + 4, 6);
      if (header === "Exif\u0000\u0000") {
        const tiffStart = offset + 10;
        const parsed = parseTiff(view, tiffStart);
        Object.entries(parsed).forEach(([key, value]) => {
          if (!result[key]) result[key] = value;
        });
      }
    }

    offset = segmentEnd;
  }

  return result;
}

function parseTiff(bytesOrView: Uint8Array | DataView, offset = 0): Record<string, string> {
  const view =
    bytesOrView instanceof DataView
      ? bytesOrView
      : new DataView(bytesOrView.buffer, bytesOrView.byteOffset, bytesOrView.byteLength);
  if (!isValidRange(view, offset, 8)) return {};

  const endian = getAsciiFromView(view, offset, 2);
  if (endian !== "II" && endian !== "MM") return {};
  const little = endian === "II";

  const magic = view.getUint16(offset + 2, little);
  if (magic !== 42) return {};

  const firstIfdPointer = view.getUint32(offset + 4, little);
  const firstIfdOffset = safeAdd(offset, firstIfdPointer);
  if (firstIfdOffset == null || !isLikelyIfdOffset(view, firstIfdOffset)) return {};

  const result: Record<string, string> = {};
  const visited = new Set<number>();
  const queue: number[] = [firstIfdOffset];
  const gpsEntries: ParsedEntry[] = [];

  while (queue.length > 0 && visited.size < MAX_TIFF_SECTIONS) {
    const ifdOffset = queue.shift();
    if (ifdOffset == null || visited.has(ifdOffset) || !isLikelyIfdOffset(view, ifdOffset)) continue;

    visited.add(ifdOffset);
    const entries = readIfd(view, ifdOffset, little, offset);

    entries.forEach((entry) => {
      if (POINTER_TAGS.has(entry.tag)) {
        const pointer = entryValueToOffset(entry.value, offset, view.byteLength);
        if (pointer != null && !visited.has(pointer)) {
          queue.push(pointer);
          if (entry.tag === 0x8825) {
            gpsEntries.push(...readIfd(view, pointer, little, offset));
          }
        }
      }

      const label = resolveTagLabel(entry.tag);
      if (!label || POINTER_TAGS.has(entry.tag)) return;
      if (!result[label]) {
        result[label] = stringifyEntryValue(entry.value);
      }
    });

    const nextIfdOffset = readNextIfdOffset(view, ifdOffset, little, offset);
    if (nextIfdOffset != null && !visited.has(nextIfdOffset)) {
      queue.push(nextIfdOffset);
    }
  }

  if (gpsEntries.length > 0) {
    const gps = buildGps(gpsEntries);
    if (gps) result.gps = gps;
  }

  return result;
}

function parsePngMetadata(bytes: Uint8Array): Record<string, string> {
  if (!isPngSignature(bytes)) return {};

  const result: Record<string, string> = {};
  const textKeys: string[] = [];
  const vendorTextKeys: string[] = [];
  let offset = 8;
  let chunkCount = 0;

  while (offset + 8 <= bytes.length && chunkCount < MAX_PNG_CHUNKS) {
    const length = readUint32BE(bytes, offset);
    const type = getAscii(bytes, offset + 4, 4);
    const dataStart = offset + 8;
    const dataEnd = safeAdd(dataStart, length);
    if (dataEnd == null || dataEnd + 4 > bytes.length) break;

    if (type === "tEXt" || type === "iTXt" || type === "zTXt") {
      const key = parsePngTextKey(bytes, dataStart, dataEnd);
      if (key) {
        textKeys.push(key);
        if (isVendorTextKey(key)) {
          vendorTextKeys.push(key);
        }
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

    chunkCount += 1;
    offset = dataEnd + 4;
    if (type === "IEND") break;
  }

  if (textKeys.length) {
    result.textKeys = textKeys.slice(0, 8).join(", ");
  }
  if (vendorTextKeys.length) {
    result.vendorTextKeys = vendorTextKeys.slice(0, 6).join(", ");
  }

  return result;
}

function parseWebpMetadata(bytes: Uint8Array): Record<string, string> {
  if (bytes.length < 12 || getAscii(bytes, 0, 4) !== "RIFF" || getAscii(bytes, 8, 4) !== "WEBP") return {};

  const result: Record<string, string> = {};
  const chunkNames: string[] = [];
  let offset = 12;
  let chunkCount = 0;

  while (offset + 8 <= bytes.length && chunkCount < MAX_WEBP_CHUNKS) {
    const type = getAscii(bytes, offset, 4);
    const size = readUint32LE(bytes, offset + 4);
    const dataStart = offset + 8;
    const dataEnd = safeAdd(dataStart, size);
    if (dataEnd == null || dataEnd > bytes.length) break;

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

    chunkCount += 1;
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
  if (!isLikelyIfdOffset(view, offset)) return [];

  const rawCount = view.getUint16(offset, little);
  const count = Math.min(rawCount, MAX_TIFF_IFD_ENTRIES);
  const entries: ParsedEntry[] = [];

  for (let i = 0; i < count; i += 1) {
    const entryOffset = offset + 2 + i * 12;
    if (!isValidRange(view, entryOffset, 12)) break;

    const tag = view.getUint16(entryOffset, little);
    const type = view.getUint16(entryOffset + 2, little);
    const itemCount = view.getUint32(entryOffset + 4, little);
    const valueOffset = view.getUint32(entryOffset + 8, little);
    const size = typeSize[type];
    if (!size || itemCount === 0) continue;

    const totalSize = size * itemCount;
    if (!Number.isFinite(totalSize) || totalSize <= 0 || totalSize > MAX_TIFF_VALUE_BYTES) continue;

    const valuePos = totalSize <= 4 ? entryOffset + 8 : start + valueOffset;
    if (!isValidRange(view, valuePos, Math.max(1, totalSize))) continue;

    const value = decodeTiffValue(view, type, valuePos, little, itemCount);
    if (value == null) continue;
    entries.push({ tag, value });
  }

  return entries;
}

function decodeTiffValue(
  view: DataView,
  type: number,
  valuePos: number,
  little: boolean,
  rawItemCount: number,
): string | number | number[] | null {
  const count = Math.max(1, Math.min(rawItemCount, MAX_TIFF_IFD_VALUES));

  if (type === 1) {
    const values = readNumberArray(count, 1, (index) => view.getUint8(valuePos + index));
    return count === 1 ? (values[0] ?? 0) : values;
  }
  if (type === 2) {
    const asciiLength = Math.max(1, Math.min(rawItemCount, MAX_ASCII_BYTES));
    const value = getAsciiFromView(view, valuePos, asciiLength).replace(/\u0000+$/, "");
    return sanitizeAscii(value);
  }
  if (type === 3) {
    const values = readNumberArray(count, 2, (index) => view.getUint16(valuePos + index * 2, little));
    return count === 1 ? (values[0] ?? 0) : values;
  }
  if (type === 4) {
    const values = readNumberArray(count, 4, (index) => view.getUint32(valuePos + index * 4, little));
    return count === 1 ? (values[0] ?? 0) : values;
  }
  if (type === 5) {
    const values = readRationals(view, valuePos, little, count, false);
    return count === 1 ? (values[0] ?? 0) : values;
  }
  if (type === 7) {
    const previewLength = Math.max(1, Math.min(rawItemCount, MAX_BINARY_PREVIEW_BYTES));
    const preview = Array.from({ length: previewLength }, (_, index) => view.getUint8(valuePos + index).toString(16).padStart(2, "0")).join("");
    return rawItemCount > previewLength ? `${preview}…` : preview;
  }
  if (type === 9) {
    const values = readNumberArray(count, 4, (index) => view.getInt32(valuePos + index * 4, little));
    return count === 1 ? (values[0] ?? 0) : values;
  }
  if (type === 10) {
    const values = readRationals(view, valuePos, little, count, true);
    return count === 1 ? (values[0] ?? 0) : values;
  }
  return null;
}

function readRationals(view: DataView, baseOffset: number, little: boolean, count: number, signed: boolean): number[] {
  const values: number[] = [];
  for (let index = 0; index < count; index += 1) {
    const base = baseOffset + index * 8;
    if (!isValidRange(view, base, 8)) break;
    const numerator = signed ? view.getInt32(base, little) : view.getUint32(base, little);
    const denominator = signed ? view.getInt32(base + 4, little) : view.getUint32(base + 4, little);
    const safeDenominator = denominator === 0 ? 1 : denominator;
    values.push(Math.round((numerator / safeDenominator) * 1000) / 1000);
  }
  return values;
}

function readNumberArray(count: number, step: number, reader: (index: number) => number): number[] {
  const values: number[] = [];
  for (let index = 0; index < count; index += 1) {
    values.push(reader(index));
    if ((index + 1) * step >= MAX_TIFF_VALUE_BYTES) break;
  }
  return values;
}

function readNextIfdOffset(view: DataView, ifdOffset: number, little: boolean, start: number): number | null {
  if (!isLikelyIfdOffset(view, ifdOffset)) return null;

  const declaredCount = view.getUint16(ifdOffset, little);
  const pointerPos = safeAdd(ifdOffset, 2 + declaredCount * 12);
  if (pointerPos == null || !isValidRange(view, pointerPos, 4)) return null;

  const nextPointer = view.getUint32(pointerPos, little);
  if (nextPointer === 0) return null;

  const absolute = safeAdd(start, nextPointer);
  if (absolute == null || !isLikelyIfdOffset(view, absolute)) return null;
  return absolute;
}

function resolveTagLabel(tag: number): string | null {
  if (tagNames[tag]) return tagNames[tag];
  if (tag >= 0xc000 || FALLBACK_VENDOR_TAGS.has(tag)) {
    return `vendorTag0x${tag.toString(16).padStart(4, "0")}`;
  }
  return null;
}

function entryValueToOffset(value: string | number | number[], start: number, length: number): number | null {
  const pointer = Array.isArray(value) ? value.find((entry) => Number.isFinite(entry)) : typeof value === "number" ? value : null;
  if (typeof pointer !== "number" || !Number.isFinite(pointer) || pointer < 0) return null;
  const absolute = safeAdd(start, Math.floor(pointer));
  if (absolute == null || absolute + 2 > length) return null;
  return absolute;
}

function stringifyEntryValue(value: string | number | number[]): string {
  if (Array.isArray(value)) {
    return value.slice(0, 8).map((entry) => String(entry)).join(", ");
  }
  return String(value);
}

function sanitizeAscii(value: string): string {
  const normalized = value.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, "").trim();
  return normalized;
}

function parsePngTextKey(bytes: Uint8Array, dataStart: number, dataEnd: number): string | null {
  const nul = bytes.indexOf(0, dataStart);
  if (nul <= dataStart || nul >= dataEnd) return null;
  const key = sanitizeAscii(getAscii(bytes, dataStart, Math.min(64, nul - dataStart)));
  return key || null;
}

function isVendorTextKey(key: string): boolean {
  const normalized = key.toLowerCase();
  return (
    normalized.includes("raw profile") ||
    normalized.includes("adobe") ||
    normalized.includes("photoshop") ||
    normalized.includes("xmp") ||
    normalized.startsWith("exif")
  );
}

function isLikelyIfdOffset(view: DataView, offset: number): boolean {
  return isValidRange(view, offset, 2);
}

function isValidRange(view: DataView, offset: number, length: number): boolean {
  return Number.isFinite(offset) && Number.isFinite(length) && offset >= 0 && length >= 0 && offset + length <= view.byteLength;
}

function safeAdd(left: number, right: number): number | null {
  const value = left + right;
  if (!Number.isFinite(value)) return null;
  return value;
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

function getAscii(bytes: Uint8Array, offset: number, length: number) {
  if (offset < 0 || length <= 0 || offset >= bytes.length) return "";
  const end = Math.min(bytes.length, offset + length);
  return asciiDecoder.decode(bytes.subarray(offset, end));
}

function getAsciiFromView(view: DataView, offset: number, length: number) {
  return getAscii(new Uint8Array(view.buffer, view.byteOffset, view.byteLength), offset, length);
}

function readUint32BE(bytes: Uint8Array, offset: number) {
  if (offset + 4 > bytes.length) return 0;
  return (((bytes[offset] << 24) >>> 0) + (bytes[offset + 1] << 16) + (bytes[offset + 2] << 8) + bytes[offset + 3]) >>> 0;
}

function readUint32LE(bytes: Uint8Array, offset: number) {
  if (offset + 4 > bytes.length) return 0;
  return (bytes[offset] + (bytes[offset + 1] << 8) + (bytes[offset + 2] << 16) + ((bytes[offset + 3] << 24) >>> 0)) >>> 0;
}

const tagNames: Record<number, string> = {
  0x010f: "make",
  0x0110: "model",
  0x0112: "orientation",
  0x0131: "software",
  0x0132: "datetime",
  0x013b: "artist",
  0x8298: "copyright",
  0x8769: "exifIfdPointer",
  0x8825: "gpsInfo",
  0x9000: "exifVersion",
  0x9003: "captured",
  0x9010: "offsetTime",
  0x9011: "offsetTimeOriginal",
  0x9012: "offsetTimeDigitized",
  0x829a: "exposureTime",
  0x829d: "fNumber",
  0x8827: "iso",
  0x9207: "meteringMode",
  0x9209: "flash",
  0x920a: "focalLength",
  0x927c: "makerNote",
  0x9286: "userComment",
  0xa002: "pixelWidth",
  0xa003: "pixelHeight",
  0xa005: "interopIfdPointer",
  0xa405: "focalLength35mm",
  0xa420: "imageUniqueId",
  0xa430: "cameraOwnerName",
  0xa431: "bodySerialNumber",
  0xa432: "lensSpecification",
  0xa433: "lensMake",
  0xa434: "lensModel",
  0xa435: "lensSerialNumber",
};

const typeSize: Record<number, number> = {
  1: 1,
  2: 1,
  3: 2,
  4: 4,
  5: 8,
  7: 1,
  9: 4,
  10: 8,
};

function buildGps(entries: ParsedEntry[]) {
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
