const MAX_FIELDS = 60;
const MAX_TIFF_IFD_ENTRIES = 1024;
const asciiDecoder = new TextDecoder();
export async function readMetadataFields(file) {
    const buffer = new Uint8Array(await file.arrayBuffer());
    const mime = file.type || "";
    const metadata = inspectMetadataFromBuffer(mime, buffer);
    return Object.entries(metadata)
        .slice(0, MAX_FIELDS)
        .map(([key, value]) => ({ key, value }));
}
export function inspectMetadataFromBuffer(mime, bytes) {
    const format = detectImageFormat(mime, bytes);
    if (format === "jpeg")
        return parseExif(bytes);
    if (format === "tiff")
        return parseTiff(bytes);
    if (format === "png")
        return parsePngMetadata(bytes);
    if (format === "webp")
        return parseWebpMetadata(bytes);
    if (format === "gif")
        return parseGifMetadata(bytes);
    return {};
}
export function detectImageFormat(mime, bytes) {
    const normalized = (mime || "").toLowerCase();
    if (normalized.includes("jpeg") || normalized.includes("jpg"))
        return "jpeg";
    if (normalized.includes("png"))
        return "png";
    if (normalized.includes("webp"))
        return "webp";
    if (normalized.includes("avif"))
        return "avif";
    if (normalized.includes("gif"))
        return "gif";
    if (normalized.includes("bmp"))
        return "bmp";
    if (normalized.includes("tiff"))
        return "tiff";
    if (normalized.includes("heic") || normalized.includes("heif"))
        return "heic";
    if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff)
        return "jpeg";
    if (isPngSignature(bytes))
        return "png";
    if (bytes.length >= 12 && getAscii(bytes, 0, 4) === "RIFF" && getAscii(bytes, 8, 4) === "WEBP")
        return "webp";
    if (bytes.length >= 6 && /^GIF8/.test(getAscii(bytes, 0, 6)))
        return "gif";
    if (bytes.length >= 2 && getAscii(bytes, 0, 2) === "BM")
        return "bmp";
    if (bytes.length >= 4 && (getAscii(bytes, 0, 4) === "II*\u0000" || getAscii(bytes, 0, 4) === "MM\u0000*"))
        return "tiff";
    return "unknown";
}
function parseExif(bytes) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    if (view.byteLength < 4 || view.getUint16(0) !== 0xffd8)
        return {};
    let offset = 2;
    const result = {};
    let gpsOffset = null;
    while (offset < view.byteLength) {
        if (offset + 4 > view.byteLength)
            break;
        if (view.getUint8(offset) !== 0xff)
            break;
        const marker = view.getUint8(offset + 1);
        const length = view.getUint16(offset + 2);
        if (length < 2)
            break;
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
                if (gpsOffset != null) {
                    const gpsTags = readIfd(view, gpsOffset, little, tiffStart);
                    const gps = buildGps(gpsTags);
                    if (gps)
                        result.gps = gps;
                }
            }
        }
        if (marker === 0xda)
            break;
        offset += 2 + length;
    }
    return result;
}
function parseTiff(bytesOrView, offset = 0) {
    const view = bytesOrView instanceof DataView
        ? bytesOrView
        : new DataView(bytesOrView.buffer, bytesOrView.byteOffset, bytesOrView.byteLength);
    if (offset + 8 > view.byteLength)
        return {};
    const endian = getAsciiFromView(view, offset, 2);
    if (endian !== "II" && endian !== "MM")
        return {};
    const little = endian === "II";
    const magic = view.getUint16(offset + 2, little);
    if (magic !== 42)
        return {};
    const ifdOffset = view.getUint32(offset + 4, little);
    const result = {};
    const tags = readIfd(view, offset + ifdOffset, little, offset);
    tags.forEach(({ tag, value }) => {
        const label = tagNames[tag];
        if (label)
            result[label] = String(value);
    });
    return result;
}
function parsePngMetadata(bytes) {
    if (!isPngSignature(bytes))
        return {};
    const result = {};
    const textKeys = [];
    let offset = 8;
    while (offset + 8 <= bytes.length) {
        const length = readUint32BE(bytes, offset);
        const type = getAscii(bytes, offset + 4, 4);
        const dataStart = offset + 8;
        const dataEnd = dataStart + length;
        if (dataEnd + 4 > bytes.length)
            break;
        if (type === "tEXt" || type === "iTXt" || type === "zTXt") {
            const nul = bytes.indexOf(0, dataStart);
            if (nul > dataStart && nul < dataEnd) {
                textKeys.push(getAscii(bytes, dataStart, Math.min(48, nul - dataStart)));
            }
        }
        else if (type === "eXIf") {
            result.exifChunk = `${length} bytes`;
            const exif = parseTiff(bytes.slice(dataStart, dataEnd));
            Object.entries(exif).forEach(([key, value]) => {
                if (!result[key])
                    result[key] = value;
            });
        }
        else if (type === "iCCP") {
            result.iccProfile = "present";
        }
        else if (type === "pHYs" && length >= 9) {
            const x = readUint32BE(bytes, dataStart);
            const y = readUint32BE(bytes, dataStart + 4);
            result.pixelDensity = `${x}x${y}`;
        }
        else if (type === "tIME" && length >= 7) {
            const year = (bytes[dataStart] << 8) + bytes[dataStart + 1];
            const month = bytes[dataStart + 2];
            const day = bytes[dataStart + 3];
            result.timestamp = `${year}-${String(month).padStart(2, "0")}-${String(day).padStart(2, "0")}`;
        }
        offset = dataEnd + 4;
        if (type === "IEND")
            break;
    }
    if (textKeys.length) {
        result.textKeys = textKeys.slice(0, 8).join(", ");
    }
    return result;
}
function parseWebpMetadata(bytes) {
    if (bytes.length < 12 || getAscii(bytes, 0, 4) !== "RIFF" || getAscii(bytes, 8, 4) !== "WEBP")
        return {};
    const result = {};
    const chunkNames = [];
    let offset = 12;
    while (offset + 8 <= bytes.length) {
        const type = getAscii(bytes, offset, 4);
        const size = readUint32LE(bytes, offset + 4);
        const dataStart = offset + 8;
        const dataEnd = dataStart + size;
        if (dataEnd > bytes.length)
            break;
        chunkNames.push(type.trim() || type);
        if (type === "EXIF") {
            result.exifChunk = `${size} bytes`;
            let exifPayload = bytes.slice(dataStart, dataEnd);
            if (exifPayload.length >= 6 && getAscii(exifPayload, 0, 6) === "Exif\u0000\u0000") {
                exifPayload = exifPayload.slice(6);
            }
            const exif = parseTiff(exifPayload);
            Object.entries(exif).forEach(([key, value]) => {
                if (!result[key])
                    result[key] = value;
            });
        }
        if (type === "XMP ")
            result.xmp = "present";
        if (type === "ICCP")
            result.iccProfile = "present";
        if (type === "ANIM")
            result.animated = "yes";
        offset = dataEnd + (size % 2);
    }
    if (chunkNames.length) {
        result.webpChunks = chunkNames.slice(0, 10).join(", ");
    }
    return result;
}
function parseGifMetadata(bytes) {
    if (bytes.length < 6 || !/^GIF8/.test(getAscii(bytes, 0, 6)))
        return {};
    let comments = 0;
    let applications = 0;
    for (let i = 0; i < bytes.length - 1; i += 1) {
        if (bytes[i] === 0x21 && bytes[i + 1] === 0xfe)
            comments += 1;
        if (bytes[i] === 0x21 && bytes[i + 1] === 0xff)
            applications += 1;
    }
    const result = {
        commentBlocks: String(comments),
    };
    if (applications > 0) {
        result.applicationBlocks = String(applications);
    }
    return result;
}
function readIfd(view, offset, little, start) {
    if (offset < 0 || offset + 2 > view.byteLength)
        return [];
    const rawCount = view.getUint16(offset, little);
    const count = Math.min(rawCount, MAX_TIFF_IFD_ENTRIES);
    const entries = [];
    for (let i = 0; i < count; i += 1) {
        const entryOffset = offset + 2 + i * 12;
        if (entryOffset + 12 > view.byteLength)
            break;
        const tag = view.getUint16(entryOffset, little);
        const type = view.getUint16(entryOffset + 2, little);
        const itemCount = view.getUint32(entryOffset + 4, little);
        const valueOffset = view.getUint32(entryOffset + 8, little);
        const size = typeSize[type] ?? 1;
        const totalSize = size * itemCount;
        const valuePos = totalSize <= 4 ? entryOffset + 8 : start + valueOffset;
        if (valuePos < 0 || valuePos + Math.max(1, totalSize) > view.byteLength)
            continue;
        let value = "";
        if (type === 2) {
            value = getAsciiFromView(view, valuePos, itemCount).replace(/\u0000+$/, "");
        }
        else if (type === 3) {
            value = view.getUint16(valuePos, little);
        }
        else if (type === 4) {
            value = view.getUint32(valuePos, little);
        }
        else if (type === 5) {
            const values = [];
            for (let item = 0; item < itemCount; item += 1) {
                const base = valuePos + item * 8;
                if (base + 8 > view.byteLength)
                    break;
                const num = view.getUint32(base, little);
                const den = view.getUint32(base + 4, little) || 1;
                values.push(Math.round((num / den) * 1000) / 1000);
            }
            value = itemCount === 1 ? (values[0] ?? 0) : values;
        }
        entries.push({ tag, value });
    }
    return entries;
}
function isPngSignature(bytes) {
    return (bytes.length >= 8 &&
        bytes[0] === 0x89 &&
        bytes[1] === 0x50 &&
        bytes[2] === 0x4e &&
        bytes[3] === 0x47 &&
        bytes[4] === 0x0d &&
        bytes[5] === 0x0a &&
        bytes[6] === 0x1a &&
        bytes[7] === 0x0a);
}
function getAscii(bytes, offset, length) {
    if (offset < 0 || length <= 0 || offset >= bytes.length)
        return "";
    const end = Math.min(bytes.length, offset + length);
    return asciiDecoder.decode(bytes.subarray(offset, end));
}
function getAsciiFromView(view, offset, length) {
    return getAscii(new Uint8Array(view.buffer, view.byteOffset, view.byteLength), offset, length);
}
function readUint32BE(bytes, offset) {
    if (offset + 4 > bytes.length)
        return 0;
    return (((bytes[offset] << 24) >>> 0) + (bytes[offset + 1] << 16) + (bytes[offset + 2] << 8) + bytes[offset + 3]) >>> 0;
}
function readUint32LE(bytes, offset) {
    if (offset + 4 > bytes.length)
        return 0;
    return (bytes[offset] + (bytes[offset + 1] << 8) + (bytes[offset + 2] << 16) + ((bytes[offset + 3] << 24) >>> 0)) >>> 0;
}
const tagNames = {
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
const typeSize = {
    1: 1,
    2: 1,
    3: 2,
    4: 4,
    5: 8,
};
function buildGps(entries) {
    const map = {};
    entries.forEach((entry) => {
        map[entry.tag] = entry.value;
    });
    const latRef = typeof map[0x0001] === "string" ? map[0x0001] : undefined;
    const lat = map[0x0002];
    const lonRef = typeof map[0x0003] === "string" ? map[0x0003] : undefined;
    const lon = map[0x0004];
    const latVal = Array.isArray(lat) ? dmsToDecimal(lat, latRef === "S") : typeof lat === "number" ? lat : null;
    const lonVal = Array.isArray(lon) ? dmsToDecimal(lon, lonRef === "W") : typeof lon === "number" ? lon : null;
    if (latVal != null && lonVal != null) {
        return `${latVal.toFixed(6)}, ${lonVal.toFixed(6)}`;
    }
    return null;
}
function dmsToDecimal(values, negative) {
    const [deg = 0, min = 0, sec = 0] = values;
    const decimal = deg + min / 60 + sec / 3600;
    return negative ? -decimal : decimal;
}
