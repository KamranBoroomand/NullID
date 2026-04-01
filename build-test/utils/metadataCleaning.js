import { chooseExportMime } from "./imageFormats.js";
import { hashBytes } from "./hash.js";
import { readMetadataFields } from "./metadataInspector.js";
export async function readHeadTailBytes(file, sliceSize) {
    if (file.size <= sliceSize * 2) {
        return new Uint8Array(await file.arrayBuffer());
    }
    const head = new Uint8Array(await file.slice(0, sliceSize).arrayBuffer());
    const tail = new Uint8Array(await file.slice(Math.max(0, file.size - sliceSize)).arrayBuffer());
    const output = new Uint8Array(head.length + tail.length);
    output.set(head, 0);
    output.set(tail, head.length);
    return output;
}
export async function sanitizeBrowserImage(file, options) {
    const url = URL.createObjectURL(file);
    try {
        const img = await loadImage(url);
        const canvas = document.createElement("canvas");
        const clampScale = Math.max(0.1, Math.min(1, options.scale ?? 1));
        canvas.width = Math.max(1, Math.round(img.naturalWidth * clampScale));
        canvas.height = Math.max(1, Math.round(img.naturalHeight * clampScale));
        const ctx = canvas.getContext("2d");
        if (!ctx)
            throw new Error("Canvas unavailable");
        ctx.drawImage(img, 0, 0);
        const preferredMime = options.outputChoice === "auto" || !options.outputChoice
            ? chooseExportMime(file.type, options.outputSupport)
            : options.outputChoice;
        const quality = Math.max(0.5, Math.min(1, options.quality ?? 0.92));
        const candidates = Array.from(new Set([preferredMime, "image/png", "image/jpeg", "image/webp", "image/avif"]))
            .filter((mime) => options.outputSupport[mime]);
        let cleanedBlob = null;
        let outputMime = preferredMime;
        for (const mime of candidates) {
            cleanedBlob = await new Promise((resolve) => {
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
    }
    finally {
        URL.revokeObjectURL(url);
    }
}
export function extensionFromMime(mime) {
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
    if (mime.includes("pdf"))
        return "pdf";
    return "jpg";
}
export async function sha256HexBlob(blob) {
    const bytes = new Uint8Array(await blob.arrayBuffer());
    return (await hashBytes(bytes, "SHA-256")).hex;
}
function loadImage(url) {
    return new Promise((resolve, reject) => {
        const img = new Image();
        img.onload = () => resolve(img);
        img.onerror = () => reject(new Error("Image load failed"));
        img.src = url;
    });
}
