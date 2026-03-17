export function toHex(bytes) {
    return Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
}
export function toBase64(bytes) {
    if (typeof btoa === "function") {
        let binary = "";
        bytes.forEach((b) => {
            binary += String.fromCharCode(b);
        });
        return btoa(binary);
    }
    return Buffer.from(bytes).toString("base64");
}
export function toBase64Url(bytes) {
    return toBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}
const BASE64_URL_RE = /^[A-Za-z0-9+/_-]+=*$/u;
export function fromBase64(value) {
    if (typeof atob === "function") {
        const binary = atob(value);
        const output = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i += 1) {
            output[i] = binary.charCodeAt(i);
        }
        return output;
    }
    return new Uint8Array(Buffer.from(value, "base64"));
}
export function fromBase64Url(value) {
    const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
    const pad = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
    return fromBase64(`${normalized}${pad}`);
}
export function decodeBase64UrlStrict(value, errorMessage) {
    if (!BASE64_URL_RE.test(value)) {
        throw new Error(errorMessage);
    }
    const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
    const hasPadding = normalized.includes("=");
    if (hasPadding && normalized.length % 4 !== 0) {
        throw new Error(errorMessage);
    }
    if (!hasPadding && normalized.length % 4 === 1) {
        throw new Error(errorMessage);
    }
    const padded = hasPadding ? normalized : `${normalized}${"=".repeat((4 - (normalized.length % 4)) % 4)}`;
    try {
        const bytes = fromBase64(padded);
        if (toBase64(bytes) !== padded) {
            throw new Error(errorMessage);
        }
        return bytes;
    }
    catch {
        throw new Error(errorMessage);
    }
}
export function utf8ToBytes(value) {
    return new TextEncoder().encode(value);
}
export function bytesToUtf8(bytes) {
    return new TextDecoder().decode(bytes);
}
export function randomBytes(length) {
    const buf = new Uint8Array(length);
    crypto.getRandomValues(buf);
    return buf;
}
