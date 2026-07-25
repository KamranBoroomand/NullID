export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function toBase64(bytes: Uint8Array): string {
  if (typeof btoa === "function") {
    let binary = "";
    bytes.forEach((b) => {
      binary += String.fromCharCode(b);
    });
    return btoa(binary);
  }
  const nodeBuffer = getNodeBuffer();
  if (!nodeBuffer) throw new Error("Base64 encoding unavailable");
  return nodeBuffer.from(bytes).toString("base64");
}

export function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}

const BASE64_URL_RE = /^[A-Za-z0-9_-]*$/u;

export function fromBase64(value: string): Uint8Array {
  if (typeof atob === "function") {
    const binary = atob(value);
    const output = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      output[i] = binary.charCodeAt(i);
    }
    return output;
  }
  const nodeBuffer = getNodeBuffer();
  if (!nodeBuffer) throw new Error("Base64 decoding unavailable");
  return new Uint8Array(nodeBuffer.from(value, "base64"));
}

export function fromBase64Url(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const pad = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  return fromBase64(`${normalized}${pad}`);
}

export function decodeBase64UrlStrict(value: string, errorMessage: string): Uint8Array {
  if (!BASE64_URL_RE.test(value) || value.length % 4 === 1) {
    throw new Error(errorMessage);
  }
  try {
    const bytes = fromBase64Url(value);
    if (toBase64Url(bytes) !== value) {
      throw new Error(errorMessage);
    }
    return bytes;
  } catch {
    throw new Error(errorMessage);
  }
}

export function utf8ToBytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

export function bytesToUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

export function randomBytes(length: number): Uint8Array {
  const buf = new Uint8Array(length);
  crypto.getRandomValues(buf);
  return buf;
}
type BufferLike = Uint8Array & {
  toString(encoding?: string): string;
};

type BufferConstructorLike = {
  from(value: Uint8Array | string, encoding?: string): BufferLike;
};

function getNodeBuffer(): BufferConstructorLike | undefined {
  return (globalThis as typeof globalThis & { Buffer?: BufferConstructorLike }).Buffer;
}
