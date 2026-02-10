import { toBase64Url, utf8ToBytes, fromBase64Url } from "./encoding.js";

export type SignatureAlgorithm = "HMAC-SHA-256";

export interface IntegritySignature {
  algorithm: SignatureAlgorithm;
  value: string;
  keyHint?: string;
}

export function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => stableStringify(entry)).join(",")}]`;
  }
  const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b));
  const body = entries.map(([key, child]) => `${JSON.stringify(key)}:${stableStringify(child)}`).join(",");
  return `{${body}}`;
}

export async function sha256Base64Url(value: unknown): Promise<string> {
  const payload = typeof value === "string" ? value : stableStringify(value);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", toArrayBuffer(utf8ToBytes(payload))));
  return toBase64Url(digest);
}

async function importHmacKey(secret: string) {
  return crypto.subtle.importKey("raw", toArrayBuffer(utf8ToBytes(secret)), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

export async function signHash(hashBase64Url: string, secret: string): Promise<string> {
  const key = await importHmacKey(secret);
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, toArrayBuffer(utf8ToBytes(hashBase64Url))));
  return toBase64Url(signature);
}

export async function verifyHashSignature(hashBase64Url: string, signatureBase64Url: string, secret: string): Promise<boolean> {
  const key = await importHmacKey(secret);
  return crypto.subtle.verify(
    "HMAC",
    key,
    toArrayBuffer(fromBase64Url(signatureBase64Url)),
    toArrayBuffer(utf8ToBytes(hashBase64Url)),
  );
}

function toArrayBuffer(bytes: Uint8Array) {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}
