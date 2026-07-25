import { toExactArrayBuffer } from "./bytes.js";
import { decodeBase64UrlStrict, toBase64Url, utf8ToBytes } from "./encoding.js";

export type SignatureAlgorithm = "HMAC-SHA-256";
export const HMAC_SHA256_ALGORITHM: SignatureAlgorithm = "HMAC-SHA-256";

export interface IntegritySignature {
  algorithm: SignatureAlgorithm;
  value: string;
  keyHint?: string;
}

const MAX_CANONICAL_DEPTH = 64;
const MAX_CANONICAL_ITEMS = 10_000;
const SHA256_BYTES = 32;

export function stableStringify(value: unknown): string {
  return canonicalJson(value, { seen: new WeakSet<object>(), depth: 0 });
}

export async function sha256Base64Url(value: unknown): Promise<string> {
  const payload = typeof value === "string" ? value : stableStringify(value);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", toExactArrayBuffer(utf8ToBytes(payload))));
  return toBase64Url(digest);
}

async function importHmacKey(secret: string) {
  return crypto.subtle.importKey("raw", toExactArrayBuffer(utf8ToBytes(secret)), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

export async function signHash(hashBase64Url: string, secret: string): Promise<string> {
  const hashBytes = decodeFixedBase64Url(hashBase64Url, SHA256_BYTES);
  const key = await importHmacKey(secret);
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, toExactArrayBuffer(utf8ToBytes(toBase64Url(hashBytes)))));
  return toBase64Url(signature);
}

export async function verifyHashSignature(hashBase64Url: string, signatureBase64Url: string, secret: string): Promise<boolean> {
  try {
    const hashBytes = decodeFixedBase64Url(hashBase64Url, SHA256_BYTES);
    const signatureBytes = decodeFixedBase64Url(signatureBase64Url, SHA256_BYTES);
    const key = await importHmacKey(secret);
    return crypto.subtle.verify(
      "HMAC",
      key,
      toExactArrayBuffer(signatureBytes),
      toExactArrayBuffer(utf8ToBytes(toBase64Url(hashBytes))),
    );
  } catch {
    return false;
  }
}

function decodeFixedBase64Url(value: string, expectedBytes: number): Uint8Array {
  const bytes = decodeBase64UrlStrict(value, "Invalid Base64URL value");
  if (bytes.byteLength !== expectedBytes) {
    throw new Error("Invalid Base64URL length");
  }
  return bytes;
}

function canonicalJson(value: unknown, state: { seen: WeakSet<object>; depth: number }): string {
  if (state.depth > MAX_CANONICAL_DEPTH) {
    throw new Error("Unsupported canonical JSON depth");
  }

  if (value === null) return "null";

  const valueType = typeof value;
  if (valueType === "string") return JSON.stringify(value);
  if (valueType === "boolean") return value ? "true" : "false";
  if (valueType === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("Unsupported canonical JSON number");
    }
    return JSON.stringify(value);
  }
  if (valueType === "undefined" || valueType === "function" || valueType === "symbol" || valueType === "bigint") {
    throw new Error("Unsupported canonical JSON value");
  }
  if (!value || valueType !== "object") {
    throw new Error("Unsupported canonical JSON value");
  }

  const record = value as object;
  const prototype = Object.getPrototypeOf(record);
  if (prototype !== Object.prototype && prototype !== null && !Array.isArray(value)) {
    throw new Error("Unsupported canonical JSON object");
  }
  if (state.seen.has(record)) {
    throw new Error("Unsupported canonical JSON cycle");
  }
  state.seen.add(record);
  try {
    if (Array.isArray(value)) {
      if (value.length > MAX_CANONICAL_ITEMS) {
        throw new Error("Unsupported canonical JSON array size");
      }
      return `[${value.map((entry) => canonicalJson(entry, { seen: state.seen, depth: state.depth + 1 })).join(",")}]`;
    }

    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length > MAX_CANONICAL_ITEMS) {
      throw new Error("Unsupported canonical JSON object size");
    }
    entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    const body = entries
      .map(([key, child]) => `${JSON.stringify(key)}:${canonicalJson(child, { seen: state.seen, depth: state.depth + 1 })}`)
      .join(",");
    return `{${body}}`;
  } finally {
    state.seen.delete(record);
  }
}
