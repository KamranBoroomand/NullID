import { sha1 } from "@noble/hashes/sha1";
import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";
import { toBase64, toHex } from "./encoding.js";

export type HashAlgorithm = "SHA-256" | "SHA-512" | "SHA-1";

export interface HashResult {
  hex: string;
  base64: string;
}

export interface HashOptions {
  onProgress?: (percent: number) => void;
  signal?: AbortSignal;
}

type HashFactory = {
  create: () => import("@noble/hashes/utils").Hash;
};

const hashers: Record<HashAlgorithm, HashFactory> = {
  "SHA-1": { create: () => sha1.create() },
  "SHA-256": { create: () => sha256.create() },
  "SHA-512": { create: () => sha512.create() },
};

const HASH_TEXT_CHUNK = 32_000;
const HASH_FILE_CHUNK = 1024 * 1024 * 2; // 2MB slices keep memory bounded even on mobile.

function ensureActive(signal?: AbortSignal) {
  if (signal?.aborted) {
    throw new DOMException("aborted", "AbortError");
  }
}

async function finalizeHash(hasher: import("@noble/hashes/utils").Hash, started: number, onProgress?: (percent: number) => void): Promise<HashResult> {
  const bytes = new Uint8Array(hasher.digest());
  const elapsed = Math.round(performance.now() - started);
  if (onProgress) onProgress(100);
  console.info(`hash: ${bytes.length * 8} bits in ${elapsed}ms`);
  return { hex: toHex(bytes), base64: toBase64(bytes) };
}

export async function hashText(text: string, algorithm: HashAlgorithm, options?: HashOptions): Promise<HashResult> {
  const hasher = hashers[algorithm].create();
  const encoder = new TextEncoder();
  const started = performance.now();
  for (let i = 0; i < text.length; i += HASH_TEXT_CHUNK) {
    ensureActive(options?.signal);
    const slice = text.slice(i, i + HASH_TEXT_CHUNK);
    hasher.update(encoder.encode(slice));
    // Let the UI breathe during long inputs.
    if (text.length > HASH_TEXT_CHUNK) {
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
  }
  return finalizeHash(hasher, started, options?.onProgress);
}

export async function hashFile(file: File, algorithm: HashAlgorithm, options?: HashOptions): Promise<HashResult> {
  const hasher = hashers[algorithm].create();
  const started = performance.now();
  let offset = 0;
  while (offset < file.size) {
    ensureActive(options?.signal);
    const end = Math.min(offset + HASH_FILE_CHUNK, file.size);
    const slice = file.slice(offset, end);
    const buffer = new Uint8Array(await slice.arrayBuffer());
    hasher.update(buffer);
    offset = end;
    const percent = Math.min(99, Math.round((offset / file.size) * 100));
    if (options?.onProgress) options.onProgress(percent);
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  return finalizeHash(hasher, started, options?.onProgress);
}

export function normalizeHashInput(value: string): string {
  return value.replace(/[^a-f0-9]/gi, "").toLowerCase();
}

export const expectedHashLengths: Record<HashAlgorithm, number> = {
  "SHA-1": 40,
  "SHA-256": 64,
  "SHA-512": 128,
};
