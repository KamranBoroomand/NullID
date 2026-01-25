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

type Hasher = {
  update: (data: Uint8Array) => unknown;
  digest: () => Uint8Array;
};

type HashFactory = {
  create: () => Hasher;
};


const hashers: Record<HashAlgorithm, HashFactory> = {
  "SHA-1": { create: () => sha1.create() },
  "SHA-256": { create: () => sha256.create() },
  "SHA-512": { create: () => sha512.create() },
};

const HASH_TEXT_CHUNK = 32_000;
const HASH_FILE_CHUNK = 1024 * 1024 * 2; // 2MB slices keep memory bounded even on mobile.
const YIELD_INTERVAL_MS = 16;
const PROGRESS_THROTTLE_MS = 80;

function ensureActive(signal?: AbortSignal) {
  if (signal?.aborted) {
    throw new DOMException("aborted", "AbortError");
  }
}

function createProgressReporter(onProgress?: (percent: number) => void) {
  let lastPercent = -1;
  let lastReport = 0;
  return (percent: number) => {
    if (!onProgress) return;
    const clamped = Math.max(0, Math.min(100, Math.round(percent)));
    const now = performance.now();
    if (clamped === lastPercent) return;
    if (clamped !== 100 && now - lastReport < PROGRESS_THROTTLE_MS) return;
    lastPercent = clamped;
    lastReport = now;
    onProgress(clamped);
  };
}

async function yieldToMain(lastYield: number) {
  if (performance.now() - lastYield < YIELD_INTERVAL_MS) return lastYield;
  if (typeof globalThis.requestAnimationFrame === "function") {
    await new Promise<void>((resolve) => globalThis.requestAnimationFrame(() => resolve()));
  } else {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  return performance.now();
}

async function finalizeHash(
  hasher: Hasher,
  started: number,
  onProgress?: (percent: number) => void
): Promise<HashResult> {
  const bytes = hasher.digest();
  const elapsed = Math.round(performance.now() - started);
  const reportProgress = createProgressReporter(onProgress);
  reportProgress(100);
  console.info(`hash: ${bytes.length * 8} bits in ${elapsed}ms`);
  return { hex: toHex(bytes), base64: toBase64(bytes) };
}

export async function hashText(text: string, algorithm: HashAlgorithm, options?: HashOptions): Promise<HashResult> {
  if (typeof text !== "string") {
    throw new TypeError("Expected text to be a string");
  }
  const factory = hashers[algorithm];
  if (!factory) {
    throw new Error(`Unsupported hash algorithm: ${algorithm}`);
  }
  const hasher = factory.create();
  const encoder = new TextEncoder();
  const started = performance.now();
  const reportProgress = createProgressReporter(options?.onProgress);
  let lastYield = performance.now();
  for (let i = 0; i < text.length; i += HASH_TEXT_CHUNK) {
    ensureActive(options?.signal);
    const slice = text.slice(i, i + HASH_TEXT_CHUNK);
    hasher.update(encoder.encode(slice));
    reportProgress(((i + slice.length) / text.length) * 100);
    lastYield = await yieldToMain(lastYield);
  }
  return finalizeHash(hasher, started, options?.onProgress);
}

export async function hashFile(file: File, algorithm: HashAlgorithm, options?: HashOptions): Promise<HashResult> {
  if (!(file instanceof File)) {
    throw new TypeError("Expected a File to hash");
  }
  const factory = hashers[algorithm];
  if (!factory) {
    throw new Error(`Unsupported hash algorithm: ${algorithm}`);
  }
  const hasher = factory.create();
  const started = performance.now();
  let offset = 0;
  const reportProgress = createProgressReporter(options?.onProgress);
  let lastYield = performance.now();
  while (offset < file.size) {
    ensureActive(options?.signal);
    const end = Math.min(offset + HASH_FILE_CHUNK, file.size);
    const slice = file.slice(offset, end);
    const buffer = new Uint8Array(await slice.arrayBuffer());
    hasher.update(buffer);
    offset = end;
    reportProgress((offset / file.size) * 100);
    lastYield = await yieldToMain(lastYield);
  }
  return finalizeHash(hasher, started, options?.onProgress);
}

export function normalizeHashInput(value: string): string {
  if (!value) return "";
  const matches = value.trim().match(/[a-f0-9]+/gi);
  if (!matches) return "";
  const longest = matches.reduce((winner, current) => (current.length > winner.length ? current : winner), "");
  return longest.toLowerCase();
}

export const expectedHashLengths: Record<HashAlgorithm, number> = {
  "SHA-1": 40,
  "SHA-256": 64,
  "SHA-512": 128,
};
