const BYTES_PER_MIB = 1024 * 1024;

export const INPUT_LIMITS = {
  batchAggregateBytes: 25 * BYTES_PER_MIB,
  batchFileBytes: 10 * BYTES_PER_MIB,
  encryptionFileBytes: 25 * BYTES_PER_MIB,
  envelopeFileBytes: 40 * BYTES_PER_MIB,
  envelopeTextChars: 40 * BYTES_PER_MIB,
  jsonImportBytes: 2 * BYTES_PER_MIB,
  metadataFileBytes: 50 * BYTES_PER_MIB,
  plaintextChars: 2 * BYTES_PER_MIB,
  previewBytes: 64 * 1024,
  previewChars: 8_000,
  textFileBytes: 5 * BYTES_PER_MIB,
  textInputChars: 5 * BYTES_PER_MIB,
} as const;

const UTF8_CHUNK_BYTES = 64 * 1024;
const TEXT_MIME_PREFIX = "text/";
const TEXT_MIME_TYPES = new Set([
  "application/json",
  "application/ld+json",
  "application/manifest+json",
  "application/xml",
  "application/xhtml+xml",
  "application/yaml",
  "application/x-yaml",
  "application/toml",
  "application/csv",
  "application/javascript",
  "application/ecmascript",
  "image/svg+xml",
]);

class InputLimitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InputLimitError";
  }
}

export interface FileLimitOptions {
  maxBytes: number;
  label: string;
}

export interface TextLimitOptions extends FileLimitOptions {
  maxChars?: number;
}

export interface DecryptedPreview {
  kind: "text" | "binary";
  text: string;
  truncated: boolean;
}

function formatByteLimit(bytes: number): string {
  if (bytes >= BYTES_PER_MIB && bytes % BYTES_PER_MIB === 0) {
    return `${bytes / BYTES_PER_MIB}MB`;
  }
  if (bytes >= 1024 && bytes % 1024 === 0) {
    return `${bytes / 1024}KB`;
  }
  return `${bytes} bytes`;
}

export function assertFileWithinLimit(file: Pick<Blob, "size"> & { name?: string }, options: FileLimitOptions): void {
  if (!Number.isFinite(file.size) || file.size < 0) {
    throw new InputLimitError(`${options.label} has an invalid size.`);
  }
  if (file.size > options.maxBytes) {
    throw new InputLimitError(`${options.label} file too large. Max ${formatByteLimit(options.maxBytes)}.`);
  }
}

export function assertFileBatchWithinLimit(
  files: ArrayLike<Pick<Blob, "size"> & { name?: string }>,
  options: FileLimitOptions & { maxFileBytes?: number; maxFiles?: number },
): void {
  if (options.maxFiles !== undefined && files.length > options.maxFiles) {
    throw new InputLimitError(`${options.label} has too many files. Max ${options.maxFiles}.`);
  }
  let totalBytes = 0;
  for (let index = 0; index < files.length; index += 1) {
    const file = files[index];
    assertFileWithinLimit(file, { label: file.name || options.label, maxBytes: options.maxFileBytes ?? options.maxBytes });
    totalBytes += file.size;
    if (totalBytes > options.maxBytes) {
      throw new InputLimitError(`${options.label} batch too large. Max ${formatByteLimit(options.maxBytes)}.`);
    }
  }
}

export async function readFileBytesWithLimit(file: Pick<Blob, "arrayBuffer" | "size">, options: FileLimitOptions): Promise<Uint8Array> {
  assertFileWithinLimit(file, options);
  return new Uint8Array(await file.arrayBuffer());
}

export async function readFileTextWithLimit(file: Pick<Blob, "size" | "text">, options: TextLimitOptions): Promise<string> {
  assertFileWithinLimit(file, options);
  const text = await file.text();
  if (options.maxChars !== undefined) {
    assertTextWithinLimit(text, { label: options.label, maxChars: options.maxChars });
  }
  return text;
}

export function assertTextWithinLimit(value: string, options: { label: string; maxChars: number }): void {
  if (value.length > options.maxChars) {
    throw new InputLimitError(`${options.label} too large. Max ${formatByteLimit(options.maxChars)}.`);
  }
}

function isTextMime(mime?: string): boolean {
  if (!mime) return false;
  const normalized = mime.split(";")[0]?.trim().toLowerCase() ?? "";
  return normalized.startsWith(TEXT_MIME_PREFIX) || TEXT_MIME_TYPES.has(normalized) || normalized.endsWith("+json") || normalized.endsWith("+xml");
}

export function buildDecryptedPreview(
  bytes: Uint8Array,
  mime?: string,
  options: { maxBytes?: number; maxChars?: number } = {},
): DecryptedPreview {
  const maxBytes = options.maxBytes ?? INPUT_LIMITS.previewBytes;
  const maxChars = options.maxChars ?? INPUT_LIMITS.previewChars;
  if (!isTextMime(mime) && !isStrictUtf8(bytes)) {
    return { kind: "binary", text: "[binary payload]", truncated: false };
  }
  try {
    const { text, bytesTruncated } = decodeUtf8Preview(bytes, maxBytes);
    const charsTruncated = text.length > maxChars;
    const preview = charsTruncated ? text.slice(0, maxChars) : text;
    const truncated = bytesTruncated || charsTruncated;
    return {
      kind: "text",
      text: truncated ? `${preview}\n[preview truncated]` : preview,
      truncated,
    };
  } catch {
    return { kind: "binary", text: "[binary payload]", truncated: false };
  }
}

function isStrictUtf8(bytes: Uint8Array): boolean {
  const decoder = new TextDecoder("utf-8", { fatal: true });
  try {
    for (let offset = 0; offset < bytes.byteLength; offset += UTF8_CHUNK_BYTES) {
      const end = Math.min(offset + UTF8_CHUNK_BYTES, bytes.byteLength);
      decoder.decode(bytes.subarray(offset, end), { stream: end < bytes.byteLength });
    }
    decoder.decode();
    return true;
  } catch {
    return false;
  }
}

function decodeUtf8Preview(bytes: Uint8Array, maxBytes: number): { text: string; bytesTruncated: boolean } {
  const bytesTruncated = bytes.byteLength > maxBytes;
  const end = Math.min(bytes.byteLength, maxBytes);
  const decoder = new TextDecoder("utf-8", { fatal: true });
  if (!bytesTruncated) {
    return { text: decoder.decode(bytes), bytesTruncated };
  }
  for (let candidateEnd = end; candidateEnd >= Math.max(0, end - 4); candidateEnd -= 1) {
    try {
      return { text: new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, candidateEnd)), bytesTruncated };
    } catch {
      // Keep backing off to avoid splitting a multi-byte sequence at the preview boundary.
    }
  }
  throw new Error("Invalid UTF-8 preview");
}
