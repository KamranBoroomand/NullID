import { toExactArrayBuffer } from "./bytes.js";
import { decodeBase64UrlStrict, toBase64Url, utf8ToBytes, bytesToUtf8, randomBytes } from "./encoding.js";
import { stableStringify } from "./integrity.js";

const LEGACY_ENVELOPE_VERSION = 1;
const ENVELOPE_VERSION = 2;
export const LEGACY_ENVELOPE_PREFIX = "NULLID:ENC:1";
export const ENVELOPE_PREFIX = "NULLID:ENC:2";
const LEGACY_AAD = utf8ToBytes("nullid:enc:v1");
const V2_AAD_DOMAIN = "nullid:enc:v2";
const MIN_SALT_BYTES = 8;
const MAX_SALT_BYTES = 64;
const ENVELOPE_IV_BYTES = 12;
const MIN_CIPHERTEXT_BYTES = 16;
const MAX_HEADER_STRING_BYTES = 512;
const MAX_FILENAME_CHARS = 120;
const MIN_KDF_ITERATIONS = 100_000;
export const MAX_KDF_ITERATIONS = 2_000_000;
const DEFAULT_KDF_ITERATIONS = 250_000;

export type KdfHash = "SHA-256" | "SHA-512";
export type KdfProfile = "compat" | "strong" | "paranoid";

export interface EnvelopeHeader {
  version: number;
  algo: "AES-GCM";
  kdf: { name: "PBKDF2"; iterations: number; hash: KdfHash; salt: string };
  iv: string;
  mime?: string;
  name?: string;
}

interface Envelope {
  header: EnvelopeHeader;
  ciphertext: string;
  metadataAuthenticated?: boolean;
}

export interface EnvelopeInspectResult {
  header: EnvelopeHeader;
  ciphertextBytes: number;
  metadataAuthenticated: boolean;
}

interface DerivedKey {
  key: CryptoKey;
  salt: Uint8Array;
}

interface KdfOptions {
  iterations?: number;
  hash?: KdfHash;
}

export interface EncryptOptions {
  mime?: string;
  name?: string;
  kdfProfile?: KdfProfile;
  kdf?: KdfOptions;
}

export interface ResolvedKdf {
  iterations: number;
  hash: KdfHash;
}

export const KDF_PROFILES: Record<KdfProfile, ResolvedKdf> = {
  compat: { iterations: DEFAULT_KDF_ITERATIONS, hash: "SHA-256" },
  strong: { iterations: 600_000, hash: "SHA-512" },
  paranoid: { iterations: 1_000_000, hash: "SHA-512" },
};

function clampIterations(value?: number): number {
  if (!Number.isFinite(value)) return DEFAULT_KDF_ITERATIONS;
  const rounded = Math.floor(value as number);
  return Math.max(MIN_KDF_ITERATIONS, Math.min(MAX_KDF_ITERATIONS, rounded));
}

function normalizeHash(value?: string): KdfHash {
  return value === "SHA-512" ? "SHA-512" : "SHA-256";
}

function resolveKdfOptions(profile?: KdfProfile, overrides?: KdfOptions): ResolvedKdf {
  const fromProfile = profile ? KDF_PROFILES[profile] : KDF_PROFILES.compat;
  return {
    iterations: clampIterations(overrides?.iterations ?? fromProfile.iterations),
    hash: normalizeHash(overrides?.hash ?? fromProfile.hash),
  };
}

async function deriveKey(passphrase: string, salt?: Uint8Array, options?: KdfOptions): Promise<DerivedKey> {
  const resolved = resolveKdfOptions(undefined, options);
  const saltBytes = salt ?? randomBytes(16);
  const keyMaterial = await crypto.subtle.importKey("raw", toExactArrayBuffer(utf8ToBytes(passphrase)), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: toExactArrayBuffer(saltBytes),
      iterations: resolved.iterations,
      hash: resolved.hash,
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  return { key, salt: saltBytes };
}

export async function encryptText(passphrase: string, plaintext: string, options?: EncryptOptions): Promise<string> {
  const data = utf8ToBytes(plaintext);
  const { blob } = await encryptBytes(passphrase, data, options);
  return blob;
}

export async function decryptText(passphrase: string, blob: string): Promise<string> {
  const { plaintext } = await decryptBlob(passphrase, blob);
  return bytesToUtf8(plaintext);
}

function normalizeEnvelopeBlob(blob: string): string {
  // Accept envelopes copied from terminals / wrapped lines.
  // - Trim leading/trailing whitespace
  // - Remove all internal whitespace characters
  // The envelope format is base64url, so whitespace is never significant.
  return (blob ?? "").trim().replace(/\s+/g, "");
}

export async function encryptBytes(
  passphrase: string,
  bytes: Uint8Array,
  options?: EncryptOptions,
): Promise<{ blob: string; header: EnvelopeHeader; ciphertext: Uint8Array }> {
  const kdf = resolveKdfOptions(options?.kdfProfile, options?.kdf);
  const { key, salt } = await deriveKey(passphrase, undefined, kdf);
  const iv = randomBytes(ENVELOPE_IV_BYTES);
  const header: EnvelopeHeader = {
    version: ENVELOPE_VERSION,
    algo: "AES-GCM",
    iv: toBase64Url(iv),
    kdf: {
      name: "PBKDF2",
      iterations: kdf.iterations,
      hash: kdf.hash,
      salt: toBase64Url(salt),
    },
  };
  header.mime = normalizeEnvelopeMime(options?.mime);
  const safeName = sanitizeEnvelopeFilename(options?.name);
  if (safeName) header.name = safeName;

  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: toExactArrayBuffer(iv), additionalData: buildV2AdditionalData(header) },
      key,
      toExactArrayBuffer(bytes),
    ),
  );

  const payload: Envelope = {
    header,
    ciphertext: toBase64Url(ciphertext),
  };

  return { blob: `${ENVELOPE_PREFIX}.${toBase64Url(utf8ToBytes(JSON.stringify(payload)))}`, header, ciphertext };
}

export async function decryptBlob(
  passphrase: string,
  blob: string,
): Promise<{ plaintext: Uint8Array; header: EnvelopeHeader; metadataAuthenticated: boolean }> {
  const envelope = parseEnvelope(blob);
  const salt = decodeBase64UrlStrict(envelope.header.kdf.salt, "Invalid envelope kdf salt");
  const { key } = await deriveKey(passphrase, salt, {
    iterations: envelope.header.kdf.iterations,
    hash: envelope.header.kdf.hash,
  });
  const iv = decodeBase64UrlStrict(envelope.header.iv, "Invalid envelope iv");
  const ciphertext = decodeBase64UrlStrict(envelope.ciphertext, "Invalid envelope ciphertext");
  const additionalData =
    envelope.header.version === ENVELOPE_VERSION
      ? buildV2AdditionalData(envelope.header)
      : toExactArrayBuffer(LEGACY_AAD);
  const plaintext = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: toExactArrayBuffer(iv), additionalData },
      key,
      toExactArrayBuffer(ciphertext),
    ),
  );
  return { plaintext, header: envelope.header, metadataAuthenticated: Boolean(envelope.metadataAuthenticated) };
}

export function inspectEnvelope(blob: string): EnvelopeInspectResult {
  const envelope = parseEnvelope(blob);
  return {
    header: envelope.header,
    ciphertextBytes: decodeBase64UrlStrict(envelope.ciphertext, "Invalid envelope ciphertext").byteLength,
    metadataAuthenticated: Boolean(envelope.metadataAuthenticated),
  };
}

function parseEnvelope(blob: string): Envelope {
  const normalized = normalizeEnvelopeBlob(blob);
  const prefix = normalized.startsWith(`${ENVELOPE_PREFIX}.`)
    ? ENVELOPE_PREFIX
    : normalized.startsWith(`${LEGACY_ENVELOPE_PREFIX}.`)
      ? LEGACY_ENVELOPE_PREFIX
      : null;
  if (!prefix) {
    throw new Error("Unsupported envelope prefix");
  }
  const encoded = normalized.slice(`${prefix}.`.length);
  const envelopeBytes = decodeBase64UrlStrict(encoded, "Invalid envelope format");
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytesToUtf8(envelopeBytes)) as unknown;
  } catch {
    throw new Error("Invalid envelope format");
  }
  return normalizeEnvelope(parsed, prefix === ENVELOPE_PREFIX ? ENVELOPE_VERSION : LEGACY_ENVELOPE_VERSION);
}

function normalizeEnvelope(value: unknown, expectedVersion: number): Envelope {
  if (!isRecord(value)) {
    throw new Error("Invalid envelope format");
  }
  const header = normalizeEnvelopeHeader(value.header, expectedVersion);
  if (typeof value.ciphertext !== "string") {
    throw new Error("Invalid envelope ciphertext");
  }
  const ciphertext = decodeBase64UrlStrict(value.ciphertext, "Invalid envelope ciphertext");
  if (ciphertext.byteLength < MIN_CIPHERTEXT_BYTES) {
    throw new Error("Invalid envelope ciphertext");
  }
  return {
    header,
    ciphertext: value.ciphertext,
    metadataAuthenticated: expectedVersion === ENVELOPE_VERSION,
  };
}

function normalizeEnvelopeHeader(value: unknown, expectedVersion: number): EnvelopeHeader {
  if (!isRecord(value)) {
    throw new Error("Invalid envelope header");
  }
  if (value.version !== expectedVersion || value.algo !== "AES-GCM") {
    throw new Error("Unsupported envelope version");
  }
  if (typeof value.iv !== "string") {
    throw new Error("Invalid envelope iv");
  }
  const iv = decodeBase64UrlStrict(value.iv, "Invalid envelope iv");
  if (iv.byteLength !== ENVELOPE_IV_BYTES) {
    throw new Error("Invalid envelope iv");
  }
  return {
    version: expectedVersion,
    algo: "AES-GCM",
    iv: value.iv,
    mime: expectedVersion === ENVELOPE_VERSION ? normalizeEnvelopeMime(value.mime) : "application/octet-stream",
    name: expectedVersion === ENVELOPE_VERSION ? sanitizeEnvelopeFilename(value.name) : undefined,
    kdf: normalizeEnvelopeKdf(value.kdf),
  };
}

function normalizeEnvelopeKdf(value: unknown): EnvelopeHeader["kdf"] {
  if (!isRecord(value) || value.name !== "PBKDF2" || typeof value.salt !== "string") {
    throw new Error("Unsupported envelope kdf");
  }
  const iterations = value.iterations;
  if (typeof iterations !== "number" || !Number.isInteger(iterations) || iterations < MIN_KDF_ITERATIONS || iterations > MAX_KDF_ITERATIONS) {
    throw new Error("Invalid envelope kdf iterations");
  }
  const salt = decodeBase64UrlStrict(value.salt, "Invalid envelope kdf salt");
  if (salt.byteLength < MIN_SALT_BYTES || salt.byteLength > MAX_SALT_BYTES) {
    throw new Error("Invalid envelope kdf salt");
  }
  if (value.hash !== "SHA-256" && value.hash !== "SHA-512") {
    throw new Error("Unsupported envelope kdf hash");
  }
  return {
    name: "PBKDF2",
    iterations,
    hash: value.hash as KdfHash,
    salt: value.salt,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function buildV2AdditionalData(header: EnvelopeHeader): ArrayBuffer {
  return toExactArrayBuffer(utf8ToBytes(stableStringify({ domain: V2_AAD_DOMAIN, header: canonicalAuthenticatedHeader(header) })));
}

function canonicalAuthenticatedHeader(header: EnvelopeHeader) {
  return {
    version: ENVELOPE_VERSION,
    algo: header.algo,
    kdf: {
      name: header.kdf.name,
      hash: header.kdf.hash,
      iterations: header.kdf.iterations,
      salt: header.kdf.salt,
    },
    iv: header.iv,
    mime: normalizeEnvelopeMime(header.mime),
    name: sanitizeEnvelopeFilename(header.name) ?? "",
  };
}

function normalizeEnvelopeMime(value: unknown): string {
  if (typeof value !== "string") return "application/octet-stream";
  const normalized = value.trim().toLowerCase();
  if (!normalized || normalized.length > 120 || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    return "application/octet-stream";
  }
  const allowed = new Set([
    "application/json",
    "application/octet-stream",
    "application/pdf",
    "application/zip",
    "image/gif",
    "image/jpeg",
    "image/png",
    "image/webp",
    "text/csv",
    "text/html",
    "text/markdown",
    "text/plain",
  ]);
  if (allowed.has(normalized)) return normalized;
  if (normalized.startsWith("text/") && /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/u.test(normalized)) {
    return normalized;
  }
  return "application/octet-stream";
}

function sanitizeEnvelopeFilename(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  let normalized = value.normalize("NFC").slice(0, MAX_HEADER_STRING_BYTES);
  normalized = normalized.replace(/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/gu, "");
  normalized = normalized.replace(/\\/g, "/").replace(/^[a-zA-Z]:\/+/u, "");
  const parts = normalized
    .split("/")
    .map((part) => part.trim())
    .filter((part) => part && part !== "." && part !== "..");
  normalized = parts.at(-1) ?? "";
  normalized = normalized.replace(/[<>:"|?*]/g, "-").replace(/\s+/g, " ").trim();
  normalized = normalized.replace(/[. ]+$/u, "").replace(/^[. ]+/u, "");
  if (!normalized) return undefined;
  if (/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/iu.test(normalized)) {
    normalized = `file-${normalized}`;
  }
  if (normalized.length > MAX_FILENAME_CHARS) {
    const dot = normalized.lastIndexOf(".");
    const extension = dot > 0 && normalized.length - dot <= 16 ? normalized.slice(dot) : "";
    normalized = `${normalized.slice(0, MAX_FILENAME_CHARS - extension.length)}${extension}`;
  }
  return normalized || undefined;
}
