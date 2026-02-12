import { fromBase64Url, toBase64Url, utf8ToBytes, bytesToUtf8, randomBytes } from "./encoding.js";

export const ENVELOPE_VERSION = 1;
export const ENVELOPE_PREFIX = "NULLID:ENC:1";
const AAD = utf8ToBytes("nullid:enc:v1");
const MIN_KDF_ITERATIONS = 100_000;
const MAX_KDF_ITERATIONS = 2_000_000;
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

export interface Envelope {
  header: EnvelopeHeader;
  ciphertext: string;
}

export interface EnvelopeInspectResult {
  header: EnvelopeHeader;
  ciphertextBytes: number;
}

export interface DerivedKey {
  key: CryptoKey;
  salt: Uint8Array;
}

export interface KdfOptions {
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

export function resolveKdfOptions(profile?: KdfProfile, overrides?: KdfOptions): ResolvedKdf {
  const fromProfile = profile ? KDF_PROFILES[profile] : KDF_PROFILES.compat;
  return {
    iterations: clampIterations(overrides?.iterations ?? fromProfile.iterations),
    hash: normalizeHash(overrides?.hash ?? fromProfile.hash),
  };
}

export async function deriveKey(passphrase: string, salt?: Uint8Array, options?: KdfOptions): Promise<DerivedKey> {
  const resolved = resolveKdfOptions(undefined, options);
  const saltBytes = salt ?? randomBytes(16);
  const keyMaterial = await crypto.subtle.importKey("raw", utf8ToBytes(passphrase).buffer as ArrayBuffer, "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: saltBytes.buffer as ArrayBuffer,
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
  const iv = randomBytes(12);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv.buffer as ArrayBuffer, additionalData: AAD.buffer as ArrayBuffer },
      key,
      bytes.buffer as ArrayBuffer,
    ),
  );
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
  if (options?.mime) header.mime = options.mime;
  if (options?.name) header.name = options.name;

  const payload: Envelope = {
    header,
    ciphertext: toBase64Url(ciphertext),
  };

  return { blob: `${ENVELOPE_PREFIX}.${toBase64Url(utf8ToBytes(JSON.stringify(payload)))}`, header, ciphertext };
}

export async function decryptBlob(passphrase: string, blob: string): Promise<{ plaintext: Uint8Array; header: EnvelopeHeader }> {
  const envelope = parseEnvelope(blob);
  if (envelope.header.version !== ENVELOPE_VERSION || envelope.header.algo !== "AES-GCM") {
    throw new Error("Unsupported envelope version");
  }
  if (envelope.header.kdf?.name !== "PBKDF2" || typeof envelope.header.kdf.salt !== "string") {
    throw new Error("Unsupported envelope kdf");
  }
  const salt = fromBase64Url(envelope.header.kdf.salt);
  const { key } = await deriveKey(passphrase, salt, {
    iterations: clampIterations(envelope.header.kdf.iterations),
    hash: normalizeHash(envelope.header.kdf.hash),
  });
  const iv = fromBase64Url(envelope.header.iv);
  const ciphertext = fromBase64Url(envelope.ciphertext);
  const plaintext = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv.buffer as ArrayBuffer, additionalData: AAD.buffer as ArrayBuffer },
      key,
      ciphertext.buffer as ArrayBuffer,
    ),
  );
  return { plaintext, header: envelope.header };
}

export function inspectEnvelope(blob: string): EnvelopeInspectResult {
  const envelope = parseEnvelope(blob);
  return {
    header: envelope.header,
    ciphertextBytes: fromBase64Url(envelope.ciphertext).byteLength,
  };
}

function parseEnvelope(blob: string): Envelope {
  const normalized = normalizeEnvelopeBlob(blob);
  if (!normalized.startsWith(`${ENVELOPE_PREFIX}.`)) {
    throw new Error("Unsupported envelope prefix");
  }
  const encoded = normalized.slice(`${ENVELOPE_PREFIX}.`.length);
  const envelopeBytes = fromBase64Url(encoded);
  try {
    return JSON.parse(bytesToUtf8(envelopeBytes)) as Envelope;
  } catch (error) {
    console.error("Envelope parse failed", error);
    throw new Error("Invalid envelope format");
  }
}
