import { fromBase64Url, toBase64Url, utf8ToBytes, bytesToUtf8, randomBytes } from "./encoding.js";

export const ENVELOPE_VERSION = 1;
export const ENVELOPE_PREFIX = "NULLID:ENC:1";
const AAD = utf8ToBytes("nullid:enc:v1");

export interface EnvelopeHeader {
  version: number;
  algo: "AES-GCM";
  kdf: { name: "PBKDF2"; iterations: number; hash: "SHA-256"; salt: string };
  iv: string;
  mime?: string;
  name?: string;
}

export interface Envelope {
  header: EnvelopeHeader;
  ciphertext: string;
}

export interface DerivedKey {
  key: CryptoKey;
  salt: Uint8Array;
}

export async function deriveKey(passphrase: string, salt?: Uint8Array, iterations = 250_000): Promise<DerivedKey> {
  const saltBytes = salt ?? randomBytes(16);
  const keyMaterial = await crypto.subtle.importKey("raw", utf8ToBytes(passphrase).buffer as ArrayBuffer, "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: saltBytes.buffer as ArrayBuffer, iterations, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  return { key, salt: saltBytes };
}

export async function encryptText(passphrase: string, plaintext: string): Promise<string> {
  const data = utf8ToBytes(plaintext);
  const { blob } = await encryptBytes(passphrase, data);
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
  options?: { mime?: string; name?: string },
): Promise<{ blob: string; header: EnvelopeHeader; ciphertext: Uint8Array }> {
  const { key, salt } = await deriveKey(passphrase);
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
      iterations: 250_000,
      hash: "SHA-256",
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
  const normalized = normalizeEnvelopeBlob(blob);
  if (!normalized.startsWith(`${ENVELOPE_PREFIX}.`)) {
    throw new Error("Unsupported envelope prefix");
  }
  const encoded = normalized.slice(`${ENVELOPE_PREFIX}.`.length);
  const envelopeBytes = fromBase64Url(encoded);
  let envelope: Envelope;
  try {
    envelope = JSON.parse(bytesToUtf8(envelopeBytes)) as Envelope;
  } catch (error) {
    console.error("Envelope parse failed", error);
    throw new Error("Invalid envelope format");
  }
  if (envelope.header.version !== ENVELOPE_VERSION || envelope.header.algo !== "AES-GCM") {
    throw new Error("Unsupported envelope version");
  }
  const salt = fromBase64Url(envelope.header.kdf.salt);
  const { key } = await deriveKey(passphrase, salt, envelope.header.kdf.iterations);
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
