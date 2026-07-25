import { decodeBase64UrlStrict, fromBase64Url, randomBytes, toBase64Url } from "./encoding.js";

export interface LocalMfaCredential {
  id: string;
  label?: string;
  createdAt: number;
}

const LOCAL_MFA_LABEL_MAX_LENGTH = 48;
const LOCAL_MFA_ID_MAX_LENGTH = 2048;
const LOCAL_MFA_CREATED_AT_MAX = Number.MAX_SAFE_INTEGER;

export function normalizeLocalMfaCredential(value: unknown): LocalMfaCredential | null {
  if (value === null) return null;
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  const expectedKeys = record.label === undefined ? ["createdAt", "id"] : ["createdAt", "id", "label"];
  if (keys.length !== expectedKeys.length || keys.some((key, index) => key !== expectedKeys[index])) return null;
  if (typeof record.id !== "string" || record.id.length < 1 || record.id.length > LOCAL_MFA_ID_MAX_LENGTH) return null;
  try {
    const bytes = decodeBase64UrlStrict(record.id, "invalid MFA credential id");
    if (bytes.byteLength < 1) return null;
  } catch {
    return null;
  }
  if (
    typeof record.createdAt !== "number" ||
    !Number.isInteger(record.createdAt) ||
    record.createdAt < 0 ||
    record.createdAt > LOCAL_MFA_CREATED_AT_MAX
  ) {
    return null;
  }
  if (record.label !== undefined && (typeof record.label !== "string" || record.label.length < 1 || record.label.length > LOCAL_MFA_LABEL_MAX_LENGTH)) {
    return null;
  }
  return {
    id: record.id,
    ...(record.label === undefined ? {} : { label: record.label }),
    createdAt: record.createdAt,
  };
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

export function isLocalMfaSupported(): boolean {
  if (typeof window === "undefined") return false;
  return Boolean(window.PublicKeyCredential && navigator.credentials);
}

export async function registerLocalMfaCredential(label?: string): Promise<LocalMfaCredential> {
  if (!isLocalMfaSupported()) {
    throw new Error("WebAuthn is not supported in this browser");
  }

  const display = label?.trim().slice(0, LOCAL_MFA_LABEL_MAX_LENGTH) || "NullID vault user";
  const userId = randomBytes(16);
  const challenge = randomBytes(32);

  const created = await navigator.credentials.create({
    publicKey: {
      rp: { name: "NullID Local Vault" },
      user: {
        id: toArrayBuffer(userId),
        name: "nullid-local-user",
        displayName: display,
      },
      challenge: toArrayBuffer(challenge),
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
      ],
      timeout: 60_000,
      authenticatorSelection: {
        userVerification: "preferred",
      },
      attestation: "none",
    },
  });

  if (!(created instanceof PublicKeyCredential)) {
    throw new Error("MFA registration failed");
  }

  const credentialId = toBase64Url(new Uint8Array(created.rawId));
  return {
    id: credentialId,
    label: display,
    createdAt: Date.now(),
  };
}

export async function verifyLocalMfaCredential(credential: LocalMfaCredential): Promise<boolean> {
  if (!isLocalMfaSupported()) {
    throw new Error("WebAuthn is not supported in this browser");
  }

  const challenge = randomBytes(32);
  const credentialId = fromBase64Url(credential.id);
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: toArrayBuffer(challenge),
      allowCredentials: [
        {
          id: toArrayBuffer(credentialId),
          type: "public-key",
        },
      ],
      userVerification: "preferred",
      timeout: 45_000,
    },
  });
  return assertion instanceof PublicKeyCredential;
}
