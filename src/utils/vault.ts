import { getVaultBackend, getAllValues, getValue, putValue, removeValue, replaceVaultStores } from "./storage.js";
import { decodeBase64UrlStrict, fromBase64Url, toBase64Url, utf8ToBytes, bytesToUtf8, randomBytes } from "./encoding.js";
import { MAX_KDF_ITERATIONS, decryptText, encryptText } from "./cryptoEnvelope.js";
import type { IntegritySignature } from "./integrity.js";
import { SnapshotIntegrityError, createSnapshotIntegrity, verifySnapshotIntegrity } from "./snapshotIntegrity.js";
import { INPUT_LIMITS, readFileTextWithLimit } from "./inputLimits.js";

const LEGACY_AAD = utf8ToBytes("nullid:vault:v1");
const NOTE_AAD_VERSION = 3;
const VAULT_EXPORT_SCHEMA_VERSION = 2;
const MIN_VAULT_ITERATIONS = 10_000;
const MIN_VAULT_SALT_BYTES = 8;
const MAX_VAULT_SALT_BYTES = 64;
const VAULT_IV_BYTES = 12;
const MIN_VAULT_CIPHERTEXT_BYTES = 16;
const MAX_VAULT_NOTES = 1000;
const MAX_VAULT_NOTE_ID_CHARS = 128;
const MAX_DECRYPTED_TITLE_CHARS = 240;
const MAX_DECRYPTED_BODY_CHARS = INPUT_LIMITS.plaintextChars;
const MAX_DECRYPTED_TAGS = 32;
const MAX_DECRYPTED_TAG_CHARS = 64;

interface VaultMeta {
  salt: string;
  iterations: number;
  version?: number;
  lockedAt?: number;
}

export type VaultNote = {
  id: string;
  ciphertext: string;
  iv: string;
  createdAt: number;
  updatedAt: number;
  version: typeof NOTE_AAD_VERSION;
};

type VaultCanary = {
  ciphertext: string;
  iv: string;
};

type VaultSnapshotData = {
  meta: VaultMeta | null;
  notes: VaultNote[];
  canary: VaultCanary | null;
};

type VaultSnapshotExport = {
  schemaVersion: number;
  kind: "vault";
  exportedAt: string;
  vault: VaultSnapshotData;
  integrity: {
    noteCount: number;
    payloadHash: string;
  };
  signature?: IntegritySignature;
};

export interface VaultExportOptions {
  signingPassphrase?: string;
  keyHint?: string;
}

export interface VaultImportOptions {
  verificationPassphrase?: string;
}

export interface VaultImportResult {
  noteCount: number;
  signed: boolean;
  verified: boolean;
  legacy: false;
}

export interface VaultSnapshotDescriptor {
  schemaVersion: number;
  kind: string;
  noteCount: number;
  signed: boolean;
  keyHint?: string;
  legacy: boolean;
}

type VaultVerificationState = "unsigned" | "integrity-checked" | "verified" | "verification-required" | "mismatch" | "invalid";

export interface VaultVerificationResult extends VaultSnapshotDescriptor {
  verificationState: VaultVerificationState;
  verificationLabel: string;
  trustBasis: string[];
  verifiedChecks: string[];
  unverifiedChecks: string[];
  warnings: string[];
  exportedAt?: string;
  noteIds: string[];
  failure?: string;
}

async function ensureVaultMeta(): Promise<VaultMeta> {
  const backend = await getVaultBackend();
  const existing = await getValue<VaultMeta & { lockedAt: number }>(backend, "meta", "meta");
  if (existing) {
    const normalized = normalizeMeta(existing);
    const resolved: VaultMeta = {
      salt: normalized.salt,
      iterations: normalized.iterations,
      version: normalized.version ?? 1,
      lockedAt: normalized.lockedAt ?? Date.now(),
    };
    if (
      existing.version !== resolved.version ||
      existing.lockedAt !== resolved.lockedAt ||
      existing.salt !== resolved.salt ||
      existing.iterations !== resolved.iterations
    ) {
      await putValue(backend, "meta", "meta", resolved);
    }
    return resolved;
  }
  const salt = toBase64Url(randomBytes(16));
  const meta: VaultMeta = { salt, iterations: 200_000, version: 1, lockedAt: Date.now() };
  await putValue(backend, "meta", "meta", meta);
  return meta;
}

export async function unlockVault(passphrase: string): Promise<CryptoKey> {
  const meta = await ensureVaultMeta();
  const key = await deriveVaultKey(passphrase, meta);
  const backend = await getVaultBackend();
  const canary = await getValue<{ ciphertext: string; iv: string }>(backend, "canary", "canary");
  if (canary) {
    await verifyCanary(key, canary.ciphertext, canary.iv);
  } else {
    await storeCanary(key);
  }
  return key;
}

async function deriveVaultKey(passphrase: string, meta: VaultMeta) {
  const salt = decodeVaultSalt(meta.salt);
  const keyMaterial = await crypto.subtle.importKey("raw", utf8ToBytes(passphrase).buffer as ArrayBuffer, "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt.buffer as ArrayBuffer, iterations: meta.iterations, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function storeCanary(key: CryptoKey) {
  const iv = randomBytes(12);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv.buffer as ArrayBuffer, additionalData: exactArrayBuffer(LEGACY_AAD) },
      key,
      exactArrayBuffer(utf8ToBytes("vault-canary")),
    ),
  );
  const backend = await getVaultBackend();
  await putValue(backend, "canary", "canary", { ciphertext: toBase64Url(ciphertext), iv: toBase64Url(iv) });
}

async function verifyCanary(key: CryptoKey, payload: string, ivText: string) {
  const normalized = normalizeCanary({ ciphertext: payload, iv: ivText });
  const ciphertext = fromBase64Url(normalized.ciphertext);
  const iv = fromBase64Url(normalized.iv);
  await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: exactArrayBuffer(iv), additionalData: exactArrayBuffer(LEGACY_AAD) },
    key,
    exactArrayBuffer(ciphertext),
  );
}

export async function loadNotes(): Promise<VaultNote[]> {
  const backend = await getVaultBackend();
  const all = await getAllValues<unknown>(backend, "notes");
  return all.map((record, index) => normalizeNote(record, index)).sort((a, b) => b.updatedAt - a.updatedAt);
}

export async function saveNote(
  key: CryptoKey,
  id: string,
  title: string,
  body: string,
  metadata: { createdAt: number; tags: string[] },
) {
  const now = Date.now();
  validateVaultNoteId(id, "Invalid vault note id");
  validateDecryptedNotePayload({
    title,
    body,
    tags: metadata.tags,
    createdAt: metadata.createdAt,
    updatedAt: now,
  });
  const backend = await getVaultBackend();
  const iv = randomBytes(12);
  const plaintext = { id, title, body, tags: metadata.tags, createdAt: metadata.createdAt, updatedAt: now };
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: exactArrayBuffer(iv), additionalData: noteAdditionalData(id, NOTE_AAD_VERSION, now) },
      key,
      exactArrayBuffer(utf8ToBytes(JSON.stringify(plaintext))),
    ),
  );
  const note: VaultNote = {
    id,
    ciphertext: toBase64Url(ciphertext),
    iv: toBase64Url(iv),
    createdAt: metadata.createdAt,
    updatedAt: now,
    version: NOTE_AAD_VERSION,
  };
  await putValue(backend, "notes", id, note);
}

export async function deleteNote(id: string) {
  const backend = await getVaultBackend();
  await removeValue(backend, "notes", id);
}

export async function decryptNote(
  key: CryptoKey,
  note: VaultNote,
): Promise<{ title: string; body: string; tags?: string[]; createdAt?: number; updatedAt?: number }> {
  const iv = decodeVaultIv(note.iv, "Invalid stored vault note iv");
  const ciphertext = decodeVaultCiphertext(note.ciphertext, "Invalid stored vault note ciphertext");
  const bytes = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: exactArrayBuffer(iv), additionalData: noteAdditionalData(note.id, note.version, note.updatedAt) },
      key,
      exactArrayBuffer(ciphertext),
    ),
  );
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytesToUtf8(bytes)) as unknown;
  } catch {
    throw new Error("Invalid decrypted vault note JSON");
  }
  const payload = validateDecryptedNotePayload(parsed);
  if (!isRecord(parsed) || parsed.id !== note.id) {
    throw new Error("Invalid decrypted vault note id");
  }
  if (payload.createdAt !== note.createdAt) {
    throw new Error("Invalid decrypted vault note createdAt");
  }
  if (payload.updatedAt !== note.updatedAt) {
    throw new Error("Invalid decrypted vault note timestamp");
  }
  return payload;
}

export async function exportVault(options?: VaultExportOptions): Promise<Blob> {
  const snapshot = await readVaultSnapshot(options);
  return new Blob([snapshot], { type: "application/json" });
}

async function readVaultSnapshot(options?: VaultExportOptions): Promise<string> {
  const snapshot = await buildVaultSnapshot(options);
  return JSON.stringify(snapshot, null, 2);
}

async function buildVaultSnapshot(options?: VaultExportOptions): Promise<VaultSnapshotExport> {
  const vault = await readVaultSnapshotData();
  const exportedAt = new Date().toISOString();
  const payload = {
    schemaVersion: VAULT_EXPORT_SCHEMA_VERSION,
    exportedAt,
    vault,
  };
  const { integrity, signature } = await createSnapshotIntegrity(payload, "noteCount", vault.notes.length, options);
  const snapshot: VaultSnapshotExport = {
    schemaVersion: VAULT_EXPORT_SCHEMA_VERSION,
    kind: "vault",
    exportedAt,
    vault,
    integrity,
  };
  if (signature) {
    snapshot.signature = signature;
  }
  return snapshot;
}

async function readVaultSnapshotData(): Promise<VaultSnapshotData> {
  const backend = await getVaultBackend();
  const notes = (await getAllValues<unknown>(backend, "notes"))
    .map((note, index) => normalizeNote(note, index))
    .sort((a, b) => a.id.localeCompare(b.id));
  const metaRaw = await getValue<unknown>(backend, "meta", "meta");
  const canaryRaw = await getValue<unknown>(backend, "canary", "canary");
  const meta = metaRaw == null ? null : normalizeMeta(metaRaw);
  const canary = canaryRaw == null ? null : normalizeCanary(canaryRaw);
  return { meta, notes, canary };
}

export async function importVault(file: File, options?: VaultImportOptions): Promise<VaultImportResult> {
  const text = await readFileTextWithLimit(file, { label: "Vault snapshot", maxBytes: INPUT_LIMITS.jsonImportBytes });
  const parsed = JSON.parse(text) as unknown;
  const resolved = await resolveImportedSnapshot(parsed, options);
  await applySnapshot(resolved.snapshot);
  return resolved.result;
}

export function describeVaultPayload(input: unknown): VaultSnapshotDescriptor {
  if (!isRecord(input)) {
    return { schemaVersion: 0, kind: "unknown", noteCount: 0, signed: false, legacy: false };
  }
  const schemaVersion = typeof input.schemaVersion === "number" ? input.schemaVersion : 0;
  const noteCount =
    isRecord(input.integrity) && typeof input.integrity.noteCount === "number" ? Math.max(0, Math.floor(input.integrity.noteCount)) : 0;
  const signature = isRecord(input.signature) ? input.signature : undefined;
  return {
    schemaVersion,
    kind: typeof input.kind === "string" ? input.kind : "vault",
    noteCount,
    signed: Boolean(signature),
    keyHint: typeof signature?.keyHint === "string" ? signature.keyHint : undefined,
    legacy: false,
  };
}

export async function verifyVaultPayload(input: unknown, options?: VaultImportOptions): Promise<VaultVerificationResult> {
  const descriptor = describeVaultPayload(input);
  if (!isRecord(input)) {
    return invalidVaultResult(descriptor, "Invalid vault snapshot payload");
  }

  const exportedAt = typeof input.exportedAt === "string" ? input.exportedAt : undefined;
  if (input.schemaVersion === VAULT_EXPORT_SCHEMA_VERSION) {
    const noteIds = sampleVaultNoteIds(input);
    try {
      const resolved = await validateSignedVaultSnapshot(input, options);
      return {
        ...descriptor,
        verificationState: resolved.signed ? "verified" : "integrity-checked",
        verificationLabel: resolved.signed ? "HMAC verified" : "Integrity checked",
        trustBasis: resolved.signed
          ? ["Shared-secret HMAC verification succeeded.", "Payload hash and note count matched the embedded metadata."]
          : ["Payload hash and note count matched the embedded integrity metadata.", "No sender identity is asserted."],
        verifiedChecks: [
          `Vault note count matched (${resolved.snapshot.notes.length}).`,
          "Payload hash matched the embedded integrity metadata.",
        ],
        unverifiedChecks: resolved.signed ? ["Shared-secret verification proves tamper detection for holders of the same secret, not public-key identity."] : [],
        warnings: [],
        exportedAt,
        noteIds,
      };
    } catch (error) {
      return vaultErrorResult(descriptor, error, exportedAt, noteIds);
    }
  }

  return invalidVaultResult(descriptor, `Unsupported vault snapshot schema version: ${String(input.schemaVersion ?? "missing")}`, exportedAt);
}

export async function exportVaultEncrypted(passphrase: string, options?: VaultExportOptions): Promise<Blob> {
  const snapshot = await readVaultSnapshot(options);
  const envelope = await encryptText(passphrase, snapshot);
  return new Blob([envelope], { type: "text/plain" });
}

export async function importVaultEncrypted(
  file: File,
  passphrase: string,
  options?: VaultImportOptions,
): Promise<VaultImportResult> {
  const payload = await readFileTextWithLimit(file, { label: "Encrypted vault snapshot", maxBytes: INPUT_LIMITS.envelopeFileBytes });
  const snapshotJson = await decryptText(passphrase, payload);
  const snapshot = JSON.parse(snapshotJson) as unknown;
  const resolved = await resolveImportedSnapshot(snapshot, options);
  await applySnapshot(resolved.snapshot);
  return resolved.result;
}

async function resolveImportedSnapshot(
  payload: unknown,
  options?: VaultImportOptions,
): Promise<{ snapshot: VaultSnapshotData; result: VaultImportResult }> {
  if (!isRecord(payload)) {
    throw new Error("Invalid vault snapshot payload");
  }

  if ("schemaVersion" in payload) {
    if (payload.schemaVersion !== VAULT_EXPORT_SCHEMA_VERSION) {
      throw new Error(`Unsupported vault snapshot schema version: ${String(payload.schemaVersion)}`);
    }
    const resolved = await validateSignedVaultSnapshot(payload, options);
    return {
      snapshot: resolved.snapshot,
      result: {
        noteCount: resolved.snapshot.notes.length,
        signed: resolved.signed,
        verified: resolved.verified,
        legacy: false,
      },
    };
  }

  throw new Error("Unsupported vault snapshot schema version: missing");
}

async function validateSignedVaultSnapshot(
  payload: Record<string, unknown>,
  options?: VaultImportOptions,
): Promise<{ snapshot: VaultSnapshotData; signed: boolean; verified: boolean }> {
  if (payload.kind !== "vault") {
    throw new Error("Invalid vault snapshot kind");
  }
  if (typeof payload.exportedAt !== "string") {
    throw new Error("Invalid vault exportedAt metadata");
  }
  if (!isRecord(payload.vault) || !isRecord(payload.integrity)) {
    throw new Error("Vault integrity metadata missing");
  }

  const snapshot = normalizeSnapshotData(payload.vault, { requireNotesArray: true, requireCanaryWhenNotesExist: true });
  const { signed, verified } = await verifySnapshotIntegrity({
    subject: "Vault snapshot",
    countKey: "noteCount",
    actualCount: snapshot.notes.length,
    payload: {
      schemaVersion: VAULT_EXPORT_SCHEMA_VERSION,
      exportedAt: payload.exportedAt,
      vault: snapshot,
    },
    integrity: payload.integrity,
    signature: payload.signature,
    verificationPassphrase: options?.verificationPassphrase,
    missingIntegrityMessage: "Vault integrity metadata missing",
    invalidIntegrityMessage: "Invalid vault integrity metadata",
    countMismatchMessage: "Vault integrity mismatch (note count)",
    hashMismatchMessage: "Vault integrity mismatch (hash)",
    invalidSignatureMessage: "Invalid vault signature metadata",
    verificationRequiredMessage: "Vault snapshot is signed; verification passphrase required",
    verificationFailedMessage: "Vault signature verification failed",
  });

  return { snapshot, signed, verified };
}

function normalizeSnapshotData(
  payload: Record<string, unknown>,
  options: { requireNotesArray?: boolean; requireCanaryWhenNotesExist?: boolean } = {},
): VaultSnapshotData {
  if (options.requireNotesArray && !Array.isArray(payload.notes)) {
    throw new Error("Invalid vault notes payload");
  }
  const notesRaw = Array.isArray(payload.notes) ? payload.notes : [];
  if (notesRaw.length > MAX_VAULT_NOTES) {
    throw new Error(`Vault note count exceeds ${MAX_VAULT_NOTES}`);
  }
  const notes = notesRaw.map((note, index) => normalizeNote(note, index));
  validateImportedNoteIds(notes);
  notes.sort((a, b) => a.id.localeCompare(b.id));
  const meta = payload.meta == null ? null : normalizeMeta(payload.meta);
  const canary = payload.canary == null ? null : normalizeCanary(payload.canary);
  if (options.requireCanaryWhenNotesExist && notes.length > 0) {
    if (!canary) {
      throw new Error("Vault snapshot requires a valid vault canary");
    }
    if (!meta) {
      throw new Error("Vault notes require valid vault meta");
    }
  }
  if (options.requireCanaryWhenNotesExist && notes.length === 0 && Boolean(meta) !== Boolean(canary)) {
    throw new Error("Vault empty snapshot must be either uninitialized or include both meta and canary");
  }
  return { meta, notes, canary };
}

function normalizeMeta(value: unknown): VaultMeta {
  if (!isRecord(value)) {
    throw new Error("Invalid vault meta payload");
  }
  const salt = value.salt;
  const iterations = value.iterations;
  const version = value.version;
  const lockedAt = value.lockedAt;
  if (typeof salt !== "string") {
    throw new Error("Invalid vault meta salt");
  }
  const saltBytes = decodeVaultSalt(salt);
  if (saltBytes.byteLength < MIN_VAULT_SALT_BYTES || saltBytes.byteLength > MAX_VAULT_SALT_BYTES) {
    throw new Error("Invalid vault meta salt");
  }
  if (typeof iterations !== "number" || !Number.isInteger(iterations) || iterations < MIN_VAULT_ITERATIONS || iterations > MAX_KDF_ITERATIONS) {
    throw new Error("Invalid vault meta iterations");
  }
  if (version !== undefined && version !== null && (typeof version !== "number" || !Number.isInteger(version) || version < 1)) {
    throw new Error("Invalid vault meta version");
  }
  if (lockedAt !== undefined && lockedAt !== null && (typeof lockedAt !== "number" || !Number.isFinite(lockedAt) || lockedAt <= 0)) {
    throw new Error("Invalid vault meta lockedAt");
  }
  const meta: VaultMeta = { salt, iterations };
  if (typeof version === "number") meta.version = version;
  if (typeof lockedAt === "number") meta.lockedAt = lockedAt;
  return meta;
}

function normalizeCanary(value: unknown): VaultCanary {
  if (!isRecord(value) || typeof value.ciphertext !== "string" || typeof value.iv !== "string") {
    throw new Error("Invalid vault canary payload");
  }
  decodeVaultCiphertext(value.ciphertext, "Invalid vault canary payload");
  decodeVaultIv(value.iv, "Invalid vault canary payload");
  return {
    ciphertext: value.ciphertext,
    iv: value.iv,
  };
}

function normalizeNote(value: unknown, index: number): VaultNote {
  if (!isRecord(value)) {
    throw new Error(`Invalid vault note at index ${index}`);
  }
  const id = value.id;
  const ciphertext = value.ciphertext;
  const iv = value.iv;
  const updatedAt = value.updatedAt;
  const createdAt = value.createdAt;
  const version = value.version;
  validateVaultNoteId(id, `Invalid vault note id at index ${index}`);
  if (typeof ciphertext !== "string") {
    throw new Error(`Invalid vault note ciphertext at index ${index}`);
  }
  decodeVaultCiphertext(ciphertext, `Invalid vault note ciphertext at index ${index}`);
  if (typeof iv !== "string") {
    throw new Error(`Invalid vault note iv at index ${index}`);
  }
  decodeVaultIv(iv, `Invalid vault note iv at index ${index}`);
  if (typeof updatedAt !== "number" || !Number.isFinite(updatedAt) || updatedAt <= 0) {
    throw new Error(`Invalid vault note timestamp at index ${index}`);
  }
  if (typeof createdAt !== "number" || !Number.isFinite(createdAt) || createdAt <= 0) {
    throw new Error(`Invalid vault note createdAt at index ${index}`);
  }
  if (version !== NOTE_AAD_VERSION) {
    const label = version === 1 || version === 2 ? `v${version}` : String(version ?? "missing");
    throw new Error(`Unsupported canonical vault note version at index ${index}: ${label}`);
  }
  const note: VaultNote = {
    id,
    ciphertext,
    iv,
    createdAt: Number(createdAt),
    updatedAt: Number(updatedAt),
    version: NOTE_AAD_VERSION,
  };
  return note;
}

function validateImportedNoteIds(notes: VaultNote[]) {
  const exact = new Set<string>();
  const caseFolded = new Map<string, string>();
  const unicodeNormalized = new Map<string, string>();
  const conservative = new Map<string, string>();
  notes.forEach((note) => {
    if (exact.has(note.id)) {
      throw new Error(`Duplicate vault note id: ${note.id}`);
    }
    exact.add(note.id);
    const caseKey = note.id.toLocaleLowerCase("en-US");
    const caseOwner = caseFolded.get(caseKey);
    if (caseOwner && caseOwner !== note.id) {
      throw new Error(`Duplicate vault note id after case folding: ${note.id}`);
    }
    caseFolded.set(caseKey, note.id);
    const unicodeKey = note.id.normalize("NFC");
    const unicodeOwner = unicodeNormalized.get(unicodeKey);
    if (unicodeOwner && unicodeOwner !== note.id) {
      throw new Error(`Duplicate vault note id after Unicode normalization: ${note.id}`);
    }
    unicodeNormalized.set(unicodeKey, note.id);
    const conservativeKey = note.id.normalize("NFC").toLocaleLowerCase("en-US");
    const conservativeOwner = conservative.get(conservativeKey);
    if (conservativeOwner && conservativeOwner !== note.id) {
      throw new Error(`Duplicate vault note id after case/Unicode normalization: ${note.id}`);
    }
    conservative.set(conservativeKey, note.id);
  });
}

function validateVaultNoteId(value: unknown, message: string): asserts value is string {
  if (typeof value !== "string" || !value.trim() || value.length > MAX_VAULT_NOTE_ID_CHARS || value.includes("\0")) {
    throw new Error(message);
  }
}

function validateDecryptedNotePayload(
  value: unknown,
): { title: string; body: string; tags?: string[]; createdAt: number; updatedAt: number } {
  if (!isRecord(value)) {
    throw new Error("Invalid decrypted vault note payload");
  }
  const { title, body, tags, createdAt, updatedAt } = value;
  if (typeof title !== "string" || title.length > MAX_DECRYPTED_TITLE_CHARS) {
    throw new Error("Invalid decrypted vault note title");
  }
  if (typeof body !== "string" || body.length > MAX_DECRYPTED_BODY_CHARS) {
    throw new Error("Invalid decrypted vault note body");
  }
  if (tags !== undefined) {
    if (!Array.isArray(tags) || tags.length > MAX_DECRYPTED_TAGS) {
      throw new Error("Invalid decrypted vault note tags");
    }
    tags.forEach((tag) => {
      if (typeof tag !== "string" || tag.length > MAX_DECRYPTED_TAG_CHARS || tag.includes("\0")) {
        throw new Error("Invalid decrypted vault note tags");
      }
    });
  }
  if (typeof createdAt !== "number" || !Number.isFinite(createdAt) || createdAt <= 0) {
    throw new Error("Invalid decrypted vault note createdAt");
  }
  if (typeof updatedAt !== "number" || !Number.isFinite(updatedAt) || updatedAt <= 0) {
    throw new Error("Invalid decrypted vault note updatedAt");
  }
  return {
    title,
    body,
    tags: tags === undefined ? undefined : [...tags],
    createdAt,
    updatedAt,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function decodeVaultSalt(value: string): Uint8Array {
  return decodeBase64UrlStrict(value, "Invalid vault meta salt");
}

function decodeVaultIv(value: string, errorMessage: string): Uint8Array {
  const bytes = decodeBase64UrlStrict(value, errorMessage);
  if (bytes.byteLength !== VAULT_IV_BYTES) {
    throw new Error(errorMessage);
  }
  return bytes;
}

function decodeVaultCiphertext(value: string, errorMessage: string): Uint8Array {
  const bytes = decodeBase64UrlStrict(value, errorMessage);
  if (bytes.byteLength < MIN_VAULT_CIPHERTEXT_BYTES) {
    throw new Error(errorMessage);
  }
  return bytes;
}

function noteAdditionalData(noteId: string, version?: number, updatedAt?: number): ArrayBuffer {
  if (version === NOTE_AAD_VERSION) {
    if (typeof updatedAt !== "number" || !Number.isFinite(updatedAt) || updatedAt <= 0) {
      throw new Error("Invalid vault note timestamp");
    }
    return exactArrayBuffer(utf8ToBytes(`nullid:vault:note:v${NOTE_AAD_VERSION}:${noteId}:${updatedAt}`));
  }
  throw new Error(`Unsupported canonical vault note version: ${String(version ?? "missing")}`);
}

function exactArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

async function applySnapshot(snapshot: VaultSnapshotData) {
  const backend = await getVaultBackend();
  await replaceVaultStores(backend, {
    meta: snapshot.meta ? { ...snapshot.meta, lockedAt: Date.now() } : null,
    canary: snapshot.canary,
    notes: snapshot.notes.map((note) => ({ id: note.id, value: note })),
  });
}

function invalidVaultResult(descriptor: VaultSnapshotDescriptor, failure: string, exportedAt?: string): VaultVerificationResult {
  return {
    ...descriptor,
    verificationState: "invalid",
    verificationLabel: "Invalid",
    trustBasis: ["NullID could not validate the structure of this vault snapshot payload."],
    verifiedChecks: [],
    unverifiedChecks: ["No integrity or authenticity guarantees could be established."],
    warnings: [failure],
    exportedAt,
    noteIds: [],
    failure,
  };
}

function vaultErrorResult(descriptor: VaultSnapshotDescriptor, error: unknown, exportedAt?: string, noteIds: string[] = []): VaultVerificationResult {
  const failure = error instanceof Error ? error.message : "Vault verification failed";
  if (error instanceof SnapshotIntegrityError) {
    if (error.code === "verification-required") {
      return {
        ...descriptor,
        verificationState: "verification-required",
        verificationLabel: "Verification required",
        trustBasis: ["Shared-secret HMAC metadata is present."],
        verifiedChecks: [],
        unverifiedChecks: ["A verification passphrase is required before authenticity can be checked."],
        warnings: descriptor.keyHint ? [`Expected key hint: ${descriptor.keyHint}`] : [],
        exportedAt,
        noteIds,
        failure,
      };
    }
    if (error.code === "verification-failed" || error.code === "integrity-count-mismatch" || error.code === "integrity-hash-mismatch") {
      return {
        ...descriptor,
        verificationState: "mismatch",
        verificationLabel: "Mismatch",
        trustBasis: ["Vault integrity metadata was present, but verification did not succeed."],
        verifiedChecks: [],
        unverifiedChecks: ["The payload may be tampered, incomplete, or paired with the wrong shared secret."],
        warnings: [failure],
        exportedAt,
        noteIds,
        failure,
      };
    }
  }
  return invalidVaultResult(descriptor, failure, exportedAt);
}

function sampleVaultNoteIds(input: unknown): string[] {
  if (!isRecord(input)) return [];
  const container = isRecord(input.vault) ? input.vault : input;
  const notes = Array.isArray(container.notes) ? container.notes : [];
  return notes
    .filter((note): note is { id: string } => isRecord(note) && typeof note.id === "string" && note.id.trim().length > 0)
    .map((note) => note.id)
    .slice(0, 6);
}
