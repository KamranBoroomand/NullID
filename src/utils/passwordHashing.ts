import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";
import { fromBase64Url, randomBytes, toBase64Url, utf8ToBytes } from "./encoding.js";

const MIN_SALT_BYTES = 8;
const DEFAULT_SALT_BYTES = 16;
const MAX_SALT_BYTES = 64;
const DEFAULT_DERIVED_BITS = 256;

const MIN_PBKDF2_ITERATIONS = 100_000;
const DEFAULT_PBKDF2_ITERATIONS = 600_000;
const MAX_PBKDF2_ITERATIONS = 2_000_000;

const MIN_ARGON2_MEMORY = 8_192;
const DEFAULT_ARGON2_MEMORY = 65_536;
const MAX_ARGON2_MEMORY = 262_144;

const MIN_ARGON2_PASSES = 1;
const DEFAULT_ARGON2_PASSES = 3;
const MAX_ARGON2_PASSES = 8;

const MIN_ARGON2_PARALLELISM = 1;
const DEFAULT_ARGON2_PARALLELISM = 1;
const MAX_ARGON2_PARALLELISM = 4;

export type PasswordHashAlgorithm = "argon2id" | "pbkdf2-sha256" | "sha512" | "sha256";
export type HashSafety = "weak" | "fair" | "strong";

export interface PasswordHashOptions {
  algorithm: PasswordHashAlgorithm;
  saltBytes?: number;
  pbkdf2Iterations?: number;
  argon2Memory?: number;
  argon2Passes?: number;
  argon2Parallelism?: number;
}

export interface PasswordHashChoiceAssessment {
  safety: HashSafety;
  warnings: string[];
}

export interface PasswordHashResult {
  encoded: string;
  algorithm: PasswordHashAlgorithm;
  assessment: PasswordHashChoiceAssessment;
}

export interface ParsedPasswordHash {
  algorithm: PasswordHashAlgorithm;
  salt: Uint8Array;
  digest: Uint8Array;
  pbkdf2Iterations?: number;
  argon2Memory?: number;
  argon2Passes?: number;
  argon2Parallelism?: number;
}

let argon2SupportCache: boolean | null = null;

function clampInt(value: number | undefined, fallback: number, min: number, max: number): number {
  if (!Number.isFinite(value)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(value as number)));
}

function concatBytes(left: Uint8Array, right: Uint8Array): Uint8Array {
  const output = new Uint8Array(left.length + right.length);
  output.set(left, 0);
  output.set(right, left.length);
  return output;
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

function createAssessment(options: PasswordHashOptions): PasswordHashChoiceAssessment {
  const warnings: string[] = [];
  if (options.algorithm === "argon2id") {
    const memory = clampInt(options.argon2Memory, DEFAULT_ARGON2_MEMORY, MIN_ARGON2_MEMORY, MAX_ARGON2_MEMORY);
    const passes = clampInt(options.argon2Passes, DEFAULT_ARGON2_PASSES, MIN_ARGON2_PASSES, MAX_ARGON2_PASSES);
    if (memory < 65_536) warnings.push("Argon2 memory cost is below 64 MiB");
    if (passes < 3) warnings.push("Argon2 passes below recommended minimum (3)");
    return { safety: warnings.length > 0 ? "fair" : "strong", warnings };
  }

  if (options.algorithm === "pbkdf2-sha256") {
    const iterations = clampInt(options.pbkdf2Iterations, DEFAULT_PBKDF2_ITERATIONS, MIN_PBKDF2_ITERATIONS, MAX_PBKDF2_ITERATIONS);
    if (iterations < 300_000) warnings.push("PBKDF2 iterations below 300,000");
    return { safety: warnings.length > 0 ? "fair" : "strong", warnings };
  }

  warnings.push("Fast SHA digests are legacy-only for password storage");
  warnings.push("Prefer Argon2id (or PBKDF2 with high iterations for compatibility)");
  return { safety: "weak", warnings };
}

async function derivePbkdf2(secret: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const keyMaterial = await crypto.subtle.importKey("raw", utf8ToBytes(secret).buffer as ArrayBuffer, "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      iterations,
      salt: salt.buffer as ArrayBuffer,
    },
    keyMaterial,
    DEFAULT_DERIVED_BITS,
  );
  return new Uint8Array(bits);
}

async function deriveArgon2id(
  secret: string,
  salt: Uint8Array,
  options: { memory: number; passes: number; parallelism: number },
): Promise<Uint8Array> {
  const subtle = crypto.subtle as SubtleCrypto & {
    importKey: (
      format: string,
      keyData: BufferSource,
      algorithm: AlgorithmIdentifier,
      extractable: boolean,
      keyUsages: KeyUsage[],
    ) => Promise<CryptoKey>;
    deriveBits: (algorithm: AlgorithmIdentifier, baseKey: CryptoKey, length: number) => Promise<ArrayBuffer>;
  };
  const keyMaterial = await subtle.importKey(
    "raw-secret",
    utf8ToBytes(secret).buffer as ArrayBuffer,
    "Argon2id",
    false,
    ["deriveBits"],
  );
  const bits = await subtle.deriveBits(
    {
      name: "Argon2id",
      nonce: salt.buffer as ArrayBuffer,
      memory: options.memory,
      passes: options.passes,
      parallelism: options.parallelism,
    } as unknown as AlgorithmIdentifier,
    keyMaterial,
    DEFAULT_DERIVED_BITS,
  );
  return new Uint8Array(bits);
}

function deriveShaDigest(secret: string, salt: Uint8Array, algorithm: "sha256" | "sha512"): Uint8Array {
  const payload = concatBytes(salt, utf8ToBytes(secret));
  return algorithm === "sha512" ? sha512(payload) : sha256(payload);
}

export async function supportsArgon2id(): Promise<boolean> {
  if (argon2SupportCache !== null) return argon2SupportCache;
  try {
    const subtle = crypto.subtle as SubtleCrypto & {
      importKey: (
        format: string,
        keyData: BufferSource,
        algorithm: AlgorithmIdentifier,
        extractable: boolean,
        keyUsages: KeyUsage[],
      ) => Promise<CryptoKey>;
      deriveBits: (algorithm: AlgorithmIdentifier, baseKey: CryptoKey, length: number) => Promise<ArrayBuffer>;
    };
    const key = await subtle.importKey("raw-secret", utf8ToBytes("probe"), "Argon2id", false, ["deriveBits"]);
    const salt = randomBytes(16);
    await subtle.deriveBits(
      {
        name: "Argon2id",
        nonce: salt.buffer as ArrayBuffer,
        memory: MIN_ARGON2_MEMORY,
        passes: 1,
        parallelism: 1,
      } as unknown as AlgorithmIdentifier,
      key,
      128,
    );
    argon2SupportCache = true;
  } catch (error) {
    console.info("Argon2id support unavailable", error);
    argon2SupportCache = false;
  }
  return argon2SupportCache;
}

export async function hashPassword(secret: string, options: PasswordHashOptions): Promise<PasswordHashResult> {
  if (!secret) {
    throw new Error("Password is required");
  }
  const saltBytes = clampInt(options.saltBytes, DEFAULT_SALT_BYTES, MIN_SALT_BYTES, MAX_SALT_BYTES);
  const salt = randomBytes(saltBytes);
  const assessment = createAssessment(options);

  if (options.algorithm === "argon2id") {
    if (!(await supportsArgon2id())) {
      throw new Error("Argon2id is not supported in this browser/runtime");
    }
    const memory = clampInt(options.argon2Memory, DEFAULT_ARGON2_MEMORY, MIN_ARGON2_MEMORY, MAX_ARGON2_MEMORY);
    const passes = clampInt(options.argon2Passes, DEFAULT_ARGON2_PASSES, MIN_ARGON2_PASSES, MAX_ARGON2_PASSES);
    const parallelism = clampInt(options.argon2Parallelism, DEFAULT_ARGON2_PARALLELISM, MIN_ARGON2_PARALLELISM, MAX_ARGON2_PARALLELISM);
    const digest = await deriveArgon2id(secret, salt, { memory, passes, parallelism });
    return {
      encoded: `$argon2id$v=19$m=${memory},t=${passes},p=${parallelism}$${toBase64Url(salt)}$${toBase64Url(digest)}`,
      algorithm: options.algorithm,
      assessment,
    };
  }

  if (options.algorithm === "pbkdf2-sha256") {
    const iterations = clampInt(
      options.pbkdf2Iterations,
      DEFAULT_PBKDF2_ITERATIONS,
      MIN_PBKDF2_ITERATIONS,
      MAX_PBKDF2_ITERATIONS,
    );
    const digest = await derivePbkdf2(secret, salt, iterations);
    return {
      encoded: `$pbkdf2-sha256$i=${iterations}$${toBase64Url(salt)}$${toBase64Url(digest)}`,
      algorithm: options.algorithm,
      assessment,
    };
  }

  const digest = deriveShaDigest(secret, salt, options.algorithm);
  return {
    encoded: `$${options.algorithm}$s=${toBase64Url(salt)}$${toBase64Url(digest)}`,
    algorithm: options.algorithm,
    assessment,
  };
}

export function parsePasswordHash(encoded: string): ParsedPasswordHash {
  const argonMatch = encoded.match(/^\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$([A-Za-z0-9_-]+)\$([A-Za-z0-9_-]+)$/u);
  if (argonMatch) {
    return {
      algorithm: "argon2id",
      argon2Memory: Number(argonMatch[1]),
      argon2Passes: Number(argonMatch[2]),
      argon2Parallelism: Number(argonMatch[3]),
      salt: fromBase64Url(argonMatch[4]),
      digest: fromBase64Url(argonMatch[5]),
    };
  }

  const pbkdf2Match = encoded.match(/^\$pbkdf2-sha256\$i=(\d+)\$([A-Za-z0-9_-]+)\$([A-Za-z0-9_-]+)$/u);
  if (pbkdf2Match) {
    return {
      algorithm: "pbkdf2-sha256",
      pbkdf2Iterations: Number(pbkdf2Match[1]),
      salt: fromBase64Url(pbkdf2Match[2]),
      digest: fromBase64Url(pbkdf2Match[3]),
    };
  }

  const shaMatch = encoded.match(/^\$(sha256|sha512)\$s=([A-Za-z0-9_-]+)\$([A-Za-z0-9_-]+)$/u);
  if (shaMatch) {
    return {
      algorithm: shaMatch[1] as "sha256" | "sha512",
      salt: fromBase64Url(shaMatch[2]),
      digest: fromBase64Url(shaMatch[3]),
    };
  }

  throw new Error("Unsupported password hash format");
}

export async function verifyPassword(secret: string, encoded: string): Promise<boolean> {
  if (!secret) return false;
  const parsed = parsePasswordHash(encoded);
  if (parsed.algorithm === "argon2id") {
    if (!(await supportsArgon2id())) {
      throw new Error("Argon2id verification is not supported in this browser/runtime");
    }
    const digest = await deriveArgon2id(secret, parsed.salt, {
      memory: parsed.argon2Memory ?? DEFAULT_ARGON2_MEMORY,
      passes: parsed.argon2Passes ?? DEFAULT_ARGON2_PASSES,
      parallelism: parsed.argon2Parallelism ?? DEFAULT_ARGON2_PARALLELISM,
    });
    return equalBytes(digest, parsed.digest);
  }

  if (parsed.algorithm === "pbkdf2-sha256") {
    const digest = await derivePbkdf2(secret, parsed.salt, parsed.pbkdf2Iterations ?? DEFAULT_PBKDF2_ITERATIONS);
    return equalBytes(digest, parsed.digest);
  }

  const digest = deriveShaDigest(secret, parsed.salt, parsed.algorithm);
  return equalBytes(digest, parsed.digest);
}

export function assessPasswordHashChoice(options: PasswordHashOptions): PasswordHashChoiceAssessment {
  return createAssessment(options);
}

export const PASSWORD_HASH_DEFAULTS = {
  saltBytes: DEFAULT_SALT_BYTES,
  pbkdf2Iterations: DEFAULT_PBKDF2_ITERATIONS,
  argon2Memory: DEFAULT_ARGON2_MEMORY,
  argon2Passes: DEFAULT_ARGON2_PASSES,
  argon2Parallelism: DEFAULT_ARGON2_PARALLELISM,
};
