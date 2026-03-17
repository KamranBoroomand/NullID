import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";
import { decodeBase64UrlStrict, randomBytes, toBase64Url, utf8ToBytes } from "./encoding.js";

const MIN_SALT_BYTES = 8;
const DEFAULT_SALT_BYTES = 16;
const MAX_SALT_BYTES = 64;
const DEFAULT_DERIVED_BITS = 256;
const DEFAULT_DERIVED_BYTES = DEFAULT_DERIVED_BITS / 8;
const ARGON2_VERSION = 19;

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

const PASSWORD_HASH_B64_SEGMENT = "[A-Za-z0-9+/_-]+={0,2}";
const PASSWORD_HASH_B64_SEGMENT_RE = new RegExp(`^${PASSWORD_HASH_B64_SEGMENT}$`, "u");

export const PASSWORD_HASH_ALGORITHMS = ["argon2id", "pbkdf2-sha256", "sha512", "sha256"] as const;
export type PasswordHashAlgorithm = (typeof PASSWORD_HASH_ALGORITHMS)[number];
export type HashSafety = "weak" | "fair" | "strong";

const PASSWORD_HASH_WARNINGS = {
  argon2MemoryBelowRecommended: "Argon2 memory cost is below 64 MiB",
  argon2PassesBelowRecommended: "Argon2 passes below recommended minimum (3)",
  pbkdf2IterationsBelowRecommended: "PBKDF2 iterations below 300,000",
  legacyFastSha: "Fast SHA digests are legacy-only for password storage",
  preferSlowKdf: "Prefer Argon2id (or PBKDF2-SHA256 with high iterations for compatibility)",
} as const;

const PASSWORD_HASH_ERRORS = {
  passwordRequired: "Password is required",
  unsupportedFormat: "Unsupported password hash format",
  invalidSaltEncoding: "Invalid password hash salt encoding",
  invalidSaltLength: "Password hash salt length is outside NullID's supported range",
  invalidDigestEncoding: "Invalid password hash digest encoding",
  invalidDigestLength: "Invalid password hash digest length",
  invalidPbkdf2Iterations: "PBKDF2 iteration count is outside NullID's supported range",
  invalidArgon2Params: "Argon2id cost parameters are outside NullID's supported range",
  argon2Unavailable: "Argon2id is not supported in this runtime",
  argon2UnavailableVerify: "Argon2id records cannot be verified in this runtime",
} as const;

export const PASSWORD_HASH_LIMITS = {
  record: {
    argon2Version: ARGON2_VERSION,
    base64Segment: PASSWORD_HASH_B64_SEGMENT,
    derivedBits: DEFAULT_DERIVED_BITS,
    derivedBytes: DEFAULT_DERIVED_BYTES,
  },
  saltBytes: {
    min: MIN_SALT_BYTES,
    default: DEFAULT_SALT_BYTES,
    max: MAX_SALT_BYTES,
  },
  pbkdf2: {
    iterations: {
      min: MIN_PBKDF2_ITERATIONS,
      default: DEFAULT_PBKDF2_ITERATIONS,
      max: MAX_PBKDF2_ITERATIONS,
      recommendedMin: 300_000,
    },
  },
  argon2: {
    memory: {
      min: MIN_ARGON2_MEMORY,
      default: DEFAULT_ARGON2_MEMORY,
      max: MAX_ARGON2_MEMORY,
      recommendedMin: 65_536,
    },
    passes: {
      min: MIN_ARGON2_PASSES,
      default: DEFAULT_ARGON2_PASSES,
      max: MAX_ARGON2_PASSES,
      recommendedMin: 3,
    },
    parallelism: {
      min: MIN_ARGON2_PARALLELISM,
      default: DEFAULT_ARGON2_PARALLELISM,
      max: MAX_ARGON2_PARALLELISM,
    },
  },
} as const;

export const PASSWORD_HASH_MESSAGES = {
  warnings: PASSWORD_HASH_WARNINGS,
  errors: PASSWORD_HASH_ERRORS,
} as const;

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

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
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
    if (memory < PASSWORD_HASH_LIMITS.argon2.memory.recommendedMin) warnings.push(PASSWORD_HASH_WARNINGS.argon2MemoryBelowRecommended);
    if (passes < PASSWORD_HASH_LIMITS.argon2.passes.recommendedMin) warnings.push(PASSWORD_HASH_WARNINGS.argon2PassesBelowRecommended);
    return { safety: warnings.length > 0 ? "fair" : "strong", warnings };
  }

  if (options.algorithm === "pbkdf2-sha256") {
    const iterations = clampInt(options.pbkdf2Iterations, DEFAULT_PBKDF2_ITERATIONS, MIN_PBKDF2_ITERATIONS, MAX_PBKDF2_ITERATIONS);
    if (iterations < PASSWORD_HASH_LIMITS.pbkdf2.iterations.recommendedMin) warnings.push(PASSWORD_HASH_WARNINGS.pbkdf2IterationsBelowRecommended);
    return { safety: warnings.length > 0 ? "fair" : "strong", warnings };
  }

  warnings.push(PASSWORD_HASH_WARNINGS.legacyFastSha);
  warnings.push(PASSWORD_HASH_WARNINGS.preferSlowKdf);
  return { safety: "weak", warnings };
}

async function derivePbkdf2(secret: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const keyMaterial = await crypto.subtle.importKey("raw", toArrayBuffer(utf8ToBytes(secret)), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      iterations,
      salt: toArrayBuffer(salt),
    },
    keyMaterial,
    PASSWORD_HASH_LIMITS.record.derivedBits,
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
    toArrayBuffer(utf8ToBytes(secret)),
    "Argon2id",
    false,
    ["deriveBits"],
  );
  const bits = await subtle.deriveBits(
    {
      name: "Argon2id",
      nonce: toArrayBuffer(salt),
      memory: options.memory,
      passes: options.passes,
      parallelism: options.parallelism,
    } as unknown as AlgorithmIdentifier,
    keyMaterial,
    PASSWORD_HASH_LIMITS.record.derivedBits,
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
    const key = await subtle.importKey("raw-secret", toArrayBuffer(utf8ToBytes("probe")), "Argon2id", false, ["deriveBits"]);
    const salt = randomBytes(16);
    await subtle.deriveBits(
      {
        name: "Argon2id",
        nonce: toArrayBuffer(salt),
        memory: MIN_ARGON2_MEMORY,
        passes: 1,
        parallelism: 1,
      } as unknown as AlgorithmIdentifier,
      key,
      128,
    );
    argon2SupportCache = true;
  } catch {
    argon2SupportCache = false;
  }
  return argon2SupportCache;
}

export async function hashPassword(secret: string, options: PasswordHashOptions): Promise<PasswordHashResult> {
  if (!secret) {
    throw new Error(PASSWORD_HASH_ERRORS.passwordRequired);
  }
  const saltBytes = clampInt(options.saltBytes, DEFAULT_SALT_BYTES, MIN_SALT_BYTES, MAX_SALT_BYTES);
  const salt = randomBytes(saltBytes);
  const assessment = createAssessment(options);

  if (options.algorithm === "argon2id") {
    if (!(await supportsArgon2id())) {
      throw new Error(PASSWORD_HASH_ERRORS.argon2Unavailable);
    }
    const memory = clampInt(options.argon2Memory, DEFAULT_ARGON2_MEMORY, MIN_ARGON2_MEMORY, MAX_ARGON2_MEMORY);
    const passes = clampInt(options.argon2Passes, DEFAULT_ARGON2_PASSES, MIN_ARGON2_PASSES, MAX_ARGON2_PASSES);
    const parallelism = clampInt(options.argon2Parallelism, DEFAULT_ARGON2_PARALLELISM, MIN_ARGON2_PARALLELISM, MAX_ARGON2_PARALLELISM);
    const digest = await deriveArgon2id(secret, salt, { memory, passes, parallelism });
    return {
      encoded: `$argon2id$v=${PASSWORD_HASH_LIMITS.record.argon2Version}$m=${memory},t=${passes},p=${parallelism}$${toBase64Url(salt)}$${toBase64Url(digest)}`,
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

function decodePasswordHashSegment(value: string, errorMessage: string): Uint8Array {
  if (!PASSWORD_HASH_B64_SEGMENT_RE.test(value)) {
    throw new Error(errorMessage);
  }
  return decodeBase64UrlStrict(value, errorMessage);
}

function validateSaltLength(salt: Uint8Array): void {
  if (salt.length < PASSWORD_HASH_LIMITS.saltBytes.min || salt.length > PASSWORD_HASH_LIMITS.saltBytes.max) {
    throw new Error(PASSWORD_HASH_ERRORS.invalidSaltLength);
  }
}

function validateDigestLength(algorithm: PasswordHashAlgorithm, digest: Uint8Array): void {
  const expectedLength = algorithm === "sha512" ? 64 : PASSWORD_HASH_LIMITS.record.derivedBytes;
  if (digest.length !== expectedLength) {
    throw new Error(PASSWORD_HASH_ERRORS.invalidDigestLength);
  }
}

function validatePbkdf2Iterations(iterations: number): void {
  if (!Number.isSafeInteger(iterations) || iterations < MIN_PBKDF2_ITERATIONS || iterations > MAX_PBKDF2_ITERATIONS) {
    throw new Error(PASSWORD_HASH_ERRORS.invalidPbkdf2Iterations);
  }
}

function validateArgon2Params(memory: number, passes: number, parallelism: number): void {
  const params = [memory, passes, parallelism];
  if (!params.every((value) => Number.isSafeInteger(value))) {
    throw new Error(PASSWORD_HASH_ERRORS.invalidArgon2Params);
  }
  if (
    memory < MIN_ARGON2_MEMORY ||
    memory > MAX_ARGON2_MEMORY ||
    passes < MIN_ARGON2_PASSES ||
    passes > MAX_ARGON2_PASSES ||
    parallelism < MIN_ARGON2_PARALLELISM ||
    parallelism > MAX_ARGON2_PARALLELISM
  ) {
    throw new Error(PASSWORD_HASH_ERRORS.invalidArgon2Params);
  }
}

export function parsePasswordHash(encoded: string): ParsedPasswordHash {
  const argonMatch = encoded.match(
    new RegExp(
      `^\\$argon2id\\$v=${PASSWORD_HASH_LIMITS.record.argon2Version}\\$m=(\\d+),t=(\\d+),p=(\\d+)\\$(${PASSWORD_HASH_LIMITS.record.base64Segment})\\$(${PASSWORD_HASH_LIMITS.record.base64Segment})$`,
      "u",
    ),
  );
  if (argonMatch) {
    const argon2Memory = Number(argonMatch[1]);
    const argon2Passes = Number(argonMatch[2]);
    const argon2Parallelism = Number(argonMatch[3]);
    validateArgon2Params(argon2Memory, argon2Passes, argon2Parallelism);
    const salt = decodePasswordHashSegment(argonMatch[4], PASSWORD_HASH_ERRORS.invalidSaltEncoding);
    validateSaltLength(salt);
    const digest = decodePasswordHashSegment(argonMatch[5], PASSWORD_HASH_ERRORS.invalidDigestEncoding);
    validateDigestLength("argon2id", digest);
    return {
      algorithm: "argon2id",
      argon2Memory,
      argon2Passes,
      argon2Parallelism,
      salt,
      digest,
    };
  }

  const pbkdf2Match = encoded.match(
    new RegExp(
      `^\\$pbkdf2-sha256\\$i=(\\d+)\\$(${PASSWORD_HASH_LIMITS.record.base64Segment})\\$(${PASSWORD_HASH_LIMITS.record.base64Segment})$`,
      "u",
    ),
  );
  if (pbkdf2Match) {
    const pbkdf2Iterations = Number(pbkdf2Match[1]);
    validatePbkdf2Iterations(pbkdf2Iterations);
    const salt = decodePasswordHashSegment(pbkdf2Match[2], PASSWORD_HASH_ERRORS.invalidSaltEncoding);
    validateSaltLength(salt);
    const digest = decodePasswordHashSegment(pbkdf2Match[3], PASSWORD_HASH_ERRORS.invalidDigestEncoding);
    validateDigestLength("pbkdf2-sha256", digest);
    return {
      algorithm: "pbkdf2-sha256",
      pbkdf2Iterations,
      salt,
      digest,
    };
  }

  const shaMatch = encoded.match(
    new RegExp(
      `^\\$(sha256|sha512)\\$s=(${PASSWORD_HASH_LIMITS.record.base64Segment})\\$(${PASSWORD_HASH_LIMITS.record.base64Segment})$`,
      "u",
    ),
  );
  if (shaMatch) {
    const algorithm = shaMatch[1] as "sha256" | "sha512";
    const salt = decodePasswordHashSegment(shaMatch[2], PASSWORD_HASH_ERRORS.invalidSaltEncoding);
    validateSaltLength(salt);
    const digest = decodePasswordHashSegment(shaMatch[3], PASSWORD_HASH_ERRORS.invalidDigestEncoding);
    validateDigestLength(algorithm, digest);
    return {
      algorithm,
      salt,
      digest,
    };
  }

  throw new Error(PASSWORD_HASH_ERRORS.unsupportedFormat);
}

export async function verifyPassword(secret: string, encoded: string): Promise<boolean> {
  if (!secret) return false;
  const parsed = parsePasswordHash(encoded);
  if (parsed.algorithm === "argon2id") {
    if (!(await supportsArgon2id())) {
      throw new Error(PASSWORD_HASH_ERRORS.argon2UnavailableVerify);
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
} as const;
