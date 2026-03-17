import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import {
  PASSWORD_HASH_ALGORITHMS,
  assessPasswordHashChoice,
  hashPassword,
  parsePasswordHash,
  PASSWORD_HASH_DEFAULTS,
  PASSWORD_HASH_LIMITS,
  PASSWORD_HASH_MESSAGES,
  supportsArgon2id,
  verifyPassword,
} from "../utils/passwordHashing.js";

const sharedSpec = JSON.parse(
  fs.readFileSync(path.resolve(process.cwd(), "src/utils/passwordHashingSpec.json"), "utf8"),
) as {
  algorithms: string[];
  record: { argon2Version: number; base64Segment: string; derivedBits: number; derivedBytes: number };
  saltBytes: { min: number; default: number; max: number };
  pbkdf2: { iterations: { min: number; default: number; max: number; recommendedMin: number } };
  argon2: {
    memory: { min: number; default: number; max: number; recommendedMin: number };
    passes: { min: number; default: number; max: number; recommendedMin: number };
    parallelism: { min: number; default: number; max: number };
  };
  warnings: Record<string, string>;
  errors: Record<string, string>;
};

function encodeBase64(byteLength: number, fill: number): string {
  return Buffer.alloc(byteLength, fill).toString("base64");
}

function getErrorMessage(action: () => void): string {
  try {
    action();
    return "";
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
}

describe("password hashing", () => {
  it("keeps the exported password hash spec aligned with the shared spec file", () => {
    assert.deepEqual(Array.from(PASSWORD_HASH_ALGORITHMS), sharedSpec.algorithms);
    assert.deepEqual(PASSWORD_HASH_LIMITS, {
      record: sharedSpec.record,
      saltBytes: sharedSpec.saltBytes,
      pbkdf2: sharedSpec.pbkdf2,
      argon2: sharedSpec.argon2,
    });
    assert.deepEqual(PASSWORD_HASH_MESSAGES, {
      warnings: sharedSpec.warnings,
      errors: sharedSpec.errors,
    });
    assert.deepEqual(PASSWORD_HASH_DEFAULTS, {
      saltBytes: sharedSpec.saltBytes.default,
      pbkdf2Iterations: sharedSpec.pbkdf2.iterations.default,
      argon2Memory: sharedSpec.argon2.memory.default,
      argon2Passes: sharedSpec.argon2.passes.default,
      argon2Parallelism: sharedSpec.argon2.parallelism.default,
    });
  });

  it("round trips PBKDF2 hashes", async () => {
    const result = await hashPassword("pbkdf2-secret", {
      algorithm: "pbkdf2-sha256",
      pbkdf2Iterations: 350_000,
      saltBytes: 16,
    });
    assert.equal(result.encoded.startsWith("$pbkdf2-sha256$"), true);
    assert.equal(await verifyPassword("pbkdf2-secret", result.encoded), true);
    assert.equal(await verifyPassword("wrong", result.encoded), false);
  });

  it("round trips legacy SHA hashes with salts", async () => {
    const result = await hashPassword("legacy-secret", {
      algorithm: "sha512",
      saltBytes: 16,
    });
    const parsed = parsePasswordHash(result.encoded);
    assert.equal(parsed.algorithm, "sha512");
    assert.equal(parsed.salt.length, 16);
    assert.equal(await verifyPassword("legacy-secret", result.encoded), true);
    assert.equal(await verifyPassword("nope", result.encoded), false);
  });

  it("round trips Argon2id hashes when supported", async () => {
    const supported = await supportsArgon2id();
    if (!supported) return;
    const result = await hashPassword("argon-secret", {
      algorithm: "argon2id",
      argon2Memory: 16_384,
      argon2Passes: 2,
      argon2Parallelism: 1,
      saltBytes: 16,
    });
    assert.equal(result.encoded.startsWith("$argon2id$"), true);
    assert.equal(await verifyPassword("argon-secret", result.encoded), true);
    assert.equal(await verifyPassword("argon-wrong", result.encoded), false);
  });

  it("reports weak algorithms", () => {
    const weak = assessPasswordHashChoice({ algorithm: "sha256" });
    const strong = assessPasswordHashChoice({ algorithm: "argon2id", argon2Memory: 65_536, argon2Passes: 3 });
    assert.equal(weak.safety, "weak");
    assert.equal(weak.warnings.length > 0, true);
    assert.equal(strong.safety, "strong");
  });

  it("rejects invalid hash formats", () => {
    let message = "";
    try {
      parsePasswordHash("not-a-hash");
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }
    assert.equal(/unsupported/i.test(message), true);
  });

  it("accepts imported records with padded standard base64 fields", () => {
    const parsed = parsePasswordHash(
      `$sha256$s=${encodeBase64(PASSWORD_HASH_LIMITS.saltBytes.min, 0xff)}$${encodeBase64(PASSWORD_HASH_LIMITS.record.derivedBytes, 0x11)}`,
    );
    assert.equal(parsed.algorithm, "sha256");
    assert.equal(parsed.salt.length, PASSWORD_HASH_LIMITS.saltBytes.min);
    assert.equal(parsed.digest.length, PASSWORD_HASH_LIMITS.record.derivedBytes);
  });

  it("rejects malformed salt encodings explicitly", () => {
    const digest = encodeBase64(PASSWORD_HASH_LIMITS.record.derivedBytes, 0x22);
    const message = getErrorMessage(() => parsePasswordHash(`$sha256$s=A=$${digest}`));
    assert.equal(message, PASSWORD_HASH_MESSAGES.errors.invalidSaltEncoding);
  });

  it("rejects unsupported salt lengths explicitly", () => {
    const digest = encodeBase64(PASSWORD_HASH_LIMITS.record.derivedBytes, 0x22);
    const shortSalt = encodeBase64(PASSWORD_HASH_LIMITS.saltBytes.min - 1, 0x01);
    const message = getErrorMessage(() => parsePasswordHash(`$sha256$s=${shortSalt}$${digest}`));
    assert.equal(message, PASSWORD_HASH_MESSAGES.errors.invalidSaltLength);
  });

  it("rejects invalid digest lengths explicitly", () => {
    const salt = encodeBase64(PASSWORD_HASH_LIMITS.saltBytes.default, 0x01);
    const shortDigest = encodeBase64(PASSWORD_HASH_LIMITS.record.derivedBytes - 1, 0x22);
    const message = getErrorMessage(() => parsePasswordHash(`$pbkdf2-sha256$i=600000$${salt}$${shortDigest}`));
    assert.equal(message, PASSWORD_HASH_MESSAGES.errors.invalidDigestLength);
  });

  it("rejects PBKDF2 iteration counts outside NullID bounds", () => {
    const salt = encodeBase64(PASSWORD_HASH_LIMITS.saltBytes.default, 0x01);
    const digest = encodeBase64(PASSWORD_HASH_LIMITS.record.derivedBytes, 0x22);
    const message = getErrorMessage(() => parsePasswordHash(`$pbkdf2-sha256$i=999999999$${salt}$${digest}`));
    assert.equal(message, PASSWORD_HASH_MESSAGES.errors.invalidPbkdf2Iterations);
  });

  it("rejects Argon2id cost parameters outside NullID bounds", () => {
    const salt = encodeBase64(PASSWORD_HASH_LIMITS.saltBytes.default, 0x01);
    const digest = encodeBase64(PASSWORD_HASH_LIMITS.record.derivedBytes, 0x22);
    const message = getErrorMessage(
      () =>
        parsePasswordHash(
          `$argon2id$v=${PASSWORD_HASH_LIMITS.record.argon2Version}$m=999999,t=${PASSWORD_HASH_LIMITS.argon2.passes.default},p=${PASSWORD_HASH_LIMITS.argon2.parallelism.default}$${salt}$${digest}`,
        ),
    );
    assert.equal(message, PASSWORD_HASH_MESSAGES.errors.invalidArgon2Params);
  });

  it("returns false for empty password candidates", async () => {
    const result = await hashPassword("non-empty-secret", { algorithm: "sha256", saltBytes: PASSWORD_HASH_LIMITS.saltBytes.default });
    assert.equal(await verifyPassword("", result.encoded), false);
  });
});
