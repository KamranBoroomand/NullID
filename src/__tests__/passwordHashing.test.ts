import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  assessPasswordHashChoice,
  hashPassword,
  parsePasswordHash,
  supportsArgon2id,
  verifyPassword,
} from "../utils/passwordHashing.js";

describe("password hashing", () => {
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
});
