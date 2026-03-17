import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import path from "node:path";
import {
  assessPasswordHashChoice,
  hashPassword,
  PASSWORD_HASH_LIMITS,
  PASSWORD_HASH_MESSAGES,
  verifyPassword,
} from "../utils/passwordHashing.js";

const cliPath = path.resolve(process.cwd(), "scripts/nullid-local.mjs");

function runCli(args: string[], env: Record<string, string> = {}) {
  const stdout = execFileSync(process.execPath, [cliPath, ...args], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: {
      ...process.env,
      ...env,
    },
  });
  return JSON.parse(stdout) as Record<string, unknown>;
}

function runCliRaw(args: string[], env: Record<string, string> = {}) {
  return spawnSync(process.execPath, [cliPath, ...args], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: {
      ...process.env,
      ...env,
    },
  });
}

describe("nullid local cli password hashing", () => {
  it("generates and verifies PBKDF2 password hash records", () => {
    const hashed = runCli(
      ["pw-hash", "--algo", "pbkdf2-sha256", "--pbkdf2-iterations", "350000", "--password-env", "NULLID_PASSWORD"],
      { NULLID_PASSWORD: "cli-secret" },
    );
    assert.equal(hashed.algorithm, "pbkdf2-sha256");
    assert.match(String(hashed.record), /^\$pbkdf2-sha256\$/u);

    const verified = runCli(
      ["pw-verify", "--record", String(hashed.record), "--password-env", "NULLID_PASSWORD"],
      { NULLID_PASSWORD: "cli-secret" },
    );
    assert.equal(verified.match, true);

    const mismatch = runCli(
      ["pw-verify", "--record", String(hashed.record), "--password-env", "NULLID_PASSWORD"],
      { NULLID_PASSWORD: "wrong-secret" },
    );
    assert.equal(mismatch.match, false);
  });

  it("keeps PBKDF2 records interoperable between the browser utility and the CLI", async () => {
    const browserRecord = await hashPassword("shared-secret", {
      algorithm: "pbkdf2-sha256",
      pbkdf2Iterations: 350_000,
      saltBytes: PASSWORD_HASH_LIMITS.saltBytes.default,
    });
    const cliVerifiedBrowserRecord = runCli(
      ["pw-verify", "--record", browserRecord.encoded, "--password-env", "NULLID_PASSWORD"],
      { NULLID_PASSWORD: "shared-secret" },
    );
    assert.equal(cliVerifiedBrowserRecord.match, true);

    const cliRecord = runCli(
      ["pw-hash", "--algo", "pbkdf2-sha256", "--pbkdf2-iterations", "350000", "--password-env", "NULLID_PASSWORD"],
      { NULLID_PASSWORD: "shared-secret" },
    );
    assert.equal(await verifyPassword("shared-secret", String(cliRecord.record)), true);
  });

  it("keeps legacy SHA records interoperable between the browser utility and the CLI", async () => {
    const browserRecord = await hashPassword("legacy-shared", {
      algorithm: "sha512",
      saltBytes: PASSWORD_HASH_LIMITS.saltBytes.default,
    });
    const cliVerifiedBrowserRecord = runCli(
      ["pw-verify", "--record", browserRecord.encoded, "--password-env", "NULLID_PASSWORD"],
      { NULLID_PASSWORD: "legacy-shared" },
    );
    assert.equal(cliVerifiedBrowserRecord.match, true);

    const cliRecord = runCli(["pw-hash", "--algo", "sha512", "--password-env", "NULLID_PASSWORD"], {
      NULLID_PASSWORD: "legacy-shared",
    });
    assert.equal(await verifyPassword("legacy-shared", String(cliRecord.record)), true);
  });

  it("keeps CLI warnings aligned with the browser-side assessment", () => {
    const cliResult = runCli(
      ["pw-hash", "--algo", "pbkdf2-sha256", "--pbkdf2-iterations", "200000", "--password-env", "NULLID_PASSWORD"],
      { NULLID_PASSWORD: "warning-secret" },
    );
    const browserAssessment = assessPasswordHashChoice({
      algorithm: "pbkdf2-sha256",
      pbkdf2Iterations: 200_000,
    });

    assert.equal(cliResult.safety, browserAssessment.safety);
    assert.deepEqual(cliResult.warnings, browserAssessment.warnings);
  });

  it("rejects malformed imported records with explicit CLI errors", () => {
    const invalidRecord = `$pbkdf2-sha256$i=600000$A=$${Buffer.alloc(PASSWORD_HASH_LIMITS.record.derivedBytes, 0x22).toString("base64")}`;
    const result = runCliRaw(["pw-verify", "--record", invalidRecord, "--password-env", "NULLID_PASSWORD"], {
      NULLID_PASSWORD: "shared-secret",
    });

    assert.equal(result.status, 1);
    assert.match(`${result.stdout}\n${result.stderr}`, new RegExp(PASSWORD_HASH_MESSAGES.errors.invalidSaltEncoding, "u"));
  });

  it("rejects out-of-range imported PBKDF2 records with explicit CLI errors", () => {
    const salt = Buffer.alloc(PASSWORD_HASH_LIMITS.saltBytes.default, 0x01).toString("base64");
    const digest = Buffer.alloc(PASSWORD_HASH_LIMITS.record.derivedBytes, 0x22).toString("base64");
    const record = `$pbkdf2-sha256$i=999999999$${salt}$${digest}`;
    const result = runCliRaw(["pw-verify", "--record", record, "--password-env", "NULLID_PASSWORD"], {
      NULLID_PASSWORD: "shared-secret",
    });

    assert.equal(result.status, 1);
    assert.match(`${result.stdout}\n${result.stderr}`, new RegExp(PASSWORD_HASH_MESSAGES.errors.invalidPbkdf2Iterations, "u"));
  });

  it("either generates Argon2id records or reports the compatibility fallback", () => {
    const result = spawnSync(process.execPath, [cliPath, "pw-hash", "--algo", "argon2id", "--password-env", "NULLID_PASSWORD"], {
      cwd: process.cwd(),
      encoding: "utf8",
      env: {
        ...process.env,
        NULLID_PASSWORD: "argon-cli-secret",
      },
    });
    if (result.status === 0) {
      const parsed = JSON.parse(result.stdout) as Record<string, unknown>;
      assert.equal(parsed.algorithm, "argon2id");
      assert.match(String(parsed.record), /^\$argon2id\$/u);
      return;
    }

    const combined = `${result.stdout}\n${result.stderr}`;
    assert.match(combined, new RegExp(PASSWORD_HASH_MESSAGES.errors.argon2Unavailable, "iu"));
  });
});
