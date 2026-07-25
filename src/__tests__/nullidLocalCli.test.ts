import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import zlib from "node:zlib";
import {
  assessPasswordHashChoice,
  hashPassword,
  PASSWORD_HASH_LIMITS,
  PASSWORD_HASH_MESSAGES,
  verifyPassword,
} from "../utils/passwordHashing.js";
import { inspectReceivedArtifact } from "../utils/packageVerification.js";
import { inspectZipArchiveBytes } from "../utils/archiveInspection.js";
import { createPolicyPackSnapshot } from "../utils/policyPack.js";
import { PROFILE_SCHEMA_VERSION } from "../utils/profile.js";
import { buildRulesState } from "../utils/sanitizeEngine.js";
import { createSnapshotIntegrity } from "../utils/snapshotIntegrity.js";
import { toBase64Url, utf8ToBytes } from "../utils/encoding.js";
import { parseZipArchive, readZipEntryBytes, ZIP_SAFETY_LIMITS } from "../utils/zipSafety.js";
import { createMinimalOfficeZip, createStoredZip, createZip } from "./zipFixtures.js";

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

async function withNodeOnlyPath<T>(action: (env: Record<string, string>) => T | Promise<T>) {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-node-path-"));
  try {
    const nodeTarget = path.join(tempDir, process.platform === "win32" ? "node.exe" : "node");
    try {
      fs.symlinkSync(process.execPath, nodeTarget);
    } catch {
      fs.copyFileSync(process.execPath, nodeTarget);
    }
    try {
      fs.chmodSync(nodeTarget, 0o700);
    } catch {
      // Windows copies keep executable permissions from the source binary.
    }
    return await action({
      PATH: tempDir,
      Path: tempDir,
      ...(process.platform === "win32" ? { PATHEXT: ".EXE" } : {}),
    });
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

async function createLegacyEnvelopeForTest(
  passphrase: string,
  bytes: Uint8Array,
  metadata: { mime?: string; name?: string } = {},
) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const keyMaterial = await crypto.subtle.importKey("raw", exactArrayBuffer(utf8ToBytes(passphrase)), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: exactArrayBuffer(salt), iterations: 250_000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: exactArrayBuffer(iv), additionalData: exactArrayBuffer(utf8ToBytes("nullid:enc:v1")) },
      key,
      exactArrayBuffer(bytes),
    ),
  );
  const payload = {
    header: {
      version: 1,
      algo: "AES-GCM",
      kdf: { name: "PBKDF2", iterations: 250_000, hash: "SHA-256", salt: toBase64Url(salt) },
      iv: toBase64Url(iv),
      mime: metadata.mime,
      name: metadata.name,
    },
    ciphertext: toBase64Url(ciphertext),
  };
  return `NULLID:ENC:1.${toBase64Url(utf8ToBytes(JSON.stringify(payload)))}`;
}

function exactArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

async function sha256Buffer(value: Uint8Array) {
  const digest = new Uint8Array(
    await globalThis.crypto.subtle.digest("SHA-256", Uint8Array.from(value).buffer),
  );
  return Array.from(digest)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function readZipText(bytes: Uint8Array, entryPath: string) {
  const parsed = parseZipArchive(bytes);
  const entry = parsed.entries.find((candidate: { path: string }) => candidate.path === entryPath);
  assert.ok(entry, `${entryPath} exists`);
  const content = readZipEntryBytes(bytes, entry, (compressed: Uint8Array, _entry: unknown, context?: { maxOutputBytes: number }) =>
    zlib.inflateRawSync(Buffer.from(compressed), context ? { maxOutputLength: Math.max(1, context.maxOutputBytes) } : undefined),
  );
  return Buffer.from(content).toString("utf8");
}

async function assertArchiveManifestMatchesZip(bytes: Uint8Array) {
  const parsed = parseZipArchive(bytes);
  const manifestText = readZipText(bytes, "nullid-archive-manifest.json");
  const manifest = JSON.parse(manifestText) as {
    createdAt: string;
    source: { label: string; sourceType: string; input?: string; provenance: string };
    policy: { baseline: string | null };
    files: Array<{ path: string; bytesAfter: number; sha256After: string }>;
  };

  for (const file of manifest.files) {
    const entry = parsed.entries.find((candidate: { path: string }) => candidate.path === file.path);
    assert.ok(entry, `${file.path} exists in generated archive`);
    assert.equal(entry.directory, false);
    const content = readZipEntryBytes(bytes, entry, (compressed: Uint8Array, _entry: unknown, context?: { maxOutputBytes: number }) =>
      zlib.inflateRawSync(Buffer.from(compressed), context ? { maxOutputLength: Math.max(1, context.maxOutputBytes) } : undefined),
    );
    assert.equal(content.length, file.bytesAfter);
    assert.equal(await sha256Buffer(content), file.sha256After);
  }

  return { manifest, parsed };
}

function writeMaskEmailBaseline(filePath: string) {
  fs.writeFileSync(
    filePath,
    JSON.stringify({
      schemaVersion: 1,
      kind: "nullid-policy-baseline",
      sanitize: { mergeMode: "strict-override", defaultConfig: { rulesState: buildRulesState(["maskEmail"]), jsonAware: false, customRules: [] }, packs: [] },
    }),
    "utf8",
  );
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

describe("nullid local cli workflow packages", () => {
  it("cleans Office packages without external archive tooling and fails closed on ZIP symlink entries", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-office-symlink-"));
    try {
      const victimPath = path.join(tempDir, "victim.txt");
      const maliciousPath = path.join(tempDir, "malicious.docx");
      const rejectedOutputPath = path.join(tempDir, "malicious.clean.docx");
      const safeInputPath = path.join(tempDir, "safe.docx");
      const safeOutputPath = path.join(tempDir, "safe.clean.docx");
      const victimBefore = Buffer.from("external victim must remain unchanged\n", "utf8");
      fs.writeFileSync(victimPath, victimBefore);
      fs.writeFileSync(
        maliciousPath,
        Buffer.from(createMinimalOfficeZip(victimPath, 0o120777)).toString("binary"),
        "binary",
      );
      fs.writeFileSync(
        safeInputPath,
        Buffer.from(createMinimalOfficeZip("<cp:coreProperties></cp:coreProperties>")).toString("binary"),
        "binary",
      );

      await withNodeOnlyPath((env) => {
        const rejected = runCliRaw(["office-clean", maliciousPath, rejectedOutputPath], env);
        assert.notEqual(rejected.status, 0);
        assert.match(`${rejected.stdout}\n${rejected.stderr}`, /symbolic link|Unsafe ZIP entry/i);
        assert.deepEqual(fs.readFileSync(victimPath), victimBefore);
        assert.equal(fs.existsSync(rejectedOutputPath), false);

        const cleaned = runCli(["office-clean", safeInputPath, safeOutputPath], env);
        assert.equal(cleaned.output, safeOutputPath);
        assert.equal(fs.existsSync(safeOutputPath), true);
      });

      const outputBytes = fs.readFileSync(safeOutputPath);
      const parsed = parseZipArchive(outputBytes);
      assert.equal(parsed.entries.some((entry: { path: string }) => entry.path === "[Content_Types].xml"), true);
      assert.equal(parsed.entries.some((entry: { path: string }) => entry.path === "docProps/core.xml"), true);
      assert.equal(parsed.entries.some((entry: { path: string }) => entry.path === "docProps/app.xml"), true);
      assert.match(readZipText(outputBytes, "docProps/core.xml"), /<dc:creator>redacted<\/dc:creator>/i);
      assert.match(readZipText(outputBytes, "docProps/app.xml"), /<Application>NullID<\/Application>/i);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("emits the shared workflow package contract from bundle and inspects it", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-workflow-"));
    try {
      const inputFile = path.join(tempDir, "incident.log");
      const outputFile = path.join(tempDir, "bundle.json");
      fs.writeFileSync(inputFile, "user=alice from 203.0.113.10", "utf8");

      const bundleResult = runCli(["bundle", inputFile, outputFile, "--preset", "nginx"]);
      assert.equal(bundleResult.schemaVersion, 2);
      assert.equal(bundleResult.workflowType, "sanitize-safe-share");

      const payload = JSON.parse(fs.readFileSync(outputFile, "utf8")) as Record<string, unknown>;
      const workflowPackage = payload.workflowPackage as Record<string, unknown>;
      const trust = workflowPackage.trust as Record<string, unknown>;
      const packageSignature = trust.packageSignature as Record<string, unknown>;
      const artifactManifest = trust.artifactManifest as Record<string, unknown>;

      assert.equal(payload.schemaVersion, 2);
      assert.equal(payload.kind, "nullid-safe-share");
      assert.equal(workflowPackage.kind, "nullid-workflow-package");
      assert.equal(workflowPackage.workflowType, "sanitize-safe-share");
      assert.equal(packageSignature.method, "none");
      assert.equal(artifactManifest.entryCount, 2);

      const inspected = runCli(["package-inspect", outputFile]);
      assert.equal(inspected.envelope, null);
      assert.equal(inspected.artifactType, "safe-share-bundle");
      assert.equal(inspected.verificationState, "integrity-checked");
      assert.equal(inspected.verificationLabel, "Integrity checked");
      assert.equal(Array.isArray(inspected.trustBasis), true);
      assert.equal(Array.isArray(inspected.artifacts), true);
      assert.equal(
        (inspected.artifacts as Array<Record<string, unknown>>).some((artifact) => artifact.status === "verified"),
        true,
      );
      assert.equal(
        (inspected.facts as Array<Record<string, unknown>>).some(
          (fact) => fact.label === "Workflow" && fact.value === "sanitize-safe-share",
        ),
        true,
      );
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("adds safe-share workflow preset metadata when bundle is used as a workflow producer path", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-safe-share-"));
    try {
      const inputFile = path.join(tempDir, "support.log");
      const outputFile = path.join(tempDir, "bundle.json");
      fs.writeFileSync(inputFile, "token=abcdefghijklmnopqrstuvwxyz12345 alice@example.com", "utf8");

      const bundleResult = runCli(["bundle", inputFile, outputFile, "--preset", "json", "--workflow", "support-ticket"]);
      assert.equal(bundleResult.schemaVersion, 2);
      assert.equal(bundleResult.workflowType, "safe-share-assistant");
      assert.equal(bundleResult.workflowPreset, "support-ticket");

      const payload = JSON.parse(fs.readFileSync(outputFile, "utf8")) as Record<string, unknown>;
      const workflowPackage = payload.workflowPackage as Record<string, unknown>;
      const workflowPreset = workflowPackage.workflowPreset as Record<string, unknown>;

      assert.equal(workflowPackage.workflowType, "safe-share-assistant");
      assert.equal(workflowPreset.id, "support-ticket");
      assert.equal(workflowPreset.label, "Support ticket / bug report");

      const inspected = runCli(["package-inspect", outputFile]);
      assert.equal(inspected.artifactType, "safe-share-bundle");
      assert.equal(inspected.verificationState, "integrity-checked");
      assert.equal(
        (inspected.facts as Array<Record<string, unknown>>).some(
          (fact) => fact.label === "Workflow preset" && fact.value === "Support ticket / bug report",
        ),
        true,
      );
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("carries incident-oriented report metadata through the existing bundle path for power users", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-incident-"));
    try {
      const inputFile = path.join(tempDir, "incident.log");
      const outputFile = path.join(tempDir, "bundle.json");
      fs.writeFileSync(inputFile, "token=abcdefghijklmnopqrstuvwxyz12345 alice@example.com", "utf8");

      const bundleResult = runCli([
        "bundle",
        inputFile,
        outputFile,
        "--preset",
        "json",
        "--workflow",
        "internal-investigation",
        "--title",
        "Incident 2026-03-18",
        "--purpose",
        "Prepare an internal responder package.",
        "--case-ref",
        "CASE-142",
        "--recipient",
        "internal responders",
      ]);
      assert.equal(bundleResult.workflowType, "safe-share-assistant");
      assert.equal(bundleResult.workflowPreset, "internal-investigation");

      const payload = JSON.parse(fs.readFileSync(outputFile, "utf8")) as Record<string, unknown>;
      const workflowPackage = payload.workflowPackage as Record<string, unknown>;
      const workflowPreset = workflowPackage.workflowPreset as Record<string, unknown>;
      const report = workflowPackage.report as Record<string, unknown>;
      const summary = workflowPackage.summary as Record<string, unknown>;

      assert.equal(workflowPreset.id, "internal-investigation");
      assert.equal(summary.title, "Incident 2026-03-18");
      assert.equal(report.purpose, "Prepare an internal responder package.");
      assert.equal(report.audience, "internal responders");

      const inspected = runCli(["package-inspect", outputFile]);
      const workflowReport = inspected.workflowReport as Record<string, unknown>;
      assert.equal(inspected.artifactType, "safe-share-bundle");
      assert.equal(inspected.verificationState, "integrity-checked");
      assert.equal(workflowReport.purpose, "Prepare an internal responder package.");
      assert.equal(workflowReport.audience, "internal responders");
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("inspects zip archives locally and verifies them against an archive manifest", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-archive-"));
    try {
      const zipPath = path.join(tempDir, "evidence.zip");
      const manifestPath = path.join(tempDir, "manifest.json");
      const entries = [
        { path: "docs/readme.txt", content: Buffer.from("hello archive") },
        { path: "logs/app.log", content: Buffer.from("token=[redacted]") },
      ];

      fs.writeFileSync(zipPath, Buffer.from(createStoredZip(entries)).toString("binary"), "binary");
      const manifestFiles = await Promise.all(
        entries.map(async (entry) => ({
          path: entry.path,
          sha256After: await sha256Buffer(entry.content),
        })),
      );
      fs.writeFileSync(
        manifestPath,
        JSON.stringify(
          {
            schemaVersion: 2,
            kind: "nullid-archive-manifest",
            files: manifestFiles,
          },
          null,
          2,
        ),
        "utf8",
      );

      const inspected = runCli(["archive-inspect", zipPath, "--manifest", manifestPath]);
      const inspection = inspected.inspection as Record<string, unknown>;
      const verification = inspected.verification as Record<string, unknown>;

      assert.equal(inspection.kind, "nullid-archive-inspection");
      assert.equal(inspection.entryCount, 2);
      assert.equal(verification.matched, 2);
      assert.equal(verification.mismatched, 0);
      assert.equal(verification.missingFromArchive, 0);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("rejects invalid archive manifests before CLI archive comparison", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-invalid-archive-manifest-"));
    try {
      const zipPath = path.join(tempDir, "evidence.zip");
      const manifestPath = path.join(tempDir, "manifest.json");
      fs.writeFileSync(zipPath, Buffer.from(createStoredZip([{ path: "safe.txt", content: Buffer.from("safe") }])).toString("binary"), "binary");
      fs.writeFileSync(
        manifestPath,
        JSON.stringify({
          schemaVersion: 2,
          kind: "nullid-archive-manifest",
          files: [
            { path: "safe.txt", sha256: "a".repeat(64) },
            { path: "SAFE.txt", sha256: "b".repeat(64) },
          ],
        }),
        "utf8",
      );

      const result = runCliRaw(["archive-inspect", zipPath, "--manifest", manifestPath]);

      assert.notEqual(result.status, 0);
      assert.match(`${result.stdout}\n${result.stderr}`, /invalid archive reference manifest|case|collision|duplicate/i);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("keeps CLI and browser ZIP false-size outcomes aligned", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-zip-false-size-"));
    try {
      const zipPath = path.join(tempDir, "false-size.zip");
      fs.writeFileSync(
        zipPath,
        Buffer.from(createZip([{ path: "false-small.txt", content: Buffer.alloc(4096, 0x61), compression: "deflate", uncompressedSizeOverride: 1 }])).toString("binary"),
        "binary",
      );

      const browserInspection = await inspectZipArchiveBytes(fs.readFileSync(zipPath));
      const cliInspection = runCli(["archive-inspect", zipPath]).inspection as {
        entries: Array<{ path: string; status: string; detail: string }>;
      };

      assert.equal(cliInspection.entries[0].path, browserInspection.entries[0].path);
      assert.equal(cliInspection.entries[0].status, browserInspection.entries[0].status);
      assert.match(cliInspection.entries[0].detail, /length|output|decompress/i);
      assert.notEqual(cliInspection.entries[0].status, "hashed");
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("rejects compressed archive inputs one byte over the central size limit before parsing", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-zip-size-"));
    try {
      const boundaryPath = path.join(tempDir, "boundary.zip");
      const overPath = path.join(tempDir, "over.zip");
      fs.closeSync(fs.openSync(boundaryPath, "w"));
      fs.truncateSync(boundaryPath, ZIP_SAFETY_LIMITS.maxArchiveCompressedBytes);
      fs.closeSync(fs.openSync(overPath, "w"));
      fs.truncateSync(overPath, ZIP_SAFETY_LIMITS.maxArchiveCompressedBytes + 1);

      const boundary = runCliRaw(["archive-inspect", boundaryPath]);
      assert.equal(boundary.status, 0);
      const boundaryReport = JSON.parse(boundary.stdout) as { inspection: { entries: Array<{ status: string; detail: string }> } };
      assert.equal(boundaryReport.inspection.entries[0].status, "malformed");
      assert.match(boundaryReport.inspection.entries[0].detail, /end-of-central-directory|malformed|not found/i);

      const over = runCliRaw(["archive-inspect", overPath]);
      assert.notEqual(over.status, 0);
      assert.match(`${over.stdout}\n${over.stderr}`, /exceeds/i);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("rejects archive-sanitize directory inputs that contain symlinks before creating output", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-archive-dir-"));
    try {
      const sourceDir = path.join(tempDir, "source");
      const outputPath = path.join(tempDir, "sanitized.zip");
      fs.mkdirSync(sourceDir);
      fs.writeFileSync(path.join(sourceDir, "safe.txt"), "safe", "utf8");
      fs.symlinkSync(path.join(tempDir, "outside.txt"), path.join(sourceDir, "link.txt"));

      const result = await withNodeOnlyPath((env) => runCliRaw(["archive-sanitize", sourceDir, outputPath], env));
      assert.notEqual(result.status, 0);
      assert.equal(fs.existsSync(outputPath), false);
      assert.match(`${result.stdout}\n${result.stderr}`, /symbolic links|symbolic link|reparse|junction/i);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("omits local paths, preserves filenames, and produces reproducible archive-sanitize output without archive tooling", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-archive-manifest-"));
    try {
      const sourceDir = path.join(tempDir, "source");
      const nestedDir = path.join(sourceDir, "nested");
      const unicodeDir = path.join(sourceDir, "unicode folder");
      const baselinePath = path.join(tempDir, "private-baseline.policy.json");
      const outputPath = path.join(tempDir, "sanitized.zip");
      const repeatOutputPath = path.join(tempDir, "sanitized-repeat.zip");
      fs.mkdirSync(nestedDir, { recursive: true });
      fs.mkdirSync(unicodeDir, { recursive: true });
      fs.writeFileSync(path.join(nestedDir, "note.txt"), "token=abcdefghijklmnopqrstuvwxyz12345", "utf8");
      fs.writeFileSync(path.join(unicodeDir, "résumé note.txt"), "alice@example.com", "utf8");
      fs.writeFileSync(path.join(sourceDir, "empty file.txt"), "", "utf8");
      fs.writeFileSync(
        baselinePath,
        JSON.stringify({
          schemaVersion: 1,
          kind: "nullid-policy-baseline",
          sanitize: { mergeMode: "strict-override", defaultConfig: { rulesState: buildRulesState(["maskEmail"]), jsonAware: false, customRules: [] }, packs: [] },
        }),
        "utf8",
      );

      await withNodeOnlyPath((env) => {
        runCli(["archive-sanitize", sourceDir, outputPath, "--baseline", baselinePath], env);
        runCli(["archive-sanitize", sourceDir, repeatOutputPath, "--baseline", baselinePath], env);
      });
      const outputBytes = fs.readFileSync(outputPath);
      const repeatOutputBytes = fs.readFileSync(repeatOutputPath);
      const manifestText = readZipText(outputBytes, "nullid-archive-manifest.json");
      const { manifest, parsed } = await assertArchiveManifestMatchesZip(outputBytes);

      assert.deepEqual(outputBytes, repeatOutputBytes);
      assert.equal(outputBytes.includes(Buffer.from(tempDir)), false);
      assert.equal(manifestText.includes(tempDir), false);
      assert.equal(manifestText.includes("../"), false);
      assert.equal(manifest.createdAt, "1970-01-01T00:00:00.000Z");
      assert.equal(manifest.source.label, "source");
      assert.equal("input" in manifest.source, false);
      assert.equal(manifest.policy.baseline, "private-baseline.policy.json");
      assert.deepEqual(
        manifest.files.map((entry) => entry.path).sort(),
        ["empty file.txt", "nested/note.txt", "unicode folder/résumé note.txt"],
      );
      assert.equal(parsed.entries.some((entry: { path: string; directory: boolean }) => entry.directory && entry.path === "nested/"), true);
      assert.equal(parsed.entries.some((entry: { path: string; directory: boolean }) => entry.directory && entry.path === "unicode folder/"), true);
      assert.equal(readZipText(outputBytes, "empty file.txt"), "");
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("sanitizes safe ZIP inputs without external archive tooling", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-archive-zip-input-"));
    try {
      const inputZip = path.join(tempDir, "input.zip");
      const baselinePath = path.join(tempDir, "baseline.json");
      const outputPath = path.join(tempDir, "sanitized.zip");
      writeMaskEmailBaseline(baselinePath);
      fs.writeFileSync(
        inputZip,
        Buffer.from(
          createStoredZip([
            { path: "docs/space name.txt", content: Buffer.from("alice@example.com", "utf8") },
            { path: "unicode/résumé.txt", content: Buffer.from("bob@example.com", "utf8") },
            { path: "empty.txt", content: Buffer.alloc(0) },
          ]),
        ).toString("binary"),
        "binary",
      );

      const result = await withNodeOnlyPath((env) => runCli(["archive-sanitize", inputZip, outputPath, "--baseline", baselinePath], env));
      const outputBytes = fs.readFileSync(outputPath);
      const { manifest } = await assertArchiveManifestMatchesZip(outputBytes);

      assert.equal(result.files, 3);
      assert.equal(manifest.source.sourceType, "zip");
      assert.deepEqual(
        manifest.files.map((entry) => entry.path).sort(),
        ["docs/space name.txt", "empty.txt", "unicode/résumé.txt"],
      );
      assert.equal(readZipText(outputBytes, "docs/space name.txt").includes("alice@example.com"), false);
      assert.equal(readZipText(outputBytes, "unicode/résumé.txt").includes("bob@example.com"), false);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("keeps archive-sanitize overwrite and no-follow output behavior intact", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-archive-output-"));
    try {
      const sourceDir = path.join(tempDir, "source");
      const baselinePath = path.join(tempDir, "baseline.json");
      const outputPath = path.join(tempDir, "sanitized.zip");
      fs.mkdirSync(sourceDir);
      fs.writeFileSync(path.join(sourceDir, "note.txt"), "alice@example.com", "utf8");
      writeMaskEmailBaseline(baselinePath);
      fs.writeFileSync(outputPath, "existing output must remain unchanged", "utf8");

      const rejected = await withNodeOnlyPath((env) => runCliRaw(["archive-sanitize", sourceDir, outputPath, "--baseline", baselinePath], env));
      assert.notEqual(rejected.status, 0);
      assert.equal(fs.readFileSync(outputPath, "utf8"), "existing output must remain unchanged");
      assert.equal(fs.readdirSync(tempDir).some((name) => name.startsWith(".nullid-")), false);

      const forced = await withNodeOnlyPath((env) => runCliRaw(["archive-sanitize", sourceDir, outputPath, "--baseline", baselinePath, "--force"], env));
      assert.equal(forced.status, 0);
      assert.equal(readZipText(fs.readFileSync(outputPath), "note.txt").includes("alice@example.com"), false);

      if (process.platform !== "win32") {
        const victimPath = path.join(tempDir, "victim.zip");
        const linkPath = path.join(tempDir, "linked-output.zip");
        fs.writeFileSync(victimPath, "victim must remain unchanged", "utf8");
        fs.symlinkSync(victimPath, linkPath);
        const symlinked = await withNodeOnlyPath((env) => runCliRaw(["archive-sanitize", sourceDir, linkPath, "--baseline", baselinePath, "--force"], env));
        assert.notEqual(symlinked.status, 0);
        assert.equal(fs.readFileSync(victimPath, "utf8"), "victim must remain unchanged");
        assert.match(`${symlinked.stdout}\n${symlinked.stderr}`, /symlink|symbolic|no-follow|output path/i);
      }
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("reports Windows drive, UNC, and case-collision archive paths in CLI inspection", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-archive-path-policy-"));
    try {
      const driveZip = path.join(tempDir, "drive.zip");
      const uncZip = path.join(tempDir, "unc.zip");
      const caseZip = path.join(tempDir, "case.zip");
      fs.writeFileSync(driveZip, Buffer.from(createStoredZip([{ path: "C:/secret.txt", content: Buffer.from("secret") }])).toString("binary"), "binary");
      fs.writeFileSync(uncZip, Buffer.from(createStoredZip([{ path: "//server/share/secret.txt", content: Buffer.from("secret") }])).toString("binary"), "binary");
      fs.writeFileSync(
        caseZip,
        Buffer.from(
          createStoredZip([
            { path: "Case.txt", content: Buffer.from("one") },
            { path: "case.txt", content: Buffer.from("two") },
          ]),
        ).toString("binary"),
        "binary",
      );

      const drive = runCli(["archive-inspect", driveZip]).inspection as { warnings: string[] };
      const unc = runCli(["archive-inspect", uncZip]).inspection as { warnings: string[] };
      const caseCollision = runCli(["archive-inspect", caseZip]).inspection as { warnings: string[] };

      assert.match(drive.warnings.join("\n"), /drive letter|Windows/i);
      assert.match(unc.warnings.join("\n"), /UNC/i);
      assert.match(caseCollision.warnings.join("\n"), /case-folding|collision/i);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("rejects unsupported special files in archive-sanitize directory inputs where the platform can create them", async () => {
    if (process.platform === "win32") return;
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-archive-special-"));
    const server = net.createServer();
    let listening = false;
    try {
      const sourceDir = path.join(tempDir, "source");
      const outputPath = path.join(tempDir, "sanitized.zip");
      const socketPath = path.join(sourceDir, "local.sock");
      fs.mkdirSync(sourceDir);
      fs.writeFileSync(path.join(sourceDir, "safe.txt"), "safe", "utf8");
      try {
        await new Promise<void>((resolve, reject) => {
          server.once("error", reject);
          server.listen(socketPath, () => {
            listening = true;
            resolve();
          });
        });
      } catch (error) {
        const code = error && typeof error === "object" && "code" in error ? String(error.code) : "";
        if (code === "EACCES" || code === "EPERM") return;
        throw error;
      }

      const result = await withNodeOnlyPath((env) => runCliRaw(["archive-sanitize", sourceDir, outputPath], env));
      assert.notEqual(result.status, 0);
      assert.equal(fs.existsSync(outputPath), false);
      assert.match(`${result.stdout}\n${result.stderr}`, /special files|special file|socket/i);
    } finally {
      if (listening) {
        await new Promise<void>((resolve) => server.close(() => resolve()));
      }
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("rejects archive-sanitize directory junctions on Windows where supported", async () => {
    if (process.platform !== "win32") return;
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-archive-junction-"));
    try {
      const sourceDir = path.join(tempDir, "source");
      const targetDir = path.join(tempDir, "target");
      const outputPath = path.join(tempDir, "sanitized.zip");
      fs.mkdirSync(sourceDir);
      fs.mkdirSync(targetDir);
      fs.writeFileSync(path.join(targetDir, "secret.txt"), "secret", "utf8");
      try {
        fs.symlinkSync(targetDir, path.join(sourceDir, "junction"), "junction");
      } catch {
        return;
      }

      const result = await withNodeOnlyPath((env) => runCliRaw(["archive-sanitize", sourceDir, outputPath], env));
      assert.notEqual(result.status, 0);
      assert.equal(fs.existsSync(outputPath), false);
      assert.match(`${result.stdout}\n${result.stderr}`, /symbolic|junction|reparse/i);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("inspects encrypted workflow package envelopes when a passphrase is provided", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-envelope-"));
    try {
      const inputFile = path.join(tempDir, "incident.log");
      const bundleFile = path.join(tempDir, "bundle.json");
      const encryptedFile = path.join(tempDir, "bundle.nullid");
      fs.writeFileSync(inputFile, "user=alice from 203.0.113.10", "utf8");

      runCli(["bundle", inputFile, bundleFile, "--preset", "nginx"]);
      runCli(["enc", bundleFile, encryptedFile, "--pass-env", "NULLID_PASSPHRASE"], {
        NULLID_PASSPHRASE: "inspect-secret",
      });
      assert.equal(fs.readFileSync(encryptedFile, "utf8").trim().startsWith("NULLID:ENC:2."), true);

      const locked = runCli(["package-inspect", encryptedFile]);
      assert.equal(locked.artifactType, "envelope");
      assert.equal(locked.verificationState, "verification-required");

      const inspected = runCli(["package-inspect", encryptedFile, "--pass-env", "NULLID_PASSPHRASE"], {
        NULLID_PASSPHRASE: "inspect-secret",
      });

      const envelope = inspected.envelope as Record<string, unknown>;
      assert.equal(inspected.artifactType, "safe-share-bundle");
      assert.equal(inspected.verificationState, "integrity-checked");
      assert.equal(envelope.prefix, "NULLID:ENC:2");
      assert.equal(envelope.metadataAuthenticated, true);
      assert.equal(
        (inspected.trustBasis as Array<unknown>)[0],
        "NULLID:ENC:2 envelope decrypted locally.",
      );
      assert.equal(
        (inspected.facts as Array<Record<string, unknown>>).some(
          (fact) => fact.label === "Workflow" && fact.value === "sanitize-safe-share",
        ),
        true,
      );
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("still inspects legacy v1 encrypted workflow package envelopes", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-legacy-envelope-"));
    try {
      const inputFile = path.join(tempDir, "incident.log");
      const bundleFile = path.join(tempDir, "bundle.json");
      const encryptedFile = path.join(tempDir, "legacy.nullid");
      fs.writeFileSync(inputFile, "user=alice from 203.0.113.10", "utf8");

      runCli(["bundle", inputFile, bundleFile, "--preset", "nginx"]);
      const legacyEnvelope = await createLegacyEnvelopeForTest(
        "inspect-secret",
        utf8ToBytes(fs.readFileSync(bundleFile, "utf8")),
        { mime: "application/json", name: "bundle.json" },
      );
      fs.writeFileSync(encryptedFile, `${legacyEnvelope}\n`, "utf8");

      const inspected = runCli(["package-inspect", encryptedFile, "--pass-env", "NULLID_PASSPHRASE"], {
        NULLID_PASSPHRASE: "inspect-secret",
      });

      const envelope = inspected.envelope as Record<string, unknown>;
      assert.equal(inspected.artifactType, "safe-share-bundle");
      assert.equal(envelope.prefix, "NULLID:ENC:1");
      assert.equal(envelope.metadataAuthenticated, false);
      assert.equal(
        (inspected.trustBasis as Array<unknown>)[0],
        "NULLID:ENC:1 envelope decrypted locally.",
      );
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("verifies signed policy packs when a shared secret is provided", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-policy-"));
    try {
      const outputFile = path.join(tempDir, "signed-policy.json");
      const snapshot = await createPolicyPackSnapshot(
        [
          {
            id: "pack-1",
            name: "team-default",
            createdAt: "2026-03-17T10:00:00.000Z",
            config: {
              rulesState: buildRulesState(["maskIp"]),
              jsonAware: true,
              customRules: [],
            },
          },
        ],
        { signingPassphrase: "policy-secret", keyHint: "secops-policy-v1" },
      );
      fs.writeFileSync(outputFile, JSON.stringify(snapshot, null, 2), "utf8");

      const required = runCli(["package-inspect", outputFile], { NULLID_VERIFY_PASSPHRASE: "" });
      assert.equal(required.artifactType, "policy-pack");
      assert.equal(required.verificationState, "verification-required");

      const verified = runCli(["package-inspect", outputFile, "--verify-pass", "policy-secret"]);
      assert.equal(verified.artifactType, "policy-pack");
      assert.equal(verified.verificationState, "verified");
      assert.equal(verified.verificationLabel, "HMAC verified");
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("reports malformed and invalid workflow artifacts cleanly", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-invalid-"));
    try {
      const malformedFile = path.join(tempDir, "malformed.json");
      const invalidWorkflowFile = path.join(tempDir, "invalid-workflow.json");
      fs.writeFileSync(malformedFile, "{bad-json", "utf8");
      fs.writeFileSync(
        invalidWorkflowFile,
        JSON.stringify({ kind: "nullid-workflow-package", schemaVersion: 99, packageType: "bundle" }, null, 2),
        "utf8",
      );

      const malformed = runCli(["package-inspect", malformedFile]);
      assert.equal(malformed.artifactType, "malformed");
      assert.equal(malformed.verificationState, "malformed");

      const invalid = runCli(["package-inspect", invalidWorkflowFile]);
      assert.equal(invalid.artifactType, "workflow-package");
      assert.equal(invalid.verificationState, "invalid");
      assert.match(String(invalid.failure), /unsupported workflow package schema: 99/i);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });
});

describe("nullid local cli redaction and filesystem safety", () => {
  it("omits exact originals from redact stdout while still writing redacted output", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-redact-privacy-"));
    try {
      const inputFile = path.join(tempDir, "input.txt");
      const outputFile = path.join(tempDir, "output.txt");
      const email = "alice@example.com";
      const token = "abcdefghijklmnopqrstuvwxyz12345";
      const privateKey = "-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----";
      fs.writeFileSync(inputFile, `email=${email}\ntoken=${token}\n${privateKey}\n`, "utf8");

      const result = runCliRaw(["redact", inputFile, outputFile]);

      assert.equal(result.status, 0);
      const stdout = result.stdout;
      const output = fs.readFileSync(outputFile, "utf8");
      for (const secret of [email, token, privateKey]) {
        assert.equal(stdout.includes(secret), false, secret);
        assert.equal(output.includes(secret), false, secret);
      }
      const parsed = JSON.parse(stdout) as { changes: Array<Record<string, unknown>> };
      assert.equal(parsed.changes.some((change) => "original" in change), false);
      assert.equal(parsed.changes.some((change) => "fingerprint" in change), false);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("refuses to write a CLI sanitize output through a symlink", () => {
    if (process.platform === "win32") return;
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-sanitize-symlink-"));
    try {
      const inputFile = path.join(tempDir, "input.txt");
      const victimFile = path.join(tempDir, "victim.txt");
      const outputLink = path.join(tempDir, "out.txt");
      fs.writeFileSync(inputFile, "alice@example.com", "utf8");
      fs.writeFileSync(victimFile, "victim must remain unchanged", "utf8");
      fs.symlinkSync(victimFile, outputLink);

      const result = runCliRaw(["sanitize", inputFile, outputLink, "--preset", "apache"]);

      assert.notEqual(result.status, 0);
      assert.equal(fs.readFileSync(victimFile, "utf8"), "victim must remain unchanged");
      assert.match(`${result.stdout}\n${result.stderr}`, /symlink|symbolic|no-follow|output path/i);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("refuses to overwrite a regular sanitize output unless force is explicit", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-sanitize-overwrite-"));
    try {
      const inputFile = path.join(tempDir, "input.txt");
      const outputFile = path.join(tempDir, "out.txt");
      const baselineFile = path.join(tempDir, "baseline.policy.json");
      fs.writeFileSync(inputFile, "alice@example.com", "utf8");
      fs.writeFileSync(outputFile, "existing output must remain unchanged", "utf8");
      fs.writeFileSync(
        baselineFile,
        JSON.stringify({
          schemaVersion: 1,
          kind: "nullid-policy-baseline",
          sanitize: {
            mergeMode: "strict-override",
            defaultConfig: { rulesState: buildRulesState(["maskEmail"]), jsonAware: false, customRules: [] },
            packs: [],
          },
        }),
        "utf8",
      );

      const rejected = runCliRaw(["sanitize", inputFile, outputFile, "--baseline", baselineFile]);

      assert.notEqual(rejected.status, 0);
      assert.equal(fs.readFileSync(outputFile, "utf8"), "existing output must remain unchanged");
      assert.match(`${rejected.stdout}\n${rejected.stderr}`, /already exists|force/i);

      const forced = runCliRaw(["sanitize", inputFile, outputFile, "--baseline", baselineFile, "--force"]);

      assert.equal(forced.status, 0);
      assert.equal(fs.readFileSync(outputFile, "utf8"), "[email]");
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("refuses precommit sanitization for paths outside the repository root", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-precommit-outside-"));
    try {
      const outsideFile = path.join(tempDir, "outside.txt");
      const original = "key AKIAABCDEFGHIJKLMNOP\n";
      fs.writeFileSync(outsideFile, original, "utf8");

      const result = runCliRaw(["precommit", "--files", outsideFile, "--apply-sanitize", "--threshold", "low"]);

      assert.notEqual(result.status, 0);
      assert.equal(fs.readFileSync(outsideFile, "utf8"), original);
      assert.match(`${result.stdout}\n${result.stderr}`, /outside|repository|worktree|precommit/i);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("refuses precommit reads from in-repository symlinks even when no write is requested", () => {
    const tempDir = fs.mkdtempSync(path.join(process.cwd(), ".tmp-nullid-cli-precommit-symlink-"));
    try {
      const targetFile = path.join(tempDir, "safe.txt");
      const linkFile = path.join(tempDir, "link.txt");
      fs.writeFileSync(targetFile, "ordinary text without findings\n", "utf8");
      try {
        fs.symlinkSync(targetFile, linkFile);
      } catch {
        return;
      }

      const result = runCliRaw(["precommit", "--files", path.relative(process.cwd(), linkFile), "--threshold", "high"]);

      assert.notEqual(result.status, 0);
      assert.match(`${result.stdout}\n${result.stderr}`, /symlink|symbolic|reparse|junction|precommit/i);
      assert.equal(fs.readFileSync(targetFile, "utf8"), "ordinary text without findings\n");
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("refuses sanitize-dir output roots that traverse through a symlinked parent", () => {
    if (process.platform === "win32") return;
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-sanitize-dir-symlink-"));
    try {
      const sourceDir = path.join(tempDir, "source");
      const victimDir = path.join(tempDir, "victim");
      const outputLink = path.join(tempDir, "out-link");
      fs.mkdirSync(sourceDir);
      fs.mkdirSync(victimDir);
      fs.writeFileSync(path.join(sourceDir, "note.txt"), "alice@example.com", "utf8");
      fs.symlinkSync(victimDir, outputLink, "dir");

      const result = runCliRaw(["sanitize-dir", sourceDir, outputLink, "--preset", "apache"]);

      assert.notEqual(result.status, 0);
      assert.equal(fs.existsSync(path.join(victimDir, "note.txt")), false);
      assert.match(`${result.stdout}\n${result.stderr}`, /symlink|symbolic|no-follow|output path/i);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });
});

describe("nullid local cli wizard", () => {
  it("walks through workflow selection, transform preview, and export", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-wizard-"));
    try {
      const outputPath = path.join(tempDir, "wizard-bundle.json");
      const result = spawnSync(process.execPath, [
        cliPath,
        "wizard",
        "--workflow",
        "support-ticket",
        "--input-mode",
        "text",
        "--preset",
        "nginx",
        "--text",
        "token=abcdefghijklmnopqrstuvwxyz12345 alice@example.com",
        "--output",
        outputPath,
        "--yes",
      ], {
        cwd: process.cwd(),
        encoding: "utf8",
      });

      assert.equal(result.status, 0);
      assert.match(result.stdout, /Preview transforms:/);
      assert.match(fs.readFileSync(outputPath, "utf8"), /workflowPackage/);

      const payload = JSON.parse(fs.readFileSync(outputPath, "utf8")) as Record<string, unknown>;
      const workflowPackage = payload.workflowPackage as Record<string, unknown>;
      const workflowPreset = workflowPackage.workflowPreset as Record<string, unknown>;
      const transforms = workflowPackage.transforms as Array<Record<string, unknown>>;

      assert.equal(workflowPackage.workflowType, "safe-share-assistant");
      assert.equal(workflowPreset.id, "support-ticket");
      assert.equal(
        transforms.some((transform) => transform.label === "Sanitize transformation"),
        true,
      );
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });
});

describe("nullid local cli sanitize parity", () => {
  it("applies international phone masking when the policy enables maskPhoneIntl", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-sanitize-phone-"));
    try {
      const inputFile = path.join(tempDir, "input.txt");
      const outputFile = path.join(tempDir, "output.txt");
      const baselineFile = path.join(tempDir, "baseline.json");
      fs.writeFileSync(inputFile, "fa: ۰۹۱۲۳۴۵۶۷۸۹ ru: +7 (912) 345-67-89", "utf8");

      fs.writeFileSync(
        baselineFile,
        JSON.stringify(
          {
            schemaVersion: 1,
            kind: "nullid-policy-baseline",
            sanitize: {
              mergeMode: "strict-override",
              defaultConfig: {
                rulesState: buildRulesState(["maskPhoneIntl"]),
                jsonAware: false,
                customRules: [],
              },
              packs: [],
            },
          },
          null,
          2,
        ),
        "utf8",
      );

      const result = runCli(["sanitize", inputFile, outputFile, "--baseline", baselineFile]);
      const output = fs.readFileSync(outputFile, "utf8");

      assert.equal(output, "fa: [phone] ru: [phone]");
      assert.deepEqual(result.appliedRules, ["maskPhoneIntl"]);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("applies Iran national ID masking when the policy enables maskIranNationalId", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-sanitize-iran-id-"));
    try {
      const inputFile = path.join(tempDir, "input.txt");
      const outputFile = path.join(tempDir, "output.txt");
      const baselineFile = path.join(tempDir, "baseline.json");
      fs.writeFileSync(inputFile, "id: ۱۰۰۰۰۰۰۰۰۱ invalid: ۱۲۳۴۵۶۷۸۹۰", "utf8");

      fs.writeFileSync(
        baselineFile,
        JSON.stringify(
          {
            schemaVersion: 1,
            kind: "nullid-policy-baseline",
            sanitize: {
              mergeMode: "strict-override",
              defaultConfig: {
                rulesState: buildRulesState(["maskIranNationalId"]),
                jsonAware: false,
                customRules: [],
              },
              packs: [],
            },
          },
          null,
          2,
        ),
        "utf8",
      );

      const result = runCli(["sanitize", inputFile, outputFile, "--baseline", baselineFile]);
      const output = fs.readFileSync(outputFile, "utf8");

      assert.equal(output, "id: [iran-id] invalid: ۱۲۳۴۵۶۷۸۹۰");
      assert.deepEqual(result.appliedRules, ["maskIranNationalId"]);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("rejects multi-pack policy input instead of silently using the first pack", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-sanitize-multipack-"));
    try {
      const inputFile = path.join(tempDir, "input.txt");
      const outputFile = path.join(tempDir, "output.txt");
      const policyFile = path.join(tempDir, "policy.json");
      fs.writeFileSync(inputFile, "alice@example.com from 203.0.113.10", "utf8");

      const snapshot = await createPolicyPackSnapshot([
        {
          id: "pack-ip",
          name: "ip-only",
          createdAt: "2026-03-31T10:10:00.000Z",
          config: {
            rulesState: buildRulesState(["maskIp"]),
            jsonAware: false,
            customRules: [],
          },
        },
        {
          id: "pack-email",
          name: "email-only",
          createdAt: "2026-03-31T10:11:00.000Z",
          config: {
            rulesState: buildRulesState(["maskEmail"]),
            jsonAware: false,
            customRules: [],
          },
        },
      ]);
      fs.writeFileSync(policyFile, JSON.stringify(snapshot, null, 2), "utf8");

      const result = runCliRaw(["sanitize", inputFile, outputFile, "--policy", policyFile]);
      assert.equal(result.status, 1);
      assert.match(
        `${result.stdout}\n${result.stderr}`,
        /multiple packs; CLI sanitize requires a single-pack export or a direct policy config/i,
      );
      assert.throws(() => fs.readFileSync(outputFile, "utf8"));
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("still applies a safe custom regex rule in the CLI sanitize path", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-sanitize-custom-safe-"));
    try {
      const inputFile = path.join(tempDir, "input.txt");
      const outputFile = path.join(tempDir, "output.txt");
      const baselineFile = path.join(tempDir, "baseline.json");
      fs.writeFileSync(inputFile, "token=abc123", "utf8");

      fs.writeFileSync(
        baselineFile,
        JSON.stringify(
          {
            schemaVersion: 1,
            kind: "nullid-policy-baseline",
            sanitize: {
              mergeMode: "strict-override",
              defaultConfig: {
                rulesState: buildRulesState([]),
                jsonAware: false,
                customRules: [{ pattern: "token=([a-z0-9]+)", replacement: "token=[redacted]", flags: "gi", scope: "text" }],
              },
              packs: [],
            },
          },
          null,
          2,
        ),
        "utf8",
      );

      const result = runCli(["sanitize", inputFile, outputFile, "--baseline", baselineFile]);
      const output = fs.readFileSync(outputFile, "utf8");

      assert.equal(output, "token=[redacted]");
      assert.equal(
        (result.report as Array<string>).some((entry) => entry === "custom:token=([a-z0-9]+):1"),
        true,
      );
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("runs finite quantified custom regex rules in the CLI worker path", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-sanitize-custom-finite-"));
    try {
      const inputFile = path.join(tempDir, "input.txt");
      const outputFile = path.join(tempDir, "output.txt");
      const baselineFile = path.join(tempDir, "baseline.json");
      fs.writeFileSync(inputFile, "a".repeat(30), "utf8");

      fs.writeFileSync(
        baselineFile,
        JSON.stringify(
          {
            schemaVersion: 1,
            kind: "nullid-policy-baseline",
            sanitize: {
              mergeMode: "strict-override",
              defaultConfig: {
                rulesState: buildRulesState([]),
                jsonAware: false,
                customRules: [{ pattern: "^(a+){10}$", replacement: "[x]", flags: "g", scope: "text" }],
              },
              packs: [],
            },
          },
          null,
          2,
        ),
        "utf8",
      );

      const result = runCli(["sanitize", inputFile, outputFile, "--baseline", baselineFile]);
      const output = fs.readFileSync(outputFile, "utf8");

      assert.equal(output, "[x]");
      assert.equal(
        (result.report as Array<string>).some((entry) => /custom:\^\(a\+\)\{10\}\$:1/i.test(entry)),
        true,
      );
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("times out unsafe custom regex rules in the CLI sanitize worker path", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-sanitize-custom-unsafe-"));
    try {
      const inputFile = path.join(tempDir, "input.txt");
      const outputFile = path.join(tempDir, "output.txt");
      const baselineFile = path.join(tempDir, "baseline.json");
      const hostileInput = `${"a".repeat(1024)}!`;
      fs.writeFileSync(inputFile, hostileInput, "utf8");

      fs.writeFileSync(
        baselineFile,
        JSON.stringify(
          {
            schemaVersion: 1,
            kind: "nullid-policy-baseline",
            sanitize: {
              mergeMode: "strict-override",
              defaultConfig: {
                rulesState: buildRulesState([]),
                jsonAware: false,
                customRules: [{ pattern: "(a+)+$", replacement: "[x]", flags: "g", scope: "text" }],
              },
              packs: [],
            },
          },
          null,
          2,
        ),
        "utf8",
      );

      const result = runCliRaw(["sanitize", inputFile, outputFile, "--baseline", baselineFile]);

      assert.notEqual(result.status, 0);
      assert.equal(fs.existsSync(outputFile), false);
      assert.match(`${result.stdout}\n${result.stderr}`, /custom regex rule .* failed \(timeout\)/i);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("leaves CLI sanitize output absent when a custom regex has invalid syntax", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-sanitize-custom-invalid-"));
    try {
      const inputFile = path.join(tempDir, "input.txt");
      const outputFile = path.join(tempDir, "output.txt");
      const baselineFile = path.join(tempDir, "baseline.json");
      fs.writeFileSync(inputFile, "email alice@example.com token=abc123", "utf8");

      fs.writeFileSync(
        baselineFile,
        JSON.stringify(
          {
            schemaVersion: 1,
            kind: "nullid-policy-baseline",
            sanitize: {
              mergeMode: "strict-override",
              defaultConfig: {
                rulesState: buildRulesState(["maskEmail"]),
                jsonAware: false,
                customRules: [{ pattern: "token=(", replacement: "token=[redacted]", flags: "g", scope: "text" }],
              },
              packs: [],
            },
          },
          null,
          2,
        ),
        "utf8",
      );

      const result = runCliRaw(["sanitize", inputFile, outputFile, "--baseline", baselineFile]);

      assert.notEqual(result.status, 0);
      assert.equal(fs.existsSync(outputFile), false);
      assert.match(`${result.stdout}\n${result.stderr}`, /custom regex rule .* failed \(syntax-error\)/i);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("leaves sanitize-dir outputs unchanged when a later custom regex file fails", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-sanitize-dir-custom-fail-"));
    try {
      const sourceDir = path.join(tempDir, "source");
      const outputDir = path.join(tempDir, "out");
      const baselineFile = path.join(tempDir, "baseline.json");
      fs.mkdirSync(sourceDir);
      fs.mkdirSync(outputDir);
      fs.writeFileSync(path.join(sourceDir, "01-safe.txt"), "clean text", "utf8");
      fs.writeFileSync(path.join(sourceDir, "02-hostile.txt"), `${"a".repeat(1024)}!`, "utf8");
      fs.writeFileSync(path.join(outputDir, "01-safe.txt"), "existing output must remain unchanged", "utf8");

      fs.writeFileSync(
        baselineFile,
        JSON.stringify(
          {
            schemaVersion: 1,
            kind: "nullid-policy-baseline",
            sanitize: {
              mergeMode: "strict-override",
              defaultConfig: {
                rulesState: buildRulesState([]),
                jsonAware: false,
                customRules: [{ pattern: "(a+)+$", replacement: "[x]", flags: "g", scope: "text" }],
              },
              packs: [],
            },
          },
          null,
          2,
        ),
        "utf8",
      );

      const result = runCliRaw(["sanitize-dir", sourceDir, outputDir, "--baseline", baselineFile, "--ext", ".txt"]);
      const summary = JSON.parse(result.stdout) as { counts: Record<string, number> };

      assert.notEqual(result.status, 0);
      assert.equal(fs.readFileSync(path.join(outputDir, "01-safe.txt"), "utf8"), "existing output must remain unchanged");
      assert.equal(fs.existsSync(path.join(outputDir, "02-hostile.txt")), false);
      assert.equal(summary.counts.failed, 1);
      assert.equal(summary.counts.processed, 0);
      assert.equal(summary.counts.prepared, 1);
      assert.match(`${result.stdout}\n${result.stderr}`, /custom regex rule .* failed \(timeout\)/i);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });
});

describe("nullid local cli verification presentation parity", () => {
  it("matches web presentation for unsigned integrity-checked policy/profile/vault snapshots", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-verify-success-"));
    try {
      const policy = await createPolicyPackSnapshot([
        {
          id: "pack-unsigned",
          name: "team-default",
          createdAt: "2026-03-17T10:00:00.000Z",
          config: {
            rulesState: buildRulesState(["maskIp"]),
            jsonAware: true,
            customRules: [],
          },
        },
      ]);
      const profile = await createUnsignedProfileSnapshotForCliTest();
      const vault = await createUnsignedVaultSnapshotForCliTest();

      const policyPath = path.join(tempDir, "policy.json");
      const profilePath = path.join(tempDir, "profile.json");
      const vaultPath = path.join(tempDir, "vault.json");
      fs.writeFileSync(policyPath, JSON.stringify(policy, null, 2), "utf8");
      fs.writeFileSync(profilePath, JSON.stringify(profile, null, 2), "utf8");
      fs.writeFileSync(vaultPath, JSON.stringify(vault, null, 2), "utf8");

      const [cliPolicy, cliProfile, cliVault] = [
        runCli(["package-inspect", policyPath]),
        runCli(["package-inspect", profilePath]),
        runCli(["package-inspect", vaultPath]),
      ];
      const [webPolicy, webProfile, webVault] = await Promise.all([
        inspectReceivedArtifact(JSON.stringify(policy)),
        inspectReceivedArtifact(JSON.stringify(profile)),
        inspectReceivedArtifact(JSON.stringify(vault)),
      ]);

      assert.equal(webPolicy.verificationState, "integrity-checked");
      assert.equal(webProfile.verificationState, "integrity-checked");
      assert.equal(webVault.verificationState, "integrity-checked");
      assertVerificationPresentationParity(cliPolicy, webPolicy, true);
      assertVerificationPresentationParity(cliProfile, webProfile, true);
      assertVerificationPresentationParity(cliVault, webVault, true);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("matches web mismatch presentation for signed policy/profile/vault snapshots", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-verify-mismatch-"));
    try {
      const policy = await createPolicyPackSnapshot(
        [
          {
            id: "pack-signed",
            name: "team-default",
            createdAt: "2026-03-17T10:00:00.000Z",
            config: {
              rulesState: buildRulesState(["maskIp"]),
              jsonAware: true,
              customRules: [],
            },
          },
        ],
        { signingPassphrase: "policy-secret" },
      );
      const profile = await createSignedProfileSnapshotForCliTest("profile-secret");
      const vault = await createSignedVaultSnapshotForCliTest("vault-secret");

      const policyPath = path.join(tempDir, "policy-signed.json");
      const profilePath = path.join(tempDir, "profile-signed.json");
      const vaultPath = path.join(tempDir, "vault-signed.json");
      fs.writeFileSync(policyPath, JSON.stringify(policy, null, 2), "utf8");
      fs.writeFileSync(profilePath, JSON.stringify(profile, null, 2), "utf8");
      fs.writeFileSync(vaultPath, JSON.stringify(vault, null, 2), "utf8");

      const [cliPolicy, cliProfile, cliVault] = [
        runCli(["package-inspect", policyPath, "--verify-pass", "wrong-secret"]),
        runCli(["package-inspect", profilePath, "--verify-pass", "wrong-secret"]),
        runCli(["package-inspect", vaultPath, "--verify-pass", "wrong-secret"]),
      ];
      const [webPolicy, webProfile, webVault] = await Promise.all([
        inspectReceivedArtifact(JSON.stringify(policy), { verificationPassphrase: "wrong-secret" }),
        inspectReceivedArtifact(JSON.stringify(profile), { verificationPassphrase: "wrong-secret" }),
        inspectReceivedArtifact(JSON.stringify(vault), { verificationPassphrase: "wrong-secret" }),
      ]);

      assert.equal(webPolicy.verificationState, "mismatch");
      assert.equal(webProfile.verificationState, "mismatch");
      assert.equal(webVault.verificationState, "mismatch");
      assertVerificationPresentationParity(cliPolicy, webPolicy, true);
      assertVerificationPresentationParity(cliProfile, webProfile, true);
      assertVerificationPresentationParity(cliVault, webVault, true);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });
});

function assertVerificationPresentationParity(cliResult: Record<string, unknown>, webResult: Awaited<ReturnType<typeof inspectReceivedArtifact>>, compareArtifacts: boolean) {
  assert.equal(cliResult.verificationState, webResult.verificationState);
  assert.equal(cliResult.verificationLabel, webResult.verificationLabel);
  if (!compareArtifacts) return;
  assert.deepEqual(
    ((cliResult.artifacts as Array<Record<string, unknown>> | undefined) ?? []).map((artifact) => artifact.status),
    webResult.artifacts.map((artifact) => artifact.status),
  );
}

async function createUnsignedProfileSnapshotForCliTest() {
  const exportedAt = "2026-03-17T09:00:00.000Z";
  const entries = { "nullid:theme": "light" };
  const { integrity } = await createSnapshotIntegrity(
    {
      schemaVersion: PROFILE_SCHEMA_VERSION,
      exportedAt,
      entries,
    },
    "entryCount",
    Object.keys(entries).length,
  );
  return {
    schemaVersion: PROFILE_SCHEMA_VERSION,
    kind: "profile" as const,
    exportedAt,
    entries,
    integrity,
  };
}

async function createSignedProfileSnapshotForCliTest(signingPassphrase: string) {
  const exportedAt = "2026-03-17T09:00:00.000Z";
  const entries = { "nullid:theme": "light" };
  const { integrity, signature } = await createSnapshotIntegrity(
    {
      schemaVersion: PROFILE_SCHEMA_VERSION,
      exportedAt,
      entries,
    },
    "entryCount",
    Object.keys(entries).length,
    { signingPassphrase },
  );
  return {
    schemaVersion: PROFILE_SCHEMA_VERSION,
    kind: "profile" as const,
    exportedAt,
    entries,
    integrity,
    signature,
  };
}

async function createUnsignedVaultSnapshotForCliTest() {
  const vault = buildVaultSnapshotFixtureForCliTest();
  const exportedAt = "2026-03-17T08:00:00.000Z";
  const { integrity } = await createSnapshotIntegrity(
    {
      schemaVersion: 2,
      exportedAt,
      vault,
    },
    "noteCount",
    vault.notes.length,
  );
  return {
    schemaVersion: 2,
    kind: "vault" as const,
    exportedAt,
    vault,
    integrity,
  };
}

async function createSignedVaultSnapshotForCliTest(signingPassphrase: string) {
  const vault = buildVaultSnapshotFixtureForCliTest();
  const exportedAt = "2026-03-17T08:00:00.000Z";
  const { integrity, signature } = await createSnapshotIntegrity(
    {
      schemaVersion: 2,
      exportedAt,
      vault,
    },
    "noteCount",
    vault.notes.length,
    { signingPassphrase },
  );
  return {
    schemaVersion: 2,
    kind: "vault" as const,
    exportedAt,
    vault,
    integrity,
    signature,
  };
}

function buildVaultSnapshotFixtureForCliTest() {
  const fixtureSalt = toBase64Url(utf8ToBytes("signed-salt-1234"));
  const fixtureIv = toBase64Url(utf8ToBytes("0123456789ab"));
  const fixtureCiphertext = toBase64Url(utf8ToBytes("0123456789abcdef"));
  return {
    meta: { salt: fixtureSalt, iterations: 200_000, version: 1 },
    notes: [{ id: "note-1", ciphertext: fixtureCiphertext, iv: fixtureIv, createdAt: 1_700_000_000_000, updatedAt: 1_710_000_000_000, version: 3 }],
    canary: { ciphertext: fixtureCiphertext, iv: fixtureIv },
  };
}
