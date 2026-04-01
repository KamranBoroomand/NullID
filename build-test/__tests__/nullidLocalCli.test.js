import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { assessPasswordHashChoice, hashPassword, PASSWORD_HASH_LIMITS, PASSWORD_HASH_MESSAGES, verifyPassword, } from "../utils/passwordHashing.js";
import { inspectReceivedArtifact } from "../utils/packageVerification.js";
import { createPolicyPackSnapshot } from "../utils/policyPack.js";
import { PROFILE_SCHEMA_VERSION } from "../utils/profile.js";
import { buildRulesState } from "../utils/sanitizeEngine.js";
import { createSnapshotIntegrity } from "../utils/snapshotIntegrity.js";
import { toBase64Url, utf8ToBytes } from "../utils/encoding.js";
const cliPath = path.resolve(process.cwd(), "scripts/nullid-local.mjs");
function runCli(args, env = {}) {
    const stdout = execFileSync(process.execPath, [cliPath, ...args], {
        cwd: process.cwd(),
        encoding: "utf8",
        env: {
            ...process.env,
            ...env,
        },
    });
    return JSON.parse(stdout);
}
function runCliRaw(args, env = {}) {
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
        const hashed = runCli(["pw-hash", "--algo", "pbkdf2-sha256", "--pbkdf2-iterations", "350000", "--password-env", "NULLID_PASSWORD"], { NULLID_PASSWORD: "cli-secret" });
        assert.equal(hashed.algorithm, "pbkdf2-sha256");
        assert.match(String(hashed.record), /^\$pbkdf2-sha256\$/u);
        const verified = runCli(["pw-verify", "--record", String(hashed.record), "--password-env", "NULLID_PASSWORD"], { NULLID_PASSWORD: "cli-secret" });
        assert.equal(verified.match, true);
        const mismatch = runCli(["pw-verify", "--record", String(hashed.record), "--password-env", "NULLID_PASSWORD"], { NULLID_PASSWORD: "wrong-secret" });
        assert.equal(mismatch.match, false);
    });
    it("keeps PBKDF2 records interoperable between the browser utility and the CLI", async () => {
        const browserRecord = await hashPassword("shared-secret", {
            algorithm: "pbkdf2-sha256",
            pbkdf2Iterations: 350_000,
            saltBytes: PASSWORD_HASH_LIMITS.saltBytes.default,
        });
        const cliVerifiedBrowserRecord = runCli(["pw-verify", "--record", browserRecord.encoded, "--password-env", "NULLID_PASSWORD"], { NULLID_PASSWORD: "shared-secret" });
        assert.equal(cliVerifiedBrowserRecord.match, true);
        const cliRecord = runCli(["pw-hash", "--algo", "pbkdf2-sha256", "--pbkdf2-iterations", "350000", "--password-env", "NULLID_PASSWORD"], { NULLID_PASSWORD: "shared-secret" });
        assert.equal(await verifyPassword("shared-secret", String(cliRecord.record)), true);
    });
    it("keeps legacy SHA records interoperable between the browser utility and the CLI", async () => {
        const browserRecord = await hashPassword("legacy-shared", {
            algorithm: "sha512",
            saltBytes: PASSWORD_HASH_LIMITS.saltBytes.default,
        });
        const cliVerifiedBrowserRecord = runCli(["pw-verify", "--record", browserRecord.encoded, "--password-env", "NULLID_PASSWORD"], { NULLID_PASSWORD: "legacy-shared" });
        assert.equal(cliVerifiedBrowserRecord.match, true);
        const cliRecord = runCli(["pw-hash", "--algo", "sha512", "--password-env", "NULLID_PASSWORD"], {
            NULLID_PASSWORD: "legacy-shared",
        });
        assert.equal(await verifyPassword("legacy-shared", String(cliRecord.record)), true);
    });
    it("keeps CLI warnings aligned with the browser-side assessment", () => {
        const cliResult = runCli(["pw-hash", "--algo", "pbkdf2-sha256", "--pbkdf2-iterations", "200000", "--password-env", "NULLID_PASSWORD"], { NULLID_PASSWORD: "warning-secret" });
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
            const parsed = JSON.parse(result.stdout);
            assert.equal(parsed.algorithm, "argon2id");
            assert.match(String(parsed.record), /^\$argon2id\$/u);
            return;
        }
        const combined = `${result.stdout}\n${result.stderr}`;
        assert.match(combined, new RegExp(PASSWORD_HASH_MESSAGES.errors.argon2Unavailable, "iu"));
    });
});
describe("nullid local cli workflow packages", () => {
    it("emits the shared workflow package contract from bundle and inspects it", () => {
        const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-workflow-"));
        try {
            const inputFile = path.join(tempDir, "incident.log");
            const outputFile = path.join(tempDir, "bundle.json");
            fs.writeFileSync(inputFile, "user=alice from 203.0.113.10", "utf8");
            const bundleResult = runCli(["bundle", inputFile, outputFile, "--preset", "nginx"]);
            assert.equal(bundleResult.schemaVersion, 2);
            assert.equal(bundleResult.workflowType, "sanitize-safe-share");
            const payload = JSON.parse(fs.readFileSync(outputFile, "utf8"));
            const workflowPackage = payload.workflowPackage;
            const trust = workflowPackage.trust;
            const packageSignature = trust.packageSignature;
            const artifactManifest = trust.artifactManifest;
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
            assert.equal(inspected.artifacts.some((artifact) => artifact.status === "verified"), true);
            assert.equal(inspected.facts.some((fact) => fact.label === "Workflow" && fact.value === "sanitize-safe-share"), true);
        }
        finally {
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
            const payload = JSON.parse(fs.readFileSync(outputFile, "utf8"));
            const workflowPackage = payload.workflowPackage;
            const workflowPreset = workflowPackage.workflowPreset;
            assert.equal(workflowPackage.workflowType, "safe-share-assistant");
            assert.equal(workflowPreset.id, "support-ticket");
            assert.equal(workflowPreset.label, "Support ticket / bug report");
            const inspected = runCli(["package-inspect", outputFile]);
            assert.equal(inspected.artifactType, "safe-share-bundle");
            assert.equal(inspected.verificationState, "integrity-checked");
            assert.equal(inspected.facts.some((fact) => fact.label === "Workflow preset" && fact.value === "Support ticket / bug report"), true);
        }
        finally {
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
            const payload = JSON.parse(fs.readFileSync(outputFile, "utf8"));
            const workflowPackage = payload.workflowPackage;
            const workflowPreset = workflowPackage.workflowPreset;
            const report = workflowPackage.report;
            const summary = workflowPackage.summary;
            assert.equal(workflowPreset.id, "internal-investigation");
            assert.equal(summary.title, "Incident 2026-03-18");
            assert.equal(report.purpose, "Prepare an internal responder package.");
            assert.equal(report.audience, "internal responders");
            const inspected = runCli(["package-inspect", outputFile]);
            const workflowReport = inspected.workflowReport;
            assert.equal(inspected.artifactType, "safe-share-bundle");
            assert.equal(inspected.verificationState, "integrity-checked");
            assert.equal(workflowReport.purpose, "Prepare an internal responder package.");
            assert.equal(workflowReport.audience, "internal responders");
        }
        finally {
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
            const locked = runCli(["package-inspect", encryptedFile]);
            assert.equal(locked.artifactType, "envelope");
            assert.equal(locked.verificationState, "verification-required");
            const inspected = runCli(["package-inspect", encryptedFile, "--pass-env", "NULLID_PASSPHRASE"], {
                NULLID_PASSPHRASE: "inspect-secret",
            });
            const envelope = inspected.envelope;
            assert.equal(inspected.artifactType, "safe-share-bundle");
            assert.equal(inspected.verificationState, "integrity-checked");
            assert.equal(envelope.prefix, "NULLID:ENC:1");
            assert.equal(inspected.trustBasis[0], "NULLID:ENC:1 envelope decrypted locally.");
            assert.equal(inspected.facts.some((fact) => fact.label === "Workflow" && fact.value === "sanitize-safe-share"), true);
        }
        finally {
            fs.rmSync(tempDir, { recursive: true, force: true });
        }
    });
    it("verifies signed policy packs when a shared secret is provided", async () => {
        const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-policy-"));
        try {
            const outputFile = path.join(tempDir, "signed-policy.json");
            const snapshot = await createPolicyPackSnapshot([
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
            ], { signingPassphrase: "policy-secret", keyHint: "secops-policy-v1" });
            fs.writeFileSync(outputFile, JSON.stringify(snapshot, null, 2), "utf8");
            const required = runCli(["package-inspect", outputFile], { NULLID_VERIFY_PASSPHRASE: "" });
            assert.equal(required.artifactType, "policy-pack");
            assert.equal(required.verificationState, "verification-required");
            const verified = runCli(["package-inspect", outputFile, "--verify-pass", "policy-secret"]);
            assert.equal(verified.artifactType, "policy-pack");
            assert.equal(verified.verificationState, "verified");
            assert.equal(verified.verificationLabel, "HMAC verified");
        }
        finally {
            fs.rmSync(tempDir, { recursive: true, force: true });
        }
    });
    it("reports malformed and invalid workflow artifacts cleanly", () => {
        const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-invalid-"));
        try {
            const malformedFile = path.join(tempDir, "malformed.json");
            const invalidWorkflowFile = path.join(tempDir, "invalid-workflow.json");
            fs.writeFileSync(malformedFile, "{bad-json", "utf8");
            fs.writeFileSync(invalidWorkflowFile, JSON.stringify({ kind: "nullid-workflow-package", schemaVersion: 99, packageType: "bundle" }, null, 2), "utf8");
            const malformed = runCli(["package-inspect", malformedFile]);
            assert.equal(malformed.artifactType, "malformed");
            assert.equal(malformed.verificationState, "malformed");
            const invalid = runCli(["package-inspect", invalidWorkflowFile]);
            assert.equal(invalid.artifactType, "workflow-package");
            assert.equal(invalid.verificationState, "invalid");
            assert.match(String(invalid.failure), /unsupported workflow package schema: 99/i);
        }
        finally {
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
            fs.writeFileSync(baselineFile, JSON.stringify({
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
            }, null, 2), "utf8");
            const result = runCli(["sanitize", inputFile, outputFile, "--baseline", baselineFile]);
            const output = fs.readFileSync(outputFile, "utf8");
            assert.equal(output, "fa: [phone] ru: [phone]");
            assert.deepEqual(result.appliedRules, ["maskPhoneIntl"]);
        }
        finally {
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
            fs.writeFileSync(baselineFile, JSON.stringify({
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
            }, null, 2), "utf8");
            const result = runCli(["sanitize", inputFile, outputFile, "--baseline", baselineFile]);
            const output = fs.readFileSync(outputFile, "utf8");
            assert.equal(output, "id: [iran-id] invalid: ۱۲۳۴۵۶۷۸۹۰");
            assert.deepEqual(result.appliedRules, ["maskIranNationalId"]);
        }
        finally {
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
            assert.match(`${result.stdout}\n${result.stderr}`, /multiple packs; CLI sanitize requires a single-pack export or a direct policy config/i);
            assert.throws(() => fs.readFileSync(outputFile, "utf8"));
        }
        finally {
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
            fs.writeFileSync(baselineFile, JSON.stringify({
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
            }, null, 2), "utf8");
            const result = runCli(["sanitize", inputFile, outputFile, "--baseline", baselineFile]);
            const output = fs.readFileSync(outputFile, "utf8");
            assert.equal(output, "token=[redacted]");
            assert.equal(result.report.some((entry) => entry === "custom:token=([a-z0-9]+):1"), true);
        }
        finally {
            fs.rmSync(tempDir, { recursive: true, force: true });
        }
    });
    it("drops unsafe custom regex rules in the CLI sanitize path just like the web engine", () => {
        const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-sanitize-custom-unsafe-"));
        try {
            const inputFile = path.join(tempDir, "input.txt");
            const outputFile = path.join(tempDir, "output.txt");
            const baselineFile = path.join(tempDir, "baseline.json");
            fs.writeFileSync(inputFile, "aaaa", "utf8");
            fs.writeFileSync(baselineFile, JSON.stringify({
                schemaVersion: 1,
                kind: "nullid-policy-baseline",
                sanitize: {
                    mergeMode: "strict-override",
                    defaultConfig: {
                        rulesState: buildRulesState([]),
                        jsonAware: false,
                        customRules: [{ pattern: "(a+)+", replacement: "[x]", flags: "g", scope: "text" }],
                    },
                    packs: [],
                },
            }, null, 2), "utf8");
            const result = runCli(["sanitize", inputFile, outputFile, "--baseline", baselineFile]);
            const output = fs.readFileSync(outputFile, "utf8");
            assert.equal(output, "aaaa");
            assert.equal(result.report.some((entry) => entry.startsWith("custom:")), false);
        }
        finally {
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
        }
        finally {
            fs.rmSync(tempDir, { recursive: true, force: true });
        }
    });
    it("matches web mismatch presentation for signed policy/profile/vault snapshots", async () => {
        const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-cli-verify-mismatch-"));
        try {
            const policy = await createPolicyPackSnapshot([
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
            ], { signingPassphrase: "policy-secret" });
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
        }
        finally {
            fs.rmSync(tempDir, { recursive: true, force: true });
        }
    });
});
function assertVerificationPresentationParity(cliResult, webResult, compareArtifacts) {
    assert.equal(cliResult.verificationState, webResult.verificationState);
    assert.equal(cliResult.verificationLabel, webResult.verificationLabel);
    if (!compareArtifacts)
        return;
    assert.deepEqual((cliResult.artifacts ?? []).map((artifact) => artifact.status), webResult.artifacts.map((artifact) => artifact.status));
}
async function createUnsignedProfileSnapshotForCliTest() {
    const exportedAt = "2026-03-17T09:00:00.000Z";
    const entries = { "nullid:theme": "light" };
    const { integrity } = await createSnapshotIntegrity({
        schemaVersion: PROFILE_SCHEMA_VERSION,
        exportedAt,
        entries,
    }, "entryCount", Object.keys(entries).length);
    return {
        schemaVersion: PROFILE_SCHEMA_VERSION,
        kind: "profile",
        exportedAt,
        entries,
        integrity,
    };
}
async function createSignedProfileSnapshotForCliTest(signingPassphrase) {
    const exportedAt = "2026-03-17T09:00:00.000Z";
    const entries = { "nullid:theme": "light" };
    const { integrity, signature } = await createSnapshotIntegrity({
        schemaVersion: PROFILE_SCHEMA_VERSION,
        exportedAt,
        entries,
    }, "entryCount", Object.keys(entries).length, { signingPassphrase });
    return {
        schemaVersion: PROFILE_SCHEMA_VERSION,
        kind: "profile",
        exportedAt,
        entries,
        integrity,
        signature,
    };
}
async function createUnsignedVaultSnapshotForCliTest() {
    const vault = buildVaultSnapshotFixtureForCliTest();
    const exportedAt = "2026-03-17T08:00:00.000Z";
    const { integrity } = await createSnapshotIntegrity({
        schemaVersion: 2,
        exportedAt,
        vault,
    }, "noteCount", vault.notes.length);
    return {
        schemaVersion: 2,
        kind: "vault",
        exportedAt,
        vault,
        integrity,
    };
}
async function createSignedVaultSnapshotForCliTest(signingPassphrase) {
    const vault = buildVaultSnapshotFixtureForCliTest();
    const exportedAt = "2026-03-17T08:00:00.000Z";
    const { integrity, signature } = await createSnapshotIntegrity({
        schemaVersion: 2,
        exportedAt,
        vault,
    }, "noteCount", vault.notes.length, { signingPassphrase });
    return {
        schemaVersion: 2,
        kind: "vault",
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
        meta: { salt: fixtureSalt, iterations: 200_000, version: 1, lockedAt: undefined },
        notes: [{ id: "note-1", ciphertext: fixtureCiphertext, iv: fixtureIv, updatedAt: 1_710_000_000_000 }],
        canary: { ciphertext: fixtureCiphertext, iv: fixtureIv },
    };
}
