import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { hashBytes } from "../utils/hash.js";
import { buildRulesState } from "../utils/sanitizeEngine.js";
import { createSanitizeSafeShareBundle, createWorkflowPackage, describeWorkflowPackagePayload, extractWorkflowPackage, normalizeWorkflowPackage, SAFE_SHARE_BUNDLE_KIND, SAFE_SHARE_BUNDLE_SCHEMA_VERSION, verifyWorkflowPackagePayload, WORKFLOW_PACKAGE_KIND, WORKFLOW_PACKAGE_SCHEMA_VERSION, } from "../utils/workflowPackage.js";
const samplePolicy = {
    rulesState: buildRulesState(["maskIp", "maskEmail"]),
    jsonAware: true,
    customRules: [],
};
describe("workflow package contract", () => {
    it("creates a versioned sanitize safe-share bundle with an honest nested workflow package", () => {
        const bundle = createSanitizeSafeShareBundle({
            producedAt: "2026-03-17T10:00:00.000Z",
            producer: {
                app: "NullID",
                surface: "web",
                module: "sanitize",
                version: "0.1.0",
                buildId: "build-123",
            },
            sourceFile: "incident.log",
            detectedFormat: "text",
            policy: samplePolicy,
            input: {
                bytes: 31,
                sha256: "1".repeat(64),
            },
            output: {
                bytes: 29,
                sha256: "2".repeat(64),
                text: "user=[user] from [ip] [email]",
            },
            summary: {
                linesAffected: 1,
                appliedRules: ["maskUser", "maskIp", "maskEmail"],
                report: ["maskUser: 1", "maskIp: 1", "maskEmail: 1"],
            },
            preset: "nginx",
        });
        assert.equal(bundle.schemaVersion, SAFE_SHARE_BUNDLE_SCHEMA_VERSION);
        assert.equal(bundle.kind, SAFE_SHARE_BUNDLE_KIND);
        assert.equal(bundle.workflowPackage.schemaVersion, WORKFLOW_PACKAGE_SCHEMA_VERSION);
        assert.equal(bundle.workflowPackage.kind, WORKFLOW_PACKAGE_KIND);
        assert.equal(bundle.workflowPackage.workflowType, "sanitize-safe-share");
        assert.equal(bundle.workflowPackage.producedAt, "2026-03-17T10:00:00.000Z");
        assert.equal(bundle.workflowPackage.producer.surface, "web");
        assert.equal(bundle.workflowPackage.trust.identity, "not-asserted");
        assert.equal(bundle.workflowPackage.trust.packageSignature.method, "none");
        assert.equal(bundle.workflowPackage.trust.encryptedPayload.method, "none");
        assert.equal(bundle.workflowPackage.trust.artifactManifest.entryCount, 2);
        assert.equal(bundle.workflowPackage.summary.title, "Sanitized safe-share package");
        assert.deepEqual(bundle.workflowPackage.summary.highlights, [
            "Detected format: text",
            "Lines affected: 1",
            "Applied rules: 3",
        ]);
        assert.match(bundle.workflowPackage.warnings.join(" "), /sender identity is not asserted/i);
        assert.equal(bundle.workflowPackage.artifacts.length, 3);
        assert.equal(bundle.workflowPackage.artifacts[1].sha256, "2".repeat(64));
        assert.equal(bundle.workflowPackage.policy?.preset, "nginx");
    });
    it("normalizes unsupported inner signature and encryption claims to honest none-based trust metadata", async () => {
        const workflowPackage = {
            schemaVersion: WORKFLOW_PACKAGE_SCHEMA_VERSION,
            kind: WORKFLOW_PACKAGE_KIND,
            packageType: "report",
            workflowType: "verification-report",
            producedAt: "2026-03-17T10:05:00.000Z",
            producer: {
                app: "NullID",
                surface: "cli",
                module: "verify",
                version: "0.1.0",
            },
            summary: {
                title: "Receiver verification report",
                description: "Local report describing verification status for a received package.",
                highlights: ["Shared secret available"],
            },
            trust: {
                packageSignature: {
                    method: "shared-secret-hmac",
                    keyHint: "team-share-v1",
                },
                artifactManifest: {
                    algorithm: "sha256",
                    entryCount: 1,
                },
                encryptedPayload: {
                    method: "NULLID:ENC:1",
                },
            },
            artifacts: [
                {
                    id: "manifest",
                    role: "manifest",
                    label: "Manifest entry",
                    kind: "manifest",
                    mediaType: "application/json",
                    included: true,
                    bytes: 42,
                    sha256: "3".repeat(64),
                },
            ],
            warnings: [],
            limitations: [],
        };
        const normalized = normalizeWorkflowPackage(workflowPackage);
        const descriptor = describeWorkflowPackagePayload(workflowPackage);
        const verified = await verifyWorkflowPackagePayload(workflowPackage);
        assert.equal(normalized === null, false);
        if (!normalized) {
            throw new Error("Expected workflow package to normalize");
        }
        assert.equal(normalized.trust.identity, "not-asserted");
        assert.equal(normalized.trust.packageSignature.method, "none");
        assert.equal(normalized.trust.packageSignature.keyHint, undefined);
        assert.equal(normalized.trust.encryptedPayload.method, "none");
        assert.match(normalized.trust.notes.join(" "), /ignored unsupported inner workflow package signature claim/i);
        assert.match(normalized.trust.notes.join(" "), /outer export envelope/i);
        assert.equal(descriptor.signatureMethod, "none");
        assert.equal(descriptor.encryptionMethod, "none");
        assert.equal(verified.verificationState, "integrity-checked");
        assert.equal(verified.failure, undefined);
        assert.equal(verified.trustBasis.some((line) => /shared-secret-hmac|NULLID:ENC:1/i.test(line)), false);
    });
    it("verifies included binary artifacts carried as base64 payloads", async () => {
        const binarySha = (await hashBytes(new Uint8Array([0, 1, 2, 3, 4]), "SHA-256")).hex;
        const workflowPackage = createWorkflowPackage({
            packageType: "bundle",
            workflowType: "safe-share-assistant",
            producedAt: "2026-03-17T10:10:00.000Z",
            producer: {
                app: "NullID",
                surface: "web",
                module: "share",
            },
            workflowPreset: {
                id: "evidence-archive",
                label: "Evidence archive / preserve context",
            },
            summary: {
                title: "Binary payload package",
                description: "Carries an included binary artifact for receiver verification.",
                highlights: ["Binary artifact included"],
            },
            artifacts: [
                {
                    id: "binary-artifact",
                    role: "output",
                    label: "Binary artifact",
                    kind: "binary",
                    mediaType: "application/octet-stream",
                    included: true,
                    base64: "AAECAwQ=",
                    sha256: binarySha,
                },
            ],
        });
        const verified = await verifyWorkflowPackagePayload(workflowPackage);
        assert.equal(workflowPackage.workflowPreset?.id, "evidence-archive");
        assert.equal(verified.verificationState, "integrity-checked");
        assert.equal(verified.artifactChecks[0].status, "verified");
        assert.match(verified.artifactChecks[0].detail, /included binary payload/i);
    });
    it("maps legacy safe-share bundles into the shared workflow package contract", () => {
        const legacyBundle = {
            schemaVersion: 1,
            kind: "nullid-safe-share",
            createdAt: "2026-03-17T09:00:00.000Z",
            tool: "sanitize",
            sourceFile: "legacy.log",
            detectedFormat: "json",
            policy: samplePolicy,
            input: {
                bytes: 11,
                sha256: "4".repeat(64),
            },
            output: {
                bytes: 9,
                sha256: "5".repeat(64),
                text: "{\"ok\":1}",
            },
            summary: {
                linesAffected: 1,
                appliedRules: ["maskIp"],
                report: ["maskIp: 1"],
            },
        };
        const descriptor = describeWorkflowPackagePayload(legacyBundle);
        const workflowPackage = extractWorkflowPackage(legacyBundle);
        assert.equal(descriptor.legacy, true);
        assert.equal(descriptor.sourceKind, "safe-share");
        assert.equal(descriptor.workflowType, "sanitize-safe-share");
        assert.equal(workflowPackage.kind, WORKFLOW_PACKAGE_KIND);
        assert.equal(workflowPackage.producedAt, "2026-03-17T09:00:00.000Z");
        assert.equal(workflowPackage.artifacts[1].text, "{\"ok\":1}");
        assert.match(workflowPackage.warnings.join(" "), /sender identity is not asserted/i);
    });
    it("rejects malformed workflow package payloads instead of guessing", () => {
        const malformed = {
            schemaVersion: 1,
            kind: "nullid-workflow-package",
            packageType: "bundle",
            workflowType: "sanitize-safe-share",
            producedAt: "2026-03-17T09:00:00.000Z",
            producer: {
                app: "NullID",
                surface: "web",
            },
            summary: {
                title: "Malformed",
                description: "Should not normalize",
                highlights: [],
            },
            trust: {
                packageSignature: {
                    method: "none",
                },
            },
            artifacts: [
                {
                    id: "bad-artifact",
                    role: "output",
                    label: "Bad artifact",
                    kind: "text",
                    mediaType: "text/plain",
                    included: true,
                    sha256: "not-a-sha",
                    text: "hello",
                },
            ],
            warnings: [],
            limitations: [],
        };
        assert.equal(normalizeWorkflowPackage(malformed), null);
        assert.throws(() => extractWorkflowPackage(malformed), /invalid workflow package payload/i);
    });
    it("rejects malformed binary base64 payloads instead of accepting broken inline bytes", () => {
        const malformed = {
            schemaVersion: 1,
            kind: "nullid-workflow-package",
            packageType: "bundle",
            workflowType: "safe-share-assistant",
            producedAt: "2026-03-17T10:15:00.000Z",
            producer: {
                app: "NullID",
                surface: "web",
            },
            summary: {
                title: "Malformed binary package",
                description: "Broken inline payload",
                highlights: [],
            },
            trust: {
                packageSignature: {
                    method: "none",
                },
            },
            artifacts: [
                {
                    id: "bad-binary",
                    role: "output",
                    label: "Bad binary artifact",
                    kind: "binary",
                    mediaType: "application/octet-stream",
                    included: true,
                    base64: "!not-base64!",
                    sha256: "0".repeat(64),
                },
            ],
            warnings: [],
            limitations: [],
        };
        assert.equal(normalizeWorkflowPackage(malformed), null);
    });
});
