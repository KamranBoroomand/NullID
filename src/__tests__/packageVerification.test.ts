import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { encryptText } from "../utils/cryptoEnvelope.js";
import { hashText } from "../utils/hash.js";
import { createIncidentTextArtifactPackage, createIncidentWorkflowPackage } from "../utils/incidentWorkflow.js";
import { toBase64Url, utf8ToBytes } from "../utils/encoding.js";
import { inspectReceivedArtifact } from "../utils/packageVerification.js";
import { createPolicyPackSnapshot } from "../utils/policyPack.js";
import { createSafeShareTextWorkflowPackage } from "../utils/safeShareAssistant.js";
import { PROFILE_SCHEMA_VERSION } from "../utils/profile.js";
import { buildRulesState } from "../utils/sanitizeEngine.js";
import { createSnapshotIntegrity } from "../utils/snapshotIntegrity.js";
import { createSanitizeSafeShareBundle } from "../utils/workflowPackage.js";

describe("received artifact verification", () => {
  it("verifies current safe-share bundles through the shared workflow package contract", async () => {
    const inputText = "user=alice from 203.0.113.10";
    const outputText = "user=[user] from [ip]";
    const bundle = createSanitizeSafeShareBundle({
      producedAt: "2026-03-17T12:00:00.000Z",
      producer: {
        app: "NullID",
        surface: "web",
        module: "sanitize",
        version: "0.1.0",
      },
      sourceFile: "incident.log",
      detectedFormat: "text",
      policy: {
        rulesState: buildRulesState(["maskIp", "maskUser"]),
        jsonAware: true,
        customRules: [],
      },
      input: {
        bytes: 29,
        sha256: "1".repeat(64),
      },
      output: {
        bytes: 27,
        sha256: "2".repeat(64),
        text: outputText,
      },
      summary: {
        linesAffected: 1,
        appliedRules: ["maskUser", "maskIp"],
        report: ["maskUser: 1", "maskIp: 1"],
      },
      preset: "nginx",
    });
    const inputSha = (await hashText(inputText, "SHA-256")).hex;
    const outputSha = (await hashText(outputText, "SHA-256")).hex;
    bundle.input.bytes = inputText.length;
    bundle.input.sha256 = inputSha;
    bundle.output.bytes = outputText.length;
    bundle.workflowPackage.artifacts[0].sha256 = inputSha;
    bundle.output.sha256 = outputSha;
    bundle.workflowPackage.artifacts[1].bytes = outputText.length;
    bundle.workflowPackage.artifacts[1].sha256 = outputSha;
    bundle.workflowPackage.artifacts[1].text = outputText;

    const result = await inspectReceivedArtifact(JSON.stringify(bundle));
    assert.equal(result.artifactType, "safe-share-bundle");
    assert.equal(result.verificationState, "integrity-checked");
    assert.equal(result.verificationLabel, "Integrity checked");
    assert.equal(
      result.facts.some((fact) => fact.label === "Verification basis" && fact.value === "Embedded workflow package"),
      true,
    );
    assert.equal(
      result.facts.some((fact) => fact.label === "Bundle schema" && fact.value === "2"),
      true,
    );
    assert.match(result.trustBasis.join(" "), /verification is based on the embedded workflow package/i);
    assert.match(result.unverifiedChecks.join(" "), /outer safe-share wrapper fields/i);
    assert.equal(result.artifacts.some((artifact) => artifact.status === "verified"), true);
  });

  it("treats tampered schema-2 safe-share outer wrapper fields as unverified while preserving nested workflow verification", async () => {
    const inputText = "user=alice from 203.0.113.10";
    const outputText = "user=[user] from [ip]";
    const bundle = createSanitizeSafeShareBundle({
      producedAt: "2026-03-17T12:00:00.000Z",
      producer: {
        app: "NullID",
        surface: "web",
        module: "sanitize",
        version: "0.1.0",
      },
      sourceFile: "incident.log",
      detectedFormat: "text",
      policy: {
        rulesState: buildRulesState(["maskIp", "maskUser"]),
        jsonAware: true,
        customRules: [],
      },
      input: {
        bytes: 29,
        sha256: "1".repeat(64),
      },
      output: {
        bytes: 27,
        sha256: "2".repeat(64),
        text: outputText,
      },
      summary: {
        linesAffected: 1,
        appliedRules: ["maskUser", "maskIp"],
        report: ["maskUser: 1", "maskIp: 1"],
      },
      preset: "nginx",
    });
    const inputSha = (await hashText(inputText, "SHA-256")).hex;
    const outputSha = (await hashText(outputText, "SHA-256")).hex;
    bundle.input.bytes = inputText.length;
    bundle.input.sha256 = inputSha;
    bundle.output.bytes = outputText.length;
    bundle.workflowPackage.artifacts[0].sha256 = inputSha;
    bundle.output.sha256 = outputSha;
    bundle.workflowPackage.artifacts[1].bytes = outputText.length;
    bundle.workflowPackage.artifacts[1].sha256 = outputSha;
    bundle.workflowPackage.artifacts[1].text = outputText;

    bundle.output.text = "tampered outer text";
    bundle.output.bytes = bundle.output.text.length;
    bundle.policy = {
      rulesState: buildRulesState([]),
      jsonAware: false,
      customRules: [],
    };

    const result = await inspectReceivedArtifact(JSON.stringify(bundle));
    assert.equal(result.artifactType, "safe-share-bundle");
    assert.equal(result.verificationState, "integrity-checked");
    assert.equal(
      result.facts.some((fact) => fact.label === "Verification basis" && fact.value === "Embedded workflow package"),
      true,
    );
    assert.match(result.trustBasis.join(" "), /embedded workflow package/i);
    assert.match(result.unverifiedChecks.join(" "), /outer safe-share wrapper fields/i);
    assert.equal(result.descriptiveWorkflowMetadata?.policySummary.find((fact) => fact.label === "Enabled rules")?.value, "2");
    assert.equal(result.artifacts.some((artifact) => artifact.status === "verified"), true);
  });

  it("verifies Safe Share Assistant workflow packages and surfaces the workflow preset", async () => {
    const workflowPackage = await createSafeShareTextWorkflowPackage({
      presetId: "support-ticket",
      producer: {
        app: "NullID",
        surface: "web",
        module: "share",
      },
      inputText: "token=abcdefghijklmnopqrstuvwxyz12345 alice@example.com",
      sourceLabel: "support.log",
      includeSourceReference: true,
      protectAtExport: false,
    });

    const result = await inspectReceivedArtifact(JSON.stringify(workflowPackage));
    assert.equal(result.artifactType, "workflow-package");
    assert.equal(result.verificationState, "integrity-checked");
    assert.equal(result.title, "Workflow package");
    assert.equal(
      result.facts.some((fact) => fact.label === "Workflow preset" && fact.value === "Support ticket / bug report"),
      false,
    );
    assert.equal(
      result.descriptiveWorkflowMetadata?.facts.some(
        (fact) => fact.label === "Workflow preset" && fact.value === "Support ticket / bug report",
      ),
      true,
    );
    assert.match(result.unverifiedChecks.join(" "), /not integrity-verified/i);
  });

  it("moves workflow-report explainability into descriptive unverified metadata for incident packages", async () => {
    const notesPackage = await createIncidentTextArtifactPackage({
      modeId: "incident-handoff",
      producer: {
        app: "NullID",
        surface: "web",
        module: "incident",
      },
      inputText: "Summary: suspicious token seen in auth logs",
      sourceLabel: "case-notes.txt",
      includeSourceReference: true,
      protectAtExport: false,
    });

    const incidentPackage = await createIncidentWorkflowPackage({
      modeId: "incident-handoff",
      producer: {
        app: "NullID",
        surface: "web",
        module: "incident",
      },
      incidentTitle: "Incident 2026-03-18",
      purpose: "Prepare a responder handoff package.",
      caseReference: "CASE-77",
      recipientScope: "incident responders",
      summaryText: "Suspicious authentication artifact observed.",
      preparedArtifacts: [{ id: "notes", label: "Case notes", kind: "notes", workflowPackage: notesPackage }],
      protectAtExport: false,
    });

    const result = await inspectReceivedArtifact(JSON.stringify(incidentPackage));
    assert.equal(result.artifactType, "workflow-package");
    assert.equal(result.verificationState, "integrity-checked");
    assert.equal(result.workflowReport, undefined);
    assert.equal(result.policySummary.length, 0);
    assert.equal(result.descriptiveWorkflowMetadata?.workflowReport?.purpose, "Prepare a responder handoff package.");
    assert.equal(result.descriptiveWorkflowMetadata?.workflowReport?.audience, "incident responders");
    assert.equal(result.descriptiveWorkflowMetadata?.workflowReport?.includedArtifacts.includes("Incident report"), true);
    assert.equal(result.descriptiveWorkflowMetadata?.workflowReport?.receiverCannotVerify.includes("Sender identity or authorship."), true);
    assert.match(result.unverifiedChecks.join(" "), /not integrity-verified/i);
  });

  it("treats tampered top-level workflow report metadata as descriptive rather than integrity-verified", async () => {
    const workflowPackage = await createSafeShareTextWorkflowPackage({
      presetId: "support-ticket",
      producer: {
        app: "NullID",
        surface: "web",
        module: "share",
      },
      inputText: "token=abcdefghijklmnopqrstuvwxyz12345 alice@example.com",
      sourceLabel: "support.log",
      includeSourceReference: true,
      protectAtExport: false,
    });

    workflowPackage.summary.title = "Tampered workflow title";
    if (workflowPackage.report) {
      workflowPackage.report.purpose = "Tampered receiver story";
    }

    const result = await inspectReceivedArtifact(JSON.stringify(workflowPackage));
    assert.equal(result.verificationState, "integrity-checked");
    assert.equal(result.title, "Workflow package");
    assert.equal(result.workflowReport, undefined);
    assert.equal(result.facts.some((fact) => fact.value === "Tampered workflow title"), false);
    assert.equal(result.descriptiveWorkflowMetadata?.title, "Tampered workflow title");
    assert.equal(result.descriptiveWorkflowMetadata?.workflowReport?.purpose, "Tampered receiver story");
    assert.match(result.unverifiedChecks.join(" "), /not integrity-verified/i);
    assert.equal(result.artifacts.some((artifact) => artifact.status === "verified"), true);
  });

  it("normalizes unsupported inner workflow trust claims before verification presentation", async () => {
    const outputText = "user=[user] from [ip]";
    const outputSha = (await hashText(outputText, "SHA-256")).hex;
    const workflowPackage = {
      schemaVersion: 1,
      kind: "nullid-workflow-package",
      packageType: "bundle",
      workflowType: "sanitize-safe-share",
      producedAt: "2026-03-17T12:00:00.000Z",
      producer: {
        app: "NullID",
        surface: "web",
        module: "sanitize",
      },
      summary: {
        title: "Sanitized safe-share package",
        description: "Portable local package containing sanitized output and manifest entries.",
        highlights: ["Applied rules: 2"],
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
          id: "shared-output",
          role: "output",
          label: "Shared output",
          kind: "text",
          mediaType: "text/plain;charset=utf-8",
          included: true,
          bytes: outputText.length,
          sha256: outputSha,
          text: outputText,
        },
      ],
      warnings: [],
      limitations: [],
    };

    const result = await inspectReceivedArtifact(JSON.stringify(workflowPackage));
    assert.equal(result.artifactType, "workflow-package");
    assert.equal(result.verificationState, "integrity-checked");
    assert.equal(result.verificationLabel, "Integrity checked");
    assert.equal(result.trustBasis.some((line) => /shared-secret-hmac|NULLID:ENC:1/i.test(line)), false);
    assert.equal(result.artifacts.some((artifact) => artifact.status === "verified"), true);
  });

  it("treats malformed workflow package payloads as invalid instead of throwing", async () => {
    const result = await inspectReceivedArtifact(
      JSON.stringify({
        kind: "nullid-workflow-package",
        schemaVersion: 99,
        packageType: "bundle",
      }),
    );
    assert.equal(result.artifactType, "workflow-package");
    assert.equal(result.verificationState, "invalid");
    assert.match(String(result.failure), /unsupported workflow package schema: 99/i);
  });

  it("reports malformed JSON cleanly", async () => {
    const result = await inspectReceivedArtifact("{bad-json");
    assert.equal(result.artifactType, "malformed");
    assert.equal(result.verificationState, "malformed");
  });

  it("inspects envelopes without decrypting when no passphrase is provided", async () => {
    const envelope = await encryptText("local-secret", JSON.stringify({ kind: "nullid-safe-share" }));
    const result = await inspectReceivedArtifact(envelope);
    assert.equal(result.artifactType, "envelope");
    assert.equal(result.verificationState, "verification-required");
    assert.equal(result.envelope?.length ? true : false, true);
  });

  it("verifies signed policy packs with a shared secret", async () => {
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

    const result = await inspectReceivedArtifact(JSON.stringify(snapshot), {
      verificationPassphrase: "policy-secret",
    });
    assert.equal(result.artifactType, "policy-pack");
    assert.equal(result.verificationState, "verified");
    assert.equal(result.verificationLabel, "HMAC verified");
  });

  it("presents unsigned integrity-checked policy/profile/vault entries as verified artifacts", async () => {
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
    const profile = await createUnsignedProfileSnapshot();
    const vault = await createUnsignedVaultSnapshot();

    const [policyResult, profileResult, vaultResult] = await Promise.all([
      inspectReceivedArtifact(JSON.stringify(policy)),
      inspectReceivedArtifact(JSON.stringify(profile)),
      inspectReceivedArtifact(JSON.stringify(vault)),
    ]);

    assert.equal(policyResult.verificationState, "integrity-checked");
    assert.deepEqual(policyResult.artifacts.map((artifact) => artifact.status), ["verified"]);

    assert.equal(profileResult.verificationState, "integrity-checked");
    assert.deepEqual(profileResult.artifacts.map((artifact) => artifact.status), ["verified"]);

    assert.equal(vaultResult.verificationState, "integrity-checked");
    assert.deepEqual(vaultResult.artifacts.map((artifact) => artifact.status), ["verified"]);
  });

  it("presents mismatch states consistently for signed policy/profile/vault payloads", async () => {
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
    const profile = await createSignedProfileSnapshot("profile-secret");
    const vault = await createSignedVaultSnapshot("vault-secret");

    const [policyResult, profileResult, vaultResult] = await Promise.all([
      inspectReceivedArtifact(JSON.stringify(policy), { verificationPassphrase: "wrong-secret" }),
      inspectReceivedArtifact(JSON.stringify(profile), { verificationPassphrase: "wrong-secret" }),
      inspectReceivedArtifact(JSON.stringify(vault), { verificationPassphrase: "wrong-secret" }),
    ]);

    assert.equal(policyResult.verificationState, "mismatch");
    assert.equal(policyResult.verificationLabel, "Mismatch");
    assert.deepEqual(policyResult.artifacts.map((artifact) => artifact.status), ["mismatch"]);

    assert.equal(profileResult.verificationState, "mismatch");
    assert.equal(profileResult.verificationLabel, "Mismatch");
    assert.deepEqual(profileResult.artifacts.map((artifact) => artifact.status), ["mismatch"]);

    assert.equal(vaultResult.verificationState, "mismatch");
    assert.equal(vaultResult.verificationLabel, "Mismatch");
    assert.deepEqual(vaultResult.artifacts.map((artifact) => artifact.status), ["mismatch"]);
  });

  it("requires a verification passphrase for signed profiles", async () => {
    const payload = {
      schemaVersion: PROFILE_SCHEMA_VERSION,
      exportedAt: "2026-03-17T09:00:00.000Z",
      entries: {
        "nullid:theme": "light",
      },
    };
    const { integrity, signature } = await createSnapshotIntegrity(payload, "entryCount", 1, {
      signingPassphrase: "profile-secret",
      keyHint: "profile-local-v1",
    });
    const snapshot = {
      schemaVersion: PROFILE_SCHEMA_VERSION,
      kind: "profile",
      exportedAt: payload.exportedAt,
      entries: payload.entries,
      integrity,
      signature,
    };

    const result = await inspectReceivedArtifact(JSON.stringify(snapshot));
    assert.equal(result.artifactType, "profile");
    assert.equal(result.verificationState, "verification-required");
  });

  it("reports vault signature mismatches clearly", async () => {
    const fixtureSalt = toBase64Url(utf8ToBytes("signed-salt-1234"));
    const fixtureIv = toBase64Url(utf8ToBytes("0123456789ab"));
    const fixtureCiphertext = toBase64Url(utf8ToBytes("0123456789abcdef"));
    const payload = {
      schemaVersion: 2,
      exportedAt: "2026-03-17T08:00:00.000Z",
      vault: {
        meta: { salt: fixtureSalt, iterations: 200_000, version: 1 },
        canary: { ciphertext: fixtureCiphertext, iv: fixtureIv },
        notes: [{ id: "note-1", ciphertext: fixtureCiphertext, iv: fixtureIv, updatedAt: 1_710_000_000_000 }],
      },
    };
    const { integrity, signature } = await createSnapshotIntegrity(payload, "noteCount", 1, {
      signingPassphrase: "vault-secret",
      keyHint: "vault-local-v1",
    });
    const snapshot = {
      schemaVersion: 2,
      kind: "vault",
      exportedAt: payload.exportedAt,
      vault: payload.vault,
      integrity,
      signature,
    };

    const result = await inspectReceivedArtifact(JSON.stringify(snapshot), {
      verificationPassphrase: "wrong-secret",
    });
    assert.equal(result.artifactType, "vault");
    assert.equal(result.verificationState, "mismatch");
  });

  it("marks unknown JSON payloads as unsupported", async () => {
    const result = await inspectReceivedArtifact(JSON.stringify({ kind: "not-nullid", hello: "world" }));
    assert.equal(result.artifactType, "unsupported");
    assert.equal(result.verificationState, "unsupported");
  });
});

async function createUnsignedProfileSnapshot() {
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

async function createSignedProfileSnapshot(signingPassphrase: string) {
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

async function createUnsignedVaultSnapshot() {
  const vault = buildVaultSnapshotFixture();
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

async function createSignedVaultSnapshot(signingPassphrase: string) {
  const vault = buildVaultSnapshotFixture();
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

function buildVaultSnapshotFixture() {
  const fixtureSalt = toBase64Url(utf8ToBytes("signed-salt-1234"));
  const fixtureIv = toBase64Url(utf8ToBytes("0123456789ab"));
  const fixtureCiphertext = toBase64Url(utf8ToBytes("0123456789abcdef"));
  return {
    meta: { salt: fixtureSalt, iterations: 200_000, version: 1, lockedAt: undefined },
    notes: [{ id: "note-1", ciphertext: fixtureCiphertext, iv: fixtureIv, updatedAt: 1_710_000_000_000 }],
    canary: { ciphertext: fixtureCiphertext, iv: fixtureIv },
  };
}
