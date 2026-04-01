import { decryptText, inspectEnvelope, type EnvelopeInspectResult } from "./cryptoEnvelope.js";
import { verifyPolicyPackPayload } from "./policyPack.js";
import { verifyProfilePayload } from "./profile.js";
import { verifyVaultPayload } from "./vault.js";
import { describeWorkflowPackagePayload, verifyWorkflowPackagePayload } from "./workflowPackage.js";

export type ReceivedArtifactType =
  | "workflow-package"
  | "safe-share-bundle"
  | "policy-pack"
  | "profile"
  | "vault"
  | "envelope"
  | "unsupported"
  | "malformed";

export type ReceivedVerificationState =
  | "unsigned"
  | "integrity-checked"
  | "verified"
  | "verification-required"
  | "mismatch"
  | "invalid"
  | "malformed"
  | "unsupported";

export interface VerificationFact {
  label: string;
  value: string;
}

export interface VerificationArtifactEntry {
  id: string;
  role: string;
  label: string;
  detail: string;
  status: "verified" | "reference" | "unverified" | "mismatch";
  included?: boolean;
  kind?: string;
  mediaType?: string;
  bytes?: number;
  sha256?: string;
}

export interface VerificationWorkflowReport {
  purpose?: string;
  audience?: string;
  includedArtifacts: string[];
  transformedArtifacts: string[];
  preservedArtifacts: string[];
  receiverCanVerify: string[];
  receiverCannotVerify: string[];
}

export interface VerificationDescriptiveWorkflowMetadata {
  title?: string;
  facts: VerificationFact[];
  transforms: VerificationFact[];
  policySummary: VerificationFact[];
  workflowReport?: VerificationWorkflowReport;
  warnings: string[];
  limitations: string[];
}

export interface ReceivedArtifactVerificationResult {
  artifactType: ReceivedArtifactType;
  artifactKindLabel: string;
  title: string;
  verificationState: ReceivedVerificationState;
  verificationLabel: string;
  trustBasis: string[];
  verifiedChecks: string[];
  unverifiedChecks: string[];
  warnings: string[];
  limitations: string[];
  facts: VerificationFact[];
  artifacts: VerificationArtifactEntry[];
  transforms: VerificationFact[];
  policySummary: VerificationFact[];
  workflowReport?: VerificationWorkflowReport;
  descriptiveWorkflowMetadata?: VerificationDescriptiveWorkflowMetadata;
  envelope?: VerificationFact[];
  failure?: string;
}

export interface InspectArtifactOptions {
  envelopePassphrase?: string;
  verificationPassphrase?: string;
  sourceLabel?: string;
}

export async function inspectReceivedArtifact(
  rawInput: string,
  options?: InspectArtifactOptions,
): Promise<ReceivedArtifactVerificationResult> {
  const trimmed = rawInput.trim();
  if (!trimmed) {
    return {
      artifactType: "malformed",
      artifactKindLabel: "Empty input",
      title: "No artifact provided",
      verificationState: "malformed",
      verificationLabel: "Malformed",
      trustBasis: [],
      verifiedChecks: [],
      unverifiedChecks: ["Paste a JSON payload or NULLID:ENC:1 envelope, or load a local file first."],
      warnings: ["No content was available to inspect."],
      limitations: [],
      facts: [],
      artifacts: [],
      transforms: [],
      policySummary: [],
      failure: "Empty input",
    };
  }

  if (trimmed.startsWith("NULLID:ENC:1.")) {
    return inspectEnvelopePayload(trimmed, options);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed) as unknown;
  } catch {
    return {
      artifactType: "malformed",
      artifactKindLabel: "Malformed artifact",
      title: options?.sourceLabel ? `Malformed artifact (${options.sourceLabel})` : "Malformed artifact",
      verificationState: "malformed",
      verificationLabel: "Malformed",
      trustBasis: [],
      verifiedChecks: [],
      unverifiedChecks: ["The content is not valid JSON and is not a NULLID:ENC:1 envelope."],
      warnings: ["NullID could not parse this artifact."],
      limitations: [],
      facts: options?.sourceLabel ? [{ label: "Source", value: options.sourceLabel }] : [],
      artifacts: [],
      transforms: [],
      policySummary: [],
      failure: "Malformed JSON or unsupported artifact encoding",
    };
  }

  return inspectParsedArtifact(parsed, options);
}

function inspectEnvelopePayload(
  payload: string,
  options?: InspectArtifactOptions,
): Promise<ReceivedArtifactVerificationResult> | ReceivedArtifactVerificationResult {
  let meta: EnvelopeInspectResult;
  try {
    meta = inspectEnvelope(payload);
  } catch (error) {
    return {
      artifactType: "malformed",
      artifactKindLabel: "Malformed envelope",
      title: "Malformed NULLID envelope",
      verificationState: "malformed",
      verificationLabel: "Malformed",
      trustBasis: [],
      verifiedChecks: [],
      unverifiedChecks: ["The envelope header could not be parsed safely."],
      warnings: [error instanceof Error ? error.message : "Invalid envelope"],
      limitations: [],
      facts: [],
      artifacts: [],
      transforms: [],
      policySummary: [],
      failure: error instanceof Error ? error.message : "Invalid envelope",
    };
  }

  const envelopeFacts = envelopeFactsFromMeta(meta);
  if (!options?.envelopePassphrase?.trim()) {
    return {
      artifactType: "envelope",
      artifactKindLabel: "Encrypted envelope",
      title: meta.header.name ? `Encrypted envelope (${meta.header.name})` : "Encrypted envelope",
      verificationState: "verification-required",
      verificationLabel: "Passphrase required",
      trustBasis: ["Envelope header is inspectable locally.", "The inner payload and AES-GCM integrity cannot be checked without the passphrase."],
      verifiedChecks: ["Envelope header parsed successfully."],
      unverifiedChecks: ["Inner payload type is unknown until the envelope is decrypted."],
      warnings: [],
      limitations: ["NullID can inspect envelope metadata without leaving the browser, but it will not guess the passphrase."],
      facts: [],
      artifacts: [],
      transforms: [],
      policySummary: [],
      envelope: envelopeFacts,
      failure: "Passphrase required to inspect inner payload",
    };
  }

  return decryptText(options.envelopePassphrase.trim(), payload)
    .then((decrypted) => inspectParsedOrMalformedAfterDecrypt(decrypted, envelopeFacts, options))
    .catch((error) => ({
      artifactType: "envelope",
      artifactKindLabel: "Encrypted envelope",
      title: meta.header.name ? `Encrypted envelope (${meta.header.name})` : "Encrypted envelope",
      verificationState: "invalid",
      verificationLabel: "Invalid",
      trustBasis: ["Envelope metadata was present, but the payload could not be decrypted successfully."],
      verifiedChecks: ["Envelope header parsed successfully."],
      unverifiedChecks: ["The inner payload could not be inspected."],
      warnings: [error instanceof Error ? error.message : "Decrypt failed"],
      limitations: ["A failed decrypt can mean the passphrase was wrong or the envelope integrity check failed."],
      facts: [],
      artifacts: [],
      transforms: [],
      policySummary: [],
      envelope: envelopeFacts,
      failure: error instanceof Error ? error.message : "Decrypt failed",
    }));
}

async function inspectParsedOrMalformedAfterDecrypt(
  decrypted: string,
  envelope: VerificationFact[],
  options?: InspectArtifactOptions,
): Promise<ReceivedArtifactVerificationResult> {
  try {
    const parsed = JSON.parse(decrypted) as unknown;
    const inner = await inspectParsedArtifact(parsed, options);
    return {
      ...inner,
      envelope,
      trustBasis: [
        "NULLID:ENC:1 envelope decrypted locally.",
        ...inner.trustBasis,
      ],
    };
  } catch {
    return {
      artifactType: "unsupported",
      artifactKindLabel: "Unsupported decrypted payload",
      title: "Unsupported decrypted payload",
      verificationState: "unsupported",
      verificationLabel: "Unsupported",
      trustBasis: ["Envelope decryption succeeded locally."],
      verifiedChecks: ["Envelope decrypted successfully."],
      unverifiedChecks: ["The decrypted payload is not one of the supported JSON artifact types in this verification surface."],
      warnings: [],
      limitations: ["This surface currently focuses on workflow packages, safe-share bundles, policy packs, profiles, and vault snapshots."],
      facts: [],
      artifacts: [],
      transforms: [],
      policySummary: [],
      envelope,
    };
  }
}

async function inspectParsedArtifact(
  parsed: unknown,
  options?: InspectArtifactOptions,
): Promise<ReceivedArtifactVerificationResult> {
  if (looksLikeWorkflowArtifact(parsed)) {
    let verified;
    try {
      verified = await verifyWorkflowPackagePayload(parsed);
    } catch (error) {
      const descriptor = describeWorkflowPackagePayload(parsed);
      return {
        artifactType: isRecord(parsed) && parsed.kind === "nullid-safe-share" ? "safe-share-bundle" : "workflow-package",
        artifactKindLabel: isRecord(parsed) && parsed.kind === "nullid-safe-share" ? "Safe-share bundle" : "Workflow package",
        title: "Invalid workflow package",
        verificationState: "invalid",
        verificationLabel: "Invalid",
        trustBasis: ["NullID recognized the workflow artifact type, but the payload could not be validated safely."],
        verifiedChecks: [],
        unverifiedChecks: ["No workflow-package integrity or authenticity guarantees could be established."],
        warnings: [error instanceof Error ? error.message : "Invalid workflow package payload"],
        limitations: ["Workflow-package verification currently checks schema structure, manifest self-consistency, and honest trust metadata only."],
        facts: [
          { label: "Schema", value: String(descriptor.schemaVersion) },
          { label: "Source", value: descriptor.sourceKind },
        ],
        artifacts: [],
        transforms: [],
        policySummary: [],
        failure: error instanceof Error ? error.message : "Invalid workflow package payload",
      };
    }
    const workflowPackage = verified.workflowPackage;
    const artifactKindLabel = verified.descriptor.sourceKind === "safe-share" ? "Safe-share bundle" : "Workflow package";
    const schema2SafeShareBundle = isSchema2SafeShareBundle(parsed);
    return {
      artifactType: verified.descriptor.sourceKind === "safe-share" ? "safe-share-bundle" : "workflow-package",
      artifactKindLabel,
      title: artifactKindLabel,
      verificationState: verified.verificationState,
      verificationLabel: verified.verificationLabel,
      trustBasis: schema2SafeShareBundle
        ? [
            "Schema-2 safe-share bundle detected. Verification is based on the embedded workflow package.",
            ...verified.trustBasis,
          ]
        : verified.trustBasis,
      verifiedChecks: verified.verifiedChecks,
      unverifiedChecks: verified.unverifiedChecks.concat(
        schema2SafeShareBundle
          ? [
              "Duplicated outer safe-share wrapper fields such as createdAt, producer, policy, input, output, summary, warnings, and limitations are not cross-checked against the embedded workflow package in this verification surface.",
              "Top-level workflow title, preset, producer details, report, policy, transforms, warnings, and limitations are descriptive metadata and are not integrity-verified by the current workflow package contract.",
            ]
          : [
              "Top-level workflow title, preset, producer details, report, policy, transforms, warnings, and limitations are descriptive metadata and are not integrity-verified by the current workflow package contract.",
            ],
      ),
      warnings: excludePackageDeclaredWorkflowLines(verified.warnings, workflowPackage.warnings),
      limitations: excludePackageDeclaredWorkflowLines(verified.limitations, workflowPackage.limitations),
      facts: schema2SafeShareBundle
        ? [
            { label: "Bundle schema", value: String(parsed.schemaVersion) },
            { label: "Embedded workflow schema", value: String(verified.descriptor.schemaVersion) },
            { label: "Verification basis", value: "Embedded workflow package" },
            { label: "Source", value: verified.descriptor.sourceKind },
          ]
        : [
            { label: "Schema", value: String(verified.descriptor.schemaVersion) },
            { label: "Source", value: verified.descriptor.sourceKind },
          ],
      artifacts: verified.artifactChecks.map((artifact) => ({
        id: artifact.id,
        role: artifact.role,
        label: artifact.label,
        detail: artifact.detail,
        status: artifact.status,
        included: artifact.included,
        kind: artifact.kind,
        mediaType: artifact.mediaType,
        bytes: artifact.bytes,
        sha256: artifact.sha256,
      })),
      transforms: [],
      policySummary: [],
      descriptiveWorkflowMetadata: summarizeDescriptiveWorkflowMetadata(workflowPackage),
      failure: verified.failure,
    };
  }

  if (looksLikePolicyPack(parsed)) {
    const verified = await verifyPolicyPackPayload(parsed, {
      verificationPassphrase: options?.verificationPassphrase,
    });
    return {
      artifactType: "policy-pack",
      artifactKindLabel: "Sanitize policy pack",
      title: "Sanitize policy pack",
      verificationState: verified.verificationState,
      verificationLabel: verified.verificationLabel,
      trustBasis: verified.trustBasis,
      verifiedChecks: verified.verifiedChecks,
      unverifiedChecks: verified.unverifiedChecks,
      warnings: verified.warnings,
      limitations: ["Policy pack verification checks payload integrity and optional shared-secret HMAC metadata only."],
      facts: [
        { label: "Schema", value: String(verified.schemaVersion) },
        { label: "Pack count", value: String(verified.packCount) },
        ...(verified.exportedAt ? [{ label: "Exported at", value: verified.exportedAt }] : []),
        ...(verified.keyHint ? [{ label: "Key hint", value: verified.keyHint }] : []),
      ],
      artifacts: verified.packNames.map((name) => ({
        id: name,
        role: "pack",
        label: name,
        detail: "Policy pack entry",
        status: overallArtifactStatus(verified.verificationState),
      })),
      transforms: [],
      policySummary: [],
      failure: verified.failure,
    };
  }

  if (looksLikeProfile(parsed)) {
    const verified = await verifyProfilePayload(parsed, {
      verificationPassphrase: options?.verificationPassphrase,
    });
    return {
      artifactType: "profile",
      artifactKindLabel: "Profile snapshot",
      title: "Profile snapshot",
      verificationState: verified.verificationState,
      verificationLabel: verified.verificationLabel,
      trustBasis: verified.trustBasis,
      verifiedChecks: verified.verifiedChecks,
      unverifiedChecks: verified.unverifiedChecks,
      warnings: verified.warnings,
      limitations: ["Profile verification checks payload integrity and optional shared-secret HMAC metadata only."],
      facts: [
        { label: "Schema", value: String(verified.schemaVersion) },
        { label: "Entry count", value: String(verified.entryCount) },
        ...(verified.exportedAt ? [{ label: "Exported at", value: verified.exportedAt }] : []),
        ...(verified.keyHint ? [{ label: "Key hint", value: verified.keyHint }] : []),
        ...(verified.legacy ? [{ label: "Legacy", value: "yes" }] : []),
      ],
      artifacts: verified.sampleKeys.map((key) => ({
        id: key,
        role: "entry",
        label: key,
        detail: "Profile entry key",
        status: overallArtifactStatus(verified.verificationState),
      })),
      transforms: [],
      policySummary: [],
      failure: verified.failure,
    };
  }

  if (looksLikeVault(parsed)) {
    const verified = await verifyVaultPayload(parsed, {
      verificationPassphrase: options?.verificationPassphrase,
    });
    return {
      artifactType: "vault",
      artifactKindLabel: "Vault snapshot",
      title: "Vault snapshot",
      verificationState: verified.verificationState,
      verificationLabel: verified.verificationLabel,
      trustBasis: verified.trustBasis,
      verifiedChecks: verified.verifiedChecks,
      unverifiedChecks: verified.unverifiedChecks,
      warnings: verified.warnings,
      limitations: ["Vault verification checks payload integrity and optional shared-secret HMAC metadata only."],
      facts: [
        { label: "Schema", value: String(verified.schemaVersion) },
        { label: "Note count", value: String(verified.noteCount) },
        ...(verified.exportedAt ? [{ label: "Exported at", value: verified.exportedAt }] : []),
        ...(verified.keyHint ? [{ label: "Key hint", value: verified.keyHint }] : []),
        ...(verified.legacy ? [{ label: "Legacy", value: "yes" }] : []),
      ],
      artifacts: verified.noteIds.map((noteId) => ({
        id: noteId,
        role: "note",
        label: noteId,
        detail: "Vault note id",
        status: overallArtifactStatus(verified.verificationState),
      })),
      transforms: [],
      policySummary: [],
      failure: verified.failure,
    };
  }

  return {
    artifactType: "unsupported",
    artifactKindLabel: "Unsupported artifact",
    title: "Unsupported artifact",
    verificationState: "unsupported",
    verificationLabel: "Unsupported",
    trustBasis: [],
    verifiedChecks: [],
    unverifiedChecks: ["This JSON payload is not a supported NullID artifact type in this verification surface."],
    warnings: [],
    limitations: ["Supported types in this step: workflow packages, safe-share bundles, sanitize policy packs, profile snapshots, vault snapshots, and NULLID envelopes."],
    facts: [],
    artifacts: [],
    transforms: [],
    policySummary: [],
  };
}

function looksLikeWorkflowArtifact(value: unknown) {
  if (!isRecord(value)) return false;
  return value.kind === "nullid-workflow-package" || value.kind === "nullid-safe-share";
}

function isSchema2SafeShareBundle(value: unknown): value is Record<string, unknown> & { schemaVersion: number } {
  return isRecord(value)
    && value.kind === "nullid-safe-share"
    && Number(value.schemaVersion) === 2
    && isRecord(value.workflowPackage);
}

function looksLikePolicyPack(value: unknown) {
  return isRecord(value) && value.kind === "sanitize-policy-pack";
}

function looksLikeProfile(value: unknown) {
  return isRecord(value) && (value.kind === "profile" || (value.entries !== undefined && value.schemaVersion !== undefined));
}

function looksLikeVault(value: unknown) {
  return isRecord(value) && (value.kind === "vault" || value.vault !== undefined || value.notes !== undefined || value.meta !== undefined);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function overallArtifactStatus(state: ReceivedVerificationState): VerificationArtifactEntry["status"] {
  if (state === "verified" || state === "integrity-checked") return "verified";
  if (state === "mismatch") return "mismatch";
  return "unverified";
}

function summarizeWorkflowPolicy(
  policy: {
    type: "sanitize";
    config?: { rulesState: Record<string, boolean>; jsonAware: boolean; customRules: unknown[] };
    preset?: string;
    packName?: string;
    baseline?: string | null;
  } | undefined,
): VerificationFact[] {
  if (!policy) return [];
  const facts: VerificationFact[] = [{ label: "Policy type", value: policy.type }];
  if (policy.preset) facts.push({ label: "Preset", value: policy.preset });
  if (policy.packName) facts.push({ label: "Pack", value: policy.packName });
  if (policy.baseline) facts.push({ label: "Baseline", value: policy.baseline });
  if (policy.config) {
    const enabledRules = Object.values(policy.config.rulesState).filter(Boolean).length;
    facts.push({ label: "Enabled rules", value: String(enabledRules) });
    facts.push({ label: "JSON aware", value: policy.config.jsonAware ? "yes" : "no" });
    facts.push({ label: "Custom rules", value: String(policy.config.customRules.length) });
  }
  return facts;
}

function summarizeWorkflowReport(
  report:
    | {
        purpose?: string;
        audience?: string;
        includedArtifacts: string[];
        transformedArtifacts: string[];
        preservedArtifacts: string[];
        receiverCanVerify: string[];
        receiverCannotVerify: string[];
      }
    | undefined,
): VerificationWorkflowReport | undefined {
  if (!report) return undefined;
  return {
    purpose: report.purpose,
    audience: report.audience,
    includedArtifacts: [...report.includedArtifacts],
    transformedArtifacts: [...report.transformedArtifacts],
    preservedArtifacts: [...report.preservedArtifacts],
    receiverCanVerify: [...report.receiverCanVerify],
    receiverCannotVerify: [...report.receiverCannotVerify],
  };
}

function summarizeDescriptiveWorkflowMetadata(workflowPackage: {
  workflowType: string;
  packageType: string;
  producedAt: string;
  producer: {
    app: string;
    surface: string;
  };
  workflowPreset?: {
    label: string;
  };
  summary: {
    title: string;
  };
  transforms?: Array<{
    label: string;
    summary: string;
  }>;
  policy?: {
    type: "sanitize";
    config?: { rulesState: Record<string, boolean>; jsonAware: boolean; customRules: unknown[] };
    preset?: string;
    packName?: string;
    baseline?: string | null;
  };
  report?: {
    purpose?: string;
    audience?: string;
    includedArtifacts: string[];
    transformedArtifacts: string[];
    preservedArtifacts: string[];
    receiverCanVerify: string[];
    receiverCannotVerify: string[];
  };
  warnings: string[];
  limitations: string[];
}): VerificationDescriptiveWorkflowMetadata | undefined {
  const facts: VerificationFact[] = [
    { label: "Workflow", value: workflowPackage.workflowType },
    { label: "Package type", value: workflowPackage.packageType },
    ...(workflowPackage.workflowPreset ? [{ label: "Workflow preset", value: workflowPackage.workflowPreset.label }] : []),
    { label: "Produced at", value: workflowPackage.producedAt },
    { label: "Producer", value: `${workflowPackage.producer.app} / ${workflowPackage.producer.surface}` },
  ];
  const transforms = (workflowPackage.transforms ?? []).map((transform) => ({
    label: transform.label,
    value: transform.summary,
  }));
  const policySummary = summarizeWorkflowPolicy(workflowPackage.policy);
  const workflowReport = summarizeWorkflowReport(workflowPackage.report);
  if (
    !workflowPackage.summary.title &&
    facts.length === 0 &&
    transforms.length === 0 &&
    policySummary.length === 0 &&
    !workflowReport &&
    workflowPackage.warnings.length === 0 &&
    workflowPackage.limitations.length === 0
  ) {
    return undefined;
  }
  return {
    title: workflowPackage.summary.title,
    facts,
    transforms,
    policySummary,
    workflowReport,
    warnings: [...workflowPackage.warnings],
    limitations: [...workflowPackage.limitations],
  };
}

function excludePackageDeclaredWorkflowLines(lines: string[], declaredLines: string[]) {
  if (declaredLines.length === 0) return lines;
  const declared = new Set(declaredLines);
  return lines.filter((line) => !declared.has(line));
}

function envelopeFactsFromMeta(meta: EnvelopeInspectResult): VerificationFact[] {
  return [
    { label: "Envelope", value: "NULLID:ENC:1" },
    { label: "KDF", value: `${meta.header.kdf.name} / ${meta.header.kdf.hash}` },
    { label: "Iterations", value: String(meta.header.kdf.iterations) },
    { label: "Ciphertext bytes", value: String(meta.ciphertextBytes) },
    ...(meta.header.name ? [{ label: "Name", value: meta.header.name }] : []),
    ...(meta.header.mime ? [{ label: "MIME", value: meta.header.mime }] : []),
  ];
}
