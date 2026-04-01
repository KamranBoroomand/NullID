import { fromBase64, toBase64 } from "./encoding.js";
import { hashBytes, hashText } from "./hash.js";
import { normalizePolicyConfig } from "./sanitizeEngine.js";
export const WORKFLOW_PACKAGE_SCHEMA_VERSION = 1;
export const WORKFLOW_PACKAGE_KIND = "nullid-workflow-package";
export const SAFE_SHARE_BUNDLE_SCHEMA_VERSION = 2;
export const SAFE_SHARE_BUNDLE_KIND = "nullid-safe-share";
const LEGACY_SAFE_SHARE_BUNDLE_SCHEMA_VERSION = 1;
const SHA256_HEX_RE = /^[a-f0-9]{64}$/i;
export function createWorkflowPackage(input) {
    const producedAt = normalizeIso(input.producedAt, "Invalid workflow package producedAt");
    const artifacts = input.artifacts.map((artifact, index) => normalizeArtifact(artifact, index));
    const entryCount = artifacts.filter((artifact) => typeof artifact.sha256 === "string").length;
    const warnings = normalizeUniqueStringList(input.warnings, 40, 240);
    const limitations = normalizeUniqueStringList(input.limitations, 40, 240);
    return {
        schemaVersion: WORKFLOW_PACKAGE_SCHEMA_VERSION,
        kind: WORKFLOW_PACKAGE_KIND,
        packageType: input.packageType,
        workflowType: sanitizeInlineString(input.workflowType, 80, "workflow package type"),
        producedAt,
        producer: normalizeProducer(input.producer),
        workflowPreset: normalizeWorkflowPreset(input.workflowPreset),
        summary: normalizeSummary(input.summary),
        report: normalizeReport(input.report),
        trust: normalizeTrust(input.trust, entryCount),
        artifacts,
        policy: normalizePolicy(input.policy),
        transforms: input.transforms?.map((transform, index) => normalizeTransform(transform, index)),
        warnings,
        limitations,
    };
}
export function createSanitizeWorkflowPackage(input) {
    const producedAt = input.producedAt ?? new Date().toISOString();
    const warnings = [
        "Unsigned package. Sender identity is not asserted.",
        "SHA-256 manifest entries help detect changes to listed artifacts, but they are not a signature.",
    ];
    const limitations = [
        "Sanitized output should still be reviewed before sharing outside the intended trust boundary.",
        "Policy metadata is included for reproducibility; NullID does not claim public-key identity for this package.",
    ];
    const ruleCount = input.summary.appliedRules.length;
    return createWorkflowPackage({
        packageType: "bundle",
        workflowType: "sanitize-safe-share",
        producedAt,
        producer: input.producer,
        summary: {
            title: "Sanitized safe-share package",
            description: "Portable local package containing sanitized output, policy snapshot, and SHA-256 manifest entries.",
            highlights: [
                `Detected format: ${input.detectedFormat ?? "text"}`,
                `Lines affected: ${input.summary.linesAffected}`,
                `Applied rules: ${ruleCount}`,
            ],
        },
        report: {
            purpose: "Prepare sanitized text for local safe sharing.",
            includedArtifacts: [
                "Original input reference",
                "Sanitized output",
                "Sanitize policy snapshot",
            ],
            transformedArtifacts: ["Sanitize transformation"],
            preservedArtifacts: ["Original input reference only"],
            receiverCanVerify: [
                "Workflow package structure and schema version.",
                "SHA-256 manifest entries for the original input reference and sanitized output.",
            ],
            receiverCannotVerify: [
                "Sender identity or authorship.",
                "Whether omitted source context outside the included artifacts was complete.",
            ],
        },
        artifacts: [
            {
                id: "source-input",
                role: "input",
                label: input.sourceFile ? `Original input (${input.sourceFile})` : "Original input",
                kind: "reference",
                mediaType: "text/plain",
                included: false,
                bytes: input.input.bytes,
                sha256: input.input.sha256,
                filename: input.sourceFile,
            },
            {
                id: "sanitized-output",
                role: "output",
                label: "Sanitized output",
                kind: "text",
                mediaType: "text/plain;charset=utf-8",
                included: true,
                bytes: input.output.bytes,
                sha256: input.output.sha256,
                text: input.output.text,
            },
            {
                id: "sanitize-policy",
                role: "policy",
                label: "Sanitize policy snapshot",
                kind: "json",
                mediaType: "application/json",
                included: true,
                bytes: byteLengthOfJson(input.policy),
                sha256: undefined,
                json: cloneSerializable(input.policy),
            },
        ],
        policy: {
            type: "sanitize",
            config: input.policy,
            preset: input.preset,
            packName: input.policyPack?.name,
            baseline: input.baselinePath ?? null,
        },
        transforms: [
            {
                id: "sanitize-transform",
                type: "sanitize",
                label: "Sanitize transformation",
                summary: `Sanitized output ready (${input.summary.linesAffected} line${input.summary.linesAffected === 1 ? "" : "s"} changed).`,
                applied: normalizeStringList(input.summary.appliedRules, 100, 80),
                report: normalizeStringList(input.summary.report, 200, 240),
                metadata: {
                    detectedFormat: input.detectedFormat ?? "text",
                },
            },
        ],
        warnings,
        limitations,
    });
}
export function createSanitizeSafeShareBundle(input) {
    const createdAt = normalizeIso(input.producedAt ?? new Date().toISOString(), "Invalid safe-share createdAt");
    const workflowPackage = createSanitizeWorkflowPackage({
        ...input,
        producedAt: createdAt,
    });
    const warnings = [...workflowPackage.warnings];
    const limitations = [...workflowPackage.limitations];
    return {
        schemaVersion: SAFE_SHARE_BUNDLE_SCHEMA_VERSION,
        kind: SAFE_SHARE_BUNDLE_KIND,
        createdAt,
        tool: "sanitize",
        producer: normalizeProducer(input.producer),
        sourceFile: sanitizeOptionalInlineString(input.sourceFile, 160),
        detectedFormat: sanitizeOptionalInlineString(input.detectedFormat, 40),
        policy: normalizePolicyConfig(input.policy) ?? input.policy,
        input: {
            bytes: normalizeByteSize(input.input.bytes, "Invalid safe-share input size"),
            sha256: normalizeSha256(input.input.sha256, "Invalid safe-share input sha256"),
        },
        output: {
            bytes: normalizeByteSize(input.output.bytes, "Invalid safe-share output size"),
            sha256: normalizeSha256(input.output.sha256, "Invalid safe-share output sha256"),
            text: String(input.output.text ?? ""),
        },
        summary: {
            linesAffected: normalizeByteSize(input.summary.linesAffected, "Invalid safe-share linesAffected"),
            appliedRules: normalizeStringList(input.summary.appliedRules, 100, 80),
            report: normalizeStringList(input.summary.report, 200, 240),
        },
        warnings,
        limitations,
        workflowPackage,
    };
}
export function describeWorkflowPackagePayload(input) {
    const direct = normalizeWorkflowPackage(input);
    if (direct) {
        return {
            schemaVersion: direct.schemaVersion,
            kind: direct.kind,
            packageType: direct.packageType,
            workflowType: direct.workflowType,
            artifactCount: direct.artifacts.length,
            signatureMethod: direct.trust.packageSignature.method,
            encryptionMethod: direct.trust.encryptedPayload.method,
            legacy: false,
            sourceKind: "workflow-package",
        };
    }
    if (isRecord(input) && input.kind === SAFE_SHARE_BUNDLE_KIND) {
        const nested = normalizeWorkflowPackage(input.workflowPackage);
        if (nested) {
            return {
                schemaVersion: nested.schemaVersion,
                kind: nested.kind,
                packageType: nested.packageType,
                workflowType: nested.workflowType,
                artifactCount: nested.artifacts.length,
                signatureMethod: nested.trust.packageSignature.method,
                encryptionMethod: nested.trust.encryptedPayload.method,
                legacy: false,
                sourceKind: "safe-share",
            };
        }
        const legacy = extractLegacySafeSharePackage(input);
        if (legacy) {
            return {
                schemaVersion: legacy.schemaVersion,
                kind: legacy.kind,
                packageType: legacy.packageType,
                workflowType: legacy.workflowType,
                artifactCount: legacy.artifacts.length,
                signatureMethod: legacy.trust.packageSignature.method,
                encryptionMethod: legacy.trust.encryptedPayload.method,
                legacy: true,
                sourceKind: "safe-share",
            };
        }
    }
    return {
        schemaVersion: 0,
        kind: "unknown",
        packageType: "unknown",
        workflowType: "unknown",
        artifactCount: 0,
        signatureMethod: "unknown",
        encryptionMethod: "unknown",
        legacy: false,
        sourceKind: "workflow-package",
    };
}
export function extractWorkflowPackage(input) {
    const direct = normalizeWorkflowPackage(input);
    if (direct)
        return direct;
    if (isRecord(input) && input.kind === SAFE_SHARE_BUNDLE_KIND) {
        const nested = normalizeWorkflowPackage(input.workflowPackage);
        if (nested)
            return nested;
        const legacy = extractLegacySafeSharePackage(input);
        if (legacy)
            return legacy;
    }
    throw new Error(describeWorkflowPackageFailure(input));
}
export function normalizeWorkflowPackage(input) {
    if (!isRecord(input))
        return null;
    if (input.kind !== WORKFLOW_PACKAGE_KIND)
        return null;
    if (Number(input.schemaVersion) !== WORKFLOW_PACKAGE_SCHEMA_VERSION)
        return null;
    try {
        const artifacts = Array.isArray(input.artifacts) ? input.artifacts.map((artifact, index) => normalizeArtifact(artifact, index)) : [];
        const manifestEntryCount = artifacts.filter((artifact) => typeof artifact.sha256 === "string").length;
        return {
            schemaVersion: WORKFLOW_PACKAGE_SCHEMA_VERSION,
            kind: WORKFLOW_PACKAGE_KIND,
            packageType: normalizePackageType(input.packageType),
            workflowType: sanitizeInlineString(input.workflowType, 80, "workflow package type"),
            producedAt: normalizeIso(input.producedAt, "Invalid workflow package producedAt"),
            producer: normalizeProducer(input.producer),
            workflowPreset: normalizeWorkflowPreset(input.workflowPreset),
            summary: normalizeSummary(input.summary),
            report: normalizeReport(input.report),
            trust: normalizeTrust(input.trust, manifestEntryCount),
            artifacts,
            policy: normalizePolicy(input.policy),
            transforms: Array.isArray(input.transforms)
                ? input.transforms.map((transform, index) => normalizeTransform(transform, index))
                : undefined,
            warnings: normalizeUniqueStringList(input.warnings, 40, 240),
            limitations: normalizeUniqueStringList(input.limitations, 40, 240),
        };
    }
    catch {
        return null;
    }
}
export async function verifyWorkflowPackagePayload(input) {
    const descriptor = describeWorkflowPackagePayload(input);
    const workflowPackage = extractWorkflowPackage(input);
    const artifactChecks = await Promise.all(workflowPackage.artifacts.map((artifact) => verifyWorkflowArtifact(artifact)));
    const manifestEntryCount = workflowPackage.artifacts.filter((artifact) => typeof artifact.sha256 === "string").length;
    const manifestCountMatches = workflowPackage.trust.artifactManifest.entryCount === manifestEntryCount;
    const mismatchArtifacts = artifactChecks.filter((artifact) => artifact.status === "mismatch");
    const verifiedArtifacts = artifactChecks.filter((artifact) => artifact.status === "verified");
    const referencedArtifacts = artifactChecks.filter((artifact) => artifact.status === "reference");
    const unverifiableArtifacts = artifactChecks.filter((artifact) => artifact.status === "unverified");
    const warnings = [...workflowPackage.warnings];
    const limitations = [...workflowPackage.limitations];
    const trustBasis = [
        "Unsigned workflow package.",
        manifestCountMatches
            ? `SHA-256 manifest entry count matches (${manifestEntryCount}).`
            : `SHA-256 manifest entry count mismatch (${workflowPackage.trust.artifactManifest.entryCount} declared vs ${manifestEntryCount} present).`,
    ];
    const verifiedChecks = [
        `Workflow package schema ${workflowPackage.schemaVersion} parsed successfully.`,
        `Artifact manifest algorithm recorded as ${workflowPackage.trust.artifactManifest.algorithm}.`,
    ];
    const unverifiedChecks = [
        "Sender identity is not asserted by this package format.",
    ];
    if (!manifestCountMatches) {
        warnings.push("Manifest metadata does not match the number of hashed artifact entries.");
    }
    if (verifiedArtifacts.length > 0) {
        verifiedChecks.push(`Verified SHA-256 for ${verifiedArtifacts.length} included artifact(s).`);
    }
    else if (manifestCountMatches) {
        unverifiedChecks.push("No included artifact carried enough inline data for SHA-256 self-consistency verification.");
    }
    if (referencedArtifacts.length > 0) {
        unverifiedChecks.push(`${referencedArtifacts.length} referenced artifact(s) were listed but not included, so their bytes could not be verified locally.`);
    }
    if (unverifiableArtifacts.length > 0) {
        unverifiedChecks.push(`${unverifiableArtifacts.length} included artifact(s) lacked inline content needed for local hash verification.`);
    }
    let verificationState = "unsigned";
    let verificationLabel = "Unsigned";
    let failure;
    if (!manifestCountMatches || mismatchArtifacts.length > 0) {
        verificationState = "mismatch";
        verificationLabel = "Mismatch";
        failure = mismatchArtifacts.length > 0
            ? `${mismatchArtifacts.length} artifact hash mismatch(es) detected.`
            : "Manifest entry count mismatch.";
    }
    else if (verifiedArtifacts.length > 0 || manifestCountMatches) {
        verificationState = "integrity-checked";
        verificationLabel = "Integrity checked";
    }
    return {
        descriptor,
        workflowPackage,
        verificationState,
        verificationLabel,
        trustBasis,
        verifiedChecks,
        unverifiedChecks,
        warnings: normalizeUniqueStringList(warnings, 60, 240),
        limitations: normalizeUniqueStringList(limitations, 60, 240),
        artifactChecks,
        failure,
    };
}
function extractLegacySafeSharePackage(input) {
    const schemaVersion = Number(input.schemaVersion);
    if (schemaVersion !== LEGACY_SAFE_SHARE_BUNDLE_SCHEMA_VERSION && schemaVersion !== SAFE_SHARE_BUNDLE_SCHEMA_VERSION) {
        return null;
    }
    const inputMeta = isRecord(input.input) ? input.input : null;
    const outputMeta = isRecord(input.output) ? input.output : null;
    const policy = normalizePolicyConfig(input.policy) ?? undefined;
    const summary = isRecord(input.summary) ? input.summary : null;
    const createdAt = typeof input.createdAt === "string" ? input.createdAt : new Date(0).toISOString();
    if (!inputMeta || !outputMeta || typeof outputMeta.text !== "string")
        return null;
    return createWorkflowPackage({
        packageType: "bundle",
        workflowType: "sanitize-safe-share",
        producedAt: createdAt,
        producer: {
            app: "NullID",
            surface: isRecord(input.producer) && typeof input.producer.surface === "string" ? normalizeSurface(input.producer.surface) : "unknown",
            module: "sanitize",
            version: isRecord(input.producer) && typeof input.producer.version === "string" ? input.producer.version : null,
            buildId: isRecord(input.producer) && typeof input.producer.buildId === "string" ? input.producer.buildId : null,
        },
        summary: {
            title: "Sanitized safe-share package",
            description: "Compatibility-mapped safe-share bundle.",
            highlights: [
                `Lines affected: ${typeof summary?.linesAffected === "number" ? summary.linesAffected : 0}`,
                `Applied rules: ${Array.isArray(summary?.appliedRules) ? summary.appliedRules.length : 0}`,
            ],
        },
        report: {
            purpose: "Compatibility-mapped sanitize safe-share package.",
            includedArtifacts: [
                "Original input reference",
                "Sanitized output",
                "Sanitize policy snapshot",
            ],
            transformedArtifacts: ["Sanitize transformation"],
            preservedArtifacts: ["Original input reference only"],
            receiverCanVerify: [
                "Workflow package structure and schema version.",
                "SHA-256 manifest entries for the original input reference and sanitized output.",
            ],
            receiverCannotVerify: [
                "Sender identity or authorship.",
                "Whether omitted source context outside the included artifacts was complete.",
            ],
        },
        artifacts: [
            {
                id: "source-input",
                role: "input",
                label: typeof input.sourceFile === "string" ? `Original input (${input.sourceFile})` : "Original input",
                kind: "reference",
                mediaType: "text/plain",
                included: false,
                bytes: typeof inputMeta.bytes === "number" ? inputMeta.bytes : undefined,
                sha256: typeof inputMeta.sha256 === "string" ? inputMeta.sha256 : undefined,
                filename: typeof input.sourceFile === "string" ? input.sourceFile : undefined,
            },
            {
                id: "sanitized-output",
                role: "output",
                label: "Sanitized output",
                kind: "text",
                mediaType: "text/plain;charset=utf-8",
                included: true,
                bytes: typeof outputMeta.bytes === "number" ? outputMeta.bytes : undefined,
                sha256: typeof outputMeta.sha256 === "string" ? outputMeta.sha256 : undefined,
                text: outputMeta.text,
            },
            {
                id: "sanitize-policy",
                role: "policy",
                label: "Sanitize policy snapshot",
                kind: "json",
                mediaType: "application/json",
                included: true,
                bytes: policy ? byteLengthOfJson(policy) : undefined,
                json: policy,
            },
        ],
        policy: policy
            ? {
                type: "sanitize",
                config: policy,
            }
            : undefined,
        transforms: [
            {
                id: "sanitize-transform",
                type: "sanitize",
                label: "Sanitize transformation",
                summary: "Compatibility-mapped sanitize report.",
                applied: Array.isArray(summary?.appliedRules) ? normalizeStringList(summary.appliedRules, 100, 80) : undefined,
                report: Array.isArray(summary?.report) ? normalizeStringList(summary.report, 200, 240) : undefined,
                metadata: {
                    detectedFormat: typeof input.detectedFormat === "string" ? input.detectedFormat : "text",
                },
            },
        ],
        warnings: normalizeUniqueStringList(normalizeStringList(input.warnings, 40, 240).concat(["Unsigned package. Sender identity is not asserted."]), 40, 240),
        limitations: normalizeUniqueStringList(input.limitations, 40, 240),
    });
}
function normalizePackageType(value) {
    return value === "report" ? "report" : "bundle";
}
function describeWorkflowPackageFailure(input) {
    if (!isRecord(input)) {
        return "Unsupported workflow package payload";
    }
    if (input.kind === WORKFLOW_PACKAGE_KIND) {
        if (Number(input.schemaVersion) !== WORKFLOW_PACKAGE_SCHEMA_VERSION) {
            return `Unsupported workflow package schema: ${String(input.schemaVersion ?? "unknown")}`;
        }
        return "Invalid workflow package payload";
    }
    if (input.kind === SAFE_SHARE_BUNDLE_KIND) {
        const schemaVersion = Number(input.schemaVersion);
        if (schemaVersion !== LEGACY_SAFE_SHARE_BUNDLE_SCHEMA_VERSION && schemaVersion !== SAFE_SHARE_BUNDLE_SCHEMA_VERSION) {
            return `Unsupported safe-share bundle schema: ${String(input.schemaVersion ?? "unknown")}`;
        }
        if (isRecord(input.workflowPackage) && input.workflowPackage.kind === WORKFLOW_PACKAGE_KIND) {
            if (Number(input.workflowPackage.schemaVersion) !== WORKFLOW_PACKAGE_SCHEMA_VERSION) {
                return `Unsupported embedded workflow package schema: ${String(input.workflowPackage.schemaVersion ?? "unknown")}`;
            }
            return "Invalid embedded workflow package payload";
        }
        return "Invalid safe-share bundle payload";
    }
    return "Unsupported workflow package payload";
}
function normalizeProducer(value) {
    const record = isRecord(value) ? value : {};
    return {
        app: "NullID",
        surface: normalizeSurface(record.surface),
        module: sanitizeOptionalInlineString(record.module, 80),
        version: normalizeOptionalString(record.version, 40),
        buildId: normalizeOptionalString(record.buildId, 80),
    };
}
function normalizeSurface(value) {
    if (value === "web" || value === "cli")
        return value;
    return "unknown";
}
function normalizeSummary(value) {
    const record = isRecord(value) ? value : {};
    return {
        title: sanitizeInlineString(record.title, 120, "workflow package summary title"),
        description: sanitizeInlineString(record.description, 280, "workflow package summary description"),
        highlights: normalizeStringList(record.highlights, 12, 180),
    };
}
function normalizeReport(value) {
    if (!isRecord(value))
        return undefined;
    const includedArtifacts = normalizeStringList(value.includedArtifacts, 40, 180);
    const transformedArtifacts = normalizeStringList(value.transformedArtifacts, 40, 180);
    const preservedArtifacts = normalizeStringList(value.preservedArtifacts, 40, 180);
    const receiverCanVerify = normalizeStringList(value.receiverCanVerify, 24, 220);
    const receiverCannotVerify = normalizeStringList(value.receiverCannotVerify, 24, 220);
    const purpose = sanitizeOptionalInlineString(value.purpose, 240);
    const audience = sanitizeOptionalInlineString(value.audience, 160);
    if (!purpose &&
        !audience &&
        includedArtifacts.length === 0 &&
        transformedArtifacts.length === 0 &&
        preservedArtifacts.length === 0 &&
        receiverCanVerify.length === 0 &&
        receiverCannotVerify.length === 0) {
        return undefined;
    }
    return {
        purpose,
        audience,
        includedArtifacts,
        transformedArtifacts,
        preservedArtifacts,
        receiverCanVerify,
        receiverCannotVerify,
    };
}
function normalizeTrust(value, artifactCount) {
    const record = isRecord(value) ? value : {};
    const signatureRecord = isRecord(record.packageSignature) ? record.packageSignature : {};
    const manifestRecord = isRecord(record.artifactManifest) ? record.artifactManifest : {};
    const encryptedRecord = isRecord(record.encryptedPayload) ? record.encryptedPayload : {};
    const ignoredPackageSignatureClaim = hasUnsupportedWorkflowTrustClaim(signatureRecord.method);
    const ignoredEncryptedPayloadClaim = hasUnsupportedWorkflowTrustClaim(encryptedRecord.method);
    return {
        identity: "not-asserted",
        packageSignature: {
            method: normalizeSignatureMethod(signatureRecord.method),
            keyHint: undefined,
        },
        artifactManifest: {
            algorithm: "sha256",
            entryCount: typeof manifestRecord.entryCount === "number" && Number.isInteger(manifestRecord.entryCount) && manifestRecord.entryCount >= 0
                ? manifestRecord.entryCount
                : artifactCount,
        },
        encryptedPayload: {
            method: normalizeEncryptionMethod(encryptedRecord.method),
        },
        notes: normalizeUniqueStringList(normalizeStringList(record.notes ?? defaultTrustNotes(), 12, 240).concat(ignoredPackageSignatureClaim
            ? ["Ignored unsupported inner workflow package signature claim. The current contract does not carry a verifiable package signature."]
            : [], ignoredEncryptedPayloadClaim
            ? ["Ignored unsupported inner workflow package encryption claim. NULLID:ENC:1 applies only to the optional outer export envelope."]
            : []), 12, 240),
    };
}
function defaultTrustNotes() {
    return [
        "Unsigned package. Sender identity is not asserted.",
        "SHA-256 manifest entries help detect changes to listed artifacts, but they are not a signature.",
    ];
}
function normalizeSignatureMethod(_value) {
    return "none";
}
function normalizeEncryptionMethod(_value) {
    return "none";
}
function hasUnsupportedWorkflowTrustClaim(value) {
    return typeof value === "string" && value !== "none";
}
function normalizeArtifact(value, index) {
    const record = isRecord(value) ? value : {};
    const binaryBase64 = typeof record.base64 === "string" ? sanitizeBase64Payload(record.base64, index) : undefined;
    const artifact = {
        id: sanitizeInlineString(record.id ?? `artifact-${index + 1}`, 80, `workflow artifact id ${index + 1}`),
        role: sanitizeInlineString(record.role ?? "artifact", 80, `workflow artifact role ${index + 1}`),
        label: sanitizeInlineString(record.label ?? `Artifact ${index + 1}`, 160, `workflow artifact label ${index + 1}`),
        kind: normalizeArtifactKind(record.kind),
        mediaType: sanitizeInlineString(record.mediaType ?? "application/octet-stream", 120, `workflow artifact media type ${index + 1}`),
        included: Boolean(record.included),
        bytes: typeof record.bytes === "number" ? normalizeByteSize(record.bytes, `Invalid artifact byte size at index ${index}`) : undefined,
        sha256: record.sha256 === undefined ? undefined : normalizeSha256(record.sha256, `Invalid artifact sha256 at index ${index}`),
        filename: sanitizeOptionalInlineString(record.filename, 160),
        text: typeof record.text === "string" ? record.text : undefined,
        json: record.json === undefined ? undefined : cloneSerializable(record.json),
        base64: binaryBase64,
    };
    if (artifact.text !== undefined && artifact.kind !== "text") {
        throw new Error(`Artifact text payload only allowed for text artifacts at index ${index}`);
    }
    if (artifact.json !== undefined && artifact.kind !== "json") {
        throw new Error(`Artifact json payload only allowed for json artifacts at index ${index}`);
    }
    if (artifact.base64 !== undefined && artifact.kind !== "binary") {
        throw new Error(`Artifact base64 payload only allowed for binary artifacts at index ${index}`);
    }
    if (artifact.kind === "binary" && artifact.base64 !== undefined && artifact.bytes === undefined) {
        artifact.bytes = fromBase64(artifact.base64).length;
    }
    return artifact;
}
function normalizeArtifactKind(value) {
    if (value === "text" || value === "json" || value === "binary" || value === "manifest" || value === "reference") {
        return value;
    }
    return "reference";
}
async function verifyWorkflowArtifact(artifact) {
    const base = {
        id: artifact.id,
        role: artifact.role,
        label: artifact.label,
        kind: artifact.kind,
        mediaType: artifact.mediaType,
        included: artifact.included,
        bytes: artifact.bytes,
        sha256: artifact.sha256,
        status: "unverified",
        detail: "No local verification performed.",
    };
    if (!artifact.sha256) {
        return {
            ...base,
            detail: "No SHA-256 manifest entry recorded for this artifact.",
        };
    }
    if (!artifact.included) {
        return {
            ...base,
            status: "reference",
            detail: "Artifact was referenced but not included, so local byte verification was not possible.",
        };
    }
    if (artifact.kind === "text" && typeof artifact.text === "string") {
        const computed = await hashText(artifact.text, "SHA-256");
        return {
            ...base,
            status: computed.hex === artifact.sha256 ? "verified" : "mismatch",
            detail: computed.hex === artifact.sha256
                ? "SHA-256 matches the included text payload."
                : "SHA-256 does not match the included text payload.",
        };
    }
    if (artifact.kind === "json" && artifact.json !== undefined) {
        const computed = await hashText(JSON.stringify(artifact.json), "SHA-256");
        return {
            ...base,
            status: computed.hex === artifact.sha256 ? "verified" : "mismatch",
            detail: computed.hex === artifact.sha256
                ? "SHA-256 matches the included JSON payload."
                : "SHA-256 does not match the included JSON payload.",
        };
    }
    if (artifact.kind === "binary" && typeof artifact.base64 === "string") {
        const computed = await hashBytes(fromBase64(artifact.base64), "SHA-256");
        return {
            ...base,
            status: computed.hex === artifact.sha256 ? "verified" : "mismatch",
            detail: computed.hex === artifact.sha256
                ? "SHA-256 matches the included binary payload."
                : "SHA-256 does not match the included binary payload.",
        };
    }
    return {
        ...base,
        detail: "Artifact includes a manifest hash, but no inline payload was available for local verification.",
    };
}
function normalizeTransform(value, index) {
    const record = isRecord(value) ? value : {};
    return {
        id: sanitizeInlineString(record.id ?? `transform-${index + 1}`, 80, `workflow transform id ${index + 1}`),
        type: sanitizeInlineString(record.type ?? "transform", 80, `workflow transform type ${index + 1}`),
        label: sanitizeInlineString(record.label ?? `Transform ${index + 1}`, 160, `workflow transform label ${index + 1}`),
        summary: sanitizeInlineString(record.summary ?? "", 280, `workflow transform summary ${index + 1}`),
        applied: record.applied === undefined ? undefined : normalizeStringList(record.applied, 120, 80),
        report: record.report === undefined ? undefined : normalizeStringList(record.report, 240, 240),
        metadata: record.metadata === undefined ? undefined : normalizeMetadata(record.metadata),
    };
}
function normalizePolicy(value) {
    if (!isRecord(value))
        return undefined;
    const type = value.type === "sanitize" ? "sanitize" : null;
    if (!type)
        return undefined;
    const next = {
        type,
    };
    const config = normalizePolicyConfig(value.config);
    if (config)
        next.config = config;
    const preset = sanitizeOptionalInlineString(value.preset, 80);
    if (preset)
        next.preset = preset;
    const packName = sanitizeOptionalInlineString(value.packName, 120);
    if (packName)
        next.packName = packName;
    if (value.baseline === null) {
        next.baseline = null;
    }
    else {
        const baseline = sanitizeOptionalInlineString(value.baseline, 200);
        if (baseline)
            next.baseline = baseline;
    }
    return next;
}
function normalizeMetadata(value) {
    if (!isRecord(value))
        return {};
    return cloneSerializable(value);
}
function normalizeWorkflowPreset(value) {
    if (!isRecord(value))
        return undefined;
    const id = sanitizeOptionalInlineString(value.id, 80);
    const label = sanitizeOptionalInlineString(value.label, 120);
    if (!id || !label)
        return undefined;
    return {
        id,
        label,
        summary: sanitizeOptionalInlineString(value.summary, 240),
    };
}
function normalizeSha256(value, errorMessage) {
    if (typeof value !== "string" || !SHA256_HEX_RE.test(value)) {
        throw new Error(errorMessage);
    }
    return value.toLowerCase();
}
function sanitizeBase64Payload(value, index) {
    const trimmed = value.trim();
    if (!trimmed || !/^[A-Za-z0-9+/]+=*$/u.test(trimmed)) {
        throw new Error(`Invalid artifact base64 payload at index ${index}`);
    }
    try {
        const bytes = fromBase64(trimmed);
        const normalized = toBase64(bytes);
        const expected = trimmed.padEnd(trimmed.length + ((4 - (trimmed.length % 4)) % 4), "=");
        if (normalized !== expected) {
            throw new Error(`Invalid artifact base64 payload at index ${index}`);
        }
        return trimmed;
    }
    catch {
        throw new Error(`Invalid artifact base64 payload at index ${index}`);
    }
}
function normalizeByteSize(value, errorMessage) {
    if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
        throw new Error(errorMessage);
    }
    return value;
}
function normalizeIso(value, errorMessage) {
    if (typeof value !== "string" || !value.trim()) {
        throw new Error(errorMessage);
    }
    const normalized = value.trim();
    if (Number.isNaN(Date.parse(normalized))) {
        throw new Error(errorMessage);
    }
    return normalized;
}
function normalizeStringList(value, maxItems, maxLength) {
    if (!Array.isArray(value))
        return [];
    return value
        .map((item) => (typeof item === "string" ? item.trim().slice(0, maxLength) : ""))
        .filter(Boolean)
        .slice(0, maxItems);
}
function normalizeUniqueStringList(value, maxItems, maxLength) {
    return Array.from(new Set(normalizeStringList(value, maxItems, maxLength))).slice(0, maxItems);
}
function sanitizeInlineString(value, maxLength, label) {
    if (typeof value !== "string") {
        throw new Error(`Missing ${label}`);
    }
    const normalized = value.trim().slice(0, maxLength);
    if (!normalized) {
        throw new Error(`Missing ${label}`);
    }
    return normalized;
}
function sanitizeOptionalInlineString(value, maxLength) {
    if (typeof value !== "string")
        return undefined;
    const normalized = value.trim().slice(0, maxLength);
    return normalized || undefined;
}
function normalizeOptionalString(value, maxLength) {
    if (value === null)
        return null;
    return sanitizeOptionalInlineString(value, maxLength) ?? null;
}
function cloneSerializable(value) {
    return JSON.parse(JSON.stringify(value));
}
function byteLengthOfJson(value) {
    return new TextEncoder().encode(JSON.stringify(cloneSerializable(value))).byteLength;
}
function isRecord(value) {
    return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
