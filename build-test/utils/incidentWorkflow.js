import { createSafeShareFileWorkflowPackage, createSafeShareTextWorkflowPackage, } from "./safeShareAssistant.js";
import { hashText } from "./hash.js";
import { createWorkflowPackage, } from "./workflowPackage.js";
export const INCIDENT_TEMPLATE_BODY = "Summary:\nImpact:\nIndicators:\nActions taken:\nNext steps:";
export const INCIDENT_TEMPLATE_TAGS = "incident,triage";
export const incidentWorkflowModes = {
    "incident-handoff": {
        id: "incident-handoff",
        label: "Incident handoff",
        description: "Prepare a responder-to-responder handoff with context, transforms, and honest limits.",
        safeSharePresetId: "incident-handoff",
        includeSourceReferenceDefault: true,
        defaultApplyMetadataClean: true,
        guidance: [
            "Best for moving a live incident between responders while keeping the package locally reviewable.",
            "Preserves responder context more readily than external-share presets.",
        ],
        limitations: [
            "This is a disciplined handoff package, not a formal chain-of-custody or identity-signing system.",
        ],
    },
    "evidence-archive": {
        id: "evidence-archive",
        label: "Evidence archive",
        description: "Preserve more context for later review while still recording what was cleaned or left intact.",
        safeSharePresetId: "evidence-archive",
        includeSourceReferenceDefault: true,
        defaultApplyMetadataClean: false,
        guidance: [
            "Use when preserving context matters more than aggressive reduction.",
            "Original binaries may remain included when cleanup would destroy needed evidence context.",
        ],
        limitations: [
            "Preserving more context can preserve more residual sensitivity or operational detail.",
        ],
    },
    "minimal-disclosure-incident-share": {
        id: "minimal-disclosure-incident-share",
        label: "Minimal disclosure incident share",
        description: "Reduce context aggressively for external incident communications or tightly scoped escalations.",
        safeSharePresetId: "external-minimum",
        includeSourceReferenceDefault: false,
        defaultApplyMetadataClean: true,
        guidance: [
            "Use when the receiver should get the least possible amount of original context.",
            "When cleanup is unavailable, this mode prefers report-only packaging instead of raw bytes.",
        ],
        limitations: [
            "Aggressive reduction can remove chronology or debugging detail an internal responder would want.",
        ],
    },
    "internal-investigation": {
        id: "internal-investigation",
        label: "Internal investigation package",
        description: "Keep more internal context available for analysis while still scrubbing obvious secrets and tokens.",
        safeSharePresetId: "internal-investigation",
        includeSourceReferenceDefault: true,
        defaultApplyMetadataClean: true,
        guidance: [
            "Designed for internal teams that need notes, chronology, and supporting artifacts in one local package.",
            "Original binaries can still be preserved when that is materially useful for the investigation.",
        ],
        limitations: [
            "Internal packages can still contain sensitive operational context and should stay within the intended trust boundary.",
        ],
    },
};
export const incidentWorkflowModeIds = Object.keys(incidentWorkflowModes);
export function getIncidentWorkflowMode(id) {
    return incidentWorkflowModes[id] ?? incidentWorkflowModes["incident-handoff"];
}
export function buildIncidentTemplateTitle(date = new Date()) {
    return `Incident ${date.toISOString().slice(0, 10)}`;
}
export function buildDefaultIncidentPurpose(modeId) {
    const mode = getIncidentWorkflowMode(modeId);
    return `Prepare a ${mode.label.toLowerCase()} package.`;
}
export async function createIncidentTextArtifactPackage(input) {
    const mode = getIncidentWorkflowMode(input.modeId);
    return createSafeShareTextWorkflowPackage({
        presetId: mode.safeSharePresetId,
        producer: input.producer,
        inputText: input.inputText,
        sourceLabel: input.sourceLabel,
        includeSourceReference: input.includeSourceReference ?? mode.includeSourceReferenceDefault,
        policyPack: input.policyPack ?? null,
        protectAtExport: input.protectAtExport,
    });
}
export async function createIncidentFileArtifactPackage(input) {
    const mode = getIncidentWorkflowMode(input.modeId);
    return createSafeShareFileWorkflowPackage({
        presetId: mode.safeSharePresetId,
        producer: input.producer,
        fileName: input.fileName,
        fileMediaType: input.fileMediaType,
        sourceBytes: input.sourceBytes,
        analysis: input.analysis,
        cleanedBytes: input.cleanedBytes,
        cleanedMediaType: input.cleanedMediaType,
        cleanedLabel: input.cleanedLabel,
        applyMetadataClean: input.applyMetadataClean ?? mode.defaultApplyMetadataClean,
        includeSourceReference: input.includeSourceReference ?? mode.includeSourceReferenceDefault,
        protectAtExport: input.protectAtExport,
    });
}
export async function createIncidentWorkflowPackage(input) {
    const mode = getIncidentWorkflowMode(input.modeId);
    const producedAt = input.producedAt ?? new Date().toISOString();
    const preparedArtifacts = input.preparedArtifacts ?? [];
    const purpose = sanitizeInline(input.purpose) || buildDefaultIncidentPurpose(mode.id);
    const incidentTitle = sanitizeInline(input.incidentTitle) || buildIncidentTemplateTitle();
    const caseReference = sanitizeInline(input.caseReference);
    const recipientScope = sanitizeInline(input.recipientScope);
    const summaryText = sanitizeMultiline(input.summaryText);
    const flattenedArtifacts = flattenPreparedArtifacts(preparedArtifacts);
    const flattenedTransforms = flattenPreparedTransforms(preparedArtifacts);
    const includedArtifacts = uniqueStrings([
        "Incident context",
        "Incident report",
        ...preparedArtifacts.flatMap((entry) => summarizeIncludedArtifacts(entry)),
    ]);
    const transformedArtifacts = uniqueStrings([
        "Incident workflow assembly",
        ...preparedArtifacts.flatMap((entry) => summarizeTransformedArtifacts(entry)),
    ]);
    const preservedArtifacts = uniqueStrings(preparedArtifacts.flatMap((entry) => summarizePreservedArtifacts(entry)));
    const receiverCanVerify = uniqueStrings([
        "Workflow package structure and schema version.",
        "SHA-256 manifest entries for included inline artifacts and references.",
        "Included incident context and incident report artifacts carried inside this package.",
        ...preparedArtifacts.flatMap((entry) => entry.workflowPackage.report?.receiverCanVerify ?? []),
    ]);
    const receiverCannotVerify = uniqueStrings([
        "Sender identity or authorship.",
        "Whether omitted evidence, timeline steps, or external case context were complete.",
        ...preparedArtifacts.flatMap((entry) => entry.workflowPackage.report?.receiverCannotVerify ?? []),
    ]);
    const contextPayload = {
        workflowType: "incident-workflow",
        mode: {
            id: mode.id,
            label: mode.label,
            description: mode.description,
        },
        incidentTitle,
        purpose,
        caseReference: caseReference ?? null,
        recipientScope: recipientScope ?? null,
        summaryText: summaryText ?? null,
        preparedArtifactCount: preparedArtifacts.length,
        notesTemplateUsed: Boolean(input.notesTemplateUsed),
    };
    const contextJson = JSON.stringify(contextPayload);
    const contextHash = await hashText(contextJson, "SHA-256");
    const reportPayload = {
        mode: {
            id: mode.id,
            label: mode.label,
        },
        incidentTitle,
        purpose,
        caseReference: caseReference ?? null,
        recipientScope: recipientScope ?? null,
        summaryText: summaryText ?? null,
        includedArtifacts,
        transformedArtifacts,
        preservedArtifacts,
        preparedArtifacts: preparedArtifacts.map((entry) => ({
            id: entry.id,
            label: entry.label,
            kind: entry.kind,
            workflowType: entry.workflowPackage.workflowType,
            workflowPreset: entry.workflowPackage.workflowPreset?.id ?? null,
            includedArtifacts: entry.workflowPackage.artifacts.filter((artifact) => artifact.included).map((artifact) => artifact.label),
            referencedArtifacts: entry.workflowPackage.artifacts.filter((artifact) => !artifact.included).map((artifact) => artifact.label),
        })),
        receiverCanVerify,
        receiverCannotVerify,
    };
    const reportJson = JSON.stringify(reportPayload);
    const reportHash = await hashText(reportJson, "SHA-256");
    const warnings = uniqueStrings([
        ...preparedArtifacts.flatMap((entry) => entry.workflowPackage.warnings),
        ...(preparedArtifacts.length === 0 ? ["No prepared incident artifacts were added; this package carries context/report data only."] : []),
        ...(input.notesTemplateUsed ? ["Case notes still use the stock incident template headings and should be completed before wider sharing."] : []),
        ...(!recipientScope ? ["Recipient scope is not recorded in this package metadata."] : []),
        "Unsigned package. Sender identity is not asserted.",
        "SHA-256 manifest entries help detect changes to included artifacts, but they are not a signature.",
    ]);
    const limitations = uniqueStrings([
        ...mode.limitations,
        ...preparedArtifacts.flatMap((entry) => entry.workflowPackage.limitations),
        ...(input.protectAtExport
            ? ["NULLID:ENC:1 protection is applied to the exported file, not as a sender signature inside the package."]
            : ["Without an outer NULLID:ENC:1 envelope, the exported package remains readable JSON on disk."]),
    ]);
    return createWorkflowPackage({
        packageType: "bundle",
        workflowType: "incident-workflow",
        producedAt,
        producer: input.producer,
        workflowPreset: {
            id: mode.id,
            label: mode.label,
            summary: mode.description,
        },
        summary: {
            title: incidentTitle,
            description: "Incident Workflow export with case context, prepared artifacts, and receiver-facing reporting.",
            highlights: [
                `Mode: ${mode.label}`,
                `Prepared artifacts: ${preparedArtifacts.length}`,
                ...(caseReference ? [`Case reference: ${caseReference}`] : []),
                `Protection: ${input.protectAtExport ? "NULLID:ENC:1 at export" : "none"}`,
            ],
        },
        report: {
            purpose,
            audience: recipientScope,
            includedArtifacts,
            transformedArtifacts,
            preservedArtifacts,
            receiverCanVerify,
            receiverCannotVerify,
        },
        artifacts: [
            {
                id: "incident-context",
                role: "context",
                label: "Incident context",
                kind: "json",
                mediaType: "application/json",
                included: true,
                bytes: new TextEncoder().encode(contextJson).byteLength,
                sha256: contextHash.hex,
                json: contextPayload,
            },
            {
                id: "incident-report",
                role: "report",
                label: "Incident report",
                kind: "json",
                mediaType: "application/json",
                included: true,
                bytes: new TextEncoder().encode(reportJson).byteLength,
                sha256: reportHash.hex,
                json: reportPayload,
            },
            ...flattenedArtifacts,
        ],
        transforms: [
            {
                id: "incident-assembly",
                type: "incident",
                label: "Incident workflow assembly",
                summary: `${mode.label} assembled ${preparedArtifacts.length} prepared artifact${preparedArtifacts.length === 1 ? "" : "s"} into one receiver-facing package.`,
                report: [
                    `mode:${mode.id}`,
                    `prepared-artifacts:${preparedArtifacts.length}`,
                    `recipient-scope:${recipientScope ? "recorded" : "omitted"}`,
                    `notes-template:${input.notesTemplateUsed ? "stock-headings" : "customized-or-omitted"}`,
                ],
                metadata: {
                    caseReference,
                    recipientScope,
                },
            },
            ...flattenedTransforms,
        ],
        warnings,
        limitations,
    });
}
function flattenPreparedArtifacts(preparedArtifacts) {
    return preparedArtifacts.flatMap((entry, entryIndex) => entry.workflowPackage.artifacts.map((artifact, artifactIndex) => ({
        id: buildFlattenedId(entry.id, artifact.id, entryIndex, artifactIndex),
        role: artifact.role,
        label: `${entry.label} · ${artifact.label}`,
        kind: artifact.kind,
        mediaType: artifact.mediaType,
        included: artifact.included,
        bytes: artifact.bytes,
        sha256: artifact.sha256,
        filename: artifact.filename,
        text: artifact.text,
        json: artifact.json,
        base64: artifact.base64,
    })));
}
function flattenPreparedTransforms(preparedArtifacts) {
    return preparedArtifacts.flatMap((entry, entryIndex) => (entry.workflowPackage.transforms ?? []).map((transform, transformIndex) => ({
        id: buildFlattenedId(entry.id, transform.id, entryIndex, transformIndex),
        type: transform.type,
        label: `${entry.label} · ${transform.label}`,
        summary: transform.summary,
        applied: transform.applied ? [...transform.applied] : undefined,
        report: transform.report ? [...transform.report] : undefined,
        metadata: {
            ...(transform.metadata ?? {}),
            incidentArtifactId: entry.id,
            incidentArtifactLabel: entry.label,
            sourceWorkflowType: entry.workflowPackage.workflowType,
        },
    })));
}
function summarizeIncludedArtifacts(entry) {
    const fromReport = entry.workflowPackage.report?.includedArtifacts ?? [];
    if (fromReport.length > 0) {
        return fromReport.map((value) => `${entry.label} · ${value}`);
    }
    return entry.workflowPackage.artifacts
        .filter((artifact) => artifact.included)
        .map((artifact) => `${entry.label} · ${artifact.label}`);
}
function summarizeTransformedArtifacts(entry) {
    const fromReport = entry.workflowPackage.report?.transformedArtifacts ?? [];
    if (fromReport.length > 0) {
        return fromReport.map((value) => `${entry.label} · ${value}`);
    }
    return (entry.workflowPackage.transforms ?? []).map((transform) => `${entry.label} · ${transform.label}`);
}
function summarizePreservedArtifacts(entry) {
    const fromReport = entry.workflowPackage.report?.preservedArtifacts ?? [];
    if (fromReport.length > 0) {
        return fromReport.map((value) => `${entry.label} · ${value}`);
    }
    return entry.workflowPackage.artifacts
        .filter((artifact) => !artifact.included)
        .map((artifact) => `${entry.label} · ${artifact.label}`);
}
function buildFlattenedId(prefix, originalId, entryIndex, itemIndex) {
    const normalized = `${prefix}-${originalId}`
        .toLowerCase()
        .replace(/[^a-z0-9_-]+/gu, "-")
        .replace(/-{2,}/gu, "-")
        .replace(/^-+|-+$/gu, "");
    return (normalized || `incident-${entryIndex + 1}-${itemIndex + 1}`).slice(0, 80);
}
function sanitizeInline(value) {
    if (typeof value !== "string")
        return undefined;
    const normalized = value.trim();
    return normalized || undefined;
}
function sanitizeMultiline(value) {
    if (typeof value !== "string")
        return undefined;
    const normalized = value.trim();
    return normalized || undefined;
}
function uniqueStrings(values) {
    return Array.from(new Set(values.map((value) => value.trim()).filter(Boolean)));
}
