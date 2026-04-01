import { toBase64 } from "./encoding.js";
import { hashBytes, hashText } from "./hash.js";
import { applySanitizeRules, buildRulesState, } from "./sanitizeEngine.js";
import { createWorkflowPackage, } from "./workflowPackage.js";
export const safeSharePresets = {
    "general-safe-share": {
        id: "general-safe-share",
        label: "General safe share",
        description: "Balanced disclosure reduction for routine sharing of text snippets and locally cleanable files.",
        includeSourceReferenceDefault: true,
        defaultApplyMetadataClean: true,
        allowOriginalBinaryPackaging: false,
        sanitizeRules: [
            "maskIp",
            "maskIpv6",
            "maskEmail",
            "maskPhoneIntl",
            "maskIranNationalId",
            "scrubJwt",
            "maskBearer",
            "maskAwsKey",
            "maskAwsSecret",
            "maskGithubToken",
            "maskSlackToken",
            "stripPrivateKeyBlock",
            "stripCookies",
            "maskUser",
            "stripJsonSecrets",
            "maskCard",
            "maskIban",
        ],
        jsonAware: true,
        guidance: [
            "Balanced preset for sharing cleaned text or locally sanitized files.",
            "Keeps the package unsigned unless you add an outer NULLID:ENC:1 envelope at export.",
        ],
        limitations: [
            "Review the package before sharing; automated cleaning does not replace human judgment.",
            "If a file cannot be cleaned locally, this preset exports report data instead of raw file bytes.",
        ],
    },
    "support-ticket": {
        id: "support-ticket",
        label: "Support ticket / bug report",
        description: "Removes obvious secrets while keeping enough operational context for debugging.",
        includeSourceReferenceDefault: true,
        defaultApplyMetadataClean: true,
        allowOriginalBinaryPackaging: false,
        sanitizeRules: [
            "maskIp",
            "maskIpv6",
            "maskEmail",
            "maskPhoneIntl",
            "maskIranNationalId",
            "scrubJwt",
            "maskBearer",
            "maskAwsKey",
            "maskAwsSecret",
            "maskGithubToken",
            "maskSlackToken",
            "stripPrivateKeyBlock",
            "stripCookies",
            "maskUser",
            "stripJsonSecrets",
        ],
        jsonAware: true,
        guidance: [
            "Keeps timestamps and some context so the receiver can still debug.",
            "Best for log snippets, stack traces, and screenshots or PDFs that need metadata cleanup first.",
        ],
        limitations: [
            "Operational context is preserved where possible, so review the output for environment-specific clues.",
            "This preset does not prove sender identity or independent authenticity.",
        ],
    },
    "external-minimum": {
        id: "external-minimum",
        label: "External share / minimum disclosure",
        description: "Aggressively reduces context and avoids packaging original references by default.",
        includeSourceReferenceDefault: false,
        defaultApplyMetadataClean: true,
        allowOriginalBinaryPackaging: false,
        sanitizeRules: [
            "maskIp",
            "maskIpv6",
            "maskEmail",
            "maskPhoneIntl",
            "maskIranNationalId",
            "scrubJwt",
            "maskBearer",
            "maskAwsKey",
            "maskAwsSecret",
            "maskGithubToken",
            "maskSlackToken",
            "stripPrivateKeyBlock",
            "stripCookies",
            "dropUA",
            "normalizeTs",
            "maskUser",
            "stripJsonSecrets",
            "maskCard",
            "maskIban",
        ],
        jsonAware: true,
        guidance: [
            "Use this when the receiver needs the least possible amount of original context.",
            "When file cleanup is unavailable, this preset exports a report-only package instead of raw file bytes.",
        ],
        limitations: [
            "Aggressive reduction may remove debugging context or chronology that an internal receiver would want.",
            "Hashes and manifests do not make the package signed or identity-bearing.",
        ],
    },
    "internal-investigation": {
        id: "internal-investigation",
        label: "Internal investigation package",
        description: "Preserves responder context for internal analysis while still scrubbing obvious secrets and tokens.",
        includeSourceReferenceDefault: true,
        defaultApplyMetadataClean: true,
        allowOriginalBinaryPackaging: true,
        sanitizeRules: [
            "maskIp",
            "maskIpv6",
            "maskEmail",
            "maskPhoneIntl",
            "maskIranNationalId",
            "scrubJwt",
            "maskBearer",
            "maskAwsKey",
            "maskAwsSecret",
            "maskGithubToken",
            "maskSlackToken",
            "stripPrivateKeyBlock",
            "stripCookies",
            "maskUser",
            "stripJsonSecrets",
            "maskCard",
            "maskIban",
        ],
        jsonAware: true,
        guidance: [
            "Designed for internal responders who need context, chronology, and attached notes without losing obvious secret hygiene.",
            "Original binaries can be preserved when needed, with explicit report metadata describing what stayed intact.",
        ],
        limitations: [
            "Internal investigation packages can still contain operationally sensitive context; review recipient scope before sharing.",
            "This preset improves packaging discipline, not evidence-chain or identity guarantees.",
        ],
    },
    "incident-handoff": {
        id: "incident-handoff",
        label: "Incident artifact handoff",
        description: "Preserves enough context for another responder while still scrubbing obvious secrets.",
        includeSourceReferenceDefault: true,
        defaultApplyMetadataClean: true,
        allowOriginalBinaryPackaging: true,
        sanitizeRules: [
            "maskIp",
            "maskIpv6",
            "maskEmail",
            "maskPhoneIntl",
            "maskIranNationalId",
            "scrubJwt",
            "maskBearer",
            "maskAwsKey",
            "maskAwsSecret",
            "maskGithubToken",
            "maskSlackToken",
            "stripPrivateKeyBlock",
            "stripCookies",
            "maskUser",
            "stripJsonSecrets",
            "maskCard",
            "maskIban",
        ],
        jsonAware: true,
        guidance: [
            "Adds hashes, transform summaries, and receiver-facing warnings for another responder.",
            "If local file cleanup is unavailable, the original binary can still be packaged with explicit warnings.",
        ],
        limitations: [
            "This is a handoff package, not a full incident case workflow or evidence chain-of-custody system.",
            "Original binary inclusion can preserve residual metadata or context; review before wider sharing.",
        ],
    },
    "evidence-archive": {
        id: "evidence-archive",
        label: "Evidence archive / preserve context",
        description: "Preserves context more conservatively and allows original file packaging when needed.",
        includeSourceReferenceDefault: true,
        defaultApplyMetadataClean: false,
        allowOriginalBinaryPackaging: true,
        sanitizeRules: [
            "maskIp",
            "maskIpv6",
            "maskEmail",
            "maskPhoneIntl",
            "maskIranNationalId",
            "scrubJwt",
            "maskBearer",
            "maskAwsKey",
            "maskAwsSecret",
            "maskGithubToken",
            "maskSlackToken",
            "stripPrivateKeyBlock",
            "stripCookies",
            "stripJsonSecrets",
            "maskCard",
            "maskIban",
        ],
        jsonAware: true,
        guidance: [
            "Use when preserving context matters more than aggressive reduction.",
            "Local cleanup is optional here; if you package the original binary, NullID makes that explicit in warnings and transforms.",
        ],
        limitations: [
            "Preserving more context can preserve more residual sensitivity.",
            "This preset is not a legal/forensic chain-of-custody guarantee.",
        ],
    },
};
export const safeSharePresetIds = Object.keys(safeSharePresets);
export function getSafeSharePreset(id) {
    return safeSharePresets[id] ?? safeSharePresets["general-safe-share"];
}
export function buildSafeShareSanitizeConfig(presetId, policyPack) {
    if (policyPack) {
        return {
            rulesState: { ...policyPack.config.rulesState },
            jsonAware: policyPack.config.jsonAware,
            customRules: [...policyPack.config.customRules],
        };
    }
    const preset = getSafeSharePreset(presetId);
    return {
        rulesState: buildRulesState(preset.sanitizeRules),
        jsonAware: preset.jsonAware,
        customRules: [],
    };
}
export function classifyTextForSafeShare(input) {
    const trimmed = input.trim();
    if (!trimmed)
        return "freeform-text";
    if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
        try {
            JSON.parse(trimmed);
            return "json-text";
        }
        catch {
            // Continue to log/text heuristics.
        }
    }
    if (/(?:\b\d{1,3}(?:\.\d{1,3}){3}\b|\buser=|\bcookie=|\btoken=|\[[0-9]{1,2}\/[A-Za-z]{3}\/[0-9]{4})/i.test(trimmed)) {
        return "structured-log";
    }
    return "freeform-text";
}
export function classifyMetadataAnalysisForSafeShare(analysis) {
    if (analysis.kind === "image")
        return "image";
    if (analysis.format === "pdf")
        return "pdf";
    if (analysis.format === "docx" || analysis.format === "xlsx" || analysis.format === "pptx")
        return "office-document";
    if (analysis.kind === "video")
        return "video";
    if (analysis.kind === "archive")
        return "archive";
    return "unknown-file";
}
export function summarizeSanitizeFindings(report) {
    return report
        .map((line) => {
        const match = line.match(/^(.*?):\s*(\d+)$/);
        if (!match)
            return null;
        return {
            label: match[1],
            count: Number(match[2]),
        };
    })
        .filter((entry) => Boolean(entry))
        .sort((a, b) => b.count - a.count);
}
export async function createSafeShareTextWorkflowPackage(input) {
    const preset = getSafeSharePreset(input.presetId);
    const policy = input.policyOverride ?? buildSafeShareSanitizeConfig(input.presetId, input.policyPack ?? null);
    const sanitize = applySanitizeRules(input.inputText, policy.rulesState, policy.customRules, policy.jsonAware);
    const findings = summarizeSanitizeFindings(sanitize.report);
    const classification = classifyTextForSafeShare(input.inputText);
    const includeSourceReference = input.includeSourceReference ?? preset.includeSourceReferenceDefault;
    const [inputHash, outputHash] = await Promise.all([
        hashText(input.inputText, "SHA-256"),
        hashText(sanitize.output, "SHA-256"),
    ]);
    const assistantReport = {
        mode: "text",
        workflowPreset: preset.id,
        classification,
        findings,
        linesAffected: sanitize.linesAffected,
        appliedRules: sanitize.applied,
        protectAtExport: Boolean(input.protectAtExport),
    };
    const assistantReportHash = await hashText(JSON.stringify(assistantReport), "SHA-256");
    const warnings = [
        ...(sanitize.applied.length === 0 ? ["No sanitize rules triggered; review the output manually before sharing."] : []),
        ...preset.guidance,
        "Unsigned package. Sender identity is not asserted.",
        "SHA-256 manifest entries help detect changes to included artifacts, but they are not a signature.",
    ];
    const limitations = [
        ...preset.limitations,
        ...(input.protectAtExport
            ? ["NULLID:ENC:1 protection is applied to the exported file, not as a sender signature inside the package."]
            : ["Without an outer NULLID:ENC:1 envelope, the exported package remains readable JSON on disk."]),
    ];
    const includedLabels = [
        ...(includeSourceReference ? [input.sourceLabel ? `Original input reference (${input.sourceLabel})` : "Original input reference"] : []),
        "Shared output",
        "Sanitize policy snapshot",
        "Safe Share report",
    ];
    const transforms = [
        {
            id: "safe-share-review",
            type: "safe-share",
            label: "Safe Share review",
            summary: `${preset.label} preset prepared a text safe-share package.`,
            report: [
                `classification:${classification}`,
                `findings:${findings.length}`,
                `source-reference:${includeSourceReference ? "included" : "omitted"}`,
            ],
            metadata: {
                workflowPreset: preset.id,
            },
        },
        {
            id: "sanitize-transform",
            type: "sanitize",
            label: "Sanitize transformation",
            summary: `Sanitized output ready (${sanitize.linesAffected} line${sanitize.linesAffected === 1 ? "" : "s"} changed).`,
            applied: sanitize.applied,
            report: sanitize.report,
            metadata: {
                classification,
            },
        },
    ];
    return createWorkflowPackage({
        packageType: "bundle",
        workflowType: "safe-share-assistant",
        producedAt: new Date().toISOString(),
        producer: input.producer,
        workflowPreset: {
            id: preset.id,
            label: preset.label,
            summary: preset.description,
        },
        summary: {
            title: `${preset.label} package`,
            description: "Safe Share Assistant export for text-based content.",
            highlights: [
                `Share class: ${formatShareClassLabel(classification)}`,
                `Applied rules: ${sanitize.applied.length}`,
                `Protection: ${input.protectAtExport ? "NULLID:ENC:1 at export" : "none"}`,
            ],
        },
        report: {
            purpose: `Prepare text content for ${preset.label.toLowerCase()}.`,
            includedArtifacts: includedLabels,
            transformedArtifacts: ["Sanitize review", "Sanitize transformation"],
            preservedArtifacts: includeSourceReference ? ["Original input reference only"] : [],
            receiverCanVerify: [
                "Workflow package structure and schema version.",
                "SHA-256 manifest entries for included inline artifacts and references.",
                ...(input.protectAtExport ? ["If wrapped at export, the outer NULLID:ENC:1 envelope can be decrypted and integrity-checked with the passphrase."] : []),
            ],
            receiverCannotVerify: [
                "Sender identity or authorship.",
                "Whether omitted context outside the included artifacts was complete.",
            ],
        },
        artifacts: [
            ...(includeSourceReference
                ? [{
                        id: "source-input",
                        role: "input",
                        label: input.sourceLabel ? `Original input (${input.sourceLabel})` : "Original input",
                        kind: "reference",
                        mediaType: "text/plain;charset=utf-8",
                        included: false,
                        bytes: new TextEncoder().encode(input.inputText).byteLength,
                        sha256: inputHash.hex,
                        filename: input.sourceLabel,
                    }]
                : []),
            {
                id: "shared-output",
                role: "output",
                label: "Shared output",
                kind: "text",
                mediaType: "text/plain;charset=utf-8",
                included: true,
                bytes: new TextEncoder().encode(sanitize.output).byteLength,
                sha256: outputHash.hex,
                text: sanitize.output,
            },
            {
                id: "sanitize-policy",
                role: "policy",
                label: "Sanitize policy snapshot",
                kind: "json",
                mediaType: "application/json",
                included: true,
                bytes: new TextEncoder().encode(JSON.stringify(policy)).byteLength,
                sha256: (await hashText(JSON.stringify(policy), "SHA-256")).hex,
                json: policy,
            },
            {
                id: "safe-share-report",
                role: "report",
                label: "Safe Share report",
                kind: "json",
                mediaType: "application/json",
                included: true,
                bytes: new TextEncoder().encode(JSON.stringify(assistantReport)).byteLength,
                sha256: assistantReportHash.hex,
                json: assistantReport,
            },
        ],
        policy: {
            type: "sanitize",
            config: policy,
            preset: preset.id,
            packName: input.policyPack?.name,
            baseline: null,
        },
        transforms,
        warnings,
        limitations,
    });
}
export async function createSafeShareFileWorkflowPackage(input) {
    const preset = getSafeSharePreset(input.presetId);
    const classification = classifyMetadataAnalysisForSafeShare(input.analysis);
    const includeSourceReference = input.includeSourceReference ?? preset.includeSourceReferenceDefault;
    const sourceHash = await hashBytes(input.sourceBytes, "SHA-256");
    const shouldUseCleaned = Boolean(input.applyMetadataClean) && Boolean(input.cleanedBytes?.length);
    const includeOriginalBinary = !shouldUseCleaned && preset.allowOriginalBinaryPackaging;
    const sharedBytes = shouldUseCleaned ? input.cleanedBytes : includeOriginalBinary ? input.sourceBytes : null;
    const sharedMediaType = shouldUseCleaned ? (input.cleanedMediaType || input.fileMediaType) : includeOriginalBinary ? input.fileMediaType : null;
    const sharedLabel = shouldUseCleaned
        ? (input.cleanedLabel || "Metadata-cleaned file")
        : includeOriginalBinary
            ? "Original file payload"
            : null;
    const sharedHash = sharedBytes ? await hashBytes(sharedBytes, "SHA-256") : null;
    const analysisReport = {
        mode: "file",
        workflowPreset: preset.id,
        classification,
        format: input.analysis.format,
        risk: input.analysis.risk,
        sanitizer: resolveSanitizerLabel(input.analysis.recommendedSanitizer),
        signals: input.analysis.signals,
        guidance: input.analysis.guidance,
        commandHint: input.analysis.commandHint,
        protectAtExport: Boolean(input.protectAtExport),
        binaryIncluded: Boolean(sharedBytes),
        cleaned: shouldUseCleaned,
    };
    const analysisHash = await hashText(JSON.stringify(analysisReport), "SHA-256");
    const warnings = [
        ...(shouldUseCleaned ? [] : input.analysis.signals.map((signal) => `${signal.label}: ${signal.detail}`)),
        ...preset.guidance,
        ...(includeOriginalBinary ? ["Original file bytes are included because this preset allows preserving context when local cleanup is unavailable or disabled."] : []),
        ...(!sharedBytes ? ["No file payload was packaged; this export contains analysis/report data plus source reference only."] : []),
        "Unsigned package. Sender identity is not asserted.",
        "SHA-256 manifest entries help detect changes to included artifacts, but they are not a signature.",
    ];
    const limitations = [
        ...preset.limitations,
        ...(input.analysis.commandHint && !shouldUseCleaned
            ? ["NullID could not fully clean this file locally; external tooling may still be required before broader sharing."]
            : []),
        ...(input.protectAtExport
            ? ["NULLID:ENC:1 protection is applied to the exported file, not as a sender signature inside the package."]
            : ["Without an outer NULLID:ENC:1 envelope, the exported package remains readable JSON on disk."]),
    ];
    const includedLabels = [
        ...(includeSourceReference ? [`Original file reference (${input.fileName})`] : []),
        ...(sharedLabel ? [sharedLabel] : []),
        "Safe Share report",
    ];
    const preservedArtifacts = [
        ...(includeOriginalBinary ? [`Original file payload (${input.fileName})`] : []),
        ...(includeSourceReference ? [`Original file reference (${input.fileName})`] : []),
    ];
    const transforms = [
        {
            id: "safe-share-review",
            type: "safe-share",
            label: "Safe Share review",
            summary: `${preset.label} preset prepared a file-oriented safe-share package.`,
            report: [
                `classification:${classification}`,
                `risk:${input.analysis.risk}`,
                `binary-included:${sharedBytes ? "yes" : "no"}`,
            ],
            metadata: {
                workflowPreset: preset.id,
            },
        },
        {
            id: "metadata-analysis",
            type: "metadata",
            label: "Metadata analysis",
            summary: `${input.analysis.format} analyzed locally with ${input.analysis.signals.length} metadata signal${input.analysis.signals.length === 1 ? "" : "s"}.`,
            report: input.analysis.signals.map((signal) => `${signal.label}: ${signal.detail}`),
            metadata: {
                recommendedSanitizer: input.analysis.recommendedSanitizer,
                risk: input.analysis.risk,
            },
        },
        ...(shouldUseCleaned
            ? [{
                    id: "metadata-clean",
                    type: "metadata-clean",
                    label: "Metadata cleanup",
                    summary: "Local cleanup was applied before packaging the shareable file artifact.",
                    metadata: {
                        outputMediaType: input.cleanedMediaType || input.fileMediaType,
                    },
                }]
            : []),
    ];
    return createWorkflowPackage({
        packageType: "bundle",
        workflowType: "safe-share-assistant",
        producedAt: new Date().toISOString(),
        producer: input.producer,
        workflowPreset: {
            id: preset.id,
            label: preset.label,
            summary: preset.description,
        },
        summary: {
            title: `${preset.label} package`,
            description: "Safe Share Assistant export for file-based content.",
            highlights: [
                `Share class: ${formatShareClassLabel(classification)}`,
                `Metadata risk: ${input.analysis.risk}`,
                `Protection: ${input.protectAtExport ? "NULLID:ENC:1 at export" : "none"}`,
            ],
        },
        report: {
            purpose: `Prepare a file artifact for ${preset.label.toLowerCase()}.`,
            includedArtifacts: includedLabels,
            transformedArtifacts: [
                "Safe Share review",
                "Metadata analysis",
                ...(shouldUseCleaned ? ["Metadata cleanup"] : []),
            ],
            preservedArtifacts,
            receiverCanVerify: [
                "Workflow package structure and schema version.",
                "SHA-256 manifest entries for included inline artifacts and references.",
                ...(input.protectAtExport ? ["If wrapped at export, the outer NULLID:ENC:1 envelope can be decrypted and integrity-checked with the passphrase."] : []),
            ],
            receiverCannotVerify: [
                "Sender identity or authorship.",
                ...(sharedBytes ? [] : ["The original file bytes are not included in this package."]),
                ...(input.analysis.commandHint && !shouldUseCleaned ? ["External cleanup steps suggested by command hints are not proven by this package."] : []),
            ],
        },
        artifacts: [
            ...(includeSourceReference
                ? [{
                        id: "source-file",
                        role: "input",
                        label: `Original file (${input.fileName})`,
                        kind: "reference",
                        mediaType: input.fileMediaType || "application/octet-stream",
                        included: false,
                        bytes: input.sourceBytes.length,
                        sha256: sourceHash.hex,
                        filename: input.fileName,
                    }]
                : []),
            ...(sharedBytes && sharedMediaType && sharedLabel && sharedHash
                ? [{
                        id: shouldUseCleaned ? "shared-clean-file" : "shared-file",
                        role: "output",
                        label: sharedLabel,
                        kind: "binary",
                        mediaType: sharedMediaType || "application/octet-stream",
                        included: true,
                        bytes: sharedBytes.length,
                        sha256: sharedHash.hex,
                        filename: shouldUseCleaned ? appendCleanSuffix(input.fileName, sharedMediaType) : input.fileName,
                        base64: toBase64(sharedBytes),
                    }]
                : []),
            {
                id: "safe-share-report",
                role: "report",
                label: "Safe Share report",
                kind: "json",
                mediaType: "application/json",
                included: true,
                bytes: new TextEncoder().encode(JSON.stringify(analysisReport)).byteLength,
                sha256: analysisHash.hex,
                json: analysisReport,
            },
        ],
        transforms,
        warnings,
        limitations,
    });
}
function appendCleanSuffix(fileName, mediaType) {
    const dot = fileName.lastIndexOf(".");
    const base = dot > 0 ? fileName.slice(0, dot) : fileName;
    const ext = dot > 0 ? fileName.slice(dot + 1) : extensionFromMediaType(mediaType);
    return `${base}-clean.${ext}`;
}
function extensionFromMediaType(mediaType) {
    if (mediaType.includes("pdf"))
        return "pdf";
    if (mediaType.includes("png"))
        return "png";
    if (mediaType.includes("webp"))
        return "webp";
    if (mediaType.includes("avif"))
        return "avif";
    return "bin";
}
function resolveSanitizerLabel(value) {
    if (value === "browser-image")
        return "browser image clean";
    if (value === "browser-pdf")
        return "browser pdf clean";
    if (value === "mat2")
        return "mat2 / external clean";
    return "analysis only";
}
export function formatShareClassLabel(value) {
    if (value === "structured-log")
        return "structured log";
    if (value === "json-text")
        return "JSON text";
    if (value === "freeform-text")
        return "freeform text";
    if (value === "office-document")
        return "office document";
    if (value === "unknown-file")
        return "unknown file";
    return value;
}
