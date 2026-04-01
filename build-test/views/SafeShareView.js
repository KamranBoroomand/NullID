import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import "./styles.css";
import { Chip } from "../components/Chip";
import { useToast } from "../components/ToastHost";
import { usePersistentState } from "../hooks/usePersistentState";
import { useI18n } from "../i18n";
import { encryptText } from "../utils/cryptoEnvelope.js";
import { probeCanvasEncodeSupport } from "../utils/imageFormats.js";
import { analyzeMetadataFromBuffer } from "../utils/metadataAdvanced.js";
import { prepareLocalMetadataCleanup } from "../utils/localArtifactPreparation.js";
import { applySanitizeRules } from "../utils/sanitizeEngine.js";
import { buildSafeShareSanitizeConfig, classifyTextForSafeShare, createSafeShareFileWorkflowPackage, createSafeShareTextWorkflowPackage, formatShareClassLabel, getSafeSharePreset, safeSharePresetIds, summarizeSanitizeFindings, } from "../utils/safeShareAssistant.js";
const textInputAccept = [
    ".txt",
    ".log",
    ".json",
    ".ndjson",
    ".csv",
    ".xml",
    ".yaml",
    ".yml",
    "text/plain",
    "application/json",
].join(",");
export function SafeShareView({ onOpenGuide }) {
    const { push } = useToast();
    const { t, tr, formatNumber } = useI18n();
    const [mode, setMode] = usePersistentState("nullid:share:mode", "text");
    const [presetId, setPresetId] = usePersistentState("nullid:share:preset", "general-safe-share");
    const [policyPacks] = usePersistentState("nullid:sanitize:policy-packs", []);
    const [selectedPolicyId, setSelectedPolicyId] = usePersistentState("nullid:share:policy-id", "");
    const [textInput, setTextInput] = usePersistentState("nullid:share:text-input", "");
    const [textSourceLabel, setTextSourceLabel] = usePersistentState("nullid:share:text-source-label", "");
    const [includeSourceReference, setIncludeSourceReference] = usePersistentState("nullid:share:include-source-reference", true);
    const [applyMetadataClean, setApplyMetadataClean] = usePersistentState("nullid:share:apply-metadata-clean", true);
    const [protectAtExport, setProtectAtExport] = usePersistentState("nullid:share:protect-export", false);
    const [exportPassphrase, setExportPassphrase] = useState("");
    const [shareFile, setShareFile] = useState(null);
    const [sourceBytes, setSourceBytes] = useState(null);
    const [analysis, setAnalysis] = useState(null);
    const [cleanedBytes, setCleanedBytes] = useState(null);
    const [cleanedMediaType, setCleanedMediaType] = useState("");
    const [cleanedLabel, setCleanedLabel] = useState("");
    const [cleanActions, setCleanActions] = useState([]);
    const [fileMessage, setFileMessage] = useState("load a file to analyze local metadata and packaging options");
    const [isAnalyzingFile, setIsAnalyzingFile] = useState(false);
    const [isPreparingPreview, setIsPreparingPreview] = useState(false);
    const [previewPackage, setPreviewPackage] = useState(null);
    const [previewError, setPreviewError] = useState(null);
    const [isExporting, setIsExporting] = useState(false);
    const [outputSupport, setOutputSupport] = useState(null);
    const textFileRef = useRef(null);
    const shareFileRef = useRef(null);
    const preset = getSafeSharePreset(presetId);
    const selectedPolicy = useMemo(() => policyPacks.find((pack) => pack.id === selectedPolicyId) ?? null, [policyPacks, selectedPolicyId]);
    const textPolicy = useMemo(() => buildSafeShareSanitizeConfig(presetId, selectedPolicy), [presetId, selectedPolicy]);
    const textPreview = useMemo(() => applySanitizeRules(textInput, textPolicy.rulesState, textPolicy.customRules, textPolicy.jsonAware), [textInput, textPolicy]);
    const textFindings = useMemo(() => summarizeSanitizeFindings(textPreview.report).slice(0, 8), [textPreview.report]);
    const shareClass = useMemo(() => (mode === "text" ? formatShareClassLabel(classifyTextForSafeShare(textInput)) : analysis ? formatShareClassLabelForFile(analysis) : "pending input"), [analysis, mode, textInput]);
    const producer = useMemo(() => ({
        app: "NullID",
        surface: "web",
        module: "share",
        buildId: typeof import.meta.env.VITE_BUILD_ID === "string" && import.meta.env.VITE_BUILD_ID.trim() ? import.meta.env.VITE_BUILD_ID.trim() : null,
    }), []);
    useEffect(() => {
        setIncludeSourceReference(preset.includeSourceReferenceDefault);
        setApplyMetadataClean(preset.defaultApplyMetadataClean);
    }, [preset.defaultApplyMetadataClean, preset.includeSourceReferenceDefault, preset.id, setApplyMetadataClean, setIncludeSourceReference]);
    useEffect(() => {
        let cancelled = false;
        void (async () => {
            try {
                const support = await probeCanvasEncodeSupport();
                if (!cancelled) {
                    setOutputSupport(support);
                }
            }
            catch (error) {
                console.error("safe-share output support failed", error);
            }
        })();
        return () => {
            cancelled = true;
        };
    }, []);
    const refreshFileCleanup = useCallback(async (file, nextAnalysis) => {
        setCleanedBytes(null);
        setCleanedMediaType("");
        setCleanedLabel("");
        setCleanActions([]);
        try {
            const cleaned = await prepareLocalMetadataCleanup(file, nextAnalysis, {
                applyMetadataClean,
                outputSupport,
            });
            setCleanedBytes(cleaned.cleanedBytes ?? null);
            setCleanedMediaType(cleaned.cleanedMediaType ?? "");
            setCleanedLabel(cleaned.cleanedLabel ?? "");
            setCleanActions(cleaned.cleanActions);
            setFileMessage(cleaned.message);
        }
        catch (error) {
            console.error(error);
            setFileMessage(error instanceof Error ? error.message : "local cleanup failed");
        }
    }, [applyMetadataClean, outputSupport]);
    const handleTextFile = useCallback(async (file) => {
        if (!file)
            return;
        try {
            setMode("text");
            setTextInput(await file.text());
            setTextSourceLabel(file.name);
            push(`loaded ${file.name}`, "accent");
        }
        catch (error) {
            console.error(error);
            push("text file load failed", "danger");
        }
    }, [push, setMode, setTextInput, setTextSourceLabel]);
    const handleShareFile = useCallback(async (file) => {
        if (!file)
            return;
        setMode("file");
        setShareFile(file);
        setAnalysis(null);
        setSourceBytes(null);
        setPreviewPackage(null);
        setPreviewError(null);
        setIsAnalyzingFile(true);
        try {
            const bytes = new Uint8Array(await file.arrayBuffer());
            const nextAnalysis = analyzeMetadataFromBuffer(file.type || "", bytes, file.name);
            setSourceBytes(bytes);
            setAnalysis(nextAnalysis);
            await refreshFileCleanup(file, nextAnalysis);
            push(`loaded ${file.name}`, "accent");
        }
        catch (error) {
            console.error(error);
            setFileMessage(error instanceof Error ? error.message : "file analysis failed");
            push("file analysis failed", "danger");
        }
        finally {
            setIsAnalyzingFile(false);
        }
    }, [push, refreshFileCleanup, setMode]);
    const buildPreviewPackage = useCallback(async () => {
        if (mode === "text") {
            if (!textInput.trim())
                return null;
            return createSafeShareTextWorkflowPackage({
                presetId,
                producer,
                inputText: textInput,
                sourceLabel: textSourceLabel.trim() || undefined,
                includeSourceReference,
                policyPack: selectedPolicy,
                protectAtExport,
            });
        }
        if (!shareFile || !sourceBytes || !analysis)
            return null;
        return createSafeShareFileWorkflowPackage({
            presetId,
            producer,
            fileName: shareFile.name,
            fileMediaType: shareFile.type || "application/octet-stream",
            sourceBytes,
            analysis,
            cleanedBytes: cleanedBytes ?? undefined,
            cleanedMediaType: cleanedMediaType || undefined,
            cleanedLabel: cleanedLabel || undefined,
            applyMetadataClean,
            includeSourceReference,
            protectAtExport,
        });
    }, [
        analysis,
        applyMetadataClean,
        cleanedBytes,
        cleanedLabel,
        cleanedMediaType,
        includeSourceReference,
        mode,
        presetId,
        producer,
        protectAtExport,
        selectedPolicy,
        shareFile,
        sourceBytes,
        textInput,
        textSourceLabel,
    ]);
    useEffect(() => {
        if (mode !== "file" || !shareFile || !analysis)
            return;
        void refreshFileCleanup(shareFile, analysis);
    }, [analysis, applyMetadataClean, mode, outputSupport, refreshFileCleanup, shareFile]);
    useEffect(() => {
        let cancelled = false;
        setIsPreparingPreview(true);
        void (async () => {
            try {
                const next = await buildPreviewPackage();
                if (cancelled)
                    return;
                setPreviewPackage(next);
                setPreviewError(null);
            }
            catch (error) {
                if (cancelled)
                    return;
                console.error(error);
                setPreviewPackage(null);
                setPreviewError(error instanceof Error ? error.message : "preview preparation failed");
            }
            finally {
                if (!cancelled) {
                    setIsPreparingPreview(false);
                }
            }
        })();
        return () => {
            cancelled = true;
        };
    }, [buildPreviewPackage]);
    const exportPackage = async () => {
        setIsExporting(true);
        try {
            const nextPackage = previewPackage ?? (await buildPreviewPackage());
            if (!nextPackage) {
                push("nothing ready to export", "danger");
                return;
            }
            if (protectAtExport && !exportPassphrase.trim()) {
                push("export passphrase required", "danger");
                return;
            }
            const json = JSON.stringify(nextPackage, null, 2);
            const fileName = buildSafeShareExportFileName(mode, presetId, textSourceLabel, shareFile?.name);
            if (protectAtExport) {
                const envelope = await encryptText(exportPassphrase.trim(), json);
                downloadBlob(new Blob([envelope], { type: "text/plain;charset=utf-8" }), `${fileName}.nullid`);
                push("protected safe-share package exported", "accent");
                return;
            }
            downloadBlob(new Blob([json], { type: "application/json" }), `${fileName}.json`);
            push("safe-share package exported", "accent");
        }
        catch (error) {
            console.error(error);
            push("safe-share export failed", "danger");
        }
        finally {
            setIsExporting(false);
        }
    };
    const resetFile = () => {
        setShareFile(null);
        setSourceBytes(null);
        setAnalysis(null);
        setCleanedBytes(null);
        setCleanedMediaType("");
        setCleanedLabel("");
        setCleanActions([]);
        setFileMessage("load a file to analyze local metadata and packaging options");
        setPreviewPackage(null);
        setPreviewError(null);
    };
    const resetText = () => {
        setTextInput("");
        setTextSourceLabel("");
        setPreviewPackage(null);
        setPreviewError(null);
    };
    return (_jsxs("div", { className: "workspace-scroll", children: [_jsx("div", { className: "guide-link", children: _jsx("button", { type: "button", className: "guide-link-button", onClick: () => onOpenGuide?.("share"), children: t("guide.link") }) }), _jsxs("section", { className: "panel", "aria-label": tr("Safe Share overview"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("Safe Share Assistant") }), _jsx("span", { className: "panel-subtext", children: tr("guided local export") })] }), _jsx("div", { className: "microcopy", children: tr("Prepare text snippets or local files for sharing with reviewable transforms, honest trust labels, and receiver-friendly workflow packages.") }), _jsxs("div", { className: "controls-row", style: { alignItems: "center" }, children: [_jsxs("div", { className: "pill-buttons", role: "group", "aria-label": tr("Safe share mode"), children: [_jsx("button", { type: "button", className: mode === "text" ? "active" : "", onClick: () => setMode("text"), children: tr("text") }), _jsx("button", { type: "button", className: mode === "file" ? "active" : "", onClick: () => setMode("file"), children: tr("file") })] }), _jsx(Chip, { label: preset.label, tone: "accent" }), _jsx(Chip, { label: tr(shareClass), tone: "muted" }), previewPackage ? _jsx(Chip, { label: protectAtExport ? tr("NULLID:ENC:1 at export") : tr("unsigned package"), tone: protectAtExport ? "accent" : "muted" }) : null] })] }), _jsxs("div", { className: "grid-two", children: [_jsxs("section", { className: "panel", "aria-label": tr("Safe share input"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("1. Choose input") }), _jsx("span", { className: "panel-subtext", children: mode === "text" ? tr("text and logs") : tr("file artifacts") })] }), mode === "text" ? (_jsxs(_Fragment, { children: [_jsx("textarea", { className: "textarea", "aria-label": tr("Safe share input text"), placeholder: tr("Paste logs, snippets, or text you want to prepare for safe sharing"), value: textInput, onChange: (event) => setTextInput(event.target.value) }), _jsx("input", { className: "input", "aria-label": tr("Safe share source label"), placeholder: tr("Optional source label (for example incident.log or support-snippet.txt)"), value: textSourceLabel, onChange: (event) => setTextSourceLabel(event.target.value) }), _jsxs("div", { className: "controls-row", children: [_jsx("button", { className: "button", type: "button", onClick: () => textFileRef.current?.click(), children: tr("load text file") }), _jsx("button", { className: "button", type: "button", onClick: resetText, children: tr("clear") }), _jsx("input", { ref: textFileRef, hidden: true, type: "file", "aria-label": tr("Safe share text file"), accept: textInputAccept, onChange: (event) => void handleTextFile(event.target.files?.[0] ?? null) })] })] })) : (_jsxs(_Fragment, { children: [_jsx("div", { className: "dropzone", role: "button", tabIndex: 0, "aria-label": tr("Choose file for safe sharing"), onClick: () => shareFileRef.current?.click(), onKeyDown: (event) => {
                                            if (event.key === "Enter" || event.key === " ") {
                                                event.preventDefault();
                                                shareFileRef.current?.click();
                                            }
                                        }, children: shareFile ? `${shareFile.name} · ${formatNumber(shareFile.size)} bytes` : tr("Choose a file to analyze locally before packaging") }), _jsx("div", { className: "microcopy", children: fileMessage }), _jsxs("div", { className: "controls-row", children: [_jsx("button", { className: "button", type: "button", onClick: () => shareFileRef.current?.click(), children: tr("load file") }), _jsx("button", { className: "button", type: "button", onClick: resetFile, children: tr("clear") }), _jsx("input", { ref: shareFileRef, hidden: true, type: "file", "aria-label": tr("Safe share file"), onChange: (event) => void handleShareFile(event.target.files?.[0] ?? null) })] })] }))] }), _jsxs("section", { className: "panel", "aria-label": tr("Safe share preset"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("2. Choose workflow mode") }), _jsx("span", { className: "panel-subtext", children: tr("preset and context") })] }), _jsx("div", { className: "pill-buttons", role: "group", "aria-label": tr("Safe share preset chooser"), children: safeSharePresetIds.map((id) => (_jsx("button", { type: "button", className: presetId === id ? "active" : "", onClick: () => setPresetId(id), children: getSafeSharePreset(id).label }, id))) }), _jsx("div", { className: "microcopy", children: preset.description }), _jsx("ul", { className: "microcopy", children: preset.guidance.map((line) => (_jsx("li", { children: tr(line) }, line))) }), mode === "text" ? (_jsxs("label", { className: "microcopy", htmlFor: "safe-share-policy-pack", children: [tr("Optional sanitize policy pack"), _jsxs("select", { id: "safe-share-policy-pack", className: "select", "aria-label": tr("Safe share policy pack"), value: selectedPolicyId, onChange: (event) => setSelectedPolicyId(event.target.value), children: [_jsx("option", { value: "", children: tr("Use the workflow preset only") }), policyPacks.map((pack) => (_jsx("option", { value: pack.id, children: pack.name }, pack.id)))] })] })) : null] })] }), _jsxs("div", { className: "grid-two", children: [_jsxs("section", { className: "panel", "aria-label": tr("Findings and transforms"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("3. Review findings") }), _jsx("span", { className: "panel-subtext", children: mode === "text" ? tr("sanitize results") : tr("metadata signals") })] }), mode === "text" ? (_jsxs(_Fragment, { children: [_jsxs("div", { className: "controls-row", style: { alignItems: "center" }, children: [_jsx(Chip, { label: `${formatNumber(textPreview.applied.length)} ${tr("rules applied")}`, tone: textPreview.applied.length > 0 ? "accent" : "muted" }), _jsx(Chip, { label: `${formatNumber(textPreview.linesAffected)} ${tr("lines changed")}`, tone: "muted" }), _jsx(Chip, { label: textPolicy.jsonAware ? tr("JSON-aware on") : tr("JSON-aware off"), tone: "muted" })] }), _jsx("ul", { className: "microcopy", children: textFindings.length > 0 ? (textFindings.map((entry) => _jsxs("li", { children: [entry.label, ": ", entry.count] }, `${entry.label}:${entry.count}`))) : (_jsx("li", { children: tr("No sanitize findings were recorded yet.") })) }), _jsx("div", { className: "panel-subtext", children: tr("Prepared output preview") }), _jsx("pre", { className: "log-preview", "aria-label": tr("Safe share output preview"), children: textPreview.output || tr("nothing to preview") })] })) : (_jsxs(_Fragment, { children: [_jsx("div", { className: "controls-row", style: { alignItems: "center" }, children: analysis ? (_jsxs(_Fragment, { children: [_jsx(Chip, { label: `risk: ${analysis.risk}`, tone: analysis.risk === "high" ? "danger" : analysis.risk === "medium" ? "accent" : "muted" }), _jsx(Chip, { label: `${tr("risk")}: ${tr(analysis.risk)}`, tone: analysis.risk === "high" ? "danger" : analysis.risk === "medium" ? "accent" : "muted" }), _jsx(Chip, { label: `${tr("sanitizer")}: ${tr(formatSanitizerLabel(analysis.recommendedSanitizer))}`, tone: "muted" }), _jsx(Chip, { label: shareFile ? `${formatNumber(shareFile.size)} ${tr("bytes")}` : tr("no file"), tone: "muted" })] })) : (_jsx(Chip, { label: isAnalyzingFile ? tr("analyzing...") : tr("waiting for file"), tone: "muted" })) }), _jsx("ul", { className: "microcopy", children: analysis?.signals.length ? analysis.signals.map((signal) => (_jsxs("li", { children: [tr(signal.label), ": ", tr(signal.detail)] }, signal.id))) : (_jsx("li", { children: analysis ? tr("No metadata risk signals were detected in the current scan window.") : tr("Load a file to inspect metadata signals.") })) }), analysis?.guidance.length ? (_jsxs(_Fragment, { children: [_jsx("div", { className: "panel-subtext", children: tr("Guidance") }), _jsx("ul", { className: "microcopy", children: analysis.guidance.map((line) => (_jsx("li", { children: tr(line) }, line))) })] })) : null, cleanActions.length ? (_jsxs(_Fragment, { children: [_jsx("div", { className: "panel-subtext", children: tr("Local cleanup actions") }), _jsx("ul", { className: "microcopy", children: cleanActions.map((line) => (_jsx("li", { children: tr(line) }, line))) })] })) : null, analysis?.commandHint ? _jsx("div", { className: "microcopy", children: analysis.commandHint }) : null] }))] }), _jsxs("section", { className: "panel", "aria-label": tr("Safe share export settings"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("4. Choose packaging") }), _jsx("span", { className: "panel-subtext", children: tr("protection and scope") })] }), _jsxs("label", { className: "microcopy", children: [_jsx("input", { type: "checkbox", checked: includeSourceReference, onChange: (event) => setIncludeSourceReference(event.target.checked), style: { marginRight: "0.45rem" } }), tr("Include a source reference (hash + filename/label, but not the original bytes) when possible")] }), mode === "file" ? (_jsxs("label", { className: "microcopy", children: [_jsx("input", { type: "checkbox", checked: applyMetadataClean, onChange: (event) => setApplyMetadataClean(event.target.checked), style: { marginRight: "0.45rem" } }), tr("Apply local metadata cleanup when this file format supports it")] })) : null, _jsxs("label", { className: "microcopy", children: [_jsx("input", { type: "checkbox", checked: protectAtExport, onChange: (event) => setProtectAtExport(event.target.checked), style: { marginRight: "0.45rem" } }), tr("Wrap the exported package in a NULLID:ENC:1 envelope")] }), protectAtExport ? (_jsx("input", { className: "input", "aria-label": tr("Safe share export passphrase"), type: "password", placeholder: tr("Envelope passphrase"), value: exportPassphrase, onChange: (event) => setExportPassphrase(event.target.value) })) : null, _jsxs("ul", { className: "microcopy", children: [_jsx("li", { children: tr("Workflow packages record transforms, hashes, warnings, and limits for the receiver.") }), _jsx("li", { children: tr("NULLID:ENC:1 adds confidentiality and AES-GCM integrity for the exported file, not sender identity.") }), _jsx("li", { children: tr("Shared workflow packages are still unsigned unless a future contract version adds verifiable package signatures.") })] })] })] }), _jsxs("div", { className: "grid-two", children: [_jsxs("section", { className: "panel", "aria-label": tr("Package summary"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("5. Review package summary") }), _jsx("span", { className: "panel-subtext", children: tr("what the receiver will get") })] }), previewPackage ? (_jsxs(_Fragment, { children: [_jsxs("div", { className: "controls-row", style: { alignItems: "center" }, children: [_jsx(Chip, { label: previewPackage.workflowType, tone: "muted" }), previewPackage.workflowPreset ? _jsx(Chip, { label: previewPackage.workflowPreset.label, tone: "accent" }) : null, _jsx(Chip, { label: previewPackage.trust.packageSignature.method === "none" ? tr("unsigned") : tr(previewPackage.trust.packageSignature.method), tone: "muted" })] }), _jsx("div", { className: "microcopy", children: tr(previewPackage.summary.description) }), _jsx("table", { className: "table", children: _jsxs("tbody", { children: [_jsxs("tr", { children: [_jsx("th", { children: tr("Workflow") }), _jsx("td", { children: previewPackage.workflowType })] }), _jsxs("tr", { children: [_jsx("th", { children: tr("Artifacts") }), _jsx("td", { children: previewPackage.artifacts.length })] }), _jsxs("tr", { children: [_jsx("th", { children: tr("Manifest entries") }), _jsx("td", { children: previewPackage.trust.artifactManifest.entryCount })] }), _jsxs("tr", { children: [_jsx("th", { children: tr("Protection") }), _jsx("td", { children: protectAtExport ? tr("NULLID:ENC:1 envelope at export") : tr("plain workflow package JSON") })] })] }) }), _jsx("ul", { className: "microcopy", children: previewPackage.summary.highlights.map((line) => (_jsx("li", { children: tr(line) }, line))) })] })) : (_jsx("div", { className: "microcopy", children: isPreparingPreview ? tr("Preparing package preview...") : tr("Add input to prepare a workflow package preview.") })), previewError ? _jsx("div", { className: "tag tag-danger", children: previewError }) : null] }), _jsxs("section", { className: "panel", "aria-label": tr("Warnings and limitations"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("Warnings & limits") }), _jsx("span", { className: "panel-subtext", children: tr("honest trust language") })] }), _jsx("ul", { className: "microcopy", children: previewPackage ? ([...previewPackage.warnings, ...previewPackage.limitations].map((line) => _jsx("li", { children: tr(line) }, line))) : (_jsx("li", { children: tr("Warnings and limitations appear after the package preview is ready.") })) })] })] }), previewPackage?.transforms?.length ? (_jsxs("section", { className: "panel", "aria-label": tr("Transform summary"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("Transform summary") }), _jsx("span", { className: "panel-subtext", children: tr("recorded workflow steps") })] }), _jsxs("table", { className: "table", children: [_jsx("thead", { children: _jsxs("tr", { children: [_jsx("th", { children: tr("Transform") }), _jsx("th", { children: tr("Summary") })] }) }), _jsx("tbody", { children: previewPackage.transforms.map((transform) => (_jsxs("tr", { children: [_jsx("td", { children: tr(transform.label) }), _jsx("td", { children: tr(transform.summary) })] }, transform.id))) })] })] })) : null, _jsxs("section", { className: "panel", "aria-label": tr("Safe share export"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("6. Export package") }), _jsx("span", { className: "panel-subtext", children: tr("receiver-friendly artifact") })] }), _jsx("div", { className: "microcopy", children: tr("Export the package when the findings, warnings, and protection level look right. The receiver can inspect it locally in Verify Package or with `package-inspect`.") }), _jsx("div", { className: "controls-row", children: _jsx("button", { className: "button", type: "button", onClick: () => void exportPackage(), disabled: isExporting || !previewPackage, children: isExporting ? tr("exporting...") : protectAtExport ? tr("export protected package") : tr("export package") }) })] })] }));
}
function formatShareClassLabelForFile(analysis) {
    if (analysis.kind === "image")
        return "image";
    if (analysis.format === "pdf")
        return "pdf";
    if (analysis.format === "docx" || analysis.format === "xlsx" || analysis.format === "pptx")
        return "office document";
    if (analysis.kind === "video")
        return "video";
    if (analysis.kind === "archive")
        return "archive";
    return "unknown file";
}
function formatSanitizerLabel(value) {
    if (value === "browser-image")
        return "browser image clean";
    if (value === "browser-pdf")
        return "browser pdf clean";
    if (value === "mat2")
        return "external offline clean";
    return "analysis only";
}
function buildSafeShareExportFileName(mode, presetId, textSourceLabel, fileName) {
    const stem = mode === "text"
        ? sanitizeStem(textSourceLabel || `safe-share-${presetId}`)
        : sanitizeStem(fileName || `safe-share-${presetId}`);
    return `${stem}-nullid-safe-share`;
}
function sanitizeStem(value) {
    return value
        .trim()
        .replace(/\.[^.]+$/u, "")
        .replace(/[^a-z0-9_-]+/giu, "-")
        .replace(/-{2,}/gu, "-")
        .replace(/^-+|-+$/gu, "")
        || "nullid-safe-share";
}
function downloadBlob(blob, fileName) {
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = fileName;
    link.click();
    URL.revokeObjectURL(url);
}
