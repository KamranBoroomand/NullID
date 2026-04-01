import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import "./styles.css";
import { Chip } from "../components/Chip";
import { useToast } from "../components/ToastHost";
import { usePersistentState } from "../hooks/usePersistentState";
import { useI18n } from "../i18n";
import { encryptText } from "../utils/cryptoEnvelope.js";
import { buildDefaultIncidentPurpose, buildIncidentTemplateTitle, createIncidentFileArtifactPackage, createIncidentTextArtifactPackage, createIncidentWorkflowPackage, getIncidentWorkflowMode, incidentWorkflowModeIds, INCIDENT_TEMPLATE_BODY, } from "../utils/incidentWorkflow.js";
import { probeCanvasEncodeSupport } from "../utils/imageFormats.js";
import { analyzeMetadataFromBuffer } from "../utils/metadataAdvanced.js";
import { prepareLocalMetadataCleanup } from "../utils/localArtifactPreparation.js";
import { applySanitizeRules } from "../utils/sanitizeEngine.js";
import { buildSafeShareSanitizeConfig, summarizeSanitizeFindings } from "../utils/safeShareAssistant.js";
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
export function IncidentWorkflowView({ onOpenGuide }) {
    const { push } = useToast();
    const { t, tr, formatNumber } = useI18n();
    const [modeId, setModeId] = usePersistentState("nullid:incident:mode", "incident-handoff");
    const [incidentTitle, setIncidentTitle] = usePersistentState("nullid:incident:title", buildIncidentTemplateTitle());
    const [caseReference, setCaseReference] = usePersistentState("nullid:incident:case-reference", "");
    const [recipientScope, setRecipientScope] = usePersistentState("nullid:incident:recipient-scope", "");
    const [purpose, setPurpose] = usePersistentState("nullid:incident:purpose", buildDefaultIncidentPurpose("incident-handoff"));
    const [summaryText, setSummaryText] = usePersistentState("nullid:incident:summary", "");
    const [notesText, setNotesText] = usePersistentState("nullid:incident:notes", INCIDENT_TEMPLATE_BODY);
    const [policyPacks] = usePersistentState("nullid:sanitize:policy-packs", []);
    const [selectedPolicyId, setSelectedPolicyId] = usePersistentState("nullid:incident:policy-id", "");
    const [includeSourceReference, setIncludeSourceReference] = usePersistentState("nullid:incident:include-source-reference", true);
    const [applyMetadataClean, setApplyMetadataClean] = usePersistentState("nullid:incident:apply-metadata-clean", true);
    const [protectAtExport, setProtectAtExport] = usePersistentState("nullid:incident:protect-export", false);
    const [exportPassphrase, setExportPassphrase] = useState("");
    const [textArtifactLabel, setTextArtifactLabel] = useState("");
    const [textArtifactInput, setTextArtifactInput] = useState("");
    const [textArtifacts, setTextArtifacts] = useState([]);
    const [fileArtifacts, setFileArtifacts] = useState([]);
    const [draftFile, setDraftFile] = useState(null);
    const [draftSourceBytes, setDraftSourceBytes] = useState(null);
    const [draftAnalysis, setDraftAnalysis] = useState(null);
    const [draftCleanedBytes, setDraftCleanedBytes] = useState(null);
    const [draftCleanedMediaType, setDraftCleanedMediaType] = useState("");
    const [draftCleanedLabel, setDraftCleanedLabel] = useState("");
    const [draftCleanActions, setDraftCleanActions] = useState([]);
    const [draftFileMessage, setDraftFileMessage] = useState("load a file to analyze local metadata risk and packaging options");
    const [isAnalyzingFile, setIsAnalyzingFile] = useState(false);
    const [isPreparingPreview, setIsPreparingPreview] = useState(false);
    const [previewPackage, setPreviewPackage] = useState(null);
    const [previewPreparedArtifacts, setPreviewPreparedArtifacts] = useState([]);
    const [previewError, setPreviewError] = useState(null);
    const [isExporting, setIsExporting] = useState(false);
    const [outputSupport, setOutputSupport] = useState(null);
    const textArtifactFileRef = useRef(null);
    const draftFileRef = useRef(null);
    const mode = getIncidentWorkflowMode(modeId);
    const selectedPolicy = useMemo(() => policyPacks.find((pack) => pack.id === selectedPolicyId) ?? null, [policyPacks, selectedPolicyId]);
    const textPolicy = useMemo(() => buildSafeShareSanitizeConfig(mode.safeSharePresetId, selectedPolicy), [mode.safeSharePresetId, selectedPolicy]);
    const notesPreview = useMemo(() => applySanitizeRules(notesText, textPolicy.rulesState, textPolicy.customRules, textPolicy.jsonAware), [notesText, textPolicy]);
    const notesFindings = useMemo(() => summarizeSanitizeFindings(notesPreview.report).slice(0, 8), [notesPreview.report]);
    const draftTextPreview = useMemo(() => applySanitizeRules(textArtifactInput, textPolicy.rulesState, textPolicy.customRules, textPolicy.jsonAware), [textArtifactInput, textPolicy]);
    const draftTextFindings = useMemo(() => summarizeSanitizeFindings(draftTextPreview.report).slice(0, 6), [draftTextPreview.report]);
    const producer = useMemo(() => ({
        app: "NullID",
        surface: "web",
        module: "incident",
        buildId: typeof import.meta.env.VITE_BUILD_ID === "string" && import.meta.env.VITE_BUILD_ID.trim() ? import.meta.env.VITE_BUILD_ID.trim() : null,
    }), []);
    useEffect(() => {
        setIncludeSourceReference(mode.includeSourceReferenceDefault);
        setApplyMetadataClean(mode.defaultApplyMetadataClean);
        setPurpose((previous) => {
            const trimmed = previous.trim();
            if (!trimmed) {
                return buildDefaultIncidentPurpose(mode.id);
            }
            const matchesKnownDefault = incidentWorkflowModeIds.some((candidate) => trimmed === buildDefaultIncidentPurpose(candidate));
            return matchesKnownDefault ? buildDefaultIncidentPurpose(mode.id) : previous;
        });
    }, [mode.defaultApplyMetadataClean, mode.id, mode.includeSourceReferenceDefault, setApplyMetadataClean, setIncludeSourceReference, setPurpose]);
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
                console.error("incident output support failed", error);
            }
        })();
        return () => {
            cancelled = true;
        };
    }, []);
    const refreshDraftCleanup = useCallback(async (file, analysis) => {
        setDraftCleanedBytes(null);
        setDraftCleanedMediaType("");
        setDraftCleanedLabel("");
        setDraftCleanActions([]);
        try {
            const cleaned = await prepareLocalMetadataCleanup(file, analysis, {
                applyMetadataClean,
                outputSupport,
            });
            setDraftCleanedBytes(cleaned.cleanedBytes ?? null);
            setDraftCleanedMediaType(cleaned.cleanedMediaType ?? "");
            setDraftCleanedLabel(cleaned.cleanedLabel ?? "");
            setDraftCleanActions(cleaned.cleanActions);
            setDraftFileMessage(cleaned.message);
        }
        catch (error) {
            console.error(error);
            setDraftFileMessage(error instanceof Error ? error.message : "local cleanup failed");
        }
    }, [applyMetadataClean, outputSupport]);
    const handleDraftFile = useCallback(async (file) => {
        if (!file)
            return;
        setDraftFile(file);
        setDraftAnalysis(null);
        setDraftSourceBytes(null);
        setIsAnalyzingFile(true);
        try {
            const bytes = new Uint8Array(await file.arrayBuffer());
            const analysis = analyzeMetadataFromBuffer(file.type || "", bytes, file.name);
            setDraftSourceBytes(bytes);
            setDraftAnalysis(analysis);
            await refreshDraftCleanup(file, analysis);
            push(`loaded ${file.name}`, "accent");
        }
        catch (error) {
            console.error(error);
            setDraftFileMessage(error instanceof Error ? error.message : "file analysis failed");
            push("file analysis failed", "danger");
        }
        finally {
            setIsAnalyzingFile(false);
        }
    }, [push, refreshDraftCleanup]);
    useEffect(() => {
        if (!draftFile || !draftAnalysis)
            return;
        void refreshDraftCleanup(draftFile, draftAnalysis);
    }, [applyMetadataClean, draftAnalysis, draftFile, outputSupport, refreshDraftCleanup]);
    const handleTextArtifactFile = useCallback(async (file) => {
        if (!file)
            return;
        try {
            setTextArtifactInput(await file.text());
            setTextArtifactLabel(file.name);
            push(`loaded ${file.name}`, "accent");
        }
        catch (error) {
            console.error(error);
            push("text file load failed", "danger");
        }
    }, [push]);
    const addTextArtifact = () => {
        if (!textArtifactInput.trim()) {
            push("text artifact is empty", "danger");
            return;
        }
        const label = textArtifactLabel.trim() || `incident-artifact-${textArtifacts.length + 1}.txt`;
        setTextArtifacts((prev) => [
            ...prev,
            {
                id: buildLocalId("text", prev.length),
                label,
                inputText: textArtifactInput,
            },
        ]);
        setTextArtifactLabel("");
        setTextArtifactInput("");
        push("text artifact added", "accent");
    };
    const addFileArtifact = () => {
        if (!draftFile || !draftSourceBytes || !draftAnalysis) {
            push("load and analyze a file first", "danger");
            return;
        }
        setFileArtifacts((prev) => [
            ...prev,
            {
                id: buildLocalId("file", prev.length),
                label: draftFile.name,
                fileName: draftFile.name,
                fileMediaType: draftFile.type || "application/octet-stream",
                sourceBytes: draftSourceBytes,
                analysis: draftAnalysis,
                cleanedBytes: draftCleanedBytes ?? undefined,
                cleanedMediaType: draftCleanedMediaType || undefined,
                cleanedLabel: draftCleanedLabel || undefined,
                cleanActions: [...draftCleanActions],
            },
        ]);
        clearDraftFile();
        push("file artifact added", "accent");
    };
    const clearDraftFile = () => {
        setDraftFile(null);
        setDraftSourceBytes(null);
        setDraftAnalysis(null);
        setDraftCleanedBytes(null);
        setDraftCleanedMediaType("");
        setDraftCleanedLabel("");
        setDraftCleanActions([]);
        setDraftFileMessage("load a file to analyze local metadata risk and packaging options");
    };
    const buildPreview = useCallback(async () => {
        const preparedArtifacts = [];
        const notesLabel = sanitizeStem(incidentTitle || buildIncidentTemplateTitle());
        if (notesText.trim()) {
            preparedArtifacts.push({
                id: "case-notes",
                label: "Case notes",
                kind: "notes",
                workflowPackage: await createIncidentTextArtifactPackage({
                    modeId,
                    producer,
                    inputText: notesText,
                    sourceLabel: `${notesLabel}-notes.txt`,
                    includeSourceReference,
                    policyPack: selectedPolicy,
                    protectAtExport,
                }),
            });
        }
        for (const [index, item] of textArtifacts.entries()) {
            preparedArtifacts.push({
                id: item.id,
                label: item.label.trim() || `Text artifact ${index + 1}`,
                kind: "text",
                workflowPackage: await createIncidentTextArtifactPackage({
                    modeId,
                    producer,
                    inputText: item.inputText,
                    sourceLabel: item.label.trim() || `incident-artifact-${index + 1}.txt`,
                    includeSourceReference,
                    policyPack: selectedPolicy,
                    protectAtExport,
                }),
            });
        }
        for (const item of fileArtifacts) {
            preparedArtifacts.push({
                id: item.id,
                label: item.label,
                kind: "file",
                workflowPackage: await createIncidentFileArtifactPackage({
                    modeId,
                    producer,
                    fileName: item.fileName,
                    fileMediaType: item.fileMediaType,
                    sourceBytes: item.sourceBytes,
                    analysis: item.analysis,
                    cleanedBytes: item.cleanedBytes,
                    cleanedMediaType: item.cleanedMediaType,
                    cleanedLabel: item.cleanedLabel,
                    applyMetadataClean,
                    includeSourceReference,
                    protectAtExport,
                }),
            });
        }
        const workflowPackage = await createIncidentWorkflowPackage({
            modeId,
            producer,
            incidentTitle,
            purpose,
            caseReference,
            recipientScope,
            summaryText,
            preparedArtifacts,
            notesTemplateUsed: notesText.trim() === INCIDENT_TEMPLATE_BODY.trim(),
            protectAtExport,
        });
        return { workflowPackage, preparedArtifacts };
    }, [
        applyMetadataClean,
        caseReference,
        fileArtifacts,
        incidentTitle,
        includeSourceReference,
        modeId,
        notesText,
        producer,
        protectAtExport,
        purpose,
        recipientScope,
        selectedPolicy,
        summaryText,
        textArtifacts,
    ]);
    useEffect(() => {
        let cancelled = false;
        setIsPreparingPreview(true);
        void (async () => {
            try {
                const next = await buildPreview();
                if (cancelled)
                    return;
                setPreviewPackage(next.workflowPackage);
                setPreviewPreparedArtifacts(next.preparedArtifacts);
                setPreviewError(null);
            }
            catch (error) {
                if (cancelled)
                    return;
                console.error(error);
                setPreviewPackage(null);
                setPreviewPreparedArtifacts([]);
                setPreviewError(error instanceof Error ? error.message : "incident preview failed");
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
    }, [buildPreview]);
    const exportPackage = async () => {
        setIsExporting(true);
        try {
            const next = previewPackage ?? (await buildPreview()).workflowPackage;
            if (!next) {
                push("nothing ready to export", "danger");
                return;
            }
            if (protectAtExport && !exportPassphrase.trim()) {
                push("export passphrase required", "danger");
                return;
            }
            const json = JSON.stringify(next, null, 2);
            const fileName = buildIncidentExportFileName(incidentTitle || mode.label);
            if (protectAtExport) {
                const envelope = await encryptText(exportPassphrase.trim(), json);
                downloadBlob(new Blob([envelope], { type: "text/plain;charset=utf-8" }), `${fileName}.nullid`);
                push("protected incident package exported", "accent");
                return;
            }
            downloadBlob(new Blob([json], { type: "application/json" }), `${fileName}.json`);
            push("incident package exported", "accent");
        }
        catch (error) {
            console.error(error);
            push("incident package export failed", "danger");
        }
        finally {
            setIsExporting(false);
        }
    };
    return (_jsxs("div", { className: "workspace-scroll", children: [_jsx("div", { className: "guide-link", children: _jsx("button", { type: "button", className: "guide-link-button", onClick: () => onOpenGuide?.("incident"), children: t("guide.link") }) }), _jsxs("section", { className: "panel", "aria-label": tr("Incident workflow overview"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("Incident Workflow") }), _jsx("span", { className: "panel-subtext", children: tr("guided operational package") })] }), _jsx("div", { className: "microcopy", children: tr("Assemble incident notes, prepared artifacts, hashes, and receiver-facing reporting into one local workflow package without leaving the browser.") }), _jsxs("div", { className: "controls-row", style: { alignItems: "center" }, children: [_jsx(Chip, { label: tr(mode.label), tone: "accent" }), _jsx(Chip, { label: `${previewPreparedArtifacts.length} ${tr("prepared artifacts")}`, tone: "muted" }), _jsx(Chip, { label: protectAtExport ? tr("NULLID:ENC:1 at export") : tr("unsigned package"), tone: protectAtExport ? "accent" : "muted" })] })] }), _jsxs("div", { className: "grid-two", children: [_jsxs("section", { className: "panel", "aria-label": tr("Incident context"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("1. Define context") }), _jsx("span", { className: "panel-subtext", children: tr("purpose and receiver scope") })] }), _jsx("input", { className: "input", "aria-label": tr("Incident title"), placeholder: tr("Incident title"), value: incidentTitle, onChange: (event) => setIncidentTitle(event.target.value) }), _jsxs("div", { className: "controls-row", children: [_jsx("input", { className: "input", "aria-label": tr("Incident case reference"), placeholder: tr("Case reference (optional)"), value: caseReference, onChange: (event) => setCaseReference(event.target.value) }), _jsx("input", { className: "input", "aria-label": tr("Incident recipient scope"), placeholder: tr("Recipient scope (optional)"), value: recipientScope, onChange: (event) => setRecipientScope(event.target.value) })] }), _jsx("input", { className: "input", "aria-label": tr("Incident purpose"), placeholder: tr("Package purpose"), value: purpose, onChange: (event) => setPurpose(event.target.value) }), _jsx("textarea", { className: "textarea", "aria-label": tr("Incident summary"), placeholder: tr("Short incident summary for the receiver"), value: summaryText, onChange: (event) => setSummaryText(event.target.value) })] }), _jsxs("section", { className: "panel", "aria-label": tr("Incident mode"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("2. Choose mode") }), _jsx("span", { className: "panel-subtext", children: tr("preset and handling posture") })] }), _jsx("div", { className: "pill-buttons", role: "group", "aria-label": tr("Incident workflow mode chooser"), children: incidentWorkflowModeIds.map((id) => (_jsx("button", { type: "button", className: modeId === id ? "active" : "", onClick: () => setModeId(id), children: getIncidentWorkflowMode(id).label }, id))) }), _jsx("div", { className: "microcopy", children: tr(mode.description) }), _jsx("ul", { className: "microcopy", children: mode.guidance.map((line) => (_jsx("li", { children: tr(line) }, line))) }), _jsxs("label", { className: "microcopy", htmlFor: "incident-policy-pack", children: [tr("Optional sanitize policy pack"), _jsxs("select", { id: "incident-policy-pack", className: "select", "aria-label": tr("Incident policy pack"), value: selectedPolicyId, onChange: (event) => setSelectedPolicyId(event.target.value), children: [_jsx("option", { value: "", children: tr("Use the workflow mode only") }), policyPacks.map((pack) => (_jsx("option", { value: pack.id, children: pack.name }, pack.id)))] })] }), _jsxs("label", { className: "microcopy", children: [_jsx("input", { type: "checkbox", checked: includeSourceReference, onChange: (event) => setIncludeSourceReference(event.target.checked), style: { marginRight: "0.45rem" } }), tr("Include source references (hash + label, not original bytes) where possible")] }), _jsxs("label", { className: "microcopy", children: [_jsx("input", { type: "checkbox", checked: applyMetadataClean, onChange: (event) => setApplyMetadataClean(event.target.checked), style: { marginRight: "0.45rem" } }), tr("Apply local metadata cleanup when supported")] }), _jsxs("label", { className: "microcopy", children: [_jsx("input", { type: "checkbox", checked: protectAtExport, onChange: (event) => setProtectAtExport(event.target.checked), style: { marginRight: "0.45rem" } }), tr("Wrap the exported incident package in a NULLID:ENC:1 envelope")] }), protectAtExport ? (_jsx("input", { className: "input", "aria-label": tr("Incident export passphrase"), type: "password", placeholder: tr("Envelope passphrase"), value: exportPassphrase, onChange: (event) => setExportPassphrase(event.target.value) })) : null] })] }), _jsxs("div", { className: "grid-two", children: [_jsxs("section", { className: "panel", "aria-label": tr("Case notes"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("3. Prepare notes") }), _jsx("span", { className: "panel-subtext", children: tr("sanitized case context") })] }), _jsxs("div", { className: "controls-row", children: [_jsx("button", { className: "button", type: "button", onClick: () => {
                                            setIncidentTitle((prev) => prev || buildIncidentTemplateTitle());
                                            setNotesText(INCIDENT_TEMPLATE_BODY);
                                        }, children: tr("use incident note template") }), _jsx(Chip, { label: `${notesPreview.applied.length} ${tr("rules applied")}`, tone: notesPreview.applied.length > 0 ? "accent" : "muted" }), _jsx(Chip, { label: `${notesPreview.linesAffected} ${tr("lines changed")}`, tone: "muted" })] }), _jsx("div", { className: "microcopy", children: tr("Uses the same incident note headings that are available in Secure Notes, but prepares them for export rather than local vault storage.") }), _jsx("textarea", { className: "textarea", "aria-label": tr("Incident notes"), placeholder: tr("Case notes to include in the incident package"), value: notesText, onChange: (event) => setNotesText(event.target.value) }), _jsx("div", { className: "panel-subtext", children: tr("Detected note findings") }), _jsx("ul", { className: "microcopy", children: notesFindings.length > 0
                                    ? notesFindings.map((entry) => _jsxs("li", { children: [tr(entry.label), ": ", entry.count] }, `${entry.label}:${entry.count}`))
                                    : _jsx("li", { children: tr("No note findings were recorded yet.") }) }), _jsx("div", { className: "panel-subtext", children: tr("Prepared note preview") }), _jsx("pre", { className: "log-preview", "aria-label": tr("Incident note preview"), children: notesPreview.output || tr("nothing to preview") })] }), _jsxs("section", { className: "panel", "aria-label": tr("Additional artifacts"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("4. Add artifacts") }), _jsx("span", { className: "panel-subtext", children: tr("text snippets and files") })] }), _jsx("div", { className: "panel-subtext", children: tr("Additional text artifact") }), _jsx("input", { className: "input", "aria-label": tr("Incident text artifact label"), placeholder: tr("Artifact label (for example auth-log-snippet.txt)"), value: textArtifactLabel, onChange: (event) => setTextArtifactLabel(event.target.value) }), _jsx("textarea", { className: "textarea", "aria-label": tr("Incident text artifact input"), placeholder: tr("Optional extra text snippet to include alongside the notes"), value: textArtifactInput, onChange: (event) => setTextArtifactInput(event.target.value) }), _jsxs("div", { className: "controls-row", children: [_jsx("button", { className: "button", type: "button", onClick: addTextArtifact, children: tr("add text artifact") }), _jsx("button", { className: "button", type: "button", onClick: () => textArtifactFileRef.current?.click(), children: tr("load text file") }), _jsx("button", { className: "button", type: "button", onClick: () => {
                                            setTextArtifactLabel("");
                                            setTextArtifactInput("");
                                        }, children: tr("clear") }), _jsx("input", { ref: textArtifactFileRef, hidden: true, type: "file", "aria-label": tr("Incident text artifact file"), accept: textInputAccept, onChange: (event) => void handleTextArtifactFile(event.target.files?.[0] ?? null) })] }), textArtifactInput.trim() ? (_jsx("ul", { className: "microcopy", children: draftTextFindings.length > 0
                                    ? draftTextFindings.map((entry) => _jsxs("li", { children: [tr(entry.label), ": ", entry.count] }, `${entry.label}:${entry.count}`))
                                    : _jsx("li", { children: tr("No findings were detected in the current text artifact draft.") }) })) : null, _jsx("div", { className: "panel-subtext", children: tr("File artifact") }), _jsx("div", { className: "dropzone", role: "button", tabIndex: 0, "aria-label": tr("Choose incident file artifact"), onClick: () => draftFileRef.current?.click(), onKeyDown: (event) => {
                                    if (event.key === "Enter" || event.key === " ") {
                                        event.preventDefault();
                                        draftFileRef.current?.click();
                                    }
                                }, children: draftFile ? `${draftFile.name} · ${formatNumber(draftFile.size)} ${tr("bytes")}` : tr("Choose a file artifact to analyze locally before adding") }), _jsx("div", { className: "microcopy", children: tr(draftFileMessage) }), _jsxs("div", { className: "controls-row", children: [_jsx("button", { className: "button", type: "button", onClick: () => draftFileRef.current?.click(), children: tr("load file") }), _jsx("button", { className: "button", type: "button", onClick: addFileArtifact, disabled: !draftAnalysis || !draftSourceBytes, children: tr("add file artifact") }), _jsx("button", { className: "button", type: "button", onClick: clearDraftFile, children: tr("clear") }), _jsx("input", { ref: draftFileRef, hidden: true, type: "file", "aria-label": tr("Incident file artifact"), onChange: (event) => void handleDraftFile(event.target.files?.[0] ?? null) })] }), _jsx("div", { className: "controls-row", style: { alignItems: "center" }, children: draftAnalysis ? (_jsxs(_Fragment, { children: [_jsx(Chip, { label: `${tr("risk")}: ${tr(draftAnalysis.risk)}`, tone: draftAnalysis.risk === "high" ? "danger" : draftAnalysis.risk === "medium" ? "accent" : "muted" }), _jsx(Chip, { label: `${tr("cleaner")}: ${tr(formatSanitizerLabel(draftAnalysis.recommendedSanitizer))}`, tone: "muted" })] })) : (_jsx(Chip, { label: isAnalyzingFile ? tr("analyzing...") : tr("waiting for file"), tone: "muted" })) }), _jsx("ul", { className: "microcopy", children: draftAnalysis?.signals.length ? draftAnalysis.signals.map((signal) => (_jsxs("li", { children: [signal.label, ": ", signal.detail] }, signal.id))) : (_jsx("li", { children: draftAnalysis ? tr("No metadata risk signals were detected in the current scan window.") : tr("Load a file to inspect metadata signals.") })) }), draftCleanActions.length ? (_jsxs(_Fragment, { children: [_jsx("div", { className: "panel-subtext", children: tr("Local cleanup actions") }), _jsx("ul", { className: "microcopy", children: draftCleanActions.map((line) => (_jsx("li", { children: line }, line))) })] })) : null, draftAnalysis?.commandHint ? _jsx("div", { className: "microcopy", children: draftAnalysis.commandHint }) : null] })] }), _jsxs("section", { className: "panel", "aria-label": tr("Incident contents"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("5. Review contents") }), _jsx("span", { className: "panel-subtext", children: tr("what will be assembled") })] }), _jsxs("table", { className: "table", children: [_jsx("thead", { children: _jsxs("tr", { children: [_jsx("th", { children: tr("Artifact") }), _jsx("th", { children: tr("Type") }), _jsx("th", { children: tr("Status") }), _jsx("th", { children: tr("Action") })] }) }), _jsxs("tbody", { children: [_jsxs("tr", { children: [_jsx("td", { children: tr("Case notes") }), _jsx("td", { children: tr("text") }), _jsx("td", { children: notesText.trim() ? tr("included") : tr("omitted") }), _jsx("td", { children: _jsx("button", { className: "button", type: "button", onClick: () => setNotesText(""), children: tr("clear") }) })] }), textArtifacts.map((item) => (_jsxs("tr", { children: [_jsx("td", { children: item.label }), _jsx("td", { children: tr("text") }), _jsx("td", { children: tr("queued") }), _jsx("td", { children: _jsx("button", { className: "button", type: "button", onClick: () => setTextArtifacts((prev) => prev.filter((entry) => entry.id !== item.id)), children: tr("remove") }) })] }, item.id))), fileArtifacts.map((item) => (_jsxs("tr", { children: [_jsx("td", { children: item.label }), _jsx("td", { children: tr("file") }), _jsx("td", { children: item.cleanedBytes && applyMetadataClean ? tr("cleanup ready") : tr("queued") }), _jsx("td", { children: _jsx("button", { className: "button", type: "button", onClick: () => setFileArtifacts((prev) => prev.filter((entry) => entry.id !== item.id)), children: tr("remove") }) })] }, item.id))), textArtifacts.length === 0 && fileArtifacts.length === 0 && !notesText.trim() ? (_jsx("tr", { children: _jsx("td", { colSpan: 4, children: tr("No incident content is queued yet.") }) })) : null] })] }), previewPreparedArtifacts.length ? (_jsx("ul", { className: "microcopy", children: previewPreparedArtifacts.map((artifact) => (_jsxs("li", { children: [tr(artifact.label), ": ", artifact.workflowPackage.artifacts.filter((entry) => entry.included).length, " ", tr("included entries"), ", ", artifact.workflowPackage.transforms?.length ?? 0, " ", tr("transform steps")] }, artifact.id))) })) : null] }), _jsxs("div", { className: "grid-two", children: [_jsxs("section", { className: "panel", "aria-label": tr("Incident package summary"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("6. Package summary") }), _jsx("span", { className: "panel-subtext", children: tr("receiver-facing overview") })] }), previewPackage ? (_jsxs(_Fragment, { children: [_jsxs("div", { className: "controls-row", style: { alignItems: "center" }, children: [_jsx(Chip, { label: previewPackage.workflowType, tone: "muted" }), previewPackage.workflowPreset ? _jsx(Chip, { label: tr(previewPackage.workflowPreset.label), tone: "accent" }) : null, _jsx(Chip, { label: previewPackage.trust.packageSignature.method === "none" ? tr("unsigned") : previewPackage.trust.packageSignature.method, tone: "muted" })] }), _jsx("div", { className: "microcopy", children: tr(previewPackage.summary.description) }), _jsx("table", { className: "table", children: _jsxs("tbody", { children: [_jsxs("tr", { children: [_jsx("th", { children: tr("Workflow") }), _jsx("td", { children: previewPackage.workflowType })] }), _jsxs("tr", { children: [_jsx("th", { children: tr("Artifacts") }), _jsx("td", { children: previewPackage.artifacts.length })] }), _jsxs("tr", { children: [_jsx("th", { children: tr("Prepared entries") }), _jsx("td", { children: previewPreparedArtifacts.length })] }), _jsxs("tr", { children: [_jsx("th", { children: tr("Manifest entries") }), _jsx("td", { children: previewPackage.trust.artifactManifest.entryCount })] }), _jsxs("tr", { children: [_jsx("th", { children: tr("Protection") }), _jsx("td", { children: protectAtExport ? tr("NULLID:ENC:1 envelope at export") : tr("plain workflow package JSON") })] })] }) }), _jsx("ul", { className: "microcopy", children: previewPackage.summary.highlights.map((line) => (_jsx("li", { children: line }, line))) })] })) : (_jsx("div", { className: "microcopy", children: isPreparingPreview ? tr("Preparing incident package preview...") : tr("Add notes or artifacts to prepare an incident package preview.") })), previewError ? _jsx("div", { className: "tag tag-danger", children: previewError }) : null] }), _jsxs("section", { className: "panel", "aria-label": tr("Incident explainability"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("7. Explainability") }), _jsx("span", { className: "panel-subtext", children: tr("what the package says and proves") })] }), previewPackage?.report ? (_jsxs(_Fragment, { children: [_jsx("table", { className: "table", children: _jsxs("tbody", { children: [previewPackage.report.purpose ? (_jsxs("tr", { children: [_jsx("th", { children: tr("Purpose") }), _jsx("td", { children: previewPackage.report.purpose })] })) : null, previewPackage.report.audience ? (_jsxs("tr", { children: [_jsx("th", { children: tr("Audience") }), _jsx("td", { children: previewPackage.report.audience })] })) : null] }) }), _jsx("div", { className: "panel-subtext", children: tr("Included artifacts") }), _jsx("ul", { className: "microcopy", children: previewPackage.report.includedArtifacts.map((line) => (_jsx("li", { children: line }, line))) }), _jsx("div", { className: "panel-subtext", children: tr("What the receiver can verify") }), _jsx("ul", { className: "microcopy", children: previewPackage.report.receiverCanVerify.map((line) => (_jsx("li", { children: line }, line))) }), _jsx("div", { className: "panel-subtext", children: tr("What the receiver cannot verify") }), _jsx("ul", { className: "microcopy", children: previewPackage.report.receiverCannotVerify.map((line) => (_jsx("li", { children: line }, line))) })] })) : (_jsx("div", { className: "microcopy", children: tr("Incident explainability appears after the package preview is ready.") }))] })] }), _jsxs("div", { className: "grid-two", children: [_jsxs("section", { className: "panel", "aria-label": tr("Warnings and limitations"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("Warnings & limits") }), _jsx("span", { className: "panel-subtext", children: tr("honest trust language") })] }), _jsx("ul", { className: "microcopy", children: previewPackage ? ([...previewPackage.warnings, ...previewPackage.limitations].map((line) => _jsx("li", { children: line }, line))) : (_jsx("li", { children: tr("Warnings and limitations appear after the incident package preview is ready.") })) })] }), _jsxs("section", { className: "panel", "aria-label": tr("Transform summary"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("Transform summary") }), _jsx("span", { className: "panel-subtext", children: tr("recorded workflow steps") })] }), previewPackage?.transforms?.length ? (_jsxs("table", { className: "table", children: [_jsx("thead", { children: _jsxs("tr", { children: [_jsx("th", { children: tr("Transform") }), _jsx("th", { children: tr("Summary") })] }) }), _jsx("tbody", { children: previewPackage.transforms.map((transform) => (_jsxs("tr", { children: [_jsx("td", { children: transform.label }), _jsx("td", { children: transform.summary })] }, transform.id))) })] })) : (_jsx("div", { className: "microcopy", children: tr("Transform details appear after the incident package preview is ready.") }))] })] }), _jsxs("section", { className: "panel", "aria-label": tr("Incident export"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("8. Export package") }), _jsx("span", { className: "panel-subtext", children: tr("receiver-friendly incident artifact") })] }), _jsx("div", { className: "microcopy", children: tr("Export once the context, transforms, warnings, and protection level look right. The receiver can inspect the package locally in Verify Package or with `package-inspect`.") }), _jsx("div", { className: "controls-row", children: _jsx("button", { className: "button", type: "button", onClick: () => void exportPackage(), disabled: isExporting || !previewPackage, children: isExporting ? tr("exporting...") : protectAtExport ? tr("export protected package") : tr("export package") }) })] })] }));
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
function buildLocalId(prefix, index) {
    return `${prefix}-${Date.now().toString(36)}-${index + 1}`;
}
function buildIncidentExportFileName(value) {
    return `${sanitizeStem(value)}-nullid-incident`;
}
function sanitizeStem(value) {
    return value
        .trim()
        .replace(/\.[^.]+$/u, "")
        .replace(/[^a-z0-9_-]+/giu, "-")
        .replace(/-{2,}/gu, "-")
        .replace(/^-+|-+$/gu, "")
        || "nullid-incident";
}
function downloadBlob(blob, fileName) {
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = fileName;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
}
