import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import "./styles.css";
import { Chip } from "../components/Chip";
import type { ModuleKey } from "../components/ModuleList";
import { useToast } from "../components/ToastHost";
import { usePersistentState } from "../hooks/usePersistentState";
import { useI18n } from "../i18n";
import { encryptText } from "../utils/cryptoEnvelope.js";
import {
  buildDefaultIncidentPurpose,
  buildIncidentTemplateTitle,
  createIncidentFileArtifactPackage,
  createIncidentTextArtifactPackage,
  createIncidentWorkflowPackage,
  getIncidentWorkflowMode,
  incidentWorkflowModeIds,
  INCIDENT_TEMPLATE_BODY,
  type IncidentPreparedArtifact,
  type IncidentWorkflowModeId,
} from "../utils/incidentWorkflow.js";
import { probeCanvasEncodeSupport, type OutputMime } from "../utils/imageFormats.js";
import { analyzeMetadataFromBuffer, type MetadataAnalysisResult } from "../utils/metadataAdvanced.js";
import { prepareLocalMetadataCleanup } from "../utils/localArtifactPreparation.js";
import { applySanitizeRules, type PolicyPack } from "../utils/sanitizeEngine.js";
import { buildSafeShareSanitizeConfig, summarizeSanitizeFindings } from "../utils/safeShareAssistant.js";
import type { WorkflowPackage } from "../utils/workflowPackage.js";

interface IncidentWorkflowViewProps {
  onOpenGuide?: (key?: ModuleKey) => void;
}

interface IncidentTextArtifactDraft {
  id: string;
  label: string;
  inputText: string;
}

interface IncidentFileArtifactDraft {
  id: string;
  label: string;
  fileName: string;
  fileMediaType: string;
  sourceBytes: Uint8Array;
  analysis: MetadataAnalysisResult;
  cleanedBytes?: Uint8Array;
  cleanedMediaType?: string;
  cleanedLabel?: string;
  cleanActions: string[];
}

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

export function IncidentWorkflowView({ onOpenGuide }: IncidentWorkflowViewProps) {
  const { push } = useToast();
  const { t, tr, formatNumber } = useI18n();
  const [modeId, setModeId] = usePersistentState<IncidentWorkflowModeId>("nullid:incident:mode", "incident-handoff");
  const [incidentTitle, setIncidentTitle] = usePersistentState<string>("nullid:incident:title", buildIncidentTemplateTitle());
  const [caseReference, setCaseReference] = usePersistentState<string>("nullid:incident:case-reference", "");
  const [recipientScope, setRecipientScope] = usePersistentState<string>("nullid:incident:recipient-scope", "");
  const [purpose, setPurpose] = usePersistentState<string>("nullid:incident:purpose", buildDefaultIncidentPurpose("incident-handoff"));
  const [summaryText, setSummaryText] = usePersistentState<string>("nullid:incident:summary", "");
  const [notesText, setNotesText] = usePersistentState<string>("nullid:incident:notes", INCIDENT_TEMPLATE_BODY);
  const [policyPacks] = usePersistentState<PolicyPack[]>("nullid:sanitize:policy-packs", []);
  const [selectedPolicyId, setSelectedPolicyId] = usePersistentState<string>("nullid:incident:policy-id", "");
  const [includeSourceReference, setIncludeSourceReference] = usePersistentState<boolean>("nullid:incident:include-source-reference", true);
  const [applyMetadataClean, setApplyMetadataClean] = usePersistentState<boolean>("nullid:incident:apply-metadata-clean", true);
  const [protectAtExport, setProtectAtExport] = usePersistentState<boolean>("nullid:incident:protect-export", false);
  const [exportPassphrase, setExportPassphrase] = useState("");
  const [textArtifactLabel, setTextArtifactLabel] = useState("");
  const [textArtifactInput, setTextArtifactInput] = useState("");
  const [textArtifacts, setTextArtifacts] = useState<IncidentTextArtifactDraft[]>([]);
  const [fileArtifacts, setFileArtifacts] = useState<IncidentFileArtifactDraft[]>([]);
  const [draftFile, setDraftFile] = useState<File | null>(null);
  const [draftSourceBytes, setDraftSourceBytes] = useState<Uint8Array | null>(null);
  const [draftAnalysis, setDraftAnalysis] = useState<MetadataAnalysisResult | null>(null);
  const [draftCleanedBytes, setDraftCleanedBytes] = useState<Uint8Array | null>(null);
  const [draftCleanedMediaType, setDraftCleanedMediaType] = useState("");
  const [draftCleanedLabel, setDraftCleanedLabel] = useState("");
  const [draftCleanActions, setDraftCleanActions] = useState<string[]>([]);
  const [draftFileMessage, setDraftFileMessage] = useState("load a file to analyze local metadata risk and packaging options");
  const [isAnalyzingFile, setIsAnalyzingFile] = useState(false);
  const [isPreparingPreview, setIsPreparingPreview] = useState(false);
  const [previewPackage, setPreviewPackage] = useState<WorkflowPackage | null>(null);
  const [previewPreparedArtifacts, setPreviewPreparedArtifacts] = useState<IncidentPreparedArtifact[]>([]);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [isExporting, setIsExporting] = useState(false);
  const [outputSupport, setOutputSupport] = useState<Record<OutputMime, boolean> | null>(null);
  const textArtifactFileRef = useRef<HTMLInputElement>(null);
  const draftFileRef = useRef<HTMLInputElement>(null);

  const mode = getIncidentWorkflowMode(modeId);
  const selectedPolicy = useMemo(
    () => policyPacks.find((pack) => pack.id === selectedPolicyId) ?? null,
    [policyPacks, selectedPolicyId],
  );
  const textPolicy = useMemo(
    () => buildSafeShareSanitizeConfig(mode.safeSharePresetId, selectedPolicy),
    [mode.safeSharePresetId, selectedPolicy],
  );
  const notesPreview = useMemo(
    () => applySanitizeRules(notesText, textPolicy.rulesState, textPolicy.customRules, textPolicy.jsonAware),
    [notesText, textPolicy],
  );
  const notesFindings = useMemo(() => summarizeSanitizeFindings(notesPreview.report).slice(0, 8), [notesPreview.report]);
  const draftTextPreview = useMemo(
    () => applySanitizeRules(textArtifactInput, textPolicy.rulesState, textPolicy.customRules, textPolicy.jsonAware),
    [textArtifactInput, textPolicy],
  );
  const draftTextFindings = useMemo(() => summarizeSanitizeFindings(draftTextPreview.report).slice(0, 6), [draftTextPreview.report]);
  const producer = useMemo(
    () => ({
      app: "NullID" as const,
      surface: "web" as const,
      module: "incident",
      buildId: typeof import.meta.env.VITE_BUILD_ID === "string" && import.meta.env.VITE_BUILD_ID.trim() ? import.meta.env.VITE_BUILD_ID.trim() : null,
    }),
    [],
  );

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
      } catch (error) {
        console.error("incident output support failed", error);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const refreshDraftCleanup = useCallback(
    async (file: File, analysis: MetadataAnalysisResult) => {
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
      } catch (error) {
        console.error(error);
        setDraftFileMessage(error instanceof Error ? error.message : "local cleanup failed");
      }
    },
    [applyMetadataClean, outputSupport],
  );

  const handleDraftFile = useCallback(
    async (file?: File | null) => {
      if (!file) return;
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
      } catch (error) {
        console.error(error);
        setDraftFileMessage(error instanceof Error ? error.message : "file analysis failed");
        push("file analysis failed", "danger");
      } finally {
        setIsAnalyzingFile(false);
      }
    },
    [push, refreshDraftCleanup],
  );

  useEffect(() => {
    if (!draftFile || !draftAnalysis) return;
    void refreshDraftCleanup(draftFile, draftAnalysis);
  }, [applyMetadataClean, draftAnalysis, draftFile, outputSupport, refreshDraftCleanup]);

  const handleTextArtifactFile = useCallback(
    async (file?: File | null) => {
      if (!file) return;
      try {
        setTextArtifactInput(await file.text());
        setTextArtifactLabel(file.name);
        push(`loaded ${file.name}`, "accent");
      } catch (error) {
        console.error(error);
        push("text file load failed", "danger");
      }
    },
    [push],
  );

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
    const preparedArtifacts: IncidentPreparedArtifact[] = [];
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
        if (cancelled) return;
        setPreviewPackage(next.workflowPackage);
        setPreviewPreparedArtifacts(next.preparedArtifacts);
        setPreviewError(null);
      } catch (error) {
        if (cancelled) return;
        console.error(error);
        setPreviewPackage(null);
        setPreviewPreparedArtifacts([]);
        setPreviewError(error instanceof Error ? error.message : "incident preview failed");
      } finally {
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
    } catch (error) {
      console.error(error);
      push("incident package export failed", "danger");
    } finally {
      setIsExporting(false);
    }
  };

  return (
    <div className="workspace-scroll">
      <div className="guide-link">
        <button type="button" className="guide-link-button" onClick={() => onOpenGuide?.("incident")}>
          {t("guide.link")}
        </button>
      </div>

      <section className="panel" aria-label={tr("Incident workflow overview")}>
        <div className="panel-heading">
          <span>{tr("Incident Workflow")}</span>
          <span className="panel-subtext">{tr("guided operational package")}</span>
        </div>
        <div className="microcopy">
          {tr("Assemble incident notes, prepared artifacts, hashes, and receiver-facing reporting into one local workflow package without leaving the browser.")}
        </div>
        <div className="controls-row" style={{ alignItems: "center" }}>
          <Chip label={tr(mode.label)} tone="accent" />
          <Chip label={`${previewPreparedArtifacts.length} ${tr("prepared artifacts")}`} tone="muted" />
          <Chip label={protectAtExport ? tr("NULLID:ENC:1 at export") : tr("unsigned package")} tone={protectAtExport ? "accent" : "muted"} />
        </div>
      </section>

      <div className="grid-two">
        <section className="panel" aria-label={tr("Incident context")}>
          <div className="panel-heading">
            <span>{tr("1. Define context")}</span>
            <span className="panel-subtext">{tr("purpose and receiver scope")}</span>
          </div>
          <input
            className="input"
            aria-label={tr("Incident title")}
            placeholder={tr("Incident title")}
            value={incidentTitle}
            onChange={(event) => setIncidentTitle(event.target.value)}
          />
          <div className="controls-row">
            <input
              className="input"
              aria-label={tr("Incident case reference")}
              placeholder={tr("Case reference (optional)")}
              value={caseReference}
              onChange={(event) => setCaseReference(event.target.value)}
            />
            <input
              className="input"
              aria-label={tr("Incident recipient scope")}
              placeholder={tr("Recipient scope (optional)")}
              value={recipientScope}
              onChange={(event) => setRecipientScope(event.target.value)}
            />
          </div>
          <input
            className="input"
            aria-label={tr("Incident purpose")}
            placeholder={tr("Package purpose")}
            value={purpose}
            onChange={(event) => setPurpose(event.target.value)}
          />
          <textarea
            className="textarea"
            aria-label={tr("Incident summary")}
            placeholder={tr("Short incident summary for the receiver")}
            value={summaryText}
            onChange={(event) => setSummaryText(event.target.value)}
          />
        </section>

        <section className="panel" aria-label={tr("Incident mode")}>
          <div className="panel-heading">
            <span>{tr("2. Choose mode")}</span>
            <span className="panel-subtext">{tr("preset and handling posture")}</span>
          </div>
          <div className="pill-buttons" role="group" aria-label={tr("Incident workflow mode chooser")}>
            {incidentWorkflowModeIds.map((id) => (
              <button key={id} type="button" className={modeId === id ? "active" : ""} onClick={() => setModeId(id)}>
                {getIncidentWorkflowMode(id).label}
              </button>
            ))}
          </div>
          <div className="microcopy">{tr(mode.description)}</div>
          <ul className="microcopy">
            {mode.guidance.map((line) => (
              <li key={line}>{tr(line)}</li>
            ))}
          </ul>
          <label className="microcopy" htmlFor="incident-policy-pack">
            {tr("Optional sanitize policy pack")}
            <select
              id="incident-policy-pack"
              className="select"
              aria-label={tr("Incident policy pack")}
              value={selectedPolicyId}
              onChange={(event) => setSelectedPolicyId(event.target.value)}
            >
              <option value="">{tr("Use the workflow mode only")}</option>
              {policyPacks.map((pack) => (
                <option key={pack.id} value={pack.id}>
                  {pack.name}
                </option>
              ))}
            </select>
          </label>
          <label className="microcopy">
            <input
              type="checkbox"
              checked={includeSourceReference}
              onChange={(event) => setIncludeSourceReference(event.target.checked)}
              style={{ marginRight: "0.45rem" }}
            />
            {tr("Include source references (hash + label, not original bytes) where possible")}
          </label>
          <label className="microcopy">
            <input
              type="checkbox"
              checked={applyMetadataClean}
              onChange={(event) => setApplyMetadataClean(event.target.checked)}
              style={{ marginRight: "0.45rem" }}
            />
            {tr("Apply local metadata cleanup when supported")}
          </label>
          <label className="microcopy">
            <input
              type="checkbox"
              checked={protectAtExport}
              onChange={(event) => setProtectAtExport(event.target.checked)}
              style={{ marginRight: "0.45rem" }}
            />
            {tr("Wrap the exported incident package in a NULLID:ENC:1 envelope")}
          </label>
          {protectAtExport ? (
            <input
              className="input"
              aria-label={tr("Incident export passphrase")}
              type="password"
              placeholder={tr("Envelope passphrase")}
              value={exportPassphrase}
              onChange={(event) => setExportPassphrase(event.target.value)}
            />
          ) : null}
        </section>
      </div>

      <div className="grid-two">
        <section className="panel" aria-label={tr("Case notes")}>
          <div className="panel-heading">
            <span>{tr("3. Prepare notes")}</span>
            <span className="panel-subtext">{tr("sanitized case context")}</span>
          </div>
          <div className="controls-row">
            <button className="button" type="button" onClick={() => {
              setIncidentTitle((prev) => prev || buildIncidentTemplateTitle());
              setNotesText(INCIDENT_TEMPLATE_BODY);
            }}>
              {tr("use incident note template")}
            </button>
            <Chip label={`${notesPreview.applied.length} ${tr("rules applied")}`} tone={notesPreview.applied.length > 0 ? "accent" : "muted"} />
            <Chip label={`${notesPreview.linesAffected} ${tr("lines changed")}`} tone="muted" />
          </div>
          <div className="microcopy">{tr("Uses the same incident note headings that are available in Secure Notes, but prepares them for export rather than local vault storage.")}</div>
          <textarea
            className="textarea"
            aria-label={tr("Incident notes")}
            placeholder={tr("Case notes to include in the incident package")}
            value={notesText}
            onChange={(event) => setNotesText(event.target.value)}
          />
          <div className="panel-subtext">{tr("Detected note findings")}</div>
          <ul className="microcopy">
            {notesFindings.length > 0
              ? notesFindings.map((entry) => <li key={`${entry.label}:${entry.count}`}>{tr(entry.label)}: {entry.count}</li>)
              : <li>{tr("No note findings were recorded yet.")}</li>}
          </ul>
          <div className="panel-subtext">{tr("Prepared note preview")}</div>
          <pre className="log-preview" aria-label={tr("Incident note preview")}>
            {notesPreview.output || tr("nothing to preview")}
          </pre>
        </section>

        <section className="panel" aria-label={tr("Additional artifacts")}>
          <div className="panel-heading">
            <span>{tr("4. Add artifacts")}</span>
            <span className="panel-subtext">{tr("text snippets and files")}</span>
          </div>
          <div className="panel-subtext">{tr("Additional text artifact")}</div>
          <input
            className="input"
            aria-label={tr("Incident text artifact label")}
            placeholder={tr("Artifact label (for example auth-log-snippet.txt)")}
            value={textArtifactLabel}
            onChange={(event) => setTextArtifactLabel(event.target.value)}
          />
          <textarea
            className="textarea"
            aria-label={tr("Incident text artifact input")}
            placeholder={tr("Optional extra text snippet to include alongside the notes")}
            value={textArtifactInput}
            onChange={(event) => setTextArtifactInput(event.target.value)}
          />
          <div className="controls-row">
            <button className="button" type="button" onClick={addTextArtifact}>
              {tr("add text artifact")}
            </button>
            <button className="button" type="button" onClick={() => textArtifactFileRef.current?.click()}>
              {tr("load text file")}
            </button>
            <button className="button" type="button" onClick={() => {
              setTextArtifactLabel("");
              setTextArtifactInput("");
            }}>
              {tr("clear")}
            </button>
            <input
              ref={textArtifactFileRef}
              hidden
              type="file"
              aria-label={tr("Incident text artifact file")}
              accept={textInputAccept}
              onChange={(event) => void handleTextArtifactFile(event.target.files?.[0] ?? null)}
            />
          </div>
          {textArtifactInput.trim() ? (
            <ul className="microcopy">
              {draftTextFindings.length > 0
                ? draftTextFindings.map((entry) => <li key={`${entry.label}:${entry.count}`}>{tr(entry.label)}: {entry.count}</li>)
                : <li>{tr("No findings were detected in the current text artifact draft.")}</li>}
            </ul>
          ) : null}

          <div className="panel-subtext">{tr("File artifact")}</div>
          <div
            className="dropzone"
            role="button"
            tabIndex={0}
            aria-label={tr("Choose incident file artifact")}
            onClick={() => draftFileRef.current?.click()}
            onKeyDown={(event) => {
              if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                draftFileRef.current?.click();
              }
            }}
          >
            {draftFile ? `${draftFile.name} · ${formatNumber(draftFile.size)} ${tr("bytes")}` : tr("Choose a file artifact to analyze locally before adding")}
          </div>
          <div className="microcopy">{tr(draftFileMessage)}</div>
          <div className="controls-row">
            <button className="button" type="button" onClick={() => draftFileRef.current?.click()}>
              {tr("load file")}
            </button>
            <button className="button" type="button" onClick={addFileArtifact} disabled={!draftAnalysis || !draftSourceBytes}>
              {tr("add file artifact")}
            </button>
            <button className="button" type="button" onClick={clearDraftFile}>
              {tr("clear")}
            </button>
            <input
              ref={draftFileRef}
              hidden
              type="file"
              aria-label={tr("Incident file artifact")}
              onChange={(event) => void handleDraftFile(event.target.files?.[0] ?? null)}
            />
          </div>
          <div className="controls-row" style={{ alignItems: "center" }}>
            {draftAnalysis ? (
              <>
                <Chip label={`${tr("risk")}: ${tr(draftAnalysis.risk)}`} tone={draftAnalysis.risk === "high" ? "danger" : draftAnalysis.risk === "medium" ? "accent" : "muted"} />
                <Chip label={`${tr("cleaner")}: ${tr(formatSanitizerLabel(draftAnalysis.recommendedSanitizer))}`} tone="muted" />
              </>
            ) : (
              <Chip label={isAnalyzingFile ? tr("analyzing...") : tr("waiting for file")} tone="muted" />
            )}
          </div>
          <ul className="microcopy">
            {draftAnalysis?.signals.length ? draftAnalysis.signals.map((signal) => (
              <li key={signal.id}>
                {signal.label}: {signal.detail}
              </li>
            )) : (
              <li>{draftAnalysis ? tr("No metadata risk signals were detected in the current scan window.") : tr("Load a file to inspect metadata signals.")}</li>
            )}
          </ul>
          {draftCleanActions.length ? (
            <>
              <div className="panel-subtext">{tr("Local cleanup actions")}</div>
              <ul className="microcopy">
                {draftCleanActions.map((line) => (
                  <li key={line}>{line}</li>
                ))}
              </ul>
            </>
          ) : null}
          {draftAnalysis?.commandHint ? <div className="microcopy">{draftAnalysis.commandHint}</div> : null}
        </section>
      </div>

      <section className="panel" aria-label={tr("Incident contents")}>
        <div className="panel-heading">
          <span>{tr("5. Review contents")}</span>
          <span className="panel-subtext">{tr("what will be assembled")}</span>
        </div>
        <table className="table">
          <thead>
            <tr>
              <th>{tr("Artifact")}</th>
              <th>{tr("Type")}</th>
              <th>{tr("Status")}</th>
              <th>{tr("Action")}</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>{tr("Case notes")}</td>
              <td>{tr("text")}</td>
              <td>{notesText.trim() ? tr("included") : tr("omitted")}</td>
              <td>
                <button className="button" type="button" onClick={() => setNotesText("")}>
                  {tr("clear")}
                </button>
              </td>
            </tr>
            {textArtifacts.map((item) => (
              <tr key={item.id}>
                <td>{item.label}</td>
                <td>{tr("text")}</td>
                <td>{tr("queued")}</td>
                <td>
                  <button
                    className="button"
                    type="button"
                    onClick={() => setTextArtifacts((prev) => prev.filter((entry) => entry.id !== item.id))}
                  >
                    {tr("remove")}
                  </button>
                </td>
              </tr>
            ))}
            {fileArtifacts.map((item) => (
              <tr key={item.id}>
                <td>{item.label}</td>
                <td>{tr("file")}</td>
                <td>{item.cleanedBytes && applyMetadataClean ? tr("cleanup ready") : tr("queued")}</td>
                <td>
                  <button
                    className="button"
                    type="button"
                    onClick={() => setFileArtifacts((prev) => prev.filter((entry) => entry.id !== item.id))}
                  >
                    {tr("remove")}
                  </button>
                </td>
              </tr>
            ))}
            {textArtifacts.length === 0 && fileArtifacts.length === 0 && !notesText.trim() ? (
              <tr>
                <td colSpan={4}>{tr("No incident content is queued yet.")}</td>
              </tr>
            ) : null}
          </tbody>
        </table>
        {previewPreparedArtifacts.length ? (
          <ul className="microcopy">
            {previewPreparedArtifacts.map((artifact) => (
              <li key={artifact.id}>
                {tr(artifact.label)}: {artifact.workflowPackage.artifacts.filter((entry) => entry.included).length} {tr("included entries")}, {artifact.workflowPackage.transforms?.length ?? 0} {tr("transform steps")}
              </li>
            ))}
          </ul>
        ) : null}
      </section>

      <div className="grid-two">
        <section className="panel" aria-label={tr("Incident package summary")}>
          <div className="panel-heading">
            <span>{tr("6. Package summary")}</span>
            <span className="panel-subtext">{tr("receiver-facing overview")}</span>
          </div>
          {previewPackage ? (
            <>
              <div className="controls-row" style={{ alignItems: "center" }}>
                <Chip label={previewPackage.workflowType} tone="muted" />
                {previewPackage.workflowPreset ? <Chip label={tr(previewPackage.workflowPreset.label)} tone="accent" /> : null}
                <Chip label={previewPackage.trust.packageSignature.method === "none" ? tr("unsigned") : previewPackage.trust.packageSignature.method} tone="muted" />
              </div>
              <div className="microcopy">{tr(previewPackage.summary.description)}</div>
              <table className="table">
                <tbody>
                  <tr>
                    <th>{tr("Workflow")}</th>
                    <td>{previewPackage.workflowType}</td>
                  </tr>
                  <tr>
                    <th>{tr("Artifacts")}</th>
                    <td>{previewPackage.artifacts.length}</td>
                  </tr>
                  <tr>
                    <th>{tr("Prepared entries")}</th>
                    <td>{previewPreparedArtifacts.length}</td>
                  </tr>
                  <tr>
                    <th>{tr("Manifest entries")}</th>
                    <td>{previewPackage.trust.artifactManifest.entryCount}</td>
                  </tr>
                  <tr>
                    <th>{tr("Protection")}</th>
                    <td>{protectAtExport ? tr("NULLID:ENC:1 envelope at export") : tr("plain workflow package JSON")}</td>
                  </tr>
                </tbody>
              </table>
              <ul className="microcopy">
                {previewPackage.summary.highlights.map((line) => (
                  <li key={line}>{line}</li>
                ))}
              </ul>
            </>
          ) : (
            <div className="microcopy">{isPreparingPreview ? tr("Preparing incident package preview...") : tr("Add notes or artifacts to prepare an incident package preview.")}</div>
          )}
          {previewError ? <div className="tag tag-danger">{previewError}</div> : null}
        </section>

        <section className="panel" aria-label={tr("Incident explainability")}>
          <div className="panel-heading">
            <span>{tr("7. Explainability")}</span>
            <span className="panel-subtext">{tr("what the package says and proves")}</span>
          </div>
          {previewPackage?.report ? (
            <>
              <table className="table">
                <tbody>
                  {previewPackage.report.purpose ? (
                    <tr>
                      <th>{tr("Purpose")}</th>
                      <td>{previewPackage.report.purpose}</td>
                    </tr>
                  ) : null}
                  {previewPackage.report.audience ? (
                    <tr>
                      <th>{tr("Audience")}</th>
                      <td>{previewPackage.report.audience}</td>
                    </tr>
                  ) : null}
                </tbody>
              </table>
              <div className="panel-subtext">{tr("Included artifacts")}</div>
              <ul className="microcopy">
                {previewPackage.report.includedArtifacts.map((line) => (
                  <li key={line}>{line}</li>
                ))}
              </ul>
              <div className="panel-subtext">{tr("What the receiver can verify")}</div>
              <ul className="microcopy">
                {previewPackage.report.receiverCanVerify.map((line) => (
                  <li key={line}>{line}</li>
                ))}
              </ul>
              <div className="panel-subtext">{tr("What the receiver cannot verify")}</div>
              <ul className="microcopy">
                {previewPackage.report.receiverCannotVerify.map((line) => (
                  <li key={line}>{line}</li>
                ))}
              </ul>
            </>
          ) : (
            <div className="microcopy">{tr("Incident explainability appears after the package preview is ready.")}</div>
          )}
        </section>
      </div>

      <div className="grid-two">
        <section className="panel" aria-label={tr("Warnings and limitations")}>
          <div className="panel-heading">
            <span>{tr("Warnings & limits")}</span>
            <span className="panel-subtext">{tr("honest trust language")}</span>
          </div>
          <ul className="microcopy">
            {previewPackage ? (
              [...previewPackage.warnings, ...previewPackage.limitations].map((line) => <li key={line}>{line}</li>)
            ) : (
              <li>{tr("Warnings and limitations appear after the incident package preview is ready.")}</li>
            )}
          </ul>
        </section>

        <section className="panel" aria-label={tr("Transform summary")}>
          <div className="panel-heading">
            <span>{tr("Transform summary")}</span>
            <span className="panel-subtext">{tr("recorded workflow steps")}</span>
          </div>
          {previewPackage?.transforms?.length ? (
            <table className="table">
              <thead>
                <tr>
                  <th>{tr("Transform")}</th>
                  <th>{tr("Summary")}</th>
                </tr>
              </thead>
              <tbody>
                {previewPackage.transforms.map((transform) => (
                  <tr key={transform.id}>
                    <td>{transform.label}</td>
                    <td>{transform.summary}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="microcopy">{tr("Transform details appear after the incident package preview is ready.")}</div>
          )}
        </section>
      </div>

      <section className="panel" aria-label={tr("Incident export")}>
        <div className="panel-heading">
          <span>{tr("8. Export package")}</span>
          <span className="panel-subtext">{tr("receiver-friendly incident artifact")}</span>
        </div>
        <div className="microcopy">
          {tr("Export once the context, transforms, warnings, and protection level look right. The receiver can inspect the package locally in Verify Package or with `package-inspect`.")}
        </div>
        <div className="controls-row">
          <button className="button" type="button" onClick={() => void exportPackage()} disabled={isExporting || !previewPackage}>
            {isExporting ? tr("exporting...") : protectAtExport ? tr("export protected package") : tr("export package")}
          </button>
        </div>
      </section>
    </div>
  );
}

function formatSanitizerLabel(value: MetadataAnalysisResult["recommendedSanitizer"]) {
  if (value === "browser-image") return "browser image clean";
  if (value === "browser-pdf") return "browser pdf clean";
  if (value === "mat2") return "external offline clean";
  return "analysis only";
}

function buildLocalId(prefix: string, index: number) {
  return `${prefix}-${Date.now().toString(36)}-${index + 1}`;
}

function buildIncidentExportFileName(value: string) {
  return `${sanitizeStem(value)}-nullid-incident`;
}

function sanitizeStem(value: string) {
  return value
    .trim()
    .replace(/\.[^.]+$/u, "")
    .replace(/[^a-z0-9_-]+/giu, "-")
    .replace(/-{2,}/gu, "-")
    .replace(/^-+|-+$/gu, "")
    || "nullid-incident";
}

function downloadBlob(blob: Blob, fileName: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = fileName;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}
