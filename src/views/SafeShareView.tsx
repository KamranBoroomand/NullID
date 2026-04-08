import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import "./styles.css";
import { Chip } from "../components/Chip";
import type { ModuleKey } from "../components/ModuleList";
import { useToast } from "../components/ToastHost";
import { usePersistentState } from "../hooks/usePersistentState";
import { useI18n } from "../i18n";
import { encryptText } from "../utils/cryptoEnvelope.js";
import { probeCanvasEncodeSupport, type OutputMime } from "../utils/imageFormats.js";
import { analyzeMetadataFromBuffer, type MetadataAnalysisResult } from "../utils/metadataAdvanced.js";
import { prepareLocalMetadataCleanup } from "../utils/localArtifactPreparation.js";
import { applySanitizeRules, type PolicyPack } from "../utils/sanitizeEngine.js";
import { analyzeFinancialIdentifiers } from "../utils/financialReview.js";
import { analyzePathPrivacy } from "../utils/pathPrivacy.js";
import {
  buildSafeShareSanitizeConfig,
  classifyTextForSafeShare,
  createSafeShareFileWorkflowPackage,
  createSafeShareTextWorkflowPackage,
  formatShareClassLabel,
  getSafeSharePreset,
  resolveSafeShareAnalysisRuleSets,
  safeSharePresetIds,
  summarizeSanitizeFindings,
  type SafeSharePresetId,
} from "../utils/safeShareAssistant.js";
import { buildWorkflowReviewDashboard } from "../utils/workflowReview.js";
import { consumeSafeShareWorkflowDraft } from "../utils/workflowDraftTransfer.js";
import type { WorkflowPackage } from "../utils/workflowPackage.js";

type ShareMode = "text" | "file";

interface SafeShareViewProps {
  onOpenGuide?: (key?: ModuleKey) => void;
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

export function SafeShareView({ onOpenGuide }: SafeShareViewProps) {
  const { push } = useToast();
  const { t, tr, formatNumber } = useI18n();
  const [mode, setMode] = usePersistentState<ShareMode>("nullid:share:mode", "text");
  const [presetId, setPresetId] = usePersistentState<SafeSharePresetId>("nullid:share:preset", "general-safe-share");
  const [policyPacks] = usePersistentState<PolicyPack[]>("nullid:sanitize:policy-packs", []);
  const [selectedPolicyId, setSelectedPolicyId] = usePersistentState<string>("nullid:share:policy-id", "");
  const [textInput, setTextInput] = usePersistentState<string>("nullid:share:text-input", "");
  const [textSourceLabel, setTextSourceLabel] = usePersistentState<string>("nullid:share:text-source-label", "");
  const [includeSourceReference, setIncludeSourceReference] = usePersistentState<boolean>("nullid:share:include-source-reference", true);
  const [applyMetadataClean, setApplyMetadataClean] = usePersistentState<boolean>("nullid:share:apply-metadata-clean", true);
  const [protectAtExport, setProtectAtExport] = usePersistentState<boolean>("nullid:share:protect-export", false);
  const [exportPassphrase, setExportPassphrase] = useState("");
  const [shareFile, setShareFile] = useState<File | null>(null);
  const [sourceBytes, setSourceBytes] = useState<Uint8Array | null>(null);
  const [analysis, setAnalysis] = useState<MetadataAnalysisResult | null>(null);
  const [cleanedBytes, setCleanedBytes] = useState<Uint8Array | null>(null);
  const [cleanedMediaType, setCleanedMediaType] = useState<string>("");
  const [cleanedLabel, setCleanedLabel] = useState<string>("");
  const [cleanActions, setCleanActions] = useState<string[]>([]);
  const [fileMessage, setFileMessage] = useState("load a file to analyze local metadata and packaging options");
  const [isAnalyzingFile, setIsAnalyzingFile] = useState(false);
  const [isPreparingPreview, setIsPreparingPreview] = useState(false);
  const [previewPackage, setPreviewPackage] = useState<WorkflowPackage | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [isExporting, setIsExporting] = useState(false);
  const [outputSupport, setOutputSupport] = useState<Record<OutputMime, boolean> | null>(null);
  const textFileRef = useRef<HTMLInputElement>(null);
  const shareFileRef = useRef<HTMLInputElement>(null);

  const preset = getSafeSharePreset(presetId);
  const selectedPolicy = useMemo(
    () => policyPacks.find((pack) => pack.id === selectedPolicyId) ?? null,
    [policyPacks, selectedPolicyId],
  );
  const textPolicy = useMemo(() => buildSafeShareSanitizeConfig(presetId, selectedPolicy), [presetId, selectedPolicy]);
  const analysisRuleSets = useMemo(() => resolveSafeShareAnalysisRuleSets(presetId), [presetId]);
  const textPreview = useMemo(
    () => applySanitizeRules(textInput, textPolicy.rulesState, textPolicy.customRules, textPolicy.jsonAware),
    [textInput, textPolicy],
  );
  const textFindings = useMemo(() => summarizeSanitizeFindings(textPreview.report).slice(0, 8), [textPreview.report]);
  const textFinancialReview = useMemo(
    () => analyzeFinancialIdentifiers(textInput, { enabledRuleSets: analysisRuleSets }),
    [analysisRuleSets, textInput],
  );
  const filePathPrivacy = useMemo(
    () => (shareFile ? analyzePathPrivacy(shareFile.name) : null),
    [shareFile],
  );
  const shareClass = useMemo(
    () => (mode === "text" ? formatShareClassLabel(classifyTextForSafeShare(textInput)) : analysis ? formatShareClassLabelForFile(analysis) : "pending input"),
    [analysis, mode, textInput],
  );
  const producer = useMemo(
    () => ({
      app: "NullID" as const,
      surface: "web" as const,
      module: "share",
      buildId: typeof import.meta.env.VITE_BUILD_ID === "string" && import.meta.env.VITE_BUILD_ID.trim() ? import.meta.env.VITE_BUILD_ID.trim() : null,
    }),
    [],
  );
  const reviewDashboard = useMemo(
    () => (previewPackage ? buildWorkflowReviewDashboard(previewPackage) : null),
    [previewPackage],
  );

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
      } catch (error) {
        console.error("safe-share output support failed", error);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const refreshFileCleanup = useCallback(
    async (file: File, nextAnalysis: MetadataAnalysisResult) => {
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
      } catch (error) {
        console.error(error);
        setFileMessage(error instanceof Error ? error.message : "local cleanup failed");
      }
    },
    [applyMetadataClean, outputSupport],
  );

  const handleTextFile = useCallback(
    async (file?: File | null) => {
      if (!file) return;
      try {
        setMode("text");
        setTextInput(await file.text());
        setTextSourceLabel(file.name);
        push(`loaded ${file.name}`, "accent");
      } catch (error) {
        console.error(error);
        push("text file load failed", "danger");
      }
    },
    [push, setMode, setTextInput, setTextSourceLabel],
  );

  const handleShareFile = useCallback(
    async (file?: File | null) => {
      if (!file) return;
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
      } catch (error) {
        console.error(error);
        setFileMessage(error instanceof Error ? error.message : "file analysis failed");
        push("file analysis failed", "danger");
      } finally {
        setIsAnalyzingFile(false);
      }
    },
    [push, refreshFileCleanup, setMode],
  );

  const buildPreviewPackage = useCallback(async () => {
    if (mode === "text") {
      if (!textInput.trim()) return null;
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

    if (!shareFile || !sourceBytes || !analysis) return null;
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
    if (mode !== "file" || !shareFile || !analysis) return;
    void refreshFileCleanup(shareFile, analysis);
  }, [analysis, applyMetadataClean, mode, outputSupport, refreshFileCleanup, shareFile]);

  useEffect(() => {
    const draft = consumeSafeShareWorkflowDraft();
    if (!draft) return;
    if (draft.item.kind === "text") {
      setMode("text");
      setTextInput(draft.item.text);
      setTextSourceLabel(draft.item.label);
      push("batch selection imported into safe share", "accent");
      return;
    }
    const file = new File([draft.item.sourceBytes.slice().buffer as ArrayBuffer], draft.item.fileName, {
      type: draft.item.fileMediaType || "application/octet-stream",
    });
    void handleShareFile(file);
    push("batch selection imported into safe share", "accent");
  }, [handleShareFile, push, setMode, setTextInput, setTextSourceLabel]);

  useEffect(() => {
    let cancelled = false;
    setIsPreparingPreview(true);
    void (async () => {
      try {
        const next = await buildPreviewPackage();
        if (cancelled) return;
        setPreviewPackage(next);
        setPreviewError(null);
      } catch (error) {
        if (cancelled) return;
        console.error(error);
        setPreviewPackage(null);
        setPreviewError(error instanceof Error ? error.message : "preview preparation failed");
      } finally {
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
    } catch (error) {
      console.error(error);
      push("safe-share export failed", "danger");
    } finally {
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

  return (
    <div className="workspace-scroll">
      <div className="guide-link">
        <button type="button" className="guide-link-button" onClick={() => onOpenGuide?.("share")}>
          {t("guide.link")}
        </button>
      </div>

      <section className="panel" aria-label={tr("Safe Share overview")}>
        <div className="panel-heading">
          <span>{tr("Safe Share Assistant")}</span>
          <span className="panel-subtext">{tr("guided local export")}</span>
        </div>
        <div className="microcopy">
          {tr("Prepare text snippets or local files for sharing with reviewable transforms, honest trust labels, and receiver-friendly workflow packages.")}
        </div>
        <div className="controls-row" style={{ alignItems: "center" }}>
          <div className="pill-buttons" role="group" aria-label={tr("Safe share mode")}>
            <button type="button" className={mode === "text" ? "active" : ""} onClick={() => setMode("text")}>
              {tr("text")}
            </button>
            <button type="button" className={mode === "file" ? "active" : ""} onClick={() => setMode("file")}>
              {tr("file")}
            </button>
          </div>
          <Chip label={tr(preset.label)} tone="accent" />
          <Chip label={tr(shareClass)} tone="muted" />
          {previewPackage ? <Chip label={protectAtExport ? tr("NULLID:ENC:1 at export") : tr("unsigned package")} tone={protectAtExport ? "accent" : "muted"} /> : null}
        </div>
      </section>

      <div className="grid-two">
        <section className="panel" aria-label={tr("Safe share input")}>
          <div className="panel-heading">
            <span>{tr("1. Choose input")}</span>
            <span className="panel-subtext">{mode === "text" ? tr("text and logs") : tr("file artifacts")}</span>
          </div>
          {mode === "text" ? (
            <>
              <textarea
                className="textarea"
                aria-label={tr("Safe share input text")}
                placeholder={tr("Paste logs, snippets, or text you want to prepare for safe sharing")}
                value={textInput}
                onChange={(event) => setTextInput(event.target.value)}
              />
              <input
                className="input"
                aria-label={tr("Safe share source label")}
                placeholder={tr("Optional source label (for example incident.log or support-snippet.txt)")}
                value={textSourceLabel}
                onChange={(event) => setTextSourceLabel(event.target.value)}
              />
              <div className="controls-row">
                <button className="button" type="button" onClick={() => textFileRef.current?.click()}>
                  {tr("load text file")}
                </button>
                <button className="button" type="button" onClick={resetText}>
                  {tr("clear")}
                </button>
                <input
                  ref={textFileRef}
                  hidden
                  type="file"
                  aria-label={tr("Safe share text file")}
                  accept={textInputAccept}
                  onChange={(event) => void handleTextFile(event.target.files?.[0] ?? null)}
                />
              </div>
            </>
          ) : (
            <>
              <div
                className="dropzone"
                role="button"
                tabIndex={0}
                aria-label={tr("Choose file for safe sharing")}
                onClick={() => shareFileRef.current?.click()}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    shareFileRef.current?.click();
                  }
                }}
              >
                {shareFile ? `${shareFile.name} · ${formatNumber(shareFile.size)} bytes` : tr("Choose a file to analyze locally before packaging")}
              </div>
              <div className="microcopy">{tr(fileMessage)}</div>
              <div className="controls-row">
                <button className="button" type="button" onClick={() => shareFileRef.current?.click()}>
                  {tr("load file")}
                </button>
                <button className="button" type="button" onClick={resetFile}>
                  {tr("clear")}
                </button>
                <input
                  ref={shareFileRef}
                  hidden
                  type="file"
                  aria-label={tr("Safe share file")}
                  onChange={(event) => void handleShareFile(event.target.files?.[0] ?? null)}
                />
              </div>
            </>
          )}
        </section>

        <section className="panel" aria-label={tr("Safe share preset")}>
          <div className="panel-heading">
            <span>{tr("2. Choose workflow mode")}</span>
            <span className="panel-subtext">{tr("preset and context")}</span>
          </div>
          <div className="pill-buttons" role="group" aria-label={tr("Safe share preset chooser")}>
            {safeSharePresetIds.map((id) => (
              <button key={id} type="button" className={presetId === id ? "active" : ""} onClick={() => setPresetId(id)}>
                {tr(getSafeSharePreset(id).label)}
              </button>
            ))}
          </div>
          <div className="microcopy">{tr(preset.description)}</div>
          <ul className="microcopy">
            {preset.guidance.map((line) => (
              <li key={line}>{tr(line)}</li>
            ))}
          </ul>
          <div className="panel-subtext">{tr("Preset transparency")}</div>
          <ul className="microcopy">
            <li>{tr("Active sanitize rules")}: {preset.sanitizeRules.join(", ")}</li>
            <li>{tr("Region detectors")}: {Object.entries(analysisRuleSets).filter(([, enabled]) => enabled).map(([key]) => key).join(", ") || tr("none")}</li>
            <li>{tr("Checklist emphasis")}: {preset.reviewChecklistEmphasis.map((line) => tr(line)).join(" | ")}</li>
          </ul>
          {mode === "text" ? (
            <label className="microcopy" htmlFor="safe-share-policy-pack">
              {tr("Optional sanitize policy pack")}
              <select
                id="safe-share-policy-pack"
                className="select"
                aria-label={tr("Safe share policy pack")}
                value={selectedPolicyId}
                onChange={(event) => setSelectedPolicyId(event.target.value)}
              >
                <option value="">{tr("Use the workflow preset only")}</option>
                {policyPacks.map((pack) => (
                  <option key={pack.id} value={pack.id}>
                    {pack.name}
                  </option>
                ))}
              </select>
            </label>
          ) : null}
        </section>
      </div>

      <div className="grid-two">
        <section className="panel" aria-label={tr("Findings and transforms")}>
          <div className="panel-heading">
            <span>{tr("3. Review findings")}</span>
            <span className="panel-subtext">{mode === "text" ? tr("sanitize results") : tr("metadata signals")}</span>
          </div>
          {mode === "text" ? (
            <>
              <div className="controls-row" style={{ alignItems: "center" }}>
                <Chip label={`${formatNumber(textPreview.applied.length)} ${tr("rules applied")}`} tone={textPreview.applied.length > 0 ? "accent" : "muted"} />
                <Chip label={`${formatNumber(textPreview.linesAffected)} ${tr("lines changed")}`} tone="muted" />
                <Chip label={textPolicy.jsonAware ? tr("JSON-aware on") : tr("JSON-aware off")} tone="muted" />
              </div>
              <ul className="microcopy">
                {textFindings.length > 0 ? (
                  textFindings.map((entry) => <li key={`${entry.label}:${entry.count}`}>{entry.label}: {entry.count}</li>)
                ) : (
                  <li>{tr("No sanitize findings were recorded yet.")}</li>
                )}
              </ul>
              <div className="panel-subtext">{tr("Financial review")}</div>
              <ul className="microcopy">
                {textFinancialReview.findings.length > 0 ? (
                  textFinancialReview.findings.slice(0, 4).map((finding) => (
                    <li key={`${finding.start}:${finding.end}:${finding.key}`}>
                      {tr(finding.label)}: {tr(finding.reason)} <code>{finding.preview}</code>
                    </li>
                  ))
                ) : (
                  <li>{tr("No financial identifier findings were detected yet.")}</li>
                )}
              </ul>
              <div className="panel-subtext">{tr("Prepared output preview")}</div>
              <pre className="log-preview" aria-label={tr("Safe share output preview")}>
                {textPreview.output || tr("nothing to preview")}
              </pre>
            </>
          ) : (
            <>
              <div className="controls-row" style={{ alignItems: "center" }}>
                {analysis ? (
                  <>
                    <Chip label={`risk: ${analysis.risk}`} tone={analysis.risk === "high" ? "danger" : analysis.risk === "medium" ? "accent" : "muted"} />
                    <Chip label={`${tr("risk")}: ${tr(analysis.risk)}`} tone={analysis.risk === "high" ? "danger" : analysis.risk === "medium" ? "accent" : "muted"} />
                    <Chip label={`${tr("sanitizer")}: ${tr(formatSanitizerLabel(analysis.recommendedSanitizer))}`} tone="muted" />
                    <Chip label={shareFile ? `${formatNumber(shareFile.size)} ${tr("bytes")}` : tr("no file")} tone="muted" />
                  </>
                ) : (
                  <Chip label={isAnalyzingFile ? tr("analyzing...") : tr("waiting for file")} tone="muted" />
                )}
              </div>
              <ul className="microcopy">
                {analysis?.signals.length ? analysis.signals.map((signal) => (
                  <li key={signal.id}>
                    {tr(signal.label)}: {tr(signal.detail)}
                  </li>
                )) : (
                  <li>{analysis ? tr("No metadata risk signals were detected in the current scan window.") : tr("Load a file to inspect metadata signals.")}</li>
                )}
              </ul>
              {analysis?.guidance.length ? (
                <>
                  <div className="panel-subtext">{tr("Guidance")}</div>
                  <ul className="microcopy">
                    {analysis.guidance.map((line) => (
                      <li key={line}>{tr(line)}</li>
                    ))}
                  </ul>
                </>
              ) : null}
              {filePathPrivacy ? (
                <>
                  <div className="panel-subtext">{tr("Filename / path privacy")}</div>
                  <ul className="microcopy">
                    {filePathPrivacy.findings.length > 0 ? (
                      filePathPrivacy.findings.map((finding) => (
                        <li key={`${finding.key}:${finding.reason}`}>
                          {tr(finding.label)}: {tr(finding.reason)}
                        </li>
                      ))
                    ) : (
                      <li>{tr("No filename/path privacy hints were generated for the current file name.")}</li>
                    )}
                  </ul>
                </>
              ) : null}
              {cleanActions.length ? (
                <>
                  <div className="panel-subtext">{tr("Local cleanup actions")}</div>
                  <ul className="microcopy">
                    {cleanActions.map((line) => (
                      <li key={line}>{tr(line)}</li>
                    ))}
                  </ul>
                </>
              ) : null}
              {analysis?.commandHint ? <div className="microcopy">{analysis.commandHint}</div> : null}
            </>
          )}
        </section>

        <section className="panel" aria-label={tr("Safe share export settings")}>
          <div className="panel-heading">
            <span>{tr("4. Choose packaging")}</span>
            <span className="panel-subtext">{tr("protection and scope")}</span>
          </div>
          <label className="microcopy">
            <input
              type="checkbox"
              checked={includeSourceReference}
              onChange={(event) => setIncludeSourceReference(event.target.checked)}
              style={{ marginRight: "0.45rem" }}
            />
            {tr("Include a source reference (hash + filename/label, but not the original bytes) when possible")}
          </label>
          {mode === "file" ? (
            <label className="microcopy">
              <input
                type="checkbox"
                checked={applyMetadataClean}
                onChange={(event) => setApplyMetadataClean(event.target.checked)}
                style={{ marginRight: "0.45rem" }}
              />
              {tr("Apply local metadata cleanup when this file format supports it")}
            </label>
          ) : null}
          <label className="microcopy">
            <input
              type="checkbox"
              checked={protectAtExport}
              onChange={(event) => setProtectAtExport(event.target.checked)}
              style={{ marginRight: "0.45rem" }}
            />
            {tr("Wrap the exported package in a NULLID:ENC:1 envelope")}
          </label>
          {protectAtExport ? (
            <input
              className="input"
              aria-label={tr("Safe share export passphrase")}
              type="password"
              placeholder={tr("Envelope passphrase")}
              value={exportPassphrase}
              onChange={(event) => setExportPassphrase(event.target.value)}
            />
          ) : null}
          <ul className="microcopy">
            <li>{tr("Workflow packages record transforms, hashes, warnings, and limits for the receiver.")}</li>
            <li>{tr("NULLID:ENC:1 adds confidentiality and AES-GCM integrity for the exported file, not sender identity.")}</li>
            <li>{tr("Shared workflow packages are still unsigned unless a future contract version adds verifiable package signatures.")}</li>
          </ul>
        </section>
      </div>

      <div className="grid-two">
        <section className="panel" aria-label={tr("Package summary")}>
          <div className="panel-heading">
            <span>{tr("5. Review package summary")}</span>
            <span className="panel-subtext">{tr("what the receiver will get")}</span>
          </div>
          {previewPackage ? (
            <>
              <div className="controls-row" style={{ alignItems: "center" }}>
                <Chip label={previewPackage.workflowType} tone="muted" />
                {previewPackage.workflowPreset ? <Chip label={tr(previewPackage.workflowPreset.label)} tone="accent" /> : null}
                <Chip label={previewPackage.trust.packageSignature.method === "none" ? tr("unsigned") : tr(previewPackage.trust.packageSignature.method)} tone="muted" />
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
                  <li key={line}>{tr(line)}</li>
                ))}
              </ul>
            </>
          ) : (
            <div className="microcopy">{isPreparingPreview ? tr("Preparing package preview...") : tr("Add input to prepare a workflow package preview.")}</div>
          )}
          {previewError ? <div className="tag tag-danger">{tr(previewError)}</div> : null}
        </section>

        <section className="panel" aria-label={tr("Warnings and limitations")}>
          <div className="panel-heading">
            <span>{tr("Warnings & limits")}</span>
            <span className="panel-subtext">{tr("honest trust language")}</span>
          </div>
          <ul className="microcopy">
            {previewPackage ? (
              [...previewPackage.warnings, ...previewPackage.limitations].map((line) => <li key={line}>{tr(line)}</li>)
            ) : (
              <li>{tr("Warnings and limitations appear after the package preview is ready.")}</li>
            )}
          </ul>
        </section>
      </div>

      {previewPackage?.transforms?.length ? (
        <section className="panel" aria-label={tr("Transform summary")}>
          <div className="panel-heading">
            <span>{tr("Transform summary")}</span>
            <span className="panel-subtext">{tr("recorded workflow steps")}</span>
          </div>
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
                  <td>{tr(transform.label)}</td>
                  <td>{tr(transform.summary)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      ) : null}

      {reviewDashboard ? (
        <section className="panel" aria-label={tr("Workflow review dashboard")}>
          <div className="panel-heading">
            <span>{tr("Workflow review dashboard")}</span>
            <span className="panel-subtext">{tr("what is being shared before export")}</span>
          </div>
          <div className="grid-two">
            {reviewDashboard.sections.map((section) => (
              <div key={section.id}>
                <div className="panel-subtext">{tr(section.label)}</div>
                <ul className="microcopy">
                  {section.items.map((line) => (
                    <li key={`${section.id}:${line}`}>{localizeWorkflowLine(line, tr)}</li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </section>
      ) : null}

      <section className="panel" aria-label={tr("Safe share export")}>
        <div className="panel-heading">
          <span>{tr("6. Export package")}</span>
          <span className="panel-subtext">{tr("receiver-friendly artifact")}</span>
        </div>
        <div className="microcopy">
          {tr("Export the package when the findings, warnings, and protection level look right. The receiver can inspect it locally in Verify Package or with `package-inspect`.")}
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

function localizeWorkflowLine(line: string, tr: (value: string) => string): string {
  const trimmed = line.trim();
  if (!trimmed) return trimmed;
  if (trimmed.includes(" · ")) {
    return trimmed
      .split(" · ")
      .map((part) => localizeWorkflowLine(part, tr))
      .join(" · ");
  }
  const colonIndex = trimmed.indexOf(":");
  if (colonIndex > 0 && colonIndex < trimmed.length - 1) {
    const left = trimmed.slice(0, colonIndex).trim();
    const right = trimmed.slice(colonIndex + 1).trim();
    if (right) {
      return `${localizeWorkflowLine(left, tr)}: ${localizeWorkflowLine(right, tr)}`;
    }
  }
  const parenMatch = trimmed.match(/^(.*)\(([^()]*)\)$/u);
  if (parenMatch) {
    const prefix = parenMatch[1].trim();
    const suffix = parenMatch[2].trim();
    return `${localizeWorkflowLine(prefix, tr)} (${suffix})`;
  }
  return tr(trimmed);
}

function formatShareClassLabelForFile(analysis: MetadataAnalysisResult) {
  if (analysis.kind === "image") return "image";
  if (analysis.format === "pdf") return "pdf";
  if (analysis.format === "docx" || analysis.format === "xlsx" || analysis.format === "pptx") return "office document";
  if (analysis.kind === "video") return "video";
  if (analysis.kind === "archive") return "archive";
  return "unknown file";
}

function formatSanitizerLabel(value: MetadataAnalysisResult["recommendedSanitizer"]) {
  if (value === "browser-image") return "browser image clean";
  if (value === "browser-pdf") return "browser pdf clean";
  if (value === "mat2") return "external offline clean";
  return "analysis only";
}

function buildSafeShareExportFileName(mode: ShareMode, presetId: SafeSharePresetId, textSourceLabel: string, fileName?: string) {
  const stem = mode === "text"
    ? sanitizeStem(textSourceLabel || `safe-share-${presetId}`)
    : sanitizeStem(fileName || `safe-share-${presetId}`);
  return `${stem}-nullid-safe-share`;
}

function sanitizeStem(value: string) {
  return value
    .trim()
    .replace(/\.[^.]+$/u, "")
    .replace(/[^a-z0-9_-]+/giu, "-")
    .replace(/-{2,}/gu, "-")
    .replace(/^-+|-+$/gu, "")
    || "nullid-safe-share";
}

function downloadBlob(blob: Blob, fileName: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = fileName;
  link.click();
  URL.revokeObjectURL(url);
}
