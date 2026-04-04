import { useMemo, useRef, useState } from "react";
import "./styles.css";
import { Chip } from "../components/Chip";
import type { ModuleKey } from "../components/ModuleList";
import { useToast } from "../components/ToastHost";
import { usePersistentState } from "../hooks/usePersistentState";
import { useI18n } from "../i18n";
import { applyRedaction, defaultRuleSetState, type RedactionRuleSet } from "../utils/redaction.js";
import { queueRedactionDraft } from "../utils/redactionTransfer.js";
import { analyzeStructuredText, type StructuredFindingCategory } from "../utils/structuredTextAnalyzer.js";

interface StructuredTextAnalyzerViewProps {
  onOpenGuide?: (key?: ModuleKey) => void;
  onSelectModule?: (key: ModuleKey) => void;
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

const categories: StructuredFindingCategory[] = ["emails", "phones", "urls", "ids", "financial", "secrets"];

export function StructuredTextAnalyzerView({ onOpenGuide, onSelectModule }: StructuredTextAnalyzerViewProps) {
  const { push } = useToast();
  const { locale, t, tr, formatNumber } = useI18n();
  const fileRef = useRef<HTMLInputElement>(null);
  const [input, setInput] = useState("");
  const [cleanOutput, setCleanOutput] = useState("");
  const [ruleSetState, setRuleSetState] = usePersistentState<Record<Exclude<RedactionRuleSet, "general">, boolean>>(
    "nullid:analyze:rule-sets",
    defaultRuleSetState(),
  );

  const result = useMemo(
    () =>
      analyzeStructuredText(input, {
        enabledRuleSets: ruleSetState,
      }),
    [input, ruleSetState],
  );
  const previewOutput = useMemo(() => applyRedaction(input, result.redactionMatches, "full"), [input, result.redactionMatches]);

  const handleLoadFile = async (file?: File | null) => {
    if (!file) return;
    try {
      setInput(await file.text());
      setCleanOutput("");
      push(`loaded ${file.name}`, "accent");
    } catch (error) {
      console.error(error);
      push("text file load failed", "danger");
    }
  };

  const handleApply = () => {
    setCleanOutput(previewOutput);
    push("structured analysis redaction applied", "accent");
  };

  const handleSendToRedaction = () => {
    queueRedactionDraft({
      text: input,
      matches: result.redactionMatches,
      message: "structured analysis sent to text redaction",
    });
    onSelectModule?.("redact");
  };

  const exportReport = () => {
    const payload = {
      schemaVersion: 1,
      kind: "nullid-structured-text-analysis",
      locale,
      createdAt: new Date().toISOString(),
      title: tr("Structured analysis report"),
      summary: [
        { label: tr("Total findings"), value: result.total },
        { label: tr("Iran / Persian rules"), value: result.countsByRuleSet.iran },
        { label: tr("Russia rules"), value: result.countsByRuleSet.russia },
      ],
      sections: [
        {
          id: "counts-by-category",
          label: tr("Counts by category"),
          items: categories.map((category) => ({
            label: tr(labelForCategory(category)),
            value: result.countsByCategory[category],
          })),
        },
        {
          id: "regional-groups",
          label: tr("Regional detection summary"),
          items: result.regionGroups.map((group) => ({
            label: formatRuleSetLabel(group.ruleSet),
            value: group.total,
            findings: group.findings.map((finding) => tr(finding.label)),
          })),
        },
        {
          id: "findings",
          label: tr("Findings"),
          items: result.findings.map((finding) => ({
            category: tr(labelForCategory(finding.category)),
            type: tr(finding.label),
            confidence: tr(finding.confidence),
            evidence: tr(finding.detectionKind),
            ruleSet: finding.ruleSet === "general" ? tr("general") : formatRuleSetLabel(finding.ruleSet),
            reason: tr(finding.reason),
            preview: finding.preview,
          })),
        },
      ],
      notes: result.notes.map((line) => tr(line)),
    };
    downloadBlob(new Blob([`${JSON.stringify(payload, null, 2)}\n`], { type: "application/json" }), `nullid-structured-analysis-${Date.now()}.json`);
    push("structured analysis report exported", "accent");
  };

  const downloadCleanText = () => {
    downloadBlob(new Blob([cleanOutput || previewOutput], { type: "text/plain;charset=utf-8" }), "structured-analysis-clean.txt");
  };

  return (
    <div className="workspace-scroll">
      <div className="guide-link">
        <button type="button" className="guide-link-button" onClick={() => onOpenGuide?.("analyze")}>
          {t("guide.link")}
        </button>
      </div>

      <div className="grid-two">
        <section className="panel" aria-label={tr("Structured analyzer input")}>
          <div className="panel-heading">
            <span>{tr("Structured Text Analyzer")}</span>
            <span className="panel-subtext">{tr("grouped local review")}</span>
          </div>
          <div className="microcopy">
            {tr("This tool groups likely sensitive findings locally so you can review emails, phones, URLs, IDs, likely secrets, and optional regional patterns before sharing.")}
          </div>
          <textarea
            className="textarea"
            aria-label={tr("Structured analyzer input")}
            placeholder={tr("Paste text, notes, exports, logs, or messages you want to analyze locally")}
            value={input}
            onChange={(event) => setInput(event.target.value)}
          />
          <div className="controls-row">
            <button className="button" type="button" onClick={() => fileRef.current?.click()}>
              {tr("load text file")}
            </button>
            <button className="button" type="button" onClick={() => {
              setInput("");
              setCleanOutput("");
            }}>
              {tr("clear")}
            </button>
            <input
              ref={fileRef}
              hidden
              type="file"
              accept={textInputAccept}
              aria-label={tr("Structured analyzer file")}
              onChange={(event) => void handleLoadFile(event.target.files?.[0] ?? null)}
            />
          </div>
          <div className="controls-row">
            <span className="section-title">{tr("Regional rule sets")}</span>
            {(["iran", "russia"] as Array<Exclude<RedactionRuleSet, "general">>).map((ruleSet) => (
              <label key={ruleSet} className="microcopy" style={{ display: "flex", alignItems: "center", gap: "0.35rem" }}>
                <input
                  type="checkbox"
                  checked={ruleSetState[ruleSet]}
                  onChange={(event) => setRuleSetState((prev) => ({ ...prev, [ruleSet]: event.target.checked }))}
                />
                {formatRuleSetLabel(ruleSet)}
              </label>
            ))}
          </div>
          <div className="microcopy">
            {tr("Regional detectors remain opt-in and conservative. Treat them as review aids, not proofs of correctness.")}
          </div>
        </section>

        <section className="panel" aria-label={tr("Structured analyzer output")}>
          <div className="panel-heading">
            <span>{tr("Analysis summary")}</span>
            <span className="panel-subtext">{tr("counts and clean-text preview")}</span>
          </div>
          <div className="controls-row" style={{ alignItems: "center" }}>
            {categories.map((category) => (
              <Chip key={category} label={`${tr(labelForCategory(category))}: ${formatNumber(result.countsByCategory[category])}`} tone={result.countsByCategory[category] > 0 ? "accent" : "muted"} />
            ))}
          </div>
          <div className="controls-row" style={{ alignItems: "center" }}>
            <Chip label={`${tr("Iran / Persian rules")}: ${formatNumber(result.countsByRuleSet.iran)}`} tone={result.countsByRuleSet.iran > 0 ? "accent" : "muted"} />
            <Chip label={`${tr("Russia rules")}: ${formatNumber(result.countsByRuleSet.russia)}`} tone={result.countsByRuleSet.russia > 0 ? "accent" : "muted"} />
          </div>
          <ul className="microcopy">
            {result.notes.map((line) => (
              <li key={line}>{tr(line)}</li>
            ))}
          </ul>
          <textarea className="textarea" readOnly aria-label={tr("Structured analyzer clean output")} value={cleanOutput || previewOutput} />
          <div className="controls-row">
            <button className="button" type="button" onClick={handleApply} disabled={!input.trim()}>
              {tr("apply redaction")}
            </button>
            <button className="button" type="button" onClick={handleSendToRedaction} disabled={!result.total}>
              {tr("send to redaction")}
            </button>
            <button className="button" type="button" onClick={downloadCleanText} disabled={!input.trim()}>
              {tr("download clean text")}
            </button>
            <button className="button" type="button" onClick={exportReport} disabled={!input.trim()}>
              {tr("export analysis report")}
            </button>
          </div>
        </section>
      </div>

      <div className="grid-two">
        {result.findingGroups.map((group) => (
          <section key={group.category} className="panel" aria-label={`${tr(labelForCategory(group.category))} ${tr("findings")}`}>
            <div className="panel-heading">
              <span>{tr(labelForCategory(group.category))}</span>
              <span className="panel-subtext">{formatNumber(group.total)} {tr("findings")}</span>
            </div>
            <ul className="microcopy">
              {group.findings.length > 0 ? (
                group.findings.slice(0, 12).map((finding) => (
                  <li key={`${finding.start}:${finding.end}:${finding.key}`}>
                    {finding.label}: {tr(finding.reason)} <code>{finding.preview}</code>
                  </li>
                ))
              ) : (
                <li>{tr("No findings in this category yet.")}</li>
              )}
            </ul>
          </section>
        ))}
      </div>

      <div className="grid-two">
        {result.regionGroups.map((group) => (
          <section key={group.ruleSet} className="panel" aria-label={`${tr(formatRuleSetLabel(group.ruleSet))} ${tr("summary")}`}>
            <div className="panel-heading">
              <span>{tr(formatRuleSetLabel(group.ruleSet))}</span>
              <span className="panel-subtext">{formatNumber(group.total)} {tr("findings")}</span>
            </div>
            <ul className="microcopy">
              {group.findings.length > 0 ? (
                group.findings.map((finding) => (
                  <li key={`${group.ruleSet}:${finding.start}:${finding.end}`}>{finding.label}: <code>{finding.preview}</code></li>
                ))
              ) : (
                <li>{tr("No optional regional findings are active in this rule set.")}</li>
              )}
            </ul>
          </section>
        ))}
      </div>
    </div>
  );
}

function labelForCategory(category: StructuredFindingCategory) {
  if (category === "emails") return "Emails";
  if (category === "phones") return "Phones";
  if (category === "urls") return "URLs";
  if (category === "ids") return "IDs";
  if (category === "financial") return "Financial identifiers";
  return "Likely secrets";
}

function formatRuleSetLabel(ruleSet: Exclude<RedactionRuleSet, "general">) {
  if (ruleSet === "iran") return "Iran / Persian rules";
  return "Russia rules";
}

function downloadBlob(blob: Blob, fileName: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = fileName;
  link.click();
  URL.revokeObjectURL(url);
}
