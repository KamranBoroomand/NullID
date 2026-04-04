import { useMemo, useRef, useState } from "react";
import "./styles.css";
import { Chip } from "../components/Chip";
import type { ModuleKey } from "../components/ModuleList";
import { useToast } from "../components/ToastHost";
import { usePersistentState } from "../hooks/usePersistentState";
import { useI18n } from "../i18n";
import { queueRedactionDraft } from "../utils/redactionTransfer.js";
import { applyRedaction, defaultRuleSetState, type RedactionRuleSet } from "../utils/redaction.js";
import { analyzeFinancialIdentifiers, type FinancialFindingCategory } from "../utils/financialReview.js";

interface FinancialReviewViewProps {
  onOpenGuide?: (key?: ModuleKey) => void;
  onSelectModule?: (key: ModuleKey) => void;
}

const textInputAccept = [
  ".txt",
  ".log",
  ".json",
  ".ndjson",
  ".csv",
  "text/plain",
  "application/json",
].join(",");

const categories: FinancialFindingCategory[] = ["bank-cards", "ibans", "accounts", "references"];

export function FinancialReviewView({ onOpenGuide, onSelectModule }: FinancialReviewViewProps) {
  const { push } = useToast();
  const { locale, t, tr, formatNumber } = useI18n();
  const fileRef = useRef<HTMLInputElement>(null);
  const [input, setInput] = useState("");
  const [output, setOutput] = useState("");
  const [ruleSetState, setRuleSetState] = usePersistentState<Record<Exclude<RedactionRuleSet, "general">, boolean>>(
    "nullid:financial:rule-sets",
    defaultRuleSetState(),
  );

  const result = useMemo(
    () => analyzeFinancialIdentifiers(input, { enabledRuleSets: ruleSetState }),
    [input, ruleSetState],
  );
  const previewOutput = useMemo(() => applyRedaction(input, result.redactionMatches, "full"), [input, result.redactionMatches]);

  const handleApply = () => {
    setOutput(previewOutput);
    push("financial review redaction applied", "accent");
  };

  const handleSendToRedaction = () => {
    queueRedactionDraft({
      text: input,
      matches: result.redactionMatches,
      message: "financial review findings sent to text redaction",
    });
    onSelectModule?.("redact");
  };

  const handleLoadFile = async (file?: File | null) => {
    if (!file) return;
    try {
      setInput(await file.text());
      setOutput("");
      push(`loaded ${file.name}`, "accent");
    } catch (error) {
      console.error(error);
      push("text file load failed", "danger");
    }
  };

  const exportReport = () => {
    const payload = {
      schemaVersion: 1,
      kind: "nullid-financial-review-report",
      locale,
      createdAt: new Date().toISOString(),
      title: tr("Financial review report"),
      summary: [
        { label: tr("Total findings"), value: result.total },
        ...categories.map((category) => ({ label: tr(labelForCategory(category)), value: result.countsByCategory[category] })),
      ],
      sections: [
        {
          id: "findings",
          label: tr("Detected"),
          items: result.findings.map((finding) => ({
            type: tr(finding.label),
            category: tr(labelForCategory(finding.category)),
            confidence: tr(finding.confidence),
            evidence: tr(finding.detectionKind),
            reason: tr(finding.reason),
            preview: finding.preview,
          })),
        },
        {
          id: "review-required",
          label: tr("Review required"),
          items: result.notes.map((note) => ({ value: tr(note) })),
        },
      ],
    };
    downloadBlob(new Blob([`${JSON.stringify(payload, null, 2)}\n`], { type: "application/json" }), `nullid-financial-review-${Date.now()}.json`);
    push("financial review report exported", "accent");
  };

  return (
    <div className="workspace-scroll">
      <div className="guide-link">
        <button type="button" className="guide-link-button" onClick={() => onOpenGuide?.("finance")}>
          {t("guide.link")}
        </button>
      </div>

      <div className="grid-two">
        <section className="panel" aria-label={tr("Financial review input")}>
          <div className="panel-heading">
            <span>{tr("Financial Identifier Review")}</span>
            <span className="panel-subtext">{tr("local banking-pattern review")}</span>
          </div>
          <div className="microcopy">
            {tr("This tool reviews bank-card numbers, IBAN or Sheba-like identifiers, account-like numbers, and invoice/reference patterns locally. It labels findings as pattern-based or likely and does not claim that any identifier is active or correctly attributed.")}
          </div>
          <textarea
            className="textarea"
            aria-label={tr("Financial review input")}
            placeholder={tr("Paste text, invoices, notes, payment references, or support logs you want to review locally")}
            value={input}
            onChange={(event) => setInput(event.target.value)}
          />
          <div className="controls-row">
            <button className="button" type="button" onClick={() => fileRef.current?.click()}>
              {tr("load text file")}
            </button>
            <button className="button" type="button" onClick={() => {
              setInput("");
              setOutput("");
            }}>
              {tr("clear")}
            </button>
            <input
              ref={fileRef}
              hidden
              type="file"
              accept={textInputAccept}
              aria-label={tr("Financial review file")}
              onChange={(event) => void handleLoadFile(event.target.files?.[0] ?? null)}
            />
          </div>
          <div className="controls-row">
            {(["iran", "russia"] as Array<Exclude<RedactionRuleSet, "general">>).map((ruleSet) => (
              <label key={ruleSet} className="microcopy" style={{ display: "flex", alignItems: "center", gap: "0.35rem" }}>
                <input
                  type="checkbox"
                  checked={ruleSetState[ruleSet]}
                  onChange={(event) => setRuleSetState((previous) => ({ ...previous, [ruleSet]: event.target.checked }))}
                />
                {ruleSet === "iran" ? tr("Iran / Persian rules") : tr("Russia rules")}
              </label>
            ))}
          </div>
        </section>

        <section className="panel" aria-label={tr("Financial review summary")}>
          <div className="panel-heading">
            <span>{tr("Financial review summary")}</span>
            <span className="panel-subtext">{tr("findings and redaction preview")}</span>
          </div>
          <div className="controls-row" style={{ alignItems: "center" }}>
            <Chip label={`${formatNumber(result.total)} ${tr("findings")}`} tone={result.total > 0 ? "accent" : "muted"} />
            {categories.map((category) => (
              <Chip key={category} label={`${tr(labelForCategory(category))}: ${formatNumber(result.countsByCategory[category])}`} tone={result.countsByCategory[category] > 0 ? "accent" : "muted"} />
            ))}
          </div>
          <ul className="microcopy">
            {result.notes.map((line) => (
              <li key={line}>{tr(line)}</li>
            ))}
          </ul>
          <textarea className="textarea" readOnly aria-label={tr("Financial review redacted output")} value={output || previewOutput} />
          <div className="controls-row">
            <button className="button" type="button" onClick={handleApply} disabled={!input.trim()}>
              {tr("apply redaction")}
            </button>
            <button className="button" type="button" onClick={handleSendToRedaction} disabled={!result.total}>
              {tr("send to redaction")}
            </button>
            <button className="button" type="button" onClick={exportReport} disabled={!input.trim()}>
              {tr("export review report")}
            </button>
          </div>
        </section>
      </div>

      <section className="panel" aria-label={tr("Financial review findings")}>
        <div className="panel-heading">
          <span>{tr("Financial review findings")}</span>
          <span className="panel-subtext">{tr("type / confidence / reason")}</span>
        </div>
        <table className="table">
          <thead>
            <tr>
              <th>{tr("type")}</th>
              <th>{tr("category")}</th>
              <th>{tr("confidence")}</th>
              <th>{tr("evidence")}</th>
              <th>{tr("reason")}</th>
              <th>{tr("preview")}</th>
            </tr>
          </thead>
          <tbody>
            {result.findings.length === 0 ? (
              <tr>
                <td colSpan={6} className="muted">{tr("No financial identifier findings detected yet.")}</td>
              </tr>
            ) : (
              result.findings.map((finding) => (
                <tr key={`${finding.start}:${finding.end}:${finding.key}`}>
                  <td>{tr(finding.label)}</td>
                  <td>{tr(labelForCategory(finding.category))}</td>
                  <td>{tr(finding.confidence)}</td>
                  <td>{tr(finding.detectionKind)}</td>
                  <td>{tr(finding.reason)}</td>
                  <td><code>{finding.preview}</code></td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </section>
    </div>
  );
}

function labelForCategory(category: FinancialFindingCategory) {
  if (category === "bank-cards") return "Bank cards";
  if (category === "ibans") return "IBAN / Sheba";
  if (category === "accounts") return "Account-like numbers";
  return "Invoice / reference numbers";
}

function downloadBlob(blob: Blob, fileName: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = fileName;
  link.click();
  URL.revokeObjectURL(url);
}
