import { useMemo, useRef, useState } from "react";
import "./styles.css";
import { Chip } from "../components/Chip";
import type { ModuleKey } from "../components/ModuleList";
import { useToast } from "../components/ToastHost";
import { usePersistentState } from "../hooks/usePersistentState";
import { useI18n } from "../i18n";
import { queueRedactionDraft } from "../utils/redactionTransfer.js";
import { applyRedaction } from "../utils/redaction.js";
import { scanSecrets, secretFindingsToRedactionMatches, type SecretScannerConfidence } from "../utils/secretScanner.js";

interface SecretScannerViewProps {
  onOpenGuide?: (key?: ModuleKey) => void;
  onSelectModule?: (key: ModuleKey) => void;
}

const textInputAccept = [
  ".txt",
  ".log",
  ".json",
  ".ndjson",
  ".env",
  ".yaml",
  ".yml",
  ".ini",
  "text/plain",
  "application/json",
].join(",");

export function SecretScannerView({ onOpenGuide, onSelectModule }: SecretScannerViewProps) {
  const { push } = useToast();
  const { locale, t, tr, formatNumber } = useI18n();
  const fileRef = useRef<HTMLInputElement>(null);
  const [input, setInput] = useState("");
  const [output, setOutput] = useState("");
  const [includeHeuristicCandidates, setIncludeHeuristicCandidates] = usePersistentState<boolean>("nullid:secret:heuristics", true);
  const [minCandidateLength, setMinCandidateLength] = usePersistentState<number>("nullid:secret:min-length", 20);

  const result = useMemo(
    () =>
      scanSecrets(input, {
        minCandidateLength,
        includeHeuristicCandidates,
      }),
    [includeHeuristicCandidates, input, minCandidateLength],
  );
  const redactionMatches = useMemo(() => secretFindingsToRedactionMatches(result.findings), [result.findings]);
  const previewOutput = useMemo(() => applyRedaction(input, redactionMatches, "full"), [input, redactionMatches]);

  const handleApply = () => {
    setOutput(previewOutput);
    push("secret scan redaction applied", "accent");
  };

  const handleSendToRedaction = () => {
    queueRedactionDraft({
      text: input,
      matches: redactionMatches,
      message: "structured findings sent to text redaction",
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
      kind: "nullid-secret-scan-report",
      locale,
      createdAt: new Date().toISOString(),
      title: tr("Secret scan report"),
      summary: [
        { label: tr("Total findings"), value: result.total },
        { label: tr("Heuristic candidates"), value: includeHeuristicCandidates ? tr("enabled") : tr("disabled") },
        { label: tr("Minimum candidate length"), value: minCandidateLength },
      ],
      sections: [
        {
          id: "counts",
          label: tr("Counts by type"),
          items: Object.entries(result.byType).map(([label, count]) => ({
            label: tr(label),
            value: count,
            confidence: tr(result.confidenceByType[label] ?? "low"),
          })),
        },
        {
          id: "findings",
          label: tr("Likely secret findings"),
          items: result.findings.map((finding) => ({
            type: tr(finding.label),
            confidence: tr(finding.confidence),
            evidence: tr(finding.evidence),
            reason: tr(finding.reason),
            preview: finding.preview,
            range: `${finding.start}-${finding.end}`,
          })),
        },
      ],
      notes: result.notes.map((line) => tr(line)),
    };
    downloadBlob(new Blob([`${JSON.stringify(payload, null, 2)}\n`], { type: "application/json" }), `nullid-secret-scan-${Date.now()}.json`);
    push("secret scan report exported", "accent");
  };

  const downloadRedacted = () => {
    downloadBlob(new Blob([output || previewOutput], { type: "text/plain;charset=utf-8" }), "secret-scanned-redacted.txt");
  };

  return (
    <div className="workspace-scroll">
      <div className="guide-link">
        <button type="button" className="guide-link-button" onClick={() => onOpenGuide?.("secret")}>
          {t("guide.link")}
        </button>
      </div>

      <div className="grid-two">
        <section className="panel" aria-label={tr("Secret scanner input")}>
          <div className="panel-heading">
            <span>{tr("Secret Scanner")}</span>
            <span className="panel-subtext">{tr("pattern-based likely secret review")}</span>
          </div>
          <div className="microcopy">
            {tr("This scanner stays local and reports pattern-based / likely secret findings only. It does not guarantee a string is truly active or valid.")}
          </div>
          <textarea
            className="textarea"
            aria-label={tr("Secret scanner input")}
            placeholder={tr("Paste text, config snippets, headers, logs, or token dumps you want to inspect locally")}
            value={input}
            onChange={(event) => setInput(event.target.value)}
          />
          <div className="controls-row">
            <label className="microcopy" style={{ display: "flex", alignItems: "center", gap: "0.35rem" }}>
              <input
                type="checkbox"
                checked={includeHeuristicCandidates}
                onChange={(event) => setIncludeHeuristicCandidates(event.target.checked)}
              />
              {tr("Include heuristic high-entropy candidates")}
            </label>
            <label className="microcopy" htmlFor="secret-min-length">
              {tr("Minimum candidate length")}
            </label>
            <input
              id="secret-min-length"
              className="input"
              type="number"
              min={12}
              max={120}
              value={minCandidateLength}
              onChange={(event) => setMinCandidateLength(clamp(Number(event.target.value) || 0, 12, 120))}
            />
          </div>
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
              aria-label={tr("Secret scanner file")}
              onChange={(event) => void handleLoadFile(event.target.files?.[0] ?? null)}
            />
          </div>
        </section>

        <section className="panel" aria-label={tr("Secret scanner summary")}>
          <div className="panel-heading">
            <span>{tr("Secret scan summary")}</span>
            <span className="panel-subtext">{tr("findings and redaction preview")}</span>
          </div>
          <div className="controls-row" style={{ alignItems: "center" }}>
            <Chip label={`${formatNumber(result.total)} ${tr("findings")}`} tone={result.total > 0 ? "accent" : "muted"} />
            <Chip label={includeHeuristicCandidates ? tr("heuristics on") : tr("heuristics off")} tone="muted" />
          </div>
          <ul className="microcopy">
            {result.notes.map((line) => (
              <li key={line}>{tr(line)}</li>
            ))}
          </ul>
          <textarea className="textarea" readOnly aria-label={tr("Secret scanner redacted output")} value={output || previewOutput} />
          <div className="controls-row">
            <button className="button" type="button" onClick={handleApply} disabled={!input.trim()}>
              {tr("apply redaction")}
            </button>
            <button className="button" type="button" onClick={handleSendToRedaction} disabled={!result.total}>
              {tr("send to redaction")}
            </button>
            <button className="button" type="button" onClick={downloadRedacted} disabled={!input.trim()}>
              {tr("download clean text")}
            </button>
            <button className="button" type="button" onClick={exportReport} disabled={!input.trim()}>
              {tr("export scan report")}
            </button>
          </div>
        </section>
      </div>

      <section className="panel" aria-label={tr("Secret findings")}>
        <div className="panel-heading">
          <span>{tr("Likely secret findings")}</span>
          <span className="panel-subtext">{tr("type / confidence / reason")}</span>
        </div>
        <table className="table">
          <thead>
            <tr>
              <th>{tr("type")}</th>
              <th>{tr("confidence")}</th>
              <th>{tr("evidence")}</th>
              <th>{tr("reason")}</th>
              <th>{tr("preview")}</th>
            </tr>
          </thead>
          <tbody>
            {result.findings.length === 0 ? (
              <tr>
                <td colSpan={5} className="muted">
                  {tr("No likely secret findings detected yet.")}
                </td>
              </tr>
            ) : (
              result.findings.map((finding) => (
                <tr key={`${finding.start}:${finding.end}:${finding.key}`}>
                  <td>{tr(finding.label)}</td>
                  <td>
                    <Chip label={tr(finding.confidence)} tone={toneForConfidence(finding.confidence)} />
                  </td>
                  <td>{tr(finding.evidence)}</td>
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

function toneForConfidence(value: SecretScannerConfidence) {
  if (value === "high") return "danger" as const;
  if (value === "medium") return "accent" as const;
  return "muted" as const;
}

function clamp(value: number, min: number, max: number) {
  return Math.min(max, Math.max(min, value));
}

function downloadBlob(blob: Blob, fileName: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = fileName;
  link.click();
  URL.revokeObjectURL(url);
}
