import { useMemo, useState } from "react";
import "./styles.css";
import { Chip } from "../components/Chip";
import type { ModuleKey } from "../components/ModuleList";
import { useToast } from "../components/ToastHost";
import { useI18n } from "../i18n";
import { analyzePathPrivacy } from "../utils/pathPrivacy.js";

interface PathPrivacyViewProps {
  onOpenGuide?: (key?: ModuleKey) => void;
}

export function PathPrivacyView({ onOpenGuide }: PathPrivacyViewProps) {
  const { push } = useToast();
  const { locale, t, tr, formatNumber } = useI18n();
  const [input, setInput] = useState("");

  const analyses = useMemo(
    () => input.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).map((line) => analyzePathPrivacy(line)),
    [input],
  );
  const total = analyses.reduce((sum, item) => sum + item.total, 0);

  const exportReport = () => {
    const payload = {
      schemaVersion: 1,
      kind: "nullid-path-privacy-report",
      locale,
      createdAt: new Date().toISOString(),
      title: tr("Filename / path privacy report"),
      summary: [
        { label: tr("Paths reviewed"), value: analyses.length },
        { label: tr("Total findings"), value: total },
      ],
      sections: analyses.map((analysis) => ({
        id: analysis.normalizedPath,
        label: analysis.normalizedPath,
        items: analysis.findings.map((finding) => ({
          type: tr(finding.label),
          confidence: tr(finding.confidence),
          reason: tr(finding.reason),
          suggestedReplacement: finding.suggestedReplacement,
          preview: analysis.suggestions.find((item) => item.replacements.some((replacement) => replacement.replacement === finding.suggestedReplacement))?.preview ?? analysis.normalizedPath,
        })),
      })),
      notes: analyses.flatMap((analysis) => analysis.notes.map((note) => tr(note))),
    };
    downloadBlob(new Blob([`${JSON.stringify(payload, null, 2)}\n`], { type: "application/json" }), `nullid-path-privacy-${Date.now()}.json`);
    push("path privacy report exported", "accent");
  };

  return (
    <div className="workspace-scroll">
      <div className="guide-link">
        <button type="button" className="guide-link-button" onClick={() => onOpenGuide?.("paths")}>
          {t("guide.link")}
        </button>
      </div>

      <div className="grid-two">
        <section className="panel" aria-label={tr("Filename / path privacy input")}>
          <div className="panel-heading">
            <span>{tr("Filename / Path Privacy")}</span>
            <span className="panel-subtext">{tr("preview-only rename review")}</span>
          </div>
          <div className="microcopy">
            {tr("Paste one filename or path per line to review potentially sensitive names, employee IDs, case/ticket IDs, project labels, usernames, or hostnames. Suggestions are preview-only and never rename files automatically.")}
          </div>
          <textarea
            className="textarea"
            aria-label={tr("Filename / path privacy input")}
            placeholder={tr("Examples: /Users/alice/Incident-4921/customer-cards.csv or project-zephyr/support_ticket_4432.txt")}
            value={input}
            onChange={(event) => setInput(event.target.value)}
          />
          <div className="controls-row">
            <button className="button" type="button" onClick={() => setInput("")}>
              {tr("clear")}
            </button>
            <button className="button" type="button" onClick={exportReport} disabled={analyses.length === 0}>
              {tr("export review report")}
            </button>
          </div>
        </section>

        <section className="panel" aria-label={tr("Filename / path privacy summary")}>
          <div className="panel-heading">
            <span>{tr("Filename / path privacy summary")}</span>
            <span className="panel-subtext">{tr("flagged segments and preview suggestions")}</span>
          </div>
          <div className="controls-row" style={{ alignItems: "center" }}>
            <Chip label={`${formatNumber(analyses.length)} ${tr("items")}`} tone={analyses.length > 0 ? "accent" : "muted"} />
            <Chip label={`${formatNumber(total)} ${tr("findings")}`} tone={total > 0 ? "accent" : "muted"} />
          </div>
          <ul className="microcopy">
            {analyses.length > 0 ? analyses.flatMap((analysis) => analysis.notes).slice(0, 4).map((note) => (
              <li key={note}>{tr(note)}</li>
            )) : <li>{tr("Paste one or more filenames/paths to start the review.")}</li>}
          </ul>
        </section>
      </div>

      <section className="panel" aria-label={tr("Filename / path privacy findings")}>
        <div className="panel-heading">
          <span>{tr("Filename / path privacy findings")}</span>
          <span className="panel-subtext">{tr("why a segment may be sensitive")}</span>
        </div>
        {analyses.length === 0 ? (
          <div className="microcopy">{tr("No filename/path review items yet.")}</div>
        ) : (
          <div className="grid-two">
            {analyses.map((analysis) => (
              <div key={analysis.normalizedPath} className="panel" aria-label={analysis.normalizedPath}>
                <div className="panel-heading">
                  <span>{analysis.normalizedPath}</span>
                  <span className="panel-subtext">{formatNumber(analysis.total)} {tr("findings")}</span>
                </div>
                <ul className="microcopy">
                  {analysis.findings.length > 0 ? analysis.findings.map((finding) => (
                    <li key={`${analysis.normalizedPath}:${finding.key}:${finding.reason}`}>
                      {tr(finding.label)}: {tr(finding.reason)}
                    </li>
                  )) : <li>{tr("No privacy hints were generated for this path.")}</li>}
                </ul>
                <div className="panel-subtext">{tr("Preview rename suggestion")}</div>
                <pre className="log-preview">{analysis.suggestions[0]?.preview ?? analysis.normalizedPath}</pre>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}

function downloadBlob(blob: Blob, fileName: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = fileName;
  link.click();
  URL.revokeObjectURL(url);
}
