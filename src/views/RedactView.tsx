import { useEffect, useMemo, useState, type ReactNode } from "react";
import "./styles.css";
import { Chip } from "../components/Chip";
import { useToast } from "../components/ToastHost";
import { usePersistentState } from "../hooks/usePersistentState";
import {
  applyRedaction,
  buildRedactionChanges,
  defaultRuleSetState,
  getRedactionDetectors,
  isOptionalRuleSet,
  resolveOverlaps,
  scanRedaction,
  type RedactionCustomRule,
  type RedactionMaskMode,
  type RedactionMatch,
  type RedactionRuleSet,
  type RedactionSeverity,
} from "../utils/redaction";
import { useClipboardPrefs, writeClipboard } from "../utils/clipboard";
import type { ModuleKey } from "../components/ModuleList";
import { useI18n } from "../i18n";
import { consumeRedactionDraft as takeQueuedRedactionDraft } from "../utils/redactionTransfer.js";

type MaskMode = RedactionMaskMode;
type SeverityThreshold = RedactionSeverity;

interface RedactViewProps {
  onOpenGuide?: (key?: ModuleKey) => void;
}

export function RedactView({ onOpenGuide }: RedactViewProps) {
  const { push } = useToast();
  const { t, tr, formatNumber } = useI18n();
  const [clipboardPrefs] = useClipboardPrefs();
  const detectors = useMemo(() => getRedactionDetectors(), []);
  const [input, setInput] = useState("");
  const [maskMode, setMaskMode] = usePersistentState<MaskMode>("nullid:redact:mask", "full");
  const [minimumSeverity, setMinimumSeverity] = usePersistentState<SeverityThreshold>("nullid:redact:min-severity", "low");
  const [minTokenLength, setMinTokenLength] = usePersistentState<number>("nullid:redact:min-token-length", 20);
  const [preserveLength, setPreserveLength] = usePersistentState<boolean>("nullid:redact:preserve-length", false);
  const [customPattern, setCustomPattern] = useState("");
  const [customLabel, setCustomLabel] = useState("custom");
  const [customRules, setCustomRules] = useState<RedactionCustomRule[]>([]);
  const [output, setOutput] = useState("");
  const [queuedMatches, setQueuedMatches] = useState<RedactionMatch[]>([]);
  const [queuedSourceText, setQueuedSourceText] = useState("");
  const [ruleSetState, setRuleSetState] = usePersistentState<Record<Exclude<RedactionRuleSet, "general">, boolean>>(
    "nullid:redact:rule-sets",
    defaultRuleSetState(),
  );
  const [detectorState, setDetectorState] = usePersistentState<Record<string, boolean>>(
    "nullid:redact:detectors",
    Object.fromEntries(detectors.map((detector) => [detector.key, true])) as Record<string, boolean>,
  );

  const activeDetectors = useMemo(
    () =>
      detectors.filter((detector) => {
        if (!(detectorState[detector.key] ?? true)) return false;
        if (!isOptionalRuleSet(detector.ruleSet)) return true;
        return ruleSetState[detector.ruleSet];
      }),
    [detectorState, detectors, ruleSetState],
  );

  const findings = useMemo(
    () => scanRedaction(input, activeDetectors, customRules, { minimumSeverity, minTokenLength }),
    [activeDetectors, customRules, input, minTokenLength, minimumSeverity],
  );
  const combinedMatches = useMemo(
    () => resolveOverlaps([...findings.matches, ...queuedMatches]),
    [findings.matches, queuedMatches],
  );
  const combinedCounts = useMemo(() => {
    return combinedMatches.reduce<Record<string, number>>((acc, match) => {
      acc[match.label] = (acc[match.label] || 0) + 1;
      return acc;
    }, {});
  }, [combinedMatches]);
  const combinedSeverityMap = useMemo(() => {
    return combinedMatches.reduce<Record<string, RedactionSeverity>>((acc, match) => {
      acc[match.label] = acc[match.label]
        ? (acc[match.label] === "high" || match.severity === "low" ? acc[match.label] : match.severity)
        : match.severity;
      return acc;
    }, {});
  }, [combinedMatches]);

  const previewChanges = useMemo(
    () => buildRedactionChanges(input, combinedMatches, maskMode, preserveLength),
    [combinedMatches, input, maskMode, preserveLength],
  );
  const redacted = useMemo(() => applyRedaction(input, combinedMatches, maskMode, preserveLength), [combinedMatches, input, maskMode, preserveLength]);
  const severityCounts = useMemo(() => {
    return combinedMatches.reduce(
      (acc, match) => {
        acc[match.severity] += 1;
        return acc;
      },
      { high: 0, medium: 0, low: 0 },
    );
  }, [combinedMatches]);
  const coverage = useMemo(() => {
    if (!input.length || combinedMatches.length === 0) return 0;
    const maskedChars = combinedMatches.reduce((sum, match) => sum + (match.end - match.start), 0);
    return Math.min(100, Math.round((maskedChars / Math.max(1, input.length)) * 100));
  }, [combinedMatches, input.length]);

  useEffect(() => {
    const draft = takeQueuedRedactionDraft();
    if (!draft) return;
    setInput(draft.text);
    setOutput("");
    setQueuedMatches(draft.matches ?? []);
    setQueuedSourceText(draft.text);
    push(draft.message ?? "text queued for redaction review", "accent");
  }, [push]);

  useEffect(() => {
    if (queuedSourceText && input !== queuedSourceText) {
      setQueuedMatches([]);
      setQueuedSourceText("");
    }
  }, [input, queuedSourceText]);

  const applyCustomRule = () => {
    if (!customPattern.trim()) return;
    try {
      const regex = new RegExp(customPattern, "gi");
      setCustomRules((prev) => [...prev, { label: customLabel || "custom", regex }]);
      setCustomPattern("");
      push("custom rule added", "accent");
    } catch (error) {
      console.error(error);
      push("invalid regex", "danger");
    }
  };

  const handleApply = () => {
    setOutput(redacted);
    push("text redacted", "accent");
  };

  const handleCopy = async () => {
    await writeClipboard(
      output || redacted,
      clipboardPrefs,
      (message, tone) => push(message, tone === "danger" ? "danger" : tone === "accent" ? "accent" : "neutral"),
      "copied",
    );
  };

  const handleDownload = () => {
    const blob = new Blob([output || redacted], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "redacted.txt";
    link.click();
    URL.revokeObjectURL(url);
  };

  const exportFindingsReport = () => {
    const payload = {
      schemaVersion: 1,
      kind: "nullid-redaction-report",
      createdAt: new Date().toISOString(),
      config: {
        maskMode,
        minimumSeverity,
        minTokenLength,
        preserveLength,
        enabledRuleSets: Object.entries(ruleSetState)
          .filter(([, enabled]) => enabled)
          .map(([key]) => key),
        enabledDetectors: activeDetectors.map((detector) => detector.key),
      },
      summary: {
        totalFindings: combinedMatches.length,
        overallSeverity: combinedMatches.some((match) => match.severity === "high")
          ? "high"
          : combinedMatches.some((match) => match.severity === "medium")
            ? "medium"
            : "low",
        coveragePercent: coverage,
        severityCounts,
      },
      byType: combinedCounts,
      matches: previewChanges.slice(0, 400).map((change) => ({
        key: change.key,
        label: change.label,
        severity: change.severity,
        ruleSet: change.ruleSet,
        start: change.start,
        end: change.end,
        original: change.original,
        replacement: change.replacement,
      })),
    };
    const blob = new Blob([`${JSON.stringify(payload, null, 2)}\n`], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `nullid-redaction-report-${Date.now()}.json`;
    link.click();
    URL.revokeObjectURL(url);
    push("redaction report exported", "accent");
  };

  return (
    <div className="workspace-scroll">
      <div className="guide-link">
        <button type="button" className="guide-link-button" onClick={() => onOpenGuide?.("redact")}>
          {t("guide.link")}
        </button>
      </div>
      <div className="grid-two">
        <div className="panel" aria-label={tr("Redaction input")}>
          <div className="panel-heading">
            <span>{tr("Input")}</span>
            <span className="panel-subtext">{tr("paste text")}</span>
          </div>
          <textarea
            className="textarea"
            placeholder={tr("Drop text for redaction...")}
            aria-label={tr("Redaction input")}
            value={input}
            onChange={(event) => setInput(event.target.value)}
          />
          <div className="controls-row">
            <span className="section-title">{tr("Mask mode")}</span>
            <div className="pill-buttons" role="group" aria-label={tr("Mask mode")}>
              {(["full", "partial"] as MaskMode[]).map((mode) => (
                <button key={mode} type="button" className={maskMode === mode ? "active" : ""} onClick={() => setMaskMode(mode)}>
                  {tr(mode)}
                </button>
              ))}
            </div>
          </div>
          <div className="controls-row">
            <label className="section-title" htmlFor="min-severity">
              {tr("Min severity")}
            </label>
            <select
              id="min-severity"
              className="select"
              value={minimumSeverity}
              onChange={(event) => setMinimumSeverity(event.target.value as SeverityThreshold)}
              aria-label={tr("Minimum severity filter")}
            >
              <option value="low">{tr("low")}</option>
              <option value="medium">{tr("medium")}</option>
              <option value="high">{tr("high")}</option>
            </select>
            <label className="section-title" htmlFor="token-length">
              {tr("Token min len")}
            </label>
            <input
              id="token-length"
              className="input"
              type="number"
              min={12}
              max={64}
              value={minTokenLength}
              onChange={(event) => setMinTokenLength(clamp(Number(event.target.value) || 0, 12, 64))}
              aria-label={tr("Minimum token detector length")}
            />
            <label className="microcopy" style={{ display: "flex", alignItems: "center", gap: "0.35rem" }}>
              <input
                type="checkbox"
                checked={preserveLength}
                onChange={(event) => setPreserveLength(event.target.checked)}
                aria-label={tr("Preserve replacement length")}
              />
              {tr("preserve length in full mask")}
            </label>
          </div>
          <div className="controls-row">
            <span className="section-title">{tr("Regional rule sets")}</span>
            {(["iran", "russia"] as Array<Exclude<RedactionRuleSet, "general">>).map((ruleSet) => (
              <label key={ruleSet} className="microcopy" style={{ display: "flex", alignItems: "center", gap: "0.35rem" }}>
                <input
                  type="checkbox"
                  checked={ruleSetState[ruleSet]}
                  onChange={(event) => setRuleSetState((prev) => ({ ...prev, [ruleSet]: event.target.checked }))}
                  aria-label={`${tr("Toggle")} ${formatRuleSetLabel(ruleSet)}`}
                />
                {formatRuleSetLabel(ruleSet)}
              </label>
            ))}
          </div>
          <div className="microcopy">
            {tr("Regional detectors stay off until you enable them. NullID only applies the optional Iran/Persian or Russia rule sets when you choose them explicitly.")}
          </div>
        </div>
        <div className="panel" aria-label={tr("Redaction output")}>
          <div className="panel-heading">
            <span>{tr("Output")}</span>
            <span className="panel-subtext">{tr("preview + apply")}</span>
          </div>
          <div className="redact-preview" aria-label={tr("Highlight view")}>
            {highlight(input, combinedMatches, tr("No findings yet."))}
          </div>
          <div className="microcopy">
            {tr("Preview updates immediately. Apply writes the current transform result into the output box without hiding what was changed.")}
          </div>
          <textarea className="textarea" readOnly value={output || redacted} aria-label={tr("Redacted output")} />
          <div className="controls-row">
            <button className="button" type="button" onClick={handleApply}>
              {tr("apply redaction")}
            </button>
            <button className="button" type="button" onClick={handleCopy}>
              {tr("copy")}
            </button>
            <button className="button" type="button" onClick={handleDownload}>
              {tr("download")}
            </button>
            <button className="button" type="button" onClick={exportFindingsReport}>
              {tr("export report")}
            </button>
          </div>
          <div className="status-line">
            <span>{tr("severity")}</span>
            <Chip
              label={tr(combinedMatches.some((match) => match.severity === "high") ? "high" : combinedMatches.some((match) => match.severity === "medium") ? "medium" : "low")}
              tone={combinedMatches.some((match) => match.severity === "high") ? "danger" : "accent"}
            />
            <span className="microcopy">{formatNumber(combinedMatches.length)} {tr("findings")}</span>
          </div>
          <div className="status-line">
            <span>{tr("coverage")}</span>
            <span className="tag">{formatNumber(coverage)}% {tr("chars masked")}</span>
            <span className="microcopy">
              {tr("high")} {formatNumber(severityCounts.high)} · {tr("medium")} {formatNumber(severityCounts.medium)} · {tr("low")} {formatNumber(severityCounts.low)}
            </span>
          </div>
        </div>
      </div>
      <div className="panel" aria-label={tr("Findings table")}>
        <div className="panel-heading">
          <span>{tr("Findings")}</span>
          <span className="panel-subtext">{tr("type / count / severity")}</span>
        </div>
        <div className="controls-row">
          {detectors.map((detector) => (
            <label key={detector.key} className="microcopy" style={{ display: "flex", alignItems: "center", gap: "0.35rem" }}>
              <input
                type="checkbox"
                checked={detectorState[detector.key]}
                onChange={(event) => setDetectorState((prev) => ({ ...prev, [detector.key]: event.target.checked }))}
                aria-label={`${tr("Toggle")} ${tr(detector.label)}`}
              />
              {tr(detector.label)}
              {isOptionalRuleSet(detector.ruleSet) ? <span className="muted">({formatRuleSetLabel(detector.ruleSet)})</span> : null}
            </label>
          ))}
        </div>
        <table className="table">
          <thead>
            <tr>
              <th>{tr("type")}</th>
              <th>{tr("count")}</th>
              <th>{tr("severity")}</th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(combinedCounts).map(([key, count]) => (
              <tr key={key}>
                <td>{tr(key)}</td>
                <td>{formatNumber(count)}</td>
                <td>
                  <span className={`tag ${combinedSeverityMap[key] === "high" ? "tag-danger" : "tag-accent"}`}>
                    {tr(combinedSeverityMap[key])}
                  </span>
                </td>
              </tr>
            ))}
            {combinedMatches.length === 0 && (
              <tr>
                <td colSpan={3} className="muted">
                  {tr("no findings detected")}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <div className="panel" aria-label={tr("Replacement preview")}>
        <div className="panel-heading">
          <span>{tr("Replacement preview")}</span>
          <span className="panel-subtext">{tr("exact before / after")}</span>
        </div>
        <table className="table">
          <thead>
            <tr>
              <th>{tr("type")}</th>
              <th>{tr("severity")}</th>
              <th>{tr("Original")}</th>
              <th>{tr("Replacement")}</th>
            </tr>
          </thead>
          <tbody>
            {previewChanges.length === 0 ? (
              <tr>
                <td colSpan={4} className="muted">
                  {tr("No findings yet.")}
                </td>
              </tr>
            ) : (
              previewChanges.slice(0, 120).map((change) => (
                <tr key={`${change.start}:${change.end}:${change.key}`}>
                  <td>
                    {tr(change.label)}
                    {isOptionalRuleSet(change.ruleSet) ? <div className="microcopy">{formatRuleSetLabel(change.ruleSet)}</div> : null}
                  </td>
                  <td>{tr(change.severity)}</td>
                  <td>{renderInlineSample(change.original)}</td>
                  <td>{renderInlineSample(change.replacement)}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
      <div className="panel" aria-label={tr("Custom rule")}>
        <div className="panel-heading">
          <span>{tr("Custom rule")}</span>
          <span className="panel-subtext">{tr("regex + label")}</span>
        </div>
        <div className="controls-row">
          <input
            className="input"
            placeholder={tr("Regex pattern")}
            value={customPattern}
            onChange={(event) => setCustomPattern(event.target.value)}
            aria-label={tr("Custom regex pattern")}
          />
          <input
            className="input"
            placeholder={tr("Label")}
            value={customLabel}
            onChange={(event) => setCustomLabel(event.target.value)}
            aria-label={tr("Custom regex label")}
          />
          <button className="button" type="button" onClick={applyCustomRule}>
            {tr("add")}
          </button>
        </div>
        <div className="microcopy">
          {tr("Safe handling: regex runs locally; errors are reported without applying. Custom rules mask with their label.")}
        </div>
      </div>
    </div>
  );
}

type Match = RedactionMatch;

function highlight(text: string, matches: Match[], emptyLabel: string) {
  if (!matches.length) return <span className="muted">{emptyLabel}</span>;
  const sorted = [...matches].sort((a, b) => a.start - b.start);
  const parts: ReactNode[] = [];
  let cursor = 0;
  sorted.forEach((m, index) => {
    parts.push(<span key={`p-${index}-pre`}>{text.slice(cursor, m.start)}</span>);
    parts.push(
      <mark key={`p-${index}-hit`} className={`highlight ${m.severity}`}>
        {text.slice(m.start, m.end)}
      </mark>,
    );
    cursor = m.end;
  });
  parts.push(<span key="tail">{text.slice(cursor)}</span>);
  return <div className="highlight-view">{parts}</div>;
}

function renderInlineSample(value: string) {
  return <code>{value.length > 48 ? `${value.slice(0, 45)}...` : value}</code>;
}

function formatRuleSetLabel(ruleSet: Exclude<RedactionRuleSet, "general">) {
  if (ruleSet === "iran") return "Iran / Persian rules";
  return "Russia rules";
}

function clamp(value: number, min: number, max: number) {
  return Math.min(max, Math.max(min, value));
}
