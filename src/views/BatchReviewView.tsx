import { useMemo, useRef, useState, type Dispatch, type SetStateAction } from "react";
import "./styles.css";
import { Chip } from "../components/Chip";
import type { ModuleKey } from "../components/ModuleList";
import { useToast } from "../components/ToastHost";
import { usePersistentState } from "../hooks/usePersistentState";
import { useI18n } from "../i18n";
import {
  buildBatchChecklist,
  reviewChecklistToText,
} from "../utils/reviewChecklist.js";
import { localizeExportValue } from "../utils/reporting.js";
import {
  buildBatchReviewExport,
  createBatchFileReviewItem,
  createBatchTextReviewItem,
  itemToChecklistInput,
  type BatchReviewItem,
} from "../utils/batchReview.js";
import { defaultRuleSetState, type RedactionRuleSet } from "../utils/redaction.js";
import {
  queueIncidentWorkflowDraft,
  queueSafeShareWorkflowDraft,
  type WorkflowDraftItem,
} from "../utils/workflowDraftTransfer.js";

interface BatchReviewViewProps {
  onOpenGuide?: (key?: ModuleKey) => void;
  onSelectModule?: (key: ModuleKey) => void;
}

export function BatchReviewView({ onOpenGuide, onSelectModule }: BatchReviewViewProps) {
  const { push } = useToast();
  const { t, tr, formatDateTime, formatNumber } = useI18n();
  const fileRef = useRef<HTMLInputElement>(null);
  const [items, setItems] = useState<BatchReviewItem[]>([]);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [textLabel, setTextLabel] = useState("");
  const [textInput, setTextInput] = useState("");
  const [isAddingFiles, setIsAddingFiles] = useState(false);
  const [ruleSetState, setRuleSetState] = usePersistentState<Record<Exclude<RedactionRuleSet, "general">, boolean>>(
    "nullid:batch:rule-sets",
    defaultRuleSetState(),
  );

  const selectedItems = useMemo(
    () => items.filter((item) => selectedIds.includes(item.id)),
    [items, selectedIds],
  );
  const checklist = useMemo(
    () => buildBatchChecklist(
      selectedItems.length > 0 ? "Batch review checklist :: selected items" : "Batch review checklist :: current session",
      (selectedItems.length > 0 ? selectedItems : items).map((item) => itemToChecklistInput(item)),
    ),
    [items, selectedItems],
  );

  const addTextItem = async () => {
    if (!textInput.trim()) {
      push("text artifact is empty", "danger");
      return;
    }
    const label = textLabel.trim() || `Batch text ${items.length + 1}`;
    const next = await createBatchTextReviewItem({
      id: buildLocalId("text"),
      label,
      text: textInput,
      enabledRuleSets: ruleSetState,
    });
    setItems((previous) => [...previous, next]);
    setTextLabel("");
    setTextInput("");
    push("batch review item added", "accent");
  };

  const handleFiles = async (list?: FileList | null) => {
    if (!list?.length) return;
    setIsAddingFiles(true);
    try {
      const nextItems = await Promise.all(
        Array.from(list).map(async (file) =>
          createBatchFileReviewItem({
            id: buildLocalId("file"),
            label: file.name,
            fileName: file.name,
            fileMediaType: file.type || "application/octet-stream",
            sourceBytes: new Uint8Array(await file.arrayBuffer()),
            enabledRuleSets: ruleSetState,
          })),
      );
      setItems((previous) => [...previous, ...nextItems]);
      push("batch review files added", "accent");
    } catch (error) {
      console.error(error);
      push("file analysis failed", "danger");
    } finally {
      setIsAddingFiles(false);
    }
  };

  const exportBatchReport = () => {
    const payload = localizeExportValue(buildBatchReviewExport(items), tr);
    downloadBlob(new Blob([`${JSON.stringify(payload, null, 2)}\n`], { type: "application/json" }), `nullid-batch-review-${Date.now()}.json`);
    push("batch review report exported", "accent");
  };

  const exportChecklistJson = () => {
    downloadBlob(new Blob([`${JSON.stringify(localizeExportValue(checklist, tr), null, 2)}\n`], { type: "application/json" }), `nullid-review-checklist-${Date.now()}.json`);
    push("review checklist exported", "accent");
  };

  const exportChecklistText = () => {
    downloadBlob(new Blob([reviewChecklistToText(checklist, { translate: tr, formatDateTime })], { type: "text/plain;charset=utf-8" }), `nullid-review-checklist-${Date.now()}.txt`);
    push("review checklist exported", "accent");
  };

  const sendSelectedToSafeShare = () => {
    if (selectedItems.length !== 1) {
      push("select exactly one item for safe share", "danger");
      return;
    }
    const item = selectedItems[0];
    if (item.kind === "text" && item.text) {
      queueSafeShareWorkflowDraft({
        source: "batch-review",
        item: {
          kind: "text",
          label: item.label,
          text: item.text,
        },
      });
    } else if (item.kind === "file" && item.fileName && item.sourceBytes && item.metadataAnalysis) {
      queueSafeShareWorkflowDraft({
        source: "batch-review",
        item: {
          kind: "file",
          label: item.label,
          fileName: item.fileName,
          fileMediaType: item.mediaType,
          sourceBytes: item.sourceBytes,
          analysis: item.metadataAnalysis,
        },
      });
    } else {
      push("selected item could not be prepared for safe share", "danger");
      return;
    }
    onSelectModule?.("share");
  };

  const sendSelectedToIncident = () => {
    if (selectedItems.length === 0) {
      push("select at least one item for incident workflow", "danger");
      return;
    }
    queueIncidentWorkflowDraft({
      source: "batch-review",
      items: selectedItems.reduce<WorkflowDraftItem[]>((acc, item) => {
        if (item.kind === "text" && item.text) {
          acc.push({ kind: "text", label: item.label, text: item.text });
        } else if (item.kind === "file" && item.fileName && item.sourceBytes && item.metadataAnalysis) {
          acc.push({
            kind: "file",
            label: item.label,
            fileName: item.fileName,
            fileMediaType: item.mediaType,
            sourceBytes: item.sourceBytes,
            analysis: item.metadataAnalysis,
          });
        }
        return acc;
      }, []),
    });
    onSelectModule?.("incident");
  };

  return (
    <div className="workspace-scroll">
      <div className="guide-link">
        <button type="button" className="guide-link-button" onClick={() => onOpenGuide?.("batch")}>
          {t("guide.link")}
        </button>
      </div>

      <div className="grid-two">
        <section className="panel" aria-label={tr("Batch review input")}>
          <div className="panel-heading">
            <span>{tr("Batch Review Workspace")}</span>
            <span className="panel-subtext">{tr("multi-item local review")}</span>
          </div>
          <div className="microcopy">
            {tr("Build one local review session across multiple pasted text entries and files, then move selected items into sharing workflows only after you see what was detected.")}
          </div>
          <input
            className="input"
            aria-label={tr("Batch text label")}
            placeholder={tr("Optional batch text label")}
            value={textLabel}
            onChange={(event) => setTextLabel(event.target.value)}
          />
          <textarea
            className="textarea"
            aria-label={tr("Batch text input")}
            placeholder={tr("Paste a text entry you want to review locally")}
            value={textInput}
            onChange={(event) => setTextInput(event.target.value)}
          />
          <div className="controls-row">
            <button className="button" type="button" onClick={() => void addTextItem()}>
              {tr("add text item")}
            </button>
            <button className="button" type="button" onClick={() => fileRef.current?.click()}>
              {tr("add files")}
            </button>
            <button className="button" type="button" onClick={() => {
              setTextLabel("");
              setTextInput("");
            }}>
              {tr("clear")}
            </button>
            <input
              ref={fileRef}
              hidden
              multiple
              type="file"
              aria-label={tr("Batch review files")}
              onChange={(event) => void handleFiles(event.target.files)}
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
          <div className="microcopy">
            {tr("Regional detectors remain opt-in and conservative in batch review as well.")}
          </div>
        </section>

        <section className="panel" aria-label={tr("Batch review summary")}>
          <div className="panel-heading">
            <span>{tr("Batch session summary")}</span>
            <span className="panel-subtext">{tr("selection, export, and workflow handoff")}</span>
          </div>
          <div className="controls-row" style={{ alignItems: "center" }}>
            <Chip label={`${formatNumber(items.length)} ${tr("items")}`} tone={items.length > 0 ? "accent" : "muted"} />
            <Chip label={`${formatNumber(selectedItems.length)} ${tr("selected")}`} tone={selectedItems.length > 0 ? "accent" : "muted"} />
            <Chip label={isAddingFiles ? tr("analyzing...") : tr("local only")} tone="muted" />
          </div>
          <div className="controls-row">
            <button className="button" type="button" onClick={exportBatchReport} disabled={items.length === 0}>
              {tr("export batch report")}
            </button>
            <button className="button" type="button" onClick={exportChecklistJson} disabled={checklist.sections.length === 0}>
              {tr("export checklist json")}
            </button>
            <button className="button" type="button" onClick={exportChecklistText} disabled={checklist.sections.length === 0}>
              {tr("export checklist text")}
            </button>
          </div>
          <div className="controls-row">
            <button className="button" type="button" onClick={sendSelectedToSafeShare} disabled={selectedItems.length !== 1}>
              {tr("send selected to safe share")}
            </button>
            <button className="button" type="button" onClick={sendSelectedToIncident} disabled={selectedItems.length === 0}>
              {tr("send selected to incident")}
            </button>
          </div>
          <ul className="microcopy">
            <li>{tr("Safe Share accepts one selected item at a time so the package preview stays explicit.")}</li>
            <li>{tr("Incident workflow can receive multiple selected items for a larger handoff package.")}</li>
          </ul>
        </section>
      </div>

      <section className="panel" aria-label={tr("Batch review items")}>
        <div className="panel-heading">
          <span>{tr("Session items")}</span>
          <span className="panel-subtext">{tr("per-item findings and actions")}</span>
        </div>
        <table className="table">
          <thead>
            <tr>
              <th>{tr("select")}</th>
              <th>{tr("item")}</th>
              <th>{tr("type")}</th>
              <th>{tr("findings")}</th>
              <th>{tr("metadata")}</th>
              <th>{tr("redaction")}</th>
              <th>{tr("secrets")}</th>
              <th>{tr("actions")}</th>
            </tr>
          </thead>
          <tbody>
            {items.length === 0 ? (
              <tr>
                <td colSpan={8} className="muted">{tr("No batch review items yet.")}</td>
              </tr>
            ) : (
              items.map((item, index) => (
                <tr key={item.id}>
                  <td>
                    <input
                      type="checkbox"
                      aria-label={`${tr("select")} ${item.label}`}
                      checked={selectedIds.includes(item.id)}
                      onChange={(event) => setSelectedIds((previous) => (
                        event.target.checked
                          ? [...previous, item.id]
                          : previous.filter((candidate) => candidate !== item.id)
                      ))}
                    />
                  </td>
                  <td>
                    <div>{item.label}</div>
                    <div className="microcopy">{formatNumber(item.sizeBytes)} {tr("bytes")}</div>
                  </td>
                  <td>{tr(item.typeLabel)}</td>
                  <td><SummaryList lines={[...item.summary.findings, ...item.summary.financial]} tr={tr} emptyLabel="No grouped findings yet." /></td>
                  <td><SummaryList lines={[...item.summary.metadata, ...item.summary.pathPrivacy]} tr={tr} emptyLabel="No metadata summary for this item." /></td>
                  <td><SummaryList lines={item.summary.redaction} tr={tr} emptyLabel="No redaction preview summary for this item." /></td>
                  <td><SummaryList lines={item.summary.secrets} tr={tr} emptyLabel="No likely secret summary for this item." /></td>
                  <td>
                    <div className="controls-row" style={{ flexWrap: "wrap" }}>
                      <button className="button" type="button" onClick={() => moveItem(setItems, index, -1)} disabled={index === 0}>
                        {tr("up")}
                      </button>
                      <button className="button" type="button" onClick={() => moveItem(setItems, index, 1)} disabled={index === items.length - 1}>
                        {tr("down")}
                      </button>
                      <button
                        className="button"
                        type="button"
                        onClick={() => {
                          setItems((previous) => previous.filter((candidate) => candidate.id !== item.id));
                          setSelectedIds((previous) => previous.filter((candidate) => candidate !== item.id));
                        }}
                      >
                        {tr("remove")}
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </section>

      <section className="panel" aria-label={tr("Manual review checklist")}>
        <div className="panel-heading">
          <span>{tr("Manual review checklist")}</span>
          <span className="panel-subtext">{tr("derived from selected or current session items")}</span>
        </div>
        <div className="grid-two">
          {checklist.sections.length > 0 ? checklist.sections.map((section) => (
            <div key={section.id}>
              <div className="panel-subtext">{tr(section.label)}</div>
              <ul className="microcopy">
                {section.items.map((item) => (
                  <li key={`${section.id}:${item}`}>{tr(item)}</li>
                ))}
              </ul>
            </div>
          )) : (
            <div className="microcopy">{tr("Add or select items to generate a checklist.")}</div>
          )}
        </div>
      </section>
    </div>
  );
}

function SummaryList({ lines, tr, emptyLabel }: { lines: string[]; tr: (value: string) => string; emptyLabel: string }) {
  return (
    <ul className="microcopy" style={{ margin: 0, paddingInlineStart: "1rem" }}>
      {lines.length > 0 ? lines.slice(0, 4).map((line) => <li key={line}>{tr(line)}</li>) : <li>{tr(emptyLabel)}</li>}
    </ul>
  );
}

function moveItem(setItems: Dispatch<SetStateAction<BatchReviewItem[]>>, index: number, delta: -1 | 1) {
  setItems((previous) => {
    const nextIndex = index + delta;
    if (nextIndex < 0 || nextIndex >= previous.length) return previous;
    const next = [...previous];
    const [item] = next.splice(index, 1);
    next.splice(nextIndex, 0, item);
    return next;
  });
}

function buildLocalId(prefix: string) {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function downloadBlob(blob: Blob, fileName: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = fileName;
  link.click();
  URL.revokeObjectURL(url);
}
