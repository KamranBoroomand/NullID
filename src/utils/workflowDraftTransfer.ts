import type { MetadataAnalysisResult } from "./metadataAdvanced.js";

export interface WorkflowDraftTextItem {
  kind: "text";
  label: string;
  text: string;
}

export interface WorkflowDraftFileItem {
  kind: "file";
  label: string;
  fileName: string;
  fileMediaType: string;
  sourceBytes: Uint8Array;
  analysis: MetadataAnalysisResult;
}

export type WorkflowDraftItem = WorkflowDraftTextItem | WorkflowDraftFileItem;

export interface SafeShareWorkflowDraft {
  source: "batch-review";
  item: WorkflowDraftItem;
}

export interface IncidentWorkflowDraft {
  source: "batch-review";
  items: WorkflowDraftItem[];
}

let pendingSafeShareDraft: SafeShareWorkflowDraft | null = null;
let pendingIncidentDraft: IncidentWorkflowDraft | null = null;

export function queueSafeShareWorkflowDraft(draft: SafeShareWorkflowDraft) {
  pendingSafeShareDraft = cloneSafeShareDraft(draft);
}

export function consumeSafeShareWorkflowDraft() {
  const draft = pendingSafeShareDraft ? cloneSafeShareDraft(pendingSafeShareDraft) : null;
  pendingSafeShareDraft = null;
  return draft;
}

export function queueIncidentWorkflowDraft(draft: IncidentWorkflowDraft) {
  pendingIncidentDraft = cloneIncidentDraft(draft);
}

export function consumeIncidentWorkflowDraft() {
  const draft = pendingIncidentDraft ? cloneIncidentDraft(pendingIncidentDraft) : null;
  pendingIncidentDraft = null;
  return draft;
}

function cloneSafeShareDraft(draft: SafeShareWorkflowDraft): SafeShareWorkflowDraft {
  return {
    ...draft,
    item: cloneItem(draft.item),
  };
}

function cloneIncidentDraft(draft: IncidentWorkflowDraft): IncidentWorkflowDraft {
  return {
    ...draft,
    items: draft.items.map((item) => cloneItem(item)),
  };
}

function cloneItem(item: WorkflowDraftItem): WorkflowDraftItem {
  if (item.kind === "text") {
    return { ...item };
  }
  return {
    ...item,
    sourceBytes: Uint8Array.from(item.sourceBytes),
    analysis: {
      ...item.analysis,
      fields: item.analysis.fields.map((field) => ({ ...field })),
      signals: item.analysis.signals.map((signal) => ({ ...signal })),
      guidance: [...item.analysis.guidance],
      remainingTraces: [...item.analysis.remainingTraces],
      removable: [...item.analysis.removable],
      cannotGuarantee: [...item.analysis.cannotGuarantee],
    },
  };
}
