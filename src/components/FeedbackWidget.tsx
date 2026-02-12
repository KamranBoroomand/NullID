import { useMemo, useState } from "react";
import { usePersistentState } from "../hooks/usePersistentState";
import { useToast } from "./ToastHost";
import type { ModuleKey } from "./ModuleList";
import "./FeedbackWidget.css";

interface FeedbackEntry {
  id: string;
  createdAt: string;
  module: ModuleKey;
  category: "idea" | "bug" | "ux" | "performance";
  priority: "low" | "medium" | "high";
  message: string;
}

interface FeedbackWidgetProps {
  activeModule: ModuleKey;
}

const storageKey = "nullid:feedback-log";

export function FeedbackWidget({ activeModule }: FeedbackWidgetProps) {
  const { push } = useToast();
  const [open, setOpen] = useState(false);
  const [category, setCategory] = usePersistentState<FeedbackEntry["category"]>("nullid:feedback-category", "idea");
  const [priority, setPriority] = usePersistentState<FeedbackEntry["priority"]>("nullid:feedback-priority", "medium");
  const [message, setMessage] = usePersistentState<string>("nullid:feedback-draft", "");
  const [entryCount, setEntryCount] = useState(() => loadFeedbackEntries().length);

  const canSave = useMemo(() => message.trim().length >= 8, [message]);

  const handleSave = () => {
    const trimmed = message.trim();
    if (trimmed.length < 8) {
      push("feedback too short (min 8 chars)", "danger");
      return;
    }
    const nextEntry: FeedbackEntry = {
      id: `fb-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
      createdAt: new Date().toISOString(),
      module: activeModule,
      category,
      priority,
      message: trimmed,
    };
    const entries = [nextEntry, ...loadFeedbackEntries()].slice(0, 100);
    localStorage.setItem(storageKey, JSON.stringify(entries));
    setEntryCount(entries.length);
    setMessage("");
    push("feedback stored locally", "accent");
  };

  const handleExport = () => {
    const entries = loadFeedbackEntries();
    if (entries.length === 0) {
      push("no saved feedback to export", "neutral");
      return;
    }
    const payload = {
      schemaVersion: 1,
      exportedAt: new Date().toISOString(),
      entries,
    };
    const blob = new Blob([`${JSON.stringify(payload, null, 2)}\n`], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `nullid-feedback-${Date.now()}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
    push("feedback export ready", "accent");
  };

  return (
    <div className="feedback-widget">
      {open ? (
        <div className="feedback-panel" aria-label="Feedback panel">
          <div className="feedback-header">
            <span className="section-title">Feedback</span>
            <button type="button" className="button" onClick={() => setOpen(false)} aria-label="Close feedback panel">
              close
            </button>
          </div>
          <div className="microcopy">
            Stored locally only ({entryCount} saved). Use export to share.
          </div>
          <div className="controls-row">
            <select
              className="select"
              value={category}
              onChange={(event) => setCategory(event.target.value as FeedbackEntry["category"])}
              aria-label="Feedback category"
            >
              <option value="idea">idea</option>
              <option value="bug">bug</option>
              <option value="ux">ux</option>
              <option value="performance">performance</option>
            </select>
            <select
              className="select"
              value={priority}
              onChange={(event) => setPriority(event.target.value as FeedbackEntry["priority"])}
              aria-label="Feedback priority"
            >
              <option value="low">low</option>
              <option value="medium">medium</option>
              <option value="high">high</option>
            </select>
          </div>
          <textarea
            className="textarea"
            value={message}
            onChange={(event) => setMessage(event.target.value)}
            placeholder={`Context: :${activeModule} (what worked, what broke, what should be added)`}
            aria-label="Feedback message"
          />
          <div className="controls-row">
            <button className="button" type="button" onClick={handleSave} disabled={!canSave}>
              save local
            </button>
            <button className="button" type="button" onClick={handleExport} disabled={entryCount === 0}>
              export json
            </button>
            <button className="button" type="button" onClick={() => setMessage("")}>
              clear draft
            </button>
          </div>
        </div>
      ) : (
        <button type="button" className="button feedback-launcher" onClick={() => setOpen(true)} aria-label="Open feedback">
          feedback
        </button>
      )}
    </div>
  );
}

function loadFeedbackEntries(): FeedbackEntry[] {
  try {
    const raw = localStorage.getItem(storageKey);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((entry) => entry && typeof entry.message === "string");
  } catch {
    return [];
  }
}
