import "./styles.css";
import { useClipboardPrefs } from "../utils/clipboard";
import { guideExtras, guideTools } from "../content/guideContent";
import "./GuideView.css";
import { useI18n } from "../i18n";

const trustSignals = [
  {
    title: "Local-only execution",
    detail: "No analytics, no network requests, and no cloud dependency for core tools.",
  },
  {
    title: "Signed export verification",
    detail: "Profiles, policy packs, and vault snapshots support optional signature verification.",
  },
  {
    title: "Deterministic crypto envelope",
    detail: "Documented NULLID envelope format (PBKDF2 + AES-GCM with AAD binding).",
  },
  {
    title: "Hygiene defaults",
    detail: "Clipboard auto-clear, lock timers, and panic lock support reduce local residue.",
  },
];

const workflowNotes = [
  {
    role: "Incident workflow",
    note: "Use :sanitize policy packs before sharing logs, then export the safe-share bundle with hashes.",
  },
  {
    role: "Artifact verification",
    note: "Use :hash manifests and :enc envelopes to exchange integrity-checked artifacts across restricted environments.",
  },
  {
    role: "Privacy publishing",
    note: "Run :meta cleanup and codec diagnostics before publishing media outside trusted channels.",
  },
];

export function GuideView() {
  const { tr } = useI18n();
  const [clipboardPrefs, setClipboardPrefs] = useClipboardPrefs();
  const buildId = (import.meta.env.VITE_BUILD_ID as string | undefined) ?? "dev";
  const buildShort = buildId.slice(0, 7);

  return (
    <div className="workspace-scroll guide-surface">
      <div className="panel" aria-label={tr("Guide overview")}>
        <div className="panel-heading">
          <span>{tr("Guide")}</span>
          <span className="panel-subtext">{tr("how to use NullID")}</span>
        </div>
        <div className="microcopy">
          {tr("Offline-first tooling; no network calls, no analytics. All processing and clipboard actions are local and best-effort cleared.")}
        </div>
      </div>
      <div className="guide-grid">
        <article className="panel guide-card" aria-label={tr("Trust signals")}>
          <div className="guide-card-header">
            <div className="guide-card-title">
              <span className="guide-key">:trust</span>
              <div className="guide-title-wrap">
                <span className="guide-name">{tr("Trust Signals")}</span>
                <span className="guide-summary">{tr("Security posture at a glance")}</span>
              </div>
            </div>
          </div>
          <ul className="microcopy guide-list">
            {trustSignals.map((signal) => (
              <li key={signal.title}>
                <span className="note-title">{tr(signal.title)}</span>
                <span className="note-body"> {tr(signal.detail)}</span>
              </li>
            ))}
          </ul>
        </article>
        <article className="panel guide-card" aria-label={tr("Workflow notes")}>
          <div className="guide-card-header">
            <div className="guide-card-title">
              <span className="guide-key">:proof</span>
              <div className="guide-title-wrap">
                <span className="guide-name">{tr("Workflow Notes")}</span>
                <span className="guide-summary">{tr("Operational guidance for common workflows")}</span>
              </div>
            </div>
          </div>
          <ul className="microcopy guide-list">
            {workflowNotes.map((note) => (
              <li key={note.role}>
                <span className="note-title">{tr(note.role)}</span>
                <span className="note-body"> {tr(note.note)}</span>
              </li>
            ))}
          </ul>
        </article>
      </div>
      <div className="guide-grid">
        {guideTools.map((tool) => (
          <article key={tool.key} id={tool.key} className="panel guide-card" aria-label={`${tr(tool.title)} ${tr("guide")}`}>
            <div className="guide-card-header">
              <div className="guide-card-title">
                <span className="guide-key">:{tool.key}</span>
                <div className="guide-title-wrap">
                  <span className="guide-name">{tr(tool.title)}</span>
                  <span className="guide-summary">{tr(tool.whatItDoes)}</span>
                </div>
              </div>
            </div>
            <GuideLists item={tool} />
          </article>
        ))}
      </div>
      <div className="guide-grid">
        {guideExtras.map((item) => (
          <article key={item.key} id={item.key} className="panel guide-card" aria-label={`${tr(item.title)} ${tr("guidance")}`}>
            <div className="guide-card-header">
              <div className="guide-card-title">
                <span className="guide-key">:{item.key}</span>
                <div className="guide-title-wrap">
                  <span className="guide-name">{tr(item.title)}</span>
                  <span className="guide-summary">{tr(item.whatItDoes)}</span>
                </div>
              </div>
            </div>
            <GuideLists item={item} />
            {item.key === "clipboard" && (
              <div className="controls-row guide-clipboard-row" style={{ alignItems: "center" }}>
                <label className="microcopy" htmlFor="clipboard-clear">
                  {tr("Auto-clear clipboard")}
                </label>
                <div className="pill-buttons" role="group" aria-label={tr("Clipboard auto clear")}>
                  <button
                    type="button"
                    className={clipboardPrefs.enableAutoClearClipboard ? "active" : ""}
                    onClick={() =>
                      setClipboardPrefs((prev) => ({ ...prev, enableAutoClearClipboard: !prev.enableAutoClearClipboard }))
                    }
                  >
                    {clipboardPrefs.enableAutoClearClipboard ? tr("enabled") : tr("disabled")}
                  </button>
                </div>
                <label className="microcopy" htmlFor="clipboard-seconds">
                  {tr("Clear after (seconds)")}
                </label>
                <input
                  id="clipboard-seconds"
                  className="input"
                  type="number"
                  min={5}
                  max={300}
                  value={clipboardPrefs.clipboardClearSeconds}
                  onChange={(event) =>
                    setClipboardPrefs((prev) => ({
                      ...prev,
                      clipboardClearSeconds: Math.max(5, Math.min(300, Number(event.target.value))),
                    }))
                  }
                  style={{ width: "6rem" }}
                />
              </div>
            )}
          </article>
        ))}
      </div>
      <div className="microcopy" style={{ marginTop: "1.25rem", textAlign: "center", color: "var(--text-muted)" }}>
        {tr("Build")} {buildShort}
      </div>
    </div>
  );
}

interface GuideListsProps {
  item: (typeof guideTools)[number] | (typeof guideExtras)[number];
}

function GuideLists({ item }: GuideListsProps) {
  const { tr } = useI18n();
  return (
    <div className="guide-card-body">
      <div className="guide-section">
        <div className="section-title">{tr("What & when")}</div>
        <ul className="microcopy guide-list">
          {item.whatWhen.map((line) => (
            <li key={line}>{tr(line)}</li>
          ))}
        </ul>
      </div>
      <div className="guide-section">
        <div className="section-title">{tr("How")}</div>
        <ol className="microcopy guide-list">
          {item.howSteps.map((line) => (
            <li key={line}>{tr(line)}</li>
          ))}
        </ol>
      </div>
      <div className="guide-section">
        <div className="section-title">{tr("Common mistakes & limits")}</div>
        <ul className="microcopy guide-list">
          {item.limits.map((line) => (
            <li key={line}>{tr(line)}</li>
          ))}
        </ul>
      </div>
      {item.privacyNotes?.length ? (
        <div className="guide-section">
          <div className="section-title">{tr("Privacy notes")}</div>
          <ul className="microcopy guide-list">
            {item.privacyNotes.map((line) => (
              <li key={line}>{tr(line)}</li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}
