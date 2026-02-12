import "./styles.css";
import { useClipboardPrefs } from "../utils/clipboard";
import { guideExtras, guideTools } from "../content/guideContent";
import "./GuideView.css";

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

const operatorNotes = [
  {
    role: "Incident response",
    quote: "Batch sanitization and signed policy packs made evidence sharing repeatable across teams.",
  },
  {
    role: "Security engineering",
    quote: "Local-only hashing and envelope tooling let us verify artifacts in restricted environments.",
  },
  {
    role: "Privacy review",
    quote: "Metadata stripping plus preview diagnostics reduced accidental EXIF leaks before publishing.",
  },
];

export function GuideView() {
  const [clipboardPrefs, setClipboardPrefs] = useClipboardPrefs();
  const buildId = (import.meta.env.VITE_BUILD_ID as string | undefined) ?? "dev";
  const buildShort = buildId.slice(0, 7);

  return (
    <div className="workspace-scroll guide-surface">
      <div className="panel" aria-label="Guide overview">
        <div className="panel-heading">
          <span>Guide</span>
          <span className="panel-subtext">how to use NullID</span>
        </div>
        <div className="microcopy">
          Offline-first tooling; no network calls, no analytics. All processing and clipboard actions are local and best-effort cleared.
        </div>
      </div>
      <div className="guide-grid">
        <article className="panel guide-card" aria-label="Trust signals">
          <div className="guide-card-header">
            <div className="guide-card-title">
              <span className="guide-key">:trust</span>
              <div className="guide-title-wrap">
                <span className="guide-name">Trust Signals</span>
                <span className="guide-summary">Security posture at a glance</span>
              </div>
            </div>
          </div>
          <ul className="microcopy guide-list">
            {trustSignals.map((signal) => (
              <li key={signal.title}>
                <span className="note-title">{signal.title}</span>
                <span className="note-body"> {signal.detail}</span>
              </li>
            ))}
          </ul>
        </article>
        <article className="panel guide-card" aria-label="Operator testimonials">
          <div className="guide-card-header">
            <div className="guide-card-title">
              <span className="guide-key">:proof</span>
              <div className="guide-title-wrap">
                <span className="guide-name">Operator Notes</span>
                <span className="guide-summary">Field feedback from common workflows</span>
              </div>
            </div>
          </div>
          <ul className="microcopy guide-list">
            {operatorNotes.map((note) => (
              <li key={note.role}>
                <span className="note-title">{note.role}</span>
                <span className="note-body"> {note.quote}</span>
              </li>
            ))}
          </ul>
        </article>
      </div>
      <div className="guide-grid">
        {guideTools.map((tool) => (
          <article key={tool.key} id={tool.key} className="panel guide-card" aria-label={`${tool.title} guide`}>
            <div className="guide-card-header">
              <div className="guide-card-title">
                <span className="guide-key">:{tool.key}</span>
                <div className="guide-title-wrap">
                  <span className="guide-name">{tool.title}</span>
                  <span className="guide-summary">{tool.whatItDoes}</span>
                </div>
              </div>
            </div>
            <GuideLists item={tool} />
          </article>
        ))}
      </div>
      <div className="guide-grid">
        {guideExtras.map((item) => (
          <article key={item.key} id={item.key} className="panel guide-card" aria-label={`${item.title} guidance`}>
            <div className="guide-card-header">
              <div className="guide-card-title">
                <span className="guide-key">:{item.key}</span>
                <div className="guide-title-wrap">
                  <span className="guide-name">{item.title}</span>
                  <span className="guide-summary">{item.whatItDoes}</span>
                </div>
              </div>
            </div>
            <GuideLists item={item} />
            {item.key === "clipboard" && (
              <div className="controls-row guide-clipboard-row" style={{ alignItems: "center" }}>
                <label className="microcopy" htmlFor="clipboard-clear">
                  Auto-clear clipboard
                </label>
                <div className="pill-buttons" role="group" aria-label="Clipboard auto clear">
                  <button
                    type="button"
                    className={clipboardPrefs.enableAutoClearClipboard ? "active" : ""}
                    onClick={() =>
                      setClipboardPrefs((prev) => ({ ...prev, enableAutoClearClipboard: !prev.enableAutoClearClipboard }))
                    }
                  >
                    {clipboardPrefs.enableAutoClearClipboard ? "enabled" : "disabled"}
                  </button>
                </div>
                <label className="microcopy" htmlFor="clipboard-seconds">
                  Clear after (seconds)
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
        Build {buildShort}
      </div>
    </div>
  );
}

interface GuideListsProps {
  item: (typeof guideTools)[number] | (typeof guideExtras)[number];
}

function GuideLists({ item }: GuideListsProps) {
  return (
    <div className="guide-card-body">
      <div className="guide-section">
        <div className="section-title">What & when</div>
        <ul className="microcopy guide-list">
          {item.whatWhen.map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
      </div>
      <div className="guide-section">
        <div className="section-title">How</div>
        <ol className="microcopy guide-list">
          {item.howSteps.map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ol>
      </div>
      <div className="guide-section">
        <div className="section-title">Common mistakes & limits</div>
        <ul className="microcopy guide-list">
          {item.limits.map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
      </div>
      {item.privacyNotes?.length ? (
        <div className="guide-section">
          <div className="section-title">Privacy notes</div>
          <ul className="microcopy guide-list">
            {item.privacyNotes.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}
