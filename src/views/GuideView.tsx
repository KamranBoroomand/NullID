import { useCallback, useEffect, useMemo, useState } from "react";
import "./styles.css";
import { useClipboardPrefs } from "../utils/clipboard";
import { guideExtras, guideTools } from "../content/guideContent";
import { guideAtlasRoutingNotes, guideGroupDefinitions, guideQuickPaths } from "../content/guideAtlas";
import "./GuideView.css";
import { useI18n } from "../i18n";
import type { ModuleKey } from "../components/ModuleList";
import { PanelOverlay } from "../components/PanelOverlay";

type GuideItem = (typeof guideTools)[number] | (typeof guideExtras)[number];
type GuideItemKey = GuideItem["key"];
type GuideSectionKey = "what" | "how" | "limits" | "privacy";
type GuideOverlayMode = "entry" | "atlas";
const guideToolKeys = new Set(guideTools.map((item) => item.key));
const previewLineCount = 2;

interface GuideViewProps {
  onOpenModule?: (key: ModuleKey) => void;
}

type GuideSectionConfig = {
  key: GuideSectionKey;
  label: string;
  lines: string[];
  ordered: boolean;
};

const doctrineFor = [
  "Local hashing, redaction, packaging, verification, and sealed note storage.",
  "Operator-reviewed workflows where outputs can be inspected before export.",
];

const doctrineNotFor = [
  "Cloud trust delegation, remote attestation, or magical anonymity guarantees.",
  "Replacing operator judgment when context or threat models are unclear.",
];

const doctrineTrust = [
  "Execution stays local unless you explicitly export something.",
  "Verification language stays narrow: NullID reports what it can actually inspect.",
];

const trustSignals = [
  {
    title: "Local-only execution",
    detail: "No analytics, no network requests, and no cloud dependency for core tools.",
  },
  {
    title: "Signed export verification",
    detail: "Profiles, policy packs, and vault snapshots support optional shared-passphrase HMAC verification.",
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
    note: "Use :share for guided package prep, or :sanitize when you need lower-level policy control before sharing logs.",
  },
  {
    role: "Artifact verification",
    note: "Use :verify to inspect received workflow packages locally, and combine :hash or :enc when you need lower-level integrity or envelope steps.",
  },
  {
    role: "Privacy publishing",
    note: "Run :meta cleanup and codec diagnostics before publishing media outside trusted channels.",
  },
];

export function GuideView({ onOpenModule }: GuideViewProps) {
  const { tr } = useI18n();
  const [clipboardPrefs, setClipboardPrefs] = useClipboardPrefs();
  const buildId = (import.meta.env.VITE_BUILD_ID as string | undefined) ?? "dev";
  const buildShort = buildId.slice(0, 7);
  const guideItems = useMemo(() => [...guideTools, ...guideExtras], []);
  const itemLookup = useMemo(() => new Map(guideItems.map((item) => [item.key, item] as const)), [guideItems]);
  const requireGuideItem = useCallback(
    (key: string, source: string) => {
      const item = itemLookup.get(key);
      if (!item) {
        throw new Error(`${source} references missing guide entry "${key}".`);
      }
      return item;
    },
    [itemLookup],
  );
  const groupedItems = useMemo(
    () =>
      guideGroupDefinitions
        .map((group) => ({
          ...group,
          items: group.keys.map((key) => requireGuideItem(key, `Guide atlas group "${group.label}"`)),
        }))
        .filter((group) => group.items.length > 0),
    [requireGuideItem],
  );
  const quickPaths = useMemo(
    () =>
      guideQuickPaths.map((path) =>
        path.kind === "entry"
          ? {
              ...path,
              target: requireGuideItem(path.target, `Quick path "${path.label}"`).key as GuideItemKey,
            }
          : path,
      ),
    [requireGuideItem],
  );
  const [selectedKey, setSelectedKey] = useState<GuideItemKey>("hash");
  const [activeSection, setActiveSection] = useState<GuideSectionKey>("what");
  const [overlayOpen, setOverlayOpen] = useState(false);
  const [overlayMode, setOverlayMode] = useState<GuideOverlayMode>("entry");
  const [overlaySection, setOverlaySection] = useState<GuideSectionKey>("what");

  useEffect(() => {
    const syncFromHash = () => {
      const hash = window.location.hash.replace(/^#/, "");
      if (itemLookup.has(hash as GuideItemKey)) {
        setSelectedKey(hash as GuideItemKey);
      }
    };

    syncFromHash();
    window.addEventListener("hashchange", syncFromHash);
    return () => window.removeEventListener("hashchange", syncFromHash);
  }, [itemLookup]);

  const selectedItem = itemLookup.get(selectedKey);
  if (!selectedItem) {
    throw new Error(`Guide selection "${selectedKey}" is not registered.`);
  }
  const selectedItemIsModule = guideToolKeys.has(selectedItem.key);
  const selectedGroup = groupedItems.find((group) => group.items.some((item) => item.key === selectedItem.key)) ?? groupedItems[0];
  const availableSections = useMemo(
    () =>
      [
        { key: "what", label: "What & when", lines: selectedItem.whatWhen, ordered: false },
        { key: "how", label: "How", lines: selectedItem.howSteps, ordered: true },
        { key: "limits", label: "Mistakes / limits", lines: selectedItem.limits, ordered: false },
        ...(selectedItem.privacyNotes?.length
          ? [{ key: "privacy", label: "Privacy notes", lines: selectedItem.privacyNotes, ordered: false }]
          : []),
      ] as GuideSectionConfig[],
    [selectedItem],
  );

  useEffect(() => {
    if (!availableSections.some((section) => section.key === activeSection)) {
      setActiveSection(availableSections[0]?.key ?? "what");
    }
  }, [activeSection, availableSections]);

  useEffect(() => {
    if (!availableSections.some((section) => section.key === overlaySection)) {
      setOverlaySection(availableSections[0]?.key ?? "what");
    }
  }, [availableSections, overlaySection]);

  const activeSectionConfig = availableSections.find((section) => section.key === activeSection) ?? availableSections[0];
  const overlaySectionConfig = availableSections.find((section) => section.key === overlaySection) ?? availableSections[0];

  const selectItem = useCallback((key: GuideItemKey) => {
    setSelectedKey(key);
    setActiveSection("what");
    if (window.location.hash !== `#${key}`) {
      window.history.replaceState(null, "", `#${key}`);
    }
  }, []);

  const openGuideOverlay = useCallback(
    (key: GuideItemKey, section: GuideSectionKey = "what") => {
      selectItem(key);
      setOverlayMode("entry");
      setOverlaySection(section);
      setOverlayOpen(true);
    },
    [selectItem],
  );

  const openAtlasOverlay = useCallback(() => {
    setOverlayMode("atlas");
    setOverlayOpen(true);
  }, []);

  const focusGuideEntry = useCallback(() => {
    setOverlayOpen(false);
    requestAnimationFrame(() => {
      document.getElementById("guide-detail")?.scrollIntoView({ block: "start" });
    });
  }, []);

  const previewLines = activeSectionConfig?.lines.slice(0, previewLineCount) ?? [];
  const previewRemaining = Math.max(0, (activeSectionConfig?.lines.length ?? 0) - previewLines.length);

  return (
    <div className="workspace-scroll guide-surface">
      <section className="guide-briefing" aria-label={tr("Guide overview")}>
        <section className="guide-doctrine panel" aria-label={tr("Guide overview")}>
          <div className="guide-doctrine-copy">
            <span className="guide-kicker">{tr("NullID operator manual")}</span>
            <h1 className="guide-doctrine-title">{tr("Local trust is earned, not assumed.")}</h1>
            <p className="guide-doctrine-text">
              {tr("NullID is an offline-first security workbench for preparing, inspecting, and exporting sensitive material under local operator control.")}
            </p>
          </div>
          <div className="guide-doctrine-grid">
            <DoctrineBlock title={tr("Use it for")} lines={doctrineFor} />
            <DoctrineBlock title={tr("Do not expect")} lines={doctrineNotFor} />
            <DoctrineBlock title={tr("Trust model")} lines={doctrineTrust} />
          </div>
        </section>

        <section className="guide-band guide-path-band panel" aria-label={tr("Quick paths")}>
          <div className="guide-band-header">
            <span className="guide-section-kicker">{tr("Quick paths")}</span>
            <p className="guide-section-copy">
              {tr("Start from the task in front of you, then jump into the exact module instead of reading the full manual first.")}
            </p>
          </div>
          <div className="guide-path-grid">
            {quickPaths.map((path) => (
              <button
                key={path.label}
                type="button"
                className={`guide-path-button ${
                  path.kind === "entry"
                    ? selectedItem.key === path.target && overlayMode === "entry"
                      ? "is-active"
                      : ""
                    : overlayOpen && overlayMode === "atlas"
                      ? "is-active"
                      : ""
                }`}
                onClick={() => (path.kind === "entry" ? openGuideOverlay(path.target) : openAtlasOverlay())}
              >
                <span className="guide-path-title">{tr(path.label)}</span>
                <span className="guide-path-note">{tr(path.note)}</span>
                <span className="guide-path-action">{tr("Open briefing")}</span>
              </button>
            ))}
          </div>
        </section>
      </section>

      <section className="guide-atlas" aria-label={tr("Tool atlas")}>
        <div className="guide-band-header">
          <span className="guide-section-kicker">{tr("Tool atlas")}</span>
          <p className="guide-section-copy">
            {tr("Use the grouped index to pick a working surface, then read only the detailed notes for that module instead of scanning the whole manual at once.")}
          </p>
        </div>
        <div className="guide-atlas-grid">
          <aside className="guide-index panel" aria-label={tr("Tool index")}>
            {groupedItems.map((group) => (
              <section key={group.label} className="guide-index-group" aria-label={tr(group.label)}>
                <div className="guide-index-header">
                  <span className="guide-index-label">{tr(group.label)}</span>
                  <span className="guide-index-copy">{tr(group.description)}</span>
                </div>
                <div className="guide-index-list">
                  {group.items.map((item) => (
                    <button
                      key={item.key}
                      type="button"
                      className={`guide-index-item ${selectedItem.key === item.key ? "is-active" : ""}`}
                      onClick={() => openGuideOverlay(item.key)}
                    >
                      <span className="guide-index-key">:{item.key}</span>
                      <span className="guide-index-body">
                        <span className="guide-index-title">{tr(item.title)}</span>
                        <span className="guide-index-summary">{tr(item.whatItDoes)}</span>
                      </span>
                    </button>
                  ))}
                </div>
              </section>
            ))}
          </aside>

          <article className="guide-detail panel" aria-label={`${tr(selectedItem.title)} ${tr("guide")}`} id="guide-detail">
            <div className="guide-detail-header">
              <div className="guide-detail-copy">
                <span className="guide-key">:{selectedItem.key}</span>
                <h2 className="guide-detail-title">{tr(selectedItem.title)}</h2>
                <p className="guide-detail-summary">{tr(selectedItem.whatItDoes)}</p>
              </div>
              <div className="guide-detail-side">
                <div className="guide-detail-stats">
                  <span>{tr(selectedGroup?.label ?? "Tool atlas")}</span>
                  <span>{selectedItem.howSteps.length} {tr("steps")}</span>
                  <span>{selectedItem.limits.length} {tr("limits")}</span>
                  {selectedItem.privacyNotes?.length ? <span>{selectedItem.privacyNotes.length} {tr("privacy notes")}</span> : null}
                  <span>{tr("Build")} {buildShort}</span>
                </div>
                <div className="guide-detail-actions">
                  <button
                    type="button"
                    className="button guide-open-briefing"
                    onClick={() => openGuideOverlay(selectedItem.key, activeSection)}
                  >
                    {tr("Open briefing")}
                  </button>
                  {selectedItemIsModule && onOpenModule ? (
                    <button
                      type="button"
                      className="button guide-open-module"
                      onClick={() => onOpenModule(selectedItem.key as ModuleKey)}
                    >
                      {tr("Open")} :{selectedItem.key}
                    </button>
                  ) : null}
                </div>
              </div>
            </div>

            <div className="guide-detail-nav" role="tablist" aria-label={tr("Guide detail sections")}>
              {availableSections.map((section) => (
                <button
                  key={section.key}
                  type="button"
                  className={`guide-detail-tab ${activeSection === section.key ? "is-active" : ""}`}
                  onClick={() => setActiveSection(section.key)}
                  role="tab"
                  aria-selected={activeSection === section.key}
                >
                  {tr(section.label)}
                </button>
              ))}
            </div>

            {activeSectionConfig ? (
              <section className="guide-detail-section guide-detail-preview" aria-label={tr(activeSectionConfig.label)}>
                <div className="guide-inline-header">
                  <span className="section-title">{tr(activeSectionConfig.label)}</span>
                  <span className="microcopy">{activeSectionConfig.lines.length} {tr("entries")}</span>
                </div>
                <GuideSectionList lines={previewLines} ordered={activeSectionConfig.ordered} />
                <div className="guide-preview-footer">
                  <span className="microcopy">
                    {previewRemaining > 0
                      ? `${previewRemaining} ${tr("more entries in briefing")}`
                      : tr("Full reference available in briefing")}
                  </span>
                  <button
                    type="button"
                    className="button guide-open-briefing"
                    onClick={() => openGuideOverlay(selectedItem.key, activeSection)}
                  >
                    {tr("Read full briefing")}
                  </button>
                </div>
              </section>
            ) : null}
          </article>
        </div>
      </section>

      <section className="guide-notes" aria-label={tr("Operator notes")}>
        <details className="guide-note-drawer">
          <summary>{tr("Trust signals")}</summary>
          <ul className="guide-drawer-list">
            {trustSignals.map((signal) => (
              <li key={signal.title}>
                <span className="note-title">{tr(signal.title)}</span>
                <span className="note-body">{tr(signal.detail)}</span>
              </li>
            ))}
          </ul>
        </details>

        <details className="guide-note-drawer">
          <summary>{tr("Workflow notes")}</summary>
          <ul className="guide-drawer-list">
            {workflowNotes.map((note) => (
              <li key={note.role}>
                <span className="note-title">{tr(note.role)}</span>
                <span className="note-body">{tr(note.note)}</span>
              </li>
            ))}
          </ul>
        </details>
      </section>

      <PanelOverlay
        open={overlayOpen}
        onClose={() => setOverlayOpen(false)}
        className="guide-overlay"
        kicker={
          overlayMode === "atlas"
            ? tr("Guide atlas / tool selection")
            : `:${selectedItem.key} / ${tr(selectedGroup?.label ?? "Guide entry")}`
        }
        title={overlayMode === "atlas" ? tr("Choose the right working surface") : tr(selectedItem.title)}
        summary={
          overlayMode === "atlas"
            ? tr("Compare grouped tools by purpose, then open the matching dossier without leaving the atlas.")
            : tr(selectedItem.whatItDoes)
        }
        actions={
          overlayMode === "entry" ? (
            <>
              <button type="button" className="button" onClick={focusGuideEntry}>
                {tr("Open full guide entry")}
              </button>
              {selectedItemIsModule && onOpenModule ? (
                <button
                  type="button"
                  className="button guide-open-module"
                  onClick={() => {
                    setOverlayOpen(false);
                    onOpenModule(selectedItem.key as ModuleKey);
                  }}
                >
                  {tr("Open")} :{selectedItem.key}
                </button>
              ) : null}
            </>
          ) : null
        }
      >
        {overlayMode === "atlas" ? (
          <div className="guide-overlay-shell guide-overlay-atlas-shell">
            <section className="guide-overlay-section" aria-label={tr("Tool selection routing notes")}>
              <div className="guide-inline-header">
                <span className="section-title">{tr("Routing notes")}</span>
                <span className="microcopy">{guideAtlasRoutingNotes.length} {tr("entries")}</span>
              </div>
              <GuideSectionList lines={guideAtlasRoutingNotes} ordered={false} />
            </section>

            <div className="guide-overlay-atlas-groups">
              {groupedItems.map((group) => (
                <section key={group.label} className="guide-index-group guide-overlay-atlas-group" aria-label={tr(group.label)}>
                  <div className="guide-index-header">
                    <span className="guide-index-label">{tr(group.label)}</span>
                    <span className="guide-index-copy">{tr(group.description)}</span>
                  </div>
                  <div className="guide-index-list">
                    {group.items.map((item) => (
                      <button
                        key={item.key}
                        type="button"
                        className={`guide-index-item ${selectedItem.key === item.key ? "is-active" : ""}`}
                        onClick={() => openGuideOverlay(item.key)}
                      >
                        <span className="guide-index-key">:{item.key}</span>
                        <span className="guide-index-body">
                          <span className="guide-index-title">{tr(item.title)}</span>
                          <span className="guide-index-summary">{tr(item.whatItDoes)}</span>
                        </span>
                      </button>
                    ))}
                  </div>
                </section>
              ))}
            </div>
          </div>
        ) : (
          <div className="guide-overlay-shell">
            <div className="guide-overlay-stats">
              <span>{tr(selectedGroup?.label ?? "Guide entry")}</span>
              <span>{selectedItem.howSteps.length} {tr("steps")}</span>
              <span>{selectedItem.limits.length} {tr("limits")}</span>
              {selectedItem.privacyNotes?.length ? <span>{selectedItem.privacyNotes.length} {tr("privacy notes")}</span> : null}
              <span>{tr("Build")} {buildShort}</span>
            </div>

            <div className="guide-overlay-nav" role="tablist" aria-label={tr("Guide briefing sections")}>
              {availableSections.map((section) => (
                <button
                  key={section.key}
                  type="button"
                  className={`guide-detail-tab ${overlaySection === section.key ? "is-active" : ""}`}
                  onClick={() => setOverlaySection(section.key)}
                  role="tab"
                  aria-selected={overlaySection === section.key}
                >
                  {tr(section.label)}
                </button>
              ))}
            </div>

            {overlaySectionConfig ? (
              <section className="guide-overlay-section" aria-label={tr(overlaySectionConfig.label)}>
                <div className="guide-inline-header">
                  <span className="section-title">{tr(overlaySectionConfig.label)}</span>
                  <span className="microcopy">{overlaySectionConfig.lines.length} {tr("entries")}</span>
                </div>
                <GuideSectionList lines={overlaySectionConfig.lines} ordered={overlaySectionConfig.ordered} />
              </section>
            ) : null}

            {selectedItem.key === "clipboard" ? (
              <section className="guide-overlay-section guide-overlay-controls" aria-label={tr("Clipboard controls")}>
                <div className="guide-inline-header">
                  <span className="section-title">{tr("Clipboard hygiene control")}</span>
                  <span className="microcopy">{tr("Adjust the local auto-clear behavior from the briefing panel.")}</span>
                </div>
                <div className="controls-row guide-clipboard-row" style={{ alignItems: "center" }}>
                  <label className="microcopy" htmlFor="guide-overlay-clipboard-clear">
                    {tr("Auto-clear clipboard")}
                  </label>
                  <div className="pill-buttons" role="group" aria-label={tr("Clipboard auto clear")}>
                    <button
                      id="guide-overlay-clipboard-clear"
                      type="button"
                      className={clipboardPrefs.enableAutoClearClipboard ? "active" : ""}
                      onClick={() =>
                        setClipboardPrefs((prev) => ({ ...prev, enableAutoClearClipboard: !prev.enableAutoClearClipboard }))
                      }
                    >
                      {clipboardPrefs.enableAutoClearClipboard ? tr("enabled") : tr("disabled")}
                    </button>
                  </div>
                  <label className="microcopy" htmlFor="guide-overlay-clipboard-seconds">
                    {tr("Clear after (seconds)")}
                  </label>
                  <input
                    id="guide-overlay-clipboard-seconds"
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
              </section>
            ) : null}
          </div>
        )}
      </PanelOverlay>
    </div>
  );
}

function DoctrineBlock({ title, lines }: { title: string; lines: string[] }) {
  const { tr } = useI18n();
  return (
    <section className="guide-doctrine-block">
      <span className="guide-block-title">{title}</span>
      <ul className="guide-block-list">
        {lines.map((line) => (
          <li key={line}>{tr(line)}</li>
        ))}
      </ul>
    </section>
  );
}

function GuideSectionList({ lines, ordered }: { lines: string[]; ordered: boolean }) {
  const { tr } = useI18n();
  const ListTag = ordered ? "ol" : "ul";

  return (
    <ListTag className={`guide-detail-list ${ordered ? "is-ordered" : ""}`}>
      {lines.map((line) => (
        <li key={line}>{tr(line)}</li>
      ))}
    </ListTag>
  );
}
