import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
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
    const buildId = import.meta.env.VITE_BUILD_ID ?? "dev";
    const buildShort = buildId.slice(0, 7);
    return (_jsxs("div", { className: "workspace-scroll guide-surface", children: [_jsxs("div", { className: "panel", "aria-label": tr("Guide overview"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("Guide") }), _jsx("span", { className: "panel-subtext", children: tr("how to use NullID") })] }), _jsx("div", { className: "microcopy", children: tr("Offline-first tooling; no network calls, no analytics. All processing and clipboard actions are local and best-effort cleared.") })] }), _jsxs("div", { className: "guide-grid", children: [_jsxs("article", { className: "panel guide-card", "aria-label": tr("Trust signals"), children: [_jsx("div", { className: "guide-card-header", children: _jsxs("div", { className: "guide-card-title", children: [_jsx("span", { className: "guide-key", children: ":trust" }), _jsxs("div", { className: "guide-title-wrap", children: [_jsx("span", { className: "guide-name", children: tr("Trust Signals") }), _jsx("span", { className: "guide-summary", children: tr("Security posture at a glance") })] })] }) }), _jsx("ul", { className: "microcopy guide-list", children: trustSignals.map((signal) => (_jsxs("li", { children: [_jsx("span", { className: "note-title", children: tr(signal.title) }), _jsxs("span", { className: "note-body", children: [" ", tr(signal.detail)] })] }, signal.title))) })] }), _jsxs("article", { className: "panel guide-card", "aria-label": tr("Workflow notes"), children: [_jsx("div", { className: "guide-card-header", children: _jsxs("div", { className: "guide-card-title", children: [_jsx("span", { className: "guide-key", children: ":proof" }), _jsxs("div", { className: "guide-title-wrap", children: [_jsx("span", { className: "guide-name", children: tr("Workflow Notes") }), _jsx("span", { className: "guide-summary", children: tr("Operational guidance for common workflows") })] })] }) }), _jsx("ul", { className: "microcopy guide-list", children: workflowNotes.map((note) => (_jsxs("li", { children: [_jsx("span", { className: "note-title", children: tr(note.role) }), _jsxs("span", { className: "note-body", children: [" ", tr(note.note)] })] }, note.role))) })] })] }), _jsx("div", { className: "guide-grid", children: guideTools.map((tool) => (_jsxs("article", { id: tool.key, className: "panel guide-card", "aria-label": `${tr(tool.title)} ${tr("guide")}`, children: [_jsx("div", { className: "guide-card-header", children: _jsxs("div", { className: "guide-card-title", children: [_jsxs("span", { className: "guide-key", children: [":", tool.key] }), _jsxs("div", { className: "guide-title-wrap", children: [_jsx("span", { className: "guide-name", children: tr(tool.title) }), _jsx("span", { className: "guide-summary", children: tr(tool.whatItDoes) })] })] }) }), _jsx(GuideLists, { item: tool })] }, tool.key))) }), _jsx("div", { className: "guide-grid", children: guideExtras.map((item) => (_jsxs("article", { id: item.key, className: "panel guide-card", "aria-label": `${tr(item.title)} ${tr("guidance")}`, children: [_jsx("div", { className: "guide-card-header", children: _jsxs("div", { className: "guide-card-title", children: [_jsxs("span", { className: "guide-key", children: [":", item.key] }), _jsxs("div", { className: "guide-title-wrap", children: [_jsx("span", { className: "guide-name", children: tr(item.title) }), _jsx("span", { className: "guide-summary", children: tr(item.whatItDoes) })] })] }) }), _jsx(GuideLists, { item: item }), item.key === "clipboard" && (_jsxs("div", { className: "controls-row guide-clipboard-row", style: { alignItems: "center" }, children: [_jsx("label", { className: "microcopy", htmlFor: "clipboard-clear", children: tr("Auto-clear clipboard") }), _jsx("div", { className: "pill-buttons", role: "group", "aria-label": tr("Clipboard auto clear"), children: _jsx("button", { type: "button", className: clipboardPrefs.enableAutoClearClipboard ? "active" : "", onClick: () => setClipboardPrefs((prev) => ({ ...prev, enableAutoClearClipboard: !prev.enableAutoClearClipboard })), children: clipboardPrefs.enableAutoClearClipboard ? tr("enabled") : tr("disabled") }) }), _jsx("label", { className: "microcopy", htmlFor: "clipboard-seconds", children: tr("Clear after (seconds)") }), _jsx("input", { id: "clipboard-seconds", className: "input", type: "number", min: 5, max: 300, value: clipboardPrefs.clipboardClearSeconds, onChange: (event) => setClipboardPrefs((prev) => ({
                                        ...prev,
                                        clipboardClearSeconds: Math.max(5, Math.min(300, Number(event.target.value))),
                                    })), style: { width: "6rem" } })] }))] }, item.key))) }), _jsxs("div", { className: "microcopy", style: { marginTop: "1.25rem", textAlign: "center", color: "var(--text-muted)" }, children: [tr("Build"), " ", buildShort] })] }));
}
function GuideLists({ item }) {
    const { tr } = useI18n();
    return (_jsxs("div", { className: "guide-card-body", children: [_jsxs("div", { className: "guide-section", children: [_jsx("div", { className: "section-title", children: tr("What & when") }), _jsx("ul", { className: "microcopy guide-list", children: item.whatWhen.map((line) => (_jsx("li", { children: tr(line) }, line))) })] }), _jsxs("div", { className: "guide-section", children: [_jsx("div", { className: "section-title", children: tr("How") }), _jsx("ol", { className: "microcopy guide-list", children: item.howSteps.map((line) => (_jsx("li", { children: tr(line) }, line))) })] }), _jsxs("div", { className: "guide-section", children: [_jsx("div", { className: "section-title", children: tr("Common mistakes & limits") }), _jsx("ul", { className: "microcopy guide-list", children: item.limits.map((line) => (_jsx("li", { children: tr(line) }, line))) })] }), item.privacyNotes?.length ? (_jsxs("div", { className: "guide-section", children: [_jsx("div", { className: "section-title", children: tr("Privacy notes") }), _jsx("ul", { className: "microcopy guide-list", children: item.privacyNotes.map((line) => (_jsx("li", { children: tr(line) }, line))) })] })) : null] }));
}
