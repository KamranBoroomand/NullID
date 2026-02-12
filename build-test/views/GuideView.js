import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
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
    const buildId = import.meta.env.VITE_BUILD_ID ?? "dev";
    const buildShort = buildId.slice(0, 7);
    return (_jsxs("div", { className: "workspace-scroll guide-surface", children: [_jsxs("div", { className: "panel", "aria-label": "Guide overview", children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: "Guide" }), _jsx("span", { className: "panel-subtext", children: "how to use NullID" })] }), _jsx("div", { className: "microcopy", children: "Offline-first tooling; no network calls, no analytics. All processing and clipboard actions are local and best-effort cleared." })] }), _jsxs("div", { className: "guide-grid", children: [_jsxs("article", { className: "panel guide-card", "aria-label": "Trust signals", children: [_jsx("div", { className: "guide-card-header", children: _jsxs("div", { className: "guide-card-title", children: [_jsx("span", { className: "guide-key", children: ":trust" }), _jsxs("div", { className: "guide-title-wrap", children: [_jsx("span", { className: "guide-name", children: "Trust Signals" }), _jsx("span", { className: "guide-summary", children: "Security posture at a glance" })] })] }) }), _jsx("ul", { className: "microcopy guide-list", children: trustSignals.map((signal) => (_jsxs("li", { children: [_jsx("span", { className: "note-title", children: signal.title }), _jsxs("span", { className: "note-body", children: [" ", signal.detail] })] }, signal.title))) })] }), _jsxs("article", { className: "panel guide-card", "aria-label": "Operator testimonials", children: [_jsx("div", { className: "guide-card-header", children: _jsxs("div", { className: "guide-card-title", children: [_jsx("span", { className: "guide-key", children: ":proof" }), _jsxs("div", { className: "guide-title-wrap", children: [_jsx("span", { className: "guide-name", children: "Operator Notes" }), _jsx("span", { className: "guide-summary", children: "Field feedback from common workflows" })] })] }) }), _jsx("ul", { className: "microcopy guide-list", children: operatorNotes.map((note) => (_jsxs("li", { children: [_jsx("span", { className: "note-title", children: note.role }), _jsxs("span", { className: "note-body", children: [" ", note.quote] })] }, note.role))) })] })] }), _jsx("div", { className: "guide-grid", children: guideTools.map((tool) => (_jsxs("article", { id: tool.key, className: "panel guide-card", "aria-label": `${tool.title} guide`, children: [_jsx("div", { className: "guide-card-header", children: _jsxs("div", { className: "guide-card-title", children: [_jsxs("span", { className: "guide-key", children: [":", tool.key] }), _jsxs("div", { className: "guide-title-wrap", children: [_jsx("span", { className: "guide-name", children: tool.title }), _jsx("span", { className: "guide-summary", children: tool.whatItDoes })] })] }) }), _jsx(GuideLists, { item: tool })] }, tool.key))) }), _jsx("div", { className: "guide-grid", children: guideExtras.map((item) => (_jsxs("article", { id: item.key, className: "panel guide-card", "aria-label": `${item.title} guidance`, children: [_jsx("div", { className: "guide-card-header", children: _jsxs("div", { className: "guide-card-title", children: [_jsxs("span", { className: "guide-key", children: [":", item.key] }), _jsxs("div", { className: "guide-title-wrap", children: [_jsx("span", { className: "guide-name", children: item.title }), _jsx("span", { className: "guide-summary", children: item.whatItDoes })] })] }) }), _jsx(GuideLists, { item: item }), item.key === "clipboard" && (_jsxs("div", { className: "controls-row guide-clipboard-row", style: { alignItems: "center" }, children: [_jsx("label", { className: "microcopy", htmlFor: "clipboard-clear", children: "Auto-clear clipboard" }), _jsx("div", { className: "pill-buttons", role: "group", "aria-label": "Clipboard auto clear", children: _jsx("button", { type: "button", className: clipboardPrefs.enableAutoClearClipboard ? "active" : "", onClick: () => setClipboardPrefs((prev) => ({ ...prev, enableAutoClearClipboard: !prev.enableAutoClearClipboard })), children: clipboardPrefs.enableAutoClearClipboard ? "enabled" : "disabled" }) }), _jsx("label", { className: "microcopy", htmlFor: "clipboard-seconds", children: "Clear after (seconds)" }), _jsx("input", { id: "clipboard-seconds", className: "input", type: "number", min: 5, max: 300, value: clipboardPrefs.clipboardClearSeconds, onChange: (event) => setClipboardPrefs((prev) => ({
                                        ...prev,
                                        clipboardClearSeconds: Math.max(5, Math.min(300, Number(event.target.value))),
                                    })), style: { width: "6rem" } })] }))] }, item.key))) }), _jsxs("div", { className: "microcopy", style: { marginTop: "1.25rem", textAlign: "center", color: "var(--text-muted)" }, children: ["Build ", buildShort] })] }));
}
function GuideLists({ item }) {
    return (_jsxs("div", { className: "guide-card-body", children: [_jsxs("div", { className: "guide-section", children: [_jsx("div", { className: "section-title", children: "What & when" }), _jsx("ul", { className: "microcopy guide-list", children: item.whatWhen.map((line) => (_jsx("li", { children: line }, line))) })] }), _jsxs("div", { className: "guide-section", children: [_jsx("div", { className: "section-title", children: "How" }), _jsx("ol", { className: "microcopy guide-list", children: item.howSteps.map((line) => (_jsx("li", { children: line }, line))) })] }), _jsxs("div", { className: "guide-section", children: [_jsx("div", { className: "section-title", children: "Common mistakes & limits" }), _jsx("ul", { className: "microcopy guide-list", children: item.limits.map((line) => (_jsx("li", { children: line }, line))) })] }), item.privacyNotes?.length ? (_jsxs("div", { className: "guide-section", children: [_jsx("div", { className: "section-title", children: "Privacy notes" }), _jsx("ul", { className: "microcopy guide-list", children: item.privacyNotes.map((line) => (_jsx("li", { children: line }, line))) })] })) : null] }));
}
