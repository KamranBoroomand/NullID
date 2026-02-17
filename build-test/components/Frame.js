import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import "./Frame.css";
export function Frame({ modulePane, workspace, header, buildMarker = "Version: Local", stacked, compact }) {
    return (_jsx("div", { className: `frame ${compact ? "frame-compact" : ""}`, children: _jsxs("div", { className: "frame-shell", children: [_jsxs("div", { className: `frame-content ${stacked ? "is-stacked" : ""}`, children: [_jsx("aside", { className: "frame-pane", children: modulePane }), _jsxs("section", { className: "frame-workspace", children: [header, workspace] })] }), _jsx("div", { className: "frame-footer", "aria-label": "Build marker", children: _jsx("span", { children: buildMarker }) })] }) }));
}
