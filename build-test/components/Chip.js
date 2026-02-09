import { jsx as _jsx } from "react/jsx-runtime";
import "./Chip.css";
export function Chip({ label, tone = "neutral", ariaLabel }) {
    return (_jsx("span", { className: `chip chip-${tone}`, "aria-label": ariaLabel ?? label, children: label }));
}
