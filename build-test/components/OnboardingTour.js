import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import "./OnboardingTour.css";
export function OnboardingTour({ open, stepIndex, steps, onStepIndexChange, onSkip, onFinish }) {
    if (!open || steps.length === 0)
        return null;
    const step = steps[Math.min(stepIndex, steps.length - 1)];
    const isFirst = stepIndex === 0;
    const isLast = stepIndex >= steps.length - 1;
    return (_jsx("div", { className: "tour-overlay", role: "dialog", "aria-modal": "true", "aria-label": "Onboarding tour", children: _jsxs("div", { className: "tour-panel", children: [_jsxs("div", { className: "tour-meta", children: [_jsx("span", { className: "tour-step", children: `step ${stepIndex + 1}/${steps.length}` }), _jsx("button", { type: "button", className: "button", onClick: onSkip, children: "skip" })] }), _jsx("h2", { className: "tour-title", children: step.title }), _jsx("p", { className: "tour-body", children: step.body }), _jsxs("div", { className: "tour-actions", children: [_jsx("button", { type: "button", className: "button", onClick: () => onStepIndexChange(Math.max(0, stepIndex - 1)), disabled: isFirst, children: "back" }), step.actionLabel && step.onAction ? (_jsx("button", { type: "button", className: "button", onClick: step.onAction, children: step.actionLabel })) : null, isLast ? (_jsx("button", { type: "button", className: "button", onClick: onFinish, children: "finish" })) : (_jsx("button", { type: "button", className: "button", onClick: () => onStepIndexChange(stepIndex + 1), children: "next" }))] })] }) }));
}
