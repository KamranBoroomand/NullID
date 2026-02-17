import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import "./OnboardingTour.css";
import { useI18n } from "../i18n";
export function OnboardingTour({ open, stepIndex, steps, onStepIndexChange, onSkip, onFinish }) {
    const { t } = useI18n();
    if (!open || steps.length === 0)
        return null;
    const step = steps[Math.min(stepIndex, steps.length - 1)];
    const isFirst = stepIndex === 0;
    const isLast = stepIndex >= steps.length - 1;
    return (_jsx("div", { className: "tour-overlay", role: "dialog", "aria-modal": "true", "aria-label": t("onboarding.dialog"), children: _jsxs("div", { className: "tour-panel", children: [_jsxs("div", { className: "tour-meta", children: [_jsx("span", { className: "tour-step", children: t("onboarding.step", { current: stepIndex + 1, total: steps.length }) }), _jsx("button", { type: "button", className: "button", onClick: onSkip, children: t("onboarding.skip") })] }), _jsx("h2", { className: "tour-title", children: step.title }), _jsx("p", { className: "tour-body", children: step.body }), _jsxs("div", { className: "tour-actions", children: [_jsx("button", { type: "button", className: "button", onClick: () => onStepIndexChange(Math.max(0, stepIndex - 1)), disabled: isFirst, children: t("onboarding.back") }), step.actionLabel && step.onAction ? (_jsx("button", { type: "button", className: "button", onClick: step.onAction, children: step.actionLabel })) : null, isLast ? (_jsx("button", { type: "button", className: "button", onClick: onFinish, children: t("onboarding.finish") })) : (_jsx("button", { type: "button", className: "button", onClick: () => onStepIndexChange(stepIndex + 1), children: t("onboarding.next") }))] })] }) }));
}
