import "./OnboardingTour.css";
import { useI18n } from "../i18n";

export interface OnboardingStep {
  id: string;
  title: string;
  body: string;
  actionLabel?: string;
  onAction?: () => void;
}

interface OnboardingTourProps {
  open: boolean;
  stepIndex: number;
  steps: OnboardingStep[];
  onStepIndexChange: (index: number) => void;
  onSkip: () => void;
  onFinish: () => void;
}

export function OnboardingTour({ open, stepIndex, steps, onStepIndexChange, onSkip, onFinish }: OnboardingTourProps) {
  const { t } = useI18n();
  if (!open || steps.length === 0) return null;
  const step = steps[Math.min(stepIndex, steps.length - 1)];
  const isFirst = stepIndex === 0;
  const isLast = stepIndex >= steps.length - 1;

  return (
    <div className="tour-overlay" role="dialog" aria-modal="true" aria-label={t("onboarding.dialog")}>
      <div className="tour-panel">
        <div className="tour-meta">
          <span className="tour-step">{t("onboarding.step", { current: stepIndex + 1, total: steps.length })}</span>
          <button type="button" className="button" onClick={onSkip}>
            {t("onboarding.skip")}
          </button>
        </div>
        <h2 className="tour-title">{step.title}</h2>
        <p className="tour-body">{step.body}</p>
        <div className="tour-actions">
          <button type="button" className="button" onClick={() => onStepIndexChange(Math.max(0, stepIndex - 1))} disabled={isFirst}>
            {t("onboarding.back")}
          </button>
          {step.actionLabel && step.onAction ? (
            <button type="button" className="button" onClick={step.onAction}>
              {step.actionLabel}
            </button>
          ) : null}
          {isLast ? (
            <button type="button" className="button" onClick={onFinish}>
              {t("onboarding.finish")}
            </button>
          ) : (
            <button type="button" className="button" onClick={() => onStepIndexChange(stepIndex + 1)}>
              {t("onboarding.next")}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
