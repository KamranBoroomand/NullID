import "./OnboardingTour.css";

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
  if (!open || steps.length === 0) return null;
  const step = steps[Math.min(stepIndex, steps.length - 1)];
  const isFirst = stepIndex === 0;
  const isLast = stepIndex >= steps.length - 1;

  return (
    <div className="tour-overlay" role="dialog" aria-modal="true" aria-label="Onboarding tour">
      <div className="tour-panel">
        <div className="tour-meta">
          <span className="tour-step">{`step ${stepIndex + 1}/${steps.length}`}</span>
          <button type="button" className="button" onClick={onSkip}>
            skip
          </button>
        </div>
        <h2 className="tour-title">{step.title}</h2>
        <p className="tour-body">{step.body}</p>
        <div className="tour-actions">
          <button type="button" className="button" onClick={() => onStepIndexChange(Math.max(0, stepIndex - 1))} disabled={isFirst}>
            back
          </button>
          {step.actionLabel && step.onAction ? (
            <button type="button" className="button" onClick={step.onAction}>
              {step.actionLabel}
            </button>
          ) : null}
          {isLast ? (
            <button type="button" className="button" onClick={onFinish}>
              finish
            </button>
          ) : (
            <button type="button" className="button" onClick={() => onStepIndexChange(stepIndex + 1)}>
              next
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
