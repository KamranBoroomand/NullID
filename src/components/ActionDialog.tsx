import { useEffect, type ReactNode } from "react";
import "./ActionDialog.css";

interface ActionDialogProps {
  open: boolean;
  title: string;
  description?: string;
  confirmLabel?: string;
  cancelLabel?: string;
  confirmDisabled?: boolean;
  danger?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
  children?: ReactNode;
}

export function ActionDialog({
  open,
  title,
  description,
  confirmLabel = "confirm",
  cancelLabel = "cancel",
  confirmDisabled,
  danger = false,
  onConfirm,
  onCancel,
  children,
}: ActionDialogProps) {
  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onCancel();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onCancel, open]);

  if (!open) return null;

  return (
    <div
      className="action-dialog-overlay"
      role="dialog"
      aria-modal="true"
      aria-label={title}
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) {
          onCancel();
        }
      }}
    >
      <div className="action-dialog-panel">
        <div className="action-dialog-header">
          <h2>{title}</h2>
        </div>
        {description ? <p className="action-dialog-description">{description}</p> : null}
        {children ? <div className="action-dialog-body">{children}</div> : null}
        <div className="action-dialog-actions">
          <button type="button" className="button" onClick={onCancel}>
            {cancelLabel}
          </button>
          <button type="button" className={`button ${danger ? "action-dialog-danger" : ""}`} onClick={onConfirm} disabled={confirmDisabled}>
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
