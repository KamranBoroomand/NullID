import { ReactNode, useEffect, useRef } from "react";
import { createPortal } from "react-dom";
import { useI18n } from "../i18n";
import "./PanelOverlay.css";

interface PanelOverlayProps {
  open: boolean;
  title: string;
  kicker?: string;
  summary?: string;
  actions?: ReactNode;
  children: ReactNode;
  onClose: () => void;
  className?: string;
}

export function PanelOverlay({
  open,
  title,
  kicker,
  summary,
  actions,
  children,
  onClose,
  className,
}: PanelOverlayProps) {
  const { t } = useI18n();
  const closeButtonRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
      }
    };
    window.addEventListener("keydown", onKey);
    requestAnimationFrame(() => closeButtonRef.current?.focus());
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose, open]);

  if (!open) return null;

  const classes = ["panel-overlay-surface", className].filter(Boolean).join(" ");

  return createPortal(
    <div
      className="panel-overlay"
      role="dialog"
      aria-modal="true"
      aria-label={title}
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) {
          onClose();
        }
      }}
    >
      <section className={classes}>
        <header className="panel-overlay-header">
          <div className="panel-overlay-heading">
            {kicker ? <span className="panel-overlay-kicker">{kicker}</span> : null}
            <h2 className="panel-overlay-title">{title}</h2>
            {summary ? <p className="panel-overlay-summary">{summary}</p> : null}
          </div>
          <div className="panel-overlay-toolbar">
            {actions ? <div className="panel-overlay-actions">{actions}</div> : null}
            <button
              ref={closeButtonRef}
              type="button"
              className="button panel-overlay-close"
              onClick={onClose}
              aria-label={t("app.close")}
            >
              {t("app.close")}
            </button>
          </div>
        </header>
        <div className="panel-overlay-body">{children}</div>
      </section>
    </div>,
    document.body,
  );
}
