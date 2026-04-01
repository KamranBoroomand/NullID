import { ReactNode } from "react";
import { useI18n } from "../i18n";
import "./Frame.css";

interface FrameProps {
  modulePane: ReactNode;
  workspace: ReactNode;
  header?: ReactNode;
  buildMarker?: string;
  stacked?: boolean;
  compact?: boolean;
}

export function Frame({ modulePane, workspace, header, buildMarker = "Version: Local", stacked, compact }: FrameProps) {
  const { t } = useI18n();

  return (
    <div className={`frame ${compact ? "frame-compact" : ""}`}>
      <div className="frame-shell">
        <div className={`frame-content ${stacked ? "is-stacked" : ""}`}>
          <aside className="frame-pane">{modulePane}</aside>
          <section className="frame-workspace">
            {header}
            {workspace}
          </section>
        </div>
        <div className="frame-footer" aria-label={t("app.buildMarker")}>
          <span>{buildMarker}</span>
        </div>
      </div>
    </div>
  );
}
