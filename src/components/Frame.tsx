import { ReactNode } from "react";
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
      </div>
      <div className="frame-footer" aria-label="Build marker">
        <span>{buildMarker}</span>
      </div>
    </div>
  );
}
