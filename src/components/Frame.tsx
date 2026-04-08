import { ReactNode } from "react";
import "./Frame.css";

interface FrameProps {
  modulePane: ReactNode;
  workspace: ReactNode;
  header?: ReactNode;
  showNavDrawer?: boolean;
  navDrawerOpen?: boolean;
  onCloseNavDrawer?: () => void;
}

export function Frame({ modulePane, workspace, header, showNavDrawer = false, navDrawerOpen = false, onCloseNavDrawer }: FrameProps) {
  return (
    <div className="frame">
      <div className="frame-shell">
        <div className="frame-ambient frame-ambient-primary" aria-hidden="true" />
        <div className="frame-ambient frame-ambient-secondary" aria-hidden="true" />
        {showNavDrawer ? (
          <div
            className={`frame-drawer-backdrop ${navDrawerOpen ? "is-open" : ""}`}
            aria-hidden={!navDrawerOpen}
            onMouseDown={(event) => {
              if (event.target === event.currentTarget) {
                onCloseNavDrawer?.();
              }
            }}
          >
            <aside className="frame-drawer-panel">{modulePane}</aside>
          </div>
        ) : null}
        <div className="frame-content">
          {!showNavDrawer ? <aside className="frame-pane">{modulePane}</aside> : null}
          <section className="frame-workspace">
            {header}
            {workspace}
          </section>
        </div>
      </div>
    </div>
  );
}
