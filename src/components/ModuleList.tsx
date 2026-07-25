import { useEffect, useMemo, useRef, useState } from "react";
import { useI18n } from "../i18n";
import { BrandMark } from "./BrandMark";
import type { ThemeMode } from "../theme/tokens";
import "./ModuleList.css";

export type ModuleKey =
  | "hash"
  | "batch"
  | "share"
  | "incident"
  | "secret"
  | "analyze"
  | "finance"
  | "paths"
  | "redact"
  | "sanitize"
  | "verify"
  | "meta"
  | "enc"
  | "pw"
  | "vault"
  | "guide"
  | "selftest";

export interface ModuleDefinition {
  key: ModuleKey;
  title: string;
  subtitle: string;
}

interface ModuleListProps {
  modules: ModuleDefinition[];
  active: ModuleKey;
  onSelect: (key: ModuleKey) => void;
  buildMarker?: string;
  mode?: "rail" | "drawer";
  theme: ThemeMode;
}

export function ModuleList({ modules, active, onSelect, buildMarker = "", mode = "rail", theme }: ModuleListProps) {
  const { t, tr } = useI18n();
  const buttonsRef = useRef<(HTMLButtonElement | null)[]>([]);
  const activeIndex = useMemo(() => Math.max(0, modules.findIndex((module) => module.key === active)), [active, modules]);
  const [focusIndex, setFocusIndex] = useState(activeIndex);
  const activeModule = modules[activeIndex] ?? modules[0];
  const groupedModules = useMemo(
    () => [
      {
        label: tr("Core tools"),
        items: modules.filter((module) => ["hash", "batch", "share", "incident"].includes(module.key)),
      },
      {
        label: tr("Verification"),
        items: modules.filter((module) => ["verify", "meta"].includes(module.key)),
      },
      {
        label: tr("Privacy"),
        items: modules.filter((module) => ["redact", "sanitize", "secret", "analyze", "finance", "paths"].includes(module.key)),
      },
      {
        label: tr("Secrets"),
        items: modules.filter((module) => ["enc", "pw", "vault"].includes(module.key)),
      },
      {
        label: tr("Diagnostics"),
        items: modules.filter((module) => ["selftest", "guide"].includes(module.key)),
      },
    ].filter((group) => group.items.length > 0),
    [modules, tr],
  );

  useEffect(() => {
    setFocusIndex(activeIndex);
  }, [activeIndex]);

  const moveFocus = (delta: 1 | -1) => {
    if (!modules.length) return;
    const nextIndex = (focusIndex + delta + modules.length) % modules.length;
    setFocusIndex(nextIndex);
    buttonsRef.current[nextIndex]?.focus();
  };

  return (
    <div className={`module-list module-list-${mode}`}>
      <div className="module-header">
        <div className="module-header-copy">
          <span className="module-kicker">{tr("Local security workbench")}</span>
          <div className="module-title-row">
            <span className="module-brand-lockup">
              <BrandMark theme={theme} variant="wordmark" className="module-brand-wordmark" decorative={false} />
            </span>
            <span className="module-count" aria-label={tr("Module count")}>
              <span className="module-count-value">{modules.length}</span>
              <span className="module-count-label">{tr("modules")}</span>
            </span>
          </div>
          <div className="module-subtitle">{t("app.tools")}</div>
        </div>
      </div>
      {activeModule ? (
        <section className="module-focus" aria-label={tr("Active workspace")}>
          <span className="module-focus-label">{tr("Active workspace")}</span>
          <span className="module-focus-title">{activeModule.title}</span>
          <span className="module-focus-copy">{activeModule.subtitle}</span>
        </section>
      ) : null}
      <nav aria-label={t("app.moduleList")}>
        {groupedModules.map((group) => (
          <section key={group.label} className="module-group" aria-label={group.label}>
            <div className="module-group-label">{group.label}</div>
            <ul>
              {group.items.map((module) => {
                const index = modules.findIndex((entry) => entry.key === module.key);
                return (
                  <li key={module.key}>
                    <button
                      ref={(el) => {
                        buttonsRef.current[index] = el;
                      }}
                      type="button"
                      className={`module-button ${active === module.key ? "active" : ""}`}
                      onClick={() => {
                        setFocusIndex(index);
                        onSelect(module.key);
                      }}
                      onFocus={() => setFocusIndex(index)}
                      onKeyDown={(event) => {
                        if (event.key === "ArrowDown") {
                          event.preventDefault();
                          moveFocus(1);
                        } else if (event.key === "ArrowUp") {
                          event.preventDefault();
                          moveFocus(-1);
                        }
                      }}
                      aria-current={active === module.key}
                      tabIndex={focusIndex === index ? 0 : -1}
                    >
                      <span className="module-key">:{module.key}</span>
                      <span className="module-copy">
                        <span className="module-name">{module.title}</span>
                        <span className="module-sub">{module.subtitle}</span>
                      </span>
                      <span className="module-indicator" aria-hidden="true">+</span>
                    </button>
                  </li>
                );
              })}
            </ul>
          </section>
        ))}
      </nav>
      <div className="module-footer">
        <span>{tr("Press / for commands")}</span>
        {buildMarker ? <span>{buildMarker}</span> : <span>{tr("Keyboard and pointer friendly")}</span>}
      </div>
    </div>
  );
}
