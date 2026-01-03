import { useEffect, useMemo, useRef, useState } from "react";
import "./ModuleList.css";

export type ModuleKey =
  | "hash"
  | "redact"
  | "sanitize"
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
}

export function ModuleList({ modules, active, onSelect }: ModuleListProps) {
  const buttonsRef = useRef<(HTMLButtonElement | null)[]>([]);
  const activeIndex = useMemo(() => Math.max(0, modules.findIndex((module) => module.key === active)), [active, modules]);
  const [focusIndex, setFocusIndex] = useState(activeIndex);

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
    <div className="module-list">
      <div className="module-header">
        <div className="module-title">Tools</div>
        <div className="module-subtitle">Navigate</div>
      </div>
      <nav aria-label="Module list">
        <ul>
          {modules.map((module, index) => (
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
                <span className="module-indicator" aria-hidden="true">⟡</span>
              </button>
            </li>
          ))}
        </ul>
      </nav>
    </div>
  );
}
