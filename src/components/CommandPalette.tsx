import { useEffect, useMemo, useRef, useState } from "react";
import "./CommandPalette.css";
import { useCommandHistory } from "../hooks/useCommandHistory";
import { useI18n } from "../i18n";

export interface CommandItem {
  id: string;
  label: string;
  description?: string;
  group: string;
  shortcut?: string;
  disabled?: boolean;
  action: () => void | Promise<void>;
}

interface CommandPaletteProps {
  open: boolean;
  commands: CommandItem[];
  onClose: () => void;
  onSelect?: (command: CommandItem) => void;
  completions?: string[];
  historyKey?: string;
}

export function CommandPalette({ open, commands, completions = [], historyKey = "palette", onClose, onSelect }: CommandPaletteProps) {
  const { t } = useI18n();
  const inputRef = useRef<HTMLInputElement>(null);
  const [query, setQuery] = useState("");
  const [activeIndex, setActiveIndex] = useState(0);
  const history = useCommandHistory(historyKey);

  useEffect(() => {
    if (!open) return;
    setQuery("");
    requestAnimationFrame(() => inputRef.current?.focus());
    history.resetCursor();
  }, [open]);

  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if (event.key === "Escape" && open) {
        event.preventDefault();
        onClose();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [open, onClose]);

  const filtered = useMemo(() => {
    const terms = query.trim().toLowerCase();
    if (!terms) return commands;
    return commands.filter(
      (command) =>
        command.label.toLowerCase().includes(terms) ||
        command.id.toLowerCase().includes(terms) ||
        command.description?.toLowerCase().includes(terms),
    );
  }, [commands, query]);

  const grouped = useMemo(() => {
    const map = new Map<string, CommandItem[]>();
    filtered.forEach((command) => {
      const list = map.get(command.group) ?? [];
      list.push(command);
      map.set(command.group, list);
    });
    return Array.from(map.entries());
  }, [filtered]);

  const flat = useMemo(() => grouped.flatMap(([, items]) => items), [grouped]);

  useEffect(() => {
    if (activeIndex >= flat.length) {
      setActiveIndex(Math.max(flat.length - 1, 0));
    }
  }, [activeIndex, flat.length]);

  useEffect(() => {
    if (!open) return;
    const firstEnabled = flat.findIndex((command) => !command.disabled);
    setActiveIndex(firstEnabled >= 0 ? firstEnabled : 0);
  }, [flat, open]);

  const moveActive = (delta: 1 | -1) => {
    if (!flat.length) return;
    let next = activeIndex;
    for (let i = 0; i < flat.length; i += 1) {
      next = (next + delta + flat.length) % flat.length;
      if (!flat[next].disabled) break;
    }
    setActiveIndex(next);
  };

  const handleKeyDown = (event: React.KeyboardEvent) => {
    if (event.key === "Tab") {
      const terms = query.trim().toLowerCase();
      if (terms.startsWith(":")) {
        const match = completions.find((entry) => entry.toLowerCase().startsWith(terms.slice(1)));
        if (match) {
          event.preventDefault();
          const completed = `:${match}`;
          setQuery(completed);
          history.push(completed);
        }
      }
      return;
    }
    if (event.key === "ArrowUp" || event.key === "ArrowDown") {
      if (document.activeElement === inputRef.current) {
        event.preventDefault();
        const next = history.navigate(event.key === "ArrowUp" ? -1 : 1);
        setQuery(next);
        return;
      }
    }
    if (!flat.length) return;
    if (event.key === "ArrowDown") {
      event.preventDefault();
      moveActive(1);
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      moveActive(-1);
    } else if (event.key === "Enter") {
      event.preventDefault();
      const command = flat[activeIndex];
      if (!command?.disabled) {
        history.push(command.id);
        onSelect?.(command);
      }
    }
  };

  if (!open) return null;

  return (
    <div className="command-overlay" role="dialog" aria-modal="true" aria-label={t("app.commandPalette")}>
      <div className="command-surface">
        <div className="command-field">
          <span aria-hidden="true">/</span>
          <input
            ref={inputRef}
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder={t("app.commandInputPlaceholder")}
            onKeyDown={handleKeyDown}
            aria-label={t("app.searchCommands")}
          />
        </div>
        <div className="command-results" role="listbox" aria-label={t("app.commandsList")}>
          {grouped.length === 0 && <div className="command-empty">{t("app.noCommands")}</div>}
          {grouped.map(([group, items]) => (
            <div className="command-group" key={group}>
              <div className="command-group-title">{group}</div>
              <ul>
                {items.map((command) => {
                  const flatIndex = flat.indexOf(command);
                  const active = flatIndex === activeIndex;
                  const isDisabled = Boolean(command.disabled);
                  return (
                    <li key={command.id}>
                      <button
                        type="button"
                        className={`command-item ${active ? "active" : ""}`}
                        onClick={() => {
                          if (isDisabled) return;
                          onSelect?.(command);
                        }}
                        role="option"
                        aria-selected={active}
                        disabled={isDisabled}
                      >
                        <div className="command-label">
                          <span className="command-id">{command.id}</span>
                          <span className="command-text">{command.label}</span>
                        </div>
                        <div className="command-meta">
                          {command.description && <span className="command-desc">{command.description}</span>}
                          {command.shortcut && <kbd className="command-key">{command.shortcut}</kbd>}
                        </div>
                      </button>
                    </li>
                  );
                })}
              </ul>
            </div>
          ))}
        </div>
      </div>
      <button type="button" className="command-dismiss" aria-label={t("app.closeCommandPalette")} onClick={onClose} />
    </div>
  );
}
