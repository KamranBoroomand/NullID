import { useCallback, useEffect, useMemo, useRef, useState, type PointerEvent as ReactPointerEvent } from "react";
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
  const previousFocusRef = useRef<HTMLElement | null>(null);
  const lastPointerPositionRef = useRef<{ x: number; y: number } | null>(null);
  const wasOpenRef = useRef(false);
  const previousQueryRef = useRef("");
  const [query, setQuery] = useState("");
  const [activeIndex, setActiveIndex] = useState(0);
  const history = useCommandHistory(historyKey);

  const closeAndRestoreFocus = useCallback(() => {
    onClose();
    requestAnimationFrame(() => previousFocusRef.current?.focus());
  }, [onClose]);

  useEffect(() => {
    if (!open) return;
    previousFocusRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    setQuery("");
    requestAnimationFrame(() => inputRef.current?.focus());
    history.resetCursor();
  }, [history, open]);

  useEffect(() => {
    const trackPointer = (event: PointerEvent) => {
      if (event.pointerType === "touch") return;
      lastPointerPositionRef.current = { x: event.clientX, y: event.clientY };
    };
    window.addEventListener("pointermove", trackPointer, { passive: true });
    return () => window.removeEventListener("pointermove", trackPointer);
  }, []);

  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if (event.key === "Escape" && open) {
        event.preventDefault();
        closeAndRestoreFocus();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [closeAndRestoreFocus, open]);

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
  const activeCommand = flat[activeIndex];
  const activeOptionId = activeCommand ? `command-option-${activeCommand.id.replace(/[^a-z0-9_-]+/gi, "-")}` : undefined;

  useEffect(() => {
    if (!open) {
      wasOpenRef.current = false;
      previousQueryRef.current = query;
      return;
    }

    const shouldReset = !wasOpenRef.current || previousQueryRef.current !== query;
    wasOpenRef.current = true;
    previousQueryRef.current = query;
    const firstEnabled = flat.findIndex((command) => !command.disabled);
    const fallbackIndex = firstEnabled >= 0 ? firstEnabled : 0;
    setActiveIndex((currentIndex) => {
      if (shouldReset) return fallbackIndex;
      const currentCommand = flat[currentIndex];
      if (!currentCommand || currentCommand.disabled) return fallbackIndex;
      return currentIndex;
    });
  }, [flat, open, query]);

  const moveActive = (delta: 1 | -1) => {
    if (!flat.length) return;
    setActiveIndex((currentIndex) => {
      let next = currentIndex;
      for (let i = 0; i < flat.length; i += 1) {
        next = (next + delta + flat.length) % flat.length;
        if (!flat[next].disabled) break;
      }
      return next;
    });
  };

  const selectCommand = useCallback(
    (command: CommandItem | undefined) => {
      if (!command || command.disabled) return;
      history.push(command.id);
      onSelect?.(command);
    },
    [history, onSelect],
  );

  const activateFromPointerMove = useCallback((event: ReactPointerEvent<HTMLDivElement>, flatIndex: number, disabled: boolean) => {
    if (disabled || event.pointerType === "touch") return;
    const previous = lastPointerPositionRef.current;
    const next = { x: event.clientX, y: event.clientY };
    lastPointerPositionRef.current = next;
    if (previous && previous.x === next.x && previous.y === next.y) return;
    setActiveIndex(flatIndex);
  }, []);

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
      if (event.altKey) {
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
      selectCommand(flat[activeIndex]);
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
            aria-controls="command-results"
            aria-activedescendant={activeOptionId}
          />
        </div>
        <div id="command-results" className="command-results" role="listbox" aria-label={t("app.commandsList")}>
          {grouped.length === 0 && <div className="command-empty">{t("app.noCommands")}</div>}
          {grouped.map(([group, items]) => (
            <div className="command-group" key={group}>
              <div className="command-group-title">{group}</div>
              <ul>
                {items.map((command) => {
                  const flatIndex = flat.indexOf(command);
                  const active = flatIndex === activeIndex;
                  const isDisabled = Boolean(command.disabled);
                  const optionId = `command-option-${command.id.replace(/[^a-z0-9_-]+/gi, "-")}`;
                  return (
                    <li key={command.id}>
                      <div
                        id={optionId}
                        className={`command-item ${active ? "active" : ""}`}
                        role="option"
                        aria-selected={active}
                        aria-disabled={isDisabled}
                        tabIndex={-1}
                        onMouseDown={(event) => event.preventDefault()}
                        onPointerMove={(event) => activateFromPointerMove(event, flatIndex, isDisabled)}
                        onClick={() => selectCommand(command)}
                      >
                        <div className="command-label">
                          <span className="command-id">{command.id}</span>
                          <span className="command-text">{command.label}</span>
                        </div>
                        <div className="command-meta">
                          {command.description && <span className="command-desc">{command.description}</span>}
                          {command.shortcut && <kbd className="command-key">{command.shortcut}</kbd>}
                        </div>
                      </div>
                    </li>
                  );
                })}
              </ul>
            </div>
          ))}
        </div>
      </div>
      <button type="button" className="command-dismiss" aria-label={t("app.closeCommandPalette")} onClick={closeAndRestoreFocus} />
    </div>
  );
}
