import { FormEvent, useRef, useState } from "react";
import { useI18n } from "../i18n";
import "./TerminalInput.css";

interface TerminalInputProps {
  onSubmit: (value: string) => void;
}

export function TerminalInput({ onSubmit }: TerminalInputProps) {
  const { tr } = useI18n();
  const [value, setValue] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault();
    onSubmit(value.trim());
    setValue("");
    inputRef.current?.focus();
  };

  return (
    <form className="terminal-input" onSubmit={handleSubmit}>
      <label className="terminal-label" htmlFor="command-input">
        {tr("cmd")}
      </label>
      <div className="terminal-field">
        <span aria-hidden="true">:</span>
        <input
          id="command-input"
          ref={inputRef}
          value={value}
          onChange={(event) => setValue(event.target.value)}
          placeholder={tr("hash | redact | sanitize | meta | enc | pw | vault")}
          autoComplete="off"
          spellCheck={false}
          aria-label={tr("Command line")}
        />
      </div>
      <button type="submit" className="terminal-submit" aria-label={tr("Execute command")}>
        {tr("return")}
      </button>
    </form>
  );
}
