import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useRef, useState } from "react";
import "./TerminalInput.css";
export function TerminalInput({ onSubmit }) {
    const [value, setValue] = useState("");
    const inputRef = useRef(null);
    const handleSubmit = (event) => {
        event.preventDefault();
        onSubmit(value.trim());
        setValue("");
        inputRef.current?.focus();
    };
    return (_jsxs("form", { className: "terminal-input", onSubmit: handleSubmit, children: [_jsx("label", { className: "terminal-label", htmlFor: "command-input", children: "cmd" }), _jsxs("div", { className: "terminal-field", children: [_jsx("span", { "aria-hidden": "true", children: ":" }), _jsx("input", { id: "command-input", ref: inputRef, value: value, onChange: (event) => setValue(event.target.value), placeholder: "hash | redact | sanitize | meta | enc | pw | vault", autoComplete: "off", spellCheck: false, "aria-label": "Command line" })] }), _jsx("button", { type: "submit", className: "terminal-submit", "aria-label": "Execute command", children: "return" })] }));
}
