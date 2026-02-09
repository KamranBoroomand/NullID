import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useEffect, useMemo, useRef, useState } from "react";
import "./ModuleList.css";
export function ModuleList({ modules, active, onSelect }) {
    const buttonsRef = useRef([]);
    const activeIndex = useMemo(() => Math.max(0, modules.findIndex((module) => module.key === active)), [active, modules]);
    const [focusIndex, setFocusIndex] = useState(activeIndex);
    useEffect(() => {
        setFocusIndex(activeIndex);
    }, [activeIndex]);
    const moveFocus = (delta) => {
        if (!modules.length)
            return;
        const nextIndex = (focusIndex + delta + modules.length) % modules.length;
        setFocusIndex(nextIndex);
        buttonsRef.current[nextIndex]?.focus();
    };
    return (_jsxs("div", { className: "module-list", children: [_jsxs("div", { className: "module-header", children: [_jsx("div", { className: "module-title", children: "Tools" }), _jsx("div", { className: "module-subtitle", children: "Navigate" })] }), _jsx("nav", { "aria-label": "Module list", children: _jsx("ul", { children: modules.map((module, index) => (_jsx("li", { children: _jsxs("button", { ref: (el) => {
                                buttonsRef.current[index] = el;
                            }, type: "button", className: `module-button ${active === module.key ? "active" : ""}`, onClick: () => {
                                setFocusIndex(index);
                                onSelect(module.key);
                            }, onFocus: () => setFocusIndex(index), onKeyDown: (event) => {
                                if (event.key === "ArrowDown") {
                                    event.preventDefault();
                                    moveFocus(1);
                                }
                                else if (event.key === "ArrowUp") {
                                    event.preventDefault();
                                    moveFocus(-1);
                                }
                            }, "aria-current": active === module.key, tabIndex: focusIndex === index ? 0 : -1, children: [_jsxs("span", { className: "module-key", children: [":", module.key] }), _jsxs("span", { className: "module-copy", children: [_jsx("span", { className: "module-name", children: module.title }), _jsx("span", { className: "module-sub", children: module.subtitle })] }), _jsx("span", { className: "module-indicator", "aria-hidden": "true", children: "\u27E1" })] }) }, module.key))) }) })] }));
}
