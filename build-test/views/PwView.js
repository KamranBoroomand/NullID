import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useEffect, useMemo, useState } from "react";
import "./styles.css";
import { useToast } from "../components/ToastHost";
import { usePersistentState } from "../hooks/usePersistentState";
import { useClipboardPrefs, writeClipboard } from "../utils/clipboard";
const symbols = "!@#$%^&*()-_=+[]{}<>?/|~";
const ambiguous = new Set(["l", "1", "I", "O", "0", "o"]);
export function PwView({ onOpenGuide }) {
    const { push } = useToast();
    const [clipboardPrefs] = useClipboardPrefs();
    const [passwordSettings, setPasswordSettings] = usePersistentState("nullid:pw-settings", {
        length: 20,
        upper: true,
        lower: true,
        digits: true,
        symbols: true,
        avoidAmbiguity: true,
        enforceMix: true,
    });
    const [passphraseSettings, setPassphraseSettings] = usePersistentState("nullid:pp-settings", {
        words: 5,
        separator: "-",
        randomCase: true,
        appendNumber: true,
        appendSymbol: true,
    });
    const [password, setPassword] = useState("");
    const [phrase, setPhrase] = useState("");
    const [wordlist] = useState(() => buildWordlist());
    useEffect(() => {
        setPassword(generatePassword(passwordSettings));
    }, [passwordSettings]);
    useEffect(() => {
        setPhrase(generatePassphrase(passphraseSettings, wordlist));
    }, [passphraseSettings, wordlist]);
    const passwordEntropy = useMemo(() => estimatePasswordEntropy(passwordSettings), [passwordSettings]);
    const passphraseEntropy = useMemo(() => estimatePassphraseEntropy(passphraseSettings, wordlist?.length ?? 0), [passphraseSettings, wordlist]);
    const applyPreset = (preset) => {
        if (preset === "high") {
            setPasswordSettings({ length: 24, upper: true, lower: true, digits: true, symbols: true, avoidAmbiguity: true, enforceMix: true });
        }
        else if (preset === "nosym") {
            setPasswordSettings({ length: 18, upper: true, lower: true, digits: true, symbols: false, avoidAmbiguity: true, enforceMix: true });
        }
        else {
            setPasswordSettings({ length: 8, upper: false, lower: false, digits: true, symbols: false, avoidAmbiguity: false, enforceMix: true });
        }
    };
    return (_jsxs("div", { className: "workspace-scroll", children: [_jsx("div", { className: "guide-link", children: _jsx("button", { type: "button", className: "guide-link-button", onClick: () => onOpenGuide?.("pw"), children: "? guide" }) }), _jsxs("div", { className: "grid-two", children: [_jsxs("div", { className: "panel", "aria-label": "Password generator", children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: "Password" }), _jsx("span", { className: "panel-subtext", children: "entropy-forward" })] }), _jsxs("div", { className: "controls-row", children: [_jsx("input", { className: "input", value: password, readOnly: true, "aria-label": "Password output" }), _jsx("button", { className: "button", type: "button", onClick: () => setPassword(generatePassword(passwordSettings)), children: "regenerate" }), _jsx("button", { className: "button", type: "button", onClick: () => writeClipboard(password, clipboardPrefs, (message, tone) => push(message, tone === "danger" ? "danger" : tone === "accent" ? "accent" : "neutral"), "password copied"), children: "copy" })] }), _jsxs("div", { className: "controls-row", children: [_jsx("label", { className: "section-title", htmlFor: "password-length", children: "Length" }), _jsx("input", { id: "password-length", className: "input", type: "number", min: 8, max: 64, value: passwordSettings.length, onChange: (event) => setPasswordSettings((prev) => ({
                                            ...prev,
                                            length: clamp(Number(event.target.value) || 0, 8, 64),
                                        })), "aria-label": "Password length" }), _jsx("div", { className: "pill-buttons", role: "group", "aria-label": "Character sets", children: ["upper", "lower", "digits", "symbols"].map((key) => (_jsx("button", { type: "button", className: passwordSettings[key] ? "active" : "", onClick: () => setPasswordSettings((prev) => ({
                                                ...prev,
                                                [key]: !prev[key],
                                            })), "aria-label": `Toggle ${key} characters`, children: key }, key))) })] }), _jsxs("div", { className: "controls-row", children: [_jsx("label", { className: "section-title", htmlFor: "avoid-ambiguous", children: "Hardening" }), _jsxs("div", { className: "pill-buttons", role: "group", "aria-label": "Hardening options", children: [_jsx("button", { id: "avoid-ambiguous", type: "button", className: passwordSettings.avoidAmbiguity ? "active" : "", onClick: () => setPasswordSettings((prev) => ({ ...prev, avoidAmbiguity: !prev.avoidAmbiguity })), "aria-label": "Avoid ambiguous characters", children: "avoid ambiguous" }), _jsx("button", { type: "button", className: passwordSettings.enforceMix ? "active" : "", onClick: () => setPasswordSettings((prev) => ({ ...prev, enforceMix: !prev.enforceMix })), "aria-label": "Require all selected character types", children: "require all sets" })] })] }), _jsxs("div", { className: "controls-row", children: [_jsx("span", { className: "section-title", children: "Presets" }), _jsxs("div", { className: "pill-buttons", role: "group", "aria-label": "Password presets", children: [_jsx("button", { type: "button", onClick: () => applyPreset("high"), children: "high security" }), _jsx("button", { type: "button", onClick: () => applyPreset("nosym"), children: "no symbols" }), _jsx("button", { type: "button", onClick: () => applyPreset("pin"), children: "pin (digits)" })] })] }), _jsxs("div", { className: "status-line", children: [_jsxs("span", { children: ["length ", passwordSettings.length] }), _jsxs("span", { className: "tag tag-accent", children: ["entropy \u2248 ", passwordEntropy, " bits"] })] })] }), _jsxs("div", { className: "panel", "aria-label": "Passphrase generator", children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: "Passphrase" }), _jsx("span", { className: "panel-subtext", children: "human-readable" })] }), _jsxs("div", { className: "controls-row", children: [_jsx("input", { className: "input", value: phrase, readOnly: true, "aria-label": "Passphrase output" }), _jsx("button", { className: "button", type: "button", onClick: () => setPhrase(generatePassphrase(passphraseSettings, wordlist)), children: "regenerate" }), _jsx("button", { className: "button", type: "button", onClick: () => writeClipboard(phrase, clipboardPrefs, (message, tone) => push(message, tone === "danger" ? "danger" : tone === "accent" ? "accent" : "neutral"), "passphrase copied"), children: "copy" })] }), _jsxs("div", { className: "controls-row", children: [_jsx("label", { className: "section-title", htmlFor: "word-count", children: "Words" }), _jsx("input", { id: "word-count", className: "input", type: "number", min: 3, max: 10, value: passphraseSettings.words, onChange: (event) => setPassphraseSettings((prev) => ({
                                            ...prev,
                                            words: clamp(Number(event.target.value) || 0, 3, 10),
                                        })), "aria-label": "Passphrase word count" }), _jsxs("select", { className: "select", value: passphraseSettings.separator, onChange: (event) => setPassphraseSettings((prev) => ({
                                            ...prev,
                                            separator: event.target.value,
                                        })), "aria-label": "Word separator", children: [_jsx("option", { value: "space", children: "space" }), _jsx("option", { value: "-", children: "-" }), _jsx("option", { value: ".", children: "." }), _jsx("option", { value: "_", children: "_" })] })] }), _jsxs("div", { className: "controls-row", children: [_jsx("label", { className: "section-title", htmlFor: "phrase-hardening", children: "Hardening" }), _jsxs("div", { className: "pill-buttons", role: "group", "aria-label": "Passphrase options", children: [_jsx("button", { id: "phrase-hardening", type: "button", className: passphraseSettings.randomCase ? "active" : "", onClick: () => setPassphraseSettings((prev) => ({ ...prev, randomCase: !prev.randomCase })), "aria-label": "Randomly vary word casing", children: "random case" }), _jsx("button", { type: "button", className: passphraseSettings.appendNumber ? "active" : "", onClick: () => setPassphraseSettings((prev) => ({ ...prev, appendNumber: !prev.appendNumber })), "aria-label": "Append number", children: "append number" }), _jsx("button", { type: "button", className: passphraseSettings.appendSymbol ? "active" : "", onClick: () => setPassphraseSettings((prev) => ({ ...prev, appendSymbol: !prev.appendSymbol })), "aria-label": "Append symbol", children: "append symbol" })] })] }), _jsxs("div", { className: "status-line", children: [_jsxs("span", { children: ["words ", passphraseSettings.words] }), _jsxs("span", { className: "tag tag-accent", children: ["entropy \u2248 ", passphraseEntropy, " bits"] })] })] })] }), _jsxs("div", { className: "panel", "aria-label": "Config line", children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: "Config" }), _jsx("span", { className: "panel-subtext", children: "status" })] }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: "charset" }), _jsx("span", { className: "tag tag-accent", children: [
                                    passwordSettings.upper && "upper",
                                    passwordSettings.lower && "lower",
                                    passwordSettings.digits && "digits",
                                    passwordSettings.symbols && "symbols",
                                ]
                                    .filter(Boolean)
                                    .join(" / ") }), _jsxs("span", { className: "tag", children: ["entropy budget: ", passwordEntropy, "b"] })] })] })] }));
}
function generatePassword(settings) {
    const pools = [];
    if (settings.upper)
        pools.push("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    if (settings.lower)
        pools.push("abcdefghijklmnopqrstuvwxyz");
    if (settings.digits)
        pools.push("0123456789");
    if (settings.symbols)
        pools.push(symbols);
    if (pools.length === 0) {
        pools.push("abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }
    const filteredPools = settings.avoidAmbiguity ? pools.map((pool) => [...pool].filter((c) => !ambiguous.has(c)).join("")) : pools;
    const alphabet = filteredPools.join("");
    const baseline = [];
    if (settings.enforceMix) {
        filteredPools.forEach((pool) => {
            if (pool.length > 0)
                baseline.push(pool[randomIndex(pool.length)]);
        });
    }
    const remaining = Math.max(settings.length - baseline.length, 0);
    for (let i = 0; i < remaining; i += 1) {
        baseline.push(alphabet[randomIndex(alphabet.length)]);
    }
    return shuffle(baseline).join("");
}
function generatePassphrase(settings, wordlist) {
    if (!wordlist.length)
        return "loading wordlist…";
    const sep = settings.separator === "space" ? " " : settings.separator;
    const picks = [];
    for (let i = 0; i < settings.words; i += 1) {
        let word = wordlist[randomIndex(wordlist.length)];
        if (settings.randomCase) {
            word = maybeCapitalize(word);
        }
        picks.push(word);
    }
    if (settings.appendNumber) {
        picks.push(String(randomIndex(10)));
    }
    if (settings.appendSymbol) {
        picks.push(symbols[randomIndex(symbols.length)]);
    }
    return picks.join(sep);
}
function maybeCapitalize(value) {
    if (value.length === 0)
        return value;
    const mode = randomIndex(3);
    if (mode === 0)
        return value.toUpperCase();
    if (mode === 1)
        return value[0].toUpperCase() + value.slice(1);
    return value;
}
function estimatePasswordEntropy(settings) {
    const pools = [];
    if (settings.upper)
        pools.push("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    if (settings.lower)
        pools.push("abcdefghijklmnopqrstuvwxyz");
    if (settings.digits)
        pools.push("0123456789");
    if (settings.symbols)
        pools.push(symbols);
    const alphabet = (settings.avoidAmbiguity ? pools.map((pool) => [...pool].filter((c) => !ambiguous.has(c)).join("")) : pools).join("");
    const size = alphabet.length || 1;
    return Math.round(settings.length * Math.log2(size));
}
function estimatePassphraseEntropy(settings, wordlistSize) {
    const base = wordlistSize > 0 ? wordlistSize : 1;
    const wordEntropy = settings.words * Math.log2(base);
    const numberEntropy = settings.appendNumber ? Math.log2(10) : 0;
    const symbolEntropy = settings.appendSymbol ? Math.log2(symbols.length) : 0;
    const caseEntropy = settings.randomCase ? settings.words * Math.log2(3) : 0;
    return Math.round(wordEntropy + numberEntropy + symbolEntropy + caseEntropy);
}
function randomIndex(max) {
    if (max <= 0)
        throw new Error("max must be positive");
    const maxUint = 0xffffffff;
    const limit = Math.floor((maxUint + 1) / max) * max;
    let value = 0;
    do {
        value = crypto.getRandomValues(new Uint32Array(1))[0];
    } while (value >= limit);
    return value % max;
}
function shuffle(input) {
    const arr = [...input];
    for (let i = arr.length - 1; i > 0; i -= 1) {
        const j = randomIndex(i + 1);
        [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
}
function clamp(value, min, max) {
    return Math.min(max, Math.max(min, value));
}
function buildWordlist() {
    const syllables = ["amber", "bison", "cinder", "delta", "ember", "fable"];
    const list = [];
    for (let a = 0; a < 6; a += 1) {
        for (let b = 0; b < 6; b += 1) {
            for (let c = 0; c < 6; c += 1) {
                for (let d = 0; d < 6; d += 1) {
                    for (let e = 0; e < 6; e += 1) {
                        const word = `${syllables[a]}${syllables[b].slice(0, 2)}${syllables[c].slice(-2)}${syllables[d][0]}${syllables[e].slice(1, 3)}`;
                        list.push(word);
                    }
                }
            }
        }
    }
    return list;
}
