import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useEffect, useMemo, useState } from "react";
import "./styles.css";
import { useToast } from "../components/ToastHost";
import { usePersistentState } from "../hooks/usePersistentState";
import { useClipboardPrefs, writeClipboard } from "../utils/clipboard";
import { useI18n } from "../i18n";
import { analyzeSecret, estimatePassphraseEntropy, estimatePasswordEntropy, generatePassphrase, generatePassphraseBatch, generatePassword, generatePasswordBatch, getPassphraseDictionaryStats, gradeLabel, } from "../utils/passwordToolkit";
export function PwView({ onOpenGuide }) {
    const { push } = useToast();
    const { t } = useI18n();
    const [clipboardPrefs] = useClipboardPrefs();
    const [passwordSettings, setPasswordSettings] = usePersistentState("nullid:pw-settings", {
        length: 22,
        upper: true,
        lower: true,
        digits: true,
        symbols: true,
        avoidAmbiguity: true,
        enforceMix: true,
        blockSequential: true,
        blockRepeats: true,
        minUniqueChars: 12,
    });
    const [passphraseSettings, setPassphraseSettings] = usePersistentState("nullid:pp-settings", {
        words: 6,
        separator: "-",
        dictionaryProfile: "extended",
        caseStyle: "random",
        numberMode: "append-2",
        symbolMode: "append",
        ensureUniqueWords: true,
    });
    const [password, setPassword] = useState("");
    const [phrase, setPhrase] = useState("");
    const [batchMode, setBatchMode] = usePersistentState("nullid:pw-batch-mode", "password");
    const [batchCount, setBatchCount] = usePersistentState("nullid:pw-batch-count", 6);
    const [batchRows, setBatchRows] = useState([]);
    const [labInput, setLabInput] = usePersistentState("nullid:pw-lab-input", "");
    const passwordToggleKeys = ["upper", "lower", "digits", "symbols"];
    useEffect(() => {
        setPassword(generatePassword(passwordSettings));
    }, [passwordSettings]);
    useEffect(() => {
        setPhrase(generatePassphrase(passphraseSettings));
    }, [passphraseSettings]);
    const passwordEntropy = useMemo(() => estimatePasswordEntropy(passwordSettings), [passwordSettings]);
    const passphraseEntropy = useMemo(() => estimatePassphraseEntropy(passphraseSettings), [passphraseSettings]);
    const passwordAssessment = useMemo(() => analyzeSecret(password, passwordEntropy), [password, passwordEntropy]);
    const passphraseAssessment = useMemo(() => analyzeSecret(phrase, passphraseEntropy), [phrase, passphraseEntropy]);
    const labAssessment = useMemo(() => analyzeSecret(labInput), [labInput]);
    const dictionary = useMemo(() => getPassphraseDictionaryStats(passphraseSettings.dictionaryProfile), [passphraseSettings.dictionaryProfile]);
    const applyPasswordPreset = (preset) => {
        if (preset === "high") {
            setPasswordSettings({
                length: 28,
                upper: true,
                lower: true,
                digits: true,
                symbols: true,
                avoidAmbiguity: true,
                enforceMix: true,
                blockSequential: true,
                blockRepeats: true,
                minUniqueChars: 14,
            });
        }
        else if (preset === "nosym") {
            setPasswordSettings({
                length: 20,
                upper: true,
                lower: true,
                digits: true,
                symbols: false,
                avoidAmbiguity: true,
                enforceMix: true,
                blockSequential: true,
                blockRepeats: true,
                minUniqueChars: 12,
            });
        }
        else {
            setPasswordSettings({
                length: 10,
                upper: false,
                lower: false,
                digits: true,
                symbols: false,
                avoidAmbiguity: false,
                enforceMix: true,
                blockSequential: true,
                blockRepeats: true,
                minUniqueChars: 6,
            });
        }
    };
    const applyPassphrasePreset = (preset) => {
        if (preset === "memorable") {
            setPassphraseSettings({
                words: 5,
                separator: "-",
                dictionaryProfile: "balanced",
                caseStyle: "title",
                numberMode: "none",
                symbolMode: "none",
                ensureUniqueWords: true,
            });
        }
        else if (preset === "balanced") {
            setPassphraseSettings({
                words: 6,
                separator: "-",
                dictionaryProfile: "extended",
                caseStyle: "random",
                numberMode: "append-2",
                symbolMode: "append",
                ensureUniqueWords: true,
            });
        }
        else {
            setPassphraseSettings({
                words: 8,
                separator: "_",
                dictionaryProfile: "maximal",
                caseStyle: "random",
                numberMode: "append-4",
                symbolMode: "wrap",
                ensureUniqueWords: true,
            });
        }
    };
    useEffect(() => {
        const count = clamp(batchCount, 3, 16);
        setBatchRows(batchMode === "password" ? generatePasswordBatch(passwordSettings, count) : generatePassphraseBatch(passphraseSettings, count));
    }, [batchCount, batchMode, passphraseSettings, passwordSettings]);
    const copySecret = (value, successMessage) => writeClipboard(value, clipboardPrefs, (message, tone) => push(message, tone === "danger" ? "danger" : tone === "accent" ? "accent" : "neutral"), successMessage);
    return (_jsxs("div", { className: "workspace-scroll", children: [_jsx("div", { className: "guide-link", children: _jsx("button", { type: "button", className: "guide-link-button", onClick: () => onOpenGuide?.("pw"), children: t("guide.link") }) }), _jsxs("div", { className: "grid-two", children: [_jsxs("div", { className: "panel", "aria-label": "Password generator", children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: "Password" }), _jsx("span", { className: "panel-subtext", children: "constraint-driven" })] }), _jsxs("div", { className: "controls-row", children: [_jsx("input", { className: "input", value: password, readOnly: true, "aria-label": "Password output" }), _jsx("button", { className: "button", type: "button", onClick: () => setPassword(generatePassword(passwordSettings)), children: "regenerate" }), _jsx("button", { className: "button", type: "button", onClick: () => copySecret(password, "password copied"), children: "copy" })] }), _jsxs("div", { className: "controls-row", children: [_jsx("label", { className: "section-title", htmlFor: "password-length", children: "Length" }), _jsx("input", { id: "password-length", className: "input", type: "number", min: 8, max: 96, value: passwordSettings.length, onChange: (event) => setPasswordSettings((prev) => ({
                                            ...prev,
                                            length: clamp(Number(event.target.value) || 0, 8, 96),
                                        })), "aria-label": "Password length" }), _jsx("div", { className: "pill-buttons", role: "group", "aria-label": "Character sets", children: passwordToggleKeys.map((key) => (_jsx("button", { type: "button", className: passwordSettings[key] ? "active" : "", onClick: () => setPasswordSettings((prev) => ({
                                                ...prev,
                                                [key]: !prev[key],
                                            })), "aria-label": `Toggle ${key} characters`, children: key }, key))) })] }), _jsxs("div", { className: "controls-row", children: [_jsx("label", { className: "section-title", htmlFor: "pw-hardening", children: "Hardening" }), _jsxs("div", { className: "pill-buttons", role: "group", "aria-label": "Hardening options", children: [_jsx("button", { id: "pw-hardening", type: "button", className: passwordSettings.avoidAmbiguity ? "active" : "", onClick: () => setPasswordSettings((prev) => ({ ...prev, avoidAmbiguity: !prev.avoidAmbiguity })), "aria-label": "Avoid ambiguous characters", children: "avoid ambiguous" }), _jsx("button", { type: "button", className: passwordSettings.enforceMix ? "active" : "", onClick: () => setPasswordSettings((prev) => ({ ...prev, enforceMix: !prev.enforceMix })), "aria-label": "Require all selected character types", children: "require all sets" }), _jsx("button", { type: "button", className: passwordSettings.blockSequential ? "active" : "", onClick: () => setPasswordSettings((prev) => ({ ...prev, blockSequential: !prev.blockSequential })), "aria-label": "Block sequential patterns", children: "block sequences" }), _jsx("button", { type: "button", className: passwordSettings.blockRepeats ? "active" : "", onClick: () => setPasswordSettings((prev) => ({ ...prev, blockRepeats: !prev.blockRepeats })), "aria-label": "Block repeated runs", children: "block repeats" })] })] }), _jsxs("div", { className: "controls-row", children: [_jsx("label", { className: "section-title", htmlFor: "pw-min-unique", children: "Min unique" }), _jsx("input", { id: "pw-min-unique", className: "input", type: "number", min: 1, max: passwordSettings.length, value: passwordSettings.minUniqueChars, onChange: (event) => setPasswordSettings((prev) => ({
                                            ...prev,
                                            minUniqueChars: clamp(Number(event.target.value) || 0, 1, prev.length),
                                        })), "aria-label": "Minimum unique characters" })] }), _jsxs("div", { className: "controls-row", children: [_jsx("span", { className: "section-title", children: "Presets" }), _jsxs("div", { className: "pill-buttons", role: "group", "aria-label": "Password presets", children: [_jsx("button", { type: "button", onClick: () => applyPasswordPreset("high"), children: "high security" }), _jsx("button", { type: "button", onClick: () => applyPasswordPreset("nosym"), children: "no symbols" }), _jsx("button", { type: "button", onClick: () => applyPasswordPreset("pin"), children: "pin (digits)" })] })] }), _jsxs("div", { className: "status-line", children: [_jsxs("span", { children: ["length ", passwordSettings.length] }), _jsxs("span", { className: "tag tag-accent", children: ["entropy \u2248 ", passwordEntropy, " bits"] }), _jsx("span", { className: gradeTagClass(passwordAssessment.grade), children: gradeLabel(passwordAssessment.grade) })] }), _jsxs("div", { className: "note-box", children: [_jsxs("div", { className: "microcopy", children: ["effective entropy \u2248 ", passwordAssessment.effectiveEntropyBits, " bits \u00B7 online crack: ", passwordAssessment.crackTime.online] }), passwordAssessment.warnings.length > 0 ? (_jsx("ul", { className: "note-list", children: passwordAssessment.warnings.map((warning) => (_jsx("li", { children: warning }, warning))) })) : (_jsx("div", { className: "microcopy", children: "No obvious pattern weaknesses detected." }))] })] }), _jsxs("div", { className: "panel", "aria-label": "Passphrase generator", children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: "Passphrase" }), _jsx("span", { className: "panel-subtext", children: "mega dictionary" })] }), _jsxs("div", { className: "controls-row", children: [_jsx("input", { className: "input", value: phrase, readOnly: true, "aria-label": "Passphrase output" }), _jsx("button", { className: "button", type: "button", onClick: () => setPhrase(generatePassphrase(passphraseSettings)), children: "regenerate" }), _jsx("button", { className: "button", type: "button", onClick: () => copySecret(phrase, "passphrase copied"), children: "copy" })] }), _jsxs("div", { className: "controls-row", children: [_jsx("label", { className: "section-title", htmlFor: "word-count", children: "Words" }), _jsx("input", { id: "word-count", className: "input", type: "number", min: 3, max: 12, value: passphraseSettings.words, onChange: (event) => setPassphraseSettings((prev) => ({
                                            ...prev,
                                            words: clamp(Number(event.target.value) || 0, 3, 12),
                                        })), "aria-label": "Passphrase word count" }), _jsxs("select", { className: "select", value: passphraseSettings.separator, onChange: (event) => setPassphraseSettings((prev) => ({
                                            ...prev,
                                            separator: event.target.value,
                                        })), "aria-label": "Word separator", children: [_jsx("option", { value: "space", children: "space" }), _jsx("option", { value: "-", children: "-" }), _jsx("option", { value: ".", children: "." }), _jsx("option", { value: "_", children: "_" }), _jsx("option", { value: "/", children: "/" }), _jsx("option", { value: ":", children: ":" })] }), _jsxs("select", { className: "select", value: passphraseSettings.dictionaryProfile, onChange: (event) => setPassphraseSettings((prev) => ({
                                            ...prev,
                                            dictionaryProfile: event.target.value,
                                        })), "aria-label": "Dictionary profile", children: [_jsx("option", { value: "balanced", children: "balanced" }), _jsx("option", { value: "extended", children: "extended" }), _jsx("option", { value: "maximal", children: "maximal" })] })] }), _jsxs("div", { className: "controls-row", children: [_jsx("label", { className: "section-title", htmlFor: "phrase-hardening", children: "Styling" }), _jsxs("select", { id: "phrase-hardening", className: "select", value: passphraseSettings.caseStyle, onChange: (event) => setPassphraseSettings((prev) => ({
                                            ...prev,
                                            caseStyle: event.target.value,
                                        })), "aria-label": "Passphrase case style", children: [_jsx("option", { value: "lower", children: "lower" }), _jsx("option", { value: "title", children: "title" }), _jsx("option", { value: "random", children: "random" }), _jsx("option", { value: "upper", children: "upper" })] }), _jsxs("select", { className: "select", value: passphraseSettings.numberMode, onChange: (event) => setPassphraseSettings((prev) => ({
                                            ...prev,
                                            numberMode: event.target.value,
                                        })), "aria-label": "Passphrase number mode", children: [_jsx("option", { value: "none", children: "no number" }), _jsx("option", { value: "append-2", children: "append 2 digits" }), _jsx("option", { value: "append-4", children: "append 4 digits" })] }), _jsxs("select", { className: "select", value: passphraseSettings.symbolMode, onChange: (event) => setPassphraseSettings((prev) => ({
                                            ...prev,
                                            symbolMode: event.target.value,
                                        })), "aria-label": "Passphrase symbol mode", children: [_jsx("option", { value: "none", children: "no symbol" }), _jsx("option", { value: "append", children: "append symbol" }), _jsx("option", { value: "wrap", children: "wrap with symbols" })] })] }), _jsxs("div", { className: "controls-row", children: [_jsx("label", { className: "section-title", children: "Hardening" }), _jsx("div", { className: "pill-buttons", role: "group", "aria-label": "Passphrase hardening options", children: _jsx("button", { type: "button", className: passphraseSettings.ensureUniqueWords ? "active" : "", onClick: () => setPassphraseSettings((prev) => ({ ...prev, ensureUniqueWords: !prev.ensureUniqueWords })), "aria-label": "Enforce unique words", children: "unique words" }) }), _jsxs("span", { className: "microcopy", children: ["dictionary: ", dictionary.label] })] }), _jsxs("div", { className: "controls-row", children: [_jsx("span", { className: "section-title", children: "Presets" }), _jsxs("div", { className: "pill-buttons", role: "group", "aria-label": "Passphrase presets", children: [_jsx("button", { type: "button", onClick: () => applyPassphrasePreset("memorable"), children: "memorable" }), _jsx("button", { type: "button", onClick: () => applyPassphrasePreset("balanced"), children: "balanced" }), _jsx("button", { type: "button", onClick: () => applyPassphrasePreset("max"), children: "max entropy" })] })] }), _jsxs("div", { className: "status-line", children: [_jsxs("span", { children: ["words ", passphraseSettings.words] }), _jsxs("span", { className: "tag", children: [dictionary.size.toLocaleString(), " words"] }), _jsxs("span", { className: "tag tag-accent", children: ["entropy \u2248 ", passphraseEntropy, " bits"] }), _jsx("span", { className: gradeTagClass(passphraseAssessment.grade), children: gradeLabel(passphraseAssessment.grade) })] }), _jsxs("div", { className: "note-box", children: [_jsxs("div", { className: "microcopy", children: ["bits/word \u2248 ", dictionary.bitsPerWord.toFixed(2), " \u00B7 offline crack: ", passphraseAssessment.crackTime.offline] }), passphraseAssessment.warnings.length > 0 ? (_jsx("ul", { className: "note-list", children: passphraseAssessment.warnings.map((warning) => (_jsx("li", { children: warning }, warning))) })) : (_jsx("div", { className: "microcopy", children: "No obvious passphrase weaknesses detected." }))] })] })] }), _jsxs("div", { className: "grid-two", children: [_jsxs("div", { className: "panel", "aria-label": "Secret strength lab", children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: "Strength Lab" }), _jsx("span", { className: "panel-subtext", children: "audit any secret" })] }), _jsx("textarea", { className: "textarea", value: labInput, onChange: (event) => setLabInput(event.target.value), placeholder: "Paste a password or passphrase to audit locally", "aria-label": "Secret strength lab input" }), _jsxs("div", { className: "status-line", children: [_jsxs("span", { children: ["entropy \u2248 ", labAssessment.entropyBits, " bits"] }), _jsxs("span", { className: "tag", children: ["effective \u2248 ", labAssessment.effectiveEntropyBits, " bits"] }), _jsx("span", { className: gradeTagClass(labAssessment.grade), children: gradeLabel(labAssessment.grade) })] }), _jsxs("div", { className: "note-box", children: [_jsxs("div", { className: "microcopy", children: ["online: ", labAssessment.crackTime.online, " \u00B7 offline: ", labAssessment.crackTime.offline] }), _jsxs("ul", { className: "note-list", children: [labAssessment.warnings.length > 0 ? (labAssessment.warnings.map((warning) => _jsx("li", { children: warning }, warning))) : (_jsx("li", { children: "no direct warning patterns detected" })), labAssessment.strengths.map((strength) => (_jsx("li", { children: strength }, strength)))] })] })] }), _jsxs("div", { className: "panel", "aria-label": "Batch generator", children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: "Batch Generator" }), _jsx("span", { className: "panel-subtext", children: "shortlist candidates" })] }), _jsxs("div", { className: "controls-row", children: [_jsxs("div", { className: "pill-buttons", role: "group", "aria-label": "Batch mode", children: [_jsx("button", { type: "button", className: batchMode === "password" ? "active" : "", onClick: () => setBatchMode("password"), children: "passwords" }), _jsx("button", { type: "button", className: batchMode === "passphrase" ? "active" : "", onClick: () => setBatchMode("passphrase"), children: "passphrases" })] }), _jsx("input", { className: "input", type: "number", min: 3, max: 16, value: batchCount, onChange: (event) => setBatchCount(clamp(Number(event.target.value) || 0, 3, 16)), "aria-label": "Batch candidate count" }), _jsx("button", { className: "button", type: "button", onClick: () => setBatchRows(batchMode === "password"
                                            ? generatePasswordBatch(passwordSettings, clamp(batchCount, 3, 16))
                                            : generatePassphraseBatch(passphraseSettings, clamp(batchCount, 3, 16))), children: "regenerate batch" })] }), _jsxs("table", { className: "table", "aria-label": "Batch candidates table", children: [_jsx("thead", { children: _jsxs("tr", { children: [_jsx("th", { children: "candidate" }), _jsx("th", { children: "entropy" }), _jsx("th", { children: "grade" }), _jsx("th", { children: "copy" })] }) }), _jsx("tbody", { children: batchRows.map((row, index) => (_jsxs("tr", { children: [_jsx("td", { className: "microcopy", children: row.value }), _jsxs("td", { children: [row.entropyBits, "b"] }), _jsx("td", { children: _jsx("span", { className: gradeTagClass(row.assessment.grade), children: gradeLabel(row.assessment.grade) }) }), _jsx("td", { children: _jsx("button", { className: "button", type: "button", onClick: () => copySecret(row.value, `${batchMode} copied`), "aria-label": `Copy candidate ${index + 1}`, children: "copy" }) })] }, `${row.value}-${index}`))) })] })] })] })] }));
}
function gradeTagClass(grade) {
    if (grade === "critical" || grade === "weak")
        return "tag tag-danger";
    if (grade === "fair")
        return "tag";
    return "tag tag-accent";
}
function clamp(value, min, max) {
    return Math.min(max, Math.max(min, value));
}
