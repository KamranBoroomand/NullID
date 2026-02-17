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
    const { t, tr, formatNumber } = useI18n();
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
    return (_jsxs("div", { className: "workspace-scroll", children: [_jsx("div", { className: "guide-link", children: _jsx("button", { type: "button", className: "guide-link-button", onClick: () => onOpenGuide?.("pw"), children: t("guide.link") }) }), _jsxs("div", { className: "grid-two", children: [_jsxs("div", { className: "panel", "aria-label": tr("Password generator"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("Password") }), _jsx("span", { className: "panel-subtext", children: tr("constraint-driven") })] }), _jsxs("div", { className: "controls-row", children: [_jsx("input", { className: "input", value: password, readOnly: true, "aria-label": tr("Password output") }), _jsx("button", { className: "button", type: "button", onClick: () => setPassword(generatePassword(passwordSettings)), children: tr("regenerate") }), _jsx("button", { className: "button", type: "button", onClick: () => copySecret(password, "password copied"), children: tr("copy") })] }), _jsxs("div", { className: "controls-row", children: [_jsx("label", { className: "section-title", htmlFor: "password-length", children: tr("Length") }), _jsx("input", { id: "password-length", className: "input", type: "number", min: 8, max: 96, value: passwordSettings.length, onChange: (event) => setPasswordSettings((prev) => ({
                                            ...prev,
                                            length: clamp(Number(event.target.value) || 0, 8, 96),
                                        })), "aria-label": tr("Password length") }), _jsx("div", { className: "pill-buttons", role: "group", "aria-label": tr("Character sets"), children: passwordToggleKeys.map((key) => (_jsx("button", { type: "button", className: passwordSettings[key] ? "active" : "", onClick: () => setPasswordSettings((prev) => ({
                                                ...prev,
                                                [key]: !prev[key],
                                            })), "aria-label": `Toggle ${key} characters`, children: key }, key))) })] }), _jsxs("div", { className: "controls-row", children: [_jsx("label", { className: "section-title", htmlFor: "pw-hardening", children: tr("Hardening") }), _jsxs("div", { className: "pill-buttons", role: "group", "aria-label": tr("Hardening options"), children: [_jsx("button", { id: "pw-hardening", type: "button", className: passwordSettings.avoidAmbiguity ? "active" : "", onClick: () => setPasswordSettings((prev) => ({ ...prev, avoidAmbiguity: !prev.avoidAmbiguity })), "aria-label": tr("Avoid ambiguous characters"), children: tr("avoid ambiguous") }), _jsx("button", { type: "button", className: passwordSettings.enforceMix ? "active" : "", onClick: () => setPasswordSettings((prev) => ({ ...prev, enforceMix: !prev.enforceMix })), "aria-label": tr("Require all selected character types"), children: tr("require all sets") }), _jsx("button", { type: "button", className: passwordSettings.blockSequential ? "active" : "", onClick: () => setPasswordSettings((prev) => ({ ...prev, blockSequential: !prev.blockSequential })), "aria-label": tr("Block sequential patterns"), children: tr("block sequences") }), _jsx("button", { type: "button", className: passwordSettings.blockRepeats ? "active" : "", onClick: () => setPasswordSettings((prev) => ({ ...prev, blockRepeats: !prev.blockRepeats })), "aria-label": tr("Block repeated runs"), children: tr("block repeats") })] })] }), _jsxs("div", { className: "controls-row", children: [_jsx("label", { className: "section-title", htmlFor: "pw-min-unique", children: tr("Min unique") }), _jsx("input", { id: "pw-min-unique", className: "input", type: "number", min: 1, max: passwordSettings.length, value: passwordSettings.minUniqueChars, onChange: (event) => setPasswordSettings((prev) => ({
                                            ...prev,
                                            minUniqueChars: clamp(Number(event.target.value) || 0, 1, prev.length),
                                        })), "aria-label": tr("Minimum unique characters") })] }), _jsxs("div", { className: "controls-row", children: [_jsx("span", { className: "section-title", children: tr("Presets") }), _jsxs("div", { className: "pill-buttons", role: "group", "aria-label": tr("Password presets"), children: [_jsx("button", { type: "button", onClick: () => applyPasswordPreset("high"), children: tr("high security") }), _jsx("button", { type: "button", onClick: () => applyPasswordPreset("nosym"), children: tr("no symbols") }), _jsx("button", { type: "button", onClick: () => applyPasswordPreset("pin"), children: tr("pin (digits)") })] })] }), _jsxs("div", { className: "status-line", children: [_jsxs("span", { children: [tr("length"), " ", formatNumber(passwordSettings.length)] }), _jsxs("span", { className: "tag tag-accent", children: [tr("entropy"), " \u2248 ", formatNumber(passwordEntropy), " ", tr("bits")] }), _jsx("span", { className: gradeTagClass(passwordAssessment.grade), children: gradeLabel(passwordAssessment.grade) })] }), _jsxs("div", { className: "note-box", children: [_jsxs("div", { className: "microcopy", children: [tr("effective entropy"), " \u2248 ", formatNumber(passwordAssessment.effectiveEntropyBits), " ", tr("bits"), " \u00B7 ", tr("online crack"), ": ", passwordAssessment.crackTime.online] }), passwordAssessment.warnings.length > 0 ? (_jsx("ul", { className: "note-list", children: passwordAssessment.warnings.map((warning) => (_jsx("li", { children: warning }, warning))) })) : (_jsx("div", { className: "microcopy", children: tr("No obvious pattern weaknesses detected.") }))] })] }), _jsxs("div", { className: "panel", "aria-label": tr("Passphrase generator"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("Passphrase") }), _jsx("span", { className: "panel-subtext", children: tr("mega dictionary") })] }), _jsxs("div", { className: "controls-row", children: [_jsx("input", { className: "input", value: phrase, readOnly: true, "aria-label": tr("Passphrase output") }), _jsx("button", { className: "button", type: "button", onClick: () => setPhrase(generatePassphrase(passphraseSettings)), children: tr("regenerate") }), _jsx("button", { className: "button", type: "button", onClick: () => copySecret(phrase, "passphrase copied"), children: tr("copy") })] }), _jsxs("div", { className: "controls-row", children: [_jsx("label", { className: "section-title", htmlFor: "word-count", children: tr("Words") }), _jsx("input", { id: "word-count", className: "input", type: "number", min: 3, max: 12, value: passphraseSettings.words, onChange: (event) => setPassphraseSettings((prev) => ({
                                            ...prev,
                                            words: clamp(Number(event.target.value) || 0, 3, 12),
                                        })), "aria-label": tr("Passphrase word count") }), _jsxs("select", { className: "select", value: passphraseSettings.separator, onChange: (event) => setPassphraseSettings((prev) => ({
                                            ...prev,
                                            separator: event.target.value,
                                        })), "aria-label": tr("Word separator"), children: [_jsx("option", { value: "space", children: tr("space") }), _jsx("option", { value: "-", children: "-" }), _jsx("option", { value: ".", children: "." }), _jsx("option", { value: "_", children: "_" }), _jsx("option", { value: "/", children: "/" }), _jsx("option", { value: ":", children: ":" })] }), _jsxs("select", { className: "select", value: passphraseSettings.dictionaryProfile, onChange: (event) => setPassphraseSettings((prev) => ({
                                            ...prev,
                                            dictionaryProfile: event.target.value,
                                        })), "aria-label": tr("Dictionary profile"), children: [_jsx("option", { value: "balanced", children: tr("balanced") }), _jsx("option", { value: "extended", children: tr("extended") }), _jsx("option", { value: "maximal", children: tr("maximal") })] })] }), _jsxs("div", { className: "controls-row", children: [_jsx("label", { className: "section-title", htmlFor: "phrase-hardening", children: tr("Styling") }), _jsxs("select", { id: "phrase-hardening", className: "select", value: passphraseSettings.caseStyle, onChange: (event) => setPassphraseSettings((prev) => ({
                                            ...prev,
                                            caseStyle: event.target.value,
                                        })), "aria-label": tr("Passphrase case style"), children: [_jsx("option", { value: "lower", children: tr("lower") }), _jsx("option", { value: "title", children: tr("title") }), _jsx("option", { value: "random", children: tr("random") }), _jsx("option", { value: "upper", children: tr("upper") })] }), _jsxs("select", { className: "select", value: passphraseSettings.numberMode, onChange: (event) => setPassphraseSettings((prev) => ({
                                            ...prev,
                                            numberMode: event.target.value,
                                        })), "aria-label": tr("Passphrase number mode"), children: [_jsx("option", { value: "none", children: tr("no number") }), _jsx("option", { value: "append-2", children: tr("append 2 digits") }), _jsx("option", { value: "append-4", children: tr("append 4 digits") })] }), _jsxs("select", { className: "select", value: passphraseSettings.symbolMode, onChange: (event) => setPassphraseSettings((prev) => ({
                                            ...prev,
                                            symbolMode: event.target.value,
                                        })), "aria-label": tr("Passphrase symbol mode"), children: [_jsx("option", { value: "none", children: tr("no symbol") }), _jsx("option", { value: "append", children: tr("append symbol") }), _jsx("option", { value: "wrap", children: tr("wrap with symbols") })] })] }), _jsxs("div", { className: "controls-row", children: [_jsx("label", { className: "section-title", children: tr("Hardening") }), _jsx("div", { className: "pill-buttons", role: "group", "aria-label": tr("Passphrase hardening options"), children: _jsx("button", { type: "button", className: passphraseSettings.ensureUniqueWords ? "active" : "", onClick: () => setPassphraseSettings((prev) => ({ ...prev, ensureUniqueWords: !prev.ensureUniqueWords })), "aria-label": tr("Enforce unique words"), children: tr("unique words") }) }), _jsxs("span", { className: "microcopy", children: [tr("dictionary"), ": ", dictionary.label] })] }), _jsxs("div", { className: "controls-row", children: [_jsx("span", { className: "section-title", children: tr("Presets") }), _jsxs("div", { className: "pill-buttons", role: "group", "aria-label": tr("Passphrase presets"), children: [_jsx("button", { type: "button", onClick: () => applyPassphrasePreset("memorable"), children: tr("memorable") }), _jsx("button", { type: "button", onClick: () => applyPassphrasePreset("balanced"), children: tr("balanced") }), _jsx("button", { type: "button", onClick: () => applyPassphrasePreset("max"), children: tr("max entropy") })] })] }), _jsxs("div", { className: "status-line", children: [_jsxs("span", { children: [tr("words"), " ", formatNumber(passphraseSettings.words)] }), _jsxs("span", { className: "tag", children: [formatNumber(dictionary.size), " ", tr("words")] }), _jsxs("span", { className: "tag tag-accent", children: [tr("entropy"), " \u2248 ", formatNumber(passphraseEntropy), " ", tr("bits")] }), _jsx("span", { className: gradeTagClass(passphraseAssessment.grade), children: gradeLabel(passphraseAssessment.grade) })] }), _jsxs("div", { className: "note-box", children: [_jsxs("div", { className: "microcopy", children: [tr("bits/word"), " \u2248 ", dictionary.bitsPerWord.toFixed(2), " \u00B7 ", tr("offline crack"), ": ", passphraseAssessment.crackTime.offline] }), passphraseAssessment.warnings.length > 0 ? (_jsx("ul", { className: "note-list", children: passphraseAssessment.warnings.map((warning) => (_jsx("li", { children: warning }, warning))) })) : (_jsx("div", { className: "microcopy", children: tr("No obvious passphrase weaknesses detected.") }))] })] })] }), _jsxs("div", { className: "grid-two", children: [_jsxs("div", { className: "panel", "aria-label": tr("Secret strength lab"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("Strength Lab") }), _jsx("span", { className: "panel-subtext", children: tr("audit any secret") })] }), _jsx("textarea", { className: "textarea", value: labInput, onChange: (event) => setLabInput(event.target.value), placeholder: tr("Paste a password or passphrase to audit locally"), "aria-label": tr("Secret strength lab input") }), _jsxs("div", { className: "status-line", children: [_jsxs("span", { children: [tr("entropy"), " \u2248 ", formatNumber(labAssessment.entropyBits), " ", tr("bits")] }), _jsxs("span", { className: "tag", children: [tr("effective"), " \u2248 ", formatNumber(labAssessment.effectiveEntropyBits), " ", tr("bits")] }), _jsx("span", { className: gradeTagClass(labAssessment.grade), children: gradeLabel(labAssessment.grade) })] }), _jsxs("div", { className: "note-box", children: [_jsxs("div", { className: "microcopy", children: [tr("online"), ": ", labAssessment.crackTime.online, " \u00B7 ", tr("offline"), ": ", labAssessment.crackTime.offline] }), _jsxs("ul", { className: "note-list", children: [labAssessment.warnings.length > 0 ? (labAssessment.warnings.map((warning) => _jsx("li", { children: warning }, warning))) : (_jsx("li", { children: tr("no direct warning patterns detected") })), labAssessment.strengths.map((strength) => (_jsx("li", { children: strength }, strength)))] })] })] }), _jsxs("div", { className: "panel", "aria-label": tr("Batch generator"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("Batch Generator") }), _jsx("span", { className: "panel-subtext", children: tr("shortlist candidates") })] }), _jsxs("div", { className: "controls-row", children: [_jsxs("div", { className: "pill-buttons", role: "group", "aria-label": tr("Batch mode"), children: [_jsx("button", { type: "button", className: batchMode === "password" ? "active" : "", onClick: () => setBatchMode("password"), children: tr("passwords") }), _jsx("button", { type: "button", className: batchMode === "passphrase" ? "active" : "", onClick: () => setBatchMode("passphrase"), children: tr("passphrases") })] }), _jsx("input", { className: "input", type: "number", min: 3, max: 16, value: batchCount, onChange: (event) => setBatchCount(clamp(Number(event.target.value) || 0, 3, 16)), "aria-label": tr("Batch candidate count") }), _jsx("button", { className: "button", type: "button", onClick: () => setBatchRows(batchMode === "password"
                                            ? generatePasswordBatch(passwordSettings, clamp(batchCount, 3, 16))
                                            : generatePassphraseBatch(passphraseSettings, clamp(batchCount, 3, 16))), children: tr("regenerate batch") })] }), _jsxs("table", { className: "table", "aria-label": tr("Batch candidates table"), children: [_jsx("thead", { children: _jsxs("tr", { children: [_jsx("th", { children: tr("candidate") }), _jsx("th", { children: tr("entropy") }), _jsx("th", { children: tr("grade") }), _jsx("th", { children: tr("copy") })] }) }), _jsx("tbody", { children: batchRows.map((row, index) => (_jsxs("tr", { children: [_jsx("td", { className: "microcopy", children: row.value }), _jsxs("td", { children: [row.entropyBits, "b"] }), _jsx("td", { children: _jsx("span", { className: gradeTagClass(row.assessment.grade), children: gradeLabel(row.assessment.grade) }) }), _jsx("td", { children: _jsx("button", { className: "button", type: "button", onClick: () => copySecret(row.value, `${batchMode} copied`), "aria-label": `Copy candidate ${index + 1}`, children: "copy" }) })] }, `${row.value}-${index}`))) })] })] })] })] }));
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
