import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useEffect, useMemo, useState } from "react";
import "./styles.css";
import { useToast } from "../components/ToastHost";
import { usePersistentState } from "../hooks/usePersistentState";
import { useClipboardPrefs, writeClipboard } from "../utils/clipboard";
import { useI18n } from "../i18n";
import { analyzeSecret, estimatePassphraseEntropy, estimatePasswordEntropy, generatePassphrase, generatePassphraseBatch, generatePassword, generatePasswordBatch, getPassphraseDictionaryStats, gradeLabel, } from "../utils/passwordToolkit";
import { PASSWORD_HASH_DEFAULTS, assessPasswordHashChoice, hashPassword, supportsArgon2id, verifyPassword, } from "../utils/passwordHashing";
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
    const [hashAlgorithm, setHashAlgorithm] = usePersistentState("nullid:pw-hash:algorithm", "argon2id");
    const [hashSaltBytes, setHashSaltBytes] = usePersistentState("nullid:pw-hash:salt", PASSWORD_HASH_DEFAULTS.saltBytes);
    const [hashPbkdf2Iterations, setHashPbkdf2Iterations] = usePersistentState("nullid:pw-hash:pbkdf2-iterations", PASSWORD_HASH_DEFAULTS.pbkdf2Iterations);
    const [hashArgon2Memory, setHashArgon2Memory] = usePersistentState("nullid:pw-hash:argon2-memory", PASSWORD_HASH_DEFAULTS.argon2Memory);
    const [hashArgon2Passes, setHashArgon2Passes] = usePersistentState("nullid:pw-hash:argon2-passes", PASSWORD_HASH_DEFAULTS.argon2Passes);
    const [hashArgon2Parallelism, setHashArgon2Parallelism] = usePersistentState("nullid:pw-hash:argon2-parallelism", PASSWORD_HASH_DEFAULTS.argon2Parallelism);
    const [hashInput, setHashInput] = useState("");
    const [hashVerifyInput, setHashVerifyInput] = useState("");
    const [hashOutput, setHashOutput] = useState("");
    const [hashBusy, setHashBusy] = useState(false);
    const [hashError, setHashError] = useState(null);
    const [hashVerifyState, setHashVerifyState] = useState("idle");
    const [argon2Available, setArgon2Available] = useState(null);
    const passwordToggleKeys = ["upper", "lower", "digits", "symbols"];
    useEffect(() => {
        setPassword(generatePassword(passwordSettings));
    }, [passwordSettings]);
    useEffect(() => {
        setPhrase(generatePassphrase(passphraseSettings));
    }, [passphraseSettings]);
    useEffect(() => {
        void (async () => {
            try {
                const available = await supportsArgon2id();
                setArgon2Available(available);
            }
            catch (error) {
                console.error(error);
                setArgon2Available(false);
            }
        })();
    }, []);
    const passwordEntropy = useMemo(() => estimatePasswordEntropy(passwordSettings), [passwordSettings]);
    const passphraseEntropy = useMemo(() => estimatePassphraseEntropy(passphraseSettings), [passphraseSettings]);
    const passwordAssessment = useMemo(() => analyzeSecret(password, passwordEntropy), [password, passwordEntropy]);
    const passphraseAssessment = useMemo(() => analyzeSecret(phrase, passphraseEntropy), [phrase, passphraseEntropy]);
    const labAssessment = useMemo(() => analyzeSecret(labInput), [labInput]);
    const hashChoiceAssessment = useMemo(() => assessPasswordHashChoice({
        algorithm: hashAlgorithm,
        saltBytes: hashSaltBytes,
        pbkdf2Iterations: hashPbkdf2Iterations,
        argon2Memory: hashArgon2Memory,
        argon2Passes: hashArgon2Passes,
        argon2Parallelism: hashArgon2Parallelism,
    }), [hashAlgorithm, hashArgon2Memory, hashArgon2Parallelism, hashArgon2Passes, hashPbkdf2Iterations, hashSaltBytes]);
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
    const handlePasswordHash = async () => {
        if (!hashInput.trim()) {
            push("enter a password to hash", "danger");
            return;
        }
        setHashBusy(true);
        try {
            const result = await hashPassword(hashInput, {
                algorithm: hashAlgorithm,
                saltBytes: clamp(hashSaltBytes, 8, 64),
                pbkdf2Iterations: clamp(hashPbkdf2Iterations, 100_000, 2_000_000),
                argon2Memory: clamp(hashArgon2Memory, 8_192, 262_144),
                argon2Passes: clamp(hashArgon2Passes, 1, 8),
                argon2Parallelism: clamp(hashArgon2Parallelism, 1, 4),
            });
            setHashOutput(result.encoded);
            setHashError(null);
            setHashVerifyState("idle");
            push(result.assessment.safety === "weak" ? "hash generated (legacy mode)" : "password hash generated", result.assessment.safety === "weak" ? "danger" : "accent");
        }
        catch (error) {
            console.error(error);
            const message = error instanceof Error ? error.message : "password hash failed";
            setHashError(message);
            push(message, "danger");
        }
        finally {
            setHashBusy(false);
        }
    };
    const handleVerifyHash = async () => {
        if (!hashOutput.trim() || !hashVerifyInput) {
            setHashVerifyState("error");
            push("hash output and candidate password are required", "danger");
            return;
        }
        setHashBusy(true);
        try {
            const matched = await verifyPassword(hashVerifyInput, hashOutput.trim());
            setHashVerifyState(matched ? "match" : "mismatch");
            push(matched ? "password match" : "password mismatch", matched ? "accent" : "danger");
        }
        catch (error) {
            console.error(error);
            setHashVerifyState("error");
            const message = error instanceof Error ? error.message : "verification failed";
            setHashError(message);
            push(message, "danger");
        }
        finally {
            setHashBusy(false);
        }
    };
    return (_jsxs("div", { className: "workspace-scroll", children: [_jsx("div", { className: "guide-link", children: _jsx("button", { type: "button", className: "guide-link-button", onClick: () => onOpenGuide?.("pw"), children: t("guide.link") }) }), _jsxs("div", { className: "grid-two", children: [_jsxs("div", { className: "panel", "aria-label": tr("Password generator"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("Password") }), _jsx("span", { className: "panel-subtext", children: tr("constraint-driven") })] }), _jsxs("div", { className: "controls-row", children: [_jsx("input", { className: "input", value: password, readOnly: true, "aria-label": tr("Password output") }), _jsx("button", { className: "button", type: "button", onClick: () => setPassword(generatePassword(passwordSettings)), children: tr("regenerate") }), _jsx("button", { className: "button", type: "button", onClick: () => copySecret(password, "password copied"), children: tr("copy") })] }), _jsxs("div", { className: "controls-row", children: [_jsx("label", { className: "section-title", htmlFor: "password-length", children: tr("Length") }), _jsx("input", { id: "password-length", className: "input", type: "number", min: 8, max: 96, value: passwordSettings.length, onChange: (event) => setPasswordSettings((prev) => ({
                                            ...prev,
                                            length: clamp(Number(event.target.value) || 0, 8, 96),
                                        })), "aria-label": tr("Password length") }), _jsx("div", { className: "pill-buttons", role: "group", "aria-label": tr("Character sets"), children: passwordToggleKeys.map((key) => (_jsx("button", { type: "button", className: passwordSettings[key] ? "active" : "", onClick: () => setPasswordSettings((prev) => ({
                                                ...prev,
                                                [key]: !prev[key],
                                            })), "aria-label": `Toggle ${key} characters`, children: key }, key))) })] }), _jsxs("div", { className: "controls-row", children: [_jsx("label", { className: "section-title", htmlFor: "pw-hardening", children: tr("Hardening") }), _jsxs("div", { className: "pill-buttons", role: "group", "aria-label": tr("Hardening options"), children: [_jsx("button", { id: "pw-hardening", type: "button", className: passwordSettings.avoidAmbiguity ? "active" : "", onClick: () => setPasswordSettings((prev) => ({ ...prev, avoidAmbiguity: !prev.avoidAmbiguity })), "aria-label": tr("Avoid ambiguous characters"), children: tr("avoid ambiguous") }), _jsx("button", { type: "button", className: passwordSettings.enforceMix ? "active" : "", onClick: () => setPasswordSettings((prev) => ({ ...prev, enforceMix: !prev.enforceMix })), "aria-label": tr("Require all selected character types"), children: tr("require all sets") }), _jsx("button", { type: "button", className: passwordSettings.blockSequential ? "active" : "", onClick: () => setPasswordSettings((prev) => ({ ...prev, blockSequential: !prev.blockSequential })), "aria-label": tr("Block sequential patterns"), children: tr("block sequences") }), _jsx("button", { type: "button", className: passwordSettings.blockRepeats ? "active" : "", onClick: () => setPasswordSettings((prev) => ({ ...prev, blockRepeats: !prev.blockRepeats })), "aria-label": tr("Block repeated runs"), children: tr("block repeats") })] })] }), _jsxs("div", { className: "controls-row", children: [_jsx("label", { className: "section-title", htmlFor: "pw-min-unique", children: tr("Min unique") }), _jsx("input", { id: "pw-min-unique", className: "input", type: "number", min: 1, max: passwordSettings.length, value: passwordSettings.minUniqueChars, onChange: (event) => setPasswordSettings((prev) => ({
                                            ...prev,
                                            minUniqueChars: clamp(Number(event.target.value) || 0, 1, prev.length),
                                        })), "aria-label": tr("Minimum unique characters") })] }), _jsxs("div", { className: "controls-row", children: [_jsx("span", { className: "section-title", children: tr("Presets") }), _jsxs("div", { className: "pill-buttons", role: "group", "aria-label": tr("Password presets"), children: [_jsx("button", { type: "button", onClick: () => applyPasswordPreset("high"), children: tr("high security") }), _jsx("button", { type: "button", onClick: () => applyPasswordPreset("nosym"), children: tr("no symbols") }), _jsx("button", { type: "button", onClick: () => applyPasswordPreset("pin"), children: tr("pin (digits)") })] })] }), _jsxs("div", { className: "status-line", children: [_jsxs("span", { children: [tr("length"), " ", formatNumber(passwordSettings.length)] }), _jsxs("span", { className: "tag tag-accent", children: [tr("entropy"), " \u2248 ", formatNumber(passwordEntropy), " ", tr("bits")] }), _jsx("span", { className: gradeTagClass(passwordAssessment.grade), children: gradeLabel(passwordAssessment.grade) })] }), _jsxs("div", { className: "note-box", children: [_jsxs("div", { className: "microcopy", children: [tr("effective entropy"), " \u2248 ", formatNumber(passwordAssessment.effectiveEntropyBits), " ", tr("bits"), " \u00B7 ", tr("online crack"), " (rate-limited median):", " ", passwordAssessment.crackTime.online] }), passwordAssessment.warnings.length > 0 ? (_jsx("ul", { className: "note-list", children: passwordAssessment.warnings.map((warning) => (_jsx("li", { children: warning }, warning))) })) : (_jsx("div", { className: "microcopy", children: tr("No obvious pattern weaknesses detected.") }))] })] }), _jsxs("div", { className: "panel", "aria-label": tr("Passphrase generator"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("Passphrase") }), _jsx("span", { className: "panel-subtext", children: tr("mega dictionary") })] }), _jsxs("div", { className: "controls-row", children: [_jsx("input", { className: "input", value: phrase, readOnly: true, "aria-label": tr("Passphrase output") }), _jsx("button", { className: "button", type: "button", onClick: () => setPhrase(generatePassphrase(passphraseSettings)), children: tr("regenerate") }), _jsx("button", { className: "button", type: "button", onClick: () => copySecret(phrase, "passphrase copied"), children: tr("copy") })] }), _jsxs("div", { className: "controls-row", children: [_jsx("label", { className: "section-title", htmlFor: "word-count", children: tr("Words") }), _jsx("input", { id: "word-count", className: "input", type: "number", min: 3, max: 12, value: passphraseSettings.words, onChange: (event) => setPassphraseSettings((prev) => ({
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
                                        })), "aria-label": tr("Passphrase symbol mode"), children: [_jsx("option", { value: "none", children: tr("no symbol") }), _jsx("option", { value: "append", children: tr("append symbol") }), _jsx("option", { value: "wrap", children: tr("wrap with symbols") })] })] }), _jsxs("div", { className: "controls-row", children: [_jsx("label", { className: "section-title", children: tr("Hardening") }), _jsx("div", { className: "pill-buttons", role: "group", "aria-label": tr("Passphrase hardening options"), children: _jsx("button", { type: "button", className: passphraseSettings.ensureUniqueWords ? "active" : "", onClick: () => setPassphraseSettings((prev) => ({ ...prev, ensureUniqueWords: !prev.ensureUniqueWords })), "aria-label": tr("Enforce unique words"), children: tr("unique words") }) }), _jsxs("span", { className: "microcopy", children: [tr("dictionary"), ": ", dictionary.label] })] }), _jsxs("div", { className: "controls-row", children: [_jsx("span", { className: "section-title", children: tr("Presets") }), _jsxs("div", { className: "pill-buttons", role: "group", "aria-label": tr("Passphrase presets"), children: [_jsx("button", { type: "button", onClick: () => applyPassphrasePreset("memorable"), children: tr("memorable") }), _jsx("button", { type: "button", onClick: () => applyPassphrasePreset("balanced"), children: tr("balanced") }), _jsx("button", { type: "button", onClick: () => applyPassphrasePreset("max"), children: tr("max entropy") })] })] }), _jsxs("div", { className: "status-line", children: [_jsxs("span", { children: [tr("words"), " ", formatNumber(passphraseSettings.words)] }), _jsxs("span", { className: "tag", children: [formatNumber(dictionary.size), " ", tr("words")] }), _jsxs("span", { className: "tag tag-accent", children: [tr("entropy"), " \u2248 ", formatNumber(passphraseEntropy), " ", tr("bits")] }), _jsx("span", { className: gradeTagClass(passphraseAssessment.grade), children: gradeLabel(passphraseAssessment.grade) })] }), _jsxs("div", { className: "note-box", children: [_jsxs("div", { className: "microcopy", children: [tr("bits/word"), " \u2248 ", dictionary.bitsPerWord.toFixed(2), " \u00B7 ", tr("offline crack"), " (slow-KDF median):", " ", passphraseAssessment.crackTime.offline] }), passphraseAssessment.warnings.length > 0 ? (_jsx("ul", { className: "note-list", children: passphraseAssessment.warnings.map((warning) => (_jsx("li", { children: warning }, warning))) })) : (_jsx("div", { className: "microcopy", children: tr("No obvious passphrase weaknesses detected.") }))] })] })] }), _jsxs("div", { className: "grid-two", children: [_jsxs("div", { className: "panel", "aria-label": tr("Secret strength lab"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("Strength Lab") }), _jsx("span", { className: "panel-subtext", children: tr("audit any secret") })] }), _jsx("textarea", { className: "textarea", value: labInput, onChange: (event) => setLabInput(event.target.value), placeholder: tr("Paste a password or passphrase to audit locally"), "aria-label": tr("Secret strength lab input") }), _jsxs("div", { className: "status-line", children: [_jsxs("span", { children: [tr("entropy"), " \u2248 ", formatNumber(labAssessment.entropyBits), " ", tr("bits")] }), _jsxs("span", { className: "tag", children: [tr("effective"), " \u2248 ", formatNumber(labAssessment.effectiveEntropyBits), " ", tr("bits")] }), _jsx("span", { className: gradeTagClass(labAssessment.grade), children: gradeLabel(labAssessment.grade) })] }), _jsxs("div", { className: "note-box", children: [_jsxs("div", { className: "microcopy", children: [tr("online"), " (rate-limited median): ", labAssessment.crackTime.online, " \u00B7 ", tr("offline"), " (slow-KDF median):", " ", labAssessment.crackTime.offline] }), _jsx("ul", { className: "note-list", children: labAssessment.crackTime.scenarios.map((scenario) => (_jsxs("li", { children: [scenario.label, ": median ", scenario.median, ", worst-case ", scenario.worstCase, " @ ", formatGuessRate(scenario.guessesPerSecond)] }, scenario.key))) }), _jsx("ul", { className: "note-list", children: labAssessment.crackTime.assumptions.map((assumption) => (_jsx("li", { children: assumption }, assumption))) }), _jsxs("ul", { className: "note-list", children: [labAssessment.warnings.length > 0 ? (labAssessment.warnings.map((warning) => _jsx("li", { children: warning }, warning))) : (_jsx("li", { children: tr("no direct warning patterns detected") })), labAssessment.strengths.map((strength) => (_jsx("li", { children: strength }, strength)))] })] })] }), _jsxs("div", { className: "panel", "aria-label": tr("Batch generator"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("Batch Generator") }), _jsx("span", { className: "panel-subtext", children: tr("shortlist candidates") })] }), _jsxs("div", { className: "controls-row", children: [_jsxs("div", { className: "pill-buttons", role: "group", "aria-label": tr("Batch mode"), children: [_jsx("button", { type: "button", className: batchMode === "password" ? "active" : "", onClick: () => setBatchMode("password"), children: tr("passwords") }), _jsx("button", { type: "button", className: batchMode === "passphrase" ? "active" : "", onClick: () => setBatchMode("passphrase"), children: tr("passphrases") })] }), _jsx("input", { className: "input", type: "number", min: 3, max: 16, value: batchCount, onChange: (event) => setBatchCount(clamp(Number(event.target.value) || 0, 3, 16)), "aria-label": tr("Batch candidate count") }), _jsx("button", { className: "button", type: "button", onClick: () => setBatchRows(batchMode === "password"
                                            ? generatePasswordBatch(passwordSettings, clamp(batchCount, 3, 16))
                                            : generatePassphraseBatch(passphraseSettings, clamp(batchCount, 3, 16))), children: tr("regenerate batch") })] }), _jsxs("table", { className: "table", "aria-label": tr("Batch candidates table"), children: [_jsx("thead", { children: _jsxs("tr", { children: [_jsx("th", { children: tr("candidate") }), _jsx("th", { children: tr("entropy") }), _jsx("th", { children: tr("grade") }), _jsx("th", { children: tr("copy") })] }) }), _jsx("tbody", { children: batchRows.map((row, index) => (_jsxs("tr", { children: [_jsx("td", { className: "microcopy", children: row.value }), _jsxs("td", { children: [row.entropyBits, "b"] }), _jsx("td", { children: _jsx("span", { className: gradeTagClass(row.assessment.grade), children: gradeLabel(row.assessment.grade) }) }), _jsx("td", { children: _jsx("button", { className: "button", type: "button", onClick: () => copySecret(row.value, `${batchMode} copied`), "aria-label": `Copy candidate ${index + 1}`, children: "copy" }) })] }, `${row.value}-${index}`))) })] })] })] }), _jsxs("div", { className: "panel", "aria-label": tr("Password storage hash lab"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("Password Storage Hashing") }), _jsx("span", { className: "panel-subtext", children: tr("salted records with cost factors") })] }), _jsxs("div", { className: "controls-row", children: [_jsx("label", { className: "section-title", htmlFor: "pw-hash-algo", children: tr("Algorithm") }), _jsxs("select", { id: "pw-hash-algo", className: "select", value: hashAlgorithm, onChange: (event) => {
                                    setHashAlgorithm(event.target.value);
                                    setHashVerifyState("idle");
                                }, "aria-label": tr("Password hash algorithm"), children: [_jsx("option", { value: "argon2id", children: "Argon2id (recommended)" }), _jsx("option", { value: "pbkdf2-sha256", children: "PBKDF2-SHA256 (compat)" }), _jsx("option", { value: "sha512", children: "SHA-512 (legacy)" }), _jsx("option", { value: "sha256", children: "SHA-256 (legacy)" })] }), _jsx("label", { className: "section-title", htmlFor: "pw-hash-salt", children: tr("Salt bytes") }), _jsx("input", { id: "pw-hash-salt", className: "input", type: "number", min: 8, max: 64, value: hashSaltBytes, onChange: (event) => setHashSaltBytes(clamp(Number(event.target.value) || 0, 8, 64)), "aria-label": tr("Hash salt bytes") })] }), hashAlgorithm === "pbkdf2-sha256" ? (_jsxs("div", { className: "controls-row", children: [_jsx("label", { className: "section-title", htmlFor: "pw-hash-pbkdf2-iterations", children: tr("PBKDF2 iterations") }), _jsx("input", { id: "pw-hash-pbkdf2-iterations", className: "input", type: "number", min: 100000, max: 2000000, step: 50000, value: hashPbkdf2Iterations, onChange: (event) => setHashPbkdf2Iterations(clamp(Number(event.target.value) || 0, 100_000, 2_000_000)), "aria-label": tr("PBKDF2 iterations") })] })) : null, hashAlgorithm === "argon2id" ? (_jsxs("div", { className: "controls-row", children: [_jsx("label", { className: "section-title", htmlFor: "pw-hash-argon2-memory", children: tr("Argon2 memory (KiB)") }), _jsx("input", { id: "pw-hash-argon2-memory", className: "input", type: "number", min: 8192, max: 262144, step: 2048, value: hashArgon2Memory, onChange: (event) => setHashArgon2Memory(clamp(Number(event.target.value) || 0, 8_192, 262_144)), "aria-label": tr("Argon2 memory") }), _jsx("label", { className: "section-title", htmlFor: "pw-hash-argon2-passes", children: tr("Passes") }), _jsx("input", { id: "pw-hash-argon2-passes", className: "input", type: "number", min: 1, max: 8, value: hashArgon2Passes, onChange: (event) => setHashArgon2Passes(clamp(Number(event.target.value) || 0, 1, 8)), "aria-label": tr("Argon2 passes") }), _jsx("label", { className: "section-title", htmlFor: "pw-hash-argon2-parallelism", children: tr("Parallelism") }), _jsx("input", { id: "pw-hash-argon2-parallelism", className: "input", type: "number", min: 1, max: 4, value: hashArgon2Parallelism, onChange: (event) => setHashArgon2Parallelism(clamp(Number(event.target.value) || 0, 1, 4)), "aria-label": tr("Argon2 parallelism") })] })) : null, _jsx("textarea", { className: "textarea", value: hashInput, onChange: (event) => setHashInput(event.target.value), placeholder: tr("Password input for hashing (local only)"), "aria-label": tr("Password input for hashing") }), _jsxs("div", { className: "controls-row", children: [_jsx("button", { className: "button", type: "button", onClick: () => void handlePasswordHash(), disabled: hashBusy || !hashInput.trim(), children: hashBusy ? tr("working…") : tr("generate hash") }), _jsx("button", { className: "button", type: "button", onClick: () => copySecret(hashOutput, "hash copied"), disabled: !hashOutput, children: tr("copy hash") }), _jsx("button", { className: "button", type: "button", onClick: () => {
                                    setHashInput("");
                                    setHashVerifyInput("");
                                    setHashOutput("");
                                    setHashError(null);
                                    setHashVerifyState("idle");
                                }, children: tr("clear") })] }), _jsx("textarea", { className: "textarea", value: hashOutput, readOnly: true, placeholder: tr("Generated password hash record"), "aria-label": tr("Generated password hash") }), _jsxs("div", { className: "controls-row", children: [_jsx("input", { className: "input", type: "password", value: hashVerifyInput, onChange: (event) => setHashVerifyInput(event.target.value), placeholder: tr("Password candidate for verification"), "aria-label": tr("Password candidate") }), _jsx("button", { className: "button", type: "button", onClick: () => void handleVerifyHash(), disabled: !hashOutput || !hashVerifyInput || hashBusy, children: tr("verify") })] }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: tr("safety") }), _jsx("span", { className: hashSafetyTagClass(hashChoiceAssessment.safety), children: hashChoiceAssessment.safety === "strong" ? tr("strong") : hashChoiceAssessment.safety === "fair" ? tr("fair") : tr("weak") }), _jsx("span", { className: hashVerifyState === "match" ? "tag tag-accent" : hashVerifyState === "mismatch" || hashVerifyState === "error" ? "tag tag-danger" : "tag", children: hashVerifyState === "match"
                                    ? tr("verified")
                                    : hashVerifyState === "mismatch"
                                        ? tr("mismatch")
                                        : hashVerifyState === "error"
                                            ? tr("error")
                                            : tr("idle") }), argon2Available === false && hashAlgorithm === "argon2id" ? (_jsx("span", { className: "microcopy", children: tr("Argon2id is not available in this runtime. Choose PBKDF2 or use a browser with Argon2id support.") })) : null] }), hashChoiceAssessment.warnings.length > 0 ? (_jsx("ul", { className: "note-list", children: hashChoiceAssessment.warnings.map((warning) => (_jsx("li", { children: warning }, warning))) })) : (_jsx("div", { className: "microcopy", children: tr("Current hash profile meets the recommended baseline.") })), hashError ? _jsx("div", { className: "microcopy", style: { color: "var(--danger)" }, children: hashError }) : null, _jsx("div", { className: "microcopy", children: tr("Legacy SHA options are kept for compatibility only. Prefer Argon2id for new password storage records.") })] })] }));
}
function gradeTagClass(grade) {
    if (grade === "critical" || grade === "weak")
        return "tag tag-danger";
    if (grade === "fair")
        return "tag";
    return "tag tag-accent";
}
function hashSafetyTagClass(safety) {
    if (safety === "weak")
        return "tag tag-danger";
    if (safety === "fair")
        return "tag";
    return "tag tag-accent";
}
function clamp(value, min, max) {
    return Math.min(max, Math.max(min, value));
}
function formatGuessRate(rate) {
    if (rate >= 1_000_000_000)
        return `${(rate / 1_000_000_000).toFixed(1)}B guesses/s`;
    if (rate >= 1_000_000)
        return `${(rate / 1_000_000).toFixed(1)}M guesses/s`;
    if (rate >= 1_000)
        return `${(rate / 1_000).toFixed(1)}K guesses/s`;
    if (rate >= 1)
        return `${Math.round(rate)} guesses/s`;
    return `${rate.toFixed(2)} guesses/s`;
}
