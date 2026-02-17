import { useEffect, useMemo, useState } from "react";
import "./styles.css";
import { useToast } from "../components/ToastHost";
import { usePersistentState } from "../hooks/usePersistentState";
import { useClipboardPrefs, writeClipboard } from "../utils/clipboard";
import type { ModuleKey } from "../components/ModuleList";
import { useI18n } from "../i18n";
import {
  analyzeSecret,
  estimatePassphraseEntropy,
  estimatePasswordEntropy,
  generatePassphrase,
  generatePassphraseBatch,
  generatePassword,
  generatePasswordBatch,
  getPassphraseDictionaryStats,
  gradeLabel,
  type CandidateRow,
  type PassphraseSettings,
  type PasswordSettings,
  type SecretGrade,
} from "../utils/passwordToolkit";
import {
  PASSWORD_HASH_DEFAULTS,
  assessPasswordHashChoice,
  hashPassword,
  supportsArgon2id,
  verifyPassword,
  type HashSafety,
  type PasswordHashAlgorithm,
} from "../utils/passwordHashing";

interface PwViewProps {
  onOpenGuide?: (key?: ModuleKey) => void;
}

export function PwView({ onOpenGuide }: PwViewProps) {
  const { push } = useToast();
  const { t, tr, formatNumber } = useI18n();
  const [clipboardPrefs] = useClipboardPrefs();
  const [passwordSettings, setPasswordSettings] = usePersistentState<PasswordSettings>("nullid:pw-settings", {
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
  const [passphraseSettings, setPassphraseSettings] = usePersistentState<PassphraseSettings>("nullid:pp-settings", {
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
  const [batchMode, setBatchMode] = usePersistentState<"password" | "passphrase">("nullid:pw-batch-mode", "password");
  const [batchCount, setBatchCount] = usePersistentState<number>("nullid:pw-batch-count", 6);
  const [batchRows, setBatchRows] = useState<CandidateRow[]>([]);
  const [labInput, setLabInput] = usePersistentState<string>("nullid:pw-lab-input", "");
  const [hashAlgorithm, setHashAlgorithm] = usePersistentState<PasswordHashAlgorithm>("nullid:pw-hash:algorithm", "argon2id");
  const [hashSaltBytes, setHashSaltBytes] = usePersistentState<number>("nullid:pw-hash:salt", PASSWORD_HASH_DEFAULTS.saltBytes);
  const [hashPbkdf2Iterations, setHashPbkdf2Iterations] = usePersistentState<number>(
    "nullid:pw-hash:pbkdf2-iterations",
    PASSWORD_HASH_DEFAULTS.pbkdf2Iterations,
  );
  const [hashArgon2Memory, setHashArgon2Memory] = usePersistentState<number>(
    "nullid:pw-hash:argon2-memory",
    PASSWORD_HASH_DEFAULTS.argon2Memory,
  );
  const [hashArgon2Passes, setHashArgon2Passes] = usePersistentState<number>(
    "nullid:pw-hash:argon2-passes",
    PASSWORD_HASH_DEFAULTS.argon2Passes,
  );
  const [hashArgon2Parallelism, setHashArgon2Parallelism] = usePersistentState<number>(
    "nullid:pw-hash:argon2-parallelism",
    PASSWORD_HASH_DEFAULTS.argon2Parallelism,
  );
  const [hashInput, setHashInput] = useState("");
  const [hashVerifyInput, setHashVerifyInput] = useState("");
  const [hashOutput, setHashOutput] = useState("");
  const [hashBusy, setHashBusy] = useState(false);
  const [hashError, setHashError] = useState<string | null>(null);
  const [hashVerifyState, setHashVerifyState] = useState<"idle" | "match" | "mismatch" | "error">("idle");
  const [argon2Available, setArgon2Available] = useState<boolean | null>(null);
  const passwordToggleKeys: Array<"upper" | "lower" | "digits" | "symbols"> = ["upper", "lower", "digits", "symbols"];

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
      } catch (error) {
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
  const hashChoiceAssessment = useMemo(
    () =>
      assessPasswordHashChoice({
        algorithm: hashAlgorithm,
        saltBytes: hashSaltBytes,
        pbkdf2Iterations: hashPbkdf2Iterations,
        argon2Memory: hashArgon2Memory,
        argon2Passes: hashArgon2Passes,
        argon2Parallelism: hashArgon2Parallelism,
      }),
    [hashAlgorithm, hashArgon2Memory, hashArgon2Parallelism, hashArgon2Passes, hashPbkdf2Iterations, hashSaltBytes],
  );
  const dictionary = useMemo(
    () => getPassphraseDictionaryStats(passphraseSettings.dictionaryProfile),
    [passphraseSettings.dictionaryProfile],
  );

  const applyPasswordPreset = (preset: "high" | "nosym" | "pin") => {
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
    } else if (preset === "nosym") {
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
    } else {
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

  const applyPassphrasePreset = (preset: "memorable" | "balanced" | "max") => {
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
    } else if (preset === "balanced") {
      setPassphraseSettings({
        words: 6,
        separator: "-",
        dictionaryProfile: "extended",
        caseStyle: "random",
        numberMode: "append-2",
        symbolMode: "append",
        ensureUniqueWords: true,
      });
    } else {
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

  const copySecret = (value: string, successMessage: string) =>
    writeClipboard(
      value,
      clipboardPrefs,
      (message, tone) => push(message, tone === "danger" ? "danger" : tone === "accent" ? "accent" : "neutral"),
      successMessage,
    );

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
    } catch (error) {
      console.error(error);
      const message = error instanceof Error ? error.message : "password hash failed";
      setHashError(message);
      push(message, "danger");
    } finally {
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
    } catch (error) {
      console.error(error);
      setHashVerifyState("error");
      const message = error instanceof Error ? error.message : "verification failed";
      setHashError(message);
      push(message, "danger");
    } finally {
      setHashBusy(false);
    }
  };

  return (
    <div className="workspace-scroll">
      <div className="guide-link">
        <button type="button" className="guide-link-button" onClick={() => onOpenGuide?.("pw")}>
          {t("guide.link")}
        </button>
      </div>
      <div className="grid-two">
        <div className="panel" aria-label={tr("Password generator")}>
          <div className="panel-heading">
            <span>{tr("Password")}</span>
            <span className="panel-subtext">{tr("constraint-driven")}</span>
          </div>
          <div className="controls-row">
            <input className="input" value={password} readOnly aria-label={tr("Password output")} />
            <button className="button" type="button" onClick={() => setPassword(generatePassword(passwordSettings))}>
              {tr("regenerate")}
            </button>
            <button className="button" type="button" onClick={() => copySecret(password, "password copied")}>
              {tr("copy")}
            </button>
          </div>
          <div className="controls-row">
            <label className="section-title" htmlFor="password-length">
              {tr("Length")}
            </label>
            <input
              id="password-length"
              className="input"
              type="number"
              min={8}
              max={96}
              value={passwordSettings.length}
              onChange={(event) =>
                setPasswordSettings((prev) => ({
                  ...prev,
                  length: clamp(Number(event.target.value) || 0, 8, 96),
                }))
              }
              aria-label={tr("Password length")}
            />
            <div className="pill-buttons" role="group" aria-label={tr("Character sets")}>
              {passwordToggleKeys.map((key) => (
                <button
                  key={key}
                  type="button"
                  className={passwordSettings[key] ? "active" : ""}
                  onClick={() =>
                    setPasswordSettings((prev) => ({
                      ...prev,
                      [key]: !prev[key],
                    }))
                  }
                  aria-label={`Toggle ${key} characters`}
                >
                  {key}
                </button>
              ))}
            </div>
          </div>
          <div className="controls-row">
            <label className="section-title" htmlFor="pw-hardening">
              {tr("Hardening")}
            </label>
            <div className="pill-buttons" role="group" aria-label={tr("Hardening options")}>
              <button
                id="pw-hardening"
                type="button"
                className={passwordSettings.avoidAmbiguity ? "active" : ""}
                onClick={() => setPasswordSettings((prev) => ({ ...prev, avoidAmbiguity: !prev.avoidAmbiguity }))}
                aria-label={tr("Avoid ambiguous characters")}
              >
                {tr("avoid ambiguous")}
              </button>
              <button
                type="button"
                className={passwordSettings.enforceMix ? "active" : ""}
                onClick={() => setPasswordSettings((prev) => ({ ...prev, enforceMix: !prev.enforceMix }))}
                aria-label={tr("Require all selected character types")}
              >
                {tr("require all sets")}
              </button>
              <button
                type="button"
                className={passwordSettings.blockSequential ? "active" : ""}
                onClick={() => setPasswordSettings((prev) => ({ ...prev, blockSequential: !prev.blockSequential }))}
                aria-label={tr("Block sequential patterns")}
              >
                {tr("block sequences")}
              </button>
              <button
                type="button"
                className={passwordSettings.blockRepeats ? "active" : ""}
                onClick={() => setPasswordSettings((prev) => ({ ...prev, blockRepeats: !prev.blockRepeats }))}
                aria-label={tr("Block repeated runs")}
              >
                {tr("block repeats")}
              </button>
            </div>
          </div>
          <div className="controls-row">
            <label className="section-title" htmlFor="pw-min-unique">
              {tr("Min unique")}
            </label>
            <input
              id="pw-min-unique"
              className="input"
              type="number"
              min={1}
              max={passwordSettings.length}
              value={passwordSettings.minUniqueChars}
              onChange={(event) =>
                setPasswordSettings((prev) => ({
                  ...prev,
                  minUniqueChars: clamp(Number(event.target.value) || 0, 1, prev.length),
                }))
              }
              aria-label={tr("Minimum unique characters")}
            />
          </div>
          <div className="controls-row">
            <span className="section-title">{tr("Presets")}</span>
            <div className="pill-buttons" role="group" aria-label={tr("Password presets")}>
              <button type="button" onClick={() => applyPasswordPreset("high")}>
                {tr("high security")}
              </button>
              <button type="button" onClick={() => applyPasswordPreset("nosym")}>
                {tr("no symbols")}
              </button>
              <button type="button" onClick={() => applyPasswordPreset("pin")}>
                {tr("pin (digits)")}
              </button>
            </div>
          </div>
          <div className="status-line">
            <span>{tr("length")} {formatNumber(passwordSettings.length)}</span>
            <span className="tag tag-accent">{tr("entropy")} ≈ {formatNumber(passwordEntropy)} {tr("bits")}</span>
            <span className={gradeTagClass(passwordAssessment.grade)}>{gradeLabel(passwordAssessment.grade)}</span>
          </div>
          <div className="note-box">
            <div className="microcopy">
              {tr("effective entropy")} ≈ {formatNumber(passwordAssessment.effectiveEntropyBits)} {tr("bits")} · {tr("online crack")} (rate-limited median):{" "}
              {passwordAssessment.crackTime.online}
            </div>
            {passwordAssessment.warnings.length > 0 ? (
              <ul className="note-list">
                {passwordAssessment.warnings.map((warning) => (
                  <li key={warning}>{warning}</li>
                ))}
              </ul>
            ) : (
              <div className="microcopy">{tr("No obvious pattern weaknesses detected.")}</div>
            )}
          </div>
        </div>
        <div className="panel" aria-label={tr("Passphrase generator")}>
          <div className="panel-heading">
            <span>{tr("Passphrase")}</span>
            <span className="panel-subtext">{tr("mega dictionary")}</span>
          </div>
          <div className="controls-row">
            <input className="input" value={phrase} readOnly aria-label={tr("Passphrase output")} />
            <button
              className="button"
              type="button"
              onClick={() => setPhrase(generatePassphrase(passphraseSettings))}
            >
              {tr("regenerate")}
            </button>
            <button className="button" type="button" onClick={() => copySecret(phrase, "passphrase copied")}>
              {tr("copy")}
            </button>
          </div>
          <div className="controls-row">
            <label className="section-title" htmlFor="word-count">
              {tr("Words")}
            </label>
            <input
              id="word-count"
              className="input"
              type="number"
              min={3}
              max={12}
              value={passphraseSettings.words}
              onChange={(event) =>
                setPassphraseSettings((prev) => ({
                  ...prev,
                  words: clamp(Number(event.target.value) || 0, 3, 12),
                }))
              }
              aria-label={tr("Passphrase word count")}
            />
            <select
              className="select"
              value={passphraseSettings.separator}
              onChange={(event) =>
                setPassphraseSettings((prev) => ({
                  ...prev,
                  separator: event.target.value as PassphraseSettings["separator"],
                }))
              }
              aria-label={tr("Word separator")}
            >
              <option value="space">{tr("space")}</option>
              <option value="-">-</option>
              <option value=".">.</option>
              <option value="_">_</option>
              <option value="/">/</option>
              <option value=":">:</option>
            </select>
            <select
              className="select"
              value={passphraseSettings.dictionaryProfile}
              onChange={(event) =>
                setPassphraseSettings((prev) => ({
                  ...prev,
                  dictionaryProfile: event.target.value as PassphraseSettings["dictionaryProfile"],
                }))
              }
              aria-label={tr("Dictionary profile")}
            >
              <option value="balanced">{tr("balanced")}</option>
              <option value="extended">{tr("extended")}</option>
              <option value="maximal">{tr("maximal")}</option>
            </select>
          </div>
          <div className="controls-row">
            <label className="section-title" htmlFor="phrase-hardening">
              {tr("Styling")}
            </label>
            <select
              id="phrase-hardening"
              className="select"
              value={passphraseSettings.caseStyle}
              onChange={(event) =>
                setPassphraseSettings((prev) => ({
                  ...prev,
                  caseStyle: event.target.value as PassphraseSettings["caseStyle"],
                }))
              }
              aria-label={tr("Passphrase case style")}
            >
              <option value="lower">{tr("lower")}</option>
              <option value="title">{tr("title")}</option>
              <option value="random">{tr("random")}</option>
              <option value="upper">{tr("upper")}</option>
            </select>
            <select
              className="select"
              value={passphraseSettings.numberMode}
              onChange={(event) =>
                setPassphraseSettings((prev) => ({
                  ...prev,
                  numberMode: event.target.value as PassphraseSettings["numberMode"],
                }))
              }
              aria-label={tr("Passphrase number mode")}
            >
              <option value="none">{tr("no number")}</option>
              <option value="append-2">{tr("append 2 digits")}</option>
              <option value="append-4">{tr("append 4 digits")}</option>
            </select>
            <select
              className="select"
              value={passphraseSettings.symbolMode}
              onChange={(event) =>
                setPassphraseSettings((prev) => ({
                  ...prev,
                  symbolMode: event.target.value as PassphraseSettings["symbolMode"],
                }))
              }
              aria-label={tr("Passphrase symbol mode")}
            >
              <option value="none">{tr("no symbol")}</option>
              <option value="append">{tr("append symbol")}</option>
              <option value="wrap">{tr("wrap with symbols")}</option>
            </select>
          </div>
          <div className="controls-row">
            <label className="section-title">{tr("Hardening")}</label>
            <div className="pill-buttons" role="group" aria-label={tr("Passphrase hardening options")}>
              <button
                type="button"
                className={passphraseSettings.ensureUniqueWords ? "active" : ""}
                onClick={() => setPassphraseSettings((prev) => ({ ...prev, ensureUniqueWords: !prev.ensureUniqueWords }))}
                aria-label={tr("Enforce unique words")}
              >
                {tr("unique words")}
              </button>
            </div>
            <span className="microcopy">{tr("dictionary")}: {dictionary.label}</span>
          </div>
          <div className="controls-row">
            <span className="section-title">{tr("Presets")}</span>
            <div className="pill-buttons" role="group" aria-label={tr("Passphrase presets")}>
              <button type="button" onClick={() => applyPassphrasePreset("memorable")}>
                {tr("memorable")}
              </button>
              <button type="button" onClick={() => applyPassphrasePreset("balanced")}>
                {tr("balanced")}
              </button>
              <button type="button" onClick={() => applyPassphrasePreset("max")}>
                {tr("max entropy")}
              </button>
            </div>
          </div>
          <div className="status-line">
            <span>{tr("words")} {formatNumber(passphraseSettings.words)}</span>
            <span className="tag">{formatNumber(dictionary.size)} {tr("words")}</span>
            <span className="tag tag-accent">{tr("entropy")} ≈ {formatNumber(passphraseEntropy)} {tr("bits")}</span>
            <span className={gradeTagClass(passphraseAssessment.grade)}>{gradeLabel(passphraseAssessment.grade)}</span>
          </div>
          <div className="note-box">
            <div className="microcopy">
              {tr("bits/word")} ≈ {dictionary.bitsPerWord.toFixed(2)} · {tr("offline crack")} (slow-KDF median):{" "}
              {passphraseAssessment.crackTime.offline}
            </div>
            {passphraseAssessment.warnings.length > 0 ? (
              <ul className="note-list">
                {passphraseAssessment.warnings.map((warning) => (
                  <li key={warning}>{warning}</li>
                ))}
              </ul>
            ) : (
              <div className="microcopy">{tr("No obvious passphrase weaknesses detected.")}</div>
            )}
          </div>
        </div>
      </div>
      <div className="grid-two">
        <div className="panel" aria-label={tr("Secret strength lab")}>
          <div className="panel-heading">
            <span>{tr("Strength Lab")}</span>
            <span className="panel-subtext">{tr("audit any secret")}</span>
          </div>
          <textarea
            className="textarea"
            value={labInput}
            onChange={(event) => setLabInput(event.target.value)}
            placeholder={tr("Paste a password or passphrase to audit locally")}
            aria-label={tr("Secret strength lab input")}
          />
          <div className="status-line">
            <span>{tr("entropy")} ≈ {formatNumber(labAssessment.entropyBits)} {tr("bits")}</span>
            <span className="tag">{tr("effective")} ≈ {formatNumber(labAssessment.effectiveEntropyBits)} {tr("bits")}</span>
            <span className={gradeTagClass(labAssessment.grade)}>{gradeLabel(labAssessment.grade)}</span>
          </div>
          <div className="note-box">
            <div className="microcopy">
              {tr("online")} (rate-limited median): {labAssessment.crackTime.online} · {tr("offline")} (slow-KDF median):{" "}
              {labAssessment.crackTime.offline}
            </div>
            <ul className="note-list">
              {labAssessment.crackTime.scenarios.map((scenario) => (
                <li key={scenario.key}>
                  {scenario.label}: median {scenario.median}, worst-case {scenario.worstCase} @ {formatGuessRate(scenario.guessesPerSecond)}
                </li>
              ))}
            </ul>
            <ul className="note-list">
              {labAssessment.crackTime.assumptions.map((assumption) => (
                <li key={assumption}>{assumption}</li>
              ))}
            </ul>
            <ul className="note-list">
              {labAssessment.warnings.length > 0 ? (
                labAssessment.warnings.map((warning) => <li key={warning}>{warning}</li>)
              ) : (
                <li>{tr("no direct warning patterns detected")}</li>
              )}
              {labAssessment.strengths.map((strength) => (
                <li key={strength}>{strength}</li>
              ))}
            </ul>
          </div>
        </div>
        <div className="panel" aria-label={tr("Batch generator")}>
          <div className="panel-heading">
            <span>{tr("Batch Generator")}</span>
            <span className="panel-subtext">{tr("shortlist candidates")}</span>
          </div>
          <div className="controls-row">
            <div className="pill-buttons" role="group" aria-label={tr("Batch mode")}>
              <button
                type="button"
                className={batchMode === "password" ? "active" : ""}
                onClick={() => setBatchMode("password")}
              >
                {tr("passwords")}
              </button>
              <button
                type="button"
                className={batchMode === "passphrase" ? "active" : ""}
                onClick={() => setBatchMode("passphrase")}
              >
                {tr("passphrases")}
              </button>
            </div>
            <input
              className="input"
              type="number"
              min={3}
              max={16}
              value={batchCount}
              onChange={(event) => setBatchCount(clamp(Number(event.target.value) || 0, 3, 16))}
              aria-label={tr("Batch candidate count")}
            />
            <button
              className="button"
              type="button"
              onClick={() =>
                setBatchRows(
                  batchMode === "password"
                    ? generatePasswordBatch(passwordSettings, clamp(batchCount, 3, 16))
                    : generatePassphraseBatch(passphraseSettings, clamp(batchCount, 3, 16)),
                )
              }
            >
              {tr("regenerate batch")}
            </button>
          </div>
          <table className="table" aria-label={tr("Batch candidates table")}>
            <thead>
              <tr>
                <th>{tr("candidate")}</th>
                <th>{tr("entropy")}</th>
                <th>{tr("grade")}</th>
                <th>{tr("copy")}</th>
              </tr>
            </thead>
            <tbody>
              {batchRows.map((row, index) => (
                <tr key={`${row.value}-${index}`}>
                  <td className="microcopy">{row.value}</td>
                  <td>{row.entropyBits}b</td>
                  <td>
                    <span className={gradeTagClass(row.assessment.grade)}>{gradeLabel(row.assessment.grade)}</span>
                  </td>
                  <td>
                    <button
                      className="button"
                      type="button"
                      onClick={() => copySecret(row.value, `${batchMode} copied`)}
                      aria-label={`Copy candidate ${index + 1}`}
                    >
                      copy
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      <div className="panel" aria-label={tr("Password storage hash lab")}>
        <div className="panel-heading">
          <span>{tr("Password Storage Hashing")}</span>
          <span className="panel-subtext">{tr("salted records with cost factors")}</span>
        </div>
        <div className="controls-row">
          <label className="section-title" htmlFor="pw-hash-algo">
            {tr("Algorithm")}
          </label>
          <select
            id="pw-hash-algo"
            className="select"
            value={hashAlgorithm}
            onChange={(event) => {
              setHashAlgorithm(event.target.value as PasswordHashAlgorithm);
              setHashVerifyState("idle");
            }}
            aria-label={tr("Password hash algorithm")}
          >
            <option value="argon2id">Argon2id (recommended)</option>
            <option value="pbkdf2-sha256">PBKDF2-SHA256 (compat)</option>
            <option value="sha512">SHA-512 (legacy)</option>
            <option value="sha256">SHA-256 (legacy)</option>
          </select>
          <label className="section-title" htmlFor="pw-hash-salt">
            {tr("Salt bytes")}
          </label>
          <input
            id="pw-hash-salt"
            className="input"
            type="number"
            min={8}
            max={64}
            value={hashSaltBytes}
            onChange={(event) => setHashSaltBytes(clamp(Number(event.target.value) || 0, 8, 64))}
            aria-label={tr("Hash salt bytes")}
          />
        </div>
        {hashAlgorithm === "pbkdf2-sha256" ? (
          <div className="controls-row">
            <label className="section-title" htmlFor="pw-hash-pbkdf2-iterations">
              {tr("PBKDF2 iterations")}
            </label>
            <input
              id="pw-hash-pbkdf2-iterations"
              className="input"
              type="number"
              min={100000}
              max={2000000}
              step={50000}
              value={hashPbkdf2Iterations}
              onChange={(event) => setHashPbkdf2Iterations(clamp(Number(event.target.value) || 0, 100_000, 2_000_000))}
              aria-label={tr("PBKDF2 iterations")}
            />
          </div>
        ) : null}
        {hashAlgorithm === "argon2id" ? (
          <div className="controls-row">
            <label className="section-title" htmlFor="pw-hash-argon2-memory">
              {tr("Argon2 memory (KiB)")}
            </label>
            <input
              id="pw-hash-argon2-memory"
              className="input"
              type="number"
              min={8192}
              max={262144}
              step={2048}
              value={hashArgon2Memory}
              onChange={(event) => setHashArgon2Memory(clamp(Number(event.target.value) || 0, 8_192, 262_144))}
              aria-label={tr("Argon2 memory")}
            />
            <label className="section-title" htmlFor="pw-hash-argon2-passes">
              {tr("Passes")}
            </label>
            <input
              id="pw-hash-argon2-passes"
              className="input"
              type="number"
              min={1}
              max={8}
              value={hashArgon2Passes}
              onChange={(event) => setHashArgon2Passes(clamp(Number(event.target.value) || 0, 1, 8))}
              aria-label={tr("Argon2 passes")}
            />
            <label className="section-title" htmlFor="pw-hash-argon2-parallelism">
              {tr("Parallelism")}
            </label>
            <input
              id="pw-hash-argon2-parallelism"
              className="input"
              type="number"
              min={1}
              max={4}
              value={hashArgon2Parallelism}
              onChange={(event) => setHashArgon2Parallelism(clamp(Number(event.target.value) || 0, 1, 4))}
              aria-label={tr("Argon2 parallelism")}
            />
          </div>
        ) : null}
        <textarea
          className="textarea"
          value={hashInput}
          onChange={(event) => setHashInput(event.target.value)}
          placeholder={tr("Password input for hashing (local only)")}
          aria-label={tr("Password input for hashing")}
        />
        <div className="controls-row">
          <button className="button" type="button" onClick={() => void handlePasswordHash()} disabled={hashBusy || !hashInput.trim()}>
            {hashBusy ? tr("working…") : tr("generate hash")}
          </button>
          <button className="button" type="button" onClick={() => copySecret(hashOutput, "hash copied")} disabled={!hashOutput}>
            {tr("copy hash")}
          </button>
          <button
            className="button"
            type="button"
            onClick={() => {
              setHashInput("");
              setHashVerifyInput("");
              setHashOutput("");
              setHashError(null);
              setHashVerifyState("idle");
            }}
          >
            {tr("clear")}
          </button>
        </div>
        <textarea
          className="textarea"
          value={hashOutput}
          readOnly
          placeholder={tr("Generated password hash record")}
          aria-label={tr("Generated password hash")}
        />
        <div className="controls-row">
          <input
            className="input"
            type="password"
            value={hashVerifyInput}
            onChange={(event) => setHashVerifyInput(event.target.value)}
            placeholder={tr("Password candidate for verification")}
            aria-label={tr("Password candidate")}
          />
          <button className="button" type="button" onClick={() => void handleVerifyHash()} disabled={!hashOutput || !hashVerifyInput || hashBusy}>
            {tr("verify")}
          </button>
        </div>
        <div className="status-line">
          <span>{tr("safety")}</span>
          <span className={hashSafetyTagClass(hashChoiceAssessment.safety)}>
            {hashChoiceAssessment.safety === "strong" ? tr("strong") : hashChoiceAssessment.safety === "fair" ? tr("fair") : tr("weak")}
          </span>
          <span className={hashVerifyState === "match" ? "tag tag-accent" : hashVerifyState === "mismatch" || hashVerifyState === "error" ? "tag tag-danger" : "tag"}>
            {hashVerifyState === "match"
              ? tr("verified")
              : hashVerifyState === "mismatch"
                ? tr("mismatch")
                : hashVerifyState === "error"
                  ? tr("error")
                  : tr("idle")}
          </span>
          {argon2Available === false && hashAlgorithm === "argon2id" ? (
            <span className="microcopy">{tr("Argon2id is not available in this runtime. Choose PBKDF2 or use a browser with Argon2id support.")}</span>
          ) : null}
        </div>
        {hashChoiceAssessment.warnings.length > 0 ? (
          <ul className="note-list">
            {hashChoiceAssessment.warnings.map((warning) => (
              <li key={warning}>{warning}</li>
            ))}
          </ul>
        ) : (
          <div className="microcopy">{tr("Current hash profile meets the recommended baseline.")}</div>
        )}
        {hashError ? <div className="microcopy" style={{ color: "var(--danger)" }}>{hashError}</div> : null}
        <div className="microcopy">
          {tr("Legacy SHA options are kept for compatibility only. Prefer Argon2id for new password storage records.")}
        </div>
      </div>
    </div>
  );
}

function gradeTagClass(grade: SecretGrade): string {
  if (grade === "critical" || grade === "weak") return "tag tag-danger";
  if (grade === "fair") return "tag";
  return "tag tag-accent";
}

function hashSafetyTagClass(safety: HashSafety): string {
  if (safety === "weak") return "tag tag-danger";
  if (safety === "fair") return "tag";
  return "tag tag-accent";
}

function clamp(value: number, min: number, max: number) {
  return Math.min(max, Math.max(min, value));
}

function formatGuessRate(rate: number): string {
  if (rate >= 1_000_000_000) return `${(rate / 1_000_000_000).toFixed(1)}B guesses/s`;
  if (rate >= 1_000_000) return `${(rate / 1_000_000).toFixed(1)}M guesses/s`;
  if (rate >= 1_000) return `${(rate / 1_000).toFixed(1)}K guesses/s`;
  if (rate >= 1) return `${Math.round(rate)} guesses/s`;
  return `${rate.toFixed(2)} guesses/s`;
}
