import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Chip } from "../components/Chip";
import { useToast } from "../components/ToastHost";
import "./styles.css";
import type { HashAlgorithm } from "../utils/hash";
import { expectedHashLengths, hashFile, hashText, normalizeHashInput } from "../utils/hash";
import { useClipboardPrefs, writeClipboard } from "../utils/clipboard";
import type { ModuleKey } from "../components/ModuleList";

export type HashViewActions = {
  copyDigest: () => void | Promise<void>;
  clearInputs: () => void;
  compare: () => void;
};

type HashDisplayFormat = "hex" | "base64" | "sha256sum";

interface HashViewProps {
  onRegisterActions?: (actions: HashViewActions | null) => void;
  onStatus?: (message: string, tone?: "neutral" | "accent" | "danger") => void;
  onOpenGuide?: (key?: ModuleKey) => void;
}

type HashSource =
  | { kind: "file"; file: File }
  | { kind: "text"; value: string };

export function HashView({ onRegisterActions, onStatus, onOpenGuide }: HashViewProps) {
  const { push } = useToast();
  const [clipboardPrefs] = useClipboardPrefs();
  const [algorithm, setAlgorithm] = useState<HashAlgorithm>("SHA-256");
  const [displayFormat, setDisplayFormat] = useState<HashDisplayFormat>("hex");
  const [textValue, setTextValue] = useState("");
  const [verifyValue, setVerifyValue] = useState("");
  const [result, setResult] = useState<{ hex: string; base64: string } | null>(null);
  const [source, setSource] = useState<HashSource | null>(null);
  const [fileName, setFileName] = useState<string>("none");
  const [comparison, setComparison] = useState<"idle" | "match" | "mismatch" | "invalid">("idle");
  const [progress, setProgress] = useState<number>(0);
  const [fileComparison, setFileComparison] = useState<"idle" | "match" | "mismatch" | "pending">("idle");
  const [fileCompareName, setFileCompareName] = useState<string>("none");
  const abortRef = useRef<AbortController | null>(null);
  const textDebounceRef = useRef<number | null>(null);
  const verifyDebounceRef = useRef<number | null>(null);
  const jobRef = useRef<number>(0);
  const textTokenRef = useRef(0);
  const verifyTokenRef = useRef(0);
  const [isComposing, setIsComposing] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const fileCompareRef = useRef<HTMLInputElement>(null);
  const algorithmRef = useRef(algorithm);
  const resultRef = useRef(result);
  const verifyValueRef = useRef(verifyValue);
  const onStatusRef = useRef(onStatus);

  const MAX_FILE_BYTES = 50 * 1024 * 1024; // 50MB (prevents browser OOM)
  const MAX_TEXT_CHARS = 1_000_000; // ~1MB text safety guard

  const digestDisplay = useMemo(() => {
    if (!result) return "";
    if (displayFormat === "hex") return result.hex;
    if (displayFormat === "base64") return result.base64;
    if (displayFormat === "sha256sum" && algorithm === "SHA-256") {
      const name = source?.kind === "file" ? source.file.name : "stdin";
      return `${result.hex}  ${name}`;
    }
    return result.hex;
  }, [algorithm, displayFormat, result, source]);

  const normalizedVerify = useMemo(() => normalizeHashInput(verifyValue), [verifyValue]);
  const expectedLength = useMemo(() => expectedHashLengths[algorithm], [algorithm]);

  const isBusy = progress > 0 && progress < 100;

  const computeHash = useCallback(
    async (input: HashSource) => {
      setComparison("idle");
      setFileComparison("idle");
      setProgress(0);
      abortRef.current?.abort();
      const controller = new AbortController();
      abortRef.current = controller;
      const jobId = (jobRef.current += 1);
      try {
        const nextResult =
          input.kind === "file"
            ? await hashFile(input.file, algorithm, { onProgress: setProgress, signal: controller.signal })
            : await hashText(input.value, algorithm, { signal: controller.signal, onProgress: setProgress });
        if (jobId === jobRef.current) {
          setResult(nextResult);
          setSource(input);
          setFileName(input.kind === "file" ? input.file.name : "inline");
          onStatus?.("digest ready", "accent");
        }
      } catch (error) {
        if ((error as Error).name === "AbortError") return;
        console.error(error);
        onStatus?.("hash failed", "danger");
      } finally {
        if (jobId === jobRef.current) {
          setProgress(100);
        }
      }
    },
    [algorithm, onStatus],
  );

  const report = useCallback(
    (message: string, tone: "neutral" | "accent" | "danger" = "neutral") => {
      onStatus?.(message, tone);
      push(message, tone === "danger" ? "danger" : tone === "accent" ? "accent" : "neutral");
    },
    [onStatus, push],
  );

  const handleFile = useCallback(
    async (file?: File | null) => {
      if (!file) return;
      if (file.size > MAX_FILE_BYTES) {
        report(`file too large (${Math.ceil(file.size / (1024 * 1024))}MB). max 50MB.`, "danger");
        return;
      }
      await computeHash({ kind: "file", file });
    },
    [MAX_FILE_BYTES, computeHash, report],
  );

  const handleTextChange = useCallback(
    (value: string) => {
      if (value.length > MAX_TEXT_CHARS) {
        report("text too large for inline hashing", "danger");
        return;
      }
      if (isComposing) {
        setTextValue(value);
        return;
      }
      setTextValue(value);
      // Debounce hashing so the UI remains responsive while typing.
      if (textDebounceRef.current) window.clearTimeout(textDebounceRef.current);
      const token = (textTokenRef.current += 1);
      textDebounceRef.current = window.setTimeout(() => {
        void (async () => {
          try {
            await computeHash({ kind: "text", value });
          } finally {
            // Only clear the timer reference if this is the latest scheduled run.
            if (textTokenRef.current === token) {
              textDebounceRef.current = null;
            }
          }
        })();
      }, 150);
    },
    [MAX_TEXT_CHARS, computeHash, isComposing, report],
  );

  const copyDigest = useCallback(async () => {
    if (!digestDisplay) {
      report("no digest", "danger");
      return;
    }
    await writeClipboard(digestDisplay, clipboardPrefs, report, "copied");
  }, [clipboardPrefs, digestDisplay, report]);

  const copyShaLine = useCallback(async () => {
    if (!result) {
      onStatus?.("no digest", "danger");
      return;
    }
    const name = source?.kind === "file" ? source.file.name : "stdin";
    const line = `${result.hex}  ${name}`;
    await writeClipboard(line, clipboardPrefs, report, "sha256sum line copied");
  }, [clipboardPrefs, report, result, source]);

  const clearInputs = useCallback(() => {
    abortRef.current?.abort();
    setTextValue("");
    setVerifyValue("");
    setResult(null);
    setSource(null);
    setFileName("none");
    setProgress(0);
    setComparison("idle");
    setFileComparison("idle");
    setFileCompareName("none");
    if (fileInputRef.current) fileInputRef.current.value = "";
    if (fileCompareRef.current) fileCompareRef.current.value = "";
    onStatus?.("cleared", "neutral");
  }, [onStatus]);

  const compare = useCallback(() => {
    const currentResult = resultRef.current;
    const currentVerify = verifyValueRef.current;
    const currentAlgorithm = algorithmRef.current;
    const status = onStatusRef.current;
    if (!currentResult) {
      setComparison("invalid");
      status?.("digest missing", "danger");
      return;
    }
    const normalized = normalizeHashInput(currentVerify);
    const expected = expectedHashLengths[currentAlgorithm];
    if (!normalized || (expected && normalized.length !== expected)) {
      setComparison("invalid");
      status?.("invalid hash", "danger");
      return;
    }
    const match = normalized === normalizeHashInput(currentResult.hex);
    setComparison(match ? "match" : "mismatch");
    status?.(match ? "hash match" : "hash mismatch", match ? "accent" : "danger");
  }, []);

  const handleVerifyChange = useCallback(
    (value: string) => {
      setVerifyValue(value);
      setComparison("idle");
      if (verifyDebounceRef.current) window.clearTimeout(verifyDebounceRef.current);
      const token = (verifyTokenRef.current += 1);
      verifyDebounceRef.current = window.setTimeout(() => {
        if (verifyTokenRef.current === token) {
          compare();
          verifyDebounceRef.current = null;
        }
      }, 200);
    },
    [compare],
  );

  useEffect(() => {
    if (source) {
      void computeHash(source);
    }
  }, [algorithm, computeHash, source]);

  useEffect(() => {
    algorithmRef.current = algorithm;
  }, [algorithm]);

  useEffect(() => {
    resultRef.current = result;
  }, [result]);

  useEffect(() => {
    verifyValueRef.current = verifyValue;
  }, [verifyValue]);

  useEffect(() => {
    onStatusRef.current = onStatus;
  }, [onStatus]);

  useEffect(() => {
    onRegisterActions?.({ copyDigest, clearInputs, compare });
    return () => onRegisterActions?.(null);
  }, [clearInputs, compare, copyDigest, onRegisterActions]);

  useEffect(() => {
    return () => {
      if (textDebounceRef.current) window.clearTimeout(textDebounceRef.current);
      if (verifyDebounceRef.current) window.clearTimeout(verifyDebounceRef.current);
      abortRef.current?.abort();
    };
  }, []);

  const comparisonTone = comparison === "match" ? "accent" : comparison === "invalid" || comparison === "mismatch" ? "danger" : "muted";

  return (
    <div className="workspace-scroll">
      <div className="guide-link">
        <button type="button" className="guide-link-button" onClick={() => onOpenGuide?.("hash")}>
          ? guide
        </button>
      </div>
      <div className="grid-two">
        <div className="panel" aria-label="Hash inputs">
          <div className="panel-heading">
            <span>Hash input</span>
            <span className="panel-subtext">text or file</span>
          </div>
          <label className="section-title" htmlFor="hash-text">
            Text
          </label>
          <textarea
            id="hash-text"
            className="textarea"
            placeholder="Type or paste text to hash"
            value={textValue}
            onCompositionStart={() => setIsComposing(true)}
            onCompositionEnd={(event) => {
              setIsComposing(false);
              handleTextChange(event.currentTarget.value);
            }}
            onChange={(event) => handleTextChange(event.target.value)}
            aria-label="Text to hash"
          />
          <div className="dropzone"
            role="button"
            tabIndex={0}
            aria-label="Drop file to hash"
            onClick={() => fileInputRef.current?.click()}
            onKeyDown={(event) => {
              if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                fileInputRef.current?.click();
              }
            }}
            onDragOver={(event) => event.preventDefault()}
            onDrop={(event) => {
              event.preventDefault();
              void handleFile(event.dataTransfer.files?.[0] ?? null);
            }}
          >
            <input
              ref={fileInputRef}
              type="file"
              aria-label="Pick file"
              onChange={(event) => void handleFile(event.target.files?.[0] ?? null)}
              style={{ position: "absolute", opacity: 0, width: 1, height: 1, pointerEvents: "none" }}
              tabIndex={-1}
            />
            <div className="section-title">Drop or select file</div>
            <div className="microcopy">progressive chunk hashing</div>
            {isBusy && <div className="microcopy">progress {progress}%</div>}
          </div>
          <div className="status-line">
            <span>source</span>
            <Chip label={fileName} tone="muted" />
            {isBusy && <Chip label="hashing…" tone="accent" />}
          </div>
        </div>
        <div className="panel" aria-label="Hash output">
          <div className="panel-heading">
            <span>Digest</span>
            <span className="panel-subtext">{algorithm.toLowerCase()}</span>
          </div>
          <div className="controls-row">
            <input className="input" value={digestDisplay} readOnly aria-label="Computed hash" />
            <button className="button" type="button" onClick={copyDigest} disabled={!result}>
              copy
            </button>
            <button className="button" type="button" onClick={copyShaLine} disabled={!result || algorithm !== "SHA-256"}>
              sha256sum line
            </button>
          </div>
          <div className="controls-row">
            <div>
              <label className="section-title" htmlFor="hash-algo">
                Algorithm
              </label>
              <select
                id="hash-algo"
                className="select"
                value={algorithm}
                onChange={(event) => setAlgorithm(event.target.value as HashAlgorithm)}
                aria-label="Select hash algorithm"
              >
                <option value="SHA-256">SHA-256</option>
                <option value="SHA-512">SHA-512</option>
                <option value="SHA-1">SHA-1 (legacy/insecure)</option>
              </select>
            </div>
            <div>
              <div className="section-title" aria-hidden="true">
                Output
              </div>
              <div className="pill-buttons" role="group" aria-label="Output format">
                {(["hex", "base64", "sha256sum"] as HashDisplayFormat[]).map((format) => (
                  <button
                    key={format}
                    type="button"
                    className={displayFormat === format ? "active" : ""}
                    onClick={() => setDisplayFormat(format)}
                    disabled={format === "sha256sum" && algorithm !== "SHA-256"}
                  >
                    {format}
                  </button>
                ))}
              </div>
            </div>
          </div>
          <label className="section-title" htmlFor="hash-verify">
            Verify digest
          </label>
          <div className="controls-row">
            <input
              id="hash-verify"
              className="input"
              placeholder="Paste hash to verify"
              value={verifyValue}
              onChange={(event) => handleVerifyChange(event.target.value)}
              aria-label="Hash to verify"
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  event.preventDefault();
                  compare();
                }
              }}
            />
            <button className="button" type="button" onClick={compare} disabled={!verifyValue}>
              compare
            </button>
          </div>
          <div className="controls-row">
            <label className="section-title" htmlFor="hash-compare-file">
              Compare against file
            </label>
            <button className="button" type="button" onClick={() => fileCompareRef.current?.click()} disabled={!result}>
              select file
            </button>
            <input
              ref={fileCompareRef}
              id="hash-compare-file"
              type="file"
              aria-label="Pick file to compare hash"
              tabIndex={-1}
              style={{ position: "absolute", opacity: 0, width: 1, height: 1, pointerEvents: "none" }}
              onChange={async (event) => {
                try {
                  const file = event.target.files?.[0];
                  if (!file) return;
                  if (!result) {
                    setFileComparison("idle");
                    onStatus?.("hash source first", "danger");
                    return;
                  }
                  setFileComparison("pending");
                  setFileCompareName(file.name);
                  const compareDigest = await hashFile(file, algorithm, { onProgress: setProgress });
                  const match = compareDigest.hex === result.hex;
                  setFileComparison(match ? "match" : "mismatch");
                  onStatus?.(match ? "files match" : "files differ", match ? "accent" : "danger");
                } catch (error) {
                  console.error(error);
                  setFileComparison("idle");
                  onStatus?.("file compare failed", "danger");
                }
              }}
            />
          </div>
          <div className="status-line">
            <span>Result</span>
            <Chip
              label={
                comparison === "match"
                  ? "MATCH"
                  : comparison === "mismatch"
                    ? "MISMATCH"
                    : comparison === "invalid"
                      ? "INVALID"
                      : "PENDING"
              }
              tone={comparisonTone}
            />
            <span className="microcopy">{result ? "digest ready" : "awaiting input"}</span>
          </div>
          <div className="status-line">
            <span>File compare</span>
            <Chip
              label={
                fileComparison === "match"
                  ? "FILES MATCH"
                  : fileComparison === "mismatch"
                    ? "FILES DIFFER"
                    : fileComparison === "pending"
                      ? "CHECKING"
                      : "IDLE"
              }
              tone={fileComparison === "match" ? "accent" : fileComparison === "mismatch" ? "danger" : "muted"}
            />
            <span className="microcopy">against: {fileCompareName}</span>
          </div>
        </div>
      </div>
    </div>
  );
}
