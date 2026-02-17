import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Chip } from "../components/Chip";
import { useToast } from "../components/ToastHost";
import { useI18n } from "../i18n";
import "./styles.css";
import type { HashAlgorithm } from "../utils/hash";
import { expectedHashLengths, hashFile, hashText, normalizeHashInput } from "../utils/hash";
import { useClipboardPrefs, writeClipboard } from "../utils/clipboard";
import type { ModuleKey } from "../components/ModuleList";
import { usePersistentState } from "../hooks/usePersistentState";

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
  const { t } = useI18n();
  const [clipboardPrefs] = useClipboardPrefs();
  const [algorithm, setAlgorithm] = useState<HashAlgorithm>("SHA-256");
  const [displayFormat, setDisplayFormat] = useState<HashDisplayFormat>("hex");
  const [textValue, setTextValue] = useState("");
  const [verifyValue, setVerifyValue] = useState("");
  const [debouncedVerifyValue, setDebouncedVerifyValue] = useState("");
  const [result, setResult] = useState<{ hex: string; base64: string } | null>(null);
  const [source, setSource] = useState<HashSource | null>(null);
  const [fileName, setFileName] = useState<string>("none");
  const [comparison, setComparison] = useState<"idle" | "match" | "mismatch" | "invalid">("idle");
  const [progress, setProgress] = useState<number>(0);
  const [fileComparison, setFileComparison] = useState<"idle" | "match" | "mismatch" | "pending">("idle");
  const [fileCompareName, setFileCompareName] = useState<string>("none");
  const [batchInput, setBatchInput] = usePersistentState<string>("nullid:hash:batch-input", "");
  const [batchAlgorithm, setBatchAlgorithm] = usePersistentState<HashAlgorithm>("nullid:hash:batch-algo", "SHA-256");
  const [batchRows, setBatchRows] = useState<Array<{ line: string; hex: string; base64: string; index: number }>>([]);
  const [isBatching, setIsBatching] = useState(false);
  const [isHashing, setIsHashing] = useState(false);
  const [lastDurationMs, setLastDurationMs] = useState<number | null>(null);
  const [lastInputBytes, setLastInputBytes] = useState<number | null>(null);
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
  const lastAlgorithmRef = useRef<HashAlgorithm>(algorithm);
  const resultRef = useRef(result);
  const debouncedVerifyRef = useRef(debouncedVerifyValue);
  const onStatusRef = useRef(onStatus);
  const handleProgress = useCallback((percent: number) => {
    setProgress(percent);
  }, []);

  const MAX_FILE_BYTES = 50 * 1024 * 1024; // 50MB (prevents browser OOM)
  const MAX_TEXT_CHARS = 1_000_000; // ~1MB text safety guard
  const TEXT_DEBOUNCE_MS = 300;

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

  const isBusy = progress > 0 && progress < 100;

  const computeHash = useCallback(
    async (input: HashSource) => {
      setComparison("idle");
      setFileComparison("idle");
      setProgress(0);
      setIsHashing(true);
      abortRef.current?.abort();
      const controller = new AbortController();
      abortRef.current = controller;
      const jobId = (jobRef.current += 1);
      const startedAt = performance.now();
      let succeeded = false;
      try {
        const nextResult =
          input.kind === "file"
            ? await hashFile(input.file, algorithm, { onProgress: handleProgress, signal: controller.signal })
            : await hashText(input.value, algorithm, { signal: controller.signal, onProgress: handleProgress });
        if (jobId === jobRef.current) {
          setResult(nextResult);
          setSource(input);
          setFileName(input.kind === "file" ? input.file.name : "inline");
          const bytes = input.kind === "file" ? input.file.size : new TextEncoder().encode(input.value).byteLength;
          setLastDurationMs(Math.round(performance.now() - startedAt));
          setLastInputBytes(bytes);
          succeeded = true;
          onStatus?.("digest ready", "accent");
        }
      } catch (error) {
        if ((error as Error).name === "AbortError") return;
        console.error(error);
        if (jobId === jobRef.current) {
          setProgress(0);
          setComparison("idle");
          setFileComparison("idle");
        }
        const message = error instanceof Error ? error.message : "hash failed";
        onStatus?.(message, "danger");
      } finally {
        if (jobId === jobRef.current && succeeded) {
          setProgress(100);
        }
        if (jobId === jobRef.current) {
          setIsHashing(false);
        }
      }
    },
    [algorithm, handleProgress, onStatus],
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
      setTextValue(value);
    },
    [MAX_TEXT_CHARS, report],
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

  const runBatchHash = useCallback(async () => {
    const lines = batchInput
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
      .slice(0, 120);
    if (lines.length === 0) {
      report("add lines for batch hashing", "danger");
      return;
    }
    setIsBatching(true);
    try {
      const rows: Array<{ line: string; hex: string; base64: string; index: number }> = [];
      for (let i = 0; i < lines.length; i += 1) {
        const digest = await hashText(lines[i], batchAlgorithm);
        rows.push({ line: lines[i], hex: digest.hex, base64: digest.base64, index: i + 1 });
      }
      setBatchRows(rows);
      report(`batch hashed ${rows.length} lines`, "accent");
    } catch (error) {
      console.error(error);
      report("batch hash failed", "danger");
    } finally {
      setIsBatching(false);
    }
  }, [batchAlgorithm, batchInput, report]);

  const exportDigestManifest = useCallback(() => {
    if (!result) {
      report("no digest to export", "danger");
      return;
    }
    const payload = {
      schemaVersion: 1,
      kind: "nullid-hash-manifest",
      createdAt: new Date().toISOString(),
      algorithm,
      source: source?.kind ?? "none",
      sourceName: source?.kind === "file" ? source.file.name : "inline",
      sourceBytes: source?.kind === "file" ? source.file.size : source?.kind === "text" ? new TextEncoder().encode(source.value).byteLength : 0,
      digest: result,
      verifyValue: verifyValue.trim() || null,
      comparison,
      fileComparison,
      fileCompareName,
      durationMs: lastDurationMs,
    };
    const blob = new Blob([`${JSON.stringify(payload, null, 2)}\n`], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `nullid-hash-manifest-${Date.now()}.json`;
    link.click();
    URL.revokeObjectURL(url);
    report("hash manifest exported", "accent");
  }, [algorithm, comparison, fileCompareName, fileComparison, lastDurationMs, report, result, source, verifyValue]);

  const exportBatchManifest = useCallback(() => {
    if (batchRows.length === 0) {
      report("no batch rows", "danger");
      return;
    }
    const payload = {
      schemaVersion: 1,
      kind: "nullid-hash-batch",
      createdAt: new Date().toISOString(),
      algorithm: batchAlgorithm,
      rows: batchRows.map((row) => ({ index: row.index, line: row.line, hex: row.hex, base64: row.base64 })),
    };
    const blob = new Blob([`${JSON.stringify(payload, null, 2)}\n`], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `nullid-hash-batch-${Date.now()}.json`;
    link.click();
    URL.revokeObjectURL(url);
    report("batch manifest exported", "accent");
  }, [batchAlgorithm, batchRows, report]);

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

  const compare = useCallback((value?: string) => {
    const currentResult = resultRef.current;
    const currentVerify = value ?? debouncedVerifyRef.current;
    const expected = expectedHashLengths[algorithmRef.current];
    const status = onStatusRef.current;
    if (!currentResult) {
      setComparison("invalid");
      status?.("digest missing", "danger");
      return;
    }
    const normalized = normalizeHashInput(currentVerify);
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
    },
    [],
  );

  useEffect(() => {
    if (lastAlgorithmRef.current === algorithm) return;
    lastAlgorithmRef.current = algorithm;
    if (source?.kind === "file") void computeHash(source);
  }, [algorithm, computeHash, source]);

  useEffect(() => {
    if (source?.kind === "file") return;
    if (isComposing) return;
    if (!textValue) {
      setResult(null);
      setSource(null);
      setFileName("none");
      setProgress(0);
      setIsHashing(false);
      return;
    }
    if (textDebounceRef.current) window.clearTimeout(textDebounceRef.current);
    const token = (textTokenRef.current += 1);
    textDebounceRef.current = window.setTimeout(() => {
      void (async () => {
        try {
          await computeHash({ kind: "text", value: textValue });
        } catch (error) {
          console.error(error);
        } finally {
          if (textTokenRef.current === token) {
            textDebounceRef.current = null;
          }
        }
      })();
    }, TEXT_DEBOUNCE_MS);
  }, [TEXT_DEBOUNCE_MS, computeHash, isComposing, source, textValue]);

  useEffect(() => {
    algorithmRef.current = algorithm;
  }, [algorithm]);

  useEffect(() => {
    resultRef.current = result;
  }, [result]);

  useEffect(() => {
    if (verifyDebounceRef.current) window.clearTimeout(verifyDebounceRef.current);
    const token = (verifyTokenRef.current += 1);
    verifyDebounceRef.current = window.setTimeout(() => {
      if (verifyTokenRef.current === token) {
        setDebouncedVerifyValue(verifyValue);
        verifyDebounceRef.current = null;
      }
    }, 300);
  }, [verifyValue]);

  useEffect(() => {
    debouncedVerifyRef.current = debouncedVerifyValue;
    if (!debouncedVerifyValue) {
      setComparison("idle");
      return;
    }
    compare();
  }, [compare, debouncedVerifyValue]);

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
  const throughput = useMemo(() => {
    if (!lastDurationMs || !lastInputBytes || lastDurationMs <= 0) return null;
    const kibPerSec = (lastInputBytes / 1024) / (lastDurationMs / 1000);
    return `${kibPerSec.toFixed(1)} KiB/s`;
  }, [lastDurationMs, lastInputBytes]);

  return (
    <div className="workspace-scroll">
      <div className="guide-link">
        <button type="button" className="guide-link-button" onClick={() => onOpenGuide?.("hash")}>
          {t("guide.link")}
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
            {isHashing && <div className="microcopy">Hashing...</div>}
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
            <button className="button" type="button" onClick={exportDigestManifest} disabled={!result}>
              export manifest
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
                  compare(verifyValue);
                }
              }}
            />
            <button className="button" type="button" onClick={() => compare(verifyValue)} disabled={!verifyValue}>
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
                  const compareDigest = await hashFile(file, algorithm, { onProgress: handleProgress });
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
            <span>Perf</span>
            <span className="tag">{lastDurationMs ? `${lastDurationMs}ms` : "pending"}</span>
            <span className="microcopy">
              {throughput ? `${throughput} · ${Math.ceil((lastInputBytes ?? 0) / 1024)} KiB` : "hash telemetry after first run"}
            </span>
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
      <div className="panel" aria-label="Batch hash lab">
        <div className="panel-heading">
          <span>Batch Hash Lab</span>
          <span className="panel-subtext">line-by-line integrity</span>
        </div>
        <div className="controls-row">
          <select
            className="select"
            value={batchAlgorithm}
            onChange={(event) => setBatchAlgorithm(event.target.value as HashAlgorithm)}
            aria-label="Batch hash algorithm"
          >
            <option value="SHA-256">SHA-256</option>
            <option value="SHA-512">SHA-512</option>
            <option value="SHA-1">SHA-1 (legacy/insecure)</option>
          </select>
          <button className="button" type="button" onClick={() => void runBatchHash()} disabled={isBatching}>
            {isBatching ? "hashing..." : "hash lines"}
          </button>
          <button className="button" type="button" onClick={exportBatchManifest} disabled={batchRows.length === 0}>
            export batch
          </button>
        </div>
        <textarea
          className="textarea"
          value={batchInput}
          onChange={(event) => setBatchInput(event.target.value)}
          placeholder="Paste one value per line (up to 120 lines)"
          aria-label="Batch hash input"
        />
        <table className="table">
          <thead>
            <tr>
              <th>#</th>
              <th>input</th>
              <th>digest (hex)</th>
            </tr>
          </thead>
          <tbody>
            {batchRows.length === 0 ? (
              <tr>
                <td colSpan={3} className="muted">run batch hashing to populate</td>
              </tr>
            ) : (
              batchRows.slice(0, 10).map((row) => (
                <tr key={`${row.index}-${row.hex}`}>
                  <td>{row.index}</td>
                  <td className="microcopy">{row.line}</td>
                  <td className="microcopy">{row.hex}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
