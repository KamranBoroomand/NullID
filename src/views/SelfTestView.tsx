import { useEffect, useRef, useState } from "react";
import "./styles.css";
import { decryptBlob, decryptText, encryptBytes, encryptText } from "../utils/cryptoEnvelope";
import { hashText } from "../utils/hash";
import { getVaultBackend, getVaultBackendInfo, putValue, getValue, clearStore } from "../utils/storage";
import { probeCanvasEncodeSupport } from "../utils/imageFormats";
import { useToast } from "../components/ToastHost";
import type { ModuleKey } from "../components/ModuleList";
import { usePersistentState } from "../hooks/usePersistentState";
import { useI18n } from "../i18n";

interface SelfTestViewProps {
  onOpenGuide?: (key?: ModuleKey) => void;
}

type Result = "idle" | "running" | "pass" | "fail";
type ExtendedResult = Result | "warn";

type CheckDefinition = {
  key: string;
  title: string;
  hint: string;
};

const checks: CheckDefinition[] = [
  {
    key: "encrypt",
    title: "Encrypt -> Decrypt (text)",
    hint: "WebCrypto may be unavailable. Use a modern browser with secure context (HTTPS/localhost).",
  },
  {
    key: "file",
    title: "Encrypt -> Decrypt (file)",
    hint: "File APIs can be blocked by hardened browser modes. Retry with local file access enabled.",
  },
  {
    key: "storage",
    title: "Storage backend health",
    hint: "IndexedDB failures often come from private mode/quota restrictions. Disable strict privacy mode or free storage.",
  },
  {
    key: "hash",
    title: "Hash responsiveness",
    hint: "Close heavy tabs/background apps if hashing is slow.",
  },
  {
    key: "secure-context",
    title: "Secure context (HTTPS/localhost)",
    hint: "Serve NullID from HTTPS or localhost to unlock secure browser features.",
  },
  {
    key: "webcrypto",
    title: "WebCrypto availability",
    hint: "Update your browser or disable compatibility mode that blocks `crypto.subtle`.",
  },
  {
    key: "indexeddb",
    title: "IndexedDB availability",
    hint: "If IndexedDB is blocked, vault falls back to localStorage with lower reliability.",
  },
  {
    key: "clipboard",
    title: "Clipboard write support",
    hint: "Allow clipboard permissions in browser site settings for copy workflows.",
  },
  {
    key: "service-worker",
    title: "Service worker support",
    hint: "PWA install/offline features require service workers; use a browser that supports them.",
  },
  {
    key: "image-codecs",
    title: "Image codec support (PNG/JPEG/WebP/AVIF)",
    hint: "Limited codec support reduces metadata cleaning export options.",
  },
];

const checkKeys = checks.map((item) => item.key);
const initialResults = Object.fromEntries(checkKeys.map((key) => [key, "idle"])) as Record<string, ExtendedResult>;

export function SelfTestView({ onOpenGuide }: SelfTestViewProps) {
  const { push } = useToast();
  const { t, formatDateTime } = useI18n();
  const [results, setResults] = useState<Record<string, ExtendedResult>>(initialResults);
  const [details, setDetails] = useState<Record<string, string>>({});
  const [message, setMessage] = useState("ready");
  const [autoMonitor, setAutoMonitor] = usePersistentState<boolean>("nullid:selftest:auto-monitor", false);
  const [monitorIntervalSec, setMonitorIntervalSec] = usePersistentState<number>("nullid:selftest:interval", 180);
  const [lastRunAt, setLastRunAt] = useState<string | null>(null);
  const resultsRef = useRef(results);

  useEffect(() => {
    resultsRef.current = results;
  }, [results]);

  const update = (key: string, value: ExtendedResult, detail?: string) => {
    resultsRef.current = { ...resultsRef.current, [key]: value };
    setResults((prev) => ({ ...prev, [key]: value }));
    if (detail) {
      setDetails((prev) => ({ ...prev, [key]: detail }));
    }
  };

  const runEncryptRoundtrip = async () => {
    update("encrypt", "running");
    try {
      const blob = await encryptText("dev-test", "nullid-selftest");
      const plain = await decryptText("dev-test", blob);
      update("encrypt", plain === "nullid-selftest" ? "pass" : "fail", "text envelope round-trip");
    } catch (error) {
      console.error(error);
      update("encrypt", "fail", "text envelope failed");
    }
  };

  const runFileRoundtrip = async () => {
    update("file", "running");
    try {
      const bytes = new TextEncoder().encode("file-selftest");
      const { blob } = await encryptBytes("dev-test", bytes, { mime: "text/plain", name: "self.txt" });
      const { plaintext } = await decryptBlob("dev-test", blob);
      const ok = new TextDecoder().decode(plaintext) === "file-selftest";
      update("file", ok ? "pass" : "fail", ok ? "binary envelope round-trip" : "binary payload mismatch");
    } catch (error) {
      console.error(error);
      update("file", "fail", "binary envelope failed");
    }
  };

  const runStorage = async () => {
    update("storage", "running");
    const backend = await getVaultBackend();
    const sample = { value: "ok", ts: Date.now() };
    try {
      await putValue(backend, "selftest", "probe", sample);
      const read = await getValue<typeof sample>(backend, "selftest", "probe");
      await clearStore(backend, "selftest");
      const info = getVaultBackendInfo();
      const good = read?.value === "ok";
      const storageResult: ExtendedResult = good ? (info.kind === "idb" ? "pass" : "warn") : "fail";
      update(
        "storage",
        storageResult,
        `backend=${info.kind}${info.fallbackReason ? `; reason=${info.fallbackReason}` : ""}`,
      );
      setMessage(`storage ${info.kind}${info.fallbackReason ? ` (${info.fallbackReason})` : ""}`);
    } catch (error) {
      console.error(error);
      update("storage", "fail", "storage probe failed");
      setMessage("storage blocked");
    }
  };

  const runHash = async () => {
    update("hash", "running");
    const value = "typing-simulation";
    const start = performance.now();
    try {
      const digest = await hashText(value, "SHA-256");
      const elapsed = Math.round(performance.now() - start);
      const ok = Boolean(digest.hex);
      const hashResult: ExtendedResult = !ok ? "fail" : elapsed > 700 ? "warn" : "pass";
      update("hash", hashResult, `${elapsed}ms`);
      setMessage(`hash in ${elapsed}ms`);
    } catch (error) {
      console.error(error);
      update("hash", "fail", "hash probe failed");
    }
  };

  const runSecureContextProbe = () => {
    update("secure-context", "running");
    const secure = window.isSecureContext;
    update("secure-context", secure ? "pass" : "fail", secure ? "secure context active" : "insecure origin");
  };

  const runWebCryptoProbe = () => {
    update("webcrypto", "running");
    const hasCrypto = typeof window.crypto !== "undefined";
    const hasSubtle = Boolean(window.crypto?.subtle);
    const result: ExtendedResult = hasCrypto && hasSubtle ? "pass" : "fail";
    update("webcrypto", result, hasCrypto && hasSubtle ? "subtle crypto ready" : "crypto/subtle unavailable");
  };

  const runIndexedDbProbe = async () => {
    update("indexeddb", "running");
    if (typeof indexedDB === "undefined") {
      update("indexeddb", "warn", "IndexedDB unavailable");
      return;
    }
    try {
      const db = await new Promise<IDBDatabase>((resolve, reject) => {
        const request = indexedDB.open("nullid-probe", 1);
        request.onupgradeneeded = () => {
          if (!request.result.objectStoreNames.contains("probe")) request.result.createObjectStore("probe");
        };
        request.onerror = () => reject(request.error ?? new Error("IndexedDB open failed"));
        request.onsuccess = () => resolve(request.result);
      });
      db.close();
      indexedDB.deleteDatabase("nullid-probe");
      update("indexeddb", "pass", "read/write probe succeeded");
    } catch (error) {
      const detail = error instanceof Error ? error.message : "IndexedDB probe failed";
      update("indexeddb", "warn", detail);
    }
  };

  const runClipboardProbe = async () => {
    update("clipboard", "running");
    if (!navigator.clipboard?.writeText) {
      update("clipboard", "warn", "clipboard API unavailable");
      return;
    }
    try {
      if (navigator.permissions?.query) {
        const status = await navigator.permissions.query({ name: "clipboard-write" as PermissionName });
        if (status.state === "denied") {
          update("clipboard", "warn", "clipboard permission denied");
          return;
        }
      }
      update("clipboard", "pass", "clipboard write API available");
    } catch (error) {
      const detail = error instanceof Error ? error.message : "clipboard permissions probe failed";
      update("clipboard", "warn", detail);
    }
  };

  const runServiceWorkerProbe = () => {
    update("service-worker", "running");
    const supported = "serviceWorker" in navigator;
    update("service-worker", supported ? "pass" : "warn", supported ? "supported" : "unsupported");
  };

  const runCodecProbe = async () => {
    update("image-codecs", "running");
    const support = await probeCanvasEncodeSupport();
    if (!support["image/png"] || !support["image/jpeg"]) {
      update("image-codecs", "fail", "baseline PNG/JPEG encode support missing");
      return;
    }
    const detail = `png=${support["image/png"] ? "yes" : "no"}, jpeg=${support["image/jpeg"] ? "yes" : "no"}, webp=${
      support["image/webp"] ? "yes" : "no"
    }, avif=${support["image/avif"] ? "yes" : "no"}`;
    const result: ExtendedResult = support["image/webp"] ? "pass" : "warn";
    update("image-codecs", result, detail);
  };

  const runCapabilityChecks = async () => {
    runSecureContextProbe();
    runWebCryptoProbe();
    runServiceWorkerProbe();
    await Promise.all([runIndexedDbProbe(), runClipboardProbe(), runCodecProbe()]);
  };

  const runAll = async () => {
    resultsRef.current = initialResults;
    setResults(initialResults);
    setDetails({});
    setMessage("running…");
    await Promise.all([runEncryptRoundtrip(), runFileRoundtrip(), runStorage(), runHash(), runCapabilityChecks()]);
    const allResults = Object.values(resultsRef.current);
    const failed = allResults.filter((value) => value === "fail").length;
    const warnings = allResults.filter((value) => value === "warn").length;
    if (failed > 0) {
      setMessage(`${failed} failed, ${warnings} warning(s)`);
      push(`self-test complete: ${failed} failed`, "danger");
      return;
    }
    if (warnings > 0) {
      setMessage(`${warnings} warning(s)`);
      push(`self-test complete: ${warnings} warning(s)`, "neutral");
      return;
    }
    setMessage("all checks passed");
    push("self-test complete", "accent");
    setLastRunAt(new Date().toISOString());
  };

  const runSingle = async (key: string) => {
    if (key === "encrypt") await runEncryptRoundtrip();
    else if (key === "file") await runFileRoundtrip();
    else if (key === "storage") await runStorage();
    else if (key === "hash") await runHash();
    else if (key === "secure-context") runSecureContextProbe();
    else if (key === "webcrypto") runWebCryptoProbe();
    else if (key === "indexeddb") await runIndexedDbProbe();
    else if (key === "clipboard") await runClipboardProbe();
    else if (key === "service-worker") runServiceWorkerProbe();
    else if (key === "image-codecs") await runCodecProbe();
    setLastRunAt(new Date().toISOString());
  };

  const exportReport = () => {
    const summary = summarizeResults(resultsRef.current);
    const payload = {
      schemaVersion: 1,
      kind: "nullid-selftest-report",
      generatedAt: new Date().toISOString(),
      autoMonitor,
      monitorIntervalSec,
      summary,
      results: checks.map((item) => ({
        key: item.key,
        title: item.title,
        status: resultsRef.current[item.key] ?? "idle",
        detail: details[item.key] ?? null,
      })),
    };
    const blob = new Blob([`${JSON.stringify(payload, null, 2)}\n`], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `nullid-selftest-${Date.now()}.json`;
    link.click();
    URL.revokeObjectURL(url);
    push("self-test report exported", "accent");
  };

  useEffect(() => {
    if (!autoMonitor) return;
    void runAll();
    const intervalMs = Math.max(30, monitorIntervalSec) * 1000;
    const timer = window.setInterval(() => {
      void runAll();
    }, intervalMs);
    return () => window.clearInterval(timer);
  }, [autoMonitor, monitorIntervalSec]);

  const summary = summarizeResults(results);

  const badge = (result: ExtendedResult) => {
    if (result === "running") return <span className="tag">running</span>;
    if (result === "pass") return <span className="tag tag-accent">pass</span>;
    if (result === "warn") return <span className="tag">warn</span>;
    if (result === "fail") return <span className="tag tag-danger">fail</span>;
    return <span className="tag">idle</span>;
  };

  return (
    <div className="workspace-scroll">
      <div className="guide-link">
        <button type="button" className="guide-link-button" onClick={() => onOpenGuide?.("guide")}>
          {t("guide.link")}
        </button>
      </div>
      <div className="panel">
        <div className="panel-heading">
          <span>Self-test</span>
          <span className="panel-subtext">dev diagnostics</span>
        </div>
        <p className="microcopy">
          Runs runtime checks for crypto, storage, browser capability support, and responsiveness. Failed or warning checks include remediation hints.
        </p>
        <div className="controls-row">
          <button className="button" type="button" onClick={runAll}>
            run all
          </button>
          <label className="microcopy" style={{ display: "flex", alignItems: "center", gap: "0.35rem" }}>
            <input
              type="checkbox"
              checked={autoMonitor}
              onChange={(event) => setAutoMonitor(event.target.checked)}
              aria-label="Enable auto monitor"
            />
            auto monitor
          </label>
          <input
            className="input"
            type="number"
            min={30}
            max={3600}
            value={monitorIntervalSec}
            onChange={(event) => setMonitorIntervalSec(Math.min(3600, Math.max(30, Number(event.target.value))))}
            aria-label="Auto monitor interval in seconds"
          />
          <button className="button" type="button" onClick={exportReport}>
            export report
          </button>
          <span className="microcopy">status: {message}</span>
        </div>
        <div className="status-line">
          <span>summary</span>
          <span className="tag tag-danger">fail {summary.fail}</span>
          <span className="tag">warn {summary.warn}</span>
          <span className="tag tag-accent">pass {summary.pass}</span>
          <span className="microcopy">health score {summary.healthScore}/100</span>
        </div>
        <div className="microcopy">last run: {lastRunAt ? formatDateTime(lastRunAt) : "never"}</div>
        <ul className="note-list">
          {checks.map((item) => {
            const result = results[item.key] ?? "idle";
            const detail = details[item.key];
            return (
              <li key={item.key}>
                <div>
                  <div className="note-title">{item.title}</div>
                  {detail ? <div className="microcopy">{detail}</div> : null}
                  {(result === "fail" || result === "warn") && <div className="microcopy">{item.hint}</div>}
                </div>
                <div className="controls-row">
                  {badge(result)}
                  <button className="button" type="button" onClick={() => void runSingle(item.key)}>
                    run
                  </button>
                </div>
              </li>
            );
          })}
        </ul>
      </div>
    </div>
  );
}

function summarizeResults(map: Record<string, ExtendedResult>) {
  const all = Object.values(map);
  const fail = all.filter((value) => value === "fail").length;
  const warn = all.filter((value) => value === "warn").length;
  const pass = all.filter((value) => value === "pass").length;
  const total = all.length || 1;
  const healthScore = Math.max(0, Math.round(((pass + warn * 0.5) / total) * 100 - fail * 6));
  return { fail, warn, pass, total, healthScore };
}
