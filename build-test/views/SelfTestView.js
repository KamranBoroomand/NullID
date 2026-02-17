import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useEffect, useRef, useState } from "react";
import "./styles.css";
import { decryptBlob, decryptText, encryptBytes, encryptText } from "../utils/cryptoEnvelope";
import { hashText } from "../utils/hash";
import { getVaultBackend, getVaultBackendInfo, putValue, getValue, clearStore } from "../utils/storage";
import { probeCanvasEncodeSupport } from "../utils/imageFormats";
import { useToast } from "../components/ToastHost";
import { usePersistentState } from "../hooks/usePersistentState";
import { useI18n } from "../i18n";
const checks = [
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
        key: "security-headers",
        title: "CSP/referrer baseline",
        hint: "Set CSP + response security headers at host/edge (`public/_headers` or `vercel.json`) and keep HTTPS enabled.",
    },
    {
        key: "image-codecs",
        title: "Image codec support (PNG/JPEG/WebP/AVIF)",
        hint: "Limited codec support reduces metadata cleaning export options.",
    },
];
const checkKeys = checks.map((item) => item.key);
const initialResults = Object.fromEntries(checkKeys.map((key) => [key, "idle"]));
export function SelfTestView({ onOpenGuide }) {
    const { push } = useToast();
    const { t, tr, formatDateTime } = useI18n();
    const [results, setResults] = useState(initialResults);
    const [details, setDetails] = useState({});
    const [message, setMessage] = useState("ready");
    const [autoMonitor, setAutoMonitor] = usePersistentState("nullid:selftest:auto-monitor", false);
    const [monitorIntervalSec, setMonitorIntervalSec] = usePersistentState("nullid:selftest:interval", 180);
    const [lastRunAt, setLastRunAt] = useState(null);
    const resultsRef = useRef(results);
    useEffect(() => {
        resultsRef.current = results;
    }, [results]);
    const update = (key, value, detail) => {
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
        }
        catch (error) {
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
        }
        catch (error) {
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
            const read = await getValue(backend, "selftest", "probe");
            await clearStore(backend, "selftest");
            const info = getVaultBackendInfo();
            const good = read?.value === "ok";
            const storageResult = good ? (info.kind === "idb" ? "pass" : "warn") : "fail";
            update("storage", storageResult, `backend=${info.kind}${info.fallbackReason ? `; reason=${info.fallbackReason}` : ""}`);
            setMessage(`storage ${info.kind}${info.fallbackReason ? ` (${info.fallbackReason})` : ""}`);
        }
        catch (error) {
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
            const hashResult = !ok ? "fail" : elapsed > 700 ? "warn" : "pass";
            update("hash", hashResult, `${elapsed}ms`);
            setMessage(`hash in ${elapsed}ms`);
        }
        catch (error) {
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
        const result = hasCrypto && hasSubtle ? "pass" : "fail";
        update("webcrypto", result, hasCrypto && hasSubtle ? "subtle crypto ready" : "crypto/subtle unavailable");
    };
    const runIndexedDbProbe = async () => {
        update("indexeddb", "running");
        if (typeof indexedDB === "undefined") {
            update("indexeddb", "warn", "IndexedDB unavailable");
            return;
        }
        try {
            const db = await new Promise((resolve, reject) => {
                const request = indexedDB.open("nullid-probe", 1);
                request.onupgradeneeded = () => {
                    if (!request.result.objectStoreNames.contains("probe"))
                        request.result.createObjectStore("probe");
                };
                request.onerror = () => reject(request.error ?? new Error("IndexedDB open failed"));
                request.onsuccess = () => resolve(request.result);
            });
            db.close();
            indexedDB.deleteDatabase("nullid-probe");
            update("indexeddb", "pass", "read/write probe succeeded");
        }
        catch (error) {
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
                const status = await navigator.permissions.query({ name: "clipboard-write" });
                if (status.state === "denied") {
                    update("clipboard", "warn", "clipboard permission denied");
                    return;
                }
            }
            update("clipboard", "pass", "clipboard write API available");
        }
        catch (error) {
            const detail = error instanceof Error ? error.message : "clipboard permissions probe failed";
            update("clipboard", "warn", detail);
        }
    };
    const runServiceWorkerProbe = () => {
        update("service-worker", "running");
        const supported = "serviceWorker" in navigator;
        update("service-worker", supported ? "pass" : "warn", supported ? "supported" : "unsupported");
    };
    const runSecurityHeadersProbe = () => {
        update("security-headers", "running");
        const csp = document.querySelector('meta[http-equiv="Content-Security-Policy"]')?.getAttribute("content") ?? "";
        const referrer = document.querySelector('meta[name="referrer"]')?.getAttribute("content") ?? "";
        const hasCsp = csp.includes("default-src");
        const hasObjectSrc = csp.includes("object-src");
        const hasReferrer = referrer === "no-referrer";
        if (!hasCsp) {
            update("security-headers", "fail", "CSP meta policy missing");
            return;
        }
        if (!hasObjectSrc || !hasReferrer) {
            update("security-headers", "warn", `csp=${hasCsp ? "yes" : "no"}, object-src=${hasObjectSrc ? "yes" : "no"}, referrer=${hasReferrer ? "yes" : "no"}`);
            return;
        }
        update("security-headers", "pass", "CSP/referrer baseline detected");
    };
    const runCodecProbe = async () => {
        update("image-codecs", "running");
        const support = await probeCanvasEncodeSupport();
        if (!support["image/png"] || !support["image/jpeg"]) {
            update("image-codecs", "fail", "baseline PNG/JPEG encode support missing");
            return;
        }
        const detail = `png=${support["image/png"] ? "yes" : "no"}, jpeg=${support["image/jpeg"] ? "yes" : "no"}, webp=${support["image/webp"] ? "yes" : "no"}, avif=${support["image/avif"] ? "yes" : "no"}`;
        const result = support["image/webp"] ? "pass" : "warn";
        update("image-codecs", result, detail);
    };
    const runCapabilityChecks = async () => {
        runSecureContextProbe();
        runWebCryptoProbe();
        runServiceWorkerProbe();
        runSecurityHeadersProbe();
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
    const runSingle = async (key) => {
        if (key === "encrypt")
            await runEncryptRoundtrip();
        else if (key === "file")
            await runFileRoundtrip();
        else if (key === "storage")
            await runStorage();
        else if (key === "hash")
            await runHash();
        else if (key === "secure-context")
            runSecureContextProbe();
        else if (key === "webcrypto")
            runWebCryptoProbe();
        else if (key === "indexeddb")
            await runIndexedDbProbe();
        else if (key === "clipboard")
            await runClipboardProbe();
        else if (key === "service-worker")
            runServiceWorkerProbe();
        else if (key === "security-headers")
            runSecurityHeadersProbe();
        else if (key === "image-codecs")
            await runCodecProbe();
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
        if (!autoMonitor)
            return;
        void runAll();
        const intervalMs = Math.max(30, monitorIntervalSec) * 1000;
        const timer = window.setInterval(() => {
            void runAll();
        }, intervalMs);
        return () => window.clearInterval(timer);
    }, [autoMonitor, monitorIntervalSec]);
    const summary = summarizeResults(results);
    const badge = (result) => {
        if (result === "running")
            return _jsx("span", { className: "tag", children: tr("running") });
        if (result === "pass")
            return _jsx("span", { className: "tag tag-accent", children: tr("pass") });
        if (result === "warn")
            return _jsx("span", { className: "tag", children: tr("warn") });
        if (result === "fail")
            return _jsx("span", { className: "tag tag-danger", children: tr("fail") });
        return _jsx("span", { className: "tag", children: tr("idle") });
    };
    return (_jsxs("div", { className: "workspace-scroll", children: [_jsx("div", { className: "guide-link", children: _jsx("button", { type: "button", className: "guide-link-button", onClick: () => onOpenGuide?.("guide"), children: t("guide.link") }) }), _jsxs("div", { className: "panel", children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("Self-test") }), _jsx("span", { className: "panel-subtext", children: tr("dev diagnostics") })] }), _jsx("p", { className: "microcopy", children: "Runs runtime checks for crypto, storage, browser capability support, and responsiveness. Failed or warning checks include remediation hints." }), _jsxs("div", { className: "controls-row", children: [_jsx("button", { className: "button", type: "button", onClick: runAll, children: tr("run all") }), _jsxs("label", { className: "microcopy", style: { display: "flex", alignItems: "center", gap: "0.35rem" }, children: [_jsx("input", { type: "checkbox", checked: autoMonitor, onChange: (event) => setAutoMonitor(event.target.checked), "aria-label": tr("Enable auto monitor") }), tr("auto monitor")] }), _jsx("input", { className: "input", type: "number", min: 30, max: 3600, value: monitorIntervalSec, onChange: (event) => setMonitorIntervalSec(Math.min(3600, Math.max(30, Number(event.target.value)))), "aria-label": tr("Auto monitor interval in seconds") }), _jsx("button", { className: "button", type: "button", onClick: exportReport, children: tr("export report") }), _jsxs("span", { className: "microcopy", children: [tr("status"), ": ", tr(message)] })] }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: tr("summary") }), _jsxs("span", { className: "tag tag-danger", children: [tr("fail"), " ", summary.fail] }), _jsxs("span", { className: "tag", children: [tr("warn"), " ", summary.warn] }), _jsxs("span", { className: "tag tag-accent", children: [tr("pass"), " ", summary.pass] }), _jsxs("span", { className: "microcopy", children: [tr("health score"), " ", summary.healthScore, "/100"] })] }), _jsxs("div", { className: "microcopy", children: [tr("last run:"), " ", lastRunAt ? formatDateTime(lastRunAt) : tr("never")] }), _jsx("ul", { className: "note-list", children: checks.map((item) => {
                            const result = results[item.key] ?? "idle";
                            const detail = details[item.key];
                            return (_jsxs("li", { children: [_jsxs("div", { children: [_jsx("div", { className: "note-title", children: item.title }), detail ? _jsx("div", { className: "microcopy", children: detail }) : null, (result === "fail" || result === "warn") && _jsx("div", { className: "microcopy", children: item.hint })] }), _jsxs("div", { className: "controls-row", children: [badge(result), _jsx("button", { className: "button", type: "button", onClick: () => void runSingle(item.key), children: tr("run") })] })] }, item.key));
                        }) })] })] }));
}
function summarizeResults(map) {
    const all = Object.values(map);
    const fail = all.filter((value) => value === "fail").length;
    const warn = all.filter((value) => value === "warn").length;
    const pass = all.filter((value) => value === "pass").length;
    const total = all.length || 1;
    const healthScore = Math.max(0, Math.round(((pass + warn * 0.5) / total) * 100 - fail * 6));
    return { fail, warn, pass, total, healthScore };
}
