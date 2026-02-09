import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useState } from "react";
import "./styles.css";
import { decryptBlob, decryptText, encryptBytes, encryptText } from "../utils/cryptoEnvelope";
import { hashText } from "../utils/hash";
import { getVaultBackend, getVaultBackendInfo, putValue, getValue, clearStore } from "../utils/storage";
import { useToast } from "../components/ToastHost";
export function SelfTestView({ onOpenGuide }) {
    const { push } = useToast();
    const [results, setResults] = useState({
        encrypt: "idle",
        file: "idle",
        storage: "idle",
        hash: "idle",
    });
    const [message, setMessage] = useState("ready");
    const update = (key, value) => setResults((prev) => ({ ...prev, [key]: value }));
    const runEncryptRoundtrip = async () => {
        update("encrypt", "running");
        try {
            const blob = await encryptText("dev-test", "nullid-selftest");
            const plain = await decryptText("dev-test", blob);
            update("encrypt", plain === "nullid-selftest" ? "pass" : "fail");
        }
        catch (error) {
            console.error(error);
            update("encrypt", "fail");
        }
    };
    const runFileRoundtrip = async () => {
        update("file", "running");
        try {
            const bytes = new TextEncoder().encode("file-selftest");
            const { blob } = await encryptBytes("dev-test", bytes, { mime: "text/plain", name: "self.txt" });
            const { plaintext } = await decryptBlob("dev-test", blob);
            update("file", new TextDecoder().decode(plaintext) === "file-selftest" ? "pass" : "fail");
        }
        catch (error) {
            console.error(error);
            update("file", "fail");
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
            update("storage", good ? "pass" : "fail");
            setMessage(`storage ${info.kind}${info.fallbackReason ? ` (${info.fallbackReason})` : ""}`);
        }
        catch (error) {
            console.error(error);
            update("storage", "fail");
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
            update("hash", ok ? "pass" : "fail");
            setMessage(`hash in ${elapsed}ms`);
        }
        catch (error) {
            console.error(error);
            update("hash", "fail");
        }
    };
    const runAll = async () => {
        setMessage("running…");
        await Promise.all([runEncryptRoundtrip(), runFileRoundtrip(), runStorage(), runHash()]);
        push("self-test complete", "accent");
    };
    const badge = (result) => {
        if (result === "running")
            return _jsx("span", { className: "tag", children: "running" });
        if (result === "pass")
            return _jsx("span", { className: "tag tag-accent", children: "pass" });
        if (result === "fail")
            return _jsx("span", { className: "tag tag-danger", children: "fail" });
        return _jsx("span", { className: "tag", children: "idle" });
    };
    return (_jsxs("div", { className: "workspace-scroll", children: [_jsx("div", { className: "guide-link", children: _jsx("button", { type: "button", className: "guide-link-button", onClick: () => onOpenGuide?.("guide"), children: "? guide" }) }), _jsxs("div", { className: "panel", children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: "Self-test" }), _jsx("span", { className: "panel-subtext", children: "dev diagnostics" })] }), _jsx("p", { className: "microcopy", children: "Run a quick round-trip of crypto, storage, and hash routines to confirm the UI is responsive and persistence is available." }), _jsxs("div", { className: "controls-row", children: [_jsx("button", { className: "button", type: "button", onClick: runAll, children: "run all" }), _jsxs("span", { className: "microcopy", children: ["status: ", message] })] }), _jsxs("ul", { className: "note-list", children: [_jsxs("li", { children: [_jsx("div", { className: "note-title", children: "Encrypt \u2192 Decrypt (text)" }), badge(results.encrypt)] }), _jsxs("li", { children: [_jsx("div", { className: "note-title", children: "Encrypt \u2192 Decrypt (file)" }), badge(results.file)] }), _jsxs("li", { children: [_jsx("div", { className: "note-title", children: "Storage (IndexedDB or fallback)" }), badge(results.storage)] }), _jsxs("li", { children: [_jsx("div", { className: "note-title", children: "Hash responsiveness" }), badge(results.hash)] })] })] })] }));
}
