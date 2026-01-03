import { useState } from "react";
import "./styles.css";
import { decryptBlob, decryptText, encryptBytes, encryptText } from "../utils/cryptoEnvelope";
import { hashText } from "../utils/hash";
import { getVaultBackend, getVaultBackendInfo, putValue, getValue, clearStore } from "../utils/storage";
import { useToast } from "../components/ToastHost";
import type { ModuleKey } from "../components/ModuleList";

interface SelfTestViewProps {
  onOpenGuide?: (key?: ModuleKey) => void;
}

type Result = "idle" | "running" | "pass" | "fail";

export function SelfTestView({ onOpenGuide }: SelfTestViewProps) {
  const { push } = useToast();
  const [results, setResults] = useState<Record<string, Result>>({
    encrypt: "idle",
    file: "idle",
    storage: "idle",
    hash: "idle",
  });
  const [message, setMessage] = useState("ready");

  const update = (key: string, value: Result) => setResults((prev) => ({ ...prev, [key]: value }));

  const runEncryptRoundtrip = async () => {
    update("encrypt", "running");
    try {
      const blob = await encryptText("dev-test", "nullid-selftest");
      const plain = await decryptText("dev-test", blob);
      update("encrypt", plain === "nullid-selftest" ? "pass" : "fail");
    } catch (error) {
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
    } catch (error) {
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
      const read = await getValue<typeof sample>(backend, "selftest", "probe");
      await clearStore(backend, "selftest");
      const info = getVaultBackendInfo();
      const good = read?.value === "ok";
      update("storage", good ? "pass" : "fail");
      setMessage(`storage ${info.kind}${info.fallbackReason ? ` (${info.fallbackReason})` : ""}`);
    } catch (error) {
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
    } catch (error) {
      console.error(error);
      update("hash", "fail");
    }
  };

  const runAll = async () => {
    setMessage("running…");
    await Promise.all([runEncryptRoundtrip(), runFileRoundtrip(), runStorage(), runHash()]);
    push("self-test complete", "accent");
  };

  const badge = (result: Result) => {
    if (result === "running") return <span className="tag">running</span>;
    if (result === "pass") return <span className="tag tag-accent">pass</span>;
    if (result === "fail") return <span className="tag tag-danger">fail</span>;
    return <span className="tag">idle</span>;
  };

  return (
    <div className="workspace-scroll">
      <div className="guide-link">
        <button type="button" className="guide-link-button" onClick={() => onOpenGuide?.("guide")}>
          ? guide
        </button>
      </div>
      <div className="panel">
        <div className="panel-heading">
          <span>Self-test</span>
          <span className="panel-subtext">dev diagnostics</span>
        </div>
        <p className="microcopy">
          Run a quick round-trip of crypto, storage, and hash routines to confirm the UI is responsive and persistence is available.
        </p>
        <div className="controls-row">
          <button className="button" type="button" onClick={runAll}>
            run all
          </button>
          <span className="microcopy">status: {message}</span>
        </div>
        <ul className="note-list">
          <li>
            <div className="note-title">Encrypt → Decrypt (text)</div>
            {badge(results.encrypt)}
          </li>
          <li>
            <div className="note-title">Encrypt → Decrypt (file)</div>
            {badge(results.file)}
          </li>
          <li>
            <div className="note-title">Storage (IndexedDB or fallback)</div>
            {badge(results.storage)}
          </li>
          <li>
            <div className="note-title">Hash responsiveness</div>
            {badge(results.hash)}
          </li>
        </ul>
      </div>
    </div>
  );
}
