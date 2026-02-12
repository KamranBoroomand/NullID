import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import "./styles.css";
import { bytesToUtf8 } from "../utils/encoding";
import { KDF_PROFILES, KdfHash, KdfProfile, decryptBlob, decryptText, encryptBytes, encryptText, inspectEnvelope } from "../utils/cryptoEnvelope";
import { Chip } from "../components/Chip";
import { useToast } from "../components/ToastHost";
import type { ModuleKey } from "../components/ModuleList";
import { analyzeSecret, gradeLabel, type SecretGrade } from "../utils/passwordToolkit";

interface EncViewProps {
  onOpenGuide?: (key?: ModuleKey) => void;
}

export function EncView({ onOpenGuide }: EncViewProps) {
  const { push } = useToast();
  const [plain, setPlain] = useState("");
  const [encPass, setEncPass] = useState("");
  const [cipherText, setCipherText] = useState("");
  const [decPass, setDecPass] = useState("");
  const [decrypted, setDecrypted] = useState("");
  const [kdfProfile, setKdfProfile] = useState<KdfProfile>("compat");
  const [kdfMode, setKdfMode] = useState<"profile" | "custom">("profile");
  const [customIterations, setCustomIterations] = useState(600_000);
  const [customHash, setCustomHash] = useState<KdfHash>("SHA-512");
  const [encFile, setEncFile] = useState<File | null>(null);
  const [encFileBlob, setEncFileBlob] = useState<string | null>(null);
  const [decFileBlob, setDecFileBlob] = useState<Uint8Array | null>(null);
  const [decFileName, setDecFileName] = useState<string | null>(null);
  const [decMime, setDecMime] = useState<string>("application/octet-stream");
  const [autoClear, setAutoClear] = useState(true);
  const [clearAfter, setClearAfter] = useState(30);
  const [error, setError] = useState<string | null>(null);
  const [isEncrypting, setIsEncrypting] = useState(false);
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [payloadMeta, setPayloadMeta] = useState<{ name?: string; mime?: string; bytes?: number } | null>(null);
  const [envelopeMeta, setEnvelopeMeta] = useState<{
    iterations: number;
    hash: KdfHash;
    cipherBytes: number;
    mime?: string;
    name?: string;
  } | null>(null);
  const [envelopeMetaError, setEnvelopeMetaError] = useState<string | null>(null);
  const encryptFileInput = useRef<HTMLInputElement>(null);
  const decryptFileInput = useRef<HTMLInputElement>(null);
  const clearTimerRef = useRef<number | null>(null);

  const MAX_FILE_BYTES = 25 * 1024 * 1024; // 25MB (envelope expands ~33%)
  const kdfConfig = useMemo(
    () =>
      kdfMode === "custom"
        ? {
            iterations: clamp(customIterations, 100_000, 2_000_000),
            hash: customHash,
          }
        : KDF_PROFILES[kdfProfile],
    [customHash, customIterations, kdfMode, kdfProfile],
  );
  const encPassAssessment = useMemo(() => analyzeSecret(encPass), [encPass]);
  const decPassAssessment = useMemo(() => analyzeSecret(decPass), [decPass]);

  const scheduleClear = useCallback(() => {
    if (!autoClear) return;
    if (clearTimerRef.current) window.clearTimeout(clearTimerRef.current);
    clearTimerRef.current = window.setTimeout(() => {
      setPlain("");
      setDecrypted("");
    }, clearAfter * 1000);
  }, [autoClear, clearAfter]);

  useEffect(() => {
    return () => {
      if (clearTimerRef.current) window.clearTimeout(clearTimerRef.current);
    };
  }, []);

  const handleEncryptText = useCallback(async () => {
    if (!plain || !encPass) return;
    setIsEncrypting(true);
    try {
      const blob = await encryptText(encPass, plain, {
        kdfProfile,
        kdf: kdfMode === "custom" ? kdfConfig : undefined,
      });
      setCipherText(blob.trim());
      setEncFileBlob(blob.trim());
      push("sealed", "accent");
      setError(null);
      setPayloadMeta({ bytes: plain.length, mime: "text/plain" });
      scheduleClear();
    } catch (err) {
      console.error(err);
      setError("encrypt failed");
      push("encrypt failed", "danger");
    } finally {
      setIsEncrypting(false);
    }
  }, [encPass, kdfConfig, kdfMode, kdfProfile, plain, push, scheduleClear]);

  const handleEncryptFile = useCallback(async () => {
    if (!encPass || !encFile) return;
    setIsEncrypting(true);
    if (encFile.size > MAX_FILE_BYTES) {
      setError(`file too large (${Math.ceil(encFile.size / (1024 * 1024))}MB). max 25MB.`);
      push("file too large", "danger");
      setIsEncrypting(false);
      return;
    }
    try {
      const bytes = new Uint8Array(await encFile.arrayBuffer());
      const { blob } = await encryptBytes(encPass, bytes, {
        mime: encFile.type,
        name: encFile.name,
        kdfProfile,
        kdf: kdfMode === "custom" ? kdfConfig : undefined,
      });
      setEncFileBlob(blob);
      setCipherText(blob.trim());
      push("file sealed", "accent");
      setPayloadMeta({ name: encFile.name, mime: encFile.type, bytes: encFile.size });
      scheduleClear();
    } catch (err) {
      console.error(err);
      setError("file encrypt failed");
      push("file encrypt failed", "danger");
    } finally {
      setIsEncrypting(false);
    }
  }, [encFile, encPass, kdfConfig, kdfMode, kdfProfile, push, scheduleClear]);

  const handleDecryptText = useCallback(async () => {
    if (!cipherText || !decPass) return;
    setIsDecrypting(true);
    try {
      const pt = await decryptText(decPass, cipherText);
      setDecrypted(pt);
      setPayloadMeta({ mime: "text/plain", bytes: pt.length });
      push("decrypted", "accent");
      setError(null);
      scheduleClear();
    } catch (err) {
      console.error(err);
      setDecrypted("");
      setDecFileBlob(null);
      setPayloadMeta(null);
      setError("decrypt failed: bad passphrase or envelope");
      push("decrypt failed", "danger");
    } finally {
      setIsDecrypting(false);
    }
  }, [cipherText, decPass, push, scheduleClear]);

  const handleDecryptFile = useCallback(async () => {
    if (!decPass || !cipherText) return;
    setIsDecrypting(true);
    try {
      const { plaintext, header } = await decryptBlob(decPass, cipherText);
      setDecFileBlob(plaintext);
      setDecFileName(header.name ?? "decrypted.bin");
      setDecMime(header.mime ?? "application/octet-stream");
      try {
        setDecrypted(bytesToUtf8(plaintext));
      } catch {
        setDecrypted("[binary payload]");
      }
      setPayloadMeta({ name: header.name, mime: header.mime, bytes: plaintext.byteLength });
      setError(null);
      push("file ready", "accent");
      scheduleClear();
    } catch (err) {
      console.error(err);
      setPayloadMeta(null);
      setError("decrypt failed: bad passphrase or envelope");
      push("decrypt failed", "danger");
    } finally {
      setIsDecrypting(false);
    }
  }, [cipherText, decPass, push, scheduleClear]);

  const safeDownload = (blob: Blob, filename: string) => {
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    link.rel = "noopener";
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(link.href), 1500);
  };

  const downloadEncryptedFile = () => {
    if (!encFileBlob) {
      push("no envelope to download", "danger");
      return;
    }
    safeDownload(new Blob([encFileBlob], { type: "text/plain;charset=utf-8" }), `${encFile?.name ?? "payload"}.nullid`);
  };

  const downloadDecryptedFile = () => {
    if (!decFileBlob) {
      push("nothing to download", "danger");
      return;
    }
    const copy = new Uint8Array(decFileBlob);
    safeDownload(new Blob([copy.buffer], { type: decMime }), decFileName ?? "decrypted.bin");
  };

  useEffect(() => {
    if (!decPass || !cipherText) {
      setDecFileBlob(null);
      setDecFileName(null);
    }
  }, [cipherText, decPass]);

  useEffect(() => {
    const trimmed = cipherText.trim();
    if (!trimmed) {
      setEnvelopeMeta(null);
      setEnvelopeMetaError(null);
      return;
    }
    try {
      const inspected = inspectEnvelope(trimmed);
      setEnvelopeMeta({
        iterations: inspected.header.kdf.iterations,
        hash: inspected.header.kdf.hash,
        cipherBytes: inspected.ciphertextBytes,
        mime: inspected.header.mime,
        name: inspected.header.name,
      });
      setEnvelopeMetaError(null);
    } catch (error) {
      setEnvelopeMeta(null);
      setEnvelopeMetaError(error instanceof Error ? error.message : "invalid envelope");
    }
  }, [cipherText]);

  return (
    <div className="workspace-scroll">
      <div className="guide-link">
        <button type="button" className="guide-link-button" onClick={() => onOpenGuide?.("enc")}>
          ? guide
        </button>
      </div>
      <div className="grid-two">
        <div className="panel" aria-label="Encrypt panel">
          <div className="panel-heading">
            <span>Encrypt</span>
            <span className="panel-subtext">PBKDF2 + AES-GCM</span>
          </div>
          <label className="section-title" htmlFor="encrypt-plain">
            Plaintext
          </label>
          <textarea
            id="encrypt-plain"
            className="textarea"
            placeholder="Enter text to encrypt"
            aria-label="Plaintext"
            value={plain}
            onChange={(event) => setPlain(event.target.value)}
          />
          <label className="section-title" htmlFor="encrypt-pass">
            Passphrase
          </label>
          <input
            id="encrypt-pass"
            className="input"
            type="password"
            placeholder="••••••"
            aria-label="Encrypt passphrase"
            value={encPass}
            onChange={(event) => setEncPass(event.target.value)}
          />
          <div className="status-line">
            <span>passphrase strength</span>
            <span className={gradeTagClass(encPassAssessment.grade)}>{gradeLabel(encPassAssessment.grade)}</span>
            <span className="microcopy">effective ≈ {encPassAssessment.effectiveEntropyBits} bits</span>
          </div>
          <div className="controls-row">
            <span className="section-title">KDF profile</span>
            <div className="pill-buttons" role="group" aria-label="KDF profile">
              {(["compat", "strong", "paranoid"] as KdfProfile[]).map((profile) => (
                <button
                  key={profile}
                  type="button"
                  className={kdfProfile === profile ? "active" : ""}
                  onClick={() => setKdfProfile(profile)}
                >
                  {profile}
                </button>
              ))}
            </div>
          </div>
          <div className="controls-row">
            <span className="section-title">KDF mode</span>
            <div className="pill-buttons" role="group" aria-label="KDF mode">
              <button type="button" className={kdfMode === "profile" ? "active" : ""} onClick={() => setKdfMode("profile")}>
                profile
              </button>
              <button type="button" className={kdfMode === "custom" ? "active" : ""} onClick={() => setKdfMode("custom")}>
                custom
              </button>
            </div>
            {kdfMode === "custom" && (
              <>
                <select
                  className="select"
                  value={customHash}
                  onChange={(event) => setCustomHash(event.target.value as KdfHash)}
                  aria-label="Custom KDF hash"
                >
                  <option value="SHA-256">SHA-256</option>
                  <option value="SHA-512">SHA-512</option>
                </select>
                <input
                  className="input"
                  type="number"
                  min={100000}
                  max={2000000}
                  step={50000}
                  value={customIterations}
                  onChange={(event) => setCustomIterations(clamp(Number(event.target.value) || 0, 100_000, 2_000_000))}
                  aria-label="Custom KDF iterations"
                />
              </>
            )}
          </div>
          <div className="microcopy">PBKDF2 {kdfConfig.hash.toLowerCase()} · {kdfConfig.iterations.toLocaleString()} iterations</div>
          <div className="controls-row">
            <button className="button" type="button" onClick={handleEncryptText} disabled={!plain || !encPass || isEncrypting}>
              seal text
            </button>
            <button className="button" type="button" onClick={() => encryptFileInput.current?.click()} disabled={!encPass || isEncrypting}>
              select file
            </button>
            <input
              ref={encryptFileInput}
              type="file"
              style={{ position: "absolute", opacity: 0, width: 1, height: 1, pointerEvents: "none" }}
              onChange={(event) => setEncFile(event.target.files?.[0] ?? null)}
              aria-label="Pick file to encrypt"
              tabIndex={-1}
            />
            <button className="button" type="button" onClick={handleEncryptFile} disabled={!encPass || !encFile || isEncrypting}>
              seal file
            </button>
          </div>
          <div className="status-line">
            <span>file</span>
            <Chip label={encFile?.name ?? "none"} tone="muted" />
            {isEncrypting && <Chip label="working…" tone="accent" />}
          </div>
        </div>
        <div className="panel" aria-label="Decrypt panel">
          <div className="panel-heading">
            <span>Decrypt</span>
            <span className="panel-subtext">verify envelope</span>
          </div>
          <label className="section-title" htmlFor="decrypt-blob">
            Ciphertext
          </label>
          <textarea
            id="decrypt-blob"
            className="textarea"
            placeholder="Paste envelope"
            aria-label="Ciphertext"
            value={cipherText}
            onChange={(event) => setCipherText(event.target.value)}
          />
          <div className="controls-row">
            <button className="button" type="button" onClick={() => decryptFileInput.current?.click()}>
              load file
            </button>
            <input
              ref={decryptFileInput}
              type="file"
              accept=".nullid,text/plain"
              style={{ position: "absolute", opacity: 0, width: 1, height: 1, pointerEvents: "none" }}
              onChange={async (event) => {
                const file = event.target.files?.[0];
                if (!file) return;
                const text = await file.text();
                setCipherText(text.trim());
              }}
              tabIndex={-1}
            />
            <button className="button" type="button" onClick={handleDecryptText} disabled={!cipherText || !decPass || isDecrypting}>
              decrypt text
            </button>
            <button className="button" type="button" onClick={handleDecryptFile} disabled={!cipherText || !decPass || isDecrypting}>
              decrypt file
            </button>
          </div>
          <label className="section-title" htmlFor="decrypt-pass">
            Passphrase
          </label>
          <input
            id="decrypt-pass"
            className="input"
            type="password"
            placeholder="••••••"
            aria-label="Decrypt passphrase"
            value={decPass}
            onChange={(event) => setDecPass(event.target.value)}
          />
          <div className="status-line">
            <span>passphrase strength</span>
            <span className={gradeTagClass(decPassAssessment.grade)}>{gradeLabel(decPassAssessment.grade)}</span>
            <span className="microcopy">effective ≈ {decPassAssessment.effectiveEntropyBits} bits</span>
          </div>
          <div className="controls-row">
            <Chip label={payloadMeta?.name ?? "text/plain"} tone="muted" />
            {payloadMeta?.bytes !== undefined && <Chip label={`${Math.ceil((payloadMeta.bytes ?? 0) / 1024)} KB`} tone="muted" />}
            {isDecrypting && <Chip label="decrypting…" tone="accent" />}
          </div>
        </div>
      </div>
      <div className="panel" aria-label="Envelope preview">
        <div className="panel-heading">
          <span>Envelope</span>
          <span className="panel-subtext">NULLID:ENC:1</span>
        </div>
        <div className="note-box">
          <div className="microcopy">
            prefix NULLID:ENC:1, AES-GCM, PBKDF2 profile: {kdfProfile} ({kdfConfig.hash.toLowerCase()} / {kdfConfig.iterations.toLocaleString()}),
            AAD bound
          </div>
          <div className="microcopy">
            {envelopeMeta
              ? `header: ${envelopeMeta.hash.toLowerCase()} / ${envelopeMeta.iterations.toLocaleString()} · ${Math.ceil(envelopeMeta.cipherBytes / 1024)} KB ciphertext${envelopeMeta.name ? ` · ${envelopeMeta.name}` : ""}`
              : envelopeMetaError
                ? `header parse: ${envelopeMetaError}`
                : "header parse pending"}
          </div>
          <pre className="output">{cipherText || "Generate an envelope to view"}</pre>
        </div>
        <div className="controls-row">
          <label className="section-title" htmlFor="auto-clear">
            Hygiene
          </label>
          <div className="pill-buttons" role="group" aria-label="Auto clear options">
            <button
              id="auto-clear"
              type="button"
              className={autoClear ? "active" : ""}
              onClick={() => setAutoClear((prev) => !prev)}
            >
              auto clear
            </button>
            <input
              className="input"
              type="number"
              min={5}
              max={300}
              value={clearAfter}
              onChange={(event) => setClearAfter(Math.min(300, Math.max(5, Number(event.target.value))))}
              aria-label="Auto clear seconds"
            />
            <button className="button" type="button" onClick={downloadEncryptedFile} disabled={!encFileBlob}>
              download envelope
            </button>
            <button className="button" type="button" onClick={downloadDecryptedFile} disabled={!decFileBlob}>
              download decrypted
            </button>
          </div>
        </div>
        <div className="status-line">
          <span>decrypt</span>
          <span className={`tag ${error ? "tag-danger" : "tag-accent"}`}>{error || decrypted || "pending"}</span>
        </div>
      </div>
      <div className="panel" aria-label="Decryption output">
        <div className="panel-heading">
          <span>Output</span>
          <span className="panel-subtext">{decFileBlob ? "file ready" : "text"}</span>
        </div>
        <div className="note-box">
          <div className="microcopy">Decrypted preview</div>
          <pre className="output" aria-live="polite">{decrypted || "[pending]"}</pre>
          {decFileBlob && (
            <div className="microcopy">
              file: {decFileName ?? "decrypted.bin"} · type: {decMime} · size: {decFileBlob.byteLength} bytes
            </div>
          )}
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

function clamp(value: number, min: number, max: number) {
  return Math.min(max, Math.max(min, value));
}
