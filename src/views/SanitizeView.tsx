import { useEffect, useMemo, useRef, useState } from "react";
import "./styles.css";
import { usePersistentState } from "../hooks/usePersistentState";
import { useToast } from "../components/ToastHost";
import { ActionDialog } from "../components/ActionDialog";
import { useClipboardPrefs, writeClipboard } from "../utils/clipboard";
import { hashText } from "../utils/hash";
import { encryptText } from "../utils/cryptoEnvelope";
import { mergeSanitizePolicyConfig, normalizeWorkspacePolicyBaseline } from "../utils/policyBaseline";
import {
  createPolicyPackSnapshot,
  describePolicyPackPayload,
  importPolicyPackPayload,
  mergePolicyPacks,
  type PolicyPackDescriptor,
} from "../utils/policyPack";
import {
  applySanitizeRules,
  buildRulesState,
  getRuleKeys,
  getRuleLabel,
  runBatchSanitize,
  sanitizePresets,
  type BatchOutput,
  type CustomRule,
  type CustomRuleScope,
  type PresetKey,
  type RulesState,
  type PolicyPack,
  type SanitizePolicyConfig,
} from "../utils/sanitizeEngine";
import type { ModuleKey } from "../components/ModuleList";
import { useI18n } from "../i18n";
import {
  SHARED_KEY_HINT_PROFILE_KEY,
  readLegacyProfiles,
  removeProfileHint,
  rotateProfileHint,
  sanitizeKeyHint,
  upsertKeyHintProfile,
  type KeyHintProfile,
} from "../utils/keyHintProfiles";

interface SanitizeViewProps {
  onOpenGuide?: (key?: ModuleKey) => void;
}

const ruleKeys = getRuleKeys();
const presetKeys = Object.keys(sanitizePresets) as PresetKey[];
const defaultRules = Object.fromEntries(ruleKeys.map((key) => [key, true])) as RulesState;

export function SanitizeView({ onOpenGuide }: SanitizeViewProps) {
  const { push } = useToast();
  const { t, tr, formatNumber } = useI18n();
  const [clipboardPrefs] = useClipboardPrefs();
  const [log, setLog] = useState(sanitizePresets.nginx.sample);
  const [rulesState, setRulesState] = usePersistentState<RulesState>("nullid:sanitize:rules", defaultRules);
  const [preset, setPreset] = usePersistentState<PresetKey>("nullid:sanitize:preset", "nginx");
  const [wrapLines, setWrapLines] = usePersistentState<boolean>("nullid:sanitize:wrap", false);
  const [jsonAware, setJsonAware] = usePersistentState<boolean>("nullid:sanitize:json", true);
  const [customRules, setCustomRules] = usePersistentState<CustomRule[]>("nullid:sanitize:custom", []);
  const [policyPacks, setPolicyPacks] = usePersistentState<PolicyPack[]>("nullid:sanitize:policy-packs", []);
  const [keyHintProfiles, setKeyHintProfiles] = usePersistentState<KeyHintProfile[]>(SHARED_KEY_HINT_PROFILE_KEY, []);
  const [selectedKeyHintProfileId, setSelectedKeyHintProfileId] = usePersistentState<string>("nullid:sanitize:key-hint-selected", "");
  const [selectedPolicyId, setSelectedPolicyId] = useState("");
  const [policyName, setPolicyName] = useState("");
  const [keyProfileName, setKeyProfileName] = useState("");
  const [keyProfileHint, setKeyProfileHint] = useState("");
  const [policyExportDialogOpen, setPolicyExportDialogOpen] = useState(false);
  const [policyExportTarget, setPolicyExportTarget] = useState<PolicyPack | null>(null);
  const [policyExportSigned, setPolicyExportSigned] = useState(false);
  const [policyExportPassphrase, setPolicyExportPassphrase] = useState("");
  const [policyExportKeyHint, setPolicyExportKeyHint] = useState("");
  const [policyExportError, setPolicyExportError] = useState<string | null>(null);
  const [policyImportDialogOpen, setPolicyImportDialogOpen] = useState(false);
  const [policyImportPassphrase, setPolicyImportPassphrase] = useState("");
  const [policyImportError, setPolicyImportError] = useState<string | null>(null);
  const [pendingPolicyImport, setPendingPolicyImport] = useState<{ payload: unknown; descriptor: PolicyPackDescriptor } | null>(null);
  const [customRuleDraft, setCustomRuleDraft] = useState<CustomRule>({
    id: "",
    pattern: "",
    replacement: "",
    flags: "gi",
    scope: "both",
  });
  const [customRuleError, setCustomRuleError] = useState<string | null>(null);
  const [batchResults, setBatchResults] = useState<BatchOutput[]>([]);
  const [bundlePassphrase, setBundlePassphrase] = useState("");
  const [isBatching, setIsBatching] = useState(false);
  const [isExportingBundle, setIsExportingBundle] = useState(false);
  const batchFileInputRef = useRef<HTMLInputElement>(null);
  const policyImportRef = useRef<HTMLInputElement>(null);
  const baselineImportRef = useRef<HTMLInputElement>(null);

  const result = useMemo(
    () => applySanitizeRules(log, rulesState, customRules, jsonAware),
    [customRules, jsonAware, log, rulesState],
  );
  const ruleImpact = useMemo(() => {
    return result.report
      .map((line) => {
        const match = line.match(/^(.*?):\s*(\d+)$/);
        if (!match) return null;
        return { label: match[1], count: Number(match[2]) };
      })
      .filter((entry): entry is { label: string; count: number } => Boolean(entry))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);
  }, [result.report]);
  const simulationRows = useMemo(() => {
    const allRulesState = Object.fromEntries(ruleKeys.map((ruleKey) => [ruleKey, true])) as RulesState;
    const presetRulesState = buildRulesState(sanitizePresets[preset].rules);
    const variants = [
      { id: "current", label: "current policy", rulesState, jsonAware, customRules },
      { id: "strict", label: "strict all-rules", rulesState: allRulesState, jsonAware: true, customRules },
      { id: "preset", label: `preset baseline (${sanitizePresets[preset].label})`, rulesState: presetRulesState, jsonAware: true, customRules: [] },
      { id: "text", label: "text-only mode", rulesState, jsonAware: false, customRules },
    ];
    return variants.map((variant) => {
      const simulated = applySanitizeRules(log, variant.rulesState, variant.customRules, variant.jsonAware);
      return {
        id: variant.id,
        label: variant.label,
        linesAffected: simulated.linesAffected,
        outputChars: simulated.output.length,
        appliedRules: simulated.applied.length,
      };
    });
  }, [customRules, jsonAware, log, preset, rulesState]);

  const selectedPolicy = useMemo(() => policyPacks.find((pack) => pack.id === selectedPolicyId) ?? null, [policyPacks, selectedPolicyId]);
  const selectedKeyHintProfile = useMemo(
    () => keyHintProfiles.find((profile) => profile.id === selectedKeyHintProfileId) ?? null,
    [keyHintProfiles, selectedKeyHintProfileId],
  );

  useEffect(() => {
    if (keyHintProfiles.length > 0) return;
    const legacy = readLegacyProfiles("nullid:sanitize:key-hints");
    if (legacy.length > 0) {
      setKeyHintProfiles(legacy);
    }
  }, [keyHintProfiles.length, setKeyHintProfiles]);

  const applyPreset = (key: PresetKey) => {
    setPreset(key);
    setLog(sanitizePresets[key].sample);
    setRulesState(buildRulesState(sanitizePresets[key].rules));
    push(`preset loaded: ${sanitizePresets[key].label}`, "accent");
  };

  const addCustomRule = () => {
    if (!customRuleDraft.pattern.trim()) {
      setCustomRuleError("Pattern is required");
      return;
    }
    try {
      // Validate regex before saving
      // eslint-disable-next-line no-new
      new RegExp(customRuleDraft.pattern, customRuleDraft.flags);
      const next: CustomRule = { ...customRuleDraft, id: crypto.randomUUID() };
      setCustomRules((prev) => [...prev, next]);
      setCustomRuleDraft({ id: "", pattern: "", replacement: "", flags: "gi", scope: "both" });
      setCustomRuleError(null);
    } catch (error) {
      setCustomRuleError((error as Error).message);
    }
  };

  const removeCustomRule = (id: string) => setCustomRules((prev) => prev.filter((rule) => rule.id !== id));

  const savePolicyPack = () => {
    const name = policyName.trim();
    if (!name) {
      push("policy name required", "danger");
      return;
    }
    const config = {
      rulesState,
      jsonAware,
      customRules,
    };
    let savedId = "";
    setPolicyPacks((prev) => {
      const existing = prev.find((pack) => pack.name.toLowerCase() === name.toLowerCase());
      if (existing) {
        savedId = existing.id;
        return prev.map((pack) => (pack.id === existing.id ? { ...pack, config, createdAt: new Date().toISOString(), name } : pack));
      }
      const created: PolicyPack = {
        id: crypto.randomUUID(),
        name,
        createdAt: new Date().toISOString(),
        config,
      };
      savedId = created.id;
      return [created, ...prev].slice(0, 30);
    });
    if (savedId) {
      setSelectedPolicyId(savedId);
    }
    push("policy pack saved locally", "accent");
  };

  const applyPolicyPack = (pack: PolicyPack) => {
    setRulesState(pack.config.rulesState);
    setJsonAware(pack.config.jsonAware);
    setCustomRules(pack.config.customRules);
    setPolicyName(pack.name);
    setSelectedPolicyId(pack.id);
    push(`policy applied: ${pack.name}`, "accent");
  };

  const deletePolicyPack = () => {
    if (!selectedPolicy) return;
    setPolicyPacks((prev) => prev.filter((pack) => pack.id !== selectedPolicy.id));
    setSelectedPolicyId("");
    push("policy pack removed", "neutral");
  };

  const currentPolicyConfig: SanitizePolicyConfig = useMemo(
    () => ({
      rulesState,
      jsonAware,
      customRules,
    }),
    [customRules, jsonAware, rulesState],
  );

  const openPolicyExportDialog = (pack?: PolicyPack | null, forceSigned = false) => {
    const sourcePacks = pack ? [pack] : policyPacks;
    if (sourcePacks.length === 0) {
      push("no policy packs to export", "danger");
      return;
    }
    setPolicyExportTarget(pack ?? null);
    setPolicyExportSigned(forceSigned);
    setPolicyExportPassphrase("");
    setPolicyExportKeyHint(selectedKeyHintProfile?.keyHint ?? "");
    setPolicyExportError(null);
    setPolicyExportDialogOpen(true);
  };

  const closePolicyExportDialog = () => {
    setPolicyExportDialogOpen(false);
    setPolicyExportPassphrase("");
    setPolicyExportError(null);
  };

  const confirmPolicyExport = async () => {
    const sourcePacks = policyExportTarget ? [policyExportTarget] : policyPacks;
    if (sourcePacks.length === 0) {
      setPolicyExportError("no policy packs to export");
      return;
    }
    if (policyExportSigned && !policyExportPassphrase.trim()) {
      setPolicyExportError("signing passphrase required");
      return;
    }
    try {
      const payload = await createPolicyPackSnapshot(sourcePacks, {
        signingPassphrase: policyExportSigned ? policyExportPassphrase : undefined,
        keyHint: policyExportSigned ? sanitizeKeyHint(policyExportKeyHint) || undefined : undefined,
      });
      const safe = sanitizeFileStem(policyExportTarget?.name ?? "sanitize-policy-packs");
      const suffix = payload.signature ? "-signed" : "";
      downloadBlob(new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" }), `${safe}${suffix}.json`);
      push(
        policyExportTarget
          ? `policy exported${payload.signature ? " (signed)" : ""}`
          : `all policies exported${payload.signature ? " (signed)" : ""}`,
        "accent",
      );
      closePolicyExportDialog();
    } catch (error) {
      console.error(error);
      setPolicyExportError(error instanceof Error ? error.message : "policy export failed");
    }
  };

  const beginPolicyImport = async (file?: File | null) => {
    if (!file) return;
    try {
      const text = await file.text();
      const payload = JSON.parse(text) as unknown;
      const descriptor = describePolicyPackPayload(payload);
      if (descriptor.kind !== "sanitize-policy-pack" || descriptor.packCount === 0) {
        throw new Error("No valid policy packs found");
      }
      setPendingPolicyImport({ payload, descriptor });
      setPolicyImportPassphrase("");
      setPolicyImportError(null);
      setPolicyImportDialogOpen(true);
    } catch (error) {
      console.error(error);
      push("policy import failed", "danger");
    }
  };

  const closePolicyImportDialog = () => {
    setPolicyImportDialogOpen(false);
    setPolicyImportPassphrase("");
    setPolicyImportError(null);
    setPendingPolicyImport(null);
  };

  const confirmPolicyImport = async () => {
    if (!pendingPolicyImport) return;
    if (pendingPolicyImport.descriptor.signed && !policyImportPassphrase.trim()) {
      setPolicyImportError("verification passphrase required for signed policy packs");
      return;
    }
    try {
      const imported = await importPolicyPackPayload(pendingPolicyImport.payload, {
        verificationPassphrase: pendingPolicyImport.descriptor.signed ? policyImportPassphrase.trim() : undefined,
        requireVerified: pendingPolicyImport.descriptor.signed,
      });
      setPolicyPacks((prev) => mergePolicyPacks(prev, imported.packs));
      setSelectedPolicyId(imported.packs[0].id);
      setPolicyName(imported.packs[0].name);
      const suffix = imported.legacy ? "legacy" : imported.signed ? (imported.verified ? "signed+verified" : "signed") : "unsigned";
      push(`imported ${imported.packs.length} policy pack(s) :: ${suffix}`, "accent");
      closePolicyImportDialog();
    } catch (error) {
      console.error(error);
      setPolicyImportError(error instanceof Error ? error.message : "policy import failed");
    }
  };

  const importWorkspaceBaseline = async (file?: File | null) => {
    if (!file) return;
    try {
      const text = await file.text();
      const parsed = JSON.parse(text) as unknown;
      const baseline = normalizeWorkspacePolicyBaseline(parsed);
      if (!baseline) {
        throw new Error("Invalid nullid.policy.json baseline file");
      }

      const merged = mergeSanitizePolicyConfig(currentPolicyConfig, baseline.sanitize.defaultConfig, baseline.sanitize.mergeMode);
      setRulesState(merged.rulesState);
      setJsonAware(merged.jsonAware);
      setCustomRules(merged.customRules);
      setPolicyPacks((prev) => mergePolicyPacks(prev, baseline.sanitize.packs));
      if (baseline.sanitize.packs.length > 0) {
        setSelectedPolicyId(baseline.sanitize.packs[0].id);
        setPolicyName(baseline.sanitize.packs[0].name);
      }
      push(
        `baseline merged (${baseline.sanitize.mergeMode})${baseline.sanitize.packs.length ? ` + ${baseline.sanitize.packs.length} pack(s)` : ""}`,
        "accent",
      );
    } catch (error) {
      console.error(error);
      push("baseline import failed", "danger");
    }
  };

  const saveKeyHintProfile = () => {
    const result = upsertKeyHintProfile(keyHintProfiles, keyProfileName, keyProfileHint);
    if (!result.ok) {
      push(result.message, "danger");
      return;
    }
    setKeyHintProfiles(result.profiles);
    setSelectedKeyHintProfileId(result.selectedId);
    setKeyProfileHint("");
    setKeyProfileName("");
    push("key hint profile saved", "accent");
  };

  const rotateSelectedKeyHintProfile = () => {
    if (!selectedKeyHintProfile) return;
    const result = rotateProfileHint(keyHintProfiles, selectedKeyHintProfile.id);
    if (!result.ok) {
      push(result.message, "danger");
      return;
    }
    setKeyHintProfiles(result.profiles);
    setPolicyExportKeyHint(result.hint);
    push(`key hint rotated → ${result.hint}`, "accent");
  };

  const deleteSelectedKeyHintProfile = () => {
    if (!selectedKeyHintProfile) return;
    setKeyHintProfiles((prev) => removeProfileHint(prev, selectedKeyHintProfile.id));
    setSelectedKeyHintProfileId("");
    push("key hint profile removed", "neutral");
  };

  const runBatch = async (files: FileList | null) => {
    if (!files || files.length === 0) return;
    setIsBatching(true);
    try {
      const batchInputs = await Promise.all(
        Array.from(files).map(async (file) => ({
          name: file.name,
          text: await file.text(),
        })),
      );
      const outputs = runBatchSanitize(batchInputs, { rulesState, jsonAware, customRules });
      setBatchResults(outputs);
      push(`batch processed: ${outputs.length} file(s)`, "accent");
    } catch (error) {
      console.error(error);
      push("batch processing failed", "danger");
    } finally {
      setIsBatching(false);
    }
  };

  const downloadBatchOutputs = () => {
    if (batchResults.length === 0) return;
    batchResults.forEach((item, index) => {
      const name = `${sanitizeFileStem(item.name)}-sanitized.log`;
      window.setTimeout(() => {
        downloadBlob(new Blob([item.output], { type: "text/plain" }), name);
      }, index * 100);
    });
    push("batch downloads started", "accent");
  };

  const exportBatchReport = () => {
    if (batchResults.length === 0) return;
    const report = {
      schemaVersion: 1,
      kind: "sanitize-batch-report",
      generatedAt: new Date().toISOString(),
      policy: { rulesState, jsonAware, customRules },
      files: batchResults.map((item) => ({
        name: item.name,
        inputChars: item.inputChars,
        outputChars: item.outputChars,
        linesAffected: item.linesAffected,
        appliedRules: item.applied,
        report: item.report,
      })),
    };
    downloadBlob(new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }), "nullid-sanitize-batch-report.json");
    push("batch report exported", "accent");
  };

  const exportShareBundle = async () => {
    setIsExportingBundle(true);
    try {
      const [inputHash, outputHash] = await Promise.all([hashText(log, "SHA-256"), hashText(result.output, "SHA-256")]);
      const bundle = {
        schemaVersion: 1,
        kind: "nullid-safe-share",
        tool: "sanitize",
        createdAt: new Date().toISOString(),
        policy: {
          rulesState,
          jsonAware,
          customRules,
        },
        input: {
          bytes: new TextEncoder().encode(log).byteLength,
          sha256: inputHash.hex,
        },
        output: {
          bytes: new TextEncoder().encode(result.output).byteLength,
          sha256: outputHash.hex,
          text: result.output,
        },
        summary: {
          linesAffected: result.linesAffected,
          appliedRules: result.applied,
          report: result.report,
        },
      };
      const json = JSON.stringify(bundle, null, 2);
      if (bundlePassphrase.trim()) {
        const envelope = await encryptText(bundlePassphrase.trim(), json);
        downloadBlob(new Blob([envelope], { type: "text/plain;charset=utf-8" }), "nullid-safe-share-bundle.nullid");
        push("encrypted safe-share bundle exported", "accent");
        return;
      }
      downloadBlob(new Blob([json], { type: "application/json" }), "nullid-safe-share-bundle.json");
      push("safe-share bundle exported", "accent");
    } catch (error) {
      console.error(error);
      push("safe-share export failed", "danger");
    } finally {
      setIsExportingBundle(false);
    }
  };

  return (
    <div className="workspace-scroll">
      <div className="guide-link">
        <button type="button" className="guide-link-button" onClick={() => onOpenGuide?.("sanitize")}>
          {t("guide.link")}
        </button>
      </div>
      <div className="grid-two">
        <div className="panel" aria-label={tr("Sanitizer input")}>
          <div className="panel-heading">
            <span>{tr("Inbound log")}</span>
            <span className="panel-subtext">{tr("raw")}</span>
          </div>
          <textarea
            className="textarea"
            value={log}
            onChange={(event) => setLog(event.target.value)}
            aria-label="Log input"
          />
          <div className="controls-row">
            <span className="section-title">{tr("Presets")}</span>
            <div className="pill-buttons" role="group" aria-label={tr("Log presets")}>
              {presetKeys.map((key) => (
                <button key={key} type="button" className={preset === key ? "active" : ""} onClick={() => applyPreset(key)}>
                  {sanitizePresets[key].label}
                </button>
              ))}
            </div>
          </div>
        </div>
        <div className="panel" aria-label={tr("Sanitized preview")}>
          <div className="panel-heading">
            <span>{tr("Preview")}</span>
            <span className="panel-subtext">diff</span>
          </div>
          <div className="log-preview" role="presentation">
            <div className="log-line">
              <span className="log-marker">-</span>
              <span className="diff-remove">{log}</span>
            </div>
            <div className="log-line">
              <span className="log-marker">+</span>
              <span className="diff-add" style={{ whiteSpace: wrapLines ? "pre-wrap" : "pre" }}>
                {highlightDiff(log, result.output)}
              </span>
            </div>
          </div>
          <div className="controls-row">
            <button
              className="button"
              type="button"
              onClick={() =>
                writeClipboard(
                  result.output,
                  clipboardPrefs,
                  (message, tone) => push(message, tone === "danger" ? "danger" : tone === "accent" ? "accent" : "neutral"),
                  "copied",
                )
              }
              disabled={!result.output}
            >
              {tr("copy sanitized")}
            </button>
            <button
              className="button"
              type="button"
              onClick={() => downloadBlob(new Blob([result.output], { type: "text/plain" }), "nullid-sanitized.log")}
              disabled={!result.output}
            >
              {tr("download sanitized")}
            </button>
            <label className="microcopy" style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
              <input
                type="checkbox"
                checked={wrapLines}
                onChange={(event) => setWrapLines(event.target.checked)}
                aria-label={tr("Wrap long lines")}
              />
              {tr("wrap long lines")}
            </label>
            <label className="microcopy" style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
              <input
                type="checkbox"
                checked={jsonAware}
                onChange={(event) => setJsonAware(event.target.checked)}
                aria-label={tr("Enable JSON redaction")}
              />
              {tr("JSON-aware redaction")}
            </label>
          </div>
          <div className="status-line">
            <span>{tr("Rules applied")}</span>
            <span className="tag tag-accent">{result.applied.length}</span>
            <span className="microcopy">{tr("lines changed:")} {formatNumber(result.linesAffected)}</span>
          </div>
        </div>
      </div>
      <div className="panel" aria-label={tr("Rule toggles")}>
        <div className="panel-heading">
          <span>{tr("Rules")}</span>
          <span className="panel-subtext">{tr("toggle")}</span>
        </div>
        <div className="rule-grid">
          {ruleKeys.map((ruleKey) => (
            <label key={ruleKey} className="rule-tile">
              <input
                type="checkbox"
                checked={rulesState[ruleKey]}
                onChange={(event) => setRulesState((prev) => ({ ...prev, [ruleKey]: event.target.checked }))}
                aria-label={getRuleLabel(ruleKey)}
              />
              <span>{getRuleLabel(ruleKey)}</span>
            </label>
          ))}
        </div>
        <div className="note-box">
          <div className="section-title">Report</div>
          <div className="microcopy">
            {result.report.length === 0 ? "no replacements yet" : result.report.map((line) => <div key={line}>{line}</div>)}
          </div>
        </div>
        <div className="note-box">
          <div className="section-title">Rule impact ranking</div>
          {ruleImpact.length === 0 ? (
            <div className="microcopy">no replacements counted yet</div>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>rule</th>
                  <th>count</th>
                </tr>
              </thead>
              <tbody>
                {ruleImpact.map((entry) => (
                  <tr key={entry.label}>
                    <td>{entry.label}</td>
                    <td>{entry.count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
        <div className="note-box">
          <div className="section-title">Custom rules</div>
          <div className="controls-row" style={{ alignItems: "flex-end" }}>
            <div style={{ flex: 1, minWidth: "180px" }}>
              <label className="microcopy" htmlFor="custom-pattern">
                Pattern (RegExp)
              </label>
              <input
                id="custom-pattern"
                className="input"
                value={customRuleDraft.pattern}
                onChange={(event) => setCustomRuleDraft((prev) => ({ ...prev, pattern: event.target.value }))}
                placeholder="token=([A-Za-z0-9._-]+)"
              />
            </div>
            <div style={{ minWidth: "140px" }}>
              <label className="microcopy" htmlFor="custom-flags">
                Flags
              </label>
              <input
                id="custom-flags"
                className="input"
                value={customRuleDraft.flags}
                onChange={(event) => setCustomRuleDraft((prev) => ({ ...prev, flags: event.target.value }))}
                placeholder="gi"
              />
            </div>
            <div style={{ flex: 1, minWidth: "160px" }}>
              <label className="microcopy" htmlFor="custom-replacement">
                Replacement
              </label>
              <input
                id="custom-replacement"
                className="input"
                value={customRuleDraft.replacement}
                onChange={(event) => setCustomRuleDraft((prev) => ({ ...prev, replacement: event.target.value }))}
                placeholder="[redacted]"
              />
            </div>
            <div style={{ minWidth: "150px" }}>
              <label className="microcopy" htmlFor="custom-scope">
                Scope
              </label>
              <select
                id="custom-scope"
                className="select"
                value={customRuleDraft.scope}
                onChange={(event) =>
                  setCustomRuleDraft((prev) => ({ ...prev, scope: event.target.value as CustomRuleScope }))
                }
              >
                <option value="both">text + json</option>
                <option value="text">text only</option>
                <option value="json">json only</option>
              </select>
            </div>
            <button className="button" type="button" onClick={addCustomRule}>
              add rule
            </button>
          </div>
          {customRuleError && <div className="microcopy" style={{ color: "var(--danger)" }}>{customRuleError}</div>}
          {customRules.length === 0 ? (
            <div className="microcopy">no custom rules</div>
          ) : (
            <ul className="note-list">
              {customRules.map((rule) => (
                <li key={rule.id}>
                  <div className="note-title">/{rule.pattern}/{rule.flags}</div>
                  <div className="note-body">→ {rule.replacement || "[empty]"} ({rule.scope})</div>
                  <button className="button" type="button" onClick={() => removeCustomRule(rule.id)}>
                    remove
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

      <div className="panel" aria-label="Policy simulation matrix">
        <div className="panel-heading">
          <span>{tr("Policy simulation matrix")}</span>
          <span className="panel-subtext">{tr("compare policy outcomes")}</span>
        </div>
        <p className="microcopy">
          Runs multiple policy variants against current input so you can compare redaction depth before sharing.
        </p>
        <table className="table">
          <thead>
            <tr>
              <th>variant</th>
              <th>rules applied</th>
              <th>lines changed</th>
              <th>output chars</th>
            </tr>
          </thead>
          <tbody>
            {simulationRows.map((row) => (
              <tr key={row.id}>
                <td>{row.label}</td>
                <td>{row.appliedRules}</td>
                <td>{row.linesAffected}</td>
                <td>{row.outputChars}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="grid-two">
        <div className="panel" aria-label={tr("Policy packs")}>
          <div className="panel-heading">
            <span>{tr("Policy packs")}</span>
            <span className="panel-subtext">{tr("local-only reusable configs")}</span>
          </div>
          <div className="controls-row">
            <input
              className="input"
              placeholder={tr("policy name")}
              value={policyName}
              onChange={(event) => setPolicyName(event.target.value)}
              aria-label={tr("Policy name")}
            />
            <button className="button" type="button" onClick={savePolicyPack}>
              {tr("save")}
            </button>
          </div>
          <div className="controls-row">
            <select
              className="select"
              aria-label="Saved policy packs"
              value={selectedPolicyId}
              onChange={(event) => setSelectedPolicyId(event.target.value)}
            >
              <option value="">{tr("select policy...")}</option>
              {policyPacks.map((pack) => (
                <option key={pack.id} value={pack.id}>
                  {pack.name}
                </option>
              ))}
            </select>
            <button className="button" type="button" onClick={() => selectedPolicy && applyPolicyPack(selectedPolicy)} disabled={!selectedPolicy}>
              {tr("apply")}
            </button>
            <button className="button" type="button" onClick={deletePolicyPack} disabled={!selectedPolicy}>
              {tr("delete")}
            </button>
          </div>
          <div className="controls-row">
            <button className="button" type="button" onClick={() => openPolicyExportDialog(selectedPolicy)} disabled={!selectedPolicy}>
              {tr("export selected")}
            </button>
            <button className="button" type="button" onClick={() => openPolicyExportDialog(selectedPolicy, true)} disabled={!selectedPolicy}>
              {tr("export signed")}
            </button>
            <button className="button" type="button" onClick={() => openPolicyExportDialog(null)} disabled={policyPacks.length === 0}>
              {tr("export all")}
            </button>
            <button className="button" type="button" onClick={() => policyImportRef.current?.click()}>
              {tr("import")}
            </button>
            <button className="button" type="button" onClick={() => baselineImportRef.current?.click()}>
              {tr("import baseline")}
            </button>
            <input
              ref={policyImportRef}
              type="file"
              accept="application/json"
              style={{ position: "absolute", opacity: 0, width: 1, height: 1, pointerEvents: "none" }}
              tabIndex={-1}
              onChange={(event) => {
                void beginPolicyImport(event.target.files?.[0] ?? null);
                event.target.value = "";
              }}
            />
            <input
              ref={baselineImportRef}
              type="file"
              accept="application/json"
              style={{ position: "absolute", opacity: 0, width: 1, height: 1, pointerEvents: "none" }}
              tabIndex={-1}
              onChange={(event) => {
                void importWorkspaceBaseline(event.target.files?.[0] ?? null);
                event.target.value = "";
              }}
            />
          </div>
          <div className="microcopy">
            Signed packs require verify-before-import. Baseline import accepts `nullid.policy.json` and merges with deterministic rules.
          </div>
          <div className="note-box">
            <div className="section-title">Signing key hints</div>
            <div className="controls-row">
              <input
                className="input"
                placeholder="profile name"
                value={keyProfileName}
                onChange={(event) => setKeyProfileName(event.target.value)}
                aria-label="Key hint profile name"
              />
              <input
                className="input"
                placeholder="key hint (public label)"
                value={keyProfileHint}
                onChange={(event) => setKeyProfileHint(event.target.value)}
                aria-label="Key hint value"
              />
              <button className="button" type="button" onClick={saveKeyHintProfile}>
                save hint
              </button>
            </div>
            <div className="controls-row">
              <select
                className="select"
                aria-label="Saved key hint profiles"
                value={selectedKeyHintProfileId}
                onChange={(event) => setSelectedKeyHintProfileId(event.target.value)}
              >
                <option value="">select key hint profile...</option>
                {keyHintProfiles.map((profile) => (
                  <option key={profile.id} value={profile.id}>
                    {profile.name} · {profile.keyHint}
                  </option>
                ))}
              </select>
              <button className="button" type="button" onClick={rotateSelectedKeyHintProfile} disabled={!selectedKeyHintProfile}>
                rotate hint
              </button>
              <button className="button" type="button" onClick={deleteSelectedKeyHintProfile} disabled={!selectedKeyHintProfile}>
                delete hint
              </button>
            </div>
            <div className="microcopy">
              Hints are local labels only; signing/verification passphrases are never stored.
              {selectedKeyHintProfile ? ` Active: ${selectedKeyHintProfile.name} (v${selectedKeyHintProfile.version})` : ""}
            </div>
          </div>
        </div>

        <div className="panel" aria-label={tr("Batch sanitize")}>
          <div className="panel-heading">
            <span>{tr("Batch sanitize")}</span>
            <span className="panel-subtext">{tr("free local processing")}</span>
          </div>
          <div className="controls-row">
            <button className="button" type="button" onClick={() => batchFileInputRef.current?.click()} disabled={isBatching}>
              {isBatching ? tr("processing...") : tr("select files")}
            </button>
            <input
              ref={batchFileInputRef}
              type="file"
              multiple
              accept=".txt,.log,.json,text/*,application/json"
              style={{ position: "absolute", opacity: 0, width: 1, height: 1, pointerEvents: "none" }}
              tabIndex={-1}
              onChange={(event) => {
                void runBatch(event.target.files);
                event.target.value = "";
              }}
            />
            <button className="button" type="button" onClick={downloadBatchOutputs} disabled={batchResults.length === 0}>
              {tr("download outputs")}
            </button>
            <button className="button" type="button" onClick={exportBatchReport} disabled={batchResults.length === 0}>
              {tr("export report")}
            </button>
          </div>
          <div className="status-line">
            <span>{tr("files processed")}</span>
            <span className="tag tag-accent">{formatNumber(batchResults.length)}</span>
          </div>
          {batchResults.length > 0 && (
            <table className="table">
              <thead>
                <tr>
                  <th>file</th>
                  <th>lines changed</th>
                  <th>size delta</th>
                </tr>
              </thead>
              <tbody>
                {batchResults.slice(0, 8).map((item) => (
                  <tr key={item.name}>
                    <td>{item.name}</td>
                    <td>{item.linesAffected}</td>
                    <td>{item.outputChars - item.inputChars}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      <div className="panel" aria-label="Safe share bundle">
        <div className="panel-heading">
          <span>{tr("Safe share bundle")}</span>
          <span className="panel-subtext">{tr("manifest + hash + sanitized output")}</span>
        </div>
        <p className="microcopy">
          Generates a portable local bundle containing sanitized output, policy snapshot, and SHA-256 integrity hashes.
        </p>
        <div className="controls-row">
          <input
            className="input"
            type="password"
            placeholder={tr("optional passphrase to encrypt bundle")}
            value={bundlePassphrase}
            onChange={(event) => setBundlePassphrase(event.target.value)}
            aria-label={tr("Bundle encryption passphrase")}
          />
          <button className="button" type="button" onClick={() => void exportShareBundle()} disabled={isExportingBundle || !result.output}>
            {isExportingBundle ? tr("exporting...") : bundlePassphrase ? tr("export encrypted bundle") : tr("export bundle")}
          </button>
        </div>
      </div>
      <ActionDialog
        open={policyExportDialogOpen}
        title={policyExportTarget ? `Export policy: ${policyExportTarget.name}` : "Export policy packs"}
        description="Signed policy exports include integrity metadata and require verification passphrase on import."
        confirmLabel={policyExportTarget ? "export policy" : "export policies"}
        onCancel={closePolicyExportDialog}
        onConfirm={() => void confirmPolicyExport()}
        confirmDisabled={policyExportSigned && !policyExportPassphrase.trim()}
      >
        <label className="action-dialog-field">
          <span>Sign export metadata</span>
          <input
            type="checkbox"
            checked={policyExportSigned}
            onChange={(event) => setPolicyExportSigned(event.target.checked)}
            aria-label="Sign policy export metadata"
          />
        </label>
        {policyExportSigned ? (
          <>
            <label className="action-dialog-field">
              <span>Signing passphrase</span>
              <input
                className="action-dialog-input"
                type="password"
                value={policyExportPassphrase}
                onChange={(event) => {
                  setPolicyExportPassphrase(event.target.value);
                  if (policyExportError) setPolicyExportError(null);
                }}
                aria-label="Policy signing passphrase"
                placeholder="required when signing"
              />
            </label>
            <div className="action-dialog-row">
              <label className="action-dialog-field">
                <span>Saved key hint</span>
                <select
                  className="action-dialog-select"
                  value={selectedKeyHintProfileId}
                  onChange={(event) => {
                    const nextId = event.target.value;
                    setSelectedKeyHintProfileId(nextId);
                    const profile = keyHintProfiles.find((entry) => entry.id === nextId);
                    setPolicyExportKeyHint(profile?.keyHint ?? "");
                  }}
                  aria-label="Policy key hint profile"
                >
                  <option value="">custom key hint</option>
                  {keyHintProfiles.map((profile) => (
                    <option key={profile.id} value={profile.id}>
                      {profile.name} · {profile.keyHint}
                    </option>
                  ))}
                </select>
              </label>
              <label className="action-dialog-field">
                <span>Key hint label</span>
                <input
                  className="action-dialog-input"
                  value={policyExportKeyHint}
                  onChange={(event) => setPolicyExportKeyHint(event.target.value)}
                  aria-label="Policy key hint"
                  placeholder="optional verification hint"
                />
              </label>
            </div>
            <p className="action-dialog-note">
              Hints are local labels only; passphrases are never stored.
              {selectedKeyHintProfile ? ` Active: ${selectedKeyHintProfile.name} (v${selectedKeyHintProfile.version})` : ""}
            </p>
          </>
        ) : (
          <p className="action-dialog-note">Unsigned packs can be imported, but authenticity verification is unavailable.</p>
        )}
        {policyExportError ? <p className="action-dialog-error">{policyExportError}</p> : null}
      </ActionDialog>
      <ActionDialog
        open={policyImportDialogOpen}
        title="Import policy pack"
        description={
          pendingPolicyImport
            ? `${pendingPolicyImport.descriptor.packCount} pack(s) · schema ${pendingPolicyImport.descriptor.schemaVersion || "unknown"}`
            : "Verify before import"
        }
        confirmLabel="import policy pack"
        onCancel={closePolicyImportDialog}
        onConfirm={() => void confirmPolicyImport()}
      >
        {pendingPolicyImport?.descriptor.signed ? (
          <>
            <p className="action-dialog-note">
              Signed pack detected{pendingPolicyImport.descriptor.keyHint ? ` (hint: ${pendingPolicyImport.descriptor.keyHint})` : ""}. Verification is required before import.
            </p>
            <label className="action-dialog-field">
              <span>Verification passphrase</span>
              <input
                className="action-dialog-input"
                type="password"
                value={policyImportPassphrase}
                onChange={(event) => {
                  setPolicyImportPassphrase(event.target.value);
                  if (policyImportError) setPolicyImportError(null);
                }}
                aria-label="Policy verification passphrase"
                placeholder="required for signed packs"
              />
            </label>
          </>
        ) : (
          <p className="action-dialog-note">Unsigned policy pack. Continue only if you trust the source.</p>
        )}
        {policyImportError ? <p className="action-dialog-error">{policyImportError}</p> : null}
      </ActionDialog>
    </div>
  );
}

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.rel = "noopener";
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1200);
}

function sanitizeFileStem(value: string) {
  const base = value.replace(/\.[^.]+$/, "").trim();
  return (base || "nullid").replace(/[^a-z0-9_-]+/gi, "-").replace(/-+/g, "-");
}

function highlightDiff(before: string, after: string) {
  if (before === after) return after;
  const beforeTokens = before.split(/(\s+)/);
  const afterTokens = after.split(/(\s+)/);
  return afterTokens.map((token, index) => {
    if (token === beforeTokens[index]) return token;
    return (
      <mark key={index} className="highlight medium">
        {token}
      </mark>
    );
  });
}
