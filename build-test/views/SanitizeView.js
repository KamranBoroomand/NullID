import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import { useEffect, useMemo, useRef, useState } from "react";
import "./styles.css";
import { usePersistentState } from "../hooks/usePersistentState";
import { useToast } from "../components/ToastHost";
import { ActionDialog } from "../components/ActionDialog";
import { useClipboardPrefs, writeClipboard } from "../utils/clipboard";
import { hashText } from "../utils/hash";
import { encryptText } from "../utils/cryptoEnvelope";
import { mergeSanitizePolicyConfig, normalizeWorkspacePolicyBaseline } from "../utils/policyBaseline";
import { createPolicyPackSnapshot, describePolicyPackPayload, importPolicyPackPayload, mergePolicyPacks, } from "../utils/policyPack";
import { applySanitizeRules, buildRulesState, getRuleKeys, getRuleLabel, runBatchSanitize, sanitizePresets, } from "../utils/sanitizeEngine";
import { useI18n } from "../i18n";
import { SHARED_KEY_HINT_PROFILE_KEY, readLegacyProfiles, removeProfileHint, rotateProfileHint, sanitizeKeyHint, upsertKeyHintProfile, } from "../utils/keyHintProfiles";
import { createSanitizeSafeShareBundle } from "../utils/workflowPackage.js";
import { formatPolicyPackTrustState, getPolicyPackExportTrustState, getPolicyPackImportTrustState, policyPackTrustTagClass, } from "./sanitizePolicyTrustState";
const ruleKeys = getRuleKeys();
const presetKeys = Object.keys(sanitizePresets);
const defaultRules = Object.fromEntries(ruleKeys.map((key) => [key, true]));
export function SanitizeView({ onOpenGuide }) {
    const { push } = useToast();
    const { t, tr, formatNumber } = useI18n();
    const [clipboardPrefs] = useClipboardPrefs();
    const [log, setLog] = useState(sanitizePresets.nginx.sample);
    const [rulesState, setRulesState] = usePersistentState("nullid:sanitize:rules", defaultRules);
    const [preset, setPreset] = usePersistentState("nullid:sanitize:preset", "nginx");
    const [wrapLines, setWrapLines] = usePersistentState("nullid:sanitize:wrap", false);
    const [jsonAware, setJsonAware] = usePersistentState("nullid:sanitize:json", true);
    const [customRules, setCustomRules] = usePersistentState("nullid:sanitize:custom", []);
    const [policyPacks, setPolicyPacks] = usePersistentState("nullid:sanitize:policy-packs", []);
    const [keyHintProfiles, setKeyHintProfiles] = usePersistentState(SHARED_KEY_HINT_PROFILE_KEY, []);
    const [selectedKeyHintProfileId, setSelectedKeyHintProfileId] = usePersistentState("nullid:sanitize:key-hint-selected", "");
    const [selectedPolicyId, setSelectedPolicyId] = useState("");
    const [policyName, setPolicyName] = useState("");
    const [keyProfileName, setKeyProfileName] = useState("");
    const [keyProfileHint, setKeyProfileHint] = useState("");
    const [policyExportDialogOpen, setPolicyExportDialogOpen] = useState(false);
    const [policyExportTarget, setPolicyExportTarget] = useState(null);
    const [policyExportSigned, setPolicyExportSigned] = useState(false);
    const [policyExportPassphrase, setPolicyExportPassphrase] = useState("");
    const [policyExportKeyHint, setPolicyExportKeyHint] = useState("");
    const [policyExportError, setPolicyExportError] = useState(null);
    const [policyImportDialogOpen, setPolicyImportDialogOpen] = useState(false);
    const [policyImportPassphrase, setPolicyImportPassphrase] = useState("");
    const [policyImportError, setPolicyImportError] = useState(null);
    const [pendingPolicyImport, setPendingPolicyImport] = useState(null);
    const [customRuleDraft, setCustomRuleDraft] = useState({
        id: "",
        pattern: "",
        replacement: "",
        flags: "gi",
        scope: "both",
    });
    const [customRuleError, setCustomRuleError] = useState(null);
    const [batchResults, setBatchResults] = useState([]);
    const [bundlePassphrase, setBundlePassphrase] = useState("");
    const [isBatching, setIsBatching] = useState(false);
    const [isExportingBundle, setIsExportingBundle] = useState(false);
    const batchFileInputRef = useRef(null);
    const policyImportRef = useRef(null);
    const baselineImportRef = useRef(null);
    const result = useMemo(() => applySanitizeRules(log, rulesState, customRules, jsonAware), [customRules, jsonAware, log, rulesState]);
    const ruleImpact = useMemo(() => {
        return result.report
            .map((line) => {
            const match = line.match(/^(.*?):\s*(\d+)$/);
            if (!match)
                return null;
            return { label: match[1], count: Number(match[2]) };
        })
            .filter((entry) => Boolean(entry))
            .sort((a, b) => b.count - a.count)
            .slice(0, 8);
    }, [result.report]);
    const simulationRows = useMemo(() => {
        const allRulesState = Object.fromEntries(ruleKeys.map((ruleKey) => [ruleKey, true]));
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
    const selectedKeyHintProfile = useMemo(() => keyHintProfiles.find((profile) => profile.id === selectedKeyHintProfileId) ?? null, [keyHintProfiles, selectedKeyHintProfileId]);
    const policyExportTrustState = useMemo(() => getPolicyPackExportTrustState({
        signed: policyExportSigned,
        hasPassphrase: Boolean(policyExportPassphrase.trim()),
    }), [policyExportPassphrase, policyExportSigned]);
    const policyImportTrustState = useMemo(() => getPolicyPackImportTrustState({
        signed: Boolean(pendingPolicyImport?.descriptor.signed),
        hasPassphrase: Boolean(policyImportPassphrase.trim()),
        error: policyImportError,
    }), [pendingPolicyImport?.descriptor.signed, policyImportError, policyImportPassphrase]);
    useEffect(() => {
        if (keyHintProfiles.length > 0)
            return;
        const legacy = readLegacyProfiles("nullid:sanitize:key-hints");
        if (legacy.length > 0) {
            setKeyHintProfiles(legacy);
        }
    }, [keyHintProfiles.length, setKeyHintProfiles]);
    const applyPreset = (key) => {
        setPreset(key);
        setLog(sanitizePresets[key].sample);
        setRulesState(buildRulesState(sanitizePresets[key].rules));
        push(`${tr("preset loaded")}: ${tr(sanitizePresets[key].label)}`, "accent");
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
            const next = { ...customRuleDraft, id: crypto.randomUUID() };
            setCustomRules((prev) => [...prev, next]);
            setCustomRuleDraft({ id: "", pattern: "", replacement: "", flags: "gi", scope: "both" });
            setCustomRuleError(null);
        }
        catch (error) {
            setCustomRuleError(error.message);
        }
    };
    const removeCustomRule = (id) => setCustomRules((prev) => prev.filter((rule) => rule.id !== id));
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
            const created = {
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
    const applyPolicyPack = (pack) => {
        setRulesState(pack.config.rulesState);
        setJsonAware(pack.config.jsonAware);
        setCustomRules(pack.config.customRules);
        setPolicyName(pack.name);
        setSelectedPolicyId(pack.id);
        push(`policy applied: ${pack.name}`, "accent");
    };
    const deletePolicyPack = () => {
        if (!selectedPolicy)
            return;
        setPolicyPacks((prev) => prev.filter((pack) => pack.id !== selectedPolicy.id));
        setSelectedPolicyId("");
        push("policy pack removed", "neutral");
    };
    const currentPolicyConfig = useMemo(() => ({
        rulesState,
        jsonAware,
        customRules,
    }), [customRules, jsonAware, rulesState]);
    const openPolicyExportDialog = (pack, forceSigned = false) => {
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
            setPolicyExportError("HMAC passphrase required");
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
            push(policyExportTarget
                ? `policy exported${payload.signature ? " (HMAC metadata)" : ""}`
                : `all policies exported${payload.signature ? " (HMAC metadata)" : ""}`, "accent");
            closePolicyExportDialog();
        }
        catch (error) {
            console.error(error);
            setPolicyExportError(error instanceof Error ? error.message : "policy export failed");
        }
    };
    const beginPolicyImport = async (file) => {
        if (!file)
            return;
        try {
            const text = await file.text();
            const payload = JSON.parse(text);
            const descriptor = describePolicyPackPayload(payload);
            if (descriptor.kind !== "sanitize-policy-pack" || descriptor.packCount === 0) {
                throw new Error("No valid policy packs found");
            }
            setPendingPolicyImport({ payload, descriptor });
            setPolicyImportPassphrase("");
            setPolicyImportError(null);
            setPolicyImportDialogOpen(true);
        }
        catch (error) {
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
        if (!pendingPolicyImport)
            return;
        if (pendingPolicyImport.descriptor.signed && !policyImportPassphrase.trim()) {
            setPolicyImportError("verification passphrase required for HMAC-protected policy packs");
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
            const suffix = imported.legacy
                ? "legacy"
                : formatPolicyPackTrustState(getPolicyPackImportTrustState({
                    signed: imported.signed,
                    hasPassphrase: Boolean(policyImportPassphrase.trim()),
                    verificationSucceeded: imported.verified,
                }));
            push(`imported ${imported.packs.length} policy pack(s) :: ${suffix}`, "accent");
            closePolicyImportDialog();
        }
        catch (error) {
            console.error(error);
            setPolicyImportError(error instanceof Error ? error.message : "policy import failed");
        }
    };
    const importWorkspaceBaseline = async (file) => {
        if (!file)
            return;
        try {
            const text = await file.text();
            const parsed = JSON.parse(text);
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
            push(`baseline merged (${baseline.sanitize.mergeMode})${baseline.sanitize.packs.length ? ` + ${baseline.sanitize.packs.length} pack(s)` : ""}`, "accent");
        }
        catch (error) {
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
        if (!selectedKeyHintProfile)
            return;
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
        if (!selectedKeyHintProfile)
            return;
        setKeyHintProfiles((prev) => removeProfileHint(prev, selectedKeyHintProfile.id));
        setSelectedKeyHintProfileId("");
        push("key hint profile removed", "neutral");
    };
    const runBatch = async (files) => {
        if (!files || files.length === 0)
            return;
        setIsBatching(true);
        try {
            const batchInputs = await Promise.all(Array.from(files).map(async (file) => ({
                name: file.name,
                text: await file.text(),
            })));
            const outputs = runBatchSanitize(batchInputs, { rulesState, jsonAware, customRules });
            setBatchResults(outputs);
            push(`batch processed: ${outputs.length} file(s)`, "accent");
        }
        catch (error) {
            console.error(error);
            push("batch processing failed", "danger");
        }
        finally {
            setIsBatching(false);
        }
    };
    const downloadBatchOutputs = () => {
        if (batchResults.length === 0)
            return;
        batchResults.forEach((item, index) => {
            const name = `${sanitizeFileStem(item.name)}-sanitized.log`;
            window.setTimeout(() => {
                downloadBlob(new Blob([item.output], { type: "text/plain" }), name);
            }, index * 100);
        });
        push("batch downloads started", "accent");
    };
    const exportBatchReport = () => {
        if (batchResults.length === 0)
            return;
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
            const buildId = typeof import.meta.env.VITE_BUILD_ID === "string" && import.meta.env.VITE_BUILD_ID.trim()
                ? import.meta.env.VITE_BUILD_ID.trim()
                : null;
            const bundle = createSanitizeSafeShareBundle({
                producer: {
                    app: "NullID",
                    surface: "web",
                    module: "sanitize",
                    buildId,
                },
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
                preset,
                policyPack: selectedPolicy,
            });
            const json = JSON.stringify(bundle, null, 2);
            if (bundlePassphrase.trim()) {
                const envelope = await encryptText(bundlePassphrase.trim(), json);
                downloadBlob(new Blob([envelope], { type: "text/plain;charset=utf-8" }), "nullid-safe-share-bundle.nullid");
                push("encrypted safe-share bundle exported", "accent");
                return;
            }
            downloadBlob(new Blob([json], { type: "application/json" }), "nullid-safe-share-bundle.json");
            push("safe-share bundle exported", "accent");
        }
        catch (error) {
            console.error(error);
            push("safe-share export failed", "danger");
        }
        finally {
            setIsExportingBundle(false);
        }
    };
    return (_jsxs("div", { className: "workspace-scroll", children: [_jsx("div", { className: "guide-link", children: _jsx("button", { type: "button", className: "guide-link-button", onClick: () => onOpenGuide?.("sanitize"), children: t("guide.link") }) }), _jsxs("div", { className: "grid-two", children: [_jsxs("div", { className: "panel", "aria-label": tr("Sanitizer input"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("Inbound log") }), _jsx("span", { className: "panel-subtext", children: tr("raw") })] }), _jsx("textarea", { className: "textarea", value: log, onChange: (event) => setLog(event.target.value), "aria-label": tr("Log input") }), _jsxs("div", { className: "controls-row", children: [_jsx("span", { className: "section-title", children: tr("Presets") }), _jsx("div", { className: "pill-buttons", role: "group", "aria-label": tr("Log presets"), children: presetKeys.map((key) => (_jsx("button", { type: "button", className: preset === key ? "active" : "", onClick: () => applyPreset(key), children: tr(sanitizePresets[key].label) }, key))) })] })] }), _jsxs("div", { className: "panel", "aria-label": tr("Sanitized preview"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("Preview") }), _jsx("span", { className: "panel-subtext", children: tr("diff") })] }), _jsxs("div", { className: "log-preview", role: "presentation", children: [_jsxs("div", { className: "log-line", children: [_jsx("span", { className: "log-marker", children: "-" }), _jsx("span", { className: "diff-remove", children: log })] }), _jsxs("div", { className: "log-line", children: [_jsx("span", { className: "log-marker", children: "+" }), _jsx("span", { className: "diff-add", style: { whiteSpace: wrapLines ? "pre-wrap" : "pre" }, children: highlightDiff(log, result.output) })] })] }), _jsxs("div", { className: "controls-row", children: [_jsx("button", { className: "button", type: "button", onClick: () => writeClipboard(result.output, clipboardPrefs, (message, tone) => push(message, tone === "danger" ? "danger" : tone === "accent" ? "accent" : "neutral"), "copied"), disabled: !result.output, children: tr("copy sanitized") }), _jsx("button", { className: "button", type: "button", onClick: () => downloadBlob(new Blob([result.output], { type: "text/plain" }), "nullid-sanitized.log"), disabled: !result.output, children: tr("download sanitized") }), _jsxs("label", { className: "microcopy", style: { display: "flex", alignItems: "center", gap: "0.5rem" }, children: [_jsx("input", { type: "checkbox", checked: wrapLines, onChange: (event) => setWrapLines(event.target.checked), "aria-label": tr("Wrap long lines") }), tr("wrap long lines")] }), _jsxs("label", { className: "microcopy", style: { display: "flex", alignItems: "center", gap: "0.5rem" }, children: [_jsx("input", { type: "checkbox", checked: jsonAware, onChange: (event) => setJsonAware(event.target.checked), "aria-label": tr("Enable JSON redaction") }), tr("JSON-aware redaction")] })] }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: tr("Rules applied") }), _jsx("span", { className: "tag tag-accent", children: result.applied.length }), _jsxs("span", { className: "microcopy", children: [tr("lines changed:"), " ", formatNumber(result.linesAffected)] })] })] })] }), _jsxs("div", { className: "panel", "aria-label": tr("Rule toggles"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("Rules") }), _jsx("span", { className: "panel-subtext", children: tr("toggle") })] }), _jsx("div", { className: "rule-grid", children: ruleKeys.map((ruleKey) => (_jsxs("label", { className: "rule-tile", children: [_jsx("input", { type: "checkbox", checked: rulesState[ruleKey], onChange: (event) => setRulesState((prev) => ({ ...prev, [ruleKey]: event.target.checked })), "aria-label": tr(getRuleLabel(ruleKey)) }), _jsx("span", { children: tr(getRuleLabel(ruleKey)) })] }, ruleKey))) }), _jsxs("div", { className: "note-box", children: [_jsx("div", { className: "section-title", children: tr("Report") }), _jsx("div", { className: "microcopy", children: result.report.length === 0 ? tr("no replacements yet") : result.report.map((line) => _jsx("div", { children: line }, line)) })] }), _jsxs("div", { className: "note-box", children: [_jsx("div", { className: "section-title", children: tr("Rule impact ranking") }), ruleImpact.length === 0 ? (_jsx("div", { className: "microcopy", children: tr("no replacements counted yet") })) : (_jsxs("table", { className: "table", children: [_jsx("thead", { children: _jsxs("tr", { children: [_jsx("th", { children: tr("rule") }), _jsx("th", { children: tr("count") })] }) }), _jsx("tbody", { children: ruleImpact.map((entry) => (_jsxs("tr", { children: [_jsx("td", { children: entry.label }), _jsx("td", { children: entry.count })] }, entry.label))) })] }))] }), _jsxs("div", { className: "note-box", children: [_jsx("div", { className: "section-title", children: tr("Custom rules") }), _jsxs("div", { className: "controls-row", style: { alignItems: "flex-end" }, children: [_jsxs("div", { style: { flex: 1, minWidth: "180px" }, children: [_jsx("label", { className: "microcopy", htmlFor: "custom-pattern", children: tr("Pattern (RegExp)") }), _jsx("input", { id: "custom-pattern", className: "input", value: customRuleDraft.pattern, onChange: (event) => setCustomRuleDraft((prev) => ({ ...prev, pattern: event.target.value })), placeholder: tr("token=([A-Za-z0-9._-]+)") })] }), _jsxs("div", { style: { minWidth: "140px" }, children: [_jsx("label", { className: "microcopy", htmlFor: "custom-flags", children: tr("Flags") }), _jsx("input", { id: "custom-flags", className: "input", value: customRuleDraft.flags, onChange: (event) => setCustomRuleDraft((prev) => ({ ...prev, flags: event.target.value })), placeholder: tr("gi") })] }), _jsxs("div", { style: { flex: 1, minWidth: "160px" }, children: [_jsx("label", { className: "microcopy", htmlFor: "custom-replacement", children: tr("Replacement") }), _jsx("input", { id: "custom-replacement", className: "input", value: customRuleDraft.replacement, onChange: (event) => setCustomRuleDraft((prev) => ({ ...prev, replacement: event.target.value })), placeholder: tr("[redacted]") })] }), _jsxs("div", { style: { minWidth: "150px" }, children: [_jsx("label", { className: "microcopy", htmlFor: "custom-scope", children: tr("Scope") }), _jsxs("select", { id: "custom-scope", className: "select", value: customRuleDraft.scope, onChange: (event) => setCustomRuleDraft((prev) => ({ ...prev, scope: event.target.value })), children: [_jsx("option", { value: "both", children: tr("text + json") }), _jsx("option", { value: "text", children: tr("text only") }), _jsx("option", { value: "json", children: tr("json only") })] })] }), _jsx("button", { className: "button", type: "button", onClick: addCustomRule, children: tr("add rule") })] }), customRuleError && _jsx("div", { className: "microcopy", style: { color: "var(--danger)" }, children: customRuleError }), customRules.length === 0 ? (_jsx("div", { className: "microcopy", children: tr("no custom rules") })) : (_jsx("ul", { className: "note-list", children: customRules.map((rule) => (_jsxs("li", { children: [_jsxs("div", { className: "note-title", children: ["/", rule.pattern, "/", rule.flags] }), _jsxs("div", { className: "note-body", children: ["\u2192 ", rule.replacement || tr("[empty]"), " (", tr(rule.scope), ")"] }), _jsx("button", { className: "button", type: "button", onClick: () => removeCustomRule(rule.id), children: tr("remove") })] }, rule.id))) }))] })] }), _jsxs("div", { className: "panel", "aria-label": tr("Policy simulation matrix"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("Policy simulation matrix") }), _jsx("span", { className: "panel-subtext", children: tr("compare policy outcomes") })] }), _jsx("p", { className: "microcopy", children: tr("Runs multiple policy variants against current input so you can compare redaction depth before sharing.") }), _jsxs("table", { className: "table", children: [_jsx("thead", { children: _jsxs("tr", { children: [_jsx("th", { children: tr("variant") }), _jsx("th", { children: tr("rules applied") }), _jsx("th", { children: tr("lines changed") }), _jsx("th", { children: tr("output chars") })] }) }), _jsx("tbody", { children: simulationRows.map((row) => (_jsxs("tr", { children: [_jsx("td", { children: tr(row.label) }), _jsx("td", { children: row.appliedRules }), _jsx("td", { children: row.linesAffected }), _jsx("td", { children: row.outputChars })] }, row.id))) })] })] }), _jsxs("div", { className: "grid-two", children: [_jsxs("div", { className: "panel", "aria-label": tr("Policy packs"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("Policy packs") }), _jsx("span", { className: "panel-subtext", children: tr("local-only reusable configs") })] }), _jsxs("div", { className: "controls-row", children: [_jsx("input", { className: "input", placeholder: tr("policy name"), value: policyName, onChange: (event) => setPolicyName(event.target.value), "aria-label": tr("Policy name") }), _jsx("button", { className: "button", type: "button", onClick: savePolicyPack, children: tr("save") })] }), _jsxs("div", { className: "controls-row", children: [_jsxs("select", { className: "select", "aria-label": tr("Saved policy packs"), value: selectedPolicyId, onChange: (event) => setSelectedPolicyId(event.target.value), children: [_jsx("option", { value: "", children: tr("select policy...") }), policyPacks.map((pack) => (_jsx("option", { value: pack.id, children: pack.name }, pack.id)))] }), _jsx("button", { className: "button", type: "button", onClick: () => selectedPolicy && applyPolicyPack(selectedPolicy), disabled: !selectedPolicy, children: tr("apply") }), _jsx("button", { className: "button", type: "button", onClick: deletePolicyPack, disabled: !selectedPolicy, children: tr("delete") })] }), _jsxs("div", { className: "controls-row", children: [_jsx("button", { className: "button", type: "button", onClick: () => openPolicyExportDialog(selectedPolicy), disabled: !selectedPolicy, children: tr("export selected") }), _jsx("button", { className: "button", type: "button", onClick: () => openPolicyExportDialog(selectedPolicy, true), disabled: !selectedPolicy, children: tr("export with HMAC") }), _jsx("button", { className: "button", type: "button", onClick: () => openPolicyExportDialog(null), disabled: policyPacks.length === 0, children: tr("export all") }), _jsx("button", { className: "button", type: "button", onClick: () => policyImportRef.current?.click(), children: tr("import") }), _jsx("button", { className: "button", type: "button", onClick: () => baselineImportRef.current?.click(), children: tr("import baseline") }), _jsx("input", { ref: policyImportRef, type: "file", accept: "application/json", style: { position: "absolute", opacity: 0, width: 1, height: 1, pointerEvents: "none" }, tabIndex: -1, onChange: (event) => {
                                            void beginPolicyImport(event.target.files?.[0] ?? null);
                                            event.target.value = "";
                                        } }), _jsx("input", { ref: baselineImportRef, type: "file", accept: "application/json", style: { position: "absolute", opacity: 0, width: 1, height: 1, pointerEvents: "none" }, tabIndex: -1, onChange: (event) => {
                                            void importWorkspaceBaseline(event.target.files?.[0] ?? null);
                                            event.target.value = "";
                                        } })] }), _jsx("div", { className: "microcopy", children: tr("Packs with HMAC metadata require verification before import. Baseline import accepts `nullid.policy.json` and merges with deterministic rules.") }), _jsxs("div", { className: "note-box", children: [_jsx("div", { className: "section-title", children: tr("Verification key hints") }), _jsxs("div", { className: "controls-row", children: [_jsx("input", { className: "input", placeholder: tr("profile name"), value: keyProfileName, onChange: (event) => setKeyProfileName(event.target.value), "aria-label": tr("Key hint profile name") }), _jsx("input", { className: "input", placeholder: tr("key hint (public label)"), value: keyProfileHint, onChange: (event) => setKeyProfileHint(event.target.value), "aria-label": tr("Key hint value") }), _jsx("button", { className: "button", type: "button", onClick: saveKeyHintProfile, children: tr("save hint") })] }), _jsxs("div", { className: "controls-row", children: [_jsxs("select", { className: "select", "aria-label": tr("Saved key hint profiles"), value: selectedKeyHintProfileId, onChange: (event) => setSelectedKeyHintProfileId(event.target.value), children: [_jsx("option", { value: "", children: tr("select key hint profile...") }), keyHintProfiles.map((profile) => (_jsxs("option", { value: profile.id, children: [profile.name, " \u00B7 ", profile.keyHint] }, profile.id)))] }), _jsx("button", { className: "button", type: "button", onClick: rotateSelectedKeyHintProfile, disabled: !selectedKeyHintProfile, children: tr("rotate hint") }), _jsx("button", { className: "button", type: "button", onClick: deleteSelectedKeyHintProfile, disabled: !selectedKeyHintProfile, children: tr("delete hint") })] }), _jsxs("div", { className: "microcopy", children: [tr("Hints are local labels only; HMAC/verification passphrases are never stored."), selectedKeyHintProfile ? ` ${tr("active")}: ${selectedKeyHintProfile.name} (v${selectedKeyHintProfile.version})` : ""] })] })] }), _jsxs("div", { className: "panel", "aria-label": tr("Batch sanitize"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("Batch sanitize") }), _jsx("span", { className: "panel-subtext", children: tr("free local processing") })] }), _jsxs("div", { className: "controls-row", children: [_jsx("button", { className: "button", type: "button", onClick: () => batchFileInputRef.current?.click(), disabled: isBatching, children: isBatching ? tr("processing...") : tr("select files") }), _jsx("input", { ref: batchFileInputRef, type: "file", multiple: true, accept: ".txt,.log,.json,text/*,application/json", style: { position: "absolute", opacity: 0, width: 1, height: 1, pointerEvents: "none" }, tabIndex: -1, onChange: (event) => {
                                            void runBatch(event.target.files);
                                            event.target.value = "";
                                        } }), _jsx("button", { className: "button", type: "button", onClick: downloadBatchOutputs, disabled: batchResults.length === 0, children: tr("download outputs") }), _jsx("button", { className: "button", type: "button", onClick: exportBatchReport, disabled: batchResults.length === 0, children: tr("export report") })] }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: tr("files processed") }), _jsx("span", { className: "tag tag-accent", children: formatNumber(batchResults.length) })] }), batchResults.length > 0 && (_jsxs("table", { className: "table", children: [_jsx("thead", { children: _jsxs("tr", { children: [_jsx("th", { children: tr("file") }), _jsx("th", { children: tr("lines changed") }), _jsx("th", { children: tr("size delta") })] }) }), _jsx("tbody", { children: batchResults.slice(0, 8).map((item) => (_jsxs("tr", { children: [_jsx("td", { children: item.name }), _jsx("td", { children: item.linesAffected }), _jsx("td", { children: item.outputChars - item.inputChars })] }, item.name))) })] }))] })] }), _jsxs("div", { className: "panel", "aria-label": tr("Safe share bundle"), children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: tr("Safe share bundle") }), _jsx("span", { className: "panel-subtext", children: tr("manifest + hash + sanitized output") })] }), _jsx("p", { className: "microcopy", children: tr("Generates a portable local bundle containing sanitized output, policy snapshot, and SHA-256 integrity hashes.") }), _jsxs("div", { className: "controls-row", children: [_jsx("input", { className: "input", type: "password", placeholder: tr("optional passphrase to encrypt bundle"), value: bundlePassphrase, onChange: (event) => setBundlePassphrase(event.target.value), "aria-label": tr("Bundle encryption passphrase") }), _jsx("button", { className: "button", type: "button", onClick: () => void exportShareBundle(), disabled: isExportingBundle || !result.output, children: isExportingBundle ? tr("exporting...") : bundlePassphrase ? tr("export encrypted bundle") : tr("export bundle") })] })] }), _jsxs(ActionDialog, { open: policyExportDialogOpen, title: policyExportTarget ? `${tr("Export policy")}: ${policyExportTarget.name}` : tr("Export policy packs"), description: tr("Policy exports can include HMAC metadata. Entering a passphrase prepares the export; actual verification happens on import."), confirmLabel: policyExportTarget ? tr("export policy") : tr("export policies"), onCancel: closePolicyExportDialog, onConfirm: () => void confirmPolicyExport(), confirmDisabled: policyExportSigned && !policyExportPassphrase.trim(), children: [_jsxs("label", { className: "action-dialog-field", children: [_jsx("span", { children: tr("Add HMAC metadata") }), _jsx("input", { type: "checkbox", checked: policyExportSigned, onChange: (event) => setPolicyExportSigned(event.target.checked), "aria-label": tr("Policy HMAC metadata") })] }), policyExportSigned ? (_jsxs(_Fragment, { children: [_jsxs("div", { className: "status-line", children: [_jsx("span", { children: tr("verification state") }), _jsx("span", { className: policyPackTrustTagClass(policyExportTrustState), children: tr(formatPolicyPackTrustState(policyExportTrustState)) }), policyExportKeyHint.trim() ? _jsxs("span", { className: "microcopy", children: [tr("hint"), ": ", policyExportKeyHint.trim()] }) : null] }), _jsxs("label", { className: "action-dialog-field", children: [_jsx("span", { children: tr("HMAC passphrase") }), _jsx("input", { className: "action-dialog-input", type: "password", value: policyExportPassphrase, onChange: (event) => {
                                            setPolicyExportPassphrase(event.target.value);
                                            if (policyExportError)
                                                setPolicyExportError(null);
                                        }, "aria-label": tr("Policy HMAC passphrase"), placeholder: tr("required when HMAC metadata is enabled") })] }), _jsxs("div", { className: "action-dialog-row", children: [_jsxs("label", { className: "action-dialog-field", children: [_jsx("span", { children: tr("Saved key hint") }), _jsxs("select", { className: "action-dialog-select", value: selectedKeyHintProfileId, onChange: (event) => {
                                                    const nextId = event.target.value;
                                                    setSelectedKeyHintProfileId(nextId);
                                                    const profile = keyHintProfiles.find((entry) => entry.id === nextId);
                                                    setPolicyExportKeyHint(profile?.keyHint ?? "");
                                                }, "aria-label": tr("Policy key hint profile"), children: [_jsx("option", { value: "", children: tr("custom key hint") }), keyHintProfiles.map((profile) => (_jsxs("option", { value: profile.id, children: [profile.name, " \u00B7 ", profile.keyHint] }, profile.id)))] })] }), _jsxs("label", { className: "action-dialog-field", children: [_jsx("span", { children: tr("Key hint label") }), _jsx("input", { className: "action-dialog-input", value: policyExportKeyHint, onChange: (event) => setPolicyExportKeyHint(event.target.value), "aria-label": tr("Policy key hint"), placeholder: tr("optional verification hint") })] })] }), _jsxs("p", { className: "action-dialog-note", children: [tr("Hints are local labels only; passphrases are never stored."), selectedKeyHintProfile ? ` ${tr("active")}: ${selectedKeyHintProfile.name} (v${selectedKeyHintProfile.version})` : ""] })] })) : (_jsx("p", { className: "action-dialog-note", children: tr("Unsigned packs can be imported, but authenticity verification is unavailable.") })), policyExportError ? _jsx("p", { className: "action-dialog-error", children: policyExportError }) : null] }), _jsxs(ActionDialog, { open: policyImportDialogOpen, title: tr("Import policy pack"), description: pendingPolicyImport
                    ? `${pendingPolicyImport.descriptor.packCount} ${tr("packs")} · ${tr("schema")} ${pendingPolicyImport.descriptor.schemaVersion || tr("unknown")}`
                    : tr("Verify before import"), confirmLabel: tr("import policy pack"), onCancel: closePolicyImportDialog, onConfirm: () => void confirmPolicyImport(), children: [pendingPolicyImport?.descriptor.signed ? (_jsxs(_Fragment, { children: [_jsxs("div", { className: "status-line", children: [_jsx("span", { children: tr("verification state") }), _jsx("span", { className: policyPackTrustTagClass(policyImportTrustState), children: tr(formatPolicyPackTrustState(policyImportTrustState)) }), pendingPolicyImport.descriptor.keyHint ? _jsxs("span", { className: "microcopy", children: [tr("hint"), ": ", pendingPolicyImport.descriptor.keyHint] }) : null] }), _jsxs("p", { className: "action-dialog-note", children: [tr("HMAC-protected pack detected"), pendingPolicyImport.descriptor.keyHint ? ` (${tr("hint")}: ${pendingPolicyImport.descriptor.keyHint})` : "", ". ", tr("Verification is required before import.")] }), _jsxs("label", { className: "action-dialog-field", children: [_jsx("span", { children: tr("Verification passphrase") }), _jsx("input", { className: "action-dialog-input", type: "password", value: policyImportPassphrase, onChange: (event) => {
                                            setPolicyImportPassphrase(event.target.value);
                                            if (policyImportError)
                                                setPolicyImportError(null);
                                        }, "aria-label": tr("Policy verification passphrase"), placeholder: tr("required for HMAC-protected packs") })] })] })) : (_jsxs(_Fragment, { children: [_jsxs("div", { className: "status-line", children: [_jsx("span", { children: tr("verification state") }), _jsx("span", { className: policyPackTrustTagClass(policyImportTrustState), children: tr(formatPolicyPackTrustState(policyImportTrustState)) })] }), _jsx("p", { className: "action-dialog-note", children: tr("Unsigned policy pack. Continue only if you trust the source.") })] })), policyImportError ? _jsx("p", { className: "action-dialog-error", children: policyImportError }) : null] })] }));
}
function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    link.rel = "noopener";
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1200);
}
function sanitizeFileStem(value) {
    const base = value.replace(/\.[^.]+$/, "").trim();
    return (base || "nullid").replace(/[^a-z0-9_-]+/gi, "-").replace(/-+/g, "-");
}
function highlightDiff(before, after) {
    if (before === after)
        return after;
    const beforeTokens = before.split(/(\s+)/);
    const afterTokens = after.split(/(\s+)/);
    return afterTokens.map((token, index) => {
        if (token === beforeTokens[index])
            return token;
        return (_jsx("mark", { className: "highlight medium", children: token }, index));
    });
}
