import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useMemo, useRef, useState } from "react";
import "./styles.css";
import { usePersistentState } from "../hooks/usePersistentState";
import { useToast } from "../components/ToastHost";
import { useClipboardPrefs, writeClipboard } from "../utils/clipboard";
import { hashText } from "../utils/hash";
import { encryptText } from "../utils/cryptoEnvelope";
import { mergeSanitizePolicyConfig, normalizeWorkspacePolicyBaseline } from "../utils/policyBaseline";
import { createPolicyPackSnapshot, describePolicyPackPayload, importPolicyPackPayload, mergePolicyPacks } from "../utils/policyPack";
import { applySanitizeRules, buildRulesState, getRuleKeys, getRuleLabel, runBatchSanitize, sanitizePresets, } from "../utils/sanitizeEngine";
const ruleKeys = getRuleKeys();
const presetKeys = Object.keys(sanitizePresets);
const defaultRules = Object.fromEntries(ruleKeys.map((key) => [key, true]));
export function SanitizeView({ onOpenGuide }) {
    const { push } = useToast();
    const [clipboardPrefs] = useClipboardPrefs();
    const [log, setLog] = useState(sanitizePresets.nginx.sample);
    const [rulesState, setRulesState] = usePersistentState("nullid:sanitize:rules", defaultRules);
    const [preset, setPreset] = usePersistentState("nullid:sanitize:preset", "nginx");
    const [wrapLines, setWrapLines] = usePersistentState("nullid:sanitize:wrap", false);
    const [jsonAware, setJsonAware] = usePersistentState("nullid:sanitize:json", true);
    const [customRules, setCustomRules] = usePersistentState("nullid:sanitize:custom", []);
    const [policyPacks, setPolicyPacks] = usePersistentState("nullid:sanitize:policy-packs", []);
    const [keyHintProfiles, setKeyHintProfiles] = usePersistentState("nullid:sanitize:key-hints", []);
    const [selectedKeyHintProfileId, setSelectedKeyHintProfileId] = usePersistentState("nullid:sanitize:key-hint-selected", "");
    const [selectedPolicyId, setSelectedPolicyId] = useState("");
    const [policyName, setPolicyName] = useState("");
    const [keyProfileName, setKeyProfileName] = useState("");
    const [keyProfileHint, setKeyProfileHint] = useState("");
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
    const selectedPolicy = useMemo(() => policyPacks.find((pack) => pack.id === selectedPolicyId) ?? null, [policyPacks, selectedPolicyId]);
    const selectedKeyHintProfile = useMemo(() => keyHintProfiles.find((profile) => profile.id === selectedKeyHintProfileId) ?? null, [keyHintProfiles, selectedKeyHintProfileId]);
    const applyPreset = (key) => {
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
    const exportPolicyPack = async (pack, forceSigned = false) => {
        const sourcePacks = pack ? [pack] : policyPacks;
        if (sourcePacks.length === 0) {
            push("no policy packs to export", "danger");
            return;
        }
        try {
            let signingPassphrase;
            let keyHint;
            if (forceSigned || confirm("Sign policy pack metadata with a passphrase?")) {
                const pass = prompt("Signing passphrase:");
                if (!pass) {
                    push("policy export cancelled", "neutral");
                    return;
                }
                signingPassphrase = pass;
                const suggestedHint = selectedKeyHintProfile?.keyHint ?? "";
                const hintPrompt = selectedKeyHintProfile
                    ? `Optional key hint (${selectedKeyHintProfile.name}):`
                    : "Optional key hint (for verification):";
                keyHint = sanitizeKeyHint(prompt(hintPrompt, suggestedHint) ?? undefined);
            }
            const payload = await createPolicyPackSnapshot(sourcePacks, { signingPassphrase, keyHint });
            const safe = sanitizeFileStem(pack?.name ?? "sanitize-policy-packs");
            const suffix = payload.signature ? "-signed" : "";
            downloadBlob(new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" }), `${safe}${suffix}.json`);
            push(pack ? `policy exported${payload.signature ? " (signed)" : ""}` : `all policies exported${payload.signature ? " (signed)" : ""}`, "accent");
        }
        catch (error) {
            console.error(error);
            push("policy export failed", "danger");
        }
    };
    const importPolicyPack = async (file) => {
        if (!file)
            return;
        try {
            const text = await file.text();
            const parsed = JSON.parse(text);
            const descriptor = describePolicyPackPayload(parsed);
            if (descriptor.kind !== "sanitize-policy-pack" || descriptor.packCount === 0) {
                throw new Error("No valid policy packs found");
            }
            let verificationPassphrase;
            if (descriptor.signed) {
                const proceed = confirm(`Policy pack is signed${descriptor.keyHint ? ` (hint: ${descriptor.keyHint})` : ""}. Verify before import?`);
                if (!proceed) {
                    push("policy import cancelled", "neutral");
                    return;
                }
                verificationPassphrase = prompt("Verification passphrase:") ?? undefined;
                if (!verificationPassphrase) {
                    push("policy import cancelled", "neutral");
                    return;
                }
            }
            else {
                const proceedUnsigned = confirm("Policy pack is unsigned. Import anyway?");
                if (!proceedUnsigned) {
                    push("policy import cancelled", "neutral");
                    return;
                }
            }
            const imported = await importPolicyPackPayload(parsed, {
                verificationPassphrase,
                requireVerified: descriptor.signed,
            });
            setPolicyPacks((prev) => mergePolicyPacks(prev, imported.packs));
            setSelectedPolicyId(imported.packs[0].id);
            setPolicyName(imported.packs[0].name);
            const suffix = imported.legacy ? "legacy" : imported.signed ? imported.verified ? "signed+verified" : "signed" : "unsigned";
            push(`imported ${imported.packs.length} policy pack(s) :: ${suffix}`, "accent");
        }
        catch (error) {
            console.error(error);
            push("policy import failed", "danger");
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
        const name = keyProfileName.trim();
        const keyHint = sanitizeKeyHint(keyProfileHint);
        if (!name || !keyHint) {
            push("profile name + key hint required", "danger");
            return;
        }
        const now = new Date().toISOString();
        let nextSelected = "";
        setKeyHintProfiles((prev) => {
            const existing = prev.find((profile) => profile.name.toLowerCase() === name.toLowerCase());
            if (existing) {
                nextSelected = existing.id;
                return prev.map((profile) => profile.id === existing.id
                    ? {
                        ...profile,
                        name,
                        keyHint,
                        updatedAt: now,
                    }
                    : profile);
            }
            const created = {
                id: crypto.randomUUID(),
                name,
                keyHint,
                version: 1,
                createdAt: now,
                updatedAt: now,
            };
            nextSelected = created.id;
            return [created, ...prev].slice(0, 20);
        });
        setSelectedKeyHintProfileId(nextSelected);
        push("key hint profile saved", "accent");
    };
    const rotateSelectedKeyHintProfile = () => {
        if (!selectedKeyHintProfile)
            return;
        const now = new Date().toISOString();
        const nextVersion = selectedKeyHintProfile.version + 1;
        const nextHint = rotateKeyHint(selectedKeyHintProfile.keyHint, nextVersion);
        setKeyHintProfiles((prev) => prev.map((profile) => profile.id === selectedKeyHintProfile.id
            ? {
                ...profile,
                version: nextVersion,
                keyHint: nextHint,
                updatedAt: now,
            }
            : profile));
        push(`key hint rotated → ${nextHint}`, "accent");
    };
    const deleteSelectedKeyHintProfile = () => {
        if (!selectedKeyHintProfile)
            return;
        setKeyHintProfiles((prev) => prev.filter((profile) => profile.id !== selectedKeyHintProfile.id));
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
        }
        catch (error) {
            console.error(error);
            push("safe-share export failed", "danger");
        }
        finally {
            setIsExportingBundle(false);
        }
    };
    return (_jsxs("div", { className: "workspace-scroll", children: [_jsx("div", { className: "guide-link", children: _jsx("button", { type: "button", className: "guide-link-button", onClick: () => onOpenGuide?.("sanitize"), children: "? guide" }) }), _jsxs("div", { className: "grid-two", children: [_jsxs("div", { className: "panel", "aria-label": "Sanitizer input", children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: "Inbound log" }), _jsx("span", { className: "panel-subtext", children: "raw" })] }), _jsx("textarea", { className: "textarea", value: log, onChange: (event) => setLog(event.target.value), "aria-label": "Log input" }), _jsxs("div", { className: "controls-row", children: [_jsx("span", { className: "section-title", children: "Presets" }), _jsx("div", { className: "pill-buttons", role: "group", "aria-label": "Log presets", children: presetKeys.map((key) => (_jsx("button", { type: "button", className: preset === key ? "active" : "", onClick: () => applyPreset(key), children: sanitizePresets[key].label }, key))) })] })] }), _jsxs("div", { className: "panel", "aria-label": "Sanitized preview", children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: "Preview" }), _jsx("span", { className: "panel-subtext", children: "diff" })] }), _jsxs("div", { className: "log-preview", role: "presentation", children: [_jsxs("div", { className: "log-line", children: [_jsx("span", { className: "log-marker", children: "-" }), _jsx("span", { className: "diff-remove", children: log })] }), _jsxs("div", { className: "log-line", children: [_jsx("span", { className: "log-marker", children: "+" }), _jsx("span", { className: "diff-add", style: { whiteSpace: wrapLines ? "pre-wrap" : "pre" }, children: highlightDiff(log, result.output) })] })] }), _jsxs("div", { className: "controls-row", children: [_jsx("button", { className: "button", type: "button", onClick: () => writeClipboard(result.output, clipboardPrefs, (message, tone) => push(message, tone === "danger" ? "danger" : tone === "accent" ? "accent" : "neutral"), "copied"), disabled: !result.output, children: "copy sanitized" }), _jsx("button", { className: "button", type: "button", onClick: () => downloadBlob(new Blob([result.output], { type: "text/plain" }), "nullid-sanitized.log"), disabled: !result.output, children: "download sanitized" }), _jsxs("label", { className: "microcopy", style: { display: "flex", alignItems: "center", gap: "0.5rem" }, children: [_jsx("input", { type: "checkbox", checked: wrapLines, onChange: (event) => setWrapLines(event.target.checked), "aria-label": "Wrap long lines" }), "wrap long lines"] }), _jsxs("label", { className: "microcopy", style: { display: "flex", alignItems: "center", gap: "0.5rem" }, children: [_jsx("input", { type: "checkbox", checked: jsonAware, onChange: (event) => setJsonAware(event.target.checked), "aria-label": "Enable JSON redaction" }), "JSON-aware redaction"] })] }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: "Rules applied" }), _jsx("span", { className: "tag tag-accent", children: result.applied.length }), _jsxs("span", { className: "microcopy", children: ["lines changed: ", result.linesAffected] })] })] })] }), _jsxs("div", { className: "panel", "aria-label": "Rule toggles", children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: "Rules" }), _jsx("span", { className: "panel-subtext", children: "toggle" })] }), _jsx("div", { className: "rule-grid", children: ruleKeys.map((ruleKey) => (_jsxs("label", { className: "rule-tile", children: [_jsx("input", { type: "checkbox", checked: rulesState[ruleKey], onChange: (event) => setRulesState((prev) => ({ ...prev, [ruleKey]: event.target.checked })), "aria-label": getRuleLabel(ruleKey) }), _jsx("span", { children: getRuleLabel(ruleKey) })] }, ruleKey))) }), _jsxs("div", { className: "note-box", children: [_jsx("div", { className: "section-title", children: "Report" }), _jsx("div", { className: "microcopy", children: result.report.length === 0 ? "no replacements yet" : result.report.map((line) => _jsx("div", { children: line }, line)) })] }), _jsxs("div", { className: "note-box", children: [_jsx("div", { className: "section-title", children: "Custom rules" }), _jsxs("div", { className: "controls-row", style: { alignItems: "flex-end" }, children: [_jsxs("div", { style: { flex: 1, minWidth: "180px" }, children: [_jsx("label", { className: "microcopy", htmlFor: "custom-pattern", children: "Pattern (RegExp)" }), _jsx("input", { id: "custom-pattern", className: "input", value: customRuleDraft.pattern, onChange: (event) => setCustomRuleDraft((prev) => ({ ...prev, pattern: event.target.value })), placeholder: "token=([A-Za-z0-9._-]+)" })] }), _jsxs("div", { style: { minWidth: "140px" }, children: [_jsx("label", { className: "microcopy", htmlFor: "custom-flags", children: "Flags" }), _jsx("input", { id: "custom-flags", className: "input", value: customRuleDraft.flags, onChange: (event) => setCustomRuleDraft((prev) => ({ ...prev, flags: event.target.value })), placeholder: "gi" })] }), _jsxs("div", { style: { flex: 1, minWidth: "160px" }, children: [_jsx("label", { className: "microcopy", htmlFor: "custom-replacement", children: "Replacement" }), _jsx("input", { id: "custom-replacement", className: "input", value: customRuleDraft.replacement, onChange: (event) => setCustomRuleDraft((prev) => ({ ...prev, replacement: event.target.value })), placeholder: "[redacted]" })] }), _jsxs("div", { style: { minWidth: "150px" }, children: [_jsx("label", { className: "microcopy", htmlFor: "custom-scope", children: "Scope" }), _jsxs("select", { id: "custom-scope", className: "select", value: customRuleDraft.scope, onChange: (event) => setCustomRuleDraft((prev) => ({ ...prev, scope: event.target.value })), children: [_jsx("option", { value: "both", children: "text + json" }), _jsx("option", { value: "text", children: "text only" }), _jsx("option", { value: "json", children: "json only" })] })] }), _jsx("button", { className: "button", type: "button", onClick: addCustomRule, children: "add rule" })] }), customRuleError && _jsx("div", { className: "microcopy", style: { color: "var(--danger)" }, children: customRuleError }), customRules.length === 0 ? (_jsx("div", { className: "microcopy", children: "no custom rules" })) : (_jsx("ul", { className: "note-list", children: customRules.map((rule) => (_jsxs("li", { children: [_jsxs("div", { className: "note-title", children: ["/", rule.pattern, "/", rule.flags] }), _jsxs("div", { className: "note-body", children: ["\u2192 ", rule.replacement || "[empty]", " (", rule.scope, ")"] }), _jsx("button", { className: "button", type: "button", onClick: () => removeCustomRule(rule.id), children: "remove" })] }, rule.id))) }))] })] }), _jsxs("div", { className: "grid-two", children: [_jsxs("div", { className: "panel", "aria-label": "Policy packs", children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: "Policy packs" }), _jsx("span", { className: "panel-subtext", children: "local-only reusable configs" })] }), _jsxs("div", { className: "controls-row", children: [_jsx("input", { className: "input", placeholder: "policy name", value: policyName, onChange: (event) => setPolicyName(event.target.value), "aria-label": "Policy name" }), _jsx("button", { className: "button", type: "button", onClick: savePolicyPack, children: "save" })] }), _jsxs("div", { className: "controls-row", children: [_jsxs("select", { className: "select", "aria-label": "Saved policy packs", value: selectedPolicyId, onChange: (event) => setSelectedPolicyId(event.target.value), children: [_jsx("option", { value: "", children: "select policy..." }), policyPacks.map((pack) => (_jsx("option", { value: pack.id, children: pack.name }, pack.id)))] }), _jsx("button", { className: "button", type: "button", onClick: () => selectedPolicy && applyPolicyPack(selectedPolicy), disabled: !selectedPolicy, children: "apply" }), _jsx("button", { className: "button", type: "button", onClick: deletePolicyPack, disabled: !selectedPolicy, children: "delete" })] }), _jsxs("div", { className: "controls-row", children: [_jsx("button", { className: "button", type: "button", onClick: () => void exportPolicyPack(selectedPolicy), disabled: !selectedPolicy, children: "export selected" }), _jsx("button", { className: "button", type: "button", onClick: () => void exportPolicyPack(selectedPolicy, true), disabled: !selectedPolicy, children: "export signed" }), _jsx("button", { className: "button", type: "button", onClick: () => void exportPolicyPack(null), disabled: policyPacks.length === 0, children: "export all" }), _jsx("button", { className: "button", type: "button", onClick: () => policyImportRef.current?.click(), children: "import" }), _jsx("button", { className: "button", type: "button", onClick: () => baselineImportRef.current?.click(), children: "import baseline" }), _jsx("input", { ref: policyImportRef, type: "file", accept: "application/json", style: { position: "absolute", opacity: 0, width: 1, height: 1, pointerEvents: "none" }, tabIndex: -1, onChange: (event) => {
                                            void importPolicyPack(event.target.files?.[0] ?? null);
                                            event.target.value = "";
                                        } }), _jsx("input", { ref: baselineImportRef, type: "file", accept: "application/json", style: { position: "absolute", opacity: 0, width: 1, height: 1, pointerEvents: "none" }, tabIndex: -1, onChange: (event) => {
                                            void importWorkspaceBaseline(event.target.files?.[0] ?? null);
                                            event.target.value = "";
                                        } })] }), _jsx("div", { className: "microcopy", children: "Signed packs require verify-before-import. Baseline import accepts `nullid.policy.json` and merges with deterministic rules." }), _jsxs("div", { className: "note-box", children: [_jsx("div", { className: "section-title", children: "Signing key hints" }), _jsxs("div", { className: "controls-row", children: [_jsx("input", { className: "input", placeholder: "profile name", value: keyProfileName, onChange: (event) => setKeyProfileName(event.target.value), "aria-label": "Key hint profile name" }), _jsx("input", { className: "input", placeholder: "key hint (public label)", value: keyProfileHint, onChange: (event) => setKeyProfileHint(event.target.value), "aria-label": "Key hint value" }), _jsx("button", { className: "button", type: "button", onClick: saveKeyHintProfile, children: "save hint" })] }), _jsxs("div", { className: "controls-row", children: [_jsxs("select", { className: "select", "aria-label": "Saved key hint profiles", value: selectedKeyHintProfileId, onChange: (event) => setSelectedKeyHintProfileId(event.target.value), children: [_jsx("option", { value: "", children: "select key hint profile..." }), keyHintProfiles.map((profile) => (_jsxs("option", { value: profile.id, children: [profile.name, " \u00B7 ", profile.keyHint] }, profile.id)))] }), _jsx("button", { className: "button", type: "button", onClick: rotateSelectedKeyHintProfile, disabled: !selectedKeyHintProfile, children: "rotate hint" }), _jsx("button", { className: "button", type: "button", onClick: deleteSelectedKeyHintProfile, disabled: !selectedKeyHintProfile, children: "delete hint" })] }), _jsxs("div", { className: "microcopy", children: ["Hints are local labels only; signing/verification passphrases are never stored.", selectedKeyHintProfile ? ` Active: ${selectedKeyHintProfile.name} (v${selectedKeyHintProfile.version})` : ""] })] })] }), _jsxs("div", { className: "panel", "aria-label": "Batch sanitize", children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: "Batch sanitize" }), _jsx("span", { className: "panel-subtext", children: "free local processing" })] }), _jsxs("div", { className: "controls-row", children: [_jsx("button", { className: "button", type: "button", onClick: () => batchFileInputRef.current?.click(), disabled: isBatching, children: isBatching ? "processing..." : "select files" }), _jsx("input", { ref: batchFileInputRef, type: "file", multiple: true, accept: ".txt,.log,.json,text/*,application/json", style: { position: "absolute", opacity: 0, width: 1, height: 1, pointerEvents: "none" }, tabIndex: -1, onChange: (event) => {
                                            void runBatch(event.target.files);
                                            event.target.value = "";
                                        } }), _jsx("button", { className: "button", type: "button", onClick: downloadBatchOutputs, disabled: batchResults.length === 0, children: "download outputs" }), _jsx("button", { className: "button", type: "button", onClick: exportBatchReport, disabled: batchResults.length === 0, children: "export report" })] }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: "files processed" }), _jsx("span", { className: "tag tag-accent", children: batchResults.length })] }), batchResults.length > 0 && (_jsxs("table", { className: "table", children: [_jsx("thead", { children: _jsxs("tr", { children: [_jsx("th", { children: "file" }), _jsx("th", { children: "lines changed" }), _jsx("th", { children: "size delta" })] }) }), _jsx("tbody", { children: batchResults.slice(0, 8).map((item) => (_jsxs("tr", { children: [_jsx("td", { children: item.name }), _jsx("td", { children: item.linesAffected }), _jsx("td", { children: item.outputChars - item.inputChars })] }, item.name))) })] }))] })] }), _jsxs("div", { className: "panel", "aria-label": "Safe share bundle", children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: "Safe share bundle" }), _jsx("span", { className: "panel-subtext", children: "manifest + hash + sanitized output" })] }), _jsx("p", { className: "microcopy", children: "Generates a portable local bundle containing sanitized output, policy snapshot, and SHA-256 integrity hashes." }), _jsxs("div", { className: "controls-row", children: [_jsx("input", { className: "input", type: "password", placeholder: "optional passphrase to encrypt bundle", value: bundlePassphrase, onChange: (event) => setBundlePassphrase(event.target.value), "aria-label": "Bundle encryption passphrase" }), _jsx("button", { className: "button", type: "button", onClick: () => void exportShareBundle(), disabled: isExportingBundle || !result.output, children: isExportingBundle ? "exporting..." : bundlePassphrase ? "export encrypted bundle" : "export bundle" })] })] })] }));
}
function sanitizeKeyHint(value) {
    const normalized = (value ?? "").trim();
    return normalized ? normalized.slice(0, 64) : "";
}
function rotateKeyHint(current, nextVersion) {
    const base = current.replace(/-v\d+$/i, "");
    return `${base}-v${nextVersion}`;
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
