import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createPolicyPackSnapshot, importPolicyPackPayload } from "../utils/policyPack.js";
import { buildRulesState } from "../utils/sanitizeEngine.js";
function samplePack(name) {
    return {
        id: crypto.randomUUID(),
        name,
        createdAt: "2026-02-11T00:00:00.000Z",
        config: {
            rulesState: buildRulesState(["maskIp", "maskEmail"]),
            jsonAware: true,
            customRules: [],
        },
    };
}
describe("policy pack integrity", () => {
    it("exports signed packs and verifies on import", async () => {
        const snapshot = await createPolicyPackSnapshot([samplePack("team-default")], {
            signingPassphrase: "policy-secret",
            keyHint: "team-key-v1",
        });
        assert.equal(snapshot.signature?.algorithm, "HMAC-SHA-256");
        const result = await importPolicyPackPayload(snapshot, {
            verificationPassphrase: "policy-secret",
            requireVerified: true,
        });
        assert.equal(result.signed, true);
        assert.equal(result.verified, true);
        assert.equal(result.legacy, false);
        assert.equal(result.packs.length, 1);
    });
    it("rejects tampered payloads", async () => {
        const snapshot = await createPolicyPackSnapshot([samplePack("team-default")], {
            signingPassphrase: "policy-secret",
        });
        const tampered = {
            ...snapshot,
            packs: snapshot.packs.map((pack) => ({
                ...pack,
                config: {
                    ...pack.config,
                    jsonAware: false,
                },
            })),
        };
        await assert.rejects(() => importPolicyPackPayload(tampered, {
            verificationPassphrase: "policy-secret",
        }));
    });
    it("imports legacy policy payloads", async () => {
        const legacy = {
            schemaVersion: 1,
            kind: "sanitize-policy-pack",
            packs: [
                {
                    name: "legacy-pack",
                    createdAt: "2025-01-01T00:00:00.000Z",
                    config: {
                        rulesState: buildRulesState(["maskIp"]),
                        jsonAware: false,
                        customRules: [],
                    },
                },
            ],
        };
        const result = await importPolicyPackPayload(legacy);
        assert.equal(result.legacy, true);
        assert.equal(result.signed, false);
        assert.equal(result.packs.length, 1);
    });
});
