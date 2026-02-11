import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { ENVELOPE_PREFIX, decryptText, encryptText } from "../utils/cryptoEnvelope.js";
import { bytesToUtf8, fromBase64Url, toBase64Url, utf8ToBytes } from "../utils/encoding.js";
import { applySanitizeRules, buildRulesState, normalizePolicyConfig } from "../utils/sanitizeEngine.js";
import { detectImageFormat, inspectMetadataFromBuffer } from "../utils/metadataInspector.js";
describe("adversarial corpus", () => {
    it("handles malformed JPEG metadata payloads without throwing", () => {
        const malformedJpeg = Uint8Array.from([
            0xff,
            0xd8,
            0xff,
            0xe1,
            0x00,
            0x10,
            0x45,
            0x78,
            0x69,
            0x66,
            0x00,
            0x00,
            0x49,
            0x49,
            0x2a,
            0x00,
            0x08,
            0x00,
            0x00,
        ]);
        const format = detectImageFormat("", malformedJpeg);
        assert.equal(format, "jpeg");
        const parsed = inspectMetadataFromBuffer("image/jpeg", malformedJpeg);
        assert.equal(Object.keys(parsed).length, 0);
    });
    it("handles malformed PNG metadata chunks without throwing", () => {
        const malformedPng = Uint8Array.from([
            0x89,
            0x50,
            0x4e,
            0x47,
            0x0d,
            0x0a,
            0x1a,
            0x0a,
            0xff,
            0xff,
            0xff,
            0xff,
            0x65,
            0x58,
            0x49,
            0x66,
        ]);
        const parsed = inspectMetadataFromBuffer("image/png", malformedPng);
        assert.equal(Object.keys(parsed).length, 0);
    });
    it("drops hostile nested-quantifier regex rules during normalization", () => {
        const normalized = normalizePolicyConfig({
            rulesState: buildRulesState([]),
            jsonAware: false,
            customRules: [{ pattern: "(a+)+$", replacement: "[x]", flags: "g", scope: "text" }],
        });
        assert.equal(Boolean(normalized), true);
        assert.equal(normalized?.customRules.length, 0);
    });
    it("skips hostile regex payloads at runtime when injected directly", () => {
        const dangerous = {
            id: "danger",
            pattern: "(a+)+$",
            replacement: "[x]",
            flags: "g",
            scope: "text",
        };
        const input = `${"a".repeat(4096)}!`;
        const result = applySanitizeRules(input, buildRulesState([]), [dangerous], false);
        assert.equal(result.output, input);
        assert.equal(result.report.length, 0);
    });
    it("rejects tampered envelope ciphertext", async () => {
        const blob = await encryptText("tamper-pass", "phase4-payload");
        const encoded = blob.slice(`${ENVELOPE_PREFIX}.`.length);
        const parsed = JSON.parse(bytesToUtf8(fromBase64Url(encoded)));
        const last = parsed.ciphertext.endsWith("A") ? "B" : "A";
        parsed.ciphertext = `${parsed.ciphertext.slice(0, -1)}${last}`;
        const tampered = `${ENVELOPE_PREFIX}.${toBase64Url(utf8ToBytes(JSON.stringify(parsed)))}`;
        await assert.rejects(() => decryptText("tamper-pass", tampered));
    });
    it("rejects malformed envelope payload JSON", async () => {
        const malformed = `${ENVELOPE_PREFIX}.${toBase64Url(utf8ToBytes("{invalid-json"))}`;
        await expectRejects(() => decryptText("irrelevant", malformed), /Invalid envelope format/i);
    });
});
async function expectRejects(fn, pattern) {
    let rejected = false;
    let message = "";
    try {
        await fn();
    }
    catch (error) {
        rejected = true;
        message = error instanceof Error ? error.message : String(error);
    }
    assert.equal(rejected, true);
    assert.equal(pattern.test(message), true);
}
