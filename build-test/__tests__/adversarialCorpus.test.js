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
    it("handles oversized TIFF value declarations without throwing", () => {
        const bytes = new Uint8Array(32);
        const view = new DataView(bytes.buffer);
        writeAscii(bytes, 0, "II*\0");
        view.setUint32(4, 8, true);
        view.setUint16(8, 1, true);
        view.setUint16(10, 0x010f, true);
        view.setUint16(12, 2, true);
        view.setUint32(14, 0xffffffff, true);
        view.setUint32(18, 24, true);
        view.setUint32(22, 0, true);
        const parsed = inspectMetadataFromBuffer("image/tiff", bytes);
        assert.equal(Object.keys(parsed).length, 0);
    });
    it("parses uncommon vendor tags from nested EXIF IFD blocks", () => {
        const bytes = buildVendorTiffSample();
        const parsed = inspectMetadataFromBuffer("image/tiff", bytes);
        assert.equal(parsed.make, "ACME");
        assert.equal(parsed.lensModel, "LENS-X");
        assert.equal(parsed.bodySerialNumber, "SN123");
        assert.equal(parsed.offsetTimeOriginal, "+01:00");
    });
    it("handles self-referential EXIF pointers without looping", () => {
        const bytes = buildVendorTiffSample();
        const view = new DataView(bytes.buffer);
        view.setUint32(30, 8, true); // Tag 0x8769 points back to IFD0.
        const parsed = inspectMetadataFromBuffer("image/tiff", bytes);
        assert.equal(parsed.make, "ACME");
    });
    it("extracts vendor-oriented PNG text keys", () => {
        const vendorKey = "Raw profile type exif";
        const textPayload = new Uint8Array([...ascii(vendorKey), 0x00, ...ascii("preview")]);
        const png = concatBytes(Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), makePngChunk("tEXt", textPayload), makePngChunk("IEND", new Uint8Array(0)));
        const parsed = inspectMetadataFromBuffer("image/png", png);
        assert.equal(parsed.textKeys, vendorKey);
        assert.equal(parsed.vendorTextKeys, vendorKey);
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
function buildVendorTiffSample() {
    const bytes = new Uint8Array(112);
    const view = new DataView(bytes.buffer);
    writeAscii(bytes, 0, "II*\0");
    view.setUint32(4, 8, true);
    view.setUint16(8, 2, true);
    view.setUint16(10, 0x010f, true);
    view.setUint16(12, 2, true);
    view.setUint32(14, 5, true);
    view.setUint32(18, 80, true);
    view.setUint16(22, 0x8769, true);
    view.setUint16(24, 4, true);
    view.setUint32(26, 1, true);
    view.setUint32(30, 38, true);
    view.setUint32(34, 0, true);
    view.setUint16(38, 3, true);
    view.setUint16(40, 0xa434, true);
    view.setUint16(42, 2, true);
    view.setUint32(44, 7, true);
    view.setUint32(48, 85, true);
    view.setUint16(52, 0xa431, true);
    view.setUint16(54, 2, true);
    view.setUint32(56, 6, true);
    view.setUint32(60, 92, true);
    view.setUint16(64, 0x9011, true);
    view.setUint16(66, 2, true);
    view.setUint32(68, 7, true);
    view.setUint32(72, 98, true);
    view.setUint32(76, 0, true);
    writeAscii(bytes, 80, "ACME\0");
    writeAscii(bytes, 85, "LENS-X\0");
    writeAscii(bytes, 92, "SN123\0");
    writeAscii(bytes, 98, "+01:00\0");
    return bytes;
}
function makePngChunk(type, data) {
    const chunk = new Uint8Array(12 + data.length);
    const view = new DataView(chunk.buffer);
    view.setUint32(0, data.length, false);
    writeAscii(chunk, 4, type);
    chunk.set(data, 8);
    // CRC is intentionally not validated by parser; zero keeps fixture compact.
    view.setUint32(8 + data.length, 0, false);
    return chunk;
}
function concatBytes(...parts) {
    const total = parts.reduce((sum, part) => sum + part.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    parts.forEach((part) => {
        out.set(part, offset);
        offset += part.length;
    });
    return out;
}
function writeAscii(target, offset, value) {
    const source = ascii(value);
    target.set(source, offset);
}
function ascii(value) {
    return Uint8Array.from(value.split("").map((char) => char.charCodeAt(0)));
}
