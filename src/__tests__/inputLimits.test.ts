import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  INPUT_LIMITS,
  assertFileWithinLimit,
  buildDecryptedPreview,
  readFileTextWithLimit,
} from "../utils/inputLimits.js";

describe("input limits", () => {
  it("rejects oversized files before invoking file readers", async () => {
    let read = false;
    const file = {
      name: "large.nullid",
      size: INPUT_LIMITS.envelopeFileBytes + 1,
      text: async () => {
        read = true;
        return "should-not-read";
      },
    } as File;

    await expectRejects(() => readFileTextWithLimit(file, { label: "Envelope", maxBytes: INPUT_LIMITS.envelopeFileBytes }), /file too large/i);
    assert.equal(read, false);
  });

  it("accepts exact file size boundaries", () => {
    assertFileWithinLimit({ name: "boundary.bin", size: INPUT_LIMITS.encryptionFileBytes }, {
      label: "Payload",
      maxBytes: INPUT_LIMITS.encryptionFileBytes,
    });
  });

  it("classifies invalid UTF-8 payloads as binary", () => {
    const preview = buildDecryptedPreview(new Uint8Array([0xff, 0xfe, 0xfd, 0x00]), "application/octet-stream");

    assert.equal(preview.kind, "binary");
    assert.equal(preview.text, "[binary payload]");
  });

  it("renders valid UTF-8 payloads with truncation bounds", () => {
    const bytes = new TextEncoder().encode("hello 😀 world");
    const preview = buildDecryptedPreview(bytes, "text/plain", { maxBytes: 10, maxChars: 20 });

    assert.equal(preview.kind, "text");
    assert.equal(preview.truncated, true);
    assert.match(preview.text, /^hello/);
    assert.match(preview.text, /\[preview truncated\]$/);
  });

  it("does not split a multi-byte character at the preview boundary", () => {
    const bytes = new TextEncoder().encode(`abc${"😀"}def`);
    const preview = buildDecryptedPreview(bytes, "application/json", { maxBytes: 6, maxChars: 20 });

    assert.equal(preview.kind, "text");
    assert.equal(preview.text, "abc\n[preview truncated]");
  });
});

async function expectRejects(fn: () => Promise<unknown>, pattern: RegExp) {
  try {
    await fn();
  } catch (error) {
    assert.match(error instanceof Error ? error.message : String(error), pattern);
    return;
  }
  throw new Error("Expected rejection");
}
