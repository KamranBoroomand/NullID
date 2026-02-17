import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  analyzeMetadataFromBuffer,
  detectMetadataFormat,
  sanitizePdfMetadataBuffer,
} from "../utils/metadataAdvanced.js";

describe("metadata advanced", () => {
  it("detects OOXML document formats from archive markers", () => {
    const bytes = concatBytes(
      Uint8Array.from([0x50, 0x4b, 0x03, 0x04]),
      ascii("[Content_Types].xml docProps/core.xml word/document.xml"),
    );

    const format = detectMetadataFormat("application/octet-stream", bytes, "sample.bin");
    assert.equal(format, "docx");
  });

  it("analyzes PDF metadata and recommends browser scrub", () => {
    const bytes = latin1(
      "%PDF-1.7\n1 0 obj\n<< /Author (Alice) /Creator (Office) /CreationDate (D:20250101000000Z) /Metadata 2 0 R >>\nendobj\n<x:xmpmeta>private</x:xmpmeta>",
    );
    const analysis = analyzeMetadataFromBuffer("application/pdf", bytes, "report.pdf");

    assert.equal(analysis.format, "pdf");
    assert.equal(analysis.kind, "document");
    assert.equal(analysis.recommendedSanitizer, "browser-pdf");
    assert.equal(analysis.risk, "high");
    assert.equal(analysis.signals.some((signal) => signal.label === "Author identity"), true);
  });

  it("scrubs common PDF metadata fields without changing byte length", () => {
    const inputText =
      "%PDF-1.7\n1 0 obj\n<< /Author (Alice Example) /Creator (NullOffice) /CreationDate (D:20250101000000Z) /Metadata 12 0 R >>\nendobj\n<x:xmpmeta>secret</x:xmpmeta>\n";
    const input = latin1(inputText);
    const result = sanitizePdfMetadataBuffer(input);
    const output = decodeLatin1(result.cleanedBytes);

    assert.equal(result.changed, true);
    assert.equal(result.cleanedBytes.length, input.length);
    assert.equal(result.actions.some((item) => item.startsWith("info-fields:")), true);
    assert.equal(output.includes("Alice Example"), false);
    assert.equal(output.includes("<x:xmpmeta>"), false);
  });

  it("detects video metadata hints and suggests external sanitization command", () => {
    const bytes = concatBytes(
      Uint8Array.from([0x00, 0x00, 0x00, 0x14, 0x66, 0x74, 0x79, 0x70, 0x6d, 0x70, 0x34, 0x32]),
      ascii("com.apple.quicktime.location.ISO6709"),
    );
    const analysis = analyzeMetadataFromBuffer("video/mp4", bytes, "clip.mp4");

    assert.equal(analysis.kind, "video");
    assert.equal(analysis.recommendedSanitizer, "mat2");
    assert.equal((analysis.commandHint || "").includes("ffmpeg"), true);
  });
});

function ascii(value: string) {
  return Uint8Array.from(value.split("").map((char) => char.charCodeAt(0)));
}

function latin1(value: string) {
  const out = new Uint8Array(value.length);
  for (let i = 0; i < value.length; i += 1) {
    out[i] = value.charCodeAt(i) & 0xff;
  }
  return out;
}

function decodeLatin1(value: Uint8Array) {
  return new TextDecoder("latin1").decode(value);
}

function concatBytes(...parts: Uint8Array[]) {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  parts.forEach((part) => {
    out.set(part, offset);
    offset += part.length;
  });
  return out;
}
