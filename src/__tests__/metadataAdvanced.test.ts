import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import {
  analyzeMetadataFromBuffer,
  detectMetadataFormat,
  sanitizePdfMetadataBuffer,
} from "../utils/metadataAdvanced.js";
import { assertEncodedImageCanvasBudget, assertImageCanvasBudget, sanitizeBrowserImage } from "../utils/metadataCleaning.js";

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

  it("builds explicit review sections for metadata exposure guidance", () => {
    const bytes = latin1(
      "%PDF-1.7\n1 0 obj\n<< /Author (Alice) /Creator (Office) /CreationDate (D:20250101000000Z) /Metadata 2 0 R >>\nendobj\n<x:xmpmeta>private</x:xmpmeta>",
    );
    const analysis = analyzeMetadataFromBuffer("application/pdf", bytes, "report.pdf");

    assert.equal(analysis.reviewSections.some((section) => section.id === "metadata-found"), true);
    assert.equal(analysis.reviewSections.some((section) => section.id === "removable-locally"), true);
    assert.equal(analysis.reviewSections.some((section) => section.id === "review-recommendations"), true);
    assert.equal(analysis.metadataFound.length > 0, true);
  });

  it("rejects unresolved or delayed encoded image dimensions before browser decode", async () => {
    const delayedJpeg = buildDelayedJpegSof(300 * 1024, 65_535, 65_535);
    await assert.rejects(
      () => assertEncodedImageCanvasBudget(new Blob([delayedJpeg], { type: "image/jpeg" })),
      /dimension|jpeg|unresolved|canvas|safety/i,
    );

    const truncatedApp = concatBytes(
      Uint8Array.from([0xff, 0xd8, 0xff, 0xe1, 0xff, 0xff]),
      new Uint8Array(64),
    );
    await assert.rejects(
      () => assertEncodedImageCanvasBudget(new Blob([truncatedApp], { type: "image/jpeg" })),
      /dimension|jpeg|truncated|malformed|canvas|safety/i,
    );
  });

  it("enforces encoded image dimension boundaries for every supported browser format", async () => {
    const cases = [
      { label: "png huge side", type: "image/png", bytes: buildPngHeader(16_385, 16) },
      { label: "png zero", type: "image/png", bytes: buildPngHeader(0, 10) },
      { label: "gif huge pixels", type: "image/gif", bytes: buildGifHeader(16_384, 16_384) },
      { label: "gif zero", type: "image/gif", bytes: buildGifHeader(0, 10) },
      { label: "webp huge side", type: "image/webp", bytes: buildWebpVp8xHeader(16_385, 10) },
      { label: "webp vp8l huge pixels", type: "image/webp", bytes: buildWebpVp8lHeader(16_384, 16_384) },
      { label: "webp vp8l malformed", type: "image/webp", bytes: buildWebpVp8lHeader(10, 10).slice(0, 24) },
      { label: "bmp huge side", type: "image/bmp", bytes: buildBmpHeader(16_385, 10) },
      { label: "jpeg huge side", type: "image/jpeg", bytes: buildJpegSof(16_385, 10) },
      { label: "unsupported image", type: "image/x-nullid-test", bytes: ascii("NOTANIMAGE") },
    ];

    for (const testCase of cases) {
      await assert.rejects(
        () => assertEncodedImageCanvasBudget(new Blob([testCase.bytes], { type: testCase.type })),
        /dimension|unresolved|unsupported|canvas|safety|invalid/i,
        testCase.label,
      );
    }

    await assert.doesNotReject(() => assertEncodedImageCanvasBudget(new Blob([buildPngHeader(16_384, 1)], { type: "image/png" })));
    await assert.doesNotReject(() => assertEncodedImageCanvasBudget(new Blob([buildWebpVp8lHeader(10, 10)], { type: "image/webp" })));
    await assert.doesNotReject(() => assertEncodedImageCanvasBudget(new Blob([buildWebpVp8lHeader(16_384, 1)], { type: "image/webp" })));
    assert.throws(() => assertImageCanvasBudget(8_000, 8_000), /canvas safety/i);
  });

  it("uses the shared metadata cleaning utility for every browser image-cleaning workflow", () => {
    const cleaningSource = fs.readFileSync("src/utils/metadataCleaning.ts", "utf8");
    const metaViewSource = fs.readFileSync("src/views/MetaView.tsx", "utf8");
    const localArtifactSource = fs.readFileSync("src/utils/localArtifactPreparation.ts", "utf8");

    assert.match(cleaningSource, /assertImageCanvasBudget|MAX_IMAGE_PIXELS|decoded image/u);
    assert.equal(typeof sanitizeBrowserImage, "function");
    assert.match(metaViewSource, /sanitizeBrowserImage/u);
    assert.match(localArtifactSource, /sanitizeBrowserImage/u);
    assert.doesNotMatch(metaViewSource, /async function renderCleanImage/u);
    assert.doesNotMatch(metaViewSource, /function loadImage/u);
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

function buildPngHeader(width: number, height: number) {
  const bytes = new Uint8Array(24);
  bytes.set([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], 0);
  bytes.set(ascii("IHDR"), 12);
  writeUint32BE(bytes, 16, width);
  writeUint32BE(bytes, 20, height);
  return bytes;
}

function buildGifHeader(width: number, height: number) {
  const bytes = new Uint8Array(10);
  bytes.set(ascii("GIF89a"), 0);
  writeUint16LE(bytes, 6, width);
  writeUint16LE(bytes, 8, height);
  return bytes;
}

function buildWebpVp8xHeader(width: number, height: number) {
  const bytes = new Uint8Array(30);
  bytes.set(ascii("RIFF"), 0);
  bytes.set(ascii("WEBP"), 8);
  bytes.set(ascii("VP8X"), 12);
  writeUint24LE(bytes, 24, width - 1);
  writeUint24LE(bytes, 27, height - 1);
  return bytes;
}

function buildWebpVp8lHeader(width: number, height: number) {
  const bytes = new Uint8Array(25);
  bytes.set(ascii("RIFF"), 0);
  bytes.set(ascii("WEBP"), 8);
  bytes.set(ascii("VP8L"), 12);
  writeUint32LE(bytes, 16, 5);
  bytes[20] = 0x2f;
  const encodedWidth = Math.max(0, width - 1);
  const encodedHeight = Math.max(0, height - 1);
  bytes[21] = encodedWidth & 0xff;
  bytes[22] = ((encodedWidth >>> 8) & 0x3f) | ((encodedHeight & 0x03) << 6);
  bytes[23] = (encodedHeight >>> 2) & 0xff;
  bytes[24] = (encodedHeight >>> 10) & 0x0f;
  return bytes;
}

function buildBmpHeader(width: number, height: number) {
  const bytes = new Uint8Array(26);
  bytes.set(ascii("BM"), 0);
  writeInt32LE(bytes, 18, width);
  writeInt32LE(bytes, 22, height);
  return bytes;
}

function buildJpegSof(width: number, height: number) {
  const bytes = new Uint8Array(13);
  bytes.set([0xff, 0xd8, 0xff, 0xc0, 0x00, 0x08, 0x08], 0);
  writeUint16BE(bytes, 7, height);
  writeUint16BE(bytes, 9, width);
  bytes.set([0x01, 0x11], 11);
  return bytes;
}

function buildDelayedJpegSof(paddingBytes: number, width: number, height: number) {
  const chunks: Uint8Array[] = [Uint8Array.from([0xff, 0xd8])];
  let remaining = paddingBytes;
  while (remaining > 0) {
    const payloadLength = Math.min(remaining, 65_000);
    const segment = new Uint8Array(payloadLength + 4);
    segment.set([0xff, 0xe1], 0);
    writeUint16BE(segment, 2, payloadLength + 2);
    chunks.push(segment);
    remaining -= payloadLength;
  }
  chunks.push(buildJpegSof(width, height).slice(2));
  return concatBytes(...chunks);
}

function writeUint16BE(bytes: Uint8Array, offset: number, value: number) {
  bytes[offset] = (value >>> 8) & 0xff;
  bytes[offset + 1] = value & 0xff;
}

function writeUint16LE(bytes: Uint8Array, offset: number, value: number) {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >>> 8) & 0xff;
}

function writeUint24LE(bytes: Uint8Array, offset: number, value: number) {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >>> 8) & 0xff;
  bytes[offset + 2] = (value >>> 16) & 0xff;
}

function writeUint32BE(bytes: Uint8Array, offset: number, value: number) {
  bytes[offset] = (value / 0x1000000) & 0xff;
  bytes[offset + 1] = (value >>> 16) & 0xff;
  bytes[offset + 2] = (value >>> 8) & 0xff;
  bytes[offset + 3] = value & 0xff;
}

function writeUint32LE(bytes: Uint8Array, offset: number, value: number) {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >>> 8) & 0xff;
  bytes[offset + 2] = (value >>> 16) & 0xff;
  bytes[offset + 3] = (value >>> 24) & 0xff;
}

function writeInt32LE(bytes: Uint8Array, offset: number, value: number) {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >>> 8) & 0xff;
  bytes[offset + 2] = (value >>> 16) & 0xff;
  bytes[offset + 3] = (value >>> 24) & 0xff;
}
