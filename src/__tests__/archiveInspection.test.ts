import { describe, it } from "node:test";
import assert from "node:assert/strict";
import zlib from "node:zlib";
import {
  buildArchiveComparisonReport,
  inspectZipArchiveBytes,
  parseArchiveReferenceDocument,
  verifyArchiveInspection,
} from "../utils/archiveInspection.js";
import { parseZipArchive, readZipEntryBytes, readZipEntryBytesAsync } from "../utils/zipSafety.js";
import { createMinimalOfficeZip, createZip } from "./zipFixtures.js";

describe("archiveInspection", () => {
  it("classifies unsafe and malformed ZIP entries instead of hashing them", async () => {
    const cases: Array<{ label: string; bytes: Uint8Array; status: string; detail: RegExp; path?: string }> = [
      {
        label: "Unix symlink entry",
        bytes: createZip([{ path: "docProps/core.xml", content: Buffer.from("/tmp/victim"), mode: 0o120777 }]),
        status: "rejected",
        detail: /symbolic link/i,
        path: "docProps/core.xml",
      },
      {
        label: "../escape traversal",
        bytes: createZip([{ path: "../escape", content: Buffer.from("x") }]),
        status: "rejected",
        detail: /traversal/i,
      },
      {
        label: "absolute POSIX path",
        bytes: createZip([{ path: "/absolute/path", content: Buffer.from("x") }]),
        status: "rejected",
        detail: /absolute/i,
      },
      {
        label: "Windows drive path",
        bytes: createZip([{ path: "C:\\Users\\victim\\file.txt", content: Buffer.from("x") }]),
        status: "rejected",
        detail: /backslashes/i,
      },
      {
        label: "UNC path",
        bytes: createZip([{ path: "\\\\server\\share\\file.txt", content: Buffer.from("x") }]),
        status: "rejected",
        detail: /backslashes/i,
      },
      {
        label: "duplicate exact path",
        bytes: createZip([
          { path: "same.txt", content: Buffer.from("a") },
          { path: "same.txt", content: Buffer.from("b") },
        ]),
        status: "rejected",
        detail: /duplicate/i,
      },
      {
        label: "case collision path",
        bytes: createZip([
          { path: "Case.txt", content: Buffer.from("a") },
          { path: "case.txt", content: Buffer.from("b") },
        ]),
        status: "rejected",
        detail: /case-folding/i,
      },
      {
        label: "Unicode normalization collision",
        bytes: createZip([
          { path: "cafe\u0301.txt", content: Buffer.from("a") },
          { path: "caf\u00e9.txt", content: Buffer.from("b") },
        ]),
        status: "rejected",
        detail: /unicode-normalization/i,
      },
      {
        label: "file directory collision",
        bytes: createZip([
          { path: "dir", content: Buffer.from("file") },
          { path: "dir/nested.txt", content: Buffer.from("child") },
        ]),
        status: "rejected",
        detail: /conflicts with file/i,
      },
      {
        label: "mismatched local filename",
        bytes: createZip([{ path: "central.txt", localPath: "local.txt", content: Buffer.from("x") }]),
        status: "malformed",
        detail: /filename/i,
      },
      {
        label: "mismatched local method",
        bytes: createZip([{ path: "method.txt", localCompressionMethod: 8, content: Buffer.from("x") }]),
        status: "malformed",
        detail: /method or flags/i,
      },
      {
        label: "declared compressed data past EOF",
        bytes: createZip([{ path: "short.txt", content: Buffer.from("x"), compression: "deflate", compressedSizeOverride: 100 }]),
        status: "malformed",
        detail: /outside|extends/i,
      },
      {
        label: "CRC mismatch",
        bytes: createZip([{ path: "crc.txt", content: Buffer.from("x"), crc32Override: 0 }]),
        status: "malformed",
        detail: /crc32/i,
      },
      {
        label: "decompressed-size mismatch",
        bytes: createZip([{ path: "size.txt", content: Buffer.from("abc"), compression: "deflate", uncompressedSizeOverride: 10 }]),
        status: "malformed",
        detail: /length/i,
      },
      {
        label: "encrypted entry",
        bytes: createZip([{ path: "secret.txt", content: Buffer.from("x"), flags: 0x0001 }]),
        status: "unsupported",
        detail: /encrypted/i,
      },
      {
        label: "unsupported method",
        bytes: createZip([{ path: "method.txt", content: Buffer.from("x"), compressionMethod: 99 }]),
        status: "unsupported",
        detail: /compression method/i,
      },
      {
        label: "excessive entry count",
        bytes: createZip(Array.from({ length: 4097 }, (_unused, index) => ({ path: `f-${index}.txt`, content: new Uint8Array() }))),
        status: "policy-limit",
        detail: /entry count/i,
        path: "(archive)",
      },
      {
        label: "excessive single entry expansion",
        bytes: createZip([{ path: "large.txt", content: Buffer.from("x"), compression: "deflate", uncompressedSizeOverride: 51 * 1024 * 1024 }]),
        status: "policy-limit",
        detail: /exceeds|compression ratio/i,
      },
      {
        label: "extreme compression ratio",
        bytes: createZip([{ path: "ratio.txt", content: Buffer.alloc(4_000, 0x61), compression: "deflate" }]),
        status: "policy-limit",
        detail: /compression ratio/i,
      },
    ];

    for (const testCase of cases) {
      const inspection = await inspectZipArchiveBytes(testCase.bytes);
      const entry = testCase.path
        ? inspection.entries.find((candidate) => candidate.path === testCase.path)
        : inspection.entries.find((candidate) => candidate.status === testCase.status);
      assert.ok(entry, testCase.label);
      assert.equal(entry.status, testCase.status, testCase.label);
      assert.match(entry.detail, testCase.detail, testCase.label);
      assert.equal(inspection.warnings.length > 0, true, testCase.label);
    }
  });

  it("classifies truncated ZIP structures as malformed archives", async () => {
    const valid = Buffer.from(createZip([{ path: "safe.txt", content: Buffer.from("ok") }]));
    const missingEocd = valid.subarray(0, valid.length - 5);
    const truncatedCentral = Buffer.from(valid);
    const eocdOffset = truncatedCentral.length - 22;
    truncatedCentral.writeUInt32LE(eocdOffset - 10, eocdOffset + 16);
    const truncatedLocal = Buffer.from(valid);
    const centralOffset = truncatedLocal.readUInt32LE(eocdOffset + 16);
    truncatedLocal.writeUInt32LE(truncatedLocal.length + 50, centralOffset + 42);

    for (const bytes of [missingEocd, truncatedCentral, truncatedLocal]) {
      const inspection = await inspectZipArchiveBytes(bytes);
      assert.equal(inspection.entries[0].status, "malformed");
      assert.equal(inspection.warnings.length, 1);
    }
  });

  it("applies aggregate expansion limits from the shared ZIP safety policy", () => {
    const parsed = parseZipArchive(
      createZip([
        { path: "one.txt", content: Buffer.from("123") },
        { path: "two.txt", content: Buffer.from("456") },
      ]),
      {
        limits: {
          maxEntries: 10,
          maxNameBytes: 4096,
          maxEntryUncompressedBytes: 10,
          maxArchiveUncompressedBytes: 4,
          maxCompressionRatio: 100,
        },
      },
    );
    const limitedEntry = parsed.entries[1] as unknown as { problem?: { status: string; detail: string } };
    assert.equal(limitedEntry.problem?.status, "policy-limit");
    assert.match(limitedEntry.problem?.detail ?? "", /aggregate/i);
  });

  it("bounds actual deflate output before materializing false-size entries", async () => {
    const actual = Buffer.alloc(4 * 1024 * 1024, 0x61);
    const archive = createZip([
      {
        path: "false-small.txt",
        content: actual,
        compression: "deflate",
        uncompressedSizeOverride: 1,
      },
    ]);
    const parsed = parseZipArchive(archive, {
      limits: {
        maxEntries: 10,
        maxNameBytes: 4096,
        maxEntryUncompressedBytes: 1024,
        maxArchiveUncompressedBytes: 1024,
        maxCompressionRatio: 100,
      },
    });
    const entry = parsed.entries[0];
    let materializedBytes = 0;

    assert.throws(
      () =>
        readZipEntryBytes(archive, entry, (compressed: Uint8Array, _entry: unknown, context?: { maxOutputBytes: number }) => {
          const inflated = zlib.inflateRawSync(Buffer.from(compressed), context ? { maxOutputLength: context.maxOutputBytes } : undefined);
          materializedBytes = inflated.byteLength;
          return inflated;
        }),
      /length|output|decompress/i,
    );
    assert.equal(materializedBytes <= 1024, true);

    let asyncMaterializedBytes = 0;
    await assert.rejects(
      () =>
        readZipEntryBytesAsync(archive, entry, async (_compressed: Uint8Array, _entry: unknown, context?: { maxOutputBytes: number }) => {
          if (context && actual.byteLength > context.maxOutputBytes) {
            throw new Error("bounded async inflate stopped before allocating output");
          }
          asyncMaterializedBytes = actual.byteLength;
          return actual;
        }),
      /length|output|bounded async inflate/i,
    );
    assert.equal(asyncMaterializedBytes <= 1024, true);
  });

  it("enforces actual per-entry and aggregate output limits while reading entries", () => {
    const perEntryArchive = createZip([{ path: "large.txt", content: Buffer.alloc(2048, 0x62), compression: "deflate" }]);
    const perEntryParsed = parseZipArchive(perEntryArchive, {
      limits: {
        maxEntries: 10,
        maxNameBytes: 4096,
        maxEntryUncompressedBytes: 1024,
        maxArchiveUncompressedBytes: 4096,
        maxCompressionRatio: 1000,
      },
    });
    assert.throws(
      () =>
        readZipEntryBytes(perEntryArchive, perEntryParsed.entries[0], (compressed: Uint8Array, _entry: unknown, context?: { maxOutputBytes: number }) =>
          zlib.inflateRawSync(Buffer.from(compressed), context ? { maxOutputLength: context.maxOutputBytes } : undefined),
        ),
      /output|decompress|exceeds/i,
    );

    const aggregateArchive = createZip([
      { path: "one.txt", content: Buffer.alloc(700, 0x63), compression: "deflate", uncompressedSizeOverride: 1 },
      { path: "two.txt", content: Buffer.alloc(700, 0x64), compression: "deflate", uncompressedSizeOverride: 1 },
    ]);
    const aggregateParsed = parseZipArchive(aggregateArchive, {
      limits: {
        maxEntries: 10,
        maxNameBytes: 4096,
        maxEntryUncompressedBytes: 1024,
        maxArchiveUncompressedBytes: 1024,
        maxCompressionRatio: 1000,
      },
    });
    const boundedInflate = (compressed: Uint8Array, _entry: unknown, context?: { maxOutputBytes: number }) =>
      zlib.inflateRawSync(Buffer.from(compressed), context ? { maxOutputLength: context.maxOutputBytes } : undefined);

    assert.throws(() => readZipEntryBytes(aggregateArchive, aggregateParsed.entries[0], boundedInflate), /length|output|decompress/i);
    assert.throws(() => readZipEntryBytes(aggregateArchive, aggregateParsed.entries[1], boundedInflate), /aggregate|output|decompress/i);
  });

  it("rejects ZIP path conflicts and collisions regardless of entry order", () => {
    const cases: Array<{ label: string; paths: Array<{ path: string; content?: Uint8Array; mode?: number }>; detail: RegExp }> = [
      {
        label: "parent file then child file",
        paths: [{ path: "dir", content: Buffer.from("file") }, { path: "dir/child.txt", content: Buffer.from("child") }],
        detail: /conflicts with file|children/i,
      },
      {
        label: "child file then parent file",
        paths: [{ path: "dir/child.txt", content: Buffer.from("child") }, { path: "dir", content: Buffer.from("file") }],
        detail: /conflicts with child|children|file/i,
      },
      {
        label: "parent file then child directory",
        paths: [{ path: "dir", content: Buffer.from("file") }, { path: "dir/", content: new Uint8Array(), mode: 0o040755 }],
        detail: /conflicts/i,
      },
      {
        label: "child directory then parent file",
        paths: [{ path: "dir/", content: new Uint8Array(), mode: 0o040755 }, { path: "dir", content: Buffer.from("file") }],
        detail: /conflicts/i,
      },
      {
        label: "explicit directory then contradictory file",
        paths: [{ path: "same/", content: new Uint8Array(), mode: 0o040755 }, { path: "same", content: Buffer.from("file") }],
        detail: /conflicts|duplicate/i,
      },
      {
        label: "implicit parent then contradictory file",
        paths: [{ path: "implicit/child.txt", content: Buffer.from("child") }, { path: "implicit", content: Buffer.from("file") }],
        detail: /conflicts with child|children|file/i,
      },
      {
        label: "exact duplicate",
        paths: [{ path: "dup.txt", content: Buffer.from("a") }, { path: "dup.txt", content: Buffer.from("b") }],
        detail: /duplicate/i,
      },
      {
        label: "case-only collision",
        paths: [{ path: "Case.txt", content: Buffer.from("a") }, { path: "case.txt", content: Buffer.from("b") }],
        detail: /collision|case/i,
      },
      {
        label: "unicode-normalization collision",
        paths: [{ path: "cafe\u0301.txt", content: Buffer.from("a") }, { path: "caf\u00e9.txt", content: Buffer.from("b") }],
        detail: /collision|unicode/i,
      },
      {
        label: "combined case plus unicode collision",
        paths: [{ path: "\u00c9.txt", content: Buffer.from("a") }, { path: "e\u0301.txt", content: Buffer.from("b") }],
        detail: /collision|unicode|case/i,
      },
    ];

    for (const testCase of cases) {
      const parsed = parseZipArchive(createZip(testCase.paths)) as unknown as { entries: Array<{ problem?: { detail: string } | null }> };
      assert.equal(
        parsed.entries.some((entry) => testCase.detail.test(entry.problem?.detail ?? "")),
        true,
        testCase.label,
      );
    }
  });

  it("rejects Windows-unsafe ZIP path components on every platform", () => {
    const unsafePaths = [
      "file.txt:secret",
      "CON",
      "PRN.txt",
      "AUX",
      "NUL.dat",
      "COM1",
      "COM9.log",
      "LPT1",
      "LPT9.log",
      "trailing-dot.",
      "trailing-space ",
      "C:/archive/file.txt",
      "//server/share/file.txt",
      "..\\escape.txt",
      "angle<left.txt",
      "angle>right.txt",
      'quote"name.txt',
      "pipe|name.txt",
      "question?.txt",
      "star*.txt",
      "control-\u0001.txt",
      "unit-\u001f.txt",
    ];

    for (const unsafePath of unsafePaths) {
      const parsed = parseZipArchive(createZip([{ path: unsafePath, content: Buffer.from("x") }])) as unknown as {
        entries: Array<{ problem?: { detail: string } | null }>;
      };
      assert.match(parsed.entries[0].problem?.detail ?? "", /windows|reserved|colon|dot|space|drive|unc|backslash|traversal|unsafe|forbidden|control/i, unsafePath);
    }

    const validUnicode = parseZipArchive(createZip([{ path: "valid/گزارش-\u00e9.txt", content: Buffer.from("x") }]));
    assert.equal(validUnicode.entries[0].problem, null);
  });

  it("interprets POSIX modes conservatively across Unix-like ZIP hosts", () => {
    const cases = [
      { label: "Unix symlink", mode: 0o120777, versionMadeBy: 0x0314, detail: /symbolic link/i },
      { label: "macOS symlink", mode: 0o120777, versionMadeBy: 0x1314, detail: /symbolic link/i },
      { label: "FIFO", mode: 0o010644, versionMadeBy: 0x0314, detail: /special file/i },
      { label: "socket", mode: 0o140644, versionMadeBy: 0x0314, detail: /special file/i },
      { label: "device", mode: 0o060644, versionMadeBy: 0x0314, detail: /special file/i },
    ];

    for (const testCase of cases) {
      const parsed = parseZipArchive(createZip([{ path: `${testCase.label}.txt`, content: Buffer.from("x"), mode: testCase.mode, versionMadeBy: testCase.versionMadeBy }])) as unknown as {
        entries: Array<{ problem?: { detail: string } | null }>;
      };
      assert.match(parsed.entries[0].problem?.detail ?? "", testCase.detail, testCase.label);
    }

    assert.equal(parseZipArchive(createZip([{ path: "safe.txt", content: Buffer.from("x"), mode: 0o100644 }])).entries[0].problem, null);
    assert.equal(parseZipArchive(createZip([{ path: "permission-only.txt", content: Buffer.from("x"), mode: 0o644, versionMadeBy: 0x0314 }])).entries[0].problem, null);
    assert.equal(parseZipArchive(createZip([{ path: "safe-dir/", content: new Uint8Array(), mode: 0o040755 }])).entries[0].problem, null);
  });

  it("hashes safe stored and deflated entries and keeps normal Office packages compatible", async () => {
    const stored = await inspectZipArchiveBytes(createZip([{ path: "safe.txt", content: Buffer.from("stored") }]));
    assert.equal(stored.entries[0].status, "hashed");
    assert.equal(stored.warnings.length, 0);

    const deflated = await inspectZipArchiveBytes(createZip([{ path: "safe-deflated.txt", content: Buffer.from("deflated"), compression: "deflate" }]));
    assert.equal(deflated.entries[0].status, "hashed");
    assert.equal(deflated.entries[0].compressionLabel, "deflate");
    assert.equal(deflated.warnings.length, 0);

    for (const extension of [".docx", ".xlsx", ".pptx"]) {
      const office = await inspectZipArchiveBytes(createMinimalOfficeZip("<cp:coreProperties></cp:coreProperties>"));
      assert.equal(office.warnings.length, 0, extension);
      assert.equal(office.entries.every((entry) => entry.status === "hashed"), true, extension);
    }
  });

  it("groups matched, missing, extra, and hash-mismatch results explicitly", () => {
    const inspection = {
      schemaVersion: 1 as const,
      kind: "nullid-archive-inspection" as const,
      createdAt: new Date().toISOString(),
      fileCount: 3,
      directoryCount: 0,
      entryCount: 3,
      entries: [
        {
          path: "docs/readme.txt",
          directory: false,
          compressionMethod: 0,
          compressionLabel: "stored",
          compressedBytes: 13,
          uncompressedBytes: 13,
          sha256: "1612156f640b4c019a738d4857bb1f2d08cb9c75a359e15d13f6f89ba16f7c83",
          status: "hashed" as const,
          detail: "SHA-256 computed from extracted entry bytes.",
        },
        {
          path: "data/report.json",
          directory: false,
          compressionMethod: 0,
          compressionLabel: "stored",
          compressedBytes: 11,
          uncompressedBytes: 11,
          sha256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
          status: "hashed" as const,
          detail: "SHA-256 computed from extracted entry bytes.",
        },
        {
          path: "extra.txt",
          directory: false,
          compressionMethod: 0,
          compressionLabel: "stored",
          compressedBytes: 5,
          uncompressedBytes: 5,
          sha256: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
          status: "hashed" as const,
          detail: "SHA-256 computed from extracted entry bytes.",
        },
      ],
      warnings: [],
    };
    const result = verifyArchiveInspection(inspection, [
      { path: "docs/readme.txt", sha256: "1612156f640b4c019a738d4857bb1f2d08cb9c75a359e15d13f6f89ba16f7c83", source: "archive-manifest" },
      { path: "data/report.json", sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", source: "archive-manifest" },
      { path: "missing.txt", sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", source: "archive-manifest" },
    ]);
    const report = buildArchiveComparisonReport(result);

    assert.equal(result.groups.matched.some((entry) => entry.path === "docs/readme.txt"), true);
    assert.equal(result.groups.hashMismatch.some((entry) => entry.path === "data/report.json"), true);
    assert.equal(result.groups.missing.some((entry) => entry.path === "missing.txt"), true);
    assert.equal(report.groups.hashMismatch.length, 1);
    assert.equal(report.groups.missing.length, 1);
    assert.equal(report.sections.some((section) => section.label === "Matched"), true);
    assert.equal(report.sections.some((section) => section.label === "Missing"), true);
    assert.equal(report.sections.some((section) => section.label === "Hash mismatch"), true);
    assert.equal(report.sections.some((section) => section.label === "Local facts"), true);
    assert.equal(report.manualReviewRecommendations.length > 0, true);
  });

  it("rejects invalid archive reference manifests before comparison", () => {
    const invalidManifests = [
      {
        label: "unsupported schema",
        payload: { schemaVersion: 999, kind: "nullid-archive-manifest", files: [] },
        detail: /schema|version/i,
      },
      {
        label: "unsafe path",
        payload: {
          schemaVersion: 2,
          kind: "nullid-archive-manifest",
          files: [{ path: "../escape.txt", sha256: "a".repeat(64) }],
        },
        detail: /path|traversal|unsafe/i,
      },
      {
        label: "non SHA-256 hash",
        payload: {
          schemaVersion: 2,
          kind: "nullid-archive-manifest",
          files: [{ path: "safe.txt", sha256: "not-a-sha" }],
        },
        detail: /sha-256|hash/i,
      },
      {
        label: "exact duplicate",
        payload: {
          schemaVersion: 2,
          kind: "nullid-archive-manifest",
          files: [
            { path: "safe.txt", sha256: "a".repeat(64) },
            { path: "safe.txt", sha256: "b".repeat(64) },
          ],
        },
        detail: /duplicate/i,
      },
      {
        label: "case collision",
        payload: {
          schemaVersion: 2,
          kind: "nullid-archive-manifest",
          files: [
            { path: "Report.txt", sha256: "a".repeat(64) },
            { path: "report.txt", sha256: "a".repeat(64) },
          ],
        },
        detail: /case|collision/i,
      },
      {
        label: "unicode collision",
        payload: {
          schemaVersion: 2,
          kind: "nullid-archive-manifest",
          files: [
            { path: "cafe\u0301.txt", sha256: "a".repeat(64) },
            { path: "caf\u00e9.txt", sha256: "a".repeat(64) },
          ],
        },
        detail: /unicode|collision/i,
      },
    ];

    for (const testCase of invalidManifests) {
      assert.throws(
        () => parseArchiveReferenceDocument(JSON.stringify(testCase.payload)),
        testCase.detail,
        testCase.label,
      );
    }
  });
});
