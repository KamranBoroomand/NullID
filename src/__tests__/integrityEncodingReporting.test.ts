import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { decodeBase64UrlStrict, toBase64Url } from "../utils/encoding.js";
import { sha256Base64Url, signHash, stableStringify, verifyHashSignature } from "../utils/integrity.js";
import { localizeExportValue, renderExportReportText } from "../utils/reporting.js";

describe("canonical integrity and strict encoding", () => {
  it("sorts object keys deterministically while preserving nested JSON values", () => {
    assert.equal(
      stableStringify({ z: [3, { b: true, a: "آ" }], a: "😀" }),
      '{"a":"😀","z":[3,{"a":"آ","b":true}]}',
    );
  });

  it("rejects unsupported canonical JSON values instead of producing ambiguous output", () => {
    for (const value of [
      undefined,
      { a: undefined },
      [1, undefined, 3],
      { fn: () => undefined },
      { symbol: Symbol("x") },
      { bigint: 1n },
      { nan: Number.NaN },
      { infinity: Number.POSITIVE_INFINITY },
      { negativeInfinity: Number.NEGATIVE_INFINITY },
    ]) {
      assert.throws(() => stableStringify(value), /canonical json/i);
    }
  });

  it("rejects cycles and excessive depth with stable errors", () => {
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    assert.throws(() => stableStringify(cyclic), /cycle/i);

    let deep: unknown = "leaf";
    for (let i = 0; i < 80; i += 1) {
      deep = { child: deep };
    }
    assert.throws(() => stableStringify(deep), /depth/i);
  });

  it("uses strict canonical Base64URL for security-boundary signatures", async () => {
    const hash = await sha256Base64Url({ payload: "value" });
    const signature = await signHash(hash, "secret");
    assert.equal(signature.length, 43);
    assert.equal(await verifyHashSignature(hash, signature, "secret"), true);

    const standardAlphabet = signature.replace(/-/g, "+").replace(/_/g, "/");
    assert.throws(() => decodeBase64UrlStrict(`${signature}=`, "bad signature"), /bad signature/);
    assert.equal(await verifyHashSignature(hash, `${signature}=`, "secret"), false);
    if (standardAlphabet !== signature) {
      assert.throws(() => decodeBase64UrlStrict(standardAlphabet, "bad signature"), /bad signature/);
      assert.equal(await verifyHashSignature(hash, standardAlphabet, "secret"), false);
    }
  });

  it("requires exact SHA-256 and HMAC lengths", async () => {
    const signature = await signHash(toBase64Url(new Uint8Array(32).fill(1)), "secret");
    assert.equal(await verifyHashSignature(toBase64Url(new Uint8Array(31).fill(1)), signature, "secret"), false);
    assert.equal(await verifyHashSignature(toBase64Url(new Uint8Array(32).fill(1)), signature.slice(1), "secret"), false);
  });
});

describe("reporting localization safety", () => {
  it("does not recursively translate machine-readable export data", () => {
    const payload = {
      hash: "Created",
      fileName: "Summary",
      mime: "Notes",
      nested: { schema: "Verified" },
    };
    const localized = localizeExportValue(payload, (value) => `translated:${value}`);
    assert.deepEqual(localized, payload);
  });

  it("does not stringify malicious report labels as [object Object]", () => {
    const text = renderExportReportText({
      title: "Report",
      createdAt: "2026-07-06T00:00:00.000Z",
      sections: [
        {
          id: "bad",
          label: "Bad section",
          items: [{ label: { nested: true }, value: "machine-token" } as unknown as Record<string, never>],
        },
      ],
    });
    assert.equal(text.includes("[object Object]"), false);
    assert.equal(text.includes("machine-token"), true);
  });
});
