import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { hashBytes, hashText } from "../utils/hash.js";
import { toHex } from "../utils/encoding.js";

describe("hashing", () => {
  it("matches known SHA-256 vector", async () => {
    const { hex, base64 } = await hashText("abc", "SHA-256");
    assert.equal(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert.equal(base64, "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=");
  });

  it("matches known SHA-512 vector", async () => {
    const { hex } = await hashText("abc", "SHA-512");
    assert.equal(
      hex,
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    );
  });

  it("matches Node SHA-256 when a surrogate pair starts before the old chunk boundary", async () => {
    const value = `${"a".repeat(31_999)}😀b`;
    const { hex } = await hashText(value, "SHA-256");
    assert.equal(hex, await nodeHash(value, "sha256"));
  });

  it("matches Node SHA-512 when a surrogate pair ends after the old chunk boundary", async () => {
    const value = `${"a".repeat(31_998)}😀b`;
    const { hex } = await hashText(value, "SHA-512");
    assert.equal(hex, await nodeHash(value, "sha512"));
  });

  it("matches Node hashes for non-BMP characters around several old chunk boundaries", async () => {
    const value = `${"a".repeat(31_999)}😀${"b".repeat(31_998)}🧪${"c".repeat(31_997)}🔒`;
    const sha256Result = await hashText(value, "SHA-256");
    const sha512Result = await hashText(value, "SHA-512");
    assert.equal(sha256Result.hex, await nodeHash(value, "sha256"));
    assert.equal(sha512Result.hex, await nodeHash(value, "sha512"));
  });

  it("does not log hash timing in normal operation and preserves byte hashing", async () => {
    const originalInfo = console.info;
    const messages: unknown[] = [];
    console.info = (...args: unknown[]) => {
      messages.push(args);
    };
    try {
      const bytes = new Uint8Array([0, 1, 2, 3, 255]);
      const result = await hashBytes(bytes, "SHA-256");
      assert.equal(result.hex, await subtleHash(bytes, "SHA-256"));
      assert.deepEqual(messages, []);
    } finally {
      console.info = originalInfo;
    }
  });
});

async function nodeHash(value: string, algorithm: "sha256" | "sha512") {
  return subtleHash(new TextEncoder().encode(value), algorithm === "sha256" ? "SHA-256" : "SHA-512");
}

async function subtleHash(bytes: Uint8Array, algorithm: "SHA-256" | "SHA-512") {
  const digest = await crypto.subtle.digest(algorithm, bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer);
  return toHex(new Uint8Array(digest));
}
