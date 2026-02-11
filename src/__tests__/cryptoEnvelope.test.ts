import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { decryptBlob, decryptText, encryptBytes, encryptText } from "../utils/cryptoEnvelope.js";

describe("crypto envelope", () => {
  it("round trips text", async () => {
    const plaintext = "nullid-test-payload";
    const passphrase = "strong passphrase";
    const blob = await encryptText(passphrase, plaintext);
    const decrypted = await decryptText(passphrase, blob);
    assert.equal(decrypted, plaintext);
  });

  it("fails with wrong passphrase", async () => {
    const blob = await encryptText("right", "data");
    await assert.rejects(() => decryptText("wrong", blob));
  });

  it("round trips binary payload", async () => {
    const bytes = new TextEncoder().encode("file-payload");
    const { blob, header } = await encryptBytes("secret", bytes, { mime: "text/plain", name: "file.txt" });
    assert.equal(header.mime, "text/plain");
    assert.equal(header.name, "file.txt");
    const { plaintext, header: decodedHeader } = await decryptBlob("secret", blob);
    assert.equal(decodedHeader.mime, "text/plain");
    assert.equal(new TextDecoder().decode(plaintext), "file-payload");
  });

  it("accepts envelopes with wrapped whitespace", async () => {
    const blob = await encryptText("wrap", "payload");
    const wrapped = `\n  ${blob.slice(0, 24)} \n${blob.slice(24)} \n`;
    const output = await decryptText("wrap", wrapped);
    assert.equal(output, "payload");
  });

  it("supports stronger KDF profiles while keeping same envelope prefix", async () => {
    const { blob, header } = await encryptBytes("profile-pass", new TextEncoder().encode("kdf-profile"), {
      kdfProfile: "strong",
      mime: "text/plain",
    });
    assert.equal(blob.startsWith("NULLID:ENC:1."), true);
    assert.equal(header.kdf.hash, "SHA-512");
    assert.equal(header.kdf.iterations, 600_000);
    const { plaintext } = await decryptBlob("profile-pass", blob);
    assert.equal(new TextDecoder().decode(plaintext), "kdf-profile");
  });
});
