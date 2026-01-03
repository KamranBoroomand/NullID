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
});
