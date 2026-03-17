import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { decryptBlob, decryptText, encryptBytes, encryptText, ENVELOPE_PREFIX } from "../utils/cryptoEnvelope.js";
import { fromBase64Url, toBase64Url, utf8ToBytes, bytesToUtf8 } from "../utils/encoding.js";
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
    it("rejects imported envelopes with out-of-range KDF settings", async () => {
        const blob = await encryptText("secret", "payload");
        const mutated = mutateEnvelope(blob, (payload) => {
            payload.header.kdf.iterations = 5_000_000;
        });
        await expectRejects(() => decryptText("secret", mutated), /Invalid envelope kdf iterations/i);
    });
    it("rejects imported envelopes with unsupported KDF hashes", async () => {
        const blob = await encryptText("secret", "payload");
        const mutated = mutateEnvelope(blob, (payload) => {
            payload.header.kdf.hash = "SHA-1";
        });
        await expectRejects(() => decryptText("secret", mutated), /Unsupported envelope kdf hash/i);
    });
    it("rejects imported envelopes with malformed IVs", async () => {
        const blob = await encryptText("secret", "payload");
        const mutated = mutateEnvelope(blob, (payload) => {
            payload.header.iv = "!!!";
        });
        await expectRejects(() => decryptText("secret", mutated), /Invalid envelope iv/i);
    });
});
function mutateEnvelope(blob, mutate) {
    const encoded = blob.slice(`${ENVELOPE_PREFIX}.`.length);
    const payload = JSON.parse(bytesToUtf8(fromBase64Url(encoded)));
    mutate(payload);
    return `${ENVELOPE_PREFIX}.${toBase64Url(utf8ToBytes(JSON.stringify(payload)))}`;
}
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
