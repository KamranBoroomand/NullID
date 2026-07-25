import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  decryptBlob,
  decryptText,
  encryptBytes,
  encryptText,
  ENVELOPE_PREFIX,
} from "../utils/cryptoEnvelope.js";
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
    assert.equal(blob.startsWith(`${ENVELOPE_PREFIX}.`), true);
    assert.equal(header.mime, "text/plain");
    assert.equal(header.name, "file.txt");
    const { plaintext, header: decodedHeader } = await decryptBlob("secret", blob);
    assert.equal(decodedHeader.mime, "text/plain");
    assert.equal(decodedHeader.name, "file.txt");
    assert.equal(new TextDecoder().decode(plaintext), "file-payload");
  });

  it("encrypts only the selected typed-array view", async () => {
    const backing = new Uint8Array([1, 2, 3, 4, 5, 6]);
    const selected = backing.subarray(2, 4);
    const { blob } = await encryptBytes("view-secret", selected, { mime: "application/octet-stream" });

    const { plaintext } = await decryptBlob("view-secret", blob);

    assert.deepEqual(Array.from(plaintext), [3, 4]);
  });

  it("round trips an empty typed-array view without leaking backing bytes", async () => {
    const backing = new Uint8Array([9, 8, 7]);
    const selected = backing.subarray(1, 1);
    const { blob } = await encryptBytes("empty-view", selected);

    const { plaintext } = await decryptBlob("empty-view", blob);

    assert.equal(plaintext.byteLength, 0);
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
    assert.equal(blob.startsWith("NULLID:ENC:2."), true);
    assert.equal(header.kdf.hash, "SHA-512");
    assert.equal(header.kdf.iterations, 600_000);
    const { plaintext } = await decryptBlob("profile-pass", blob);
    assert.equal(new TextDecoder().decode(plaintext), "kdf-profile");
  });

  it("rejects tampered v2 authenticated header metadata", async () => {
    const { blob } = await encryptBytes("secret", utf8ToBytes("payload"), {
      mime: "text/plain",
      name: "safe.txt",
    });
    for (const mutate of [
      (payload: MutableEnvelope) => {
        payload.header.name = "invoice.exe";
      },
      (payload: MutableEnvelope) => {
        payload.header.mime = "application/x-msdownload";
      },
      (payload: MutableEnvelope) => {
        payload.header.iv = toBase64Url(new Uint8Array(12).fill(7));
      },
      (payload: MutableEnvelope) => {
        payload.header.kdf.salt = toBase64Url(new Uint8Array(16).fill(8));
      },
      (payload: MutableEnvelope) => {
        payload.header.kdf.iterations += 1;
      },
      (payload: MutableEnvelope) => {
        payload.header.kdf.hash = (payload.header.kdf.hash === "SHA-256" ? "SHA-512" : "SHA-256") as "SHA-256" | "SHA-512";
      },
    ]) {
      await expectRejects(() => decryptText("secret", mutateEnvelope(blob, mutate)), /decrypt|operation|auth/i);
    }
  });

  it("rejects tampered v2 ciphertext", async () => {
    const { blob } = await encryptBytes("secret", utf8ToBytes("payload"));
    const mutated = mutateEnvelope(blob, (payload) => {
      const bytes = fromBase64Url(payload.ciphertext);
      bytes[0] ^= 0xff;
      payload.ciphertext = toBase64Url(bytes);
    });

    await expectRejects(() => decryptBlob("secret", mutated), /decrypt|operation|auth/i);
  });

  it("does not trust v1 filename and MIME metadata after decryption", async () => {
    const legacy = await encryptLegacyV1ForTest("secret", utf8ToBytes("legacy"), {
      mime: "text/plain",
      name: "safe.txt",
    });
    const tampered = mutateEnvelope(legacy, (payload) => {
      payload.header.name = "../../payload.exe";
      payload.header.mime = "application/x-msdownload";
    }, LEGACY_ENVELOPE_PREFIX_FOR_TEST);

    const result = await decryptBlob("secret", tampered);

    assert.equal(bytesToUtf8(result.plaintext), "legacy");
    assert.equal((result as { metadataAuthenticated?: boolean }).metadataAuthenticated, false);
    assert.equal(result.header.name, undefined);
    assert.equal(result.header.mime, "application/octet-stream");
  });

  it("sanitizes dangerous v2 filenames and MIME types before authentication", async () => {
    const { blob, header } = await encryptBytes("secret", utf8ToBytes("payload"), {
      name: "../../con\u0000aux.exe".padEnd(400, "x"),
      mime: "application/x-msdownload",
    });

    assert.equal(header.mime, "application/octet-stream");
    assert.equal(header.name?.includes("/"), false);
    assert.equal(header.name?.includes("\\"), false);
    assert.equal((header.name ?? "").length <= 120, true);

    const decrypted = await decryptBlob("secret", blob);
    assert.equal(decrypted.header.mime, "application/octet-stream");
    assert.equal(decrypted.header.name, header.name);
    assert.equal((decrypted as { metadataAuthenticated?: boolean }).metadataAuthenticated, true);
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

function mutateEnvelope(
  blob: string,
  mutate: (payload: MutableEnvelope) => void,
  prefix = ENVELOPE_PREFIX,
) {
  const encoded = blob.slice(`${prefix}.`.length);
  const payload = JSON.parse(bytesToUtf8(fromBase64Url(encoded))) as MutableEnvelope;
  mutate(payload);
  return `${prefix}.${toBase64Url(utf8ToBytes(JSON.stringify(payload)))}`;
}

interface MutableEnvelope {
  header: {
    version: number;
    algo: string;
    kdf: { name: string; iterations: number; hash: string; salt: string };
    iv: string;
    mime?: string;
    name?: string;
  };
  ciphertext: string;
}

const LEGACY_ENVELOPE_PREFIX_FOR_TEST = "NULLID:ENC:1";

async function encryptLegacyV1ForTest(passphrase: string, bytes: Uint8Array, metadata: { mime?: string; name?: string }) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const keyMaterial = await crypto.subtle.importKey("raw", exactArrayBuffer(utf8ToBytes(passphrase)), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: exactArrayBuffer(salt), iterations: 250_000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: exactArrayBuffer(iv), additionalData: exactArrayBuffer(utf8ToBytes("nullid:enc:v1")) },
      key,
      exactArrayBuffer(bytes),
    ),
  );
  const payload: MutableEnvelope = {
    header: {
      version: 1,
      algo: "AES-GCM",
      iv: toBase64Url(iv),
      mime: metadata.mime,
      name: metadata.name,
      kdf: { name: "PBKDF2", iterations: 250_000, hash: "SHA-256", salt: toBase64Url(salt) },
    },
    ciphertext: toBase64Url(ciphertext),
  };
  return `${LEGACY_ENVELOPE_PREFIX_FOR_TEST}.${toBase64Url(utf8ToBytes(JSON.stringify(payload)))}`;
}

function exactArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

async function expectRejects(fn: () => Promise<unknown>, pattern: RegExp) {
  let rejected = false;
  let message = "";
  try {
    await fn();
  } catch (error) {
    rejected = true;
    message = error instanceof Error ? error.message : String(error);
  }
  assert.equal(rejected, true);
  assert.equal(pattern.test(message), true);
}
