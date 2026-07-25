import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { consumeRedactionDraft, queueRedactionDraft } from "../utils/redactionTransfer.js";

class MemoryStorage implements Storage {
  private map = new Map<string, string>();

  get length() {
    return this.map.size;
  }

  clear() {
    this.map.clear();
  }

  getItem(key: string) {
    return this.map.has(key) ? this.map.get(key)! : null;
  }

  key(index: number) {
    return Array.from(this.map.keys())[index] ?? null;
  }

  removeItem(key: string) {
    this.map.delete(key);
  }

  setItem(key: string, value: string) {
    this.map.set(key, value);
  }
}

describe("redaction draft transfer", () => {
  it("keeps queued sensitive text ephemeral instead of persisting it in localStorage", () => {
    const storage = new MemoryStorage();
    Object.defineProperty(globalThis, "window", {
      configurable: true,
      writable: true,
      value: { localStorage: storage },
    });
    const secretText = "email alice@example.com token=abcdefghijklmnopqrstuvwxyz12345";

    queueRedactionDraft({ text: secretText, message: "queued" });

    assert.equal(storage.getItem("nullid:redact:draft"), null);
    assert.equal(JSON.stringify(storage).includes(secretText), false);
    assert.deepEqual(consumeRedactionDraft(), { text: secretText, message: "queued", matches: [] });
    assert.equal(consumeRedactionDraft(), null);
  });

  it("purges the legacy persisted draft at startup without consuming the ephemeral transfer", async () => {
    const storage = new MemoryStorage();
    Object.defineProperty(globalThis, "window", {
      configurable: true,
      writable: true,
      value: { localStorage: storage },
    });
    storage.setItem("nullid:redact:draft", JSON.stringify({ text: "stale secret" }));
    queueRedactionDraft({ text: "ephemeral secret", message: "queued" });
    const transfer = await import("../utils/redactionTransfer.js") as { purgeLegacyRedactionDraft?: () => void };
    const purgeLegacyRedactionDraft = transfer.purgeLegacyRedactionDraft;
    assert.equal(typeof purgeLegacyRedactionDraft, "function");

    purgeLegacyRedactionDraft?.();

    assert.equal(storage.getItem("nullid:redact:draft"), null);
    assert.deepEqual(consumeRedactionDraft(), { text: "ephemeral secret", message: "queued", matches: [] });
  });

  it("purges legacy persisted drafts before the app mounts", () => {
    const source = fs.readFileSync("src/main.tsx", "utf8");
    const purgeIndex = source.indexOf("purgeLegacyRedactionDraft");
    const renderIndex = source.indexOf("ReactDOM.createRoot");

    assert.notEqual(purgeIndex, -1);
    assert.ok(purgeIndex < renderIndex);
  });
});
