import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { clearClipboardIfUnchanged, defaultClipboardPrefs, writeClipboard } from "../utils/clipboard.js";

describe("clipboard safety", () => {
  it("clears the clipboard when the copied value is unchanged", async () => {
    const clipboard = fakeClipboard("copied secret");

    const result = await clearClipboardIfUnchanged("copied secret", clipboard);

    assert.equal(result.cleared, true);
    assert.equal(clipboard.value, "");
  });

  it("does not clear the clipboard when the user copied a new value", async () => {
    const clipboard = fakeClipboard("new clipboard value");

    const result = await clearClipboardIfUnchanged("copied secret", clipboard);

    assert.equal(result.cleared, false);
    assert.equal(result.reason, "changed");
    assert.equal(clipboard.value, "new clipboard value");
  });

  it("does not crash or clear when clipboard read fails", async () => {
    const clipboard = fakeClipboard("copied secret", { failRead: true });

    const result = await clearClipboardIfUnchanged("copied secret", clipboard);

    assert.equal(result.cleared, false);
    assert.equal(result.reason, "read-failed");
    assert.equal(clipboard.value, "copied secret");
  });

  it("reports clipboard write failures cleanly", async () => {
    Object.defineProperty(globalThis, "navigator", {
      value: { clipboard: fakeClipboard("", { failWrite: true }) },
      configurable: true,
      writable: true,
    });
    const reports: string[] = [];

    const result = await writeClipboard("copied secret", defaultClipboardPrefs, (message) => reports.push(message));

    assert.equal(result.ok, false);
    assert.equal(result.error, "clipboard unavailable");
    assert.deepEqual(reports, ["clipboard unavailable"]);
  });
});

function fakeClipboard(initialValue: string, options: { failRead?: boolean; failWrite?: boolean } = {}) {
  return {
    value: initialValue,
    async readText() {
      if (options.failRead) {
        throw new Error("read denied");
      }
      return this.value;
    },
    async writeText(next: string) {
      if (options.failWrite) {
        throw new Error("write denied");
      }
      this.value = next;
    },
  };
}
