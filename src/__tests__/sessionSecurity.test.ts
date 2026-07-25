import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { clearVaultSessionCookie, setVaultSessionCookie } from "../utils/sessionSecurity.js";

describe("vault session presence cookie", () => {
  it("scopes browser-set presence cookies to the current app path instead of the whole origin", () => {
    const assignments: string[] = [];
    Object.defineProperty(globalThis, "window", {
      configurable: true,
      writable: true,
      value: {
        isSecureContext: true,
        location: {
          protocol: "https:",
          pathname: "/secure/nullid/vault",
        },
      },
    });
    Object.defineProperty(globalThis, "document", {
      configurable: true,
      writable: true,
      value: {
        get cookie() {
          return "";
        },
        set cookie(value: string) {
          assignments.push(value);
        },
      },
    });

    setVaultSessionCookie(60);
    clearVaultSessionCookie();

    assert.match(assignments[0], /Path=\/secure\/nullid\b/u);
    assert.doesNotMatch(assignments[0], /Path=\/(?:;|$)/u);
    assert.match(assignments[1], /Path=\/(?:;|$)/u);
    assert.match(assignments[1], /Max-Age=0/u);
    assert.match(assignments[2], /Path=\/secure\/nullid\b/u);
    assert.doesNotMatch(assignments[2], /Path=\/(?:;|$)/u);
    assert.match(assignments[3], /Path=\/(?:;|$)/u);
    assert.match(assignments[3], /Max-Age=0/u);
  });
});
