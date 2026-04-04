import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { guideExtras, guideTools } from "../content/guideContent.js";
import type { ModuleKey } from "../components/ModuleList.js";

describe("guide content coverage", () => {
  it("covers every primary tool module exactly once", () => {
    const expected: ModuleKey[] = ["hash", "batch", "share", "incident", "secret", "analyze", "finance", "paths", "redact", "sanitize", "verify", "meta", "enc", "pw", "vault", "selftest"];
    const actual = guideTools.map((item) => item.key).sort();
    assert.deepEqual(actual, [...expected].sort());
  });

  it("keeps the cross-cutting guidance cards present", () => {
    const actual = guideExtras.map((item) => item.key).sort();
    assert.deepEqual(actual, ["clipboard", "models", "profiles"]);
  });
});
