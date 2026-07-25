import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { resolveOverlaps } from "../utils/redaction.js";

describe("redaction overlap resolution", () => {
  it("prefers longer matches over nested shorter ones", () => {
    const matches = [
      { start: 0, end: 5, label: "short", severity: "medium" as const },
      { start: 0, end: 10, label: "long", severity: "low" as const },
    ];
    const resolved = resolveOverlaps(matches);
    assert.equal(resolved.length, 1);
    assert.equal(resolved[0].label, "long");
  });

  it("uses severity when lengths match", () => {
    const matches = [
      { start: 0, end: 5, label: "med", severity: "medium" as const },
      { start: 0, end: 5, label: "high", severity: "high" as const },
    ];
    const resolved = resolveOverlaps(matches);
    assert.equal(resolved[0].label, "high");
  });

  it("keeps earliest when tie on length and severity", () => {
    const matches = [
      { start: 5, end: 8, label: "later", severity: "medium" as const },
      { start: 0, end: 3, label: "earlier", severity: "medium" as const },
    ];
    const resolved = resolveOverlaps(matches);
    assert.equal(resolved[0].label, "earlier");
  });
});
