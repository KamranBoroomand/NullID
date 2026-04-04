import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { analyzePathPrivacy } from "../utils/pathPrivacy.js";

describe("pathPrivacy", () => {
  it("flags usernames, case identifiers, and internal project labels", () => {
    const result = analyzePathPrivacy("/Users/alice/projects/zephyr/incident-4432/customer-cards.csv");

    assert.equal(result.findings.some((finding) => finding.label === "Username in path"), true);
    assert.equal(result.findings.some((finding) => finding.label === "Case / ticket ID in filename/path"), true);
    assert.equal(result.findings.some((finding) => finding.label === "Internal project name"), true);
    assert.match(result.suggestions[0]?.preview ?? "", /user|project-name|case-id/i);
  });
});
