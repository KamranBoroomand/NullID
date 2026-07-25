import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { scanSecrets, secretFindingsToRedactionMatches } from "../utils/secretScanner.js";
import { applyRedaction } from "../utils/redaction.js";

describe("secret scanner", () => {
  it("detects concrete token formats and redacts them locally", () => {
    const input = [
      "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.signaturePart123456",
      "github_pat_1234567890_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef",
      "-----BEGIN PRIVATE KEY-----",
      "abc123",
      "-----END PRIVATE KEY-----",
    ].join("\n");

    const result = scanSecrets(input, { includeHeuristicCandidates: false });
    const redacted = applyRedaction(input, secretFindingsToRedactionMatches(result.findings), "full");

    assert.equal(result.findings.some((finding) => finding.key === "bearer"), true);
    assert.equal(result.findings.some((finding) => finding.key === "github-token"), true);
    assert.equal(result.findings.some((finding) => finding.key === "private-key"), true);
    assert.match(redacted, /\[bearer-token\]/i);
    assert.match(redacted, /\[github-token\]/i);
    assert.match(redacted, /\[private-key\]/i);
  });

  it("labels heuristic entropy candidates as likely rather than guaranteed", () => {
    const input = "tokenish=4fHk9Pq2Xa8mV1cL7nR0sD3wB6yT9uI2";
    const result = scanSecrets(input, { includeHeuristicCandidates: true, minCandidateLength: 20 });
    const heuristic = result.findings.find((finding) => finding.key === "high-entropy-candidate");

    assert.equal(Boolean(heuristic), true);
    assert.equal(heuristic?.evidence, "heuristic");
    assert.match(String(heuristic?.reason), /entropy/i);
  });
});
