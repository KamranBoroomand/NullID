import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  formatPolicyPackTrustState,
  getPolicyPackExportTrustState,
  getPolicyPackImportTrustState,
} from "../views/sanitizePolicyTrustState.js";

describe("sanitize policy-pack trust language", () => {
  it("does not treat export passphrase entry alone as verified", () => {
    const state = getPolicyPackExportTrustState({ signed: true, hasPassphrase: true });
    assert.equal(state, "pending");
    assert.equal(formatPolicyPackTrustState(state), "not yet verified");
  });

  it("uses a positive trust state only after verification succeeds", () => {
    const state = getPolicyPackImportTrustState({
      signed: true,
      hasPassphrase: true,
      verificationSucceeded: true,
    });
    assert.equal(state, "verified");
    assert.equal(formatPolicyPackTrustState(state), "verification succeeded");
  });

  it("maps verification failures to a non-success trust state", () => {
    const state = getPolicyPackImportTrustState({
      signed: true,
      hasPassphrase: true,
      error: "Policy signature verification failed",
    });
    assert.equal(state, "failed");
    assert.equal(formatPolicyPackTrustState(state), "verification failed");
  });
});
