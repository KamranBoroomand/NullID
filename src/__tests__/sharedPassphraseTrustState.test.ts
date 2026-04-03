import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  formatSharedPassphraseTrustState,
  getSharedPassphraseExportTrustState,
  getSharedPassphraseImportTrustState,
} from "../utils/sharedPassphraseTrustState.js";

describe("shared-passphrase trust language", () => {
  it("does not treat export passphrase entry alone as verified", () => {
    const state = getSharedPassphraseExportTrustState({ signed: true, hasPassphrase: true });
    assert.equal(state, "pending");
    assert.equal(formatSharedPassphraseTrustState(state), "not yet verified");
  });

  it("requires a passphrase before signed imports can be verified", () => {
    const state = getSharedPassphraseImportTrustState({ signed: true, hasPassphrase: false });
    assert.equal(state, "setup-required");
    assert.equal(formatSharedPassphraseTrustState(state), "passphrase required");
  });

  it("maps verification failures to a non-success trust state", () => {
    const state = getSharedPassphraseImportTrustState({
      signed: true,
      hasPassphrase: true,
      error: "Vault signature mismatch",
    });
    assert.equal(state, "failed");
    assert.equal(formatSharedPassphraseTrustState(state), "verification failed");
  });
});
