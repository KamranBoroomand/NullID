import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  applyUnlockFailure,
  clearUnlockFailures,
  cooldownSecondsForFailureCount,
  createHumanCheckChallenge,
  createUnlockThrottleState,
  isUnlockBlocked,
  shouldRequireHumanCheck,
  verifyHumanCheck,
} from "../utils/unlockHardening.js";

describe("unlock hardening", () => {
  it("requires human check after repeated failures", () => {
    let state = createUnlockThrottleState();
    assert.equal(shouldRequireHumanCheck(state), false);
    state = applyUnlockFailure(state, 1_000);
    state = applyUnlockFailure(state, 2_000);
    state = applyUnlockFailure(state, 3_000);
    assert.equal(shouldRequireHumanCheck(state), true);
  });

  it("applies exponential lockout once failures cross threshold", () => {
    let state = createUnlockThrottleState();
    const now = 100_000;
    for (let i = 0; i < 5; i += 1) {
      state = applyUnlockFailure(state, now);
    }
    assert.equal(isUnlockBlocked(state, now), true);
    const cooldown = Math.round((state.lockoutUntil - now) / 1000);
    assert.equal(cooldown, cooldownSecondsForFailureCount(5));
  });

  it("resets failures on successful unlock", () => {
    const failed = applyUnlockFailure(createUnlockThrottleState(), 1000);
    assert.equal(failed.failures > 0, true);
    const cleared = clearUnlockFailures();
    assert.equal(cleared.failures, 0);
    assert.equal(cleared.lockoutUntil, 0);
  });

  it("validates human check answers", () => {
    const challenge = createHumanCheckChallenge();
    assert.equal(verifyHumanCheck(challenge, String(challenge.answer)), true);
    assert.equal(verifyHumanCheck(challenge, "999999"), false);
  });
});
