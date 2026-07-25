import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { removeProfileHint, rotateProfileHint, type KeyHintProfile } from "../utils/keyHintProfiles.js";

describe("key hint profile collection mutations", () => {
  it("refuses ambiguous duplicate-id rotations and removals", () => {
    const profiles = [
      profile("shared-id", "Team A", "team-a-v1"),
      profile("shared-id", "Team B", "team-b-v1"),
    ];

    const rotated = rotateProfileHint(profiles, "shared-id", "2026-01-02T00:00:00.000Z");

    assert.equal(rotated.ok, false);
    assert.deepEqual(removeProfileHint(profiles, "shared-id"), profiles);
  });

  it("rotates and removes a single unambiguous profile id", () => {
    const profiles = [profile("first", "Team A", "team-a-v1"), profile("second", "Team B", "team-b-v1")];

    const rotated = rotateProfileHint(profiles, "first", "2026-01-02T00:00:00.000Z");

    assert.equal(rotated.ok, true);
    assert.equal(rotated.ok ? rotated.hint : "", "team-a-v2");
    assert.deepEqual(removeProfileHint(rotated.ok ? rotated.profiles : profiles, "first").map((entry) => entry.id), ["second"]);
  });
});

function profile(id: string, name: string, keyHint: string): KeyHintProfile {
  return {
    id,
    name,
    keyHint,
    version: 1,
    createdAt: "2026-01-01T00:00:00.000Z",
    updatedAt: "2026-01-01T00:00:00.000Z",
  };
}
