import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { HMAC_SHA256_ALGORITHM, sha256Base64Url, signHash } from "../utils/integrity.js";
import { classifySnapshotIntegrityError, createSnapshotIntegrity, verifySnapshotIntegrity } from "../utils/snapshotIntegrity.js";
describe("snapshot integrity helper", () => {
    it("stays canonical and deterministic for profile, policy, and vault payload shapes", async () => {
        const cases = [
            {
                label: "profile",
                payload: {
                    schemaVersion: 2,
                    exportedAt: "2026-03-16T00:00:00.000Z",
                    entries: {
                        "nullid:theme": "dark",
                        "nullid:vault:pref:unlock-rate-limit": true,
                    },
                },
                countKey: "entryCount",
                count: 2,
            },
            {
                label: "policy",
                payload: {
                    schemaVersion: 2,
                    kind: "sanitize-policy-pack",
                    exportedAt: "2026-03-16T00:00:00.000Z",
                    packs: [
                        {
                            name: "team-default",
                            createdAt: "2026-03-15T00:00:00.000Z",
                            config: { jsonAware: true, customRules: [], rulesState: { maskIp: true } },
                        },
                    ],
                },
                countKey: "packCount",
                count: 1,
            },
            {
                label: "vault",
                payload: {
                    schemaVersion: 2,
                    exportedAt: "2026-03-16T00:00:00.000Z",
                    vault: {
                        meta: { salt: "c2FsdA", iterations: 200_000, version: 1 },
                        canary: { ciphertext: "Y2lwaGVydGV4dA", iv: "MDEyMzQ1Njc4OWFi" },
                        notes: [{ id: "note-1", ciphertext: "Y2lwaGVydGV4dA", iv: "MDEyMzQ1Njc4OWFi", updatedAt: 1 }],
                    },
                },
                countKey: "noteCount",
                count: 1,
            },
        ];
        for (const testCase of cases) {
            const signed = await createSnapshotIntegrity(testCase.payload, testCase.countKey, testCase.count, {
                signingPassphrase: `${testCase.label}-secret`,
                keyHint: "  local-hint  ",
            });
            const expectedHash = await sha256Base64Url(testCase.payload);
            const expectedSignature = await signHash(expectedHash, `${testCase.label}-secret`);
            assert.equal(signed.integrity.payloadHash, expectedHash);
            assert.equal(signed.integrity[testCase.countKey], testCase.count);
            assert.equal(signed.signature?.algorithm, HMAC_SHA256_ALGORITHM);
            assert.equal(signed.signature?.value, expectedSignature);
            assert.equal(signed.signature?.keyHint, "local-hint");
            const verified = await verifySnapshotIntegrity({
                subject: testCase.label,
                countKey: testCase.countKey,
                actualCount: testCase.count,
                payload: testCase.payload,
                integrity: signed.integrity,
                signature: signed.signature,
                verificationPassphrase: `${testCase.label}-secret`,
            });
            assert.equal(verified.signed, true);
            assert.equal(verified.verified, true);
            assert.equal(verified.algorithm, HMAC_SHA256_ALGORITHM);
        }
    });
    it("classifies metadata, integrity, and verification failures", async () => {
        const signed = await createSnapshotIntegrity({
            schemaVersion: 2,
            exportedAt: "2026-03-16T00:00:00.000Z",
            entries: { "nullid:theme": "dark" },
        }, "entryCount", 1, { signingPassphrase: "secret" });
        await expectRejects(async () => {
            try {
                await verifySnapshotIntegrity({
                    subject: "Profile",
                    countKey: "entryCount",
                    actualCount: 2,
                    payload: {
                        schemaVersion: 2,
                        exportedAt: "2026-03-16T00:00:00.000Z",
                        entries: { "nullid:theme": "dark" },
                    },
                    integrity: signed.integrity,
                });
            }
            catch (error) {
                assert.equal(classifySnapshotIntegrityError(error), "integrity");
                throw error;
            }
        }, /mismatch/i);
        await expectRejects(async () => {
            try {
                await verifySnapshotIntegrity({
                    subject: "Profile",
                    countKey: "entryCount",
                    actualCount: 1,
                    payload: {
                        schemaVersion: 2,
                        exportedAt: "2026-03-16T00:00:00.000Z",
                        entries: { "nullid:theme": "dark" },
                    },
                    integrity: signed.integrity,
                    signature: signed.signature,
                });
            }
            catch (error) {
                assert.equal(classifySnapshotIntegrityError(error), "verification");
                throw error;
            }
        }, /verification passphrase required/i);
    });
});
async function expectRejects(fn, pattern) {
    let rejected = false;
    let message = "";
    try {
        await fn();
    }
    catch (error) {
        rejected = true;
        message = error instanceof Error ? error.message : String(error);
    }
    assert.equal(rejected, true);
    assert.equal(pattern.test(message), true);
}
