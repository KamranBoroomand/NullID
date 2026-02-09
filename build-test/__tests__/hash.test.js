import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { hashText } from "../utils/hash.js";
describe("hashing", () => {
    it("matches known SHA-256 vector", async () => {
        const { hex, base64 } = await hashText("abc", "SHA-256");
        assert.equal(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert.equal(base64, "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=");
    });
    it("matches known SHA-512 vector", async () => {
        const { hex } = await hashText("abc", "SHA-512");
        assert.equal(hex, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    });
});
