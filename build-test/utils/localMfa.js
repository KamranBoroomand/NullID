import { fromBase64Url, randomBytes, toBase64Url } from "./encoding.js";
function toArrayBuffer(bytes) {
    return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}
export function isLocalMfaSupported() {
    if (typeof window === "undefined")
        return false;
    return Boolean(window.PublicKeyCredential && navigator.credentials);
}
export async function registerLocalMfaCredential(label) {
    if (!isLocalMfaSupported()) {
        throw new Error("WebAuthn is not supported in this browser");
    }
    const display = label?.trim().slice(0, 48) || "NullID vault user";
    const userId = randomBytes(16);
    const challenge = randomBytes(32);
    const created = await navigator.credentials.create({
        publicKey: {
            rp: { name: "NullID Local Vault" },
            user: {
                id: toArrayBuffer(userId),
                name: "nullid-local-user",
                displayName: display,
            },
            challenge: toArrayBuffer(challenge),
            pubKeyCredParams: [
                { type: "public-key", alg: -7 },
                { type: "public-key", alg: -257 },
            ],
            timeout: 60_000,
            authenticatorSelection: {
                userVerification: "preferred",
            },
            attestation: "none",
        },
    });
    if (!(created instanceof PublicKeyCredential)) {
        throw new Error("MFA registration failed");
    }
    const credentialId = toBase64Url(new Uint8Array(created.rawId));
    return {
        id: credentialId,
        label: display,
        createdAt: Date.now(),
    };
}
export async function verifyLocalMfaCredential(credential) {
    if (!isLocalMfaSupported()) {
        throw new Error("WebAuthn is not supported in this browser");
    }
    const challenge = randomBytes(32);
    const credentialId = fromBase64Url(credential.id);
    const assertion = await navigator.credentials.get({
        publicKey: {
            challenge: toArrayBuffer(challenge),
            allowCredentials: [
                {
                    id: toArrayBuffer(credentialId),
                    type: "public-key",
                },
            ],
            userVerification: "preferred",
            timeout: 45_000,
        },
    });
    return assertion instanceof PublicKeyCredential;
}
