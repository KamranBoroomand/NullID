import { HMAC_SHA256_ALGORITHM, sha256Base64Url, signHash, verifyHashSignature } from "./integrity.js";
const MIN_PAYLOAD_HASH_LENGTH = 16;
const MAX_KEY_HINT_LENGTH = 64;
export class SnapshotIntegrityError extends Error {
    code;
    category;
    constructor(code, message) {
        super(message);
        this.name = "SnapshotIntegrityError";
        this.code = code;
        this.category = classifySnapshotIntegrityCode(code);
    }
}
export async function createSnapshotIntegrity(payload, countKey, count, options) {
    if (!Number.isInteger(count) || count < 0) {
        throw new SnapshotIntegrityError("integrity-invalid", `Invalid snapshot ${countKey}`);
    }
    const payloadHash = await sha256Base64Url(payload);
    const integrity = {
        [countKey]: count,
        payloadHash,
    };
    if (!options?.signingPassphrase) {
        return { integrity };
    }
    return {
        integrity,
        signature: {
            algorithm: HMAC_SHA256_ALGORITHM,
            value: await signHash(payloadHash, options.signingPassphrase),
            keyHint: sanitizeSnapshotKeyHint(options.keyHint),
        },
    };
}
export async function verifySnapshotIntegrity(options) {
    const integrityRecord = asRecord(options.integrity);
    if (!integrityRecord) {
        throw new SnapshotIntegrityError("integrity-missing", options.missingIntegrityMessage ?? `${options.subject} integrity metadata missing`);
    }
    const countValue = integrityRecord[options.countKey];
    const payloadHash = integrityRecord.payloadHash;
    if (typeof countValue !== "number" || !Number.isInteger(countValue) || countValue < 0 || typeof payloadHash !== "string" || payloadHash.length < MIN_PAYLOAD_HASH_LENGTH) {
        throw new SnapshotIntegrityError("integrity-invalid", options.invalidIntegrityMessage ?? `Invalid ${options.subject.toLowerCase()} integrity metadata`);
    }
    if (countValue !== options.actualCount) {
        throw new SnapshotIntegrityError("integrity-count-mismatch", options.countMismatchMessage ?? `${options.subject} integrity mismatch (${options.countKey})`);
    }
    const computedHash = await sha256Base64Url(options.payload);
    if (computedHash !== payloadHash) {
        throw new SnapshotIntegrityError("integrity-hash-mismatch", options.hashMismatchMessage ?? `${options.subject} integrity mismatch (hash)`);
    }
    const signatureRecord = options.signature === undefined ? null : asRecord(options.signature);
    if (options.signature !== undefined) {
        if (!signatureRecord ||
            signatureRecord.algorithm !== HMAC_SHA256_ALGORITHM ||
            typeof signatureRecord.value !== "string" ||
            (signatureRecord.keyHint !== undefined && typeof signatureRecord.keyHint !== "string")) {
            throw new SnapshotIntegrityError("signature-invalid", options.invalidSignatureMessage ?? `Invalid ${options.subject.toLowerCase()} signature metadata`);
        }
        if (!options.verificationPassphrase) {
            throw new SnapshotIntegrityError("verification-required", options.verificationRequiredMessage ?? `${options.subject} is signed; verification passphrase required`);
        }
        const verified = await verifyHashSignature(payloadHash, signatureRecord.value, options.verificationPassphrase);
        if (!verified) {
            throw new SnapshotIntegrityError("verification-failed", options.verificationFailedMessage ?? `${options.subject} signature verification failed`);
        }
        return {
            payloadHash,
            signed: true,
            verified: true,
            keyHint: signatureRecord.keyHint,
            algorithm: HMAC_SHA256_ALGORITHM,
        };
    }
    return {
        payloadHash,
        signed: false,
        verified: false,
    };
}
export function sanitizeSnapshotKeyHint(value) {
    const trimmed = value?.trim().slice(0, MAX_KEY_HINT_LENGTH);
    return trimmed ? trimmed : undefined;
}
export function classifySnapshotIntegrityError(error) {
    if (!(error instanceof SnapshotIntegrityError))
        return "unknown";
    return error.category;
}
function asRecord(value) {
    if (!value || typeof value !== "object" || Array.isArray(value))
        return null;
    return value;
}
function classifySnapshotIntegrityCode(code) {
    if (code === "integrity-missing" || code === "integrity-invalid" || code === "signature-invalid")
        return "metadata";
    if (code === "integrity-count-mismatch" || code === "integrity-hash-mismatch")
        return "integrity";
    if (code === "verification-required" || code === "verification-failed")
        return "verification";
    return "unknown";
}
