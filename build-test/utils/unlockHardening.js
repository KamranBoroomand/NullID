import { randomBytes } from "./encoding.js";
export const DEFAULT_UNLOCK_POLICY = {
    captchaAfterFailures: 3,
    lockoutAfterFailures: 5,
    baseCooldownSeconds: 15,
    maxCooldownSeconds: 300,
};
function clampInt(value, min, max) {
    return Math.min(max, Math.max(min, Math.floor(value)));
}
export function createUnlockThrottleState() {
    return { failures: 0, lockoutUntil: 0 };
}
export function isUnlockBlocked(state, now = Date.now()) {
    return Number.isFinite(state.lockoutUntil) && state.lockoutUntil > now;
}
export function shouldRequireHumanCheck(state, policy = DEFAULT_UNLOCK_POLICY) {
    return state.failures >= policy.captchaAfterFailures;
}
export function cooldownSecondsForFailureCount(failures, policy = DEFAULT_UNLOCK_POLICY) {
    if (failures < policy.lockoutAfterFailures)
        return 0;
    const exponent = failures - policy.lockoutAfterFailures;
    const raw = policy.baseCooldownSeconds * 2 ** exponent;
    return clampInt(raw, policy.baseCooldownSeconds, policy.maxCooldownSeconds);
}
export function applyUnlockFailure(state, now = Date.now(), policy = DEFAULT_UNLOCK_POLICY) {
    const failures = state.failures + 1;
    const cooldownSeconds = cooldownSecondsForFailureCount(failures, policy);
    const lockoutUntil = cooldownSeconds > 0 ? now + cooldownSeconds * 1000 : state.lockoutUntil;
    return { failures, lockoutUntil };
}
export function clearUnlockFailures() {
    return createUnlockThrottleState();
}
export function createHumanCheckChallenge() {
    const values = randomBytes(4);
    const left = (values[0] % 9) + 1;
    const right = (values[1] % 9) + 1;
    const useMultiply = values[2] % 3 === 0;
    const answer = useMultiply ? left * right : left + right;
    const prompt = useMultiply ? `${left} × ${right} = ?` : `${left} + ${right} = ?`;
    return {
        id: `${Date.now().toString(36)}-${values[3].toString(16).padStart(2, "0")}`,
        prompt,
        answer,
    };
}
export function verifyHumanCheck(challenge, candidate) {
    const parsed = Number(candidate.trim());
    if (!Number.isFinite(parsed))
        return false;
    return parsed === challenge.answer;
}
