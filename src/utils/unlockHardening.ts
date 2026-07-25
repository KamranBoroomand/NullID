import { randomBytes } from "./encoding.js";

export interface UnlockPolicy {
  captchaAfterFailures: number;
  lockoutAfterFailures: number;
  baseCooldownSeconds: number;
  maxCooldownSeconds: number;
}

export interface UnlockThrottleState {
  failures: number;
  lockoutUntil: number;
}

export interface HumanCheckChallenge {
  id: string;
  prompt: string;
  answer: number;
}

export const DEFAULT_UNLOCK_POLICY: UnlockPolicy = {
  captchaAfterFailures: 3,
  lockoutAfterFailures: 5,
  baseCooldownSeconds: 15,
  maxCooldownSeconds: 300,
};

function clampInt(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, Math.floor(value)));
}

export function createUnlockThrottleState(): UnlockThrottleState {
  return { failures: 0, lockoutUntil: 0 };
}

export function isUnlockBlocked(state: UnlockThrottleState, now = Date.now()): boolean {
  return Number.isFinite(state.lockoutUntil) && state.lockoutUntil > now;
}

export function shouldRequireHumanCheck(state: UnlockThrottleState, policy: UnlockPolicy = DEFAULT_UNLOCK_POLICY): boolean {
  return state.failures >= policy.captchaAfterFailures;
}

export function cooldownSecondsForFailureCount(failures: number, policy: UnlockPolicy = DEFAULT_UNLOCK_POLICY): number {
  if (failures < policy.lockoutAfterFailures) return 0;
  const exponent = failures - policy.lockoutAfterFailures;
  const raw = policy.baseCooldownSeconds * 2 ** exponent;
  return clampInt(raw, policy.baseCooldownSeconds, policy.maxCooldownSeconds);
}

export function applyUnlockFailure(
  state: UnlockThrottleState,
  now = Date.now(),
  policy: UnlockPolicy = DEFAULT_UNLOCK_POLICY,
): UnlockThrottleState {
  const failures = state.failures + 1;
  const cooldownSeconds = cooldownSecondsForFailureCount(failures, policy);
  const lockoutUntil = cooldownSeconds > 0 ? now + cooldownSeconds * 1000 : state.lockoutUntil;
  return { failures, lockoutUntil };
}

export function clearUnlockFailures(): UnlockThrottleState {
  return createUnlockThrottleState();
}

export function createHumanCheckChallenge(): HumanCheckChallenge {
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

export function verifyHumanCheck(challenge: HumanCheckChallenge, candidate: string): boolean {
  const parsed = Number(candidate.trim());
  if (!Number.isFinite(parsed)) return false;
  return parsed === challenge.answer;
}
