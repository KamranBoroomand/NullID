export const SELF_TEST_INTERVAL_SECONDS = {
  defaultValue: 180,
  min: 30,
  max: 3600,
} as const;

export function clampSelfTestIntervalSeconds(value: number) {
  return Math.min(SELF_TEST_INTERVAL_SECONDS.max, Math.max(SELF_TEST_INTERVAL_SECONDS.min, value));
}
