export type MotionMode = "off" | "signal";

// Flip this to "off" for a clean rollback to the static baseline.
export const EXPERIMENTAL_MOTION_MODE: MotionMode = "signal";

export function resolveMotionMode(prefersReducedMotion: boolean): MotionMode {
  if (prefersReducedMotion) {
    return "off";
  }

  return EXPERIMENTAL_MOTION_MODE;
}
