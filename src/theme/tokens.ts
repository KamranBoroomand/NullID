export type ThemeMode = "light" | "dark";

export type ThemePalette = {
  background: string;
  surface0: string;
  surface1: string;
  surface2: string;
  surface3: string;
  workspaceBg: string;
  panelAlt: string;
  controlBg: string;
  controlBgHover: string;
  tokenBg: string;
  outputBg: string;
  overlayBackdrop: string;
  borderSubtle: string;
  borderStrong: string;
  textPrimary: string;
  textSecondary: string;
  textMuted: string;
  accent: string;
  accentSoft: string;
  danger: string;
  success: string;
  focusRing: string;
};

export const themeTokens: Record<ThemeMode, ThemePalette> = {
  light: {
    background: "#ece6dc",
    surface0: "#f7f2e8",
    surface1: "#efe7d9",
    surface2: "#e4dac8",
    surface3: "#d2c3ae",
    workspaceBg: "linear-gradient(180deg, var(--surface-0), color-mix(in srgb, var(--background) 86%, var(--surface-1) 14%))",
    panelAlt: "#f2ebdf",
    controlBg: "#f4eee2",
    controlBgHover: "#ece4d4",
    tokenBg: "#e9e0d1",
    outputBg: "#eee6d9",
    overlayBackdrop: "rgba(27, 22, 16, 0.62)",
    borderSubtle: "#b3a691",
    borderStrong: "#7d6f5e",
    textPrimary: "#161310",
    textSecondary: "#2c2721",
    textMuted: "#62584d",
    accent: "#5f7712",
    accentSoft: "rgba(95, 119, 18, 0.12)",
    danger: "#b94d3b",
    success: "#22764c",
    focusRing: "#5f7712",
  },
  dark: {
    background: "#020304",
    surface0: "#07090b",
    surface1: "#0d1115",
    surface2: "#141a20",
    surface3: "#1d252d",
    workspaceBg: "linear-gradient(180deg, var(--surface-0), color-mix(in srgb, var(--background) 90%, var(--surface-1) 10%))",
    panelAlt: "#090b0d",
    controlBg: "#06080a",
    controlBgHover: "#0f1418",
    tokenBg: "#090b0d",
    outputBg: "#030405",
    overlayBackdrop: "rgba(3, 4, 5, 0.84)",
    borderSubtle: "#2f3944",
    borderStrong: "#556271",
    textPrimary: "#f4f0e8",
    textSecondary: "#d8d2c5",
    textMuted: "#7f8985",
    accent: "#d6ff62",
    accentSoft: "rgba(214, 255, 98, 0.1)",
    danger: "#ff8f78",
    success: "#6dcf9e",
    focusRing: "#cbf36a",
  },
};

export const contrastThresholds = {
  text: 4.5,
  largeText: 3,
  accent: 3,
  disabled: 3,
};
