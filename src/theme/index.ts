import { themeTokens, ThemeMode } from "./tokens";
import { DEFAULT_THEME_MODE, isThemeMode } from "../utils/persistedSettings.js";

export function applyTheme(mode: ThemeMode) {
  const root = document.documentElement;
  const resolvedMode = isThemeMode(mode) ? mode : DEFAULT_THEME_MODE;
  const palette = themeTokens[resolvedMode];
  Object.entries(palette).forEach(([key, value]) => {
    root.style.setProperty(`--${toKebab(key)}`, value);
  });
  root.dataset.theme = resolvedMode;
}

function toKebab(value: string) {
  return value.replace(/[A-Z]/g, (m) => `-${m.toLowerCase()}`);
}
