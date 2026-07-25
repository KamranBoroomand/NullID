import { describe, it } from "node:test";
import * as assert from "node:assert/strict";
import { themeTokens } from "../theme/tokens.js";

function hexToRgb(hex: string) {
  const normalized = hex.replace("#", "");
  const value = normalized.length === 3 ? normalized.split("").map((c) => c + c).join("") : normalized;
  const int = parseInt(value, 16);
  return [(int >> 16) & 255, (int >> 8) & 255, int & 255];
}

function relativeLuminance(color: string) {
  const [r, g, b] = hexToRgb(color).map((channel) => {
    const c = channel / 255;
    return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrastRatio(foreground: string, background: string) {
  const L1 = relativeLuminance(foreground);
  const L2 = relativeLuminance(background);
  const [light, dark] = L1 > L2 ? [L1, L2] : [L2, L1];
  return (light + 0.05) / (dark + 0.05);
}

describe("theme contrast", () => {
  it("meets text and accent contrast targets", () => {
    Object.values(themeTokens).forEach((palette) => {
      assert.equal(contrastRatio(palette.textPrimary, palette.background) >= 4.5, true);
      assert.equal(contrastRatio(palette.textPrimary, palette.surface0) >= 4.5, true);
      assert.equal(contrastRatio(palette.textMuted, palette.background) >= 3, true);
      assert.equal(contrastRatio(palette.accent, palette.background) >= 3, true);
      assert.equal(contrastRatio(palette.accent, palette.surface1) >= 3, true);
    });
  });
});
