import { expect, test } from "@playwright/test";

type ThemeMode = "light" | "dark";

const desktopViewport = { width: 1366, height: 900 };
const themes: ThemeMode[] = ["light", "dark"];
const coreModules: Array<{ key: string; button: RegExp; maxDiffPixelRatio?: number }> = [
  { key: "hash", button: /Hash & Verify/i },
  { key: "redact", button: /Text Redaction/i },
  { key: "sanitize", button: /Log Sanitizer/i },
  { key: "meta", button: /Metadata Inspector/i },
  { key: "enc", button: /Encrypt \/ Decrypt/i },
  { key: "pw", button: /Password & Passphrase/i, maxDiffPixelRatio: 0.02 },
  { key: "vault", button: /Secure Notes/i },
];

for (const moduleEntry of coreModules) {
  for (const theme of themes) {
    test(`desktop visual snapshot :: ${moduleEntry.key} :: ${theme}`, async ({ browser }) => {
      const context = await browser.newContext({
        viewport: desktopViewport,
        colorScheme: theme === "dark" ? "dark" : "light",
      });
      const page = await context.newPage();
      await openApp(page, theme);
      await page.getByRole("button", { name: moduleEntry.button }).click();
      await expect(page).toHaveScreenshot(`desktop-${moduleEntry.key}-${theme}.png`, {
        animations: "disabled",
        caret: "hide",
        fullPage: false,
        maxDiffPixelRatio: moduleEntry.maxDiffPixelRatio ?? 0,
      });
      await context.close();
    });
  }
}

async function openApp(page: import("@playwright/test").Page, theme: ThemeMode) {
  await page.addInitScript((themeMode) => {
    Math.random = () => 0.123456789;
    window.localStorage.setItem("nullid:onboarding-complete", "true");
    window.localStorage.setItem("nullid:onboarding-step", "0");
    window.localStorage.setItem("nullid:theme", JSON.stringify(themeMode));
    window.localStorage.setItem("nullid:locale", "en");
  }, theme);
  await page.goto("/");
  const onboardingDialog = page.getByRole("dialog", { name: /Onboarding tour/i });
  if (await onboardingDialog.isVisible()) {
    await page.getByRole("button", { name: /^skip$/i }).click();
    await expect(onboardingDialog).toBeHidden();
  }
}
