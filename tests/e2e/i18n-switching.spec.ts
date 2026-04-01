import { expect, test, type Page } from "@playwright/test";

type AppLocale = "en" | "ru" | "fa";

const expected = {
  en: {
    hashTitle: "Hash & Verify",
    verifyTitle: "Verify Package",
    commandPlaceholder: "Type a command or tool…",
    onboardingDialog: "Onboarding tour",
    onboardingSkip: "skip",
    lang: "en-US",
    dir: "ltr",
  },
  ru: {
    hashTitle: "Хэш и проверка",
    verifyTitle: "Проверить пакет",
    commandPlaceholder: "Введите команду или инструмент…",
    onboardingDialog: "Тур онбординга",
    onboardingSkip: "пропустить",
    lang: "ru-RU",
    dir: "ltr",
  },
  fa: {
    hashTitle: "هش و اعتبارسنجی",
    verifyTitle: "اعتبارسنجی بسته",
    commandPlaceholder: "یک فرمان یا ابزار بنویسید…",
    onboardingDialog: "راهنمای شروع",
    onboardingSkip: "رد کردن",
    lang: "fa-IR",
    dir: "rtl",
  },
} as const;

const locales: AppLocale[] = ["en", "ru", "fa"];

test("locale switching updates html metadata and key UI surfaces", async ({ page }) => {
  await openApp(page, { locale: "en", onboardingComplete: true });

  for (const locale of locales) {
    await switchLocale(page, locale);
    await assertLocaleSurface(page, locale);
  }
});

test.describe("localized onboarding + verification shell", () => {
  for (const locale of locales) {
    test(`onboarding and verify shell localize cleanly :: ${locale}`, async ({ page }) => {
      await openApp(page, { locale, onboardingComplete: false, module: "verify" });

      const spec = expected[locale];
      await expect(page.getByRole("dialog", { name: spec.onboardingDialog })).toBeVisible();
      await page.getByRole("button", { name: new RegExp(`^${escapeRegex(spec.onboardingSkip)}$`, "i") }).click();
      await expect(page.getByRole("dialog", { name: spec.onboardingDialog })).toBeHidden();

      const verifyButton = page.locator("button.module-button").filter({ hasText: ":verify" }).first();
      await verifyButton.click();
      await expect(page.locator(".page-title")).toHaveText(spec.verifyTitle);

      if (locale !== "en") {
        await expect(page.locator(".page-title")).not.toHaveText(expected.en.verifyTitle);
      }
    });
  }
});

async function assertLocaleSurface(page: Page, locale: AppLocale) {
  const spec = expected[locale];

  await expect(page.locator("html")).toHaveAttribute("lang", spec.lang);
  await expect(page.locator("html")).toHaveAttribute("dir", spec.dir);

  const hashButton = page.locator("button.module-button").filter({ hasText: ":hash" }).first();
  await expect(hashButton).toContainText(spec.hashTitle);
  if (locale !== "en") {
    await expect(hashButton).not.toContainText(expected.en.hashTitle);
  }

  await page.keyboard.press("/");
  const commandInput = page.locator(".command-field input");
  await expect(commandInput).toHaveAttribute("placeholder", spec.commandPlaceholder);
  await page.keyboard.press("Escape");

  const verifyButton = page.locator("button.module-button").filter({ hasText: ":verify" }).first();
  await verifyButton.click();
  await expect(page.locator(".page-title")).toHaveText(spec.verifyTitle);
}

async function openApp(
  page: Page,
  options: { locale: AppLocale; onboardingComplete: boolean; module?: string },
) {
  await page.addInitScript(
    ({ locale, onboardingComplete, module }) => {
      window.localStorage.setItem("nullid:locale", locale);
      window.localStorage.setItem("nullid:onboarding-complete", onboardingComplete ? "true" : "false");
      window.localStorage.setItem("nullid:onboarding-step", "0");
      window.localStorage.setItem("nullid:last-module", module ?? "hash");
    },
    { locale: options.locale, onboardingComplete: options.onboardingComplete, module: options.module ?? "hash" },
  );

  await page.goto("/");
  await expect(page.locator(".frame-shell")).toBeVisible();
}

async function switchLocale(page: Page, locale: AppLocale) {
  const desktopLocale = page.locator(".action-row .header-locale-select");
  if ((await desktopLocale.count()) > 0) {
    await desktopLocale.selectOption(locale);
    return;
  }

  const compactToggle = page.locator(".compact-actions > button").first();
  await compactToggle.click();
  await page.locator(".compact-menu .header-locale-select").selectOption(locale);
}

function escapeRegex(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
