import { expect, test, type Page } from "@playwright/test";

type AppLocale = "en" | "ru" | "fa";

const expected = {
  en: {
    hashTitle: "Hash & Verify",
    verifyTitle: "Verify Package",
    commandPlaceholder: "Type a command or tool…",
    onboardingDialog: "Onboarding tour",
    onboardingSkip: "skip",
    incidentPurposeLabel: "Incident purpose",
    safeSharePreset: "General safe share",
    safeSharePreview: "Safe Share Assistant export for text-based content.",
    incidentMode: "Incident handoff",
    incidentPreview: "Incident Workflow export with case context, prepared artifacts, and receiver-facing reporting.",
    incidentPurpose: "Prepare an incident handoff package.",
    lang: "en-US",
    dir: "ltr",
  },
  ru: {
    hashTitle: "Хэш и проверка",
    verifyTitle: "Проверить пакет",
    commandPlaceholder: "Введите команду или инструмент…",
    onboardingDialog: "Тур онбординга",
    onboardingSkip: "пропустить",
    incidentPurposeLabel: "Цель инцидента",
    safeSharePreset: "Общая безопасная передача",
    safeSharePreview: "Экспорт Safe Share Assistant для текстового контента.",
    incidentMode: "Передача инцидента",
    incidentPreview: "Экспорт Incident Workflow с контекстом кейса, подготовленными артефактами и отчетностью для получателя.",
    incidentPurpose: "Подготовьте пакет передачи инцидента.",
    lang: "ru-RU",
    dir: "ltr",
  },
  fa: {
    hashTitle: "هش و اعتبارسنجی",
    verifyTitle: "اعتبارسنجی بسته",
    commandPlaceholder: "یک فرمان یا ابزار بنویسید…",
    onboardingDialog: "راهنمای شروع",
    onboardingSkip: "رد کردن",
    incidentPurposeLabel: "هدف رخداد",
    safeSharePreset: "اشتراک امن عمومی",
    safeSharePreview: "خروجی «دستیار اشتراک امن» برای محتوای متن‌محور.",
    incidentMode: "تحویل رخداد",
    incidentPreview: "خروجی «گردش‌کار رخداد» با زمینهٔ پرونده، اقلام آماده‌شده و گزارش رو‌به‌گیرنده.",
    incidentPurpose: "یک بستهٔ تحویل رخداد آماده کنید.",
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

  const shareButton = page.locator("button.module-button").filter({ hasText: ":share" }).first();
  await shareButton.click();
  await expect(page.getByRole("button", { name: spec.safeSharePreset, exact: true })).toBeVisible();
  if (locale !== "en") {
    await expect(page.getByRole("button", { name: expected.en.safeSharePreset, exact: true })).toHaveCount(0);
  }
  await page.locator("textarea").first().fill("token=abcdefghijklmnopqrstuvwxyz12345 alice@example.com");
  await expect(page.getByText(spec.safeSharePreview, { exact: true })).toBeVisible();
  if (locale !== "en") {
    await expect(page.getByText(expected.en.safeSharePreview, { exact: true })).toHaveCount(0);
  }

  const incidentButton = page.locator("button.module-button").filter({ hasText: ":incident" }).first();
  await incidentButton.click();
  await expect(page.getByRole("button", { name: spec.incidentMode, exact: true })).toBeVisible();
  if (locale !== "en") {
    await expect(page.getByRole("button", { name: expected.en.incidentMode, exact: true })).toHaveCount(0);
  }
  await expect(page.getByText(spec.incidentPreview, { exact: true })).toBeVisible();
  await expect(page.getByLabel(spec.incidentPurposeLabel)).toHaveValue(spec.incidentPurpose);
  if (locale !== "en") {
    await expect(page.getByText(expected.en.incidentPreview, { exact: true })).toHaveCount(0);
    await expect(page.getByLabel(spec.incidentPurposeLabel)).not.toHaveValue(expected.en.incidentPurpose);
  }
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
