import { expect, test, type Page } from "@playwright/test";

type AppLocale = "ru" | "fa";
type ModuleKey = "hash" | "redact" | "sanitize" | "meta" | "enc" | "pw" | "vault" | "selftest" | "guide";

interface ViewportScenario {
  label: string;
  width: number;
  height: number;
}

interface LayoutMetrics {
  docOverflow: number;
  bodyOverflow: number;
  headerOverflow: number;
  moduleHeaderOverflow: number;
  frameShellFound: boolean;
  frameShellRadius: number;
  frameShellOverflowX: string;
  frameShellOverflowY: string;
}

const locales: AppLocale[] = ["ru", "fa"];
const moduleKeys: ModuleKey[] = ["hash", "redact", "sanitize", "meta", "enc", "pw", "vault", "selftest", "guide"];
const viewports: ViewportScenario[] = [
  { label: "desktop", width: 1280, height: 900 },
  { label: "mobile", width: 390, height: 844 },
];
const MAX_HORIZONTAL_OVERFLOW_PX = 2;

for (const viewport of viewports) {
  for (const locale of locales) {
    test(`i18n layout integrity :: ${viewport.label} :: ${locale}`, async ({ browser }) => {
      const context = await browser.newContext({ viewport: { width: viewport.width, height: viewport.height } });

      for (const moduleKey of moduleKeys) {
        const page = await context.newPage();
        await openLocalizedModule(page, locale, moduleKey);
        const metrics = await collectLayoutMetrics(page);
        await page.close();

        const scenario = `${viewport.label}/${locale}/${moduleKey}`;
        expect(metrics.frameShellFound, `${scenario}: frame shell is missing`).toBe(true);
        expect(metrics.docOverflow, `${scenario}: document has horizontal overflow`).toBeLessThanOrEqual(MAX_HORIZONTAL_OVERFLOW_PX);
        expect(metrics.bodyOverflow, `${scenario}: body has horizontal overflow`).toBeLessThanOrEqual(MAX_HORIZONTAL_OVERFLOW_PX);
        expect(metrics.headerOverflow, `${scenario}: header has horizontal overflow`).toBeLessThanOrEqual(MAX_HORIZONTAL_OVERFLOW_PX);
        expect(metrics.moduleHeaderOverflow, `${scenario}: module header has horizontal overflow`).toBeLessThanOrEqual(MAX_HORIZONTAL_OVERFLOW_PX);
        expect(metrics.frameShellRadius, `${scenario}: frame corners should remain rounded`).toBeGreaterThan(0);
        expect(metrics.frameShellOverflowX, `${scenario}: frame shell must clip X overflow`).toBe("hidden");
        expect(metrics.frameShellOverflowY, `${scenario}: frame shell must clip Y overflow`).toBe("hidden");
      }

      await context.close();
    });
  }
}

async function openLocalizedModule(page: Page, locale: AppLocale, moduleKey: ModuleKey) {
  await page.addInitScript(({ initialLocale, initialModule }) => {
    window.localStorage.setItem("nullid:onboarding-complete", "true");
    window.localStorage.setItem("nullid:onboarding-step", "0");
    window.localStorage.setItem("nullid:locale", initialLocale);
    window.localStorage.setItem("nullid:last-module", initialModule);
  }, { initialLocale: locale, initialModule: moduleKey });

  await page.goto("/");
  await expect(page.locator(".frame-shell")).toBeVisible();
  await expect(page.locator(".global-header")).toBeVisible();
  await page.evaluate(async () => {
    if (!("fonts" in document)) return;
    try {
      await document.fonts.ready;
    } catch {
      // Ignore font API failures and continue with measured layout.
    }
  });
  await page.waitForTimeout(250);
}

async function collectLayoutMetrics(page: Page): Promise<LayoutMetrics> {
  return page.evaluate(() => {
    const horizontalOverflow = (node: Element | null) => {
      if (!(node instanceof HTMLElement)) return 0;
      return Math.max(0, Math.round(node.scrollWidth - node.clientWidth));
    };

    const frameShell = document.querySelector(".frame-shell");
    const frameStyle = frameShell instanceof HTMLElement ? getComputedStyle(frameShell) : null;
    const radius = Number.parseFloat(frameStyle?.borderTopLeftRadius ?? "0");

    return {
      docOverflow: horizontalOverflow(document.documentElement),
      bodyOverflow: horizontalOverflow(document.body),
      headerOverflow: horizontalOverflow(document.querySelector(".global-header")),
      moduleHeaderOverflow: horizontalOverflow(document.querySelector(".module-header")),
      frameShellFound: frameShell instanceof HTMLElement,
      frameShellRadius: Number.isFinite(radius) ? radius : 0,
      frameShellOverflowX: frameStyle?.overflowX ?? "",
      frameShellOverflowY: frameStyle?.overflowY ?? "",
    };
  });
}
