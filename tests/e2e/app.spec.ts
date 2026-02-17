import { test, expect } from "@playwright/test";
import path from "node:path";
import fs from "node:fs";

async function openApp(page: import("@playwright/test").Page) {
  await page.addInitScript(() => {
    window.localStorage.setItem("nullid:onboarding-complete", "true");
    window.localStorage.setItem("nullid:onboarding-step", "0");
  });
  await page.goto("/");
  const onboardingDialog = page.getByRole("dialog", { name: /Onboarding tour/i });
  if (await onboardingDialog.isVisible()) {
    await page.getByRole("button", { name: /^skip$/i }).click();
    await expect(onboardingDialog).toBeHidden();
  }
}

test("hash input stays responsive", async ({ page }) => {
  await openApp(page);
  await page.getByRole("button", { name: /Hash & Verify/i }).click();
  const textarea = page.getByLabel("Text to hash");
  await textarea.click();
  await textarea.type("hello world", { delay: 10 });
  await expect(textarea).toHaveValue("hello world");
  const digestInput = page.getByLabel("Computed hash");
  await expect(digestInput).not.toHaveValue("");
});

test("secure note persists after reload", async ({ page }) => {
  await openApp(page);
  await page.getByRole("button", { name: /Secure Notes/i }).click();
  await page.getByLabel("Vault key").fill("playwright-pass");
  await page.getByRole("button", { name: /^unlock$/i }).click();
  await page.getByLabel("Note title").fill("pw-note");
  await page.getByLabel("Note body").fill("persist me");
  await page.getByRole("button", { name: /^store$/i }).click();
  await expect(page.getByText("pw-note").first()).toBeVisible();
  await page.reload();
  await page.getByRole("button", { name: /Secure Notes/i }).click();
  await page.getByLabel("Vault key").fill("playwright-pass");
  await page.getByRole("button", { name: /^unlock$/i }).click();
  await expect(page.getByText("pw-note").first()).toBeVisible();
});

test("encrypt and decrypt text renders output", async ({ page }) => {
  await openApp(page);
  await page.getByRole("button", { name: /Encrypt \/ Decrypt/i }).click();
  await page.getByLabel("Plaintext").fill("roundtrip text");
  await page.getByLabel("Encrypt passphrase").fill("play-pass");
  await page.getByRole("button", { name: "seal text" }).click();
  await page.getByLabel("Decrypt passphrase").fill("play-pass");
  await page.getByRole("button", { name: "decrypt text" }).click();
  await expect(page.getByText("roundtrip text")).toBeVisible();
});

test("download envelope button triggers download", async ({ page }) => {
  await openApp(page);
  await page.getByRole("button", { name: /Encrypt \/ Decrypt/i }).click();
  await page.getByLabel("Encrypt passphrase").fill("play-pass");
  const filePath = path.join(process.cwd(), "tests/e2e/tmp.txt");
  fs.writeFileSync(filePath, "file-download");
  await page.locator('input[aria-label="Pick file to encrypt"]').setInputFiles(filePath);
  await page.getByRole("button", { name: "seal file" }).click();
  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "download envelope" }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toContain(".nullid");
  fs.unlinkSync(filePath);
});

test("redaction module applies masking for detected values", async ({ page }) => {
  await openApp(page);
  await page.getByRole("button", { name: /Text Redaction/i }).click();
  await page.getByRole("textbox", { name: "Redaction input" }).fill("Reach me at alice@example.com token abcdefghijklmnopqrstuvwxyz1234");
  await page.getByRole("button", { name: /apply redaction/i }).click();
  const output = page.getByLabel("Redacted output");
  await expect(output).toContainText("[Email]");
  await expect(output).toContainText("[Bearer / token]");
});

test("metadata module flags HEIC inputs as unsupported with remediation text", async ({ page }) => {
  await openApp(page);
  await page.getByRole("button", { name: /Metadata Inspector/i }).click();
  const imageInput = page.locator('input[type="file"][accept="image/*"]');
  await imageInput.setInputFiles({
    name: "sample.heic",
    mimeType: "image/heic",
    buffer: Buffer.from("heic"),
  });
  await expect(page.getByText(/HEIC\/HEIF parsing is usually blocked/i)).toBeVisible();
  await expect(page.getByLabel("unsupported")).toBeVisible();
});

test("sanitize module exports local safe-share bundle", async ({ page }) => {
  await openApp(page);
  await page.getByRole("button", { name: /Log Sanitizer/i }).click();
  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: /^export bundle$/i }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toContain("nullid-safe-share-bundle");
});

test("sanitize module batch-processes local files", async ({ page }) => {
  await openApp(page);
  await page.getByRole("button", { name: /Log Sanitizer/i }).click();
  const batchInput = page.locator('input[type="file"][multiple]');
  await batchInput.setInputFiles([
    { name: "batch-a.log", mimeType: "text/plain", buffer: Buffer.from("alice@example.com from 203.0.113.10") },
    { name: "batch-b.log", mimeType: "text/plain", buffer: Buffer.from("user=bob token=abcdefghijklmnopqrstuvwxyz12345") },
  ]);
  await expect(page.getByText("batch-a.log")).toBeVisible();
  await expect(page.getByText("batch-b.log")).toBeVisible();
});

test("mobile navigation scrolls and allows selection", async ({ browser }) => {
  const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
  const page = await context.newPage();
  await openApp(page);
  await page.getByRole("button", { name: /Encrypt \/ Decrypt/i }).click();
  await expect(page.getByText("Encrypt").first()).toBeVisible();
  await context.close();
});

test("mobile secure notes flow supports create and render", async ({ browser }) => {
  const context = await browser.newContext({ viewport: { width: 375, height: 812 } });
  const page = await context.newPage();
  await openApp(page);
  await page.getByRole("button", { name: /Secure Notes/i }).click();
  await page.getByLabel("Vault key").fill("mobile-pass");
  await page.getByRole("button", { name: /^unlock$/i }).click();
  await page.getByLabel("Note title").fill("mobile-note");
  await page.getByLabel("Note body").fill("created on mobile");
  await page.getByRole("button", { name: /^store$/i }).click();
  await expect(page.getByText("mobile-note").first()).toBeVisible();
  await context.close();
});

test("mobile visual snapshot :: sanitize module", async ({ browser }) => {
  test.skip(!hasSnapshotBaseline("mobile-sanitize.png"), `snapshot baseline missing for ${process.platform}`);
  await expectMobileModuleSnapshot(browser, /Log Sanitizer/i, "mobile-sanitize.png");
});

test("mobile visual snapshot :: metadata module", async ({ browser }) => {
  test.skip(!hasSnapshotBaseline("mobile-metadata.png"), `snapshot baseline missing for ${process.platform}`);
  await expectMobileModuleSnapshot(browser, /Metadata Inspector/i, "mobile-metadata.png");
});

test("mobile visual snapshot :: vault module", async ({ browser }) => {
  test.skip(!hasSnapshotBaseline("mobile-vault.png"), `snapshot baseline missing for ${process.platform}`);
  await expectMobileModuleSnapshot(browser, /Secure Notes/i, "mobile-vault.png");
});

async function expectMobileModuleSnapshot(
  browser: import("@playwright/test").Browser,
  moduleButton: RegExp,
  snapshotName: string,
) {
  const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
  const page = await context.newPage();
  await openApp(page);
  await page.getByRole("button", { name: moduleButton }).click();
  await expect(page.locator(".workspace")).toHaveScreenshot(snapshotName, {
    animations: "disabled",
    caret: "hide",
  });
  await context.close();
}

function hasSnapshotBaseline(snapshotName: string) {
  const stem = snapshotName.replace(/\.png$/i, "");
  const file = path.join(process.cwd(), "tests/e2e/app.spec.ts-snapshots", `${stem}-${process.platform}.png`);
  return fs.existsSync(file);
}
