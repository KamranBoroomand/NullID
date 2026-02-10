import { test, expect } from "@playwright/test";
import path from "node:path";
import fs from "node:fs";

test("hash input stays responsive", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: /Hash & Verify/i }).click();
  const textarea = page.getByLabel("Text to hash");
  await textarea.click();
  await textarea.type("hello world", { delay: 10 });
  await expect(textarea).toHaveValue("hello world");
  const digestInput = page.getByLabel("Computed hash");
  await expect(digestInput).not.toHaveValue("");
});

test("secure note persists after reload", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: /Secure Notes/i }).click();
  await page.getByLabel("Vault key").fill("playwright-pass");
  await page.getByRole("button", { name: /^unlock$/i }).click();
  await page.getByLabel("Note title").fill("pw-note");
  await page.getByLabel("Note body").fill("persist me");
  await page.getByRole("button", { name: /^store$/i }).click();
  await page.reload();
  await page.getByRole("button", { name: /Secure Notes/i }).click();
  await page.getByLabel("Vault key").fill("playwright-pass");
  await page.getByRole("button", { name: /^unlock$/i }).click();
  await expect(page.getByText("pw-note").first()).toBeVisible();
});

test("encrypt and decrypt text renders output", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: /Encrypt \/ Decrypt/i }).click();
  await page.getByLabel("Plaintext").fill("roundtrip text");
  await page.getByLabel("Encrypt passphrase").fill("play-pass");
  await page.getByRole("button", { name: "seal text" }).click();
  await page.getByLabel("Decrypt passphrase").fill("play-pass");
  await page.getByRole("button", { name: "decrypt text" }).click();
  await expect(page.getByText("roundtrip text")).toBeVisible();
});

test("download envelope button triggers download", async ({ page }) => {
  await page.goto("/");
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
  await page.goto("/");
  await page.getByRole("button", { name: /Text Redaction/i }).click();
  await page.getByLabel("Redaction input").fill("Reach me at alice@example.com token abcdefghijklmnopqrstuvwxyz1234");
  await page.getByRole("button", { name: /apply redaction/i }).click();
  const output = page.getByLabel("Redacted output");
  await expect(output).toContainText("[email]");
  await expect(output).toContainText("[token]");
});

test("metadata module flags HEIC inputs as unsupported with remediation text", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: /Metadata Inspector/i }).click();
  const imageInput = page.locator('input[type="file"][accept="image/*"]');
  await imageInput.setInputFiles({
    name: "sample.heic",
    mimeType: "image/heic",
    buffer: Buffer.from("heic"),
  });
  await expect(page.getByText(/HEIC\/HEIF parsing is usually blocked/i)).toBeVisible();
  await expect(page.getByText(/unsupported/i)).toBeVisible();
});

test("mobile navigation scrolls and allows selection", async ({ browser }) => {
  const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
  const page = await context.newPage();
  await page.goto("/");
  await page.getByRole("button", { name: /Encrypt \/ Decrypt/i }).click();
  await expect(page.getByText("Encrypt").first()).toBeVisible();
  await context.close();
});

test("mobile secure notes flow supports create and render", async ({ browser }) => {
  const context = await browser.newContext({ viewport: { width: 375, height: 812 } });
  const page = await context.newPage();
  await page.goto("/");
  await page.getByRole("button", { name: /Secure Notes/i }).click();
  await page.getByLabel("Vault key").fill("mobile-pass");
  await page.getByRole("button", { name: /^unlock$/i }).click();
  await page.getByLabel("Note title").fill("mobile-note");
  await page.getByLabel("Note body").fill("created on mobile");
  await page.getByRole("button", { name: /^store$/i }).click();
  await expect(page.getByText("mobile-note").first()).toBeVisible();
  await context.close();
});
