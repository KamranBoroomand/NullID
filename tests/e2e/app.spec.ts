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

test("password storage hash lab keeps legacy options but warns", async ({ page }) => {
  await openApp(page);
  await page.getByRole("button", { name: /Password & Passphrase/i }).click();
  await page.getByLabel("Password hash algorithm").selectOption("sha256");
  await expect(page.getByText("Fast SHA digests are legacy-only for password storage")).toBeVisible();
  await page.getByLabel("Password input for hashing").fill("playwright-secret");
  await page.getByRole("button", { name: /generate hash/i }).click();
  await expect(page.getByLabel("Password hash record")).not.toHaveValue("");
});

test("password storage hash lab verifies a pasted saved record", async ({ page }) => {
  await openApp(page);
  await page.getByRole("button", { name: /Password & Passphrase/i }).click();
  await page.getByLabel("Password hash algorithm").selectOption("sha256");
  await page.getByLabel("Password input for hashing").fill("playwright-secret");
  await page.getByRole("button", { name: /generate hash/i }).click();

  const recordField = page.getByLabel("Password hash record");
  const savedRecord = await recordField.inputValue();
  await expect(savedRecord.length).toBeGreaterThan(0);

  await page.getByRole("button", { name: /^clear$/i }).click();
  await recordField.fill(savedRecord);
  await page.getByLabel("Password candidate").fill("playwright-secret");
  await page.getByRole("button", { name: /^verify$/i }).click();

  await expect(page.getByText(/^verified$/i)).toBeVisible();
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

test("sanitize module exports local safe-share bundle with shared workflow package metadata", async ({ page }) => {
  await openApp(page);
  await page.getByRole("button", { name: /Log Sanitizer/i }).click();
  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: /^export bundle$/i }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toContain("nullid-safe-share-bundle");
  const filePath = await download.path();
  expect(filePath).not.toBeNull();
  const payload = JSON.parse(fs.readFileSync(filePath!, "utf8")) as Record<string, unknown>;
  const workflowPackage = payload.workflowPackage as Record<string, unknown>;
  const trust = workflowPackage.trust as Record<string, unknown>;
  const packageSignature = trust.packageSignature as Record<string, unknown>;
  expect(payload.schemaVersion).toBe(2);
  expect(payload.kind).toBe("nullid-safe-share");
  expect(workflowPackage.kind).toBe("nullid-workflow-package");
  expect(workflowPackage.workflowType).toBe("sanitize-safe-share");
  expect(trust.identity).toBe("not-asserted");
  expect(packageSignature.method).toBe("none");
});

test("verify package surface inspects a received safe-share bundle honestly", async ({ page }) => {
  await openApp(page);
  await page.getByRole("button", { name: /Log Sanitizer/i }).click();
  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: /^export bundle$/i }).click();
  const download = await downloadPromise;
  const filePath = await download.path();
  expect(filePath).not.toBeNull();
  const payload = fs.readFileSync(filePath!, "utf8");

  await page.getByRole("button", { name: /Verify Package/i }).click();
  await page.getByLabel("Verification input").fill(payload);
  await page.getByRole("button", { name: /inspect artifact/i }).click();

  await expect(page.getByLabel("Safe-share bundle").first()).toBeVisible();
  await expect(page.getByLabel("Integrity checked").first()).toBeVisible();
  await expect(page.getByText("Sender identity is not asserted by this package format.")).toBeVisible();
  await expect(page.getByLabel("Reported transforms").getByText("Sanitize transformation")).toBeVisible();
});

test("safe share assistant exports a receiver-friendly workflow package", async ({ page }) => {
  await openApp(page);
  await page.getByRole("button", { name: /Safe Share/i }).click();
  await page.getByLabel("Safe share input text").fill("token=abcdefghijklmnopqrstuvwxyz12345 alice@example.com");
  await page.getByRole("button", { name: /Support ticket \/ bug report/i }).click();

  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: /^export package$/i }).click();
  const download = await downloadPromise;
  const filePath = await download.path();
  expect(filePath).not.toBeNull();

  const payload = JSON.parse(fs.readFileSync(filePath!, "utf8")) as Record<string, unknown>;
  const trust = payload.trust as Record<string, unknown>;
  const packageSignature = trust.packageSignature as Record<string, unknown>;
  const workflowPreset = payload.workflowPreset as Record<string, unknown>;
  expect(payload.kind).toBe("nullid-workflow-package");
  expect(payload.workflowType).toBe("safe-share-assistant");
  expect(workflowPreset.id).toBe("support-ticket");
  expect(packageSignature.method).toBe("none");

  await page.getByRole("button", { name: /Verify Package/i }).click();
  await page.getByLabel("Verification input").fill(fs.readFileSync(filePath!, "utf8"));
  await page.getByRole("button", { name: /inspect artifact/i }).click();

  await expect(page.getByLabel("Workflow package").first()).toBeVisible();
  await expect(page.getByLabel("Integrity checked").first()).toBeVisible();
  await expect(page.getByRole("cell", { name: "Support ticket / bug report", exact: true })).toBeVisible();
});

test("incident workflow exports a receiver-friendly incident package", async ({ page }) => {
  await openApp(page);
  await page.getByRole("button", { name: /Incident Workflow/i }).click();
  await page.getByLabel("Incident title").fill("Incident playwright handoff");
  await page.getByLabel("Incident purpose").fill("Prepare a local responder handoff package.");
  await page.getByLabel("Incident summary").fill("Suspicious token and account activity were observed.");
  await page.getByLabel("Incident notes").fill("Summary: suspicious token seen in auth logs\nImpact: limited\nIndicators: alice@example.com");
  await page.getByLabel("Incident text artifact label").fill("auth-snippet.txt");
  await page.getByLabel("Incident text artifact input").fill("token=abcdefghijklmnopqrstuvwxyz12345 alice@example.com");
  await page.getByRole("button", { name: /^add text artifact$/i }).click();

  await expect(page.getByText(/Incident Workflow export with case context, prepared artifacts, and receiver-facing reporting\./i)).toBeVisible();
  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: /^export package$/i }).click();
  const download = await downloadPromise;
  const filePath = await download.path();
  expect(filePath).not.toBeNull();

  const payload = JSON.parse(fs.readFileSync(filePath!, "utf8")) as Record<string, unknown>;
  const workflowPreset = payload.workflowPreset as Record<string, unknown>;
  const trust = payload.trust as Record<string, unknown>;
  const packageSignature = trust.packageSignature as Record<string, unknown>;
  const report = payload.report as Record<string, unknown>;
  expect(payload.kind).toBe("nullid-workflow-package");
  expect(payload.workflowType).toBe("incident-workflow");
  expect(workflowPreset.id).toBe("incident-handoff");
  expect(packageSignature.method).toBe("none");
  expect(report.purpose).toBe("Prepare a local responder handoff package.");

  await page.getByRole("button", { name: /Verify Package/i }).click();
  await page.getByLabel("Verification input").fill(fs.readFileSync(filePath!, "utf8"));
  await page.getByRole("button", { name: /inspect artifact/i }).click();

  await expect(page.getByLabel("Workflow package").first()).toBeVisible();
  await expect(page.getByLabel("Integrity checked").first()).toBeVisible();
  await expect(page.getByRole("cell", { name: "Incident handoff", exact: true })).toBeVisible();
  await expect(page.getByLabel("Reported transforms").getByText("Incident workflow assembly")).toBeVisible();
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

test("self-test records last run even when warnings are present", async ({ page }) => {
  await openApp(page);
  await page.getByRole("button", { name: /Self-test/i }).click();
  const lastRun = page.locator(".panel .microcopy").filter({ hasText: /last run:/i }).first();
  await expect(lastRun).toContainText(/never/i);
  await page.getByRole("button", { name: /^run all$/i }).click();
  await expect(lastRun).not.toContainText(/never/i);
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
