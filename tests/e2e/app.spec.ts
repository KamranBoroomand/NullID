import { test, expect } from "@playwright/test";
import path from "node:path";
import fs from "node:fs";

const shellViewports = [
  { label: "360x740", width: 360, height: 740 },
  { label: "390x844", width: 390, height: 844 },
  { label: "430x932", width: 430, height: 932 },
  { label: "820x1180", width: 820, height: 1180 },
  { label: "1366x900", width: 1366, height: 900 },
] as const;

const maxHorizontalOverflowPx = 2;

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
  await expect(page.getByLabel("Replacement preview")).toContainText("alice@example.com");
  await expect(page.getByLabel("Replacement preview")).toContainText("[email]");
  await page.getByRole("button", { name: /apply redaction/i }).click();
  const output = page.getByLabel("Redacted output");
  await expect(output).toHaveValue(/\[email\]/i);
  await expect(output).toHaveValue(/\[token\]|\[bearer/i);
});

test("secret scanner flags likely secrets with reasons", async ({ page }) => {
  await openApp(page);
  await page.getByRole("button", { name: /Secret Scanner/i }).click();
  await page.getByRole("textbox", { name: "Secret scanner input" }).fill("Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456 github_pat_1234567890_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef");
  const findingsRegion = page.getByRole("region", { name: /Secret findings/i });
  await expect(findingsRegion).toContainText("Bearer token");
  await expect(findingsRegion).toContainText("GitHub token");
  const reportDownload = page.waitForEvent("download");
  await page.getByRole("button", { name: /export scan report/i }).click();
  const report = await reportDownload;
  const reportPath = await report.path();
  expect(reportPath).not.toBeNull();
  const payload = JSON.parse(fs.readFileSync(reportPath!, "utf8")) as Record<string, unknown>;
  expect(payload.kind).toBe("nullid-secret-scan-report");
  expect(Array.isArray(payload.sections)).toBeTruthy();
  await page.getByRole("button", { name: /apply redaction/i }).click();
  await expect(page.getByLabel("Secret scanner redacted output")).toHaveValue(/bearer-token/i);
});

test("structured analyzer groups findings and can hand them to redaction", async ({ page }) => {
  await openApp(page);
  await page.getByRole("button", { name: /Structured Analyzer/i }).click();
  await page.getByRole("checkbox", { name: /Iran \/ Persian rules/i }).check();
  await page.getByRole("checkbox", { name: /Russia rules/i }).check();
  await page.getByRole("textbox", { name: "Structured analyzer input" }).fill("alice@example.com called شماره کارت: ۶۰۳۷-۹۹۷۳-۹۱۸۹-۸۰۸۸ Телефон: 8 (912) 345 67 89 and shared https://nullid.local token=ABCDEFGHIJKLMNOPQRSTUV123456");
  await expect(page.getByLabel(/Emails findings/i)).toContainText("Email");
  await expect(page.getByLabel(/Financial identifiers findings/i)).toContainText("Iran bank card");
  await expect(page.getByLabel(/Likely secrets findings/i)).toContainText("Credential-like assignment");
  await expect(page.getByLabel(/Iran \/ Persian rules summary/i)).toContainText("6037-9973-9189-8088");
  await expect(page.getByLabel(/Russia rules summary/i)).toContainText("+7 912 345-67-89");
  await page.getByRole("button", { name: /send to redaction/i }).click();
  await expect(page.getByRole("button", { name: /Text Redaction/i })).toHaveAttribute("aria-current", "true");
  await expect(page.getByLabel("Redacted output")).toHaveValue(/\[email\]/i);
});

test("financial review detects Iranian banking identifiers and exports a report", async ({ page }) => {
  await openApp(page);
  await page.getByRole("button", { name: /Financial Review/i }).click();
  await page.getByRole("checkbox", { name: /Iran \/ Persian rules/i }).check();
  await page.getByRole("textbox", { name: "Financial review input" }).fill("شماره کارت: ۶۰۳۷-۹۹۷۳-۹۱۸۹-۸۰۸۸ شبا IR۸۲۰۵۴۰۱۰۲۶۸۰۰۲۰۸۱۷۹۰۹۰۰۲");
  await expect(page.getByRole("table")).toContainText("Iran bank card");
  const reportDownload = page.waitForEvent("download");
  await page.getByRole("button", { name: /export review report/i }).click();
  const report = await reportDownload;
  const reportPath = await report.path();
  expect(reportPath).not.toBeNull();
  const payload = JSON.parse(fs.readFileSync(reportPath!, "utf8")) as Record<string, unknown>;
  expect(payload.kind).toBe("nullid-financial-review-report");
  await page.getByRole("button", { name: /apply redaction/i }).click();
  await expect(page.getByLabel("Financial review redacted output")).toHaveValue(/\[iran-card\]|\[financial-card\]/i);
});

test("filename privacy analyzer flags sensitive path segments and exports a report", async ({ page }) => {
  await openApp(page);
  await page.getByRole("button", { name: /Filename Privacy/i }).click();
  await page.getByRole("textbox", { name: "Filename / path privacy input" }).fill("/Users/alice/projects/zephyr/incident-4432/customer-cards.csv");
  const findingsRegion = page.getByRole("region", { name: "Filename / path privacy findings" });
  await expect(findingsRegion).toContainText("Username in path");
  await expect(findingsRegion).toContainText("Case / ticket ID in filename/path");
  const reportDownload = page.waitForEvent("download");
  await page.getByRole("button", { name: /export review report/i }).click();
  const report = await reportDownload;
  const reportPath = await report.path();
  expect(reportPath).not.toBeNull();
  const payload = JSON.parse(fs.readFileSync(reportPath!, "utf8")) as Record<string, unknown>;
  expect(payload.kind).toBe("nullid-path-privacy-report");
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
  await expect(page.getByText("Sender identity is not asserted by this package format.").first()).toBeVisible();
  await expect(page.getByText("What is declared only")).toBeVisible();
  await expect(page.getByText("What to review manually")).toBeVisible();
  await expect(page.getByRole("button", { name: /export checklist json/i })).toBeVisible();
  await expect(page.getByLabel("Reported transforms").getByText("Sanitize transformation")).toBeVisible();
});

test("metadata module compares archive contents and exports a comparison report", async ({ page }) => {
  await openApp(page);
  await page.getByRole("button", { name: /Metadata Inspector/i }).click();
  const advancedDropzone = page.getByRole("button", { name: /Drop file for advanced metadata analysis/i });
  const zipInput = advancedDropzone.locator('input[type="file"]');
  const archiveBuffer = createStoredZip([
    { name: "docs/readme.txt", content: Buffer.from("hello archive") },
    { name: "data/report.json", content: Buffer.from("{\"ok\":true}") },
  ]);
  await zipInput.setInputFiles({
    name: "sample.zip",
    mimeType: "application/zip",
    buffer: archiveBuffer,
  });
  await expect(page.getByText("sample.zip").first()).toBeVisible();
  await expect(page.getByText("Archive contents")).toBeVisible();

  const manifestInput = page.locator('input[type="file"][accept="application/json,.json"]');
  const manifest = {
    kind: "nullid-archive-manifest",
    files: [
      { path: "docs/readme.txt", sha256: "1612156f640b4c019a738d4857bb1f2d08cb9c75a359e15d13f6f89ba16f7c83" },
      { path: "missing.txt", sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
    ],
  };
  await manifestInput.setInputFiles({
    name: "manifest.json",
    mimeType: "application/json",
    buffer: Buffer.from(JSON.stringify(manifest)),
  });
  const comparisonGroups = page.locator(".note-box").filter({ has: page.getByText("Archive comparison groups", { exact: true }) });
  await expect(comparisonGroups).toBeVisible();
  await expect(comparisonGroups.getByText("Matched", { exact: true })).toBeVisible();
  await expect(comparisonGroups.getByText("Hash mismatch", { exact: true })).toBeVisible();
  await expect(page.getByText(/missing\.txt: missing from archive/i)).toBeVisible();

  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: /download analysis report/i }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toContain("archive-comparison-report");
  const filePath = await download.path();
  expect(filePath).not.toBeNull();
  const report = JSON.parse(fs.readFileSync(filePath!, "utf8")) as Record<string, unknown>;
  const archiveComparison = report.archiveComparison as Record<string, unknown>;
  const groups = archiveComparison.groups as Record<string, unknown>;
  expect(Array.isArray(groups.missing)).toBeTruthy();
  expect(Array.isArray(groups.extra)).toBeTruthy();
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
  await expect(page.getByText("Workflow review dashboard")).toBeVisible();

  await page.getByRole("button", { name: /Verify Package/i }).click();
  await page.getByLabel("Verification input").fill(fs.readFileSync(filePath!, "utf8"));
  await page.getByRole("button", { name: /inspect artifact/i }).click();

  await expect(page.getByLabel("Workflow package").first()).toBeVisible();
  await expect(page.getByLabel("Integrity checked").first()).toBeVisible();
  await expect(page.getByRole("cell", { name: "Support ticket / bug report", exact: true })).toBeVisible();
});

test("safe share file mode surfaces filename privacy hints before export", async ({ page }) => {
  await openApp(page);
  await page.getByRole("button", { name: /Safe Share/i }).click();
  await page.getByRole("button", { name: /^file$/i }).click();
  const fileInput = page.locator('input[aria-label="Safe share file"]');
  await fileInput.setInputFiles({
    name: "employee-12345-incident-4432.txt",
    mimeType: "text/plain",
    buffer: Buffer.from("sample"),
  });
  const findingsRegion = page.getByRole("region", { name: "Filename / path privacy findings" });
  await expect(findingsRegion).toContainText("Filename / path privacy");
  await expect(findingsRegion).toContainText("Employee ID in filename/path");
  await expect(findingsRegion).toContainText("Case / ticket ID in filename/path");
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
  await expect(page.getByText("Workflow review dashboard")).toBeVisible();
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

test("batch review workspace can route selected items into workflows", async ({ page }) => {
  await openApp(page);
  await page.getByRole("button", { name: /Batch Review/i }).click();
  await page.getByRole("checkbox", { name: /Iran \/ Persian rules/i }).check();
  await page.getByLabel("Batch text label").fill("batch-snippet.txt");
  await page.getByLabel("Batch text input").fill("alice@example.com شماره کارت: ۶۰۳۷-۹۹۷۳-۹۱۸۹-۸۰۸۸ token=abcdefghijklmnopqrstuvwxyz12345");
  await page.getByRole("button", { name: /add text item/i }).click();
  await expect(page.getByText("batch-snippet.txt", { exact: true }).first()).toBeVisible();
  const reportDownload = page.waitForEvent("download");
  await page.getByRole("button", { name: /export batch report/i }).click();
  const report = await reportDownload;
  const reportPath = await report.path();
  expect(reportPath).not.toBeNull();
  const payload = JSON.parse(fs.readFileSync(reportPath!, "utf8")) as Record<string, unknown>;
  expect(payload.kind).toBe("nullid-batch-review-report");
  const checklistDownload = page.waitForEvent("download");
  await page.getByRole("button", { name: /export checklist json/i }).click();
  const checklist = await checklistDownload;
  const checklistPath = await checklist.path();
  expect(checklistPath).not.toBeNull();
  const checklistPayload = JSON.parse(fs.readFileSync(checklistPath!, "utf8")) as Record<string, unknown>;
  expect(checklistPayload.kind).toBe("nullid-review-checklist");
  expect(JSON.stringify(checklistPayload)).toContain("Region-specific identifiers detected");
  await page.getByLabel(/select batch-snippet\.txt/i).check();
  await page.getByRole("button", { name: /send selected to safe share/i }).click();
  await expect(page.getByRole("button", { name: /Safe Share/i })).toHaveAttribute("aria-current", "true");
  await expect(page.getByLabel("Safe share input text")).toHaveValue(/alice@example\.com/);
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
  await page.getByRole("button", { name: /Module list/i }).click();
  await page.getByRole("button", { name: /Encrypt \/ Decrypt/i }).click();
  await expect(page.getByLabel("Encrypt panel")).toBeVisible();
  await context.close();
});

for (const viewport of shellViewports) {
  test(`responsive app shell layout :: ${viewport.label}`, async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: viewport.width, height: viewport.height } });
    const page = await context.newPage();
    await openApp(page);
    await expect(page.locator(".frame-shell")).toBeVisible();
    await expectNoHorizontalOverflow(page, viewport.label);
    await expectWorkspaceUsable(page, viewport);

    if (viewport.width >= 1040) {
      await expectDesktopModuleFooterAnchored(page, viewport.label);
    } else {
      await expectMobileFeedbackClearance(page, viewport.label);
      await page.getByRole("button", { name: /Module list/i }).click();
      await expect(page.locator(".frame-drawer-backdrop.is-open")).toBeVisible();
      await expectDrawerModuleFooterAnchored(page, viewport.label);
      await page.getByRole("button", { name: /Encrypt \/ Decrypt/i }).click();
      await expect(page.locator(".frame-drawer-backdrop.is-open")).toBeHidden();
      await expect(page.getByLabel("Encrypt panel")).toBeVisible();
      await expectNoHorizontalOverflow(page, `${viewport.label}/drawer-select`);
      await expectFeedbackDoesNotOverlapPanelControls(page, `${viewport.label}/drawer-select`);
    }

    await waitForToastsToClear(page);
    await expect(page).toHaveScreenshot(`app-shell-${viewport.label}.png`, {
      animations: "disabled",
      caret: "hide",
      fullPage: false,
      maxDiffPixelRatio: 0.025,
    });
    await context.close();
  });
}

test("mobile command surfaces fit inside the viewport", async ({ browser }) => {
  const context = await browser.newContext({ viewport: { width: 360, height: 740 } });
  const page = await context.newPage();
  await openApp(page);

  await page.keyboard.press("/");
  await expect(page.locator(".command-surface")).toBeVisible();
  await expectSurfaceWithinViewport(page, ".command-surface", "command palette");
  await expect(page.locator(".command-results")).toHaveCSS("overflow-y", "auto");
  await page.keyboard.press("Escape");
  await expect(page.locator(".command-surface")).toBeHidden();

  await page.getByRole("button", { name: /Open quick actions/i }).click();
  await page.getByRole("menuitem", { name: /feedback/i }).click();
  await expect(page.locator(".feedback-panel")).toBeVisible();
  await expectSurfaceWithinViewport(page, ".feedback-panel", "feedback panel");
  await page.getByRole("button", { name: /^close$/i }).click();
  await expect(page.locator(".feedback-panel")).toBeHidden();

  await page.getByRole("button", { name: /Open quick actions/i }).click();
  await page.getByRole("menuitem", { name: /wipe/i }).click();
  await expect(page.locator(".action-dialog-panel")).toBeVisible();
  await expectSurfaceWithinViewport(page, ".action-dialog-panel", "action dialog");
  await expect(page.locator(".action-dialog-body")).toHaveCSS("overflow-y", "auto");
  await page.getByRole("button", { name: /^cancel$/i }).click();
  await expect(page.locator(".action-dialog-panel")).toBeHidden();

  await page.getByRole("button", { name: /Module list/i }).click();
  await page.getByRole("button", { name: /^:guide/i }).click();
  await page.locator(".guide-open-briefing").first().click();
  await expect(page.locator(".panel-overlay-surface")).toBeVisible();
  await expectSurfaceWithinViewport(page, ".panel-overlay-surface", "panel overlay");
  await expect(page.locator(".panel-overlay-body")).toHaveCSS("overflow-y", "auto");
  await context.close();
});

function createStoredZip(entries: Array<{ name: string; content: Buffer }>) {
  const localParts: Uint8Array[] = [];
  const centralParts: Uint8Array[] = [];
  let offset = 0;

  entries.forEach((entry) => {
    const name = Buffer.from(entry.name, "utf8");
    const size = entry.content.length;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 6);
    local.writeUInt16LE(0, 8);
    local.writeUInt32LE(0, 10);
    local.writeUInt32LE(0, 14);
    local.writeUInt32LE(size, 18);
    local.writeUInt32LE(size, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    localParts.push(local, name, entry.content);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0, 8);
    central.writeUInt16LE(0, 10);
    central.writeUInt32LE(0, 12);
    central.writeUInt32LE(0, 16);
    central.writeUInt32LE(size, 20);
    central.writeUInt32LE(size, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt16LE(0, 30);
    central.writeUInt16LE(0, 32);
    central.writeUInt16LE(0, 34);
    central.writeUInt16LE(0, 36);
    central.writeUInt32LE(0, 38);
    central.writeUInt32LE(offset, 42);
    centralParts.push(central, name);

    offset += local.length + name.length + entry.content.length;
  });

  const centralDirectory = Buffer.concat(centralParts.map((part) => Buffer.from(part)));
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralDirectory.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);
  return Buffer.concat([...localParts.map((part) => Buffer.from(part)), centralDirectory, eocd]);
}

test("mobile secure notes flow supports create and render", async ({ browser }) => {
  const context = await browser.newContext({ viewport: { width: 375, height: 812 } });
  const page = await context.newPage();
  await openApp(page);
  await page.getByRole("button", { name: /Module list/i }).click();
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
  await page.getByRole("button", { name: /Module list/i }).click();
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

async function expectNoHorizontalOverflow(page: import("@playwright/test").Page, scenario: string) {
  const overflow = await page.evaluate(() => {
    const measure = (element: Element | null) => {
      if (!(element instanceof HTMLElement)) return 0;
      return Math.max(0, Math.round(element.scrollWidth - element.clientWidth));
    };

    return {
      document: measure(document.documentElement),
      body: measure(document.body),
    };
  });

  expect(overflow.document, `${scenario}: document horizontal overflow`).toBeLessThanOrEqual(maxHorizontalOverflowPx);
  expect(overflow.body, `${scenario}: body horizontal overflow`).toBeLessThanOrEqual(maxHorizontalOverflowPx);
}

async function expectWorkspaceUsable(
  page: import("@playwright/test").Page,
  viewport: { label: string; width: number; height: number },
) {
  await expect(page.locator(".workspace-scroll")).toBeVisible();
  const metrics = await page.evaluate(() => {
    const header = document.querySelector(".global-header");
    const workspaceScroll = document.querySelector(".workspace-scroll");
    const headerRect = header instanceof HTMLElement ? header.getBoundingClientRect() : null;
    const scrollStyle = workspaceScroll instanceof HTMLElement ? getComputedStyle(workspaceScroll) : null;
    const scrollRect = workspaceScroll instanceof HTMLElement ? workspaceScroll.getBoundingClientRect() : null;

    return {
      headerHeight: Math.round(headerRect?.height ?? 0),
      workspaceHeight: Math.round(scrollRect?.height ?? 0),
      workspaceOverflowY: scrollStyle?.overflowY ?? "",
      workspaceScrollHeight: workspaceScroll instanceof HTMLElement ? Math.round(workspaceScroll.scrollHeight) : 0,
      workspaceClientHeight: workspaceScroll instanceof HTMLElement ? Math.round(workspaceScroll.clientHeight) : 0,
    };
  });

  const maxHeaderHeight = viewport.width < 840 ? Math.min(176, viewport.height * 0.26) : viewport.height * 0.22;
  expect(metrics.headerHeight, `${viewport.label}: compact header height`).toBeLessThanOrEqual(maxHeaderHeight);
  expect(metrics.workspaceHeight, `${viewport.label}: workspace remains visible`).toBeGreaterThan(220);
  expect(metrics.workspaceOverflowY, `${viewport.label}: workspace scroll container`).toBe("auto");
  expect(metrics.workspaceScrollHeight, `${viewport.label}: workspace has measurable content`).toBeGreaterThanOrEqual(metrics.workspaceClientHeight);
}

async function expectDesktopModuleFooterAnchored(page: import("@playwright/test").Page, scenario: string) {
  const metrics = await collectModuleFooterMetrics(page, ".frame-pane");
  expect(metrics.listOverflowY, `${scenario}: module list should not own vertical scrolling`).toBe("hidden");
  expect(metrics.navOverflowY, `${scenario}: module nav should own vertical scrolling`).toMatch(/auto|scroll/);
  expect(metrics.footerFlexShrink, `${scenario}: footer should stay flex-stable`).toBe("0");
  expect(metrics.footerBottomDelta, `${scenario}: footer bottom should align with rail bottom`).toBeLessThanOrEqual(24);
  expect(metrics.footerTopRatio, `${scenario}: footer should sit low in rail`).toBeGreaterThan(0.72);
  expect(metrics.overlappingButtons, `${scenario}: footer should not overlay module buttons`).toBe(0);
}

async function expectDrawerModuleFooterAnchored(page: import("@playwright/test").Page, scenario: string) {
  const metrics = await collectModuleFooterMetrics(page, ".frame-drawer-panel");
  expect(metrics.listOverflowY, `${scenario}: drawer module list should not own vertical scrolling`).toBe("hidden");
  expect(metrics.navOverflowY, `${scenario}: drawer module nav should own vertical scrolling`).toMatch(/auto|scroll/);
  expect(metrics.footerFlexShrink, `${scenario}: drawer footer should stay flex-stable`).toBe("0");
  expect(metrics.footerBottomDelta, `${scenario}: drawer footer bottom should align with drawer bottom`).toBeLessThanOrEqual(24);
  expect(metrics.footerTopRatio, `${scenario}: drawer footer should sit low in drawer`).toBeGreaterThan(0.72);
  expect(metrics.overlappingButtons, `${scenario}: drawer footer should not overlay module buttons`).toBe(0);
  expect(metrics.maxButtonOverflow, `${scenario}: drawer module buttons should not overflow`).toBeLessThanOrEqual(maxHorizontalOverflowPx);
}

async function collectModuleFooterMetrics(page: import("@playwright/test").Page, containerSelector: string) {
  return page.evaluate((selector) => {
    const container = document.querySelector(selector);
    const list = container?.querySelector(".module-list");
    const nav = container?.querySelector(".module-list nav");
    const footer = container?.querySelector(".module-footer");
    if (!(container instanceof HTMLElement) || !(list instanceof HTMLElement) || !(nav instanceof HTMLElement) || !(footer instanceof HTMLElement)) {
      return {
        listOverflowY: "",
        navOverflowY: "",
        footerFlexShrink: "",
        footerBottomDelta: Number.POSITIVE_INFINITY,
        footerTopRatio: 0,
        overlappingButtons: Number.POSITIVE_INFINITY,
        maxButtonOverflow: Number.POSITIVE_INFINITY,
      };
    }

    const containerRect = container.getBoundingClientRect();
    const navRect = nav.getBoundingClientRect();
    const footerRect = footer.getBoundingClientRect();
    const footerStyle = getComputedStyle(footer);
    const visibleButtonRects = Array.from(container.querySelectorAll(".module-button"))
      .map((button) => {
        const rect = button.getBoundingClientRect();
        return {
          top: Math.max(rect.top, navRect.top),
          right: Math.min(rect.right, navRect.right),
          bottom: Math.min(rect.bottom, navRect.bottom),
          left: Math.max(rect.left, navRect.left),
        };
      })
      .filter((rect) => rect.right > rect.left && rect.bottom > rect.top);
    const overlaps = visibleButtonRects.filter(
      (rect) =>
        rect.left < footerRect.right &&
        rect.right > footerRect.left &&
        rect.top < footerRect.bottom &&
        rect.bottom > footerRect.top,
    ).length;
    const buttonOverflows = Array.from(container.querySelectorAll(".module-button")).map((button) =>
      button instanceof HTMLElement ? Math.max(0, Math.round(button.scrollWidth - button.clientWidth)) : 0,
    );

    return {
      listOverflowY: getComputedStyle(list).overflowY,
      navOverflowY: getComputedStyle(nav).overflowY,
      footerFlexShrink: footerStyle.flexShrink,
      footerBottomDelta: Math.abs(Math.round(containerRect.bottom - footerRect.bottom)),
      footerTopRatio: (footerRect.top - containerRect.top) / Math.max(1, containerRect.height),
      overlappingButtons: overlaps,
      maxButtonOverflow: Math.max(0, ...buttonOverflows),
    };
  }, containerSelector);
}

async function expectMobileFeedbackClearance(page: import("@playwright/test").Page, scenario: string) {
  const metrics = await page.evaluate(() => {
    const launcher = document.querySelector(".feedback-launcher");
    const workspaceScroll = document.querySelector(".workspace-scroll");
    const launcherStyle = launcher instanceof HTMLElement ? getComputedStyle(launcher) : null;
    const launcherRect = launcher instanceof HTMLElement && launcherStyle?.display !== "none" ? launcher.getBoundingClientRect() : null;
    const workspaceStyle = workspaceScroll instanceof HTMLElement ? getComputedStyle(workspaceScroll) : null;
    return {
      launcherVisible: Boolean(launcherRect),
      launcherHeight: Math.round(launcherRect?.height ?? 0),
      workspacePaddingBottom: Number.parseFloat(workspaceStyle?.paddingBottom ?? "0"),
    };
  });

  if (!metrics.launcherVisible) return;
  expect(metrics.launcherHeight, `${scenario}: feedback launcher should be measurable`).toBeGreaterThan(0);
  expect(metrics.workspacePaddingBottom, `${scenario}: workspace bottom padding should clear feedback launcher`).toBeGreaterThanOrEqual(
    metrics.launcherHeight + 12,
  );
}

async function expectFeedbackDoesNotOverlapPanelControls(page: import("@playwright/test").Page, scenario: string) {
  const overlaps = await page.evaluate(() => {
    const launcher = document.querySelector(".feedback-launcher");
    if (!(launcher instanceof HTMLElement) || getComputedStyle(launcher).display === "none") return [];
    const launcherRect = launcher.getBoundingClientRect();
    const controls = Array.from(
      document.querySelectorAll(".workspace-scroll .panel button, .workspace-scroll .panel input, .workspace-scroll .panel textarea, .workspace-scroll .panel select"),
    );

    return controls
      .filter((control): control is HTMLElement => control instanceof HTMLElement)
      .filter((control) => {
        const style = getComputedStyle(control);
        const rect = control.getBoundingClientRect();
        return style.visibility !== "hidden" && style.display !== "none" && rect.width > 0 && rect.height > 0;
      })
      .filter((control) => {
        const rect = control.getBoundingClientRect();
        return rect.left < launcherRect.right && rect.right > launcherRect.left && rect.top < launcherRect.bottom && rect.bottom > launcherRect.top;
      })
      .map((control) => control.getAttribute("aria-label") ?? control.textContent?.trim() ?? control.tagName);
  });

  expect(overlaps, `${scenario}: feedback launcher should not overlap visible panel controls`).toEqual([]);
}

async function expectSurfaceWithinViewport(page: import("@playwright/test").Page, selector: string, label: string) {
  const metrics = await page.evaluate((surfaceSelector) => {
    const surface = document.querySelector(surfaceSelector);
    const rect = surface instanceof HTMLElement ? surface.getBoundingClientRect() : null;
    return {
      found: Boolean(rect),
      top: Math.round(rect?.top ?? 0),
      right: Math.round(rect?.right ?? 0),
      bottom: Math.round(rect?.bottom ?? 0),
      left: Math.round(rect?.left ?? 0),
      viewportWidth: window.innerWidth,
      viewportHeight: window.innerHeight,
    };
  }, selector);

  expect(metrics.found, `${label}: surface exists`).toBe(true);
  expect(metrics.left, `${label}: left edge within viewport`).toBeGreaterThanOrEqual(0);
  expect(metrics.top, `${label}: top edge within viewport`).toBeGreaterThanOrEqual(0);
  expect(metrics.right, `${label}: right edge within viewport`).toBeLessThanOrEqual(metrics.viewportWidth);
  expect(metrics.bottom, `${label}: bottom edge within viewport`).toBeLessThanOrEqual(metrics.viewportHeight);
}

async function waitForToastsToClear(page: import("@playwright/test").Page) {
  await page.waitForFunction(() => document.querySelectorAll(".toast").length === 0, undefined, { timeout: 4_500 });
}
