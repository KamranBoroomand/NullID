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
  await expect(page.getByText("Username in path")).toBeVisible();
  await expect(page.getByText("Case / ticket ID in filename/path")).toBeVisible();
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
  await expect(page.getByText("Filename / path privacy")).toBeVisible();
  await expect(page.getByText("Employee ID in filename/path")).toBeVisible();
  await expect(page.getByText("Case / ticket ID in filename/path")).toBeVisible();
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
  await page.getByRole("button", { name: /Encrypt \/ Decrypt/i }).click();
  await expect(page.getByText("Encrypt").first()).toBeVisible();
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
