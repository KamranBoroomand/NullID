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

const shellModules = [
  { key: "hash", title: "Hash & Verify" },
  { key: "batch", title: "Batch Review" },
  { key: "share", title: "Safe Share" },
  { key: "incident", title: "Incident Workflow" },
  { key: "secret", title: "Secret Scanner" },
  { key: "analyze", title: "Structured Analyzer" },
  { key: "finance", title: "Financial Review" },
  { key: "paths", title: "Filename Privacy" },
  { key: "verify", title: "Verify Package" },
  { key: "redact", title: "Text Redaction" },
  { key: "sanitize", title: "Log Sanitizer" },
  { key: "meta", title: "Metadata Inspector" },
  { key: "enc", title: "Encrypt / Decrypt" },
  { key: "pw", title: "Password & Passphrase" },
  { key: "vault", title: "Secure Notes" },
  { key: "selftest", title: "Self-test" },
  { key: "guide", title: "Guide" },
] as const;

async function openApp(page: import("@playwright/test").Page) {
  await page.addInitScript(() => {
    window.localStorage.setItem("nullid:onboarding-complete", "true");
    window.localStorage.setItem("nullid:onboarding-step", "0");
    window.localStorage.setItem("nullid:locale", "en");
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

test("root tool query opens only known workbench modules", async ({ page }) => {
  await page.addInitScript(() => {
    window.localStorage.setItem("nullid:onboarding-complete", "true");
    window.localStorage.setItem("nullid:onboarding-step", "0");
    window.localStorage.setItem("nullid:locale", "en");
    window.localStorage.setItem("nullid:last-module", JSON.stringify("hash"));
  });
  await page.goto("/?tool=enc");
  await expect(page.getByRole("heading", { name: "Encrypt / Decrypt" })).toBeVisible();
  await expect(page.getByLabel("Encrypt panel")).toBeVisible();

  await page.evaluate(() => {
    window.localStorage.setItem("nullid:last-module", JSON.stringify("hash"));
  });
  await page.goto("/?tool=not-a-module");
  await expect(page.getByRole("heading", { name: "Hash & Verify" })).toBeVisible();
  await expect(page.getByLabel("Text to hash")).toBeVisible();
  expect(await page.evaluate(() => window.localStorage.getItem("nullid:last-module"))).toBe(JSON.stringify("hash"));
});

test("app renders with corrupted persisted theme and language settings", async ({ page }) => {
  const pageErrors: string[] = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));
  await page.addInitScript(() => {
    window.localStorage.setItem("nullid:onboarding-complete", "true");
    window.localStorage.setItem("nullid:onboarding-step", "0");
    window.localStorage.setItem("nullid:theme", JSON.stringify("system"));
    window.localStorage.setItem("nullid:locale", JSON.stringify("bad"));
    window.localStorage.setItem("nullid:language", JSON.stringify("also-bad"));
  });

  await page.goto("/");

  await expect(page.getByRole("button", { name: /Hash & Verify/i })).toBeVisible();
  expect(pageErrors).toEqual([]);
});

test("first-run short desktop onboarding points feedback to compact actions", async ({ browser }) => {
  const context = await browser.newContext({ viewport: { width: 1366, height: 700 } });
  const page = await context.newPage();
  await page.addInitScript(() => {
    window.localStorage.setItem("nullid:locale", "en");
    window.localStorage.setItem("nullid:onboarding-step", "0");
  });

  await page.goto("/");

  const onboardingDialog = page.getByRole("dialog", { name: /Onboarding tour/i });
  await expect(onboardingDialog).toBeVisible();

  for (let stepIndex = 0; stepIndex < 4; stepIndex += 1) {
    await onboardingDialog.getByRole("button", { name: /^next$/i }).click();
  }

  await expect(onboardingDialog.getByRole("heading", { name: "Track feedback locally" })).toBeVisible();
  await expect(onboardingDialog).not.toContainText(/bottom-left/i);
  await expect(onboardingDialog).toContainText(/Actions\s*→\s*Feedback/i);

  await onboardingDialog.getByRole("button", { name: /^finish$/i }).click();
  await expect(onboardingDialog).toBeHidden();
  await expect(page.getByRole("button", { name: /Open feedback/i })).toHaveCount(0);

  await page.getByRole("button", { name: /Open quick actions/i }).click();
  await page.getByRole("menuitem", { name: /feedback/i }).click();
  await expect(page.getByLabel("Feedback panel")).toBeVisible();
  await context.close();
});

test("feedback access stays available on desktop, short desktop, and mobile", async ({ browser }) => {
  const feedbackViewports = [
    { label: "desktop", width: 1366, height: 900, compact: false },
    { label: "short desktop", width: 1366, height: 700, compact: true },
    { label: "mobile", width: 390, height: 844, compact: true },
  ] as const;

  for (const viewport of feedbackViewports) {
    const context = await browser.newContext({ viewport: { width: viewport.width, height: viewport.height } });
    const page = await context.newPage();
    await openApp(page);

    if (viewport.compact) {
      await expect(page.getByRole("button", { name: /Open feedback/i })).toHaveCount(0);
      await page.getByRole("button", { name: /Open quick actions/i }).click();
      await page.getByRole("menuitem", { name: /feedback/i }).click();
    } else {
      const launcher = page.getByRole("button", { name: /Open feedback/i });
      await expect(launcher).toBeVisible();
      await launcher.click();
    }

    await expect(page.getByLabel("Feedback panel")).toBeVisible();
    await expectSurfaceWithinViewport(page, ".feedback-panel", `${viewport.label} feedback panel`);
    await expectNoHorizontalOverflow(page, `${viewport.label} feedback access`);
    await context.close();
  }
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

test("decrypting a binary envelope shows a bounded binary preview", async ({ page }) => {
  await openApp(page);
  await page.getByRole("button", { name: /Encrypt \/ Decrypt/i }).click();
  await page.getByLabel("Encrypt passphrase").fill("play-pass");
  const filePath = path.join(process.cwd(), "tests/e2e/tmp-binary.bin");
  try {
    fs.writeFileSync(filePath, Buffer.from([0xff, 0xfe, 0xfd, 0x00, 0x80, 0x81]));

    await page.locator('input[aria-label="Pick file to encrypt"]').setInputFiles(filePath);
    await page.getByRole("button", { name: "seal file" }).click();
    await page.getByLabel("Decrypt passphrase").fill("play-pass");
    await page.getByRole("button", { name: "decrypt file" }).click();

    const output = page.getByLabel("Decryption output");
    await expect(output).toContainText("[binary payload]");
    await expect(output).not.toContainText("���");
  } finally {
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  }
});

test("decrypt file loader rejects oversized envelopes before reading", async ({ page }) => {
  await openApp(page);
  await page.getByRole("button", { name: /Encrypt \/ Decrypt/i }).click();
  const filePath = path.join(process.cwd(), "tests/e2e/tmp-oversized.nullid");
  try {
    fs.writeFileSync(filePath, Buffer.alloc(40 * 1024 * 1024 + 1, "A"));

    await page.getByLabel("Load envelope file").setInputFiles(filePath);

    await expect(page.getByLabel("Envelope preview").getByText(/file too large/i)).toBeVisible();
    await expect(page.getByLabel("Ciphertext")).toHaveValue("");
  } finally {
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  }
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
  await page.getByRole("textbox", { name: "Filename / path privacy input" }).fill("workspace/users/alice/projects/zephyr/incident-4432/customer-cards.csv");
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
  const advancedInput = page.locator('input[type="file"][accept^="image/*,video/*"]');
  await advancedInput.setInputFiles({
    name: "sample.heic",
    mimeType: "image/heic",
    buffer: Buffer.from("heic"),
  });
  await expect(page.getByText(/in-browser sanitizer not available for this format/i)).toBeVisible();
  await expect(page.getByText(/mat2 "sample\.heic"/i)).toBeVisible();
  await expect(page.getByText(/cleanup depends on external offline tooling/i).first()).toBeVisible();
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
    schemaVersion: 2,
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

for (const viewport of shellViewports.filter((entry) => entry.width < 1040)) {
  test(`mobile drawer exposes every module :: ${viewport.label}`, async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: viewport.width, height: viewport.height } });
    const page = await context.newPage();
    await openApp(page);

    for (const module of shellModules) {
      await openModuleDrawer(page);
      await expectDrawerNavScrollableWhenNeeded(page, viewport.label);
      const drawer = page.locator(".frame-drawer-panel");
      const button = moduleButtonByKeyAndTitle(drawer, module);
      await button.scrollIntoViewIfNeeded();
      await expect(button, `${viewport.label}: ${module.title} is visible in drawer`).toBeVisible();
      await button.click();
      await expect(page.locator(".frame-drawer-backdrop.is-open")).toBeHidden();
      await expect(page.locator(".page-title")).toContainText(module.title);
      await expectNoHorizontalOverflow(page, `${viewport.label}/${module.key}`);
      await expectWorkspaceHasNoDeadZone(page, `${viewport.label}/${module.key}`);
    }

    await context.close();
  });
}

test("forced desktop layout uses permanent sidebar on phone viewport", async ({ browser }) => {
  const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
  const page = await context.newPage();
  await page.addInitScript(() => {
    window.localStorage.setItem("nullid:onboarding-complete", "true");
    window.localStorage.setItem("nullid:onboarding-step", "0");
    window.localStorage.setItem("nullid:locale", "en");
    window.localStorage.setItem("nullid:layout-mode", JSON.stringify("desktop"));
  });
  await page.goto("/");

  await expect(page.locator(".frame-pane")).toBeVisible();
  await expect(page.getByRole("button", { name: /Module list/i })).toHaveCount(0);

  const rail = page.locator(".frame-pane");
  for (const module of shellModules) {
    const button = moduleButtonByKeyAndTitle(rail, module);
    await button.scrollIntoViewIfNeeded();
    await expect(button, `forced desktop: ${module.title} reachable`).toBeVisible();
    await button.click();
    await expect(page.locator(".page-title")).toContainText(module.title);
  }

  await expectNoHorizontalOverflow(page, "forced-desktop-phone");
  await context.close();
});

test("forced mobile layout uses drawer at desktop width", async ({ browser }) => {
  const context = await browser.newContext({ viewport: { width: 1366, height: 900 } });
  const page = await context.newPage();
  await page.addInitScript(() => {
    window.localStorage.setItem("nullid:onboarding-complete", "true");
    window.localStorage.setItem("nullid:onboarding-step", "0");
    window.localStorage.setItem("nullid:locale", "en");
    window.localStorage.setItem("nullid:layout-mode", JSON.stringify("mobile"));
  });
  await page.goto("/");

  await expect(page.locator(".frame-pane")).toHaveCount(0);
  await openModuleDrawer(page);
  await expect(page.locator(".frame-drawer-panel")).toBeVisible();
  await expectDrawerNavScrollableWhenNeeded(page, "forced-mobile-desktop");
  const guideButton = moduleButtonByKeyAndTitle(page.locator(".frame-drawer-panel"), { key: "guide", title: "Guide" });
  await guideButton.scrollIntoViewIfNeeded();
  await guideButton.click();
  await expect(page.locator(".page-title")).toContainText("Guide");
  await context.close();
});

test("mobile shell keeps usable height after portrait and landscape viewport changes", async ({ browser }) => {
  const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
  const page = await context.newPage();
  await openApp(page);

  await expectWorkspaceHasNoDeadZone(page, "initial portrait");
  await expectNoHorizontalOverflow(page, "initial portrait");

  await page.setViewportSize({ width: 390, height: 640 });
  await expectWorkspaceHasNoDeadZone(page, "short portrait");
  await expectNoHorizontalOverflow(page, "short portrait");

  await page.setViewportSize({ width: 740, height: 390 });
  await expectWorkspaceHasNoDeadZone(page, "landscape");
  await expectNoHorizontalOverflow(page, "landscape");

  await context.close();
});

for (const viewport of shellViewports) {
  test(`responsive app shell layout :: ${viewport.label}`, async ({ browser }) => {
    test.skip(
      !hasSnapshotBaseline(`app-shell-${viewport.label}.png`),
      `snapshot baseline missing for ${process.platform}`,
    );
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

test("command palette arrow keys navigate results while input stays focused", async ({ page }) => {
  await openApp(page);
  await page.keyboard.press("/");
  await expect(page.locator(".command-surface")).toBeVisible();
  const search = page.getByLabel("Search commands");
  await expect(search).toBeFocused();
  await expect(page.locator(".command-item.active .command-id")).toHaveText(":hash");

  await search.press("ArrowDown");
  await expect(search).toBeFocused();
  await expect(page.locator(".command-item.active .command-id")).toHaveText(":batch");

  await search.press("ArrowUp");
  await expect(search).toBeFocused();
  await expect(page.locator(".command-item.active .command-id")).toHaveText(":hash");
});

test("command palette keyboard selection ignores stale pointer hover", async ({ page }) => {
  await openApp(page);
  await page.getByRole("button", { name: /Command palette/i }).click();
  await expect(page.locator(".command-surface")).toBeVisible();
  const search = page.getByLabel("Search commands");
  await expect(search).toBeFocused();

  const languageRu = page.locator(".command-item", { hasText: "language-ru" });
  await languageRu.scrollIntoViewIfNeeded();
  const box = await languageRu.boundingBox();
  if (!box) throw new Error("language-ru command was not rendered");
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
  await expect(page.locator(".command-item.active .command-id")).toHaveText("language-ru");

  await search.press("ArrowDown");
  await expect(search).toBeFocused();
  await expect(page.locator(".command-item.active .command-id")).toHaveText(":hash");

  await languageRu.dispatchEvent("mouseover", {
    bubbles: true,
    clientX: box.x + box.width / 2,
    clientY: box.y + box.height / 2,
  });
  await expect(page.locator(".command-item.active .command-id")).toHaveText(":hash");

  await page.mouse.move(box.x + box.width / 2 + 8, box.y + box.height / 2);
  await expect(page.locator(".command-item.active .command-id")).toHaveText("language-ru");
});

test("command palette pointer selection records command history", async ({ page }) => {
  await openApp(page);
  await page.keyboard.press("/");
  await expect(page.locator(".command-surface")).toBeVisible();

  await page.locator(".command-item", { hasText: ":batch" }).click();
  await expect(page.locator(".command-surface")).toBeHidden();
  await expect(page.getByText("Batch Review Workspace")).toBeVisible();

  const history = await page.evaluate(() => JSON.parse(window.localStorage.getItem("nullid-history:command-bar") ?? "[]"));
  expect(history).toContain(":batch");
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

function moduleButtonByKeyAndTitle(
  container: import("@playwright/test").Locator,
  module: { key: string; title: string },
) {
  return container.getByRole("button", {
    name: new RegExp(`^:${escapeRegExp(module.key)}\\s+${escapeRegExp(module.title)}(?:\\s|$)`),
  });
}

function escapeRegExp(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
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
  if (metrics.footerVisible) {
    expect(metrics.footerBottomDelta, `${scenario}: drawer footer bottom should align with drawer bottom`).toBeLessThanOrEqual(24);
    expect(metrics.footerTopRatio, `${scenario}: drawer footer should sit low in drawer`).toBeGreaterThan(0.72);
  } else {
    expect(metrics.footerDisplay, `${scenario}: hidden drawer footer should be deliberately removed from layout`).toBe("none");
  }
  expect(metrics.overlappingButtons, `${scenario}: drawer footer should not overlay module buttons`).toBe(0);
  expect(metrics.maxButtonOverflow, `${scenario}: drawer module buttons should not overflow`).toBeLessThanOrEqual(maxHorizontalOverflowPx);
}

async function openModuleDrawer(page: import("@playwright/test").Page) {
  const toggle = page.getByRole("button", { name: /Module list/i });
  await expect(toggle).toBeVisible();
  await toggle.click();
  await expect(page.locator(".frame-drawer-backdrop.is-open")).toBeVisible();
  await expect(page.locator(".frame-drawer-panel")).toBeVisible();
}

async function expectDrawerNavScrollableWhenNeeded(page: import("@playwright/test").Page, scenario: string) {
  const metrics = await page.evaluate(() => {
    const drawer = document.querySelector(".frame-drawer-panel");
    const nav = drawer?.querySelector(".module-list nav");
    const lastButton = drawer?.querySelector(".module-list nav .module-button:last-of-type");
    if (!(drawer instanceof HTMLElement) || !(nav instanceof HTMLElement)) {
      return {
        found: false,
        navClientHeight: 0,
        navScrollHeight: 0,
        overflowY: "",
        drawerRight: 0,
        viewportWidth: window.innerWidth,
        lastButtonBottom: 0,
        navBottom: 0,
      };
    }
    const drawerRect = drawer.getBoundingClientRect();
    const navRect = nav.getBoundingClientRect();
    const lastRect = lastButton instanceof HTMLElement ? lastButton.getBoundingClientRect() : null;
    return {
      found: true,
      navClientHeight: Math.round(nav.clientHeight),
      navScrollHeight: Math.round(nav.scrollHeight),
      overflowY: getComputedStyle(nav).overflowY,
      drawerRight: Math.round(drawerRect.right),
      viewportWidth: window.innerWidth,
      lastButtonBottom: Math.round(lastRect?.bottom ?? 0),
      navBottom: Math.round(navRect.bottom),
    };
  });

  expect(metrics.found, `${scenario}: drawer nav exists`).toBe(true);
  expect(metrics.navClientHeight, `${scenario}: drawer nav gets usable height`).toBeGreaterThan(220);
  expect(metrics.navScrollHeight, `${scenario}: drawer nav has full module content`).toBeGreaterThan(metrics.navClientHeight);
  expect(metrics.overflowY, `${scenario}: drawer nav owns vertical scrolling`).toMatch(/auto|scroll/);
  expect(metrics.drawerRight, `${scenario}: drawer should not be clipped horizontally`).toBeLessThanOrEqual(metrics.viewportWidth);
}

async function expectWorkspaceHasNoDeadZone(page: import("@playwright/test").Page, scenario: string) {
  await expect(page.locator(".workspace-scroll"), `${scenario}: workspace scroll container should render`).toBeVisible();
  const metrics = await page.evaluate(() => {
    const frameShell = document.querySelector(".frame-shell");
    const workspace = document.querySelector(".workspace");
    const workspaceScroll = document.querySelector(".workspace-scroll");
    const activePanel = document.querySelector(".workspace-scroll .panel");
    const frameRect = frameShell instanceof HTMLElement ? frameShell.getBoundingClientRect() : null;
    const workspaceRect = workspace instanceof HTMLElement ? workspace.getBoundingClientRect() : null;
    const scrollRect = workspaceScroll instanceof HTMLElement ? workspaceScroll.getBoundingClientRect() : null;
    const panelRect = activePanel instanceof HTMLElement ? activePanel.getBoundingClientRect() : null;
    const viewportHeight = window.innerHeight;
    return {
      frameHeight: Math.round(frameRect?.height ?? 0),
      frameBottomGap: Math.round(viewportHeight - (frameRect?.bottom ?? 0)),
      workspaceHeight: Math.round(workspaceRect?.height ?? 0),
      workspaceBottomGap: Math.round(viewportHeight - (workspaceRect?.bottom ?? 0)),
      scrollHeight: Math.round(scrollRect?.height ?? 0),
      scrollBottomGap: Math.round(viewportHeight - (scrollRect?.bottom ?? 0)),
      panelTop: Math.round(panelRect?.top ?? 0),
      panelBottom: Math.round(panelRect?.bottom ?? 0),
      viewportHeight,
    };
  });

  expect(metrics.frameHeight, `${scenario}: shell should occupy most viewport height`).toBeGreaterThan(metrics.viewportHeight * 0.88);
  expect(metrics.frameBottomGap, `${scenario}: shell should not leave a large lower dead region`).toBeLessThanOrEqual(24);
  expect(metrics.workspaceHeight, `${scenario}: workspace should remain usable`).toBeGreaterThan(Math.min(220, metrics.viewportHeight * 0.48));
  expect(metrics.scrollHeight, `${scenario}: workspace scroll region should remain usable`).toBeGreaterThan(Math.min(180, metrics.viewportHeight * 0.38));
  expect(metrics.scrollBottomGap, `${scenario}: workspace scroll should reach lower shell area`).toBeLessThanOrEqual(32);
  expect(metrics.panelTop, `${scenario}: active panel should be in visible workspace`).toBeLessThan(metrics.viewportHeight);
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
        footerDisplay: "",
        footerVisible: false,
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
    const footerVisible = footerStyle.display !== "none" && footerRect.height > 0;
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
      footerDisplay: footerStyle.display,
      footerVisible,
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
