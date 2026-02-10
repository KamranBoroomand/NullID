import { mkdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "@playwright/test";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, "..");
const publicDir = path.join(projectRoot, "public");
const iconsDir = path.join(publicDir, "icons");

const iconSvg = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024" role="img" aria-label="NullID icon">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1024" y2="1024">
      <stop offset="0%" stop-color="#0a0f12" />
      <stop offset="100%" stop-color="#142028" />
    </linearGradient>
    <linearGradient id="ring" x1="132" y1="132" x2="892" y2="892">
      <stop offset="0%" stop-color="#e5ff67" />
      <stop offset="100%" stop-color="#b4f500" />
    </linearGradient>
  </defs>
  <rect width="1024" height="1024" rx="224" fill="url(#bg)" />
  <rect x="142" y="142" width="740" height="740" rx="184" fill="none" stroke="url(#ring)" stroke-width="52" />
  <path d="M326 716V308L698 716V308" fill="none" stroke="#f7f7f2" stroke-width="106" stroke-linecap="round" stroke-linejoin="round" />
  <rect x="304" y="790" width="416" height="58" rx="29" fill="#d8f500" />
</svg>
`;

function iconPageMarkup() {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <style>
      html, body {
        width: 100%;
        height: 100%;
        margin: 0;
        background: #0a0f12;
      }
      svg {
        display: block;
        width: 100%;
        height: 100%;
      }
    </style>
  </head>
  <body>
    ${iconSvg}
  </body>
</html>`;
}

function previewPageMarkup() {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <style>
      html, body {
        margin: 0;
        width: 100%;
        height: 100%;
        color: #f7f7f2;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Helvetica Neue", Arial, sans-serif;
        background:
          radial-gradient(1400px 680px at 92% 8%, rgba(216, 245, 0, 0.22), transparent 60%),
          radial-gradient(1000px 620px at 10% 92%, rgba(34, 203, 255, 0.16), transparent 70%),
          linear-gradient(135deg, #06090c 0%, #0d141b 50%, #101820 100%);
      }
      .canvas {
        position: relative;
        width: 1200px;
        height: 630px;
        overflow: hidden;
      }
      .grid {
        position: absolute;
        inset: -2px;
        background-image:
          linear-gradient(rgba(247, 247, 242, 0.04) 1px, transparent 1px),
          linear-gradient(90deg, rgba(247, 247, 242, 0.04) 1px, transparent 1px);
        background-size: 52px 52px;
        mask-image: radial-gradient(ellipse at center, rgba(0, 0, 0, 0.95) 30%, rgba(0, 0, 0, 0.15) 85%, transparent 100%);
      }
      .panel {
        position: absolute;
        left: 56px;
        top: 56px;
        right: 56px;
        bottom: 56px;
        display: flex;
        align-items: center;
        gap: 52px;
        padding: 48px 52px;
        border-radius: 36px;
        border: 1px solid rgba(247, 247, 242, 0.16);
        background: linear-gradient(145deg, rgba(11, 17, 22, 0.78), rgba(16, 24, 31, 0.92));
        box-shadow: 0 24px 80px rgba(0, 0, 0, 0.45), inset 0 0 0 1px rgba(216, 245, 0, 0.08);
      }
      .icon {
        width: 220px;
        height: 220px;
        flex: 0 0 auto;
      }
      .text h1 {
        margin: 0 0 8px;
        font-size: 102px;
        line-height: 0.92;
        letter-spacing: -2.8px;
      }
      .text p {
        margin: 0;
        font-size: 34px;
        line-height: 1.24;
        color: rgba(247, 247, 242, 0.88);
      }
      .pills {
        display: flex;
        gap: 12px;
        margin-top: 30px;
      }
      .pill {
        font-size: 20px;
        line-height: 1;
        padding: 11px 16px;
        border-radius: 999px;
        border: 1px solid rgba(247, 247, 242, 0.2);
        background: rgba(5, 9, 12, 0.5);
        color: rgba(247, 247, 242, 0.92);
      }
      .pill.highlight {
        border-color: rgba(216, 245, 0, 0.7);
        color: #e8ff7a;
      }
      .foot {
        position: absolute;
        left: 76px;
        right: 76px;
        bottom: 24px;
        display: flex;
        justify-content: space-between;
        font-size: 17px;
        letter-spacing: 0.35px;
        color: rgba(247, 247, 242, 0.74);
      }
      .label {
        color: #d8f500;
      }
    </style>
  </head>
  <body>
    <div class="canvas">
      <div class="grid"></div>
      <div class="panel">
        <div class="icon">${iconSvg}</div>
        <div class="text">
          <h1>NullID</h1>
          <p>Offline-first security toolbox for privacy and cryptography workflows.</p>
          <div class="pills">
            <div class="pill highlight">Installable Web App</div>
            <div class="pill">Works Offline</div>
            <div class="pill">No Runtime Network Calls</div>
          </div>
        </div>
      </div>
      <div class="foot">
        <span><span class="label">NULLID</span> · Local-first security utilities</span>
        <span>Hash · Redact · Encrypt · Vault</span>
      </div>
    </div>
  </body>
</html>`;
}

async function renderPng(browser, options) {
  const page = await browser.newPage({
    viewport: { width: options.width, height: options.height },
    deviceScaleFactor: 1,
  });
  await page.setContent(options.html, { waitUntil: "load" });
  await page.screenshot({
    path: options.path,
    type: "png",
    fullPage: false,
  });
  await page.close();
}

async function main() {
  await mkdir(iconsDir, { recursive: true });
  const browser = await chromium.launch();
  try {
    const iconHtml = iconPageMarkup();
    await renderPng(browser, {
      width: 512,
      height: 512,
      html: iconHtml,
      path: path.join(iconsDir, "icon-512.png"),
    });
    await renderPng(browser, {
      width: 512,
      height: 512,
      html: iconHtml,
      path: path.join(iconsDir, "icon-512-maskable.png"),
    });
    await renderPng(browser, {
      width: 192,
      height: 192,
      html: iconHtml,
      path: path.join(iconsDir, "icon-192.png"),
    });
    await renderPng(browser, {
      width: 180,
      height: 180,
      html: iconHtml,
      path: path.join(iconsDir, "apple-touch-icon.png"),
    });
    await renderPng(browser, {
      width: 32,
      height: 32,
      html: iconHtml,
      path: path.join(iconsDir, "favicon-32.png"),
    });
    await renderPng(browser, {
      width: 16,
      height: 16,
      html: iconHtml,
      path: path.join(iconsDir, "favicon-16.png"),
    });

    const previewHtml = previewPageMarkup();
    await renderPng(browser, {
      width: 1200,
      height: 630,
      html: previewHtml,
      path: path.join(publicDir, "nullid-preview.png"),
    });
    await renderPng(browser, {
      width: 1200,
      height: 630,
      html: previewHtml,
      path: path.join(projectRoot, "nullid-preview.png"),
    });
  } finally {
    await browser.close();
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
