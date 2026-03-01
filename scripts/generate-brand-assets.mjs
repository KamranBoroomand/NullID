import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { deflateSync, inflateSync } from "node:zlib";
import { chromium } from "@playwright/test";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, "..");
const publicDir = path.join(projectRoot, "public");
const iconsDir = path.join(publicDir, "icons");
const PNG_SIGNATURE = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
const CRC32_TABLE = buildCrc32Table();

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

async function ensurePngRgba(filePath) {
  const input = await readFile(filePath);
  if (!input.subarray(0, 8).equals(PNG_SIGNATURE)) {
    throw new Error(`not a PNG file: ${filePath}`);
  }

  const chunks = [];
  for (let offset = 8; offset < input.length;) {
    const length = input.readUInt32BE(offset);
    const type = input.toString("ascii", offset + 4, offset + 8);
    const dataStart = offset + 8;
    const dataEnd = dataStart + length;
    chunks.push({ type, data: input.subarray(dataStart, dataEnd) });
    offset = dataEnd + 4;
  }

  const ihdr = chunks.find((chunk) => chunk.type === "IHDR");
  if (!ihdr) throw new Error(`missing IHDR chunk: ${filePath}`);
  const width = ihdr.data.readUInt32BE(0);
  const height = ihdr.data.readUInt32BE(4);
  const bitDepth = ihdr.data[8];
  const colorType = ihdr.data[9];

  if (colorType === 6) return;
  if (bitDepth !== 8 || colorType !== 2) {
    throw new Error(`unsupported PNG color format for ${filePath}: bitDepth=${bitDepth}, colorType=${colorType}`);
  }

  const idat = Buffer.concat(chunks.filter((chunk) => chunk.type === "IDAT").map((chunk) => chunk.data));
  const decoded = inflateSync(idat);
  const inputStride = width * 3;
  const inputRowLength = 1 + inputStride;
  if (decoded.length !== inputRowLength * height) {
    throw new Error(`unexpected PNG row size: ${filePath}`);
  }

  const reconstructedRows = [];
  const bpp = 3;
  let cursor = 0;
  for (let y = 0; y < height; y++) {
    const filter = decoded[cursor++];
    const row = decoded.subarray(cursor, cursor + inputStride);
    cursor += inputStride;
    const out = Buffer.alloc(inputStride);
    for (let i = 0; i < inputStride; i++) {
      const left = i >= bpp ? out[i - bpp] : 0;
      const up = y > 0 ? reconstructedRows[y - 1][i] : 0;
      const upLeft = y > 0 && i >= bpp ? reconstructedRows[y - 1][i - bpp] : 0;
      if (filter === 0) out[i] = row[i];
      else if (filter === 1) out[i] = (row[i] + left) & 0xff;
      else if (filter === 2) out[i] = (row[i] + up) & 0xff;
      else if (filter === 3) out[i] = (row[i] + ((left + up) >> 1)) & 0xff;
      else if (filter === 4) out[i] = (row[i] + paethPredictor(left, up, upLeft)) & 0xff;
      else throw new Error(`unsupported PNG filter type ${filter} in ${filePath}`);
    }
    reconstructedRows.push(out);
  }

  const outputStride = width * 4;
  const outputRows = Buffer.alloc((1 + outputStride) * height);
  let outCursor = 0;
  for (let y = 0; y < height; y++) {
    outputRows[outCursor++] = 0; // use filter type 0 for deterministic output
    const source = reconstructedRows[y];
    for (let x = 0; x < width; x++) {
      const src = x * 3;
      outputRows[outCursor++] = source[src];
      outputRows[outCursor++] = source[src + 1];
      outputRows[outCursor++] = source[src + 2];
      outputRows[outCursor++] = 255;
    }
  }

  const rebuiltIhdr = Buffer.from(ihdr.data);
  rebuiltIhdr[9] = 6; // RGBA
  const passthrough = chunks.filter((chunk) => !["IHDR", "IDAT", "IEND"].includes(chunk.type));
  const rebuilt = Buffer.concat([
    PNG_SIGNATURE,
    pngChunk("IHDR", rebuiltIhdr),
    ...passthrough.map((chunk) => pngChunk(chunk.type, chunk.data)),
    pngChunk("IDAT", deflateSync(outputRows, { level: 9 })),
    pngChunk("IEND", Buffer.alloc(0)),
  ]);

  await writeFile(filePath, rebuilt);
}

function pngChunk(type, data) {
  const typeBuffer = Buffer.from(type, "ascii");
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length, 0);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([typeBuffer, data])), 0);
  return Buffer.concat([length, typeBuffer, data, crc]);
}

function crc32(buffer) {
  let current = 0xffffffff;
  for (const byte of buffer) {
    current = CRC32_TABLE[(current ^ byte) & 0xff] ^ (current >>> 8);
  }
  return (current ^ 0xffffffff) >>> 0;
}

function buildCrc32Table() {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let current = n;
    for (let bit = 0; bit < 8; bit++) {
      current = (current & 1) ? (0xedb88320 ^ (current >>> 1)) : (current >>> 1);
    }
    table[n] = current >>> 0;
  }
  return table;
}

function paethPredictor(a, b, c) {
  const p = a + b - c;
  const pa = Math.abs(p - a);
  const pb = Math.abs(p - b);
  const pc = Math.abs(p - c);
  if (pa <= pb && pa <= pc) return a;
  if (pb <= pc) return b;
  return c;
}

async function writeIcoFromPng(pngPath, icoPath) {
  const png = await readFile(pngPath);
  if (!png.subarray(0, 8).equals(PNG_SIGNATURE)) {
    throw new Error(`not a PNG file: ${pngPath}`);
  }
  const ihdrType = png.toString("ascii", 12, 16);
  if (ihdrType !== "IHDR") {
    throw new Error(`invalid PNG header: ${pngPath}`);
  }
  const width = png.readUInt32BE(16);
  const height = png.readUInt32BE(20);
  if (width < 1 || height < 1) {
    throw new Error(`invalid PNG dimensions in ${pngPath}`);
  }

  const iconDir = Buffer.alloc(6);
  iconDir.writeUInt16LE(0, 0); // reserved
  iconDir.writeUInt16LE(1, 2); // icon type
  iconDir.writeUInt16LE(1, 4); // image count

  const entry = Buffer.alloc(16);
  entry[0] = width >= 256 ? 0 : width;
  entry[1] = height >= 256 ? 0 : height;
  entry[2] = 0; // color palette size
  entry[3] = 0; // reserved
  entry.writeUInt16LE(1, 4); // color planes
  entry.writeUInt16LE(32, 6); // bits per pixel
  entry.writeUInt32LE(png.length, 8); // image bytes
  entry.writeUInt32LE(iconDir.length + entry.length, 12); // image offset

  await writeFile(icoPath, Buffer.concat([iconDir, entry, png]));
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
      width: 256,
      height: 256,
      html: iconHtml,
      path: path.join(iconsDir, "icon-256.png"),
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

    await Promise.all([
      ensurePngRgba(path.join(iconsDir, "icon-512.png")),
      ensurePngRgba(path.join(iconsDir, "icon-512-maskable.png")),
      ensurePngRgba(path.join(iconsDir, "icon-192.png")),
      ensurePngRgba(path.join(iconsDir, "icon-256.png")),
      ensurePngRgba(path.join(iconsDir, "apple-touch-icon.png")),
      ensurePngRgba(path.join(iconsDir, "favicon-32.png")),
      ensurePngRgba(path.join(iconsDir, "favicon-16.png")),
    ]);

    await writeIcoFromPng(path.join(iconsDir, "icon-256.png"), path.join(iconsDir, "icon.ico"));
  } finally {
    await browser.close();
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
