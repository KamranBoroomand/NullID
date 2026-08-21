#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import {
  PRODUCTION_ORIGIN,
  SITE_NAME,
  SOCIAL_IMAGE_ALT,
  SOCIAL_IMAGE_URL,
  canonicalUrl,
  publicPages,
  sitemapPaths,
} from "./public-site-data.mjs";

const DIST_DIR = path.resolve("dist");
const DEPLOYMENT_BASE_PATH = normalizeDeploymentBasePath(process.env.VITE_BASE ?? "/");

try {
  validatePages();
  for (const page of publicPages) {
    writeFileForRoute(page.path, renderPage(page));
  }
  fs.writeFileSync(path.join(DIST_DIR, "robots.txt"), renderRobots(), "utf8");
  fs.writeFileSync(path.join(DIST_DIR, "sitemap.xml"), renderSitemap(), "utf8");
  fs.writeFileSync(path.join(DIST_DIR, "404.html"), renderNotFound(), "utf8");
  console.log(`[public-site] generated ${publicPages.length} pages, sitemap, robots.txt, and 404.html`);
} catch (error) {
  console.error(`[public-site] ${error instanceof Error ? error.message : "generation failed"}`);
  process.exit(1);
}

function validatePages() {
  const seenPaths = new Set();
  const seenTitles = new Set();
  const seenDescriptions = new Set();
  const knownPaths = new Set(sitemapPaths);
  for (const page of publicPages) {
    if (!/^\/[a-z0-9-]+\/$/u.test(page.path)) throw new Error(`invalid public route: ${page.path}`);
    if (!page.title?.trim()) throw new Error(`missing title for ${page.path}`);
    if (!page.description?.trim()) throw new Error(`missing description for ${page.path}`);
    if (!page.h1?.trim()) throw new Error(`missing h1 for ${page.path}`);
    if (seenPaths.has(page.path)) throw new Error(`duplicate route: ${page.path}`);
    if (seenTitles.has(page.title)) throw new Error(`duplicate title: ${page.title}`);
    if (seenDescriptions.has(page.description)) throw new Error(`duplicate description: ${page.description}`);
    seenPaths.add(page.path);
    seenTitles.add(page.title);
    seenDescriptions.add(page.description);
    for (const related of page.related ?? []) {
      if (!knownPaths.has(related)) throw new Error(`${page.path} links to unknown related route ${related}`);
    }
    for (const section of page.sections ?? []) {
      for (const linked of section.links ?? []) {
        if (!knownPaths.has(linked)) throw new Error(`${page.path} links to unknown section route ${linked}`);
      }
    }
    for (const card of page.cards ?? []) {
      if (!knownPaths.has(card.href)) throw new Error(`${page.path} links to unknown card route ${card.href}`);
    }
  }
}

function writeFileForRoute(route, html) {
  const targetDir = path.join(DIST_DIR, route.slice(1));
  fs.mkdirSync(targetDir, { recursive: true });
  fs.writeFileSync(path.join(targetDir, "index.html"), html, "utf8");
}

function renderPage(page) {
  const bodyClass = page.path === "/tools/" ? "public-page public-page-tools" : "public-page";
  const pageSections = page.faqs ? renderFaqs(page.faqs) : renderSections(page.sections ?? []);
  return htmlDocument({
    route: page.path,
    title: page.title,
    description: page.description,
    canonical: canonicalUrl(page.path),
    bodyClass,
    noindex: false,
    body: `
      ${renderHeader(page.path)}
      <main class="site-main" itemscope itemtype="https://schema.org/WebApplication">
        ${renderMicrodata(page.description)}
        <section class="site-hero">
          <p class="site-kicker">${escapeHtml(SITE_NAME)} public guide</p>
          <h1>${escapeHtml(page.h1)}</h1>
          <p class="site-lede">${escapeHtml(page.intro)}</p>
          ${page.cta ? `<p class="site-actions"><a class="site-button" href="${escapeAttr(page.cta.href)}">${escapeHtml(page.cta.label)}</a><a class="site-link" href="/tools/">Browse tools</a></p>` : ""}
        </section>
        ${page.cards ? renderCards(page.cards) : ""}
        ${pageSections}
        ${renderRelated(page.related ?? [])}
      </main>
      ${renderFooter()}
    `,
  });
}

function renderMicrodata(description) {
  return `
    <meta itemprop="name" content="NullID" />
    <meta itemprop="url" content="${PRODUCTION_ORIGIN}/" />
    <meta itemprop="description" content="${escapeAttr(description)}" />
    <meta itemprop="applicationCategory" content="SecurityApplication" />
    <meta itemprop="operatingSystem" content="Modern browsers" />
    <span itemprop="offers" itemscope itemtype="https://schema.org/Offer">
      <meta itemprop="price" content="0" />
      <meta itemprop="priceCurrency" content="USD" />
    </span>
  `;
}

function renderSections(sections) {
  return sections
    .map((section) => {
      const content = section.list
        ? `<ul>${section.list.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`
        : `<p>${escapeHtml(section.body ?? "")}</p>`;
      const links = section.links?.length
        ? `<p class="section-links">${section.links.map((href) => `<a href="${escapeAttr(href)}">${escapeHtml(labelForPath(href))}</a>`).join("")}</p>`
        : "";
      return `<section class="site-panel"><h2>${escapeHtml(section.heading)}</h2>${content}${links}</section>`;
    })
    .join("\n");
}

function renderCards(cards) {
  return `
    <section class="site-card-grid" aria-label="NullID tools">
      ${cards
        .map(
          (card) => `
            <article class="site-card">
              <h2><a href="${escapeAttr(card.href)}">${escapeHtml(card.title)}</a></h2>
              <p>${escapeHtml(card.body)}</p>
            </article>
          `,
        )
        .join("")}
    </section>
  `;
}

function renderFaqs(faqs) {
  return `
    <section class="site-faq-list" aria-label="Frequently asked questions">
      ${faqs
        .map(
          (item) => `
            <article class="site-panel">
              <h2>${escapeHtml(item.question)}</h2>
              <p>${escapeHtml(item.answer)}</p>
            </article>
          `,
        )
        .join("")}
    </section>
  `;
}

function renderRelated(paths) {
  if (!paths.length) return "";
  return `
    <nav class="site-related" aria-label="Related pages">
      <h2>Related NullID pages</h2>
      <ul>
        ${paths.map((href) => `<li><a href="${escapeAttr(href)}">${escapeHtml(labelForPath(href))}</a></li>`).join("")}
      </ul>
    </nav>
  `;
}

function renderHeader(activePath) {
  const navItems = [
    ["/", "Workbench"],
    ["/tools/", "Tools"],
    ["/privacy/", "Privacy"],
    ["/faq/", "FAQ"],
  ];
  return `
    <header class="site-header">
      <a class="site-brand" href="/" aria-label="NullID workbench">
        <img src="${relativeAssetPrefix(activePath)}brand/nullid-lockup-light.svg" alt="NullID" width="142" height="34" />
      </a>
      <nav aria-label="Public navigation">
        ${navItems.map(([href, label]) => `<a href="${href}"${href === activePath ? " aria-current=\"page\"" : ""}>${label}</a>`).join("")}
      </nav>
    </header>
  `;
}

function renderFooter() {
  return `
    <footer class="site-footer">
      <p>NullID processes sensitive workflows locally in the browser after the application is delivered from its production origin.</p>
      <p><a href="/privacy/">Privacy Policy</a> · <a href="/faq/">FAQ</a> · <a href="/tools/">Tools</a></p>
    </footer>
  `;
}

function renderRobots() {
  return `User-agent: *\nAllow: /\nSitemap: ${PRODUCTION_ORIGIN}/sitemap.xml\n`;
}

function renderSitemap() {
  const urls = sitemapPaths.map((pathname) => `  <url><loc>${canonicalUrl(pathname)}</loc></url>`).join("\n");
  return `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls}\n</urlset>\n`;
}

function renderNotFound() {
  return htmlDocument({
    route: "/404",
    title: "Page not found - NullID",
    description: "The requested NullID page was not found.",
    canonical: "",
    bodyClass: "public-page public-page-404",
    noindex: true,
    body: `
      ${renderHeader("/404")}
      <main class="site-main">
        <section class="site-hero">
          <p class="site-kicker">NullID</p>
          <h1>Page not found</h1>
          <p class="site-lede">The requested page does not exist. Open the workbench or browse the public tool guide.</p>
          <p class="site-actions"><a class="site-button" href="/">Open workbench</a><a class="site-link" href="/tools/">Browse tools</a><a class="site-link" href="/faq/">Read FAQ</a></p>
        </section>
      </main>
      ${renderFooter()}
    `,
  });
}

function htmlDocument({ route, title, description, canonical, bodyClass, noindex, body }) {
  const assetPrefix = relativeAssetPrefix(route);
  const canonicalTags = canonical
    ? `<link rel="canonical" href="${escapeAttr(canonical)}" />\n    <meta property="og:url" content="${escapeAttr(canonical)}" />`
    : "";
  const robots = noindex ? `\n    <meta name="robots" content="noindex" />` : "";
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>${escapeHtml(title)}</title>
    <meta name="description" content="${escapeAttr(description)}" />${robots}
    ${canonicalTags}
    <meta property="og:type" content="website" />
    <meta property="og:site_name" content="NullID" />
    <meta property="og:title" content="${escapeAttr(title)}" />
    <meta property="og:description" content="${escapeAttr(description)}" />
    <meta property="og:image" content="${SOCIAL_IMAGE_URL}" />
    <meta property="og:image:secure_url" content="${SOCIAL_IMAGE_URL}" />
    <meta property="og:image:type" content="image/png" />
    <meta property="og:image:width" content="1200" />
    <meta property="og:image:height" content="630" />
    <meta property="og:image:alt" content="${SOCIAL_IMAGE_ALT}" />
    <meta name="twitter:card" content="summary_large_image" />
    <meta name="twitter:title" content="${escapeAttr(title)}" />
    <meta name="twitter:description" content="${escapeAttr(description)}" />
    <meta name="twitter:image" content="${SOCIAL_IMAGE_URL}" />
    <meta name="twitter:image:alt" content="${SOCIAL_IMAGE_ALT}" />
    <link rel="shortcut icon" href="${assetPrefix}icons/icon.ico" />
    <link rel="icon" type="image/png" sizes="32x32" href="${assetPrefix}icons/favicon-32.png" />
    <link rel="icon" type="image/png" sizes="16x16" href="${assetPrefix}icons/favicon-16.png" />
    <link rel="icon" type="image/svg+xml" href="${assetPrefix}favicon.svg" />
    <link rel="apple-touch-icon" href="${assetPrefix}icons/apple-touch-icon.png" />
    <link rel="stylesheet" href="${assetPrefix}site.css" />
  </head>
  <body class="${escapeAttr(bodyClass)}">
${body}
  </body>
</html>
`;
}

function relativeAssetPrefix(route) {
  if (route === "/404") return DEPLOYMENT_BASE_PATH;
  return route === "/" ? "./" : "../";
}

function normalizeDeploymentBasePath(value) {
  const trimmed = String(value || "/").trim();
  const withLeadingSlash = trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
  return withLeadingSlash.endsWith("/") ? withLeadingSlash : `${withLeadingSlash}/`;
}

function labelForPath(href) {
  if (href === "/") return "Workbench";
  const page = publicPages.find((entry) => entry.path === href);
  return page ? page.h1 : href;
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/gu, "&amp;")
    .replace(/</gu, "&lt;")
    .replace(/>/gu, "&gt;")
    .replace(/"/gu, "&quot;");
}

function escapeAttr(value) {
  return escapeHtml(value);
}
