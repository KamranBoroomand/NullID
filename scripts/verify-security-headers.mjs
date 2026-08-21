import fs from "node:fs";
import path from "node:path";
import { parseHeadersFile, validateStaticHostHeaderPolicy } from "./header-policy.mjs";

const ROOT = process.cwd();

try {
  validateStaticHostHeaderPolicy(parseHeadersFile(loadHeadersFile()), "public/_headers");
  console.log("security headers: strict Cloudflare Pages baseline config verified");
} catch (error) {
  const message = error instanceof Error ? error.message : "header verification failed";
  console.error(`security headers: ${message}`);
  process.exitCode = 1;
}

function loadHeadersFile() {
  const file = path.join(ROOT, "public", "_headers");
  if (!fs.existsSync(file)) throw new Error("Missing public/_headers security policy file");
  return fs.readFileSync(file, "utf8");
}
