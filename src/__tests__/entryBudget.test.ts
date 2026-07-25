import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const scriptPath = path.resolve(process.cwd(), "scripts/verify-entry-budget.mjs");

describe("entry bundle budget", () => {
  it("fails when a static initial dependency pushes the graph over budget", () => {
    const distDir = createBudgetFixture();
    const result = runBudget(distDir, 100);

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /initial JavaScript graph budget exceeded/i);
    assert.match(result.stderr, /assets\/index\.js/);
    assert.match(result.stderr, /assets\/vendor\.js/);
  });

  it("excludes dynamic imports from the initial graph budget", () => {
    const distDir = createBudgetFixture();
    const result = runBudget(distDir, 180);

    assert.equal(result.status, 0);
    assert.match(result.stdout, /initial JavaScript graph budget passed/i);
    assert.doesNotMatch(result.stdout, /lazy\.js/);
  });
});

function createBudgetFixture() {
  const distDir = mkdtempSync(path.join(tmpdir(), "nullid-budget-"));
  mkdirSync(path.join(distDir, "assets"), { recursive: true });
  mkdirSync(path.join(distDir, ".vite"), { recursive: true });
  writeFileSync(path.join(distDir, "index.html"), '<script type="module" src="/assets/index.js"></script>');
  writeFileSync(path.join(distDir, "assets", "index.js"), "i".repeat(40));
  writeFileSync(path.join(distDir, "assets", "vendor.js"), "v".repeat(120));
  writeFileSync(path.join(distDir, "assets", "lazy.js"), "l".repeat(1_000));
  writeFileSync(
    path.join(distDir, ".vite", "manifest.json"),
    JSON.stringify({
      "src/main.tsx": {
        file: "assets/index.js",
        isEntry: true,
        imports: ["_vendor.js"],
        dynamicImports: ["_lazy.js"],
      },
      "_vendor.js": { file: "assets/vendor.js" },
      "_lazy.js": { file: "assets/lazy.js" },
    }),
  );
  return distDir;
}

function runBudget(distDir: string, budgetBytes: number) {
  return spawnSync(process.execPath, [scriptPath, distDir], {
    encoding: "utf8",
    env: {
      ...process.env,
      NULLID_ENTRY_BUDGET_BYTES: String(budgetBytes),
    },
  });
}
