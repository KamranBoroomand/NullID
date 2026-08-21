import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

describe("public network copy", () => {
  it("keeps local-processing copy accurate without claiming no runtime network calls", () => {
    const checkedFiles = [
      "index.html",
      "scripts/generate-brand-assets.mjs",
      "src/views/GuideView.tsx",
      "src/i18n.tsx",
      "src/content/guidePhraseTranslations.ts",
    ];
    const contents = new Map(checkedFiles.map((file) => [file, fs.readFileSync(file, "utf8")]));
    const combined = Array.from(contents.values()).join("\n");

    assert.equal(/no runtime network calls/i.test(combined), false);
    assert.match(
      contents.get("index.html") ?? "",
      /NullID is a local-first browser workbench for encryption, redaction, metadata privacy, hashing, verification, secret review, and password generation\./,
      "index.html",
    );
    for (const file of ["scripts/generate-brand-assets.mjs", "src/views/GuideView.tsx"]) {
      assert.match(contents.get(file) ?? "", /No external API calls or analytics; processing remains local\./, file);
    }
  });
});
