import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { SUPPORTED_LOCALES, localeMeta, messages, phraseTranslations } from "../i18n.js";
import { guidePhraseTranslations } from "../content/guidePhraseTranslations.js";
import { runtimePhraseTranslations } from "../content/runtimePhraseTranslations.js";
import { workflowPhraseTranslations } from "../content/workflowPhraseTranslations.js";
describe("i18n locale contract", () => {
    it("supports exactly en, fa, ru", () => {
        assert.deepEqual(SUPPORTED_LOCALES, ["en", "fa", "ru"]);
    });
    it("keeps direction + bcp47 metadata stable", () => {
        assert.equal(localeMeta.en.direction, "ltr");
        assert.equal(localeMeta.ru.direction, "ltr");
        assert.equal(localeMeta.fa.direction, "rtl");
        assert.equal(localeMeta.en.bcp47, "en-US");
        assert.equal(localeMeta.ru.bcp47, "ru-RU");
        assert.equal(localeMeta.fa.bcp47, "fa-IR");
    });
    it("keeps non-English message keys aligned with English", () => {
        const enKeys = new Set(Object.keys(messages.en));
        for (const locale of ["fa", "ru"]) {
            const localeKeys = new Set(Object.keys(messages[locale]));
            const missing = [...enKeys].filter((key) => !localeKeys.has(key));
            assert.deepEqual(missing, []);
        }
    });
    it("keeps phrase catalogs complete for fa/ru entries", () => {
        const merged = {
            ...phraseTranslations,
            ...runtimePhraseTranslations,
            ...workflowPhraseTranslations,
            ...guidePhraseTranslations,
        };
        const missingFa = Object.entries(merged).filter(([, entry]) => entry.fa.trim().length === 0);
        const missingRu = Object.entries(merged).filter(([, entry]) => entry.ru.trim().length === 0);
        assert.deepEqual(missingFa, []);
        assert.deepEqual(missingRu, []);
    });
    it("keeps critical runtime phrases localized without obvious English leakage", () => {
        const checks = [
            { phrase: "vault locked", faExcludes: /vault/i, ruExcludes: /vault/i, faIncludes: /گاوصندوق/, ruIncludes: /сейф/i },
            {
                phrase: "safe-share export failed",
                faExcludes: /safe-share/i,
                ruExcludes: /safe-share/i,
                faIncludes: /اشتراک امن/,
                ruIncludes: /безопасн/i,
            },
            {
                phrase: "encrypted safe-share bundle exported",
                faExcludes: /safe-share/i,
                ruExcludes: /safe-share/i,
                faIncludes: /اشتراک امن/,
                ruIncludes: /безопасн/i,
            },
            { phrase: "Export policy packs", faIncludes: /بسته.*خط‌مشی/, ruIncludes: /пакет.*политик/i },
            { phrase: "Import policy pack", faIncludes: /بسته.*خط‌مشی/, ruIncludes: /пакет.*политик/i },
            { phrase: "feedback stored locally", ruIncludes: /обратн/i, ruExcludes: /фидбек/i },
        ];
        for (const check of checks) {
            const entry = phraseTranslations[check.phrase] ?? runtimePhraseTranslations[check.phrase];
            assert.equal(entry === undefined, false);
            if (!entry)
                continue;
            if (check.faExcludes)
                assert.equal(check.faExcludes.test(entry.fa), false);
            if (check.ruExcludes)
                assert.equal(check.ruExcludes.test(entry.ru), false);
            if (check.faIncludes)
                assert.equal(check.faIncludes.test(entry.fa), true);
            if (check.ruIncludes)
                assert.equal(check.ruIncludes.test(entry.ru), true);
        }
    });
    it("keeps dense trust/help phrases free of obvious mixed-language leakage", () => {
        const checks = [
            {
                phrase: "Paste a workflow package, safe-share bundle, profile, policy pack, vault snapshot, or NULLID envelope",
                source: "workflow",
                faExcludes: /snapshot/i,
                ruExcludes: /vault/i,
                faIncludes: /اسنپ‌شات/,
                ruIncludes: /сейф/i,
            },
            {
                phrase: "Uses the same incident note headings that are available in Secure Notes, but prepares them for export rather than local vault storage.",
                source: "workflow",
                ruExcludes: /vault/i,
                ruIncludes: /сейф/i,
            },
            {
                phrase: "Profiles, policy packs, and vault snapshots support optional signature verification.",
                source: "guide",
                faExcludes: /snapshot|vault/i,
                ruExcludes: /vault|policy pack/i,
                faIncludes: /اسنپ.*گاوصندوق/,
                ruIncludes: /снимк.*сейф/i,
            },
            {
                phrase: "Vault content lives in IndexedDB and is not included; export the vault separately.",
                source: "guide",
                faExcludes: /vault/i,
                ruExcludes: /vault/i,
                faIncludes: /گاوصندوق/,
                ruIncludes: /сейф/i,
            },
            {
                phrase: "Rule-based scrubbing for logs with diff preview, reusable local policy packs, optional shared-passphrase HMAC metadata, simulation matrix comparisons, rule-impact ranking, batch file sanitization, baseline policy merge, and safe-share bundle export (including GitHub/Slack token and private-key block stripping).",
                source: "guide",
                faExcludes: /policy pack|baseline|safe-share/i,
                ruExcludes: /policy pack|baseline|safe-share/i,
                faIncludes: /خط‌مشی پایه|اشتراک امن/,
                ruIncludes: /базов.*политик|безопасн/i,
            },
        ];
        for (const check of checks) {
            const entry = check.source === "guide" ? guidePhraseTranslations[check.phrase] : workflowPhraseTranslations[check.phrase];
            assert.equal(entry === undefined, false);
            if (!entry)
                continue;
            if (check.faExcludes)
                assert.equal(check.faExcludes.test(entry.fa), false);
            if (check.ruExcludes)
                assert.equal(check.ruExcludes.test(entry.ru), false);
            if (check.faIncludes)
                assert.equal(check.faIncludes.test(entry.fa), true);
            if (check.ruIncludes)
                assert.equal(check.ruIncludes.test(entry.ru), true);
        }
    });
});
