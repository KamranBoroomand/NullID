import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  analyzeSecret,
  estimatePassphraseEntropy,
  generatePassphrase,
  generatePassword,
  getPassphraseDictionaryStats,
  type PassphraseSettings,
  type PasswordSettings,
} from "../utils/passwordToolkit.js";

function hasSequentialRun(value: string, minRun = 3): boolean {
  const lower = value.toLowerCase();
  const sources = ["abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiopasdfghjklzxcvbnm"];
  return sources.some((source) => {
    for (let i = 0; i <= source.length - minRun; i += 1) {
      const fragment = source.slice(i, i + minRun);
      const reverse = fragment.split("").reverse().join("");
      if (lower.includes(fragment) || lower.includes(reverse)) return true;
    }
    return false;
  });
}

describe("password toolkit", () => {
  it("reports larger dictionary profiles", () => {
    const balanced = getPassphraseDictionaryStats("balanced");
    const extended = getPassphraseDictionaryStats("extended");
    const maximal = getPassphraseDictionaryStats("maximal");
    assert.equal(balanced.size, 32_768);
    assert.equal(extended.size, 1_048_576);
    assert.equal(maximal.size, 16_777_216);
  });

  it("generates passphrases with unique words and wraps", () => {
    const settings: PassphraseSettings = {
      words: 7,
      separator: "-",
      dictionaryProfile: "maximal",
      caseStyle: "random",
      numberMode: "append-4",
      symbolMode: "wrap",
      ensureUniqueWords: true,
    };
    const passphrase = generatePassphrase(settings);
    assert.equal(passphrase.length > 10, true);
    assert.equal(/^\S+$/.test(passphrase), true);
    assert.equal(/\d{4}/.test(passphrase), true);
  });

  it("raises passphrase entropy when using larger dictionaries", () => {
    const baseline: PassphraseSettings = {
      words: 5,
      separator: "-",
      dictionaryProfile: "balanced",
      caseStyle: "lower",
      numberMode: "none",
      symbolMode: "none",
      ensureUniqueWords: true,
    };
    const stronger: PassphraseSettings = { ...baseline, dictionaryProfile: "maximal", words: 7, symbolMode: "append" };
    assert.equal(estimatePassphraseEntropy(stronger) > estimatePassphraseEntropy(baseline), true);
  });

  it("generates passwords that satisfy hardening constraints", () => {
    const settings: PasswordSettings = {
      length: 24,
      upper: true,
      lower: true,
      digits: true,
      symbols: true,
      avoidAmbiguity: true,
      enforceMix: true,
      blockSequential: true,
      blockRepeats: true,
      minUniqueChars: 14,
    };
    for (let i = 0; i < 20; i += 1) {
      const password = generatePassword(settings);
      assert.equal(password.length, 24);
      assert.equal(hasSequentialRun(password, 3), false);
      assert.equal(new Set(password).size >= 14, true);
      assert.equal(/(.)\1\1/.test(password), false);
    }
  });

  it("penalizes weak patterns during analysis", () => {
    const weak = analyzeSecret("password123");
    const strong = analyzeSecret("Q7$wLm2!kP9@rT5#");
    assert.equal(weak.effectiveEntropyBits < strong.effectiveEntropyBits, true);
    assert.equal(weak.warnings.length > 0, true);
  });
});
