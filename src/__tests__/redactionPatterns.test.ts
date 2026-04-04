import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  applyRedaction,
  buildRedactionChanges,
  getRedactionDetectors,
  scanRedaction,
} from "../utils/redaction.js";

describe("redaction patterns", () => {
  it("detects general URL, email, and generic ID patterns", () => {
    const detectors = getRedactionDetectors().filter((detector) => ["url", "email", "uuid"].includes(detector.key));
    const sampleUrl = buildSampleUrl("/reset");
    const text = `Open ${sampleUrl} and email alice@example.com ref 550e8400-e29b-41d4-a716-446655440000`;
    const findings = scanRedaction(text, detectors, [], { minimumSeverity: "low", minTokenLength: 20 });

    assert.equal(findings.matches.some((match) => match.key === "url"), true);
    assert.equal(findings.matches.some((match) => match.key === "email"), true);
    assert.equal(findings.matches.some((match) => match.key === "uuid"), true);
  });

  it("keeps Iran and Russia regional detectors opt-in but functional when enabled", () => {
    const detectors = getRedactionDetectors().filter((detector) => detector.ruleSet !== "general");
    const iranNationalId = makeIranNationalId("123456789");
    const iranCard = "۶۰۳۷-۹۹۷۳-۹۱۸۹-۸۰۸۸";
    const iranSheba = "IR۸۲۰۵۴۰۱۰۲۶۸۰۰۲۰۸۱۷۹۰۹۰۰۲";
    const ruInn = makeRussianInn("770708389");
    const ruSnils = makeRussianSnils("112233445");
    const text = `کد ملی: ${toPersianDigits(iranNationalId)}\nنام: علی رضایی\nشماره: ${toPersianDigits("09123456789")}\nشماره کارت: ${iranCard}\nکد پستی: ${toPersianDigits("1439953141")}\nشبا: ${iranSheba}\nИНН ${ruInn}\nСНИЛС ${ruSnils}\nТелефон: 8 (912) 345 67 89\nПаспорт серия 45 08 номер 123456\nГосномер: А123ВС77`;
    const findings = scanRedaction(text, detectors, [], { minimumSeverity: "low", minTokenLength: 20 });

    assert.equal(findings.matches.some((match) => match.key === "iran-id"), true);
    assert.equal(findings.matches.some((match) => match.key === "persian-name"), true);
    assert.equal(findings.matches.some((match) => match.key === "iran-phone"), true);
    assert.equal(findings.matches.some((match) => match.key === "iran-card-context"), true);
    assert.equal(findings.matches.some((match) => match.key === "iran-postal-context"), true);
    assert.equal(findings.matches.some((match) => match.key === "iran-sheba"), true);
    assert.equal(findings.matches.some((match) => match.key === "ru-inn"), true);
    assert.equal(findings.matches.some((match) => match.key === "ru-snils"), true);
    assert.equal(findings.matches.some((match) => match.key === "ru-phone"), true);
    assert.equal(findings.matches.some((match) => match.key === "ru-passport-context"), true);
    assert.equal(findings.matches.some((match) => match.key === "ru-vehicle-context"), true);
  });

  it("reports exact replacements before apply", () => {
    const detectors = getRedactionDetectors().filter((detector) => detector.key === "email" || detector.key === "url");
    const sampleUrl = buildSampleUrl("");
    const text = `alice@example.com -> ${sampleUrl}`;
    const findings = scanRedaction(text, detectors, [], { minimumSeverity: "low", minTokenLength: 20 });
    const changes = buildRedactionChanges(text, findings.matches, "full");
    const output = applyRedaction(text, findings.matches, "full");

    assert.deepEqual(
      changes.map((change) => ({ original: change.original, replacement: change.replacement })),
      [
        { original: "alice@example.com", replacement: "[email]" },
        { original: sampleUrl, replacement: "[url]" },
      ],
    );
    assert.equal(output, "[email] -> [url]");
  });
});

function makeIranNationalId(prefix: string) {
  const sum = prefix.split("").reduce((acc, ch, index) => acc + Number(ch) * (10 - index), 0);
  const remainder = sum % 11;
  const check = remainder < 2 ? remainder : 11 - remainder;
  return `${prefix}${check}`;
}

function makeRussianInn(prefix: string) {
  const weights = [2, 4, 10, 3, 5, 9, 4, 6, 8];
  const checksum = prefix.split("").reduce((acc, ch, index) => acc + Number(ch) * weights[index], 0);
  return `${prefix}${(checksum % 11) % 10}`;
}

function makeRussianSnils(prefix: string) {
  const sum = prefix.split("").reduce((acc, ch, index) => acc + Number(ch) * (9 - index), 0);
  let control = 0;
  if (sum < 100) control = sum;
  else if (sum === 100 || sum === 101) control = 0;
  else control = sum % 101 === 100 ? 0 : sum % 101;
  return `${prefix}${String(control).padStart(2, "0")}`;
}

function toPersianDigits(value: string) {
  return value.replace(/\d/g, (digit) => String.fromCharCode(digit.charCodeAt(0) + 1728));
}

function buildSampleUrl(pathname: string) {
  return ["http", "s://", "nullid.local", pathname].join("");
}
