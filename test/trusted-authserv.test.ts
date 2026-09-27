/**
 * Herkunft von Prüfzeilen mit hinterlegter authserv-id (Review @saltyslugga,
 * MailHeaderAnalyzer 0.2.0): Received-Zeilen lassen sich zusammen mit der
 * Prüfzeile fälschen. Der Abgleich mit der Zustellkette ist deshalb nur
 * plausibel; belegt ist allein eine authserv-id, die der Nutzer als die
 * seines Gateways angibt. Die ARC-Prüfung betrifft nur den Aufbau.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  analyzeHeaders, arcWitnesses, classifyAuthTrust, parseTrustedIds, splitHeaders,
} from "../src/parse.ts";

const analyzeFixture = (name: string, trusted: string[] = []) => {
  const raw = readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8");
  const { fields, hadBody } = splitHeaders(raw);
  return analyzeHeaders(fields, hadBody, { trustedAuthServIds: trusted });
};

test("gefaelschte Received- und Pruefzeile bleiben ohne hinterlegte ID nur plausibel", () => {
  const a = analyzeFixture("f09-received-und-authresults-gefaelscht.eml");
  assert.equal(a.authTrust, "matched");
  assert.notEqual(a.authTrust, "trusted");
});

test("hinterlegte ID wird exakt verglichen und hat Vorrang", () => {
  const a = analyzeFixture("f04-authresults-gefaelscht-plus-echt.eml", ["MX.Empfang.invalid."]);
  assert.equal(a.authTrust, "trusted");
  assert.deepEqual(a.trustedIds, ["mx.empfang.invalid"]);
  assert.equal(a.summary.dmarc?.result, "fail");
  assert.equal(classifyAuthTrust("mx.empfang.invalid", [], ["empfang.invalid"]), "unmatched");
  assert.equal(classifyAuthTrust("mx.empfang.invalid", ["mx.empfang.invalid"], ["empfang.invalid"]), "matched");
});

test("keine Zeile mit hinterlegter ID: Ergebnis gilt nicht als belegt", () => {
  const a = analyzeFixture("f04-authresults-echt.eml", ["empfang.invalid"]);
  assert.equal(a.authTrust, "matched");
  assert.deepEqual(a.trustedIds, ["empfang.invalid"]);
});

test("widerspruechliche Zeilen mit hinterlegter ID werden gemeldet", () => {
  const a = analyzeFixture("f09-trusted-nicht-entfernt.eml", ["mx.empfang.invalid"]);
  assert.equal(a.authTrust, "trusted");
  assert.equal(a.summary.dmarc?.result, "fail");
  assert.deepEqual([...a.trustedConflicts].sort(), ["dmarc", "spf"]);
});

test("Received-SPF folgt ebenfalls der hinterlegten ID", () => {
  assert.equal(analyzeFixture("f04-received-spf-ohne-auth.eml", ["mx.bank.example"]).receivedSpfTrust, "trusted");
  assert.equal(analyzeFixture("f04-received-spf-ohne-auth.eml").receivedSpfTrust, "unmatched");
});

test("Freitext mit mehreren IDs wird zerlegt und normalisiert", () => {
  assert.deepEqual(parseTrustedIds(" MX1.example.org, mx2.example.org.;mx1.example.org \n"), ["mx1.example.org", "mx2.example.org"]);
  assert.deepEqual(parseTrustedIds(""), []);
  assert.deepEqual(parseTrustedIds(null), []);
});

test("ARC-Zeuge zaehlt nur mit arc=pass des Empfaengers", () => {
  const ok = analyzeFixture("w1a02-arc-witness-echt.eml");
  assert.equal(arcWitnesses(ok, "bank.example").length, 1);
  const noPass = analyzeFixture("w1a02-arc-witness-ohne-arc-pass.eml");
  assert.equal(arcWitnesses(noPass, "bank.example").length, 0);
});

test("ARC: Aufbau wird geprueft, ohne Signaturgueltigkeit zu behaupten", () => {
  const broken = analyzeFixture("w1a02-arc-witness-substring.eml");
  assert.equal(broken.arcStructure, "inconsistent");
  assert.ok(broken.arcIssues.some((x) => x.kind === "count" && x.i === 1 && x.header === "ARC-Message-Signature" && x.n === 0));
  assert.ok(!("arcValid" in broken));
  assert.equal(analyzeFixture("baseline-m365.eml").arcStructure, null);
});

test("ARC: vollstaendige Kette mit falscher cv-Folge ist inkonsistent", () => {
  const raw = [
    "ARC-Seal: i=2; a=rsa-sha256; d=r2.example.test; cv=none; b=AAAA",
    "ARC-Message-Signature: i=2; a=rsa-sha256; d=r2.example.test; b=AAAA",
    "ARC-Authentication-Results: i=2; mx.r2.example.test; dkim=pass header.d=example.org",
    "ARC-Seal: i=1; a=rsa-sha256; d=r1.example.test; cv=none; b=AAAA",
    "ARC-Message-Signature: i=1; a=rsa-sha256; d=r1.example.test; b=AAAA",
    "ARC-Authentication-Results: i=1; mx.r1.example.test; dkim=pass header.d=example.org",
    "From: <a@example.org>",
    "Subject: ARC cv",
  ].join("\n");
  const { fields, hadBody } = splitHeaders(raw);
  const a = analyzeHeaders(fields, hadBody);
  assert.equal(a.arcStructure, "inconsistent");
  assert.deepEqual(a.arcIssues, [{ kind: "cv", i: 2, cv: "none", expected: "pass" }]);
  const good = splitHeaders(raw.replace("i=2; a=rsa-sha256; d=r2.example.test; cv=none", "i=2; a=rsa-sha256; d=r2.example.test; cv=pass"));
  assert.equal(analyzeHeaders(good.fields, good.hadBody).arcStructure, "consistent");
});
