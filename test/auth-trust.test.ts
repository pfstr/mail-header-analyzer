/**
 * F-04 (TS-2.B1 und TS-2.B3): Prüfergebnisse gelten nur als plausibel, wenn die
 * authserv-id einer Station der Zustellkette entspricht (RFC 8601 §5).
 * Eine vorangestellte Zeile fremder Herkunft darf nie als bestätigt gelten.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { analyzeHeaders, classifyAuthTrust, splitHeaders } from "../src/parse.ts";

const analyzeFixture = (name: string) => {
  const raw = readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8");
  const { fields, hadBody } = splitHeaders(raw);
  return analyzeHeaders(fields, hadBody);
};

test("F-04: erfundene authserv-id gilt nicht als bestaetigt", () => {
  const a = analyzeFixture("f04-authresults-gefaelscht.eml");
  assert.equal(a.authTrust, "unmatched");
  assert.equal(a.deliveredBy, "mx.empfang.invalid");
  assert.deepEqual(a.byHosts, ["mx.empfang.invalid"]);
  assert.equal(a.authoritative?.authserv, "mx.bank.example");
  // Die Ergebnisse bleiben sichtbar, aber sie sind ausdruecklich unbelegt.
  assert.equal(a.summary.dmarc?.result, "pass");
  assert.notEqual(a.authTrust, "matched");
});

test("F-04: die belegte Zeile schlaegt die vorangestellte Faelschung", () => {
  const a = analyzeFixture("f04-authresults-gefaelscht-plus-echt.eml");
  assert.equal(a.authTrust, "matched");
  assert.equal(a.authoritative?.authserv, "mx.empfang.invalid");
  assert.equal(a.summary.spf?.result, "fail");
  assert.equal(a.summary.dmarc?.result, "fail");
  assert.equal(a.authMixedOrigins, true, "zwei Herkuenfte muessen gemeldet werden");
});

test("F-04: passende authserv-id gilt als plausibel (matched, nicht trusted)", () => {
  const a = analyzeFixture("f04-authresults-echt.eml");
  assert.equal(a.authTrust, "matched");
  assert.equal(a.authMixedOrigins, false);
  assert.equal(a.summary.dmarc?.result, "pass");
});

test("F-04: fehlende authserv-id ist weder belegt noch verdaechtig", () => {
  const a = analyzeFixture("baseline-m365.eml");
  assert.equal(a.authTrust, "absent");
  assert.equal(a.authMixedOrigins, false);
});

test("F-04 (TS-2.B3): Received-SPF ohne Pruefzeile wird als nicht zuordenbar gefuehrt", () => {
  const a = analyzeFixture("f04-received-spf-ohne-auth.eml");
  assert.equal(a.spfFromReceivedSpf, true);
  assert.equal(a.receivedSpfTrust, "unmatched");
  assert.equal(a.summary.spf?.result, "pass");
  assert.equal(a.authTrust, "none");
});

test("F-04: Herkunftspruefung vergleicht Hosts an der Punktgrenze", () => {
  const chain = ["mx.empfang.invalid", "relay.example.test"];
  assert.equal(classifyAuthTrust("mx.empfang.invalid", chain), "matched");
  assert.equal(classifyAuthTrust("empfang.invalid", chain), "matched");
  assert.equal(classifyAuthTrust("spam.mx.empfang.invalid", chain), "matched");
  assert.equal(classifyAuthTrust("mx.bank.example", chain), "unmatched");
  assert.equal(classifyAuthTrust("boesempfang.invalid", chain), "unmatched");
  assert.equal(classifyAuthTrust(null, chain), "absent");
  assert.equal(classifyAuthTrust("mx.empfang.invalid", []), "unmatched");
});
