/**
 * Grundzüge des Header-Parsers. Belegt zugleich, dass die reine Logik ohne
 * DOM importierbar ist (Voraussetzung für alle weiteren Suiten).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { analyzeHeaders, orgDomain, align, splitHeaders } from "../src/parse.ts";

const fixture = (name: string) =>
  readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8");

export const analyzeFixture = (name: string) => {
  const { fields, hadBody } = splitHeaders(fixture(name));
  return analyzeHeaders(fields, hadBody);
};

test("Parser laeuft ohne DOM und zerlegt den Beispiel-Header", () => {
  const a = analyzeFixture("baseline-m365.eml");
  assert.equal(a.fields.length, 15);
  assert.equal(a.hops.length, 3);
  assert.equal(a.hops[0].fromHost, "client.example.net");
  assert.equal(a.hops[2].byHost, "ZR0P278MB0570.CHEP278.PROD.OUTLOOK.COM");
  assert.equal(a.from?.domain, "example.org");
  assert.equal(a.subject, "Service-Report für März");
  assert.equal(a.summary.spf?.result, "pass");
  assert.equal(a.summary.dkim?.result, "pass");
  assert.equal(a.summary.dmarc?.result, "pass");
  assert.equal(a.dkimSigs.length, 1);
  assert.equal(a.dkimSigs[0].receiverResult, "pass");
  assert.equal(a.mailFromDomain, "example.org");
});

test("Organisations-Domain und Alignment", () => {
  assert.equal(orgDomain("mx.eur02.prod.example.com"), "example.com");
  assert.equal(orgDomain("a.b.example.co.uk"), "example.co.uk");
  assert.equal(align("example.com", "example.com"), "strict");
  assert.equal(align("example.com", "mail.example.com"), "relaxed");
  assert.equal(align("example.com", "example.invalid"), "none");
});
