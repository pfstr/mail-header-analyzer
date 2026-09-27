/**
 * W1A-10 (TS-2.C): Ein Byte Order Mark vor dem ersten Feldnamen darf keine
 * Kopfzeile kosten. Exporte aus Windows-Werkzeugen tragen ihn regelmässig.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { analyzeHeaders, splitHeaders } from "../src/parse.ts";

const BOM = String.fromCharCode(0xfeff);
const fixture = (name: string) =>
  readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8");

test("W1A-10: das Fixture traegt wirklich ein BOM", () => {
  assert.equal(fixture("w1a10-bom.eml").startsWith(BOM), true);
});

test("W1A-10: mit BOM bleibt das erste Feld erhalten", () => {
  const mitBom = fixture("w1a10-bom.eml");
  const ohneBom = mitBom.slice(1);

  const a = splitHeaders(mitBom);
  const b = splitHeaders(ohneBom);
  assert.deepEqual(a.fields.map((f) => f.name), b.fields.map((f) => f.name));
  assert.equal(a.fields.length, 5);
  assert.equal(a.fields[0].name, "Received");

  const ana = analyzeHeaders(a.fields, a.hadBody);
  assert.equal(ana.hops.length, 2, "beide Stationen muessen erhalten bleiben");
  assert.equal(ana.deliveredBy, "mx.empfang.invalid");
});

test("W1A-10: ein BOM mitten im Text bleibt unangetastet", () => {
  const { fields } = splitHeaders(`Subject: a${BOM}b\nFrom: <x@example.test>\nTo: <y@example.test>\n`);
  assert.equal(fields.length, 3);
  assert.equal(fields[0].value, `a${BOM}b`);
});

test("W1A-10: Zeilenenden bleiben untereinander gleichwertig", () => {
  const roh = "Received: from a.example.test by mx.empfang.invalid; Tue, 04 Aug 2026 11:00:00 +0200|From: <x@example.test>|Subject: Zeilenenden|";
  const namen = (sep: string) => splitHeaders(roh.split("|").join(sep)).fields.map((f) => f.name);
  assert.deepEqual(namen("\n"), ["Received", "From", "Subject"]);
  assert.deepEqual(namen("\r\n"), ["Received", "From", "Subject"]);
  assert.deepEqual(namen("\r"), ["Received", "From", "Subject"]);
  assert.deepEqual(splitHeaders(BOM + roh.split("|").join("\r\n")).fields.map((f) => f.name),
    ["Received", "From", "Subject"]);
});
