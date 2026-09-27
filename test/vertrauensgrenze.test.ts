/**
 * F-08 (TS-2.B2): In der Received-Kette ist allein die oberste Zeile vom
 * empfangenden System geschrieben. Alle darunter liegenden Stationen sind
 * Behauptung des Absenders und dürfen nicht gleichwertig erscheinen.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { analyzeHeaders, attestedNodeIndex, splitHeaders } from "../src/parse.ts";

const analyzeFixture = (name: string) => {
  const raw = readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8");
  const { fields, hadBody } = splitHeaders(raw);
  return analyzeHeaders(fields, hadBody);
};

test("F-08: nur die letzte Station ist bezeugt", () => {
  const a = analyzeFixture("f08-gefaelschte-hops.eml");
  assert.equal(a.hops.length, 3);
  assert.deepEqual(a.hops.map((h) => h.attested), [false, false, true]);
  // Bezeugt ist die Zeile, die der zustellende Server geschrieben hat.
  assert.equal(a.hops[2].byHost, "mx.empfang.invalid");
  assert.equal(a.deliveredBy, "mx.empfang.invalid");
  // Die erfundenen Stationen bleiben sichtbar, aber eben nicht bezeugt.
  assert.equal(a.hops[0].byHost, "mail.bank.example");
  assert.equal(a.hops[0].attested, false);
});

test("F-08: die Grenze liegt in der Grafik vor dem letzten Abschnitt", () => {
  // Knotenliste ist [Absender, by je Hop]: bei 3 Hops also 4 Knoten,
  // bezeugt sind die Knoten 2 und 3.
  assert.equal(attestedNodeIndex(3), 2);
  assert.equal(attestedNodeIndex(2), 1);
  // Bei einer einzigen Station gibt es nichts abzugrenzen.
  assert.equal(attestedNodeIndex(1), 0);
  assert.equal(attestedNodeIndex(0), -1);
});

test("F-08: bei genau einer Station ist diese bezeugt", () => {
  const raw = [
    "Received: from a.example.test (a.example.test [203.0.113.9]) by mx.empfang.invalid; Tue, 04 Aug 2026 11:00:00 +0200",
    "From: <absender@example.test>",
    "Subject: F-08 eine Station",
    "",
  ].join("\n");
  const { fields, hadBody } = splitHeaders(raw);
  const a = analyzeHeaders(fields, hadBody);
  assert.deepEqual(a.hops.map((h) => h.attested), [true]);
});

test("F-08: der Beispiel-Header markiert genau eine bezeugte Station", () => {
  const a = analyzeFixture("baseline-m365.eml");
  assert.equal(a.hops.filter((h) => h.attested).length, 1);
  assert.equal(a.hops[a.hops.length - 1].attested, true);
});
