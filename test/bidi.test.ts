/**
 * F-06 (TS-2.B6): Unicode-Richtungssteuerung kehrt die Darstellung um.
 * Ein Werkzeug zur Phishing-Analyse muss den Trick zeigen, nicht ausführen.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  analyzeHeaders, hasBidiControls, splitHeaders, visibleControls,
} from "../src/parse.ts";

// Nicht als Literal: das Zeichen wuerde diese Quelldatei umsortieren.
const RLO = String.fromCodePoint(0x202e);

const analyzeFixture = (name: string) => {
  const raw = readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8");
  const { fields, hadBody } = splitHeaders(raw);
  return analyzeHeaders(fields, hadBody);
};

test("F-06: Steuerzeichen werden als Codepunkt sichtbar gemacht", () => {
  assert.equal(visibleControls(`Rechnung ${RLO}fdp.exe`), "Rechnung <U+202E>fdp.exe");
  assert.equal(visibleControls("Rechnung fdp.exe"), "Rechnung fdp.exe");
  for (const cp of [0x200e, 0x200f, 0x061c, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
    0x2066, 0x2067, 0x2068, 0x2069]) {
    const ch = String.fromCodePoint(cp);
    assert.equal(hasBidiControls(`a${ch}b`), true, `U+${cp.toString(16)} muss erkannt werden`);
    assert.equal(visibleControls(`a${ch}b`).includes(ch), false,
      `U+${cp.toString(16)} darf nicht unveraendert durchgereicht werden`);
  }
});

test("F-06: harmlose Texte bleiben unveraendert", () => {
  const plain = "Rechnung 2026-08 für Beispiel AG (Nr. 4711) – 100 €";
  assert.equal(visibleControls(plain), plain);
  assert.equal(hasBidiControls(plain), false);
  assert.equal(hasBidiControls(null), false);
});

test("F-06: betroffene Kopfzeilen werden benannt", () => {
  const a = analyzeFixture("f06-bidi-rlo.eml");
  assert.deepEqual(a.bidiFields, ["Subject", "Reply-To"]);
  // Der Betreff selbst bleibt roh in der Analyse; sichtbar gemacht wird er
  // erst bei der Ausgabe, damit der Befund als solcher erkennbar bleibt.
  assert.equal(hasBidiControls(a.subject), true);
  assert.equal(visibleControls(a.subject ?? ""), "Rechnung <U+202E>fdp.exe F-06");
});

test("F-06: unauffaelliger Header meldet keine Steuerzeichen", () => {
  assert.deepEqual(analyzeFixture("baseline-m365.eml").bidiFields, []);
});
