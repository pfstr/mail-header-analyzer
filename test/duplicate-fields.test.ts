/**
 * F-05 (TS-2.B4): Mehrere From-, Reply-To- oder Return-Path-Zeilen sind ein
 * RFC-5322-Verstoss und ein klassisches Spoofing-Muster. Die stille Auswahl
 * der ersten Zeile darf nicht unkommentiert bleiben.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { analyzeHeaders, splitHeaders } from "../src/parse.ts";

const analyzeFixture = (name: string) => {
  const raw = readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8");
  const { fields, hadBody } = splitHeaders(raw);
  return analyzeHeaders(fields, hadBody);
};

test("F-05: doppelte Absenderzeilen werden mit allen Werten gemeldet", () => {
  const a = analyzeFixture("f05-doppelte-absenderzeilen.eml");
  const names = a.duplicates.map((d) => d.name);
  assert.deepEqual(names, ["From", "Reply-To", "Return-Path"]);

  const from = a.duplicates.find((d) => d.name === "From")!;
  assert.equal(from.values.length, 2);
  assert.deepEqual(from.values, [
    '"security@bank.example" <angreifer@evil.invalid>',
    "<zweiter-absender@evil2.invalid>",
  ]);
  // Ausgewertet wird weiterhin die erste Zeile, das muss nachvollziehbar sein.
  assert.equal(a.from?.addr, "angreifer@evil.invalid");
});

test("F-05: einfache Kopfzeilen erzeugen keine Meldung", () => {
  assert.deepEqual(analyzeFixture("baseline-m365.eml").duplicates, []);
});

test("F-05: die Pruefung deckt alle Einzelfelder aus RFC 5322 Abschnitt 3.6 ab", () => {
  const raw = [
    "Received: from a.example.test by mx.empfang.invalid; Tue, 04 Aug 2026 11:00:00 +0200",
    "Subject: erster Betreff",
    "Subject: zweiter Betreff",
    "Date: Tue, 4 Aug 2026 11:00:00 +0200",
    "Date: Wed, 5 Aug 2026 11:00:00 +0200",
    "Message-ID: <eins@example.test>",
    "Message-ID: <zwei@example.test>",
    "From: <a@example.test>",
    "",
  ].join("\n");
  const { fields, hadBody } = splitHeaders(raw);
  const a = analyzeHeaders(fields, hadBody);
  assert.deepEqual(a.duplicates.map((d) => d.name), ["Subject", "Date", "Message-ID"]);
  // Received darf nicht als Verstoss gelten, es ist ein Trace-Feld.
  assert.equal(a.duplicates.some((d) => d.name === "Received"), false);
});
