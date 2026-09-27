/**
 * W1A-01 und W1A-02: der `d=`-Wert einer DKIM-Signatur bestimmt der Absender.
 * Er darf weder in ein zur Laufzeit gebautes Muster fliessen noch per
 * Teilstring auf die versiegelten ARC-Ergebnisse passen.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  analyzeHeaders, arcAttestsDkim, hostMatches, normDomain, sameDomain, splitHeaders,
} from "../src/parse.ts";

const analyzeFixture = (name: string) => {
  const raw = readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8");
  const { fields, hadBody } = splitHeaders(raw);
  return analyzeHeaders(fields, hadBody);
};

/** Zeugensuche wie in der Flussgrafik: alle ARC-Instanzen für eine Signatur. */
const witnesses = (name: string) => {
  const a = analyzeFixture(name);
  const d = a.dkimSigs[0]?.tags.d ?? null;
  return a.arc.filter((inst) => arcAttestsDkim(inst, d));
};

test("W1A-01: praeparierter d-Wert kostet keine Rechenzeit (kein dynamisches Muster)", () => {
  const started = performance.now();
  const found = witnesses("w1a01-dkim-d-redos.eml");
  const ms = performance.now() - started;
  assert.equal(found.length, 0, "der Fuelltext ist kein Zeuge fuer d=(a+)+$");
  // Vor der Behebung: 8475 ms fuer genau diesen Header. Die Schwelle ist
  // bewusst grosszuegig, sie schlaegt nur bei einem echten Rueckfall an.
  assert.ok(ms < 250, `Auswertung dauerte ${ms.toFixed(1)} ms`);
});

test("W1A-01: Metazeichen im d-Wert werfen keine Ausnahme", () => {
  for (const d of ["(", "[", "\\", "a{2,1}", "(?<", "*", "+", "(a+)+$"]) {
    assert.doesNotThrow(() => arcAttestsDkim(
      { i: 1, sealDomain: "relay.example.test", cv: "none", aar: null, aarMethods: [] }, d));
  }
  // Und ueber den echten Parser, inklusive Analyse des ganzen Headers.
  assert.doesNotThrow(() => witnesses("w1a01-dkim-d-syntax.eml"));
});

test("W1A-01: Regex-Metazeichen erzeugen keinen falschen Zeugen", () => {
  const inst = {
    i: 1, sealDomain: "relay.example.test", cv: "none",
    aar: "mx.relay.example.test; dkim=pass header.d=voellig-fremd.example",
    aarMethods: [{
      method: "dkim", result: "pass",
      props: { "header.d": "voellig-fremd.example" }, comments: [],
    }],
  };
  assert.equal(arcAttestsDkim(inst, ".*"), false);
  assert.equal(arcAttestsDkim(inst, "[a-z-]+\\.example"), false);
  assert.equal(arcAttestsDkim(inst, "voellig-fremd.example"), true);
});

test("W1A-02: Teilstring-Treffer gelten nicht als Zeuge", () => {
  assert.deepEqual(witnesses("w1a02-arc-witness-substring.eml"), []);
  assert.equal(sameDomain("bank.example", "evil-bank.example"), false);
  assert.equal(sameDomain("bank.example", "bank.example.evil.test"), false);
  assert.equal(sameDomain("bank.example", "xxbank.exampleyy"), false);
});

test("W1A-02: identische Domain gilt als Zeuge, unabhaengig von Schreibweise und Endpunkt", () => {
  const found = witnesses("w1a02-arc-witness-echt.eml");
  assert.equal(found.length, 1);
  assert.equal(found[0].sealDomain, "relay1.example.test");
  assert.equal(sameDomain("bank.example", "BANK.example."), true);
  assert.equal(normDomain(" <Bank.Example.> "), "bank.example");
});

test("W1A-02: dkim=fail in einer ARC-Instanz bezeugt nichts", () => {
  const inst = {
    i: 1, sealDomain: "relay.example.test", cv: "none", aar: null,
    aarMethods: [{ method: "dkim", result: "fail", props: { "header.d": "bank.example" }, comments: [] }],
  };
  assert.equal(arcAttestsDkim(inst, "bank.example"), false);
});

test("W1A-02: Hostvergleich nur an der Punktgrenze", () => {
  assert.equal(hostMatches("mx.bank.example", "bank.example"), true);
  assert.equal(hostMatches("bank.example", "mx.bank.example"), true);
  assert.equal(hostMatches("evil-bank.example", "bank.example"), false);
  assert.equal(hostMatches("bank.exampleyy", "bank.example"), false);
  assert.equal(hostMatches(null, "bank.example"), false);
});
