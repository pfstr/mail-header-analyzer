/**
 * W1A-03 und W1A-04: Rechenaufwand und Grenzen. Die fünf quadratischen
 * Stellen laufen linear, die Zahl der Stationen ist gedeckelt.
 *
 * Gemessen wird gegen eine grosszügige Schwelle: die alten Fassungen lagen
 * bei denselben Eingaben zwischen 5,5 und 8,6 Sekunden, ein Rückfall fällt
 * also auch auf langsamer Hardware sofort auf.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  analyzeHeaders, MAX_HOPS, parseAddr, parseForefront, rspamdSymbols,
  spamAssassinTests, splitHeaders, trimEndChars,
} from "../src/parse.ts";

const SCHWELLE_MS = 250;
const dauer = (fn: () => unknown) => {
  const t = performance.now();
  fn();
  return performance.now() - t;
};

test("W1A-03: alle fuenf Stellen bleiben bei 100 000 Zeichen unter der Schwelle", () => {
  const faelle: Array<[string, () => unknown]> = [
    ["R-1 parseAddr", () => parseAddr("<" + "@".repeat(100_000))],
    ["R-2 Domain-Trim", () => trimEndChars("a@" + ";".repeat(100_000) + "x>", ">;,")],
    ["R-8 Forefront", () => parseForefront("A".repeat(100_000))],
    ["R-5 SpamAssassin", () => spamAssassinTests("tests=" + " ".repeat(100_000) + "x")],
    ["R-6 rspamd", () => rspamdSymbols("A".repeat(100_000))],
  ];
  for (const [name, fn] of faelle) {
    const ms = dauer(fn);
    assert.ok(ms < SCHWELLE_MS, `${name} brauchte ${ms.toFixed(1)} ms`);
  }
});

test("W1A-03: der Aufwand waechst linear, nicht quadratisch", () => {
  // Kleinster Wert aus mehreren Läufen: eine einzelne Messung im
  // Zehntelmillisekunden-Bereich kippt schon durch eine GC-Pause.
  const messe = (n: number) => {
    const eingabe = "<" + "@".repeat(n);
    return Math.min(...Array.from({ length: 7 }, () => dauer(() => parseAddr(eingabe))));
  };
  messe(50_000); // aufwaermen
  const klein = Math.max(messe(50_000), 0.05);
  const gross = messe(200_000);
  // Vierfache Eingabe darf hoechstens etwa vierfache Zeit kosten; quadratisch
  // waere der Faktor 16 und mehr.
  assert.ok(gross / klein < 12, `Faktor ${(gross / klein).toFixed(1)} bei vierfacher Eingabe`);
});

test("W1A-03: die entschaerften Muster werten weiterhin richtig aus", () => {
  const a = parseAddr('"Beispiel Newsletter" <news@example.org>');
  assert.equal(a.addr, "news@example.org");
  assert.equal(a.domain, "example.org");
  assert.equal(a.name, "Beispiel Newsletter");
  assert.equal(parseAddr("bounce@example.org").domain, "example.org");
  assert.equal(parseAddr("<a@example.org>;").domain, "example.org");

  assert.equal(trimEndChars("example.org>;,", ">;,"), "example.org");
  assert.equal(trimEndChars("example.org", ">;,"), "example.org");
  assert.equal(trimEndChars(">>>", ">;,"), "");

  // Ohne Prototyp angelegt, damit Schluessel wie "constructor" nichts erben.
  assert.equal(Object.getPrototypeOf(parseForefront("A:1")), null);
  assert.deepEqual({ ...parseForefront("CIP:203.0.113.25;CTRY:CH;LANG:de;SCL:1;SRV:;IPV:NLI;") },
    { CIP: "203.0.113.25", CTRY: "CH", LANG: "de", SCL: "1", SRV: "", IPV: "NLI" });
  assert.deepEqual({ ...parseForefront("kein Doppelpunkt") }, {});

  assert.deepEqual(
    spamAssassinTests("Yes, score=6.1 required=5.0 tests=BAYES_99,HTML_MESSAGE,URIBL_BLACK autolearn=no version=3.4.6"),
    ["BAYES_99", "HTML_MESSAGE", "URIBL_BLACK"]);
  assert.deepEqual(spamAssassinTests("No, score=-1.0 required=5.0"), []);

  assert.deepEqual(rspamdSymbols("default: False [-1.20 / 15.00]; BAYES_HAM(-3.00); MIME_GOOD(-0.10); R_SPF_ALLOW(-0.20)"),
    [{ name: "BAYES_HAM", score: "-3.00" }, { name: "MIME_GOOD", score: "-0.10" },
     { name: "R_SPF_ALLOW", score: "-0.20" }]);
  assert.deepEqual(rspamdSymbols("KEINE SYMBOLE HIER"), []);
});

test("W1A-04: die Zahl der Stationen ist gedeckelt", () => {
  const zeile = (i: number) =>
    `Received: from a${i}.example.test (a${i}.example.test [203.0.113.9]) by b${i}.example.invalid; Mon, 3 Aug 2026 09:00:00 +0000`;
  const raw = [...Array(1000)].map((_, i) => zeile(i)).join("\n")
    + "\nFrom: <absender@example.com>\nSubject: W1A-04\n";
  const { fields, hadBody } = splitHeaders(raw);
  const a = analyzeHeaders(fields, hadBody);
  assert.equal(a.hops.length, MAX_HOPS);
  assert.equal(a.hopOverflow, 1000 - MAX_HOPS);
  // Ausgewertet werden die juengsten Zeilen, also die oberen im Header.
  assert.equal(a.hops[a.hops.length - 1].byHost, "b0.example.invalid");
});

test("W1A-04: die Obergrenze liegt weit unter der Spread-Grenze von V8", () => {
  // Math.max(1, ...hops) wirft ab etwa 150 000 Argumenten einen RangeError.
  assert.ok(MAX_HOPS <= 1000, `MAX_HOPS ist ${MAX_HOPS}`);
  const gross = [...Array(MAX_HOPS)].map((_, i) => i);
  assert.doesNotThrow(() => Math.max(1, ...gross));
});

test("W1A-04: eine sehr grosse Kette bricht die Auswertung nicht ab", () => {
  const raw = [...Array(20_000)].map((_, i) =>
    `Received: from a${i}.example.test by b${i}.example.invalid; Mon, 3 Aug 2026 09:00:00 +0000`).join("\n")
    + "\nFrom: <absender@example.com>\n";
  const { fields, hadBody } = splitHeaders(raw);
  const ms = dauer(() => {
    const a = analyzeHeaders(fields, hadBody);
    assert.equal(a.hops.length, MAX_HOPS);
  });
  assert.ok(ms < 2000, `Auswertung dauerte ${ms.toFixed(0)} ms`);
});
