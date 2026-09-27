/**
 * Öffentliche API: analyze() und summarize() inklusive Befund-Codes.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { analyze, summarize } from "../src/index.ts";

const fixture = (name: string) =>
  readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8");

test("analyze() entspricht splitHeaders + analyzeHeaders", () => {
  const a = analyze(fixture("baseline-m365.eml"));
  assert.equal(a.hops.length, 3);
  assert.equal(a.from?.domain, "example.org");
});

test("summarize() ist JSON-serialisierbar und ohne Befunde beim Normalfall", () => {
  const s = summarize(analyze(fixture("baseline-m365.eml")));
  assert.deepEqual(JSON.parse(JSON.stringify(s)), s);
  assert.equal(s.hops.length, 3);
  assert.equal(s.hops[2].attested, true);
  assert.deepEqual(s.findings.filter((f) => f.code === "bidi-controls" || f.code === "duplicate-singleton-field"), []);
});

test("summarize() meldet Bidi-Steuerzeichen", () => {
  const s = summarize(analyze(fixture("f06-bidi-rlo.eml")));
  assert.ok(s.findings.some((f) => f.code === "bidi-controls"));
});

test("summarize() meldet doppelte Absenderzeilen", () => {
  const s = summarize(analyze(fixture("f05-doppelte-absenderzeilen.eml")));
  assert.ok(s.findings.some((f) => f.code === "duplicate-singleton-field"));
});

test("summarize() meldet gefälschte Authentication-Results", () => {
  const s = summarize(analyze(fixture("f04-authresults-gefaelscht.eml")));
  assert.ok(s.findings.some((f) => f.code === "auth-results-unverified"));
});

test("summarize() mit trustedAuthServIds: belegte Quelle und Widerspruch", () => {
  const ok = summarize(analyze(fixture("f04-authresults-echt.eml"), { trustedAuthServIds: ["mx.empfang.invalid"] }));
  assert.equal(ok.auth.source, "trusted");
  const miss = summarize(analyze(fixture("f04-authresults-echt.eml"), { trustedAuthServIds: ["empfang.invalid"] }));
  assert.ok(miss.findings.some((f) => f.code === "auth-results-not-trusted"));
  const plausible = summarize(analyze(fixture("f09-received-und-authresults-gefaelscht.eml")));
  assert.ok(plausible.findings.some((f) => f.code === "auth-results-plausible-only"));
});
