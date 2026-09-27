/**
 * mail-header-analyzer: Einstiegspunkt der Bibliothek.
 *
 * `analyze()` liefert die vollständige Auswertung, `summarize()` eine
 * kompakte, JSON-taugliche Zusammenfassung mit Befunden.
 */
import { analyzeHeaders, splitHeaders, type Analysis, type AnalyzeOptions } from "./parse.ts";

export * from "./parse.ts";
export { detectProvider } from "./providers.ts";

/**
 * Rohen Header-Text (oder eine ganze .eml-Datei) zerlegen und auswerten.
 * `trustedAuthServIds`: authserv-ids des eigenen Eingangs-Gateways; nur deren
 * Authentication-Results gelten als belegt.
 */
export function analyze(raw: string, opts: AnalyzeOptions = {}): Analysis {
  const { fields, hadBody } = splitHeaders(raw);
  return analyzeHeaders(fields, hadBody, opts);
}

export type FindingCode =
  | "bidi-controls"
  | "duplicate-singleton-field"
  | "auth-results-unverified"
  | "auth-results-plausible-only"
  | "auth-results-not-trusted"
  | "auth-results-trusted-conflict"
  | "arc-structure-inconsistent"
  | "auth-results-mixed-origins"
  | "received-spf-unverified"
  | "clock-skew"
  | "hop-limit-exceeded"
  | "reply-to-differs"
  | "dmarc-not-pass";

export type Finding = { code: FindingCode; detail: string };

export type Summary = {
  from: string | null;
  replyTo: string | null;
  returnPath: string | null;
  subject: string | null;
  date: string | null;
  messageId: string | null;
  deliveredBy: string | null;
  totalSeconds: number | null;
  auth: {
    spf: string | null;
    dkim: string | null;
    dmarc: string | null;
    arc: string | null;
    compauth: string | null;
    source: "trusted" | "matched" | "unmatched" | "absent" | "none";
  };
  /** Nur der Aufbau der ARC-Kette, keine Signaturprüfung. */
  arcStructure: "consistent" | "inconsistent" | null;
  hops: Array<{
    n: number;
    from: string | null;
    ip: string | null;
    by: string | null;
    protocol: string | null;
    tls: string | null;
    date: string | null;
    delaySeconds: number | null;
    provider: string | null;
    attested: boolean;
  }>;
  findings: Finding[];
};

const iso = (d: Date | null) => (d ? d.toISOString() : null);

/** Kompakte Zusammenfassung einer Auswertung, geeignet für JSON-Ausgabe. */
export function summarize(a: Analysis): Summary {
  const findings: Finding[] = [];
  if (a.bidiFields.length) {
    findings.push({ code: "bidi-controls", detail: `Unicode direction controls in: ${a.bidiFields.join(", ")}` });
  }
  for (const d of a.duplicates) {
    findings.push({ code: "duplicate-singleton-field", detail: `${d.name} appears ${d.values.length} times` });
  }
  if (a.authTrust === "unmatched") {
    findings.push({
      code: "auth-results-unverified",
      detail: `authserv-id ${a.authoritative?.authserv ?? "?"} does not match any receiving host`,
    });
  }
  if (a.authTrust === "matched" && !a.trustedIds.length) {
    findings.push({
      code: "auth-results-plausible-only",
      detail: "authserv-id matches a Received host, but Received fields can be forged; pass trustedAuthServIds to verify",
    });
  }
  if (a.trustedIds.length && a.authTrust !== "trusted") {
    findings.push({ code: "auth-results-not-trusted", detail: `No Authentication-Results from ${a.trustedIds.join(", ")}` });
  }
  if (a.trustedConflicts.length) {
    findings.push({
      code: "auth-results-trusted-conflict",
      detail: `Conflicting results with a trusted authserv-id for: ${a.trustedConflicts.join(", ")}`,
    });
  }
  if (a.arcStructure === "inconsistent") {
    findings.push({ code: "arc-structure-inconsistent", detail: `${a.arcIssues.length} structural ARC issue(s)` });
  }
  if (a.authMixedOrigins) {
    findings.push({ code: "auth-results-mixed-origins", detail: "Authentication-Results from several systems" });
  }
  if (a.spfFromReceivedSpf && a.receivedSpfTrust === "unmatched") {
    findings.push({ code: "received-spf-unverified", detail: "SPF result only from an unverified Received-SPF field" });
  }
  if (a.hasSkew) findings.push({ code: "clock-skew", detail: "Negative delay between hops" });
  if (a.hopOverflow > 0) {
    findings.push({ code: "hop-limit-exceeded", detail: `${a.hopOverflow} Received fields beyond the limit were ignored` });
  }
  if (a.from?.domain && a.replyTo?.domain && a.from.domain !== a.replyTo.domain) {
    findings.push({ code: "reply-to-differs", detail: `Reply-To domain ${a.replyTo.domain} differs from From domain ${a.from.domain}` });
  }
  const dmarc = a.summary.dmarc?.result ?? null;
  if (dmarc && dmarc !== "pass" && dmarc !== "bestguesspass") {
    findings.push({ code: "dmarc-not-pass", detail: `dmarc=${dmarc}` });
  }

  return {
    from: a.from?.display ?? null,
    replyTo: a.replyTo?.display ?? null,
    returnPath: a.returnPath?.display ?? null,
    subject: a.subject,
    date: iso(a.date),
    messageId: a.messageId,
    deliveredBy: a.deliveredBy,
    totalSeconds: a.totalSec,
    auth: {
      spf: a.summary.spf?.result ?? null,
      dkim: a.summary.dkim?.result ?? null,
      dmarc,
      arc: a.summary.arc?.result ?? null,
      compauth: a.summary.compauth?.result ?? null,
      source: a.authTrust,
    },
    arcStructure: a.arcStructure,
    hops: a.hops.map((h) => ({
      n: h.n,
      from: h.rdns ?? h.fromHost,
      ip: h.ip,
      by: h.byHost,
      protocol: h.proto,
      tls: h.tlsVersion,
      date: iso(h.date),
      delaySeconds: h.delaySec,
      provider: h.provider,
      attested: h.attested,
    })),
    findings,
  };
}
