/**
 * Reine Auswertungslogik: Zerlegung, Normalisierung, Bewertung. Kein
 * DOM-Zugriff, keine Netzwerkanfrage; läuft unverändert in Node und im Browser.
 *
 * Dieselbe Logik steckt im Web-Tool https://rafaelpfister.ch/tools/header-analyzer
 */
import { detectProvider } from "./providers.ts";

// ---------------------------------------------------------------------------
// RFC 2047: encoded-words in Betreff-/Adresszeilen dekodieren
// ---------------------------------------------------------------------------
export function b64bytes(s: string): Uint8Array {
  const bin = atob(s.replace(/\s+/g, ""));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function qpBytes(s: string): Uint8Array {
  const out: number[] = [];
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === "_") { out.push(0x20); continue; }
    if (ch === "=" && i + 2 < s.length && /^[0-9a-f]{2}$/i.test(s.slice(i + 1, i + 3))) {
      out.push(parseInt(s.slice(i + 1, i + 3), 16));
      i += 2;
      continue;
    }
    out.push(ch.charCodeAt(0) & 0xff);
  }
  return new Uint8Array(out);
}

export function decodeWords(s: string): string {
  // Aufeinanderfolgende encoded-words: der Whitespace dazwischen entfällt (RFC 2047 §6.2).
  const joined = s.replace(/(=\?[^?\s]+\?[BbQq]\?[^?]*\?=)\s+(?==\?)/g, "$1");
  return joined.replace(/=\?([^?\s]+)\?([BbQq])\?([^?]*)\?=/g, (m, cs: string, enc: string, data: string) => {
    try {
      const bytes = enc.toUpperCase() === "B" ? b64bytes(data) : qpBytes(data);
      // RFC 2231 erlaubt einen Sprach-Suffix am Charset ("utf-8*de").
      return new TextDecoder(cs.replace(/\*.*$/, "")).decode(bytes);
    } catch {
      return m;
    }
  });
}

// ---------------------------------------------------------------------------
// Unicode-Richtungssteuerung sichtbar machen
// ---------------------------------------------------------------------------
/**
 * Bidi-Steuerzeichen: LRM/RLM, ALM, die eingebetteten Overrides U+202A bis
 * U+202E und die Isolate U+2066 bis U+2069. `Rechnung <U+202E>fdp.exe`
 * erscheint sonst als `Rechnung exe.pdf`: genau die Täuschung, die dieses
 * Werkzeug aufklären soll (F-06).
 */
// Bewusst als Escape-Folgen: die Zeichen selbst würden diese Quelldatei
// beim Lesen umsortieren (Trojan Source).
const BIDI_RE = /[\u200E\u200F\u061C\u202A-\u202E\u2066-\u2069]/;
const BIDI_RE_G = new RegExp(BIDI_RE.source, "g");

export function hasBidiControls(s: string | null | undefined): boolean {
  return typeof s === "string" && BIDI_RE.test(s);
}

/** Steuerzeichen durch ihre Codepunkt-Schreibweise ersetzen. */
export function visibleControls(s: string): string {
  if (!BIDI_RE.test(s)) return s;
  return s.replace(BIDI_RE_G, (ch) =>
    `<U+${ch.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}>`);
}

// ---------------------------------------------------------------------------
// Header in Felder zerlegen (Unfolding + Toleranz für hart umbrochene Kopien)
// ---------------------------------------------------------------------------
export type HeaderField = { name: string; value: string; raw: string };

export function splitHeaders(input: string): { fields: HeaderField[]; hadBody: boolean } {
  // Byte Order Mark entfernen: Exporte aus Windows-Werkzeugen und Kopien aus
  // Notepad tragen sie regelmässig, und ohne diesen Schnitt scheitert der
  // Feldnamen-Test in der ersten Zeile, die dann ersatzlos entfällt (W1A-10).
  const lines = input.replace(/^\uFEFF/, "").replace(/\r\n?/g, "\n").split("\n");
  const rawFields: string[] = [];
  let cur: string | null = null;
  let hadBody = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim() === "") {
      // Erste Leerzeile nach Feldern trennt Header und Body (.eml eingefügt).
      if (rawFields.length || cur) {
        if (lines.slice(i + 1).some((l) => l.trim() !== "")) hadBody = true;
        break;
      }
      continue;
    }
    if (/^[ \t]/.test(line)) {
      // Klassische Faltung (folding whitespace).
      if (cur !== null) cur += "\n" + line;
      continue;
    }
    if (/^[\x21-\x39\x3B-\x7E]+:/.test(line)) {
      if (cur !== null) rawFields.push(cur);
      cur = line;
      continue;
    }
    // mbox-Trennzeile "From ..." vor dem ersten Feld überspringen.
    if (cur === null) continue;
    // Zeile ohne Feldnamen und ohne führenden Whitespace: hart umbrochene
    // Kopie (z. B. aus einem Mailclient-Dialog) und gehört zum Vorgänger.
    cur += " " + line.trim();
  }
  if (cur !== null) rawFields.push(cur);

  const fields = rawFields.map((raw) => {
    const idx = raw.indexOf(":");
    return {
      name: raw.slice(0, idx).trim(),
      value: raw.slice(idx + 1).replace(/\n[ \t]+/g, " ").trim(),
      raw,
    };
  });
  return { fields, hadBody };
}

export const first = (fields: HeaderField[], name: string) =>
  fields.find((f) => f.name.toLowerCase() === name.toLowerCase());
export const all = (fields: HeaderField[], name: string) =>
  fields.filter((f) => f.name.toLowerCase() === name.toLowerCase());

// ---------------------------------------------------------------------------
// Datum (RFC 5322 date-time inklusive obsoleter Zonenkürzel)
// ---------------------------------------------------------------------------
const OBS_ZONE: Record<string, string> = {
  UT: "+0000", GMT: "+0000", EST: "-0500", EDT: "-0400", CST: "-0600",
  CDT: "-0500", MST: "-0700", MDT: "-0600", PST: "-0800", PDT: "-0700",
};

export function parseMailDate(s: string | undefined): Date | null {
  if (!s) return null;
  let t = s.replace(/\([^()]*\)/g, " ").replace(/\([^()]*\)/g, " ").replace(/\s+/g, " ").trim();
  t = t.replace(/\b(UT|GMT|EST|EDT|CST|CDT|MST|MDT|PST|PDT)\b\s*$/i, (_, z: string) => OBS_ZONE[z.toUpperCase()] ?? "+0000");
  const d = new Date(t);
  if (!isNaN(d.getTime())) return d;
  const m = t.match(/(\d{1,2})\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+(\d{2,4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*([+-]\d{4})?/i);
  if (!m) return null;
  const months = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
  let year = parseInt(m[3], 10);
  if (year < 100) year += year >= 70 ? 1900 : 2000;
  const off = m[7] ?? "+0000";
  const offMin = (off[0] === "-" ? -1 : 1) * (parseInt(off.slice(1, 3), 10) * 60 + parseInt(off.slice(3, 5), 10));
  const utc = Date.UTC(year, months.indexOf(m[2].toLowerCase()), parseInt(m[1], 10),
    parseInt(m[4], 10), parseInt(m[5], 10), parseInt(m[6] ?? "0", 10)) - offMin * 60000;
  return new Date(utc);
}

// ---------------------------------------------------------------------------
// Received-Kette
// ---------------------------------------------------------------------------
type Seg = { kind: "word" | "comment"; text: string };

/** Received-Wert in Wörter und Klammer-Kommentare zerlegen (Klammern können verschachtelt sein). */
export function segments(value: string): Seg[] {
  const segs: Seg[] = [];
  let depth = 0, word = "", comment = "";
  const flush = () => { if (word) { segs.push({ kind: "word", text: word }); word = ""; } };
  for (const ch of value) {
    if (depth === 0) {
      if (ch === "(") { flush(); depth = 1; comment = ""; }
      else if (/\s/.test(ch)) flush();
      else word += ch;
    } else {
      if (ch === "(") { depth++; comment += ch; }
      else if (ch === ")") {
        depth--;
        if (depth === 0) segs.push({ kind: "comment", text: comment.replace(/\s+/g, " ").trim() });
        else comment += ch;
      } else comment += ch;
    }
  }
  flush();
  if (depth > 0 && comment.trim()) segs.push({ kind: "comment", text: comment.replace(/\s+/g, " ").trim() });
  return segs;
}

/** Position des letzten Semikolons ausserhalb von Klammern (Datums-Separator). */
export function lastTopSemicolon(s: string): number {
  let depth = 0;
  for (let i = s.length - 1; i >= 0; i--) {
    const ch = s[i];
    if (ch === ")") depth++;
    else if (ch === "(") depth = Math.max(0, depth - 1);
    else if (ch === ";" && depth === 0) return i;
  }
  return -1;
}

export type Hop = {
  n: number;
  fromHost: string | null;
  helo: string | null;
  rdns: string | null;
  ip: string | null;
  internal: boolean;
  byHost: string | null;
  software: string | null;
  proto: string | null;
  protoClass: "tlsAuth" | "tls" | "auth" | "plain" | "local" | "http" | "mapi" | null;
  tlsVersion: string | null;
  tlsCipher: string | null;
  id: string | null;
  forAddr: string | null;
  via: string | null;
  date: Date | null;
  delaySec: number | null;
  provider: string | null;
  /**
   * Vom empfangenden System selbst geschrieben. Das trifft nur auf die
   * oberste Received-Zeile zu; alle darunter liegenden standen bereits in
   * der Nachricht und sind unbelegte Behauptung des Absenders (F-08).
   */
  attested: boolean;
  raw: string;
};

/**
 * Erster Knoten der Schnellübersicht, der vom empfangenden System bezeugt
 * ist. Die Knotenliste ist `[Absender, by-Host je Hop]`, also um eins länger
 * als die Hop-Liste; bezeugt sind allein die beiden Enden des letzten
 * Abschnitts.
 */
export function attestedNodeIndex(hopCount: number): number {
  return hopCount >= 1 ? hopCount - 1 : -1;
}

const IP_RE = /\[(?:IPv6:)?([0-9a-fA-F:.]+)\]/;
const V4_RE = /\b((?:\d{1,3}\.){3}\d{1,3})\b/;

export function isPrivateIp(ip: string): boolean {
  const v4 = ip.match(/^(\d+)\.(\d+)\./);
  if (v4) {
    const a = +v4[1], b = +v4[2];
    return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
      (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127);
  }
  const low = ip.toLowerCase();
  return low === "::1" || low.startsWith("fe80:") || low.startsWith("fc") || low.startsWith("fd");
}

export function normTlsVersion(v: string): string {
  return v.replace(/^TLSv?/i, "TLS ").replace(/_/g, ".").replace(/^TLS \./, "TLS 1.").replace(/\s+/g, " ").trim()
    .replace(/^TLS ?1\.?([0-3])$/, "TLS 1.$1");
}

export function parseReceived(value: string, raw: string): Hop {
  const semi = lastTopSemicolon(value);
  const dateRaw = semi >= 0 ? value.slice(semi + 1).trim() : "";
  const rest = semi >= 0 ? value.slice(0, semi) : value;

  const KEYWORDS = new Set(["from", "by", "via", "with", "id", "for"]);
  const groups: Record<string, Seg[]> = {};
  const pre: Seg[] = [];
  let cur: string | null = null;
  for (const seg of segments(rest)) {
    const low = seg.text.toLowerCase();
    if (seg.kind === "word" && KEYWORDS.has(low) && !(cur && groups[cur].length === 0)) {
      cur = low;
      groups[cur] ??= [];
    } else if (cur) {
      groups[cur].push(seg);
    } else {
      pre.push(seg);
    }
  }

  const words = (k: string) => (groups[k] ?? []).filter((s) => s.kind === "word").map((s) => s.text);
  const comments = (k: string) => (groups[k] ?? []).filter((s) => s.kind === "comment").map((s) => s.text);

  const fromHost = words("from")[0] ?? null;
  const fromCmts = comments("from").join(" ");
  const byHost = (words("by")[0] ?? null)?.replace(/\.$/, "") ?? null;
  const software = comments("by").join(" ") || null;
  const proto = words("with").join(" ") || null;
  const id = words("id").join(" ") || null;
  const forAddr = words("for")[0]?.replace(/[<>]/g, "") ?? null;
  const via = words("via").join(" ") || null;

  // IP: bevorzugt aus eckigen Klammern im from-Kommentar, sonst nackte v4,
  // sonst ein IP-Literal als HELO-Name.
  let ip: string | null = fromCmts.match(IP_RE)?.[1] ?? fromCmts.match(V4_RE)?.[1] ?? null;
  if (!ip && fromHost) {
    const lit = fromHost.match(/^\[(?:IPv6:)?([0-9a-fA-F:.]+)\]$/);
    if (lit) ip = lit[1];
    else if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(fromHost)) ip = fromHost;
  }

  // rDNS: erster Hostname im from-Kommentar, der nicht die IP selbst ist.
  let rdns: string | null = null;
  const rd = fromCmts.match(/(?:^|[\s(])([a-z0-9][a-z0-9._-]*\.[a-z][a-z0-9-]*)\.?(?=\s*\[)/i);
  if (rd && rd[1].toLowerCase() !== "unknown") rdns = rd[1].toLowerCase();
  const heloM = fromCmts.match(/\bhelo=([^\s)]+)/i);
  const helo = heloM ? heloM[1] : fromHost;

  // TLS-Angaben aus der ganzen Zeile (Microsoft-, Postfix- und Exim-Schreibweisen).
  const rawOne = raw.replace(/\s+/g, " ");
  let tlsVersion: string | null = null, tlsCipher: string | null = null;
  const msTls = rawOne.match(/version=([A-Za-z0-9_.]+)[,\s)]+cipher=([A-Za-z0-9_-]+)/);
  const pfTls = rawOne.match(/using\s+(TLSv?[0-9._]+)(?:\s+with\s+cipher\s+([A-Z0-9_-]+))?/i);
  const anyTls = rawOne.match(/\b(TLSv?1[._][0-3])\b/);
  if (msTls) { tlsVersion = normTlsVersion(msTls[1]); tlsCipher = msTls[2]; }
  else if (pfTls) { tlsVersion = normTlsVersion(pfTls[1]); tlsCipher = pfTls[2] ?? null; }
  else if (anyTls) tlsVersion = normTlsVersion(anyTls[1]);
  if (!tlsCipher) tlsCipher = rawOne.match(/\bcipher[= ]([A-Z0-9_-]{8,})/i)?.[1] ?? null;

  // Protokoll-Klasse (RFC 3848 "with"-Werte plus Microsoft-Varianten).
  const p = (proto ?? "").toUpperCase();
  let protoClass: Hop["protoClass"] = null;
  if (p) {
    if (p.includes("HTTP")) protoClass = "http";
    else if (p.includes("MAPI")) protoClass = "mapi";
    else if (p === "LOCAL" || p.includes("LOCAL")) protoClass = "local";
    else if (/SMTPSA$|LMTPSA$/.test(p)) protoClass = "tlsAuth";
    else if (/SMTPS$|LMTPS$/.test(p)) protoClass = "tls";
    else if (/SMTPA$|LMTPA$/.test(p)) protoClass = "auth";
    else if (p.includes("SMTP") || p.includes("LMTP")) protoClass = tlsVersion ? "tls" : "plain";
  } else if (tlsVersion) {
    protoClass = "tls";
  }

  const hostsForProvider = [rdns, fromHost, byHost].filter((h): h is string => !!h).map((h) => h.toLowerCase());

  return {
    n: 0,
    fromHost, helo: helo ?? null, rdns, ip,
    internal: ip ? isPrivateIp(ip) : false,
    byHost, software, proto, protoClass, tlsVersion, tlsCipher,
    id, forAddr, via,
    date: parseMailDate(dateRaw),
    delaySec: null,
    provider: detectProvider(hostsForProvider),
    attested: false,
    raw,
  };
}

// ---------------------------------------------------------------------------
// Authentication-Results (RFC 8601), Received-SPF, DKIM/ARC-Tag-Listen
// ---------------------------------------------------------------------------
/** Top-Level-Split unter Beachtung von Klammern und Anführungszeichen. */
export function splitTop(s: string, sep: string): string[] {
  const parts: string[] = [];
  let depth = 0, inQ = false, buf = "";
  for (const ch of s) {
    if (inQ) { buf += ch; if (ch === '"') inQ = false; continue; }
    if (ch === '"') { inQ = true; buf += ch; continue; }
    if (ch === "(") depth++;
    if (ch === ")") depth = Math.max(0, depth - 1);
    if (ch === sep && depth === 0) { parts.push(buf); buf = ""; continue; }
    buf += ch;
  }
  if (buf.trim()) parts.push(buf);
  return parts;
}

/** Klammer-Kommentare entfernen und separat einsammeln. */
export function extractComments(s: string, into: string[]): string {
  let depth = 0, out = "", comment = "";
  for (const ch of s) {
    if (ch === "(") { if (depth === 0) comment = ""; else comment += ch; depth++; continue; }
    if (ch === ")") {
      depth = Math.max(0, depth - 1);
      if (depth === 0) { if (comment.trim()) into.push(comment.replace(/\s+/g, " ").trim()); }
      else comment += ch;
      continue;
    }
    if (depth > 0) comment += ch;
    else out += ch;
  }
  return out;
}

export type AuthMethod = {
  method: string;
  result: string;
  props: Record<string, string>;
  comments: string[];
};
/**
 * Herkunft einer Prüfzeile:
 * `trusted`   die authserv-id ist eine, die der Nutzer als die seines
 *             Eingangs-Gateways angegeben hat (RFC 8601 §5). Belastbar nur,
 *             wenn das Gateway fremde Zeilen mit dieser ID entfernt,
 * `matched`   die authserv-id kommt als `by`-Host in der Received-Kette vor.
 *             Nur plausibel: eine Fälschung kann die passende Received-Zeile
 *             gleich mitliefern,
 * `unmatched` weder noch (der Absender kann die Zeile selbst geschrieben haben),
 * `absent`    die Zeile trägt keine authserv-id (bei Microsoft 365 üblich).
 */
export type AuthTrust = "trusted" | "matched" | "unmatched" | "absent";

export type AuthResults = {
  authserv: string | null;
  methods: AuthMethod[];
  raw: string;
  trust: AuthTrust;
};

export function parseAuthResults(field: HeaderField): AuthResults {
  const parts = splitTop(field.value, ";").map((p) => p.trim()).filter(Boolean);
  let authserv: string | null = null;
  let start = 0;
  if (parts.length) {
    const cmts: string[] = [];
    const head = extractComments(parts[0], cmts).trim();
    // Nur eine authserv-id, wenn der erste Teil kein method=result-Muster ist
    // (Microsoft lässt die authserv-id weg und beginnt direkt mit spf=...).
    if (head && !/=/.test(head.split(/\s+/)[0])) {
      authserv = head.split(/\s+/)[0];
      start = 1;
    }
  }
  const methods: AuthMethod[] = [];
  for (const part of parts.slice(start)) {
    const comments: string[] = [];
    const clean = extractComments(part, comments).trim();
    if (!clean || clean.toLowerCase() === "none") continue;
    const m = clean.match(/^([\w/.-]+)\s*=\s*(\S+)\s*(.*)$/s);
    if (!m) continue;
    const props: Record<string, string> = {};
    for (const pm of m[3].matchAll(/([\w-]+(?:\.[\w-]+)?)\s*=\s*("[^"]*"|[^\s;]+)/g)) {
      props[pm[1].toLowerCase()] = pm[2].replace(/^"|"$/g, "");
    }
    methods.push({
      method: m[1].split("/")[0].toLowerCase(),
      result: m[2].toLowerCase().replace(/[.,]+$/, ""),
      props,
      comments,
    });
  }
  return { authserv, methods, raw: field.raw, trust: authserv ? "unmatched" : "absent" };
}

/**
 * Herkunft einer Prüfzeile einstufen. Massgeblich ist allein die Zeile, deren
 * authserv-id die empfangende Organisation als eigene kennt (RFC 8601 §5);
 * vertrauenswürdige IDs werden exakt verglichen. Der Abgleich mit der
 * Zustellkette ist nur eine Plausibilitätsprüfung, weil sich Received-Zeilen
 * genauso fälschen lassen wie die Prüfzeile selbst.
 */
export function classifyAuthTrust(authserv: string | null, byHosts: string[], trustedIds: string[] = []): AuthTrust {
  if (!normDomain(authserv)) return "absent";
  if (trustedIds.some((t) => sameDomain(authserv, t))) return "trusted";
  return byHosts.some((h) => hostMatches(authserv, h)) ? "matched" : "unmatched";
}

/**
 * Freitext mit einer oder mehreren authserv-ids (Komma, Semikolon oder
 * Leerraum getrennt) in normalisierte IDs zerlegen.
 */
export function parseTrustedIds(text: string | null | undefined): string[] {
  if (!text) return [];
  return [...new Set(text.split(/[\s,;]+/).map((t) => normDomain(t)).filter((t): t is string => !!t))];
}

export type ReceivedSpf = { result: string; props: Record<string, string>; comments: string[]; raw: string };

export function parseReceivedSpf(field: HeaderField): ReceivedSpf {
  const comments: string[] = [];
  const clean = extractComments(field.value, comments).trim();
  const result = (clean.split(/\s+/)[0] ?? "").toLowerCase();
  const props: Record<string, string> = {};
  for (const pm of clean.matchAll(/([\w-]+)\s*=\s*("[^"]*"|[^\s;]+)/g)) {
    props[pm[1].toLowerCase()] = pm[2].replace(/^"|"$/g, "").replace(/;$/, "");
  }
  return { result, props, comments, raw: field.raw };
}

/** DKIM-/ARC-Tag-Liste (k=v; k=v; ...) parsen. */
export function parseTagList(value: string): Record<string, string> {
  const tags: Record<string, string> = {};
  for (const part of splitTop(value, ";")) {
    const m = part.match(/^\s*([a-z][a-z0-9_-]*)\s*=\s*([\s\S]*)$/i);
    if (m) tags[m[1].toLowerCase()] = m[2].replace(/\s+/g, m[1].toLowerCase() === "h" ? "" : " ").trim();
  }
  return tags;
}

// ---------------------------------------------------------------------------
// Organisations-Domain (Heuristik für relaxed alignment, ohne vollständige PSL)
// ---------------------------------------------------------------------------
const MULTI_SLD = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk",
  "com.au", "net.au", "org.au", "co.nz", "com.br", "com.mx", "com.ar",
  "com.tr", "com.cn", "com.tw", "com.hk", "com.sg", "co.jp", "or.jp", "ne.jp",
  "co.in", "co.za", "com.pl", "co.il", "com.ua",
]);

export function orgDomain(d: string): string {
  const parts = d.toLowerCase().replace(/\.$/, "").split(".");
  if (parts.length <= 2) return parts.join(".");
  const last2 = parts.slice(-2).join(".");
  return MULTI_SLD.has(last2) ? parts.slice(-3).join(".") : last2;
}

/**
 * Domainnamen für den Vergleich vereinheitlichen: klein, ohne umgebenden
 * Whitespace, ohne Endpunkt, ohne spitze Klammern. Gibt null zurück, wenn
 * nichts Vergleichbares übrig bleibt.
 */
export function normDomain(d: string | null | undefined): string | null {
  if (!d) return null;
  const s = d.trim().toLowerCase().replace(/^[<"']+|[>"',;]+$/g, "").replace(/\.+$/, "");
  return s || null;
}

/** Exakter Domainvergleich. Kein Teilstring, kein Muster (W1A-01, W1A-02). */
export function sameDomain(a: string | null | undefined, b: string | null | undefined): boolean {
  const x = normDomain(a), y = normDomain(b);
  return x !== null && x === y;
}

/** Gleiche Domain oder echte Unterdomain, immer an der Punktgrenze. */
export function hostMatches(a: string | null | undefined, b: string | null | undefined): boolean {
  const x = normDomain(a), y = normDomain(b);
  if (x === null || y === null) return false;
  if (x === y) return true;
  return x.endsWith(`.${y}`) || y.endsWith(`.${x}`);
}

export type Alignment = "strict" | "relaxed" | "none";
export function align(a: string | null, b: string | null): Alignment | null {
  if (!a || !b) return null;
  const x = a.toLowerCase().replace(/\.$/, ""), y = b.toLowerCase().replace(/\.$/, "");
  if (x === y) return "strict";
  return orgDomain(x) === orgDomain(y) ? "relaxed" : "none";
}

// ---------------------------------------------------------------------------
// Adressen
// ---------------------------------------------------------------------------
export type Addr = { name: string | null; addr: string | null; domain: string | null; display: string };

/**
 * Zeichen am Ende abschneiden. Ersetzt `replace(/[>;,]+$/, "")`: das Muster
 * probiert bei einer langen Wiederholung jeden Startpunkt durch und läuft
 * dadurch quadratisch (W1A-03, R-2).
 */
export function trimEndChars(s: string, chars: string): string {
  let end = s.length;
  while (end > 0 && chars.includes(s[end - 1])) end--;
  return end === s.length ? s : s.slice(0, end);
}

export function parseAddr(value: string): Addr {
  const dec = decodeWords(value).replace(/\s+/g, " ").trim();
  // Das @ gehört in keine der beiden Klassen: sonst überlappen sie, und der
  // Motor probiert jeden Trennpunkt durch (W1A-03, R-1).
  const m = dec.match(/<([^<>\s@]+@[^<>\s@]+)>/);
  const addr = m?.[1] ?? dec.match(/[\w.+=-]+@[\w.-]+/)?.[0] ?? null;
  let name: string | null = null;
  if (m && m.index !== undefined && m.index > 0) {
    name = dec.slice(0, m.index).trim().replace(/^"(.*)"$/, "$1").trim() || null;
  }
  const domain = addr ? trimEndChars(addr.split("@")[1]?.toLowerCase() ?? "", ">;,") || null : null;
  return { name, addr, domain, display: name && addr ? `${name} <${addr}>` : (addr ?? dec) };
}

// ---------------------------------------------------------------------------
// Spamfilter-Kopfzeilen (Werte sind fremdbestimmt, deshalb ohne Rückverfolgung)
// ---------------------------------------------------------------------------
/** `CIP:203.0.113.25;CTRY:CH;...` in ein Wörterbuch zerlegen. */
export function parseForefront(value: string): Record<string, string> {
  const out: Record<string, string> = Object.create(null);
  for (const part of value.split(";")) {
    const idx = part.indexOf(":");
    if (idx <= 0) continue;
    const key = part.slice(0, idx).trim();
    if (!/^[A-Z]+$/.test(key)) continue;
    out[key] = part.slice(idx + 1).trim();
  }
  return out;
}

/** Ausgelöste SpamAssassin-Tests aus `X-Spam-Status` lesen. */
export function spamAssassinTests(value: string): string[] {
  const idx = value.toLowerCase().indexOf("tests=");
  if (idx < 0) return [];
  const tokens = value.slice(idx + 6).split(/\s+/);
  const collected: string[] = [];
  for (const tok of tokens) {
    // Das nächste `schlüssel=` beendet die Liste.
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(tok)) break;
    collected.push(tok);
  }
  return collected.join(" ").split(",").map((x) => x.trim()).filter(Boolean);
}

/** rspamd-Symbole `NAME(-1.20)` einsammeln. */
export function rspamdSymbols(value: string): Array<{ name: string; score: string }> {
  const out: Array<{ name: string; score: string }> = [];
  // Der Klammerteil ist optional: dadurch verschiebt sich lastIndex auch
  // ohne Treffer hinter den ganzen Namen, statt jede Position zu probieren.
  for (const m of value.matchAll(/[A-Z][A-Z0-9_]{2,}(\(([-\d.]+)\))?/g)) {
    if (m[2] !== undefined) out.push({ name: m[0].slice(0, m[0].indexOf("(")), score: m[2] });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Analyse
// ---------------------------------------------------------------------------
export type DkimSig = {
  tags: Record<string, string>;
  receiverResult: "pass" | "fail" | null;
  raw: string;
};

export type ArcInstance = {
  i: number;
  sealDomain: string | null;
  cv: string | null;
  aar: string | null;
  /** Die versiegelten Prüfergebnisse, mit demselben Parser gelesen wie AR. */
  aarMethods: AuthMethod[];
};

/**
 * Bezeugt diese ARC-Instanz eine gültige DKIM-Signatur der Domain `d`?
 *
 * Verglichen werden Domainnamen, nicht Zeichenketten: der `d=`-Wert der
 * Signatur ist fremdbestimmt und darf weder in ein Muster fliessen (W1A-01)
 * noch per Teilstring treffen (W1A-02). `evil-bank.example` ist kein Zeuge
 * für `bank.example`.
 */
export function arcAttestsDkim(inst: ArcInstance, d: string | null | undefined): boolean {
  if (!normDomain(d)) return false;
  return inst.aarMethods.some((m) =>
    m.method === "dkim" && m.result === "pass" && sameDomain(m.props["header.d"], d));
}

/** Abweichung vom Aufbau einer ARC-Kette (RFC 8617), sprachneutral. */
export type ArcIssue =
  | { kind: "count"; i: number; header: "ARC-Seal" | "ARC-Message-Signature" | "ARC-Authentication-Results"; n: number }
  | { kind: "cv"; i: number; cv: string | null; expected: "none" | "pass" }
  | { kind: "limit"; n: number }
  | { kind: "noInstance" };

/** Höchste zulässige ARC-Instanz (RFC 8617). */
export const MAX_ARC = 50;

export type AnalyzeOptions = {
  /** authserv-ids des eigenen Eingangs-Gateways; nur deren Zeilen sind belegt. */
  trustedAuthServIds?: string[];
};

/**
 * ARC-Instanzen, die eine DKIM-Signatur der Domain `d` bezeugen. Die Angaben
 * in ARC-Authentication-Results sind Aussagen der jeweiligen Weiterleitung;
 * sie zählen nur, wenn der Empfänger die Kette selbst geprüft hat (arc=pass).
 */
export function arcWitnesses(a: Pick<Analysis, "arc" | "summary">, d: string | null | undefined): ArcInstance[] {
  if (a.summary.arc?.result !== "pass") return [];
  return a.arc.filter((inst) => arcAttestsDkim(inst, d));
}
export type Analysis = {
  fields: HeaderField[];
  hadBody: boolean;
  hops: Hop[];
  /** Received-Zeilen jenseits der Obergrenze, die nicht ausgewertet wurden. */
  hopOverflow: number;
  totalSec: number | null;
  slowestIdx: number;
  hasSkew: boolean;
  ar: AuthResults[];
  /** `by`-Hosts der Received-Kette, normalisiert; Massstab für die Herkunft. */
  byHosts: string[];
  /** Station, die zugestellt hat: der `by`-Host des jüngsten Received-Hops. */
  deliveredBy: string | null;
  /** Die Prüfzeile, aus der die Zusammenfassung stammt. */
  authoritative: AuthResults | null;
  authTrust: AuthTrust | "none";
  /** Mehrere Prüfzeilen unterschiedlicher Herkunft im Header. */
  authMixedOrigins: boolean;
  /** Die vom Nutzer angegebenen vertrauenswürdigen authserv-ids, normalisiert. */
  trustedIds: string[];
  /**
   * Methoden, für die sich Zeilen mit vertrauenswürdiger ID widersprechen:
   * mindestens eine stammt nicht vom Gateway, es entfernt fremde Zeilen nicht.
   */
  trustedConflicts: string[];
  receivedSpf: ReceivedSpf | null;
  receivedSpfTrust: AuthTrust | "none";
  /** Das SPF-Ergebnis stammt nur aus Received-SPF, nicht aus einer Prüfzeile. */
  spfFromReceivedSpf: boolean;
  dkimSigs: DkimSig[];
  arc: ArcInstance[];
  /**
   * Aufbau der ARC-Kette: Instanznummern, ein Header-Satz je Instanz,
   * cv=-Folge. Keine Signaturprüfung; das kryptografische Urteil ist
   * `summary.arc`, also das Ergebnis des Empfängers.
   */
  arcStructure: "consistent" | "inconsistent" | null;
  arcIssues: ArcIssue[];
  summary: Record<"spf" | "dkim" | "dmarc" | "arc" | "compauth", AuthMethod | null>;
  from: Addr | null;
  replyTo: Addr | null;
  returnPath: Addr | null;
  subject: string | null;
  date: Date | null;
  messageId: string | null;
  mailFromDomain: string | null;
  /** Namen der Kopfzeilen, die Bidi-Steuerzeichen enthalten (F-06). */
  bidiFields: string[];
  /** Kopfzeilen, die es laut RFC 5322 §3.6 nur einmal geben darf (F-05). */
  duplicates: Array<{ name: string; values: string[] }>;
};

/** Kopfzeilen, die RFC 5322 §3.6 auf höchstens eine Instanz begrenzt. */
const SINGLETON_FIELDS = ["From", "Sender", "Reply-To", "To", "Cc", "Bcc",
  "Subject", "Date", "Message-ID", "Return-Path", "In-Reply-To", "References"];

/**
 * Obergrenze für die Zahl ausgewerteter Received-Zeilen. Eine echte Zustellung
 * kommt mit weniger als 30 Stationen aus; RFC 5321 §6.3 empfiehlt 100 als
 * Schleifenschutz. Ohne Grenze erzeugt eine präparierte Nachricht beliebig
 * viele Aufklappblöcke und lässt `Math.max(1, ...hops)` mit einem RangeError
 * abbrechen (W1A-04). Gezählt wird von oben, also von der Zustellung her: die
 * jüngsten Stationen sind die belastbaren.
 */
export const MAX_HOPS = 200;

export function analyzeHeaders(fields: HeaderField[], hadBody: boolean, opts: AnalyzeOptions = {}): Analysis {
  // Hops: im Header steht der letzte zuoberst; chronologisch ist umgekehrt.
  const received = all(fields, "Received");
  const hopOverflow = Math.max(0, received.length - MAX_HOPS);
  const hops = received.slice(0, MAX_HOPS).map((f) => parseReceived(f.value, f.raw)).reverse();
  hops.forEach((h, i) => {
    h.n = i + 1;
    // Nur die zuletzt hinzugefügte Zeile stammt vom empfangenden System.
    h.attested = i === hops.length - 1;
  });
  let hasSkew = false;
  let slowestIdx = -1, slowest = -1;
  for (let i = 1; i < hops.length; i++) {
    const a = hops[i - 1].date, b = hops[i].date;
    if (a && b) {
      hops[i].delaySec = Math.round((b.getTime() - a.getTime()) / 1000);
      if (hops[i].delaySec! < 0) hasSkew = true;
      if (hops[i].delaySec! > slowest) { slowest = hops[i].delaySec!; slowestIdx = i; }
    }
  }
  const dated = hops.filter((h) => h.date);
  const totalSec = dated.length >= 2
    ? Math.round((dated[dated.length - 1].date!.getTime() - dated[0].date!.getTime()) / 1000)
    : null;

  const ar = [
    ...all(fields, "Authentication-Results"),
    ...all(fields, "Authentication-Results-Original"),
  ].map(parseAuthResults);

  const spfField = first(fields, "Received-SPF");
  const receivedSpf = spfField ? parseReceivedSpf(spfField) : null;

  // Herkunft der Prüfzeilen. Beleg ist nur eine authserv-id, die der Nutzer als
  // die seines Gateways angibt; der Abgleich mit der Zustellkette ist bloss
  // plausibel, weil der Absender die Received-Zeile gleich mitfälschen kann.
  const byHosts = hops.map((h) => normDomain(h.byHost)).filter((h): h is string => !!h);
  const deliveredBy = hops.length ? normDomain(hops[hops.length - 1].byHost) : null;
  const trustedIds = [...new Set((opts.trustedAuthServIds ?? []).map((t) => normDomain(t)).filter((t): t is string => !!t))];
  for (const set of ar) set.trust = classifyAuthTrust(set.authserv, byHosts, trustedIds);

  // Die beste vorhandene Herkunftsstufe zählt, die übrigen Zeilen nicht
  // (RFC 8601 §5). Innerhalb der Stufe gilt die Reihenfolge, oberste zuerst.
  const bestLevel = (["trusted", "matched"] as const).find((lvl) => ar.some((set) => set.trust === lvl));
  const ranked = bestLevel ? ar.filter((set) => set.trust === bestLevel) : ar;

  // Widersprechen sich Zeilen mit vertrauenswürdiger ID, hat das Gateway eine
  // fremde Zeile nicht entfernt. DKIM ausgenommen: mehrere Signaturen dürfen
  // legitim unterschiedlich ausfallen.
  const trustedResults = new Map<string, Set<string>>();
  for (const set of ar.filter((x) => x.trust === "trusted")) {
    for (const m of set.methods) {
      if (!["spf", "dmarc", "arc", "compauth"].includes(m.method)) continue;
      if (!trustedResults.has(m.method)) trustedResults.set(m.method, new Set());
      trustedResults.get(m.method)!.add(m.result);
    }
  }
  const trustedConflicts = [...trustedResults].filter(([, r]) => r.size > 1).map(([k]) => k);
  const summary: Analysis["summary"] = { spf: null, dkim: null, dmarc: null, arc: null, compauth: null };
  for (const set of ranked) {
    for (const m of set.methods) {
      const key = m.method as keyof Analysis["summary"];
      if (key in summary && !summary[key]) summary[key] = m;
    }
  }
  const authoritative = ranked.find((set) => set.methods.length > 0) ?? null;
  const withMethods = ar.filter((set) => set.methods.length > 0);
  const authMixedOrigins =
    new Set(withMethods.map((set) => normDomain(set.authserv) ?? "")).size > 1;

  const receivedSpfTrust: AuthTrust | "none" = receivedSpf
    ? classifyAuthTrust(receivedSpf.props.receiver ?? null, byHosts, trustedIds)
    : "none";
  const spfFromReceivedSpf = !summary.spf && !!receivedSpf;
  if (spfFromReceivedSpf && receivedSpf) {
    summary.spf = { method: "spf", result: receivedSpf.result, props: receivedSpf.props, comments: receivedSpf.comments };
  }

  // DKIM-Signaturen; Empfänger-Ergebnis über header.d (und wenn vorhanden header.s) zuordnen.
  const dkimResults = ranked.flatMap((s) => s.methods.filter((m) => m.method === "dkim"));
  const usedResult = new Set<AuthMethod>();
  const dkimSigs: DkimSig[] = all(fields, "DKIM-Signature").map((f) => {
    const tags = parseTagList(f.value);
    const match = dkimResults.find((m) => {
      if (usedResult.has(m)) return false;
      const d = m.props["header.d"]?.toLowerCase();
      const s = m.props["header.s"]?.toLowerCase();
      if (!d || d !== tags.d?.toLowerCase()) return false;
      return !s || !tags.s || s === tags.s.toLowerCase();
    });
    if (match) usedResult.add(match);
    return {
      tags,
      receiverResult: match ? (match.result === "pass" ? "pass" : "fail") : null,
      raw: f.raw,
    };
  });

  // ARC-Kette aus den Seals gruppieren. Geprüft wird nur der Aufbau
  // (RFC 8617 §5.1.1), keine Signatur: das kryptografische Urteil ist das
  // arc=-Ergebnis des Empfängers.
  const arcMap = new Map<number, ArcInstance>();
  const arcCounts = new Map<string, number>();
  const bump = (key: string) => arcCounts.set(key, (arcCounts.get(key) ?? 0) + 1);
  const instOf = (t: Record<string, string>) => (/^\d+$/.test(t.i ?? "") ? parseInt(t.i, 10) : 0);
  for (const f of all(fields, "ARC-Seal")) {
    const t = parseTagList(f.value);
    const i = instOf(t);
    bump(`ARC-Seal|${i}`);
    arcMap.set(i, { i, sealDomain: t.d ?? null, cv: t.cv?.toLowerCase() ?? null, aar: null, aarMethods: [] });
  }
  for (const f of all(fields, "ARC-Message-Signature")) bump(`ARC-Message-Signature|${instOf(parseTagList(f.value))}`);
  for (const f of all(fields, "ARC-Authentication-Results")) {
    const i = parseInt(f.value.match(/^\s*i\s*=\s*(\d+)/)?.[1] ?? "0", 10);
    bump(`ARC-Authentication-Results|${i}`);
    const inst = arcMap.get(i);
    if (inst) {
      inst.aar = f.value.replace(/^\s*i\s*=\s*\d+\s*;\s*/, "");
      inst.aarMethods = parseAuthResults({ name: f.name, value: inst.aar, raw: f.raw }).methods;
    }
  }
  const arc = [...arcMap.values()].sort((a, b) => a.i - b.i);
  const arcIssues: ArcIssue[] = [];
  let arcStructure: Analysis["arcStructure"] = null;
  if (arcCounts.size) {
    const top = Math.max(...[...arcCounts.keys()].map((k) => parseInt(k.split("|")[1], 10)));
    if (top > MAX_ARC) arcIssues.push({ kind: "limit", n: top });
    const headers = ["ARC-Seal", "ARC-Message-Signature", "ARC-Authentication-Results"] as const;
    for (let i = 1; i <= Math.min(top, MAX_ARC); i++) {
      for (const header of headers) {
        const n = arcCounts.get(`${header}|${i}`) ?? 0;
        if (n !== 1) arcIssues.push({ kind: "count", i, header, n });
      }
      const inst = arcMap.get(i);
      const expected = i === 1 ? "none" : "pass";
      if (inst && inst.cv !== expected) arcIssues.push({ kind: "cv", i, cv: inst.cv, expected });
    }
    if (headers.some((h) => arcCounts.has(`${h}|0`))) arcIssues.push({ kind: "noInstance" });
    arcStructure = arcIssues.length ? "inconsistent" : "consistent";
  }

  const fromField = first(fields, "From");
  const from = fromField ? parseAddr(fromField.value) : null;
  const replyToField = first(fields, "Reply-To");
  const returnPathField = first(fields, "Return-Path");
  const subjectField = first(fields, "Subject");

  const mailFromDomain =
    summary.spf?.props["smtp.mailfrom"]?.split("@").pop()?.toLowerCase() ??
    (returnPathField ? parseAddr(returnPathField.value).domain : null);

  return {
    fields, hadBody, hops, hopOverflow, totalSec, slowestIdx, hasSkew,
    ar, byHosts, deliveredBy, authoritative,
    authTrust: authoritative ? authoritative.trust : "none",
    authMixedOrigins, trustedIds, trustedConflicts,
    receivedSpf, receivedSpfTrust, spfFromReceivedSpf,
    dkimSigs, arc, arcStructure, arcIssues, summary,
    from,
    replyTo: replyToField ? parseAddr(replyToField.value) : null,
    returnPath: returnPathField ? parseAddr(returnPathField.value) : null,
    subject: subjectField ? decodeWords(subjectField.value) : null,
    date: parseMailDate(first(fields, "Date")?.value),
    messageId: first(fields, "Message-ID")?.value ?? null,
    mailFromDomain,
    bidiFields: [...new Set(fields.filter((f) => hasBidiControls(f.raw)).map((f) => f.name))],
    duplicates: SINGLETON_FIELDS
      .map((name) => ({ name, values: all(fields, name).map((f) => f.value) }))
      .filter((d) => d.values.length > 1),
  };
}
