#!/usr/bin/env node
/**
 * Kommandozeile: liest Header aus einer Datei oder von stdin und gibt
 * eine Zusammenfassung als Text oder JSON aus. Kein Netzwerkzugriff.
 */
import { readFileSync } from "node:fs";
import { analyze, summarize, type Summary } from "./index.ts";

const HELP = `Usage: mail-header-analyzer [file] [--json]

Analyze email headers offline: Received chain, SPF/DKIM/DMARC/ARC,
trust of Authentication-Results, and anomalies. Reads stdin if no file is given.

Options:
  --json     Print the summary as JSON
  -h, --help Show this help

Browser version (runs locally, no upload):
  https://rafaelpfister.ch/en/tools/header-analyzer
`;

function readInput(file: string | undefined): string {
  return readFileSync(file ?? 0, "utf8");
}

function text(s: Summary): string {
  const lines: string[] = [];
  const row = (k: string, v: string | number | null) => { if (v !== null && v !== "") lines.push(`${k.padEnd(14)}${v}`); };
  row("From", s.from);
  row("Reply-To", s.replyTo);
  row("Return-Path", s.returnPath);
  row("Subject", s.subject);
  row("Date", s.date);
  row("Delivered by", s.deliveredBy);
  row("Transit", s.totalSeconds === null ? null : `${s.totalSeconds}s`);
  lines.push("");
  const a = s.auth;
  lines.push(`Auth          spf=${a.spf ?? "-"} dkim=${a.dkim ?? "-"} dmarc=${a.dmarc ?? "-"} arc=${a.arc ?? "-"} compauth=${a.compauth ?? "-"} (source: ${a.source})`);
  lines.push("");
  lines.push("Hops");
  for (const h of s.hops) {
    const delay = h.delaySeconds === null ? "" : ` +${h.delaySeconds}s`;
    const mark = h.attested ? " [attested]" : "";
    lines.push(`  ${h.n}. ${h.from ?? "?"}${h.ip ? ` [${h.ip}]` : ""} -> ${h.by ?? "?"}${h.tls ? ` ${h.tls}` : ""}${delay}${mark}`);
  }
  lines.push("");
  if (s.findings.length) {
    lines.push("Findings");
    for (const f of s.findings) lines.push(`  ! ${f.code}: ${f.detail}`);
  } else {
    lines.push("Findings      none");
  }
  return lines.join("\n");
}

const args = process.argv.slice(2);
if (args.includes("-h") || args.includes("--help")) {
  process.stdout.write(HELP);
  process.exit(0);
}
const file = args.find((x) => !x.startsWith("-"));
try {
  const summary = summarize(analyze(readInput(file)));
  process.stdout.write((args.includes("--json") ? JSON.stringify(summary, null, 2) : text(summary)) + "\n");
} catch (err) {
  process.stderr.write(`mail-header-analyzer: ${(err as Error).message}\n`);
  process.exit(1);
}
