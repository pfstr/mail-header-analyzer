# mail-header-analyzer

Offline email header analysis for Node.js and the browser: Received chain, SPF/DKIM/DMARC/ARC, trust of `Authentication-Results`, Exchange Online headers and anomalies such as Unicode direction tricks or duplicated sender fields.

No dependencies, no network access. The headers never leave the process.

This is the analysis engine of the **[Mail Header Analyzer](https://rafaelpfister.ch/en/tools/header-analyzer)** web tool, which runs the same code locally in your browser. A PowerShell port is available as [MailHeaderAnalyzer](https://www.powershellgallery.com/packages/MailHeaderAnalyzer) on the PowerShell Gallery.

## Install

```bash
npm install mail-header-analyzer
```

## Command line

```bash
npx mail-header-analyzer message.eml
```

```bash
pbpaste | npx mail-header-analyzer --json
```

```bash
npx mail-header-analyzer message.eml --trusted-authserv mx.contoso.com
```

Example output:

```text
From          Beispiel Newsletter <news@example.org>
Delivered by  zr0p278mb0570.chep278.prod.outlook.com
Transit       42s

Auth          spf=pass dkim=pass dmarc=pass arc=- compauth=pass (source: absent)

Hops
  1. client.example.net [198.51.100.34] -> mail.example.org
  2. mail.example.org [203.0.113.25] -> mx.eur02.prod.protection.outlook.com TLS 1.3 +41s
  3. AM0EUR02FT056.eop-EUR02.prod.protection.outlook.com -> ZR0P278MB0570... TLS 1.2 +1s [attested]

Findings      none
```

## Library

```js
import { analyze, summarize } from "mail-header-analyzer";

const analysis = analyze(rawHeaders, {
  trustedAuthServIds: ["mx.contoso.com"], // optional, your inbound gateway
});                                       // full result
const summary = summarize(analysis);    // compact, JSON-friendly

console.log(summary.auth.dmarc);        // "pass"
console.log(summary.findings);          // [{ code: "auth-results-unverified", detail: "..." }]
```

`analyze()` accepts pasted headers or a complete `.eml` file. It tolerates folded lines, hard-wrapped copies from mail clients, a leading mbox `From ` line and a byte order mark.

### What it checks

| Area | Details |
|---|---|
| Received chain | Hops in chronological order, IP, rDNS, HELO, TLS version and cipher, delay per hop, clock skew, known gateways and providers |
| Trust boundary | Only the topmost Received field is written by the receiving system. It is marked `attested`; everything below is an unverified claim of the sender |
| Authentication-Results | RFC 8601 parsing with a trust level per line: `trusted` (authserv-id of your gateway, via `trustedAuthServIds`), `matched` (matches a Received host, plausible only, since Received can be forged), `unmatched`, `absent`. A forged line inserted by the sender is reported instead of trusted |
| SPF / DKIM / DMARC / ARC | Results, DKIM signature to result mapping, ARC chain structure (RFC 8617, no signature verification; the cryptographic verdict is the receiver's `arc=`), alignment helpers |
| Microsoft 365 | `compauth`, Exchange Online headers, Forefront antispam fields |
| Anomalies | Unicode bidi controls (`invoice<U+202E>fdp.exe`), duplicated singleton fields (RFC 5322 §3.6), hop limit |

### Finding codes

`bidi-controls`, `duplicate-singleton-field`, `auth-results-unverified`, `auth-results-plausible-only`, `auth-results-not-trusted`, `auth-results-trusted-conflict`, `auth-results-mixed-origins`, `received-spf-unverified`, `arc-structure-inconsistent`, `clock-skew`, `hop-limit-exceeded`, `reply-to-differs`, `dmarc-not-pass`

Microsoft 365 writes `Authentication-Results` without an authserv-id; leave `trustedAuthServIds` empty there.

## Background articles

- [Analyze email headers without uploading the email](https://rafaelpfister.ch/en/blog/analyze-email-headers-without-uploading-the-email-locally-in-the-browser-instead-of-in-a-web)
- [compauth in Microsoft 365: composite authentication and all reason codes](https://rafaelpfister.ch/en/blog/compauth-in-microsoft-365-composite-authentication-and-all-reason-codes)
- [Internal or external? Interpreting Exchange hybrid mail headers](https://rafaelpfister.ch/en/blog/internal-or-external-interpreting-exchange-hybrid-mail-headers-authas-messagedirectionality-and)
- [MailHeaderAnalyzer: analyze email headers in PowerShell](https://rafaelpfister.ch/en/blog/mailheaderanalyzer-analyze-email-headers-in-powershell-without-network-access)

## License

MIT © [Rafael Pfister](https://rafaelpfister.ch)
