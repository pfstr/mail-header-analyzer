/**
 * Erkennung des Mail-Providers/Gateways anhand der MX-Hostnamen.
 * Kuratierte Liste: bewusst die im DACH-/CH-Umfeld verbreiteten Anbieter
 * zuerst. Kein Anspruch auf Vollständigkeit; ohne Treffer zeigt das
 * Host-Panel immer noch den Netz-Inhaber (RIPE Stat).
 */
const PROVIDERS: Array<{ re: RegExp; name: string }> = [
  // Sichere-Mail-Gateways (Schweiz/DACH)
  { re: /\bseppmail\./i, name: "SEPPmail" },
  { re: /\bhin\.ch$/i, name: "HIN Mailgateway" },
  { re: /\b(totemo|kereon)\./i, name: "totemomail" },
  { re: /\bhornetsecurity\.|antispameurope\./i, name: "Hornetsecurity" },
  { re: /\bretarus\./i, name: "Retarus" },
  { re: /\bnospamproxy\./i, name: "NoSpamProxy" },

  // Grosse Plattformen
  { re: /\.protection\.outlook\.com$/i, name: "Microsoft 365 (Exchange Online Protection)" },
  { re: /\b(aspmx|gmail-smtp-in)\.l\.google\.com$|\.googlemail\.com$/i, name: "Google Workspace" },
  { re: /\bmail\.protection\.sophos\.com$/i, name: "Sophos Email" },
  { re: /\b(pphosted|ppe-hosted|ppops)\.(com|net)$/i, name: "Proofpoint" },
  { re: /\bmimecast\./i, name: "Mimecast" },
  { re: /\bmessagelabs\.com$/i, name: "Broadcom (Symantec.cloud)" },
  { re: /\bbarracuda(networks)?\.com$/i, name: "Barracuda" },
  { re: /\biphmx\.com$|\bcisco\./i, name: "Cisco Secure Email" },
  { re: /\btrendmicro\.(com|eu)$/i, name: "Trend Micro" },
  { re: /\bavanan\./i, name: "Check Point (Avanan)" },

  // Mailbox-/Hosting-Anbieter Schweiz
  { re: /\binfomaniak\.(ch|com)$/i, name: "Infomaniak" },
  { re: /\bhostpoint\.ch$/i, name: "Hostpoint" },
  { re: /\bcyon\.ch$/i, name: "cyon" },
  { re: /\bmetanet\.ch$/i, name: "Metanet" },
  { re: /\bhosttech\./i, name: "hosttech" },
  { re: /\bgreen\.ch$/i, name: "green.ch" },
  { re: /\b(bluewin|swisscom)\.ch$/i, name: "Swisscom" },
  { re: /\bprotonmail\.ch$|\bproton\.me$/i, name: "Proton Mail" },

  // Mailbox-/Hosting-Anbieter international
  { re: /\bmailbox\.org$|\bheinlein/i, name: "mailbox.org (Heinlein)" },
  { re: /\bposteo\.de$/i, name: "Posteo" },
  { re: /\bionos\.|kundenserver\.de$|\b1and1\.|\b1und1\./i, name: "IONOS" },
  { re: /\bstrato(server)?\.(de|net)$/i, name: "Strato" },
  { re: /\bkasserver\.com$|\ball-inkl\./i, name: "All-Inkl" },
  { re: /\byour-server\.de$|\bhetzner\./i, name: "Hetzner" },
  { re: /\bovh\.(net|com)$/i, name: "OVHcloud" },
  { re: /\bzoho(mail)?\.(eu|com)$/i, name: "Zoho Mail" },
  { re: /\bfastmail\.com$|\bmessagingengine\.com$/i, name: "Fastmail" },
  { re: /\bicloud\.com$|\bapple\.com$/i, name: "Apple iCloud Mail" },
  { re: /\byahoodns\.net$/i, name: "Yahoo" },
  { re: /\bmail\.gandi\.net$/i, name: "Gandi" },
  { re: /\bsecureserver\.net$/i, name: "GoDaddy" },
  { re: /\bemailsrvr\.com$/i, name: "Rackspace Email" },
  { re: /\bamazonaws\.com$|\bawsapps\.com$/i, name: "Amazon WorkMail/SES" },
  { re: /\bmailgun\./i, name: "Mailgun" },
  { re: /\bsendgrid\.net$/i, name: "SendGrid" },
  { re: /\bmailroute\.net$/i, name: "MailRoute" },
  { re: /\bspamtitan\./i, name: "SpamTitan" },
  { re: /\bopen-xchange\.|\boxcs\./i, name: "Open-Xchange" },
];

/** Erster Treffer über alle MX-Hosts (Hosts sind bereits lowercase/ohne Endpunkt). */
export function detectProvider(hosts: string[]): string | null {
  for (const host of hosts) {
    for (const p of PROVIDERS) {
      if (p.re.test(host)) return p.name;
    }
  }
  return null;
}
