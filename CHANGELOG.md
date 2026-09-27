# Changelog

## 0.1.0

- First release: analysis engine of the Mail Header Analyzer web tool as a standalone package
- `analyze()` and `summarize()` API with finding codes
- `mail-header-analyzer` command line tool (text or `--json`)
- `trustedAuthServIds` option / `--trusted-authserv` flag: only Authentication-Results of your own gateway count as verified
- ARC is checked for structure only (RFC 8617); the cryptographic verdict is the receiver's `arc=` result
