SECURITY.md
```markdown
# Security Policy

This project processes logs that may contain sensitive identifiers (serials, IMEI/ICCID-like numbers, MACs, IPs, UUIDs, etc.). The toolkit includes aggressive redaction to support safe sharing.

## Supported versions

The latest tagged release is supported. If you report a security issue, please include the tag or commit hash.

## Reporting a vulnerability

If you believe you found a vulnerability or a redaction leak:

1. Do **not** open a public GitHub issue with raw logs.
2. Create a minimal reproduction (ideally with synthetic lines).
3. Open a private report through your preferred channel (email/DM) or use GitHub Security Advisories if enabled.

Include:
- Tool version / commit hash
- Exact command used (flags matter)
- A minimal sample line that bypassed redaction

## Redaction model (high level)

### What `--safe` is for
`--safe` is designed for logs that may be posted publicly (issues, pastebins, matrix, etc.). It prioritizes preventing leaks even if it slightly reduces forensic detail.

### What gets redacted (examples)
- MAC addresses
- IPv4/IPv6 addresses
- Long hex identifiers (hashes, tokens, some UUID forms)
- Suspected device identifiers and serial-like strings
- Suspected IMEI/ICCID-like numbers

### Luhn-validated redaction (why it exists)
Some numeric identifiers (notably IMEI/ICCID-like) follow a checksum pattern (Luhn). The tool uses this to reduce over-redaction in non-safe mode while still catching obvious identifier leaks. In `--safe`, redaction is more aggressive and should not rely solely on Luhn.

### Limits / user responsibility
- Logs can contain novel formats. If you find a leak pattern, report it.
- For maximum privacy, always use `--safe` before sharing logs.
- Do not paste raw `logcat`/`dmesg` from a personal daily-use phone without `--safe`.

## Threat model

This tool:
- Does not execute untrusted code from logs.
- Does not modify devices.
- Does not transmit logs anywhere by itself.

Primary risk:
- Accidental publishing of sensitive identifiers contained in logs.

Mitigations:
- Default guidance recommends `--safe`.
- Watchdog capture can be configured; users should treat `PROJECT/` outputs as sensitive until redacted.

## Hardening recommendations

- Use `--safe` when generating reports for sharing.
- Keep `PROJECT/` directories private if you captured `logcat` from Android user sessions.
- If you use Pulse mode, assume your terminal scrollback may contain unredacted data unless `--safe` is applied to the producer stream.
