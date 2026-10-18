# Changelog

## v0.1.0-alpha — 2026-10-18

First alpha: a local, capability-protected HTTPS diagnostic workbench with a
working Go probe engine. Binaries are unsigned; the test suite runs on Linux,
macOS, and Windows in CI.

### Added
- Local loopback server: single-use bootstrap token exchanged for a per-launch
  capability, exact Host/Origin checks, a strict Content Security Policy, and an
  embedded single-page UI.
- Native Go probe covering DNS, TCP, TLS, certificate, and HTTP stages, with
  per-stage evidence and only the TLS fields the public API exposes.
- Exact TLS 1.2 / TLS 1.3 version probes and single key-exchange-group probes
  (X25519, P-256, P-384, P-521).
- Approved external-client adapters (curl, openssl) run with a no-shell safety
  harness and a sanitized environment (SSLKEYLOGFILE and proxy variables removed).
- Static Nginx configuration review (operator-supplied text; never executed, no
  include files opened).
- Protocol-posture assessment with an "as known by" date and primary-source
  citations, plus a legacy / Intermediate / Modern profile comparison.
- Plain-language findings and text / JSON reports; in-memory, append-only
  evidence model.

### Known limits
- Binaries are unsigned — macOS Gatekeeper and Windows SmartScreen will warn.
- Legacy TLS 1.0 / 1.1 are not tested, and TLS 1.3 cipher suites cannot be
  enumerated in Go; use the openssl adapter or a dedicated scanner for those.
- No independent security review of the local API yet, and no manual multi-OS QA.
- PCI DSS references are from widely-cited guidance, not re-verified at the
  PCI SSC source.
