# Changelog

## v0.2.0 — 2026-10-20

Reports now lead with the answer: every report — text, JSON, and the web UI —
opens with a plain-language executive summary and places the server on a
compatibility/security tier, and the "Run tests" UI explains each test in plain
words. Still an early 0.x release; interfaces and behavior may still change.

### Added
- Executive summary leading every report — the text report, the JSON export, and
  the web UI's "Where this server lands" panel: the bottom line, whether a
  verified HTTPS connection was obtained, the security tier the observed posture
  is consistent with (its "standing"), the issues actually seen, and items worth
  watching. A scoped summary of what was observed — never a grade, a score, or a
  pass/fail verdict.

### Changed
- Compatibility & security tier placement is now shown in the text report and the
  JSON export, not only in the web UI as before: the observed TLS-version posture
  against the Widest-compatibility (legacy, below baseline), Good security
  (Intermediate), and Highest security (Modern) targets, with how the run matches
  and what is missing or untested for each. (The three-target comparison itself
  shipped in v0.1.0; this broadens where it appears.)
- JSON export is now a self-contained document — `summary`, `run`, `assessment`,
  and `profiles` — instead of the bare evidence run. The raw run moves under the
  `run` key, so a tool that parsed the previous export must now read `run`.
- Web UI report controls: the on-page "Export JSON" preview is replaced by
  "Download report (.txt)" and "Download data (.json)", which save a local file
  named `httpsdiag-<host>-<timestamp>`; "Preview report" still renders the text
  report in-page. Downloads are produced locally and never leave the loopback
  server.
- Clearer "Run tests" UI: each test is grouped under the plain question it
  answers — "Does HTTPS work at all?", "Which TLS versions does the server
  accept?", "Which key-exchange methods work?" (advanced), "Compare a real
  installed client" (advanced), and "Report" — each with a one-line caption of
  what it checks and what a pass or fail means, instead of bare buttons. Results
  now lead with the tier placement.

## v0.1.0 — 2026-10-18

First official release (0.x — early; interfaces and behavior may still change).
A local, capability-protected HTTPS diagnostic workbench with a working Go probe
engine. All targets, including the macOS `.app`, are built and attested by CI.
Binaries are unsigned; the test suite runs on Linux, macOS, and Windows in CI.
Promotes the v0.1.0-alpha preview with the same capabilities.

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
