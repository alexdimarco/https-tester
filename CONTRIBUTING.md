# Contributing to HTTPS Diagnostic Workbench

Thanks for your interest. The HTTPS Diagnostic Workbench is a working,
local-only tool: a Go program under [`cmd/`](cmd/) with a loopback web UI that
tests one HTTPS endpoint at a time, built from the specification in
[`docs/HTTPS_Diagnostic_Workbench_Design.md`](docs/HTTPS_Diagnostic_Workbench_Design.md).
See [`README.md`](README.md) for what it does and how to run it, and
[`CHANGELOG.md`](CHANGELOG.md) for recent changes.

Valuable contributions include bug reports backed by reproducible evidence, new
or sharpened diagnostics, test coverage, and careful reviews of the design and
its guidance — especially gaps in diagnostic coverage, places where a conclusion
outruns its evidence, or security and privacy concerns.

## Ground rules from the design

This tool exists to diagnose honestly, so contributions are held to the same
standard the design sets:

- **Observation is not conclusion.** A failure at one layer is not proof of a
  failure at another. Keep claims scoped to what was actually observed.
- **Summaries and standings report posture, not a grade.** The executive
  summary, its standing, and the compatibility/security-tier placement describe
  how the observed posture matches a named target and cite their sources. They
  must never present an overall score or letter grade, or treat a single rejected
  offer as proof that a setting is disabled.
- **No auto-remediation.** The tool never changes a remote server. Features
  that would "fix" a target are out of scope.
- **Local-only.** No telemetry, cloud analysis, or external AI in the core
  product.
- **Redact secrets.** Never paste real tokens, cookies, private keys, or
  internal hostnames into issues, pull requests, or test fixtures. Use
  placeholders.

## Development

Prerequisites: a recent **Go** toolchain. The baseline is pinned in
[`go.mod`](go.mod) (currently Go 1.27.2).

```sh
go build ./...
go vet ./...
gofmt -l .        # should print nothing
go test ./... -race
```

Continuous integration runs these on every pull request — see
[`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## Submitting changes

1. Open an issue first for anything non-trivial, so the approach can be agreed
   before you invest time.
2. Fork, branch from `main`, and keep each pull request focused on one change.
3. Write a clear commit message explaining *why*, not just *what*.
4. Make sure `go vet`, `gofmt`, and the tests pass locally.
5. Fill in the pull-request template.

## Code of conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
