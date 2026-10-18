# Contributing to HTTPS Diagnostic Workbench

Thanks for your interest. This project is **design-stage** — there is no
application code yet, only the specification in
[`docs/HTTPS_Diagnostic_Workbench_Design.md`](docs/HTTPS_Diagnostic_Workbench_Design.md).
The most valuable contributions right now are careful reviews of that design:
gaps in diagnostic coverage, places where a conclusion outruns its evidence, or
security and privacy concerns.

## Ground rules from the design

This tool exists to diagnose honestly, so contributions are held to the same
standard the design sets:

- **Observation is not conclusion.** A failure at one layer is not proof of a
  failure at another. Keep claims scoped to what was actually observed.
- **No auto-remediation.** The tool never changes a remote server. Features
  that would "fix" a target are out of scope.
- **Local-only.** No telemetry, cloud analysis, or external AI in the core
  product.
- **Redact secrets.** Never paste real tokens, cookies, private keys, or
  internal hostnames into issues, pull requests, or test fixtures. Use
  placeholders.

## Development (once code lands)

Prerequisites: a recent **Go** toolchain (the design pins Go 1.27.2 as the
baseline; check `go.mod` once it exists).

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
