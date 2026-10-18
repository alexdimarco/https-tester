# HTTPS Diagnostic Workbench

A local-only, cross-platform tool for troubleshooting HTTPS connections — one
test at a time, with every result labelled by what it does and does **not**
prove.

> **Status: v0.1.0-alpha.** The Go probe engine works and is tested on Linux,
> macOS, and Windows in CI. Binaries are **unsigned** (your OS will warn on first
> run), there is no independent security review of the local API yet, and legacy
> TLS 1.0/1.1 and cipher-suite enumeration are out of scope for this build. See
> the [CHANGELOG](CHANGELOG.md) and the full design in
> [`docs/HTTPS_Diagnostic_Workbench_Design.md`](docs/HTTPS_Diagnostic_Workbench_Design.md).

## Quick start

```sh
# from source
go run ./cmd/httpsdiag
# then open the printed http://127.0.0.1:<port>/#... URL in your browser
```

Or download a binary from the [releases](https://github.com/alexdimarco/https-tester/releases).
Because the binaries are unsigned, verify what you downloaded and clear the OS
guard before running:

```sh
shasum -a 256 -c SHA256SUMS                               # checksums
gh attestation verify ./httpsdiag-<os>-<arch> --repo alexdimarco/https-tester
xattr -d com.apple.quarantine ./httpsdiag-darwin-*        # macOS only
```

## What it will do

An administrator enters an HTTPS address, authorises a bounded set of
connection attempts, and works through an investigation one step at a time.
For each observation the tool explains:

- what it observed,
- what that observation does **not** establish,
- the smallest next test that would distinguish the competing explanations.

It does not administer the remote server, change its configuration, upload
results, or require any AI or cloud service.

## Design principles

- **Local-only.** The UI, test engine, evidence store, and reports all run on
  the operator's machine. Network traffic goes only to the approved target and
  resolver.
- **One test at a time.** No silent cascades; the operator authorises each
  step.
- **Evidence with provenance.** Every result records its source, client
  version, and scope. Findings keep observation separate from hypothesis.
- **No auto-remediation.** The tool never changes a server or "fixes" a config.
  Every recommendation comes with a bounded verification step.
- **Honest limits.** Unknowns stay visible rather than being converted into
  guessed root causes.

## Planned stack

Go — a single static binary per operating-system/architecture target — with an
embedded browser UI, standard-library TLS/HTTP, and optional
operator-approved `curl`/`openssl` adapters. See the design document for the
full architecture, data model, diagnostic coverage, and delivery gates.

## License

[MIT](LICENSE)
