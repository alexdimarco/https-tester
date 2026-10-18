// Package report renders a run into a plain-language text report or a JSON
// document. Provenance sits beside every observation; nothing is presented as a
// measurement that was not one. No A–F security grade is produced.
package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/alexdimarco/https-tester/internal/evidence"
)

// JSON renders the run as indented JSON.
func JSON(run evidence.Run) ([]byte, error) {
	return json.MarshalIndent(run, "", "  ")
}

// Text renders a human-readable report.
func Text(run evidence.Run) string {
	var b bytes.Buffer

	line(&b, "HTTPS Diagnostic Workbench — investigation report")
	line(&b, "%s", strings.Repeat("=", 52))
	line(&b, "")
	line(&b, "Run ID:           %s", run.RunID)
	line(&b, "Worked on (UTC):  %s", run.StartedAtUTC.Format("2006-01-02 15:04:05"))
	line(&b, "Clock source:     %s", run.ClockSource)
	line(&b, "Build:            %s", run.AppBuild)
	line(&b, "Platform:         %s/%s", run.Platform, run.Architecture)
	line(&b, "Register:         findings about observed results; root causes remain open unless stated")
	line(&b, "")

	line(&b, "Scope (what was authorized)")
	line(&b, "  Address:    %s", run.TargetScope.InputURL)
	line(&b, "  Authority:  %s", run.TargetScope.Authority)
	line(&b, "  Addresses:  %s", orNone(strings.Join(run.TargetScope.SelectedAddresses, ", ")))
	line(&b, "  Trust mode: %s", run.TrustMode)
	line(&b, "  Authorized: %t (%s)", run.Authorization.OperatorAcknowledged, orNone(run.Authorization.Note))
	line(&b, "")

	line(&b, "Observed results (each line is a recorded observation)")
	if len(run.Observations) == 0 {
		line(&b, "  (none yet)")
	}
	for _, o := range run.Observations {
		line(&b, "  [%s] %s — %s", strings.ToUpper(string(o.Stage)), o.Outcome, provenance(o))
		for _, kv := range sortedDetail(o) {
			line(&b, "        %s: %s", kv[0], kv[1])
		}
		if o.RawErrorRedacted != "" {
			line(&b, "        error: %s", o.RawErrorRedacted)
		}
		for _, u := range o.RemainingUnknowns {
			line(&b, "        not checked: %s", u)
		}
	}
	line(&b, "")

	line(&b, "Findings")
	if len(run.Claims) == 0 {
		line(&b, "  (none yet)")
	}
	for _, c := range run.Claims {
		line(&b, "  • %s", c.Statement)
		line(&b, "      register:   %s / %s", c.Register, c.Status)
		line(&b, "      scope:      %s", c.Scope)
		for _, a := range c.Alternatives {
			line(&b, "      alternative: %s", a)
		}
		for _, u := range c.UncheckedItems {
			line(&b, "      not checked: %s", u)
		}
		line(&b, "      next check: %s", c.NextDiscriminatingCheck)
	}
	line(&b, "")

	line(&b, "Redaction and sharing")
	line(&b, "  Credential-bearing headers (Authorization, Cookie, …) are removed before storage.")
	line(&b, "  Token-like URL query values and userinfo are masked. Review before sharing widely.")
	line(&b, "")

	line(&b, "Method counters (software-recorded unless marked self-report)")
	line(&b, "  Observations recorded: %d", len(run.Observations))
	line(&b, "  Claims recorded:       %d", len(run.Claims))
	line(&b, "  Consent events:        %d", len(run.ConsentEvents))
	line(&b, "  Schema/rule versions:  %s / %s", run.SchemaVersion, orNone(run.RuleCatalogVersion))
	line(&b, "  Self-report: this tool does not certify the remote server, only what this client observed.")

	return b.String()
}

func provenance(o evidence.Observation) string {
	parts := []string{fmt.Sprintf("source=%s", o.SourceKind)}
	if o.DurationMS > 0 {
		parts = append(parts, fmt.Sprintf("%dms", o.DurationMS))
	}
	return strings.Join(parts, " ")
}

func sortedDetail(o evidence.Observation) [][2]string {
	var out [][2]string
	add := func(k, v string) {
		if v != "" {
			out = append(out, [2]string{k, v})
		}
	}
	add("version", o.NegotiatedVersion)
	add("cipher", o.CipherSuite)
	add("group", o.Group)
	add("alpn", o.ApplicationProtocol)
	add("verification", o.VerificationStatus)
	if o.HTTPStatus != 0 {
		add("http_status", fmt.Sprintf("%d", o.HTTPStatus))
	}
	keys := make([]string, 0, len(o.Detail))
	for k := range o.Detail {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		add(k, o.Detail[k])
	}
	return out
}

func line(b *bytes.Buffer, format string, args ...any) {
	fmt.Fprintf(b, format, args...)
	b.WriteByte('\n')
}

func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(none)"
	}
	return s
}
