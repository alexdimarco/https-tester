// Package report renders a run into a plain-language text report or a JSON
// document. It leads with what was found, in words a non-specialist can read,
// and keeps the raw technical detail below. Provenance sits beside every
// observation; nothing is presented as a measurement that was not one. No A–F
// security grade is produced.
package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/alexdimarco/https-tester/internal/assess"
	"github.com/alexdimarco/https-tester/internal/evidence"
)

// JSON renders the run as indented JSON (the structured, second-layer view).
func JSON(run evidence.Run) ([]byte, error) {
	return json.MarshalIndent(run, "", "  ")
}

// Text renders a human-readable report.
func Text(run evidence.Run) string {
	var b bytes.Buffer

	line(&b, "HTTPS Diagnostic Workbench — investigation report")
	line(&b, "%s", strings.Repeat("=", 52))
	line(&b, "")
	line(&b, "Address worked on:  %s", run.TargetScope.InputURL)
	line(&b, "Worked on (UTC):    %s", run.StartedAtUTC.Format("2006-01-02 15:04:05"))
	line(&b, "This machine:       %s/%s, build %s", run.Platform, run.Architecture, run.AppBuild)
	line(&b, "Trust used:         %s", run.TrustMode)
	line(&b, "What this is:       findings about what THIS client observed. It does not certify the server.")
	line(&b, "")

	// --- what we found, in plain words ---
	line(&b, "WHAT WE FOUND")
	line(&b, "%s", strings.Repeat("-", 52))
	if len(run.Claims) == 0 {
		line(&b, "  No tests have been run yet.")
	}
	for _, c := range run.Claims {
		mark := claimMark(run, c)
		line(&b, "")
		line(&b, "%s %s", mark, c.Statement)
		if c.Checked != "" {
			line(&b, "    We checked:          %s", c.Checked)
		}
		for _, a := range c.Alternatives {
			line(&b, "    It could also be:    %s", a)
		}
		for _, u := range c.UncheckedItems {
			line(&b, "    Not established:     %s", u)
		}
		if c.NextDiscriminatingCheck != "" {
			line(&b, "    Suggested next test: %s", c.NextDiscriminatingCheck)
		}
	}
	line(&b, "")

	// --- protocol assessment (posture, scoped to what was tested) ---
	a := assess.Build(run)
	line(&b, "PROTOCOL ASSESSMENT")
	line(&b, "%s", strings.Repeat("-", 52))
	line(&b, "  Security knowledge as of: %s (author baseline; re-review periodically)", a.KnowledgeAsOf)
	line(&b, "  Scope: %s", a.Scope)
	if len(a.Properties) == 0 {
		line(&b, "  Nothing assessable yet — run some tests first.")
	}
	for _, p := range a.Properties {
		line(&b, "  [%s] %s — %s", p.Severity, p.Name, p.State)
		line(&b, "        %s", p.Note)
	}
	if len(a.NotTested) > 0 {
		line(&b, "  Not tested (and why it still matters):")
		for _, g := range a.NotTested {
			line(&b, "    - %s: %s", g.Name, g.Why)
		}
	}
	line(&b, "  %s", a.Disclaimer)
	line(&b, "")

	// --- test details (the raw observations, with friendly labels) ---
	line(&b, "TEST DETAILS")
	line(&b, "%s", strings.Repeat("-", 52))
	if len(run.Observations) == 0 {
		line(&b, "  (none yet)")
	}
	for _, o := range run.Observations {
		line(&b, "  %-18s %s", stageLabel(o.Stage), plainOutcome(o.Outcome))
		for _, kv := range friendlyDetail(o) {
			line(&b, "      %-14s %s", kv[0]+":", kv[1])
		}
		if msg := plainError(o.NormalizedError); msg != "" {
			line(&b, "      reason:        %s", msg)
		}
		if o.RawErrorRedacted != "" {
			line(&b, "      technical:     %s", o.RawErrorRedacted)
		}
		for _, u := range o.RemainingUnknowns {
			line(&b, "      not checked:   %s", u)
		}
	}
	line(&b, "")

	line(&b, "SHARING")
	line(&b, "%s", strings.Repeat("-", 52))
	line(&b, "  Credential headers (Authorization, Cookie, …) are removed before storage.")
	line(&b, "  Token-like URL values and userinfo are masked. Review before sharing widely.")
	line(&b, "")

	line(&b, "COUNTERS (software-recorded)")
	line(&b, "  Tests run: %d    Observations: %d    Consent events: %d",
		len(run.Claims), len(run.Observations), len(run.ConsentEvents))
	line(&b, "  This tool reports what this client observed; it does not certify the remote server.")

	return b.String()
}

// claimMark is a plain status marker derived from the claim's supporting
// observations: did the connection reach a verified HTTP response?
func claimMark(run evidence.Run, c evidence.Claim) string {
	ids := map[string]bool{}
	for _, id := range c.SupportingObservations {
		ids[id] = true
	}
	httpPass, anyFail := false, false
	for _, o := range run.Observations {
		if !ids[o.ID] {
			continue
		}
		if o.Stage == evidence.StageHTTP && o.Outcome == evidence.OutcomePass {
			httpPass = true
		}
		if o.Outcome == evidence.OutcomeFail || o.Outcome == evidence.OutcomeInconclusive {
			anyFail = true
		}
	}
	switch {
	case httpPass:
		return "[ worked ]  "
	case anyFail:
		return "[ failed ]  "
	default:
		return "[ note ]    "
	}
}

func friendlyDetail(o evidence.Observation) [][2]string {
	var out [][2]string
	add := func(k, v string) {
		if v != "" {
			out = append(out, [2]string{k, v})
		}
	}
	add("TLS version", o.NegotiatedVersion)
	add("key exchange", friendlyGroup(o.Group))
	add("cipher", o.CipherSuite)
	if o.ApplicationProtocol != "" && o.ApplicationProtocol != "none" {
		add("protocol", o.ApplicationProtocol)
	}
	add("certificate", o.VerificationStatus)
	if o.HTTPStatus != 0 {
		add("HTTP status", fmt.Sprintf("%d", o.HTTPStatus))
	}
	// A few helpful raw-detail keys, in a stable order.
	for _, k := range []string{"requested_profile", "resolved_addresses", "dial_address", "subject", "not_after"} {
		if v, ok := o.Detail[k]; ok {
			add(k, v)
		}
	}
	return out
}

func stageLabel(s evidence.Stage) string {
	switch s {
	case evidence.StageInput:
		return "Address check"
	case evidence.StageDNS:
		return "DNS lookup"
	case evidence.StageTCP:
		return "TCP connection"
	case evidence.StageTLS:
		return "TLS handshake"
	case evidence.StageCertificate:
		return "Certificate check"
	case evidence.StageHTTP:
		return "HTTP response"
	default:
		return string(s)
	}
}

func plainOutcome(o evidence.Outcome) string {
	switch o {
	case evidence.OutcomePass:
		return "worked"
	case evidence.OutcomeFail:
		return "failed"
	case evidence.OutcomeInconclusive:
		return "couldn't tell"
	case evidence.OutcomeNotTested:
		return "not tested"
	case evidence.OutcomeUnsupportedByClient:
		return "this client can't do it"
	case evidence.OutcomeCancelled:
		return "cancelled"
	case evidence.OutcomeInternalError:
		return "tool error"
	default:
		return string(o)
	}
}

func friendlyGroup(g string) string {
	switch g {
	case "CurveP256":
		return "P-256"
	case "CurveP384":
		return "P-384"
	case "CurveP521":
		return "P-521"
	case "X25519MLKEM768":
		return "X25519 + ML-KEM-768 (hybrid post-quantum)"
	case "SecP256r1MLKEM768":
		return "P-256 + ML-KEM-768 (hybrid post-quantum)"
	case "none_or_legacy_rsa_key_exchange":
		return "none (legacy RSA key exchange)"
	case "", "unknown":
		return ""
	default:
		return g
	}
}

func plainError(normalized string) string {
	switch normalized {
	case "certificate_invalid":
		return "the certificate is expired or not yet valid"
	case "certificate_hostname_mismatch":
		return "the certificate does not cover the address requested"
	case "certificate_unknown_authority":
		return "the certificate's issuer is not trusted by this machine"
	case "timeout":
		return "the server did not respond in time"
	case "tls_handshake_failure":
		return "the TLS handshake was refused (for a single-group test, the server most likely does not accept that group)"
	case "tls_version_not_supported":
		return "the server does not support that TLS version"
	case "connection_refused":
		return "the connection was refused"
	case "network_unreachable":
		return "the network path was unreachable"
	default:
		return ""
	}
}

func line(b *bytes.Buffer, format string, args ...any) {
	fmt.Fprintf(b, format, args...)
	b.WriteByte('\n')
}
