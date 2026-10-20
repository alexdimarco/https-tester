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

// Document is the self-contained JSON export: the executive summary first, then
// the full evidence run, the protocol assessment, and the profile comparison.
// It leads with the summary for the same reason the text report does.
type Document struct {
	Summary    assess.Summary         `json:"summary"`
	Run        evidence.Run           `json:"run"`
	Assessment assess.Assessment      `json:"assessment"`
	Profiles   []assess.ProfileTarget `json:"profiles"`
}

// JSONDocument renders the complete export document (summary + run + assessment
// + profiles) as indented JSON.
func JSONDocument(run evidence.Run) ([]byte, error) {
	doc := Document{
		Summary:    assess.Summarize(run),
		Run:        run,
		Assessment: assess.Build(run),
		Profiles:   assess.CompareProfiles(run),
	}
	return json.MarshalIndent(doc, "", "  ")
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

	// --- executive summary (the short, lead-with-the-answer view) ---
	sum := assess.Summarize(run)
	writeSummary(&b, sum)

	// --- where this lands: the security tier, with how it matches ---
	writeTierPlacement(&b, sum, assess.CompareProfiles(run))

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
	if len(a.References) > 0 {
		line(&b, "  Sources (risk claims checked against these on %s):", a.KnowledgeAsOf)
		for _, r := range a.References {
			line(&b, "    - %s — %s", r.Cite, r.URL)
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

// writeSummary renders the short executive summary at the top of the report.
func writeSummary(b *bytes.Buffer, s assess.Summary) {
	line(b, "EXECUTIVE SUMMARY")
	line(b, "%s", strings.Repeat("-", 52))
	line(b, "  Bottom line:  %s", s.Headline)
	line(b, "  Connection:   %s — %s", connWord(s.Connection), s.ConnectionNote)
	line(b, "  Standing:     %s", s.StandingLabel)
	line(b, "                %s", s.StandingNote)
	if len(s.Issues) == 0 {
		line(b, "  Issues:       none observed in the tests run")
	} else {
		line(b, "  Issues needing attention:")
		for _, is := range s.Issues {
			line(b, "    - %s", is)
		}
	}
	if len(s.Watch) > 0 {
		line(b, "  Also worth noting:")
		for _, w := range s.Watch {
			line(b, "    - %s", w)
		}
	}
	line(b, "  Tests run: %d    Security knowledge as of: %s", s.TestsRun, s.KnowledgeAsOf)
	line(b, "  %s", s.Caveat)
	line(b, "")
}

// writeTierPlacement ranks the observed posture into one of the named tiers and
// shows, for each tier, how the run matched and what is still missing. This is
// the text-report counterpart of the on-screen "Where this server lands" view.
func writeTierPlacement(b *bytes.Buffer, s assess.Summary, profiles []assess.ProfileTarget) {
	line(b, "WHERE THIS LANDS (compatibility & security tier)")
	line(b, "%s", strings.Repeat("-", 52))
	line(b, "  Observed tier:  %s", s.StandingLabel)
	if s.StandingNote != "" {
		line(b, "                  %s", s.StandingNote)
	}
	line(b, "")
	line(b, "  Measured against the named targets (TLS-version posture only;")
	line(b, "  cipher strength and legacy TLS 1.0/1.1 are not fully testable here):")
	for _, p := range profiles {
		mark := ""
		if p.Standing == s.Standing && s.Standing != "below-baseline" {
			mark = "   <-- server lands here"
		}
		var matched, missing []assess.ProfileCheck
		for _, c := range p.Checks {
			if c.Status == "met" {
				matched = append(matched, c)
			} else {
				missing = append(missing, c)
			}
		}
		line(b, "")
		line(b, "  [%s] %s%s", tierWord(p.Standing), p.Name, mark)
		line(b, "      %s", p.Summary)
		if len(matched) > 0 {
			line(b, "      How it matches:")
			for _, c := range matched {
				line(b, "        - %s: %s", c.Expectation, checkWord(c.Status))
			}
		}
		if len(missing) > 0 {
			line(b, "      What's missing / to confirm:")
			for _, c := range missing {
				line(b, "        - %s: %s — %s", c.Expectation, checkWord(c.Status), c.Detail)
			}
		}
		line(b, "      Source: %s", p.Source)
	}
	line(b, "")
}

// tierWord is the short label for a tier's standing in the text report.
func tierWord(standing string) string {
	switch standing {
	case "recommended":
		return "Recommended"
	case "high-security":
		return "Highest security"
	case "below-baseline":
		return "Below baseline"
	default:
		return standing
	}
}

// checkWord is the plain-language word for a per-tier check result.
func checkWord(status string) string {
	switch status {
	case "met":
		return "met"
	case "unmet":
		return "not met in this run"
	case "not_tested":
		return "not tested yet"
	case "consider":
		return "policy choice"
	default:
		return status
	}
}

func connWord(state string) string {
	switch state {
	case "verified":
		return "verified"
	case "failed":
		return "not completed"
	default:
		return "not tested yet"
	}
}

func line(b *bytes.Buffer, format string, args ...any) {
	fmt.Fprintf(b, format, args...)
	b.WriteByte('\n')
}
