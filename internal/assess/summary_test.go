package assess

import (
	"strings"
	"testing"

	"github.com/alexdimarco/https-tester/internal/evidence"
)

// withClaims attaches n placeholder claims so TestsRun / the "nothing run yet"
// guard behave as they would after real probes.
func withClaims(run evidence.Run, n int) evidence.Run {
	for i := 0; i < n; i++ {
		run.Claims = append(run.Claims, evidence.Claim{})
	}
	return run
}

func TestSummarizeNothingRun(t *testing.T) {
	s := Summarize(evidence.Run{})
	if s.Connection != "not_tested" {
		t.Errorf("Connection = %q, want not_tested", s.Connection)
	}
	if s.Standing != "not_tested" {
		t.Errorf("Standing = %q, want not_tested", s.Standing)
	}
	if !strings.Contains(strings.ToLower(s.Headline), "no test") {
		t.Errorf("Headline = %q, want it to say no test has run", s.Headline)
	}
	if len(s.Issues) != 0 {
		t.Errorf("Issues = %v, want none", s.Issues)
	}
}

func TestSummarizeVerifiedTLS13Recommended(t *testing.T) {
	// A default verified request that negotiated TLS 1.3 (no separate 1.2 test).
	run := withClaims(evidence.Run{
		Observations: []evidence.Observation{
			{ProbeID: "HTTPS-01", Stage: evidence.StageTLS, Outcome: evidence.OutcomePass, NegotiatedVersion: "TLS 1.3", Group: "X25519"},
			{ProbeID: "HTTPS-01", Stage: evidence.StageCertificate, Outcome: evidence.OutcomePass},
			{ProbeID: "HTTPS-01", Stage: evidence.StageHTTP, Outcome: evidence.OutcomePass, HTTPStatus: 200},
		},
	}, 1)

	s := Summarize(run)
	if s.Connection != "verified" {
		t.Errorf("Connection = %q, want verified", s.Connection)
	}
	if s.Standing != "recommended" {
		t.Errorf("Standing = %q, want recommended", s.Standing)
	}
	if len(s.Issues) != 0 {
		t.Errorf("Issues = %v, want none for a clean verified run", s.Issues)
	}
	if !strings.Contains(s.StandingNote, "TLS 1.2") {
		t.Errorf("StandingNote = %q, want a prompt to confirm TLS 1.2", s.StandingNote)
	}
}

func TestSummarizeTLS13OnlyIsHighSecurity(t *testing.T) {
	// TLS 1.3 works; a direct TLS 1.2 offer did not complete.
	run := withClaims(evidence.Run{
		Observations: []evidence.Observation{
			{ProbeID: "TLS-13", Stage: evidence.StageTLS, Outcome: evidence.OutcomePass, NegotiatedVersion: "TLS 1.3"},
			{ProbeID: "HTTPS-01", Stage: evidence.StageHTTP, Outcome: evidence.OutcomePass, HTTPStatus: 200},
			{ProbeID: "TLS-12", Stage: evidence.StageTLS, Outcome: evidence.OutcomeFail, NormalizedError: "tls_version_not_supported"},
		},
	}, 3)

	s := Summarize(run)
	if s.Standing != "high-security" {
		t.Errorf("Standing = %q, want high-security", s.Standing)
	}
	if len(s.Issues) != 0 {
		t.Errorf("Issues = %v, want none (TLS 1.2 absent is not a defect)", s.Issues)
	}
}

func TestSummarizeCertificateFailureIsAnIssue(t *testing.T) {
	// Certificate failures surface as a TLS-stage fail carrying the cert error.
	run := withClaims(evidence.Run{
		Observations: []evidence.Observation{
			{ProbeID: "HTTPS-01", Stage: evidence.StageTLS, Outcome: evidence.OutcomeFail, NormalizedError: "certificate_unknown_authority"},
		},
	}, 1)

	s := Summarize(run)
	if s.Connection != "failed" {
		t.Errorf("Connection = %q, want failed", s.Connection)
	}
	if s.Standing != "below-baseline" {
		t.Errorf("Standing = %q, want below-baseline", s.Standing)
	}
	if len(s.Issues) == 0 {
		t.Fatalf("expected a certificate issue, got none")
	}
	if !strings.Contains(strings.ToLower(s.Issues[0]), "certificate") {
		t.Errorf("Issues[0] = %q, want it to name the certificate", s.Issues[0])
	}
	if !strings.Contains(s.Headline, "attention") {
		t.Errorf("Headline = %q, want it to flag attention", s.Headline)
	}
	if !strings.Contains(s.Headline, "1 issue needs attention") {
		t.Errorf("Headline = %q, want subject-agreeing singular phrasing", s.Headline)
	}
}

func TestSummarizeDirectTLS13FailureIsBelowBaseline(t *testing.T) {
	// A direct TLS 1.3 test that did not complete (no certificate problem).
	run := withClaims(evidence.Run{
		Observations: []evidence.Observation{
			{ProbeID: "TLS-13", Stage: evidence.StageTLS, Outcome: evidence.OutcomeFail, NormalizedError: "tls_version_not_supported"},
		},
	}, 1)

	s := Summarize(run)
	if s.Standing != "below-baseline" {
		t.Errorf("Standing = %q, want below-baseline", s.Standing)
	}
	if !strings.Contains(s.StandingNote, "TLS 1.3") {
		t.Errorf("StandingNote = %q, want it to mention TLS 1.3", s.StandingNote)
	}
}

func TestConnectionStateReportsDeepestStageNotLast(t *testing.T) {
	// An earlier probe reached the TLS stage before failing; a later probe failed
	// earlier, at TCP. The note must name the deepest stage reached (TLS), not the
	// last one in record order (TCP).
	run := withClaims(evidence.Run{
		Observations: []evidence.Observation{
			{ProbeID: "HTTPS-01", Stage: evidence.StageTLS, Outcome: evidence.OutcomeFail, NormalizedError: "tls_handshake_failure"},
			{ProbeID: "TLS-12", Stage: evidence.StageTCP, Outcome: evidence.OutcomeFail, NormalizedError: "connection_refused"},
		},
	}, 2)
	s := Summarize(run)
	if s.Connection != "failed" {
		t.Fatalf("Connection = %q, want failed", s.Connection)
	}
	if !strings.Contains(s.ConnectionNote, "TLS stage") {
		t.Errorf("ConnectionNote = %q, want it to name the deepest (TLS) stage", s.ConnectionNote)
	}
	if strings.Contains(s.ConnectionNote, "TCP stage") {
		t.Errorf("ConnectionNote = %q, should not report the shallower TCP stage as deepest", s.ConnectionNote)
	}
}

func TestSummarizeAlwaysCarriesCaveatAndDate(t *testing.T) {
	s := Summarize(withClaims(evidence.Run{}, 1))
	if s.KnowledgeAsOf != KnowledgeAsOf {
		t.Errorf("KnowledgeAsOf = %q, want %q", s.KnowledgeAsOf, KnowledgeAsOf)
	}
	if !strings.Contains(s.Caveat, "not a security grade") {
		t.Errorf("Caveat = %q, want the no-grade caveat", s.Caveat)
	}
}
