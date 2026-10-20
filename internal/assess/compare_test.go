package assess

import (
	"strings"
	"testing"

	"github.com/alexdimarco/https-tester/internal/evidence"
)

// run13 is a verified TLS 1.3 run (no separate TLS 1.2 test), like a default
// verified request to a modern server.
func run13(host string) evidence.Run {
	return evidence.Run{
		SchemaVersion: evidence.SchemaVersion,
		TargetScope:   evidence.TargetScope{Host: host, Authority: host + ":443"},
		Claims:        []evidence.Claim{{Statement: "A verified HTTPS response was obtained."}},
		Observations: []evidence.Observation{
			{ProbeID: "HTTPS-01", Stage: evidence.StageTLS, Outcome: evidence.OutcomePass, NegotiatedVersion: "TLS 1.3"},
			{ProbeID: "HTTPS-01", Stage: evidence.StageCertificate, Outcome: evidence.OutcomePass},
			{ProbeID: "HTTPS-01", Stage: evidence.StageHTTP, Outcome: evidence.OutcomePass, HTTPStatus: 200},
		},
	}
}

// run13plus12 additionally confirms TLS 1.2 works (broad compatibility).
func run13plus12(host string) evidence.Run {
	r := run13(host)
	r.Claims = append(r.Claims, evidence.Claim{Statement: "TLS 1.2 also completed."})
	r.Observations = append(r.Observations,
		evidence.Observation{ProbeID: "TLS-12", Stage: evidence.StageTLS, Outcome: evidence.OutcomePass, NegotiatedVersion: "TLS 1.2"})
	return r
}

// certFailRun fails during the TLS handshake because the certificate is not
// trusted — the shape the native prober records (Go validates the certificate
// as part of the handshake, so an untrusted cert is a TLS-stage failure).
func certFailRun(host string) evidence.Run {
	return evidence.Run{
		SchemaVersion: evidence.SchemaVersion,
		TargetScope:   evidence.TargetScope{Host: host, Authority: host + ":443"},
		Claims:        []evidence.Claim{{Statement: "The certificate failed validation."}},
		Observations: []evidence.Observation{
			{ProbeID: "HTTPS-01", Stage: evidence.StageTLS, Outcome: evidence.OutcomeFail, NormalizedError: "certificate_unknown_authority"},
		},
	}
}

func rowByDimension(c Comparison, dim string) (CompareRow, bool) {
	for _, r := range c.Rows {
		if r.Dimension == dim {
			return r, true
		}
	}
	return CompareRow{}, false
}

func TestCompareSameTierReadsAsSame(t *testing.T) {
	c := Compare(run13("a.test"), run13("b.test"))
	if c.A.Standing != c.B.Standing {
		t.Fatalf("expected equal standings, got %q vs %q", c.A.Standing, c.B.Standing)
	}
	row, ok := rowByDimension(c, "TLS 1.3")
	if !ok {
		t.Fatalf("no TLS 1.3 row:\n%+v", c.Rows)
	}
	if row.Agreement != agreeSame {
		t.Errorf("TLS 1.3 should be the same on both; got %q", row.Agreement)
	}
	if !strings.Contains(c.Verdict, "same tier") {
		t.Errorf("verdict should note the shared tier: %q", c.Verdict)
	}
}

func TestCompareNeverDeclaresAWinner(t *testing.T) {
	// A is TLS 1.3-only-ish (high security), B is 1.2+1.3 (recommended): a real
	// standing difference, but the verdict must not rank one above the other.
	a := run13("a.test")
	a.Observations = append(a.Observations,
		evidence.Observation{ProbeID: "TLS-12", Stage: evidence.StageTLS, Outcome: evidence.OutcomeFail})
	a.Claims = append(a.Claims, evidence.Claim{Statement: "TLS 1.2 offer did not complete."})
	c := Compare(a, run13plus12("b.test"))
	for _, banned := range []string{"better", "worse", "winner", "superior", "beats"} {
		if strings.Contains(strings.ToLower(c.Verdict), banned) {
			t.Errorf("verdict ranks the servers (%q): %q", banned, c.Verdict)
		}
	}
	// Both hosts should be named so the reader can judge for themselves.
	if !strings.Contains(c.Verdict, "a.test") || !strings.Contains(c.Verdict, "b.test") {
		t.Errorf("verdict should name both hosts for the reader to judge: %q", c.Verdict)
	}
}

func TestCompareMarksOneSidedTestsIncomparable(t *testing.T) {
	// A ran a TLS 1.2 test; B did not. The TLS 1.2 row cannot be compared.
	c := Compare(run13plus12("a.test"), run13("b.test"))
	row, ok := rowByDimension(c, "TLS 1.2")
	if !ok {
		t.Fatalf("no TLS 1.2 row")
	}
	if row.Agreement != agreeNone {
		t.Errorf("TLS 1.2 tested on only one side should be incomparable; got %q", row.Agreement)
	}
	if !strings.Contains(row.Note, "server B") {
		t.Errorf("note should point at the untested server: %q", row.Note)
	}
}

func TestCompareFlagsConnectionAndCertDifference(t *testing.T) {
	c := Compare(run13("a.test"), certFailRun("b.test"))
	conn, _ := rowByDimension(c, "Verified connection")
	if conn.Agreement != agreeDiff {
		t.Errorf("verified vs failed connection should differ; got %q", conn.Agreement)
	}
	cert, _ := rowByDimension(c, "Certificate")
	if cert.Agreement != agreeDiff {
		t.Errorf("valid vs untrusted certificate should differ; got %q", cert.Agreement)
	}
	// B's certificate failure is an observed issue; A's is clean.
	if c.A.IssueCount != 0 || c.B.IssueCount == 0 {
		t.Errorf("expected issues only on B; got A=%d B=%d", c.A.IssueCount, c.B.IssueCount)
	}
}

func TestCompareEmptyRunsAskForTests(t *testing.T) {
	empty := evidence.Run{TargetScope: evidence.TargetScope{Host: "a.test", Authority: "a.test:443"}}
	c := Compare(empty, empty)
	if !strings.Contains(strings.ToLower(c.Verdict), "neither server") {
		t.Errorf("empty comparison should ask for tests: %q", c.Verdict)
	}
}
