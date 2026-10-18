package assess

import (
	"strings"
	"testing"

	"github.com/alexdimarco/https-tester/internal/evidence"
)

func TestBuildPostureAndKnowledgeDate(t *testing.T) {
	run := evidence.Run{
		TargetScope: evidence.TargetScope{Authority: "example.com:443"},
		Observations: []evidence.Observation{
			{ProbeID: "TLS-13", Stage: evidence.StageTLS, Outcome: evidence.OutcomePass, NegotiatedVersion: "TLS 1.3", Group: "X25519"},
			{ProbeID: "GROUP-X25519", Stage: evidence.StageTLS, Outcome: evidence.OutcomePass, Group: "X25519"},
			{ProbeID: "GROUP-P384", Stage: evidence.StageTLS, Outcome: evidence.OutcomeFail, NormalizedError: "tls_handshake_failure"},
			{ProbeID: "HTTPS-01", Stage: evidence.StageCertificate, Outcome: evidence.OutcomePass},
		},
	}

	a := Build(run)

	if a.KnowledgeAsOf == "" || a.KnowledgeAsOf != KnowledgeAsOf {
		t.Errorf("KnowledgeAsOf = %q, want %q", a.KnowledgeAsOf, KnowledgeAsOf)
	}

	find := func(substr string) *Property {
		for i := range a.Properties {
			if strings.Contains(a.Properties[i].Name+" "+a.Properties[i].State, substr) {
				return &a.Properties[i]
			}
		}
		return nil
	}

	if p := find("TLS 1.3"); p == nil || !strings.Contains(p.State, "observed working") {
		t.Errorf("expected a TLS 1.3 observed-working property, got %+v", p)
	}
	if p := find("accepted"); p == nil || !strings.Contains(p.State, "X25519") {
		t.Errorf("expected an accepted-groups property naming X25519, got %+v", p)
	}
	rej := find("rejected")
	if rej == nil || !strings.Contains(rej.State, "P-384") {
		t.Fatalf("expected a rejected-for-offer property naming P-384, got %+v", rej)
	}
	// The design's forbidden leap must not appear: never claim the group is disabled.
	if strings.Contains(strings.ToLower(rej.Note), "disabled server-side") && !strings.Contains(rej.Note, "not proof") {
		t.Errorf("rejected-group note must not assert the group is disabled: %q", rej.Note)
	}

	if len(a.NotTested) == 0 {
		t.Error("expected not-tested gaps")
	}
	legacy := false
	for _, g := range a.NotTested {
		if strings.Contains(g.Name, "Legacy TLS") {
			legacy = true
		}
	}
	if !legacy {
		t.Error("expected a legacy TLS gap in not-tested")
	}

	if len(a.References) == 0 {
		t.Error("expected authoritative references backing the risk claims")
	}
	for _, r := range a.References {
		if r.Cite == "" || r.URL == "" {
			t.Errorf("reference is missing a citation or URL: %+v", r)
		}
	}
}
