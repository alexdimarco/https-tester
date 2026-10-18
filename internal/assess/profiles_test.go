package assess

import (
	"strings"
	"testing"

	"github.com/alexdimarco/https-tester/internal/evidence"
)

func TestCompareProfiles(t *testing.T) {
	// A run where TLS 1.3 works and TLS 1.2 works.
	run := evidence.Run{
		Observations: []evidence.Observation{
			{ProbeID: "TLS-13", Stage: evidence.StageTLS, Outcome: evidence.OutcomePass, NegotiatedVersion: "TLS 1.3"},
			{ProbeID: "TLS-12", Stage: evidence.StageTLS, Outcome: evidence.OutcomePass, NegotiatedVersion: "TLS 1.2"},
		},
	}
	profiles := CompareProfiles(run)
	if len(profiles) != 3 {
		t.Fatalf("expected 3 profile targets, got %d", len(profiles))
	}

	byName := map[string]ProfileTarget{}
	for _, p := range profiles {
		byName[p.Standing] = p
	}
	legacy, ok := byName["below-baseline"]
	if !ok {
		t.Fatal("expected a below-baseline (legacy) target")
	}
	if !strings.Contains(strings.ToLower(legacy.Summary+legacy.Source), "retired") {
		t.Errorf("legacy target must state the Old tier is retired, got source=%q summary=%q", legacy.Source, legacy.Summary)
	}

	inter := byName["recommended"]
	if !strings.Contains(inter.Source, "RFC 9325") {
		t.Errorf("Intermediate target should cite RFC 9325, got %q", inter.Source)
	}
	if got := checkStatus(inter, "TLS 1.3 supported"); got != "met" {
		t.Errorf("Intermediate TLS 1.3 check: want met, got %q", got)
	}

	modern := byName["high-security"]
	// TLS 1.2 reachable → Modern flags it as a consideration, not a hard fail.
	if got := checkStatus(modern, "TLS 1.2 not offered"); got != "consider" {
		t.Errorf("Modern TLS1.2-absent check with 1.2 reachable: want consider, got %q", got)
	}
}

func TestCompareProfilesUntested(t *testing.T) {
	// A run with no TLS observations: everything version-specific is not_tested.
	profiles := CompareProfiles(evidence.Run{})
	for _, p := range profiles {
		for _, c := range p.Checks {
			if c.Status == "met" || c.Status == "unmet" {
				t.Errorf("profile %q check %q should be not_tested on an empty run, got %q", p.Name, c.Expectation, c.Status)
			}
		}
	}
}

func checkStatus(p ProfileTarget, substr string) string {
	for _, c := range p.Checks {
		if strings.Contains(c.Expectation, substr) {
			return c.Status
		}
	}
	return ""
}
