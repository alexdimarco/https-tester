package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// TestClaimLinksObservations guards the finding-to-observation linkage that the
// report's status badge depends on: every supporting-observation ID a claim
// records must be a non-empty ID that actually exists among the run's
// observations.
func TestClaimLinksObservations(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	u, _ := url.Parse(ts.URL)

	s := NewSession("test-build")
	ctx := context.Background()

	run, err := s.CreateRun(ctx, CreateRunRequest{URL: ts.URL + "/", LocalPrivateApproved: true})
	if err != nil {
		t.Fatalf("CreateRun(%s): %v", u, err)
	}
	after, err := s.RunProbe(ctx, run.RunID, "")
	if err != nil {
		t.Fatalf("RunProbe: %v", err)
	}
	if len(after.Claims) == 0 {
		t.Fatal("expected at least one claim")
	}

	ids := map[string]bool{}
	for _, o := range after.Observations {
		if o.ID == "" {
			t.Error("stored observation has an empty ID")
		}
		ids[o.ID] = true
	}
	c := after.Claims[len(after.Claims)-1]
	if len(c.SupportingObservations) == 0 {
		t.Fatal("claim has no supporting observations")
	}
	for _, id := range c.SupportingObservations {
		if id == "" || !ids[id] {
			t.Errorf("claim references observation %q not present in the run", id)
		}
	}
}
