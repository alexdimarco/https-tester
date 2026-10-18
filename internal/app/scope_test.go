package app

import (
	"context"
	"strings"
	"testing"
)

// TestScopeBlocksLinkLocal ensures a link-local / metadata target is refused.
func TestScopeBlocksLinkLocal(t *testing.T) {
	s := NewSession("test")
	_, err := s.CreateRun(context.Background(), CreateRunRequest{URL: "https://169.254.169.254/"})
	if err == nil {
		t.Fatal("a link-local (cloud metadata) target must be refused")
	}
}

// TestScopeRequiresPrivateApproval ensures loopback/private needs explicit opt-in.
func TestScopeRequiresPrivateApproval(t *testing.T) {
	s := NewSession("test")
	if _, err := s.CreateRun(context.Background(), CreateRunRequest{URL: "https://127.0.0.1/"}); err == nil {
		t.Fatal("a loopback target without approval must be refused")
	}
	run, err := s.CreateRun(context.Background(), CreateRunRequest{URL: "https://127.0.0.1/", LocalPrivateApproved: true})
	if err != nil {
		t.Fatalf("a loopback target WITH approval should be allowed: %v", err)
	}
	if len(run.TargetScope.SelectedAddresses) == 0 {
		t.Error("expected the approved loopback address in scope")
	}
}

// TestScopeBlocksOwnListener ensures the workbench never targets itself.
func TestScopeBlocksOwnListener(t *testing.T) {
	s := NewSession("test")
	s.SetSelfAuthority("127.0.0.1:443")
	_, err := s.CreateRun(context.Background(), CreateRunRequest{URL: "https://127.0.0.1:443/", LocalPrivateApproved: true})
	if err == nil || !strings.Contains(err.Error(), "no permitted address") {
		t.Fatalf("targeting the workbench's own listener must be refused, got err=%v", err)
	}
}
