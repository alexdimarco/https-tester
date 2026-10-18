package localapi

import (
	"net/http"
	"testing"
)

// TestCrossOriginRejected ensures a request carrying a foreign Origin is refused
// even on an unauthenticated route — a hostile page must not drive the tool.
func TestCrossOriginRejected(t *testing.T) {
	s := startServer(t)
	code, _ := do(t, s, "GET", "/", "", map[string]string{"Origin": "https://evil.example"}, "")
	if code != http.StatusForbidden {
		t.Fatalf("cross-origin request: want 403, got %d", code)
	}
}

// TestSameOriginAllowed ensures the legitimate same-origin Origin passes.
func TestSameOriginAllowed(t *testing.T) {
	s := startServer(t)
	code, _ := do(t, s, "GET", "/", "", map[string]string{"Origin": "http://" + s.Addr()}, "")
	if code != http.StatusOK {
		t.Fatalf("same-origin request: want 200, got %d", code)
	}
}

// TestStateChangingRouteNeedsPost ensures a run cannot be created with GET.
func TestRunCreationRequiresPost(t *testing.T) {
	s := startServer(t)
	// GET on a POST-only route: the mux returns 405 Method Not Allowed.
	code, _ := do(t, s, "GET", "/api/runs", "", nil, "")
	if code != http.StatusMethodNotAllowed {
		t.Fatalf("GET on POST-only /api/runs: want 405, got %d", code)
	}
}
