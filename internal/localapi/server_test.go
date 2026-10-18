package localapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/alexdimarco/https-tester/internal/app"
)

func startServer(t *testing.T) *Server {
	t.Helper()
	s, err := New(app.NewSession("test-build"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	go func() { _ = s.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	return s
}

func do(t *testing.T, s *Server, method, path string, hostOverride string, headers map[string]string, body string) (int, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = bytes.NewBufferString(body)
	}
	req, err := http.NewRequest(method, "http://"+s.Addr()+path, rdr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if hostOverride != "" {
		req.Host = hostOverride
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

func TestBindsLoopbackOnly(t *testing.T) {
	s := startServer(t)
	host, _, err := net.SplitHostPort(s.Addr())
	if err != nil {
		t.Fatalf("addr %q: %v", s.Addr(), err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		t.Fatalf("server must bind loopback, bound %q", s.Addr())
	}
}

func TestUnauthenticatedRequestsRefused(t *testing.T) {
	s := startServer(t)

	// Sensitive route without a capability header is rejected.
	if code, _ := do(t, s, "GET", "/api/capabilities", "", nil, ""); code != http.StatusUnauthorized {
		t.Fatalf("no-capability request: want 401, got %d", code)
	}

	// The security headers are present even on a rejection.
	req, _ := http.NewRequest("GET", "http://"+s.Addr()+"/api/capabilities", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	resp.Body.Close()
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("missing/weak CSP: %q", csp)
	}
}

func TestBootstrapThenCapability(t *testing.T) {
	s := startServer(t)

	// Exchange the single-use token for the session capability.
	code, body := do(t, s, "POST", "/api/bootstrap", "", nil, `{"bootstrap":"`+s.bootstrapToken+`"}`)
	if code != http.StatusOK {
		t.Fatalf("bootstrap: want 200, got %d (%s)", code, body)
	}
	var out struct {
		Capability string `json:"capability"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.Capability == "" {
		t.Fatalf("bootstrap response: %v (%s)", err, body)
	}
	if out.Capability != s.capability {
		t.Fatal("returned capability does not match server capability")
	}

	// With the capability, the sensitive route works.
	if code, _ := do(t, s, "GET", "/api/capabilities", "", map[string]string{"X-Capability": out.Capability}, ""); code != http.StatusOK {
		t.Fatalf("authenticated capabilities: want 200, got %d", code)
	}

	// The bootstrap token is single-use.
	if code, _ := do(t, s, "POST", "/api/bootstrap", "", nil, `{"bootstrap":"`+s.bootstrapToken+`"}`); code != http.StatusForbidden {
		t.Fatalf("re-used bootstrap: want 403, got %d", code)
	}
}

func TestUnexpectedHostRejected(t *testing.T) {
	s := startServer(t)
	_, port, _ := net.SplitHostPort(s.Addr())
	if code, _ := do(t, s, "GET", "/", "evil.example.com:"+port, nil, ""); code != http.StatusForbidden {
		t.Fatalf("unexpected Host: want 403, got %d", code)
	}
}
