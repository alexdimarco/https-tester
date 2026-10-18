package redact

import (
	"net/http"
	"strings"
	"testing"
)

func TestHeadersRemovesCredentials(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Bearer sk-secret-value")
	h.Set("Cookie", "session=abc123")
	h.Set("Set-Cookie", "session=abc123")
	h.Set("Server", "nginx")
	out := Headers(h)

	for _, k := range []string{"Authorization", "Cookie", "Set-Cookie"} {
		if out[k] != Placeholder {
			t.Errorf("%s should be redacted, got %q", k, out[k])
		}
	}
	if out["Server"] != "nginx" {
		t.Errorf("non-sensitive header should pass through, got %q", out["Server"])
	}
	for _, v := range out {
		if strings.Contains(v, "secret") || strings.Contains(v, "abc123") {
			t.Errorf("a secret leaked through redaction: %q", v)
		}
	}
}

func TestURLMasksUserinfoAndTokens(t *testing.T) {
	in := "https://user:p4ssw0rd@host.example/path?access_token=SEKRET&page=2"
	out := URL(in)
	for _, bad := range []string{"p4ssw0rd", "SEKRET"} {
		if strings.Contains(out, bad) {
			t.Errorf("secret %q leaked through URL redaction: %q", bad, out)
		}
	}
	if !strings.Contains(out, "page=2") {
		t.Errorf("non-sensitive query value should be preserved: %q", out)
	}
}

func TestURLUnparsableReturnsPlaceholder(t *testing.T) {
	if got := URL("://%%%not a url"); got == "" {
		t.Error("unparsable URL should not return empty (risk of silent leak)")
	}
}
