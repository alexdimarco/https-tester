package nginxreview

import (
	"strings"
	"testing"
)

func hasTopic(r Review, substr string) *Finding {
	for i := range r.Findings {
		if strings.Contains(r.Findings[i].Topic, substr) {
			return &r.Findings[i]
		}
	}
	return nil
}

func TestDuplicateP256Alias(t *testing.T) {
	cfg := `
server {
    listen 443 ssl default_server;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ecdh_curve prime256v1:secp256r1:secp384r1;
}`
	r := Analyze(cfg)
	dup := hasTopic(r, "Duplicate key-exchange group")
	if dup == nil {
		t.Fatal("expected a duplicate-alias finding for prime256v1 + secp256r1")
	}
	if !strings.Contains(dup.Detail, "P-256") || !strings.Contains(dup.Detail, "version-dependent") {
		t.Errorf("duplicate finding should name P-256 and flag version-dependence: %q", dup.Detail)
	}
	// Must NOT claim every build will fail (forbidden over-generalization).
	if strings.Contains(strings.ToLower(dup.Detail), "every") && strings.Contains(strings.ToLower(dup.Detail), "fail") {
		t.Errorf("must not claim every build fails: %q", dup.Detail)
	}
	if hasTopic(r, "Default server") == nil {
		t.Error("expected default_server to be detected")
	}
}

func TestWeakProtocolsFlagged(t *testing.T) {
	r := Analyze(`ssl_protocols TLSv1 TLSv1.1 TLSv1.2;`)
	f := hasTopic(r, "TLS protocols")
	if f == nil || f.Severity != SeverityAttention {
		t.Fatalf("expected an attention finding for weak protocols, got %+v", f)
	}
	if !strings.Contains(f.Detail, "RFC 8996") {
		t.Errorf("weak-protocol finding should cite RFC 8996: %q", f.Detail)
	}
}

func TestTLS13CiphersMisplaced(t *testing.T) {
	r := Analyze(`ssl_ciphers "TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256";`)
	if hasTopic(r, "TLS 1.3 suite names in ssl_ciphers") == nil {
		t.Error("expected a finding that TLS 1.3 suite names are misplaced in ssl_ciphers")
	}
}

func TestReloadFailureAndParseErrors(t *testing.T) {
	r := Analyze(`nginx: [emerg] unknown directive "ssl_protcols" in /etc/nginx/nginx.conf:10
server { ssl_protocols TLSv1.2;`)
	if hasTopic(r, "Reload / config test") == nil {
		t.Error("expected a reload/config-test finding from [emerg] output")
	}
	if len(r.ParseErrors) == 0 {
		t.Error("expected a parse error for the unclosed server block")
	}
}

func TestCommentsAndQuotesLexed(t *testing.T) {
	cfg := `# a comment with ; and { braces }
ssl_ecdh_curve "X25519"; # trailing comment`
	dirs, errs := lex(cfg)
	if len(errs) != 0 {
		t.Errorf("unexpected parse errors: %v", errs)
	}
	found := false
	for _, d := range dirs {
		if d.name == "ssl_ecdh_curve" && len(d.args) == 1 && d.args[0] == "X25519" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected ssl_ecdh_curve X25519 parsed past the comment, got %+v", dirs)
	}
}
