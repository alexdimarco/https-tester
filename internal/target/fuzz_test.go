package target

import (
	"strings"
	"testing"
)

// FuzzParseAndValidate checks the URL validator never panics and that anything
// it accepts satisfies the invariants the rest of the tool relies on.
func FuzzParseAndValidate(f *testing.F) {
	for _, s := range []string{
		"https://example.com/", "http://x", "https://u:p@h/",
		"https://[::1]:443/", "https://a.com:70000/", "",
		"https://exämple.com/", "https://例え.test/", "https://a.com:0/",
		"https://a.com/\x00", "https://", "ftp://a.com/", "https://a.com:443/a b",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		tgt, err := ParseAndValidate(s)
		if err != nil {
			return // rejection is always acceptable
		}
		if tgt.Host == "" {
			t.Errorf("accepted %q with empty host", s)
		}
		if tgt.Port == "" {
			t.Errorf("accepted %q with empty port", s)
		}
		if !strings.HasPrefix(tgt.RequestURL(), "https://") {
			t.Errorf("accepted %q but request URL is not https: %q", s, tgt.RequestURL())
		}
		if strings.ContainsAny(tgt.Host, " \t\r\n") {
			t.Errorf("accepted %q with whitespace in host", s)
		}
	})
}
