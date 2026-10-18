package target

import (
	"net/netip"
	"testing"
)

func TestParseAndValidate(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantErr bool
		host    string
		port    string
	}{
		{"simple", "https://example.com/", false, "example.com", "443"},
		{"explicit port and path", "https://example.com:8443/a/b", false, "example.com", "8443"},
		{"ip literal", "https://127.0.0.1/", false, "127.0.0.1", "443"},
		{"no scheme", "example.com", true, "", ""},
		{"http rejected", "http://example.com/", true, "", ""},
		{"userinfo rejected", "https://user:pass@example.com/", true, "", ""},
		{"bad port", "https://example.com:99999/", true, "", ""},
		{"empty", "   ", true, "", ""},
		{"control char", "https://exa\x00mple.com/", true, "", ""},
		{"non-ascii host", "https://exämple.com/", true, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ParseAndValidate(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got none", c.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", c.in, err)
			}
			if got.Host != c.host || got.Port != c.port {
				t.Errorf("got host=%q port=%q, want host=%q port=%q", got.Host, got.Port, c.host, c.port)
			}
		})
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		addr string
		want Class
	}{
		{"1.1.1.1", ClassPublic},
		{"8.8.8.8", ClassPublic},
		{"127.0.0.1", ClassPrivateOrLoopback},
		{"10.0.0.5", ClassPrivateOrLoopback},
		{"192.168.1.1", ClassPrivateOrLoopback},
		{"169.254.169.254", ClassBlocked}, // link-local / cloud metadata
		{"224.0.0.1", ClassBlocked},       // multicast
		{"0.0.0.0", ClassBlocked},         // unspecified
		{"255.255.255.255", ClassBlocked}, // broadcast
	}
	for _, c := range cases {
		got, reason := Classify(netip.MustParseAddr(c.addr))
		if got != c.want {
			t.Errorf("Classify(%s) = %v (%s), want %v", c.addr, got, reason, c.want)
		}
	}
}
