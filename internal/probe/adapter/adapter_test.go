package adapter

import (
	"context"
	"os/exec"
	"testing"
)

func TestDiscoverReportsAvailability(t *testing.T) {
	tools := Discover(context.Background())
	if len(tools) != 2 {
		t.Fatalf("expected curl and openssl entries, got %d", len(tools))
	}
	for _, tool := range tools {
		_, lookErr := exec.LookPath(tool.Name)
		present := lookErr == nil
		if tool.Available != present {
			t.Errorf("%s: Available=%v but LookPath present=%v", tool.Name, tool.Available, present)
		}
		if present && tool.Version == "" {
			t.Errorf("%s is present but no version was captured", tool.Name)
		}
		if !present && tool.Note == "" {
			t.Errorf("%s is absent but no explanatory note was set", tool.Name)
		}
	}
}

func TestSanitizedEnvDropsKeyLogAndProxy(t *testing.T) {
	t.Setenv("SSLKEYLOGFILE", "/tmp/keys.log")
	t.Setenv("HTTPS_PROXY", "http://evil.example:8080")
	for _, kv := range sanitizedEnv() {
		if len(kv) >= len("SSLKEYLOGFILE=") && kv[:len("SSLKEYLOGFILE=")] == "SSLKEYLOGFILE=" {
			t.Error("SSLKEYLOGFILE must be stripped from the child environment")
		}
		if len(kv) >= len("HTTPS_PROXY=") && kv[:len("HTTPS_PROXY=")] == "HTTPS_PROXY=" {
			t.Error("HTTPS_PROXY must be stripped for the direct baseline")
		}
	}
}

func TestBoundedBufferTruncates(t *testing.T) {
	b := &boundedBuffer{max: 10}
	_, _ = b.Write([]byte("0123456789ABCDEF"))
	got := b.String()
	if len(got) == 0 || got[len(got)-len("(truncated)"):] != "(truncated)" {
		t.Errorf("expected truncation marker, got %q", got)
	}
}
