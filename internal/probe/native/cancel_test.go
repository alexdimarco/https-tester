package native

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/alexdimarco/https-tester/internal/evidence"
)

// TestVerifiedRequestCancelled ensures an already-cancelled context yields a
// prompt, non-passing result rather than hanging or panicking.
func TestVerifiedRequestCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan *Result, 1)
	go func() {
		done <- VerifiedRequest(ctx, Request{
			ProbeID:  "HTTPS-01",
			URL:      "https://192.0.2.1/", // TEST-NET-1, unroutable
			Host:     "192.0.2.1",
			Port:     "443",
			DialAddr: netip.MustParseAddr("192.0.2.1"),
			Timeouts: DefaultTimeouts(),
		})
	}()

	select {
	case res := <-done:
		if res.Outcome == evidence.OutcomePass {
			t.Error("a cancelled probe must not report pass")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("cancelled probe did not return promptly")
	}
}
