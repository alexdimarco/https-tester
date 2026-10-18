package native

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"

	"github.com/alexdimarco/https-tester/internal/evidence"
)

// newFixture starts a local TLS server and returns the request pieces plus a
// cert pool that trusts it. This is the design's "smallest next implementation
// check": an owned local fixture, not a live service.
func newFixture(t *testing.T) (reqURL, host, port string, pool *x509.CertPool) {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parse fixture URL: %v", err)
	}
	pool = x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	return ts.URL + "/", u.Hostname(), u.Port(), pool
}

func findStage(obs []evidence.Observation, stage evidence.Stage) (evidence.Observation, bool) {
	for _, o := range obs {
		if o.Stage == stage {
			return o, true
		}
	}
	return evidence.Observation{}, false
}

func TestVerifiedRequestSuccess(t *testing.T) {
	reqURL, host, port, pool := newFixture(t)

	res := VerifiedRequest(context.Background(), Request{
		ProbeID:   "HTTPS-01",
		URL:       reqURL,
		Host:      host,
		Port:      port,
		DialAddr:  netip.MustParseAddr(host),
		RootCAs:   pool,
		TrustName: "test_bundle",
		Timeouts:  DefaultTimeouts(),
	})

	if res.StageReached != evidence.StageHTTP || res.Outcome != evidence.OutcomePass {
		t.Fatalf("want http/pass, got %s/%s", res.StageReached, res.Outcome)
	}
	tlsObs, ok := findStage(res.Observations, evidence.StageTLS)
	if !ok {
		t.Fatal("no TLS observation recorded")
	}
	if tlsObs.HandshakeComplete == nil || !*tlsObs.HandshakeComplete {
		t.Error("TLS handshake should be recorded complete")
	}
	if tlsObs.NegotiatedVersion == "" {
		t.Error("negotiated TLS version should be recorded")
	}
	certObs, ok := findStage(res.Observations, evidence.StageCertificate)
	if !ok {
		t.Fatal("no certificate observation recorded")
	}
	if certObs.PeerCertificatePresent == nil || !*certObs.PeerCertificatePresent {
		t.Error("peer certificate should be recorded present")
	}
	httpObs, ok := findStage(res.Observations, evidence.StageHTTP)
	if !ok || httpObs.HTTPStatus != http.StatusOK {
		t.Errorf("want HTTP 200 observation, got %+v", httpObs)
	}
}

// TestVerifiedRequestUntrusted confirms the tool reports an honest failure, not
// a pass, when the fixture's certificate is not trusted.
func TestVerifiedRequestUntrusted(t *testing.T) {
	reqURL, host, port, _ := newFixture(t)

	res := VerifiedRequest(context.Background(), Request{
		ProbeID:  "HTTPS-01",
		URL:      reqURL,
		Host:     host,
		Port:     port,
		DialAddr: netip.MustParseAddr(host),
		RootCAs:  x509.NewCertPool(), // empty: trusts nothing
		Timeouts: DefaultTimeouts(),
	})

	if res.StageReached != evidence.StageTLS || res.Outcome != evidence.OutcomeFail {
		t.Fatalf("want tls/fail for an untrusted cert, got %s/%s", res.StageReached, res.Outcome)
	}
	tlsObs, _ := findStage(res.Observations, evidence.StageTLS)
	if tlsObs.NormalizedError != "certificate_unknown_authority" {
		t.Errorf("want certificate_unknown_authority, got %q", tlsObs.NormalizedError)
	}
	if _, ok := findStage(res.Observations, evidence.StageHTTP); ok {
		t.Error("no HTTP observation should exist when the handshake failed")
	}
}
