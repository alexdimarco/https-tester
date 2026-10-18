// Package native runs the workbench's own Go TLS/HTTP probe. It is the
// mandatory foundation: it depends on no installed command-line tools.
//
// A probe dials exactly one operator-approved address while preserving the
// logical hostname for SNI and certificate verification, observes each stage of
// the connection through net/http/httptrace, and records only fields the public
// crypto/tls API actually exposes in this Go version. A false or zero value in
// a failed handshake is never recorded as proof that an event did not occur.
package native

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"time"

	"github.com/alexdimarco/https-tester/internal/evidence"
	"github.com/alexdimarco/https-tester/internal/redact"
)

// SourceKind labels observations produced by this engine.
const SourceKind = "go-native"

// Timeouts bounds each phase and the probe as a whole. The whole-probe deadline
// overrides the per-phase allowances.
type Timeouts struct {
	DNS        time.Duration
	TCP        time.Duration
	TLS        time.Duration
	HTTPHeader time.Duration
	Whole      time.Duration
}

// DefaultTimeouts are the design's proposed Gate A defaults (section 8.4).
func DefaultTimeouts() Timeouts {
	return Timeouts{
		DNS:        5 * time.Second,
		TCP:        5 * time.Second,
		TLS:        8 * time.Second,
		HTTPHeader: 8 * time.Second,
		Whole:      20 * time.Second,
	}
}

// Request is one verified HTTPS attempt against a single approved address.
type Request struct {
	ProbeID   string
	URL       string         // https://authority/path
	Host      string         // hostname used for SNI and certificate identity
	Port      string         // numeric port
	DialAddr  netip.Addr     // the single approved address to connect to
	RootCAs   *x509.CertPool // nil means system trust
	TrustName string         // human label for the trust source, e.g. "system"
	UserAgent string
	Timeouts  Timeouts
}

// Result is the ordered set of observations plus a summary of how far the
// connection got and its overall outcome.
type Result struct {
	Observations []evidence.Observation
	StageReached evidence.Stage
	Outcome      evidence.Outcome
}

// Resolve looks up a hostname. It is separate from VerifiedRequest so the
// caller can classify and approve addresses before any connection is attempted.
func Resolve(ctx context.Context, host string, timeout time.Duration) ([]netip.Addr, error) {
	if timeout <= 0 {
		timeout = DefaultTimeouts().DNS
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return (&net.Resolver{}).LookupNetIP(ctx, "ip", host)
}

// VerifiedRequest performs one bounded, verified HTTPS HEAD request to the
// approved address and returns the staged observations.
func VerifiedRequest(ctx context.Context, req Request) *Result {
	t := req.Timeouts
	if t.Whole <= 0 {
		t = DefaultTimeouts()
	}
	if !req.DialAddr.IsValid() {
		return singleObservation(req, evidence.StageTCP, evidence.OutcomeInternalError,
			"no approved address was provided to dial")
	}

	ctx, cancel := context.WithTimeout(ctx, t.Whole)
	defer cancel()

	dialTarget := net.JoinHostPort(req.DialAddr.String(), req.Port)

	var (
		connErr, tlsErr error
		connOK, tlsDone bool
		connState       tls.ConnectionState
		startConnect    time.Time
		startTLS        time.Time
		tcpDur, tlsDur  time.Duration
	)
	trace := &httptrace.ClientTrace{
		ConnectStart: func(_, _ string) { startConnect = time.Now() },
		ConnectDone: func(_, _ string, err error) {
			tcpDur = time.Since(startConnect)
			if err != nil {
				connErr = err
			} else {
				connOK = true
			}
		},
		TLSHandshakeStart: func() { startTLS = time.Now() },
		TLSHandshakeDone: func(cs tls.ConnectionState, err error) {
			tlsDur = time.Since(startTLS)
			if err != nil {
				tlsErr = err
			} else {
				tlsDone = true
				connState = cs
			}
		},
	}

	dialer := &net.Dialer{Timeout: t.TCP}
	transport := &http.Transport{
		Proxy: nil, // direct baseline: no implicit proxy
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			// Always dial the single approved address; the URL's host is kept
			// only for SNI and certificate verification.
			return dialer.DialContext(ctx, "tcp", dialTarget)
		},
		TLSClientConfig: &tls.Config{
			ServerName: req.Host,
			MinVersion: tls.VersionTLS12,
			RootCAs:    req.RootCAs,
		},
		TLSHandshakeTimeout:   t.TLS,
		ResponseHeaderTimeout: t.HTTPHeader,
		ForceAttemptHTTP2:     true,
		DisableKeepAlives:     true,
		DisableCompression:    true,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			// Do not auto-follow; a redirect is recorded as the HTTP result.
			return http.ErrUseLastResponse
		},
	}

	ua := req.UserAgent
	if ua == "" {
		ua = "https-diagnostic-workbench"
	}
	httpReq, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodHead, req.URL, nil)
	if err != nil {
		return singleObservation(req, evidence.StageHTTP, evidence.OutcomeInternalError,
			"could not build the request: "+redact.Error(err))
	}
	httpReq.Header.Set("User-Agent", ua)

	resp, doErr := client.Do(httpReq)
	if resp != nil {
		defer resp.Body.Close()
	}

	res := &Result{}

	// --- TCP ---
	if connErr != nil {
		res.append(req, evidence.StageTCP, evidence.OutcomeFail, obsFields{
			dur:    tcpDur,
			rawErr: connErr,
			detail: map[string]string{"dial_address": dialTarget},
		})
		return res.finish(evidence.StageTCP, evidence.OutcomeFail)
	}
	if !connOK {
		// No connect error was reported but the connection never completed —
		// usually the whole-probe deadline fired first. Report honestly.
		res.append(req, evidence.StageTCP, evidence.OutcomeInconclusive, obsFields{
			rawErr: doErr,
			detail: map[string]string{"dial_address": dialTarget},
			note:   "the connection did not complete and no specific connect error was captured",
		})
		return res.finish(evidence.StageTCP, evidence.OutcomeInconclusive)
	}
	res.append(req, evidence.StageTCP, evidence.OutcomePass, obsFields{
		dur:    tcpDur,
		detail: map[string]string{"dial_address": dialTarget},
	})

	// --- TLS + certificate ---
	if tlsErr != nil {
		res.append(req, evidence.StageTLS, evidence.OutcomeFail, obsFields{
			dur:       tlsDur,
			rawErr:    tlsErr,
			handshake: boolPtr(false),
			detail:    map[string]string{"server_name": req.Host, "trust_source": req.TrustName},
		})
		return res.finish(evidence.StageTLS, evidence.OutcomeFail)
	}
	if !tlsDone {
		res.append(req, evidence.StageTLS, evidence.OutcomeInconclusive, obsFields{
			handshake: boolPtr(false),
			note:      "the TLS handshake did not complete and no handshake error was captured",
		})
		return res.finish(evidence.StageTLS, evidence.OutcomeInconclusive)
	}

	res.appendTLS(req, connState)
	res.appendCertificate(req, connState)

	// --- HTTP ---
	if doErr != nil {
		res.append(req, evidence.StageHTTP, evidence.OutcomeFail, obsFields{
			rawErr: doErr,
			note:   "the TLS handshake completed but no HTTP response header was obtained",
		})
		return res.finish(evidence.StageHTTP, evidence.OutcomeFail)
	}
	res.append(req, evidence.StageHTTP, evidence.OutcomePass, obsFields{
		httpStatus: resp.StatusCode,
		detail:     httpDetail(resp),
	})
	return res.finish(evidence.StageHTTP, evidence.OutcomePass)
}

// obsFields collects the optional pieces an observation may carry.
type obsFields struct {
	dur        time.Duration
	rawErr     error
	handshake  *bool
	httpStatus int
	detail     map[string]string
	note       string
}

func (r *Result) append(req Request, stage evidence.Stage, outcome evidence.Outcome, f obsFields) {
	o := evidence.Observation{
		ProbeID:      req.ProbeID,
		SourceKind:   SourceKind,
		TimestampUTC: time.Now().UTC(),
		DurationMS:   f.dur.Milliseconds(),
		Stage:        stage,
		Outcome:      outcome,
		HRRStatus:    "not_observable_at_this_gate",
		Detail:       f.detail,
	}
	if f.rawErr != nil {
		o.RawErrorRedacted = redact.Error(f.rawErr)
		o.NormalizedError = normalize(f.rawErr)
	}
	if f.handshake != nil {
		o.HandshakeComplete = f.handshake
	}
	if f.httpStatus != 0 {
		o.HTTPStatus = f.httpStatus
	}
	if f.note != "" {
		if o.Detail == nil {
			o.Detail = map[string]string{}
		}
		o.Detail["note"] = f.note
	}
	r.Observations = append(r.Observations, o)
}

func (r *Result) appendTLS(req Request, cs tls.ConnectionState) {
	group := "unknown"
	if cs.CurveID != 0 {
		group = cs.CurveID.String()
	} else {
		group = "none_or_legacy_rsa_key_exchange"
	}
	alpn := cs.NegotiatedProtocol
	if alpn == "" {
		alpn = "none"
	}
	r.Observations = append(r.Observations, evidence.Observation{
		ProbeID:             req.ProbeID,
		SourceKind:          SourceKind,
		TimestampUTC:        time.Now().UTC(),
		Stage:               evidence.StageTLS,
		Outcome:             evidence.OutcomePass,
		HandshakeComplete:   boolPtr(true),
		NegotiatedVersion:   tls.VersionName(cs.Version),
		CipherSuite:         tls.CipherSuiteName(cs.CipherSuite),
		Group:               group,
		ApplicationProtocol: alpn,
		HRRStatus:           "not_observable_at_this_gate",
		CaptureCompleteness: "public_connectionstate_fields_only",
		Detail:              map[string]string{"server_name": req.Host, "trust_source": req.TrustName},
	})
}

func (r *Result) appendCertificate(req Request, cs tls.ConnectionState) {
	o := evidence.Observation{
		ProbeID:            req.ProbeID,
		SourceKind:         SourceKind,
		TimestampUTC:       time.Now().UTC(),
		Stage:              evidence.StageCertificate,
		Outcome:            evidence.OutcomePass,
		VerificationStatus: "verified_against_" + trustLabel(req),
		HRRStatus:          "not_observable_at_this_gate",
		RemainingUnknowns:  []string{"revocation status (OCSP/CRL) was not checked", "certificate transparency was not checked"},
	}
	present := len(cs.PeerCertificates) > 0
	o.PeerCertificatePresent = boolPtr(present)
	if present {
		leaf := cs.PeerCertificates[0]
		o.Detail = map[string]string{
			"subject":    leaf.Subject.String(),
			"issuer":     leaf.Issuer.String(),
			"not_before": leaf.NotBefore.UTC().Format(time.RFC3339),
			"not_after":  leaf.NotAfter.UTC().Format(time.RFC3339),
			"dns_names":  joinNames(leaf.DNSNames),
		}
	}
	r.Observations = append(r.Observations, o)
}

func (r *Result) finish(stage evidence.Stage, outcome evidence.Outcome) *Result {
	r.StageReached = stage
	r.Outcome = outcome
	return r
}

func singleObservation(req Request, stage evidence.Stage, outcome evidence.Outcome, note string) *Result {
	r := &Result{}
	r.append(req, stage, outcome, obsFields{note: note})
	return r.finish(stage, outcome)
}

func httpDetail(resp *http.Response) map[string]string {
	d := map[string]string{
		"status":   resp.Status,
		"protocol": resp.Proto,
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		d["location"] = redact.URL(loc)
	}
	if server := resp.Header.Get("Server"); server != "" {
		// A Server header is self-reported by the peer, not authoritative
		// infrastructure identification.
		d["server_header_self_reported"] = server
	}
	return d
}

func trustLabel(req Request) string {
	if req.TrustName != "" {
		return req.TrustName
	}
	if req.RootCAs == nil {
		return "system_trust"
	}
	return "supplied_bundle"
}

func normalize(err error) string {
	if err == nil {
		return ""
	}
	var ce x509.CertificateInvalidError
	if errors.As(err, &ce) {
		return "certificate_invalid"
	}
	var he x509.HostnameError
	if errors.As(err, &he) {
		return "certificate_hostname_mismatch"
	}
	var ua x509.UnknownAuthorityError
	if errors.As(err, &ua) {
		return "certificate_unknown_authority"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	return "see_raw_error"
}

func boolPtr(b bool) *bool { return &b }

func joinNames(names []string) string {
	out := ""
	for i, n := range names {
		if i > 0 {
			out += ", "
		}
		out += n
	}
	if out == "" {
		return "(none)"
	}
	return out
}
