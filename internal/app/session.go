// Package app wires the pieces together and owns the lifecycle of a single
// local session: it validates targets, resolves and scope-checks addresses,
// records the operator's authorization, runs one probe at a time, and derives
// scoped claims from the observations.
package app

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/alexdimarco/https-tester/internal/assess"
	"github.com/alexdimarco/https-tester/internal/evidence"
	"github.com/alexdimarco/https-tester/internal/probe/native"
	"github.com/alexdimarco/https-tester/internal/report"
	"github.com/alexdimarco/https-tester/internal/target"
)

// Session holds the in-memory runs for one launch of the workbench.
type Session struct {
	build    string
	trust    string
	timeouts native.Timeouts

	mu       sync.Mutex
	probeMu  sync.Mutex // serializes outbound probes: one at a time per session
	runs     map[string]*evidence.LiveRun
	selfAuth string // the workbench's own listener authority, never a valid target
}

// NewSession creates an empty session with system trust (the Gate A default).
func NewSession(build string) *Session {
	return &Session{
		build:    build,
		trust:    "system",
		timeouts: native.DefaultTimeouts(),
		runs:     map[string]*evidence.LiveRun{},
	}
}

// SetSelfAuthority records the workbench's own listener host:port so a target
// can never be the diagnostic process itself.
func (s *Session) SetSelfAuthority(authority string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.selfAuth = authority
}

// Capabilities describes the build and which client profiles are available.
type Capabilities struct {
	AppBuild  string   `json:"app_build"`
	Clients   []string `json:"clients"`
	TrustMode string   `json:"trust_mode"`
}

// Capabilities reports current build and client availability.
func (s *Session) Capabilities() Capabilities {
	return Capabilities{
		AppBuild:  s.build,
		Clients:   []string{native.SourceKind},
		TrustMode: s.trust,
	}
}

// CreateRunRequest is the operator's authorization to investigate one target.
type CreateRunRequest struct {
	URL                  string `json:"url"`
	Note                 string `json:"note"`
	LocalPrivateApproved bool   `json:"local_private_approved"`
}

// CreateRun validates the target, resolves and scope-checks addresses, records
// authorization, and returns a snapshot of the new run.
func (s *Session) CreateRun(ctx context.Context, req CreateRunRequest) (evidence.Run, error) {
	t, err := target.ParseAndValidate(req.URL)
	if err != nil {
		return evidence.Run{}, err
	}

	selected, family, notes, err := s.resolveAndScope(ctx, t, req.LocalPrivateApproved)
	if err != nil {
		return evidence.Run{}, err
	}

	now := time.Now().UTC()
	runID := evidence.NewID("run")
	run := evidence.NewLiveRun(evidence.Run{
		SchemaVersion:      evidence.SchemaVersion,
		RunID:              runID,
		AppBuild:           s.build,
		RuleCatalogVersion: "gate-a-builtin",
		StartedAtUTC:       now,
		ClockSource:        "local system clock (not independently verified)",
		Platform:           runtime.GOOS,
		Architecture:       runtime.GOARCH,
		TrustMode:          s.trust,
		Authorization: evidence.Authorization{
			OperatorAcknowledged: true,
			LocalPrivateApproved: req.LocalPrivateApproved,
			Note:                 req.Note,
			AuthorizedAtUTC:      now,
		},
		TargetScope: evidence.TargetScope{
			InputURL:          t.InputURL,
			Authority:         t.Authority,
			Host:              t.Host,
			Port:              t.Port,
			Path:              t.Path,
			SelectedAddresses: addrStrings(selected),
			AddressFamily:     family,
		},
	})
	run.AddConsentEvent(evidence.ConsentEvent{
		AtUTC:  now,
		Kind:   "target_authorized",
		Detail: fmt.Sprintf("authority=%s addresses=%s", t.Authority, strings.Join(addrStrings(selected), ",")),
	})
	for _, n := range notes {
		run.AddConsentEvent(evidence.ConsentEvent{AtUTC: now, Kind: "scope_note", Detail: n})
	}
	// Record the input/DNS stage as the first observation.
	run.AddObservation(evidence.Observation{
		ProbeID:      "DNS-01",
		SourceKind:   native.SourceKind,
		TimestampUTC: now,
		Stage:        evidence.StageDNS,
		Outcome:      evidence.OutcomePass,
		Detail: map[string]string{
			"resolved_addresses": strings.Join(addrStrings(selected), ", "),
			"address_family":     family,
		},
		RemainingUnknowns: []string{"this is not an authoritative DNS zone audit; TTLs were not recorded"},
	})

	s.mu.Lock()
	s.runs[runID] = run
	s.mu.Unlock()

	return run.Snapshot(), nil
}

// RunProbe runs one probe profile against the first selected address and
// appends its observations and a derived claim. The empty profile is the
// default verified request; named profiles test an exact TLS version or a
// single key-exchange group.
func (s *Session) RunProbe(ctx context.Context, runID, profile string) (evidence.Run, error) {
	run, err := s.lookup(runID)
	if err != nil {
		return evidence.Run{}, err
	}
	spec, err := profileSpec(profile)
	if err != nil {
		return evidence.Run{}, err
	}

	s.probeMu.Lock() // one outbound probe at a time per session
	defer s.probeMu.Unlock()

	scope := run.Scope()
	if len(scope.SelectedAddresses) == 0 {
		return evidence.Run{}, fmt.Errorf("no approved address is available to probe")
	}
	dialAddr, perr := netip.ParseAddr(scope.SelectedAddresses[0])
	if perr != nil {
		return evidence.Run{}, fmt.Errorf("the approved address %q is not valid", scope.SelectedAddresses[0])
	}

	reqURL := "https://" + scope.Authority + scope.Path
	result := native.VerifiedRequest(ctx, native.Request{
		ProbeID:    spec.probeID,
		URL:        reqURL,
		Host:       scope.Host,
		Port:       scope.Port,
		DialAddr:   dialAddr,
		TrustName:  s.trust + "_trust",
		UserAgent:  "https-diagnostic-workbench/" + s.build,
		Timeouts:   s.timeouts,
		MinVersion: spec.min,
		MaxVersion: spec.max,
		Curves:     spec.curves,
		Profile:    spec.label,
	})
	// Assign observation IDs before storing so the derived claim can reference
	// them (the status badge in the report is computed from this linkage).
	for i := range result.Observations {
		if result.Observations[i].ID == "" {
			result.Observations[i].ID = evidence.NewID("obs")
		}
	}
	for _, o := range result.Observations {
		run.AddObservation(o)
	}
	run.AddClaim(deriveClaim(result, scope, spec))

	return run.Snapshot(), nil
}

// probe describes one named test profile and the exact TLS knobs it sets.
type probe struct {
	profile string // caller-supplied key
	probeID string // evidence probe id
	kind    string // "default", "version", or "group"
	label   string // human-readable profile description
	group   string // group name for the "group" kind
	min     uint16
	max     uint16
	curves  []tls.CurveID
}

// profileSpec maps a profile key to its TLS controls. Only groups Go actually
// supports are offered; it never invents an unsupported constant.
func profileSpec(profile string) (probe, error) {
	switch profile {
	case "", "default":
		return probe{profile: "default", probeID: "HTTPS-01", kind: "default",
			label: "default (minimum TLS 1.2, library default groups)"}, nil
	case "tls12":
		return probe{profile: profile, probeID: "TLS-12", kind: "version",
			label: "TLS 1.2", min: tls.VersionTLS12, max: tls.VersionTLS12}, nil
	case "tls13":
		return probe{profile: profile, probeID: "TLS-13", kind: "version",
			label: "TLS 1.3", min: tls.VersionTLS13, max: tls.VersionTLS13}, nil
	case "group:x25519":
		return groupProbe(profile, "GROUP-X25519", "X25519", tls.X25519), nil
	case "group:p256":
		return groupProbe(profile, "GROUP-P256", "P-256", tls.CurveP256), nil
	case "group:p384":
		return groupProbe(profile, "GROUP-P384", "P-384", tls.CurveP384), nil
	case "group:p521":
		return groupProbe(profile, "GROUP-P521", "P-521", tls.CurveP521), nil
	default:
		return probe{}, fmt.Errorf("unknown probe profile %q", profile)
	}
}

func groupProbe(profile, probeID, groupName string, curve tls.CurveID) probe {
	return probe{
		profile: profile, probeID: probeID, kind: "group", group: groupName,
		label: "TLS 1.3, " + groupName + " only",
		min:   tls.VersionTLS13, max: tls.VersionTLS13,
		curves: []tls.CurveID{curve},
	}
}

// Assess returns the protocol-posture assessment derived from a run's
// observations.
func (s *Session) Assess(runID string) (assess.Assessment, error) {
	run, err := s.lookup(runID)
	if err != nil {
		return assess.Assessment{}, err
	}
	return assess.Build(run.Snapshot()), nil
}

// Get returns a redacted snapshot of a run.
func (s *Session) Get(runID string) (evidence.Run, error) {
	run, err := s.lookup(runID)
	if err != nil {
		return evidence.Run{}, err
	}
	return run.Snapshot(), nil
}

// Export renders a run as text or JSON.
func (s *Session) Export(runID, format string) (string, error) {
	run, err := s.lookup(runID)
	if err != nil {
		return "", err
	}
	snap := run.Snapshot()
	switch format {
	case "json":
		b, jerr := report.JSON(snap)
		if jerr != nil {
			return "", jerr
		}
		return string(b), nil
	case "", "text":
		return report.Text(snap), nil
	default:
		return "", fmt.Errorf("unknown report format %q (use text or json)", format)
	}
}

func (s *Session) lookup(runID string) (*evidence.LiveRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[runID]
	if !ok {
		return nil, fmt.Errorf("no run with id %q", runID)
	}
	return run, nil
}

// resolveAndScope resolves the host (or uses the IP literal), hard-blocks unsafe
// classes, enforces private/loopback approval, blocks the workbench's own
// listener, and returns the selected addresses with any scope notes.
func (s *Session) resolveAndScope(ctx context.Context, t *target.Target, privateApproved bool) ([]netip.Addr, string, []string, error) {
	var candidates []netip.Addr
	if t.IsIP {
		a, _ := netip.ParseAddr(t.Host)
		candidates = []netip.Addr{a}
	} else {
		addrs, err := native.Resolve(ctx, t.Host, s.timeouts.DNS)
		if err != nil {
			return nil, "", nil, fmt.Errorf("could not resolve %q: %w", t.Host, err)
		}
		candidates = addrs
	}

	s.mu.Lock()
	self := s.selfAuth
	s.mu.Unlock()

	var selected []netip.Addr
	var notes []string
	for _, a := range candidates {
		a = a.Unmap()
		if self != "" && equalAuthority(a, t.Port, self) {
			notes = append(notes, "dropped the workbench's own listener address from scope")
			continue
		}
		class, reason := target.Classify(a)
		switch class {
		case target.ClassBlocked:
			notes = append(notes, fmt.Sprintf("blocked %s: %s", a, reason))
		case target.ClassPrivateOrLoopback:
			if !privateApproved {
				notes = append(notes, fmt.Sprintf("skipped private/loopback address %s (needs explicit approval)", a))
				continue
			}
			selected = append(selected, a)
		default:
			selected = append(selected, a)
		}
	}

	if len(selected) == 0 {
		if containsPrivate(candidates) && !privateApproved {
			return nil, "", notes, fmt.Errorf("this target resolves only to private or loopback addresses; re-run with explicit approval to test a private target")
		}
		return nil, "", notes, fmt.Errorf("no permitted address remained after scope checks")
	}

	// Gate A dials the first selected address; the budget is 4 addresses total.
	if len(selected) > 4 {
		notes = append(notes, fmt.Sprintf("%d addresses resolved; scope limited to the first 4", len(selected)))
		selected = selected[:4]
	}
	return selected, familyOf(selected), notes, nil
}

func deriveClaim(r *native.Result, scope evidence.TargetScope, spec probe) evidence.Claim {
	base := evidence.Claim{
		RuleID:   "gate-b-" + spec.kind,
		Register: "finding about observed results",
		Checked:  checkedText(spec),
		Status:   evidence.StatusObserved,
		Scope:    fmt.Sprintf("the Go native client (%s), against %s at %s", spec.label, scope.Authority, strings.Join(scope.SelectedAddresses, ", ")),
	}
	for _, o := range r.Observations {
		base.SupportingObservations = append(base.SupportingObservations, o.ID)
	}
	pass := r.StageReached == evidence.StageHTTP && r.Outcome == evidence.OutcomePass
	deepest := deepestNonPass(r.Observations)
	stage := strings.ToUpper(string(r.StageReached))

	switch spec.kind {
	case "version":
		if pass {
			base.Statement = fmt.Sprintf("With %s, a verified HTTPS response was obtained for this attempt.", spec.label)
			base.NextDiscriminatingCheck = "compare the other TLS version on the same endpoint to characterize version-dependent behavior."
		} else {
			base.Statement = fmt.Sprintf("With %s, the connection did not complete a verified request; it reached the %s stage (%s) for this attempt.%s", spec.label, stage, r.Outcome, certSuffix(deepest))
			base.Alternatives = []string{"version-dependent behavior in these tests", "a client/profile or trust difference", "a path or virtual-host difference not yet examined"}
			base.NextDiscriminatingCheck = "run the other TLS version, then controlled single key-exchange groups, on the same endpoint."
		}
		base.UncheckedItems = []string{"this does not establish behavior for the other TLS version", "the server's effective configuration was not examined"}
		return base

	case "group":
		if pass {
			base.Statement = fmt.Sprintf("Under TLS 1.3 offering only the %s key-exchange group, the handshake succeeded for this attempt.", spec.group)
			base.NextDiscriminatingCheck = "offer the other single groups and compare which succeed and which fail."
		} else {
			base.Statement = fmt.Sprintf("Under TLS 1.3 offering only the %s key-exchange group, the handshake failed for this attempt. This does not prove the server disables %s.", spec.group, spec.group)
			base.Alternatives = []string{
				fmt.Sprintf("the server may not have %s active, OR", spec.group),
				"a runtime policy, default virtual host, or path difference may explain it",
				"this client build may not have offered it as expected",
			}
			base.NextDiscriminatingCheck = fmt.Sprintf("offer other single groups and compare; then obtain the server's active group configuration and a handshake trace for %s.", spec.group)
		}
		base.UncheckedItems = []string{"a single-group result does not enumerate every group the server accepts", "the server's effective configuration was not examined"}
		return base
	}

	// default profile
	if pass {
		base.Statement = "A verified HTTPS response was obtained from this endpoint with the Go native client."
		base.UncheckedItems = []string{
			"this represents the Go client's profile, not a browser or an installed curl/OpenSSL",
			"revocation, certificate transparency, and HSTS/ECH/HTTP3 were not tested",
		}
		base.NextDiscriminatingCheck = "compare an approved installed client (curl/OpenSSL) or a browser against the same endpoint to confirm client-independence."
		return base
	}
	switch deepest.NormalizedError {
	case "certificate_invalid":
		base.Statement = "The server's certificate failed validation for this attempt: it is expired or not yet valid, as presented to this client."
		base.NextDiscriminatingCheck = "check the certificate's not-before/not-after dates against an independently trusted clock, and compare with a browser."
	case "certificate_hostname_mismatch":
		base.Statement = "The server's certificate does not cover the requested hostname for this attempt, as presented to this client."
		base.NextDiscriminatingCheck = "compare the requested host against the certificate's subject alternative names, and confirm the intended virtual host."
	case "certificate_unknown_authority":
		base.Statement = "The server's certificate chains to an authority this client does not trust for this attempt."
		base.NextDiscriminatingCheck = "compare against the intended trust bundle and check for a missing intermediate certificate; compare with a browser."
	case "timeout":
		base.Statement = fmt.Sprintf("The connection timed out at the %s stage for this attempt.", stage)
		base.NextDiscriminatingCheck = "retry the same profile, then compare another approved network path or address and check firewall/listener state."
	default:
		base.Statement = fmt.Sprintf("The connection did not produce a verified HTTPS response; it reached the %s stage with outcome %q for this attempt.", stage, r.Outcome)
		base.NextDiscriminatingCheck = "repeat with an exact TLS-version profile and, if needed, single key-exchange groups on the same endpoint; then gather server-side evidence."
	}
	base.Alternatives = []string{
		"a client/profile or trust-store difference rather than a server defect",
		"a network path, firewall, or load-balancer difference for this address",
		"a server-side protocol, certificate, or virtual-host setting not yet examined",
	}
	base.UncheckedItems = []string{"the server's effective configuration and logs were not examined"}
	return base
}

func certSuffix(o evidence.Observation) string {
	switch o.NormalizedError {
	case "certificate_invalid":
		return " The certificate is expired or not yet valid as presented to this client."
	case "certificate_hostname_mismatch":
		return " The certificate does not cover the requested hostname."
	case "certificate_unknown_authority":
		return " The certificate chains to an authority this client does not trust."
	default:
		return ""
	}
}

func checkedText(spec probe) string {
	switch spec.kind {
	case "version":
		return fmt.Sprintf("Whether the server completes a connection using %s.", spec.label)
	case "group":
		return fmt.Sprintf("Whether the server completes a TLS 1.3 connection when only the %s key-exchange group is offered.", spec.group)
	default:
		return "Whether this machine can complete a verified HTTPS request to the endpoint, with the certificate trusted."
	}
}

func deepestNonPass(obs []evidence.Observation) evidence.Observation {
	var deepest evidence.Observation
	for _, o := range obs {
		if o.Outcome != evidence.OutcomePass {
			deepest = o
		}
	}
	return deepest
}

func equalAuthority(a netip.Addr, port, selfAuthority string) bool {
	host, p, ok := splitHostPort(selfAuthority)
	if !ok || p != port {
		return false
	}
	sa, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return sa.Unmap() == a.Unmap()
}

func splitHostPort(s string) (string, string, bool) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", "", false
	}
	host := strings.TrimPrefix(strings.TrimSuffix(s[:i], "]"), "[")
	return host, s[i+1:], true
}

func addrStrings(addrs []netip.Addr) []string {
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = a.String()
	}
	return out
}

func containsPrivate(addrs []netip.Addr) bool {
	for _, a := range addrs {
		if c, _ := target.Classify(a.Unmap()); c == target.ClassPrivateOrLoopback {
			return true
		}
	}
	return false
}

func familyOf(addrs []netip.Addr) string {
	var v4, v6 bool
	for _, a := range addrs {
		if a.Is4() {
			v4 = true
		} else {
			v6 = true
		}
	}
	switch {
	case v4 && v6:
		return "ipv4+ipv6"
	case v6:
		return "ipv6"
	default:
		return "ipv4"
	}
}
